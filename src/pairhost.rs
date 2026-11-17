//! 邀请服务（A1）：把「管理身份 + 邀请签发」装到**服务器**上，再从这里调用。
//!
//! 为什么放在服务器上：邀请码要固定的那几样东西——公网入口、TLS 证书指纹、管理签名身份——
//! 只有服务器自己知道，而且邀请码被用掉时必须由服务器把设备加进隧道。客户端全程只持
//! 「签好的邀请码」，不持签名能力，所以一台管理电脑被拿走也不会泄漏签发权。
//!
//! 本模块只做三件事：把 [`SCRIPT`] 传到服务器、调用它的子命令、把回包解析成结构化结果。
//! 协议的密码学部分在 `pairing` 里（客户端侧），两边是**同一份契约的两头**：
//! 这里生成的邀请码必须能被 `pairing::parse_code` 与 `pairing::read_invitation` 验过，
//! 否则就是「服务器说签好了、客户端说不是它签的」——最难查的一类故障。

use std::time::Duration;

use base64::Engine;
use serde_json::Value;

use crate::pairing;
use crate::ssh;

/// 服务器上的根目录。与旧版的 `/var/lib/tradechannel/pairing-online` **故意不同**：
/// 同一台机器上允许两版并存，路径撞了就等于互相覆盖对方的邀请记录。
pub const REMOTE_DIR: &str = "/var/lib/tradechannel/pairing-rs";
const REMOTE_SCRIPT: &str = "/var/lib/tradechannel/pairing-rs/tc-pair.py";
const REMOTE_DIGEST: &str = "/var/lib/tradechannel/pairing-rs/tc-pair.sha256";

/// 服务器侧的脚本本体。编译进 exe，部署时上传，不上网下载。
pub const SCRIPT: &str = include_str!("../assets/tc-pair.py");

/// 18443 接收服务。装成 systemd 单元而不是 `nohup`：
/// 服务器重启后邀请码还得能用（旧版的「重新开启接收服务」就是补这一步），
/// 而 `nohup` 起的进程活不过重启，用户看到的会是「邀请码没过期，就是连不上」。
const SERVICE: &str = "tc-pair.service";
const UNIT: &str = "\
[Unit]
Description=SpiderVPN invitation receiver (18443)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -I /var/lib/tradechannel/pairing-rs/tc-pair.py serve
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
";

/// 单次上传的切片长度。SSH exec 的命令串受单包上限约束，整段 20 KB 塞进去
/// 在部分服务端会被拒；6000 字符是 base64 的纯 ASCII，单引号不会出现，拼接安全。
const UPLOAD_CHUNK: usize = 6_000;
const TIMEOUT: Duration = Duration::from_secs(120);

/// 失败要带「该退几号」，与 `crate::exit` 一致；界面据此决定提示重试还是让人改配置。
#[derive(Debug, Clone)]
pub struct Fault {
    pub code: u8,
    pub message: String,
}

impl Fault {
    fn new(code: u8, message: impl Into<String>) -> Fault {
        Fault {
            code,
            message: message.into(),
        }
    }
}

/// 这一次「开启接收服务」对服务器脚本做了什么。
///
/// 用户最需要知道的正是这件事：旧服务器上页面会说「请重新执行一次开启接收服务」，
/// 但执行完之后，只有说清「换了新脚本」还是「本来就已经是最新」，他才算真完成那一步。
/// 看不出结论时，人只会再点一次、再点一次。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// 服务器上已经是这一份脚本，没有重传。
    UpToDate,
    /// 这次把新脚本传上去并落了盘。
    Pushed,
}

impl PushOutcome {
    /// CLI 与界面共用的一句话。别在调用点各写一遍，否则两处说法迟早会漂。
    pub fn label(self) -> &'static str {
        match self {
            PushOutcome::UpToDate => "已是最新，未重传",
            PushOutcome::Pushed => "已上传新脚本",
        }
    }
}

/// 服务器侧已就绪的身份。`fingerprint` 是管理签名身份，`tls_sha256` 是证书指纹，
/// 两者都会写进每一张邀请码——装完就该记下来，后面比对上就是「还是不是这台服务器」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub endpoint: String,
    pub tls_sha256: String,
    pub management_fingerprint: String,
    pub node_id: String,
    pub server_public_key: String,
    /// 本次安装对脚本做了什么（见 [`PushOutcome`]）。
    pub script: PushOutcome,
}

/// 一张签好的邀请。
#[derive(Debug, Clone)]
pub struct Issued {
    /// 已经过 `pairing::parse_code` 校验的邀请码——调用方可以直接显示或投递。
    pub invite: pairing::Invite,
    /// 服务器签名的邀请本身（RS256 JWS）。在线流程用不到它，离线交接要把它
    /// 交给新电脑：对方连不上 18443，没法用 TCI1 码回服务器读描述符。
    /// 它不含令牌，单独拿到也消费不了邀请。
    pub invite_jws: String,
    pub expires_at_utc: String,
    /// 服务器登记的设备名（新电脑加入时的默认名字）。
    pub device_name: String,
}

/// 按线路找到它对应的服务器记录。
///
/// 依据是线路文件里 `outbounds[].server` 的字面地址与服务器记录的 `host` 相等——
/// 线路文件是**已经落盘、真正会被引擎读的那一份**，比任何内存里的推测都可靠。
/// 一条线路可能同时有 vless 与 wireguard 两个出站（兼容/标准各一），两个都要看，
/// 否则「同一台服务器的两条线路只有一条能邀请」。
/// 线路文件里出现过的服务器地址。
///
/// **两处都要看**：
/// - 出站的 `server`：兼容连接（VLESS）与代理类出站写在这里；
/// - 端点的 `endpoints[].peers[].address`：标准线路（WireGuard）根本没有 `server`
///   字段，服务器地址只在这里。漏掉这一支，就等于「自己部署出来的标准线路不属于
///   任何服务器」——邀请入口恒灰、服务器页也看不到它。
fn line_addresses(value: &Value) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    if let Some(outbounds) = value.get("outbounds").and_then(Value::as_array) {
        for outbound in outbounds {
            if let Some(server) = outbound.get("server").and_then(Value::as_str) {
                hosts.push(server.to_string());
            }
        }
    }
    if let Some(endpoints) = value.get("endpoints").and_then(Value::as_array) {
        for endpoint in endpoints {
            if let Some(peers) = endpoint.get("peers").and_then(Value::as_array) {
                for peer in peers {
                    if let Some(address) = peer.get("address").and_then(Value::as_str) {
                        hosts.push(address.to_string());
                    }
                }
            }
        }
    }
    hosts
        .into_iter()
        .filter_map(|raw| {
            let host = raw.trim().to_ascii_lowercase();
            if host.is_empty() {
                return None;
            }
            // 有些线路文件把端口写在地址里（`host:51820`）；服务器记录里只有 host。
            match host.rsplit_once(':') {
                Some((head, port))
                    if !head.is_empty()
                        && !port.is_empty()
                        && port.chars().all(|c| c.is_ascii_digit()) =>
                {
                    Some(head.to_string())
                }
                _ => Some(host),
            }
        })
        .collect()
}

/// 这台机器上所有线路的 `(线路 id, 服务器地址)` 对。
///
/// **归属判据只有这一份**：服务器一览（`LineIds` / 邀请入口）与邀请命令
/// （`server_for_line`）都从这里取，避免同一个问题出现两个结论。
pub fn line_hosts(root: &std::path::Path) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join("lines")) else {
        return pairs;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(line_id) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(value) = serde_json::from_str::<Value>(&text) else { continue };
        for host in line_addresses(&value) {
            pairs.push((line_id.to_string(), host));
        }
    }
    pairs
}

pub fn server_for_line<'a>(
    root: &std::path::Path,
    line_id: &str,
    records: &'a [crate::serverstore::ServerRecord],
) -> Option<&'a crate::serverstore::ServerRecord> {
    let hosts: Vec<String> = line_hosts(root)
        .into_iter()
        .filter(|(id, _)| id == line_id)
        .map(|(_, host)| host)
        .collect();
    if hosts.is_empty() {
        return None;
    }
    records
        .iter()
        .find(|record| hosts.contains(&record.host.trim().to_ascii_lowercase()))
}

/// 本机记录「这台服务器是谁签的」的位置。**按服务器记**，不按线路：一台服务器上的
/// 多条线路共用同一个管理身份，分线路存会让「同一台机器有两个身份」成为可能。
pub fn identity_path(root: &std::path::Path, server_id: &str) -> std::path::PathBuf {
    root.join("invites").join(format!("{server_id}.json"))
}

pub fn load_identity(path: &std::path::Path) -> Option<Identity> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let identity = Identity {
        endpoint: text_of(&value, "Endpoint"),
        tls_sha256: text_of(&value, "TlsSha256"),
        management_fingerprint: text_of(&value, "ManagementFingerprint"),
        node_id: text_of(&value, "NodeId"),
        server_public_key: text_of(&value, "ServerPublicKey"),
        // 从记录里读回来的身份不代表本次有上传动作——`script` 是「这一次
        // 开启接收服务做了什么」的结论，不落盘（`save_identity` 不写它）。
        // CLI 只在 `install` 的返回值上打印这句，不会读这条路径。
        script: PushOutcome::UpToDate,
    };
    if identity.management_fingerprint.is_empty() || identity.tls_sha256.is_empty() {
        return None;
    }
    Some(identity)
}

pub fn save_identity(path: &std::path::Path, identity: &Identity) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("建不了目录：{error}"))?;
    }
    let body = serde_json::json!({
        "SchemaVersion": 1,
        "Endpoint": identity.endpoint,
        "TlsSha256": identity.tls_sha256,
        "ManagementFingerprint": identity.management_fingerprint,
        "NodeId": identity.node_id,
        "ServerPublicKey": identity.server_public_key,
    });
    std::fs::write(path, format!("{body}\n"))
        .map_err(|error| format!("写不了 {}：{error}", path.display()))
}

/// 单引号包裹一个 shell 实参。脚本路径与接口名都是固定的 ASCII，但设备名是用户输入，
/// 必须能安全穿过 shell——**只有**这一条路，不做「看着像特殊字符才转义」的判断。
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn explain(error: ssh::Error) -> Fault {
    match error {
        ssh::Error::HostKeyUnknown { .. } => Fault::new(
            crate::exit::ENVIRONMENT,
            "这台服务器还没有确认身份，请先在「自己搭服务器」里核对一次主机指纹。",
        ),
        ssh::Error::HostKeyMismatch { .. } => Fault::new(
            crate::exit::CONFLICT,
            "服务器身份与上次记录不一致，已中止：请确认这台机器没有被换掉。",
        ),
        ssh::Error::Auth => Fault::new(crate::exit::ENVIRONMENT, "服务器拒绝了登录凭据。"),
        ssh::Error::Connect(text) => Fault::new(crate::exit::NETWORK, format!("连不上服务器：{text}")),
        ssh::Error::Timeout => Fault::new(crate::exit::NETWORK, "连接服务器超时，可以重试。"),
        ssh::Error::Command(text) => Fault::new(crate::exit::INTERNAL, format!("服务器上的命令没有跑完：{text}")),
    }
}

fn run<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    command: &str,
) -> Result<ssh::Output, Fault> {
    // 显式标注：`impl Into<Auth>` 的入参再 `.into()` 时，`Auth: Into<Auth>` 的
    // 恒等实现会让编译器无法唯一确定目标类型（E0283）。
    let auth: ssh::Auth<'a> = auth.into();
    // An independently fenced server must not be reactivated by this old
    // client, including during digest probe, auto-upload, create, cancel,
    // authorize-request or service restart. The guard runs in the same SSH
    // command BEFORE any old side effect, with no extra round trip.
    let protected = crate::legacy_writer_fence::guard_ssh_command(command);
    let result = ssh::exec(target, auth, expected, &protected, TIMEOUT)
        .map_err(explain)?;
    if crate::legacy_writer_fence::remote_says_fenced(result.code, &result.stderr) {
        return Err(Fault::new(crate::exit::CONFLICT,
            "该服务器已进入旧配对写入禁用状态，禁止旧客户端重新上传或启动旧接收器；请使用经过验收的管理路径。"));
    }
    Ok(result)
}

/// 上传脚本。先比摘要：同一版本的脚本已经在服务器上时不再传，
/// 让「只是再生成一张邀请码」不必每次都搬运 20 KB。
fn push<'a>(target: &ssh::Target, auth: impl Into<ssh::Auth<'a>>, expected: Option<&str>) -> Result<PushOutcome, Fault> {
    // `Auth: Copy`：下面要按摘要探测两三次，转换一次就够（不转换时每次转发都会
    // 消费掉 `impl Into<Auth>`，第二次就没有东西可用了）。
    // 显式标注的理由同 `run`：不标会撞上 `Auth: Into<Auth>` 的恒等实现（E0283）。
    let auth: ssh::Auth<'a> = auth.into();
    use sha2::Digest;
    let digest = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(SCRIPT.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let probe = format!("cat {REMOTE_DIGEST} 2>/dev/null");
    if let Ok(output) = run(target, auth, expected, &probe) {
        if output.code == 0 && output.stdout.trim() == digest {
            return Ok(PushOutcome::UpToDate);
        }
    }

    let probe = format!("command -v python3 >/dev/null 2>&1 && echo yes");
    let output = run(target, auth, expected, &probe)?;
    if output.stdout.trim() != "yes" {
        return Err(Fault::new(
            crate::exit::ENVIRONMENT,
            "服务器上没有 python3：邀请服务需要它（只需要标准库）。",
        ));
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(SCRIPT.as_bytes());
    let prepare = format!(
        "mkdir -p {dir} && chmod 700 {dir} && : > {dir}/tc-pair.py.b64",
        dir = REMOTE_DIR
    );
    run(target, auth, expected, &prepare)?;
    for chunk in encoded.as_bytes().chunks(UPLOAD_CHUNK) {
        let text = std::str::from_utf8(chunk).map_err(|_| Fault::new(crate::exit::INTERNAL, "上传分片编码失败。"))?;
        let append = format!("printf '%s' {} >> {dir}/tc-pair.py.b64", quote(text), dir = REMOTE_DIR);
        let output = run(target, auth, expected, &append)?;
        if output.code != 0 {
            return Err(Fault::new(
                crate::exit::NETWORK,
                format!("上传邀请服务脚本被中断（{}）。", output.stderr.trim()),
            ));
        }
    }
    let finish = format!(
        "base64 -d {dir}/tc-pair.py.b64 > {REMOTE_SCRIPT} && rm -f {dir}/tc-pair.py.b64 \
         && chmod 600 {REMOTE_SCRIPT} && printf '%s' '{digest}' > {REMOTE_DIGEST} \
         && python3 -I -c 'import sys' && echo TC_PUSH_OK",
        dir = REMOTE_DIR,
        digest = digest
    );
    let output = run(target, auth, expected, &finish)?;
    if !output.stdout.contains("TC_PUSH_OK") {
        return Err(Fault::new(
            crate::exit::CONFIG,
            format!("邀请服务脚本没能在服务器上落地：{}", output.stderr.trim()),
        ));
    }
    Ok(PushOutcome::Pushed)
}

/// 调用服务器脚本的一个子命令，返回 `ok:true` 的那一层 JSON。
///
/// 脚本的失败约定是 `{"ok":false,"code":"…","message":"…"}` 且退出码 1——
/// 这里把两种失败（脚本说不行 / 脚本没跑起来）分开报，否则「没装 python3」
/// 会被念成「邀请码无效」。
fn call<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    action: &str,
    args: &[(&str, String)],
) -> Result<Value, Fault> {
    let auth = auth.into();
    let mut command = format!("python3 -I {REMOTE_SCRIPT} {action}");
    for (flag, value) in args {
        command.push(' ');
        command.push_str(flag);
        command.push(' ');
        command.push_str(&quote(value));
    }
    let output = run(target, auth, expected, &command)?;
    let last = output
        .stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or_else(|| {
            Fault::new(
                crate::exit::ENVIRONMENT,
                format!(
                    "邀请服务没有返回结果（退出码 {}）：{}",
                    output.code,
                    output.stderr.trim().chars().take(200).collect::<String>()
                ),
            )
        })?;
    let value: Value = serde_json::from_str(last.trim())
        .map_err(|_| Fault::new(crate::exit::INTERNAL, "邀请服务的回包不是合法 JSON。"))?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        let code = value.get("code").and_then(Value::as_str).unwrap_or("Internal");
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("邀请服务没有说明原因。");
        // 服务器侧的错误码到退出码：能靠改配置解决的归 CONFIG，其余按环境/内部。
        let exit = match code {
            "InviteNotFound" | "InvalidLifetime" | "InvalidDeviceName" | "InvalidEndpoint"
            | "InvalidClientKey" | "NotInitialized" | "ServerKeyMissing"
            // 离线批准：申请本身不对（编码/签名/摘要/绑定）要人去改资料，不是服务器坏了。
            | "InvalidRequest" | "InvalidPairRequest" | "PairingMismatch" | "InviteMismatch"
            | "InviteCancelled" | "InviteExpired" => crate::exit::CONFIG,
            "InviteConsumed" => crate::exit::CONFLICT,
            "MissingOpenSSL" | "SigningOperationFailed" => crate::exit::ENVIRONMENT,
            _ => crate::exit::INTERNAL,
        };
        return Err(Fault::new(exit, format!("{message}（{code}）")));
    }
    Ok(value)
}

fn text_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn identity_of(value: &Value, script: PushOutcome) -> Identity {
    Identity {
        endpoint: text_of(value, "endpoint"),
        tls_sha256: text_of(value, "tlsSha256"),
        management_fingerprint: text_of(value, "managementFingerprint"),
        node_id: text_of(value, "nodeId"),
        server_public_key: text_of(value, "serverPublicKey"),
        script,
    }
}

/// 装好（或确认已经装好）管理身份与 TLS 证书。**幂等**：私钥与证书存在就不重新造——
/// 重造会让所有已发出的邀请码失效，而用户看到的只是「邀请码突然不能用了」。
pub fn install<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    interface: &str,
    endpoint: &str,
) -> Result<Identity, Fault> {
    let auth = auth.into();
    let script = push(target, auth, expected)?;
    let value = call(
        target,
        auth,
        expected,
        "init",
        &[("--interface", interface.to_string()), ("--endpoint", endpoint.to_string())],
    )?;
    let identity = identity_of(&value, script);
    if identity.management_fingerprint.is_empty() || identity.tls_sha256.is_empty() {
        return Err(Fault::new(
            crate::exit::INTERNAL,
            "邀请服务初始化完成，但没有返回管理身份指纹。",
        ));
    }
    enable_service(target, auth, expected)?;
    Ok(identity)
}

/// 写单元文件并（重新）启动接收服务。
///
/// `restart` 而不是 `start`：脚本升级后旧进程还在内存里跑旧代码，
/// 而 `start` 对已经在跑的服务是空操作——那会变成「改了没生效」。
fn enable_service<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
) -> Result<(), Fault> {
    let auth = auth.into();
    let unit = base64::engine::general_purpose::STANDARD.encode(UNIT.as_bytes());
    let command = format!(
        "printf '%s' '{unit}' | base64 -d > /etc/systemd/system/{SERVICE} \
         && systemctl daemon-reload && systemctl enable {SERVICE} >/dev/null 2>&1 \
         && systemctl restart {SERVICE} && sleep 1 && systemctl is-active {SERVICE}",
        unit = unit,
        SERVICE = SERVICE
    );
    let output = run(target, auth, expected, &command)?;
    if output.stdout.trim() != "active" {
        // 服务起不来时把最近几行日志带回来：用户能自己看到「端口被占」这类原因，
        // 而不是只收到一句「初始化失败」。
        let logs = run(
            target,
            auth,
            expected,
            &format!("journalctl -u {SERVICE} -n 6 --no-pager 2>&1 | tail -6"),
        )
        .map(|out| out.stdout.trim().to_string())
        .unwrap_or_default();
        return Err(Fault::new(
            crate::exit::ENVIRONMENT,
            format!(
                "邀请接收服务没能启动（当前状态：{}）。{}",
                output.stdout.trim(),
                logs.replace('\n', " / ")
            ),
        ));
    }
    Ok(())
}

/// 签发一张邀请。`lifetime` 是秒；`device` 是新电脑的默认名字（对方可以改）。
///
/// 回包里的邀请码**一定**再过一遍 `pairing::parse_code`：这一段是本机第一次
/// 以「接收方视角」看自己刚签出来的东西，能在这里挡住协议漂移。
pub fn create<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    lifetime: i64,
    device: &str,
    identity: &Identity,
    now_unix: i64,
) -> Result<Issued, Fault> {
    let auth = auth.into();
    push(target, auth, expected)?;
    let value = call(
        target,
        auth,
        expected,
        "create",
        &[
            ("--lifetime", lifetime.to_string()),
            ("--device", device.to_string()),
        ],
    )?;
    let code = text_of(&value, "code");
    let invite = pairing::parse_code(&code, false, now_unix).map_err(|error| {
        Fault::new(
            crate::exit::INTERNAL,
            format!("服务器签出的邀请码在本机校验不通过：{}", error.message),
        )
    })?;
    // 指纹与入口必须和安装时记下的一致：变了一个字节就说明这台服务器换过身份，
    // 而此时用户手上还拿着旧邀请码的假设。
    if invite.management_fingerprint != identity.management_fingerprint {
        return Err(Fault::new(
            crate::exit::CONFLICT,
            "服务器的管理身份与安装时记录的不一致，请确认这台服务器没有被重装。",
        ));
    }
    if invite.tls_sha256 != identity.tls_sha256 {
        return Err(Fault::new(
            crate::exit::CONFLICT,
            "服务器的证书与安装时记录的不一致，请确认这台服务器没有被重装。",
        ));
    }
    let invite_jws = text_of(&value, "invite");
    if invite_jws.is_empty() {
        return Err(Fault::new(
            crate::exit::ENVIRONMENT,
            "服务器没有返回签名的邀请本身，离线交接无法进行；请重新执行一次「开启接收服务」。",
        ));
    }
    Ok(Issued {
        invite,
        invite_jws,
        expires_at_utc: text_of(&value, "expiresAtUtc"),
        device_name: text_of(&value, "deviceName"),
    })
}

/// 查一张邀请的状态（`Open` / `Consumed` / `Cancelled` / `Expired`）。
pub fn status<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    invite_id: &str,
) -> Result<Value, Fault> {
    let auth = auth.into();
    call(target, auth, expected, "status", &[("--id", invite_id.to_string())])
}

/// 作废一张邀请。已经被用掉的邀请不能作废（那要撤设备，是另一条路）。
pub fn cancel<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    invite_id: &str,
) -> Result<Value, Fault> {
    let auth = auth.into();
    call(target, auth, expected, "cancel", &[("--id", invite_id.to_string())])
}

/// 离线批准：把新电脑交回的签名申请交给服务器，换回加密授权。
///
/// 与在线加入共用服务器上的同一套授权逻辑（`authorize_invite`），差别只在
/// 「谁证明有权批准」：这里是 SSH 登录，不是邀请码里的令牌。**先推脚本**——
/// 旧服务器没有这个子命令，不推会报「不认识的动作」。
pub fn authorize_request<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    request: &str,
) -> Result<Value, Fault> {
    let auth = auth.into();
    push(target, auth, expected)?;
    call(
        target,
        auth,
        expected,
        "authorize-request",
        &[("--request", request.to_string())],
    )
}

/// 删除一台**已不在隧道上**的设备的名称记录（C1「设备记录删除」）。
///
/// 只清服务器上的 `device-names.json`；peer 由撤销负责，邀请审计保留。
/// 先推脚本：旧服务器没有 `forget-device` 子命令。
pub fn forget_device<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    public_key: &str,
) -> Result<Value, Fault> {
    let auth = auth.into();
    push(target, auth, expected)?;
    call(
        target,
        auth,
        expected,
        "forget-device",
        &[("--key", public_key.to_string())],
    )
}

/// 服务器上记着的设备显示名（公钥 → {Name, UpdatedAtUtc}）。
///
/// 只读、失败不致命：设备页可以没有名字（部署创建的设备本来就没有），
/// 不能因为名字读不出来就连设备列表一起不给。**先推一次脚本**：旧服务器上的
/// 脚本没有这个子命令，不推就会永远「改名不可用」——r66 首轮真机就是这么暴露的。
pub fn device_names<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
) -> Result<Value, Fault> {
    let auth = auth.into();
    push(target, auth, expected)?;
    call(target, auth, expected, "device-names", &[])
}

/// 改一台设备的显示名。按公钥定位，只写服务器上的 `device-names.json`。
///
/// 改名是写操作，先推一次脚本：旧版脚本没有这个子命令，不推就会报「不认识的动作」。
pub fn rename_device<'a>(
    target: &ssh::Target,
    auth: impl Into<ssh::Auth<'a>>,
    expected: Option<&str>,
    key: &str,
    name: &str,
) -> Result<Value, Fault> {
    let auth = auth.into();
    push(target, auth, expected)?;
    call(
        target,
        auth,
        expected,
        "rename-device",
        &[
            ("--key", key.to_string()),
            ("--name", name.to_string()),
        ],
    )
}

#[cfg(test)]
mod line_hosts_tests {
    use super::*;
    use crate::serverstore::ServerRecord;

    fn record(id: &str, host: &str) -> ServerRecord {
        ServerRecord {
            id: id.to_string(),
            name: format!("root@{host}"),
            host: host.to_string(),
            port: 22,
            user: "root".to_string(),
            fingerprint: "SHA256:abcdefghijkl".to_string(),
            created_at: "2026-11-10T00:00:00Z".to_string(),
            updated_at: "2026-11-10T00:00:00Z".to_string(),
        }
    }

    fn write_line(root: &std::path::Path, id: &str, body: Value) {
        let dir = root.join("lines");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.json")), body.to_string()).unwrap();
    }

    /// 邀请那条路与服务器一览共用同一份归属判据：标准线路的地址在端点里，也必须认。
    #[test]
    fn a_wireguard_line_finds_its_server_through_the_endpoint() {
        let root = std::env::temp_dir().join(format!("tc-line-hosts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write_line(
            &root,
            "L-udp",
            serde_json::json!({
                "endpoints": [{
                    "type": "wireguard",
                    "peers": [{"address": "192.0.2.10", "port": 51820}]
                }],
                "outbounds": [{"type": "selector", "tag": "trade-exit"}]
            }),
        );
        let records = vec![record("S1", "192.0.2.10")];

        let found = server_for_line(&root, "L-udp", &records).expect("标准线路必须找到它的服务器");
        assert_eq!(found.id, "S1");

        // 反过来：不存在的线路不能瞎认一台服务器。
        assert!(server_for_line(&root, "L-none", &records).is_none());

        let hosts = line_hosts(&root);
        assert_eq!(hosts, vec![("L-udp".to_string(), "192.0.2.10".to_string())]);

        let _ = std::fs::remove_dir_all(&root);
    }
}

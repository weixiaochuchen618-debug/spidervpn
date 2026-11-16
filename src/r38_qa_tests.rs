//! R38「新电脑用邀请码真正加入」的**独立复核**用例（QA 编写，只读产品逻辑、不改它）。
//!
//! 这一组用例盯的是一个具体的缺口：工程师的自测（`tests/r38_consume.py`）两边都是
//! Python——**自己签申请、自己解 JWE**。它能证明「Python 客户端与 Python 服务器」同源，
//! 却证明不了「现场那份 Rust 客户端能不能吃下这份授权」。而后者才是用户点「加入」时
//! 真正跑的东西。
//!
//! 所以这里全部走**真链路**：
//!
//! * 服务器是 `assets/tc-pair.py`（磁盘上那一份，不是 `include_str!` 的副本）真的
//!   `serve` 起来的进程，TLS 1.2 + 证书指纹固定都是客户端亲自校验的；
//! * 客户端是本 crate 的 `pairing::join::run`，用真 RSA/真 JWS/真 JWE，不抄一份协议；
//! * WireGuard 侧用四个覆盖点接假 `wg`／`wg-quick`（这台机器上没有 WireGuard）。
//!
//! **为什么入口用局域网地址而不是 127.0.0.1**：客户端对邀请里的 `PublicEndpoint`
//! 有一条硬规则——回环地址一律拒绝（`pairing::invite::valid_endpoint`，与旧版对齐）。
//! 那是设计使然，不是缺陷，所以本机复现只能在「非回环的本机地址」上跑：服务器绑
//! `0.0.0.0`，邀请码里写本机局域网 IP。生产环境的服务器本来就有公网地址，不涉及这条。
//!
//! **两种「服务器回旧词」的模拟**：把生产脚本复制一份到临时目录再改那一处，用来复现
//! r37 的服务器（`Open`）与「表外的词」。生产脚本本身一个字节都不动（`with_script`
//! 里有锚点断言：锚点找不到了说明脚本漂移，用例直接红）。

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::pairing::{self, join, Invite};

// ---------------------------------------------------------------------------
// 夹具：一套隔离的现场（pair 数据根 + 假 WireGuard + 真 python 服务）
// ---------------------------------------------------------------------------

const INTERFACE: &str = "tc00000000";

/// 已经接入的另一台设备：地址分配必须跳过 `10.66.0.5`。内容与工程师自测的夹具一致，
/// 但这一份是**这里自己写死的**——不 import 别人的常量。
const BASE_CONF: &str = "[Interface]\n\
Address = 10.66.0.1/24\n\
ListenPort = 51820\n\
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
\n\
[Peer]\n\
# 已经接入的另一台设备：地址分配必须跳过它。\n\
PublicKey = kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK/kK=\n\
AllowedIPs = 10.66.0.5/32\n";

const FAKE_WG: &str = r#"
import json, os, sys
ROOT = os.environ["TC_FAKE_WG_ROOT"]
args = sys.argv[1:]
with open(os.path.join(ROOT, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": "wg", "args": args}) + "\n")
if args[:1] == ["pubkey"]:
    with open(os.path.join(ROOT, "server.pub"), encoding="ascii") as stream:
        sys.stdout.write(stream.read().strip())
    sys.exit(0)
if args[:1] == ["syncconf"]:
    source, target = args[2], os.path.join(ROOT, "synced.conf")
    with open(source, encoding="utf-8") as source_stream:
        with open(target, "w", encoding="utf-8") as target_stream:
            target_stream.write(source_stream.read())
    sys.exit(0)
sys.stderr.write("fake wg: unsupported\n")
sys.exit(2)
"#;

const FAKE_WGQUICK: &str = r#"
import json, os, sys
ROOT = os.environ["TC_FAKE_WG_ROOT"]
args = sys.argv[1:]
with open(os.path.join(ROOT, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": "wg-quick", "args": args}) + "\n")
if args[:1] == ["strip"]:
    with open(os.path.join(ROOT, args[1] + ".conf"), encoding="utf-8") as stream:
        sys.stdout.write(stream.read())
    sys.exit(0)
sys.stderr.write("fake wg-quick: unsupported\n")
sys.exit(2)
"#;

/// 找一个能用的解释器。与 `pairhost_tests` 同一套顺序（`TC_PYTHON` 优先）。
fn interpreter() -> Option<String> {
    if let Ok(value) = std::env::var("TC_PYTHON") {
        let trimmed = value.trim();
        if !trimmed.is_empty() && Path::new(trimmed).exists() {
            return Some(trimmed.to_string());
        }
    }
    for name in ["python3", "python"] {
        let ok = Command::new(name)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if ok {
            return Some(name.to_string());
        }
    }
    None
}

/// 本机的**非回环** IPv4：邀请里不能写 127.0.0.1（客户端硬拒回环入口）。
/// 只是问内核「去默认路由会从哪个地址出去」，不发包。
fn lan_ipv4() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip.to_string()),
        _ => None,
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("占端口");
    listener.local_addr().expect("取端口").port()
}

// ---------------------------------------------------------------------------
// 并发闸：只限制**本文件**的重用例，不改任何别人用例的超时预算
// ---------------------------------------------------------------------------

/// 本文件每条用例都要起一个 python 服务、生成 RSA 密钥（debug 下每次几秒、纯 CPU），
/// 有的还要真起 sing-box。11 条一起上会把 8 核打满，实测会把本机另外两条**时间敏感**
/// 的既有用例（`ipc::tests::ping_answers_while_a_long_command_is_running` /
/// `pipe_waits_for_the_ui_transaction_gate_but_ping_still_answers`，它们给命名管道
/// 就绪只留 2 秒）压到超时——那两条单独跑 1.5 秒全绿。
///
/// 所以这里给自己加一道闸：最多两条重用例同时在跑。这不是「让测试变慢」，是让
/// **别人**的时间预算重新变得有意义。
static HEAVY_RUNNING: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static HEAVY_FREED: std::sync::Condvar = std::sync::Condvar::new();
const HEAVY_LIMIT: usize = 2;

struct HeavyPermit;

impl Drop for HeavyPermit {
    fn drop(&mut self) {
        let mut running = HEAVY_RUNNING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *running = running.saturating_sub(1);
        drop(running);
        HEAVY_FREED.notify_one();
    }
}

fn heavy_permit() -> HeavyPermit {
    let mut running = HEAVY_RUNNING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    while *running >= HEAVY_LIMIT {
        running = HEAVY_FREED
            .wait(running)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    *running += 1;
    HeavyPermit
}

fn now_unix() -> i64 {
    crate::model::now_epoch_secs_u64() as i64
}

struct Site {
    python: String,
    root: PathBuf,
    pair_root: PathBuf,
    wg_root: PathBuf,
    tools: PathBuf,
    script: PathBuf,
    clients: PathBuf,
    host: String,
    port: u16,
    server: Option<Child>,
    server_log: PathBuf,
}

impl Site {
    fn new(tag: &str) -> Option<Site> {
        Site::with_script(tag, None)
    }

    /// `patch` = 复制一份脚本并把这一处替换掉，用来复现旧版服务器/表外的状态词。
    fn with_script(tag: &str, patch: Option<(&str, &str)>) -> Option<Site> {
        let python = interpreter()?;
        let host = lan_ipv4()?;
        let root = std::env::temp_dir().join(format!("tcrs-qa38-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for name in ["pair", "wireguard", "tools", "clients"] {
            std::fs::create_dir_all(root.join(name)).expect("建临时目录");
        }
        let pair_root = root.join("pair");
        let wg_root = root.join("wireguard");
        let tools = root.join("tools");
        let clients = root.join("clients");

        std::fs::write(tools.join("fake_wg.py"), FAKE_WG).unwrap();
        std::fs::write(tools.join("fake_wgquick.py"), FAKE_WGQUICK).unwrap();
        std::fs::write(wg_root.join("server.pub"), server_public_key()).unwrap();
        std::fs::write(
            wg_root.join(format!("{INTERFACE}.key")),
            b64std(&(1u8..=32).collect::<Vec<u8>>()),
        )
        .unwrap();
        std::fs::write(wg_root.join(format!("{INTERFACE}.conf")), BASE_CONF).unwrap();

        // 服务器脚本：生产脚本原样拷一份；需要模拟旧版时在**副本**上改一处。
        let original = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join("tc-pair.py");
        let text = std::fs::read_to_string(&original).expect("读不到生产脚本 assets/tc-pair.py");
        let text = match patch {
            None => text,
            Some((from, to)) => {
                assert!(
                    text.contains(from),
                    "补丁锚点在资产脚本里找不到了（脚本已漂移，请复查这条用例）：{from}"
                );
                text.replace(from, to)
            }
        };
        let script = root.join("tc-pair.py");
        std::fs::write(&script, text).unwrap();

        let port = free_port();
        let server_log = root.join("server.log");
        let site = Site {
            python,
            root,
            pair_root,
            wg_root,
            tools,
            script,
            clients,
            host,
            port,
            server: None,
            server_log,
        };
        site.require_no_spaces();
        Some(site)
    }

    /// `command_of` 按空格拆 argv：覆盖点里带空格会被拆错，这里提前拦住。
    fn require_no_spaces(&self) {
        let tools = self.tools.to_string_lossy().into_owned();
        let wg_root = self.wg_root.to_string_lossy().into_owned();
        let root = self.root.to_string_lossy().into_owned();
        for path in [&self.python, &tools, &wg_root, &root] {
            assert!(!path.contains(' '), "测试现场路径里不能有空格：{path}");
        }
    }

    fn envs(&self) -> Vec<(String, String)> {
        vec![
            ("TC_PAIR_ROOT".into(), self.pair_root.to_string_lossy().into_owned()),
            ("TC_PAIR_WG_ROOT".into(), self.wg_root.to_string_lossy().into_owned()),
            (
                "TC_PAIR_WG_BIN".into(),
                format!("{} {}", self.python, self.tools.join("fake_wg.py").display()),
            ),
            (
                "TC_PAIR_WGQUICK_BIN".into(),
                format!("{} {}", self.python, self.tools.join("fake_wgquick.py").display()),
            ),
            // 故意指向不存在的 ip 命令：让「退回配置里的 Address」这条兜底也跑到。
            ("TC_PAIR_IP_BIN".into(), self.tools.join("no-such-ip").display().to_string()),
            ("TC_FAKE_WG_ROOT".into(), self.wg_root.to_string_lossy().into_owned()),
        ]
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.python);
        command.arg(&self.script);
        // Windows 的管道 stdout 默认按本地代码页（GBK）编码：假 wg 把带中文注释的
        // 配置写回去时，另一个假 wg 按 UTF-8 读就会炸。测试不该随调用者 locale 变红。
        command.env("PYTHONUTF8", "1");
        for (key, value) in self.envs() {
            command.env(key, value);
        }
        command
    }

    fn run(&self, args: &[&str]) -> Value {
        let output = self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|error| panic!("跑不起来 python（{}）：{error}", self.python));
        assert!(
            output.status.success(),
            "tc-pair {args:?} 失败：stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "tc-pair {args:?} 的输出不是 JSON：{error} / {}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
    }

    /// 允许失败的一次调用：离线批准要验「劣质申请必须被拒」。
    fn attempt(&self, args: &[&str]) -> (bool, Value) {
        let output = self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|error| panic!("跑不起来 python（{}）：{error}", self.python));
        let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output.status.success(), value)
    }

    fn init(&self) -> Value {
        // 端口必须与码里的一致：客户端连的是邀请里的 p，服务器监听的是 --port。
        let endpoint = format!("{}:{}", self.host, self.port);
        self.run(&["init", "--interface", INTERFACE, "--endpoint", &endpoint])
    }

    fn create(&self, device: &str) -> Value {
        self.run(&["create", "--lifetime", "1800", "--device", device])
    }

    fn cancel(&self, invite_id: &str) -> Value {
        self.run(&["cancel", "--id", invite_id])
    }

    fn start(&mut self, code: &str) {
        let log = std::fs::File::create(&self.server_log).expect("建服务日志");
        let child = self
            .command()
            .args(["serve", "--port", &self.port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("起不来邀请服务");
        self.server = Some(child);

        // 只等端口通不够：监听套接字在 TLS 包装之前就已经在 listen。
        // 用客户端自己的 `http::get` 探活，顺带把「证书指纹对不对」也验掉了。
        let invite = pairing::parse_code(code, true, now_unix()).expect("邀请码本机解析不了");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if pairing::http::get(&invite, Duration::from_secs(2)).is_ok() {
                return;
            }
            if Instant::now() >= deadline {
                let log = std::fs::read_to_string(&self.server_log).unwrap_or_default();
                panic!("邀请服务没有在 20 秒内可用。服务日志：\n{log}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // ---- 现场文件

    fn conf(&self) -> String {
        std::fs::read_to_string(self.wg_root.join(format!("{INTERFACE}.conf"))).expect("读 wg 配置")
    }

    fn synced(&self) -> String {
        std::fs::read_to_string(self.wg_root.join("synced.conf")).unwrap_or_default()
    }

    fn calls(&self) -> Vec<Value> {
        std::fs::read_to_string(self.wg_root.join("calls.jsonl"))
            .map(|text| {
                text.lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| serde_json::from_str::<Value>(line).expect("调用记录不是 JSON"))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn invites(&self) -> Value {
        let text = std::fs::read_to_string(self.pair_root.join("invites.json"))
            .expect("服务器没写 invites.json");
        serde_json::from_str(&text).expect("invites.json 不是 JSON")
    }

    fn invite_record(&self, invite_id: &str) -> Value {
        self.invites()["Invites"][invite_id].clone()
    }

    fn client_root(&self, tag: &str) -> PathBuf {
        let root = self.clients.join(tag);
        std::fs::create_dir_all(&root).unwrap();
        root
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        if let Some(mut child) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn b64std(raw: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// 与服务器假 `wg pubkey` 返回的一致（32 字节 0x00..0x1f 的 base64）。
fn server_public_key() -> String {
    b64std(&(0u8..32).collect::<Vec<u8>>())
}

// ---------------------------------------------------------------------------
// 真引擎验收（与 `pairing` 内既有用例同一套两步法：先 check，再真起一次）
// ---------------------------------------------------------------------------

fn engine_binary() -> Option<String> {
    if let Ok(value) = std::env::var("SPIDERVPN_ENGINE_BIN") {
        if Path::new(&value).exists() {
            return Some(value);
        }
    }
    let vendor = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vendor")
        .join("sing-box.exe");
    if vendor.exists() {
        return Some(vendor.to_string_lossy().into_owned());
    }
    None
}

/// 主端口与自检端口（+3）都空着才算可用：`line::build` 会把 `端口+3` 烤成自检入站。
fn free_port_pair() -> u16 {
    for port in 20_000u16..30_000 {
        let Ok(main) = std::net::TcpListener::bind(("127.0.0.1", port)) else { continue };
        let Ok(probe) = std::net::TcpListener::bind(("127.0.0.1", port + 3)) else { continue };
        drop((main, probe));
        return port;
    }
    panic!("20000–30000 里找不到一对空闲端口");
}

struct EngineGuard(Child);

impl Drop for EngineGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 一份**由真客户端生成的** `client.conf` → 线路文件 → 真引擎 `check` + 真起一次。
///
/// 字段级断言全过、引擎仍然拒绝配置的情况是存在的（类型名、必填项、DNS 引用由引擎
/// 自己的 schema 决定），只有真引擎能提前发现。这里不碰网络：只到「起得来、在监听」。
fn engine_accepts_and_listens(engine: &str, conf: &pairing::line::ClientConf) {
    let port = free_port_pair();
    let body = pairing::line::build(
        conf,
        None,
        port,
        crate::config::Mode::Proxy,
        &crate::config::SplitConfig::default(),
        &crate::config::AgentsConfig::default(),
    )
    .expect("真客户端生成的隧道参数必须能变成线路文件");

    let root = std::env::temp_dir().join(format!("tcrs-qa38-engine-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&root);
    let file = root.join("line.json");
    std::fs::write(&file, &body).expect("写线路文件");

    let check = Command::new(engine)
        .args(["check", "-c"])
        .arg(&file)
        .stdin(Stdio::null())
        .output()
        .expect("跑不起来引擎");
    assert!(
        check.status.success(),
        "引擎拒绝了真客户端生成的线路文件：{}\n{}",
        String::from_utf8_lossy(&check.stderr),
        body
    );

    let child = Command::new(engine)
        .args(["run", "-c"])
        .arg(&file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("引擎起不来");
    let mut guard = EngineGuard(child);
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            let mut message = String::new();
            if let Some(mut pipe) = guard.0.stderr.take() {
                use std::io::Read;
                let _ = pipe.read_to_string(&mut message);
            }
            panic!("引擎提前退出（{status}）：{message}\n{body}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("引擎没有在 15 秒内监听 127.0.0.1:{port}\n{body}");
}

// ---------------------------------------------------------------------------
// 1. 主链路：真 Rust 客户端 × 真 python 服务器
// ---------------------------------------------------------------------------

#[test]
fn r38_qa_real_client_joins_through_the_real_server() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("join") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    // 流程用例用小密钥（3072 位在 debug 下太慢）；规格另有专门用例钉住。
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let created = site.create("测试设备");
    let code = created["code"].as_str().expect("没有码").to_string();
    let invite_id = created["inviteId"].as_str().expect("没有邀请 id").to_string();
    site.start(&code);

    let root = site.client_root("A");
    let now = now_unix();
    let invite = pairing::parse_code(&code, true, now).expect("邀请码本机解析不了");
    // 界面/IPC 传的是 `allow_loopback=false`（`src/ipc.rs`）。真服务器发出来的码不该
    // 因为这道闸被挡住——顺手把它钉住，免得以后改成本机回环入口再加测试。
    pairing::parse_code(&code, false, now)
        .expect("真服务器发的码必须能过界面那道「不许回环」的闸");
    let outcome = join::run(&root, &code, "测试设备", true, now, Duration::from_secs(15))
        .unwrap_or_else(|error| {
            panic!("真客户端吃不下真服务器的授权：{} / {}", error.code, error.message)
        });

    // ---- 结果本身
    assert_eq!(outcome.state, "Completed", "只有生成出可用线路才叫完成");
    assert!(!outcome.resumed, "首次加入不该是「重试」");
    assert_eq!(outcome.invite_id, invite_id);
    // 这条断言**曾经是重言式**：`authorization["RequestId"] == outcome.device_id`，
    // 而 `outcome.device_id` 装的就是 `request_id_of(&enrollment)`——两边同源，
    // 永远不会红，却写着「设备 id 必须与授权一致」。等于没验。
    //
    // 现在改成真判据：授权的 `DeviceId` 必须等于**登记里那份申请**的 `DeviceId`，
    // 而且必须**不等于** `RequestId`（相等就说明又拿同一个值自比了）。
    // 后半句是这条断言的自检——没有它，换个写法还能继续空转。
    let enrollment = crate::pairstore::find_by_invite(&root, &invite_id)
        .expect("查登记不该失败")
        .expect("刚加入完必须有登记");
    let device_id = enrollment.client_request["DeviceId"]
        .as_str()
        .expect("登记里没有 DeviceId");
    assert_eq!(
        outcome.authorization["DeviceId"].as_str(),
        Some(device_id),
        "授权必须绑在本机这份申请的 DeviceId 上"
    );
    assert_ne!(
        outcome.authorization["DeviceId"].as_str(),
        outcome.authorization["RequestId"].as_str(),
        "DeviceId 与 RequestId 是两个不同的 id：相等说明断言又变成同源自比了"
    );

    // ---- 客户端配置能被本机解析器吃下（渲染↔解析是同一套契约）
    let config_text = std::fs::read_to_string(&outcome.config_path).expect("没写出 client.conf");
    let conf = pairing::line::parse_client_conf(&config_text)
        .unwrap_or_else(|error| panic!("client.conf 解析不了：{} / {}\n{config_text}", error.code, error.message));
    assert_eq!(conf.address, "10.66.0.2", "10.66.0.0 网段里 .1 是服务端、.5 已被占用，第一台设备应当拿 .2");
    assert_eq!(conf.allowed_ips, vec!["0.0.0.0/0".to_string()]);
    assert_eq!(conf.persistent_keepalive, 25);
    assert_eq!(conf.endpoint_port, site.port, "隧道入口必须指向这张码里的端口");
    assert_eq!(conf.public_key, server_public_key(), "对端必须是服务器接口公钥");
    assert!(
        conf.private_key.len() == 44 && conf.private_key.ends_with('='),
        "隧道私钥形状不对：{}",
        conf.private_key
    );

    // ---- 服务器侧：邀请被标成已消费、地址与申请都记下来了
    let record = site.invite_record(&invite_id);
    assert_eq!(record["State"], "Consumed");
    assert_eq!(record["ClientAddress"], "10.66.0.2/32");
    assert_eq!(record["RequestId"], outcome.request_id);
    let peer_key = record["ClientPublicKey"].as_str().expect("没记公钥").to_string();
    assert_eq!(
        tunnel_public_from_private(&conf.private_key),
        peer_key,
        "客户端私钥推出来的公钥必须就是服务器记下的那一个"
    );

    // ---- WireGuard 侧：真的加了这一段，而且只加了一段
    let wg = site.conf();
    assert_eq!(wg.matches(&format!("PublicKey = {peer_key}")).count(), 1, "同一台设备只许有一段：\n{wg}");
    assert_eq!(wg.matches("AllowedIPs = 10.66.0.2/32").count(), 1, "地址必须是 .2/32：\n{wg}");
    assert_eq!(wg.matches("[Peer]").count(), 2, "原有 1 段 + 新增 1 段，别的 peer 不许被吞掉：\n{wg}");
    assert!(wg.contains("10.66.0.5/32"), "老 peer 不许被踢掉：\n{wg}");
    assert!(wg.contains(&outcome.request_id), "配置里要留 RequestId 便于排查：\n{wg}");
    assert!(
        site.calls().iter().any(|call| call["args"][0] == "syncconf"),
        "加 peer 之后必须真的热更新（wg syncconf）"
    );
    assert!(
        site.synced().contains(&peer_key),
        "syncconf 收到的内容里必须有这台设备"
    );

    // ---- 真引擎：这份配置能不能被现场那个 sing-box 吃下
    match engine_binary() {
        Some(engine) => engine_accepts_and_listens(&engine, &conf),
        None => eprintln!("跳过引擎验收：没找到 sing-box（设 SPIDERVPN_ENGINE_BIN 可指定）"),
    }

    // ---- 另一台电脑拿同一张码：必须被挡住，而且不许动服务器配置
    //
    // 分**两条路**验，缺一条就会漏：
    // 1. 本机客户端会自己短路（GET 回 RetryOnly + 本机没有原申请 → 直接 `InviteConsumed`），
    //    这条短路不经过服务器；
    // 2. 服务器自己那条「已被别人占用」的分支必须单独打一遍——否则把服务器侧的
    //    `RequestId` 比较删掉，上面那条也照样绿（第一次做变异测试时就是这样漏掉的）。
    let (_, descriptor) =
        pairing::read_invitation(&code, true, Duration::from_secs(15), now).expect("GET 应当成功");
    let binding = descriptor
        .invite
        .get("ServerBinding")
        .cloned()
        .expect("邀请里必须有 ServerBinding");
    let second = pairing::keys::generate().expect("生成第二把接收密钥");
    let intruder = pairing::client_request::ClientRequest {
        request_id: pairing::random_uuid_v4(),
        device_id: pairing::random_uuid_v4(),
        created_at_utc: pairing::rfc3339_micros(now),
        client_public_key: second.tunnel_public_b64.clone(),
    };
    let intruder_body = json!({"PairRequest": signed_request(
        &invite_id, &binding, &second.recipient_jwk, &second.recipient_private,
        &intruder, &intruder.digest().expect("算摘要"))})
    .to_string();
    assert_eq!(
        consume_error_code(&invite, &intruder_body),
        "InviteConsumed",
        "另一台电脑直接把申请打到服务器：必须由服务器自己挡住（不能靠本机短路）"
    );

    let other_root = site.client_root("B");
    let hijack = join::run(&other_root, &code, "别人的电脑", true, now, Duration::from_secs(15));
    let error = hijack.expect_err("同一张码不许被第二台电脑用掉");
    assert_eq!(error.code, "InviteConsumed", "要说「已被使用」，不能说「协议不对」：{error:?}");
    assert_eq!(
        site.conf(),
        wg,
        "被挡住的那次请求不许改动服务器上的 WireGuard 配置"
    );
    assert!(
        crate::pairstore::list(&other_root).unwrap().is_empty(),
        "被挡住的那台电脑不该留下登记"
    );
}

/// 由隧道私钥推公钥（走产品自己的实现：`keys::tunnel_public_from_private_b64`）。
fn tunnel_public_from_private(private_b64: &str) -> String {
    pairing::keys::tunnel_public_from_private_b64(private_b64).expect("隧道私钥推不出公钥")
}

// ---------------------------------------------------------------------------
// 2. 重试：同一张码再来一次，地址不变、peer 不增
// ---------------------------------------------------------------------------

#[test]
fn r38_qa_retry_with_the_same_code_keeps_address_and_single_peer() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("retry") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let created = site.create("测试设备");
    let code = created["code"].as_str().unwrap().to_string();
    let invite_id = created["inviteId"].as_str().unwrap().to_string();
    site.start(&code);

    let root = site.client_root("A");
    let now = now_unix();
    let first = join::run(&root, &code, "测试设备", true, now, Duration::from_secs(15))
        .expect("首次加入必须成功");
    let wg_after_first = site.conf();

    // 第二次：同一个数据根、同一张码。服务器这时回的是 `RetryOnly`。
    let retry = join::run(&root, &code, "测试设备", true, now, Duration::from_secs(15))
        .expect("同一张码重试必须成功（幂等是硬要求）");
    assert!(retry.resumed, "重试必须复用本机已有的申请");
    assert_eq!(retry.enrollment_id, first.enrollment_id, "重试不许新建登记");
    assert_eq!(retry.config_path, first.config_path, "重试必须写回同一份 client.conf");
    assert_eq!(retry.state, "Completed");
    assert_eq!(crate::pairstore::list(&root).unwrap().len(), 1, "重试之后仍然只有一份登记");

    // 服务器侧：地址不变、状态不变。
    let record = site.invite_record(&invite_id);
    assert_eq!(record["State"], "Consumed");
    assert_eq!(record["ClientAddress"], "10.66.0.2/32", "重试不许换地址");

    // WireGuard 侧：段数不变，同一个公钥只有一段。
    let wg = site.conf();
    assert_eq!(wg.matches("[Peer]").count(), 2, "重试不许堆第二个 peer 段：\n{wg}");
    assert_eq!(wg, wg_after_first, "同一份申请的重试必须让配置逐字节不变：\n{wg}");

    // 客户端视角：GET 现在说的是 `RetryOnly`（客户端只认这四个词之一）。
    let invite = pairing::parse_code(&code, true, now).unwrap();
    let reply = pairing::http::get(&invite, Duration::from_secs(10)).expect("GET 应当成功");
    let data = pairing::http::data(&reply).expect("GET 信封应当可读");
    assert_eq!(data["Status"], "RetryOnly", "消费过的邀请对客户端只能说这个");
}

// ---------------------------------------------------------------------------
// 3. 反向用例：每种都必须给**准确**的错误码
// ---------------------------------------------------------------------------

fn consume_error_code(invite: &Invite, body: &str) -> String {
    let reply = pairing::http::post_consume(invite, body, Duration::from_secs(15))
        .unwrap_or_else(|error| panic!("POST 应当在传输层成功（{}）：{}", error.code, error.message));
    match pairing::http::data(&reply) {
        Ok(data) => panic!("期望失败，实际成功：{data}"),
        Err(error) => error.code,
    }
}

/// 自己拼一份签过名的申请：签名是真的（真 RSA 私钥），但摘要/绑定可以由调用方指定。
fn signed_request(
    invite_id: &str,
    binding: &Value,
    recipient: &pairing::jwk::RsaJwk,
    key: &rsa::RsaPrivateKey,
    client: &pairing::client_request::ClientRequest,
    digest: &str,
) -> String {
    let payload = json!({
        "SchemaVersion": 1,
        "Kind": "TradeChannel.PairRequest",
        "InviteId": invite_id,
        "ServerBinding": binding,
        "ClientRequest": {
            "SchemaVersion": 1,
            "Kind": "TradeChannel.ClientRequest",
            "RequestId": client.request_id,
            "DeviceId": client.device_id,
            "CreatedAtUtc": client.created_at_utc,
            "ClientPublicKey": client.client_public_key,
            "AddressFamilies": ["IPv4"],
        },
        "DeviceName": "测试设备",
        "RecipientJwk": {"kty": "RSA", "n": recipient.n, "e": recipient.e},
        "RequestDigest": digest,
        "RequestDigestAlgorithm": "TC-ClientRequest-v1",
        "CreatedAtUtc": client.created_at_utc,
    });
    pairing::request::sign_rs256(&payload, key)
}

/// 不经 `http.client` 的裸 TLS 请求：用来构造「缺 Content-Length / 分块」这类畸形报文。
/// 请求先转 base64 再作为 argv 传，避免换行在命令行上被改写。
fn raw_exchange(python: &str, port: u16, request: &str) -> String {
    const SCRIPT: &str = r#"
import base64, socket, ssl, sys
port = int(sys.argv[1])
data = base64.b64decode(sys.argv[2])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
out = b""
with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
    with ctx.wrap_socket(sock) as tls:
        tls.sendall(data)
        try:
            while True:
                piece = tls.recv(4096)
                if not piece:
                    break
                out += piece
        except OSError:
            pass
sys.stdout.write(out.decode("utf-8", "replace"))
"#;
    let encoded = b64std(request.as_bytes());
    let output = Command::new(python)
        .arg("-c")
        .arg(SCRIPT)
        .arg(port.to_string())
        .arg(encoded)
        .stdin(Stdio::null())
        .output()
        .expect("跑不起来裸 TLS 请求");
    assert!(
        output.status.success(),
        "裸 TLS 请求失败：{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn r38_qa_server_rejections_carry_exact_codes() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("reject") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let created = site.create("测试设备");
    let code = created["code"].as_str().unwrap().to_string();
    let invite_id = created["inviteId"].as_str().unwrap().to_string();
    site.start(&code);

    let now = now_unix();
    let invite = pairing::parse_code(&code, true, now).expect("码本机解析不了");
    let (status, descriptor) =
        pairing::read_invitation(&code, true, Duration::from_secs(15), now).expect("GET 应当成功");
    assert_eq!(status, "InvitationReady", "新脚本对未消费的邀请只能说这个");
    let binding = descriptor
        .invite
        .get("ServerBinding")
        .cloned()
        .expect("邀请里必须有 ServerBinding");

    // ---- 凭据与目标
    let mut wrong_token = invite.clone();
    wrong_token.token = "A".repeat(43);
    assert_eq!(
        consume_error_code(&wrong_token, r#"{"PairRequest":"x"}"#),
        "Forbidden",
        "令牌不对必须说「凭据不对」，不能退化成「协议不对」"
    );

    let mut ghost = invite.clone();
    ghost.invite_id = pairing::random_uuid_v4();
    assert_eq!(
        consume_error_code(&ghost, r#"{"PairRequest":"x"}"#),
        "InviteNotFound",
        "不在这台服务器上的邀请要单独成码"
    );

    // ---- 正文形态
    assert_eq!(consume_error_code(&invite, "not json"), "InvalidRequest");
    assert_eq!(consume_error_code(&invite, "[]"), "InvalidRequest");

    // ---- 签名与绑定的四种篡改（签名都是真的，只有被签的内容不对）
    let keys = pairing::keys::generate().expect("生成接收密钥");
    let client = pairing::client_request::ClientRequest {
        request_id: pairing::random_uuid_v4(),
        device_id: pairing::random_uuid_v4(),
        created_at_utc: pairing::rfc3339_micros(now),
        client_public_key: keys.tunnel_public_b64.clone(),
    };
    let good_digest = client.digest().expect("算摘要");

    let tampered_digest = json!({"PairRequest": signed_request(
        &invite_id, &binding, &keys.recipient_jwk, &keys.recipient_private,
        &client, &"0".repeat(64))})
    .to_string();
    assert_eq!(
        consume_error_code(&invite, &tampered_digest),
        "PairingMismatch",
        "摘要被改必须是「摘要不匹配」"
    );

    let mut foreign_binding = binding.clone();
    foreign_binding["NodeId"] = json!(pairing::random_uuid_v4());
    let swapped_binding = json!({"PairRequest": signed_request(
        &invite_id, &foreign_binding, &keys.recipient_jwk, &keys.recipient_private,
        &client, &good_digest)})
    .to_string();
    assert_eq!(
        consume_error_code(&invite, &swapped_binding),
        "InviteMismatch",
        "换服务器绑定必须报「不是给这张邀请的」"
    );

    // 签名动一个字符：结构没变、字节变了。
    let honest = signed_request(
        &invite_id, &binding, &keys.recipient_jwk, &keys.recipient_private, &client, &good_digest,
    );
    let mut segments: Vec<String> = honest.split('.').map(str::to_string).collect();
    let flipped = if segments[2].starts_with('A') { "B" } else { "A" };
    segments[2] = format!("{flipped}{}", &segments[2][1..]);
    let broken_signature = json!({"PairRequest": segments.join(".")}).to_string();
    assert_eq!(
        consume_error_code(&invite, &broken_signature),
        "InvalidPairRequest",
        "签名不对必须说「申请不对」，不是「服务器坏了」"
    );

    // 别人的私钥签「本机」的公钥：验签公钥取自申请里的 RecipientJwk，必须失败。
    let impostor = pairing::keys::generate().expect("生成第二把接收密钥");
    let forged = json!({"PairRequest": signed_request(
        &invite_id, &binding, &keys.recipient_jwk, &impostor.recipient_private,
        &client, &good_digest)})
    .to_string();
    assert_eq!(
        consume_error_code(&invite, &forged),
        "InvalidPairRequest",
        "换个私钥签同一份载荷必须被拒（否则谁都能替别人提交申请）"
    );

    // ---- 畸形报文：缺 Content-Length / 分块
    let path = format!("/v1/invitations/{invite_id}/consume");
    let no_length = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/json\r\nConnection: close\r\n\r\n{{}}",
        invite.token
    );
    let reply = raw_exchange(&site.python, site.port, &no_length);
    assert!(
        reply.contains("\"Code\":\"InvalidRequest\""),
        "缺 Content-Length 必须报 InvalidRequest，实际：{reply}"
    );

    let chunked = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\
         Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n\
         Connection: close\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n",
        invite.token
    );
    let reply = raw_exchange(&site.python, site.port, &chunked);
    assert!(
        reply.contains("\"Code\":\"InvalidRequest\""),
        "分块传输必须报 InvalidRequest，实际：{reply}"
    );

    // ---- 这一串失败之后，邀请必须还是**能用的**：状态没变、配置没动
    let (status, _) =
        pairing::read_invitation(&code, true, Duration::from_secs(15), now).expect("GET 应当成功");
    assert_eq!(status, "InvitationReady", "失败的申请不许把邀请用掉");
    assert_eq!(site.conf(), BASE_CONF, "失败的申请不许改服务器配置");
    assert_eq!(
        site.invite_record(&invite_id)["State"],
        "Open",
        "失败的申请不许把邀请标成已消费"
    );
}

// ---------------------------------------------------------------------------
// 4. 状态词表：旧脚本 / 作废 / 过期 / 表外的词
// ---------------------------------------------------------------------------

/// r37 的服务器（GET 回 `Open`）：码本身没问题，是**脚本**没升级。
/// 出路是「让对方重开一次接收服务」，所以必须给 `InviteServerOutdated`。
#[test]
fn r38_qa_old_server_status_open_is_reported_as_server_outdated() {
    // 把映射整段去掉 = 旧脚本原样透出 `Open`。
    let _permit = heavy_permit();
    let Some(mut site) = Site::with_script(
        "old-open",
        Some(("return CLIENT_STATES.get(state, state)", "return state")),
    ) else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let created = site.create("测试设备");
    let code = created["code"].as_str().unwrap().to_string();
    site.start(&code);

    let now = now_unix();
    let invite = pairing::parse_code(&code, true, now).unwrap();
    let reply = pairing::http::get(&invite, Duration::from_secs(10)).expect("GET 应当成功");
    let data = pairing::http::data(&reply).expect("GET 信封应当可读");
    assert_eq!(data["Status"], "Open", "这是旧脚本的形状（本用例的前提）");

    let root = site.client_root("A");
    let error = join::run(&root, &code, "测试设备", true, now, Duration::from_secs(15))
        .expect_err("服务器说 Open 时不能继续");
    assert_eq!(
        error.code, "InviteServerOutdated",
        "旧脚本要说「服务器该升级了」，不能说「协议不对」：{error:?}"
    );
    assert!(
        error.message.contains("开启接收服务"),
        "错误里要有一句能照做的话：{}",
        error.message
    );
    assert!(
        crate::pairstore::list(&root).unwrap().is_empty(),
        "拒绝时不该留下登记"
    );
}

/// 服务器作废之后：必须给 `InviteCancelled`（出路是重新生成一张）。
#[test]
fn r38_qa_cancelled_invite_is_reported_as_cancelled() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("cancelled") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let created = site.create("测试设备");
    let code = created["code"].as_str().unwrap().to_string();
    let invite_id = created["inviteId"].as_str().unwrap().to_string();
    site.start(&code);

    site.cancel(&invite_id);
    let now = now_unix();
    let invite = pairing::parse_code(&code, true, now).unwrap();
    let reply = pairing::http::get(&invite, Duration::from_secs(10)).expect("GET 应当成功");
    let data = pairing::http::data(&reply).expect("GET 信封应当可读");
    assert_eq!(data["Status"], "Cancelled", "作废之后 GET 必须说 Cancelled");

    let root = site.client_root("A");
    let error = join::run(&root, &code, "测试设备", true, now, Duration::from_secs(15))
        .expect_err("作废的邀请不能继续");
    assert_eq!(error.code, "InviteCancelled", "{error:?}");
}

/// 服务器说 `Expired`：必须给 `InviteExpired`。
///
/// 构造方式：只把**状态文件**里的有效期改到过去（码里与描述符里的过期时间没动），
/// 于是「本机看这张码还没过期、服务器说它过期了」——正是这条分支存在的理由。
#[test]
fn r38_qa_expired_invite_is_reported_as_expired() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("expired") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let created = site.create("测试设备");
    let code = created["code"].as_str().unwrap().to_string();
    let invite_id = created["inviteId"].as_str().unwrap().to_string();
    site.start(&code);

    let mut state = site.invites();
    state["Invites"][&invite_id]["ExpiresAtUtc"] = json!("2020-01-01T00:00:00Z");
    std::fs::write(
        site.pair_root.join("invites.json"),
        serde_json::to_string(&state).unwrap() + "\n",
    )
    .expect("改状态文件");

    let now = now_unix();
    let invite = pairing::parse_code(&code, true, now).expect("码本身还没过期（本用例的前提）");
    let reply = pairing::http::get(&invite, Duration::from_secs(10)).expect("GET 应当成功");
    let data = pairing::http::data(&reply).expect("GET 信封应当可读");
    assert_eq!(data["Status"], "Expired", "服务器应当说 Expired");

    let root = site.client_root("A");
    let error = join::run(&root, &code, "测试设备", true, now, Duration::from_secs(15))
        .expect_err("过期的邀请不能继续");
    assert_eq!(error.code, "InviteExpired", "{error:?}");
}

/// 谁也没定义过的词：必须拒绝，不许猜成「可以继续」。
#[test]
fn r38_qa_unknown_status_word_is_refused() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::with_script(
        "unknown-word",
        Some(("\"Open\": \"InvitationReady\",", "\"Open\": \"SomethingElse\",")),
    ) else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let created = site.create("测试设备");
    let code = created["code"].as_str().unwrap().to_string();
    site.start(&code);

    let now = now_unix();
    let invite = pairing::parse_code(&code, true, now).unwrap();
    let reply = pairing::http::get(&invite, Duration::from_secs(10)).expect("GET 应当成功");
    let data = pairing::http::data(&reply).expect("GET 信封应当可读");
    assert_eq!(data["Status"], "SomethingElse", "本用例的前提");

    let root = site.client_root("A");
    let error = join::run(&root, &code, "测试设备", true, now, Duration::from_secs(15))
        .expect_err("表外的状态词不能继续");
    assert_eq!(
        error.code, "InvalidOnlineResponse",
        "认不出来的词不许被猜成任何可继续的语义：{error:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. 页面该给哪个按钮：走 `WebUi` 的公开路由（与界面同一条路）
// ---------------------------------------------------------------------------

/// 把「加入失败」的真回包喂给页面，看它给哪个主按钮。
///
/// 这一条与上面几条串起来看才有意义：上面证明**客户端确实会产出**这些错误码，
/// 这里证明**页面拿到这些码之后**给的按钮能照做。
#[test]
fn r38_qa_pair_failure_offers_a_button_the_user_can_follow() {
    for (code, want) in [
        // 服务器脚本旧了：码还能用，重开一次接收服务再点一次就成。
        ("InviteServerOutdated", "Retry"),
        // 码被作废 / 已过期：只能换一张。
        ("InviteCancelled", "Reenter"),
        ("InviteExpired", "Reenter"),
        // 服务器说了认不出来的话：也只能重来。
        ("InvalidOnlineResponse", "Reenter"),
    ] {
        let mut ui = crate::uiweb::WebUi::new();
        let fetch = |_: &str| -> Value { Value::Null };

        // 1) 校验邀请码：成功 → 进入「待加入」。
        ui.route(
            r#"{"Type":"pairOnline","Phase":"Verify","Id":"","Code":"TCI1.abc","Name":"管理电脑","Sequence":1}"#,
            &fetch,
        );
        let round = ui.snapshot(&fetch)["State"]["Pair"]["PairId"]
            .as_str()
            .expect("会话必须带 PairId")
            .to_string();
        ui.finish_op(&json!({
            "ok": true,
            "pairVerify": {
                "Code": "", "Message": "", "Status": "InvitationReady",
                "NodeId": "node-1", "NodeName": "香港 01", "Host": "203.0.113.10",
                "ExpiresAtUtc": "2027-01-01T00:00:00Z", "DeviceName": "管理电脑",
                "PairId": round,
            }
        }));

        // 2) 点「加入」：真的发一条 pair-join 长命令。
        let steps = ui.route(
            r#"{"Type":"pairOnline","Phase":"Join","Id":"x","Name":"香港 01","Sequence":2}"#,
            &fetch,
        );
        assert!(
            matches!(steps.first(), Some(crate::uiweb::Step::Long(command)) if command.contains("pair-join")),
            "加入必须走长命令：{steps:?}"
        );
        let round = ui.snapshot(&fetch)["State"]["Pair"]["PairId"]
            .as_str()
            .expect("会话必须带 PairId")
            .to_string();

        // 3) 宿主的失败回包（码就是上面几条用例证明客户端会产出的那些）。
        ui.finish_op(&json!({
            "ok": false,
            "pairJoin": {"Code": code, "Message": "测试注入", "PairId": round}
        }));

        let snapshot = ui.snapshot(&fetch);
        let pair = &snapshot["State"]["Pair"];
        assert_eq!(pair["Phase"], "Failed", "失败回包必须转失败态：{pair}");
        assert_eq!(pair["ErrorCode"], code, "{pair}");
        assert_eq!(
            pair["NextAction"], want,
            "错误码 {code} 之后页面给的按钮不对：{pair}"
        );
        assert!(!pair["NextAction"].as_str().unwrap_or("").is_empty(), "动作不许留空");
    }
}

// ---------------------------------------------------------------------------
// 6. 多设备：地址连续分配，先来者的 peer 段不许被后来者吞掉
// ---------------------------------------------------------------------------

/// 按 `[Peer]` 段切开，保留每段的原文（逐字节比较用）。
///
/// 每段都去掉**尾部空行**：`render_sections` 用 `\n\n` 连接各段，同一段在「中间」
/// 与「末尾」时的尾部空行数不同，但那不是段内容的一部分。
fn peer_sections(text: &str) -> Vec<String> {
    let mut sections = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("[peer]") {
            if let Some(section) = current.take() {
                sections.push(section.trim_end().to_string());
            }
            current = Some(String::new());
            continue;
        }
        if trimmed.starts_with('[') {
            if let Some(section) = current.take() {
                sections.push(section.trim_end().to_string());
            }
            continue;
        }
        if let Some(section) = current.as_mut() {
            section.push_str(line);
            section.push('\n');
        }
    }
    if let Some(section) = current {
        sections.push(section.trim_end().to_string());
    }
    sections
}

fn peer_section_of(text: &str, public_key: &str) -> String {
    let wanted = format!("PublicKey = {public_key}");
    peer_sections(text)
        .into_iter()
        .find(|section| section.contains(&wanted))
        .unwrap_or_else(|| panic!("配置里没有 {public_key} 的 [Peer] 段：\n{text}"))
}

/// 三台设备依次加入：`.2` → `.3` → `.4`，且后来者不许改动先来者的段。
///
/// 「加一台设备」最容易犯的错是整段重写配置：受害者只会看到「另一台电脑突然连不上」，
/// 而服务器上没有任何报错。所以要逐字节比**先前那两段**，不是「公钥还在」。
#[test]
fn r38_qa_three_devices_get_their_own_addresses_and_keep_earlier_peers() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("three") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let first = site.create("设备甲");
    let code1 = first["code"].as_str().unwrap().to_string();
    let id1 = first["inviteId"].as_str().unwrap().to_string();
    site.start(&code1);
    let now = now_unix();

    let a = join::run(&site.client_root("A"), &code1, "设备甲", true, now, Duration::from_secs(15))
        .expect("第一台必须能接入");
    assert_eq!(a.state, "Completed");
    let record_a = site.invite_record(&id1);
    assert_eq!(record_a["ClientAddress"], "10.66.0.2/32", "第一台拿 .2");
    let key_a = record_a["ClientPublicKey"].as_str().unwrap().to_string();
    let section_a_first = peer_section_of(&site.conf(), &key_a);
    assert_eq!(
        pairing::line::parse_client_conf(&std::fs::read_to_string(&a.config_path).unwrap())
            .unwrap()
            .address,
        "10.66.0.2",
        "客户端自己的配置里也必须是 .2"
    );

    // ---- 第二台
    let second = site.create("设备乙");
    let code2 = second["code"].as_str().unwrap().to_string();
    let id2 = second["inviteId"].as_str().unwrap().to_string();
    let b = join::run(&site.client_root("B"), &code2, "设备乙", true, now, Duration::from_secs(15))
        .expect("第二台必须能接入");
    assert_eq!(b.state, "Completed");
    let record_b = site.invite_record(&id2);
    assert_eq!(record_b["ClientAddress"], "10.66.0.3/32", "第二台拿 .3（跳过 .5 那台老设备）");
    let key_b = record_b["ClientPublicKey"].as_str().unwrap().to_string();
    let conf_after_b = site.conf();
    assert_eq!(
        peer_section_of(&conf_after_b, &key_a),
        section_a_first,
        "乙接入不许改动甲那一段（逐字节）"
    );
    let section_b_first = peer_section_of(&conf_after_b, &key_b);
    assert_eq!(peer_sections(&conf_after_b).len(), 3, "原有 .5 + 甲 + 乙");

    // ---- 第三台
    let third = site.create("设备丙");
    let code3 = third["code"].as_str().unwrap().to_string();
    let id3 = third["inviteId"].as_str().unwrap().to_string();
    let c = join::run(&site.client_root("C"), &code3, "设备丙", true, now, Duration::from_secs(15))
        .expect("第三台必须能接入");
    assert_eq!(c.state, "Completed");
    let record_c = site.invite_record(&id3);
    assert_eq!(record_c["ClientAddress"], "10.66.0.4/32", "第三台拿 .4");
    let key_c = record_c["ClientPublicKey"].as_str().unwrap().to_string();

    let conf = site.conf();
    assert_eq!(
        peer_section_of(&conf, &key_a),
        section_a_first,
        "丙接入后，甲那一段必须逐字节还在"
    );
    assert_eq!(
        peer_section_of(&conf, &key_b),
        section_b_first,
        "丙接入后，乙那一段必须逐字节还在"
    );
    assert_eq!(peer_sections(&conf).len(), 4, "原有 .5 + 甲 + 乙 + 丙，一段不多一段不少");
    assert!(conf.contains("AllowedIPs = 10.66.0.5/32"), "老设备不许被吞：\n{conf}");
    let section_c = peer_section_of(&conf, &key_c);
    assert!(
        section_c.contains("AllowedIPs = 10.66.0.4/32"),
        "丙那一段必须是 .4：{section_c}"
    );

    // 三个地址互不相同（服务器记录 + 各自 client.conf 两处都要对得上）。
    let mut addresses = vec![
        record_a["ClientAddress"].as_str().unwrap().to_string(),
        record_b["ClientAddress"].as_str().unwrap().to_string(),
        record_c["ClientAddress"].as_str().unwrap().to_string(),
    ];
    assert_eq!(addresses.len(), 3);
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 3, "三台设备的地址不许重复");
    for (label, outcome, want) in [("甲", &a, "10.66.0.2"), ("乙", &b, "10.66.0.3"), ("丙", &c, "10.66.0.4")]
    {
        let text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let conf = pairing::line::parse_client_conf(&text).unwrap();
        assert_eq!(conf.address, want, "{label} 的 client.conf 地址不对");
    }

    // 每个 /32 只能出现在一段里——这是「同址双写」唯一的机器可查证据。
    let mut seen = std::collections::BTreeSet::new();
    for line in conf.lines().filter(|line| line.trim().to_ascii_lowercase().starts_with("allowedips")) {
        assert!(seen.insert(line.trim().to_string()), "同一个 AllowedIPs 被写进了两段：{line}\n{conf}");
    }
    assert_eq!(seen.len(), 4, "四个 peer 应当各有各的 AllowedIPs：{conf}");
}

// ---------------------------------------------------------------------------
// 7. 并发：两张不同的合法申请同时打同一张码，只能有一个赢
// ---------------------------------------------------------------------------

/// 一次 consume 的结果：成功给 `Data`，失败给**服务器的错误码**。
fn consume_result(invite: &Invite, body: &str) -> Result<Value, String> {
    let reply = match pairing::http::post_consume(invite, body, Duration::from_secs(25)) {
        Ok(reply) => reply,
        Err(error) => return Err(format!("传输层失败：{} / {}", error.code, error.message)),
    };
    match pairing::http::data(&reply) {
        Ok(data) => Ok(data),
        Err(error) => Err(error.code),
    }
}

/// 造一份「合法但属于另一台电脑」的申请：不同的 `RequestId`、不同的接收密钥。
fn fresh_request(keys: &pairing::keys::PairingKeys, now: i64) -> pairing::client_request::ClientRequest {
    pairing::client_request::ClientRequest {
        request_id: pairing::random_uuid_v4(),
        device_id: pairing::random_uuid_v4(),
        created_at_utc: pairing::rfc3339_micros(now),
        client_public_key: keys.tunnel_public_b64.clone(),
    }
}

fn body_for(
    invite_id: &str,
    binding: &Value,
    keys: &pairing::keys::PairingKeys,
    client: &pairing::client_request::ClientRequest,
) -> String {
    json!({"PairRequest": signed_request(
        invite_id, binding, &keys.recipient_jwk, &keys.recipient_private, client,
        &client.digest().expect("算摘要"))})
    .to_string()
}

#[test]
fn r38_qa_two_computers_racing_on_one_code_let_exactly_one_win() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("race") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let prime = site.create("预热");
    let prime_code = prime["code"].as_str().unwrap().to_string();
    site.start(&prime_code);
    let now = now_unix();

    // `ServerBinding` 对同一台服务器上的所有邀请是同一份，取一次即可。
    let (_, descriptor) =
        pairing::read_invitation(&prime_code, true, Duration::from_secs(15), now).expect("GET 应当成功");
    let binding = descriptor.invite.get("ServerBinding").cloned().expect("邀请里必须有 ServerBinding");

    let mut winner_addresses: Vec<String> = Vec::new();

    // 三轮：线程调度没法保证「一定真交叉」，多跑几轮把交叉的机会提上来；
    // 而结论（恰好一台赢）与是否交叉无关——`CONSUME_LOCK` 就是为这件事存在的。
    //
    // 每轮都用**全新的两把接收密钥**：服务器按公钥去重（`with_client_peer` 会先删同
    // 公钥的旧段再写新段），复用同一把密钥会让「第二轮赢家把第一轮的段顶掉」，
    // 那时地址与段数都会变，测的就不再是「两台电脑抢一张码」了。
    for round in 0..3 {
        let alpha = pairing::keys::generate().expect("生成甲的接收密钥");
        let beta = pairing::keys::generate().expect("生成乙的接收密钥");
        let created = site.create(&format!("并发设备{round}"));
        let code = created["code"].as_str().unwrap().to_string();
        let invite_id = created["inviteId"].as_str().unwrap().to_string();
        let invite = pairing::parse_code(&code, true, now).expect("解析码");

        let client_a = fresh_request(&alpha, now);
        let client_b = fresh_request(&beta, now);
        let body_a = body_for(&invite_id, &binding, &alpha, &client_a);
        let body_b = body_for(&invite_id, &binding, &beta, &client_b);

        let (result_a, result_b) = std::thread::scope(|scope| {
            let handle_a = scope.spawn(|| consume_result(&invite, &body_a));
            let handle_b = scope.spawn(|| consume_result(&invite, &body_b));
            (handle_a.join().expect("甲线程 panic"), handle_b.join().expect("乙线程 panic"))
        });

        let wins = [result_a.is_ok(), result_b.is_ok()];
        assert_eq!(
            wins.iter().filter(|won| **won).count(),
            1,
            "第 {round} 轮：必须恰好一台成功。甲={result_a:?} 乙={result_b:?}"
        );
        for (label, result) in [("甲", &result_a), ("乙", &result_b)] {
            if let Err(code) = result {
                assert_eq!(
                    code, "InviteConsumed",
                    "第 {round} 轮 {label} 落败时必须说「已被使用」，不能说「协议不对」：{result:?}"
                );
            }
        }

        // 赢家是谁不确定，但服务器记下的必须是赢家那一份。
        let (winner_client, winner_keys, loser_client) = if result_a.is_ok() {
            (&client_a, &alpha, &client_b)
        } else {
            (&client_b, &beta, &client_a)
        };
        let record = site.invite_record(&invite_id);
        assert_eq!(
            record["RequestId"], winner_client.request_id,
            "第 {round} 轮：invites.json 里的 RequestId 只能记赢家"
        );
        assert_ne!(
            record["RequestId"], loser_client.request_id,
            "第 {round} 轮：落败那台的 RequestId 不许被记下"
        );
        assert_eq!(record["ClientPublicKey"], winner_keys.tunnel_public_b64);
        assert_eq!(record["State"], "Consumed");

        let conf = site.conf();
        assert_eq!(
            conf.matches(&format!("PublicKey = {}", winner_keys.tunnel_public_b64)).count(),
            1,
            "第 {round} 轮：赢家只许有一段 peer"
        );
        // 「落败那台没进配置」要按**这一轮的 RequestId** 判，不能按公钥：两把接收密钥
        // 是跨轮复用的，前一轮的赢家这一轮可能是输家，它的公钥本来就该在配置里。
        assert!(
            conf.contains(&winner_client.request_id),
            "第 {round} 轮：赢家那段应当带着它的 RequestId：\n{conf}"
        );
        assert!(
            !conf.contains(&loser_client.request_id),
            "第 {round} 轮：落败那台的 RequestId 不许出现在配置里：\n{conf}"
        );
        assert_eq!(
            peer_sections(&conf).len(),
            round + 2,
            "第 {round} 轮：原有 .5 + 每轮恰好一段新 peer：\n{conf}"
        );
        winner_addresses.push(record["ClientAddress"].as_str().unwrap().to_string());
    }

    // 三轮各占一个地址，互不相同；且服务器上任何一段 AllowedIPs 都不重复。
    let mut unique = winner_addresses.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 3, "三轮的地址不许有重复：{winner_addresses:?}");

    let conf = site.conf();
    assert_eq!(peer_sections(&conf).len(), 4, "原有 .5 + 三轮各一台：\n{conf}");
    let mut seen = std::collections::BTreeSet::new();
    for line in conf.lines().filter(|line| line.trim().to_ascii_lowercase().starts_with("allowedips")) {
        assert!(
            seen.insert(line.trim().to_string()),
            "同一个 /32 被写进了两段 peer（地址重复分配）：{line}\n{conf}"
        );
    }
    assert_eq!(seen.len(), 4, "四段 peer 应当有四个不同的 AllowedIPs：\n{conf}");
}

/// 两张**不同**的码并发消费：互不相干，两台都必须成功且拿到不同地址。
///
/// 这一条是上一组的对照：锁不是「一律拒绝第二个」，只有一个邀请被两张申请抢时才该拒。
#[test]
fn r38_qa_two_different_codes_consumed_in_parallel_both_succeed() {
    let _permit = heavy_permit();
    let Some(mut site) = Site::new("parallel") else {
        eprintln!("跳过：这台机器上没有 python3 或没有非回环 IPv4");
        return;
    };
    let _bits = pairing::keys::test_bits(2048);
    site.init();
    let first = site.create("并发甲");
    let second = site.create("并发乙");
    let code1 = first["code"].as_str().unwrap().to_string();
    let id1 = first["inviteId"].as_str().unwrap().to_string();
    let code2 = second["code"].as_str().unwrap().to_string();
    let id2 = second["inviteId"].as_str().unwrap().to_string();
    site.start(&code1);
    let now = now_unix();

    let (_, descriptor) =
        pairing::read_invitation(&code1, true, Duration::from_secs(15), now).expect("GET 应当成功");
    let binding = descriptor.invite.get("ServerBinding").cloned().expect("邀请里必须有 ServerBinding");

    let alpha = pairing::keys::generate().expect("生成甲的接收密钥");
    let beta = pairing::keys::generate().expect("生成乙的接收密钥");
    let client_a = fresh_request(&alpha, now);
    let client_b = fresh_request(&beta, now);
    let body_a = body_for(&id1, &binding, &alpha, &client_a);
    let body_b = body_for(&id2, &binding, &beta, &client_b);
    let invite_a = pairing::parse_code(&code1, true, now).unwrap();
    let invite_b = pairing::parse_code(&code2, true, now).unwrap();

    let (result_a, result_b) = std::thread::scope(|scope| {
        let handle_a = scope.spawn(|| consume_result(&invite_a, &body_a));
        let handle_b = scope.spawn(|| consume_result(&invite_b, &body_b));
        (handle_a.join().expect("甲线程 panic"), handle_b.join().expect("乙线程 panic"))
    });

    assert!(result_a.is_ok(), "两张不同的码不该互相挡：甲={result_a:?}");
    assert!(result_b.is_ok(), "两张不同的码不该互相挡：乙={result_b:?}");

    let record_a = site.invite_record(&id1);
    let record_b = site.invite_record(&id2);
    assert_eq!(record_a["RequestId"], client_a.request_id);
    assert_eq!(record_b["RequestId"], client_b.request_id);
    assert_eq!(record_a["ClientPublicKey"], alpha.tunnel_public_b64);
    assert_eq!(record_b["ClientPublicKey"], beta.tunnel_public_b64);

    let address_a = record_a["ClientAddress"].as_str().unwrap().to_string();
    let address_b = record_b["ClientAddress"].as_str().unwrap().to_string();
    assert_ne!(address_a, address_b, "两台设备不许拿到同一个地址");
    let mut pair = vec![address_a, address_b];
    pair.sort();
    assert_eq!(pair, vec!["10.66.0.2/32".to_string(), "10.66.0.3/32".to_string()], "应当是 .2 与 .3");

    let conf = site.conf();
    assert_eq!(peer_sections(&conf).len(), 3, "原有 .5 + 两台新设备：\n{conf}");
    assert_eq!(conf.matches(&format!("PublicKey = {}", alpha.tunnel_public_b64)).count(), 1);
    assert_eq!(conf.matches(&format!("PublicKey = {}", beta.tunnel_public_b64)).count(), 1);
}

/// 离线交接：不经过 18443，用「邀请 → 申请 → 授权」两次人工传递完成同一份加入。
///
/// 这条用例把两边的**生产实现**接在一起：邀请来自真服务器脚本的 `create`，
/// 申请来自 Rust 的 `offline::prepare`，批准走服务器脚本的 `authorize-request`，
/// 授权再由 Rust 的 `offline::complete` 解封并落线路。任何一处字段名/编码漂移都会红。
#[test]
fn 离线交接在本机与真服务器之间完成一次接入() {
    let Some(site) = Site::new("offline") else {
        eprintln!("跳过：这台机器上没有 python3");
        return;
    };
    site.init();
    let created = site.run(&["create", "--lifetime", "86400", "--device", "离线电脑"]);
    let invite_id = created["inviteId"].as_str().expect("没报邀请编号");
    let invite_jws = created["invite"].as_str().expect("服务器没有返回完整邀请");
    let fingerprint = created["managementFingerprint"].as_str().expect("没报管理指纹");
    assert!(
        invite_jws.split('.').count() == 3,
        "离线交接要的是签名邀请本身（三段 JWS），实际：{invite_jws}"
    );

    let client_root = site.client_root("offline");
    let prepared = pairing::offline::prepare(
        &client_root,
        invite_jws,
        fingerprint,
        "离线电脑",
        now_unix(),
    )
    .expect("本机生成离线申请失败");
    assert_eq!(prepared.pairing_code.len(), 12);

    let authorized = site.run(&["authorize-request", "--request", &prepared.request_text]);
    let authorization = authorized["authorization"].as_str().expect("没返回加密授权");
    assert_eq!(authorized["inviteId"], invite_id);
    assert_eq!(authorized["deviceName"], "离线电脑");

    // 服务器侧：邀请被消费、地址从 10.66.0.0/24 分配并跳过已在用的 .5。
    let record = site.invite_record(invite_id);
    assert_eq!(record["State"], "Consumed");
    assert_eq!(record["ClientAddress"], "10.66.0.2/32");
    let request_payload = pairing::request::verify(&prepared.request_text, now_unix())
        .expect("本机申请必须自洽");
    assert_eq!(record["RequestId"], request_payload["ClientRequest"]["RequestId"]);
    assert_eq!(site.conf().matches("PublicKey = ").count(), 2, "原有 .5 + 这台新设备");

    // 本机侧：解封授权、生成 client.conf 与线路。
    let outcome = pairing::offline::complete(
        &client_root,
        &prepared.enrollment_id,
        authorization,
        Some("离线线路"),
        now_unix(),
        &crate::events::Origin::ui(),
    )
    .expect("导入离线授权失败");
    assert_eq!(outcome.line_name, "离线线路");
    assert!(client_root
        .join("identities")
        .join(&prepared.enrollment_id)
        .join("client.conf")
        .exists());

    // 幂等：同一份申请再批准一次，必须拿回同一份签名授权（JWE 每次重新封装）。
    let replay = site.run(&["authorize-request", "--request", &prepared.request_text]);
    let stored = crate::pairstore::load_private(&client_root, &prepared.enrollment_id).unwrap();
    let private = pairing::keys::recipient_from_pkcs8_b64(&stored.recipient_pkcs8_b64).unwrap();
    let first = pairing::jwe::decrypt(authorization, &private).expect("第一次授权解不开");
    let second = pairing::jwe::decrypt(
        replay["authorization"].as_str().expect("重放没有授权"),
        &private,
    )
    .expect("重放授权解不开");
    assert_eq!(first, second, "重放必须拿到同一份签名授权，不能重新分配地址");

    // 改一个字节的申请必须被服务器拒绝。
    let mut tampered = prepared.request_text.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let (ok, reply) = site.attempt(&["authorize-request", "--request", &tampered]);
    assert!(!ok, "篡改过的申请不该被批准：{reply}");
}

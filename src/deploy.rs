//! 服务器环境检查（部署的第一步，**只读**）。
//!
//! 只回答一个问题：这台机器够不够格装我们的服务。它不改任何东西、不装包、不写文件，
//! 所以在「确认指纹」和「真正部署」之间可以随时重跑。
//!
//! 一次 SSH 往返取全部信息：逐条命令往返会把 3 秒的检查拖成十几秒，而部署向导里
//! 用户就等在屏幕前。输出用 `TC_*=` 前缀逐行返回，最后用 `TC_DONE=1` 收尾——
//! 少一行就说明脚本没跑完（被截断、被 `exit`、被老 shell 卡住），那时**不能**把
//! 缺字段当成「没有这个能力」。

use std::time::Duration;

use crate::ssh::{self, Auth, Error, Target};

/// 一次检查的结果。字段全部来自远端，不做任何推断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// `uname -s`：只接受 `Linux`。
    pub kernel: String,
    /// `uname -m`，例如 `x86_64` / `aarch64`。
    pub arch: String,
    /// `id -u`：0 = root。部署要 root，否则第一步就得让用户换账户。
    pub uid: u32,
    /// `/etc/os-release` 的 `ID`，例如 `debian` / `ubuntu`。
    pub distro: String,
    /// `/etc/os-release` 的 `VERSION_ID`，可能为空（滚动发行版）。
    pub distro_version: String,
    pub systemd: bool,
    pub openssl: bool,
    pub wireguard_tools: bool,
    /// `/etc/wireguard` 目录是否存在（有过 WireGuard 配置的机器上通常存在）。
    pub wireguard_dir: bool,
    /// 这条线路的隧道状态；`None` = 这台服务器上还没有对应的隧道（没部署或接口名对不上）。
    pub tunnel: Option<TunnelStatus>,
    /// 是否装了 docker。Docker 会把 FORWARD 策略改成 DROP——隧道能握手但上不了网，
    /// 十有八九是它。
    pub docker: bool,
    /// `iptables -S FORWARD` 的策略（`ACCEPT` / `DROP` / `unknown`）。
    pub forward_policy: String,
    /// ufw 的状态：`active` / `inactive` / `absent`。
    ///
    /// 云主机上 ufw 开着而没放行 UDP 端口，是最常见的「服务器起来了但连不上」。
    /// 本程序**不改**别人的防火墙，只如实报出来让人自己放行。
    pub ufw: String,
}

/// 隧道在服务器那边的真实状态。握手时间与收发字节是判断「通不通」的硬证据：
/// 握手 0 说明对端根本没握上（UDP 被拦 / 密钥不对），有握手但 RX 不涨说明回程没通。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelStatus {
    pub up: bool,
    /// `wg show latest-handshakes` 的秒数（0 = 从未握手）。
    pub latest_handshake: i64,
    pub peers: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// 服务端看到的对端地址（`ip:port`）。空 = 对端还没从任何地址连上来。
    pub peer_endpoint: String,
    /// `wg show <iface>` 的原文（诊断用）。只在读数自相矛盾时展示。
    pub raw: String,
    /// 逐台设备。界面「服务器与设备」靠它列出「谁在这条隧道上」。
    pub devices: Vec<PeerInfo>,
}

/// 服务端看到的一台设备（`wg show dump` 的一行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// 隧道内地址，例如 `10.66.0.2/32`。
    pub address: String,
    /// WireGuard 公钥（base64，44 位）。
    pub public_key: String,
    /// 最近握手（unix 秒，0 = 从未）。
    pub handshake: i64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// 服务端看到的对端地址；`(none)` = 还没从任何地址连上来。
    pub endpoint: String,
}

impl PeerInfo {
    /// 隧道地址去掉掩码：界面上写 `10.66.0.2` 比 `10.66.0.2/32` 好读。
    pub fn host(&self) -> &str {
        self.address.split('/').next().unwrap_or(&self.address)
    }
}

impl Environment {
    /// 能不能在这台机器上部署。返回 `None` = 可以，`Some(原因)` = 不行。
    ///
    /// 判据刻意少而硬：只挡「一定装不上」的情况。缺 openssl/wg 属于**要装的东西**，
    /// 由部署步骤处理，不在这里判死。
    pub fn blocking_reason(&self) -> Option<String> {
        if self.kernel != "Linux" {
            return Some(format!("这不是 Linux 服务器（内核：{}）", self.kernel));
        }
        if self.uid != 0 {
            return Some(format!(
                "当前账户不是 root（uid={}）。部署要写 /etc/wireguard 并启用系统服务，请用 root 或 sudo 账户。",
                self.uid
            ));
        }
        if !self.systemd {
            return Some("这台服务器没有 systemd，本版的部署脚本不支持其它 init 系统。".to_string());
        }
        None
    }

    /// 给用户看的一段话。每一项都写清楚「有没有」，不猜。
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "系统：{} {}（{}）",
            if self.distro.is_empty() { "未知发行版" } else { &self.distro },
            if self.distro_version.is_empty() { "" } else { &self.distro_version },
            self.arch
        ));
        lines.push(format!(
            "权限：{}",
            if self.uid == 0 { "root".to_string() } else { format!("uid={}（不是 root）", self.uid) }
        ));
        lines.push(format!("systemd：{}", yes_no(self.systemd)));
        lines.push(format!("openssl：{}", yes_no(self.openssl)));
        lines.push(format!("WireGuard 工具（wg）：{}", yes_no(self.wireguard_tools)));
        lines.push(format!("已有 /etc/wireguard 目录：{}", yes_no(self.wireguard_dir)));
        match &self.tunnel {
            None => lines.push("隧道：这台服务器上还没有对应接口（未部署，或接口名对不上）。".to_string()),
            Some(status) if !status.up => lines.push("隧道：接口不存在（服务没起来）。".to_string()),
            Some(status) => {
                let handshake = if status.latest_handshake <= 0 {
                    "从未握手".to_string()
                } else {
                    format!("最近握手于 {}", stamp(status.latest_handshake))
                };
                lines.push(format!(
                    "隧道：运行中，{}，peer {}，收 {} / 发 {} 字节{}",
                    handshake,
                    status.peers,
                    status.rx_bytes,
                    status.tx_bytes,
                    if status.peer_endpoint.is_empty() {
                        String::new()
                    } else {
                        format!("，对端 {}", status.peer_endpoint)
                    }
                ));
                // 逐台设备。界面「服务器与设备」用的也是这份数据，所以命令行
                // 与界面看到的是同一件事——两边各算一遍迟早会给出不同的答案。
                for device in &status.devices {
                    let last = if device.handshake <= 0 {
                        "从未握手".to_string()
                    } else {
                        format!("最近握手于 {}", stamp(device.handshake))
                    };
                    lines.push(format!(
                        "  设备 {}：{}，{}，收 {} / 发 {} 字节{}",
                        device.host(),
                        short_key(&device.public_key),
                        last,
                        device.rx_bytes,
                        device.tx_bytes,
                        if device.endpoint.is_empty() || device.endpoint == "(none)" {
                            String::new()
                        } else {
                            format!("，对端 {}", device.endpoint)
                        }
                    ));
                }
                // 读数自相矛盾（有流量但握手 0）时把原文附上：那说明我对 `wg dump`
                // 的理解有问题，藏着只会让人继续猜。
                if status.latest_handshake <= 0 && status.rx_bytes > 0 && !status.raw.is_empty() {
                    lines.push(format!("  wg 原文：\n{}", indent(&status.raw)));
                }
            }
        }
        if self.forward_policy.eq_ignore_ascii_case("DROP") {
            lines.push(format!(
                "转发策略：FORWARD={}（{}）—— 隧道的包会在转发链被丢掉，需要在转发链里放行。",
                self.forward_policy,
                if self.docker { "docker 装在本机，通常是它设的" } else { "不是默认值" }
            ));
        } else {
            lines.push(format!("转发策略：FORWARD={}", self.forward_policy));
        }
        match self.ufw.as_str() {
            "active" => lines.push(
                "防火墙：ufw 已启用 —— 部署后需要在云服务器或 ufw 里放行本线路的 UDP 端口，否则连不上。"
                    .to_string(),
            ),
            "inactive" => lines.push("防火墙：ufw 已安装但未启用。".to_string()),
            "absent" => lines.push("防火墙：本机没有 ufw（云平台安全组仍可能拦 UDP）。".to_string()),
            other => lines.push(format!("防火墙：状态未知（{other}）。")),
        }
        match self.blocking_reason() {
            None => lines.push("结论：可以部署。".to_string()),
            Some(reason) => lines.push(format!("结论：不能部署——{reason}")),
        }
        lines.join("\n")
    }
}

/// 公钥只露前 8 位。完整公钥在界面上没有意义，截图和工单里还会把设备身份带出去。
fn short_key(key: &str) -> String {
    let mut text: String = key.chars().take(8).collect();
    if key.chars().count() > 8 {
        text.push('…');
    }
    text
}

/// 给多行文本加两个空格缩进（嵌在摘要里用）。
fn indent(text: &str) -> String {
    text.lines().map(|line| format!("    {line}")).collect::<Vec<_>>().join("\n")
}

/// 把 unix 秒数写成 UTC 时间。手写而不是引格式化库：只需要一种形状，
/// 而 `time` 的格式化特性没在本仓启用。
fn stamp(unix: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(unix) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute()
        ),
        Err(_) => "未知时间".to_string(),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "有"
    } else {
        "没有"
    }
}

/// 一次往返拿全部信息。**不要拆成多条命令**：每条都是一次 SSH 通道，
/// 逐条问会把「检查环境」拖到十几秒，而这一步在向导里是要等用户的。
///
/// `command -v` 失败不写 stderr（重定向到 /dev/null），否则某些发行版会把
/// `command not found` 混进 stderr，让「检查通过但有噪音」看起来像失败。
pub const INSPECT_SCRIPT: &str = r#"LC_ALL=C
echo "TC_KERNEL=$(uname -s 2>/dev/null)"
echo "TC_ARCH=$(uname -m 2>/dev/null)"
echo "TC_UID=$(id -u 2>/dev/null)"
echo "TC_DISTRO=$(. /etc/os-release 2>/dev/null; echo ${ID:-unknown})"
echo "TC_VERSION=$(. /etc/os-release 2>/dev/null; echo ${VERSION_ID:-})"
echo "TC_SYSTEMD=$(command -v systemctl >/dev/null 2>&1 && echo yes || echo no)"
echo "TC_OPENSSL=$(command -v openssl >/dev/null 2>&1 && echo yes || echo no)"
echo "TC_WG=$(command -v wg >/dev/null 2>&1 && echo yes || echo no)"
echo "TC_WGDIR=$(test -d /etc/wireguard && echo yes || echo no)"
if command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | head -1 | grep -q '^Status: active'; then echo "TC_UFW=active"; else echo "TC_UFW=inactive"; fi
else
  echo "TC_UFW=absent"
fi
echo "TC_DOCKER=$(command -v docker >/dev/null 2>&1 && echo yes || echo no)"
FW_POLICY=$(iptables -S FORWARD 2>/dev/null | head -1 | sed -n 's/.*-P FORWARD \([A-Z]*\).*/\1/p')
echo "TC_FORWARD_POLICY=${FW_POLICY:-unknown}"
"#;

/// 隧道状态那一段：只在知道接口名时追加（不知道就别问，问了也只会得到「down」）。
///
/// 用一次 `wg show <iface> dump` 取全，而不是分别调 `latest-handshakes` / `transfer`：
/// 多次调用之间状态会变（握手随时可能刷新），分开取会出现「有流量但握手 0」这种
/// 自相矛盾的读数——那正是第一版踩到的坑。
fn tunnel_probe(interface: &str) -> String {
    format!(
        r#"
IFACE_PROBE='{interface}'
DUMP=$(wg show "$IFACE_PROBE" dump 2>/dev/null) || DUMP=''
if [ -n "$DUMP" ]; then
  echo "TC_TUNNEL=up"
  echo "TC_LISTEN=$(printf '%s\n' "$DUMP" | awk 'NR==1 {{print $3}}')"
  echo "TC_PEERS=$(printf '%s\n' "$DUMP" | awk 'NR>1' | wc -l | tr -d ' ')"
  echo "TC_HANDSHAKE=$(printf '%s\n' "$DUMP" | awk 'NR==2 {{print $5}}')"
  echo "TC_RX=$(printf '%s\n' "$DUMP" | awk 'NR>1 {{s+=$6}} END {{print s+0}}')"
  echo "TC_TX=$(printf '%s\n' "$DUMP" | awk 'NR>1 {{s+=$7}} END {{print s+0}}')"
  echo "TC_PEER_ENDPOINT=$(printf '%s\n' "$DUMP" | awk 'NR==2 {{print $3}}')"
  # 每台设备一行：地址|公钥|最近握手|收|发|对端。
  # 用 `|` 分隔而不是空格：endpoint 里可能有冒号，公钥里没有 `|`。
  printf '%s\n' "$DUMP" | awk 'NR>1 {{print "TC_WG_PEER=" $4 "|" $1 "|" $5 "|" $6 "|" $7 "|" $3}}'
  echo "TC_WG_RAW=$(wg show "$IFACE_PROBE" 2>/dev/null | base64 -w0 2>/dev/null || echo '')"
else
  echo "TC_TUNNEL=down"
fi
"#
    )
}

/// 拼出这次要跑的检查脚本。`interface` 来自服务器记录（`Spec::for_record`），
/// 有它才能顺带读一次隧道状态。
pub fn inspect_script(interface: Option<&str>) -> String {
    let mut text = INSPECT_SCRIPT.to_string();
    if let Some(interface) = interface {
        text.push_str(&tunnel_probe(interface));
    }
    text.push_str("echo \"TC_DONE=1\"\n");
    text
}

/// 解析检查输出。缺字段一律报错：**静默补默认值会把「没读到」变成「不支持」**。
pub fn parse_inspect(stdout: &str) -> Result<Environment, String> {
    let mut kernel = None;
    let mut arch = None;
    let mut uid = None;
    let mut distro = None;
    let mut version = None;
    let mut systemd = None;
    let mut openssl = None;
    let mut wg = None;
    let mut wgdir = None;
    let mut ufw = None;
    let mut tunnel_up = None;
    let mut handshake = None;
    let mut peers = None;
    let mut rx = None;
    let mut tx = None;
    let mut peer_endpoint = None;
    let mut docker = None;
    let mut forward_policy = None;
    let mut wg_raw = None;
    let mut devices: Vec<PeerInfo> = Vec::new();
    let mut done = false;

    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim().to_string();
        match key {
            "TC_KERNEL" => kernel = Some(value),
            "TC_ARCH" => arch = Some(value),
            "TC_UID" => {
                uid = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| format!("服务器返回的 uid 不是数字：{value}"))?,
                )
            }
            "TC_DISTRO" => distro = Some(value),
            "TC_VERSION" => version = Some(value),
            "TC_SYSTEMD" => systemd = Some(flag(&value)?),
            "TC_OPENSSL" => openssl = Some(flag(&value)?),
            "TC_WG" => wg = Some(flag(&value)?),
            "TC_WGDIR" => wgdir = Some(flag(&value)?),
            "TC_UFW" => {
                if !matches!(value.as_str(), "active" | "inactive" | "absent") {
                    return Err(format!("环境检查返回了不认识的防火墙状态：{value}"));
                }
                ufw = Some(value);
            }
            "TC_TUNNEL" => {
                if !matches!(value.as_str(), "up" | "down") {
                    return Err(format!("环境检查返回了不认识的隧道状态：{value}"));
                }
                tunnel_up = Some(value == "up");
            }
            "TC_HANDSHAKE" => handshake = Some(value.parse::<i64>().unwrap_or(0)),
            "TC_PEERS" => peers = Some(value.parse::<u32>().unwrap_or(0)),
            "TC_RX" => rx = Some(value.parse::<u64>().unwrap_or(0)),
            "TC_TX" => tx = Some(value.parse::<u64>().unwrap_or(0)),
            "TC_PEER_ENDPOINT" => peer_endpoint = Some(value),
            "TC_WG_PEER" => {
                let parts: Vec<&str> = value.split('|').collect();
                if parts.len() != 6 {
                    return Err(format!("设备行格式不对（应为 6 段）：{value}"));
                }
                devices.push(PeerInfo {
                    address: parts[0].to_string(),
                    public_key: parts[1].to_string(),
                    handshake: parts[2].parse().unwrap_or(0),
                    rx_bytes: parts[3].parse().unwrap_or(0),
                    tx_bytes: parts[4].parse().unwrap_or(0),
                    endpoint: parts[5].to_string(),
                });
            }
            "TC_DOCKER" => docker = Some(flag(&value)?),
            "TC_WG_RAW" => {
                use base64::Engine;
                wg_raw = base64::engine::general_purpose::STANDARD
                    .decode(value.as_bytes())
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
            }
            "TC_FORWARD_POLICY" => forward_policy = Some(value),
            "TC_DONE" => done = value == "1",
            _ => {}
        }
    }

    if !done {
        return Err(
            "环境检查没有跑完（服务器没有返回结束标记）：可能被截断，请重试。".to_string()
        );
    }
    let missing = |name: &str| format!("环境检查缺少 {name}：服务器可能不是标准的 Linux。");
    Ok(Environment {
        kernel: kernel.ok_or_else(|| missing("内核"))?,
        arch: arch.ok_or_else(|| missing("架构"))?,
        uid: uid.ok_or_else(|| missing("uid"))?,
        distro: distro.ok_or_else(|| missing("发行版"))?,
        distro_version: version.ok_or_else(|| missing("发行版版本"))?,
        systemd: systemd.ok_or_else(|| missing("systemd"))?,
        openssl: openssl.ok_or_else(|| missing("openssl"))?,
        wireguard_tools: wg.ok_or_else(|| missing("WireGuard 工具"))?,
        wireguard_dir: wgdir.ok_or_else(|| missing("WireGuard 目录"))?,
        tunnel: tunnel_up.map(|up| TunnelStatus {
            up,
            latest_handshake: handshake.unwrap_or(0),
            peers: peers.unwrap_or(0),
            rx_bytes: rx.unwrap_or(0),
            tx_bytes: tx.unwrap_or(0),
            peer_endpoint: peer_endpoint.unwrap_or_default(),
            raw: wg_raw.unwrap_or_default(),
            devices,
        }),
        docker: docker.ok_or_else(|| missing("docker 状态"))?,
        forward_policy: forward_policy.ok_or_else(|| missing("FORWARD 策略"))?,
        ufw: ufw.ok_or_else(|| missing("防火墙状态"))?,
    })
}

fn flag(value: &str) -> Result<bool, String> {
    match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(format!("环境检查返回了不认识的是/否值：{other}")),
    }
}

/// 连上去做一次检查。`expected` 为 `None` 时只会拿到指纹（[`Error::HostKeyUnknown`]），
/// **不会发送密码**。
pub fn inspect<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: Option<&str>,
    interface: Option<&str>,
    timeout: Duration,
) -> Result<Environment, Error> {
    let auth = auth.into();
    let script = inspect_script(interface);
    let output = ssh::exec(target, auth, expected, &script, timeout)?;
    if output.truncated {
        return Err(Error::Command("环境检查的输出被截断，未采用".to_string()));
    }
    if output.code != 0 {
        let detail = output.stderr.trim();
        return Err(Error::Command(if detail.is_empty() {
            format!("环境检查退出码 {}", output.code)
        } else {
            format!("环境检查退出码 {}：{detail}", output.code)
        }));
    }
    parse_inspect(&output.stdout).map_err(Error::Command)
}

// ---------- 只读核对：标准连接到底生效没有 ----------

/// 标准连接的只读状态。四个问题，一条命令回答完。
///
/// 为什么不能复用 [`inspect`]：它只回答「接口在不在」（`TC_TUNNEL=up/down`），
/// 看不到 conf 是否存在、unit 是否 active、监听端口是多少。缺这三项就没法把
/// 「明确未生效」和「结果仍未知」分开，只能一律判 Unknown —— 那太保守，用户会被
/// 卡在一步上永远走不下去。
///
/// **只读**：不写文件、不重启服务、不下载。可以随时重跑。
///
/// **不含任何秘密**：`wg show <iface> dump` 的第一行第一个字段就是服务端私钥，
/// 所以脚本只取第三字段（监听端口）与 peer 公钥，绝不回传整份 dump。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpState {
    /// 接口在、`wg` 能读到它（`wg show <iface> dump` 有输出）。
    pub tunnel_up: bool,
    /// `/etc/wireguard/<iface>.conf` 存在。
    pub conf_present: bool,
    /// `wg-quick@<iface>` 这个 unit 现在是不是 active。
    pub unit_active: bool,
    /// 接口的监听端口。`None` = 没读到（接口没起、或读不出来），**不是 0**。
    pub listen_port: Option<u16>,
    /// 接口上已经登记的 peer 公钥（**公钥**，不是私钥）。
    pub peers: Vec<String>,
}

impl UdpState {
    /// 计划里的端口是不是真的在监听。三个条件同时成立才算「生效」。
    ///
    /// 下面三个判据的调用方是部署引擎（T03 的「结果未知处置矩阵」）。T02 只把
    /// 探针与解析做出来并用假输出验过，所以本阶段这三个方法标为未使用。
    #[allow(dead_code)]
    pub fn matches_plan(&self, udp_port: u16) -> bool {
        self.tunnel_up && self.listen_port == Some(udp_port)
    }

    /// 「明确没生效」：三个否定条件**同时**成立才敢这么说。
    ///
    /// 只要有一条不成立（典型是 conf 在、接口却 down —— 服务没起来），
    /// 就只能是「不知道」，不能顺手当失败去重装。
    #[allow(dead_code)]
    pub fn clearly_not_applied(&self) -> bool {
        !self.tunnel_up && !self.conf_present && !self.unit_active
    }

    /// 设备列表里有没有这把公钥。
    #[allow(dead_code)]
    pub fn has_peer(&self, public_key: &str) -> bool {
        let wanted = public_key.trim();
        !wanted.is_empty() && self.peers.iter().any(|item| item == wanted)
    }
}

/// 只读核对脚本。`@@IFACE@@` 由 [`udp_state_script`] 替换。
///
/// 三条硬约束：
/// - `set -eu` 之下每一步都要能失败而不中断（`if` 条件里的失败是安全的）；
/// - `systemctl is-active` 在 inactive 时**返回非 0**，所以只能放在 `if` 里；
/// - 私钥绝不出现：只打印第一行的第三字段与 peer 公钥。
pub const UDP_STATE_SCRIPT: &str = r#"set -eu
IFACE='@@IFACE@@'
CONF="/etc/wireguard/$IFACE.conf"
if [ -f "$CONF" ]; then echo "TC_UDP_CONF=present"; else echo "TC_UDP_CONF=absent"; fi
if systemctl is-active --quiet "wg-quick@$IFACE" >/dev/null 2>&1; then echo "TC_UDP_UNIT=active"; else echo "TC_UDP_UNIT=inactive"; fi
DUMP=$(wg show "$IFACE" dump 2>/dev/null) || DUMP=''
if [ -n "$DUMP" ]; then
  echo "TC_UDP_TUNNEL=up"
  echo "TC_UDP_LISTEN=$(printf '%s\n' "$DUMP" | awk 'NR==1 {print $3}')"
  printf '%s\n' "$DUMP" | awk 'NR>1 {print "TC_UDP_PEER=" $1}'
else
  echo "TC_UDP_TUNNEL=down"
fi
echo "TC_DONE=1"
"#;

/// 拼出这次要跑的核对脚本。接口名先过形状检查：它会被拼进 shell。
pub fn udp_state_script(interface: &str) -> Result<String, String> {
    let name = interface.trim();
    if name.is_empty()
        || name.len() > 15
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(format!("接口名不合法，无法只读核对：{interface}"));
    }
    Ok(UDP_STATE_SCRIPT.replace("@@IFACE@@", name))
}

/// 解析核对输出。
///
/// **缺字段一律报错**（不许默认 `false`）：把「没读到」当成「没有」正是
/// 「把还在装的东西当成没装、然后重装一遍」的来源。
///
/// **表外值不回显**（F4）：这段输出来自远端脚本，把任意文本拼进错误消息，等于给它
/// 开了一条进日志和界面的通道。表外值只可能是脚本被换过，知道是哪一类就够定位了。
pub fn parse_udp_state(stdout: &str) -> Result<UdpState, String> {
    let mut tunnel = None;
    let mut conf = None;
    let mut unit = None;
    let mut listen: Option<Option<u16>> = None;
    let mut peers: Vec<String> = Vec::new();
    let mut done = false;

    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim();
        match key {
            "TC_UDP_TUNNEL" => {
                tunnel = Some(match value {
                    "up" => true,
                    "down" => false,
                    _ => {
                        return Err(
                            "只读核对返回了不认识的隧道状态（只接受 up / down）：可能不是本程序装的脚本。"
                                .to_string(),
                        )
                    }
                })
            }
            "TC_UDP_CONF" => {
                conf = Some(match value {
                    "present" => true,
                    "absent" => false,
                    _ => {
                        return Err(
                            "只读核对返回了不认识的配置状态（只接受 present / absent）：可能不是本程序装的脚本。"
                                .to_string(),
                        )
                    }
                })
            }
            "TC_UDP_UNIT" => {
                unit = Some(match value {
                    "active" => true,
                    "inactive" => false,
                    _ => {
                        return Err(
                            "只读核对返回了不认识的服务状态（只接受 active / inactive）：可能不是本程序装的脚本。"
                                .to_string(),
                        )
                    }
                })
            }
            "TC_UDP_LISTEN" => {
                listen = Some(if value.is_empty() {
                    None
                } else {
                    Some(value.parse::<u16>().map_err(|_| {
                        // 只报长度，不回显内容：够判断「是不是被截断了」。
                        format!(
                            "只读核对返回的监听端口不是 0-65535 的整数（{} 个字符）",
                            value.chars().count()
                        )
                    })?)
                })
            }
            "TC_UDP_PEER" => {
                if !value.is_empty() {
                    peers.push(value.to_string());
                }
            }
            "TC_DONE" => done = value == "1",
            _ => {}
        }
    }

    if !done {
        return Err("只读核对没有跑完（服务器没有返回结束标记）：可能被截断，请重试。".to_string());
    }
    let missing = |name: &str| format!("只读核对缺少 {name}：无法判断这一步到底生效没有。");
    Ok(UdpState {
        tunnel_up: tunnel.ok_or_else(|| missing("隧道状态"))?,
        conf_present: conf.ok_or_else(|| missing("配置文件状态"))?,
        unit_active: unit.ok_or_else(|| missing("服务状态"))?,
        listen_port: listen.unwrap_or(None),
        peers,
    })
}

/// 真跑一次只读核对。**一次 SSH 往返**，只读，不改服务器上任何东西。
///
/// `expected` 必须是已确认的指纹：核对也要防中间人，否则「读到的状态」本身就不可信。
///
/// 调用方是 A2/A3 的部署引擎（T03 的 `Ops::probe_udp_state`）；T02 只把它做出来
/// 并用假输出验过解析，所以本阶段暂时标为未使用。
#[allow(dead_code)]
pub fn probe_udp_state<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    interface: &str,
    timeout: Duration,
) -> Result<UdpState, Error> {
    let auth = auth.into();
    let script = udp_state_script(interface).map_err(Error::Command)?;
    let output = ssh::exec(target, auth, Some(expected), &script, timeout)?;
    if output.truncated {
        return Err(Error::Command("只读核对的输出被截断，未采用".to_string()));
    }
    if output.code != 0 {
        let detail = output.stderr.trim();
        return Err(Error::Command(if detail.is_empty() {
            format!("只读核对退出码 {}", output.code)
        } else {
            format!("只读核对退出码 {}：{detail}", output.code)
        }));
    }
    parse_udp_state(&output.stdout).map_err(Error::Command)
}

// ---------- 客户端接入：把本机变成这台服务器的一个 peer ----------

/// 客户端在隧道里的地址。服务端是网段首 +1（`10.66.0.1`），客户端从 +2 起。
pub const CLIENT_ADDRESS: &str = "10.66.0.2";

/// 在服务端配置里写入本机这个 peer，**不断开已有连接**。
///
/// 两条都是硬要求，不是优化：
/// - **按公钥增删**，不是整段替换。整段替换会把别人的设备一起删掉，而受害者只会
///   看到「另一台电脑突然连不上」，根本查不到原因。
/// - **`wg syncconf` 热更新**，不是重启接口。重启会让所有正在连的设备同时掉线；
///   旧版的 `WireGuardSync` + `wg syncconf` 就是同一套做法。
///
/// `wg-quick strip` 负责把主配置转成 syncconf 的格式（去掉 Address/MTU/Table 这些
/// 只对 `wg-quick up` 有意义的字段），再交给 `wg syncconf` 应用差异。
pub fn peer_script(spec: &Spec, client_public: &str) -> String {
    let Spec { interface, .. } = spec;
    format!(
        r#"set -eu
{fence}umask 077
IFACE='{interface}'
CONF="/etc/wireguard/$IFACE.conf"
KEY="/etc/wireguard/$IFACE.key"
SYNC="/etc/wireguard/$IFACE.sync.conf"
PUB='{client_public}'
CLIENT_IP='{client_ip}/32'
fail() {{ echo "TC_ERROR=$1"; exit 1; }}

[ "${{#PUB}}" -eq 44 ] || fail InvalidClientKey
case "$PUB" in *[!A-Za-z0-9+/=]*) fail InvalidClientKey ;; esac
[ -f "$CONF" ] || fail NoServerConfig
[ -f "$KEY" ] || fail NoServerKey

# 1) 主配置：只替换**同一个公钥**的旧段，别的 peer 一个都不动。
# 以前这里是「整段重写 [Peer]」，结果第二台设备接入会把第一台挤掉。
TMP="$CONF.tcnew"
awk -v pub="$PUB" -v ip="$CLIENT_IP" '
BEGIN {{ RS=""; ORS="\n\n" }}
{{
  if ($0 ~ /^\[Peer\]/) {{
    if (match($0, /PublicKey[ \t]*=[ \t]*[^ \t\r\n]+/)) {{
      k = substr($0, RSTART, RLENGTH)
      sub(/^[^=]*=[ \t]*/, "", k)
      if (k == pub) next
    }}
  }}
  print
}}
END {{ printf "[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", pub, ip }}
' "$CONF" > "$TMP"
mv "$TMP" "$CONF"
chmod 600 "$CONF"

# 2) 热更新：`wg syncconf` 只应用差异，**不重启接口**。
# 重启会让所有正在连的设备同时掉线——加一台设备不该把别人踢掉。
wg-quick strip "$IFACE" > "$SYNC" || fail SyncConfigFailed
chmod 600 "$SYNC"
if wg show "$IFACE" >/dev/null 2>&1; then
  wg syncconf "$IFACE" "$SYNC" || fail PeerSyncFailed
else
  # 接口没起：配置已经写好了，起来时自然带上这个 peer。
  systemctl start "wg-quick@$IFACE" || {{
    journalctl -u "wg-quick@$IFACE" -n 20 --no-pager 2>&1 | tail -20 >&2
    fail TunnelStartFailed
  }}
fi

# 3) 后置：peer 必须真的在接口上——不能只看命令退出码。
wg show "$IFACE" peers | grep -qx "$PUB" || fail PeerMissing

echo "TC_PEER=$PUB"
echo "TC_SERVER_PUBLIC=$(printf '%s' "$(cat "$KEY")" | wg pubkey)"
echo "TC_DONE=1"
"#,
        client_ip = CLIENT_ADDRESS,
        fence = crate::legacy_writer_fence::SHELL_DENY_PRELUDE,
    )
}

/// peer 脚本的结果：服务端确认收到的客户端公钥，以及服务端自己的公钥
/// （客户端配置要用后者，而它只在服务器上算得出来）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAck {
    pub client_public: String,
    pub server_public: String,
}

pub fn parse_peer(stdout: &str) -> Result<PeerAck, String> {
    let mut peer = None;
    let mut server_public = None;
    let mut done = false;
    let mut failure = None;
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim().to_string();
        match key {
            "TC_PEER" => peer = Some(value),
            "TC_SERVER_PUBLIC" => server_public = Some(value),
            "TC_DONE" => done = value == "1",
            "TC_ERROR" => failure = Some(value),
            _ => {}
        }
    }
    if let Some(code) = failure {
        return Err(format!("服务器没有接受这台电脑：{code}"));
    }
    if !done {
        return Err("写入 peer 的脚本没有跑完（没有结束标记）：可能被截断，请重试。".to_string());
    }
    let client_public = peer.ok_or_else(|| "服务器没有回报已登记的客户端公钥。".to_string())?;
    let server_public =
        server_public.ok_or_else(|| "服务器没有回报自己的公钥。".to_string())?;
    Ok(PeerAck { client_public, server_public })
}

/// 真执行：把客户端公钥写进服务端配置并重启隧道。
pub fn add_peer<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    spec: &Spec,
    client_public: &str,
    timeout: Duration,
) -> Result<PeerAck, Error> {
    let auth = auth.into();
    spec.validate().map_err(Error::Command)?;
    let output = ssh::exec(
        target,
        auth,
        Some(expected),
        &peer_script(spec, client_public),
        timeout,
    )?;
    match parse_peer(&output.stdout) {
        Ok(ack) => Ok(ack),
        Err(message) => {
            let mut detail = message;
            let stderr = output.stderr.trim();
            if !stderr.is_empty() {
                let total = stderr.chars().count();
                let mut tail: String = stderr.chars().skip(total.saturating_sub(2000)).collect();
                if total > 2000 {
                    tail.insert_str(0, "…（前面已截断）\n");
                }
                detail.push_str("\n--- 服务器上的最后输出 ---\n");
                detail.push_str(&tail);
            }
            Err(Error::Command(detail))
        }
    }
}

/// 从 WireGuard 配置里按公钥删掉一个 `[Peer]` 段，其它段原样保留。
///
/// 抽成常量是为了**能单独测**：真机上跑一次改 peer 的脚本代价很大，而
/// 「删谁、留谁」全靠这段 awk。脚本里它仍然内联执行（单引号包裹，内容里不能有单引号）。
const DROP_PEER_AWK: &str = r#"BEGIN { RS=""; ORS="\n\n" }
{
  if ($0 ~ /^\[Peer\]/) {
    if (match($0, /PublicKey[ \t]*=[ \t]*[^ \t\r\n]+/)) {
      k = substr($0, RSTART, RLENGTH)
      sub(/^[^=]*=[ \t]*/, "", k)
      if (k == pub) next
    }
  }
  print
}"#;

/// 撤销一台设备的接入权：从服务端配置里删掉**这一个公钥**的 `[Peer]` 段，然后热应用。
///
/// 与加 peer 同一条纪律：
/// - 只按公钥删自己那一段，别人的一个都不动（用 `awk` 按 `[Peer]` 分段比对，不做整段重写）；
/// - `wg syncconf` 热更新，**不重启** `wg-quick@`（重启会把所有在线设备一起踢掉）；
/// - 删完要**回读确认**接口上真的没有了，不能只看命令退出码。
///
/// 三条拒绝：不删服务器自己的密钥（删了整条隧道就没了）、不删不存在的 peer
/// （否则「成功」是假的）、配置里还残留这个公钥就中止（宁可不改也不写坏配置）。
pub fn revoke_script(spec: &Spec, public_key: &str) -> String {
    let Spec { interface, .. } = spec;
    format!(
        r#"set -eu
{fence}umask 077
IFACE='{interface}'
CONF="/etc/wireguard/$IFACE.conf"
KEY="/etc/wireguard/$IFACE.key"
SYNC="/etc/wireguard/$IFACE.sync.conf"
PUB='{public_key}'
fail() {{ echo "TC_ERROR=$1"; exit 1; }}

[ "${{#PUB}}" -eq 44 ] || fail InvalidClientKey
case "$PUB" in *[!A-Za-z0-9+/=]*) fail InvalidClientKey ;; esac
[ -f "$CONF" ] || fail NoServerConfig
[ -f "$KEY" ] || fail NoServerKey
wg show "$IFACE" >/dev/null 2>&1 || fail NoInterface

# 服务器自己的公钥绝不能删：删了之后所有设备都连不上，而且改回来要重配服务端。
SERVER_PUB=$(wg show "$IFACE" public-key 2>/dev/null || printf '%s' "$(cat "$KEY")" | wg pubkey)
[ "$PUB" = "$SERVER_PUB" ] && fail RefuseServerKey

# 不在接口上的 peer 直接拒绝：没有可删的东西时，「成功」只会让人以为已经撤销了。
wg show "$IFACE" peers | grep -qx "$PUB" || fail PeerNotFound

TMP="$CONF.tcnew"
awk -v pub="$PUB" '{drop_peer_awk}' "$CONF" > "$TMP"

# 双保险：新配置里不许再出现这个公钥。awk 失手时宁可保留原配置也不写坏它。
if grep -q "$PUB" "$TMP"; then rm -f "$TMP"; fail ConfigStillHasPeer; fi
mv "$TMP" "$CONF"
chmod 600 "$CONF"

wg-quick strip "$IFACE" > "$SYNC" || fail SyncConfigFailed
chmod 600 "$SYNC"
wg syncconf "$IFACE" "$SYNC" || fail PeerSyncFailed

# 后置：接口上必须真的没有了（配置改了但没同步，是最容易漏的一种）。
if wg show "$IFACE" peers | grep -qx "$PUB"; then fail PeerStillConnected; fi
PEERS=$(wg show "$IFACE" peers | wc -l | tr -d ' ')
echo "TC_REVOKED=$PUB"
echo "TC_PEERS=$PEERS"
echo "TC_DONE=1"
"#,
        drop_peer_awk = DROP_PEER_AWK,
        fence = crate::legacy_writer_fence::SHELL_DENY_PRELUDE,
    )
}

/// 撤销脚本的结果：被移除的公钥，以及服务器上还剩几台设备。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAck {
    pub public_key: String,
    pub peers: u32,
}

/// 解析撤销脚本的输出。失败码翻译成一句能照做的话——`PeerNotFound` 与
/// `PeerStillConnected` 对用户来说是完全不同的两件事。
pub fn parse_revoke(stdout: &str) -> Result<RevokeAck, String> {
    let mut revoked = None;
    let mut peers = None;
    let mut done = false;
    let mut failure = None;
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim().to_string();
        match key {
            "TC_REVOKED" => revoked = Some(value),
            "TC_PEERS" => peers = value.parse::<u32>().ok(),
            "TC_DONE" => done = value == "1",
            "TC_ERROR" => failure = Some(value),
            _ => {}
        }
    }
    if let Some(code) = failure {
        let human = match code.as_str() {
            "PeerNotFound" => "这台设备已经不在服务器上了（可能已经被移除过）".to_string(),
            "RefuseServerKey" => "不能移除服务器自己的密钥——那会让整条隧道失效".to_string(),
            "NoInterface" => "服务器上的隧道没有起来，等它恢复后再试".to_string(),
            "ConfigStillHasPeer" => "新配置里仍有这台设备，已中止（服务器配置未改动）".to_string(),
            "PeerStillConnected" => "配置已更新，但接口上仍能看到这台设备；请重试一次".to_string(),
            other => format!("服务器返回 {other}"),
        };
        return Err(format!("没有移除这台设备：{human}"));
    }
    if !done {
        return Err("撤销脚本没有跑完（没有结束标记）：可能被截断，请重试。".to_string());
    }
    let public_key = revoked.ok_or_else(|| "服务器没有回报被移除的公钥。".to_string())?;
    let peers = peers.ok_or_else(|| "服务器没有回报剩余设备数。".to_string())?;
    Ok(RevokeAck { public_key, peers })
}

/// 真执行：把一台设备从服务端摘掉，并热应用配置。
pub fn revoke_peer<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    spec: &Spec,
    public_key: &str,
    timeout: Duration,
) -> Result<RevokeAck, Error> {
    let auth = auth.into();
    spec.validate().map_err(Error::Command)?;
    let output = ssh::exec(
        target,
        auth,
        Some(expected),
        &revoke_script(spec, public_key),
        timeout,
    )?;
    match parse_revoke(&output.stdout) {
        Ok(ack) => Ok(ack),
        Err(message) => {
            let mut detail = message;
            let stderr = output.stderr.trim();
            if !stderr.is_empty() {
                let total = stderr.chars().count();
                let mut tail: String = stderr.chars().skip(total.saturating_sub(2000)).collect();
                if total > 2000 {
                    tail.insert_str(0, "…（前面已截断）\n");
                }
                detail.push_str("\n--- 服务器上的最后输出 ---\n");
                detail.push_str(&tail);
            }
            Err(Error::Command(detail))
        }
    }
}

/// 卸载脚本：停并移除本工具在这台服务器上的通道服务与规则。
///
/// **保留**：`/etc/tradechannel/transport.env`（REALITY 身份）、
/// `/var/lib/tradechannel/pairing-rs`（管理身份与审计）、`/usr/lib/tradechannel`
/// （组件）。所以重新部署不用重下组件，邀请身份也不会换——旧版
/// `uninstall` 同样是「保留审计和身份」。
///
/// **移除**：transport 单元、`tc-pair` 单元、WireGuard 配置与私钥、
/// transport 配置；WireGuard 接口会被 down 掉。云服务器不会被释放。
pub fn uninstall_script(spec: &Spec) -> String {
    format!(
        r#"set -eu
{fence}IFACE='{interface}'
CONF_DIR='{conf_dir}'
fail() {{ echo "TC_ERROR=$1"; shift; printf '%s\n' "$*" >&2; exit 1; }}
[ "$(id -u)" = 0 ] || fail NotRoot '需要 root 权限。'
command -v systemctl >/dev/null 2>&1 || fail NoSystemd '需要 systemd。'

TRANSPORT_REMOVED=0
if [ -f "/etc/systemd/system/$IFACE-transport.service" ]; then
  systemctl disable --now "$IFACE-transport.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$IFACE-transport.service"
  TRANSPORT_REMOVED=1
fi
INVITE_REMOVED=0
if [ -f "/etc/systemd/system/tc-pair.service" ]; then
  systemctl disable --now tc-pair.service >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/tc-pair.service"
  INVITE_REMOVED=1
fi
systemctl daemon-reload >/dev/null 2>&1 || true

if command -v wg-quick >/dev/null 2>&1; then
  wg-quick down "$IFACE" >/dev/null 2>&1 || true
fi
systemctl disable --now "wg-quick@$IFACE" >/dev/null 2>&1 || true
rm -f "/etc/wireguard/$IFACE.conf" "/etc/wireguard/$IFACE.key" "/etc/wireguard/$IFACE.sync.conf"
rm -f "$CONF_DIR/transport.json"

if [ -e "/sys/class/net/$IFACE" ]; then IFACE_PRESENT=1; else IFACE_PRESENT=0; fi
echo "TC_TRANSPORT_REMOVED=$TRANSPORT_REMOVED"
echo "TC_INVITE_REMOVED=$INVITE_REMOVED"
echo "TC_INTERFACE_PRESENT=$IFACE_PRESENT"
echo "TC_DONE=1"
"#,
        interface = spec.interface,
        conf_dir = TRANSPORT_CONF_DIR,
        fence = crate::legacy_writer_fence::SHELL_DENY_PRELUDE,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallAck {
    pub transport_removed: bool,
    pub invite_removed: bool,
    pub interface_present: bool,
}

pub fn parse_uninstall(stdout: &str) -> Result<UninstallAck, String> {
    let mut transport = None;
    let mut invite = None;
    let mut present = None;
    let mut done = false;
    let mut failure = None;
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim().to_string();
        match key {
            "TC_TRANSPORT_REMOVED" => transport = Some(value == "1"),
            "TC_INVITE_REMOVED" => invite = Some(value == "1"),
            "TC_INTERFACE_PRESENT" => present = Some(value == "1"),
            "TC_DONE" => done = value == "1",
            "TC_ERROR" => failure = Some(value),
            _ => {}
        }
    }
    if let Some(code) = failure {
        let human = match code.as_str() {
            "NotRoot" => "服务器上的账户不是 root，无法卸载服务".to_string(),
            "NoSystemd" => "这台服务器没有 systemd，本版不支持卸载".to_string(),
            other => format!("服务器返回 {other}"),
        };
        return Err(format!("没有卸载服务器服务：{human}"));
    }
    if !done {
        return Err("卸载脚本没有跑完（没有结束标记）：可能被截断，请重试。".to_string());
    }
    Ok(UninstallAck {
        transport_removed: transport.ok_or_else(|| "服务器没有回报兼容连接是否被移除。".to_string())?,
        invite_removed: invite.ok_or_else(|| "服务器没有回报邀请服务是否被移除。".to_string())?,
        interface_present: present.ok_or_else(|| "服务器没有回报接口是否还在。".to_string())?,
    })
}

/// 真执行卸载。调用方必须**先确认没有活动连接**：接口被 down 掉会立刻断线。
pub fn uninstall<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    spec: &Spec,
    timeout: Duration,
) -> Result<UninstallAck, Error> {
    let auth = auth.into();
    spec.validate().map_err(Error::Command)?;
    let output = ssh::exec(
        target,
        auth,
        Some(expected),
        &uninstall_script(spec),
        timeout,
    )?;
    match parse_uninstall(&output.stdout) {
        Ok(ack) => Ok(ack),
        Err(message) => {
            let mut detail = message;
            let stderr = output.stderr.trim();
            if !stderr.is_empty() {
                let total = stderr.chars().count();
                let mut tail: String = stderr.chars().skip(total.saturating_sub(2000)).collect();
                if total > 2000 {
                    tail.insert_str(0, "…（前面已截断）\n");
                }
                detail.push_str("\n--- 服务器上的最后输出 ---\n");
                detail.push_str(&tail);
            }
            Err(Error::Command(detail))
        }
    }
}

/// 本机的 WireGuard 客户端配置。字段与 `pairing::tunnel::render` 逐项一致，
/// 这样「加入别人的服务器」与「自己搭服务器」两条路写出来的是同一种文件。
pub fn client_conf(spec: &Spec, server_public: &str, host: &str, client_private: &str) -> String {
    format!(
        "[Interface]\r\nPrivateKey = {client_private}\r\nAddress = {address}/32\r\nMTU = {mtu}\r\n\r\n[Peer]\r\nPublicKey = {server_public}\r\nAllowedIPs = 0.0.0.0/0\r\nEndpoint = {host}:{port}\r\nPersistentKeepalive = 25\r\n",
        address = CLIENT_ADDRESS,
        mtu = spec.mtu,
        server_public = server_public,
        host = host,
        port = spec.port,
    )
}

// ───────────────────── 兼容连接：服务端 TCP / REALITY ─────────────────────

/// 官方 sing-box 的固定版本，与旧版的 `transport_support.VERSION` 一致。
///
/// 不跟最新版走：REALITY 的参数语义在版本之间变过，两端各用一版就是「连不上」，
/// 而且那种失败在日志里只表现为握手超时，几乎查不出来。
pub const TRANSPORT_VERSION: &str = "1.14.2";

/// TCP 监听端口。旧版的候选是 443 / 8443 / 2443，默认 8443：
/// 443 容易被本机已有的 web 服务占住，2443 太像「非标准端口」反而显眼。
pub const TRANSPORT_PORT: u16 = 8443;

/// REALITY 的握手 SNI。必须是一个真实存在、支持 TLS 1.3 的站点——
/// REALITY 的伪装就是「让中间设备以为你在访问这个站点」。
pub const TRANSPORT_SERVER_NAME: &str = "www.bing.com";

/// 组件安装目录（与旧版一字对齐，运维习惯和卸载脚本都能对上）。
pub const TRANSPORT_BIN_DIR: &str = "/usr/lib/tradechannel/1.14.2";
/// 身份与配置目录。权限 700：里面有一把 REALITY 私钥。
pub const TRANSPORT_CONF_DIR: &str = "/etc/tradechannel";

/// 官方 release 的固定摘要，取自 旧版的 `transport_support.RELEASES`。
///
/// **不是我们自己算的**：这些值的唯一作用就是「拿到的必须是那一份官方产物」，
/// 自己重新算一遍等于没校验。整包、二进制、运行库三层都要对，因为只校验整包时
/// 包里的成员仍可能被换过（tar 的路径就是攻击面）。
struct Release {
    archive: &'static str,
    binary: &'static str,
    library: &'static str,
    /// ELF 头 `e_machine`：amd64=62、arm64=183。
    elf_machine: u16,
}

const AMD64: Release = Release {
    archive: "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6",
    binary: "fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8",
    library: "23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294",
    elf_machine: 62,
};

const ARM64: Release = Release {
    archive: "b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f",
    binary: "b8610f45abb7e967e195264383f5cbd20fba7821a3c37e3a8c4c5ab6cad28eac",
    library: "3c1fcfcb56261a4b318ffb6d2227b9726782edb5a894e74db2b534406db62498",
    elf_machine: 183,
};

/// 服务端的 REALITY 身份。**生成一次、长期复用**：它变了，所有已接入设备的
/// 线路参数同时失效，而客户端只会表现成「连不上」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIdentity {
    /// base64url（43 位、无填充）。REALITY 只认这个形状，标准 base64 的 `=` 和 `+/` 都不行。
    pub private_key: String,
    pub public_key: String,
    /// 16 位十六进制（8 字节）。旧版的 `transport_support` 也是 `os.urandom(8).hex()`。
    pub short_id: String,
    pub uuid: String,
    pub port: u16,
    pub server_name: String,
}

/// 把标准 base64（44 位带 `=`）转成 REALITY 要的 base64url（43 位无填充）。
///
/// 密钥本身是同一串 32 字节，只是编码不同。**必须解码再编码**，不能做字符串替换：
/// 标准 base64 的 `+` `/` 与 url-safe 的 `-` `_` 不是一一对应（填充位置也不同）。
fn url_key(standard_b64: &str) -> Result<String, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(standard_b64.trim())
        .map_err(|_| "密钥不是合法的 base64。".to_string())?;
    if raw.len() != 32 {
        return Err(format!("密钥长度不是 32 字节（收到 {}）。", raw.len()));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// 生成一份新的服务端身份。**只在服务器上还没有身份时才会被采用**
/// （脚本里有身份就复用，忽略这里生成的）。
pub fn new_identity() -> Result<TransportIdentity, String> {
    new_identity_with(TRANSPORT_PORT, TRANSPORT_SERVER_NAME)
}

/// 生成一份新的服务端身份，并指定兼容连接的端口与握手域名。
///
/// 端口/域名只在**服务器上还没有身份**时生效（脚本里有身份就复用，见
/// [`transport_script`] 的模板替换）；已有身份的服务器换端口要另走一次
/// 「重新配置兼容连接」，否则客户端会按新端口去连一个还在旧端口上的服务。
pub fn new_identity_with(port: u16, server_name: &str) -> Result<TransportIdentity, String> {
    use rsa::rand_core::{OsRng, RngCore};
    if !matches!(port, 443 | 8443 | 2443) {
        return Err(format!("TCP 首选端口仅支持 443、8443、2443（收到 {port}）"));
    }
    if !is_tls_server_name(server_name) {
        return Err(format!("TCP 握手目标必须是一个域名（收到 {server_name}）"));
    }
    let (private_std, _) = crate::pairing::keys::tunnel_keypair();
    let public_std = crate::pairing::keys::tunnel_public_from_private_b64(&private_std)
        .map_err(|error| error.message.clone())?;
    let mut short = [0u8; 8];
    OsRng.fill_bytes(&mut short);
    Ok(TransportIdentity {
        private_key: url_key(&private_std)?,
        public_key: url_key(&public_std)?,
        short_id: short.iter().map(|b| format!("{b:02x}")).collect(),
        uuid: crate::pairing::random_uuid_v4(),
        port,
        server_name: server_name.trim().to_string(),
    })
}

/// 服务端 REALITY 配置。形状与旧版的 `transport_support.configuration` 逐项对齐。
///
/// 核心是那两条路由规则：
/// - 只有**发往「本机公网 IP : WireGuard 端口」的 UDP** 才会被改写成 `127.0.0.1:WireGuard 端口`
///   交给本机 wg —— 所以服务端的 wg 完全不用暴露在公网，传输层就是 REALITY 本身；
/// - 其余一律 `reject`。少了这条，这台机器就是一台开放代理，REALITY 伪装得再好也没用。
/// 用真实身份渲染一份服务端配置。**只用于测试对照**：生产路径走
/// [`config_template`] + 服务器侧替换，因为「实际生效的身份」只有服务器知道。
/// 保留它是因为测试需要一份「标准答案」来钉住模板的正确性。
#[cfg(test)]
pub fn transport_config(identity: &TransportIdentity, wg_port: u16, host_ip: &str) -> String {
    config_json(
        &identity.private_key,
        &identity.uuid,
        &identity.short_id,
        &identity.port.to_string(),
        &identity.server_name,
        &wg_port.to_string(),
        host_ip,
    )
}

/// 配置模板：与 [`transport_config`] **同一段代码**，只是把「会变的值」换成占位符。
///
/// 为什么不能直接用本地生成的身份：服务端已经有一份身份时，脚本会复用它（那是必须的，
/// 换身份会让已接入的设备全部失效），而本地这份是新的。第一版就是这里错的——
/// 配置里写新私钥、`transport.env` 里留旧私钥，客户端于是永远 `reality verification failed`。
fn config_template(wg_port: u16) -> String {
    config_json(
        "@@C_PRIV@@",
        "@@C_UUID@@",
        "@@C_SID@@",
        "@@C_PORT@@",
        "@@C_SNI@@",
        &wg_port.to_string(),
        "@@C_HOST_IP@@",
    )
}

#[allow(clippy::too_many_arguments)]
fn config_json(
    private_key: &str,
    uuid: &str,
    short_id: &str,
    port: &str,
    server_name: &str,
    wg_port: &str,
    host_ip: &str,
) -> String {
    // 端口在这里是字符串：模板要用占位符，真实值用 `to_string()`。让类型退一步，
    // 换来的是「模板与真实配置由同一段代码产出」——那正是最容易出错的地方。
    let port = match port.parse::<u16>() {
        Ok(number) => serde_json::json!(number),
        Err(_) => serde_json::json!(port),
    };
    let wg_port = match wg_port.parse::<u16>() {
        Ok(number) => serde_json::json!(number),
        Err(_) => serde_json::json!(wg_port),
    };
    serde_json::json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": [{
            "type": "vless",
            "tag": "tc-transport-in",
            "listen": "0.0.0.0",
            "listen_port": port,
            "users": [{ "uuid": uuid }],
            "tls": {
                "enabled": true,
                "server_name": server_name,
                "reality": {
                    "enabled": true,
                    "handshake": { "server": server_name, "server_port": 443 },
                    "private_key": private_key,
                    "short_id": [short_id]
                }
            }
        }],
        "outbounds": [{ "type": "direct", "tag": "wg-relay" }],
        "route": {
            "rules": [
                {
                    "inbound": ["tc-transport-in"],
                    "network": "udp",
                    "ip_cidr": [format!("{host_ip}/32")],
                    "port": [wg_port],
                    "action": "route",
                    "outbound": "wg-relay",
                    "override_address": "127.0.0.1"
                },
                {
                    "inbound": ["tc-transport-in"],
                    "network": "udp",
                    "port": [53],
                    "action": "route",
                    "outbound": "wg-relay",
                    "override_address": "127.0.0.1"
                },
                { "inbound": ["tc-transport-in"], "action": "reject" }
            ],
            "final": "wg-relay"
        }
    })
    .to_string()
}

/// 服务端安装脚本。用 `@@名字@@` 占位符而不是 `format!`：脚本里满屏的 `{` `}` 是
/// JSON 和 shell 的语法，转义成 `{{` `}}` 之后没人读得懂，改一行错一处的风险极高。
const TRANSPORT_SCRIPT: &str = r#"set -eu
IFACE='@@IFACE@@'
HOST='@@HOST@@'
PORT='@@PORT@@'
SNI='@@SNI@@'
WG_PORT='@@WG_PORT@@'
NEW_PRIV='@@PRIV@@'
NEW_PUB='@@PUB@@'
NEW_SID='@@SID@@'
NEW_UUID='@@UUID@@'
BIN_DIR='@@BIN_DIR@@'
CONF_DIR='@@CONF_DIR@@'
BIN="$BIN_DIR/sing-box"
LIB="$BIN_DIR/libcronet.so"
RECEIPT="$BIN.sha256"
IDENTITY="$CONF_DIR/transport.env"
CONF="$CONF_DIR/transport.json"
UNIT="/etc/systemd/system/$IFACE-transport.service"
AMD64_ARCHIVE='@@AMD64_ARCHIVE@@'
AMD64_BIN='@@AMD64_BIN@@'
AMD64_LIB='@@AMD64_LIB@@'
ARM64_ARCHIVE='@@ARM64_ARCHIVE@@'
ARM64_BIN='@@ARM64_BIN@@'
ARM64_LIB='@@ARM64_LIB@@'

fail() { echo "TC_ERROR=$1"; shift; printf '%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail NotRoot '需要 root 权限。'
command -v systemctl >/dev/null 2>&1 || fail NoSystemd '需要 systemd。'

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64; ELF='@@AMD64_ELF@@'; ARCHIVE_SHA="$AMD64_ARCHIVE"; BIN_SHA="$AMD64_BIN"; LIB_SHA="$AMD64_LIB" ;;
  aarch64|arm64) ARCH=arm64; ELF='@@ARM64_ELF@@'; ARCHIVE_SHA="$ARM64_ARCHIVE"; BIN_SHA="$ARM64_BIN"; LIB_SHA="$ARM64_LIB" ;;
  *) fail UnsupportedArchitecture "只支持 amd64 与 arm64，这台是 $(uname -m)。" ;;
esac

mkdir -p /usr/lib/tradechannel "$BIN_DIR" "$CONF_DIR"
chmod 755 /usr/lib/tradechannel "$BIN_DIR"
chmod 700 "$CONF_DIR"

elf_machine() { od -An -tu1 -j18 -N2 "$1" | awk '{print $1 + $2 * 256}'; }
check_elf() {
  [ "$(od -An -tx1 -N4 "$1" | tr -d ' \n')" = '7f454c46' ] || fail TransportArchitectureMismatch "$2 不是 ELF 文件。"
  [ "$(od -An -tu1 -j4 -N1 "$1" | tr -d ' ')" = 2 ] || fail TransportArchitectureMismatch "$2 不是 64 位。"
  [ "$(od -An -tu1 -j5 -N1 "$1" | tr -d ' ')" = 1 ] || fail TransportArchitectureMismatch "$2 不是小端。"
  [ "$(elf_machine "$1")" = "$ELF" ] || fail TransportArchitectureMismatch "$2 的架构与本机不符。"
}

# 1) 组件：摘要全对就复用。重跑不重新下载，也不覆盖已经验过的文件。
COMPONENT=reused
if [ -x "$BIN" ] && [ -f "$LIB" ] && [ -f "$RECEIPT" ] \
   && [ "$(sha256sum "$BIN" | cut -d' ' -f1)" = "$BIN_SHA" ] \
   && [ "$(sha256sum "$LIB" | cut -d' ' -f1)" = "$LIB_SHA" ]; then
  :
else
  COMPONENT=installed
  command -v curl >/dev/null 2>&1 || fail NoCurl '服务器上没有 curl，无法下载组件。'
  URL="https://github.com/SagerNet/sing-box/releases/download/v@@VERSION@@/sing-box-@@VERSION@@-linux-$ARCH.tar.gz"
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT INT TERM
  curl -fsSL --retry 2 --connect-timeout 20 --max-time 300 -o "$TMP/pkg.tar.gz" "$URL" \
    || fail TransportDownloadFailed "下载失败：$URL（服务器可能连不上 GitHub）"
  [ "$(sha256sum "$TMP/pkg.tar.gz" | cut -d' ' -f1)" = "$ARCHIVE_SHA" ] \
    || fail TransportHashMismatch '下载的包与固定摘要不符。'
  PKG="sing-box-@@VERSION@@-linux-$ARCH"
  tar -xzf "$TMP/pkg.tar.gz" -C "$TMP" "$PKG/sing-box" "$PKG/libcronet.so" \
    || fail TransportArchiveInvalid '压缩包里没有预期的组件。'
  [ "$(sha256sum "$TMP/$PKG/sing-box" | cut -d' ' -f1)" = "$BIN_SHA" ] \
    || fail TransportHashMismatch '二进制与固定摘要不符。'
  [ "$(sha256sum "$TMP/$PKG/libcronet.so" | cut -d' ' -f1)" = "$LIB_SHA" ] \
    || fail TransportHashMismatch '运行库与固定摘要不符。'
  check_elf "$TMP/$PKG/sing-box" 'sing-box'
  check_elf "$TMP/$PKG/libcronet.so" 'libcronet.so'
  install -m 0755 "$TMP/$PKG/sing-box" "$BIN"
  install -m 0644 "$TMP/$PKG/libcronet.so" "$LIB"
  printf '%s|%s|%s\n' "$ARCHIVE_SHA" "$BIN_SHA" "$LIB_SHA" > "$RECEIPT"
  chmod 600 "$RECEIPT"
  rm -rf "$TMP"
  trap - EXIT INT TERM
fi

# 2) 身份：服务器上已有就以它为准，**忽略本次传入的那份**。
# 这是第二台、第三台电脑接入时的关键：身份换了，先接入的设备会静默失效。
if [ -s "$IDENTITY" ]; then
  . "$IDENTITY"
  PORT="$TCP_PORT"; SNI="$SERVER_NAME"
  PUB="$PUBLIC_KEY"; SID="$SHORT_ID"; UUID="$CLIENT_UUID"
  PRIV="$PRIVATE_KEY"
  IDENTITY_STATE=reused
else
  IDENTITY_STATE=created
  umask 077
  {
    printf "PRIVATE_KEY='%s'\n" "$NEW_PRIV"
    printf "PUBLIC_KEY='%s'\n" "$NEW_PUB"
    printf "SHORT_ID='%s'\n" "$NEW_SID"
    printf "CLIENT_UUID='%s'\n" "$NEW_UUID"
    printf "TCP_PORT='%s'\n" "$PORT"
    printf "SERVER_NAME='%s'\n" "$SNI"
  } > "$IDENTITY"
  chmod 600 "$IDENTITY"
  PUB="$NEW_PUB"; SID="$NEW_SID"; UUID="$NEW_UUID"; PRIV="$NEW_PRIV"
fi

# 3) 公网地址：路由规则要按「客户端看到的那个 IP」匹配。
case "$HOST" in
  *[!0-9.]*) HOST_IP=$(getent ahostsv4 "$HOST" 2>/dev/null | awk 'NR==1{print $1}') ;;
  *) HOST_IP="$HOST" ;;
esac
[ -n "${HOST_IP:-}" ] || fail AddressUnresolved "解析不出 $HOST 的 IPv4 地址。"

# 4) 端口占用：只在我们自己的服务没在跑时才判死（重启用例要走得通）。
if command -v ss >/dev/null 2>&1 && ss -lnH "sport = :$PORT" 2>/dev/null | grep -q .; then
  if ! systemctl is-active --quiet "$IFACE-transport" 2>/dev/null; then
    fail TransportPortBusy "TCP $PORT 已被其它程序占用。"
  fi
fi

# 5) 配置：先写再自检。起不来的配置在这里就该被拦住，而不是留给 journal。
#
# 配置正文由 Rust 侧生成（`transport_config`）后整段嵌进来，脚本只替换公网 IP：
# 两处各写一份 JSON 迟早会漂移，而漂移的后果是「服务能起但客户端连不上」。
cat > "$CONF" <<'JSON'
@@CONFIG@@
JSON
sed -i \
  -e "s|@@C_PRIV@@|$PRIV|g" \
  -e "s|@@C_UUID@@|$UUID|g" \
  -e "s|@@C_SID@@|$SID|g" \
  -e "s|\"@@C_PORT@@\"|$PORT|g" \
  -e "s|@@C_SNI@@|$SNI|g" \
  -e "s|@@C_HOST_IP@@|$HOST_IP|g" \
  "$CONF"
chmod 600 "$CONF"
"$BIN" check -c "$CONF" || fail TransportConfigInvalid '生成的配置没有通过引擎自检。'

# 6) systemd：跟着 WireGuard 一起起停（PartOf），wg 不在时它也没有意义。
cat > "$UNIT" <<UNIT
[Unit]
Description=SpiderVPN TCP transport ($IFACE)
Wants=network-online.target
Requires=wg-quick@$IFACE.service
After=network-online.target wg-quick@$IFACE.service
PartOf=wg-quick@$IFACE.service

[Service]
Type=simple
ExecStart=$BIN run -c $CONF
WorkingDirectory=$BIN_DIR
Environment=LD_LIBRARY_PATH=$BIN_DIR
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$UNIT"

systemctl daemon-reload
systemctl enable --quiet "$IFACE-transport.service" >/dev/null 2>&1 || true
systemctl restart "$IFACE-transport.service" || {
  journalctl -u "$IFACE-transport.service" -n 20 --no-pager >&2 || true
  fail TransportStartFailed '传输服务没有起来。'
}
sleep 1
systemctl is-active --quiet "$IFACE-transport.service" || {
  journalctl -u "$IFACE-transport.service" -n 20 --no-pager >&2 || true
  fail TransportNotActive '传输服务没有保持运行。'
}
if command -v ss >/dev/null 2>&1; then
  ss -lnH "sport = :$PORT" 2>/dev/null | grep -q . || fail TransportNotListening "TCP $PORT 没有在监听。"
fi

# 隧道内 DNS：客户端把 DNS 查询（UDP:53）发进中转，这里的规则会把它改写到
# 127.0.0.1:53。用 unbound 而不是 dnsmasq：真机实测这台服务器**出站 UDP 53 也被封**，
# dnsmasq 只会转发 UDP，查询会一直挂着；unbound 可以 `forward-tcp-upstream: yes`
# 走上游 TCP。
if ! command -v unbound >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y unbound >/dev/null 2>&1 || true
fi
if command -v unbound >/dev/null 2>&1; then
  mkdir -p /etc/unbound/unbound.conf.d
  cat > /etc/unbound/unbound.conf.d/tc-tunnel.conf <<EOF
server:
    # 两个地址都要听：127.0.0.1 是「中转把 UDP:53 改写过来」的落点，
    # 10.66.0.1 是隧道内地址——只写 127.0.0.1 时，客户端经隧道的查询会拿到 EOF。
    interface: 127.0.0.1
    interface: 10.66.0.1
    port: 53
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    do-not-query-localhost: no
forward-zone:
    name: "."
    # 转发给服务器**自己的**系统解析器：它的答案就是这台机器真实能用的地址
    # （实测 `www.tradingview.com → 13.249.213.x`，服务器直连 200）。
    # 出站 UDP 53 被封、外部 DoT 853 也不通，只有本机解析器这条路稳。
    forward-addr: 127.0.0.53
EOF
  systemctl enable --quiet unbound >/dev/null 2>&1 || true
  systemctl restart unbound >/dev/null 2>&1 || true
  sleep 1
  systemctl is-active --quiet unbound || echo "TC_WARN=unbound 没有起来，交易域名会解析不到" >&2
fi

echo "TC_TRANSPORT_PUBLIC=$PUB"
echo "TC_TRANSPORT_UUID=$UUID"
echo "TC_TRANSPORT_SHORT_ID=$SID"
echo "TC_TRANSPORT_PORT=$PORT"
echo "TC_TRANSPORT_SERVER_NAME=$SNI"
echo "TC_TRANSPORT_COMPONENT=$COMPONENT"
echo "TC_TRANSPORT_IDENTITY=$IDENTITY_STATE"
echo "TC_DONE=1"
"#;

/// 拼出这次要跑的安装脚本。
pub fn transport_script(spec: &Spec, host: &str, identity: &TransportIdentity) -> String {
    // 配置用**模板**注入，真正的值由脚本在 source 完身份文件之后替换：
    // 服务器上已有身份时以它为准，本地这份可能已经过时。
    let config = config_template(spec.port);
    let rendered = TRANSPORT_SCRIPT
        .replace("@@CONFIG@@", &config)
        .replace("@@IFACE@@", &spec.interface)
        .replace("@@HOST@@", host.trim())
        .replace("@@PORT@@", &identity.port.to_string())
        .replace("@@SNI@@", &identity.server_name)
        .replace("@@WG_PORT@@", &spec.port.to_string())
        .replace("@@PRIV@@", &identity.private_key)
        .replace("@@PUB@@", &identity.public_key)
        .replace("@@SID@@", &identity.short_id)
        .replace("@@UUID@@", &identity.uuid)
        .replace("@@BIN_DIR@@", TRANSPORT_BIN_DIR)
        .replace("@@CONF_DIR@@", TRANSPORT_CONF_DIR)
        .replace("@@VERSION@@", TRANSPORT_VERSION)
        .replace("@@AMD64_ARCHIVE@@", AMD64.archive)
        .replace("@@AMD64_BIN@@", AMD64.binary)
        .replace("@@AMD64_LIB@@", AMD64.library)
        .replace("@@AMD64_ELF@@", &AMD64.elf_machine.to_string())
        .replace("@@ARM64_ARCHIVE@@", ARM64.archive)
        .replace("@@ARM64_BIN@@", ARM64.binary)
        .replace("@@ARM64_LIB@@", ARM64.library)
        .replace("@@ARM64_ELF@@", &ARM64.elf_machine.to_string());
    crate::legacy_writer_fence::guard_legacy_mutation_script(&rendered)
}

/// 服务端装好之后回显的参数。**以服务器上那份为准**，不是本地生成的那份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportInstalled {
    pub public_key: String,
    pub uuid: String,
    pub short_id: String,
    pub port: u16,
    pub server_name: String,
    /// `reused` = 复用了已装的二进制；`installed` = 这次新装的。
    pub component: String,
    /// `reused` = 复用了已有身份；`created` = 这次新建的。
    pub identity: String,
}

/// 43 位 base64url。REALITY 公钥的形状，与旧版的 `^[A-Za-z0-9_-]{43}$` 一致。
fn is_url_key_43(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// 解析安装结果。`None` = 服务器上还没有兼容连接（只读回显时的正常结果）。
///
/// **形状不对就报错**：这几个字段错了，客户端只会表现成「连不上」，
/// 而那时已经隔了一层隧道，查起来最费劲。
pub fn parse_transport(stdout: &str) -> Result<Option<TransportInstalled>, String> {
    let mut public_key = None;
    let mut uuid = None;
    let mut short_id = None;
    let mut port = None;
    let mut server_name = None;
    let mut component = None;
    let mut identity = None;
    let mut absent = false;
    let mut done = false;

    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim().to_string();
        match key {
            "TC_TRANSPORT_PUBLIC" => public_key = Some(value),
            "TC_TRANSPORT_UUID" => uuid = Some(value),
            "TC_TRANSPORT_SHORT_ID" => short_id = Some(value),
            "TC_TRANSPORT_PORT" => {
                port = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| format!("服务器返回的 TCP 端口不是数字：{value}"))?,
                )
            }
            "TC_TRANSPORT_SERVER_NAME" => server_name = Some(value),
            "TC_TRANSPORT_COMPONENT" => component = Some(value),
            "TC_TRANSPORT_IDENTITY" => identity = Some(value),
            "TC_TRANSPORT_ABSENT" => absent = value == "1",
            "TC_DONE" => done = value == "1",
            _ => {}
        }
    }

    if !done {
        return Err(
            "传输服务安装没有跑完（服务器没有返回结束标记）：可能被截断，请重试。".to_string(),
        );
    }

    if absent {
        return Ok(None);
    }

    let public_key = public_key.ok_or_else(|| "服务器没有回报 REALITY 公钥。".to_string())?;
    if !is_url_key_43(&public_key) {
        return Err(format!("服务器回报的 REALITY 公钥形状不对：{public_key}"));
    }
    let uuid = uuid.ok_or_else(|| "服务器没有回报 UUID。".to_string())?;
    if !crate::pairing::is_uuid_v4_shape(&uuid) {
        return Err(format!("服务器回报的 UUID 形状不对：{uuid}"));
    }
    let short_id = short_id.ok_or_else(|| "服务器没有回报 ShortId。".to_string())?;
    if short_id.len() != 16 || !short_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("服务器回报的 ShortId 形状不对：{short_id}"));
    }
    let port = port.ok_or_else(|| "服务器没有回报 TCP 端口。".to_string())?;
    if port == 0 {
        return Err("服务器回报的 TCP 端口是 0。".to_string());
    }
    let server_name = server_name.ok_or_else(|| "服务器没有回报握手域名。".to_string())?;
    if server_name.is_empty() {
        return Err("服务器回报的握手域名是空的。".to_string());
    }

    Ok(Some(TransportInstalled {
        public_key,
        uuid,
        short_id,
        port,
        server_name,
        component: component.unwrap_or_else(|| "unknown".to_string()),
        identity: identity.unwrap_or_else(|| "unknown".to_string()),
    }))
}

impl TransportInstalled {
    /// 转成线路生成用的兼容连接参数。
    ///
    /// `server` 用**用户填的那个地址**（可能是域名），不是解析出来的 IP：
    /// 客户端要连的是「用户认得的那个入口」，换 IP 时线路不用跟着改。
    pub fn compatible(&self, server: &str) -> crate::pairing::line::Compatible {
        crate::pairing::line::Compatible {
            server: server.trim().to_string(),
            port: self.port,
            uuid: self.uuid.clone(),
            server_name: self.server_name.clone(),
            reality_public_key: self.public_key.clone(),
            reality_short_id: self.short_id.clone(),
        }
    }
}

/// 计划文本：`--server-transport` 不带 `--apply` 时打印它，**不连接**。
pub fn transport_plan_text(spec: &Spec, address: &str) -> String {
    format!(
        "将在 {address} 上安装兼容连接（TCP）服务（预览，尚未连接）：\n\
         \x20 · 下载官方 sing-box {version}（amd64/arm64），整包与两个成员逐层校验固定摘要\n\
         \x20 · 装到 {bin_dir}（已装且摘要一致则复用，不重复下载）\n\
         \x20 · 生成/复用 REALITY 身份：{conf_dir}/transport.env（权限 600，私钥不出服务器）\n\
         \x20 · 写 {conf_dir}/transport.json：VLESS + REALITY，TCP {port}，握手域名 {sni}\n\
         \x20 · 只有发往「本机公网 IP : UDP {wg_port}」的包才转给本机 WireGuard，其余拒绝\n\
         \x20 · 启用并重启 {iface}-transport.service（跟随 wg-quick@{iface} 起停）\n\
         确认无误后加 --apply 执行。",
        version = TRANSPORT_VERSION,
        bin_dir = TRANSPORT_BIN_DIR,
        conf_dir = TRANSPORT_CONF_DIR,
        port = TRANSPORT_PORT,
        sni = TRANSPORT_SERVER_NAME,
        wg_port = spec.port,
        iface = spec.interface,
    )
}

/// 连上去装/更新传输服务。
pub fn install_transport<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    spec: &Spec,
    host: &str,
    identity: &TransportIdentity,
    timeout: Duration,
) -> Result<TransportInstalled, Error> {
    let auth = auth.into();
    spec.validate().map_err(Error::Command)?;
    let script = transport_script(spec, host, identity);
    let output = ssh::exec(target, auth, Some(expected), &script, timeout)?;
    match parse_transport(&output.stdout) {
        Ok(Some(installed)) => Ok(installed),
        Ok(None) => Err(Error::Command(
            "脚本报告安装完成，但服务器上仍然没有兼容连接身份。".to_string(),
        )),
        Err(message) => {
            // 与 `install()` 同一条规矩：脚本把 journal 尾巴送到 stderr，
            // 少了它用户只看到「TransportStartFailed」，而原因九成就在那几行里。
            let mut detail = message;
            let stderr = output.stderr.trim();
            if !stderr.is_empty() {
                let total = stderr.chars().count();
                let mut tail: String = stderr.chars().skip(total.saturating_sub(2000)).collect();
                if total > 2000 {
                    tail.insert_str(0, "…（前面已截断）\n");
                }
                detail.push_str("\n--- 服务器上的最后输出 ---\n");
                detail.push_str(&tail);
            }
            if output.code != 0 && !detail.contains("没有跑完") {
                Err(Error::Command(format!("{detail}（退出码 {}）", output.code)))
            } else {
                Err(Error::Command(detail))
            }
        }
    }
}

/// 只读回显：服务器上到底装没装兼容连接、参数是什么。
///
/// **纯读**：不下载、不写文件、不重启服务。`--server-join` 靠它决定「要不要多登记一条
/// 兼容连接线路」，所以它必须能在任何时候安全地跑。
const TRANSPORT_PROBE_SCRIPT: &str = r#"set -eu
IDENTITY='@@CONF_DIR@@/transport.env'
if [ -s "$IDENTITY" ]; then
  . "$IDENTITY"
  echo "TC_TRANSPORT_PUBLIC=$PUBLIC_KEY"
  echo "TC_TRANSPORT_UUID=$CLIENT_UUID"
  echo "TC_TRANSPORT_SHORT_ID=$SHORT_ID"
  echo "TC_TRANSPORT_PORT=$TCP_PORT"
  echo "TC_TRANSPORT_SERVER_NAME=$SERVER_NAME"
  echo "TC_TRANSPORT_COMPONENT=present"
  echo "TC_TRANSPORT_IDENTITY=present"
else
  echo "TC_TRANSPORT_ABSENT=1"
fi
echo "TC_DONE=1"
"#;

/// 读服务器上的兼容连接参数。`Ok(None)` = 还没装（不是错误）。
pub fn read_transport<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    timeout: Duration,
) -> Result<Option<TransportInstalled>, Error> {
    let auth = auth.into();
    let script = TRANSPORT_PROBE_SCRIPT.replace("@@CONF_DIR@@", TRANSPORT_CONF_DIR);
    let output = ssh::exec(target, auth, Some(expected), &script, timeout)?;
    parse_transport(&output.stdout).map_err(|message| {
        let mut detail = message;
        let stderr = output.stderr.trim();
        if !stderr.is_empty() {
            let total = stderr.chars().count();
            let tail: String = stderr.chars().skip(total.saturating_sub(1000)).collect();
            detail.push_str("\n--- 服务器上的最后输出 ---\n");
            detail.push_str(&tail);
        }
        Error::Command(detail)
    })
}

/// 导出兼容连接身份（含**私钥**）。只读：不下载、不写文件、不重启服务。
///
/// 为什么要有这一步：`transport.env` 是服务器上的唯一副本。服务器重装 / 磁盘坏掉之后，
/// 所有已接入设备的 `client.conf` 都会失效，只能重新部署并让每台设备重连。
/// 允许用户把身份离线存一份，是为了灾难恢复，不是为了日常搬运。
const TRANSPORT_EXPORT_SCRIPT: &str = r#"set -eu
umask 077
IDENTITY='@@CONF_DIR@@/transport.env'
[ -s "$IDENTITY" ] || { echo "TC_TRANSPORT_ABSENT=1"; echo "TC_DONE=1"; exit 0; }
. "$IDENTITY"
echo "TC_PRIVATE=$PRIVATE_KEY"
echo "TC_PUBLIC=$PUBLIC_KEY"
echo "TC_SHORT_ID=$SHORT_ID"
echo "TC_UUID=$CLIENT_UUID"
echo "TC_PORT=$TCP_PORT"
echo "TC_SERVER_NAME=$SERVER_NAME"
echo "TC_IDENTITY_SHA=$(sha256sum "$IDENTITY" | cut -d' ' -f1)"
echo "TC_DONE=1"
"#;

/// 从服务器读回来的身份（含私钥）与它所在文件的哈希。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportExport {
    pub identity: TransportIdentity,
    /// 服务器上 `transport.env` 的 SHA-256。恢复时用它判断「是不是同一份身份」。
    pub identity_sha256: String,
}

pub fn parse_transport_export(stdout: &str) -> Result<Option<TransportExport>, String> {
    let mut fields: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
    let mut absent = false;
    let mut done = false;
    let mut failure = None;
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        match key {
            "TC_TRANSPORT_ABSENT" => absent = value.trim() == "1",
            "TC_DONE" => done = value.trim() == "1",
            "TC_ERROR" => failure = Some(value.trim().to_string()),
            _ => {
                fields.insert(key, value.trim().to_string());
            }
        }
    }
    if let Some(code) = failure {
        return Err(format!("读不到兼容连接身份：{code}"));
    }
    if !done {
        return Err("读取身份的脚本没有跑完（没有结束标记）：可能被截断，请重试。".to_string());
    }
    if absent {
        return Ok(None);
    }
    let take = |key: &str| {
        fields
            .get(key)
            .cloned()
            .ok_or_else(|| format!("服务器没有回报 {key}。"))
    };
    let identity = TransportIdentity {
        private_key: take("TC_PRIVATE")?,
        public_key: take("TC_PUBLIC")?,
        short_id: take("TC_SHORT_ID")?,
        uuid: take("TC_UUID")?,
        port: take("TC_PORT")?
            .parse::<u16>()
            .map_err(|_| "服务器回报的端口不是数字。".to_string())?,
        server_name: take("TC_SERVER_NAME")?,
    };
    validate_identity(&identity)?;
    Ok(Some(TransportExport {
        identity,
        identity_sha256: take("TC_IDENTITY_SHA")?,
    }))
}

/// 身份的形状校验。恢复时这是**唯一一道**能拦住「把服务器写坏」的本地关卡，
/// 所以每条都要说清楚是哪一项不对。
pub fn validate_identity(identity: &TransportIdentity) -> Result<(), String> {
    let check_key = |name: &str, value: &str| -> Result<(), String> {
        if value.len() != 43
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "{name} 不是 REALITY 要的形状（43 位 base64url、无填充）：{value}"
            ));
        }
        Ok(())
    };
    check_key("REALITY 私钥", &identity.private_key)?;
    check_key("REALITY 公钥", &identity.public_key)?;
    if identity.private_key == identity.public_key {
        return Err("私钥与公钥相同，这份身份是坏的。".to_string());
    }
    if identity.short_id.len() != 16
        || !identity.short_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(format!("ShortId 必须是 16 位十六进制：{}", identity.short_id));
    }
    let uuid = &identity.uuid;
    let uuid_ok = uuid.len() == 36
        && uuid
            .chars()
            .enumerate()
            .all(|(index, c)| match index {
                8 | 13 | 18 | 23 => c == '-',
                _ => c.is_ascii_hexdigit(),
            });
    if !uuid_ok {
        return Err(format!("UUID 形状不对：{uuid}"));
    }
    if identity.port < 1024 {
        return Err(format!("TCP 端口必须在 1024 以上：{}", identity.port));
    }
    if identity.server_name.is_empty()
        || identity.server_name.len() > 253
        || !identity
            .server_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!("握手域名不合法：{}", identity.server_name));
    }
    Ok(())
}

/// 只读导出：把服务器上的身份读回来。`Ok(None)` = 服务器上没装兼容连接。
pub fn export_transport<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    timeout: Duration,
) -> Result<Option<TransportExport>, Error> {
    let auth = auth.into();
    let script = TRANSPORT_EXPORT_SCRIPT.replace("@@CONF_DIR@@", TRANSPORT_CONF_DIR);
    let output = ssh::exec(target, auth, Some(expected), &script, timeout)?;
    parse_transport_export(&output.stdout).map_err(|message| {
        let mut detail = message;
        let stderr = output.stderr.trim();
        if !stderr.is_empty() {
            let total = stderr.chars().count();
            let tail: String = stderr.chars().skip(total.saturating_sub(1000)).collect();
            detail.push_str("\n--- 服务器上的最后输出 ---\n");
            detail.push_str(&tail);
        }
        Error::Command(detail)
    })
}

/// 离线备份文件的内容。**含私钥**：写盘位置与提醒由调用方负责。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportBackup {
    pub target: String,
    pub host: String,
    pub created_at: String,
    pub identity: TransportIdentity,
    pub identity_sha256: String,
}

impl TransportBackup {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "Kind": "TradeChannel.TransportIdentityBackup",
            "SchemaVersion": 1,
            "Warning": "本文件包含 REALITY 私钥。它等同于这台服务器的兼容连接身份，请离线保存，不要提交到代码仓库或发到聊天里。",
            "Target": self.target,
            "Host": self.host,
            "CreatedAtUtc": self.created_at,
            "PrivateKey": self.identity.private_key,
            "PublicKey": self.identity.public_key,
            "ShortId": self.identity.short_id,
            "ClientUuid": self.identity.uuid,
            "Port": self.identity.port,
            "ServerName": self.identity.server_name,
            "IdentitySha256": self.identity_sha256,
        })
    }

    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("备份文件缺少 {key}。"))
        };
        let kind = text("Kind")?;
        if kind != "TradeChannel.TransportIdentityBackup" {
            return Err(format!("这不是线路身份备份文件（Kind={kind}）。"));
        }
        let identity = TransportIdentity {
            private_key: text("PrivateKey")?,
            public_key: text("PublicKey")?,
            short_id: text("ShortId")?,
            uuid: text("ClientUuid")?,
            port: value
                .get("Port")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "备份文件缺少 Port。".to_string())? as u16,
            server_name: text("ServerName")?,
        };
        validate_identity(&identity)?;
        Ok(TransportBackup {
            target: text("Target")?,
            host: text("Host")?,
            created_at: text("CreatedAtUtc")?,
            identity,
            identity_sha256: text("IdentitySha256")?,
        })
    }
}

/// 写身份文件。**只在服务器上执行**：先比对现有哈希，不同就拒绝（除非 force）。
///
/// 为什么默认拒绝：覆盖一份不同的身份，会让所有已接入设备的 `client.conf` 立刻失效。
/// 这个后果必须让用户明确点头，不能靠「点了恢复」就发生。
pub fn identity_restore_script(spec: &Spec, backup: &TransportBackup, force: bool) -> String {
    let _ = spec;
    let identity = &backup.identity;
    let rendered = format!(
        r#"set -eu
umask 077
CONF_DIR='{conf_dir}'
IDENTITY="$CONF_DIR/transport.env"
EXPECT_SHA='{expected_sha}'
FORCE='{force}'
fail() {{ echo "TC_ERROR=$1"; exit 1; }}

mkdir -p "$CONF_DIR"
if [ -f "$IDENTITY" ]; then
  CUR=$(sha256sum "$IDENTITY" | cut -d' ' -f1)
  if [ "$CUR" != "$EXPECT_SHA" ] && [ "$FORCE" != "1" ]; then
    fail IdentityDiffers
  fi
fi

cat > "$IDENTITY" <<'TC_IDENTITY_EOF'
PRIVATE_KEY='{private_key}'
PUBLIC_KEY='{public_key}'
SHORT_ID='{short_id}'
CLIENT_UUID='{uuid}'
TCP_PORT='{port}'
SERVER_NAME='{server_name}'
TC_IDENTITY_EOF
chmod 600 "$IDENTITY"
echo "TC_IDENTITY_WRITTEN=1"
echo "TC_IDENTITY_SHA=$(sha256sum "$IDENTITY" | cut -d' ' -f1)"
echo "TC_DONE=1"
"#,
        conf_dir = TRANSPORT_CONF_DIR,
        expected_sha = backup.identity_sha256,
        force = if force { "1" } else { "0" },
        private_key = identity.private_key,
        public_key = identity.public_key,
        short_id = identity.short_id,
        uuid = identity.uuid,
        port = identity.port,
        server_name = identity.server_name,
    );
    crate::legacy_writer_fence::guard_legacy_mutation_script(&rendered)
}

/// 恢复身份：把备份写回服务器，再用既有安装脚本重新渲染配置并重启服务。
///
/// 复用 `install_transport` 而不是另写一套：那份脚本已经处理了「身份已存在就复用」
/// 「渲染配置」「起服务」「后置验听」，单独再写一遍只会长出第二套行为。
pub fn restore_transport<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    spec: &Spec,
    host: &str,
    backup: &TransportBackup,
    force: bool,
    timeout: Duration,
) -> Result<TransportInstalled, Error> {
    let auth = auth.into();
    spec.validate().map_err(Error::Command)?;
    validate_identity(&backup.identity).map_err(Error::Command)?;
    let script = identity_restore_script(spec, backup, force);
    let output = ssh::exec(target, auth, Some(expected), &script, timeout)?;
    if !output.stdout.contains("TC_DONE=1") {
        let code = output
            .stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("TC_ERROR="))
            .unwrap_or("Unknown");
        let human = match code {
            "IdentityDiffers" => {
                "服务器上已经有一份不同的身份。覆盖会让所有已接入的设备立刻失效；确认后加 --force 重试。"
            }
            other => {
                let _ = other;
                "写身份文件没有完成。"
            }
        };
        let mut detail = human.to_string();
        let stderr = output.stderr.trim();
        if !stderr.is_empty() {
            detail.push_str("\n--- 服务器上的最后输出 ---\n");
            detail.push_str(stderr);
        }
        return Err(Error::Command(detail));
    }
    install_transport(target, auth, expected, spec, host, &backup.identity, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 卸载只碰「本工具装的东西」：服务、WireGuard 配置、transport 配置；
    /// **保留** transport.env（身份）与 pairing 状态（审计）。
    #[test]
    fn uninstall_script_removes_our_units_and_keeps_identity() {
        let spec = Spec::for_record("0f8fad5b-d9cb-469f-a165-70867728950e");
        let script = uninstall_script(&spec);
        assert!(script.contains(&format!("IFACE='{}'", spec.interface)), "{script}");
        assert!(script.contains("$IFACE-transport.service"), "{script}");
        assert!(script.contains("tc-pair.service"), "{script}");
        assert!(script.contains("wg-quick down \"$IFACE\""), "{script}");
        assert!(script.contains("/etc/wireguard/$IFACE.conf"), "{script}");
        assert!(script.contains("$CONF_DIR/transport.json"), "{script}");
        assert!(
            !script.contains("transport.env"),
            "transport.env 是身份，不能删：{script}"
        );
        assert!(!script.contains("/var/lib/tradechannel"), "审计与身份目录不能碰：{script}");
    }

    #[test]
    fn uninstall_output_is_parsed_and_failures_are_humanized() {
        let ack = parse_uninstall(
            "TC_TRANSPORT_REMOVED=1\nTC_INVITE_REMOVED=0\nTC_INTERFACE_PRESENT=0\nTC_DONE=1\n",
        )
        .expect("完整输出必须能解析");
        assert!(ack.transport_removed);
        assert!(!ack.invite_removed);
        assert!(!ack.interface_present);

        let error = parse_uninstall("TC_ERROR=NotRoot\n").expect_err("失败必须报错");
        assert!(error.contains("root"), "{error}");

        let truncated = parse_uninstall("TC_TRANSPORT_REMOVED=1\n").expect_err("缺结束标记必须报错");
        assert!(truncated.contains("没有跑完"), "{truncated}");
    }

    const SAMPLE: &str = "TC_KERNEL=Linux\n\
TC_ARCH=x86_64\n\
TC_UID=0\n\
TC_DISTRO=debian\n\
TC_VERSION=12\n\
TC_SYSTEMD=yes\n\
TC_OPENSSL=yes\n\
TC_WG=no\n\
TC_WGDIR=no\n\
TC_UFW=absent\n\
TC_DOCKER=no\n\
TC_FORWARD_POLICY=ACCEPT\n\
TC_DONE=1\n";

    #[test]
    fn a_complete_report_is_parsed_field_by_field() {
        let env = parse_inspect(SAMPLE).expect("完整输出必须能解析");
        assert_eq!(env.kernel, "Linux");
        assert_eq!(env.arch, "x86_64");
        assert_eq!(env.uid, 0);
        assert_eq!(env.distro, "debian");
        assert_eq!(env.distro_version, "12");
        assert!(env.systemd);
        assert!(env.openssl);
        assert!(!env.wireguard_tools);
        assert!(!env.wireguard_dir);
        assert_eq!(env.blocking_reason(), None, "debian 12 + root + systemd 应当可以部署");
    }

    #[test]
    fn a_truncated_report_is_refused_instead_of_guessed() {
        // 少了 TC_DONE：说明脚本没跑完。缺字段绝不能当「没有这个能力」。
        let truncated = SAMPLE.replace("TC_DONE=1\n", "");
        let error = parse_inspect(&truncated).expect_err("没有结束标记必须报错");
        assert!(error.contains("没有跑完"), "{error}");
    }

    #[test]
    fn a_missing_field_names_what_is_missing() {
        let partial = "TC_KERNEL=Linux\nTC_DONE=1\n";
        let error = parse_inspect(partial).expect_err("缺字段必须报错");
        assert!(error.contains("缺少"), "{error}");
    }

    // ---------- 只读核对（标准连接到底生效没有） ----------

    const UDP_UP: &str = "TC_UDP_CONF=present\n\
TC_UDP_UNIT=active\n\
TC_UDP_TUNNEL=up\n\
TC_UDP_LISTEN=51820\n\
TC_UDP_PEER=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
TC_UDP_PEER=d+u6Rd53MtjGqKr+jmV/k5TfWrIFdF6OSqqINw61SKo=\n\
TC_DONE=1\n";

    const UDP_DOWN: &str = "TC_UDP_CONF=absent\n\
TC_UDP_UNIT=inactive\n\
TC_UDP_TUNNEL=down\n\
TC_DONE=1\n";

    /// 起来了：接口在、端口对、conf 在、unit active、设备列表读得到。
    #[test]
    fn a_live_tunnel_is_parsed_with_its_port_and_peers() {
        let state = parse_udp_state(UDP_UP).expect("完整输出必须能解析");
        assert!(state.tunnel_up);
        assert!(state.conf_present);
        assert!(state.unit_active);
        assert_eq!(state.listen_port, Some(51_820));
        assert_eq!(state.peers.len(), 2);
        assert!(state.matches_plan(51_820), "端口一致才算生效");
        assert!(!state.matches_plan(51_821), "端口不符不能算生效");
        assert!(state.has_peer("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
        assert!(!state.has_peer("不存在的公钥"), "不许误判成已接入");
        assert!(!state.has_peer(""), "空公钥不能命中任何人");
        assert!(!state.clearly_not_applied());
    }

    /// 明确没生效：三个否定条件同时成立才敢这么说。
    #[test]
    fn a_totally_absent_tunnel_is_the_only_clear_negative() {
        let state = parse_udp_state(UDP_DOWN).expect("down 也是完整输出");
        assert!(!state.tunnel_up);
        assert!(!state.conf_present);
        assert!(!state.unit_active);
        assert_eq!(state.listen_port, None, "没读到端口就是 None，不是 0");
        assert!(state.peers.is_empty());
        assert!(state.clearly_not_applied(), "三个条件同时成立才是「明确没生效」");
        assert!(!state.matches_plan(51_820));

        // conf 在、接口却 down（服务没起来）：这是典型的「不知道」，不许当失败去重装。
        let half = parse_udp_state(
            "TC_UDP_CONF=present\nTC_UDP_UNIT=inactive\nTC_UDP_TUNNEL=down\nTC_DONE=1\n",
        )
        .expect("半截状态也是完整输出");
        assert!(!half.clearly_not_applied(), "conf 在就不能说「明确没生效」");
    }

    /// 缺字段 → 报错，绝不默认成 false（默认成 false 就等于说「没装」）。
    #[test]
    fn a_missing_probe_field_is_refused_instead_of_defaulted() {
        let missing_unit = "TC_UDP_CONF=present\nTC_UDP_TUNNEL=up\nTC_DONE=1\n";
        let error = parse_udp_state(missing_unit).expect_err("缺服务状态必须报错");
        assert!(error.contains("缺少"), "{error}");

        let truncated = UDP_UP.replace("TC_DONE=1\n", "");
        let error = parse_udp_state(&truncated).expect_err("没有结束标记必须报错");
        assert!(error.contains("没有跑完"), "{error}");

        let bad_port = UDP_UP.replace("TC_UDP_LISTEN=51820", "TC_UDP_LISTEN=很多");
        let error = parse_udp_state(&bad_port).expect_err("端口不是数字必须报错");
        assert!(error.contains("0-65535"), "{error}");
        assert!(!error.contains("很多"), "错误消息不许回显远端返回的原文：{error}");

        let bad_tunnel = UDP_UP.replace("TC_UDP_TUNNEL=up", "TC_UDP_TUNNEL=maybe");
        let error = parse_udp_state(&bad_tunnel).expect_err("表外值不许猜");
        assert!(!error.contains("maybe"), "错误消息不许回显远端返回的原文：{error}");
    }

    /// F4：表外值一律不回显。远端返回的内容不能顺着错误消息进日志或界面。
    #[test]
    fn an_unknown_probe_value_is_never_echoed_back() {
        let payload = "<img src=x onerror=alert(1)>";
        for (field, original) in [
            ("TC_UDP_TUNNEL", "TC_UDP_TUNNEL=up"),
            ("TC_UDP_CONF", "TC_UDP_CONF=present"),
            ("TC_UDP_UNIT", "TC_UDP_UNIT=active"),
        ] {
            let tampered = UDP_UP.replace(original, &format!("{field}={payload}"));
            let error = parse_udp_state(&tampered).expect_err("表外值必须报错");
            assert!(
                !error.contains(payload) && !error.contains("onerror"),
                "{field} 的原文被回显了：{error}"
            );
        }
    }

    /// 核对脚本必须**只读**，而且绝不回传私钥。
    #[test]
    fn the_probe_script_is_read_only_and_never_echoes_a_private_key() {
        let script = udp_state_script("tc3f2b9c1e").expect("合法接口名");
        // 只读：一条写命令都没有。
        for forbidden in ["wg-quick up", "wg-quick down", "systemctl restart", "systemctl start", "> /etc", "rm -f"] {
            assert!(!script.contains(forbidden), "核对脚本里出现了写动作：{forbidden}");
        }
        // `wg show dump` 只被读进变量一次，取的是第三字段（监听端口）与 peer 公钥。
        assert_eq!(script.matches("wg show").count(), 1, "只允许一次 wg show");
        assert!(script.contains("NR==1 {print $3}"), "只取监听端口");
        assert!(!script.contains("TC_UDP_RAW"), "不许把整份 dump 回传（里面有私钥）");
        assert!(script.contains("TC_DONE=1"));

        // 接口名会被拼进 shell：形状不对就必须拒绝，不能带进注入。
        for bad in ["", "tc'; rm -rf /", "TC3f2b9c1e", "tc-3f2b9c1e", "这太长太长的接口名了abc"] {
            assert!(udp_state_script(bad).is_err(), "非法接口名必须拒绝：{bad}");
        }
    }

    #[test]
    fn a_non_linux_host_is_blocked_with_its_kernel_named() {
        let env = Environment {
            kernel: "FreeBSD".to_string(),
            arch: "amd64".to_string(),
            uid: 0,
            distro: String::new(),
            distro_version: String::new(),
            systemd: true,
            openssl: true,
            wireguard_tools: true,
            wireguard_dir: false,
            tunnel: None,
            docker: false,
            forward_policy: "ACCEPT".to_string(),
            ufw: "absent".to_string(),
        };
        let reason = env.blocking_reason().expect("非 Linux 必须被挡住");
        assert!(reason.contains("FreeBSD"), "{reason}");
    }

    #[test]
    fn a_non_root_account_is_blocked_before_anything_is_installed() {
        let env = Environment {
            kernel: "Linux".to_string(),
            arch: "x86_64".to_string(),
            uid: 1000,
            distro: "ubuntu".to_string(),
            distro_version: "24.04".to_string(),
            systemd: true,
            openssl: true,
            wireguard_tools: true,
            wireguard_dir: false,
            tunnel: None,
            docker: false,
            forward_policy: "ACCEPT".to_string(),
            ufw: "absent".to_string(),
        };
        let reason = env.blocking_reason().expect("非 root 必须被挡住");
        assert!(reason.contains("root"), "{reason}");
        assert!(reason.contains("1000"), "要把实际 uid 说出来：{reason}");
    }

    #[test]
    fn missing_tools_are_reported_but_not_treated_as_blocking() {
        // 缺 openssl/wg 是「要装」，不是「装不了」——部署步骤会处理它们。
        let env = parse_inspect(SAMPLE).unwrap();
        assert!(!env.wireguard_tools);
        assert_eq!(env.blocking_reason(), None);
        assert!(env.summary().contains("WireGuard 工具（wg）：没有"), "{}", env.summary());
    }

    /// 端到端：真握手 → 真执行检查脚本 → 真解析。
    ///
    /// 与 `ssh` 的用例共用同一台本地 SSH 服务：传输层和部署检查必须是同一条真链路，
    /// 各自养一套桩只会证明「桩和桩对得上」。
    #[test]
    fn inspect_runs_over_a_real_ssh_session() {
        let (port, fingerprint) = crate::ssh::test_support::start_server();
        let target = crate::ssh::test_support::target(port);
        let env = inspect(
            &target,
            crate::ssh::test_support::PASSWORD,
            Some(&fingerprint),
            None,
            Duration::from_secs(10),
        )
        .expect("应当能读到服务器环境");
        assert_eq!(env.distro, "debian");
        assert_eq!(env.distro_version, "12");
        assert!(env.systemd);
        assert!(!env.wireguard_tools);
        assert_eq!(env.blocking_reason(), None);
    }

    #[test]
    fn inspect_refuses_an_unconfirmed_host_before_anything_else() {
        let (port, _) = crate::ssh::test_support::start_server();
        let target = crate::ssh::test_support::target(port);
        let error = inspect(&target, "whatever", None, None, Duration::from_secs(10))
            .expect_err("没有钉住指纹时不能继续");
        assert!(matches!(error, Error::HostKeyUnknown { .. }), "{error:?}");
    }

    #[test]
    fn a_tunnel_status_is_parsed_when_the_server_reports_one() {
        let text = SAMPLE.replace(
            "TC_DONE=1",
            "TC_TUNNEL=up\nTC_HANDSHAKE=1700000000\nTC_PEERS=1\nTC_RX=1024\nTC_TX=2048\nTC_DONE=1",
        );
        let env = parse_inspect(&text).unwrap();
        let tunnel = env.tunnel.clone().expect("必须解析出隧道状态");
        assert!(tunnel.up);
        assert_eq!(tunnel.latest_handshake, 1_700_000_000);
        assert_eq!(tunnel.peers, 1);
        assert_eq!(tunnel.rx_bytes, 1024);
        assert_eq!(tunnel.tx_bytes, 2048);
        assert!(env.summary().contains("隧道：运行中"), "{}", env.summary());
    }

    #[test]
    fn no_tunnel_block_means_no_tunnel_claim() {
        let env = parse_inspect(SAMPLE).unwrap();
        assert!(env.tunnel.is_none(), "没报隧道就不能编一个出来");
        assert!(env.summary().contains("还没有对应接口"), "{}", env.summary());
    }

    const INSTALLED: &str = "TC_INTERFACE=tc9f1c2a44\n\
TC_SERVER_PUBLIC=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
TC_LISTEN_PORT=51820\n\
TC_SUBNET=10.66.0.0/24\n\
TC_IFACE_ADDRESS=10.66.0.1/24\n\
TC_DONE=1\n";

    fn spec() -> Spec {
        Spec::for_record("9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b")
    }

    #[test]
    fn the_interface_name_comes_from_the_record_id_and_fits_the_kernel_limit() {
        let spec = spec();
        assert_eq!(spec.interface, "tc9f1c2a44");
        assert!(spec.interface.len() <= 15, "Linux 的接口名上限是 15 个字符");
        spec.validate().expect("默认参数必须合法");
    }

    /// r93：TCP 端口与握手域名在**连服务器之前**就要判。
    #[test]
    fn the_compatible_transport_choices_are_validated_before_connecting() {
        let mut bad = spec();
        bad.transport_port = 80;
        assert!(bad.validate().unwrap_err().contains("443、8443、2443"));
        bad.transport_port = 0;
        bad.validate().expect("0 = 默认值，必须合法");

        let mut bad = spec();
        bad.transport_server_name = "not a domain".to_string();
        assert!(bad.validate().unwrap_err().contains("握手目标"));
        bad.transport_server_name = "localhost".to_string();
        assert!(bad.validate().is_err(), "单段域名不是握手目标");
        bad.transport_server_name = String::new();
        bad.validate().expect("空 = 默认值，必须合法");
    }

    /// r93：自定义端口与握手域名必须真的进到服务器脚本里。
    #[test]
    fn a_custom_tcp_port_and_server_name_reach_the_script() {
        let identity = new_identity_with(2443, "www.example.com").expect("应当能生成身份");
        let script = transport_script(&spec(), "203.0.113.10", &identity);
        // 脚本顶部的两个变量就是服务端最终写入 transport.env 的值。
        assert!(script.contains("PORT='2443'"), "{script}");
        assert!(script.contains("SNI='www.example.com'"), "{script}");
        // 配置模板用占位符，再由这两个变量替换——所以也要确认替换链在。
        assert!(script.contains("@@C_PORT@@"), "{script}");
        assert!(script.contains("@@C_SNI@@"), "{script}");
        assert!(script.contains("|$PORT|g"), "{script}");
        assert!(script.contains("|$SNI|g"), "{script}");
    }

    /// r93：私钥/端口越界时 `new_identity_with` 不生成任何东西。
    #[test]
    fn an_invalid_transport_choice_never_creates_an_identity() {
        assert!(new_identity_with(80, "www.bing.com").is_err());
        assert!(new_identity_with(443, "bad").is_err());
        assert!(new_identity_with(443, "").is_err());
    }

    #[test]
    fn an_illegal_interface_name_is_refused_before_connecting() {
        let mut bad = spec();
        bad.interface = "tc-9f1c2a44".to_string();
        assert!(bad.validate().unwrap_err().contains("下划线"));
        bad.interface = "t".repeat(16);
        assert!(bad.validate().unwrap_err().contains("1–15"));
        let mut port = spec();
        port.port = 80;
        assert!(port.validate().unwrap_err().contains("1024"));
    }

    /// 私钥是本产品最不能泄的东西：它只能落到 600 的文件里，
    /// **绝不能**出现在 stdout（stdout 会进日志、进工单、进聊天记录）。
    #[test]
    fn the_install_script_never_echoes_the_private_key() {
        let script = install_script(&spec());
        assert!(script.contains("[ -s \"$KEY\" ] || wg genkey > \"$KEY\""), "必须复用已有密钥");
        assert!(script.contains("chmod 600 \"$KEY\""));
        assert!(!script.contains("echo \"$PRIV\""), "脚本把私钥打出来了");
        assert!(!script.contains("echo $PRIV"), "脚本把私钥打出来了");
        // 只有一处把私钥写进配置（heredoc），那是对的。
        assert_eq!(script.matches("$PRIV").count(), 2, "私钥只该出现在读入与写配置两处");
    }

    /// 重跑不能因为 nft 表已存在而失败：PostUp 先删再建。
    #[test]
    fn the_install_script_can_run_twice() {
        let script = install_script(&spec());
        // 删表必须容错：wg-quick 用 `set -e` 跑 PostUp，表不存在时 `nft delete`
        // 返回 1 会让整条钩子中止、接口被回滚——真机上就是这么失败的。
        assert!(script.contains("nft delete table inet $TABLE 2>/dev/null || true;"), "{script}");
        assert!(script.contains("systemctl restart \"wg-quick@$IFACE\""), "重跑要重新拉起服务");
        assert!(script.contains("TC_DONE=1"));
    }

    /// 语法必须是合法的 POSIX shell。
    ///
    /// 这条能在**没有 Linux 的机器上**抓住绝大多数手写脚本的事故：引号没闭合、
    /// heredoc 少一个 EOF、`if` 少了 `fi`。真机验收仍然必须做，但语法错不该等到那时才发现。
    #[test]
    fn the_install_script_parses_as_posix_shell() {
        use std::io::Write;
        let script = install_script(&spec());
        let Ok(mut child) = std::process::Command::new("sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("跳过：本机没有 sh，无法做语法检查");
            return;
        };
        child
            .stdin
            .as_mut()
            .expect("stdin 已接管")
            .write_all(script.as_bytes())
            .expect("应当能写入脚本");
        let out = child.wait_with_output().expect("等待 sh");
        assert!(
            out.status.success(),
            "部署脚本不是合法的 shell：{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn a_complete_result_yields_the_public_key_port_and_subnet() {
        let installed = parse_install(INSTALLED).expect("完整输出必须能解析");
        assert_eq!(installed.interface, "tc9f1c2a44");
        assert_eq!(installed.port, 51820);
        assert_eq!(installed.subnet, "10.66.0.0/24");
        assert_eq!(installed.server_public_key, "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
    }

    #[test]
    fn a_failure_marker_is_reported_with_its_code() {
        let error = parse_install("TC_ERROR=PortBusy\n").expect_err("失败码必须报错");
        assert!(error.contains("PortBusy"), "{error}");
    }

    #[test]
    fn a_result_without_the_done_marker_is_refused() {
        let truncated = INSTALLED.replace("TC_DONE=1\n", "");
        let error = parse_install(&truncated).expect_err("没有结束标记必须报错");
        assert!(error.contains("没有跑完"), "{error}");
    }

    #[test]
    fn a_public_key_of_the_wrong_shape_is_refused() {
        let bad = INSTALLED.replace(
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "not-a-key",
        );
        let error = parse_install(&bad).expect_err("公钥形状不对必须报错");
        assert!(error.contains("公钥形状"), "{error}");
    }

    /// 计划文本必须**如实**：说清要碰哪些文件，且不能出现「已完成」这种话。
    #[test]
    fn the_plan_names_every_file_and_never_claims_to_have_done_anything() {
        let text = plan_text(&spec(), "root@203.0.113.10:22");
        assert!(text.contains("预览"), "{text}");
        assert!(text.contains("/etc/wireguard/tc9f1c2a44.conf"), "{text}");
        assert!(text.contains("UDP 51820"), "{text}");
        assert!(text.contains("10.66.0.1/24"), "{text}");
        assert!(text.contains("--server-deploy-apply"), "要告诉用户下一步怎么执行：{text}");
        assert!(!text.contains("已完成"), "预览不能说成已完成：{text}");
    }

    /// 端到端：真握手 → 真执行部署脚本 → 真解析结果。
    #[test]
    fn install_runs_over_a_real_ssh_session() {
        let (port, fingerprint) = crate::ssh::test_support::start_server();
        let target = crate::ssh::test_support::target(port);
        let installed = install(
            &target,
            crate::ssh::test_support::PASSWORD,
            &fingerprint,
            &spec(),
            Duration::from_secs(10),
        )
        .expect("应当能完成部署");
        assert_eq!(installed.interface, "tc9f1c2a44");
        assert_eq!(installed.port, 51820);
        assert_eq!(installed.interface_address, "10.66.0.1/24");
    }

    // ---- 客户端接入 ----

    #[test]
    fn the_peer_script_syncs_one_peer_without_touching_the_others() {
        let script = peer_script(&spec(), "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
        // 按公钥只替换自己那一段：别人的 peer 必须原样留着。
        // （以前是「整段重写 [Peer]」，第二台设备接入会把第一台挤掉。）
        assert!(script.contains("if (k == pub) next"), "必须按公钥去重：{script}");
        // 热更新，不重启接口：重启会把所有在线设备同时踢掉。
        assert!(
            script.contains("wg syncconf \"$IFACE\" \"$SYNC\""),
            "必须用 syncconf 热更新：{script}"
        );
        assert!(
            !script.contains("systemctl restart \"wg-quick@"),
            "不能重启隧道——那会断开所有已连接的设备：{script}"
        );
        // 后置校验：不能只看命令退出码。
        assert!(script.contains("grep -qx \"$PUB\""), "后置必须核对 peer 真的挂上了");
        assert!(!script.contains("echo \"$PRIV\""), "脚本不能把私钥打出来");
    }

    #[test]
    fn the_peer_script_parses_as_posix_shell() {
        use std::io::Write;
        let script = peer_script(&spec(), "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
        let Ok(mut child) = std::process::Command::new("sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("跳过：本机没有 sh");
            return;
        };
        child.stdin.as_mut().unwrap().write_all(script.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "peer 脚本不是合法的 shell：{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn a_peer_result_without_the_server_key_is_refused() {
        let error = parse_peer("TC_PEER=abc\nTC_DONE=1\n").expect_err("缺服务端公钥必须报错");
        assert!(error.contains("自己的公钥"), "{error}");
        let error = parse_peer("TC_ERROR=PeerMissing\n").expect_err("失败码必须报错");
        assert!(error.contains("PeerMissing"), "{error}");
    }

    #[test]
    fn old_wireguard_writers_refuse_retired_pairing_host_before_side_effects() {
        let s = spec();
        let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        for script in [
            peer_script(&s,key),
            revoke_script(&s,key),
            uninstall_script(&s),
        ] {
            let prelude = crate::legacy_writer_fence::SHELL_DENY_PRELUDE;
            assert!(script.starts_with(&format!("set -eu\n{prelude}")), "{script}");
            assert!(script.find("exit 73").unwrap() < script.find("IFACE=").unwrap());
            assert!(script.contains("TC_ERROR=LegacyWriterFenced"));
        }
    }

    #[test]
    fn sec01_install_transport_restore_are_guarded_before_all_mutations() {
        let policy=crate::legacy_writer_fence::SHELL_DENY_PRELUDE;
        let s=spec();
        let install=install_script(&s);
        let transport=transport_script(&s,"203.0.113.10",&sample_identity());
        let restore=identity_restore_script(&s,&sample_backup(),false);
        for (name,script) in [
            ("wireguard install", install.as_str()),
            ("transport install", transport.as_str()),
            ("identity restore", restore.as_str()),
        ] {
            assert!(script.starts_with(&format!("set -eu\n{policy}")), "{name}");
            assert_eq!(script.matches("TC_ERROR=LegacyWriterFenced").count(),1,
                "{name} must have exactly one strict retirement guard");
            let first_write=["mkdir -p","cat >","apt-get install","systemctl restart",
                "mv \"", "wg syncconf","chmod "]
                .into_iter().filter_map(|cmd|script.find(cmd)).min()
                .expect("writer should contain at least one persistent side effect");
            assert!(script.find("exit 73").unwrap() < first_write, "{name}");
        }
        assert!(install.contains("wg-quick@$IFACE"), "original WG installation retained");
        assert!(transport.contains("@@CONFIG@@")==false, "transport render still applies");
        assert!(restore.contains("IdentityDiffers"), "restore conflict check retained");
    }

    // ---- 撤销设备 ----

    #[test]
    fn the_revoke_script_removes_only_that_peer_and_never_restarts() {
        let script = revoke_script(&spec(), "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
        // 仍然是按公钥分段比对：只删自己那一段，别人的设备一个都不能掉。
        assert!(script.contains("if (k == pub) next"), "{script}");
        assert!(script.contains("wg syncconf \"$IFACE\" \"$SYNC\""), "必须热更新：{script}");
        assert!(
            !script.contains("systemctl restart \"wg-quick@"),
            "撤销不能重启隧道——那会把所有在线设备一起踢掉：{script}"
        );
        // 三条拒绝：服务器自己的密钥、不存在的 peer、配置里还残留。
        assert!(script.contains("fail RefuseServerKey"), "{script}");
        assert!(script.contains("fail PeerNotFound"), "{script}");
        assert!(script.contains("fail ConfigStillHasPeer"), "{script}");
        // 后置必须回读接口，而不是只看退出码。
        assert!(script.contains("fail PeerStillConnected"), "{script}");
        assert!(!script.contains("echo \"$PRIV\""), "脚本不能把私钥打出来");
    }

    #[test]
    fn the_revoke_script_parses_as_posix_shell() {
        use std::io::Write;
        let script = revoke_script(&spec(), "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
        let Ok(mut child) = std::process::Command::new("sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("跳过：本机没有 sh");
            return;
        };
        child.stdin.as_mut().unwrap().write_all(script.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "撤销脚本不是合法的 shell：{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// 真正决定「删谁、留谁」的是这段 awk：用一份真配置跑一遍，别人的 peer 必须原样在。
    #[test]
    fn the_drop_peer_awk_removes_only_the_named_device() {
        use std::io::Write;
        const MINE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        const OTHER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!(
            "[Interface]\nPrivateKey = k\nListenPort = 51820\n\n\
             [Peer]\nPublicKey = {OTHER}\nAllowedIPs = 10.66.0.3/32\n\n\
             [Peer]\nPublicKey = {MINE}\nAllowedIPs = 10.66.0.2/32\n"
        );
        let Ok(mut child) = std::process::Command::new("awk")
            .arg("-v")
            .arg(format!("pub={MINE}"))
            .arg(DROP_PEER_AWK)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("跳过：本机没有 awk");
            return;
        };
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(config.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "awk 失败：{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(text.contains(OTHER), "别的设备必须留着：{text}");
        assert!(!text.contains(MINE), "目标设备必须删掉：{text}");
        assert!(text.contains("[Interface]"), "接口段不能被删：{text}");
    }

    #[test]
    fn revoke_failures_are_translated_into_next_steps() {
        let error = parse_revoke("TC_ERROR=PeerNotFound\n").expect_err("必须报错");
        assert!(error.contains("已经不在服务器上"), "{error}");
        let error = parse_revoke("TC_ERROR=RefuseServerKey\n").expect_err("必须报错");
        assert!(error.contains("不能移除服务器自己的密钥"), "{error}");
        let error = parse_revoke("TC_REVOKED=abc\n").expect_err("没有结束标记必须报错");
        assert!(error.contains("没有跑完"), "{error}");
        let ack = parse_revoke("TC_REVOKED=abc\nTC_PEERS=1\nTC_DONE=1\n").expect("正常回包");
        assert_eq!(ack.public_key, "abc");
        assert_eq!(ack.peers, 1);
    }

    #[test]
    fn the_client_conf_matches_the_joined_line_shape() {
        let conf = client_conf(
            &spec(),
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "203.0.113.10",
            "iICrpF8+i0hEzrYg3i6uQjUGfsPTQJq9WaYyDS4Bjkg=",
        );
        // 与 `pairing::tunnel::render` 同一种文件：CRLF、结尾一个 CRLF、全量路由、保活 25。
        assert!(conf.contains("\r\n"), "必须用 CRLF");
        assert!(conf.ends_with("\r\n") && !conf.ends_with("\r\n\r\n"));
        assert!(conf.contains("Address = 10.66.0.2/32"), "{conf}");
        assert!(conf.contains("AllowedIPs = 0.0.0.0/0"), "{conf}");
        assert!(conf.contains("PersistentKeepalive = 25"), "{conf}");
        assert!(conf.contains("Endpoint = 203.0.113.10:51820"), "{conf}");
        // 生成的配置必须能被我们自己的解析器读回来（两条路同一种形状）。
        let parsed = crate::pairing::line::parse_client_conf(&conf).expect("必须能被解析");
        assert_eq!(parsed.address, "10.66.0.2");
        assert_eq!(parsed.endpoint_port, 51820);
    }

    #[test]
    fn add_peer_round_trips_the_client_key_over_a_real_session() {
        let (port, fingerprint) = crate::ssh::test_support::start_server();
        let target = crate::ssh::test_support::target(port);
        let client_public = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let ack = add_peer(
            &target,
            crate::ssh::test_support::PASSWORD,
            &fingerprint,
            &spec(),
            client_public,
            Duration::from_secs(10),
        )
        .expect("应当能登记 peer");
        assert_eq!(ack.client_public, client_public, "服务器确认的必须就是我们发的那把");
        assert_eq!(ack.server_public, "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
    }

    // ---- 兼容连接（服务端 TCP / REALITY）----

    /// REALITY 的密钥是同一串 32 字节，只是编码不同。**不能做字符串替换**：
    /// 标准 base64 的 `+` `/` 与 url-safe 的 `-` `_` 不是一一对应。
    #[test]
    fn url_keys_are_the_same_32_bytes_in_another_encoding() {
        let standard = "d+u6Rd53MtjGqKr+jmV/k5TfWrIFdF6OSqqINw61SKo=";
        let url = url_key(standard).unwrap();
        assert_eq!(url.len(), 43, "REALITY 只认 43 位无填充：{url}");
        assert!(!url.contains('+') && !url.contains('/') && !url.contains('='), "{url}");
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&url)
                .unwrap(),
            base64::engine::general_purpose::STANDARD
                .decode(standard)
                .unwrap(),
            "换编码不能换字节"
        );
    }

    /// 新生成的身份必须形状正确，而且**公私钥是同一对**——
    /// 私钥换了公钥没跟着换，客户端永远握不上手，日志里只看到超时。
    #[test]
    fn a_fresh_identity_is_self_consistent() {
        let identity = new_identity().expect("应当能生成身份");
        assert!(is_url_key_43(&identity.private_key), "{}", identity.private_key);
        assert!(is_url_key_43(&identity.public_key), "{}", identity.public_key);
        assert_eq!(identity.short_id.len(), 16);
        assert!(identity.short_id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(crate::pairing::is_uuid_v4_shape(&identity.uuid), "{}", identity.uuid);
        assert_eq!(identity.port, TRANSPORT_PORT);

        use base64::Engine;
        let to_standard = |url: &str| {
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(url)
                .unwrap();
            base64::engine::general_purpose::STANDARD.encode(raw)
        };
        let derived =
            crate::pairing::keys::tunnel_public_from_private_b64(&to_standard(&identity.private_key))
                .unwrap();
        assert_eq!(
            to_standard(&identity.public_key),
            derived,
            "公钥必须能从私钥推出来"
        );
    }

    /// 服务端配置的两条路由规则是这条链路的安全边界：
    /// 只转发到本机 WireGuard，其余一律拒绝。少了 reject 就是一台开放代理。
    #[test]
    fn the_server_config_only_relays_the_tunnel_and_rejects_everything_else() {
        let identity = new_identity().unwrap();
        let text = transport_config(&identity, 51820, "203.0.113.10");
        let value: serde_json::Value = serde_json::from_str(&text).expect("必须是合法 JSON");
        let inbound = &value["inbounds"][0];
        assert_eq!(inbound["type"], "vless");
        assert_eq!(inbound["listen_port"], identity.port);
        assert_eq!(inbound["users"][0]["uuid"], identity.uuid);
        assert_eq!(inbound["tls"]["reality"]["private_key"], identity.private_key);
        assert_eq!(inbound["tls"]["reality"]["short_id"][0], identity.short_id);
        assert_eq!(
            inbound["tls"]["reality"]["handshake"]["server_port"], 443,
            "握手必须打到真站点的 443"
        );

        let relay = &value["route"]["rules"][0];
        assert_eq!(relay["network"], "udp");
        assert_eq!(relay["ip_cidr"][0], "203.0.113.10/32");
        assert_eq!(relay["port"][0], 51820);
        assert_eq!(relay["override_address"], "127.0.0.1", "改写到本机回环");
        // 中转只做两件事：转发 WireGuard 包、把客户端的 DNS 查询改写到本机解析器。
        // 第二条是「连上但网站打不开」换来的：本机 DNS 被污染，必须让解析也走隧道，
        // 而客户端到上游的 UDP 53 在这类服务器上是封的，只能由服务器本地 unbound
        // 代为解析（其上游走 TCP）。
        let dns = &value["route"]["rules"][1];
        assert_eq!(dns["network"], "udp");
        assert_eq!(dns["port"][0], 53);
        assert_eq!(dns["override_address"], "127.0.0.1", "改写到本机解析器");
        assert_eq!(value["route"]["rules"][2]["action"], "reject", "其余一律拒绝");
    }

    /// 脚本里的配置模板必须与 `transport_config` **同源**：把占位符换成真实值之后
    /// 逐字节相同。这是「配置只有一处定义」的机器保证。
    ///
    /// 这条用例是拿真机 bug 换来的：第一版脚本里嵌的是**本地新生成**的身份，
    /// 而服务器上已有身份时脚本会复用旧的 —— 配置里写新私钥、身份文件里留旧私钥，
    /// 客户端于是永远 `reality verification failed`，而两边看上去都「正常」。
    #[test]
    fn the_script_template_renders_to_the_generated_config() {
        let identity = new_identity().unwrap();
        let script = transport_script(&spec(), "203.0.113.10", &identity);

        let rendered = script
            .replace("@@C_PRIV@@", &identity.private_key)
            .replace("@@C_UUID@@", &identity.uuid)
            .replace("@@C_SID@@", &identity.short_id)
            .replace("\"@@C_PORT@@\"", &identity.port.to_string())
            .replace("@@C_SNI@@", &identity.server_name)
            .replace("@@C_HOST_IP@@", "203.0.113.10");
        let expected = transport_config(&identity, spec().port, "203.0.113.10");
        assert!(
            rendered.contains(&expected),
            "模板替换后必须与真实配置一致\n期望：{expected}"
        );

        // 身份以服务器上那份为准：脚本先 source 已有身份，再逐项替换进配置。
        assert!(script.contains(". \"$IDENTITY\""), "必须先 source 已有身份");
        assert!(script.contains("s|@@C_PRIV@@|$PRIV|g"), "私钥必须由脚本替换");
        assert!(script.contains("s|@@C_UUID@@|$UUID|g"), "UUID 必须由脚本替换");
        // 端口在 JSON 里是**数字**：模板里它是字符串，替换时必须连引号一起去掉，
        // 否则引擎会拿到 `"listen_port": "8443"` 并拒绝启动。
        assert!(
            script.contains("s|\\\"@@C_PORT@@\\\"|$PORT|g"),
            "端口替换必须去掉引号：{script}"
        );
        // 单引号 heredoc：配置里的字符一个都不能被 shell 展开。
        assert!(script.contains("<<'JSON'"), "配置必须用不展开的 heredoc 写入");
    }

    /// 安装脚本必须是合法 POSIX shell。这条用例在**没有 Linux 的机器上**
    /// 就能抓住引号没闭合、heredoc 少 EOF、`if` 少了 `fi` 这类事故。
    #[test]
    fn the_transport_script_parses_as_posix_shell() {
        use std::io::Write;
        let identity = new_identity().unwrap();
        let script = transport_script(&spec(), "203.0.113.10", &identity);
        let Ok(mut child) = std::process::Command::new("sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("跳过：本机没有 sh");
            return;
        };
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "传输安装脚本不是合法的 shell：{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// 三个摘要必须都在脚本里，而且私钥**绝不能出现在任何 echo 里**。
    #[test]
    fn the_transport_script_pins_digests_and_never_echoes_the_private_key() {
        let identity = new_identity().unwrap();
        let script = transport_script(&spec(), "203.0.113.10", &identity);
        for digest in [AMD64.archive, AMD64.binary, AMD64.library, ARM64.archive, ARM64.binary, ARM64.library] {
            assert!(script.contains(digest), "缺摘要 {digest}");
        }
        assert!(script.contains("sha256sum"), "必须真的校验");
        assert!(script.contains(&identity.private_key), "配置需要私钥");
        for line in script.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("echo") || trimmed.starts_with("printf") {
                assert!(
                    !line.contains(&identity.private_key),
                    "私钥不能出现在会回显的行里：{line}"
                );
            }
        }
        // ELF 架构号也来自常量：脚本里硬编码一份，改架构时会漏掉一处。
        assert!(script.contains("ELF='62'"), "amd64 的 ELF 架构号要来自常量");
        assert!(script.contains("ELF='183'"), "arm64 的 ELF 架构号要来自常量");
        // 身份文件存在时必须复用，否则第二台电脑接入会把第一台挤掉。
        assert!(script.contains(". \"$IDENTITY\""), "必须 source 已有身份");
        assert!(script.contains("IDENTITY_STATE=reused"));
        // **除 `@@C_*@@` 外一个占位符都不许漏**。`@@C_*@@` 是留给服务器侧 sed 的
        // （身份以服务器上那份为准），其余漏掉的那个会被当成字面量写进脚本或配置，
        // 而错误要到真机上才以「起不来」的形式出现。
        let mut leftovers: Vec<String> = Vec::new();
        let mut rest = script.as_str();
        while let Some(start) = rest.find("@@") {
            let after = &rest[start + 2..];
            let Some(end) = after.find("@@") else { break };
            let token = &rest[start..start + 2 + end + 2];
            if !token.starts_with("@@C_") {
                leftovers.push(token.to_string());
            }
            rest = &rest[start + 2 + end + 2..];
        }
        assert!(leftovers.is_empty(), "占位符必须全部替换：{leftovers:?}");
    }

    /// 服务器上还没装兼容连接时，只读回显给的是 `TC_TRANSPORT_ABSENT`，
    /// 这**不是错误**——join 要据此只登记标准连接。
    #[test]
    fn a_missing_transport_is_reported_as_absent_not_as_an_error() {
        assert_eq!(
            parse_transport("TC_TRANSPORT_ABSENT=1\nTC_DONE=1\n").unwrap(),
            None
        );
    }

    /// 形状不对必须拒绝：这些字段错了，客户端只会表现成「连不上」。
    #[test]
    fn a_malformed_transport_report_is_refused() {
        let bad_key = "TC_TRANSPORT_PUBLIC=too-short\n\
TC_TRANSPORT_UUID=9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b\n\
TC_TRANSPORT_SHORT_ID=0123456789abcdef\n\
TC_TRANSPORT_PORT=8443\n\
TC_TRANSPORT_SERVER_NAME=www.bing.com\n\
TC_DONE=1\n";
        assert!(parse_transport(bad_key).unwrap_err().contains("公钥"));

        let bad_sid = "TC_TRANSPORT_PUBLIC=yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk\n\
TC_TRANSPORT_UUID=9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b\n\
TC_TRANSPORT_SHORT_ID=zz\n\
TC_TRANSPORT_PORT=8443\n\
TC_TRANSPORT_SERVER_NAME=www.bing.com\n\
TC_DONE=1\n";
        assert!(parse_transport(bad_sid).unwrap_err().contains("ShortId"));

        // 没有结束标记 = 脚本没跑完，缺字段不能当成「没有这个能力」。
        assert!(parse_transport("TC_TRANSPORT_PUBLIC=x\n")
            .unwrap_err()
            .contains("没有跑完"));
    }

    /// 每台设备一行。界面「服务器与设备」靠它列出「谁在这条隧道上」，
    /// 所以解析错了不是少显示一行，而是页面给出错误的设备清单。
    #[test]
    fn a_tunnel_device_row_is_parsed_into_one_peer() {
        let text = SAMPLE.replace(
            "TC_DONE=1",
            "TC_TUNNEL=up\n\
TC_WG_PEER=10.66.0.2/32|zOzOTCHg/zSsmaaCu3FzUTWyGBbZdviQFre8ocltxEU=|1700000000|1024|2048|203.0.113.5:51820\n\
TC_WG_PEER=10.66.0.3/32|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|0|0|0|(none)\n\
TC_DONE=1",
        );
        let env = parse_inspect(&text).unwrap();
        let tunnel = env.tunnel.clone().expect("应当有隧道");
        assert_eq!(tunnel.devices.len(), 2, "两台设备要各占一行");
        assert_eq!(tunnel.devices[0].host(), "10.66.0.2", "掩码要去掉");
        assert_eq!(tunnel.devices[0].handshake, 1_700_000_000);
        assert_eq!(tunnel.devices[0].rx_bytes, 1024);
        assert_eq!(tunnel.devices[0].endpoint, "203.0.113.5:51820");
        assert_eq!(tunnel.devices[1].handshake, 0, "从未握手要如实记 0");
        assert!(env.summary().contains("设备 10.66.0.2"), "{}", env.summary());
        assert!(env.summary().contains("设备 10.66.0.3"), "{}", env.summary());
    }

    /// 设备行格式不对时必须报错：宁可整页说「读不到」，也不要列一份错的设备清单。
    #[test]
    fn a_malformed_device_row_is_refused() {
        let text = SAMPLE.replace("TC_DONE=1", "TC_WG_PEER=only-two|parts\nTC_DONE=1");
        let error = parse_inspect(&text).unwrap_err();
        assert!(error.contains("设备行"), "{error}");
    }

    /// 一份完整的回显必须逐字段读回来。
    #[test]
    fn a_complete_transport_report_is_parsed_field_by_field() {
        let text = "TC_TRANSPORT_PUBLIC=yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk\n\
TC_TRANSPORT_UUID=9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b\n\
TC_TRANSPORT_SHORT_ID=0123456789abcdef\n\
TC_TRANSPORT_PORT=8443\n\
TC_TRANSPORT_SERVER_NAME=www.bing.com\n\
TC_TRANSPORT_COMPONENT=installed\n\
TC_TRANSPORT_IDENTITY=created\n\
TC_DONE=1\n";
        let installed = parse_transport(text).unwrap().expect("必须解析出结果");
        assert_eq!(installed.public_key, "yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk");
        assert_eq!(installed.port, 8443);
        assert_eq!(installed.component, "installed");
        assert_eq!(installed.identity, "created");

        let compatible = installed.compatible("203.0.113.10");
        assert_eq!(compatible.server, "203.0.113.10");
        assert_eq!(compatible.port, 8443);
        assert_eq!(compatible.reality_short_id, "0123456789abcdef");
    }

    // ---- 身份备份与恢复 ----

    fn sample_identity() -> TransportIdentity {
        TransportIdentity {
            private_key: "yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk".to_string(),
            public_key: "Q2x7b1oD3nR5tY8uI0pA4sD6fG9hJ2kL5mN8qR1sT4v".to_string(),
            short_id: "0123456789abcdef".to_string(),
            uuid: "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b".to_string(),
            port: 8443,
            server_name: "www.bing.com".to_string(),
        }
    }

    fn sample_backup() -> TransportBackup {
        TransportBackup {
            target: "root@203.0.113.10:22".to_string(),
            host: "203.0.113.10".to_string(),
            created_at: "2026-11-04T05:00:00Z".to_string(),
            identity: sample_identity(),
            identity_sha256: "abc123".to_string(),
        }
    }

    #[test]
    fn a_transport_export_round_trips_and_reports_absence_honestly() {
        let identity = sample_identity();
        let text = format!(
            "TC_PRIVATE={}\nTC_PUBLIC={}\nTC_SHORT_ID=0123456789abcdef\n\
TC_UUID=9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b\nTC_PORT=8443\n\
TC_SERVER_NAME=www.bing.com\nTC_IDENTITY_SHA=abc123\nTC_DONE=1\n",
            identity.private_key, identity.public_key
        );
        let exported = parse_transport_export(&text).unwrap().expect("必须解析出身份");
        assert_eq!(exported.identity, identity);
        assert_eq!(exported.identity_sha256, "abc123");

        // 没装就是没装，不是错误。
        assert!(parse_transport_export("TC_TRANSPORT_ABSENT=1\nTC_DONE=1\n")
            .unwrap()
            .is_none());
        // 失败码与截断都必须报错。
        assert!(parse_transport_export("TC_ERROR=NoIdentity\n")
            .unwrap_err()
            .contains("NoIdentity"));
        assert!(parse_transport_export("TC_PRIVATE=x\nTC_DONE=1\n")
            .unwrap_err()
            .contains("TC_PUBLIC"));
    }

    #[test]
    fn identity_validation_names_the_bad_field() {
        let mut identity = sample_identity();
        validate_identity(&identity).expect("样例本身必须合法");

        identity.private_key = "short".into();
        assert!(validate_identity(&identity).unwrap_err().contains("私钥"));

        identity = sample_identity();
        identity.public_key = sample_identity().private_key;
        assert!(validate_identity(&identity).unwrap_err().contains("相同"));

        identity = sample_identity();
        identity.short_id = "xyz".into();
        assert!(validate_identity(&identity).unwrap_err().contains("ShortId"));

        identity = sample_identity();
        identity.uuid = "not-a-uuid".into();
        assert!(validate_identity(&identity).unwrap_err().contains("UUID"));

        identity = sample_identity();
        identity.port = 80;
        assert!(validate_identity(&identity).unwrap_err().contains("1024"));

        identity = sample_identity();
        identity.server_name = "bad host".into();
        assert!(validate_identity(&identity).unwrap_err().contains("握手域名"));
    }

    #[test]
    fn a_backup_file_carries_a_warning_and_rejects_foreign_files() {
        let backup = sample_backup();
        let json = backup.to_json();
        assert_eq!(json["Kind"], "TradeChannel.TransportIdentityBackup");
        assert!(
            json["Warning"].as_str().unwrap_or("").contains("私钥"),
            "备份文件必须自己写明含私钥"
        );
        let back = TransportBackup::from_json(&json).expect("自己的文件必须能读回");
        assert_eq!(back, backup);

        let mut foreign = json.clone();
        foreign["Kind"] = serde_json::json!("TradeChannel.ServerRecord");
        assert!(TransportBackup::from_json(&foreign)
            .unwrap_err()
            .contains("不是线路身份备份"));
    }

    #[test]
    fn the_restore_script_writes_the_same_env_shape_and_refuses_to_clobber() {
        let backup = sample_backup();
        let script = identity_restore_script(&spec(), &backup, false);
        // 与生成脚本逐字同形：一个字段名写错，服务器就会读不到身份。
        assert!(
            script.contains("PRIVATE_KEY='yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk'"),
            "{script}"
        );
        assert!(
            script.contains("CLIENT_UUID='9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b'"),
            "{script}"
        );
        assert!(script.contains("TCP_PORT='8443'"), "{script}");
        assert!(script.contains("chmod 600 \"$IDENTITY\""), "{script}");
        // 身份不同且没有 --force 时必须停手：覆盖会让所有已接入设备失效。
        assert!(script.contains("EXPECT_SHA='abc123'"), "{script}");
        assert!(script.contains("FORCE='0'"), "{script}");
        assert!(script.contains("fail IdentityDiffers"), "{script}");
        assert!(identity_restore_script(&spec(), &backup, true).contains("FORCE='1'"));
    }

    #[test]
    fn the_backup_scripts_parse_as_posix_shell() {
        use std::io::Write;
        let scripts = [
            TRANSPORT_EXPORT_SCRIPT.replace("@@CONF_DIR@@", TRANSPORT_CONF_DIR),
            identity_restore_script(&spec(), &sample_backup(), true),
        ];
        for script in scripts {
            let Ok(mut child) = std::process::Command::new("sh")
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            else {
                eprintln!("跳过：本机没有 sh");
                return;
            };
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "身份备份/恢复脚本不是合法的 shell：{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

// ---------- 部署：装包、写配置、起服务 ----------

/// 一次部署的目标参数。**全部由本机决定**，不从服务器读：
/// 网段、端口、MTU 是客户端配置要引用的东西，先定下来才能两边对齐。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// WireGuard 接口名。Linux 的 IFNAMSIZ 是 16（含结尾 0），所以最多 15 个字符。
    pub interface: String,
    /// UDP 监听端口。
    pub port: u16,
    /// 隧道网段，例如 `10.66.0.0/24`。
    pub subnet: String,
    /// 服务端地址（网段首 +1），例如 `10.66.0.1/24`。
    pub address: String,
    pub mtu: u16,
    /// 兼容连接（TCP/REALITY）的首选端口。0 = 用默认值（见 [`TRANSPORT_PORT`]）。
    ///
    /// 旧版的 `DeployTcpPort` 只允许 443 / 8443 / 2443；这里保持同一组候选。
    pub transport_port: u16,
    /// 兼容连接的 REALITY 握手域名（旧版的`DeployServerName`，默认 `www.bing.com`）。
    /// 空 = 用默认值。
    pub transport_server_name: String,
}

/// 默认网段。选 10.66.0.0/24 是因为它落在 旧版用过的那一段里，
/// 现场的客户端配置与习惯都对得上；脚本里另有冲突检测，撞了会明确失败而不是硬上。
pub const DEFAULT_SUBNET: &str = "10.66.0.0/24";
pub const DEFAULT_PORT: u16 = 51_820;
pub const DEFAULT_MTU: u16 = 1380;

impl Spec {
    /// 从服务器记录 id 派生接口名：`tc` + id 去掉横线后的前 8 位。
    ///
    /// 用记录 id 而不是主机名：同一台机器换 IP 之后接口名不变，重跑不会留下两个接口。
    pub fn for_record(record_id: &str) -> Spec {
        let hex: String = record_id
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(8)
            .collect::<String>()
            .to_ascii_lowercase();
        Spec {
            interface: format!("tc{hex}"),
            port: DEFAULT_PORT,
            subnet: DEFAULT_SUBNET.to_string(),
            address: server_address(DEFAULT_SUBNET),
            mtu: DEFAULT_MTU,
            transport_port: TRANSPORT_PORT,
            transport_server_name: TRANSPORT_SERVER_NAME.to_string(),
        }
    }

    /// 兼容连接实际要用的 TCP 端口（0 = 默认值）。
    pub fn tcp_port(&self) -> u16 {
        if self.transport_port == 0 {
            TRANSPORT_PORT
        } else {
            self.transport_port
        }
    }

    /// 兼容连接实际要用的握手域名（空 = 默认值）。
    pub fn tcp_server_name(&self) -> &str {
        if self.transport_server_name.trim().is_empty() {
            TRANSPORT_SERVER_NAME
        } else {
            self.transport_server_name.trim()
        }
    }

    /// 形状检查。**在连服务器之前**做：一个非法接口名会让 `wg-quick` 在远端
    /// 报一句看不懂的话，而那时包已经装完了。
    pub fn validate(&self) -> Result<(), String> {
        let name = &self.interface;
        if name.is_empty() || name.len() > 15 {
            return Err(format!("接口名长度必须在 1–15 之间（收到 {name}）"));
        }
        if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(format!("接口名只能用小写字母、数字和下划线：{name}"));
        }
        if self.port < 1024 {
            return Err(format!("端口必须 ≥1024（收到 {}）", self.port));
        }
        if self.subnet != DEFAULT_SUBNET {
            // 这一版只支持默认网段：客户端配置、防火墙规则、地址计算都按它写死，
            // 放开成可配置只会让「服务端与客户端不一致」这种故障更难查。
            return Err(format!("这一版只支持 {DEFAULT_SUBNET}（收到 {}）", self.subnet));
        }
        if self.address != server_address(&self.subnet) {
            return Err("服务端地址必须是网段首 +1".to_string());
        }
        if !(1280..=1420).contains(&self.mtu) {
            return Err(format!("MTU 必须在 1280–1420 之间（收到 {}）", self.mtu));
        }
        // 兼容连接的端口与握手域名：旧版的 `Get-TCDeploymentPreferredTcpPorts`
        // 与 `Start-TCDeployment` 的域名正则就是这两条判据。
        if !matches!(self.tcp_port(), 443 | 8443 | 2443) {
            return Err(format!(
                "TCP 首选端口仅支持 443、8443、2443（收到 {}）",
                self.tcp_port()
            ));
        }
        if !is_tls_server_name(self.tcp_server_name()) {
            return Err(format!(
                "TCP 握手目标必须是一个域名（例如 www.bing.com），收到 {}",
                self.tcp_server_name()
            ));
        }
        Ok(())
    }
}

/// 兼容连接握手域名的形状检查。
///
/// 与旧版的`DeploymentFlow.psm1:744` 的正则同义：至少两段，每段 1–63 个
/// 字母/数字/连字符且不以连字符开头结尾，顶级域 2–63 个字母。
/// 不引入正则引擎：这几条用字符循环写出来更直白，也便于给出中文原因。
pub fn is_tls_server_name(name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    for part in &parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }
        let bytes = part.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return false;
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return false;
        }
    }
    let tld = parts[parts.len() - 1];
    (2..=63).contains(&tld.len()) && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

fn server_address(subnet: &str) -> String {
    // 只处理 /24：这一版网段固定，不做通用 CIDR 运算。
    let base = subnet.split('/').next().unwrap_or("");
    let mut parts: Vec<&str> = base.split('.').collect();
    if parts.len() == 4 {
        parts[3] = "1";
        format!("{}/24", parts.join("."))
    } else {
        String::new()
    }
}

/// 部署脚本。**幂等**：密钥已存在就复用，配置每次重写，服务每次重启。
///
/// 几条硬约束：
/// - 私钥只写进 `/etc/wireguard/*.key`（600），**绝不 echo**；
/// - 任何一步失败都先打 `TC_ERROR=<码>` 再退出，调用方据此给人话；
/// - 成功时以 `TC_DONE=1` 收尾，缺它就是没跑完（被截断/被杀）；
/// - 失败时把 `journalctl` 的最后几行送到 stderr——隧道起不来的原因九成在那里面。
pub fn install_script(spec: &Spec) -> String {
    let Spec {
        interface,
        port,
        subnet,
        address,
        mtu,
        ..
    } = spec;
    let table = format!("tc_{interface}");
    let rendered = format!(
        r#"set -eu
umask 077
IFACE='{interface}'
PORT='{port}'
SUBNET='{subnet}'
ADDR='{address}'
MTU='{mtu}'
TABLE='{table}'
DIR=/etc/wireguard
KEY="$DIR/$IFACE.key"
CONF="$DIR/$IFACE.conf"
fail() {{ echo "TC_ERROR=$1"; exit 1; }}

[ "$(id -u)" = 0 ] || fail NotRoot
command -v systemctl >/dev/null 2>&1 || fail NoSystemd

# 1) 依赖：已装就跳过；认不出包管理器就明确失败，不猜。
if ! command -v wg >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || fail PackageIndexFailed
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools nftables >/dev/null 2>&1 || fail PackageInstallFailed
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q wireguard-tools nftables >/dev/null 2>&1 || fail PackageInstallFailed
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q wireguard-tools nftables >/dev/null 2>&1 || fail PackageInstallFailed
  else
    fail UnsupportedPackageManager
  fi
fi
command -v wg >/dev/null 2>&1 || fail WireGuardToolsMissing
command -v nft >/dev/null 2>&1 || fail NftMissing

# 2) 端口与网段：撞了就说清楚，不自动改（改了就与计划里写的不一致）。
if ss -lun 2>/dev/null | awk 'NR>1 {{print $4}}' | grep -q ":$PORT$"; then fail PortBusy; fi
if ip -4 route show 2>/dev/null | awk '{{print $1}}' | grep -qx "$SUBNET"; then fail SubnetConflict; fi

# 3) 密钥：已有就复用，重跑不会换掉客户端正在用的那把。
mkdir -p "$DIR"
chmod 700 "$DIR"
[ -s "$KEY" ] || wg genkey > "$KEY"
chmod 600 "$KEY"
PRIV=$(cat "$KEY")
PUB=$(printf '%s' "$PRIV" | wg pubkey)
[ -n "$PUB" ] || fail KeyGenerationFailed

# 4) 配置。PostUp 里先删表再建：重跑时 nft add 不会因为「已存在」失败。
WAN=$(ip route show default 2>/dev/null | awk '/^default/ {{print $5; exit}}')
[ -n "$WAN" ] || fail NoDefaultRoute
cat > "$CONF" <<EOF
[Interface]
Address = $ADDR
ListenPort = $PORT
PrivateKey = $PRIV
MTU = $MTU
PostUp = nft delete table inet $TABLE 2>/dev/null || true; nft add table inet $TABLE; nft 'add chain inet $TABLE post {{ type nat hook postrouting priority 100 ; }}'; nft add rule inet $TABLE post ip saddr $SUBNET oifname "$WAN" masquerade; nft 'add chain inet $TABLE lanefwd {{ type filter hook forward priority -10 ; policy accept ; }}'; nft add rule inet $TABLE lanefwd iifname "$IFACE" accept; nft add rule inet $TABLE lanefwd oifname "$IFACE" accept; sysctl -q -w net.ipv4.ip_forward=1
PostDown = nft delete table inet $TABLE 2>/dev/null || true
EOF
chmod 600 "$CONF"

# 5) 转发持久化：只在重启后仍然生效才算真的开了。
echo 'net.ipv4.ip_forward=1' > "/etc/sysctl.d/99-$IFACE.conf"
sysctl -q -w net.ipv4.ip_forward=1

# 6) 服务。失败时把日志尾巴送到 stderr：隧道起不来的原因九成在那里面。
systemctl enable "wg-quick@$IFACE" >/dev/null 2>&1 || true
if ! systemctl restart "wg-quick@$IFACE"; then
  journalctl -u "wg-quick@$IFACE" -n 20 --no-pager 2>&1 | tail -20 >&2
  fail TunnelStartFailed
fi
systemctl is-active --quiet "wg-quick@$IFACE" || fail TunnelNotActive

# 7) 后置校验：服务说 active 不等于接口真的带着地址起来了。
IFACE_ADDR=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk 'NR==1 {{print $4}}')
[ "$IFACE_ADDR" = "$ADDR" ] || fail TunnelAddressMismatch
IFACE_PORT=$(wg show "$IFACE" listen-port 2>/dev/null)
[ "$IFACE_PORT" = "$PORT" ] || fail TunnelPortMismatch

echo "TC_INTERFACE=$IFACE"
echo "TC_SERVER_PUBLIC=$PUB"
echo "TC_LISTEN_PORT=$IFACE_PORT"
echo "TC_IFACE_ADDRESS=$IFACE_ADDR"
echo "TC_SUBNET=$SUBNET"
echo "TC_DONE=1"
"#
    );
    crate::legacy_writer_fence::guard_legacy_mutation_script(&rendered)
}

/// 部署成功后服务器那边的事实。客户端配置要用它。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub interface: String,
    pub server_public_key: String,
    pub port: u16,
    pub subnet: String,
    /// 接口上真实的地址（脚本用 `ip -4 -o addr` 读回来的，不是把参数抄一遍）。
    pub interface_address: String,
}

pub fn parse_install(stdout: &str) -> Result<Installed, String> {
    let mut interface = None;
    let mut public = None;
    let mut port = None;
    let mut subnet = None;
    let mut iface_address = None;
    let mut done = false;
    let mut failure = None;

    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim().to_string();
        match key {
            "TC_INTERFACE" => interface = Some(value),
            "TC_SERVER_PUBLIC" => public = Some(value),
            "TC_LISTEN_PORT" => {
                port = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| format!("服务器返回的端口不是数字：{value}"))?,
                )
            }
            "TC_SUBNET" => subnet = Some(value),
            "TC_IFACE_ADDRESS" => iface_address = Some(value),
            "TC_DONE" => done = value == "1",
            "TC_ERROR" => failure = Some(value),
            _ => {}
        }
    }

    if let Some(code) = failure {
        return Err(format!("服务器上的部署没有完成：{code}"));
    }
    if !done {
        return Err("部署脚本没有跑完（服务器没有返回结束标记）：可能被截断，请重试。".to_string());
    }
    let missing = |name: &str| format!("部署结果缺少 {name}：服务器可能没按预期执行。");
    let public = public.ok_or_else(|| missing("服务端公钥"))?;
    if public.len() != 44 || !public.ends_with('=') {
        return Err(format!("服务器返回的公钥形状不对：{public}"));
    }
    Ok(Installed {
        interface: interface.ok_or_else(|| missing("接口名"))?,
        server_public_key: public,
        port: port.ok_or_else(|| missing("监听端口"))?,
        subnet: subnet.ok_or_else(|| missing("隧道网段"))?,
        interface_address: iface_address.ok_or_else(|| missing("接口地址"))?,
    })
}

/// 真执行。`expected` 必须是已确认的指纹（部署是改系统的动作，不接受「先连上再说」）。
pub fn install<'a>(
    target: &Target,
    auth: impl Into<Auth<'a>>,
    expected: &str,
    spec: &Spec,
    timeout: Duration,
) -> Result<Installed, Error> {
    let auth = auth.into();
    spec.validate().map_err(Error::Command)?;
    let output = ssh::exec(target, auth, Some(expected), &install_script(spec), timeout)?;
    if output.truncated {
        return Err(Error::Command("部署输出被截断，未采用".to_string()));
    }
    // 失败码在 stdout 里（脚本先 echo 再 exit），所以**先解析再看退出码**：
    // 只看退出码会把「PortBusy」说成「命令失败」，用户不知道该改什么。
    match parse_install(&output.stdout) {
        Ok(installed) => Ok(installed),
        Err(message) => {
            // 脚本在失败时把 `journalctl` 的尾巴送到了 stderr——**必须带出去**。
            // 少了它，用户看到的只有「TunnelStartFailed」，而原因九成就在那几行里。
            let mut detail = message;
            let stderr = output.stderr.trim();
            if !stderr.is_empty() {
                // 取**最后** 2000 字：有用的永远是末尾（journal 的最新几行），
                // 保留开头只会把真正的原因截掉。
                let total = stderr.chars().count();
                let mut tail: String = stderr.chars().skip(total.saturating_sub(2000)).collect();
                if total > 2000 {
                    tail.insert_str(0, "…（前面已截断）\n");
                }
                detail.push_str("\n--- 服务器上的最后输出 ---\n");
                detail.push_str(&tail);
            }
            if output.code != 0 && !detail.contains("没有完成") {
                Err(Error::Command(format!("{detail}（退出码 {}）", output.code)))
            } else {
                Err(Error::Command(detail))
            }
        }
    }
}

/// 计划文本。**不连接**、不读服务器：它回答的是「将要做什么」，
/// 所以只能在 `--server-deploy` 里打印，不能在 apply 之后补。
pub fn plan_text(spec: &Spec, address: &str) -> String {
    format!(
        "将在 {address} 上执行（预览，尚未连接）：\n\
         \x20 · 安装 wireguard-tools、nftables（已安装则跳过）\n\
         \x20 · 生成/复用服务端密钥 /etc/wireguard/{iface}.key（权限 600，私钥不出服务器）\n\
         \x20 · 写 /etc/wireguard/{iface}.conf：{addr}，UDP {port}，MTU {mtu}\n\
         \x20 · 开 IPv4 转发并持久化，建 nftables 表 tc_{iface} 做 NAT（出接口取默认路由）\n\
         \x20 · 启用并重启 wg-quick@{iface}\n\
         确认无误后加 --server-deploy-apply 执行。",
        iface = spec.interface,
        addr = spec.address,
        port = spec.port,
        mtu = spec.mtu,
    )
}


//! 自动选路（A8 第一阶段）：候选探测、网络指纹、证据过期与排名。
//!
//! 这一层只回答一个问题：**在这台电脑当前的网络下，这条线路的标准连接与兼容连接
//! 哪一个真的能用、哪个更快**。答案不是猜的，也不是只看「上次连通过」：每个候选
//! 都用一次临时引擎真实拨过去，经 `tc-check` 入站发一次 HTTP 请求，拿到响应才算通。
//!
//! 边界（写清楚，免得把「第一阶段」当成 旧版的全套）：
//! - 只在**连接前**探测；不监听网络变化、不在连接中自动切换；
//! - 网络指纹只取「到公网的本机源地址」，换 Wi-Fi/换网段会变，同一网段内换 AP 不一定变；
//! - 证据 30 分钟后过期；过期或网络变了就重测；
//! - 用户显式固定的连接方式永远优先，探测不会覆盖它；
//! - 探测失败不是错误：回落到「已验证 → 标准连接」，并在证据里留下原因。
//!
//! 为什么用临时引擎而不是裸 TCP 握手：兼容连接是 VLESS+REALITY，裸 TCP 只能证明
//! 端口开着；标准连接是 WireGuard/UDP，连端口开没开都看不出来。只有让引擎按真实的
//! 方式拨一次，才配叫「候选探测」。

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::{AppConfig, LineConfig, Mode, Transport};

pub const KIND: &str = "TradeChannel.AutoRoute";
pub const SCHEMA: u32 = 1;
/// 证据有效期：与旧版的协议证据一致（30 分钟）。超过就重测，不拿旧网络下的结论
/// 给新网络用。
pub const EVIDENCE_TTL_SECS: i64 = 1_800;
const PROBE_WAIT_MS: u64 = 4_000;
/// 真实 VPS 上 WireGuard 握手 + 一次 HTTP 往返约 5.3 秒（2026-11-12 实测）。
/// 4 秒会把「慢但能用」的标准连接误判成不可达，进而无谓地选兼容连接。
const PROBE_REQUEST_MS: u64 = 8_000;
const MAX_ERROR_CHARS: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub transport: Transport,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: String,
    pub checked_at_unix: i64,
    /// 这一次读数是怎么来的：`direct`（无引擎 UDP 直探）或 `engine`（临时引擎）。
    /// 旧证据里没有这个字段，按 `engine` 读——不能把「以前没有直探」说成直探。
    pub method: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub network: String,
    pub checked_at_unix: i64,
    pub expires_at_unix: i64,
    pub candidates: Vec<Candidate>,
    pub winner: Option<Transport>,
}

/// 一次自动选择的结果。`source` 是给用户看的依据，不是内部枚举：
/// `UserChoice`（用户固定）、`Evidence`（新鲜证据）、`Probe`（刚测的）、`Fallback`（没依据）。
#[derive(Clone, Debug)]
pub struct Choice {
    pub transport: Transport,
    pub source: &'static str,
    pub evidence: Option<Evidence>,
    pub note: String,
}

fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_ERROR_CHARS {
        return text.to_string();
    }
    let mut out: String = text.chars().take(MAX_ERROR_CHARS).collect();
    out.push('…');
    out
}

fn store_path(root: &Path) -> PathBuf {
    root.join("autoroute.json")
}

/// 本机当前出口网络：源地址 + 默认网卡。
///
/// 指纹里带上网卡名，是因为「源地址不变、网卡变了」真的会发生（双网卡同网段、
/// VPN 虚拟网卡抢占默认路由）。只比源地址会把这种情况当成「网络没变」，
/// 拿旧证据去连一条刚换过出口的线路。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkInfo {
    pub source_ip: String,
    pub interface: String,
    /// 参与新鲜度比较的串：`源地址|网卡`；拿不到源地址时为空（不参与判断）。
    pub fingerprint: String,
}

/// 默认出口网卡的名称。取不到就是空串——它只增强指纹，不是探测的前置条件。
#[cfg(windows)]
fn default_interface() -> String {
    use std::ffi::CStr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{if_indextoname, GetBestInterface};
    // 1.1.1.1 与 `network_fingerprint` 的 UDP connect 用同一个目的地，
    // 保证「网卡」与「源地址」说的是同一条默认路由。
    let destination = u32::from_ne_bytes([1, 1, 1, 1]);
    let mut index: u32 = 0;
    // SAFETY: 两个参数都是本栈上的有效地址；成功时 index 被写入。
    let result = unsafe { GetBestInterface(destination, &mut index) };
    if result != 0 || index == 0 {
        return String::new();
    }
    let mut buffer = [0u8; 256];
    // SAFETY: buffer 是可写的 256 字节，`if_indextoname` 最多写 IF_NAMESIZE 字节。
    let name = unsafe { if_indextoname(index, buffer.as_mut_ptr()) };
    if name.is_null() {
        return String::new();
    }
    // SAFETY: 成功时返回以 NUL 结尾的串。
    unsafe { CStr::from_ptr(name.cast()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(not(windows))]
fn default_interface() -> String {
    String::new()
}

/// 本机所有网卡名（给「出口网卡」下拉用），第一项是默认路由走的那张。
///
/// 用 `if_indextoname` 逐个索引问，而不是 `GetAdaptersAddresses`：后者要
/// 自己走链表、管缓冲区与对齐，这里只要名字；索引问不到名字就当到头了。
/// 与 [`default_interface`] 同一个 API、同一个命名口径——`bind_interface`
/// 要的是同一串名字，两处口径一旦不同，绑上去就是静默失效。
#[cfg(windows)]
pub fn interfaces() -> Vec<String> {
    use std::ffi::CStr;
    use windows_sys::Win32::NetworkManagement::IpHelper::if_indextoname;

    let mut seen: Vec<String> = Vec::new();
    for index in 1u32..=64 {
        let mut buffer = [0u8; 256];
        // SAFETY: buffer 是可写的 256 字节，`if_indextoname` 最多写 IF_NAMESIZE 字节。
        let name = unsafe { if_indextoname(index, buffer.as_mut_ptr()) };
        if name.is_null() {
            continue;
        }
        // SAFETY: 成功时返回以 NUL 结尾的串。
        let text = unsafe { CStr::from_ptr(name.cast()) }
            .to_string_lossy()
            .into_owned();
        let text = text.trim().to_string();
        // `loopback_*` / `tunnel_*` 永远不会是「出口网卡」：绑上去等于把出站塞进
        // 本机回环或一条隧道。列出来只会让人选错，直接不给。
        if text.starts_with("loopback_") || text.starts_with("tunnel_") {
            continue;
        }
        if text.is_empty() || seen.iter().any(|item| item == &text) {
            continue;
        }
        seen.push(text);
    }
    // 默认网卡排第一：多数人只需要「保持默认」，把它藏在一串名字里反而难找。
    let default = default_interface();
    if !default.is_empty() {
        if let Some(position) = seen.iter().position(|item| item == &default) {
            seen.remove(position);
        }
        seen.insert(0, default);
    }
    seen
}

#[cfg(not(windows))]
pub fn interfaces() -> Vec<String> {
    Vec::new()
}

/// 取一次当前网络。所有探测共用这一份：同一个连接里两次取到不同的网卡，
/// 说明网络在探测过程中变了，那种读数本来就不能用。
pub fn network_info() -> NetworkInfo {
    let source_ip = {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();
        socket
            .and_then(|socket| {
                socket.connect("1.1.1.1:80").ok()?;
                socket.local_addr().ok()
            })
            .and_then(|address| match address {
                std::net::SocketAddr::V4(address) => Some(address.ip().to_string()),
                std::net::SocketAddr::V6(address) => Some(address.ip().to_string()),
            })
            .unwrap_or_default()
    };
    let interface = default_interface();
    let fingerprint = if source_ip.is_empty() {
        String::new()
    } else if interface.is_empty() {
        source_ip.clone()
    } else {
        format!("{source_ip}|{interface}")
    };
    NetworkInfo {
        source_ip,
        interface,
        fingerprint,
    }
}

/// 本机到公网的源地址。拿不到就是空串——空串**不参与**新鲜度判断（宁可重测）。
pub fn network_fingerprint() -> String {
    network_info().fingerprint
}

/// 读证据库。损坏/不存在都当成空：证据是可丢弃的缓存，不该让连接失败。
fn load_store(root: &Path) -> Value {
    let text = match std::fs::read_to_string(store_path(root)) {
        Ok(text) => text,
        Err(_) => return json!({"Kind": KIND, "Lines": {}}),
    };
    let mut value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if value.get("Kind").and_then(Value::as_str) != Some(KIND) {
        return json!({"Kind": KIND, "Lines": {}});
    }
    if !value.get("Lines").map(Value::is_object).unwrap_or(false) {
        value["Lines"] = json!({});
    }
    value
}

fn save_store(root: &Path, store: &Value) -> Result<(), String> {
    let file = store_path(root);
    let text = serde_json::to_string_pretty(store)
        .map_err(|error| format!("自动选路证据无法序列化：{error}"))?;
    let temp = file.with_extension("json.tmp");
    std::fs::write(&temp, text)
        .map_err(|error| format!("写入自动选路证据失败：{error}"))?;
    std::fs::rename(&temp, &file)
        .map_err(|error| format!("写入自动选路证据失败：{error}"))
}

fn candidate_to_json(candidate: &Candidate) -> Value {
    json!({
        "Transport": candidate.transport.id(),
        "Label": candidate.transport.label(),
        "Reachable": candidate.reachable,
        "LatencyMs": candidate.latency_ms,
        "Error": candidate.error,
        "CheckedAtUnix": candidate.checked_at_unix,
        "CheckedAtUtc": crate::pairing::rfc3339_micros(candidate.checked_at_unix),
        "Method": candidate.method,
    })
}

fn candidate_from_json(value: &Value) -> Option<Candidate> {
    let transport = match value.get("Transport").and_then(Value::as_str)? {
        "udp" => Transport::Udp,
        "tcp" => Transport::Tcp,
        _ => return None,
    };
    Some(Candidate {
        transport,
        reachable: value.get("Reachable").and_then(Value::as_bool).unwrap_or(false),
        latency_ms: value.get("LatencyMs").and_then(Value::as_u64),
        error: value.get("Error").and_then(Value::as_str).unwrap_or("").to_string(),
        checked_at_unix: value.get("CheckedAtUnix").and_then(Value::as_i64).unwrap_or(0),
        method: value
            .get("Method")
            .and_then(Value::as_str)
            .filter(|method| !method.is_empty())
            .unwrap_or("engine")
            .to_string(),
    })
}

fn evidence_to_json(evidence: &Evidence) -> Value {
    json!({
        "NetworkFingerprint": evidence.network,
        "CheckedAtUnix": evidence.checked_at_unix,
        "CheckedAtUtc": crate::pairing::rfc3339_micros(evidence.checked_at_unix),
        "ExpiresAtUnix": evidence.expires_at_unix,
        "ExpiresAtUtc": crate::pairing::rfc3339_micros(evidence.expires_at_unix),
        "Winner": evidence.winner.map(|t| t.id()).unwrap_or(""),
        "Candidates": evidence.candidates.iter().map(candidate_to_json).collect::<Vec<_>>(),
    })
}

fn evidence_from_json(value: &Value) -> Option<Evidence> {
    let candidates: Vec<Candidate> = value
        .get("Candidates")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(candidate_from_json)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let winner = match value.get("Winner").and_then(Value::as_str).unwrap_or("") {
        "udp" => Some(Transport::Udp),
        "tcp" => Some(Transport::Tcp),
        _ => None,
    };
    Some(Evidence {
        network: value.get("NetworkFingerprint").and_then(Value::as_str).unwrap_or("").to_string(),
        checked_at_unix: value.get("CheckedAtUnix").and_then(Value::as_i64).unwrap_or(0),
        expires_at_unix: value.get("ExpiresAtUnix").and_then(Value::as_i64).unwrap_or(0),
        candidates,
        winner,
    })
}

/// 这条线路的证据还新不新。三个条件缺一不可：有赢家、网络指纹相同、未过期。
pub fn is_fresh(evidence: &Evidence, network: &str, now_unix: i64) -> bool {
    !network.is_empty()
        && evidence.winner.is_some()
        && evidence.network == network
        && evidence.expires_at_unix > now_unix
}

/// 排名：能用的优先；都能用时延迟低的优先；延迟相同选标准连接（少一层中转）。
pub fn rank(candidates: &[Candidate]) -> Option<Transport> {
    candidates
        .iter()
        .filter(|candidate| candidate.reachable)
        .min_by_key(|candidate| {
            (
                candidate.latency_ms.unwrap_or(u64::MAX),
                match candidate.transport {
                    Transport::Udp => 0u8,
                    Transport::Tcp => 1u8,
                },
            )
        })
        .map(|candidate| candidate.transport)
}

fn evidence_view(evidence: &Evidence, now_unix: i64, current_network: &str) -> Value {
    let expired = evidence.expires_at_unix <= now_unix;
    // 空指纹是旧记录/手工夹具，不据此判「换了网络」；有值时不一致就必须明说。
    let network_changed =
        !evidence.network.is_empty() && !current_network.is_empty() && evidence.network != current_network;
    let summary = match evidence.winner {
        Some(transport) => {
            let latency = evidence
                .candidates
                .iter()
                .find(|candidate| candidate.transport == transport)
                .and_then(|candidate| candidate.latency_ms);
            let base = match latency {
                Some(ms) => format!("自动：{}（{ms} ms）", transport.label()),
                None => format!("自动：{}", transport.label()),
            };
            if network_changed {
                format!("{base}（网络已变化，下次连接重测）")
            } else {
                base
            }
        }
        None => "自动：两种方式都没有通过探测".to_string(),
    };
    json!({
        "NetworkFingerprint": evidence.network,
        "CheckedAtUtc": crate::pairing::rfc3339_micros(evidence.checked_at_unix),
        "ExpiresAtUtc": crate::pairing::rfc3339_micros(evidence.expires_at_unix),
        "Expired": expired,
        "NetworkChanged": network_changed,
        "Fresh": !expired && !network_changed && evidence.winner.is_some(),
        "Winner": evidence.winner.map(|t| t.id()).unwrap_or(""),
        "WinnerLabel": evidence.winner.map(|t| t.label()).unwrap_or(""),
        "Summary": summary,
        "Candidates": evidence.candidates.iter().map(candidate_to_json).collect::<Vec<_>>(),
    })
}

/// 所有线路的证据投影（给界面读）。只读、不探测。
pub fn list_view(root: &Path, now_unix: i64) -> Value {
    let store = load_store(root);
    let current = network_fingerprint();
    let mut lines = serde_json::Map::new();
    if let Some(items) = store.get("Lines").and_then(Value::as_object) {
        for (id, value) in items {
            if let Some(evidence) = evidence_from_json(value) {
                lines.insert(id.clone(), evidence_view(&evidence, now_unix, &current));
            }
        }
    }
    json!({
        "NetworkFingerprint": current,
        "Lines": Value::Object(lines),
    })
}

fn probe_plan(line: &LineConfig) -> (u16, String, String) {
    // 与连接自检同一条规则：优先用代理端口 +3，算不出来就临时绑一个空口。
    // 凭据每次不同；临时引擎停止后配置会被删除，不留第二份可拨的口。
    if let crate::selfcheck::ProbePlan::Dial { port, username, password } =
        crate::selfcheck::plan_probe(&line.proxy_endpoint)
    {
        return (port, username, password);
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .unwrap_or(0);
    let token = || crate::pairing::random_uuid_v4().replace('-', "");
    (port, token(), token())
}

fn wait_port(port: u16) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_millis(PROBE_WAIT_MS);
    loop {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("探测入站 {port} 没有在 {} ms 内就绪", PROBE_WAIT_MS));
        }
        std::thread::sleep(Duration::from_millis(80));
    }
}

/// 从线路文件里取出标准连接（WireGuard）的参数。取不到就不做直探。
///
/// 字段来自 `pairing::wireguard_endpoint` 写下的形状：`endpoints[type=wireguard]`
/// 的 `private_key` 与 `peers[0]` 的 `address` / `port` / `public_key`。
fn wireguard_params(line_path: &Path) -> Option<(String, u16, String, String)> {
    let text = std::fs::read_to_string(line_path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let endpoint = value
        .get("endpoints")
        .and_then(Value::as_array)?
        .iter()
        .find(|endpoint| endpoint.get("type").and_then(Value::as_str) == Some("wireguard"))?;
    let private = endpoint.get("private_key").and_then(Value::as_str)?.to_string();
    let peer = endpoint.get("peers").and_then(Value::as_array)?.first()?;
    let host = peer.get("address").and_then(Value::as_str)?.to_string();
    let port = peer.get("port").and_then(Value::as_u64)? as u16;
    let public = peer.get("public_key").and_then(Value::as_str)?.to_string();
    if private.is_empty() || host.is_empty() || public.is_empty() || port == 0 {
        return None;
    }
    Some((host, port, private, public))
}

/// 真正拨一次：先做无引擎 UDP 直探（标准连接），不通再起临时引擎。
///
/// 不碰系统代理、不写 `runtime.json`，引擎停止后删除临时配置。它和「连接」唯一的
/// 区别是：不接管网络，只借道问一句「这条方式现在通不通、多久」。
///
/// 返回 `(耗时, 方法)`；方法是 `direct` 或 `engine`，写进证据让界面能说清读数来自哪。
fn probe_with_engine(
    root: &Path,
    cfg: &AppConfig,
    line: &LineConfig,
    engine_binary: &Path,
    transport: Transport,
) -> Result<(u64, &'static str), String> {
    let line_path = line.engine_config_path(root);
    if !line_path.exists() {
        return Err("线路引擎配置不存在".to_string());
    }
    // 标准连接不需要引擎：一次真实的 WireGuard 握手就够了。直探失败要落到引擎，
    // 因为「没有响应」也可能是我们的字段没对上，而引擎是最权威的判据。
    if transport == Transport::Udp {
        if let Some((host, port, private, public)) = wireguard_params(&line_path) {
            let network = network_info();
            let bind = network.source_ip.parse::<std::net::IpAddr>().ok();
            // 先按默认出口的源地址绑定（指定网卡），失败再让系统选路。
            // 绑定是「更精确」，不是「更正确」：这台机器上确实存在绑定后
            // 收不到响应的路由组合，不能让它把一次可达探测变成不可达。
            let mut direct = None;
            if bind.is_some() {
                direct = crate::wgprobe::handshake(
                    &host,
                    port,
                    &private,
                    &public,
                    bind,
                    Duration::from_millis(2_000),
                )
                .ok();
            }
            if direct.is_none() {
                direct = crate::wgprobe::handshake(
                    &host,
                    port,
                    &private,
                    &public,
                    None,
                    Duration::from_millis(PROBE_REQUEST_MS),
                )
                .ok();
            }
            if let Some(latency) = direct {
                return Ok((latency, "direct"));
            }
        }
    }
    let (port, username, password) = probe_plan(line);
    if port == 0 {
        return Err("找不到可用的探测端口".to_string());
    }
    let runtime = root.join(format!("runtime-autoroute-{}.json", crate::pairing::random_uuid_v4()));
    // 探针同样要绑物理网卡：它测的是「从这块网卡能不能到服务器」，
    // 不绑的话 TUN 连接期间探针会绕进隧道，测出来的是隧道而不是出口。
    // 用与真实连接同一个判据（线路指定 > 系统默认）；指定的网卡不在了这里只当
    // 「不知道该绑哪张」——探测是只读的，真正的拒绝发生在连接前。
    let (bind_interface, _) = crate::netbind::for_connect(root, &line.id);
    let prepared = crate::engine_config::prepare_engine_config(
        &line_path,
        &cfg.split,
        &cfg.agents,
        transport,
        Mode::Proxy,
        &runtime,
        &bind_interface,
        Some((username.as_str(), password.as_str())),
        Some(port),
    )?;
    let settings = crate::config::EngineSettings {
        binary: engine_binary.to_string_lossy().to_string(),
    };
    let engine_cfg = settings.to_engine(&prepared);
    let log_dir = root.join("logs").join("autoroute");
    let started = std::time::Instant::now();
    let handle = crate::engine::start(&engine_cfg, &log_dir)?;
    let result = (|| -> Result<u64, String> {
        wait_port(port)?;
        let (status, _body) = crate::selfcheck::socks5_text(
            port,
            &username,
            &password,
            "checkip.amazonaws.com",
            "/",
            PROBE_REQUEST_MS,
        )
        .map_err(|error| match error {
            crate::selfcheck::ProbeError::NotListening { port } => {
                format!("探测入站 {port} 没有监听")
            }
            crate::selfcheck::ProbeError::Failed(message) => message,
        })?;
        if (200..400).contains(&status) {
            Ok(started.elapsed().as_millis() as u64)
        } else {
            Err(format!("探测请求返回 HTTP {status}"))
        }
    })();
    let _ = crate::engine::stop(handle.pid, 1_500);
    let _ = std::fs::remove_file(&runtime);
    result.map(|latency| (latency, "engine"))
}

/// 对一条线路跑两个候选，写证据，返回结论。`probe` 注入是为了单测不真的起引擎。
pub fn probe_line_with(
    root: &Path,
    line: &LineConfig,
    now_unix: i64,
    probe: &dyn Fn(Transport) -> Result<u64, String>,
) -> Evidence {
    probe_line_with_method(root, line, now_unix, &|transport| {
        probe(transport).map(|latency| (latency, "engine".to_string()))
    })
}

fn probe_line_with_method(
    root: &Path,
    line: &LineConfig,
    now_unix: i64,
    probe: &dyn Fn(Transport) -> Result<(u64, String), String>,
) -> Evidence {
    let network = network_info().fingerprint;
    let candidates: Vec<Candidate> = [Transport::Udp, Transport::Tcp]
        .into_iter()
        .map(|transport| match probe(transport) {
            Ok((latency_ms, method)) => Candidate {
                transport,
                reachable: true,
                latency_ms: Some(latency_ms),
                error: String::new(),
                checked_at_unix: now_unix,
                method,
            },
            Err(error) => Candidate {
                transport,
                reachable: false,
                latency_ms: None,
                error: clip(&error),
                checked_at_unix: now_unix,
                method: "engine".to_string(),
            },
        })
        .collect();
    let winner = rank(&candidates);
    let evidence = Evidence {
        network,
        checked_at_unix: now_unix,
        expires_at_unix: now_unix + EVIDENCE_TTL_SECS,
        candidates,
        winner,
    };
    let mut store = load_store(root);
    if !store.get("Lines").map(Value::is_object).unwrap_or(false) {
        store["Lines"] = json!({});
    }
    store["SchemaVersion"] = json!(SCHEMA);
    store["Kind"] = json!(KIND);
    store["Lines"][&line.id] = evidence_to_json(&evidence);
    // 证据写不进去不改变结论：这一次连接仍按刚测出来的排名走，只是下次要重测。
    let _ = save_store(root, &store);
    evidence
}

pub fn probe_line(root: &Path, cfg: &AppConfig, line: &LineConfig, engine_binary: &Path, now_unix: i64) -> Evidence {
    probe_line_with_method(root, line, now_unix, &|transport| {
        probe_with_engine(root, cfg, line, engine_binary, transport)
            .map(|(latency, method)| (latency, method.to_string()))
    })
}

/// 连接中只探测**另一个**候选：把结果合并进现有证据，不假装测过当前这一种。
///
/// 连接中不能测当前正在用的标准连接（同一个 WireGuard 身份，探测会把服务端记录的
/// 对端地址改到探测 socket 上，等于打断用户）。所以这里只测备选，返回它的候选事实。
pub fn probe_alternate(
    root: &Path,
    cfg: &AppConfig,
    line: &LineConfig,
    engine_binary: &Path,
    transport: Transport,
    now_unix: i64,
) -> Candidate {
    let network = network_info().fingerprint;
    let mut store = load_store(root);
    let existing = store
        .get("Lines")
        .and_then(|lines| lines.get(&line.id))
        .and_then(evidence_from_json)
        .filter(|evidence| evidence.network == network);
    let result = probe_with_engine(root, cfg, line, engine_binary, transport);
    let candidate = match result {
        Ok((latency_ms, method)) => Candidate {
            transport,
            reachable: true,
            latency_ms: Some(latency_ms),
            error: String::new(),
            checked_at_unix: now_unix,
            method: method.to_string(),
        },
        Err(error) => Candidate {
            transport,
            reachable: false,
            latency_ms: None,
            error: clip(&error),
            checked_at_unix: now_unix,
            method: "engine".to_string(),
        },
    };
    let mut candidates = existing.map(|evidence| evidence.candidates).unwrap_or_default();
    candidates.retain(|candidate| candidate.transport != transport);
    candidates.push(candidate.clone());
    let winner = rank(&candidates);
    let evidence = Evidence {
        network,
        checked_at_unix: now_unix,
        expires_at_unix: now_unix + EVIDENCE_TTL_SECS,
        candidates,
        winner,
    };
    if !store.get("Lines").map(Value::is_object).unwrap_or(false) {
        store["Lines"] = json!({});
    }
    store["SchemaVersion"] = json!(SCHEMA);
    store["Kind"] = json!(KIND);
    store["Lines"][&line.id] = evidence_to_json(&evidence);
    let _ = save_store(root, &store);
    candidate
}

/// 读一条线路的现有证据（不判断新旧）。自动切换用它比较「备选是否真的赢了」。
pub fn load_evidence(root: &Path, line_id: &str) -> Option<Evidence> {
    load_store(root)
        .get("Lines")
        .and_then(|lines| lines.get(line_id))
        .and_then(evidence_from_json)
}

/// 连接前的选择：用户固定 → 新鲜证据 → 现场探测 → 兜底（已验证→标准）。
///
/// `allow_probe = false`（例如连接已经在跑）时只用证据或兜底：再起一个引擎去探测
/// 会和正在跑的连接抢同一个 WireGuard 身份，把用户正在用的通道打断。
pub fn choose_transport(
    root: &Path,
    cfg: &AppConfig,
    line: &LineConfig,
    engine_binary: Option<&Path>,
    allow_probe: bool,
    now_unix: i64,
) -> Choice {
    if let Some(fixed) = line.transport {
        return Choice {
            transport: fixed,
            source: "UserChoice",
            evidence: None,
            note: "使用你固定的连接方式".to_string(),
        };
    }
    let network = network_fingerprint();
    let store = load_store(root);
    if let Some(evidence) = store
        .get("Lines")
        .and_then(|lines| lines.get(&line.id))
        .and_then(evidence_from_json)
    {
        if is_fresh(&evidence, &network, now_unix) {
            let winner = evidence.winner.unwrap_or_else(|| line.effective_transport());
            return Choice {
                transport: winner,
                source: "Evidence",
                note: format!("使用 {} 分钟内测得的自动选路结果", EVIDENCE_TTL_SECS / 60),
                evidence: Some(evidence),
            };
        }
    }
    if allow_probe && !network.is_empty() {
        if let Some(binary) = engine_binary {
            let evidence = probe_line(root, cfg, line, binary, now_unix);
            let transport = evidence.winner.unwrap_or_else(|| line.effective_transport());
            let source = if evidence.winner.is_some() { "Probe" } else { "Fallback" };
            let note = if evidence.winner.is_some() {
                "刚按当前网络探测并选出的连接方式".to_string()
            } else {
                "两种方式都没有通过探测，按上次成功的方式连接".to_string()
            };
            return Choice {
                transport,
                source,
                evidence: Some(evidence),
                note,
            };
        }
    }
    Choice {
        transport: line.effective_transport(),
        source: "Fallback",
        evidence: None,
        note: "没有可用的自动探测结果，按上次成功的方式连接".to_string(),
    }
}

/// `auto-route` 命令的回包投影。
pub fn choice_view(choice: &Choice, now_unix: i64) -> Value {
    // 这次选择用的证据本身就是按当前网络挑出来的，不再拿一次指纹去制造假「网络已变化」。
    let evidence = choice
        .evidence
        .as_ref()
        .map(|evidence| evidence_view(evidence, now_unix, &evidence.network));
    json!({
        "LineId": "",
        "Transport": choice.transport.id(),
        "TransportLabel": choice.transport.label(),
        "Source": choice.source,
        "Note": choice.note,
        "Evidence": evidence.unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(transport: Transport, reachable: bool, latency: Option<u64>) -> Candidate {
        Candidate {
            transport,
            reachable,
            latency_ms: latency,
            error: String::new(),
            checked_at_unix: 1_800_000_000,
            method: "engine".to_string(),
        }
    }

    #[test]
    fn a_line_with_a_wireguard_endpoint_yields_direct_probe_params() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-autoroute-wg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let line = LineConfig {
            id: "L1".to_string(),
            name: "测试".to_string(),
            proxy_endpoint: "127.0.0.1:17890".to_string(),
            transport: None,
            verified_transport: None,
        };
        let path = line.engine_config_path(&root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let private = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let public = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
        std::fs::write(
            &path,
            json!({
                "endpoints": [{
                    "type": "wireguard",
                    "tag": "tc",
                    "private_key": private,
                    "address": ["10.66.0.2/32"],
                    "peers": [{
                        "address": "203.0.113.10",
                        "port": 51820,
                        "public_key": public,
                        "allowed_ips": ["0.0.0.0/0"],
                        "persistent_keepalive_interval": 25
                    }]
                }],
                "outbounds": [{"type": "direct", "tag": "direct"}]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            wireguard_params(&path),
            Some((
                "203.0.113.10".to_string(),
                51820,
                private.to_string(),
                public.to_string()
            ))
        );

        // 没有 WireGuard endpoint 的线路不做直探（兼容连接线路本来就没有标准连接）。
        std::fs::write(&path, json!({"endpoints": [], "outbounds": []}).to_string()).unwrap();
        assert_eq!(wireguard_params(&path), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_candidate_round_trips_its_probe_method() {
        let mut direct = candidate(Transport::Udp, true, Some(5));
        direct.method = "direct".to_string();
        let back = candidate_from_json(&candidate_to_json(&direct)).unwrap();
        assert_eq!(back.method, "direct");
        // 旧证据没有 Method：按 engine 读，不能把「以前没有直探」说成直探。
        let mut old = candidate_to_json(&direct);
        old.as_object_mut().unwrap().remove("Method");
        assert_eq!(candidate_from_json(&old).unwrap().method, "engine");
    }

    #[test]
    fn ranking_prefers_reachable_then_latency_then_udp() {
        assert_eq!(
            rank(&[candidate(Transport::Udp, true, Some(80)), candidate(Transport::Tcp, true, Some(40))]),
            Some(Transport::Tcp)
        );
        assert_eq!(
            rank(&[candidate(Transport::Udp, true, Some(40)), candidate(Transport::Tcp, true, Some(40))]),
            Some(Transport::Udp),
            "延迟相同时标准连接少一层中转"
        );
        assert_eq!(
            rank(&[candidate(Transport::Udp, false, None), candidate(Transport::Tcp, true, Some(90))]),
            Some(Transport::Tcp)
        );
        assert_eq!(
            rank(&[candidate(Transport::Udp, false, None), candidate(Transport::Tcp, false, None)]),
            None
        );
    }

    #[test]
    fn evidence_is_fresh_only_for_the_same_network_and_before_expiry() {
        let evidence = Evidence {
            network: "10.1.2.3".to_string(),
            checked_at_unix: 100,
            expires_at_unix: 1_900,
            candidates: vec![candidate(Transport::Udp, true, Some(20))],
            winner: Some(Transport::Udp),
        };
        assert!(is_fresh(&evidence, "10.1.2.3", 1_000));
        assert!(!is_fresh(&evidence, "10.1.2.4", 1_000), "换了网络不能拿旧证据");
        assert!(!is_fresh(&evidence, "10.1.2.3", 1_900), "过期不能拿旧证据");
        assert!(!is_fresh(&evidence, "", 1_000), "指纹未知时不信任");
        let mut no_winner = evidence.clone();
        no_winner.winner = None;
        assert!(!is_fresh(&no_winner, "10.1.2.3", 1_000), "没有赢家的证据不能自动应用");
    }

    #[test]
    fn probing_stores_evidence_and_survives_a_round_trip() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-autoroute-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let line = LineConfig {
            id: "L1".to_string(),
            name: "测试".to_string(),
            proxy_endpoint: "127.0.0.1:17890".to_string(),
            transport: None,
            verified_transport: None,
        };
        let evidence = probe_line_with(&root, &line, 1_000, &|transport| match transport {
            Transport::Udp => Ok(31),
            Transport::Tcp => Err("兼容连接没有参数".to_string()),
        });
        assert_eq!(evidence.winner, Some(Transport::Udp));
        assert_eq!(evidence.candidates.len(), 2);
        assert!(!evidence.candidates[1].reachable);
        let view = list_view(&root, 1_100);
        let lines = view["Lines"].as_object().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines["L1"]["Winner"], "udp");
        assert!(lines["L1"]["Summary"].as_str().unwrap().contains("标准连接"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_fixed_choice_always_wins_and_fallback_never_probes_when_disallowed() {
        let root = std::env::temp_dir().join(format!(
            "tcrs-autoroute-choice-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut line = LineConfig {
            id: "L1".to_string(),
            name: "测试".to_string(),
            proxy_endpoint: "127.0.0.1:17890".to_string(),
            transport: Some(Transport::Tcp),
            verified_transport: Some(Transport::Udp),
        };
        let cfg = crate::config::AppConfig {
            schema: 2,
            mode: Mode::Proxy,
            auto_start: false,
            auto_connect: false,
            close_to_tray: false,
            quality_warning: true,
            auto_trust_first_connection: true,
            selected: "L1".to_string(),
            lines: vec![line.clone()],
            exits: Default::default(),
            split: Default::default(),
            agents: Default::default(),
            engine: None,
        };
        let choice = choose_transport(&root, &cfg, &line, None, true, 1_000);
        assert_eq!(choice.transport, Transport::Tcp);
        assert_eq!(choice.source, "UserChoice");

        line.transport = None;
        let choice = choose_transport(&root, &cfg, &line, None, true, 1_000);
        assert_eq!(choice.transport, Transport::Udp, "没有证据时按「已验证」兜底");
        assert_eq!(choice.source, "Fallback");
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn interfaces_lists_this_machine_adapters() {
        let list = interfaces();
        println!("网卡：{list:?}｜默认：{:?}", default_interface());
        #[cfg(windows)]
        assert!(!list.is_empty(), "Windows 上至少要有回环之外的网卡");
        assert_eq!(list.len(), list.iter().collect::<std::collections::HashSet<_>>().len(), "不许重名");
    }

}

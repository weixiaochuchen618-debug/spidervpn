//! 节点端口诊断（`--diagnose`）：只回答"这些 **TCP** 端口现在通不通"，以及**不能**据此推断什么。
//!
//! 语义照旧版的`Diagnostics.psm1:43-50`，核心是**不撒谎**：
//! - 有中转（Reality/VLESS）时探 `server:server_port` + 22（管理端口）；
//! - 纯 UDP WireGuard 没有 TCP 传输端口，探 22/443 只代表"管理或 Web 端口可达"，
//!   **不能**据此说隧道通了——UDP 与设备授权根本没验（本版没有 wg 工具，也不打算造一个假的结论）；
//! - 一个端口都不通时，总结句必须明说"纯 UDP 服务器可能仍正常，不能据此判定离线"。
//!
//! 只做 TCP 连接：WireGuard 的 peer 是 UDP 端点，拿 TCP 去探它是错的，所以只把它列出来说明"不适用"。

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

/// 单端口探测上限。与旧版一致（2500ms）——再长会让"诊断"变成"等"。
pub const TIMEOUT: Duration = Duration::from_millis(2500);

/// 管理端口：有中转时除了传输端口，还要看服务器的 SSH/管理口通不通（旧版同款）。
pub const ADMIN_PORT: u16 = 22;

/// 纯 UDP 线路没有传输端口，退而探这两个常见的 Web/管理口。
pub const FALLBACK_PORTS: [u16; 2] = [22, 443];

/// 一个 TCP 探测目标。
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// 一次 TCP 探测的分类。不可达不再只是一个空延迟：页面可以据此给出事实性提示。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    Reachable,
    Timeout,
    Refused,
    ResolveFailed,
    Unreachable,
}

impl ProbeResult {
    pub fn id(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Timeout => "timeout",
            Self::Refused => "refused",
            Self::ResolveFailed => "resolve-failed",
            Self::Unreachable => "unreachable",
        }
    }
}

/// 一次探测的结果。`latency_ms` 保留给旧的可达性判断；`elapsed_ms` 成功失败都记录实际耗时。
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub target: Target,
    pub latency_ms: Option<u128>,
    pub elapsed_ms: u128,
    pub result: ProbeResult,
}

/// 给 CLI 与 IPC 共用的结构化行。`text` 也由本模块生成，避免界面另写一套诊断文案。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Item {
    pub target: String,
    pub port: Option<u16>,
    pub purpose: String,
    pub result: String,
    pub ms: Option<u128>,
    pub text: String,
}

/// 结论与下一步必须同源；`text` 不把 TCP 可达夸大成隧道已通。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub code: String,
    pub text: String,
    pub next: String,
}

/// 从线路引擎配置推导出来的探测计划（纯数据，便于单测）。
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// 线路有没有中转（有 = 兼容连接形状）。总结句走哪一条由它决定。
    pub transport: bool,
    /// 要探的 TCP 目标（去重、保序）。
    pub tcp: Vec<Target>,
    /// WireGuard 的 UDP 端点，形如 `198.51.100.7:51820`。**只用于说明"TCP 探测不适用"**。
    pub udp: Vec<String>,
    /// 一个 TCP 目标都没有时的原因（例如线路文件里既没有中转也没有 peer 地址）。
    pub no_target: Option<String>,
}

/// 从线路引擎配置推导目标。
///
/// 中转出站认 `tag=tc-transport` 的 vless——与连接方式派生用的是同一个标签，
/// 换成别处再定义一遍，两边迟早点不出同一条出站。
pub fn plan(obj: &serde_json::Map<String, Value>, transport: crate::config::Transport) -> Plan {
    let tag = crate::engine_config::TRANSPORT_TAG;
    let outbounds = obj.get("outbounds").and_then(Value::as_array);
    // 只有这条线路**实际走**兼容连接时才认中转出站：选了标准连接时，那份中转不会被用上，
    // 拿它的端口当"传输端口"去诊断就是诊断了另一条路（正是本命令要避免的撒谎）。
    let use_transport = transport == crate::config::Transport::Tcp;
    let transport = use_transport
        .then(|| {
            outbounds.and_then(|list| {
                list.iter().find(|o| {
                    o.get("type").and_then(Value::as_str) == Some("vless")
                        && o.get("tag").and_then(Value::as_str) == Some(tag)
                })
            })
        })
        .flatten();
    let transport_endpoint = transport.and_then(|o| {
        let host = o.get("server").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())?;
        let port = o.get("server_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok())?;
        Some(Target { host: host.to_string(), port })
    });

    let (udp, peer_host) = wireguard_peers(obj);

    let mut tcp: Vec<Target> = Vec::new();
    if let Some(t) = &transport_endpoint {
        // 传输端口优先，管理口随后：顺序固定，输出才稳定可比。
        for port in [t.port, ADMIN_PORT] {
            push_unique(&mut tcp, Target { host: t.host.clone(), port });
        }
    } else if !use_transport {
        // 标准连接：没有任何 TCP 传输端口，只能看管理/Web 口。
        // 已选兼容连接却没有中转出站时不走这条——那条路连接时会被直接拒绝，
        // 这里替它探 22/443 就等于给出一个"看起来还行"的假结论。
        if let Some(host) = &peer_host {
            for port in FALLBACK_PORTS {
                push_unique(&mut tcp, Target { host: host.clone(), port });
            }
        }
    }
    let no_target = if tcp.is_empty() {
        Some(if use_transport && transport.is_none() {
            format!("已选兼容连接，但线路文件里没有可用的中转出站（tag={tag}），没有可探测的传输端口")
        } else if transport.is_some() {
            format!("线路里的中转出站（{tag}）没有写 server / server_port，没有可探测的地址")
        } else if udp.is_empty() {
            "线路文件里没有可探测的服务器地址（既没有中转出站，也没有 WireGuard peer 的 address/port）"
                .to_string()
        } else {
            format!("WireGuard 端点 {} 是按名字写的，没有可直接探测的服务器地址", udp.join("、"))
        })
    } else {
        None
    };
    Plan { transport: transport_endpoint.is_some(), tcp, udp, no_target }
}

fn push_unique(list: &mut Vec<Target>, t: Target) {
    if !list.iter().any(|x| x.host == t.host && x.port == t.port) {
        list.push(t);
    }
}

/// 取 WireGuard 的 UDP 端点（`host:port` 形式，仅用于展示）与第一个服务器地址。
///
/// 两种写法都认：sing-box 1.11+ 的 `endpoints[].peers[].address/port`，
/// 以及老一点的 endpoint 级 `server`/`server_port`——线路文件是用户导入的，不能只认一种。
fn wireguard_peers(obj: &serde_json::Map<String, Value>) -> (Vec<String>, Option<String>) {
    let mut udp: Vec<String> = Vec::new();
    let mut host: Option<String> = None;
    let Some(list) = obj.get("endpoints").and_then(Value::as_array) else {
        return (udp, host);
    };
    for ep in list.iter().filter(|e| e.get("type").and_then(Value::as_str) == Some("wireguard")) {
        let mut add = |h: &str, p: Option<u64>| {
            let h = h.trim();
            if h.is_empty() {
                return;
            }
            if host.is_none() {
                host = Some(h.to_string());
            }
            if let Some(p) = p {
                let one = format!("{h}:{p}");
                if !udp.contains(&one) {
                    udp.push(one);
                }
            }
        };
        if let Some(peers) = ep.get("peers").and_then(Value::as_array) {
            for peer in peers {
                if let Some(h) = peer.get("address").or_else(|| peer.get("server")).and_then(Value::as_str) {
                    add(h, peer.get("port").or_else(|| peer.get("server_port")).and_then(Value::as_u64));
                }
            }
        }
        if let Some(h) = ep.get("server").and_then(Value::as_str) {
            add(h, ep.get("server_port").and_then(Value::as_u64));
        }
    }
    (udp, host)
}

/// 探一个 TCP 目标。只建立连接，不发任何字节（诊断不该在别人的服务上留痕）。
pub fn probe(target: &Target) -> Probe {
    // 从解析前开始计时：失败也报告这次实际花了多久，不能拿 2500ms 上限冒充测量值。
    let started = Instant::now();
    let addr = match (target.host.as_str(), target.port).to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(_) => None,
    };
    let Some(addr) = addr else {
        return Probe {
            target: target.clone(),
            latency_ms: None,
            elapsed_ms: started.elapsed().as_millis(),
            result: ProbeResult::ResolveFailed,
        };
    };
    match TcpStream::connect_timeout(&addr, TIMEOUT) {
        Ok(_) => {
            let ms = started.elapsed().as_millis();
            Probe { target: target.clone(), latency_ms: Some(ms), elapsed_ms: ms, result: ProbeResult::Reachable }
        }
        Err(e) => {
            let result = match e.kind() {
                std::io::ErrorKind::TimedOut => ProbeResult::Timeout,
                std::io::ErrorKind::ConnectionRefused => ProbeResult::Refused,
                _ => ProbeResult::Unreachable,
            };
            Probe {
                target: target.clone(),
                latency_ms: None,
                elapsed_ms: started.elapsed().as_millis(),
                result,
            }
        }
    }
}

pub fn probe_all(p: &Plan) -> Vec<Probe> {
    p.tcp.iter().map(probe).collect()
}

/// 有任一目标可达就算"探通了"。**纯 UDP 未验证不算失败**（旧版明确不据此判定离线）。
pub fn any_reachable(probes: &[Probe]) -> bool {
    probes.iter().any(|p| p.latency_ms.is_some())
}

fn endpoint(t: &Target) -> String {
    if t.host.contains(':') && !t.host.starts_with('[') {
        format!("[{}]:{}", t.host, t.port)
    } else {
        format!("{}:{}", t.host, t.port)
    }
}

/// 结构化诊断项：TCP、UDP 说明与未探测原因都从这里产生，顺序与旧文本输出一致。
pub fn items(p: &Plan, probes: &[Probe]) -> Vec<Item> {
    let mut out = Vec::new();
    for (index, pr) in probes.iter().enumerate() {
        let purpose = if p.transport && index == 0 {
            "transport"
        } else if !p.transport && pr.target.port == 443 {
            "web"
        } else {
            "admin"
        };
        let text = if pr.latency_ms.is_some() {
            format!("TCP {}  可建立连接，耗时 {} ms", endpoint(&pr.target), pr.elapsed_ms)
        } else {
            format!(
                "TCP {}  无可用 TCP 响应，耗时 {} ms；可能未监听、端口受限或路径不可达",
                endpoint(&pr.target), pr.elapsed_ms
            )
        };
        out.push(Item {
            target: pr.target.host.clone(),
            port: Some(pr.target.port),
            purpose: purpose.to_string(),
            result: pr.result.id().to_string(),
            ms: Some(pr.elapsed_ms),
            text,
        });
    }
    for ep in &p.udp {
        let (host, port) = ep
            .rsplit_once(':')
            .and_then(|(h, raw)| raw.parse::<u16>().ok().map(|port| (h.to_string(), Some(port))))
            .unwrap_or_else(|| (ep.clone(), None));
        out.push(Item {
            target: host,
            port,
            purpose: "udp".to_string(),
            result: "not-applicable".to_string(),
            ms: None,
            text: format!("UDP {ep}  该端点走 UDP，TCP 探测不适用"),
        });
    }
    if let Some(reason) = &p.no_target {
        out.push(Item {
            target: String::new(),
            port: None,
            purpose: "configuration".to_string(),
            result: "not-run".to_string(),
            ms: None,
            text: format!("未探测任何端口：{reason}"),
        });
    }
    out
}

fn transport_reachable(p: &Plan, probes: &[Probe]) -> bool {
    probes
        .iter()
        .find(|pr| Some(pr.target.port) == p.tcp.first().map(|t| t.port))
        .map(|pr| pr.latency_ms.is_some())
        .unwrap_or(false)
}

/// 结论与对应的下一步。已经在兼容连接时，绝不再建议“改用兼容连接”原地绕圈。
pub fn verdict(p: &Plan, probes: &[Probe]) -> Verdict {
    let text = summary(p, probes);
    let (code, next) = if p.transport {
        if transport_reachable(p, probes) {
            let admin_failed = probes.iter().skip(1).any(|pr| pr.latency_ms.is_none());
            if admin_failed {
                (
                    "management-unreachable",
                    "管理端口不通时线路可能失效，请联系服务商或在 旧版重新部署；传输端口可达不代表管理侧正常。",
                )
            } else {
                (
                    "transport-reachable",
                    "连接后再检查 Reality 认证、WireGuard 握手与转发；本次 TCP 结果不等于通道已可用。",
                )
            }
        } else {
            (
                "transport-unreachable",
                "请检查中转服务、对应端口与云安全组后重试；当前已是兼容连接，不要只在原连接方式上重复切换。",
            )
        }
    } else if probes.is_empty() {
        (
            "no-target",
            "请检查线路的中转或 WireGuard peer 地址；需要重新部署时请使用 旧版。",
        )
    } else if any_reachable(probes) {
        if probes.iter().any(|pr| pr.latency_ms.is_none()) {
            (
                "management-unreachable",
                "不通的管理/Web 端口需联系服务商检查，线路可能失效时请在 旧版重新部署；UDP 与设备授权仍未验证。",
            )
        } else {
            (
                "udp-tcp-reachable",
                "连接后另行检查 UDP 与设备授权；本次管理/Web TCP 结果不代表隧道已通。",
            )
        }
    } else {
        (
            "udp-no-tcp-response",
            "请检查网络侧封禁、云安全组与本地防火墙；确认线路支持后可改用兼容连接重试，UDP 与设备授权仍需连接后验证。",
        )
    };
    Verdict { code: code.to_string(), text, next: next.to_string() }
}

/// 一段完整的诊断输出（每行一条，调用方负责加缩进与换行）。
pub fn render(p: &Plan, probes: &[Probe]) -> Vec<String> {
    let mut out: Vec<String> = items(p, probes).into_iter().map(|item| item.text).collect();
    let v = verdict(p, probes);
    out.push(format!("结论：{}；下一步：{}", v.text, v.next));
    out
}

/// 总结句三态（有中转可达 / 有中转不可达 / 无中转）。措辞照旧版，别简写成一句。
pub fn summary(p: &Plan, probes: &[Probe]) -> String {
    if p.transport {
        // 中转模式下"传输端口通不通"才是结论；22 通不通只是附带信息。
        return if transport_reachable(p, probes) {
            "TCP 传输端口可达；Reality 认证、WireGuard 握手及转发需连接后检查。".to_string()
        } else {
            "TCP 传输端口不可达，请检查对应服务与云安全组。".to_string()
        };
    }
    if any_reachable(probes) {
        "管理或 Web 端口可达；当前为 UDP WireGuard，尚未验证 UDP 与设备授权。".to_string()
    } else if probes.is_empty() {
        // 什么都没探到（没有可探测的地址）：这是"没做诊断"，不是"服务器离线"。
        "没有可探测的 TCP 目标，本次未做任何端口验证；这不代表服务器离线。".to_string()
    } else {
        "未探测到 TCP 22/443 响应。纯 UDP 服务器可能仍正常，不能据此判定离线。".to_string()
    }
}

/// 交易保护（WFP）小节：把 `GuardStatus` 摊成诊断行。
///
/// 诊断页是用户**唯一**能看到「规则到底在不在、证据是谁写的、还能不能信」的地方，
/// 所以这里只写事实，不写结论式的话——结论句由 `summary` 统一给（与首页同一句）。
pub fn guard_items(st: &crate::guard::GuardStatus) -> Vec<Item> {
    use crate::guard::GuardState;

    let mut out = Vec::new();
    let state_text = match st.state {
        GuardState::Protected => "已保护",
        GuardState::Unprotected => "未完整启用",
        GuardState::Unknown => "无法确认",
    };
    let mut head = format!("{state_text}：{}（{}）", st.summary, st.reason.as_str());
    if !st.age_text.is_empty() {
        head.push_str(&format!("；依据{}", st.age_text));
    }
    out.push(guard_item("状态", head));

    out.push(guard_item(
        "基础设施",
        format!(
            "provider {} / subLayer {} / 定义校验 {} / BFE {}",
            yes_no(st.detection.provider_present),
            yes_no(st.detection.sublayer_present),
            if st.detection.infrastructure_verified { "通过" } else { "未通过" },
            if st.detection.bfe_ready { "就绪" } else { "未就绪" }
        ),
    ));

    for p in &st.programs {
        let detail = if p.participated {
            format!("IPv4 {} / IPv6 {}", slot_text(&p.ipv4), slot_text(&p.ipv6))
        } else {
            format!(
                "不参与保护：{}",
                p.unresolved_reason.as_deref().unwrap_or("未解析")
            )
        };
        out.push(guard_item(
            "程序",
            format!(
                "{}（{}）：{detail}",
                p.name,
                p.path.as_deref().unwrap_or("无路径")
            ),
        ));
    }

    let mut record = format!(
        "来源 {} / 存储 {} / 可信 {}",
        if st.source.is_some() { st.source.as_str() } else { "无" },
        if st.store_kind.is_empty() { "未知" } else { st.store_kind.as_str() },
        if st.evidence_trusted { "是" } else { "否（同用户任何程序都能改）" }
    );
    record.push_str(&format!(
        " / 开机标识 {} / 名单摘要 {}",
        if st.boot_id_match { "匹配" } else { "不匹配" },
        if st.config_digest_match { "匹配" } else { "不匹配" }
    ));
    if st.verify_pending.is_pending() {
        record.push_str(&format!(" / 本次核验：{}", st.verify_pending.as_str()));
    }
    out.push(guard_item("核验记录", record));

    out.push(guard_item(
        "范围",
        format!(
            "只阻止名单内程序的 IPv4/IPv6 直连；不改 DNS、不拦其他程序。\
             旧版 旧版的对象：{}",
            if st.detection.legacy_guard_present {
                "检测到（只标记，不接管不删除）"
            } else {
                "未检测到"
            }
        ),
    ));
    out
}

/// 给 `--diagnose` 与管道用的纯文本行（与 [`guard_items`] 同源，不另写文案）。
pub fn guard_lines(st: &crate::guard::GuardStatus) -> Vec<String> {
    guard_items(st).into_iter().map(|item| item.text).collect()
}

fn guard_item(purpose: &str, text: String) -> Item {
    Item {
        target: "交易保护".to_string(),
        port: None,
        purpose: purpose.to_string(),
        result: purpose.to_string(),
        ms: None,
        text: format!("交易保护·{purpose}  {text}"),
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "在"
    } else {
        "不在"
    }
}

/// 一条规则在这个协议族上的真实状态。**按「为什么不合格」分开说**：
/// 「缺失」和「被禁用」对用户是两件事（一个要重装，一个要重新启用）。
fn slot_text(slot: &crate::guard::FilterSlot) -> String {
    if slot.ok() {
        return "合格".to_string();
    }
    if !slot.present {
        return "缺失".to_string();
    }
    if slot.disabled {
        return "被禁用".to_string();
    }
    if !slot.persistent {
        return "非持久（重启后消失）".to_string();
    }
    if !slot.recognized {
        return "认不出（不是我们的规则）".to_string();
    }
    "不合格".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Transport;
    use serde_json::json;

    fn obj(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    /// 纯 UDP 线路：WireGuard endpoint 带着 peer（服务器地址 + UDP 端口）。
    fn udp_line(host: &str, port: u16) -> serde_json::Map<String, Value> {
        obj(json!({
            "endpoints": [{
                "type": "wireguard", "tag": "hk",
                "address": ["10.7.0.2/32"],
                "peers": [{ "address": host, "port": port, "public_key": "x" }]
            }],
            "outbounds": [
                { "type": "selector", "tag": "trade-exit", "outbounds": ["hk"], "default": "hk" },
                { "type": "direct", "tag": "direct" }
            ]
        }))
    }

    /// 兼容连接线路：有 tag=tc-transport 的 vless。
    fn tcp_line(host: &str, port: u16) -> serde_json::Map<String, Value> {
        let mut o = udp_line(host, 51820);
        let mut outbounds = o["outbounds"].as_array().unwrap().clone();
        outbounds.insert(
            0,
            json!({
                "type": "vless", "tag": crate::engine_config::TRANSPORT_TAG,
                "server": host, "server_port": port,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "tls": { "enabled": true, "server_name": "cdn.example.com",
                         "reality": { "enabled": true, "public_key": "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1", "short_id": "ab12" } }
            }),
        );
        o.insert("outbounds".to_string(), Value::Array(outbounds));
        o
    }

    fn reachable(port: u16, ms: u128) -> Probe {
        Probe {
            target: Target { host: "h".into(), port },
            latency_ms: Some(ms),
            elapsed_ms: ms,
            result: ProbeResult::Reachable,
        }
    }
    fn unreachable(port: u16) -> Probe {
        Probe {
            target: Target { host: "h".into(), port },
            latency_ms: None,
            elapsed_ms: 0,
            result: ProbeResult::Unreachable,
        }
    }

    #[test]
    fn udp_line_probes_22_and_443_and_never_probes_the_wireguard_port() {
        let p = plan(&udp_line("203.0.113.9", 51820), Transport::Udp);
        assert!(!p.transport, "没有 tc-transport 就不是中转线路");
        assert_eq!(
            p.tcp.iter().map(|t| t.port).collect::<Vec<_>>(),
            vec![22, 443],
            "纯 UDP 只能探管理/Web 口"
        );
        assert!(
            !p.tcp.iter().any(|t| t.port == 51820),
            "WireGuard 的端口是 UDP，拿 TCP 去探它是错的"
        );
        // 但必须把它说出来，否则用户以为"没提就是没问题"
        assert_eq!(p.udp, vec!["203.0.113.9:51820".to_string()]);
        assert!(p.no_target.is_none());
    }

    #[test]
    fn transport_line_probes_the_transport_port_then_the_admin_port() {
        let p = plan(&tcp_line("203.0.113.7", 443), Transport::Tcp);
        assert!(p.transport);
        assert_eq!(p.tcp, vec![
            Target { host: "203.0.113.7".into(), port: 443 },
            Target { host: "203.0.113.7".into(), port: 22 },
        ]);
        // 传输端口恰好是 22 时不许重复探两次
        let p = plan(&tcp_line("203.0.113.7", 22), Transport::Tcp);
        assert_eq!(p.tcp.len(), 1);
    }

    #[test]
    fn summary_has_three_distinct_states() {
        // ① 有中转 + 传输端口可达
        let p = plan(&tcp_line("h", 443), Transport::Tcp);
        assert_eq!(
            summary(&p, &[reachable(443, 38), unreachable(22)]),
            "TCP 传输端口可达；Reality 认证、WireGuard 握手及转发需连接后检查。"
        );
        // ② 有中转 + 传输端口不通（哪怕 22 通，结论也只说传输端口）
        assert_eq!(
            summary(&p, &[unreachable(443), reachable(22, 5)]),
            "TCP 传输端口不可达，请检查对应服务与云安全组。"
        );
        // ③ 无中转：管理口可达 —— 但必须声明 UDP 与授权没验
        let u = plan(&udp_line("h", 51820), Transport::Udp);
        assert_eq!(
            summary(&u, &[reachable(22, 38), reachable(443, 52)]),
            "管理或 Web 端口可达；当前为 UDP WireGuard，尚未验证 UDP 与设备授权。"
        );
        // ③' 无中转且都不通：不许暗示"服务器离线"
        assert_eq!(
            summary(&u, &[unreachable(22), unreachable(443)]),
            "未探测到 TCP 22/443 响应。纯 UDP 服务器可能仍正常，不能据此判定离线。"
        );
    }

    #[test]
    fn render_lists_every_target_and_labels_the_udp_endpoint() {
        let p = plan(&udp_line("198.51.100.7", 51820), Transport::Udp);
        let mut ok = reachable(22, 38);
        let mut bad = unreachable(443);
        ok.target.host = "198.51.100.7".into();
        bad.target.host = "198.51.100.7".into();
        let lines = render(&p, &[ok, bad]);
        assert_eq!(lines[0], "TCP 198.51.100.7:22  可建立连接，耗时 38 ms");
        assert_eq!(
            lines[1],
            "TCP 198.51.100.7:443  无可用 TCP 响应，耗时 0 ms；可能未监听、端口受限或路径不可达"
        );
        assert_eq!(lines[2], "UDP 198.51.100.7:51820  该端点走 UDP，TCP 探测不适用");
        assert!(lines[3].starts_with("结论：管理或 Web 端口可达"), "{lines:?}");
        assert!(lines[3].contains("；下一步："), "结论与下一步必须同在末尾一行：{lines:?}");
    }

    #[test]
    fn t10_failure_guidance_matches_the_actual_transport_and_failed_purpose() {
        let tcp = plan(&tcp_line("h", 443), Transport::Tcp);
        let blocked = render(&tcp, &[unreachable(443), reachable(22, 5)]);
        assert!(blocked.last().unwrap().contains("TCP 传输端口不可达"), "{blocked:?}");
        assert!(blocked.last().unwrap().contains("检查中转服务"), "{blocked:?}");
        assert!(!blocked.last().unwrap().contains("可改用兼容连接"), "已经在兼容连接，不能给绕回原地的建议：{blocked:?}");

        let admin = render(&tcp, &[reachable(443, 8), unreachable(22)]);
        assert!(admin.last().unwrap().contains("线路可能失效"), "{admin:?}");
        assert!(admin.last().unwrap().contains("联系服务商或在 旧版重新部署"), "{admin:?}");

        let udp = plan(&udp_line("h", 51820), Transport::Udp);
        let no_tcp = render(&udp, &[unreachable(22), unreachable(443)]);
        let last = no_tcp.last().unwrap();
        assert!(last.contains("网络侧封禁"), "{last}");
        assert!(last.contains("可改用兼容连接"), "{last}");
        assert!(last.contains("不能据此判定离线"), "{last}");
    }

    #[test]
    fn t10_items_keep_failure_elapsed_time_purpose_and_verdict() {
        let p = plan(&tcp_line("h", 443), Transport::Tcp);
        let mut failed = unreachable(443);
        failed.elapsed_ms = 17;
        failed.result = ProbeResult::Timeout;
        let list = items(&p, &[failed, reachable(22, 5)]);
        assert_eq!(list[0].target, "h");
        assert_eq!(list[0].port, Some(443));
        assert_eq!(list[0].purpose, "transport");
        assert_eq!(list[0].result, "timeout");
        assert_eq!(list[0].ms, Some(17), "失败不得丢掉实际耗时");
        assert!(list[0].text.contains("TCP h:443") && list[0].text.contains("17 ms"));
        assert_eq!(list[1].purpose, "admin");
        assert_eq!(verdict(&p, &[unreachable(443), reachable(22, 5)]).code, "transport-unreachable");
    }

    #[test]
    fn a_line_without_any_address_says_it_probed_nothing_instead_of_failing_the_server() {
        // 我们的老夹具就是这种：endpoints 里只有 type/tag，没有 peer 地址。
        let mut o = udp_line("h", 51820);
        o["endpoints"] = json!([{ "type": "wireguard", "tag": "hk" }]);
        let p = plan(&o, Transport::Udp);
        assert!(p.tcp.is_empty());
        assert!(p.no_target.is_some(), "要说明为什么什么都没探");
        let lines = render(&p, &[]);
        assert!(lines[0].starts_with("未探测任何端口："), "{lines:?}");
        assert!(summary(&p, &[]).contains("不代表服务器离线"), "{lines:?}");
        let list = items(&p, &[]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].result, "not-run");
        assert_eq!(list[0].ms, None, "没做探测就不能伪造耗时");
    }

    #[test]
    fn a_tcp_shaped_file_diagnosed_as_standard_connection_does_not_probe_the_transit() {
        // 选了标准连接时那份中转不会被用上：拿它的端口当"传输端口"就是诊断了另一条路。
        let p = plan(&tcp_line("203.0.113.7", 443), Transport::Udp);
        assert!(!p.transport, "走标准连接就不是中转线路");
        assert_eq!(p.tcp.iter().map(|t| t.port).collect::<Vec<_>>(), vec![22, 443]);
        assert!(
            p.tcp.iter().all(|t| t.host == "203.0.113.7"),
            "探的是 peer 所在主机（这里恰好同一台），不是中转出站的口径"
        );
        // 反过来：已选兼容连接但文件里没有中转出站 → 说清原因，不静默退回 UDP 口径
        let mut no_transit = udp_line("h", 51820);
        no_transit.remove("outbounds");
        let p = plan(&no_transit, Transport::Tcp);
        assert!(p.tcp.is_empty(), "没有中转出站就没有传输端口可探");
        let reason = p.no_target.as_deref().expect("必须说明为什么什么都没探");
        assert!(reason.contains("兼容连接"), "{reason}");
        assert!(
            render(&p, &[]).iter().any(|l| l.starts_with("未探测任何端口：")),
            "要明说没做验证"
        );
    }

    #[test]
    fn probing_a_local_listener_is_reachable_and_a_closed_port_is_not() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let ok = probe(&Target { host: "127.0.0.1".into(), port });
        assert_eq!(ok.latency_ms.is_some(), true, "本地监听必须探得到");
        drop(l);
        // 关掉之后同一个端口立刻不可达（端口是刚才绑过的，避免撞上别的服务）
        let bad = probe(&Target { host: "127.0.0.1".into(), port });
        assert_eq!(bad.latency_ms, None, "已关闭的端口不许报可达");
        assert_eq!(bad.result, ProbeResult::Refused, "本机关闭端口应保留拒绝分类");
        assert!(bad.elapsed_ms < 2_500, "失败行也必须记录实际耗时：{bad:?}");
        // 非法 IP 字面量在本机立即解析失败，避免外部 DNS 让用例依赖网络环境。
        let unresolvable = probe(&Target { host: "999.1.1.1".into(), port: 443 });
        assert_eq!(unresolvable.latency_ms, None);
        assert_eq!(unresolvable.result, ProbeResult::ResolveFailed);
        assert!(unresolvable.elapsed_ms < 2_500, "解析失败同样记录实际耗时：{unresolvable:?}");
    }

    #[test]
    fn guard_section_reports_rules_record_and_scope_without_claiming_more() {
        use crate::guard::state::ProgramGuardStatus;
        use crate::guard::{
            FilterSlot, GuardDetection, GuardReason, GuardSource, GuardState, GuardStatus,
        };

        let slot = |disabled: bool, id: u64| FilterSlot {
            present: true,
            recognized: true,
            persistent: true,
            disabled,
            filter_id: Some(id),
        };
        let mut st = GuardStatus::new(GuardState::Protected, GuardReason::Ok);
        st.trade_program_count = 1;
        st.source = GuardSource::ElevatedVerify;
        st.store_kind = "Registry".into();
        st.evidence_trusted = true;
        st.boot_id_match = true;
        st.config_digest_match = true;
        st.age_text = "较旧：25 分钟前核验".into();
        st.detection = GuardDetection {
            provider_present: true,
            sublayer_present: true,
            infrastructure_verified: true,
            legacy_guard_present: false,
            bfe_ready: true,
        };
        st.programs.push(ProgramGuardStatus {
            name: "TDXW.exe".into(),
            path: Some("C:\\app\\TDXW.exe".into()),
            device_path: None,
            participated: true,
            unresolved_reason: None,
            ipv4: slot(false, 11),
            ipv6: slot(true, 12),
        });

        let text = guard_lines(&st).join("\n");
        assert!(text.contains("已保护"), "{text}");
        assert!(text.contains("依据较旧：25 分钟前核验"), "{text}");
        // 两族分开说：一个合格、一个被禁用，不能合并成「已保护」了事
        assert!(text.contains("IPv4 合格"), "{text}");
        assert!(text.contains("IPv6 被禁用"), "{text}");
        assert!(text.contains("存储 Registry"), "{text}");
        assert!(text.contains("只阻止名单内程序的 IPv4/IPv6 直连"), "{text}");
        assert!(!text.contains("实时"), "诊断页也不许出现「实时」：{text}");
    }

    #[test]
    fn guard_section_says_unknown_instead_of_borrowing_a_verdict() {
        use crate::guard::{GuardReason, GuardState, GuardStatus};

        let st = GuardStatus::unknown(GuardReason::NotVerifiedYet, 2);
        let text = guard_lines(&st).join("\n");
        assert!(text.contains("无法确认"), "{text}");
        assert!(!text.contains("已保护"), "没有证据时不许出现「已保护」：{text}");
        assert!(text.contains("来源 无"), "{text}");
    }
}

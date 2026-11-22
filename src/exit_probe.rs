//! 交易出口的**实际出口 IP** 观测（B1）。
//!
//! 自检（`selfcheck`）只证明「经交易出口发出的 HTTP 请求拿到了 2xx」，它证明不了流量最后
//! 从哪个 IP 出去。交易场景里用户真正关心的是后者：钱和行情走的是不是那台境外服务器。
//! 这里用**同一条认证 SOCKS 探测入站**（路由写死 `trade-exit`）去问一个出口 IP 服务，
//! 把答案连同「是否等于线路服务器地址」一起记下来。
//!
//! 三条口径，缺一条就是假话：
//! 1. **观测值，不是承诺**：拿不到就什么都不写，绝不回退成上一次的 IP；
//! 2. **能判归属就判，判不了就说不知道**：线路文件里 outbound 的 `server` 是公网 IP 时
//!    直接比对；是域名或本机中转时只报观测值（`attributed=false`），不猜；
//! 3. **只属于本次连接**：记录带 `started_at`，与当前 runtime 对不上就不采用——把上一次
//!    连接的出口 IP 挂在这一条连接上，比「没有证据」更糟。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// 记录文件：`<数据根>/exit-probe.json`。与 `last-check.json` 同级、同样只描述当前连接。
pub const FILE_NAME: &str = "exit-probe.json";

/// 一次出口观测。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// 观测时刻（epoch 秒）。
    pub at: u64,
    /// 观测到的出口 IP（已规范化）。
    pub ip: String,
    /// 是哪个服务回答的（排错用：不同服务在不同网络里可达性不同）。
    pub endpoint: String,
    /// 观测 IP 是否等于线路服务器地址。`false` 不等于「错了」，只等于「判不了／不是它」。
    pub attributed: bool,
    pub line_id: String,
    /// 观测时 runtime 的 `started_at`：用来判断这条记录还属不属于当前连接。
    pub started_at: String,
    /// Original nonsecret identity captured around the actual SOCKS request.
    /// Old exit JSON remains readable but cannot be current-verified without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<AttributionBinding>,
}

/// Not an authentication MAC; these digests only detect ordinary session,
/// route and line-file changes between observation and later consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionBinding {
    session_fingerprint: String,
    engine_fingerprint: String,
    port: u16,
    line_fingerprint: String,
}

/// 出口 IP 服务（明文 HTTP、端口 80）：`(host, path)`。
///
/// 为什么用明文 HTTP：探测入站出去的流量已经整段走在隧道里，IP 回显本身不是机密；
/// 而 TLS 要走 rustls + SNI，代价远大于「问一句我出来是谁」。三个服务互为备份——
/// 任何一个在某些网络里不可达都是常态。首个成功即用，记录里写明是谁答的。
const ENDPOINTS: [(&str, &str); 3] = [
    ("checkip.amazonaws.com", "/"),
    ("api.ipify.org", "/"),
    ("ip-api.com", "/line/?fields=query"),
];

/// 把记录读回来。坏文件当作没有：宁可显示「尚未核验」，也不要显示一个读不懂的东西。
pub fn load(root: &Path) -> Option<Record> {
    let text = std::fs::read_to_string(root.join(FILE_NAME)).ok()?;
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

/// 写记录。与自检结论同样先写临时文件再替换：断在半路会留下半截 JSON。
pub fn save(root: &Path, rec: &Record) -> Result<(), String> {
    let path = root.join(FILE_NAME);
    let text = serde_json::to_string_pretty(rec).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("{}：{e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}：{e}", path.display()))
}

/// 清掉记录（断开、连接失败、换线路都算「这条证据过期了」）。
pub fn clear(root: &Path) {
    let _ = std::fs::remove_file(root.join(FILE_NAME));
}

/// Capture a qualified ORIGINAL session/route + selected line from disk.
/// The route and credentials must match the current pinned automatic Check,
/// never a new fingerprint fabricated after the HTTP request.
fn current_binding(
    root: &Path, line_id: &str, port: u16,
    expected_credentials: Option<(&str, &str)>,
) -> Option<AttributionBinding> {
    let cfg = crate::config::load_readonly(&root.join(crate::config::DEFAULT_PATH))
        .ok()??;
    let line = cfg.current_line()?;
    if line.id != line_id {
        return None;
    }
    let (session_fingerprint, engine_fingerprint) =
        crate::selfcheck::current_exit_probe_binding(root, port, expected_credentials)?;
    // A server-address change cannot relabel an old observed IP as belonging
    // to a different line file, even when line ID and StartedAt are reused.
    use sha2::Digest;
    let bytes = std::fs::read(line.engine_config_path(root)).ok()?;
    let mut hash = sha2::Sha256::new();
    hash.update(b"spidervpn/exit-line-config/v1\0");
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(&bytes);
    let line_fingerprint = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Some(AttributionBinding {
        session_fingerprint, engine_fingerprint, port, line_fingerprint,
    })
}

/// An old observation may still be read via load() for historical context,
/// but only an exact original binding, live qualified trade Check and current
/// selected line can authorize it as evidence for the running connection.
pub fn belongs_to_current_connection(rec: &Record, root: &Path) -> bool {
    let Some(bound) = rec.binding.as_ref() else { return false };
    if !root.join("runtime-engine.json").is_file()
        || crate::selfcheck::runtime_started_at(root).as_deref()
            != Some(rec.started_at.as_str())
    {
        return false;
    }
    current_binding(root, &rec.line_id, bound.port, None).as_ref() == Some(bound)
}

/// 观测一次出口 IP 并落盘。**失败不写、不覆盖、不报错给用户**——它只是证据采集，
/// 不该让一次已经成功的连接因为「IP 回显服务连不上」而看起来失败。
///
/// `timeout_ms` 是总预算（跨多个端点）；单个端点最多 1200 ms，剩余不足 200 ms 就收手。
pub fn probe_and_record(
    root: &Path,
    line: &crate::config::LineConfig,
    plan: &crate::selfcheck::ProbePlan,
    timeout_ms: u64,
) -> Option<Record> {
    let crate::selfcheck::ProbePlan::Dial { port, username, password } = plan else {
        // 连探测入站都没有（端口拿不到）：自检已经报「跳过」，这里再做一次只会刷超时。
        return None;
    };
    let started_at = crate::selfcheck::runtime_started_at(root)?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    // Never skip collecting actual SOCKS observations merely because the
    // caller's prior Check.ok became stale. Capture the *pre-request* proof.
    let before = current_binding(root, &line.id, *port, Some((username, password)));
    let targets = server_ips(root, line);
    for (host, path) in ENDPOINTS {
        let left = deadline.saturating_duration_since(Instant::now());
        let budget = u64::try_from(left.as_millis()).unwrap_or(u64::MAX).min(1_200);
        if budget < 200 {
            break;
        }
        let Ok((status, body)) =
            crate::selfcheck::socks5_text(*port, username, password, host, path, budget)
        else {
            continue;
        };
        if !(200..=299).contains(&status) {
            continue;
        }
        let Some(ip) = parse_ip(&body) else { continue };
        // If route, credentials, line selection or server file moved while
        // the HTTP exchange ran, retain the raw IP on disk UNATTRIBUTED.
        let after = current_binding(root, &line.id, *port, Some((username, password)));
        let binding = before.clone().filter(|snapshot| after.as_ref() == Some(snapshot));
        let mut rec = Record {
            at: crate::model::now_epoch_secs_u64(),
            ip: ip.clone(),
            endpoint: (*host).to_string(),
            attributed: binding.is_some() && targets.iter().any(|t| t == &ip),
            line_id: line.id.clone(),
            started_at: started_at.clone(),
            binding,
        };
        let _ = save(root, &rec);
        // The read boundary independently revalidates the original binding;
        // downgrade the return value too, so CLI cannot echo stale "verified".
        if !belongs_to_current_connection(&rec, root) {
            rec.attributed = false;
            rec.binding = None;
            let _ = save(root, &rec);
        }
        return Some(rec);
    }
    None
}

/// 线路服务器地址（只取**公网字面 IP**）。
///
/// 从线路文件（`<数据根>/lines/<id>.json`）的 `outbounds[].server` 里取：标准连接是
/// 服务器的公网地址；兼容连接是那条 vless 的服务器。取不到就返回空——空集合意味着
/// 「判不了归属」，不是「归属错了」。
pub fn server_ips(root: &Path, line: &crate::config::LineConfig) -> Vec<String> {
    let path = line.engine_config_path(root);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for outbound in value
        .get("outbounds")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let Some(server) = outbound.get("server").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(ip) = IpAddr::from_str(server.trim()) else {
            continue;
        };
        if !is_public(ip) {
            continue;
        }
        let text = ip.to_string();
        if !out.contains(&text) {
            out.push(text);
        }
    }
    out
}

/// 从一段文本里取第一个**公网** IP。
///
/// 不要求正文只有 IP：`api.ipify.org` 给纯文本，`ip-api.com` 给纯文本，
/// Cloudflare trace 给 `ip=…` 的行。但也因此**必须**校验——正文里任何一串数字都可能
/// 长得像地址（错误页里的 `0.0.0.0`、版本号、HTML 里的样式值）。
pub fn parse_ip(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        return is_public(ip).then(|| ip.to_string());
    }
    // IPv4：数字与点组成的 token。
    if let Some(ip) = scan(text, |c| c.is_ascii_digit() || c == '.') {
        return Some(ip);
    }
    // IPv6：十六进制、冒号与点（内嵌 v4）。
    scan(text, |c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

fn scan(text: &str, keep: impl Fn(char) -> bool) -> Option<String> {
    let mut token = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if keep(c) {
            token.push(c);
            continue;
        }
        if let Some(found) = token_ip(&token) {
            return Some(found);
        }
        token.clear();
    }
    None
}

fn token_ip(token: &str) -> Option<String> {
    let token = token.trim_matches('.');
    if token.len() < 7 {
        return None;
    }
    let ip = IpAddr::from_str(token).ok()?;
    is_public(ip).then(|| ip.to_string())
}

/// 公网判定。私有/回环/链路本地/未指定/文档地址一律不算出口：
/// 观测到这些只说明「隧道没把流量带出去」，拿它当证据等于把故障写成成功。
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            let first = v6.segments()[0];
            // fc00::/7（唯一本地）与 fe80::/10（链路本地）
            !((first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("tcrs-exitprobe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::create_dir_all(&p);
        p
    }

    /// 假探测入站：走完 SOCKS5 认证 + CONNECT，然后回一个带正文的 200。
    /// 最多接三次（探测会依次试三个端点，前两个失败时仍要有人应答）。
    fn fake_socks5(body: &'static str, expect_user: &'static str, expect_pass: &'static str) -> u16 {
        let l = TcpListener::bind(("127.0.0.1", 0)).expect("绑定随机端口");
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for _ in 0..3 {
                let Ok((mut s, _)) = l.accept() else { return };
                // 一整帧读完再说话：`read` 可能只给半个问候，后面所有长度字段都会跟着错位。
                let mut g = [0u8; 4];
                if s.read_exact(&mut g).is_err() {
                    continue;
                }
                let _ = s.write_all(&[0x05, 0x02]);
                let mut h = [0u8; 2];
                if s.read_exact(&mut h).is_err() {
                    continue;
                }
                let mut u = vec![0u8; h[1] as usize];
                if s.read_exact(&mut u).is_err() {
                    continue;
                }
                let mut pl = [0u8; 1];
                if s.read_exact(&mut pl).is_err() {
                    continue;
                }
                let mut p = vec![0u8; pl[0] as usize];
                if s.read_exact(&mut p).is_err() {
                    continue;
                }
                let authed = u == expect_user.as_bytes() && p == expect_pass.as_bytes();
                let _ = s.write_all(&[0x01, u8::from(!authed)]);
                if !authed {
                    continue;
                }
                let mut head = [0u8; 5];
                if s.read_exact(&mut head).is_err() {
                    continue;
                }
                let mut rest = vec![0u8; head[4] as usize + 2];
                if s.read_exact(&mut rest).is_err() {
                    continue;
                }
                let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
                let mut req = vec![0u8; 512];
                let _ = s.read(&mut req);
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
            }
        });
        port
    }

    fn line_with(root: &Path, id: &str, outbounds: serde_json::Value) -> crate::config::LineConfig {
        let config = crate::config::parse(
            r#"{"schema":2,"lines":[{"id":"hk","name":"香港 01","proxy_endpoint":"127.0.0.1:17891"}]}"#,
        )
        .expect("最小线路配置");
        let line = config.lines.into_iter().next().expect("必须有一条线路");
        std::fs::create_dir_all(root.join("lines")).unwrap();
        std::fs::write(
            line.engine_config_path(root),
            serde_json::json!({ "outbounds": outbounds }).to_string(),
        )
        .unwrap();
        let _ = id;
        line
    }

    #[test]
    fn parse_ip_accepts_plain_json_and_trace_bodies() {
        assert_eq!(parse_ip("8.8.8.8\n").as_deref(), Some("8.8.8.8"));
        assert_eq!(parse_ip(r#"{"ip":"8.8.8.8"}"#).as_deref(), Some("8.8.8.8"));
        assert_eq!(parse_ip("fl=1f\nip=8.8.8.8\nts=1\n").as_deref(), Some("8.8.8.8"));
        // HTML 错误页里塞一个地址也要认出来（服务可达但被中间人改了页面时就是这种样子）。
        assert_eq!(
            parse_ip("<html><body>Your IP: 8.8.8.8</body></html>").as_deref(),
            Some("8.8.8.8")
        );
        // 文档地址（TEST-NET）也是「不是真出口」：解析出来但不能当证据。
        assert_eq!(parse_ip("203.0.113.7"), None);
    }

    #[test]
    fn parse_ip_refuses_non_public_and_non_addresses() {
        // 私有/回环/未指定：只能说明隧道没把流量带出去，不能当出口证据。
        assert_eq!(parse_ip("10.66.0.2"), None);
        assert_eq!(parse_ip("127.0.0.1"), None);
        assert_eq!(parse_ip("0.0.0.0"), None);
        assert_eq!(parse_ip("192.168.1.9"), None);
        assert_eq!(parse_ip("172.16.0.9"), None);
        // 不是地址：版本号、空正文、错误文案。
        assert_eq!(parse_ip("1.14.2"), None);
        assert_eq!(parse_ip(""), None);
        assert_eq!(parse_ip("no address here"), None);
    }

    #[test]
    fn server_ips_only_takes_public_literals() {
        let root = tmp_root("servers");
        let line = line_with(
            &root,
            "hk",
            serde_json::json!([
                {"type":"vless","tag":"tc-transport","server":"8.8.8.8","server_port":8443},
                {"type":"selector","tag":"trade-exit"},
                {"type":"socks","tag":"local","server":"127.0.0.1","server_port":9000},
                {"type":"wireguard","tag":"wg","server":"example.com","server_port":51820}
            ]),
        );
        // 只认公网字面 IP：域名（example.com）与回环（127.0.0.1）都判不了归属。
        assert_eq!(server_ips(&root, &line), vec!["8.8.8.8".to_string()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn probe_records_the_observed_ip_and_attributes_it_to_the_line() {
        let root = tmp_root("probe");
        let line = line_with(
            &root,
            "hk",
            serde_json::json!([{"type":"vless","server":"8.8.8.8","server_port":8443}]),
        );
        // This positive test must model a REAL current authenticated trade
        // session and valid pinned auto-Check, not just StartedAt + {}.
        let cfg = crate::config::parse(
            r#"{"schema":2,"selected":"hk","lines":[{"id":"hk","name":"香港 01","proxy_endpoint":"127.0.0.1:17891"}]}"#
        ).unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        let runtime = format!(
            r#"{{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":{},"StartedAt":"2026-11-06T02:00:00Z","State":"Running"}}"#,
            std::process::id()
        );
        std::fs::write(root.join("runtime.json"), runtime).unwrap();
        crate::selfcheck::record_probe_creds(&root.join("runtime.json"), "u", "p").unwrap();
        let port = fake_socks5("8.8.8.8\n", "u", "p");
        std::fs::write(root.join("runtime-engine.json"), format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"hk"}},{{"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"}}],
                "inbounds":[{{"type":"socks","tag":"tc-check","listen":"127.0.0.1","listen_port":{port},
                  "users":[{{"username":"u","password":"p"}}]}}],
                "route":{{"rules":[{{"inbound":["tc-check"],"outbound":"trade-exit"}}]}}}}"#
        )).unwrap();
        // 先钉住底层两件事：runtime 读得出 started_at，握手+正文读得回。缺一条，
        // 下面「观测不到」就说明不了任何事。
        assert_eq!(
            crate::selfcheck::runtime_started_at(&root).as_deref(),
            Some("2026-11-06T02:00:00Z")
        );
        let (status, body) =
            crate::selfcheck::socks5_text(port, "u", "p", "checkip.amazonaws.com", "/", 1_500)
                .expect("假服务的握手必须走通");
        assert_eq!(status, 200);
        assert!(body.contains("8.8.8.8"), "正文必须读回：{body:?}");
        let plan = crate::selfcheck::ProbePlan::Dial {
            port,
            username: "u".to_string(),
            password: "p".to_string(),
        };
        // The second synthetic SOCKS response is the real successful 2xx
        // automatic check, including original port/session/engine bindings.
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.via_trade_exit && check.status == Some(200), "{check:?}");
        assert_eq!(crate::selfcheck::load(&root), Some(check));
        let rec = probe_and_record(&root, &line, &plan, 2_000).expect("假服务必须能观测到");
        assert_eq!(rec.ip, "8.8.8.8");
        assert!(rec.attributed, "与线路服务器地址一致时必须判为已归属");
        assert_eq!(rec.started_at, "2026-11-06T02:00:00Z");
        // 落盘且能读回：界面读的是这份文件，不是内存里的返回值。
        let loaded = load(&root).expect("必须落盘");
        assert_eq!(loaded, rec);
        assert!(belongs_to_current_connection(&loaded, &root));
        // Same StartedAt with rotated credentials is a NEW authenticated
        // session, even if both the IP and saved Check were once successful.
        let original_runtime = std::fs::read(root.join("runtime.json")).unwrap();
        crate::selfcheck::record_probe_creds(&root.join("runtime.json"), "new-u", "new-p").unwrap();
        assert!(!belongs_to_current_connection(&loaded, &root));
        std::fs::write(root.join("runtime.json"), original_runtime).unwrap();
        assert!(belongs_to_current_connection(&loaded, &root));
        // Changing a current route to direct must revoke the original proof.
        let engine_path = root.join("runtime-engine.json");
        let original_engine = std::fs::read(&engine_path).unwrap();
        let mut engine: serde_json::Value = serde_json::from_slice(&original_engine).unwrap();
        engine["route"]["rules"][0]["outbound"] = serde_json::json!("direct");
        std::fs::write(&engine_path, engine.to_string()).unwrap();
        assert!(!belongs_to_current_connection(&loaded, &root));
        std::fs::write(&engine_path, original_engine).unwrap();
        assert!(belongs_to_current_connection(&loaded, &root));
        // Switching the selected line cannot award this IP to a different one.
        let config_path = root.join(crate::config::DEFAULT_PATH);
        let mut cfg = crate::config::load_readonly(&config_path).unwrap().unwrap();
        let original_cfg = cfg.clone();
        let mut other = cfg.lines[0].clone();
        other.id = "another-line".into();
        cfg.lines.push(other);
        cfg.selected = "another-line".into();
        crate::config::save(&config_path, &cfg).unwrap();
        assert!(!belongs_to_current_connection(&loaded, &root));
        crate::config::save(&config_path, &original_cfg).unwrap();
        assert!(belongs_to_current_connection(&loaded, &root));
        // runtime 变了（换了一次连接）就不再属于当前连接。
        std::fs::write(root.join("runtime.json"), r#"{"SchemaVersion":1,"StartedAt":"2026-11-06T03:00:00Z"}"#)
            .unwrap();
        assert!(!belongs_to_current_connection(&loaded, &root));
        // 断开之后（`runtime-engine.json` 没了）也不算：上一条连接的出口 IP 不能挂在空转的界面上。
        std::fs::write(root.join("runtime.json"), r#"{"SchemaVersion":1,"StartedAt":"2026-11-06T02:00:00Z"}"#)
            .unwrap();
        std::fs::remove_file(root.join("runtime-engine.json")).unwrap();
        assert!(!belongs_to_current_connection(&loaded, &root));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_exit_json_is_readable_but_never_promoted_to_current_verified() {
        let root = tmp_root("legacy-unbound");
        std::fs::write(root.join(FILE_NAME), r#"{
            "at":42,"ip":"8.8.8.8","endpoint":"checkip.amazonaws.com",
            "attributed":true,"line_id":"hk","started_at":"same-started-at"
        }"#).unwrap();
        std::fs::write(root.join("runtime.json"),
            r#"{"SchemaVersion":1,"StartedAt":"same-started-at"}"#).unwrap();
        std::fs::write(root.join("runtime-engine.json"), "{}").unwrap();
        let previous = load(&root).expect("old exit JSON must remain readable");
        assert_eq!(previous.ip, "8.8.8.8");
        assert!(previous.attributed, "historical observation retained unmodified");
        assert!(previous.binding.is_none());
        assert!(!belongs_to_current_connection(&previous, &root),
            "StartedAt-only old JSON must not upgrade to current verified");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn probe_writes_nothing_when_the_exit_returns_a_private_address() {
        let root = tmp_root("private");
        let line = line_with(&root, "hk", serde_json::json!([]));
        std::fs::write(root.join("runtime.json"), r#"{"SchemaVersion":1,"StartedAt":"t"}"#).unwrap();
        let port = fake_socks5("10.66.0.2\n", "u", "p");
        let plan = crate::selfcheck::ProbePlan::Dial {
            port,
            username: "u".to_string(),
            password: "p".to_string(),
        };
        assert_eq!(probe_and_record(&root, &line, &plan, 800), None);
        assert_eq!(load(&root), None, "拿不到观测值时绝不能留下旧记录或半条记录");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn probe_skips_without_a_dial_plan() {
        let root = tmp_root("skip");
        let line = line_with(&root, "hk", serde_json::json!([]));
        let plan = crate::selfcheck::ProbePlan::Skip { port: None, reason: "x".into() };
        assert_eq!(probe_and_record(&root, &line, &plan, 500), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}

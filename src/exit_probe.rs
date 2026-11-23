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

// Same-process, same-root writers are tracked by lifetime, not a single
// HashSet bit. An overlapping writer's successful rename may NOT revoke
// another active writer or a failure in the same overlapping group (#62).
// This is NOT an interprocess lock/crash-proof on-disk tombstone.
#[derive(Default)]
struct ExitWriteState {
    active_writers: usize,
    failed_in_group: bool,
}

fn uncommitted_exit_writes() -> &'static std::sync::Mutex<
    std::collections::HashMap<std::path::PathBuf, ExitWriteState>
> {
    static PENDING: std::sync::OnceLock<std::sync::Mutex<
        std::collections::HashMap<std::path::PathBuf, ExitWriteState>
    >> = std::sync::OnceLock::new();
    PENDING.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

// RAII also records an abandoned/panicking write as failed. A previous
// failed group remains dirty until a new group really finishes successfully.
struct ExitWriteGuard {
    root: std::path::PathBuf,
    committed: bool,
}

impl ExitWriteGuard {
    fn begin(root: &Path) -> Result<Self, String> {
        let mut roots = uncommitted_exit_writes()
            .lock()
            .map_err(|_| "exit pending-write lock poisoned".to_string())?;
        let state = roots.entry(root.to_path_buf()).or_default();
        if state.active_writers == 0 {
            // Beginning a new recovery group does not grant CURRENT: the
            // entry remains present until its final successful completion.
            state.failed_in_group = false;
        }
        state.active_writers = state.active_writers.checked_add(1)
            .ok_or_else(|| "exit pending writer count overflow".to_string())?;
        Ok(Self { root: root.to_path_buf(), committed: false })
    }
}

impl Drop for ExitWriteGuard {
    fn drop(&mut self) {
        let Ok(mut roots) = uncommitted_exit_writes().lock() else {
            return; // Poisoned readers fail closed, never authorize CURRENT.
        };
        let Some(state) = roots.get_mut(&self.root) else { return };
        if !self.committed {
            state.failed_in_group = true;
        }
        state.active_writers = state.active_writers.saturating_sub(1);
        if self.committed && state.active_writers == 0 && !state.failed_in_group {
            roots.remove(&self.root);
        }
    }
}

fn exit_write_uncommitted(root: &Path) -> bool {
    root.join(FILE_NAME).with_extension("json.tmp").exists()
        || uncommitted_exit_writes()
            .lock()
            .map(|roots| roots.contains_key(root))
            .unwrap_or(true) // Poisoned guard must never authorize current.
}

/// 把记录读回来。坏文件当作没有：宁可显示「尚未核验」，也不要显示一个读不懂的东西。
pub fn load(root: &Path) -> Option<Record> {
    let text = std::fs::read_to_string(root.join(FILE_NAME)).ok()?;
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

/// 写记录。与自检结论同样先写临时文件再替换：断在半路会留下半截 JSON。
pub fn save(root: &Path, rec: &Record) -> Result<(), String> {
    // Deny current attribution from the beginning of a write through its
    // commit. If either temp creation or rename fails, keep the guard until
    // a later genuinely successful save; a best-effort clear() is not proof.
    let mut pending = ExitWriteGuard::begin(root)?;
    #[cfg(test)]
    tests::after_pending_save_test_hook();
    let result = (|| -> Result<(), String> {
        let path = root.join(FILE_NAME);
        let text = serde_json::to_string_pretty(rec).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("{}：{e}", tmp.display()))?;
        #[cfg(test)]
        tests::after_tmp_write_before_rename_test_hook();
        std::fs::rename(&tmp, &path).map_err(|e| format!("{}：{e}", path.display()))
    })();
    if result.is_ok() {
        pending.committed = true;
    }
    result
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
    // Historical JSON may remain readable, but a failed/pending newer write
    // revokes its CURRENT authority even if deletion was refused by Windows.
    !exit_write_uncommitted(root) && original_exit_binding_still_current(rec, root)
}

fn original_exit_binding_still_current(rec: &Record, root: &Path) -> bool {
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
        let rec = Record {
            at: crate::model::now_epoch_secs_u64(),
            ip: ip.clone(),
            endpoint: (*host).to_string(),
            attributed: binding.is_some() && targets.iter().any(|t| t == &ip),
            line_id: line.id.clone(),
            started_at: started_at.clone(),
            binding,
        };
        // There must never be an earlier attributed JSON visible before the
        // final live qualification. Persist the FINAL observation only once.
        // Failed writes cannot authorize a current verified return value.
        return Some(persist_final_observation(root, rec));
    }
    None
}

/// Last qualification precedes the one persistence attempt. The caller still
/// receives the real observed IP on failure, but never a verified attribution.
/// This is not a cross-file atomic transaction: IPC/readers must independently
/// validate the original binding against the live session and route.
fn persist_final_observation(root: &Path, mut rec: Record) -> Record {
    // Requalify the NEW authenticated observation independently of a
    // previous failed-save guard. Readers must remain denied until this
    // attempt actually completes its only successful rename.
    if !original_exit_binding_still_current(&rec, root) {
        rec.attributed = false;
        rec.binding = None;
    }
    if let Err(e) = save(root, &rec) {
        // A failed rename may leave an older record. Try to invalidate it,
        // without claiming that deletion can defeat another local writer.
        clear(root);
        rec.attributed = false;
        rec.binding = None;
        eprintln!("出口观测写盘失败，不能视为当前已核验出口：{e}");
    }
    rec
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

    // Thread-local test hook: pause a REAL save after the production pending
    // mark and before its filesystem writes. Release code remains unchanged.
    std::thread_local! {
        static AFTER_PENDING_SAVE_HOOK:
            std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            std::cell::RefCell::new(None);
    }

    pub(super) fn after_pending_save_test_hook() {
        AFTER_PENDING_SAVE_HOOK.with(|slot| {
            let callback = slot.borrow_mut().take();
            if let Some(callback) = callback {
                callback();
            }
        });
    }

    // #64 TEST-ONLY: reached only after the REAL production fs::write
    // returned successfully, and before that same save() invokes rename.
    std::thread_local! {
        static AFTER_TMP_WRITE_BEFORE_RENAME_HOOK:
            std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            std::cell::RefCell::new(None);
    }

    pub(super) fn after_tmp_write_before_rename_test_hook() {
        AFTER_TMP_WRITE_BEFORE_RENAME_HOOK.with(|slot| {
            let callback = slot.borrow_mut().take();
            if let Some(callback) = callback {
                callback();
            }
        });
    }

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


    /// Prepare the SAME authenticated trade route/session/line needed by the
    /// production check reader. Test traffic remains on loopback; 8.8.8.8 is
    /// only a synthetic local HTTP response body.
    fn qualified_probe_fixture(root: &Path, port: u16) -> crate::config::LineConfig {
        let line = line_with(root, "hk",
            serde_json::json!([{"type":"vless","server":"8.8.8.8","server_port":8443}]));
        let cfg = crate::config::parse(
            r#"{"schema":2,"selected":"hk","lines":[{"id":"hk","name":"香港 01","proxy_endpoint":"127.0.0.1:17891"}]}"#
        ).unwrap();
        crate::config::save(&root.join(crate::config::DEFAULT_PATH), &cfg).unwrap();
        std::fs::write(root.join("runtime.json"), format!(
            r#"{{"SchemaVersion":1,"SupervisorPid":0,"EnginePid":{},"StartedAt":"2026-11-06T02:00:00Z","State":"Running"}}"#,
            std::process::id()
        )).unwrap();
        crate::selfcheck::record_probe_creds(&root.join("runtime.json"), "u", "p").unwrap();
        std::fs::write(root.join("runtime-engine.json"), format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"hk"}},{{"type":"selector","tag":"trade-exit","outbounds":["hk"],"default":"hk"}}],
                "inbounds":[{{"type":"socks","tag":"tc-check","listen":"127.0.0.1","listen_port":{port},
                  "users":[{{"username":"u","password":"p"}}]}}],
                "route":{{"rules":[{{"inbound":["tc-check"],"outbound":"trade-exit"}}]}}}}"#
        )).unwrap();
        line
    }

    fn qualified_plan(port: u16) -> crate::selfcheck::ProbePlan {
        crate::selfcheck::ProbePlan::Dial {
            port, username: "u".into(), password: "p".into(),
        }
    }

    #[test]
    fn failed_final_exit_save_returns_raw_ip_without_verified_attribution() {
        let root = tmp_root("failed-final-save");
        let port = fake_socks5("8.8.8.8\n", "u", "p");
        let line = qualified_probe_fixture(&root, port);
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && crate::selfcheck::current_qualified_trade_pass(&root),
            "must fail at actual final save, not at the qualified check: {check:?}");
        // Directory-as-file reliably prevents rename on Windows and Unix.
        std::fs::create_dir(root.join(FILE_NAME)).unwrap();
        let observed = probe_and_record(&root, &line, &plan, 2_000)
            .expect("real local SOCKS response must still be parsed");
        assert_eq!(observed.ip, "8.8.8.8");
        assert!(!observed.attributed);
        assert!(observed.binding.is_none());
        assert_eq!(load(&root), None, "failed final rename must not create a verified record");
        assert!(!belongs_to_current_connection(&observed, &root));
        let _ = std::fs::remove_dir_all(root);
    }

    /// Two-phase authenticated local SOCKS server: the second HTTP response is
    /// withheld until the test has changed the runtime route. No sleeps/races.
    fn gated_two_phase_socks() -> (
        u16, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (at_response_tx, at_response_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            for n in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                let mut greet = [0u8; 4];
                s.read_exact(&mut greet).unwrap();
                assert_eq!(greet, [0x05, 0x02, 0x00, 0x02]);
                s.write_all(&[0x05, 0x02]).unwrap();
                let mut auth = [0u8; 2];
                s.read_exact(&mut auth).unwrap();
                assert_eq!(auth[0], 0x01);
                let mut user = vec![0u8; usize::from(auth[1])];
                s.read_exact(&mut user).unwrap();
                assert_eq!(user, b"u");
                let mut plen = [0u8; 1];
                s.read_exact(&mut plen).unwrap();
                let mut pass = vec![0u8; usize::from(plen[0])];
                s.read_exact(&mut pass).unwrap();
                assert_eq!(pass, b"p");
                s.write_all(&[0x01, 0x00]).unwrap();
                let mut connect = [0u8; 5];
                s.read_exact(&mut connect).unwrap();
                let mut rest = vec![0u8; usize::from(connect[4]) + 2];
                s.read_exact(&mut rest).unwrap();
                s.write_all(&[0x05, 0, 0, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();
                let mut req = [0u8; 512];
                s.read(&mut req).unwrap();
                if n == 1 {
                    at_response_tx.send(()).unwrap();
                    continue_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                let (status, body) = if n == 0 {
                    ("204 No Content", "")
                } else {
                    ("200 OK", "8.8.8.8\n")
                };
                s.write_all(format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ).as_bytes()).unwrap();
            }
        });
        (port, at_response_rx, continue_tx, server)
    }

    #[test]
    fn route_changed_while_exit_http_in_flight_persists_one_unattributed_record() {
        let root = tmp_root("in-flight-final-save");
        let (port, at_response, proceed, server) = gated_two_phase_socks();
        let line = qualified_probe_fixture(&root, port);
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.status == Some(204), "{check:?}");
        let worker_root = root.clone();
        let probe = std::thread::spawn(move ||
            probe_and_record(&worker_root, &line, &plan, 2_500)
        );
        at_response.recv_timeout(Duration::from_secs(10))
            .expect("second authenticated SOCKS HTTP request must reach server");
        // Occurs AFTER producer captured its initial binding and issued HTTP,
        // but BEFORE it gets the final body/qualification/persistence.
        let engine_path = root.join("runtime-engine.json");
        let mut runtime: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&engine_path).unwrap()).unwrap();
        runtime["route"]["rules"][0]["outbound"] = serde_json::json!("direct");
        std::fs::write(&engine_path, runtime.to_string()).unwrap();
        assert!(!crate::selfcheck::current_qualified_trade_pass(&root));
        proceed.send(()).unwrap();
        let observed = probe.join().unwrap().expect("local HTTP200 IP must be preserved");
        server.join().unwrap();
        let disk = load(&root);
        assert_eq!(disk, Some(observed.clone()), "exact one final observation persisted");
        assert_eq!(observed.ip, "8.8.8.8");
        assert!(!observed.attributed);
        assert!(observed.binding.is_none());
        assert!(!belongs_to_current_connection(&observed, &root));
        assert!(!root.join("exit-probe.json.tmp").exists(),
            "no second downgrade-save/temporary intermediate file");
        let _ = std::fs::remove_dir_all(root);
    }


    /// Three REAL authenticated loopback SOCKS HTTP exchanges, all on the
    /// original qualified Check port: initial Check 204, old exit 8.8.8.8,
    /// and new exit 1.1.1.1. Neither public IP is ever contacted.
    #[cfg(windows)]
    fn three_sequential_windows_socks_observations() -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for n in 0..3 {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut greeting = [0u8; 4];
                s.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
                s.write_all(&[0x05, 0x02]).unwrap();
                let mut auth = [0u8; 2];
                s.read_exact(&mut auth).unwrap();
                assert_eq!(auth[0], 0x01);
                let mut user = vec![0u8; usize::from(auth[1])];
                s.read_exact(&mut user).unwrap();
                let mut plen = [0u8; 1];
                s.read_exact(&mut plen).unwrap();
                let mut pass = vec![0u8; usize::from(plen[0])];
                s.read_exact(&mut pass).unwrap();
                assert_eq!(user, b"u");
                assert_eq!(pass, b"p");
                s.write_all(&[0x01, 0x00]).unwrap();
                let mut connect = [0u8; 5];
                s.read_exact(&mut connect).unwrap();
                assert_eq!(&connect[..4], &[0x05, 0x01, 0x00, 0x03]);
                let mut target = vec![0u8; usize::from(connect[4]) + 2];
                s.read_exact(&mut target).unwrap();
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();
                let mut request = [0u8; 512];
                assert!(s.read(&mut request).unwrap() > 0);
                let (status, body) = match n {
                    0 => ("204 No Content", ""),
                    1 => ("200 OK", "8.8.8.8\n"),
                    _ => ("200 OK", "1.1.1.1\n"),
                };
                s.write_all(format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ).as_bytes()).unwrap();
            }
        });
        (port, server)
    }

    /// RED FIRST: A *real* readable, current-qualified old JSON survives a
    /// failed Windows rename AND failed delete, not the directory-as-file
    /// shortcut in the existing test. File-share mode denies DELETE only.

    #[test]
    fn failed_exit_tmp_write_without_tmp_still_denies_current_and_recovers_on_success() {
        let root = tmp_root("failed-exit-no-temp-marker");
        let port = fake_socks5("8.8.8.8\n", "u", "p");
        let line = qualified_probe_fixture(&root, port);
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.via_trade_exit, "{check:?}");
        let old = probe_and_record(&root, &line, &plan, 2_000)
            .expect("real authenticated loopback exit positive");
        assert!(old.attributed && belongs_to_current_connection(&old, &root));
        assert_eq!(load(&root), Some(old.clone()));

        // Actual filesystem error BEFORE a new temp file is written: remove
        // the blocking directory afterward so the path itself no longer
        // supplies the fail-closed guard. The same-process marker must.
        let tmp = root.join(FILE_NAME).with_extension("json.tmp");
        std::fs::create_dir(&tmp).unwrap();
        assert!(save(&root, &old).is_err(), "directory-as-temp must refuse real write");
        assert_eq!(load(&root), Some(old.clone()), "old history must survive");
        std::fs::remove_dir(&tmp).unwrap();
        assert!(!tmp.exists(), "no residual temp path to help the reader");
        assert!(!belongs_to_current_connection(&old, &root),
            "a same-process failed write without any temp must revoke old current evidence");
        assert_eq!(load(&root), Some(old.clone()), "historic JSON remains readable");

        // A later truly successful save is the ONLY action that clears the
        // pending-failure guard and permits renewed qualified current reads.
        save(&root, &old).expect("save should succeed after removing obstruction");
        assert!(!tmp.exists(), "success must consume the temp file");
        assert_eq!(load(&root), Some(old.clone()));
        assert!(belongs_to_current_connection(&old, &root),
            "successful atomic record save must restore the legitimate positive");
        let _ = std::fs::remove_dir_all(root);
    }

    /// #62 TEST-ONLY RED: two actual overlapping production save() calls.
    /// No sleep, mock save result, or release-build behavior changes.
    #[test]
    fn overlapping_same_root_save_cannot_clear_another_writer_pending_or_failed() {
        use std::sync::mpsc;
        let root = tmp_root("same-root-overlap-red");
        let port = fake_socks5("8.8.8.8\n", "u", "p");
        let line = qualified_probe_fixture(&root, port);
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.via_trade_exit
            && crate::selfcheck::current_qualified_trade_pass(&root),
            "real authenticated loopback trade Check required: {check:?}");
        let old = probe_and_record(&root, &line, &plan, 2_000)
            .expect("real authenticated SOCKS exit observation");
        assert!(old.attributed && old.binding.is_some());
        assert_eq!(load(&root), Some(old.clone()));
        assert!(belongs_to_current_connection(&old, &root),
            "original old JSON must be CURRENT before overlap");

        let (pending_tx, pending_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let b_root = root.clone();
        let b_record = old.clone();
        let b = std::thread::spawn(move || {
            AFTER_PENDING_SAVE_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    pending_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(20))
                        .expect("writer B must be explicitly released");
                }));
            });
            save(&b_root, &b_record)
        });
        pending_rx.recv_timeout(Duration::from_secs(20))
            .expect("writer B must enter actual save after pending mark");
        assert!(exit_write_uncommitted(&root));
        let tmp = root.join(FILE_NAME).with_extension("json.tmp");
        assert!(!tmp.exists(), "writer B is blocked before temp creation");

        // A genuinely commits the old qualified record while B is unfinished.
        save(&root, &old).expect("concurrent writer A must succeed");
        assert_eq!(load(&root), Some(old.clone()));
        assert!(!tmp.exists(), "A consumed its temp on rename");
        let current_while_b_pending = belongs_to_current_connection(&old, &root);

        // B now encounters a REAL std::fs::write OS error, not a mock.
        std::fs::create_dir(&tmp).unwrap();
        release_tx.send(()).unwrap();
        let b_error = b.join().expect("writer B must finish")
            .expect_err("directory-as-temp must cause actual filesystem failure");
        assert!(tmp.is_dir());
        std::fs::remove_dir(&tmp).unwrap();
        assert!(!tmp.exists(), "no temp residue may hide root-marker defect");
        assert_eq!(load(&root), Some(old.clone()), "old JSON remains readable");
        let current_after_b_failed = belongs_to_current_connection(&old, &root);

        save(&root, &old).expect("later real successful save restores CURRENT");
        assert_eq!(load(&root), Some(old.clone()));
        let recovered_current = belongs_to_current_connection(&old, &root);
        eprintln!(
            "SAME_ROOT_OVERLAP_RED: real_B_error={b_error}; in_flight_old_current={current_while_b_pending}; failed_no_tmp_old_current={current_after_b_failed}; recovered_current={recovered_current}"
        );
        assert!(!current_while_b_pending,
            "STALE CURRENT: A cleared B's root pending while writer B remained unfinished");
        assert!(!current_after_b_failed,
            "STALE CURRENT: B failed real IO with no tmp, but old current evidence was accepted");
        assert!(recovered_current, "a later successful save restores qualified CURRENT");
        let _ = std::fs::remove_dir_all(root);
    }

    /// #64 strict TEST-ONLY: two genuine concurrent save() calls use one
    /// PathBuf root but distinct Records. Channel ordering proves the second
    /// write completes before the first rename, without sleep or mocked IO.
    #[test]
    fn same_root_overlapping_saves_commit_only_the_successful_writer_record() {
        use std::sync::mpsc;
        let root = tmp_root("same-root-shared-tmp-collision");
        let port = fake_socks5("8.8.8.8\\n", "u", "p");
        let line = qualified_probe_fixture(&root, port);
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.via_trade_exit
            && crate::selfcheck::current_qualified_trade_pass(&root),
            "real authenticated loopback Check required: {check:?}");
        let record_a = probe_and_record(&root, &line, &plan, 2_000)
            .expect("real authenticated SOCKS exit observation");
        assert!(record_a.attributed && record_a.binding.is_some());
        assert_eq!(load(&root), Some(record_a.clone()));
        assert!(belongs_to_current_connection(&record_a, &root),
            "qualified original disk JSON must be CURRENT before the collision");

        let mut record_b = record_a.clone();
        record_b.at = record_b.at.checked_add(1).unwrap();
        record_b.endpoint = "second-concurrent-writer.test".into();
        assert_ne!(record_a, record_b, "two real saves need distinct records");

        let (a_written_tx, a_written_rx) = mpsc::channel::<()>();
        let (release_a_tx, release_a_rx) = mpsc::channel::<()>();
        let a_root = root.clone();
        let a_rec = record_a.clone();
        let writer_a = std::thread::spawn(move || {
            AFTER_TMP_WRITE_BEFORE_RENAME_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    a_written_tx.send(()).unwrap();
                    release_a_rx.recv_timeout(Duration::from_secs(20))
                        .expect("A must be released for its real rename");
                }));
            });
            save(&a_root, &a_rec)
        });
        a_written_rx.recv_timeout(Duration::from_secs(20))
            .expect("A must finish its actual disk tmp write");
        assert!(exit_write_uncommitted(&root));

        let (b_written_tx, b_written_rx) = mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = mpsc::channel::<()>();
        let b_root = root.clone();
        let b_rec = record_b.clone();
        let writer_b = std::thread::spawn(move || {
            AFTER_TMP_WRITE_BEFORE_RENAME_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    b_written_tx.send(()).unwrap();
                    release_b_rx.recv_timeout(Duration::from_secs(20))
                        .expect("B must be released for its real rename");
                }));
            });
            save(&b_root, &b_rec)
        });
        b_written_rx.recv_timeout(Duration::from_secs(20))
            .expect("B must finish its actual disk tmp write before A renames");

        // This is the REAL filesystem's shared temp content, not a mocked
        // rename failure. On the original source B has overwritten A's tmp.
        let shared_tmp = root.join(FILE_NAME).with_extension("json.tmp");
        let staged: Record = serde_json::from_slice(&std::fs::read(&shared_tmp)
            .expect("A's real shared tmp must exist before its rename")).unwrap();
        assert!(staged == record_a || staged == record_b,
            "intermediate tmp must contain one complete serialized Record");
        assert!(!belongs_to_current_connection(&record_a, &root),
            "overlapping writers must deny CURRENT before either rename");
        eprintln!(
            "SAME_ROOT_SHARED_TMP_STAGE: A={:?}, B={:?}, staged_shared_tmp={:?}",
            record_a.endpoint, record_b.endpoint, staged.endpoint
        );

        release_a_tx.send(()).unwrap();
        let a_result = writer_a.join().expect("A real save must complete");
        // B stays after its genuine tmp write; its rename MUST follow A.
        assert!(!belongs_to_current_connection(&record_a, &root),
            "B is still pending after A's completed rename");
        release_b_tx.send(()).unwrap();
        let b_result = writer_b.join().expect("B real save must complete");
        let persisted = load(&root).expect("a complete successful Record on disk");
        eprintln!(
            "SAME_ROOT_SHARED_TMP_RESULTS: A={a_result:?}; B={b_result:?}; disk={:?}; A_expected={:?}; B_expected={:?}",
            persisted.endpoint, record_a.endpoint, record_b.endpoint
        );
        match (&a_result, &b_result) {
            (Ok(()), Err(_)) => assert_eq!(persisted, record_a,
                "A returned Ok and B Err: disk must be A, not failed writer B"),
            (Err(_), Ok(())) => assert_eq!(persisted, record_b,
                "B returned Ok and A Err: disk must be B"),
            (Ok(()), Ok(())) => assert_eq!(persisted, record_b,
                "B's successful rename strictly follows A's: disk must be B"),
            (Err(a), Err(b)) => panic!(
                "both real saves failed on a writable root: A={a}; B={b}"),
        }
        if b_result.is_err() || a_result.is_err() {
            assert!(!belongs_to_current_connection(&persisted, &root),
                "a failed member of overlapping group keeps CURRENT denied");
            save(&root, &record_a).expect("real later save must restore CURRENT");
            assert_eq!(load(&root), Some(record_a.clone()));
            assert!(belongs_to_current_connection(&record_a, &root));
        } else {
            assert!(belongs_to_current_connection(&persisted, &root),
                "two committed writes restore a genuinely qualified CURRENT");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_failed_save_locked_old_current_exit_must_fail_closed() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = tmp_root("win-locked-old-current");
        let (port, server) = three_sequential_windows_socks_observations();
        let line = qualified_probe_fixture(&root, port);
        // Both responses match legitimate configured public literal servers.
        // A successful latest save would be current-attributed, so testing a
        // new differently observed IP is meaningful.
        std::fs::write(line.engine_config_path(&root), serde_json::json!({
            "outbounds": [
                {"type":"vless","server":"8.8.8.8","server_port":8443},
                {"type":"vless","server":"1.1.1.1","server_port":8443}
            ]
        }).to_string()).unwrap();
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.via_trade_exit && check.status == Some(204),
            "real authenticated auto-Check must pass: {check:?}");
        let old = probe_and_record(&root, &line, &plan, 2_000)
            .expect("original authenticated SOCKS IP must be observed");
        assert_eq!(old.ip, "8.8.8.8");
        assert!(old.attributed && old.binding.is_some());
        assert_eq!(load(&root), Some(old.clone()));
        assert!(belongs_to_current_connection(&old, &root),
            "original disk JSON must genuinely qualify as current");

        let path = root.join(FILE_NAME);
        // Windows FILE_SHARE_READ | FILE_SHARE_WRITE, intentionally omit
        // FILE_SHARE_DELETE (0x4). This is a real OS file-handle share denial,
        // with the old file still readable; no error mocking or directory swap.
        let locked_old = std::fs::OpenOptions::new().read(true)
            .share_mode(0x0000_0001 | 0x0000_0002)
            .open(&path).expect("old current JSON must be opened without DELETE sharing");
        assert_eq!(load(&root), Some(old.clone()));
        assert!(belongs_to_current_connection(&old, &root));

        let latest = probe_and_record(&root, &line, &plan, 2_000)
            .expect("third real authenticated SOCKS HTTP200 must return an IP");
        server.join().expect("all three authentic loopback SOCKS sessions");
        assert_eq!(latest.ip, "1.1.1.1", "newly observed IP must differ from old evidence");
        assert!(!latest.attributed && latest.binding.is_none(),
            "failed save may return observation but never new verified attribution");
        let pending = std::fs::read_to_string(path.with_extension("json.tmp"))
            .expect("actual failed Windows replace must leave the new temp JSON");
        assert!(pending.contains("1.1.1.1"), "new IP must have reached the real disk temp file");
        let original_disk = load(&root)
            .expect("old JSON must remain genuinely readable despite failed replace/delete");
        assert_eq!(original_disk, old, "new save failed and old file was not replaced");
        let delete_err = std::fs::remove_file(&path)
            .expect_err("real Windows file-share violation must refuse removing old JSON");
        eprintln!(
            "WINDOWS_LOCKED_OLD_RED: latest_ip={}, persisted_old_ip={}, delete_error={delete_err}, tmp_exists={}",
            latest.ip, original_disk.ip, path.with_extension("json.tmp").exists(),
        );
        assert!(!belongs_to_current_connection(&original_disk, &root),
            "STALE CURRENT EVIDENCE: newest exit save and clear BOTH failed, but independently read original old attributed JSON still qualifies as CURRENT");
        drop(locked_old);
        let _ = std::fs::remove_dir_all(root);
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

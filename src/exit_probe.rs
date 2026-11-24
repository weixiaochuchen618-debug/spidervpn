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

// Same-process writers are grouped by the actual directory object, not
// its spelling or current location. This is not an interprocess lock,
// crash-proof tombstone or protection against arbitrary file-ID reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ExitDirectoryId(u64, u64);

#[cfg(windows)]
fn open_exit_directory(path: &Path, pin: bool) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    };
    // Registration/lookup permits directory movement. Only the actual IO
    // phase denies delete sharing, so a direct root rename/replacement
    // cannot occur while this matching directory handle is held.
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE
        | if pin { 0 } else { FILE_SHARE_DELETE };
    std::fs::OpenOptions::new().read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .share_mode(share)
        .open(path)
}

#[cfg(not(windows))]
fn open_exit_directory(path: &Path, _pin: bool) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(windows)]
fn exit_directory_id(dir: &std::fs::File) -> std::io::Result<ExitDirectoryId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: dir owns a live handle; info is valid writable SDK storage.
    if unsafe { GetFileInformationByHandle(dir.as_raw_handle() as _, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 || index == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "exit root has no usable native directory identity"));
    }
    Ok(ExitDirectoryId(u64::from(info.dwVolumeSerialNumber), index))
}

#[cfg(unix)]
fn exit_directory_id(dir: &std::fs::File) -> std::io::Result<ExitDirectoryId> {
    use std::os::unix::fs::MetadataExt;
    let md = dir.metadata()?;
    if !md.is_dir() || md.ino() == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "exit root has no usable native directory identity"));
    }
    Ok(ExitDirectoryId(md.dev(), md.ino()))
}

#[cfg(not(any(windows, unix)))]
fn exit_directory_id(_dir: &std::fs::File) -> std::io::Result<ExitDirectoryId> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
        "native exit directory identity unavailable"))
}

fn read_exit_directory_id(path: &Path) -> std::io::Result<ExitDirectoryId> {
    exit_directory_id(&open_exit_directory(path, false)?)
}

fn resolve_exit_directory(root: &Path) -> std::io::Result<(std::path::PathBuf, ExitDirectoryId)> {
    let path = std::fs::canonicalize(root)?;
    let id = read_exit_directory_id(&path)?;
    Ok((path, id))
}

#[derive(PartialEq, Eq, Hash)]
enum ExitWriteKey {
    Directory(ExitDirectoryId),
    // An actual failed identity lookup cannot be attributed to an object.
    // Preserve the old raw-alias failure semantics separately.
    Unresolved(std::path::PathBuf),
}

#[derive(Default)]
struct ExitWriteState {
    active_writers: usize,
    failed_in_group: bool,
}

type ExitWriteMap = std::collections::HashMap<ExitWriteKey, ExitWriteState>;

fn uncommitted_exit_writes() -> &'static std::sync::Mutex<ExitWriteMap> {
    static PENDING: std::sync::OnceLock<std::sync::Mutex<ExitWriteMap>> =
        std::sync::OnceLock::new();
    PENDING.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

// RAII records abandoned/panicking writes as failed. A successful group
// cannot retire another object's active or failed state.
struct ExitWriteGuard {
    root: std::path::PathBuf,
    identity: ExitDirectoryId,
    completed: bool,
    is_clear: bool,
    isolated_tmp: bool,
}

impl ExitWriteGuard {
    fn begin(root: &Path) -> Result<Self, String> {
        Self::begin_operation(root, false)
    }

    fn begin_operation(root: &Path, is_clear: bool) -> Result<Self, String> {
        let (path, identity) = match resolve_exit_directory(root) {
            Ok(resolved) => resolved,
            Err(e) => {
                let mut roots = uncommitted_exit_writes()
                    .lock()
                    .map_err(|_| "exit pending-write lock poisoned".to_string())?;
                let failed = roots.entry(ExitWriteKey::Unresolved(root.to_path_buf()))
                    .or_default();
                failed.failed_in_group = true;
                return Err(format!("exit root identity {}：{e}", root.display()));
            }
        };
        let mut roots = uncommitted_exit_writes()
            .lock()
            .map_err(|_| "exit pending-write lock poisoned".to_string())?;
        let state = roots.entry(ExitWriteKey::Directory(identity)).or_default();
        if state.active_writers == 0 && !is_clear {
            // Only a genuine save can start recovery of an earlier failed
            // group. A clear must preserve its failure even if deletion works.
            state.failed_in_group = false;
        }
        let isolated_tmp = state.active_writers != 0;
        state.active_writers = state.active_writers.checked_add(1)
            .ok_or_else(|| "exit pending writer count overflow".to_string())?;
        Ok(Self {
            root: path, identity, completed: false, is_clear, isolated_tmp,
        })
    }

    fn verify_io_root(&self, path: &Path) -> Result<(), String> {
        let id = read_exit_directory_id(path)
            .map_err(|e| format!("exit IO directory identity {}：{e}", path.display()))?;
        if id != self.identity {
            return Err(format!("exit registered directory replaced: {}", path.display()));
        }
        Ok(())
    }

    fn open_io_root(&self) -> Result<(std::fs::File, std::path::PathBuf), String> {
        // Reopen AFTER registration: the original object may have moved.
        // A same-name replacement is rejected before any temp-file IO.
        let dir = open_exit_directory(&self.root, true)
            .map_err(|e| format!("exit IO directory {}：{e}", self.root.display()))?;
        let id = exit_directory_id(&dir).map_err(|e| e.to_string())?;
        if id != self.identity {
            return Err(format!("exit registered directory replaced: {}", self.root.display()));
        }
        #[cfg(windows)]
        let path = self.root.clone();
        #[cfg(target_os = "linux")]
        let path = {
            use std::os::fd::AsRawFd;
            // File operations stay relative to the opened directory even
            // if its pathname moves during IO. Missing procfs fails closed.
            std::path::PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        };
        #[cfg(not(any(windows, target_os = "linux")))]
        return Err("exit directory IO pinning unavailable on this platform".into());
        #[cfg(any(windows, target_os = "linux"))]
        {
            // Windows still uses the canonical path under a no-delete
            // directory handle. Ancestor replacement/reparse races are
            // not a general guarantee of this bounded direct-root fix.
            self.verify_io_root(&path)?;
            Ok((dir, path))
        }
    }
}

impl Drop for ExitWriteGuard {
    fn drop(&mut self) {
        let Ok(mut roots) = uncommitted_exit_writes().lock() else {
            return; // Poisoned readers fail closed, never authorize CURRENT.
        };
        let key = ExitWriteKey::Directory(self.identity);
        let Some(state) = roots.get_mut(&key) else { return };
        if !self.completed {
            state.failed_in_group = true;
        }
        state.active_writers = state.active_writers.saturating_sub(1);
        if self.completed && state.active_writers == 0 && !state.failed_in_group {
            roots.remove(&key);
            // A clean clear may retire its completed pending group, but
            // absence/deletion is not a successful save of new evidence.
            // Only a genuine save can recover unresolved alias failures.
            if !self.is_clear {
                // Retire only unresolved raw aliases that NOW resolve to
                // this committed directory object. Never retire a different
                // object's ordinary failed write at the same pathname.
                roots.retain(|key, other| {
                    let ExitWriteKey::Unresolved(raw) = key else { return true };
                    other.active_writers != 0
                        || !other.failed_in_group
                        || resolve_exit_directory(raw).ok().map(|(_, id)| id) != Some(self.identity)
                });
            }
        }
    }
}

fn exit_write_uncommitted(root: &Path) -> bool {
    if root.join(FILE_NAME).with_extension("json.tmp").exists() {
        return true;
    }
    let Ok((path, identity)) = resolve_exit_directory(root) else { return true };
    uncommitted_exit_writes()
        .lock()
        .map(|roots| roots.contains_key(&ExitWriteKey::Directory(identity))
            || roots.contains_key(&ExitWriteKey::Unresolved(root.to_path_buf()))
            || roots.contains_key(&ExitWriteKey::Unresolved(path)))
        .unwrap_or(true)
}

/// 把记录读回来。坏文件当作没有：宁可显示「尚未核验」，也不要显示一个读不懂的东西。
pub fn load(root: &Path) -> Option<Record> {
    let text = std::fs::read_to_string(root.join(FILE_NAME)).ok()?;
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

/// 写记录。与自检结论同样先写临时文件再替换：断在半路会留下半截 JSON。
pub fn save(root: &Path, rec: &Record) -> Result<(), String> {
    save_record(root, rec, false)
}

fn save_record(root: &Path, rec: &Record, invalidate_on_failure: bool) -> Result<(), String> {
    // Deny current attribution from the beginning of a write through its
    // commit. If either temp creation or rename fails, keep the guard until
    // a later genuinely successful save; a best-effort clear() is not proof.
    let mut pending = ExitWriteGuard::begin(root)?;
    #[cfg(test)]
    tests::after_pending_save_test_hook();
    let result = (|| -> Result<(), String> {
        // Pin only during actual IO, not during the after-registration gate.
        // An identity mismatch returns before staging or cleanup.
        let (_directory, io_root) = pending.open_io_root()?;
        let path = io_root.join(FILE_NAME);
        let written = (|| -> Result<(), String> {
            let text = serde_json::to_string_pretty(rec).map_err(|e| e.to_string())?;
            // Concurrent same-root writers may overlap through rename, but must
            // never write one another's staged bytes. Keep the legacy fixed tmp
            // for the first writer and old single-writer Windows failure tests.
            let tmp = if pending.isolated_tmp {
                static NEXT_TMP_ID: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let id = NEXT_TMP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                path.with_extension(format!("json.tmp.{}-{id}", std::process::id()))
            } else {
                path.with_extension("json.tmp")
            };
            pending.verify_io_root(&io_root)?;
            if pending.isolated_tmp {
                // No stale filename may be silently overwritten (even if a PID
                // and sequence repeat after a process restart). An existing
                // file must fail closed instead of stealing another writer's IO.
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
                    .open(&tmp).map_err(|e| format!("{}：{e}", tmp.display()))?;
                let written = file.write_all(text.as_bytes());
                drop(file); // Windows rename must not race our own open handle.
                if let Err(e) = written {
                    if pending.verify_io_root(&io_root).is_ok() {
                        let _ = std::fs::remove_file(&tmp);
                    }
                    return Err(format!("{}：{e}", tmp.display()));
                }
            } else {
                std::fs::write(&tmp, text).map_err(|e| format!("{}：{e}", tmp.display()))?;
            }
            #[cfg(test)]
            tests::after_tmp_write_before_rename_test_hook();
            pending.verify_io_root(&io_root)?;
            let renamed = std::fs::rename(&tmp, &path)
                .map_err(|e| format!("{}：{e}", path.display()));
            if renamed.is_err() && pending.isolated_tmp
                && pending.verify_io_root(&io_root).is_ok() {
                // On a failed overlapping rename keep the #62 failure group
                // pending, but best-effort remove this writer's orphaned tmp.
                let _ = std::fs::remove_file(&tmp);
            }
            renamed
        })();
        // Preserve the existing producer's best-effort invalidation for
        // ordinary write failures, but only inside the matching IO root.
        // Failure to open/verify the registered object never reaches here.
        if written.is_err() && invalidate_on_failure
            && pending.verify_io_root(&io_root).is_ok() {
            let _ = std::fs::remove_file(&path);
        }
        written
    })();
    if result.is_ok() {
        pending.completed = true;
    }
    result
}

/// 清掉记录（断开、连接失败、换线路都算「这条证据过期了」）。
pub fn clear(root: &Path) {
    // A refused deletion may leave readable, still-bound history. Register
    // invalidation before IO, using the same native object group as save.
    // Failed lookup records an unresolved alias; failed reopen/verification
    // marks the registered object failed through the guard, without deleting
    // anything at an unchecked replacement path.
    let Ok(mut pending) = ExitWriteGuard::begin_operation(root, true) else { return };
    let Ok((_directory, io_root)) = pending.open_io_root() else { return };
    if pending.verify_io_root(&io_root).is_err() {
        return;
    }
    match std::fs::remove_file(io_root.join(FILE_NAME)) {
        Ok(()) => pending.completed = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => pending.completed = true,
        // Guard drop retains the failed marker until genuine save recovery.
        Err(_) => {}
    }
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
    if let Err(e) = save_record(root, &rec, true) {
        // Never clear a mutable caller pathname after a failed save.
        // Any ordinary best-effort invalidation is limited to the verified
        // IO directory inside save_record; identity rejection does no IO.
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
        let port = fake_socks5("8.8.8.8\n", "u", "p");
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

    /// #66 TEST-ONLY: distinct PathBuf spellings of one proven physical root
    /// must share temp ownership and pending/failure-group authority.
    /// Both writers use the real production save() and real filesystem IO.
    #[test]
    fn physical_root_alias_overlapping_saves_preserve_record_ownership_and_current_denial() {
        use std::sync::mpsc;
        let root = tmp_root("physical-root-alias-red");
        let child = root.join("alias-child");
        std::fs::create_dir(&child).expect("create real alias-child first");
        let alias = child.join("..");
        assert_ne!(root, alias, "PathBuf keys must truly differ (not root/.)");
        assert_eq!(
            std::fs::canonicalize(&root).expect("original physical directory"),
            std::fs::canonicalize(&alias).expect("alias physical directory"),
            "different PathBuf spellings must resolve to one real directory",
        );
        assert!(alias.is_dir(), "Windows must be able to traverse real child/..");

        let port = fake_socks5("8.8.8.8\n", "u", "p");
        let line = qualified_probe_fixture(&root, port);
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.via_trade_exit
            && crate::selfcheck::current_qualified_trade_pass(&root),
            "real authenticated local SOCKS qualified Check required: {check:?}");
        let record_a = probe_and_record(&root, &line, &plan, 2_000)
            .expect("real authenticated SOCKS observation");
        assert!(record_a.attributed && record_a.binding.is_some());
        assert_eq!(load(&root), Some(record_a.clone()));
        assert_eq!(load(&alias), Some(record_a.clone()),
            "the alias must read the same genuine old physical JSON");
        assert_eq!(
            std::fs::canonicalize(root.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(alias.join(FILE_NAME)).unwrap(),
            "actual JSON files must be one physical file, not duplicated copies",
        );
        assert_eq!(
            std::fs::read(root.join(FILE_NAME)).unwrap(),
            std::fs::read(alias.join(FILE_NAME)).unwrap(),
            "Windows actual file reads must agree across both paths",
        );
        assert!(belongs_to_current_connection(&record_a, &root),
            "old normal path genuinely CURRENT before any overlap");
        assert!(belongs_to_current_connection(&record_a, &alias),
            "old alias path genuinely CURRENT before any overlap");

        let mut record_b = record_a.clone();
        record_b.at = record_b.at.checked_add(1).unwrap();
        record_b.endpoint = "physical-alias-writer-b.test".into();
        assert_ne!(record_a, record_b);

        let (a_written_tx, a_written_rx) = mpsc::channel::<()>();
        let (release_a_tx, release_a_rx) = mpsc::channel::<()>();
        let a_root = root.clone();
        let a_rec = record_a.clone();
        let writer_a = std::thread::spawn(move || {
            AFTER_TMP_WRITE_BEFORE_RENAME_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    a_written_tx.send(()).unwrap();
                    release_a_rx.recv_timeout(Duration::from_secs(20))
                        .expect("A must be explicitly released for actual rename");
                }));
            });
            save(&a_root, &a_rec)
        });
        a_written_rx.recv_timeout(Duration::from_secs(20))
            .expect("A must complete real tmp write before B begins");
        assert!(exit_write_uncommitted(&root));
        assert!(root.join(FILE_NAME).with_extension("json.tmp").is_file());

        let (b_written_tx, b_written_rx) = mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = mpsc::channel::<()>();
        let b_alias = alias.clone();
        let b_rec = record_b.clone();
        let writer_b = std::thread::spawn(move || {
            AFTER_TMP_WRITE_BEFORE_RENAME_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    b_written_tx.send(()).unwrap();
                    release_b_rx.recv_timeout(Duration::from_secs(20))
                        .expect("B must be explicitly released for actual rename");
                }));
            });
            save(&b_alias, &b_rec)
        });
        b_written_rx.recv_timeout(Duration::from_secs(20))
            .expect("B must complete genuine tmp write before A renames");

        let a_tmp = root.join(FILE_NAME).with_extension("json.tmp");
        let b_fixed_tmp = alias.join(FILE_NAME).with_extension("json.tmp");
        assert_eq!(
            std::fs::canonicalize(&a_tmp).expect("A's on-disk fixed temp"),
            std::fs::canonicalize(&b_fixed_tmp).expect("same file through B alias"),
            "two paths must resolve to one physical fixed-temp file",
        );
        let staged_a: Record = serde_json::from_slice(&std::fs::read(&a_tmp).unwrap()).unwrap();
        let staged_b: Record = serde_json::from_slice(&std::fs::read(&b_fixed_tmp).unwrap()).unwrap();
        assert_eq!(staged_a, staged_b, "both real file paths must see the same staged bytes");
        assert!(staged_a == record_a || staged_a == record_b,
            "one complete record must be staged, not torn JSON");
        let a_pending_before = belongs_to_current_connection(&record_a, &root);
        let b_pending_before = belongs_to_current_connection(&record_a, &alias);
        eprintln!(
            "ROOT_ALIAS_STAGE: raw_path_unequal={}; physical_root_equal=true; fixed_tmp_same=true; staged={:?}; current_root={a_pending_before}; current_alias={b_pending_before}",
            root != alias, staged_a.endpoint
        );

        release_a_tx.send(()).unwrap();
        let a_result = writer_a.join().expect("A real save must finish");
        let current_root_while_b_pending = belongs_to_current_connection(&record_a, &root);
        let current_alias_while_b_pending = belongs_to_current_connection(&record_a, &alias);
        release_b_tx.send(()).unwrap();
        let b_result = writer_b.join().expect("B real save must finish");
        let persisted = load(&root).expect("real durable full JSON");
        assert_eq!(load(&alias), Some(persisted.clone()),
            "actual disk JSON read must agree across aliases after rename");
        let current_root_after = belongs_to_current_connection(&persisted, &root);
        let current_alias_after = belongs_to_current_connection(&persisted, &alias);
        eprintln!(
            "ROOT_ALIAS_RESULTS: A={a_result:?}; B={b_result:?}; disk={:?}; A_expected={:?}; B_expected={:?}; root_while_B={current_root_while_b_pending}; alias_while_B={current_alias_while_b_pending}; root_after={current_root_after}; alias_after={current_alias_after}",
            persisted.endpoint, record_a.endpoint, record_b.endpoint
        );
        match (&a_result, &b_result) {
            (Ok(()), Err(_)) => assert_eq!(persisted, record_a,
                "A returned Ok and alias B Err: disk must be A, never failed B"),
            (Err(_), Ok(())) => assert_eq!(persisted, record_b,
                "alias B returned Ok and A Err: disk must be B"),
            (Ok(()), Ok(())) => assert_eq!(persisted, record_b,
                "B's actual rename follows A's: disk must be B"),
            (Err(a), Err(b)) => panic!(
                "both saves failed despite verified writable physical directory: A={a}; B={b}"),
        }
        assert!(!a_pending_before && !b_pending_before,
            "both path aliases must deny CURRENT during overlapping real writes");
        assert!(!current_root_while_b_pending && !current_alias_while_b_pending,
            "A success must not promote either alias while B is still pending");
        if a_result.is_err() || b_result.is_err() {
            assert!(!current_root_after && !current_alias_after,
                "failed overlapping group must deny CURRENT through both aliases");
            save(&root, &record_a).expect("later real successful save restores current");
            assert_eq!(load(&alias), Some(record_a.clone()));
            assert!(belongs_to_current_connection(&record_a, &root));
            assert!(belongs_to_current_connection(&record_a, &alias));
        } else {
            assert!(current_root_after && current_alias_after,
                "both successful complete saves restore CURRENT for each alias");
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

    /// #68 TEST-ONLY RED: a real failed canonicalization under alias A must
    /// not permanently veto a later proven successful save through B.
    /// There are no mocks, sleeps, direct pending-map edits or production hooks.
    #[test]
    fn recovered_physical_alias_after_real_canonicalization_failure_accepts_new_committed_record() {
        // Test-only real directory aliases; NEVER manipulate writer-state maps.
        // The junction and its target are siblings inside one isolated sandbox,
        // so removing the link cannot recursively delete the target directory.
        fn create_alias(link: &Path, target: &Path) {
            #[cfg(windows)]
            {
                let output = std::process::Command::new("cmd.exe")
                    .args(["/C", "mklink", "/J"])
                    .arg(link).arg(target).output()
                    .expect("execute native Windows mklink /J");
                assert!(output.status.success(),
                    "native junction creation failed: status={}; stdout={}; stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr));
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, link)
                .expect("create real on-disk directory symlink for Unix testing");
        }
        fn remove_alias(link: &Path) {
            #[cfg(windows)]
            {
                // Windows rmdir <junction> WITHOUT /S removes only the link.
                let output = std::process::Command::new("cmd.exe")
                    .args(["/C", "rmdir"]).arg(link).output()
                    .expect("execute native Windows junction-only rmdir");
                assert!(output.status.success(),
                    "junction-only rmdir failed: status={}; stdout={}; stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr));
            }
            #[cfg(unix)]
            std::fs::remove_file(link)
                .expect("unlink directory symlink without touching target");
        }

        let sandbox = tmp_root("canonicalization-alias-cross-recovery-red");
        let root = sandbox.join("data");
        std::fs::create_dir(&root).expect("real qualified data directory");
        let child = sandbox.join("alias-junction");
        assert!(!child.exists(), "junction must not preexist");
        create_alias(&child, &root);
        let alias_a = child.clone();
        let alias_b = root.clone();
        assert_ne!(alias_a, alias_b, "junction path must differ from physical target");
        let physical = std::fs::canonicalize(&alias_b).expect("existing B root");
        assert_eq!(std::fs::canonicalize(&alias_a).unwrap(), physical);
        assert!(alias_a.is_dir() && alias_b.is_dir());

        // Actual qualified, authenticated loopback SOCKS Check, not a forged
        // binding or a mocked successful save.
        let port = fake_socks5("8.8.8.8\n", "u", "p");
        let line = qualified_probe_fixture(&root, port);
        let plan = qualified_plan(port);
        let check = crate::selfcheck::check_and_record(&root, &plan, 2_000);
        assert!(check.ok && check.via_trade_exit
            && crate::selfcheck::current_qualified_trade_pass(&root),
            "original actual authenticated Check must succeed: {check:?}");
        let old = probe_and_record(&root, &line, &plan, 2_000)
            .expect("original real authenticated SOCKS exit observation");
        assert!(old.attributed && old.binding.is_some());
        assert_eq!(load(&alias_b), Some(old.clone()));
        assert_eq!(load(&alias_a), Some(old.clone()));
        assert_eq!(
            std::fs::canonicalize(alias_a.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(alias_b.join(FILE_NAME)).unwrap(),
            "the historical disk record must be one real physical file"
        );
        assert!(belongs_to_current_connection(&old, &alias_a));
        assert!(belongs_to_current_connection(&old, &alias_b));

        // Remove ONLY the Windows junction (no /S and no recursion), never
        // its physical target. The real OS must now refuse A, while B works.
        remove_alias(&child);
        assert!(std::fs::symlink_metadata(&child).is_err(),
            "junction itself must actually be gone");
        assert!(alias_b.is_dir() && !child.exists());
        let canonical_error = std::fs::canonicalize(&alias_a)
            .expect_err("real OS must refuse removed junction alias");
        assert!(std::fs::canonicalize(&alias_b).is_ok());
        let attempted = save(&alias_a, &old);
        assert!(attempted.is_err(),
            "actual save through unresolved A must fail, got {attempted:?}");
        assert_eq!(load(&alias_b), Some(old.clone()),
            "failed identity lookup must not overwrite original disk JSON");
        assert!(!belongs_to_current_connection(&old, &alias_a),
            "while identity resolution is broken CURRENT must fail closed");
        assert!(!alias_b.join(FILE_NAME).with_extension("json.tmp").exists(),
            "no temp file should be created before identity failure");

        // Restore the real junction. A again resolves to the physical B root;
        // no recovered CURRENT is allowed before a genuine new B commit.
        create_alias(&child, &root);
        assert_eq!(std::fs::canonicalize(&alias_a).unwrap(), physical);
        assert_eq!(std::fs::canonicalize(&alias_b).unwrap(), physical);
        assert_eq!(load(&alias_a), Some(old.clone()));
        assert!(!belongs_to_current_connection(&old, &alias_a),
            "restoring a path alone cannot clear an unresolved failed save");

        // This new record preserves the actual observed IP, line, session
        // and original binding; only its timestamp identifies a new commit.
        // A real save(B) must be the recovery boundary, not marker deletion.
        let mut committed = old.clone();
        committed.at = old.at.checked_add(1).expect("distinct new record time");
        assert_ne!(committed, old);
        assert!(original_exit_binding_still_current(&committed, &alias_b),
            "current original session/line binding required before new commit");
        save(&alias_b, &committed).expect("real B writer must complete on writable root");
        assert_eq!(load(&alias_b), Some(committed.clone()));
        assert_eq!(load(&alias_a), Some(committed.clone()),
            "both spellings must read the exact newly committed disk JSON");
        assert_eq!(
            std::fs::canonicalize(alias_a.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(alias_b.join(FILE_NAME)).unwrap(),
            "new JSON remains a single physical file"
        );
        assert!(!alias_b.join(FILE_NAME).with_extension("json.tmp").exists());
        let b_current = belongs_to_current_connection(&committed, &alias_b);
        let a_current = belongs_to_current_connection(&committed, &alias_a);
        eprintln!(
            "CANONICAL_ALIAS_RECOVERY: raw_unequal={}; physical_equal=true; actual_canon_err={canonical_error}; actual_save_a={attempted:?}; committed_new_at={}; disk_at={}; A_current={a_current}; B_current={b_current}; binding_valid={}",
            alias_a != alias_b, committed.at, load(&alias_b).unwrap().at,
            original_exit_binding_still_current(&committed, &alias_b)
        );
        assert!(b_current, "B positive CURRENT control after real successful save");
        assert!(a_current,
            "A must recover only after B's completed save of a valid record to the same physical root");

        // Reopening CURRENT must never bypass live session/engine binding.
        std::fs::write(root.join("runtime-engine.json"), "{}")
            .expect("change real engine binding after successful recovery");
        assert!(!belongs_to_current_connection(&committed, &alias_b),
            "stale line/engine binding must revoke B CURRENT");
        assert!(!belongs_to_current_connection(&committed, &alias_a),
            "stale line/engine binding must revoke A CURRENT");
        remove_alias(&child); // link-only removal before sandbox cleanup.
        let _ = std::fs::remove_dir_all(sandbox);
    }

    /// #70 TEST-ONLY: a successful B commit must not retire a raw A
    /// identity-failure marker when A now resolves to a different root C.
    /// This is an ordered real-filesystem regression, not a TOCTOU proof.
    #[test]
    fn retargeted_junction_to_distinct_root_keeps_failed_alias_dirty_after_b_commit() {
        fn create_alias(link: &Path, target: &Path) {
            #[cfg(windows)]
            {
                let output = std::process::Command::new("cmd.exe")
                    .args(["/C", "mklink", "/J"])
                    .arg(link).arg(target).output()
                    .expect("execute real Windows mklink /J");
                assert!(output.status.success(),
                    "junction creation failed: status={}; stdout={}; stderr={}",
                    output.status, String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr));
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, link)
                .expect("create real Unix directory alias");
        }

        fn remove_alias(link: &Path) {
            #[cfg(windows)]
            {
                // rmdir without /S removes only the directory junction.
                let output = std::process::Command::new("cmd.exe")
                    .args(["/C", "rmdir"]).arg(link).output()
                    .expect("execute native junction-only rmdir");
                assert!(output.status.success(),
                    "junction-only removal failed: status={}; stdout={}; stderr={}",
                    output.status, String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr));
            }
            #[cfg(unix)]
            std::fs::remove_file(link).expect("unlink alias only");
            assert!(std::fs::symlink_metadata(link).is_err(),
                "the alias itself must be gone");
        }

        let sandbox = tmp_root("cross-root-retarget-dirty-marker");
        let b = sandbox.join("data-b");
        let c = sandbox.join("data-c");
        let a = sandbox.join("alias-a");
        std::fs::create_dir(&b).expect("create actual physical B");
        std::fs::create_dir(&c).expect("create actual physical C");
        assert_ne!(a, b);
        assert_ne!(a, c);
        let physical_b = std::fs::canonicalize(&b).unwrap();
        let physical_c = std::fs::canonicalize(&c).unwrap();
        assert_ne!(physical_b, physical_c, "B and C must be different physical roots");

        // Independently qualified authenticated SOCKS observations in both
        // roots. C is deliberately otherwise CURRENT so the negative test
        // cannot pass merely because its JSON or original binding is invalid.
        let port_b = fake_socks5("8.8.8.8\n", "u", "p");
        let port_c = fake_socks5("8.8.8.8\n", "u", "p");
        assert_ne!(port_b, port_c, "distinct live probe bindings");
        let line_b = qualified_probe_fixture(&b, port_b);
        let line_c = qualified_probe_fixture(&c, port_c);
        let plan_b = qualified_plan(port_b);
        let plan_c = qualified_plan(port_c);
        let check_b = crate::selfcheck::check_and_record(&b, &plan_b, 2_000);
        let check_c = crate::selfcheck::check_and_record(&c, &plan_c, 2_000);
        assert!(check_b.ok && check_b.via_trade_exit
            && crate::selfcheck::current_qualified_trade_pass(&b), "{check_b:?}");
        assert!(check_c.ok && check_c.via_trade_exit
            && crate::selfcheck::current_qualified_trade_pass(&c), "{check_c:?}");
        let old_b = probe_and_record(&b, &line_b, &plan_b, 2_000)
            .expect("actual authenticated B observation");
        let old_c = probe_and_record(&c, &line_c, &plan_c, 2_000)
            .expect("actual authenticated C observation");
        assert!(old_b.attributed && old_b.binding.is_some());
        assert!(old_c.attributed && old_c.binding.is_some());
        assert_ne!(old_b.binding, old_c.binding, "independent engine/probe bindings");
        assert!(belongs_to_current_connection(&old_b, &b));
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(!original_exit_binding_still_current(&old_b, &c));
        assert!(!original_exit_binding_still_current(&old_c, &b));
        assert_eq!(load(&b), Some(old_b.clone()));
        assert_eq!(load(&c), Some(old_c.clone()));
        let c_disk = std::fs::read(c.join(FILE_NAME)).unwrap();
        assert_ne!(std::fs::canonicalize(b.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(c.join(FILE_NAME)).unwrap());

        create_alias(&a, &b);
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_b);
        assert_eq!(std::fs::canonicalize(a.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(b.join(FILE_NAME)).unwrap());
        assert_eq!(load(&a), Some(old_b.clone()));
        assert!(belongs_to_current_connection(&old_b, &a),
            "A starts genuinely CURRENT through B");

        remove_alias(&a);
        let canonical_error = std::fs::canonicalize(&a)
            .expect_err("removed junction must cause a real OS identity error");
        assert_eq!(std::fs::canonicalize(&b).unwrap(), physical_b);
        assert_eq!(std::fs::canonicalize(&c).unwrap(), physical_c);
        let failed = save(&a, &old_b);
        assert!(failed.is_err(), "actual save through missing A must fail");
        assert!(exit_write_uncommitted(&a));
        assert!(!belongs_to_current_connection(&old_b, &a));
        assert_eq!(load(&b), Some(old_b.clone()));
        assert_eq!(load(&c), Some(old_c.clone()));
        assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_disk);
        assert!(!b.join(FILE_NAME).with_extension("json.tmp").exists());
        assert!(!c.join(FILE_NAME).with_extension("json.tmp").exists());

        // The same raw alias now resolves to C, NOT the root B which will
        // commit. C's real current record must not become CURRENT through A
        // merely because its original binding and historical JSON are valid.
        create_alias(&a, &c);
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
        assert_ne!(std::fs::canonicalize(&a).unwrap(), physical_b);
        assert_eq!(std::fs::canonicalize(a.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(c.join(FILE_NAME)).unwrap());
        assert_eq!(load(&a), Some(old_c.clone()));
        assert!(original_exit_binding_still_current(&old_c, &a),
            "retargeted C binding must itself be valid, isolating the dirty guard");
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(exit_write_uncommitted(&a), "restoring another target must not retire raw A");
        assert!(!belongs_to_current_connection(&old_c, &a));
        assert!(!a.join(FILE_NAME).with_extension("json.tmp").exists());

        let mut committed_b = old_b.clone();
        committed_b.at = old_b.at.checked_add(1).expect("distinct new B record");
        assert_ne!(committed_b, old_b);
        assert!(original_exit_binding_still_current(&committed_b, &b));
        save(&b, &committed_b).expect("genuine successful B commit");
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
        assert_eq!(std::fs::canonicalize(&b).unwrap(), physical_b);
        assert_eq!(load(&b), Some(committed_b.clone()));
        assert_eq!(load(&a), Some(old_c.clone()));
        assert_eq!(load(&c), Some(old_c.clone()));
        assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_disk);
        assert!(!b.join(FILE_NAME).with_extension("json.tmp").exists());
        assert!(!a.join(FILE_NAME).with_extension("json.tmp").exists());
        let b_current = belongs_to_current_connection(&committed_b, &b);
        let c_current = belongs_to_current_connection(&old_c, &c);
        let a_binding_valid = original_exit_binding_still_current(&old_c, &a);
        let a_dirty = exit_write_uncommitted(&a);
        let a_current = belongs_to_current_connection(&old_c, &a);
        eprintln!(
            "CROSS_ROOT_RETARGET: raw_A={a:?}; physical_B={physical_b:?}; physical_C={physical_c:?}; canonical_err={canonical_error}; save_A={failed:?}; B_disk_at={}; C_disk_at={}; B_current={b_current}; C_current={c_current}; A_binding_valid={a_binding_valid}; A_dirty={a_dirty}; A_current={a_current}",
            load(&b).unwrap().at, load(&c).unwrap().at
        );
        assert!(b_current && c_current && a_binding_valid,
            "B success and C's independent live binding must remain valid");
        assert!(a_dirty, "successful B commit must not clear raw A dirty at different physical C");
        assert!(!a_current, "retargeted A must fail closed despite otherwise valid C evidence");
        assert!(!belongs_to_current_connection(&committed_b, &a),
            "B record must not authorize CURRENT through physical C");

        // Retargeting back by itself cannot repair the old failed write.
        // Only a new successful same-physical-root B group may recover A.
        remove_alias(&a);
        create_alias(&a, &b);
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_b);
        assert_eq!(load(&a), Some(committed_b.clone()));
        assert!(original_exit_binding_still_current(&committed_b, &a));
        assert!(exit_write_uncommitted(&a));
        assert!(!belongs_to_current_connection(&committed_b, &a));
        let mut recovered_b = committed_b.clone();
        recovered_b.at = committed_b.at.checked_add(1).unwrap();
        save(&b, &recovered_b).expect("new same-root B commit to recover A");
        assert_eq!(load(&a), Some(recovered_b.clone()));
        assert_eq!(load(&b), Some(recovered_b.clone()));
        assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_disk);
        assert!(!exit_write_uncommitted(&a));
        assert!(belongs_to_current_connection(&recovered_b, &b));
        assert!(belongs_to_current_connection(&recovered_b, &a));
        assert!(belongs_to_current_connection(&old_c, &c));

        std::fs::write(b.join("runtime-engine.json"), "{}")
            .expect("invalidate actual B engine binding");
        assert!(!belongs_to_current_connection(&recovered_b, &a));
        assert!(!belongs_to_current_connection(&recovered_b, &b));
        assert!(belongs_to_current_connection(&old_c, &c),
            "B binding invalidation must not affect independent C");
        remove_alias(&a);
        std::fs::remove_dir_all(&sandbox).expect("clean isolated sandbox after link removal");
    }

    /// #72 TEST-ONLY: a real in-flight save must never write into a different
    /// physical root after the existing registration-to-IO gate is released.
    #[test]
    fn inflight_save_retargeted_junction_never_commits_to_unregistered_root() {
        use std::sync::mpsc;

        fn link_dir(link: &Path, target: &Path) {
            #[cfg(windows)]
            {
                let out = std::process::Command::new("cmd.exe")
                    .args(["/C", "mklink", "/J"]).arg(link).arg(target).output()
                    .expect("execute real junction creation");
                assert!(out.status.success(), "fixture mklink failed: {out:?}");
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, link).expect("create real directory symlink");
        }

        fn unlink_dir(link: &Path) -> std::io::Result<()> {
            #[cfg(windows)]
            {
                // No /S: remove ONLY the disposable junction, never its target.
                let out = std::process::Command::new("cmd.exe")
                    .args(["/C", "rmdir"]).arg(link).output()?;
                if !out.status.success() {
                    return Err(std::io::Error::other(format!("fixture rmdir failed: {out:?}")));
                }
            }
            #[cfg(unix)]
            std::fs::remove_file(link)?;
            Ok(())
        }

        // Cleanup on both normal completion and assertion unwind. Never
        // recurse into the sandbox until the alias itself is confirmed absent.
        struct Sandbox {
            root: std::path::PathBuf,
            alias: std::path::PathBuf,
        }
        impl Sandbox {
            fn cleanup(&self) -> std::io::Result<()> {
                match std::fs::symlink_metadata(&self.alias) {
                    Ok(_) => unlink_dir(&self.alias)?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                    Err(e) => return Err(e),
                }
                match std::fs::symlink_metadata(&self.alias) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                    Err(e) => return Err(e),
                    Ok(_) => return Err(std::io::Error::other("alias still exists; refusing recursive cleanup")),
                }
                match std::fs::remove_dir_all(&self.root) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    result => result,
                }
            }
        }
        impl Drop for Sandbox {
            fn drop(&mut self) {
                if let Err(e) = self.cleanup() {
                    eprintln!("INFLIGHT_RETARGET fixture cleanup refused or failed: {e}");
                }
            }
        }

        let root = tmp_root("inflight-alias-retarget");
        let a = root.join("alias-a");
        let cleanup = Sandbox { root: root.clone(), alias: a.clone() };
        let b = root.join("data-b");
        let c = root.join("data-c");
        std::fs::create_dir(&b).unwrap();
        std::fs::create_dir(&c).unwrap();
        let physical_b = std::fs::canonicalize(&b).unwrap();
        let physical_c = std::fs::canonicalize(&c).unwrap();
        assert_ne!(physical_b, physical_c, "fixture must have distinct physical roots");
        assert_ne!(a, b);
        assert_ne!(a, c);

        // Both roots have independent genuine qualified loopback Check and
        // observed records, not fabricated bindings or missing-data negatives.
        let observe = |dir: &Path| {
            let port = fake_socks5("8.8.8.8\n", "u", "p");
            let line = qualified_probe_fixture(dir, port);
            let plan = qualified_plan(port);
            let check = crate::selfcheck::check_and_record(dir, &plan, 2_000);
            assert!(check.ok && check.via_trade_exit
                && crate::selfcheck::current_qualified_trade_pass(dir), "{check:?}");
            let record = probe_and_record(dir, &line, &plan, 2_000)
                .expect("actual authenticated exit observation");
            assert!(record.attributed && record.binding.is_some());
            assert_eq!(load(dir), Some(record.clone()));
            assert!(belongs_to_current_connection(&record, dir));
            record
        };
        let old_b = observe(&b);
        let old_c = observe(&c);
        assert_ne!(old_b.binding, old_c.binding);
        assert!(!original_exit_binding_still_current(&old_b, &c));
        assert!(!original_exit_binding_still_current(&old_c, &b));
        let b_before = std::fs::read(b.join(FILE_NAME)).unwrap();
        let c_before = std::fs::read(c.join(FILE_NAME)).unwrap();
        assert_ne!(std::fs::canonicalize(b.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(c.join(FILE_NAME)).unwrap());

        link_dir(&a, &b);
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_b);
        assert_eq!(std::fs::canonicalize(a.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(b.join(FILE_NAME)).unwrap());
        assert_eq!(load(&a), Some(old_b.clone()));
        assert!(belongs_to_current_connection(&old_b, &a));

        let mut proposed = old_b.clone();
        proposed.at = proposed.at.checked_add(1).unwrap();
        assert_ne!(proposed, old_b);
        assert_ne!(proposed, old_c);
        assert!(original_exit_binding_still_current(&proposed, &a));
        let tmp_b = b.join(FILE_NAME).with_extension("json.tmp");
        let tmp_c = c.join(FILE_NAME).with_extension("json.tmp");

        let (pending_tx, pending_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let writer_path = a.clone();
        let writer_record = proposed.clone();
        let writer = std::thread::spawn(move || {
            AFTER_PENDING_SAVE_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    pending_tx.send(()).expect("actual registration gate reached");
                    release_rx.recv_timeout(Duration::from_secs(30))
                        .expect("controller must release actual save");
                }));
            });
            save(&writer_path, &writer_record)
        });

        // Catch any setup/assertion panic in the controller so the real save
        // always receives a release and is joined BEFORE filesystem cleanup.
        let stage = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pending_rx.recv_timeout(Duration::from_secs(30))
                .expect("actual save must register before identity change");
            assert!(exit_write_uncommitted(&b));
            assert!(exit_write_uncommitted(&a));
            assert!(!belongs_to_current_connection(&old_b, &b));
            assert!(!belongs_to_current_connection(&old_b, &a));
            assert!(belongs_to_current_connection(&old_c, &c));
            assert!(!tmp_b.exists() && !tmp_c.exists());
            assert_eq!(std::fs::read(b.join(FILE_NAME)).unwrap(), b_before);
            assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);

            unlink_dir(&a).expect("remove only real in-flight junction");
            let missing = std::fs::canonicalize(&a)
                .expect_err("fixture: actual removed alias must not resolve");
            assert_eq!(std::fs::canonicalize(&b).unwrap(), physical_b);
            assert_eq!(std::fs::canonicalize(&c).unwrap(), physical_c);
            link_dir(&a, &c);
            assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
            assert_ne!(std::fs::canonicalize(&a).unwrap(), physical_b);
            assert_eq!(std::fs::canonicalize(a.join(FILE_NAME)).unwrap(),
                std::fs::canonicalize(c.join(FILE_NAME)).unwrap());
            assert_eq!(load(&a), Some(old_c.clone()));
            assert!(original_exit_binding_still_current(&old_c, &a));
            assert!(!belongs_to_current_connection(&proposed, &a),
                "B binding cannot authorize a record through physical C");
            assert!(exit_write_uncommitted(&b));
            assert!(!belongs_to_current_connection(&old_b, &b));
            assert!(belongs_to_current_connection(&old_c, &c));
            assert!(!tmp_b.exists() && !tmp_c.exists());
            assert_eq!(std::fs::read(b.join(FILE_NAME)).unwrap(), b_before);
            assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);
            eprintln!("INFLIGHT_RETARGET_STAGE: B={physical_b:?}; C={physical_c:?}; removed_err={missing}; A_now_C=true; B_pending=true; B_current=false; C_current=true; before_IO=true");
        }));
        let released = release_tx.send(());
        let joined = writer.join();
        if let Err(panic) = stage {
            // Gate has been released (or already terminated) and joined.
            std::panic::resume_unwind(panic);
        }
        released.expect("writer must receive deterministic release");
        let result = joined.expect("actual save must finish without panic");

        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
        let disk_b = load(&b);
        let disk_c = load(&c);
        let b_bytes = std::fs::read(b.join(FILE_NAME)).unwrap();
        let c_bytes = std::fs::read(c.join(FILE_NAME)).unwrap();
        let b_dirty = exit_write_uncommitted(&b);
        let b_old_current = belongs_to_current_connection(&old_b, &b);
        let c_disk_current = disk_c.as_ref()
            .is_some_and(|rec| belongs_to_current_connection(rec, &c));
        let a_disk_current = disk_c.as_ref()
            .is_some_and(|rec| belongs_to_current_connection(rec, &a));
        eprintln!(
            "INFLIGHT_RETARGET_RESULT: save_A={result:?}; B_unchanged={}; C_unchanged={}; B_has_proposed={}; C_has_proposed={}; B_dirty={b_dirty}; B_old_current={b_old_current}; C_disk_current={c_disk_current}; A_disk_current={a_disk_current}; C_binding_still_valid={}",
            b_bytes == b_before, c_bytes == c_before,
            disk_b.as_ref() == Some(&proposed), disk_c.as_ref() == Some(&proposed),
            original_exit_binding_still_current(&old_c, &c)
        );

        // Safety invariant, independent of the implementation's choice:
        // commit exclusively to registered B or reject without touching C.
        assert_eq!(c_bytes, c_before,
            "SAFETY: in-flight save must never overwrite unregistered physical root C");
        assert_eq!(disk_c, Some(old_c.clone()));
        assert!(c_disk_current, "independent C must remain healthy");
        assert!(!tmp_c.exists(), "no foreign-root temporary residue");
        assert!(!belongs_to_current_connection(&proposed, &a));
        if result.is_ok() {
            assert_eq!(disk_b, Some(proposed.clone()),
                "a successful save must commit to its registered physical B");
            assert!(!b_dirty);
            assert!(belongs_to_current_connection(&proposed, &b));
        } else {
            assert_eq!(b_bytes, b_before, "rejected save preserves original B JSON");
            assert!(b_dirty, "rejected in-flight save must leave B fail-closed");
            assert!(!b_old_current);
        }

        // Restore original identity and exercise ordinary qualified recovery.
        unlink_dir(&a).unwrap();
        link_dir(&a, &b);
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_b);
        if result.is_err() {
            assert!(!belongs_to_current_connection(&old_b, &a));
        }
        let mut recovered = proposed.clone();
        recovered.at = proposed.at.checked_add(1).unwrap();
        assert!(original_exit_binding_still_current(&recovered, &b));
        save(&b, &recovered).expect("later real B commit restores qualified evidence");
        assert_eq!(load(&a), Some(recovered.clone()));
        assert_eq!(load(&b), Some(recovered.clone()));
        assert!(belongs_to_current_connection(&recovered, &a));
        assert!(belongs_to_current_connection(&recovered, &b));
        assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);
        assert!(belongs_to_current_connection(&old_c, &c));
        std::fs::write(b.join("runtime-engine.json"), "{}").unwrap();
        assert!(!belongs_to_current_connection(&recovered, &a));
        assert!(!belongs_to_current_connection(&recovered, &b));
        assert!(belongs_to_current_connection(&old_c, &c));
        cleanup.cleanup().expect("remove disposable alias before sandbox cleanup");
    }

    /// #74 TEST-ONLY: a genuine prior raw identity failure must survive a
    /// same-caller in-flight save whose alias retargets to another healthy root.
    #[test]
    fn inflight_retarget_preserves_prior_failed_alias_marker_until_matching_commit() {
        use std::sync::mpsc;

        fn link_dir(link: &Path, target: &Path) {
            #[cfg(windows)]
            {
                let out = std::process::Command::new("cmd.exe")
                    .args(["/C", "mklink", "/J"]).arg(link).arg(target).output()
                    .expect("execute real junction creation");
                assert!(out.status.success(), "fixture mklink failed: {out:?}");
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, link).expect("create real directory symlink");
        }

        fn unlink_dir(link: &Path) -> std::io::Result<()> {
            #[cfg(windows)]
            {
                // No /S: remove ONLY the disposable junction, never its target.
                let out = std::process::Command::new("cmd.exe")
                    .args(["/C", "rmdir"]).arg(link).output()?;
                if !out.status.success() {
                    return Err(std::io::Error::other(format!("fixture rmdir failed: {out:?}")));
                }
            }
            #[cfg(unix)]
            std::fs::remove_file(link)?;
            Ok(())
        }

        // Cleanup on both normal completion and assertion unwind. Never
        // recurse into the sandbox until the alias itself is confirmed absent.
        struct Sandbox {
            root: std::path::PathBuf,
            alias: std::path::PathBuf,
        }
        impl Sandbox {
            fn cleanup(&self) -> std::io::Result<()> {
                match std::fs::symlink_metadata(&self.alias) {
                    Ok(_) => unlink_dir(&self.alias)?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                    Err(e) => return Err(e),
                }
                match std::fs::symlink_metadata(&self.alias) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                    Err(e) => return Err(e),
                    Ok(_) => return Err(std::io::Error::other("alias still exists; refusing recursive cleanup")),
                }
                match std::fs::remove_dir_all(&self.root) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    result => result,
                }
            }
        }
        impl Drop for Sandbox {
            fn drop(&mut self) {
                if let Err(e) = self.cleanup() {
                    eprintln!("INFLIGHT_DIRTY_ALIAS fixture cleanup refused or failed: {e}");
                }
            }
        }

        let root = tmp_root("inflight-dirty-alias-marker");
        let a = root.join("alias-a");
        let cleanup = Sandbox { root: root.clone(), alias: a.clone() };
        let b = root.join("data-b");
        let c = root.join("data-c");
        std::fs::create_dir(&b).unwrap();
        std::fs::create_dir(&c).unwrap();
        let physical_b = std::fs::canonicalize(&b).unwrap();
        let physical_c = std::fs::canonicalize(&c).unwrap();
        assert_ne!(physical_b, physical_c, "fixture must have distinct physical roots");
        assert_ne!(a, b);
        assert_ne!(a, c);

        // Both roots have independent genuine qualified loopback Check and
        // observed records, not fabricated bindings or missing-data negatives.
        let observe = |dir: &Path| {
            let port = fake_socks5("8.8.8.8\n", "u", "p");
            let line = qualified_probe_fixture(dir, port);
            let plan = qualified_plan(port);
            let check = crate::selfcheck::check_and_record(dir, &plan, 2_000);
            assert!(check.ok && check.via_trade_exit
                && crate::selfcheck::current_qualified_trade_pass(dir), "{check:?}");
            let record = probe_and_record(dir, &line, &plan, 2_000)
                .expect("actual authenticated exit observation");
            assert!(record.attributed && record.binding.is_some());
            assert_eq!(load(dir), Some(record.clone()));
            assert!(belongs_to_current_connection(&record, dir));
            record
        };
        let old_b = observe(&b);
        let old_c = observe(&c);
        assert_ne!(old_b.binding, old_c.binding);
        assert!(!original_exit_binding_still_current(&old_b, &c));
        assert!(!original_exit_binding_still_current(&old_c, &b));
        let b_before = std::fs::read(b.join(FILE_NAME)).unwrap();
        let c_before = std::fs::read(c.join(FILE_NAME)).unwrap();
        assert_ne!(std::fs::canonicalize(b.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(c.join(FILE_NAME)).unwrap());

        link_dir(&a, &b);
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_b);
        assert_eq!(std::fs::canonicalize(a.join(FILE_NAME)).unwrap(),
            std::fs::canonicalize(b.join(FILE_NAME)).unwrap());
        assert_eq!(load(&a), Some(old_b.clone()));
        assert!(belongs_to_current_connection(&old_b, &a));

        // Establish the raw A marker using the actual public save failure,
        // before the new writer registers. A is initially a healthy B alias.
        unlink_dir(&a).expect("remove only original disposable junction");
        let initial_missing = std::fs::canonicalize(&a)
            .expect_err("fixture: removed alias must genuinely fail canonicalization");
        let initial_failure = save(&a, &old_b)
            .expect_err("real save with missing root must fail");
        assert!(exit_write_uncommitted(&a));
        assert!(!belongs_to_current_connection(&old_b, &a));
        assert_eq!(std::fs::canonicalize(&b).unwrap(), physical_b);
        assert_eq!(std::fs::canonicalize(&c).unwrap(), physical_c);
        assert_eq!(std::fs::read(b.join(FILE_NAME)).unwrap(), b_before);
        assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);
        assert!(belongs_to_current_connection(&old_b, &b));
        assert!(belongs_to_current_connection(&old_c, &c));
        link_dir(&a, &b);
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_b);
        assert_eq!(load(&a), Some(old_b.clone()));
        assert!(original_exit_binding_still_current(&old_b, &a));
        assert!(exit_write_uncommitted(&a),
            "prior raw failure must survive mere restoration of the alias");
        assert!(!belongs_to_current_connection(&old_b, &a));
        assert!(!exit_write_uncommitted(&b));
        assert!(belongs_to_current_connection(&old_b, &b));
        assert!(!b.join(FILE_NAME).with_extension("json.tmp").exists());
        assert!(!c.join(FILE_NAME).with_extension("json.tmp").exists());
        eprintln!("INFLIGHT_DIRTY_ALIAS_PRIOR: real_canonical_error={initial_missing}; real_save_error={initial_failure}; A_now_B=true; A_dirty=true; A_binding_valid=true; A_current=false; B_current=true; C_current=true");

        let mut proposed = old_b.clone();
        proposed.at = proposed.at.checked_add(1).unwrap();
        assert_ne!(proposed, old_b);
        assert_ne!(proposed, old_c);
        assert!(original_exit_binding_still_current(&proposed, &a));
        let tmp_b = b.join(FILE_NAME).with_extension("json.tmp");
        let tmp_c = c.join(FILE_NAME).with_extension("json.tmp");

        let (pending_tx, pending_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let writer_path = a.clone();
        let writer_record = proposed.clone();
        let writer = std::thread::spawn(move || {
            AFTER_PENDING_SAVE_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    pending_tx.send(()).expect("actual registration gate reached");
                    release_rx.recv_timeout(Duration::from_secs(30))
                        .expect("controller must release actual save");
                }));
            });
            save(&writer_path, &writer_record)
        });

        // Catch any setup/assertion panic in the controller so the real save
        // always receives a release and is joined BEFORE filesystem cleanup.
        let stage = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pending_rx.recv_timeout(Duration::from_secs(30))
                .expect("actual save must register before identity change");
            assert!(exit_write_uncommitted(&b));
            assert!(exit_write_uncommitted(&a));
            assert!(!belongs_to_current_connection(&old_b, &b));
            assert!(!belongs_to_current_connection(&old_b, &a));
            assert!(belongs_to_current_connection(&old_c, &c));
            assert!(!tmp_b.exists() && !tmp_c.exists());
            assert_eq!(std::fs::read(b.join(FILE_NAME)).unwrap(), b_before);
            assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);

            unlink_dir(&a).expect("remove only real in-flight junction");
            let missing = std::fs::canonicalize(&a)
                .expect_err("fixture: actual removed alias must not resolve");
            assert_eq!(std::fs::canonicalize(&b).unwrap(), physical_b);
            assert_eq!(std::fs::canonicalize(&c).unwrap(), physical_c);
            link_dir(&a, &c);
            assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
            assert_ne!(std::fs::canonicalize(&a).unwrap(), physical_b);
            assert_eq!(std::fs::canonicalize(a.join(FILE_NAME)).unwrap(),
                std::fs::canonicalize(c.join(FILE_NAME)).unwrap());
            assert_eq!(load(&a), Some(old_c.clone()));
            assert!(original_exit_binding_still_current(&old_c, &a));
            // The raw marker is now the only reason the otherwise qualified
            // C record must be denied through A: C itself is not pending.
            assert!(exit_write_uncommitted(&a),
                "SAFETY: prior alias marker must survive in-flight retarget");
            assert!(!belongs_to_current_connection(&old_c, &a),
                "SAFETY: valid C binding must not bypass prior dirty A");
            assert!(!exit_write_uncommitted(&c));
            assert!(!belongs_to_current_connection(&proposed, &a),
                "B binding cannot authorize a record through physical C");
            assert!(exit_write_uncommitted(&b));
            assert!(!belongs_to_current_connection(&old_b, &b));
            assert!(belongs_to_current_connection(&old_c, &c));
            assert!(!tmp_b.exists() && !tmp_c.exists());
            assert_eq!(std::fs::read(b.join(FILE_NAME)).unwrap(), b_before);
            assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);
            eprintln!("INFLIGHT_DIRTY_ALIAS_STAGE: B={physical_b:?}; C={physical_c:?}; removed_err={missing}; A_now_C=true; A_dirty=true; A_binding_valid=true; A_current=false; B_pending=true; B_current=false; C_current=true; before_IO=true");
        }));
        let released = release_tx.send(());
        let joined = writer.join();
        if let Err(panic) = stage {
            // Gate has been released (or already terminated) and joined.
            std::panic::resume_unwind(panic);
        }
        released.expect("writer must receive deterministic release");
        let result = joined.expect("actual save must finish without panic");

        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
        let disk_b = load(&b);
        let disk_c = load(&c);
        let b_bytes = std::fs::read(b.join(FILE_NAME)).unwrap();
        let c_bytes = std::fs::read(c.join(FILE_NAME)).unwrap();
        let b_dirty = exit_write_uncommitted(&b);
        let a_dirty = exit_write_uncommitted(&a);
        let a_c_binding_valid = original_exit_binding_still_current(&old_c, &a);
        let b_old_current = belongs_to_current_connection(&old_b, &b);
        let c_disk_current = disk_c.as_ref()
            .is_some_and(|rec| belongs_to_current_connection(rec, &c));
        let a_disk_current = disk_c.as_ref()
            .is_some_and(|rec| belongs_to_current_connection(rec, &a));
        eprintln!(
            "INFLIGHT_DIRTY_ALIAS_RESULT: save_A={result:?}; B_unchanged={}; C_unchanged={}; B_has_proposed={}; C_has_proposed={}; B_dirty={b_dirty}; B_old_current={b_old_current}; C_disk_current={c_disk_current}; A_dirty={a_dirty}; A_C_binding_valid={a_c_binding_valid}; A_disk_current={a_disk_current}; C_binding_still_valid={}",
            b_bytes == b_before, c_bytes == c_before,
            disk_b.as_ref() == Some(&proposed), disk_c.as_ref() == Some(&proposed),
            original_exit_binding_still_current(&old_c, &c)
        );

        // Safety invariant, independent of the implementation's choice:
        // commit exclusively to registered B or reject without touching C.
        assert_eq!(c_bytes, c_before,
            "SAFETY: in-flight save must never overwrite unregistered physical root C");
        assert_eq!(disk_c, Some(old_c.clone()));
        assert!(c_disk_current, "independent C must remain healthy");
        assert!(!exit_write_uncommitted(&c));
        assert!(!tmp_c.exists(), "no foreign-root temporary residue");
        assert_eq!(load(&a), Some(old_c.clone()));
        assert!(a_c_binding_valid, "unchanged C record must have valid binding through A");
        assert!(a_dirty,
            "SAFETY: completion at registered B must not retire prior dirty A now resolving to C");
        assert!(!a_disk_current,
            "SAFETY: otherwise CURRENT C evidence must remain denied through dirty A");
        assert!(!belongs_to_current_connection(&proposed, &a));
        if result.is_ok() {
            assert_eq!(disk_b, Some(proposed.clone()),
                "a successful save must commit to its registered physical B");
            assert!(!b_dirty);
            assert!(belongs_to_current_connection(&proposed, &b));
        } else {
            assert_eq!(b_bytes, b_before, "rejected save preserves original B JSON");
            assert!(b_dirty, "rejected in-flight save must leave B fail-closed");
            assert!(!b_old_current);
        }

        // Keep A at C while a later successful B commit restores B if
        // necessary. Even a genuine new successful B group cannot retire A
        // while A denotes a different physical root.
        let mut recovered_b = proposed.clone();
        recovered_b.at = proposed.at.checked_add(1).unwrap();
        assert!(original_exit_binding_still_current(&recovered_b, &b));
        save(&b, &recovered_b).expect("later real B commit restores qualified B");
        assert_eq!(load(&b), Some(recovered_b.clone()));
        assert!(belongs_to_current_connection(&recovered_b, &b));
        assert!(!exit_write_uncommitted(&b));
        assert!(!tmp_b.exists());
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
        assert_eq!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);
        assert_eq!(load(&a), Some(old_c.clone()));
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(original_exit_binding_still_current(&old_c, &a));
        assert!(exit_write_uncommitted(&a));
        assert!(!belongs_to_current_connection(&old_c, &a),
            "another successful B commit cannot recover dirty A at C");

        // Now a real successful save in the root A currently resolves to
        // may retire the previous identity failure. No marker/map mutation.
        let b_after = std::fs::read(b.join(FILE_NAME)).unwrap();
        let mut recovered_c = old_c.clone();
        recovered_c.at = old_c.at.checked_add(1).unwrap();
        assert_ne!(recovered_c, old_c);
        assert!(original_exit_binding_still_current(&recovered_c, &a));
        save(&c, &recovered_c).expect("later real matching C commit must recover A");
        assert_eq!(std::fs::canonicalize(&a).unwrap(), physical_c);
        assert_eq!(load(&a), Some(recovered_c.clone()));
        assert_eq!(load(&c), Some(recovered_c.clone()));
        assert_ne!(std::fs::read(c.join(FILE_NAME)).unwrap(), c_before);
        assert!(!tmp_c.exists());
        assert!(!exit_write_uncommitted(&a));
        assert!(!exit_write_uncommitted(&c));
        assert!(belongs_to_current_connection(&recovered_c, &a));
        assert!(belongs_to_current_connection(&recovered_c, &c));
        assert_eq!(std::fs::read(b.join(FILE_NAME)).unwrap(), b_after);
        assert!(belongs_to_current_connection(&recovered_b, &b));
        eprintln!("INFLIGHT_DIRTY_ALIAS_RECOVERY: matching_C_commit=true; A_dirty=false; A_current=true; B_current=true; C_current=true");

        // The recovered dirty marker never substitutes for the live binding.
        std::fs::write(c.join("runtime-engine.json"), "{}").unwrap();
        assert!(!original_exit_binding_still_current(&recovered_c, &a));
        assert!(!belongs_to_current_connection(&recovered_c, &a));
        assert!(!belongs_to_current_connection(&recovered_c, &c));
        assert!(belongs_to_current_connection(&recovered_b, &b));
        cleanup.cleanup().expect("remove disposable alias before sandbox cleanup");
    }

    /// #76 TEST-ONLY: the already registered real directory itself is moved
    /// aside and a different real directory takes its exact former pathname.
    #[test]
    fn inflight_save_replaced_resolved_root_preserves_physical_ownership() {
        use std::sync::mpsc;

        // Obtain native object identity independently of the canonical text.
        // Windows handles are closed before each directory move; the test
        // itself must not prevent the replacement it is trying to establish.
        #[cfg(windows)]
        fn dir_id(path: &Path) -> (u64, u64) {
            use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
            use windows_sys::Win32::Storage::FileSystem::{
                GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
                FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
                FILE_SHARE_DELETE,
            };
            let dir = std::fs::OpenOptions::new().read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(path).expect("fixture: open native directory for identity");
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            let ok = unsafe {
                GetFileInformationByHandle(dir.as_raw_handle() as _, &mut info)
            };
            assert_ne!(ok, 0, "fixture: native directory identity: {}",
                std::io::Error::last_os_error());
            (u64::from(info.dwVolumeSerialNumber),
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow))
        }

        #[cfg(unix)]
        fn dir_id(path: &Path) -> (u64, u64) {
            use std::os::unix::fs::MetadataExt;
            let md = std::fs::metadata(path).expect("fixture: native directory identity");
            (md.dev(), md.ino())
        }

        // Compare all actual fixture file bytes by relative path, not just
        // load() or the pending map. No links are created in this test.
        fn snapshot(dir: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
            fn walk(base: &Path, dir: &Path,
                out: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>) {
                for entry in std::fs::read_dir(dir).expect("read isolated fixture directory") {
                    let path = entry.expect("fixture entry").path();
                    let md = std::fs::symlink_metadata(&path).unwrap();
                    assert!(!md.file_type().is_symlink(), "fixture must not contain links");
                    if md.is_dir() {
                        walk(base, &path, out);
                    } else {
                        assert!(md.is_file());
                        out.insert(path.strip_prefix(base).unwrap().to_path_buf(),
                            std::fs::read(&path).expect("read actual fixture bytes"));
                    }
                }
            }
            let mut out = std::collections::BTreeMap::new();
            walk(dir, dir, &mut out);
            out
        }

        // Only real sibling directories beneath this disposable sandbox.
        // No junction, product root, external path or privileged operation.
        struct Sandbox(std::path::PathBuf);
        impl Drop for Sandbox {
            fn drop(&mut self) {
                if let Err(e) = std::fs::remove_dir_all(&self.0) {
                    eprintln!("RESOLVED_ROOT_REPLACEMENT fixture cleanup failed: {e}");
                }
            }
        }
        let root = tmp_root("resolved-root-replacement");
        let cleanup = Sandbox(root.clone());
        let b = root.join("registered-b");
        let c = root.join("replacement-c");
        let d = root.join("unaffected-d");
        let parked = root.join("parked-original-b");
        for dir in [&b, &c, &d] {
            std::fs::create_dir(dir).unwrap();
        }
        let id_b = dir_id(&b);
        let id_c = dir_id(&c);
        let id_d = dir_id(&d);
        assert_ne!(id_b, id_c, "fixture: genuinely distinct native directory IDs");
        assert_ne!(id_b, id_d);
        assert_ne!(id_c, id_d);
        assert!(!parked.exists());
        let registered_path = std::fs::canonicalize(&b).unwrap();
        let c_path = std::fs::canonicalize(&c).unwrap();
        assert_ne!(registered_path, c_path);

        let observe = |dir: &Path| {
            let port = fake_socks5("8.8.8.8\n", "u", "p");
            let line = qualified_probe_fixture(dir, port);
            let plan = qualified_plan(port);
            let check = crate::selfcheck::check_and_record(dir, &plan, 2_000);
            assert!(check.ok && check.via_trade_exit
                && crate::selfcheck::current_qualified_trade_pass(dir), "{check:?}");
            let record = probe_and_record(dir, &line, &plan, 2_000)
                .expect("actual authenticated exit observation");
            assert!(record.attributed && record.binding.is_some());
            assert_eq!(load(dir), Some(record.clone()));
            assert!(original_exit_binding_still_current(&record, dir));
            assert!(belongs_to_current_connection(&record, dir));
            record
        };
        let old_b = observe(&b);
        let old_c = observe(&c);
        let old_d = observe(&d);
        assert_ne!(old_b.binding, old_c.binding);
        assert_ne!(old_b.binding, old_d.binding);
        assert_ne!(old_c.binding, old_d.binding);
        assert!(!original_exit_binding_still_current(&old_b, &c));
        assert!(!original_exit_binding_still_current(&old_c, &b));
        assert!(!original_exit_binding_still_current(&old_b, &d));
        // Independent provenance witnesses move with each physical directory.
        std::fs::write(b.join("fixture-provenance"), b"original-b").unwrap();
        std::fs::write(c.join("fixture-provenance"), b"replacement-c").unwrap();
        std::fs::write(d.join("fixture-provenance"), b"unaffected-d").unwrap();
        let b_before = snapshot(&b);
        let c_before = snapshot(&c);
        let d_before = snapshot(&d);
        let tmp_name = std::path::PathBuf::from(FILE_NAME).with_extension("json.tmp");
        assert!(!b_before.contains_key(&tmp_name));
        assert!(!c_before.contains_key(&tmp_name));
        assert!(!d_before.contains_key(&tmp_name));
        let mut proposed = old_b.clone();
        proposed.at = old_b.at.checked_add(1).unwrap();
        assert_ne!(proposed, old_b);
        assert_ne!(proposed, old_c);
        assert!(original_exit_binding_still_current(&proposed, &b));

        let (pending_tx, pending_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let writer_path = b.clone();
        let writer_record = proposed.clone();
        let writer = std::thread::spawn(move || {
            AFTER_PENDING_SAVE_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    pending_tx.send(()).expect("actual registration gate reached");
                    release_rx.recv_timeout(Duration::from_secs(30))
                        .expect("controller must release actual save");
                }));
            });
            save(&writer_path, &writer_record)
        });

        // Capture the pending observation, but let the actual writer finish
        // before asserting target safety so disk ownership is also tested.
        // On any fixture/assertion panic, release and join before cleanup.
        let stage = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pending_rx.recv_timeout(Duration::from_secs(30))
                .expect("fixture: actual save registered before replacement");
            assert!(exit_write_uncommitted(&b));
            assert!(!belongs_to_current_connection(&old_b, &b));
            assert!(belongs_to_current_connection(&old_c, &c));
            assert!(belongs_to_current_connection(&old_d, &d));
            assert_eq!(snapshot(&b), b_before);
            assert_eq!(snapshot(&c), c_before);
            assert_eq!(snapshot(&d), d_before);

            std::fs::rename(&b, &parked)
                .expect("fixture: move registered physical directory aside");
            let missing = std::fs::canonicalize(&b)
                .expect_err("fixture: original pathname actually vacant");
            std::fs::rename(&c, &b)
                .expect("fixture: move distinct physical directory to registered pathname");
            assert!(!c.exists());
            assert_eq!(dir_id(&parked), id_b);
            assert_eq!(dir_id(&b), id_c);
            assert_ne!(dir_id(&b), id_b);
            assert_eq!(dir_id(&d), id_d);
            assert_eq!(std::fs::canonicalize(&b).unwrap(), registered_path,
                "fixture: same canonical pathname, different native identity");
            assert_ne!(std::fs::canonicalize(&parked).unwrap(), registered_path);
            assert_eq!(snapshot(&parked), b_before);
            assert_eq!(snapshot(&b), c_before);
            assert_eq!(snapshot(&d), d_before);
            assert_eq!(load(&parked), Some(old_b.clone()));
            assert_eq!(load(&b), Some(old_c.clone()));
            assert!(!original_exit_binding_still_current(&proposed, &b),
                "replacement must not acquire original B binding");
            assert!(belongs_to_current_connection(&old_d, &d));

            // Legitimate movement may invalidate a path-dependent binding;
            // record that separately from native identity and actual bytes.
            let moved_binding = original_exit_binding_still_current(&old_b, &parked);
            let moved_pending = exit_write_uncommitted(&parked);
            let moved_current = belongs_to_current_connection(&old_b, &parked);
            let replacement_binding = original_exit_binding_still_current(&old_c, &b);
            let replacement_pending = exit_write_uncommitted(&b);
            eprintln!("RESOLVED_ROOT_REPLACEMENT_STAGE: B_ID={id_b:?}; C_ID={id_c:?}; D_ID={id_d:?}; vacant_error={missing}; same_canonical_path=true; actual_path_is_C=true; B_at_parked=true; bytes_unchanged=true; moved_binding={moved_binding}; moved_pending={moved_pending}; moved_current={moved_current}; replacement_binding={replacement_binding}; replacement_pending={replacement_pending}; D_current=true; before_IO=true");
            (moved_binding, moved_pending, moved_current)
        }));
        let released = release_tx.send(());
        let joined = writer.join();
        let (moved_binding, moved_pending, moved_current) = match stage {
            Ok(values) => values,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        released.expect("writer must receive deterministic release");
        let result = joined.expect("actual save must complete without panic");

        assert_eq!(dir_id(&parked), id_b);
        assert_eq!(dir_id(&b), id_c);
        assert_eq!(dir_id(&d), id_d);
        let original_disk = load(&parked);
        let replacement_disk = load(&b);
        let original_after = snapshot(&parked);
        let replacement_after = snapshot(&b);
        let original_dirty = exit_write_uncommitted(&parked);
        let replacement_dirty = exit_write_uncommitted(&b);
        let original_live = original_exit_binding_still_current(&old_b, &parked);
        let original_current = belongs_to_current_connection(&old_b, &parked);
        let replacement_current = replacement_disk.as_ref()
            .is_some_and(|rec| belongs_to_current_connection(rec, &b));
        eprintln!("RESOLVED_ROOT_REPLACEMENT_RESULT: save_B={result:?}; B_bytes_unchanged={}; C_bytes_unchanged={}; B_has_proposed={}; C_has_proposed={}; B_dirty={original_dirty}; B_binding={original_live}; B_old_current={original_current}; C_dirty={replacement_dirty}; C_disk_current={replacement_current}; D_unchanged={}",
            original_after == b_before, replacement_after == c_before,
            original_disk.as_ref() == Some(&proposed),
            replacement_disk.as_ref() == Some(&proposed), snapshot(&d) == d_before);

        // Primary safety assertion independent of binding changes: C is a
        // different native directory even though its pathname is identical.
        // All actual C files must be intact, including absence of foreign tmp.
        assert!(replacement_after == c_before,
            "SAFETY: save must not alter the distinct replacement physical directory C");
        assert_eq!(replacement_disk, Some(old_c.clone()));
        assert!(!belongs_to_current_connection(&proposed, &b));
        assert_eq!(snapshot(&d), d_before);
        assert_eq!(load(&d), Some(old_d.clone()));
        assert!(belongs_to_current_connection(&old_d, &d));
        if moved_binding {
            assert!(!moved_current,
                "SAFETY: original physical directory with valid binding must not authorize CURRENT while its writer is pending");
        }
        if result.is_ok() {
            assert_eq!(original_disk, Some(proposed.clone()),
                "SAFETY: success requires actual commit to original native directory B");
            let mut expected = b_before.clone();
            expected.insert(std::path::PathBuf::from(FILE_NAME),
                std::fs::read(parked.join(FILE_NAME)).unwrap());
            assert!(original_after == expected,
                "successful save must change only original B record");
            assert!(!original_dirty);
            if original_exit_binding_still_current(&proposed, &parked) {
                assert!(belongs_to_current_connection(&proposed, &parked));
            }
        } else {
            assert!(original_after == b_before,
                "safe rejection preserves original B files");
            if original_live {
                assert!(original_dirty,
                    "SAFETY: failed original B write with valid binding remains dirty");
                assert!(!original_current);
            }
        }
        // Read the diagnostic even when movement invalidates the binding.
        eprintln!("RESOLVED_ROOT_REPLACEMENT_PENDING: moved_binding={moved_binding}; moved_pending={moved_pending}; moved_current={moved_current}");

        // Return the two native directory objects to their original paths.
        // A valid old binding at that point must not bypass a failed save.
        std::fs::rename(&b, &c).expect("fixture: restore replacement C to its own path");
        std::fs::rename(&parked, &b).expect("fixture: restore original B identity");
        assert_eq!(dir_id(&b), id_b);
        assert_eq!(dir_id(&c), id_c);
        assert_eq!(dir_id(&d), id_d);
        assert_eq!(std::fs::canonicalize(&b).unwrap(), registered_path);
        assert_eq!(snapshot(&c), c_before);
        assert_eq!(snapshot(&d), d_before);
        assert!(original_exit_binding_still_current(&old_c, &c));
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(belongs_to_current_connection(&old_d, &d));
        assert!(original_exit_binding_still_current(&old_b, &b),
            "fixture: restored original identity must retain its original binding");
        if result.is_err() {
            assert_eq!(load(&b), Some(old_b.clone()));
            assert!(exit_write_uncommitted(&b));
            assert!(!belongs_to_current_connection(&old_b, &b),
                "SAFETY: returning failed original B to its path alone cannot recover CURRENT");
        }
        let mut recovered = proposed.clone();
        recovered.at = proposed.at.checked_add(1).unwrap();
        assert!(original_exit_binding_still_current(&recovered, &b));
        save(&b, &recovered).expect("later genuine save under restored original identity");
        assert_eq!(dir_id(&b), id_b);
        assert_eq!(load(&b), Some(recovered.clone()));
        assert!(!exit_write_uncommitted(&b));
        assert!(belongs_to_current_connection(&recovered, &b));
        assert_eq!(snapshot(&c), c_before);
        assert_eq!(snapshot(&d), d_before);
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(belongs_to_current_connection(&old_d, &d));
        std::fs::write(b.join("runtime-engine.json"), "{}").unwrap();
        assert!(!original_exit_binding_still_current(&recovered, &b));
        assert!(!belongs_to_current_connection(&recovered, &b));
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(belongs_to_current_connection(&old_d, &d));
        eprintln!("RESOLVED_ROOT_REPLACEMENT_RECOVERY: original_identity_restored=true; later_B_commit=true; stale_binding_denied=true; C_healthy=true; D_healthy=true");
        drop(cleanup);
    }

    /// #78 TEST-ONLY: exercise the real producer (including its failure
    /// invalidation), not just public save(), after registration of B.
    #[test]
    fn producer_identity_rejection_preserves_raw_ip_and_physical_records() {
        use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc};

        // Native identity independent of the production identity helper.
        #[cfg(windows)]
        fn dir_id(path: &Path) -> (u64, u64) {
            use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
            use windows_sys::Win32::Storage::FileSystem::{
                GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
                FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
                FILE_SHARE_DELETE,
            };
            let dir = std::fs::OpenOptions::new().read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(path).expect("fixture: open native directory");
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            assert_ne!(unsafe { GetFileInformationByHandle(dir.as_raw_handle() as _, &mut info) },
                0, "fixture: native directory identity: {}", std::io::Error::last_os_error());
            let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
            assert_ne!(index, 0);
            (u64::from(info.dwVolumeSerialNumber), index)
        }

        #[cfg(unix)]
        fn dir_id(path: &Path) -> (u64, u64) {
            use std::os::unix::fs::MetadataExt;
            let md = std::fs::metadata(path).expect("fixture: native directory identity");
            assert!(md.is_dir());
            assert_ne!(md.ino(), 0);
            (md.dev(), md.ino())
        }

        // Include directories as well as file bytes so foreign staging,
        // deletion or an unexpected empty directory cannot hide in load().
        type Snapshot = std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>;
        fn snapshot(root: &Path) -> Snapshot {
            fn walk(base: &Path, dir: &Path, out: &mut Snapshot) {
                for entry in std::fs::read_dir(dir).expect("fixture: read directory") {
                    let path = entry.unwrap().path();
                    let md = std::fs::symlink_metadata(&path).unwrap();
                    assert!(!md.file_type().is_symlink());
                    let relative = path.strip_prefix(base).unwrap().to_path_buf();
                    if md.is_dir() {
                        out.insert(relative, None);
                        walk(base, &path, out);
                    } else {
                        assert!(md.is_file());
                        out.insert(relative, Some(std::fs::read(&path).unwrap()));
                    }
                }
            }
            let mut out = Snapshot::new();
            walk(root, root, &mut out);
            out
        }

        struct Sandbox(std::path::PathBuf);
        impl Drop for Sandbox {
            fn drop(&mut self) {
                if let Err(e) = std::fs::remove_dir_all(&self.0) {
                    eprintln!("PRODUCER_IDENTITY fixture cleanup failed: {e}");
                }
            }
        }

        // Real authenticated SOCKS5 and synthetic HTTP, exclusively on
        // loopback. Keep each listener reserved so control bindings cannot
        // accidentally share an ephemeral port. A cancellation connection
        // wakes accept on fixture failure; all accepted IO is time-bounded.
        struct Loopback {
            listener: TcpListener,
            stop: Arc<AtomicBool>,
            worker: Option<std::thread::JoinHandle<usize>>,
        }
        impl Loopback {
            fn start(label: String, bodies: Vec<&'static str>) -> Self {
                let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
                let active = listener.try_clone().unwrap();
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = Arc::clone(&stop);
                let worker = std::thread::spawn(move || {
                    let mut completed = 0;
                    for (phase, body) in bodies.into_iter().enumerate() {
                        let (mut s, _) = active.accept().expect("fixture: loopback accept");
                        if worker_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                        s.set_nodelay(true).unwrap();
                        eprintln!("PRODUCER_FIXTURE {label} phase={phase}: accepted");
                        let mut greet = [0u8; 4];
                        s.read_exact(&mut greet).unwrap();
                        assert_eq!(greet, [0x05, 0x02, 0x00, 0x02]);
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
                        eprintln!("PRODUCER_FIXTURE {label} phase={phase}: authenticated");
                        let mut connect = [0u8; 5];
                        s.read_exact(&mut connect).unwrap();
                        assert_eq!(&connect[..4], &[0x05, 0x01, 0x00, 0x03]);
                        let mut target = vec![0u8; usize::from(connect[4]) + 2];
                        s.read_exact(&mut target).unwrap();
                        let (host, path) = if body.is_empty() {
                            ("www.gstatic.com", "/generate_204")
                        } else {
                            ("checkip.amazonaws.com", "/")
                        };
                        assert_eq!(&target[..target.len() - 2], host.as_bytes(),
                            "fixture {label} phase={phase}: expected SOCKS host");
                        assert_eq!(&target[target.len() - 2..], &80u16.to_be_bytes());
                        s.write_all(&[0x05, 0, 0, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();
                        // Consume the complete bounded origin-form HTTP request.
                        let mut req = Vec::new();
                        let mut chunk = [0u8; 512];
                        while !req.ends_with(b"\r\n\r\n") {
                            let n = s.read(&mut chunk).expect("fixture: HTTP request read");
                            assert_ne!(n, 0, "fixture: premature HTTP request EOF");
                            req.extend_from_slice(&chunk[..n]);
                            assert!(req.len() <= 8192, "fixture: bounded HTTP header");
                        }
                        assert!(req.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()),
                            "fixture {label} phase={phase}: origin-form GET");
                        eprintln!("PRODUCER_FIXTURE {label} phase={phase}: HTTP request complete host={host}");
                        let status = if body.is_empty() { "204 No Content" } else { "200 OK" };
                        s.write_all(format!(
                            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        ).as_bytes()).expect("fixture: HTTP response write");
                        // socks5_text reads the body through EOF, not only
                        // Content-Length. Finish the write half explicitly.
                        if !body.is_empty() {
                            s.shutdown(std::net::Shutdown::Write)
                                .expect("fixture: complete response EOF");
                        }
                        completed += 1;
                        eprintln!("PRODUCER_FIXTURE {label} phase={phase}: response completed status={status} body={body:?}");
                    }
                    completed
                });
                Self { listener, stop, worker: Some(worker) }
            }

            fn port(&self) -> u16 {
                self.listener.local_addr().unwrap().port()
            }

            fn stop_and_join(&mut self) -> Option<std::thread::Result<usize>> {
                let worker = self.worker.take()?;
                self.stop.store(true, Ordering::SeqCst);
                if !worker.is_finished() {
                    // Only an isolated local listener; no remote connection.
                    let addr = self.listener.local_addr().unwrap();
                    let _ = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2));
                }
                Some(worker.join())
            }

            fn finish(&mut self, expected: usize) {
                let completed = self.stop_and_join().unwrap().expect("fixture: authenticated server");
                assert_eq!(completed, expected, "fixture: exact real HTTP exchange count");
            }
        }
        impl Drop for Loopback {
            fn drop(&mut self) {
                if let Some(result) = self.stop_and_join() {
                    match result {
                        Ok(count) => eprintln!("PRODUCER_FIXTURE cleanup: completed={count}"),
                        Err(_) => eprintln!("PRODUCER_FIXTURE cleanup: server thread panicked (see actual panic above)"),
                    }
                }
            }
        }

        let root = tmp_root("producer-identity-rejection");
        let cleanup = Sandbox(root.clone());
        let b = root.join("registered-b");
        let c = root.join("replacement-c");
        let d = root.join("unaffected-d");
        let parked = root.join("parked-original-b");
        for dir in [&b, &c, &d] {
            std::fs::create_dir(dir).unwrap();
        }
        let (id_b, id_c, id_d) = (dir_id(&b), dir_id(&c), dir_id(&d));
        assert_ne!(id_b, id_c);
        assert_ne!(id_b, id_d);
        assert_ne!(id_c, id_d);
        let registered = std::fs::canonicalize(&b).unwrap();
        assert_ne!(registered, std::fs::canonicalize(&c).unwrap());

        // All three B answers are target IPs in the SAME unchanged line
        // file, so an unverified new return cannot be explained by an
        // unmatched IP or deliberately stale Check before the save gate.
        let observe = |dir: &Path, bodies: Vec<&'static str>| {
            let mut server = Loopback::start(dir.display().to_string(), bodies);
            let line = qualified_probe_fixture(dir, server.port());
            let plan = qualified_plan(server.port());
            std::fs::write(line.engine_config_path(dir), serde_json::json!({
                "outbounds": [
                    {"type":"vless","server":"8.8.8.8","server_port":8443},
                    {"type":"vless","server":"1.1.1.1","server_port":8443},
                    {"type":"vless","server":"9.9.9.9","server_port":8443}
                ]
            }).to_string()).unwrap();
            let check = crate::selfcheck::check_and_record(dir, &plan, 2_000);
            assert!(check.ok && check.via_trade_exit && check.status == Some(204)
                && crate::selfcheck::current_qualified_trade_pass(dir),
                "fixture: authenticated qualified Check: {check:?}");
            let old = match probe_and_record(dir, &line, &plan, 2_000) {
                Some(record) => record,
                None => {
                    let joined = server.stop_and_join();
                    eprintln!("PRODUCER_FIXTURE initial observation absent: root={}; server_result={joined:?}",
                        dir.display());
                    panic!("fixture: real initial authenticated observation for {}", dir.display());
                }
            };
            assert_eq!(old.ip, "8.8.8.8");
            assert!(old.attributed && old.binding.is_some());
            assert_eq!(load(dir), Some(old.clone()));
            assert!(original_exit_binding_still_current(&old, dir));
            assert!(belongs_to_current_connection(&old, dir));
            (server, line, plan, old)
        };
        let (mut server_b, line_b, plan_b, old_b) =
            observe(&b, vec!["", "8.8.8.8\n", "1.1.1.1\n", "9.9.9.9\n"]);
        let (mut server_c, _, _, old_c) = observe(&c, vec!["", "8.8.8.8\n"]);
        let (mut server_d, _, _, old_d) = observe(&d, vec!["", "8.8.8.8\n"]);
        server_c.finish(2);
        server_d.finish(2);
        assert_ne!(old_b.binding, old_c.binding);
        assert_ne!(old_b.binding, old_d.binding);
        assert_ne!(old_c.binding, old_d.binding);
        assert!(!original_exit_binding_still_current(&old_b, &c));
        assert!(!original_exit_binding_still_current(&old_b, &d));
        assert!(server_ips(&b, &line_b).contains(&"1.1.1.1".to_string()));
        assert_eq!(current_binding(&b, &line_b.id, server_b.port(), Some(("u", "p"))),
            old_b.binding);
        std::fs::write(b.join("fixture-provenance"), b"producer-b").unwrap();
        std::fs::write(c.join("fixture-provenance"), b"replacement-c").unwrap();
        std::fs::write(d.join("fixture-provenance"), b"control-d").unwrap();
        let (b_before, c_before, d_before) = (snapshot(&b), snapshot(&c), snapshot(&d));
        for files in [&b_before, &c_before, &d_before] {
            assert!(files.keys().all(|path|
                !path.file_name().unwrap().to_string_lossy().starts_with("exit-probe.json.tmp")));
        }

        let (pending_tx, pending_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let worker_root = b.clone();
        let worker_line = line_b.clone();
        let worker_plan = qualified_plan(server_b.port());
        let worker = std::thread::spawn(move || {
            AFTER_PENDING_SAVE_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    pending_tx.send(()).expect("actual producer registration gate");
                    release_rx.recv_timeout(Duration::from_secs(30))
                        .expect("controller must release producer persistence");
                }));
            });
            // REAL HTTP request, before/after binding, final persistence
            // and returned observation; no direct save or mocked error here.
            probe_and_record(&worker_root, &worker_line, &worker_plan, 2_000)
        });

        let stage = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pending_rx.recv_timeout(Duration::from_secs(30))
                .expect("fixture: producer reached real after-registration gate");
            assert_eq!(snapshot(&b), b_before);
            assert_eq!(snapshot(&c), c_before);
            assert_eq!(snapshot(&d), d_before);
            assert!(original_exit_binding_still_current(&old_b, &b));
            let initial_pending = exit_write_uncommitted(&b);
            let initial_current = belongs_to_current_connection(&old_b, &b);
            assert!(belongs_to_current_connection(&old_c, &c));
            assert!(belongs_to_current_connection(&old_d, &d));

            std::fs::rename(&b, &parked).expect("fixture: move actual original B");
            let missing = std::fs::canonicalize(&b).expect_err("fixture: vacant B path");
            std::fs::rename(&c, &b).expect("fixture: move actual C to B path");
            assert!(!c.exists());
            assert_eq!(dir_id(&parked), id_b);
            assert_eq!(dir_id(&b), id_c);
            assert_eq!(dir_id(&d), id_d);
            assert_eq!(std::fs::canonicalize(&b).unwrap(), registered);
            assert_ne!(std::fs::canonicalize(&parked).unwrap(), registered);
            assert_eq!(snapshot(&parked), b_before);
            assert_eq!(snapshot(&b), c_before);
            assert_eq!(snapshot(&d), d_before);
            assert_eq!(load(&parked), Some(old_b.clone()));
            assert_eq!(load(&b), Some(old_c.clone()));
            assert!(!original_exit_binding_still_current(&old_b, &b));
            let moved_binding = original_exit_binding_still_current(&old_b, &parked);
            let moved_pending = exit_write_uncommitted(&parked);
            let moved_current = belongs_to_current_connection(&old_b, &parked);
            let c_binding = original_exit_binding_still_current(&old_c, &b);
            let c_pending = exit_write_uncommitted(&b);
            let c_current = belongs_to_current_connection(&old_c, &b);
            eprintln!("PRODUCER_IDENTITY_STAGE: B={id_b:?}; C={id_c:?}; D={id_d:?}; vacant={missing}; same_path=true; original_registered=true; moved_binding={moved_binding}; moved_pending={moved_pending}; moved_current={moved_current}; C_binding={c_binding}; C_pending={c_pending}; C_current={c_current}");
            (initial_pending, initial_current, moved_binding, moved_pending, moved_current,
                c_binding, c_pending, c_current)
        }));
        // Always release and join before propagating fixture failures or
        // cleaning up; even a panic cannot leave a blocked production save.
        let released = release_tx.send(());
        let joined = worker.join();
        let (initial_pending, initial_current, moved_binding, moved_pending, moved_current,
            c_binding, c_pending, c_current) = match stage {
            Ok(values) => values,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        released.expect("fixture: deterministic producer release");
        let observed = joined.expect("actual producer must not panic")
            .expect("actual authenticated HTTP IP must be returned even on identity rejection");

        assert_eq!(dir_id(&parked), id_b);
        assert_eq!(dir_id(&b), id_c);
        assert_eq!(dir_id(&d), id_d);
        let original_after = snapshot(&parked);
        let replacement_after = snapshot(&b);
        let original_disk = load(&parked);
        let replacement_disk = load(&b);
        let original_dirty = exit_write_uncommitted(&parked);
        let original_current = belongs_to_current_connection(&old_b, &parked);
        let replacement_dirty = exit_write_uncommitted(&b);
        let rejected = original_after == b_before;
        eprintln!("PRODUCER_IDENTITY_RESULT: ip={}; attributed={}; binding_present={}; original_unchanged={rejected}; C_unchanged={}; B_dirty={original_dirty}; B_old_current={original_current}; C_dirty={replacement_dirty}; D_unchanged={}",
            observed.ip, observed.attributed, observed.binding.is_some(),
            replacement_after == c_before, snapshot(&d) == d_before);

        // The observed IP differs from B's historical record and is a
        // configured target. Independent C/D bytes must survive ALL producer
        // failure invalidation and temp handling regardless of qualification.
        assert_eq!(observed.ip, "1.1.1.1", "SAFETY: retain actual raw observed IP");
        assert_eq!(observed.endpoint, "checkip.amazonaws.com");
        assert_eq!(observed.line_id, old_b.line_id);
        assert_eq!(observed.started_at, old_b.started_at);
        assert_eq!(replacement_after, c_before,
            "SAFETY: producer must not overwrite, clear or stage in replacement C");
        assert_eq!(replacement_disk, Some(old_c.clone()));
        assert_eq!(snapshot(&d), d_before);
        assert_eq!(load(&d), Some(old_d.clone()));
        assert!(belongs_to_current_connection(&old_d, &d));
        assert!(!belongs_to_current_connection(&observed, &b));
        assert!(initial_pending && !initial_current);
        assert!(moved_pending, "SAFETY: pending guard must follow original native B");
        if moved_binding {
            assert!(!moved_current, "SAFETY: moved original B cannot become CURRENT while pending");
        }
        assert!(!c_pending && !replacement_dirty,
            "SAFETY: different native C must not inherit B's pending/failed group");
        if c_binding {
            assert!(c_current);
            assert!(belongs_to_current_connection(&old_c, &b));
        }

        if rejected {
            assert_eq!(original_disk, Some(old_b.clone()));
            assert!(!observed.attributed && observed.binding.is_none(),
                "SAFETY: failed producer persistence must return unverified raw IP without binding");
            assert!(original_dirty, "SAFETY: identity rejection retains original B failure");
            assert!(!original_current);
            assert!(!belongs_to_current_connection(&observed, &parked));
        } else {
            // Accept only a genuine alternative commit to the originally
            // registered object, never a false success or foreign mutation.
            assert_eq!(original_disk, Some(observed.clone()),
                "SAFETY: changed B must contain the actual new returned observation");
            let mut expected = b_before.clone();
            expected.insert(std::path::PathBuf::from(FILE_NAME),
                Some(std::fs::read(parked.join(FILE_NAME)).unwrap()));
            assert_eq!(original_after, expected, "only B's committed record may change");
            assert!(!original_dirty);
            if observed.attributed {
                assert_eq!(observed.binding, old_b.binding);
                if original_exit_binding_still_current(&observed, &parked) {
                    assert!(belongs_to_current_connection(&observed, &parked));
                }
            } else {
                assert!(observed.binding.is_none());
                assert!(!belongs_to_current_connection(&observed, &parked));
            }
        }

        std::fs::rename(&b, &c).expect("fixture: restore distinct C");
        std::fs::rename(&parked, &b).expect("fixture: restore original B identity");
        assert_eq!(dir_id(&b), id_b);
        assert_eq!(dir_id(&c), id_c);
        assert_eq!(dir_id(&d), id_d);
        assert_eq!(std::fs::canonicalize(&b).unwrap(), registered);
        assert!(original_exit_binding_still_current(&old_b, &b),
            "fixture: restored B has valid original binding independently of failure guard");
        assert_eq!(snapshot(&c), c_before);
        assert_eq!(snapshot(&d), d_before);
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(belongs_to_current_connection(&old_d, &d));
        if rejected {
            assert_eq!(snapshot(&b), b_before);
            assert_eq!(load(&b), Some(old_b.clone()));
            assert!(exit_write_uncommitted(&b));
            assert!(!belongs_to_current_connection(&old_b, &b),
                "SAFETY: restoring pathname alone cannot clear failed B denial");
        }

        // A new REAL authenticated producer observation under the restored
        // matching identity must succeed, not merely erase a guard.
        let recovered = probe_and_record(&b, &line_b, &plan_b, 2_000)
            .expect("fixture: real authenticated recovery observation");
        server_b.finish(4);
        assert_eq!(recovered.ip, "9.9.9.9");
        assert!(recovered.attributed);
        assert_eq!(recovered.binding, old_b.binding);
        assert_eq!(load(&b), Some(recovered.clone()));
        assert_eq!(dir_id(&b), id_b);
        assert!(!exit_write_uncommitted(&b));
        assert!(belongs_to_current_connection(&recovered, &b));
        let mut expected = b_before.clone();
        expected.insert(std::path::PathBuf::from(FILE_NAME),
            Some(std::fs::read(b.join(FILE_NAME)).unwrap()));
        assert_eq!(snapshot(&b), expected);
        assert_eq!(snapshot(&c), c_before);
        assert_eq!(snapshot(&d), d_before);
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(belongs_to_current_connection(&old_d, &d));

        std::fs::write(b.join("runtime-engine.json"), "{}").unwrap();
        assert!(!original_exit_binding_still_current(&recovered, &b));
        assert!(!belongs_to_current_connection(&recovered, &b));
        assert_eq!(snapshot(&c), c_before);
        assert_eq!(snapshot(&d), d_before);
        assert!(belongs_to_current_connection(&old_c, &c));
        assert!(belongs_to_current_connection(&old_d, &d));
        eprintln!("PRODUCER_IDENTITY_RECOVERY: rejected={rejected}; original_identity_restored=true; genuine_producer_commit=true; stale_binding_denied=true; C_healthy=true; D_healthy=true");
        drop(cleanup);
    }

    /// #80: direct clear() must revoke old CURRENT authority even if the
    /// Windows filesystem refuses deletion. This is a same-session API
    /// contract, not proof of reachability in a normal GUI/CLI lifecycle.
    #[cfg(windows)]
    #[test]
    fn windows_direct_clear_delete_refusal_revokes_current_and_recovers() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        struct Sandbox(std::path::PathBuf);
        impl Drop for Sandbox {
            fn drop(&mut self) {
                if let Err(e) = std::fs::remove_dir_all(&self.0) {
                    eprintln!("CLEAR_FIXTURE cleanup failed: {e}");
                }
            }
        }

        // Same authenticated, bounded loopback transport pattern as the
        // native-passing #78 fixture, with finite cancellation and joining.
        struct Loopback {
            listener: TcpListener,
            stop: Arc<AtomicBool>,
            worker: Option<std::thread::JoinHandle<usize>>,
        }
        impl Loopback {
            fn start(label: String, bodies: Vec<&'static str>) -> Self {
                let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
                let active = listener.try_clone().unwrap();
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = Arc::clone(&stop);
                let worker = std::thread::spawn(move || {
                    let mut completed = 0;
                    for (phase, body) in bodies.into_iter().enumerate() {
                        let (mut s, _) = active.accept().expect("fixture: loopback accept");
                        if worker_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                        s.set_nodelay(true).unwrap();
                        eprintln!("CLEAR_FIXTURE {label} phase={phase}: accepted");
                        let mut greet = [0u8; 4];
                        s.read_exact(&mut greet).unwrap();
                        assert_eq!(greet, [0x05, 0x02, 0x00, 0x02]);
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
                        eprintln!("CLEAR_FIXTURE {label} phase={phase}: authenticated");
                        let mut connect = [0u8; 5];
                        s.read_exact(&mut connect).unwrap();
                        assert_eq!(&connect[..4], &[0x05, 0x01, 0x00, 0x03]);
                        let mut target = vec![0u8; usize::from(connect[4]) + 2];
                        s.read_exact(&mut target).unwrap();
                        let (host, path) = if body.is_empty() {
                            ("www.gstatic.com", "/generate_204")
                        } else {
                            ("checkip.amazonaws.com", "/")
                        };
                        assert_eq!(&target[..target.len() - 2], host.as_bytes(),
                            "fixture {label} phase={phase}: expected SOCKS host");
                        assert_eq!(&target[target.len() - 2..], &80u16.to_be_bytes());
                        s.write_all(&[0x05, 0, 0, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();
                        // Consume the complete bounded origin-form HTTP request.
                        let mut req = Vec::new();
                        let mut chunk = [0u8; 512];
                        while !req.ends_with(b"\r\n\r\n") {
                            let n = s.read(&mut chunk).expect("fixture: HTTP request read");
                            assert_ne!(n, 0, "fixture: premature HTTP request EOF");
                            req.extend_from_slice(&chunk[..n]);
                            assert!(req.len() <= 8192, "fixture: bounded HTTP header");
                        }
                        assert!(req.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()),
                            "fixture {label} phase={phase}: origin-form GET");
                        eprintln!("CLEAR_FIXTURE {label} phase={phase}: HTTP request complete host={host}");
                        let status = if body.is_empty() { "204 No Content" } else { "200 OK" };
                        s.write_all(format!(
                            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        ).as_bytes()).expect("fixture: HTTP response write");
                        // socks5_text reads the body through EOF, not only
                        // Content-Length. Finish the write half explicitly.
                        if !body.is_empty() {
                            s.shutdown(std::net::Shutdown::Write)
                                .expect("fixture: complete response EOF");
                        }
                        completed += 1;
                        eprintln!("CLEAR_FIXTURE {label} phase={phase}: response completed status={status} body={body:?}");
                    }
                    completed
                });
                Self { listener, stop, worker: Some(worker) }
            }

            fn port(&self) -> u16 {
                self.listener.local_addr().unwrap().port()
            }

            fn stop_and_join(&mut self) -> Option<std::thread::Result<usize>> {
                let worker = self.worker.take()?;
                self.stop.store(true, Ordering::SeqCst);
                if !worker.is_finished() {
                    // Only an isolated local listener; no remote connection.
                    let addr = self.listener.local_addr().unwrap();
                    let _ = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2));
                }
                Some(worker.join())
            }

            fn finish(&mut self, expected: usize) {
                let completed = self.stop_and_join().unwrap().expect("fixture: authenticated server");
                assert_eq!(completed, expected, "fixture: exact real HTTP exchange count");
            }
        }
        impl Drop for Loopback {
            fn drop(&mut self) {
                if let Some(result) = self.stop_and_join() {
                    match result {
                        Ok(count) => eprintln!("CLEAR_FIXTURE cleanup: completed={count}"),
                        Err(_) => eprintln!("CLEAR_FIXTURE cleanup: server thread panicked (see actual panic above)"),
                    }
                }
            }
        }

        fn snapshot(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
            fn walk(base: &Path, dir: &Path,
                out: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>) {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    let md = std::fs::symlink_metadata(&path).unwrap();
                    assert!(!md.file_type().is_symlink());
                    if md.is_dir() {
                        walk(base, &path, out);
                    } else {
                        assert!(md.is_file());
                        out.insert(path.strip_prefix(base).unwrap().to_path_buf(),
                            std::fs::read(&path).unwrap());
                    }
                }
            }
            let mut out = std::collections::BTreeMap::new();
            walk(root, root, &mut out);
            out
        }

        fn no_staging(root: &Path) {
            for entry in std::fs::read_dir(root).unwrap() {
                let name = entry.unwrap().file_name();
                assert!(!name.to_string_lossy().starts_with("exit-probe.json.tmp"),
                    "unexpected exit staging: {name:?}");
            }
        }

        let sandbox = tmp_root("direct-clear-delete-refusal");
        let cleanup = Sandbox(sandbox.clone());
        let root = sandbox.join("target");
        let control = sandbox.join("independent-control");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&control).unwrap();
        assert_ne!(read_exit_directory_id(&root).unwrap(),
            read_exit_directory_id(&control).unwrap());

        let observe = |dir: &Path, bodies: Vec<&'static str>| {
            let mut server = Loopback::start(dir.display().to_string(), bodies);
            let line = qualified_probe_fixture(dir, server.port());
            // The old and new response IPs both match the unchanged line.
            std::fs::write(line.engine_config_path(dir), serde_json::json!({
                "outbounds": [
                    {"type":"vless","server":"8.8.8.8","server_port":8443},
                    {"type":"vless","server":"1.1.1.1","server_port":8443}
                ]
            }).to_string()).unwrap();
            let plan = qualified_plan(server.port());
            let check = crate::selfcheck::check_and_record(dir, &plan, 2_000);
            assert!(check.ok && check.via_trade_exit && check.status == Some(204)
                && crate::selfcheck::current_qualified_trade_pass(dir),
                "fixture: genuinely qualified Check {dir:?}: {check:?}");
            let old = match probe_and_record(dir, &line, &plan, 2_000) {
                Some(record) => record,
                None => {
                    let joined = server.stop_and_join();
                    panic!("fixture: initial real observation absent for {dir:?}; server={joined:?}");
                }
            };
            assert_eq!(old.ip, "8.8.8.8");
            assert!(old.attributed && old.binding.is_some());
            assert_eq!(load(dir), Some(old.clone()));
            assert!(original_exit_binding_still_current(&old, dir));
            assert!(belongs_to_current_connection(&old, dir));
            assert!(!exit_write_uncommitted(dir));
            no_staging(dir);
            (server, line, plan, old, check)
        };
        let (mut target_server, line, plan, old, check) =
            observe(&root, vec!["", "8.8.8.8\n", "1.1.1.1\n"]);
        let (mut control_server, _, _, independent, control_check) =
            observe(&control, vec!["", "8.8.8.8\n"]);
        control_server.finish(2);
        assert_ne!(old.binding, independent.binding);
        assert!(!original_exit_binding_still_current(&old, &control));
        assert!(!original_exit_binding_still_current(&independent, &root));
        let control_before = snapshot(&control);
        let original_before = snapshot(&root);
        let path = root.join(FILE_NAME);
        let original_bytes = std::fs::read(&path).unwrap();

        // Real readable Win32 file handle without FILE_SHARE_DELETE.
        // RAII releases it even if any prerequisite fails. No save() call,
        // pending-map edit, forced session change or mocked filesystem error.
        let mut locked = std::fs::OpenOptions::new().read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path).expect("fixture: readable file without delete sharing");
        let mut handle_bytes = Vec::new();
        locked.read_to_end(&mut handle_bytes).unwrap();
        assert_eq!(handle_bytes, original_bytes);
        let delete_error = std::fs::remove_file(&path)
            .expect_err("fixture: native Windows delete must actually be refused");
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert_eq!(load(&root), Some(old.clone()));
        assert_eq!(crate::selfcheck::load(&root), Some(check.clone()));
        assert!(crate::selfcheck::current_qualified_trade_pass(&root));
        assert!(original_exit_binding_still_current(&old, &root));
        assert!(!exit_write_uncommitted(&root));
        assert!(belongs_to_current_connection(&old, &root),
            "fixture: direct OS refusal alone must not invalidate the original evidence");
        no_staging(&root);
        assert_eq!(snapshot(&root), original_before);
        assert!(belongs_to_current_connection(&independent, &control));

        // The ONLY attempted production invalidation since the qualified
        // initial save. It cannot delete the locked file. Capture the target
        // result instead of panicking before recovery and cleanup.
        clear(&root);
        let still_readable = load(&root).expect("fixture: refused deletion leaves readable JSON");
        assert_eq!(still_readable, old);
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert_eq!(crate::selfcheck::load(&root), Some(check.clone()));
        assert!(crate::selfcheck::current_qualified_trade_pass(&root),
            "fixture: no lifecycle/Check change may manufacture denial");
        assert!(original_exit_binding_still_current(&still_readable, &root),
            "fixture: original live binding must independently remain valid");
        no_staging(&root);
        let current_while_locked = belongs_to_current_connection(&still_readable, &root);
        let dirty_after_clear = exit_write_uncommitted(&root);
        let control_while_locked = belongs_to_current_connection(&independent, &control);
        let control_bytes_after_clear = snapshot(&control) == control_before;
        eprintln!("DIRECT_CLEAR_CONTRACT_STAGE: delete_error={delete_error}; raw_os_error={:?}; old_bytes_unchanged=true; old_readable=true; check_live=true; binding_live=true; no_staging=true; current_while_locked={current_while_locked}; dirty_after_clear={dirty_after_clear}; control_current={control_while_locked}; control_bytes_unchanged={control_bytes_after_clear}",
            delete_error.raw_os_error());

        drop(locked);
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert_eq!(load(&root), Some(old.clone()));
        assert!(original_exit_binding_still_current(&old, &root));
        assert!(crate::selfcheck::current_qualified_trade_pass(&root));
        let current_after_unlock = belongs_to_current_connection(&old, &root);
        no_staging(&root);

        // Genuine new authenticated observation on the same session. No
        // retry, no clear of the map, no fake replacement record.
        let recovered = match probe_and_record(&root, &line, &plan, 2_000) {
            Some(record) => record,
            None => {
                let joined = target_server.stop_and_join();
                panic!("fixture: real recovery observation absent; server={joined:?}");
            }
        };
        target_server.finish(3);
        assert_eq!(recovered.ip, "1.1.1.1");
        let recovered_binding_same = recovered.binding == old.binding;
        let recovered_current = belongs_to_current_connection(&recovered, &root);
        let recovered_disk_exact = load(&root).as_ref() == Some(&recovered);
        let recovery_clean = !exit_write_uncommitted(&root);
        no_staging(&root);
        assert_eq!(crate::selfcheck::load(&root), Some(check));
        assert!(crate::selfcheck::current_qualified_trade_pass(&root));
        assert!(original_exit_binding_still_current(&old, &root),
            "old IP alone is not a stale-binding test");
        let control_current_after = belongs_to_current_connection(&independent, &control);
        let control_bytes_after = snapshot(&control) == control_before;
        let control_disk_exact = load(&control).as_ref() == Some(&independent);
        assert_eq!(crate::selfcheck::load(&control), Some(control_check));
        assert!(crate::selfcheck::current_qualified_trade_pass(&control));
        no_staging(&control);
        eprintln!("DIRECT_CLEAR_CONTRACT_RECOVERY: current_after_unlock={current_after_unlock}; new_ip={}; attributed={}; same_binding={recovered_binding_same}; new_disk_exact={recovered_disk_exact}; new_current={recovered_current}; clean={recovery_clean}; control_current={control_current_after}; control_bytes_unchanged={control_bytes_after}; control_disk_exact={control_disk_exact}",
            recovered.ip, recovered.attributed);

        // Cleanup before reporting the target contract verdict. Retain
        // actual failure diagnostics even when the primary assertion fails.
        drop(cleanup);
        assert!(!sandbox.exists(), "fixture: sandbox cleanup");
        assert!(!current_while_locked && !current_after_unlock,
            "TRUE_DIRECT_API_CONTRACT_RED: direct clear deletion refused; readable old record with live original binding still qualifies as CURRENT (locked={current_while_locked}, unlocked={current_after_unlock})");
        assert!(control_while_locked && control_bytes_after_clear && control_current_after
            && control_bytes_after && control_disk_exact,
            "SAFETY: direct clear cannot invalidate or change independent control evidence");
        assert!(recovered.attributed && recovered_binding_same && recovered_disk_exact
            && recovered_current && recovery_clean,
            "SAFETY: genuine same-session producer commit must restore new CURRENT evidence");
    }
}

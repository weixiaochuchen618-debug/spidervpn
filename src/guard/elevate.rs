//! 一次性提权通道（架构 A-1 / §5.1 / T03 DoD 7）。
//!
//! # 形状
//!
//! 提权 = **自身 exe 的一次性子进程**：
//!
//! ```text
//! 父进程（普通权限）
//!   elevate::apply(req)
//!     ├─ 写请求到私有临时文件 req.json（含 nonce，ACL 只给当前用户）
//!     ├─ ShellExecuteExW(lpVerb="runas", SW_HIDE, SEE_MASK_NOCLOSEPROCESS)
//!     ├─ WaitForSingleObject(120s)
//!     ├─ 取退出码：0=成功 / 1223=用户拒绝 / 其它=失败
//!     ├─ 读 res.json（大小上限 + nonce 校验 + JSON）
//!     └─ 删两个临时文件
//!
//! 子进程（提权）
//!   --guard-apply req.json res.json
//!     ├─ 白名单动作（install/sync/remove/verify），别的一律拒绝
//!     ├─ 真实 WFP 事务（见 wfp_win::WindowsWfp）
//!     ├─ 写证据（同一提权会话内的逐条枚举，A19）
//!     └─ 写 res.json + 退出码
//! ```
//!
//! # 为什么不做常驻提权服务
//!
//! 常驻特权面要安装、要自启、要签名与杀软信任、要处理生命周期与升级；而产品约束是
//! 「只在必要时一次、理由可读、可拒绝、失败可见」——那正好就是一次性子进程的形状。
//!
//! # 最重要的两条
//!
//! 1. **`1223 ERROR_CANCELLED` = 用户拒绝，不是失败**。把它记成「出错」会诱导实现者
//!    「重试一次也许就成了」，从而变成 UAC 风暴（PRD §5.3）。
//! 2. **安装 API 的返回值不是证据**。子进程必须把「同一事务里逐条枚举到的结果」写进
//!    证据；只带「成功」二字的回复会被父进程判成 [`ElevateError::BadReply`]（A19）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::evidence::{EvidenceStore, StoreKind};
use super::identity::ProgramIdentity;
use super::state::{GuardEvidence, GuardRecord};
use super::wfp::{WfpError, ERROR_CANCELLED};

/// 子进程入口开关（父进程与子进程共用同一个字面量）。
pub const APPLY_FLAG: &str = "--guard-apply";

/// 请求/回复文件大小上限（8 KiB）。请求里只有几十条路径，超了就是有人在乱写。
pub const MAX_IPC_FILE_BYTES: usize = 8 * 1024;

/// 等子进程的最长时间（秒）。超时**不代表成功**，只代表「无法确认」。
pub const ELEVATE_WAIT_TIMEOUT_SECS: u64 = 120;

/// 一次提权动作的种类。子进程只认这四个，别的一律拒绝（SEC-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardAction {
    /// 安装/补齐（连接前 0.7 步）。
    Install,
    /// 名单变更后的整笔同步（一个事务内全量替换）。
    Sync,
    /// 显式解除（维护页，二次确认之后）。
    Remove,
    /// 只读核验（刷新证据）。
    Verify,
}

impl GuardAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardAction::Install => "install",
            GuardAction::Sync => "sync",
            GuardAction::Remove => "remove",
            GuardAction::Verify => "verify",
        }
    }

    /// 从字符串还原。**白名单**：不认识的一律 `None`（子进程据此拒绝）。
    pub fn parse(text: &str) -> Option<GuardAction> {
        match text.trim().to_ascii_lowercase().as_str() {
            "install" => Some(GuardAction::Install),
            "sync" => Some(GuardAction::Sync),
            "remove" => Some(GuardAction::Remove),
            "verify" => Some(GuardAction::Verify),
            _ => None,
        }
    }
}

/// 请求（父进程 → 子进程，走临时文件）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardRequest {
    pub action: GuardAction,
    pub programs: Vec<ProgramIdentity>,
    /// 用户主动点的（绕过 600 秒抑制窗）。
    pub explicit: bool,
    /// 父进程算出的名单摘要（子进程原样写进证据）。
    pub config_digest: String,
    /// 父进程分配到的一次性标识：写完回读必须对上。
    pub nonce: String,
    pub boot_id: String,
    /// 证据写哪种存储（`Registry` / `IsolatedFile`）。
    pub store_kind: String,
    /// 旧版 旧版当时是否在跑（写进证据，用于冲突态变化判定）。
    pub legacy_running: bool,
    /// 证据记录版本（递增，诊断用）。
    pub record_version: u64,
}

/// 回复（子进程 → 父进程）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardReply {
    /// 逐条枚举结果（`Result` 里包着 `WfpError`，便于父进程区分「拒绝/失败/没权限」）。
    pub result: Result<GuardEvidence, WfpError>,
    /// 给用户看的补充说明（例如「检测到旧版对象但不接管」）。
    pub notes: Vec<String>,
}

/// 提权失败的全部形态。每一种都对应一句**不同**的用户可见结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevateError {
    /// 用户在 UAC 上点了「否」（`1223`）。**不是错误，是拒绝**。
    Declined,
    /// 子进程起不来（`ShellExecuteExW` 失败，或被杀软拦下）。
    SpawnFailed(String),
    /// 子进程起来了但退出码非 0。
    ChildFailed(i32),
    /// 子进程失败，且**它自己写了原因**（`res.json` 的 notes）。
    ///
    /// 只报「退出码 3」等于没报：真正的 WFP 错误名（`WfpError::…`）就在回复文件里，
    /// 而旧实现先删目录再返回，把唯一能看的线索扔了。
    ChildFailedNote(i32, String),
    /// 子进程说成功，但结果文件不合法（缺 nonce / 大小超限 / 解析失败 / 不是逐条枚举）。
    BadReply(String),
    /// 等不到子进程结束。**不许**假设成功。
    Timeout,
}

impl ElevateError {
    /// 用户可见的一句话。**必须**能回答「现在是什么状态、下一步做什么」。
    pub fn message(&self) -> String {
        match self {
            ElevateError::Declined => {
                "本次未启用交易保护（未获得管理员确认）".to_string()
            }
            ElevateError::SpawnFailed(e) => format!("无法启动提权助手，交易保护未启用：{e}"),
            ElevateError::ChildFailed(code) => {
                format!("提权助手报告失败（退出码 {code}），交易保护可能未启用")
            }
            ElevateError::ChildFailedNote(code, note) => {
                format!("提权助手报告失败（退出码 {code}）：{note}")
            }
            ElevateError::BadReply(e) => format!("提权助手的结果无法确认，不能当作成功：{e}"),
            ElevateError::Timeout => {
                "没有等到管理员确认的结果，无法确认交易保护是否已启用".to_string()
            }
        }
    }

    /// 是不是「用户明确拒绝」（→ 本会话不再自动重试，写抑制窗）。
    pub fn is_declined(&self) -> bool {
        matches!(self, ElevateError::Declined)
    }

    /// 稳定键（诊断/操作记录用；不随文案变化）。
    pub fn id(&self) -> &'static str {
        match self {
            ElevateError::Declined => "Declined",
            ElevateError::SpawnFailed(_) => "SpawnFailed",
            ElevateError::ChildFailed(_) | ElevateError::ChildFailedNote(_, _) => "ChildFailed",
            ElevateError::BadReply(_) => "BadReply",
            ElevateError::Timeout => "Timeout",
        }
    }
}

/// `ShellExecuteExW` 失败时的 `GetLastError` → 结局。
///
/// 只有 `1223` 是「拒绝」；其它一律是「起不来」。这条区分**不能合并**。
pub fn classify_spawn_error(native: u32) -> ElevateError {
    if native == ERROR_CANCELLED {
        ElevateError::Declined
    } else {
        ElevateError::SpawnFailed(format!("GetLastError={native}"))
    }
}

/// 子进程退出码 → 结局。`0` = 成功；`1223` = 拒绝；其余 = 失败。
pub fn classify_exit_code(code: i32) -> Option<ElevateError> {
    if code == 0 {
        None
    } else if code == ERROR_CANCELLED as i32 {
        Some(ElevateError::Declined)
    } else {
        Some(ElevateError::ChildFailed(code))
    }
}

/// 本进程是否已提权（与 `probe::elevated` 同判据：能写 HKLM\SOFTWARE 就是）。
pub fn is_elevated() -> bool {
    crate::probe::elevated()
}

// ---------------------------------------------------------------------------
// 请求/回复文件的读写（大小上限 + nonce + 严格 JSON）
// ---------------------------------------------------------------------------

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_IPC_FILE_BYTES {
        return Err(format!("请求/回复超过 {} 字节上限", MAX_IPC_FILE_BYTES));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("建临时目录失败：{e}"))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("写临时文件失败：{e}"))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("读临时文件失败：{e}"))?;
    if meta.len() as usize > MAX_IPC_FILE_BYTES {
        return Err(format!("临时文件超过 {} 字节上限", MAX_IPC_FILE_BYTES));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("读临时文件失败：{e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("临时文件不是合法 JSON：{e}"))
}

fn temp_pair(nonce: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("SpiderVPN-guard-{}", ci_safe(nonce)));
    (dir.join("req.json"), dir.join("res.json"))
}

fn ci_safe(text: &str) -> String {
    text.chars().filter(|c| c.is_ascii_alphanumeric()).take(32).collect()
}

// ---------------------------------------------------------------------------
// 父进程侧：起子进程
// ---------------------------------------------------------------------------

/// 起提权子进程执行一次动作。**唯一的提权入口**。
///
/// **所有** action 都走提权，`Verify` 也不例外：它虽然不装/删 WFP 规则，但要把核验结果
/// 写进证据存储（`GuardSource::ElevatedVerify`）并刷新时龄，所以它同样是写动作。
/// 历史上这里有过 `GuardAction::writes()` 声称「只读核验不值得让用户点一次 UAC」，
/// 但 `apply()` 从未按它分支，生产代码也没人调用——那是没被实现的意图，已删除
/// （2026-11-06，r25）。`tests/acceptance-guard.ps1` 的 A2/A3 曾按那条意图写预期，
/// 因此把「非提权 verify 会弹 UAC → 点否 = Declined」误判成 `NoPermission`。
pub fn apply(req: &GuardRequest) -> Result<GuardReply, ElevateError> {
    let (req_path, res_path) = temp_pair(&req.nonce);
    // 上次残留（同 nonce 几乎不可能，但删掉更干净）
    let _ = std::fs::remove_file(&res_path);
    write_json_file(&req_path, req).map_err(ElevateError::SpawnFailed)?;

    let exe = std::env::current_exe().map_err(|e| ElevateError::SpawnFailed(e.to_string()))?;
    let code = run_elevated(&exe, &req_path, &res_path)?;

    // 先看退出码：非 0 一律失败。**失败也要读回复**——子进程把真正的原因写在
    // `notes` 里（例如 `WfpError::InvalidState`），只报退出码等于把唯一线索扔掉。
    if let Some(err) = classify_exit_code(code) {
        let note = read_json_file::<GuardReply>(&res_path)
            .ok()
            .and_then(|reply| {
                let joined = reply.notes.join("；");
                if joined.trim().is_empty() { None } else { Some(joined) }
            });
        let _ = std::fs::remove_dir_all(req_path.parent().unwrap_or(Path::new(".")));
        return Err(match note {
            Some(note) => ElevateError::ChildFailedNote(code, note),
            None => err,
        });
    }
    let reply: GuardReply = match read_json_file(&res_path) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_dir_all(req_path.parent().unwrap_or(Path::new(".")));
            return Err(ElevateError::BadReply(e));
        }
    };
    // 回复里的证据必须带来源（A19：安装 API 的返回值不算证据）
    if let Ok(ev) = &reply.result {
        if ev.source == super::state::GuardSource::None {
            let _ = std::fs::remove_dir_all(req_path.parent().unwrap_or(Path::new(".")));
            return Err(ElevateError::BadReply("回复缺少证据来源".to_string()));
        }
    }
    let _ = std::fs::remove_dir_all(req_path.parent().unwrap_or(Path::new(".")));
    Ok(reply)
}

#[cfg(windows)]
fn run_elevated(exe: &Path, req: &Path, res: &Path) -> Result<i32, ElevateError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let wide = |s: &std::ffi::OsStr| -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0u16)).collect()
    };
    let file = wide(exe.as_os_str());
    let params = wide(
        std::ffi::OsStr::new(&format!(
            "{APPLY_FLAG} \"{}\" \"{}\"",
            req.display(),
            res.display()
        )),
    );
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0u16)).collect();

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    // runas = 触发 UAC；SW_HIDE = 不闪黑窗；NOCLOSEPROCESS = 我们要拿进程句柄等它。
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(classify_spawn_error(err));
    }
    if info.hProcess.is_null() {
        return Err(ElevateError::SpawnFailed("没有拿到子进程句柄".to_string()));
    }
    let handle: HANDLE = info.hProcess;
    // 等它结束（上限 120 秒）。超时 = 无法确认，不是成功。
    let wait = unsafe { WaitForSingleObject(handle, (ELEVATE_WAIT_TIMEOUT_SECS * 1000) as u32) };
    if wait != 0 {
        unsafe { CloseHandle(handle) };
        let _ = INFINITE; // 保留常量引用，避免误改成无限等待
        return Err(ElevateError::Timeout);
    }
    let mut code: u32 = 1;
    let got = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe { CloseHandle(handle) };
    if got == 0 {
        return Err(ElevateError::ChildFailed(-1));
    }
    Ok(code as i32)
}

#[cfg(not(windows))]
fn run_elevated(_exe: &Path, _req: &Path, _res: &Path) -> Result<i32, ElevateError> {
    Err(ElevateError::SpawnFailed("当前平台不支持提权".to_string()))
}

// ---------------------------------------------------------------------------
// 子进程侧：--guard-apply
// ---------------------------------------------------------------------------

/// 子进程入口。返回进程退出码（0 = 成功；非 0 = 失败；`1223` 由父进程从 shell 侧拿）。
///
/// **只接受白名单动作**；任何解析/校验失败都写「失败回复」并返回非 0——
/// 退出码是权威，回复只是给人看的补充。
pub fn guard_apply_main(req_path: &Path, res_path: &Path, backend: &dyn super::GuardBackend) -> i32 {
    let req: GuardRequest = match read_json_file(req_path) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_json_file(
                res_path,
                &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
            );
            return 2;
        }
    };
    // 白名单：动作解析是从枚举来的（反序列化已经过滤），这里再确认一次它确实是四种之一。
    if GuardAction::parse(req.action.as_str()).is_none() {
        let _ = write_json_file(
            res_path,
            &GuardReply {
                result: Err(WfpError::InvalidState),
                notes: vec![format!("不支持的动作：{}", req.action.as_str())],
            },
        );
        return 2;
    }
    if req.programs.len() > super::MAX_PROGRAMS {
        let _ = write_json_file(
            res_path,
            &GuardReply {
                result: Err(WfpError::InvalidState),
                notes: vec![format!("程序数量超过 {} 上限", super::MAX_PROGRAMS)],
            },
        );
        return 2;
    }

    let store_kind = StoreKind::parse(&req.store_kind).unwrap_or(StoreKind::Registry);
    let expect = super::Expect {
        boot_id: req.boot_id.clone(),
        config_digest: req.config_digest.clone(),
        store_kind,
        legacy_running: req.legacy_running,
    };

    // 真实动作（在提权会话里跑）
    let outcome = match req.action {
        GuardAction::Install => backend.install(&req.programs, &expect),
        GuardAction::Sync => backend.sync(&req.programs, &expect),
        GuardAction::Verify => backend.read(&req.programs, &expect),
        GuardAction::Remove => backend.remove(),
    };

    match outcome {
        Err(err) => {
            let _ = write_json_file(
                res_path,
                &GuardReply { result: Err(err), notes: vec![err.message()] },
            );
            3
        }
        Ok(mut ev) => {
            // 子进程补上「谁核验的、什么时候、哪种存储」
            ev.boot_id = req.boot_id.clone();
            ev.config_digest = req.config_digest.clone();
            ev.legacy_running_at_verify = req.legacy_running;
            ev.store_kind = store_kind.as_str().to_string();
            ev.source = match req.action {
                GuardAction::Install => super::GuardSource::ElevatedInstallReadback,
                GuardAction::Sync => super::GuardSource::ElevatedInstallReadback,
                GuardAction::Verify => super::GuardSource::ElevatedVerify,
                // 解除没有「证据」可言：用 ElevatedVerify 表示「这次是提权读回的」
                GuardAction::Remove => super::GuardSource::ElevatedVerify,
            };
            ev.verified_at_epoch = Some(super::now_epoch());
            ev.verified_at_tick_ms = Some(super::tick_ms());

            // 写证据：**只有提权会话内**做得到（HKLM 可写）。
            let store: Box<dyn EvidenceStore> = match evidence_store_for(&req) {
                Ok(s) => s,
                Err(e) => {
                    let _ = write_json_file(
                        res_path,
                        &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
                    );
                    return 5;
                }
            };
            if matches!(req.action, GuardAction::Remove) {
                // 解除成功（backend.remove 已回读 ProviderPresent=false）：
                // 1) 先写同键的 `Removed` 标记（用户意图，跨下次打开仍在）；
                // 2) 再删除 `Evidence` 值——旧证据物理上不存在，才不会被回灌成 Protected。
                let marker = super::RemovedMarker::new(
                    &super::state::iso8601_utc_millis(super::now_epoch()),
                    "ElevatedRemove",
                );
                if let Err(e) = store.write_removed(&marker) {
                    let _ = write_json_file(
                        res_path,
                        &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
                    );
                    return 4;
                }
                if let Err(e) = store.invalidate("user-remove") {
                    let _ = write_json_file(
                        res_path,
                        &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
                    );
                    return 4;
                }
            } else {
                let rec = GuardRecord::from_evidence(
                    &ev,
                    &req.nonce,
                    std::process::id(),
                    true,
                    req.record_version,
                );
                if let Err(e) = store.write(&rec) {
                    let _ = write_json_file(
                        res_path,
                        &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
                    );
                    return 4;
                }
                // 安装/核验成功 → 清掉「已解除」标记（Q8：下次连接重新启用）
                let _ = store.clear_removed();
            }
            let _ = write_json_file(res_path, &GuardReply { result: Ok(ev), notes: Vec::new() });
            0
        }
    }
}

/// 子进程该写哪种存储：与父进程一致（由请求里的 `store_kind` 决定）。
///
/// 生产走 [`super::select`]；隔离环境（`SPIDERVPN_ROOT`）走文件 store——
/// 子进程继承了父进程的环境变量，所以两边看到的是同一个 store。
fn evidence_store_for(_req: &GuardRequest) -> Result<Box<dyn EvidenceStore>, String> {
    let root = std::env::var("SPIDERVPN_ROOT").unwrap_or_default();
    let root = if root.trim().is_empty() {
        // 生产：不需要数据根（走注册表）
        PathBuf::from(".")
    } else {
        PathBuf::from(root)
    };
    super::evidence::select(&root).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_cancel_is_declined_not_failure() {
        assert_eq!(classify_spawn_error(1223), ElevateError::Declined);
        assert_eq!(classify_exit_code(1223), Some(ElevateError::Declined));
        assert!(classify_spawn_error(1223).is_declined());
        assert!(ElevateError::Declined.message().contains("未获得管理员确认"));
        assert!(!ElevateError::Declined.message().contains("出错"));
    }

    #[test]
    fn other_spawn_errors_are_not_declined() {
        for code in [2u32, 5, 740, 1053] {
            let e = classify_spawn_error(code);
            assert!(!e.is_declined(), "只有 1223 是拒绝：{code}");
            assert!(matches!(e, ElevateError::SpawnFailed(_)));
            assert!(e.message().contains("未启用"));
        }
    }

    #[test]
    fn exit_codes_map_to_success_or_child_failure() {
        assert_eq!(classify_exit_code(0), None, "0 = 成功");
        assert_eq!(classify_exit_code(3), Some(ElevateError::ChildFailed(3)));
        assert_eq!(classify_exit_code(-1), Some(ElevateError::ChildFailed(-1)));
        assert!(ElevateError::ChildFailed(3).message().contains('3'));
        assert!(ElevateError::Timeout.message().contains("无法确认"));
        assert!(ElevateError::BadReply("缺 nonce".into()).message().contains("不能当作成功"));
    }

    #[test]
    fn actions_are_whitelisted() {
        assert_eq!(GuardAction::parse("install"), Some(GuardAction::Install));
        assert_eq!(GuardAction::parse(" SYNC "), Some(GuardAction::Sync));
        assert_eq!(GuardAction::parse("remove"), Some(GuardAction::Remove));
        assert_eq!(GuardAction::parse("verify"), Some(GuardAction::Verify));
        for bad in ["", "exec", "cmd", "install; rm -rf", "powershell"] {
            assert_eq!(GuardAction::parse(bad), None, "不该接受：{bad}");
        }
    }

    #[test]
    fn error_ids_are_stable_and_unique() {
        let all = [
            ElevateError::Declined,
            ElevateError::SpawnFailed("x".into()),
            ElevateError::ChildFailed(1),
            ElevateError::BadReply("x".into()),
            ElevateError::Timeout,
        ];
        let mut ids: Vec<&str> = all.iter().map(|e| e.id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
        for e in all {
            assert!(!e.message().is_empty());
        }
    }

    #[test]
    fn request_and_reply_round_trip_through_a_file() {
        let dir = std::env::temp_dir().join(format!("tcrs-apply-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let req = GuardRequest {
            action: GuardAction::Verify,
            programs: Vec::new(),
            explicit: true,
            config_digest: "d".into(),
            nonce: "n1".into(),
            boot_id: "b1".into(),
            store_kind: "IsolatedFile".into(),
            legacy_running: false,
            record_version: 3,
        };
        let path = dir.join("req.json");
        write_json_file(&path, &req).unwrap();
        let back: GuardRequest = read_json_file(&path).unwrap();
        assert_eq!(back, req);
        // 超过上限直接拒绝
        let big = "x".repeat(MAX_IPC_FILE_BYTES + 10);
        let err = write_json_file(&dir.join("big.json"), &big).unwrap_err();
        assert!(err.contains("上限"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tampered_or_truncated_reply_is_a_bad_reply_not_a_success() {
        let dir = std::env::temp_dir().join(format!("tcrs-apply2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("res.json");
        std::fs::write(&path, b"{\"result\":").unwrap();
        assert!(read_json_file::<GuardReply>(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

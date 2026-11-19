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
use super::identity::{resolve_entry, IdentityEnv, ProgramIdentity};
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
// 已打开文件的硬链接安全检查（符号链接/reparse 校验不能覆盖 hard link）。
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn require_single_link(file: &std::fs::File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(format!(
            "无法核验提权 IPC 文件的硬链接计数：{}",
            std::io::Error::last_os_error()
        ));
    }
    if info.nNumberOfLinks != 1 {
        return Err("提权 IPC 文件存在其它硬链接，拒绝读写".into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn require_single_link(_file: &std::fs::File) -> Result<(), String> {
    // 此 helper 只在 Windows 产品中实际提权；非 Windows 用于纯逻辑测试。
    Ok(())
}

// ---------------------------------------------------------------------------
// 请求/回复文件的读写（大小上限 + nonce + 严格 JSON）
// ---------------------------------------------------------------------------

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), String> {
    use std::io::Write;
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_IPC_FILE_BYTES {
        return Err(format!("请求/回复超过 {} 字节上限", MAX_IPC_FILE_BYTES));
    }
    // 只允许本次调用写一次：不存在“上一笔的回复”可以覆盖/复用。
    // 先创建空文件，再收紧 DACL，最后才写 JSON；不留敏感窗口。
    // Windows 原生创建同时携带受保护 DACL；不允许先创建开放文件再补权限。
    let mut file = crate::secretfile::create_private_ipc_file(path)
        .map_err(|e| format!("建立受保护临时文件失败：{e}"))?;
    if let Err(err) = require_single_link(&file) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(err);
    }
    if let Err(err) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("写临时文件失败：{err}"));
    }
    Ok(())
}

/// 普通权限主进程先创建“受保护的空回执”，保证它仍是文件 owner。
/// 提权后的管理员可向这份文件写入，但绝不创建一个主程序无法读取的新文件。
fn prepare_reply_file(path: &Path) -> Result<(), String> {
    // 创建这一瞬间就应用 owner/admin/SYSTEM 私有 DACL，文件不曾可由他人打开。
    let file = crate::secretfile::create_private_ipc_file(path)
        .map_err(|e| format!("建立受保护提权回执文件失败：{e}"))?;
    drop(file);
    Ok(())
}

/// 只准填充主程序建立的空回执。不能任意创建或覆盖其他文件。
fn write_reply_file(path: &Path, value: &impl Serialize) -> Result<(), String> {
    use std::io::Write;
    let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if data.len() > MAX_IPC_FILE_BYTES {
        return Err("提权回执超出大小上限".into());
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("受保护的回执文件不存在：{e}"))?;
    if !meta.file_type().is_file() || meta.len() != 0 {
        return Err("提权回执必须是已建立且尚未写入的空普通文件".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT，不能通过换成符号链接劫持管理员写入。
        options.custom_flags(0x0020_0000);
    }
    let mut file = options.open(path).map_err(|e| format!("打开回执文件失败：{e}"))?;
    let live_meta = file.metadata().map_err(|e| e.to_string())?;
    if !live_meta.is_file() || live_meta.len() != 0 {
        return Err("回执句柄不是预先创建的空普通文件，拒绝写入".into());
    }
    require_single_link(&file)?;
    file.write_all(&data).and_then(|_| file.sync_all())
        .map_err(|e| format!("写回执文件失败：{e}"))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("读临时文件失败：{e}"))?;
    if !meta.file_type().is_file() || meta.len() == 0
        || meta.len() as usize > MAX_IPC_FILE_BYTES
    {
        return Err("临时请求必须是非空、大小受限的普通文件（不允许链接）".into());
    }
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file = opts.open(path).map_err(|e| format!("打开临时文件失败：{e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("临时文件句柄并非普通文件".into());
    }
    require_single_link(&file)?;
    let mut data = Vec::new();
    file.take(MAX_IPC_FILE_BYTES as u64 + 1).read_to_end(&mut data)
        .map_err(|e| format!("读临时文件失败：{e}"))?;
    if data.is_empty() || data.len() > MAX_IPC_FILE_BYTES {
        return Err("临时文件在读取时超出大小上限或为空".into());
    }
    serde_json::from_slice(&data).map_err(|e| format!("临时文件不是合法 JSON：{e}"))
}

/// 受保护的独立 IPC 会话。只清理本会话创建的两个文件与目录，
/// 不能对可能被替换的路径递归 remove_dir_all。
struct GuardIpcFiles {
    dir: PathBuf,
    req: PathBuf,
    res: PathBuf,
}
impl Drop for GuardIpcFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.req);
        let _ = std::fs::remove_file(&self.res);
        let _ = std::fs::remove_dir(&self.dir);
    }
}
impl GuardIpcFiles {
    fn create(req: &GuardRequest) -> Result<Self, String> {
        use ring::rand::{SecureRandom, SystemRandom};
        use sha2::{Digest, Sha256};
        let mut token = [0u8; 16];
        SystemRandom::new().fill(&mut token)
            .map_err(|_| "无法生成安全的 Guard IPC 会话标识".to_string())?;
        let nonce: String = token.iter().map(|b| format!("{b:02x}")).collect();
        // 请求字节的 SHA256 被写入 UAC 子进程命令行中不可变的目录名。
        // 即便同用户恶意进程可改写请求文件，也不能修改已发起进程的 argv。
        let encoded = serde_json::to_vec(req).map_err(|e| e.to_string())?;
        let digest = Sha256::digest(&encoded);
        let hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("SpiderVPN-guard-{nonce}-{hash}"));
        // create_dir 不会重用已有目录；任何碰撞或恶意预占都拒绝。
        crate::secretfile::create_private_ipc_dir(&dir)
            .map_err(|e| format!("创建受保护独立提权目录失败：{e}"))?;
        Ok(Self { req: dir.join("req.json"), res: dir.join("res.json"), dir })
    }
}

/// 提权子进程从 argv 所绑定的 SHA256 校验**本次读取的确切字节**，
/// 同一份字节再反序列化；不得验证完文件路径后又重新从磁盘读一次。
fn read_attested_guard_request(path: &Path) -> Result<GuardRequest, String> {
    use sha2::{Digest, Sha256};
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("提权请求不存在：{e}"))?;
    if !meta.file_type().is_file() || meta.len() == 0
        || meta.len() as usize > MAX_IPC_FILE_BYTES
    {
        return Err("提权请求必须是大小受限的普通文件".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut input = options.open(path)
        .map_err(|e| format!("读取提权请求失败：{e}"))?;
    if !input.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("提权请求文件句柄不是普通文件".into());
    }
    require_single_link(&input)?;
    use std::io::Read;
    let mut data = Vec::new();
    input.by_ref().take(MAX_IPC_FILE_BYTES as u64 + 1)
        .read_to_end(&mut data).map_err(|e| e.to_string())?;
    if data.is_empty() || data.len() > MAX_IPC_FILE_BYTES {
        return Err("提权请求读取时长度异常".into());
    }
    let dirname = path.parent().and_then(|p| p.file_name())
        .and_then(|v| v.to_str()).ok_or("提权请求目录无效")?;
    let Some((_, expected_hash)) = dirname.rsplit_once('-') else {
        return Err("缺少提权请求摘要".into());
    };
    let calculated = Sha256::digest(&data);
    let digest: String = calculated.iter().map(|b| format!("{b:02x}")).collect();
    if digest != expected_hash {
        return Err("提权请求内容与 UAC 启动时绑定的 SHA256 不符，拒绝执行".into());
    }
    serde_json::from_slice(&data)
        .map_err(|e| format!("提权请求 JSON 无效：{e}"))
}

fn validate_guard_ipc_paths(req: &Path, res: &Path) -> Result<(), String> {
    use std::path::Component;
    if !req.is_absolute() || !res.is_absolute() {
        return Err("提权请求与回复必须使用绝对路径".into());
    }
    if req.file_name().and_then(|v| v.to_str()) != Some("req.json")
        || res.file_name().and_then(|v| v.to_str()) != Some("res.json")
        || req.parent() != res.parent()
    {
        return Err("提权请求与回复必须位于同一独立目录，且文件名固定".into());
    }
    if req.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || res.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("提权 IPC 路径不能包含相对跳转".into());
    }
    let dir = req.parent().ok_or("提权请求缺少父目录")?;
    let name = dir.file_name().and_then(|v| v.to_str()).unwrap_or("");
    let Some(suffix) = name.strip_prefix("SpiderVPN-guard-") else {
        return Err("未知 Guard IPC 目录命名".into());
    };
    let Some((nonce, hash)) = suffix.split_once('-') else {
        return Err("Guard IPC 缺少请求内容摘要".into());
    };
    if nonce.len() != 32 || !nonce.bytes().all(|c| c.is_ascii_hexdigit())
        || hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("Guard IPC 目录必须使用独立随机标识与 SHA256 摘要".into());
    }
    if !std::fs::symlink_metadata(dir)
        .map_err(|e| format!("读取提权目录失败：{e}"))?.file_type().is_dir()
    {
        return Err("Guard IPC 目录不能是链接或非目录对象".into());
    }
    #[cfg(windows)]
    {
        use super::identity::{reparse_chain, IdentityEnv};
        let env = super::wfp_win::SystemIdentityEnv::new();
        if reparse_chain(req).iter().any(|p| env.is_reparse_point(p))
            || reparse_chain(res).iter().any(|p| env.is_reparse_point(p))
        {
            return Err("提权 IPC 路径包含目录联接或重解析点".into());
        }
        // 路径与 SHA256 均正确也不能信任已经被放宽的 DACL。
        // 审核发生在提权子进程触碰 Guard backend 之前，失败即拒绝。
        for path in [dir, req, res] {
            crate::secretfile::verify_private_ipc_acl(path)?;
        }
    }
    Ok(())
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
    let files = GuardIpcFiles::create(req).map_err(ElevateError::SpawnFailed)?;
    let (req_path, res_path) = (&files.req, &files.res);
    write_json_file(req_path, req).map_err(ElevateError::SpawnFailed)?;
    prepare_reply_file(res_path).map_err(ElevateError::SpawnFailed)?;

    let exe = std::env::current_exe().map_err(|e| ElevateError::SpawnFailed(e.to_string()))?;
    let code = run_elevated(&exe, req_path, res_path)?;

    // 先看退出码：非 0 一律失败。**失败也要读回复**——子进程把真正的原因写在
    // `notes` 里（例如 `WfpError::InvalidState`），只报退出码等于把唯一线索扔掉。
    if let Some(err) = classify_exit_code(code) {
        let note = read_json_file::<GuardReply>(&res_path)
            .ok()
            .and_then(|reply| {
                let joined = reply.notes.join("；");
                if joined.trim().is_empty() { None } else { Some(joined) }
            });
        return Err(match note {
            Some(note) => ElevateError::ChildFailedNote(code, note),
            None => err,
        });
    }
    let reply: GuardReply = match read_json_file(&res_path) {
        Ok(v) => v,
        Err(e) => {
                return Err(ElevateError::BadReply(e));
        }
    };
    // 回复里的证据必须带来源（A19：安装 API 的返回值不算证据）
    if let Ok(ev) = &reply.result {
        if ev.source == super::state::GuardSource::None {
                return Err(ElevateError::BadReply("回复缺少证据来源".to_string()));
        }
    }
    Ok(reply)
}

#[cfg(windows)]
fn run_elevated(exe: &Path, req: &Path, res: &Path) -> Result<i32, ElevateError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
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
    if wait != WAIT_OBJECT_0 {
        // 之前超时仅丢失 handle，但高权限子进程可能仍继续改变 WFP。
        // 尽力终止并等待其退出；无法终止时按“未知、未保护”对待，不认成功。
        if wait == WAIT_TIMEOUT {
            unsafe {
                TerminateProcess(handle, 1);
                WaitForSingleObject(handle, 5_000);
            }
        }
        unsafe { CloseHandle(handle) };
        return if wait == WAIT_TIMEOUT {
            Err(ElevateError::Timeout)
        } else {
            Err(ElevateError::ChildFailed(-1))
        };
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

/// 提权子进程不得从父进程的 JSON 自由选择证据存储：
/// release 必须使用 Registry；仅测试/调试 build 且显式设置
/// SPIDERVPN_ROOT 时才允许 IsolatedFile。必须在调用 WFP backend 前验证。
fn validate_elevated_store_kind(kind: StoreKind) -> Result<(), String> {
    let required = if crate::isolation::dev_root_override().is_some() {
        StoreKind::IsolatedFile
    } else {
        StoreKind::Registry
    };
    if kind != required {
        return Err(format!(
            "提权请求存储类型 {} 与运行环境预期 {} 不一致",
            kind.as_str(), required.as_str()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 提权边界：请求中只信任“要处理的程序路径”，不信任其自称的 WFP AppId。
// Remove 不需要 AppId，不能因为用户删除了旧 exe 就使解除功能失效。
// ---------------------------------------------------------------------------

fn validate_elevated_programs(
    req: &GuardRequest,
    env: &dyn IdentityEnv,
) -> Result<(), String> {
    if req.programs.len() > super::MAX_PROGRAMS {
        return Err(format!("程序数量超过 {} 上限", super::MAX_PROGRAMS));
    }
    if matches!(req.action, GuardAction::Remove) {
        // Remove 操作只删除我方 provider 自有对象；身份列表不作为删除条件。
        // 保留旧行为：即使目标 exe 已卸载也仍然可以解除 WFP 持久规则。
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    for entry in &req.programs {
        if !super::identity::looks_like_bare_name(&entry.name) {
            return Err("提权请求中的交易程序名称不是有效文件名".into());
        }
        let path = entry.path.to_str()
            .ok_or_else(|| "交易程序路径含无法检查的 Unicode 字符".to_string())?;
        let resolved = resolve_entry(&entry.name, Some(path), env)
            .map_err(|e| format!("交易程序「{}」身份重新核验失败：{}", entry.name, e.reason()))?;
        if entry.path != resolved.path
            || entry.app_id != resolved.app_id
            || entry.device_path != resolved.device_path
        {
            return Err(format!(
                "交易程序「{}」WFP AppId/设备路径与系统实际身份不符，拒绝提权请求",
                entry.name
            ));
        }
        if !seen.insert(resolved.app_id) {
            return Err("交易程序名单存在重复的 WFP AppId，拒绝歧义规则集".into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 子进程侧：--guard-apply
// ---------------------------------------------------------------------------

/// 子进程入口。返回进程退出码（0 = 成功；非 0 = 失败；`1223` 由父进程从 shell 侧拿）。
///
/// **只接受白名单动作**；任何解析/校验失败都写「失败回复」并返回非 0——
/// 退出码是权威，回复只是给人看的补充。
pub fn guard_apply_main(req_path: &Path, res_path: &Path, backend: &dyn super::GuardBackend) -> i32 {
    // 任何请求文件读取、错误回复写入之前验证固定路径与 reparse 链。
    // 未验证的外部路径不能被提权进程当成“错误回复位置”写入。
    if validate_guard_ipc_paths(req_path, res_path).is_err() {
        return 2;
    }
    let req: GuardRequest = match read_attested_guard_request(req_path) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_reply_file(
                res_path,
                &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
            );
            return 2;
        }
    };
    // 白名单：动作解析是从枚举来的（反序列化已经过滤），这里再确认一次它确实是四种之一。
    if GuardAction::parse(req.action.as_str()).is_none() {
        let _ = write_reply_file(
            res_path,
            &GuardReply {
                result: Err(WfpError::InvalidState),
                notes: vec![format!("不支持的动作：{}", req.action.as_str())],
            },
        );
        return 2;
    }
    // 此处已经处于高权限上下文。不能直接使用低权限父进程写进
    // JSON 的 AppId / device_path：必须由 Windows 现场重新派生并逐项比对。
    if let Err(reason) = validate_elevated_programs(
        &req, &super::wfp_win::SystemIdentityEnv::new(),
    ) {
        let _ = write_reply_file(
            res_path,
            &GuardReply { result: Err(WfpError::InvalidState), notes: vec![reason] },
        );
        return 2;
    }

    // 未知 StoreKind 不能静默降级为 Registry：防止伪造请求写错证据位置。
    let Some(store_kind) = StoreKind::parse(&req.store_kind) else {
        let _ = write_reply_file(
            res_path,
            &GuardReply {
                result: Err(WfpError::InvalidState),
                notes: vec!["不支持的 Guard 证据存储类型".into()],
            },
        );
        return 2;
    };
    if let Err(reason) = validate_elevated_store_kind(store_kind) {
        let _ = write_reply_file(
            res_path,
            &GuardReply {
                result: Err(WfpError::InvalidState),
                notes: vec![reason],
            },
        );
        return 2;
    }
    let expect = super::Expect {
        boot_id: req.boot_id.clone(),
        config_digest: req.config_digest.clone(),
        store_kind,
        legacy_running: req.legacy_running,
    };

    // The final executor, not the waiting UAC parent, owns these locks.
    // Acquire lifecycle first, then the existing shared Guard mutex. Both
    // stay live through backend, evidence mutation/readback and reply.
    let _lifecycle = match super::lifecycle_gate::LifecycleGate::acquire() {
        Ok(gate) => gate,
        Err(reason) => {
            let _ = write_reply_file(res_path, &GuardReply {
                result: Err(WfpError::InvalidState), notes: vec![reason],
            });
            return 3;
        }
    };
    let _short_guard = match super::acquire_guard_mutex() {
        Ok(gate) => gate,
        Err(reason) => {
            let _ = write_reply_file(res_path, &GuardReply {
                result: Err(WfpError::InvalidState),
                notes: vec![format!("G1_SHORT_LOCK: {reason}")],
            });
            return 3;
        }
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
            let _ = write_reply_file(
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
                    let _ = write_reply_file(
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
                    let _ = write_reply_file(
                        res_path,
                        &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
                    );
                    return 4;
                }
                if let Err(e) = store.invalidate("user-remove") {
                    let _ = write_reply_file(
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
                    let _ = write_reply_file(
                        res_path,
                        &GuardReply { result: Err(WfpError::InvalidState), notes: vec![e] },
                    );
                    return 4;
                }
                // 安装/核验成功 → 清掉「已解除」标记（Q8：下次连接重新启用）
                let _ = store.clear_removed();
            }
            // 回执是调用方确认这次提升操作的唯一返回通道。
            // 如果 WFP/证据写入成功但回执失败，绝不能退出 0 假装全程成功。
            match write_reply_file(res_path, &GuardReply { result: Ok(ev), notes: Vec::new() }) {
                Ok(()) => 0,
                Err(_) => 6,
            }
        }
    }
}

/// 子进程该写哪种存储：与父进程一致（由请求里的 `store_kind` 决定）。
///
/// 生产走 [`super::select`]；隔离环境（`SPIDERVPN_ROOT`）走文件 store——
/// 子进程继承了父进程的环境变量，所以两边看到的是同一个 store。
fn evidence_store_for(_req: &GuardRequest) -> Result<Box<dyn EvidenceStore>, String> {
    // 由编译模式和隔离测试入口决定，绝不读取未经审查的 release 环境变量。
    let root = crate::isolation::dev_root_override()
        .unwrap_or_else(|| PathBuf::from("."));
    super::evidence::select(&root).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeIdentityEnv;
    impl IdentityEnv for FakeIdentityEnv {
        fn exists(&self, path: &Path) -> bool {
            path == Path::new(r"C:\safe\trader.exe")
        }
        fn is_reparse_point(&self, _path: &Path) -> bool { false }
        fn app_id(&self, _path: &Path) -> Result<Vec<u8>, super::super::identity::IdentityError> {
            Ok("trusted-device-path\0".encode_utf16().flat_map(u16::to_le_bytes).collect())
        }
    }

    fn identity_request(action: GuardAction) -> GuardRequest {
        let id = resolve_entry("trader.exe", Some(r"C:\safe\trader.exe"), &FakeIdentityEnv)
            .expect("fake identity resolves");
        GuardRequest {
            action, programs: vec![id], explicit: true, config_digest: "digest".into(),
            nonce: "once".into(), boot_id: "boot".into(),
            store_kind: "Registry".into(), legacy_running: false, record_version: 1,
        }
    }

    #[test]
    fn elevated_guard_rederives_wfp_appid_and_rejects_tampered_identity() {
        let req = identity_request(GuardAction::Install);
        assert!(validate_elevated_programs(&req, &FakeIdentityEnv).is_ok());

        let mut changed = req.clone();
        changed.programs[0].app_id[0] ^= 1;
        assert!(validate_elevated_programs(&changed, &FakeIdentityEnv).is_err(),
            "篡改的 APP_ID 必须在任何 WFP 写操作之前被拒绝");

        changed = req.clone();
        changed.programs[0].device_path.push_str("-forged");
        assert!(validate_elevated_programs(&changed, &FakeIdentityEnv).is_err());

        changed = req.clone();
        changed.programs[0].path = PathBuf::from(r"C:\wrong\trader.exe");
        assert!(validate_elevated_programs(&changed, &FakeIdentityEnv).is_err());

        changed = req.clone();
        changed.programs.push(changed.programs[0].clone());
        assert!(validate_elevated_programs(&changed, &FakeIdentityEnv).is_err(),
            "不能接受重复交易程序身份");
    }

    #[test]
    fn elevated_remove_does_not_depend_on_deleted_trader_exe() {
        let mut req = identity_request(GuardAction::Remove);
        req.programs[0].path = PathBuf::from(r"C:\deleted\trader.exe");
        assert!(validate_elevated_programs(&req, &FakeIdentityEnv).is_ok(),
            "卸载交易软件之后仍必须能删除自有持久 WFP 规则");
        req.programs = vec![req.programs[0].clone(); super::super::MAX_PROGRAMS + 1];
        assert!(validate_elevated_programs(&req, &FakeIdentityEnv).is_err());
    }

    struct CountingBackend(std::sync::atomic::AtomicUsize);
    impl super::super::GuardBackend for CountingBackend {
        fn available(&self) -> bool { true }
        fn read(&self, _: &[ProgramIdentity], _: &super::super::Expect)
            -> Result<GuardEvidence, WfpError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(WfpError::InvalidState)
        }
        fn install(&self, _: &[ProgramIdentity], _: &super::super::Expect)
            -> Result<GuardEvidence, WfpError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(WfpError::InvalidState)
        }
        fn sync(&self, _: &[ProgramIdentity], _: &super::super::Expect)
            -> Result<GuardEvidence, WfpError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(WfpError::InvalidState)
        }
        fn remove(&self) -> Result<GuardEvidence, WfpError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(WfpError::InvalidState)
        }
    }

    #[test]
    fn elevated_entry_rejects_modified_request_before_any_wfp_backend_call() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut req = test_ipc_request();
        let files = GuardIpcFiles::create(&req).unwrap();
        write_json_file(&files.req, &req).unwrap();
        prepare_reply_file(&files.res).unwrap();
        req.action = GuardAction::Remove;
        std::fs::write(&files.req, serde_json::to_vec(&req).unwrap()).unwrap();

        let backend = CountingBackend(AtomicUsize::new(0));
        assert_eq!(guard_apply_main(&files.req, &files.res, &backend), 2);
        assert_eq!(backend.0.load(Ordering::SeqCst), 0,
            "被替换的请求不允许调用任何 WFP 后端动作");
    }

    #[test]
    fn valid_but_wrong_elevated_store_kind_is_rejected_before_wfp() {
        let expected = if crate::isolation::dev_root_override().is_some() {
            StoreKind::IsolatedFile
        } else {
            StoreKind::Registry
        };
        let mismatched = if expected == StoreKind::Registry {
            StoreKind::IsolatedFile
        } else {
            StoreKind::Registry
        };
        assert!(validate_elevated_store_kind(expected).is_ok());
        assert!(validate_elevated_store_kind(mismatched).is_err(),
            "即便 StoreKind 是已知枚举，提权端也不能信任它选择任意证据存储");
    }

    #[test]
    fn unknown_elevated_store_is_rejected_before_any_wfp_backend_call() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut req = test_ipc_request();
        req.store_kind = "ForgedStore".into();
        let files = GuardIpcFiles::create(&req).unwrap();
        write_json_file(&files.req, &req).unwrap();
        prepare_reply_file(&files.res).unwrap();
        let backend = CountingBackend(AtomicUsize::new(0));
        assert_eq!(guard_apply_main(&files.req, &files.res, &backend), 2);
        assert_eq!(backend.0.load(Ordering::SeqCst), 0,
            "未知 StoreKind 必须在更改 WFP 前拒绝");
    }


    // Explicit CI-only regression with the fixed production name. The
    // actual debug product EXE uses the existing isolated evidence store;
    // no real install/sync/remove or product persistent BFE write occurs.
    #[cfg(windows)]
    #[test]
    #[ignore = "explicit isolated elevated Windows runner, actual Guard executor"]
    fn g1_final_executor_transaction() {
        use super::super::lifecycle_gate::LifecycleGate;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        use std::sync::atomic::{AtomicUsize, Ordering};

        const ROLE: &str = "SPIDERVPN_G1_EXECUTOR_TEST_ROLE";
        const TEST: &str = "guard::elevate::tests::g1_final_executor_transaction";
        struct Spy(AtomicUsize);
        impl Spy {
            fn observe(&self) -> Result<GuardEvidence, WfpError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(|| {
                    assert_eq!(LifecycleGate::acquire().err().unwrap(), "G1_GATE_EXISTING win32=183");
                    assert!(super::super::acquire_guard_mutex().is_err());
                    println!("G1_EXECUTOR_BACKEND_SPY outer_held=true short_held=true real_bfe_write=false");
                }).join().unwrap();
                Ok(GuardEvidence::default())
            }
        }
        impl super::super::GuardBackend for Spy {
            fn available(&self) -> bool { true }
            fn read(&self, _: &[ProgramIdentity], _: &super::super::Expect) -> Result<GuardEvidence, WfpError> { self.observe() }
            fn install(&self, _: &[ProgramIdentity], _: &super::super::Expect) -> Result<GuardEvidence, WfpError> { self.observe() }
            fn sync(&self, _: &[ProgramIdentity], _: &super::super::Expect) -> Result<GuardEvidence, WfpError> { self.observe() }
            fn remove(&self) -> Result<GuardEvidence, WfpError> { self.observe() }
        }
        fn request(label: &str, action: GuardAction) -> (GuardRequest, GuardIpcFiles) {
            let mut req = test_ipc_request();
            req.action = action;
            req.nonce = format!("g1-{label}");
            req.store_kind = StoreKind::IsolatedFile.as_str().into();
            let files = GuardIpcFiles::create(&req).unwrap();
            write_json_file(&files.req, &req).unwrap();
            prepare_reply_file(&files.res).unwrap();
            assert!(validate_guard_ipc_paths(&files.req, &files.res).is_ok());
            assert_eq!(read_attested_guard_request(&files.req).unwrap(), req);
            (req, files)
        }
        fn wait(mut command: Command) -> i32 {
            let mut child = command.stdin(Stdio::null()).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = child.try_wait().unwrap() { return status.code().unwrap(); }
                if Instant::now() >= deadline {
                    let _ = child.kill(); let _ = child.wait();
                    panic!("G1 real executor child did not exit within bound");
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        }
        fn cli(exe: &Path, root: &Path, label: &str) -> (i32, GuardReply, String) {
            let (req, files) = request(label, GuardAction::Verify);
            let mut cmd = Command::new(exe);
            cmd.arg(APPLY_FLAG).arg(&files.req).arg(&files.res)
                .env("SPIDERVPN_ROOT", root);
            let code = wait(cmd);
            let reply = read_json_file(&files.res).expect("real product Guard reply");
            (code, reply, req.nonce)
        }
        fn no_record(store: &super::super::IsolatedFileStore) {
            assert!(matches!(store.read(), Err(super::super::RecordError::Missing)));
            assert!(store.read_removed().is_none());
        }
        if std::env::var(ROLE).as_deref() == Ok("spy") {
            let root = crate::isolation::dev_root_override().expect("explicit isolated spy store");
            assert!(root.starts_with(std::env::temp_dir()) && root.is_dir());
            let store = super::super::IsolatedFileStore::new(&root).unwrap();
            let spy = Spy(AtomicUsize::new(0));
            for action in [GuardAction::Install, GuardAction::Sync, GuardAction::Verify, GuardAction::Remove] {
                let (req, files) = request(action.as_str(), action);
                assert_eq!(guard_apply_main(&files.req, &files.res, &spy), 0);
                let reply: GuardReply = read_json_file(&files.res).unwrap();
                assert!(reply.result.is_ok());
                if action == GuardAction::Remove {
                    assert!(matches!(store.read(), Err(super::super::RecordError::Missing)));
                    assert!(store.read_removed().is_some());
                } else {
                    assert_eq!(store.read().unwrap().nonce, req.nonce);
                    assert!(store.read_removed().is_none());
                }
                // Neither lock survives the actual executor's return.
                let _outer = LifecycleGate::acquire().unwrap();
                let _short = super::super::acquire_guard_mutex().unwrap();
                println!("G1_EXECUTOR_SPY_RESULT action={} record_readback=true locks_released_after_reply=true", action.as_str());
            }
            assert_eq!(spy.0.load(Ordering::SeqCst), 4);
            return;
        }
        let exe = PathBuf::from(std::env::var_os("SPIDERVPN_G1_PRODUCT_EXE")
            .expect("CI must supply the actual debug product EXE path"));
        assert!(exe.is_absolute() && exe.is_file());
        let nonce = {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut b = [0u8;16]; SystemRandom::new().fill(&mut b).unwrap();
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        };
        let root = std::env::temp_dir().join(format!("spidervpn-g1-executor-{nonce}"));
        std::fs::create_dir(&root).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
        let _cleanup = Cleanup(root.clone());
        let store = super::super::IsolatedFileStore::new(&root).unwrap();
        let sentinel = root.join("neighbor");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        // Full valid attested request, not an earlier IPC rejection.
        {
            let _outer = LifecycleGate::acquire().unwrap();
            let (code, reply, _) = cli(&exe, &root, "outer-contention");
            assert_eq!(code, 3);
            assert!(reply.result.is_err());
            assert_eq!(reply.notes, vec!["G1_GATE_EXISTING win32=183".to_string()]);
            no_record(&store);
            println!("G1_EXECUTOR_CLI_REFUSED gate=outer rc=3 native_rc=183 no_evidence=true");
        }
        {
            // Simulate the old writer/maintenance short lock only.
            let _short = super::super::acquire_guard_mutex().unwrap();
            let (code, reply, _) = cli(&exe, &root, "short-contention");
            assert_eq!(code, 3);
            assert!(reply.result.is_err());
            assert!(reply.notes.iter().any(|n| n.starts_with("G1_SHORT_LOCK:")));
            no_record(&store);
            println!("G1_EXECUTOR_CLI_REFUSED gate=short rc=3 no_evidence=true");
        }
        // Real --guard-apply Verify: a read-only BFE backend plus real
        // isolated evidence write. No persistent WFP mutation is needed.
        let (code, reply, nonce) = cli(&exe, &root, "uncontended-verify");
        assert_eq!(code, 0, "{reply:?}");
        let ev = reply.result.unwrap();
        assert_eq!(ev.source, super::super::GuardSource::ElevatedVerify);
        assert!(!ev.detection.provider_present && !ev.detection.sublayer_present,
            "G1 runner must not contain product persistent WFP infrastructure");
        assert_eq!(store.read().unwrap().nonce, nonce);
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        println!("G1_EXECUTOR_CLI_VERIFY real_exe=true real_bfe_read=true isolated_evidence=true provider_present=false no_persistent_write=true");
        {
            let _outer = LifecycleGate::acquire().unwrap();
            let _short = super::super::acquire_guard_mutex().unwrap();
        }
        let spy_root = root.join("spy");
        std::fs::create_dir(&spy_root).unwrap();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--ignored", "--exact", TEST, "--nocapture"])
            .env(ROLE, "spy").env("SPIDERVPN_ROOT", &spy_root);
        assert_eq!(wait(cmd), 0);
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        println!("G1_EXECUTOR_COMPLETE real_cli_negative=2 real_verify=true spy_actions=4 no_persistent_write=true cross_sid_not_run=true actual_uac_not_run=true");
    }

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

    fn test_ipc_request() -> GuardRequest {
        GuardRequest {
            action: GuardAction::Verify, programs: Vec::new(), explicit: true,
            config_digest: "hash".into(), nonce: "test-nonce".into(),
            boot_id: "boot".into(), store_kind: "Registry".into(),
            legacy_running: false, record_version: 1,
        }
    }

    #[test]
    fn guarded_ipc_rejects_arbitrary_paths_and_reused_names() {
        let request = test_ipc_request();
        let files = GuardIpcFiles::create(&request).unwrap();
        // 子进程只会在 apply() 已创建请求和空回执后启动；不存在的
        // 文件在 SystemIdentityEnv::is_reparse_point 中必须被保守拒绝。
        assert!(validate_guard_ipc_paths(&files.req, &files.res).is_err(),
            "不存在的 IPC 文件必须拒绝，不能放松安全检查来满足测试");
        write_json_file(&files.req, &request).unwrap();
        prepare_reply_file(&files.res).unwrap();
        let verification = validate_guard_ipc_paths(&files.req, &files.res);
        assert!(verification.is_ok(),
            "真实启动顺序中已创建的受保护请求/回执应该通过路径安全校验：{verification:?}");
        let bad = files.dir.join("other.json");
        assert!(validate_guard_ipc_paths(&files.req, &bad).is_err());
        assert!(validate_guard_ipc_paths(&files.req, &files.dir.join("req.json")).is_err());
        assert!(validate_guard_ipc_paths(&files.req, &std::env::temp_dir().join("res.json")).is_err());
        assert!(files.dir.file_name().unwrap().to_string_lossy().len() >= 113);
    }

    #[cfg(windows)]
    #[test]
    fn elevated_entry_rejects_widened_reply_acl_before_wfp() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let request = test_ipc_request();
        let files = GuardIpcFiles::create(&request).unwrap();
        write_json_file(&files.req, &request).unwrap();
        prepare_reply_file(&files.res).unwrap();
        let verification = validate_guard_ipc_paths(&files.req, &files.res);
        assert!(verification.is_ok(),
            "正常受保护目录/请求/回执必须成功通过实际 DACL 读回：{verification:?}");

        // 同账户攻击者能够放宽自己创建的回执 DACL；提权端必须按对象的
        // 实际状态拒绝，而不是仅信父进程曾调用过 protect。
        let output = std::process::Command::new("icacls")
            .arg(&files.res)
            .arg("/grant")
            .arg("*S-1-5-11:(M)")
            .output()
            .expect("隔离 Windows runner 必须有 icacls");
        assert!(output.status.success(),
            "无法构造 ACL 降级负对照：{}", String::from_utf8_lossy(&output.stderr));
        assert!(crate::secretfile::verify_private_ipc_acl(&files.res).is_err());
        assert!(validate_guard_ipc_paths(&files.req, &files.res).is_err());
        let backend = CountingBackend(AtomicUsize::new(0));
        assert_eq!(guard_apply_main(&files.req, &files.res, &backend), 2);
        assert_eq!(backend.0.load(Ordering::SeqCst), 0,
            "ACL 被放宽的 IPC 不允许访问 WFP 后端");
    }

    #[test]
    fn elevated_request_is_bound_to_original_uac_directory_digest() {
        let req = test_ipc_request();
        let files = GuardIpcFiles::create(&req).unwrap();
        write_json_file(&files.req, &req).unwrap();
        assert_eq!(read_attested_guard_request(&files.req).unwrap(), req);
        // 恶意进程修改已写请求，UAC argv 绑定的目录摘要并不会改变。
        let mut forged = req.clone();
        forged.action = GuardAction::Remove;
        std::fs::write(&files.req, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(read_attested_guard_request(&files.req).is_err(),
            "请求文件在 UAC 之后被替换时不能执行 Remove");
    }

    #[test]
    fn response_write_failure_is_never_treated_as_success() {
        // 删除/替换回执后，已成功执行的高权限动作也不能返回“成功”。
        let files = GuardIpcFiles::create(&test_ipc_request()).unwrap();
        let reply = GuardReply {
            result: Err(WfpError::InvalidState),
            notes: vec!["test".into()],
        };
        assert!(write_reply_file(&files.res, &reply).is_err());
        prepare_reply_file(&files.res).unwrap();
        assert!(write_reply_file(&files.res, &reply).is_ok());
        assert!(write_reply_file(&files.res, &reply).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn elevated_ipc_rejects_request_and_reply_hardlinks_by_handle() {
        let request = test_ipc_request();
        let files = GuardIpcFiles::create(&request).unwrap();
        write_json_file(&files.req, &request).unwrap();
        prepare_reply_file(&files.res).unwrap();

        let req_alias = files.dir.join("req-alias.json");
        std::fs::hard_link(&files.req, &req_alias)
            .expect("Windows hard link creation should be available on local NTFS runner");
        assert!(read_attested_guard_request(&files.req).is_err(),
            "不能把硬链接的请求当成唯一的可信文件");
        std::fs::remove_file(req_alias).unwrap();

        let reply_alias = files.dir.join("res-alias.json");
        std::fs::hard_link(&files.res, &reply_alias)
            .expect("Windows hard link creation should be available on local NTFS runner");
        let fake = GuardReply {
            result: Err(WfpError::InvalidState),
            notes: vec!["test".into()],
        };
        assert!(write_reply_file(&files.res, &fake).is_err(),
            "不能向可能与其它敏感文件共享 inode 的硬链接回执写入");
        assert_eq!(std::fs::metadata(&files.res).unwrap().len(), 0);
        std::fs::remove_file(reply_alias).unwrap();

        assert_eq!(read_attested_guard_request(&files.req).unwrap(), request);
        assert!(write_reply_file(&files.res, &fake).is_ok(),
            "移除硬链接后正常受保护 IPC 不应受影响");
    }

    #[test]
    fn one_shot_ipc_cannot_overwrite_existing_request_or_response() {
        let files = GuardIpcFiles::create(&test_ipc_request()).unwrap();
        let data = serde_json::json!({"Safe":true});
        write_json_file(&files.req, &data).unwrap();
        assert!(write_json_file(&files.req, &data).is_err(),
            "提权请求不允许覆盖或重放");
        assert_eq!(read_json_file::<serde_json::Value>(&files.req).unwrap(), data);
        prepare_reply_file(&files.res).unwrap();
        assert!(prepare_reply_file(&files.res).is_err());
        assert!(write_reply_file(&files.res, &data).is_ok(),
            "提权子进程应该能填写受保护的主程序回执");
        assert!(write_reply_file(&files.res, &data).is_err(),
            "已填写的回复不允许重放或覆盖");
        assert_eq!(read_json_file::<serde_json::Value>(&files.res).unwrap(), data);
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

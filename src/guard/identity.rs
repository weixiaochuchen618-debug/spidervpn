//! 名单 → 程序身份（`ProgramIdentity`）。
//!
//! 为什么要有这一层：WFP 的匹配条件是**可执行文件身份**（`FwpmGetAppIdFromFileName0`
//! 返回的 device path 字节），不是「名字」。拿名字去猜路径会绑错二进制——同名木马、
//! 多版本、安装目录不同都会中招，而绑错的结果是「保护了另一个程序、真正要保护的那个照样裸奔」。
//! 所以（PRD P0-9 / 架构 A-5）：
//!
//! - 名单条目必须能解析出**唯一存在的绝对 `.exe` 路径**；
//! - 解析不出来就标记为「不参与保护」并给出原因，**绝不猜**；
//! - 路径（含任一级父目录）是 reparse point（符号链接/目录联接）时拒绝——那是劫持的常见入口。
//!
//! 本文件不 import `windows-sys`：文件系统与 appId 解析通过 [`IdentityEnv`] 注入，
//! 生产实现是 `wfp_win::SystemIdentityEnv`，测试用假环境铺临时目录。
//! 因此「全部分支」都能在普通权限、不需要管理员的环境里自动验证。

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 名单条目上限：PRD Open Q1 的默认值（沿用 旧版的 64）。
///
/// 超过上限的条目**不静默丢弃**：它们会以 [`IdentityError::TooMany`] 出现在
/// 「未参与保护」清单里，界面上必须看得见。
pub const MAX_PROGRAMS: usize = 64;

/// 一条名单条目（值 = 程序名，可选的程序绝对路径）。
///
/// `path` 为 `None` 的是**老条目**：只有 exe 名。这种条目一定 `Unresolved`——
/// 不去磁盘上按名字搜索（那是猜，见文件头）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryRef<'a> {
    pub name: &'a str,
    pub path: Option<&'a str>,
}

impl<'a> EntryRef<'a> {
    pub fn new(name: &'a str, path: Option<&'a str>) -> EntryRef<'a> {
        EntryRef { name, path }
    }
}

/// 身份解析失败的原因。每个变体对应一种**可在界面上说清**的处置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// 老条目：没有路径。
    MissingPath,
    /// 不是绝对路径（`x.exe` / `.\x.exe` / `C:x.exe`）。
    NotAbsolute,
    /// 扩展名不是 `.exe`。
    NotExe,
    /// 文件不存在（或路径指向目录）。
    NotFound,
    /// 路径（含父目录）是 reparse point。
    ReparsePoint,
    /// 系统拒绝给出 appId（路径不可解析/被拒绝）。
    AppIdFailed,
    /// 超过条数上限。
    TooMany,
}

impl IdentityError {
    /// 给用户看的一句话（进入名单页与诊断）。**必须**能回答「为什么不参与保护」。
    pub fn reason(&self) -> String {
        match self {
            IdentityError::MissingPath => {
                "需要确认程序位置（旧条目只有程序名，本程序不会去猜路径）".to_string()
            }
            IdentityError::NotAbsolute => "程序路径不是绝对路径，请重新选择程序文件".to_string(),
            IdentityError::NotExe => "不是 .exe 程序".to_string(),
            IdentityError::NotFound => "找不到程序文件".to_string(),
            IdentityError::ReparsePoint => {
                "程序路径包含符号链接或目录联接，出于安全考虑不参与保护".to_string()
            }
            IdentityError::AppIdFailed => "无法取得该程序的系统身份，本条不参与保护".to_string(),
            IdentityError::TooMany => {
                format!("超过 {MAX_PROGRAMS} 条上限，本条不参与保护")
            }
        }
    }

    /// 诊断/证据里的稳定键（不随文案变化）。
    pub fn id(&self) -> &'static str {
        match self {
            IdentityError::MissingPath => "MissingPath",
            IdentityError::NotAbsolute => "NotAbsolute",
            IdentityError::NotExe => "NotExe",
            IdentityError::NotFound => "NotFound",
            IdentityError::ReparsePoint => "ReparsePoint",
            IdentityError::AppIdFailed => "AppIdFailed",
            IdentityError::TooMany => "TooMany",
        }
    }
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

/// 文件系统与 appId 解析的注入点。
///
/// 生产实现只有一处（`wfp_win::SystemIdentityEnv`）。单测用它造 reparse point、
/// 造「存在但 appId 解析失败」等分支，不必真的去改系统。
pub trait IdentityEnv {
    /// 路径是否存在（且不是目录）。
    fn exists(&self, path: &Path) -> bool;
    /// 该路径本身是不是 reparse point（符号链接/目录联接/挂载点）。
    fn is_reparse_point(&self, path: &Path) -> bool;
    /// `FwpmGetAppIdFromFileName0` 的字节结果（UTF-16LE + 结尾 NUL）。
    fn app_id(&self, path: &Path) -> Result<Vec<u8>, IdentityError>;
}

/// 解析成功的程序身份。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramIdentity {
    /// 名单里的名字（用于显示；**不是**身份）。
    pub name: String,
    /// 绝对路径（人可读、可重选；落盘保存的就是它）。
    pub path: PathBuf,
    /// WFP 的 appId 字节（真正的身份；磁盘上**不存**，安装时现算）。
    pub app_id: Vec<u8>,
    /// appId 解码出的 device path（诊断用；盘符/挂载点变化时它会变，path 不会）。
    pub device_path: String,
}

impl ProgramIdentity {
    /// 身份比较：以 appId 字节为准（大小写/盘符写法差异不影响身份）。
    pub fn same_identity(&self, other: &ProgramIdentity) -> bool {
        self.app_id == other.app_id
    }
}

/// 轻量身份：只做「这条名单条目到底指向哪个文件」的判定，不算 appId。
///
/// 为什么分成两种：状态快照（每次 UI 事件都会来）只需要「参与了没有 / 为什么没参与」，
/// 而 `FwpmGetAppIdFromFileName0` 是每次一条的 RPC 调用——放进状态刷新会把 UI 拖慢，
/// 且会让「读状态」这种只读操作去碰 BFE。appId 只在**安装/同步/证据记录**时算。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntry {
    pub name: String,
    pub path: PathBuf,
}

/// 一条不参与保护的条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedEntry {
    /// 名单里的名字（显示用）。
    pub name: String,
    /// 人能读懂的原因（[`IdentityError::reason`]）。
    pub reason: String,
    /// 机器可读的原因键（[`IdentityError::id`]）。
    pub reason_id: String,
    /// 原样保留的路径输入（诊断用；可能为空）。
    pub path: Option<String>,
}

impl UnresolvedEntry {
    pub fn new(name: &str, path: Option<&str>, error: &IdentityError) -> UnresolvedEntry {
        UnresolvedEntry {
            name: name.to_string(),
            reason: error.reason(),
            reason_id: error.id().to_string(),
            path: path.map(|p| p.to_string()),
        }
    }
}

/// 一次全量解析的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveOutcome {
    /// 参与保护的程序（已按 appId 去重）。
    pub programs: Vec<ProgramIdentity>,
    /// 不参与保护的条目（超限/无路径/找不到/…）。
    pub unresolved: Vec<UnresolvedEntry>,
    /// 名单原始条数（= `TradeProgramCount`）。
    pub total: usize,
}

impl ResolveOutcome {
    pub fn participated(&self) -> usize {
        self.programs.len()
    }

    /// 是否全部条目都参与保护（`false` 时状态最多 `Unprotected`）。
    pub fn all_participated(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// 轻量解析结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveOutcomeLight {
    pub entries: Vec<ResolvedEntry>,
    pub unresolved: Vec<UnresolvedEntry>,
    pub total: usize,
}

// ---------------------------------------------------------------------------
// 纯判定部分（不碰文件系统，先跑这一层能把绝大多数坏输入挡住）
// ---------------------------------------------------------------------------

/// 是否是绝对路径。
///
/// 用 `Path::is_absolute` 而不是「有没有冒号」：`C:x.exe`（盘符相对）**不是**绝对路径，
/// 它到底指哪里取决于当前目录——这种输入正是「看起来像路径」的陷阱。
pub fn is_absolute_path(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    let p = Path::new(t);
    p.is_absolute()
}

/// 扩展名是不是 `.exe`（大小写不敏感）。
pub fn has_exe_extension(text: &str) -> bool {
    Path::new(text.trim())
        .extension()
        .map(|e| e.to_string_lossy().eq_ignore_ascii_case("exe"))
        .unwrap_or(false)
}

/// 逐级要检查 reparse point 的路径列表：从最顶层可命名目录一直到文件本身。
///
/// 为什么要逐级：只查最后一级挡不住「父目录被换成目录联接」这种劫持方式；
/// 旧版的 `Assert-TCTradeAppPath` 也是逐级查的。
pub fn reparse_chain(path: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut acc = PathBuf::new();
    for comp in path.components() {
        acc.push(comp.as_os_str());
        match comp {
            // 盘符/根前缀本身（`C:\`）没有独立的「文件属性」，跳过
            Component::Prefix(_) | Component::RootDir => continue,
            _ => out.push(acc.clone()),
        }
    }
    out
}

/// 程序名不该带路径（界面/命令行输入的统一校验，与 `SplitConfig::validate_process` 同义）。
///
/// 这里保留一份独立实现是**故意的**：`guard` 模块不能依赖 `config`（否则状态判定就会
/// 被配置结构绑架），而这条判定要被身份层直接用。
pub fn looks_like_bare_name(text: &str) -> bool {
    let t = text.trim();
    !t.is_empty() && !t.contains('\\') && !t.contains('/') && !t.contains(':')
}

/// 从 appId 字节解出 device path（UTF-16LE，去掉结尾 NUL）。
///
/// 解不出来（奇数长度/非法 UTF-16）就返回空串——调用方随之把这条判成
/// `AppIdFailed`，**不要**用「原始字节的十六进制」冒充路径。
pub fn device_path_from_app_id(bytes: &[u8]) -> String {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return String::new();
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed: Vec<u16> = units.into_iter().take_while(|u| *u != 0).collect();
    if trimmed.is_empty() {
        return String::new();
    }
    String::from_utf16(&trimmed).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 解析（唯一入口）
// ---------------------------------------------------------------------------

/// 解析一条名单条目为**完整身份**（含 appId）。
///
/// 顺序刻意如此：纯判定（绝对路径/exe）→ 存在性 → reparse 链 → appId。
/// 先做纯判定，坏输入就不会产生任何系统调用；这也是单测能覆盖全部分支的原因。
pub fn resolve_entry(
    name: &str,
    path: Option<&str>,
    env: &dyn IdentityEnv,
) -> Result<ProgramIdentity, IdentityError> {
    let Some(raw) = path.map(str::trim).filter(|p| !p.is_empty()) else {
        return Err(IdentityError::MissingPath);
    };
    if !is_absolute_path(raw) {
        return Err(IdentityError::NotAbsolute);
    }
    if !has_exe_extension(raw) {
        return Err(IdentityError::NotExe);
    }
    let p = PathBuf::from(raw);
    if !env.exists(&p) {
        return Err(IdentityError::NotFound);
    }
    for step in reparse_chain(&p) {
        if env.is_reparse_point(&step) {
            return Err(IdentityError::ReparsePoint);
        }
    }
    let app_id = env.app_id(&p)?;
    let device_path = device_path_from_app_id(&app_id);
    if device_path.is_empty() {
        // appId 拿回来了但解不出 device path：不能拿它当身份（不可诊断、不可比对）
        return Err(IdentityError::AppIdFailed);
    }
    Ok(ProgramIdentity {
        name: name.trim().to_string(),
        path: p,
        app_id,
        device_path,
    })
}

/// 解析一条名单条目为**轻量身份**（不做 appId 的 RPC）。
pub fn resolve_entry_light(
    name: &str,
    path: Option<&str>,
    env: &dyn IdentityEnv,
) -> Result<ResolvedEntry, IdentityError> {
    let Some(raw) = path.map(str::trim).filter(|p| !p.is_empty()) else {
        return Err(IdentityError::MissingPath);
    };
    if !is_absolute_path(raw) {
        return Err(IdentityError::NotAbsolute);
    }
    if !has_exe_extension(raw) {
        return Err(IdentityError::NotExe);
    }
    let p = PathBuf::from(raw);
    if !env.exists(&p) {
        return Err(IdentityError::NotFound);
    }
    for step in reparse_chain(&p) {
        if env.is_reparse_point(&step) {
            return Err(IdentityError::ReparsePoint);
        }
    }
    Ok(ResolvedEntry { name: name.trim().to_string(), path: p })
}

/// 全量解析（完整身份）。
///
/// 规则：
/// - 超过 [`MAX_PROGRAMS`] 的条目进 `unresolved`（原因 `TooMany`），**不静默丢弃**；
/// - 同一 `appId` 出现两次 → 只保留第一条（不同名字指向同一个 exe 时只建 2 条规则）；
/// - 失败条目保留原始输入与原因，供界面显示「不参与保护（原因）」。
pub fn resolve_all(entries: &[EntryRef<'_>], env: &dyn IdentityEnv) -> ResolveOutcome {
    let mut out = ResolveOutcome { total: entries.len(), ..Default::default() };
    for (index, entry) in entries.iter().enumerate() {
        if index >= MAX_PROGRAMS {
            out.unresolved
                .push(UnresolvedEntry::new(entry.name, entry.path, &IdentityError::TooMany));
            continue;
        }
        match resolve_entry(entry.name, entry.path, env) {
            Ok(id) => {
                if out.programs.iter().any(|p| p.same_identity(&id)) {
                    // 去重：同一 appId 只留第一条（保留它的名字与路径，行为写在这里）
                    continue;
                }
                out.programs.push(id);
            }
            Err(e) => out
                .unresolved
                .push(UnresolvedEntry::new(entry.name, entry.path, &e)),
        }
    }
    out
}

/// 全量解析（轻量，状态快照用）。
pub fn resolve_all_light(
    entries: &[EntryRef<'_>],
    env: &dyn IdentityEnv,
) -> ResolveOutcomeLight {
    let mut out = ResolveOutcomeLight { total: entries.len(), ..Default::default() };
    for (index, entry) in entries.iter().enumerate() {
        if index >= MAX_PROGRAMS {
            out.unresolved
                .push(UnresolvedEntry::new(entry.name, entry.path, &IdentityError::TooMany));
            continue;
        }
        match resolve_entry_light(entry.name, entry.path, env) {
            Ok(id) => {
                // 轻量路径没有 appId 可比，按**路径**去重（大小写不敏感，Windows 语义）
                if out
                    .entries
                    .iter()
                    .any(|e| e.path.to_string_lossy().eq_ignore_ascii_case(&id.path.to_string_lossy()))
                {
                    continue;
                }
                out.entries.push(id);
            }
            Err(e) => out
                .unresolved
                .push(UnresolvedEntry::new(entry.name, entry.path, &e)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 单测
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_blob(text: &str) -> Vec<u8> {
        text.encode_utf16().chain(std::iter::once(0u16)).flat_map(|u| u.to_le_bytes()).collect()
    }

    /// 假环境：把「磁盘」塞进一张表，reparse point 也塞进去。
    struct FakeEnv {
        files: Vec<(String, bool)>, // (路径, 是否 reparse)
        app_id_fails: Vec<String>,
    }

    impl FakeEnv {
        fn new() -> FakeEnv {
            FakeEnv { files: Vec::new(), app_id_fails: Vec::new() }
        }

        fn with_file(mut self, path: &str) -> FakeEnv {
            self.files.push((path.to_lowercase(), false));
            self
        }

        fn with_reparse(mut self, path: &str) -> FakeEnv {
            self.files.push((path.to_lowercase(), true));
            self
        }

        fn failing_app_id(mut self, path: &str) -> FakeEnv {
            self.app_id_fails.push(path.to_lowercase());
            self
        }

        fn has(&self, path: &Path) -> bool {
            let p = path.to_string_lossy().to_lowercase();
            self.files.iter().any(|(f, _)| *f == p)
        }
    }

    impl IdentityEnv for FakeEnv {
        fn exists(&self, path: &Path) -> bool {
            self.has(path)
        }

        fn is_reparse_point(&self, path: &Path) -> bool {
            let p = path.to_string_lossy().to_lowercase();
            self.files.iter().any(|(f, reparse)| *f == p && *reparse)
        }

        fn app_id(&self, path: &Path) -> Result<Vec<u8>, IdentityError> {
            let p = path.to_string_lossy().to_lowercase();
            if self.app_id_fails.iter().any(|f| *f == p) {
                return Err(IdentityError::AppIdFailed);
            }
            Ok(utf16_blob(&format!("\\device\\harddiskvolume3{}", p.replace(':', ""))))
        }
    }

    #[test]
    fn absolute_and_extension_checks_are_strict() {
        assert!(is_absolute_path("C:\\Program Files\\T\\Trader.exe"));
        assert!(is_absolute_path("\\\\server\\share\\t.exe"), "UNC 也是绝对路径");
        assert!(!is_absolute_path("Trader.exe"));
        assert!(!is_absolute_path(".\\Trader.exe"));
        assert!(!is_absolute_path("C:Trader.exe"), "盘符相对不是绝对路径");
        assert!(!is_absolute_path("   "));

        assert!(has_exe_extension("C:\\a\\B.EXE"));
        assert!(has_exe_extension("C:\\a\\b.exe"));
        assert!(!has_exe_extension("C:\\a\\b.dll"));
        assert!(!has_exe_extension("C:\\a\\b"));
        assert!(!has_exe_extension("C:\\a\\b.exe.tmp"));

        assert!(looks_like_bare_name("TDXW.exe"));
        assert!(!looks_like_bare_name("C:\\a\\b.exe"));
        assert!(!looks_like_bare_name("a/b.exe"));
        assert!(!looks_like_bare_name(""));
    }

    #[test]
    fn reparse_chain_walks_every_level_but_skips_the_root_prefix() {
        let chain = reparse_chain(Path::new("C:\\Program Files\\T\\Trader.exe"));
        let shown: Vec<String> = chain.iter().map(|p| p.to_string_lossy().to_string()).collect();
        assert_eq!(
            shown,
            vec![
                "C:\\Program Files".to_string(),
                "C:\\Program Files\\T".to_string(),
                "C:\\Program Files\\T\\Trader.exe".to_string(),
            ],
            "必须逐级检查父目录，且不要把 `C:\\` 本身当成一级"
        );
    }

    #[test]
    fn device_path_decoding_strips_nul_and_rejects_garbage() {
        let ok = utf16_blob("\\device\\harddiskvolume3\\app\\trader.exe");
        assert_eq!(device_path_from_app_id(&ok), "\\device\\harddiskvolume3\\app\\trader.exe");
        assert_eq!(device_path_from_app_id(&[1, 2, 3]), "", "奇数长度不是 UTF-16");
        assert_eq!(device_path_from_app_id(&[]), "");
        assert_eq!(device_path_from_app_id(&[0, 0]), "", "只有 NUL 等于没有路径");
    }

    #[test]
    fn old_entries_without_path_are_unresolved_and_never_guessed() {
        // 这是最重要的一条：只有 exe 名时，**不许**去磁盘上按名字搜索。
        let env = FakeEnv::new().with_file("C:\\tools\\trader.exe");
        let err = resolve_entry("trader.exe", None, &env).unwrap_err();
        assert_eq!(err, IdentityError::MissingPath);
        assert!(err.reason().contains("不会去猜路径"));
        let err = resolve_entry("trader.exe", Some("   "), &env).unwrap_err();
        assert_eq!(err, IdentityError::MissingPath, "空白路径等于没有路径");
    }

    #[test]
    fn resolve_entry_covers_every_failure_branch() {
        let env = FakeEnv::new()
            .with_file("C:\\tools\\trader.exe")
            .with_reparse("C:\\link\\trader.exe")
            .failing_app_id("C:\\tools\\broken.exe")
            .with_file("C:\\tools\\broken.exe");

        assert_eq!(
            resolve_entry("t", Some("trader.exe"), &env).unwrap_err(),
            IdentityError::NotAbsolute
        );
        assert_eq!(
            resolve_entry("t", Some("C:\\tools\\trader.dll"), &env).unwrap_err(),
            IdentityError::NotExe
        );
        assert_eq!(
            resolve_entry("t", Some("C:\\tools\\missing.exe"), &env).unwrap_err(),
            IdentityError::NotFound
        );
        assert_eq!(
            resolve_entry("t", Some("C:\\link\\trader.exe"), &env).unwrap_err(),
            IdentityError::ReparsePoint,
            "reparse point 必须拒绝（劫持入口）"
        );
        assert_eq!(
            resolve_entry("t", Some("C:\\tools\\broken.exe"), &env).unwrap_err(),
            IdentityError::AppIdFailed
        );

        let ok = resolve_entry("Trader", Some("C:\\tools\\trader.exe"), &env).unwrap();
        assert_eq!(ok.name, "Trader");
        assert_eq!(ok.path, PathBuf::from("C:\\tools\\trader.exe"));
        assert!(!ok.app_id.is_empty());
        assert!(ok.device_path.to_lowercase().contains("trader.exe"));
    }

    #[test]
    fn parent_directory_reparse_point_is_rejected() {
        let env = FakeEnv::new()
            .with_file("C:\\link\\sub\\trader.exe")
            .with_reparse("C:\\link");
        assert_eq!(
            resolve_entry("t", Some("C:\\link\\sub\\trader.exe"), &env).unwrap_err(),
            IdentityError::ReparsePoint,
            "父目录是目录联接也要拒绝"
        );
    }

    #[test]
    fn unresolved_entries_keep_reason_for_the_ui() {
        let env = FakeEnv::new();
        let entries = [
            EntryRef::new("old.exe", None),
            EntryRef::new("gone.exe", Some("C:\\nope\\gone.exe")),
        ];
        let out = resolve_all(&entries, &env);
        assert_eq!(out.total, 2);
        assert!(out.programs.is_empty());
        assert!(!out.all_participated());
        assert_eq!(out.unresolved.len(), 2);
        assert_eq!(out.unresolved[0].reason_id, "MissingPath");
        assert_eq!(out.unresolved[1].reason_id, "NotFound");
        assert!(out.unresolved[0].reason.contains("旧条目"));
        assert_eq!(out.unresolved[0].path, None);
        assert_eq!(out.unresolved[1].path.as_deref(), Some("C:\\nope\\gone.exe"));
    }

    #[test]
    fn duplicate_app_ids_are_deduplicated_but_total_is_kept() {
        let env = FakeEnv::new()
            .with_file("C:\\a\\trader.exe")
            .with_file("C:\\b\\trader.exe");
        let entries = [
            EntryRef::new("trader.exe", Some("C:\\a\\trader.exe")),
            EntryRef::new("TRADER.EXE", Some("C:\\b\\trader.exe")),
        ];
        let out = resolve_all(&entries, &env);
        // 假环境按路径尾部造 appId，两个不同路径 → 两个不同 appId
        assert_eq!(out.programs.len(), 2, "路径不同 = 身份不同");
        assert_eq!(out.total, 2);

        // 同一个路径写两遍：只留一条，但 total 仍是 2
        let entries = [
            EntryRef::new("trader.exe", Some("C:\\a\\trader.exe")),
            EntryRef::new("trader.exe", Some("C:\\A\\TRADER.EXE")),
        ];
        let out = resolve_all(&entries, &env);
        assert_eq!(out.programs.len(), 1, "同一个 appId 只建一组规则");
        assert_eq!(out.total, 2, "TradeProgramCount 仍是名单条数");
    }

    #[test]
    fn more_than_the_limit_is_reported_not_dropped() {
        let mut env = FakeEnv::new();
        let mut paths = Vec::new();
        for i in 0..(MAX_PROGRAMS + 3) {
            let p = format!("C:\\tools\\p{i}.exe");
            env = env.with_file(&p);
            paths.push(p);
        }
        let entries: Vec<EntryRef<'_>> =
            paths.iter().enumerate().map(|(i, p)| EntryRef::new(Box::leak(format!("p{i}.exe").into_boxed_str()), Some(p.as_str()))).collect();
        let out = resolve_all(&entries, &env);
        assert_eq!(out.total, MAX_PROGRAMS + 3);
        assert_eq!(out.programs.len(), MAX_PROGRAMS);
        assert_eq!(out.unresolved.len(), 3, "超限条目必须出现在未参与清单里");
        assert!(out.unresolved.iter().all(|u| u.reason_id == "TooMany"));
    }

    #[test]
    fn light_resolution_skips_app_id_but_keeps_the_same_verdicts() {
        // 轻量路径不调 appId：即使 appId 解析会失败，轻量解析也应成功
        let env = FakeEnv::new()
            .with_file("C:\\tools\\trader.exe")
            .failing_app_id("C:\\tools\\trader.exe");
        assert!(resolve_entry("t", Some("C:\\tools\\trader.exe"), &env).is_err());
        let light = resolve_entry_light("t", Some("C:\\tools\\trader.exe"), &env).unwrap();
        assert_eq!(light.path, PathBuf::from("C:\\tools\\trader.exe"));

        let entries = [
            EntryRef::new("old.exe", None),
            EntryRef::new("t", Some("C:\\tools\\trader.exe")),
            EntryRef::new("t2", Some("C:\\TOOLS\\TRADER.EXE")),
        ];
        let out = resolve_all_light(&entries, &env);
        assert_eq!(out.total, 3);
        assert_eq!(out.entries.len(), 1, "同一路径（大小写不同）只算一条");
        assert_eq!(out.unresolved.len(), 1);
        assert_eq!(out.unresolved[0].reason_id, "MissingPath");
    }

    #[test]
    fn every_reason_is_readable_and_stable() {
        for e in [
            IdentityError::MissingPath,
            IdentityError::NotAbsolute,
            IdentityError::NotExe,
            IdentityError::NotFound,
            IdentityError::ReparsePoint,
            IdentityError::AppIdFailed,
            IdentityError::TooMany,
        ] {
            assert!(!e.reason().is_empty());
            assert!(!e.id().is_empty());
            assert!(!e.reason().contains("0x"));
        }
        assert_eq!(MAX_PROGRAMS, 64, "PRD Open Q1 的默认上限");
    }
}

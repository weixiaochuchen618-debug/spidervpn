//! SEC-09: Rust uninstall safety policy. The PowerShell script may copy/delete
//! a fixed manifest only AFTER this preflight succeeds. No changes to the
//! connection state machine, WFP persistent BLOCK implementation or UI.
//!
//! Default uninstall removes ONLY our provider's WFP objects, verifies their
//! absence, writes the existing Removed marker and invalidates stale evidence.
//! It works with missing/corrupt config.json, unlike --guard-remove. All
//! errors fail closed and leave the executable installed for recovery.
//! --keep-guard is a deliberate, separately acknowledged exception.

#![cfg(windows)]

use std::path::{Path, Component};
use crate::guard::{
    self, GuardBackend, evidence::{EvidenceStore, RegistryStore, RemovedMarker},
    state::{GuardEvidence, RecordError},
};

/// The installation allowlist is the one Rust source of truth shared by
/// install, removal and regression tests. The PS thin wrapper is checked
/// against this list in CI before any release is considered.
pub fn code_file_manifest() -> &'static [&'static str] {
    crate::install_trust::BIN_FILES
}

fn safe_local_root(root: &Path) -> Result<(), String> {
    // Disallow lexical escapes, UNC and drive roots; must point to the
    // already-running SpiderVPN exe, never an arbitrary install tree.
    if root.to_string_lossy().split(['\\', '/']).any(|s| s == "." || s == "..") {
        return Err("卸载目标包含路径跳转".into());
    }
    let mut components = root.components();
    let disk = matches!(components.next(),
        Some(Component::Prefix(p)) if matches!(p.kind(), std::path::Prefix::Disk(_)));
    if !disk || !matches!(components.next(), Some(Component::RootDir))
        || !components.any(|c| matches!(c, Component::Normal(_)))
    {
        return Err("卸载目标必须是本机磁盘上的非根绝对目录".into());
    }
    if !cfg!(debug_assertions)
        && !root.to_string_lossy().eq_ignore_ascii_case(crate::isolation::Rewrite::INSTALL_DIR)
    {
        return Err("正式版本只支持 C:\\SpiderVPN 的安全卸载".into());
    }
    Ok(())
}

fn no_reparse(path: &Path) -> Result<(), String> {
    use crate::guard::identity::IdentityEnv;
    let env = crate::guard::wfp_win::SystemIdentityEnv::new();
    for p in crate::guard::identity::reparse_chain(path) {
        match std::fs::symlink_metadata(&p) {
            Ok(_) if env.is_reparse_point(&p) => {
                return Err(format!("卸载路径存在符号链接/联接点：{}", p.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("无法验证卸载路径 {}：{e}", p.display())),
        }
    }
    Ok(())
}

/// Prevent using a test/injected copy of SpiderVPN to remove a different
/// installation's WFP rules. This is a runtime gate, not a mockable check.
fn actual_installation(root: &Path) -> Result<(), String> {
    safe_local_root(root)?;
    let bin = root.join("bin");
    let expected = bin.join("spidervpn.exe");
    for p in [root, bin.as_path(), expected.as_path()] {
        no_reparse(p)?;
    }
    let actual = std::env::current_exe()
        .map_err(|e| format!("无法确定卸载客户端身份：{e}"))?;
    no_reparse(&actual)?;
    let resolved_actual = std::fs::canonicalize(&actual)
        .map_err(|e| format!("无法验证正在执行的客户端：{e}"))?;
    let resolved_expected = std::fs::canonicalize(&expected)
        .map_err(|e| format!("无法验证安装位置的客户端：{e}"))?;
    if resolved_actual != resolved_expected {
        return Err("正在运行的 SpiderVPN 并非目标安装目录中的原始程序，拒绝卸载".into());
    }
    Ok(())
}

/// Same decision on fresh and existing installations: a pending proxy
/// journal must be restored by the normal Disconnect flow before uninstall.
/// The old script allowed bypassing this with a prompt; that can leave the
/// system proxy pointing to a deleted engine.
fn preflight_data(root: &Path) -> Result<(), String> {
    let data = root.join("data");
    no_reparse(&data)?;
    let journal = data.join("proxy-journal.json");
    no_reparse(&journal)?;
    match std::fs::symlink_metadata(&journal) {
        Ok(_) => Err("发现未还原的系统代理记录 proxy-journal.json；先在客户端断开并还原代理，拒绝删除程序".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("无法证明代理恢复记录不存在（{}）：{e}；拒绝卸载", journal.display())),
    }
}

fn release_guard_with(
    root: &Path,
    keep_guard: bool,
    backend: &dyn GuardBackend,
    store: &dyn EvidenceStore,
) -> Result<(), String> {
    preflight_data(root)?;
    if keep_guard {
        return Ok(());
    }
    // Do not consult config.json. It can be absent while persistent WFP
    // filters still exist. The backend is transactional, exclusively selects
    // our provider GUID and verifies provider/sublayer after commit.
    let state: GuardEvidence = backend.remove()
        .map_err(|e| format!("解除交易保护 WFP 失败：{}", e.message()))?;
    if state.read_error.is_some()
        || !state.detection.bfe_ready
        || state.detection.provider_present
        || state.detection.sublayer_present
    {
        return Err("WFP 解除后仍存在提供方或子层/回读状态未知；不允许删除客户端".into());
    }
    let marker = RemovedMarker::new(
        &guard::state::iso8601_utc_millis(guard::now_epoch()),
        "ElevatedRemove",
    );
    store.write_removed(&marker)
        .map_err(|e| format!("WFP 已解除但保存解除标记失败，拒绝继续卸载：{e}"))?;
    store.invalidate("uninstall")
        .map_err(|e| format!("WFP 已解除但作废旧证据失败，拒绝继续卸载：{e}"))?;
    if store.read_removed().is_none() {
        return Err("解除标记回读失败，不允许删除客户端".into());
    }
    match store.read() {
        Err(RecordError::Missing) => Ok(()),
        Ok(_) => Err("解除后旧的 WFP 保护证据仍存在，不允许删除客户端".into()),
        Err(e) => Err(format!("卸载前证据回读失败，拒绝删除客户端：{}", e.message())),
    }
}

/// Called from the installed EXE only. The Rust code makes all security
/// decisions; PowerShell may delete the fixed package manifest afterwards.
pub fn preflight(root: &Path, keep_guard: bool) -> Result<(), String> {
    if !crate::probe::is_elevated() {
        return Err("安全卸载需要管理员权限；请以管理员身份运行卸载入口".into());
    }
    actual_installation(root)?;
    let backend = crate::guard::wfp_win::WindowsWfp::new();
    let store = RegistryStore::new();
    guard::with_guard_mutex(|| release_guard_with(root, keep_guard, &backend, &store))?
}

/// Only match two EXACT templates written by install.ps1; never use substring
/// Contains(), which wrongly classifies C:\SpiderVPN2 as C:\SpiderVPN.
/// The default release root is ASCII, so the original GBK launcher content
/// and these templates are byte-identical. Unknown/custom scripts are kept.
fn launcher_template(root: &Path, name: &str) -> Option<String> {
    let exe = root.join("bin").join("spidervpn.exe");
    if name.eq_ignore_ascii_case("启动SpiderVPN.cmd") {
        Some(format!("@echo off\r\nstart \"\" \"{}\"\r\n", exe.display()))
    } else if name.eq_ignore_ascii_case("卸载SpiderVPN.cmd") {
        let script = root.join("uninstall.ps1");
        Some(format!(
            "@echo off\r\npowershell -NoProfile -ExecutionPolicy Bypass -File \"{}\"\r\npause\r\n",
            script.display()
        ))
    } else {
        None
    }
}

fn owned_launcher_bytes(contents: &[u8], root: &Path, name: &str) -> bool {
    let Some(template) = launcher_template(root, name) else { return false; };
    contents.eq_ignore_ascii_case(template.as_bytes())
}

// D1 only: a bounded read of one named local disk object. This is NOT a
// capability to delete it later by pathname. The caller still needs a
// separate same-object removal and uninstall-lifecycle gate.
const MAX_LAUNCHER_BYTES: u64 = 8192;

fn launcher_reserved_device(part: &str) -> bool {
    // Win32 also recognizes these DOS devices with a suffix/extension,
    // including superscript digits 1–3 for COM/LPT. Refuse before any open.
    let stem = part.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$")
        || stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"))
}

fn launcher_path_parts(path: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    // Reject namespace/relative paths, ADS, lexical aliases, empty segments
    // and Win32 trailing-dot/space normalization before opening anything.
    let text = path.to_str().ok_or("快捷方式路径不是有效文本")?.replace('/', "\\");
    let bytes = text.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':' || bytes[2] != b'\\'
    {
        return Err("快捷方式必须是本机磁盘绝对路径".into());
    }
    let mut current = std::path::PathBuf::from(&text[..3]);
    let mut parts = vec![current.clone()];
    for part in text[3..].split('\\') {
        if part.is_empty() || part.ends_with(['.', ' ']) || launcher_reserved_device(part)
            || part.chars().any(|c| c.is_control() || ":*?\"<>|".contains(c))
        {
            return Err("快捷方式路径包含不安全的名称或别名".into());
        }
        current.push(part);
        parts.push(current.clone());
    }
    Ok(parts)
}

fn launcher_handle_info(file: &std::fs::File, directory: bool)
    -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION, String>
{
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_DEVICE, FILE_TYPE_DISK,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: live borrowed file handle, correctly sized initialized output.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
    {
        return Err("无法核验快捷方式磁盘文件对象".into());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && (info.nNumberOfLinks != 1
            || (info.nFileIndexHigh == 0 && info.nFileIndexLow == 0)))
    {
        return Err("快捷方式对象为链接、设备、非普通文件或身份未知".into());
    }
    Ok(info)
}

fn launcher_handle_path(file: &std::fs::File, expected: &Path) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS = 0. Reject aliases, including
    // short names or redirected volumes that do not resolve to this name.
    let mut buffer = vec![0u16; 32768];
    let n = unsafe {
        GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(),
            buffer.len() as u32, 0)
    } as usize;
    if n == 0 || n >= buffer.len() {
        return Err("无法读取快捷方式对象的规范路径".into());
    }
    let actual = String::from_utf16(&buffer[..n]).map_err(|_| "快捷方式对象路径无效")?;
    let actual = actual.strip_prefix(r"\\?\").ok_or("快捷方式对象不是本地 DOS 路径")?;
    let expected = expected.to_str().ok_or("快捷方式路径无效")?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err("快捷方式路径与打开的对象不一致".into());
    }
    Ok(())
}

fn launcher_size(info: &windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION) -> u64 {
    (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)
}

fn read_launcher_bounded(reader: &mut impl std::io::Read) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    // Do not trust the initial metadata length to bound allocation or I/O.
    let mut bytes = Vec::with_capacity((MAX_LAUNCHER_BYTES + 1) as usize);
    reader.take(MAX_LAUNCHER_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_launcher_file(path: &Path) -> Result<Option<Vec<u8>>, String> {
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let parts = launcher_path_parts(path)?;
    let drive: Vec<u16> = parts[0].as_os_str().encode_wide().chain(Some(0)).collect();
    // GetDriveTypeW: DRIVE_FIXED = 3. No mapped network/removable or unknown
    // volume is accepted as a safe local desktop launcher.
    if unsafe { GetDriveTypeW(drive.as_ptr()) } != 3 {
        return Err("快捷方式不在固定本机磁盘上".into());
    }
    let (leaf, parents) = parts.split_last().ok_or("快捷方式路径为空")?;
    let mut dirs = Vec::with_capacity(parents.len());
    // Open root-to-leaf and keep all ancestor handles live for the whole
    // observation. No delete/write sharing; reject reparse points at every
    // level, not just a separate symlink_metadata check of the leaf.
    for parent in parents {
        let dir = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(parent).map_err(|e| format!("无法打开快捷方式祖先目录 {}：{e}", parent.display()))?;
        launcher_handle_info(&dir, true)?;
        launcher_handle_path(&dir, parent)?;
        dirs.push(dir);
    }
    let mut file = std::fs::OpenOptions::new().read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(leaf).map_err(|e| format!("读取快捷方式 {} 失败：{e}", path.display()))?;
    let before = launcher_handle_info(&file, false)?;
    launcher_handle_path(&file, leaf)?;
    if launcher_size(&before) > MAX_LAUNCHER_BYTES {
        return Ok(None);
    }
    let bytes = read_launcher_bounded(&mut file)
        .map_err(|e| format!("读取快捷方式 {} 失败：{e}", path.display()))?;
    if bytes.len() as u64 > MAX_LAUNCHER_BYTES {
        return Ok(None);
    }
    let after = launcher_handle_info(&file, false)?;
    launcher_handle_path(&file, leaf)?;
    if launcher_size(&before) != bytes.len() as u64
        || launcher_size(&after) != bytes.len() as u64
        || before.dwVolumeSerialNumber != after.dwVolumeSerialNumber
        || before.nFileIndexHigh != after.nFileIndexHigh
        || before.nFileIndexLow != after.nFileIndexLow
        || before.dwFileAttributes != after.dwFileAttributes
        || before.ftLastWriteTime.dwHighDateTime != after.ftLastWriteTime.dwHighDateTime
        || before.ftLastWriteTime.dwLowDateTime != after.ftLastWriteTime.dwLowDateTime
    {
        return Err("快捷方式对象在读取期间变化，拒绝确认归属".into());
    }
    for (dir, parent) in dirs.iter().zip(parents) {
        launcher_handle_info(dir, true)?;
        launcher_handle_path(dir, parent)?;
    }
    Ok(Some(bytes))
}

/// This only reports ownership for known desktop/start-menu launchers.
/// No deletion, no filesystem mutation and no WFP access.
pub fn owns_launcher(path: &Path, root: &Path) -> Result<bool, String> {
    actual_installation(root)?;
    let name = path.file_name().and_then(|s| s.to_str())
        .ok_or_else(|| "快捷方式文件名不是有效文本".to_string())?;
    let Some(_) = launcher_template(root, name) else { return Ok(false); };
    let Some(content) = read_launcher_file(path)? else { return Ok(false); };
    Ok(owned_launcher_bytes(&content, root, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use crate::guard::{
        identity::ProgramIdentity, Expect, WfpError, state::{GuardDetection},
        evidence::IsolatedFileStore,
    };

    struct FakeBackend {
        calls: AtomicUsize,
        fails: bool,
        still_present: bool,
    }
    impl FakeBackend {
        fn new(fails: bool, still_present: bool) -> Self {
            Self { calls: AtomicUsize::new(0), fails, still_present }
        }
        fn calls(&self) -> usize { self.calls.load(Ordering::SeqCst) }
    }
    impl GuardBackend for FakeBackend {
        fn available(&self) -> bool { true }
        fn read(&self, _: &[ProgramIdentity], _: &Expect) -> Result<GuardEvidence, WfpError> {
            Err(WfpError::InvalidState)
        }
        fn install(&self, _: &[ProgramIdentity], _: &Expect) -> Result<GuardEvidence, WfpError> {
            Err(WfpError::InvalidState)
        }
        fn sync(&self, _: &[ProgramIdentity], _: &Expect) -> Result<GuardEvidence, WfpError> {
            Err(WfpError::InvalidState)
        }
        fn remove(&self) -> Result<GuardEvidence, WfpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fails { return Err(WfpError::InvalidState); }
            Ok(GuardEvidence {
                programs: Vec::new(),
                detection: GuardDetection {
                    bfe_ready: true,
                    provider_present: self.still_present,
                    sublayer_present: self.still_present,
                    ..Default::default()
                },
                read_error: None,
                verified_at_epoch: None,
                verified_at_tick_ms: None,
                source: guard::GuardSource::ElevatedVerify,
                config_digest: String::new(),
                boot_id: String::new(),
                extra_owned_filters: 0,
                legacy_running_at_verify: false,
                store_kind: String::new(),
            })
        }
    }

    fn root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "tcrs-sec09-{tag}-{}", std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn missing_config_does_not_skip_guard_removal() {
        let p = root("no-config");
        let store = IsolatedFileStore::new(&p).unwrap();
        let fake = FakeBackend::new(false, false);
        assert!(!p.join("data").join("config.json").exists());
        release_guard_with(&p, false, &fake, &store).unwrap();
        assert_eq!(fake.calls(), 1);
        assert!(store.read_removed().is_some());
        assert_eq!(store.read().unwrap_err(), RecordError::Missing);
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn failed_or_unconfirmed_wfp_removal_must_never_authorize_deletion() {
        let p = root("failed");
        let store = IsolatedFileStore::new(&p).unwrap();
        for fake in [FakeBackend::new(true, false), FakeBackend::new(false, true)] {
            assert!(release_guard_with(&p, false, &fake, &store).is_err());
            assert_eq!(fake.calls(), 1);
            assert!(store.read_removed().is_none());
        }
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn unreadable_or_linked_journal_is_never_treated_as_absent() {
        let p = root("journal-link");
        let data = p.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let real = data.join("pending-restore.txt");
        std::fs::write(&real, b"pending proxy restore").unwrap();
        let linked = data.join("proxy-journal.json");
        std::os::windows::fs::symlink_file(&real, &linked)
            .or_else(|_| std::fs::hard_link(&real, &linked))
            .unwrap();
        assert!(preflight_data(&p).is_err(), "linked journal still blocks uninstall");
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn wfp_removed_but_marker_storage_failure_still_refuses_uninstall() {
        let p = root("marker-write-failure");
        // Make the fake evidence directory a regular file. The WFP backend
        // succeeds, but the Removed marker cannot be persisted.
        std::fs::write(p.join("guard"), b"blocking placeholder").unwrap();
        let store = IsolatedFileStore::new(&p).unwrap();
        let fake = FakeBackend::new(false, false);
        assert!(release_guard_with(&p, false, &fake, &store).is_err(),
            "a marker persistence error must retain the installed executable");
        assert_eq!(fake.calls(), 1);
        assert!(p.join("guard").is_file(), "never delete unrelated files");
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn journal_blocks_even_explicit_keep_guard_without_wfp_call() {
        let p = root("journal");
        let data = p.join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("proxy-journal.json"), b"pending").unwrap();
        let store = IsolatedFileStore::new(&p).unwrap();
        let fake = FakeBackend::new(false, false);
        assert!(release_guard_with(&p, false, &fake, &store).is_err());
        assert!(release_guard_with(&p, true, &fake, &store).is_err());
        assert_eq!(fake.calls(), 0);
        assert!(store.read_removed().is_none());
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn explicit_keep_guard_does_not_remove_persistent_wfp() {
        let p = root("keep-guard");
        let store = IsolatedFileStore::new(&p).unwrap();
        let fake = FakeBackend::new(false, false);
        release_guard_with(&p, true, &fake, &store).unwrap();
        assert_eq!(fake.calls(), 0);
        assert!(store.read_removed().is_none());
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn launcher_owner_is_exact_not_substring_or_directory_prefix() {
        let root = Path::new(r"C:\SpiderVPN");
        let other = Path::new(r"C:\SpiderVPN2");
        let ok = launcher_template(root, "启动SpiderVPN.cmd").unwrap();
        assert!(owned_launcher_bytes(ok.as_bytes(), root, "启动SpiderVPN.cmd"));
        assert!(!owned_launcher_bytes(ok.as_bytes(), other, "启动SpiderVPN.cmd"));
        assert!(!owned_launcher_bytes(format!("{ok}rem anything").as_bytes(), root, "启动SpiderVPN.cmd"));
        let uninstaller = launcher_template(root, "卸载SpiderVPN.cmd").unwrap();
        assert!(owned_launcher_bytes(uninstaller.as_bytes(), root, "卸载SpiderVPN.cmd"));
        assert!(!owned_launcher_bytes(uninstaller.as_bytes(), other, "卸载SpiderVPN.cmd"));
        assert!(!owned_launcher_bytes(b"@echo off\r\nrem arbitrary custom command\r\n", root, "卸载SpiderVPN.cmd"));
        assert!(!owned_launcher_bytes(ok.as_bytes(), root, "random.cmd"));
    }

    #[test]
    fn uninstall_script_manifest_matches_rust_install_manifest_without_duplicates() {
        let script = include_str!("../package-files/uninstall.ps1");
        let manifest_line = script.lines()
            .find(|line| line.trim_start().starts_with("foreach ($n in @('sing-box.exe'"))
            .expect("thin wrapper must have a fixed bin file deletion list");
        let ps_names: Vec<_> = manifest_line.split("'").enumerate()
            .filter_map(|(i, segment)| if i % 2 == 1 { Some(segment) } else { None })
            .collect();
        let rust_names = code_file_manifest();
        assert_eq!(ps_names.len(), rust_names.len());
        for file in rust_names {
            assert_eq!(ps_names.iter().filter(|name| *name == file).count(), 1,
                "every packaged Rust manifest item must be deleted exactly once: {file}");
        }
        assert_eq!(ps_names.last().copied(), Some("spidervpn.exe"),
            "client recovery executable must be the final bin deletion");

        let launchers = script.find("foreach ($n in @('启动SpiderVPN.cmd'")
            .expect("known root scripts must be handled explicitly");
        let root_section = &script[launchers..script.find("# 3) ").unwrap()];
        assert!(!root_section.contains("'uninstall.ps1'"),
            "never remove recovery uninstaller before deleting other binaries");
        let final_script_cleanup = script.find("Remove-Item -LiteralPath $uninstaller -Force")
            .expect("uninstaller must eventually be cleaned");
        assert!(final_script_cleanup > script.find("foreach ($n in @('sing-box.exe'").unwrap(),
            "uninstaller may be deleted only after the binary cleanup loop");

        let installer = include_str!("../package-files/install.ps1");
        for required in ["'sing-box.exe'", "'WebView2Loader.dll'",
                         "'sing-box.LICENSE.txt'"] {
            assert!(installer.contains(required), "installer manifest drift: {required}");
        }
    }

    #[test]
    fn manifest_contains_engine_and_does_not_admit_wildcards() {
        assert!(code_file_manifest().contains(&"sing-box.exe"));
        assert!(code_file_manifest().contains(&"WebView2Loader.dll"));
        assert!(code_file_manifest().contains(&"spidervpn.exe"));
        assert!(code_file_manifest().iter().all(|n| !n.contains('*') && !n.contains('\\')));
    }

    #[test]
    fn launcher_bounded_reader_stops_at_8193_even_after_real_file_growth() {
        use std::io::{Seek, Write};
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let p = root("bounded-growth");
        let path = p.join("grow.cmd");
        std::fs::write(&path, b"small").unwrap();
        // Deliberately allow a writer in this helper-level fault injection.
        // The real identity gate denies write sharing instead.
        let mut read = std::fs::OpenOptions::new().read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE).open(&path).unwrap();
        assert_eq!(read.metadata().unwrap().len(), 5);
        let mut writer = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&vec![b'x'; 32000]).unwrap();
        writer.flush().unwrap();
        let got = read_launcher_bounded(&mut read).unwrap();
        assert_eq!(got.len(), 8193);
        assert_eq!(read.stream_position().unwrap(), 8193);
        drop(writer);
        drop(read);
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn launcher_path_rejects_namespace_and_normalization_aliases() {
        for name in [r"C:relative\启动SpiderVPN.cmd", r"\\server\share\启动SpiderVPN.cmd",
            r"\\?\C:\folder\启动SpiderVPN.cmd", r"C:\a\..\启动SpiderVPN.cmd",
            r"C:\a\.\启动SpiderVPN.cmd", r"C:\a.\启动SpiderVPN.cmd",
            r"C:\a \启动SpiderVPN.cmd", r"C:\a:stream\启动SpiderVPN.cmd",
            r"C:\a\\启动SpiderVPN.cmd", r"C:\NUL.txt\启动SpiderVPN.cmd",
            r"C:\COM1\启动SpiderVPN.cmd", r"C:\LPT²\启动SpiderVPN.cmd",
            r"C:\CONIN$\启动SpiderVPN.cmd"] {
            assert!(launcher_path_parts(Path::new(name)).is_err(), "{name}");
        }
        assert!(launcher_path_parts(Path::new(r"C:\Users\Public\启动SpiderVPN.cmd")).is_ok());
    }


    // D2-LAB only. An isolated filesystem experiment, NOT the production
    // uninstall implementation or a reusable arbitrary-path delete command.
    mod d2_lab {
        use super::super::*;
        use std::{
            fs::{self, File, OpenOptions},
            io::{Seek, SeekFrom, Write},
            os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
            path::PathBuf,
        };
        use windows_sys::Win32::{
            Foundation::GENERIC_READ,
            Storage::FileSystem::{
                GetDriveTypeW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
                SetFileInformationByHandle,
                BY_HANDLE_FILE_INFORMATION, FILE_DISPOSITION_INFO, FILE_STANDARD_INFO,
                FileDispositionInfo, FileStandardInfo, DELETE, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            },
        };

        const FLAGS: u32 = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
        const ALL_SHARES: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        // The only paths the experiment permits disposal of are the two
        // exact launcher names beneath this freshly created random root.
        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                use ring::rand::{SecureRandom, SystemRandom};
                let mut nonce = [0u8; 16];
                SystemRandom::new().fill(&mut nonce).unwrap();
                let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
                // Resolve only the test fixture base, never a candidate
                // launcher. Retain the checked handles until fixture creation.
                let (base, base_handles) = fixture_base().expect("D2 canonical isolated temp base");
                let path = base.join(format!("spider-d2-lab-{}-{suffix}", std::process::id()));
                fs::create_dir(&path).expect("fresh exclusively created D2 fixture");
                check_ancestors(&base_handles).expect("D2 temp base stable after create");
                drop(base_handles);
                let fixture = Self(path);
                for dir in [fixture.desktop(), fixture.install(), fixture.neighbor(), fixture.install().join("bin")] {
                    fs::create_dir(dir).unwrap();
                }
                fixture
            }
            fn desktop(&self) -> PathBuf { self.0.join("desktop") }
            fn install(&self) -> PathBuf { self.0.join("install") }
            fn neighbor(&self) -> PathBuf { self.0.join("neighbor") }
            fn path(&self, which: Launcher) -> PathBuf { self.desktop().join(which.name()) }
            fn bytes(&self, which: Launcher) -> Vec<u8> {
                launcher_template(&self.install(), which.name()).unwrap().into_bytes()
            }
            fn write_launcher(&self, which: Launcher) {
                fs::write(self.path(which), self.bytes(which)).unwrap();
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                // Test cleanup only, never part of the disposition primitive.
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        #[derive(Clone, Copy)]
        enum Launcher { Start, Uninstall }
        impl Launcher {
            fn name(self) -> &'static str {
                match self { Self::Start => "启动SpiderVPN.cmd", Self::Uninstall => "卸载SpiderVPN.cmd" }
            }
        }
        fn id(info: &BY_HANDLE_FILE_INFORMATION) -> (u32, u32, u32) {
            (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow)
        }
        fn unchanged(before: &BY_HANDLE_FILE_INFORMATION, after: &BY_HANDLE_FILE_INFORMATION) -> bool {
            id(before) == id(after)
                && before.dwFileAttributes == after.dwFileAttributes
                && before.nNumberOfLinks == after.nNumberOfLinks
                && launcher_size(before) == launcher_size(after)
                && before.ftLastWriteTime.dwHighDateTime == after.ftLastWriteTime.dwHighDateTime
                && before.ftLastWriteTime.dwLowDateTime == after.ftLastWriteTime.dwLowDateTime
        }
        fn open_error(where_: &str, e: std::io::Error) -> String {
            format!("{where_} win32={:?}: {e}", e.raw_os_error())
        }
        type Ancestors = Vec<(PathBuf, File, BY_HANDLE_FILE_INFORMATION)>;

        // Diagnostic only: the original production D1 path comparison is
        // always the decision for candidate and canonical ancestor objects.
        fn dos_path(file: &File) -> Result<PathBuf, String> {
            let mut buffer = vec![0u16; 32768];
            let n = unsafe {
                GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(),
                    buffer.len() as u32, 0)
            } as usize;
            if n == 0 { return Err(open_error("D2_FINAL_PATH", std::io::Error::last_os_error())); }
            if n >= buffer.len() { return Err("D2_FINAL_PATH_OVERSIZE".into()); }
            let actual = String::from_utf16(&buffer[..n]).map_err(|_| "D2_FINAL_PATH_UTF16")?;
            let dos = actual.strip_prefix(r"\\?\").ok_or("D2_FINAL_PATH_NOT_DOS")?;
            Ok(PathBuf::from(dos))
        }
        fn strict_path(file: &File, expected: &Path) -> Result<(), String> {
            launcher_handle_path(file, expected).map_err(|reason| {
                let actual = dos_path(file);
                marker(&format!("D2_LAB_PATH_REJECT expected={expected:?} actual={actual:?} reason={reason}"));
                format!("{reason}; expected={expected:?} actual={actual:?}")
            })
        }
        fn fixed_drive(parts: &[PathBuf]) -> Result<(), String> {
            let drive: Vec<u16> = parts[0].as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe { GetDriveTypeW(drive.as_ptr()) } != 3 {
                return Err("D2_NOT_FIXED_DISK".into());
            }
            Ok(())
        }
        fn open_dir(path: &Path) -> Result<File, String> {
            OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ).custom_flags(FLAGS)
                .open(path).map_err(|e| format!("{} component={path:?}", open_error("D2_OPEN_PARENT", e)))
        }
        fn fixture_base() -> Result<(PathBuf, Ancestors), String> {
            let raw = std::env::temp_dir();
            marker(&format!("D2_LAB_TEMP_RAW path={raw:?}"));
            // GetTempPath may include a trailing separator. Build a
            // non-opened synthetic child exactly as the original fixture
            // joined its child, then discard that component. The strict
            // parser still rejects interior aliases/empty segments.
            let mut original = launcher_path_parts(&raw.join("spider-d2-base-component-probe"))?;
            original.pop().ok_or("D2_TEMP_EMPTY")?;
            if original.len() < 2 { return Err("D2_TEMP_DRIVE_ROOT".into()); }
            fixed_drive(&original)?;
            // No canonicalize()/follow-reparse shortcut: inspect each
            // lexical component with OPEN_REPARSE_POINT, retaining handles.
            let mut first = Vec::new();
            let mut normalized = Vec::new();
            for path in &original {
                let file = open_dir(path)?;
                let info = launcher_handle_info(&file, true)
                    .map_err(|e| format!("D2_TEMP_OBJECT component={path:?} {e}"))?;
                let actual = dos_path(&file)?;
                let same_spelling = path.to_str().ok_or("D2_TEMP_UTF8")?
                    .eq_ignore_ascii_case(actual.to_str().ok_or("D2_TEMP_UTF8")?);
                marker(&format!("D2_LAB_TEMP_COMPONENT expected={path:?} actual={actual:?} strict_spelling={same_spelling} id={:?} nonreparse=true", id(&info)));
                normalized.push(actual);
                first.push((path.clone(), file, info));
            }
            let base = normalized.last().ok_or("D2_TEMP_EMPTY")?.clone();
            let canonical = launcher_path_parts(&base)?;
            fixed_drive(&canonical)?;
            // Only accept an alternative DOS spelling of the same component
            // chain. No redirected drive, skipped ancestor or symlink target.
            if canonical.len() != original.len()
                || !canonical[0].to_str().ok_or("D2_TEMP_UTF8")?
                    .eq_ignore_ascii_case(original[0].to_str().ok_or("D2_TEMP_UTF8")?)
            {
                return Err("D2_TEMP_CHAIN_CHANGED".into());
            }
            let mut held = Vec::new();
            for ((path, actual), (_, original_file, before)) in
                canonical.iter().zip(&normalized).zip(&first)
            {
                let file = open_dir(path)?;
                let info = launcher_handle_info(&file, true)?;
                strict_path(&file, path)?;
                strict_path(original_file, actual)?;
                let now = launcher_handle_info(original_file, true)?;
                if id(&info) != id(before) || id(&now) != id(before)
                    || (info.nFileIndexHigh == 0 && info.nFileIndexLow == 0)
                    || !path.to_str().ok_or("D2_TEMP_UTF8")?
                        .eq_ignore_ascii_case(actual.to_str().ok_or("D2_TEMP_UTF8")?)
                {
                    return Err(format!("D2_TEMP_ID_OR_CHAIN_MISMATCH component={path:?} actual={actual:?}"));
                }
                held.push((path.clone(), file, info));
            }
            check_ancestors(&held)?;
            marker(&format!("D2_LAB_TEMP_VERIFIED raw={raw:?} canonical={base:?} fixed_disk=true same_component_ids=true nonreparse=true strict_canonical=true"));
            Ok((base, held))
        }
        fn hold_ancestors(path: &Path) -> Result<Ancestors, String> {
            let parts = launcher_path_parts(path)?;
            fixed_drive(&parts)?;
            let (_, parents) = parts.split_last().ok_or("D2_NO_PARENTS")?;
            let mut held = Vec::new();
            for parent in parents {
                let file = open_dir(parent)?;
                let info = launcher_handle_info(&file, true)
                    .map_err(|e| format!("D2_PARENT_OBJECT component={parent:?} {e}"))?;
                strict_path(&file, parent)?;
                held.push((parent.clone(), file, info));
            }
            Ok(held)
        }
        fn check_ancestors(held: &Ancestors) -> Result<(), String> {
            for (path, file, before) in held {
                let now = launcher_handle_info(file, true)?;
                if id(before) != id(&now) { return Err("D2_PARENT_ID_CHANGED".into()); }
                strict_path(file, path)?;
            }
            Ok(())
        }
        fn open_delete_read(path: &Path) -> std::io::Result<File> {
            OpenOptions::new().access_mode(GENERIC_READ | DELETE)
                .share_mode(FILE_SHARE_READ).custom_flags(FLAGS).open(path)
        }
        fn independent_read(path: &Path) -> std::io::Result<File> {
            OpenOptions::new().read(true).share_mode(ALL_SHARES)
                .custom_flags(FLAGS).open(path)
        }
        fn pending(file: &File) -> std::io::Result<bool> {
            let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
            // SAFETY: live handle and correctly sized SDK output struct.
            if unsafe {
                GetFileInformationByHandleEx(file.as_raw_handle(), FileStandardInfo,
                    (&mut info as *mut FILE_STANDARD_INFO).cast(),
                    std::mem::size_of::<FILE_STANDARD_INFO>() as u32)
            } == 0 { return Err(std::io::Error::last_os_error()); }
            Ok(info.DeletePending as u8 != 0)
        }
        fn set_disposition(file: &File) -> std::io::Result<()> {
            let info = FILE_DISPOSITION_INFO { DeleteFile: true as _ };
            // SAFETY: live handle; SDK layout; no pathname or second open.
            if unsafe {
                SetFileInformationByHandle(file.as_raw_handle(), FileDispositionInfo,
                    (&info as *const FILE_DISPOSITION_INFO).cast(),
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32)
            } == 0 { return Err(std::io::Error::last_os_error()); }
            Ok(())
        }
        struct Verified<'a> {
            fixture: &'a Fixture,
            which: Launcher,
            path: PathBuf,
            parents: Ancestors,
            file: File,
            before: BY_HANDLE_FILE_INFORMATION,
        }
        impl<'a> Verified<'a> {
            fn open(fixture: &'a Fixture, which: Launcher) -> Result<Self, String> {
                let path = fixture.path(which);
                let parents = hold_ancestors(&path)?;
                let file = open_delete_read(&path).map_err(|e| open_error("D2_OPEN_LEAF", e))?;
                let before = launcher_handle_info(&file, false)
                    .map_err(|e| format!("D2_LEAF_OBJECT {e}"))?;
                let mut verified = Self { fixture, which, path, parents, file, before };
                verified.recheck()?;
                Ok(verified)
            }
            fn recheck(&mut self) -> Result<(), String> {
                check_ancestors(&self.parents)?;
                strict_path(&self.file, &self.path)?;
                let first = launcher_handle_info(&self.file, false)
                    .map_err(|e| format!("D2_LEAF_OBJECT {e}"))?;
                if !unchanged(&self.before, &first) || launcher_size(&first) > MAX_LAUNCHER_BYTES {
                    return Err("D2_LEAF_CHANGED_OR_OVERSIZE".into());
                }
                self.file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                let bytes = read_launcher_bounded(&mut self.file).map_err(|e| e.to_string())?;
                let last = launcher_handle_info(&self.file, false)?;
                if bytes.len() as u64 != launcher_size(&last) || !unchanged(&first, &last)
                    || !owned_launcher_bytes(&bytes, &self.fixture.install(), self.which.name())
                {
                    return Err("D2_TEMPLATE_OR_IDENTITY_MISMATCH".into());
                }
                strict_path(&self.file, &self.path)?;
                check_ancestors(&self.parents)?;
                if pending(&self.file).map_err(|e| open_error("D2_PENDING_QUERY", e))? {
                    return Err("D2_ALREADY_PENDING".into());
                }
                Ok(())
            }
            fn mark(&mut self) -> Result<(), String> {
                self.recheck()?;
                set_disposition(&self.file).map_err(|e| open_error("D2_DISPOSITION_FAILED", e))?;
                // Success of the call alone is not proof of deletion.
                if !pending(&self.file).map_err(|e| open_error("D2_PENDING_QUERY", e))? {
                    return Err("D2_DISPOSITION_NOT_READ_BACK".into());
                }
                Ok(())
            }
            fn close_and_read_back(self) -> Result<(), String> {
                if !pending(&self.file).map_err(|e| open_error("D2_PENDING_QUERY", e))? {
                    return Err("D2_NOT_MARKED".into());
                }
                let Self { file, path, parents, .. } = self;
                drop(file);
                // Keep the original ancestor handles until completion is
                // checked by a separate open AND enumeration of the parent.
                check_ancestors(&parents)?;
                match independent_read(&path) {
                    Err(e) if e.raw_os_error() == Some(2) => {}
                    Err(e) => return Err(open_error("D2_ABSENCE_UNKNOWN", e)),
                    Ok(_) => return Err("D2_NAME_STILL_EXISTS".into()),
                }
                let name = path.file_name().ok_or("D2_NO_NAME")?;
                for entry in fs::read_dir(path.parent().ok_or("D2_NO_PARENT")?)
                    .map_err(|e| open_error("D2_ENUM_FAILED", e))?
                {
                    if entry.map_err(|e| open_error("D2_ENUM_FAILED", e))?.file_name() == name {
                        return Err("D2_NAME_STILL_ENUMERATED".into());
                    }
                }
                check_ancestors(&parents)?;
                Ok(())
            }
        }
        fn refusal<T>(result: Result<T, String>, prefix: &str) -> String {
            match result {
                Err(e) if e.starts_with(prefix) => e,
                Err(e) => panic!("expected {prefix}, got {e}"),
                Ok(_) => panic!("unexpected acceptance: {prefix}"),
            }
        }
        fn win32_refused<T>(result: std::io::Result<T>, label: &str, codes: &[i32]) -> i32 {
            let err = match result { Ok(_) => panic!("{label}: unexpected success"), Err(e) => e };
            let code = err.raw_os_error().expect("actual Win32 error");
            assert!(codes.contains(&code), "{label}: unexpected Win32 error {code}: {err}");
            code
        }
        fn snapshot(path: &Path) -> ((u32, u32, u32), Vec<u8>) {
            // Identity and bytes must come from one independently opened
            // object; no second pathname open between those observations.
            let mut file = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ)
                .custom_flags(FLAGS).open(path).unwrap();
            let before = launcher_handle_info(&file, false).unwrap();
            strict_path(&file, path).unwrap();
            assert!(launcher_size(&before) <= MAX_LAUNCHER_BYTES);
            let bytes = read_launcher_bounded(&mut file).unwrap();
            let after = launcher_handle_info(&file, false).unwrap();
            strict_path(&file, path).unwrap();
            assert!(unchanged(&before, &after));
            assert_eq!(bytes.len() as u64, launcher_size(&after));
            (id(&before), bytes)
        }
        fn marker(line: &str) {
            // Direct stdout is not swallowed by libtest's normal capture;
            // existing filtered GNU and MSVC CI need no workflow changes.
            writeln!(std::io::stdout().lock(), "{line}").unwrap();
        }

        #[test]
        fn d2_same_handle_disposition_pending_then_independent_absence() {
            let fixture = Fixture::new();
            let neighbor = fixture.neighbor().join(Launcher::Start.name());
            fs::write(&neighbor, fixture.bytes(Launcher::Start)).unwrap();
            let unrelated = fixture.desktop().join("unknown.cmd");
            fs::write(&unrelated, b"unrelated data").unwrap();
            let keep = snapshot(&neighbor);
            let keep_unknown = snapshot(&unrelated);
            for which in [Launcher::Start, Launcher::Uninstall] {
                fixture.write_launcher(which);
                let path = fixture.path(which);
                let mut verified = Verified::open(&fixture, which).unwrap();
                let observer = independent_read(&path).unwrap();
                assert_eq!(id(&verified.before), id(&launcher_handle_info(&observer, false).unwrap()));
                assert!(!pending(&observer).unwrap());
                verified.mark().unwrap();
                assert!(pending(&observer).unwrap(), "independent live handle must observe disposition");
                let reopen = win32_refused(independent_read(&path), "delete-pending reopen", &[5, 32, 303]);
                // Last close, not SetFileInformationByHandle alone, proves removal.
                drop(observer);
                verified.close_and_read_back().unwrap();
                assert_eq!(snapshot(&neighbor), keep);
                assert_eq!(snapshot(&unrelated), keep_unknown);
                marker(&format!("D2_LAB_DISPOSITION name={} same_id=true pending_readback=true pending_open_win32={reopen} absent_after_close=true neighbor_preserved=true", which.name()));
            }
        }

        #[test]
        fn d2_old_write_and_delete_share_block_before_disposition() {
            let fixture = Fixture::new();
            let which = Launcher::Start;
            fixture.write_launcher(which);
            let path = fixture.path(which);
            let original = snapshot(&path);
            // Independently opened old write handle, even when it shares all
            // access, conflicts with the candidate's refusal to share writes.
            let mut writer = OpenOptions::new().write(true).share_mode(ALL_SHARES).open(&path).unwrap();
            let old_write = refusal(Verified::open(&fixture, which), "D2_OPEN_LEAF win32=Some(32)");
            writer.seek(SeekFrom::Start(0)).unwrap();
            writer.write_all(&fixture.bytes(which)).unwrap();
            writer.flush().unwrap();
            drop(writer);
            assert_eq!(snapshot(&path), original);
            let reader = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE).open(&path).unwrap();
            let no_delete = refusal(Verified::open(&fixture, which), "D2_OPEN_LEAF win32=Some(32)");
            drop(reader);
            assert_eq!(snapshot(&path), original);
            let mut verified = Verified::open(&fixture, which).unwrap();
            assert_eq!(id(&verified.before), original.0);
            verified.mark().unwrap();
            verified.close_and_read_back().unwrap();
            marker(&format!("D2_LAB_OLD_HANDLES old_write={old_write:?} no_delete_share={no_delete:?} preserved_until_release=true deletion_after_release=true"));
        }

        #[test]
        fn d2_verified_object_blocks_rename_replacement_and_ancestor_move() {
            let fixture = Fixture::new();
            let which = Launcher::Start;
            fixture.write_launcher(which);
            let path = fixture.path(which);
            let original = snapshot(&path);
            let replacement = fixture.desktop().join("replacement.cmd");
            fs::write(&replacement, b"neighbor replacement sentinel").unwrap();
            let replacement_before = snapshot(&replacement);
            let mut verified = Verified::open(&fixture, which).unwrap();
            let write = win32_refused(OpenOptions::new().write(true).share_mode(ALL_SHARES).open(&path), "write reopen", &[32]);
            let rename = win32_refused(fs::rename(&path, fixture.desktop().join("moved.cmd")), "leaf rename", &[5, 32]);
            let replace = win32_refused(fs::rename(&replacement, &path), "replacement", &[5, 32]);
            let parent = win32_refused(fs::rename(fixture.desktop(), fixture.0.join("moved-desktop")), "parent rename", &[5, 32]);
            let ancestor = win32_refused(fs::rename(&fixture.0, fixture.0.with_extension("moved")), "ancestor rename", &[5, 32]);
            verified.recheck().unwrap();
            let mut observer = independent_read(&path).unwrap();
            let observed = read_launcher_bounded(&mut observer).unwrap();
            assert_eq!(id(&launcher_handle_info(&observer, false).unwrap()), original.0);
            assert_eq!(observed, original.1);
            drop(observer);
            assert_eq!(snapshot(&replacement), replacement_before);
            verified.mark().unwrap();
            verified.close_and_read_back().unwrap();
            assert_eq!(snapshot(&replacement), replacement_before);
            marker(&format!("D2_LAB_COMPETITION write={write} rename={rename} replace={replace} parent={parent} ancestor={ancestor} same_id=true replacement_preserved=true"));
        }

        #[test]
        fn d2_custom_other_install_hardlink_and_reparse_are_preserved() {
            let fixture = Fixture::new();
            let which = Launcher::Start;
            let path = fixture.path(which);
            let other = launcher_template(&fixture.neighbor(), which.name()).unwrap();
            fs::write(&path, other.as_bytes()).unwrap();
            let before = snapshot(&path);
            refusal(Verified::open(&fixture, which), "D2_TEMPLATE_OR_IDENTITY_MISMATCH");
            assert_eq!(snapshot(&path), before);
            fs::write(&path, b"@echo off\r\nrem custom user script\r\n").unwrap();
            let before = snapshot(&path);
            refusal(Verified::open(&fixture, which), "D2_TEMPLATE_OR_IDENTITY_MISMATCH");
            assert_eq!(snapshot(&path), before);
            fixture.write_launcher(which);
            let before = snapshot(&path);
            let linked = fixture.neighbor().join("linked.cmd");
            fs::hard_link(&path, &linked).unwrap();
            refusal(Verified::open(&fixture, which), "D2_LEAF_OBJECT");
            assert_eq!(fs::read(&path).unwrap(), before.1);
            assert_eq!(fs::read(&linked).unwrap(), before.1);
            fs::remove_file(&linked).unwrap();
            assert_eq!(snapshot(&path), before);

            // Create an actual directory junction to another fixture dir,
            // not a symlink emulation. Never descend through it for deletion.
            let real_desktop = fixture.0.join("original-desktop");
            fs::rename(fixture.desktop(), &real_desktop).unwrap();
            let target = fixture.neighbor().join(which.name());
            fs::write(&target, fixture.bytes(which)).unwrap();
            let target_before = snapshot(&target);
            let output = std::process::Command::new(PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("cmd.exe"))
                .args(["/D", "/C", "mklink", "/J"]).arg(fixture.desktop()).arg(fixture.neighbor())
                .output().unwrap();
            assert!(output.status.success(), "junction fixture failed: {:?}", output);
            refusal(Verified::open(&fixture, which), "D2_PARENT_OBJECT");
            assert_eq!(snapshot(&target), target_before);
            fs::remove_dir(fixture.desktop()).unwrap();
            fs::rename(&real_desktop, fixture.desktop()).unwrap();
            assert_eq!(snapshot(&path), before);
            // Leaf symlink needs privilege/developer mode. Attempt it and
            // report actual unsupported privilege, not a fabricated pass.
            let leaf = fixture.path(Launcher::Uninstall);
            match std::os::windows::fs::symlink_file(&target, &leaf) {
                Ok(()) => {
                    refusal(Verified::open(&fixture, Launcher::Uninstall), "D2_LEAF_OBJECT");
                    assert_eq!(snapshot(&target), target_before);
                    assert!(fs::symlink_metadata(&leaf).unwrap().file_type().is_symlink());
                    fs::remove_file(&leaf).unwrap();
                    marker("D2_LAB_LEAF_SYMLINK actual=true refused=true target_preserved=true");
                }
                Err(e) if matches!(e.raw_os_error(), Some(1314) | Some(5)) => {
                    marker(&format!("D2_LAB_LEAF_SYMLINK NOT_RUN win32={:?}", e.raw_os_error()));
                }
                Err(e) => panic!("unexpected symlink fixture failure: {e}"),
            }
            marker("D2_LAB_NONOWNED other_install=true custom=true hardlink=true ancestor_junction=true unchanged=true");
        }

        // The recovery group is deliberately non-executable fixture data.
        // Acquire candidates without any disposition: a failed member or
        // absent independent trusted recovery entry cannot break the group.
        fn recovery_stop_before_mutation(fixture: &Fixture) -> Result<(), String> {
            let bin = fixture.install().join("bin");
            let paths = [bin.join("spidervpn.exe"), bin.join("WebView2Loader.dll")];
            let parents = hold_ancestors(&paths[0])?;
            let mut files = Vec::new();
            for path in &paths {
                let file = open_delete_read(path).map_err(|e| open_error("D2_RECOVERY_MEMBER_OPEN", e))?;
                launcher_handle_info(&file, false)?;
                strict_path(&file, path)?;
                files.push(file);
            }
            check_ancestors(&parents)?;
            // There is no production trusted recovery entry in this LAB.
            // No argument, boolean or test switch can convert this to permission.
            Err("D2_NO_TRUSTED_RECOVERY_ENTRY".into())
        }

        #[test]
        fn d2_real_disposition_error_and_recovery_group_stops_intact() {
            let fixture = Fixture::new();
            let which = Launcher::Start;
            fixture.write_launcher(which);
            let path = fixture.path(which);
            let original = snapshot(&path);
            // Actual kernel rejection, not an injected HRESULT. A read-only
            // access handle has no DELETE access; this is a prerequisite
            // negative control, not a failure of the validated DELETE handle.
            let reader = independent_read(&path).unwrap();
            assert!(!pending(&reader).unwrap());
            let error = win32_refused(set_disposition(&reader), "disposition without DELETE access", &[5]);
            assert!(!pending(&reader).unwrap());
            drop(reader);
            assert_eq!(snapshot(&path), original);
            // Distinct actual disposition failure on a fully validated
            // DELETE+read handle: classic FileDispositionInfo cannot mark
            // a read-only file for deletion. No attribute change is made
            // by the candidate. Restore the fixture attribute only after
            // verifying that the original object remains intact.
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).unwrap();
            let readonly_before = snapshot(&path);
            let mut verified = Verified::open(&fixture, which).unwrap();
            assert_eq!(id(&verified.before), readonly_before.0);
            let disposition_error = refusal(verified.mark(), "D2_DISPOSITION_FAILED win32=Some(5)");
            assert!(!pending(&verified.file).unwrap());
            drop(verified);
            assert_eq!(snapshot(&path), readonly_before);
            assert!(fs::metadata(&path).unwrap().permissions().readonly());
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions).unwrap();
            assert_eq!(snapshot(&path), original);
            marker(&format!("D2_LAB_VALIDATED_DISPOSITION_ERROR error={disposition_error:?} granted_delete=true read_only=true pending=false same_id_bytes=true"));
            let bin = fixture.install().join("bin");
            let exe = bin.join("spidervpn.exe");
            let dll = bin.join("WebView2Loader.dll");
            fs::write(&exe, b"LAB only recovery main sentinel, not executable").unwrap();
            fs::write(&dll, b"LAB only dependency sentinel, not executable").unwrap();
            let exe_before = snapshot(&exe);
            let dll_before = snapshot(&dll);
            let old_writer = OpenOptions::new().write(true).share_mode(ALL_SHARES).open(&dll).unwrap();
            refusal(recovery_stop_before_mutation(&fixture), "D2_RECOVERY_MEMBER_OPEN win32=Some(32)");
            drop(old_writer);
            assert_eq!(snapshot(&exe), exe_before);
            assert_eq!(snapshot(&dll), dll_before);
            refusal(recovery_stop_before_mutation(&fixture), "D2_NO_TRUSTED_RECOVERY_ENTRY");
            assert_eq!(snapshot(&exe), exe_before);
            assert_eq!(snapshot(&dll), dll_before);
            marker(&format!("D2_LAB_RECOVERY disposition_without_delete_win32={error} pending=false dependency_open_failed=true group_unchanged=true no_trusted_entry_stopped=true real_recovery_process=false production_recovery_proven=false"));
        }
    }
}

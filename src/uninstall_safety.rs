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

}

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

const BIN_MANIFEST: &[&str] = &[
    "spidervpn.exe",
    "sing-box.exe",
    "WebView2Loader.dll",
    "sing-box.LICENSE.txt",
];

/// Names of the files the thin script is allowed to delete. Keeping this
/// manifest in Rust avoids PS inventing an unreviewed wildcard deletion.
pub fn code_file_manifest() -> &'static [&'static str] { BIN_MANIFEST }

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

/// This only reports ownership for known desktop/start-menu launchers.
/// No deletion, no filesystem mutation and no WFP access.
pub fn owns_launcher(path: &Path, root: &Path) -> Result<bool, String> {
    actual_installation(root)?;
    let name = path.file_name().and_then(|s| s.to_str())
        .ok_or_else(|| "快捷方式文件名不是有效文本".to_string())?;
    let Some(_) = launcher_template(root, name) else { return Ok(false); };
    let content = std::fs::read(path)
        .map_err(|e| format!("读取快捷方式 {} 失败：{e}", path.display()))?;
    if content.len() > 8192 { return Ok(false); }
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
    fn manifest_contains_engine_and_does_not_admit_wildcards() {
        assert!(code_file_manifest().contains(&"sing-box.exe"));
        assert!(code_file_manifest().contains(&"WebView2Loader.dll"));
        assert!(code_file_manifest().contains(&"spidervpn.exe"));
        assert!(code_file_manifest().iter().all(|n| !n.contains('*') && !n.contains('\\')));
    }
}

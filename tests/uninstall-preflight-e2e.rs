//! Real CLI shape tests for the SEC-09 uninstall authorization boundary.
//! These checks never operate on a real installation, WFP filters or proxy.

#![cfg(windows)]

use std::process::Command;

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .args(args)
        .output()
        .expect("run real compiled SpiderVPN CLI")
}

#[test]
fn uninstall_preflight_must_refuse_target_unrelated_to_running_exe() {
    // Even when a CI runner happens to have admin privileges, this binary
    // is not installed at the production root. It must not touch WFP.
    let result = cli(&["--uninstall-preflight", r"C:\SpiderVPN2"]);
    assert_ne!(result.status.code(), Some(0),
        "an unrelated root must never authorize uninstall");
}

#[test]
fn keep_guard_does_not_bypass_real_installed_exe_identity_gate() {
    let result = cli(&["--uninstall-preflight", r"C:\SpiderVPN2", "--keep-guard"]);
    assert_ne!(result.status.code(), Some(0),
        "keep-guard cannot turn an unrelated executable into an uninstaller");
}

#[test]
fn shortcut_ownership_cannot_be_checked_against_untrusted_install_root() {
    let result = cli(&[
        "--uninstall-owns-shortcut", r"C:\non-existent-custom-shortcut.cmd",
        r"C:\SpiderVPN2",
    ]);
    assert_ne!(result.status.code(), Some(0),
        "must refuse to certify shortcuts for an unrelated install root");
}

#[test]
fn required_arguments_are_checked_before_gui_startup() {
    for args in [
        vec!["--uninstall-preflight"],
        vec!["--uninstall-owns-shortcut", "only-one-argument"],
    ] {
        let result = cli(&args);
        assert_eq!(result.status.code(), Some(2),
            "invalid internal args must report usage error, not start UI");
    }
}


#[test]
fn package_uninstall_script_honors_rust_gate_before_any_deletion() {
    let script = include_str!("../package-files/uninstall.ps1");
    let gate = script.find("--uninstall-preflight").expect("Rust WFP preflight");
    let owned = script.find("--uninstall-owns-shortcut").expect("Rust launcher identity");
    let first_cleanup = script.find("Remove-Item").expect("uninstall file cleanup");
    assert!(gate < owned && owned < first_cleanup,
        "never clean launchers/binaries before Rust WFP and ownership gates");
    assert!(!script.contains("elseif ($guardCode -eq 3)"),
        "config-missing WFP failure must never be treated as permission to delete");
    assert!(!script.contains(".Contains($TargetDir)"),
        "substring path ownership can delete neighboring installations");
    assert!(script.contains("'sing-box.exe'"), "bundled engine must not survive uninstall");
    assert!(script.contains("'sing-box.LICENSE.txt'"));
    assert!(!script.contains("Read-Host '  确实要继续卸载吗？输入 FORCE 继续'"),
        "unrestored proxy journal must not have a FORCE bypass");
}


// Real debug-install fixture: copied actual executable, isolated root and
// no preflight/WFP/delete calls. Canonicalize temp before choosing a plain
// local DOS path (Windows temp may be provided in short-name form).
#[test]
fn launcher_ownership_real_cli_is_bounded_and_refuses_unsafe_objects() {
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    static ID: AtomicU64 = AtomicU64::new(0);
    let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let temp = temp.to_str().unwrap().strip_prefix(r"\\?\").unwrap_or(temp.to_str().unwrap());
    let root = PathBuf::from(temp).join(format!("spider-uninstall-read-{}-{}",
        std::process::id(), ID.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
    }
    let _cleanup = Cleanup(root.clone());
    let install = root.join("install");
    let bin = install.join("bin");
    let desktop = root.join("desktop");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir(&desktop).unwrap();
    let source = PathBuf::from(env!("CARGO_BIN_EXE_spidervpn"));
    let exe = bin.join("spidervpn.exe");
    std::fs::copy(&source, &exe).unwrap();
    // Preserve any adjacent loader required by this build; do not execute
    // an installer or affect real desktop files.
    let loader = source.parent().unwrap().join("WebView2Loader.dll");
    if loader.is_file() {
        std::fs::copy(loader, bin.join("WebView2Loader.dll")).unwrap();
    }
    let ownership = |path: &std::path::Path, code: i32| {
        let output = Command::new(&exe).arg("--uninstall-owns-shortcut")
            .arg(path).arg(&install).output().expect("run isolated real CLI");
        assert_eq!(output.status.code(), Some(code), "{}: {}",
            path.display(), String::from_utf8_lossy(&output.stderr));
    };
    let launch = desktop.join("启动SpiderVPN.cmd");
    let exact = format!("@echo off\r\nstart \"\" \"{}\"\r\n", exe.display());
    let uninstall = desktop.join("卸载SpiderVPN.cmd");
    let exact_uninstall = format!("@echo off\r\npowershell -NoProfile -ExecutionPolicy Bypass -File \"{}\"\r\npause\r\n",
        install.join("uninstall.ps1").display());
    std::fs::write(&launch, exact.as_bytes()).unwrap();
    std::fs::write(&uninstall, exact_uninstall.as_bytes()).unwrap();
    ownership(&launch, 0);
    ownership(&uninstall, 0);
    assert_eq!(std::fs::read(&launch).unwrap(), exact.as_bytes());
    assert_eq!(std::fs::read(&uninstall).unwrap(), exact_uninstall.as_bytes());
    std::fs::write(&launch, exact.replace("install\\bin", "install2\\bin")).unwrap();
    ownership(&launch, 3);
    std::fs::write(&launch, format!("{exact}rem custom")).unwrap();
    ownership(&launch, 3);
    for size in [8192, 8193, 1024 * 1024] {
        std::fs::write(&launch, vec![b'x'; size]).unwrap();
        ownership(&launch, 3);
        assert_eq!(std::fs::metadata(&launch).unwrap().len(), size as u64);
    }
    std::fs::write(&launch, exact.as_bytes()).unwrap();
    let other = desktop.join("external.cmd");
    std::fs::hard_link(&launch, &other).unwrap();
    ownership(&launch, 4);
    assert_eq!(std::fs::read(&other).unwrap(), exact.as_bytes());
    std::fs::remove_file(&other).unwrap();
    let writer = std::fs::OpenOptions::new().write(true)
        .share_mode(FILE_SHARE_READ).open(&launch).unwrap();
    ownership(&launch, 4);
    drop(writer);
    ownership(&launch, 0);
    let missing = root.join("missing").join("启动SpiderVPN.cmd");
    ownership(&missing, 4);
    let directory = root.join("directory");
    std::fs::create_dir(&directory).unwrap();
    let disguised = directory.join("启动SpiderVPN.cmd");
    std::fs::create_dir(&disguised).unwrap();
    ownership(&disguised, 4);
    let alias = root.join("junction");
    // Directory junction creation on the isolated fixed NTFS runner
    // does not require the optional symbolic-link developer privilege.
    let output = Command::new("cmd.exe").args(["/D", "/C", "mklink", "/J"])
        .arg(&alias).arg(&desktop).output().unwrap();
    assert!(output.status.success(), "junction fixture: {}", String::from_utf8_lossy(&output.stderr));
    ownership(&alias.join("启动SpiderVPN.cmd"), 4);
    // Remove ONLY the fixture junction, not its target.
    std::fs::remove_dir(&alias).unwrap();
    assert_eq!(std::fs::read(&launch).unwrap(), exact.as_bytes());
    match std::os::windows::fs::symlink_file(&launch, &other) {
        Ok(()) => {
            // Use a known launcher name too, so the read gate is exercised.
            let linked = directory.join("卸载SpiderVPN.cmd");
            std::os::windows::fs::symlink_file(&uninstall, &linked).unwrap();
            ownership(&linked, 4);
            std::fs::remove_file(&linked).unwrap();
            std::fs::remove_file(&other).unwrap();
            println!("LAUNCHER_LEAF_SYMLINK_REFUSED");
        }
        Err(e) if e.raw_os_error() == Some(1314) => {
            println!("LAUNCHER_LEAF_SYMLINK_UNAVAILABLE privilege=1314; mandatory junction/hardlink verified");
        }
        Err(e) => panic!("unexpected symlink fixture failure: {e}"),
    }
    ownership(&desktop.join("unknown.cmd"), 3);
    ownership(&uninstall, 0);
    assert_eq!(std::fs::read(&launch).unwrap(), exact.as_bytes());
    assert_eq!(std::fs::read(&uninstall).unwrap(), exact_uninstall.as_bytes());
    println!("LAUNCHER_READ_CLI_COMPLETE exact=true oversize_refused=true hardlink_refused=true junction_refused=true writer_refused=true unchanged=true");
}

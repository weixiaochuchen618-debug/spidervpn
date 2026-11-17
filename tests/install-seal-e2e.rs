//! SEC-03: exercise the real Rust CLI entry during an isolated install.
//! No GUI, real WFP filters, system proxy, or production C:\SpiderVPN touched.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "spidervpn-sec03-installer-e2e-{tag}-{}", std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn run(root: &Path, arg: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_spidervpn"))
        .arg("--install-seal").arg(arg)
        .env("SPIDERVPN_ROOT", root)
        .output().expect("run actual Rust binary")
}

fn admin() -> bool {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_WRITE};
    winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags("SOFTWARE", KEY_WRITE).is_ok()
}

#[test]
fn install_seal_requires_actual_admin_and_preserves_writable_data() {
    let root = temp_root("fresh");
    let arg = root.to_str().expect("Windows test temp must be UTF-8");
    let result = run(&root, arg);
    let out = String::from_utf8_lossy(&result.stdout);
    let err = String::from_utf8_lossy(&result.stderr);
    if admin() {
        assert_eq!(result.status.code(), Some(0), "admin install should seal: {out} {err}");
        assert!(root.join("bin").is_dir());
        let data = root.join("data");
        assert!(data.is_dir());
        std::fs::write(data.join("config.json"), "user settings must remain writable")
            .expect("user data was accidentally sealed like code");
        let again = run(&root, arg);
        assert_eq!(again.status.code(), Some(0), "seal must be idempotent");
        assert_eq!(std::fs::read_to_string(data.join("config.json")).unwrap(),
            "user settings must remain writable");
        std::fs::remove_dir_all(root).unwrap();
    } else {
        assert_eq!(result.status.code(), Some(4), "unprivileged install must refuse: {out} {err}");
        assert!(!root.join("bin").exists(), "refused install must not create code directory");
    }
}

#[test]
fn install_seal_rejects_volume_root_without_touching_it() {
    let root = temp_root("volume");
    let result = run(&root, r"C:\");
    assert_ne!(result.status.code(), Some(0),
        "volume root must not become a SpiderVPN installation target");
    assert!(!root.exists(), "rejected command must not create a data root");
}

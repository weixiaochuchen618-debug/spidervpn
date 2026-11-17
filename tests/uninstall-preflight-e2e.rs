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

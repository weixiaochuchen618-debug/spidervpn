//! SEC-01/08 pre-integration, opt-in Linux root-only legacy Python retirement.
//!
//! NOT a cutover authorization: no migration, TLS listener or WireGuard writes.
//! Requires an already stopped and persistently masked tc-pair.service; no
//! caller-controlled paths, stdin approvals, or implicit rollback.
//! Compile only with linux-legacy-retire-cli, never enabled by default.
//! 'verify' is a root-only read-only post-reboot check. It does NOT repair or
//! restart an old service and cannot prove non-cooperating root writers absent.
#![cfg(target_os = "linux")]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use spidervpn_pairing_authority::legacy_cutover::observe_old_python_shutdown;
use spidervpn_pairing_authority::legacy_retire::{
    observe_offline_retired_entrypoint, stage_offline_legacy_retirement, RetirementWitness,
};

const APPROVAL: &str = "RETIRE tc-pair.py WITHOUT MIGRATION";
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_LINE: usize = 96;
const POLLIN: i16 = 0x0001;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}
unsafe extern "C" {
    fn geteuid() -> u32;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Denied {
    RootRequired,
    InvalidArguments,
    ShutdownUnverified,
    ApprovalDenied,
    RetirementUncertain,
}

/// The injected operations exist only to test strict call ordering.
/// Actual production dispatch is bound to the local Rust observer and
/// offline filesystem primitive; there is no network-facing API here.
fn run_with<O, A, R>(
    args: &[OsString], uid: u32, mut observe: O, mut approve: A, mut retire: R,
) -> Result<RetirementWitness, Denied>
where
    O: FnMut() -> Result<(), ()>,
    A: FnMut() -> Result<bool, ()>,
    R: FnMut() -> Result<RetirementWitness, ()>,
{
    if uid != 0 {
        return Err(Denied::RootRequired);
    }
    if args.len() != 1 || args[0].as_os_str() != OsStr::new("retire") {
        return Err(Denied::InvalidArguments);
    }
    observe().map_err(|_| Denied::ShutdownUnverified)?;
    if !approve().map_err(|_| Denied::ApprovalDenied)? {
        return Err(Denied::ApprovalDenied);
    }
    // Never use the pre-prompt observation as post-confirmation authority.
    // The retirement primitive also repeats its own root/systemd/process/
    // TCP-listener checks before and after its atomic exchange and fsync.
    observe().map_err(|_| Denied::ShutdownUnverified)?;
    require_witness(retire().map_err(|_| Denied::RetirementUncertain)?)
}

/// A witness proves only the known old script pathname and quarantine
/// representation, NOT exclusive control of all root/SSH writers.
fn require_witness(witness: RetirementWitness) -> Result<RetirementWitness, Denied> {
    if !witness.legacy_script_path_is_directory || !witness.original_script_preserved
        || witness.authorizes_migration() || witness.authorizes_new_listener()
    {
        return Err(Denied::RetirementUncertain);
    }
    Ok(witness)
}

/// Explicit post-reboot *read-only* re-attestation, NOT a resume/retry of
/// retirement. Re-observe the old Python service state on both sides of
/// the existing root-only tombstone+quarantine inspection. No TTY approval
/// is needed because this operation cannot mutate files, peers, or ledger.
fn verify_with<O, V>(
    args: &[OsString], uid: u32, mut observe: O, mut verify: V,
) -> Result<RetirementWitness, Denied>
where
    O: FnMut() -> Result<(), ()>,
    V: FnMut() -> Result<RetirementWitness, ()>,
{
    if uid != 0 {
        return Err(Denied::RootRequired);
    }
    if args.len() != 1 || args[0].as_os_str() != OsStr::new("verify") {
        return Err(Denied::InvalidArguments);
    }
    observe().map_err(|_| Denied::ShutdownUnverified)?;
    let witness = require_witness(verify().map_err(|_| Denied::RetirementUncertain)?)?;
    observe().map_err(|_| Denied::ShutdownUnverified)?;
    Ok(witness)
}

/// Poll each byte with a deadline. No indefinite root-owned TTY block,
/// non-ASCII input, terminal paste longer than MAX_LINE, or partial lines.
fn read_line(tty: &mut File, timeout: Duration) -> Result<String, ()> {
    let started = Instant::now();
    let mut bytes = Vec::new();
    loop {
        let remaining = timeout.checked_sub(started.elapsed()).ok_or(())?;
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut pfd = PollFd { fd: tty.as_raw_fd(), events: POLLIN, revents: 0 };
        let status = unsafe { poll(&mut pfd, 1, millis) };
        if status <= 0 || pfd.revents & POLLIN == 0 {
            return Err(());
        }
        let mut byte = [0u8; 1];
        if tty.read(&mut byte).map_err(|_| ())? != 1 {
            return Err(());
        }
        if byte[0] == b'\n' {
            return String::from_utf8(bytes).map_err(|_| ());
        }
        if !byte[0].is_ascii_graphic() && byte[0] != b' ' {
            return Err(());
        }
        if bytes.len() >= MAX_LINE {
            return Err(());
        }
        bytes.push(byte[0]);
    }
}

/// No stdin, argument, environment, or SSH-exec approval fallback.
/// A privileged SSH session with an allocated PTY is still possible and
/// does not prove older root/SSH writers have been disabled.
fn approve_from_tty() -> Result<bool, ()> {
    let mut tty = OpenOptions::new().read(true).write(true)
        .open("/dev/tty").map_err(|_| ())?;
    if !tty.is_terminal() {
        return Err(());
    }
    writeln!(tty,
        "SpiderVPN EXPERIMENTAL offline legacy Python entrypoint retirement.\n\
         The original tc-pair.py is quarantined; its old path becomes a\n\
         protected empty directory. Proceed only after a separate trusted\n\
         operator has persistently masked and stopped tc-pair.service.\n\
         This does NOT block other root/old SSH writers, import revoked\n\
         invitations, start Rust TLS, or authorize a production cutover.\n\
         Type exactly within 45 seconds:\n{APPROVAL}")
        .map_err(|_| ())?;
    tty.flush().map_err(|_| ())?;
    Ok(read_line(&mut tty, APPROVAL_TIMEOUT)? == APPROVAL)
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let uid = unsafe { geteuid() };
    let is_verify = args.first()
        .is_some_and(|arg| arg.as_os_str() == OsStr::new("verify"));
    let result = if is_verify {
        verify_with(
            &args, uid,
            || observe_old_python_shutdown().map(|_| ()).map_err(|_| ()),
            || observe_offline_retired_entrypoint().map_err(|_| ()),
        )
    } else {
        run_with(
            &args, uid,
            || observe_old_python_shutdown().map(|_| ()).map_err(|_| ()),
            approve_from_tty,
            || stage_offline_legacy_retirement().map_err(|_| ()),
        )
    };
    match result {
        Ok(_) if is_verify => println!(
            "Read-only post-reboot verification: old Python service remains \
             stopped/masked; known tc-pair.py path is an empty private \
             directory and original bytes remain quarantined. \
             NO authorization to migrate grants, start a listener, or \
             modify WireGuard. Other root/SSH writers are NOT excluded."
        ),
        Ok(_) => println!(
            "Offline legacy Python script-path retirement observed. \
             NO authorization to migrate grants, start a listener, or modify \
             WireGuard. Reinspect service and script-path state after reboot."
        ),
        Err(reason) => {
            let message = match reason {
                Denied::RootRequired => "root privileges required",
                Denied::InvalidArguments =>
                    "exact command 'retire' or 'verify' required; no paths or flags accepted",
                Denied::ShutdownUnverified => "old Python shutdown cannot be proven",
                Denied::ApprovalDenied => "controlling TTY approval denied or timed out",
                Denied::RetirementUncertain =>
                    "retirement uncertain; inspect disk before any retry or rollback",
            };
            eprintln!("spidervpn-pair-retire: {message}; NO migration or listener authorization");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    fn args(input: &[&str]) -> Vec<OsString> {
        input.iter().map(|s| OsString::from(*s)).collect()
    }
    fn witness() -> RetirementWitness {
        RetirementWitness {
            legacy_script_path_is_directory: true,
            original_script_preserved: true,
        }
    }
    #[test]
    fn nonroot_and_invalid_args_cannot_read_tty_or_mutate() {
        for (uid, argv, reason) in [
            (1001, args(&["retire"]), Denied::RootRequired),
            (0, args(&[]), Denied::InvalidArguments),
            (0, args(&["retire", "--yes"]), Denied::InvalidArguments),
            (0, args(&["retire", "/tmp/other"]), Denied::InvalidArguments),
            (0, args(&["inspect"]), Denied::InvalidArguments),
        ] {
            let calls = Cell::new(0);
            assert_eq!(run_with(&argv, uid,
                || { calls.set(calls.get()+1); Ok(()) },
                || { calls.set(calls.get()+1); Ok(true) },
                || { calls.set(calls.get()+1); Ok(witness()) }), Err(reason));
            assert_eq!(calls.get(), 0);
        }
    }
    #[test]
    fn failed_shutdown_or_denied_approval_never_retires() {
        let argv = args(&["retire"]);
        let inspected = Cell::new(0);
        assert_eq!(run_with(&argv, 0,
            || { inspected.set(inspected.get()+1); Err(()) },
            || panic!("no prompt after failed shutdown"),
            || panic!("no retirement after failed shutdown")),
            Err(Denied::ShutdownUnverified));
        assert_eq!(inspected.get(), 1);
        for approved in [Ok(false), Err(())] {
            let retired = Cell::new(false);
            assert_eq!(run_with(&argv, 0, || Ok(()), || approved,
                || { retired.set(true); Ok(witness()) }), Err(Denied::ApprovalDenied));
            assert!(!retired.get());
        }
    }
    #[test]
    fn rechecks_shutdown_after_terminal_confirmation() {
        let inspected = Cell::new(0);
        let retired = Cell::new(false);
        assert_eq!(run_with(&args(&["retire"]), 0,
            || { inspected.set(inspected.get()+1);
                if inspected.get() == 1 { Ok(()) } else { Err(()) } },
            || Ok(true),
            || { retired.set(true); Ok(witness()) }), Err(Denied::ShutdownUnverified));
        assert_eq!(inspected.get(), 2);
        assert!(!retired.get());
    }
    #[test]
    fn valid_offline_result_cannot_authorize_migration_or_listener() {
        let calls = Cell::new(0);
        let result = run_with(&args(&["retire"]), 0,
            || { calls.set(calls.get()+1); Ok(()) },
            || { calls.set(calls.get()+1); Ok(true) },
            || { calls.set(calls.get()+1); Ok(witness()) });
        assert_eq!(result, Ok(witness()));
        assert_eq!(calls.get(), 4);
        assert!(!result.unwrap().authorizes_migration());
        assert!(!witness().authorizes_new_listener());
    }
    #[test]
    fn uncertain_swap_and_incomplete_witness_fail_closed() {
        let argv = args(&["retire"]);
        assert_eq!(run_with(&argv, 0, || Ok(()), || Ok(true), || Err(())),
            Err(Denied::RetirementUncertain));
        for fake in [
            RetirementWitness { legacy_script_path_is_directory: false, original_script_preserved: true },
            RetirementWitness { legacy_script_path_is_directory: true, original_script_preserved: false },
        ] {
            assert_eq!(run_with(&argv, 0, || Ok(()), || Ok(true), || Ok(fake)),
                Err(Denied::RetirementUncertain));
        }
    }
    #[test]
    fn postboot_verify_is_read_only_and_rechecks_service_state() {
        let argv = args(&["verify"]);
        let seq = std::cell::RefCell::new(Vec::new());
        let report = verify_with(
            &argv, 0,
            || { seq.borrow_mut().push("shutdown"); Ok(()) },
            || { seq.borrow_mut().push("known-tombstone"); Ok(witness()) },
        );
        assert_eq!(report, Ok(witness()));
        assert_eq!(*seq.borrow(), vec!["shutdown", "known-tombstone", "shutdown"]);
        assert!(!report.unwrap().authorizes_migration());
    }
    #[test]
    fn postboot_verify_denies_nonroot_bad_arguments_and_uncertain_shutdown() {
        for (uid, input, expected) in [
            (1001, args(&["verify"]), Denied::RootRequired),
            (0, args(&["verify", "--yes"]), Denied::InvalidArguments),
            (0, args(&["verify", "/tmp/other"]), Denied::InvalidArguments),
            (0, args(&["retire"]), Denied::InvalidArguments),
            (0, args(&[]), Denied::InvalidArguments),
        ] {
            assert_eq!(verify_with(&input, uid,
                || panic!("invalid verification must not read old service"),
                || panic!("invalid verification must not touch disk")),
                Err(expected));
        }
        let count = Cell::new(0);
        assert_eq!(verify_with(&args(&["verify"]), 0,
            || { count.set(count.get() + 1);
                if count.get() == 1 { Ok(()) } else { Err(()) } },
            || Ok(witness())),
            Err(Denied::ShutdownUnverified));
        assert_eq!(count.get(), 2);
        assert_eq!(verify_with(&args(&["verify"]), 0, || Err(()),
            || panic!("missing service evidence must deny before disk")),
            Err(Denied::ShutdownUnverified));
        assert_eq!(verify_with(&args(&["verify"]), 0, || Ok(()),
            || Err(())), Err(Denied::RetirementUncertain));
    }
    #[test]
    fn postboot_verify_rejects_false_or_incomplete_tombstone_witness() {
        for invalid in [
            RetirementWitness { legacy_script_path_is_directory: false,
                original_script_preserved: true },
            RetirementWitness { legacy_script_path_is_directory: true,
                original_script_preserved: false },
        ] {
            let second = Cell::new(false);
            assert_eq!(verify_with(&args(&["verify"]), 0,
                || { second.set(true); Ok(()) }, || Ok(invalid)),
                Err(Denied::RetirementUncertain));
            assert!(second.get());
        }
    }
    #[test]
    fn bounded_terminal_input_rejects_non_ascii_crlf_and_partial_lines() {
        let root = std::env::temp_dir().join(format!(
            "spidervpn-retire-tty-{}",std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes, accepted) in [
            ("exact", format!("{APPROVAL}\n").into_bytes(), true),
            ("wrong", b"RETIRE tc-pair.py WITH MIGRATION\n".to_vec(), true),
            ("crlf", format!("{APPROVAL}\r\n").into_bytes(), false),
            ("unicode", "RETIRE 中文\n".as_bytes().to_vec(), false),
            ("oversized", format!("{}\n", "x".repeat(MAX_LINE+1)).into_bytes(), false),
            ("no-newline", APPROVAL.as_bytes().to_vec(), false),
        ] {
            let path = root.join(name);
            std::fs::write(&path, bytes).unwrap();
            let mut file = File::open(&path).unwrap();
            let line = read_line(&mut file, Duration::from_secs(1));
            assert_eq!(line.is_ok(), accepted, "input {name}");
            if name == "exact" { assert_eq!(line.as_deref(), Ok(APPROVAL)); }
            if name == "wrong" { assert_ne!(line.as_deref(), Ok(APPROVAL)); }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

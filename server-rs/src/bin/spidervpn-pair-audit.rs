//! SEC-01: local, root-only inspection of interrupted pairing transactions.
//!
//! PRE-INTEGRATION ONLY. This command never authorizes a request, changes
//! WireGuard peers, writes wg.conf, finalizes the ledger or issues recovery
//! approval. It only observes a pre-existing, protected Rust authority ledger
//! and verified live/config snapshots under the SEC-08 cross-process lock.
//! The deployed Python pairing receiver is unchanged and still unsafe.
//!
//! Usage:
//!   spidervpn-pair-audit inspect /absolute/private/ledger-dir wg0 <invite-uuid>
//!
//! The lock helper may create its 0600 lock file in the protected directory;
//! no authority records or WireGuard state are changed by this command.

#![cfg(target_os = "linux")]

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spidervpn_pairing_authority::ledger_disk::LedgerStore;
use spidervpn_pairing_authority::recovery_inspect::{
    inspect_pinned_recovery, RecoveryInspection,
};
use spidervpn_pairing_authority::wg_readonly::valid_interface;

unsafe extern "C" {
    fn geteuid() -> u32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliError {
    RootRequired,
    InvalidArguments,
    Clock,
    InspectionDenied,
}

struct InspectRequest {
    root: PathBuf,
    interface: String,
    invite_id: String,
}

fn valid_invite_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36 && bytes.iter().enumerate().all(|(i, ch)| match i {
        8 | 13 | 18 | 23 => *ch == b'-',
        _ => ch.is_ascii_digit() || (b'a'..=b'f').contains(ch),
    })
}

fn parse(args: &[String]) -> Result<InspectRequest, CliError> {
    if args.len() != 4 || args[0] != "inspect" {
        return Err(CliError::InvalidArguments);
    }
    let root = PathBuf::from(&args[1]);
    // Reject ambiguous traversal before opening a root-owned authority
    // directory. LedgerStore enforces actual owner/mode/lock-file checks.
    if !root.is_absolute()
        || root.components().any(|component| matches!(
            component, Component::ParentDir | Component::CurDir
        ))
        || args[1].split('/').any(|piece| piece == "." || piece == "..")
        || !valid_interface(&args[2])
        || !valid_invite_id(&args[3])
    {
        return Err(CliError::InvalidArguments);
    }
    Ok(InspectRequest {
        root,
        interface: args[2].clone(),
        invite_id: args[3].clone(),
    })
}

/// Caller-supplied inspector exists only to test that rejected arguments and
/// non-root users cannot even reach a ledger/WireGuard read.
fn run_with<F>(
    args: &[String],
    effective_uid: u32,
    now_unix: i64,
    inspect: F,
) -> Result<String, CliError>
where
    F: FnOnce(&Path, &str, &str, i64) -> Result<RecoveryInspection, ()>,
{
    if effective_uid != 0 {
        return Err(CliError::RootRequired);
    }
    if now_unix < 0 {
        return Err(CliError::Clock);
    }
    let request = parse(args)?;
    let report = inspect(
        &request.root,
        &request.interface,
        &request.invite_id,
        now_unix,
    ).map_err(|_| CliError::InspectionDenied)?;

    // Only known enum values and booleans are rendered. No tokens, private
    // keys, pairing requests, raw JSON or wg.conf bytes can enter stdout.
    Ok(format!(
        "invite={} stage={:?} action={:?} config_has_peer={} kernel_has_peer={}",
        request.invite_id, report.stage, report.action,
        report.config_has_peer, report.kernel_has_peer,
    ))
}

fn system_inspect(
    root: &Path,
    interface: &str,
    invite_id: &str,
    now_unix: i64,
) -> Result<RecoveryInspection, ()> {
    let store = LedgerStore::open_existing(root, Duration::from_secs(2))
        .map_err(|_| ())?;
    inspect_pinned_recovery(&store, interface, invite_id, now_unix)
        .map_err(|_| ())
}

fn main() {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect::<Result<Vec<String>, _>>();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok());
    let uid = unsafe { geteuid() };
    let result = match (args, now) {
        (Ok(args), Some(now)) => run_with(&args, uid, now, system_inspect),
        (Err(_), _) => Err(CliError::InvalidArguments),
        (_, None) => Err(CliError::Clock),
    };
    match result {
        Ok(report) => println!("{report}"),
        Err(err) => {
            let message = match err {
                CliError::RootRequired => "root privileges required",
                CliError::InvalidArguments => "invalid command or arguments",
                CliError::Clock => "system time unavailable",
                CliError::InspectionDenied => "inspection denied (ledger, lock or WireGuard state unverified)",
            };
            eprintln!("spidervpn-pair-audit: {message}; no recovery action taken");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use spidervpn_pairing_authority::recovery_inspect::{
        RecoveryAction, RecoveryStage,
    };

    const INV: &str = "11111111-1111-4111-8111-111111111111";

    fn args(root: &str, interface: &str, invite: &str) -> Vec<String> {
        ["inspect", root, interface, invite]
            .into_iter().map(str::to_owned).collect()
    }
    fn example_report() -> RecoveryInspection {
        RecoveryInspection {
            stage: RecoveryStage::RevokingRemove,
            action: RecoveryAction::RepairKernelWithApproval,
            config_has_peer: false,
            kernel_has_peer: true,
        }
    }

    #[test]
    fn non_root_is_denied_before_reading_any_authority_or_wireguard_state() {
        let called = Cell::new(false);
        let result = run_with(&args("/var/lib/spidervpn-pair", "wg0", INV), 1001, 200, |_, _, _, _| {
            called.set(true);
            Ok(example_report())
        });
        assert_eq!(result, Err(CliError::RootRequired));
        assert!(!called.get());
    }

    #[test]
    fn invalid_interface_invite_or_root_path_never_reaches_reader() {
        for input in [
            args("relative/path", "wg0", INV),
            args("/tmp/../private", "wg0", INV),
            args("/tmp/./private", "wg0", INV),
            args("/var/lib/spidervpn-pair", "all", INV),
            args("/var/lib/spidervpn-pair", "-wg0", INV),
            args("/var/lib/spidervpn-pair", "wg0", "revoked"),
            args("/var/lib/spidervpn-pair", "wg0", "11111111-1111-4111-8111-11111111111Z"),
        ] {
            let called = Cell::new(false);
            let result = run_with(&input, 0, 200, |_, _, _, _| {
                called.set(true);
                Ok(example_report())
            });
            assert_eq!(result, Err(CliError::InvalidArguments));
            assert!(!called.get());
        }
    }

    #[test]
    fn wrong_verb_extra_args_and_clock_failure_fail_closed() {
        let good = args("/var/lib/spidervpn-pair", "wg0", INV);
        let mut extra = good.clone();
        extra.push("auto-repair".to_owned());
        let mut wrong = good.clone();
        wrong[0] = "repair".to_owned();
        for input in [&extra, &wrong, &Vec::new()] {
            assert_eq!(run_with(input, 0, 200, |_, _, _, _| Ok(example_report())),
                Err(CliError::InvalidArguments));
        }
        assert_eq!(run_with(&good, 0, -1, |_, _, _, _| Ok(example_report())),
            Err(CliError::Clock));
    }

    #[test]
    fn verified_diagnostic_reports_only_non_secret_enums_and_presence() {
        let input = args("/var/lib/spidervpn-pair", "wg0", INV);
        let called = Cell::new(false);
        let result = run_with(&input, 0, 200, |root, interface, id, now| {
            called.set(true);
            assert_eq!(root, Path::new("/var/lib/spidervpn-pair"));
            assert_eq!(interface, "wg0");
            assert_eq!(id, INV);
            assert_eq!(now, 200);
            Ok(example_report())
        }).unwrap();
        assert!(called.get());
        assert_eq!(result, format!(
            "invite={INV} stage=RevokingRemove action=RepairKernelWithApproval config_has_peer=false kernel_has_peer=true"
        ));
        assert!(!result.contains("PrivateKey"));
        assert!(!result.contains("PresharedKey"));
    }

    #[test]
    fn failed_verified_read_never_outputs_a_partial_or_untrusted_report() {
        let result = run_with(&args("/var/lib/spidervpn-pair", "wg0", INV),
            0, 200, |_, _, _, _| Err(()));
        assert_eq!(result, Err(CliError::InspectionDenied));
    }
}

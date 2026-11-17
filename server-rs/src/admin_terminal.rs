//! SEC-01: explicit local root TTY confirmation for an ALREADY COMPLETE
//! Pending/Revoking WireGuard transaction. Not a WG repair path.
//!
//! Compiled only with the opt-in "linux-admin-finalize" feature. It is NOT
//! used by HTTP, the Python receiver, Windows admin actions or default builds.
//! No approval token is serialized, returned to a caller, or reusable: the
//! acknowledgment is read directly from the controlling /dev/tty while the
//! existing Linux cross-process authority flock remains held.
//!
//! Only the VerifyAndFinalize case is supported. This module NEVER runs
//! "wg set", writes wg.conf, or creates a missing peer. All partial states
//! remain denied until a separately reviewed safe repair implementation.

#![cfg(all(target_os = "linux", feature = "linux-admin-finalize"))]

use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ledger_disk::LedgerStore;
use crate::recovery_inspect::{
    finalize_stable_prepared, inspect_recovery, RecoveryAction, RecoveryStage,
};
use crate::wg_conf_audit::{read_verified_snapshot, require_exact_match};
use crate::Peer;

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_LINE: usize = 160;
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
pub enum AdminFinalizeError {
    RootRequired,
    ClockUnavailable,
    LedgerUnverified,
    SnapshotUnverified,
    NotAlreadyComplete,
    StaleReview,
    NoControllingTerminal,
    ApprovalDenied,
    ApprovalTimedOut,
    FinalizationUncertain,
}

/// Sealed, process-local review. Never clone or serialize a review/approval.
/// It is not a reusable bearer credential, and cannot be constructed by a
/// pairing request or CLI string. The Rust library itself checks euid.
struct TerminalReview {
    invite_id: String,
    generation: u64,
    stage: RecoveryStage,
    peers: Vec<Peer>,
}

fn require_root(uid: u32) -> Result<(), AdminFinalizeError> {
    if uid == 0 { Ok(()) } else { Err(AdminFinalizeError::RootRequired) }
}

fn now_unix() -> Result<i64, AdminFinalizeError> {
    let n = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| AdminFinalizeError::ClockUnavailable)?;
    i64::try_from(n.as_secs()).map_err(|_| AdminFinalizeError::ClockUnavailable)
}

/// Requires a protected, fully matched live/config snapshot before showing
/// any approval prompt. It cannot promote incomplete Pending/Revoking data.
fn begin_review(
    store: &LedgerStore, invite_id: &str, peers: &[Peer], now: i64,
) -> Result<TerminalReview, AdminFinalizeError> {
    let report = inspect_recovery(store, invite_id, peers, peers, now)
        .map_err(|_| AdminFinalizeError::NotAlreadyComplete)?;
    if report.action != RecoveryAction::VerifyAndFinalize {
        return Err(AdminFinalizeError::NotAlreadyComplete);
    }
    let generation = store.generation()
        .map_err(|_| AdminFinalizeError::LedgerUnverified)?;
    Ok(TerminalReview {
        invite_id: invite_id.to_owned(), generation, stage: report.stage,
        peers: peers.to_vec(),
    })
}

fn challenge(review: &TerminalReview) -> String {
    let stage = match review.stage {
        RecoveryStage::PendingAdd => "PendingAdd",
        RecoveryStage::RevokingRemove => "RevokingRemove",
    };
    format!("FINALIZE {} {} {}", review.invite_id, review.generation, stage)
}

/// Explicitly reject a changed generation or ANY peer inventory drift,
/// including unrelated peers. The caller must use new trusted triple reads,
/// not a cached or network-provided snapshot.
fn recheck_review(
    store: &LedgerStore, review: &TerminalReview, peers: &[Peer], now: i64,
) -> Result<(), AdminFinalizeError> {
    let generation = store.generation()
        .map_err(|_| AdminFinalizeError::LedgerUnverified)?;
    if generation != review.generation
        || require_exact_match(peers, &review.peers).is_err()
    {
        return Err(AdminFinalizeError::StaleReview);
    }
    let next = inspect_recovery(store, &review.invite_id, peers, peers, now)
        .map_err(|_| AdminFinalizeError::StaleReview)?;
    if next.action != RecoveryAction::VerifyAndFinalize || next.stage != review.stage {
        return Err(AdminFinalizeError::StaleReview);
    }
    Ok(())
}

/// Poll before every read so the root-held authority lock cannot wait
/// forever on an unattended terminal. Limit input to one ASCII line.
fn read_approval_line(file: &mut File, limit: Duration)
    -> Result<String, AdminFinalizeError>
{
    let start = Instant::now();
    let mut raw = Vec::new();
    loop {
        let remaining = limit.checked_sub(start.elapsed())
            .ok_or(AdminFinalizeError::ApprovalTimedOut)?;
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut pfd = PollFd { fd: file.as_raw_fd(), events: POLLIN, revents: 0 };
        let status = unsafe { poll(&mut pfd, 1, millis) };
        if status == 0 {
            return Err(AdminFinalizeError::ApprovalTimedOut);
        }
        if status < 0 || (pfd.revents & POLLIN) == 0 {
            return Err(AdminFinalizeError::ApprovalDenied);
        }
        let mut byte = [0u8; 1];
        if file.read(&mut byte).map_err(|_| AdminFinalizeError::ApprovalDenied)? != 1 {
            return Err(AdminFinalizeError::ApprovalDenied);
        }
        if byte[0] == b'\n' {
            return String::from_utf8(raw).map_err(|_| AdminFinalizeError::ApprovalDenied);
        }
        if !byte[0].is_ascii_graphic() && byte[0] != b' ' {
            return Err(AdminFinalizeError::ApprovalDenied);
        }
        if raw.len() >= MAX_LINE {
            return Err(AdminFinalizeError::ApprovalDenied);
        }
        raw.push(byte[0]);
    }
}

/// The only production-facing entry, intentionally absent from default
/// builds. Root alone is necessary but insufficient: a controlling TTY,
/// exact generation+invitation+stage confirmation, full inventory readback,
/// and the same active ledger flock are mandatory.
///
/// The finalizer rereads live/config/live AGAIN before the durable commit.
/// No WG kernel/config mutation is reachable through this function.
pub fn finalize_from_root_tty(
    root: &Path, interface: &str, invite_id: &str,
) -> Result<RecoveryStage, AdminFinalizeError> {
    require_root(unsafe { geteuid() })?;
    let mut store = LedgerStore::open_existing(root, Duration::from_secs(2))
        .map_err(|_| AdminFinalizeError::LedgerUnverified)?;
    let before = read_verified_snapshot(interface)
        .map_err(|_| AdminFinalizeError::SnapshotUnverified)?;
    let review = begin_review(&store, invite_id, &before, now_unix()?)?;

    // NO stdin/stdout fallback: redirected or remotely supplied approval
    // strings must never become a privileged authority transition.
    let mut tty = OpenOptions::new().read(true).write(true)
        .open("/dev/tty").map_err(|_| AdminFinalizeError::NoControllingTerminal)?;
    if !tty.is_terminal() {
        return Err(AdminFinalizeError::NoControllingTerminal);
    }
    let expected = challenge(&review);
    writeln!(tty,
        "SpiderVPN local-only terminal ledger finalization.\n\
         This will not add/remove WireGuard peers or write wg.conf.\n\
         Pending/Revoking state must already be fully reconciled.\n\
         Type exactly within 45 seconds:\n{expected}")
        .map_err(|_| AdminFinalizeError::ApprovalDenied)?;
    tty.flush().map_err(|_| AdminFinalizeError::ApprovalDenied)?;
    let entered = read_approval_line(&mut tty, APPROVAL_TIMEOUT)?;
    if entered != expected {
        return Err(AdminFinalizeError::ApprovalDenied);
    }

    let fresh = read_verified_snapshot(interface)
        .map_err(|_| AdminFinalizeError::SnapshotUnverified)?;
    recheck_review(&store, &review, &fresh, now_unix()?)?;
    let finished = finalize_stable_prepared(
        &mut store, interface, &review.invite_id, now_unix()?,
    ).map_err(|_| AdminFinalizeError::FinalizationUncertain)?;
    if finished != review.stage {
        return Err(AdminFinalizeError::FinalizationUncertain);
    }
    Ok(finished)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddressPool, Claims, Grant, InviteState};
    use crate::ledger_disk;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;

    const INV: &str = "11111111-1111-4111-8111-111111111111";
    const DEV: &str = "33333333-3333-4333-8333-333333333333";
    const REQ: &str = "44444444-4444-4444-8444-444444444444";

    fn fixture(tag: &str, revoking: bool) -> (std::path::PathBuf, LedgerStore, Grant) {
        let dir = std::env::temp_dir().join(format!(
            "spidervpn-terminal-approval-{tag}-{}",std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
        ledger_disk::bootstrap_for_test(&dir).unwrap();
        let mut store = LedgerStore::open_existing(&dir, Duration::ZERO).unwrap();
        store.update(|l|l.insert_open(INV, 1000)).unwrap();
        let grant = store.update(|l|l.reserve(Claims {
            invite_id: INV.into(), request_id: REQ.into(), device_id: DEV.into(),
            public_key: format!("{}=","A".repeat(43)),request_digest: "a".repeat(64),
            recipient_jwk_digest: "b".repeat(64),
        },100,AddressPool{network:Ipv4Addr::new(10,66,0,0),prefix:24},Some(&[]))).unwrap();
        if revoking {
            store.update(|l|l.confirm_consumed(INV,Some(&[target(&grant)]))).unwrap();
            store.update(|l|l.begin_revocation(INV)).unwrap();
        }
        (dir,store,grant)
    }
    fn target(g: &Grant) -> Peer {
        Peer {public_key:g.claims.public_key.clone(), address:g.address}
    }
    fn end(dir: std::path::PathBuf, store: LedgerStore) {
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_non_root_before_opening_any_authority_or_tty() {
        assert_eq!(require_root(1001),Err(AdminFinalizeError::RootRequired));
        assert_eq!(require_root(65534),Err(AdminFinalizeError::RootRequired));
        assert_eq!(require_root(0),Ok(()));
    }

    #[test]
    fn pending_complete_requires_exact_generation_invite_and_stage() {
        let (dir, store, grant)=fixture("pending",false);
        let review=begin_review(&store,INV,&[target(&grant)],200).unwrap();
        let token=challenge(&review);
        assert_eq!(token,format!("FINALIZE {INV} {} PendingAdd",store.generation().unwrap()));
        assert!(recheck_review(&store,&review,&[target(&grant)],201).is_ok());
        assert!(recheck_review(&store,&review,&[],201).is_err());
        assert!(token.len() < MAX_LINE);
        end(dir,store);
    }

    #[test]
    fn incomplete_pending_never_gets_a_terminal_approval_challenge() {
        let (dir,store,_)=fixture("partial",false);
        assert!(matches!(begin_review(&store,INV,&[],200),
            Err(AdminFinalizeError::NotAlreadyComplete)));
        end(dir,store);
    }

    #[test]
    fn revoking_requires_confirmed_absence_and_rejects_generation_drift() {
        let (dir,mut store,grant)=fixture("revoking",true);
        assert!(matches!(begin_review(&store,INV,&[target(&grant)],200),
            Err(AdminFinalizeError::NotAlreadyComplete)));
        let review=begin_review(&store,INV,&[],200).unwrap();
        assert_eq!(challenge(&review),
            format!("FINALIZE {INV} {} RevokingRemove",store.generation().unwrap()));
        store.update(|l|l.insert_open("99999999-9999-4999-8999-999999999999",800)).unwrap();
        assert_eq!(recheck_review(&store,&review,&[],200),Err(AdminFinalizeError::StaleReview));
        assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Revoking(_))));
        end(dir,store);
    }

    #[test]
    fn bounded_line_reader_accepts_only_exact_ascii_one_line() {
        let dir=std::env::temp_dir().join(format!(
            "spidervpn-tty-input-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name,bytes,accepted) in [
            ("valid",b"FINALIZE 1 2 PendingAdd\n".to_vec(),true),
            ("eof",b"FINALIZE 1 2 PendingAdd".to_vec(),false),
            ("newline",b"FINALIZE 1 2 PendingAdd\r\n".to_vec(),false),
            ("utf8","FINALIZE 中文\n".as_bytes().to_vec(),false),
            ("oversize",format!("{}\n","A".repeat(MAX_LINE+1)).into_bytes(),false),
        ] {
            let p=dir.join(name);
            std::fs::write(&p,bytes).unwrap();
            let mut f=File::open(&p).unwrap();
            let result=read_approval_line(&mut f,Duration::from_secs(1));
            assert_eq!(result.is_ok(),accepted,"case {name}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

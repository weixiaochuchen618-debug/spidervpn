//! SEC-01 S03: narrow, no-shell live WireGuard peer update and confirmed
//! config/live/ledger choreography. PRE-INTEGRATION ONLY: Python production
//! service and Windows revoke UI are unchanged.
//!
//! Instead of rebuilding and syncing *every* peer via wg-quick, use the
//! system WireGuard command's one-peer operation:
//!   wg set IFACE peer KEY allowed-ips A.B.C.D/32
//!   wg set IFACE peer KEY remove
//! This cannot silently remove unrelated peers. The protected wg.conf is
//! committed BEFORE the kernel change; strict live/disk readback and the
//! final ledger state are committed only after the kernel update succeeds.
//! All failures leave the original Pending/Revoking ledger state, so a
//! partially applied operation cannot authorize replay automatically.
//!
//! A privileged/root actor not participating in the authority flock could
//! race these checks; network-namespace real-WG and power-loss tests remain
//! mandatory before deployment.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{claims_valid, wg_key, Grant, InviteState, Peer};
use crate::ledger_disk::{LedgerStore, StoreError};
use crate::wg_atomic::{write_pinned_config, AtomicError};
use crate::wg_conf_audit::{read_verified_snapshot, require_exact_match, ConfigError};
use crate::wg_peer_plan::Change;
use crate::wg_readonly::{valid_interface, ReadError};

const WG_BINARY: &str = "/usr/bin/wg";
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveError {
    UnsafeBinary,
    InvalidArguments,
    SpawnFailed,
    TimedOut,
    CommandFailed,
}
#[derive(Debug)]
pub enum ApplyError {
    Ledger(StoreError),
    Config(AtomicError),
    Readback(ConfigError),
    Live(LiveError),
}

/// No string goes to a shell or an attacker-controlled executable path.
/// Even malformed public keys and option-like interfaces are rejected.
pub fn peer_command_args(
    interface: &str, grant: &Grant, operation: Change,
) -> Result<Vec<String>, LiveError> {
    if !valid_interface(interface)
        || !claims_valid(&grant.claims)
        || !grant.address.is_private()
        || !wg_key(&grant.claims.public_key)
    {
        return Err(LiveError::InvalidArguments);
    }
    let mut args = vec![
        "set".into(), interface.into(), "peer".into(),
        grant.claims.public_key.clone(),
    ];
    match operation {
        Change::Add => {
            args.push("allowed-ips".into());
            args.push(format!("{}/32", grant.address));
        }
        Change::Remove => args.push("remove".into()),
    }
    Ok(args)
}
fn checked_wg_executable() -> Result<(), LiveError> {
    // Reuse the same root-owned/no-symlink protection as the read-only
    // snapshot reader. No fallback to PATH on a missing binary.
    crate::wg_readonly::trusted_wg_binary(Path::new(WG_BINARY))
        .map_err(|_: ReadError| LiveError::UnsafeBinary)
}
pub fn set_one_peer(
    interface: &str, grant: &Grant, operation: Change,
) -> Result<(), LiveError> {
    let args = peer_command_args(interface, grant, operation)?;
    checked_wg_executable()?;
    let mut child = Command::new(WG_BINARY)
        .args(&args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| LiveError::SpawnFailed)?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(LiveError::CommandFailed),
            Ok(None) if start.elapsed() < TIMEOUT =>
                thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LiveError::TimedOut);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LiveError::CommandFailed);
            }
        }
    }
}
fn expected_after(
    before: &[Peer], grant: &Grant, operation: Change,
) -> Result<Vec<Peer>, LiveError> {
    let mut peers = before.to_vec();
    match operation {
        Change::Add => {
            if peers.iter().any(|p| p.public_key == grant.claims.public_key
                || p.address == grant.address)
            {
                return Err(LiveError::InvalidArguments);
            }
            peers.push(Peer {
                public_key: grant.claims.public_key.clone(),
                address: grant.address,
            });
        }
        Change::Remove => {
            let found_key = peers.iter().any(|p| p.public_key == grant.claims.public_key);
            let found_ip = peers.iter().any(|p| p.address == grant.address);
            if found_key != found_ip
                || peers.iter().any(|p| p.public_key == grant.claims.public_key
                    && p.address != grant.address)
            {
                return Err(LiveError::InvalidArguments);
            }
            peers.retain(|p| p.public_key != grant.claims.public_key);
        }
    }
    Ok(peers)
}

/// The only production-capable live mutation entrypoint. It requires a
/// trusted, already durable LedgerStore Pending/Revoking state, a stable
/// exact live+wg.conf pre-snapshot, a safe atomic config update, the *one
/// targeted peer* wg command, and a fresh stable live+config post-snapshot.
/// Commit the final durable state only after all conditions hold.
pub fn apply_and_confirm(
    store: &mut LedgerStore, interface: &str,
    grant: &Grant, operation: Change,
) -> Result<(), ApplyError> {
    let ledger = store.view().map_err(ApplyError::Ledger)?;
    let prepared = match (operation, ledger.state(&grant.claims.invite_id)) {
        (Change::Add, Some(InviteState::Pending(g))) => g == grant,
        (Change::Remove, Some(InviteState::Revoking(g))) => g == grant,
        _ => false,
    };
    if !prepared { return Err(ApplyError::Live(LiveError::InvalidArguments)); }
    let before = read_verified_snapshot(interface).map_err(ApplyError::Readback)?;
    let expected = expected_after(&before, grant, operation).map_err(ApplyError::Live)?;
    let changed = write_pinned_config(store, interface, grant, operation)
        .map_err(ApplyError::Config)?;
    if changed {
        set_one_peer(interface, grant, operation).map_err(ApplyError::Live)?;
    }
    let after = read_verified_snapshot(interface).map_err(ApplyError::Readback)?;
    require_exact_match(&expected, &after).map_err(ApplyError::Readback)?;
    match operation {
        Change::Add => {
            store.update(|ledger| ledger.confirm_consumed(
                &grant.claims.invite_id, Some(&after)
            )).map_err(ApplyError::Ledger)?;
        }
        Change::Remove => {
            store.update(|ledger| ledger.confirm_revocation(
                &grant.claims.invite_id, Some(&after)
            )).map_err(ApplyError::Ledger)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Claims;
    use std::net::Ipv4Addr;

    fn grant() -> Grant {
        Grant {
            claims: Claims {
                invite_id:"11111111-1111-4111-8111-111111111111".into(),
                request_id:"22222222-2222-4222-8222-222222222222".into(),
                device_id:"33333333-3333-4333-8333-333333333333".into(),
                public_key:format!("{}=","A".repeat(43)),
                request_digest:"a".repeat(64),
                recipient_jwk_digest:"b".repeat(64),
            },
            address:Ipv4Addr::new(10,66,0,2),
        }
    }

    #[test]
    fn command_is_exactly_one_peer_and_never_uses_shell() {
        let g=grant();
        assert_eq!(peer_command_args("wg0",&g,Change::Add).unwrap(),vec![
            "set","wg0","peer",&g.claims.public_key,"allowed-ips","10.66.0.2/32"
        ]);
        assert_eq!(peer_command_args("wg0",&g,Change::Remove).unwrap(),vec![
            "set","wg0","peer",&g.claims.public_key,"remove"
        ]);
    }
    #[test]
    fn invalid_interface_and_public_key_are_rejected_before_launch() {
        let g=grant();
        for bad in ["--help","all","wg0;sh","wg0\nroot","","wg0 test"] {
            assert_eq!(peer_command_args(bad,&g,Change::Add),
                Err(LiveError::InvalidArguments));
        }
        let mut bad=g.clone();
        bad.claims.public_key="; rm -rf /".into();
        assert_eq!(peer_command_args("wg0",&bad,Change::Remove),
            Err(LiveError::InvalidArguments));
    }
    #[test]
    fn add_changes_only_expected_target_and_keeps_other_peers() {
        let g=grant();
        let unrelated=Peer {
            public_key:format!("{}=","B".repeat(43)),
            address:Ipv4Addr::new(10,66,0,3),
        };
        let expected=expected_after(&[unrelated.clone()],&g,Change::Add).unwrap();
        assert_eq!(expected.len(),2);
        assert!(expected.contains(&unrelated));
        assert!(expected.contains(&Peer {
            public_key:g.claims.public_key.clone(),address:g.address
        }));
    }
    #[test]
    fn revoke_existing_or_already_missing_peer_is_idempotent() {
        let g=grant();
        let current=Peer{public_key:g.claims.public_key.clone(),address:g.address};
        assert_eq!(expected_after(&[current],&g,Change::Remove).unwrap(),vec![]);
        assert_eq!(expected_after(&[],&g,Change::Remove).unwrap(),vec![]);
    }
    #[test]
    fn revoke_wrong_ip_or_add_duplicate_target_is_refused() {
        let g=grant();
        let wrong=Peer{public_key:g.claims.public_key.clone(),
            address:Ipv4Addr::new(10,66,0,9)};
        assert_eq!(expected_after(&[wrong.clone()],&g,Change::Remove),
            Err(LiveError::InvalidArguments));
        assert_eq!(expected_after(&[wrong],&g,Change::Add),
            Err(LiveError::InvalidArguments));
        let wrong_key=Peer{public_key:format!("{}=","B".repeat(43)),
            address:g.address};
        assert_eq!(expected_after(&[wrong_key],&g,Change::Remove),
            Err(LiveError::InvalidArguments));
    }
}

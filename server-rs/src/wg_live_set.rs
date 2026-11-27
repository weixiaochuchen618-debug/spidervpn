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

use crate::{Grant, Peer};
#[cfg(feature = "linux-pairing-process")]
use crate::existing_devices::ExistingDevice;
use crate::ledger_disk::{LedgerStore, StoreError};
use crate::wg_atomic::{write_pinned_config, AtomicError};
use crate::wg_conf_audit::{read_verified_snapshot, require_exact_match, ConfigError};
use crate::wg_peer_plan::{Change, PeerChange};
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
    command_args(interface, PeerChange::Invitation(grant, operation))
}

fn command_args(interface: &str, change: PeerChange<'_>) -> Result<Vec<String>, LiveError> {
    if !valid_interface(interface) || !change.valid() {
        return Err(LiveError::InvalidArguments);
    }
    let (public_key, address, operation) = change.target();
    let mut args = vec![
        "set".into(), interface.into(), "peer".into(),
        public_key.to_owned(),
    ];
    match operation {
        Change::Add => {
            args.push("allowed-ips".into());
            args.push(format!("{address}/32"));
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
fn set_one_peer(interface: &str, change: PeerChange<'_>) -> Result<(), LiveError> {
    let args = command_args(interface, change)?;
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
fn expected_after(before: &[Peer], change: PeerChange<'_>) -> Result<Vec<Peer>, LiveError> {
    let (public_key, address, operation) = change.target();
    let mut peers = before.to_vec();
    match operation {
        Change::Add => {
            if peers.iter().any(|p| p.public_key == public_key || p.address == address)
            {
                return Err(LiveError::InvalidArguments);
            }
            peers.push(Peer {
                public_key: public_key.to_owned(),
                address,
            });
        }
        Change::Remove => {
            let found_key = peers.iter().any(|p| p.public_key == public_key);
            let found_ip = peers.iter().any(|p| p.address == address);
            if found_key != found_ip
                || peers.iter().any(|p| p.public_key == public_key && p.address != address)
            {
                return Err(LiveError::InvalidArguments);
            }
            peers.retain(|p| p.public_key != public_key);
        }
    }
    Ok(peers)
}

/// Adapter for the protected file writer and the fixed-argv WG command.
/// The transaction implementation is separately testable with a FakeOps
/// that cannot execute any system command or modify any network device.
trait MutationOps {
    fn snapshot(&mut self, store: &LedgerStore) -> Result<Vec<Peer>, ApplyError>;
    fn write(&mut self, store: &LedgerStore, change: PeerChange<'_>) -> Result<bool, ApplyError>;
    fn mutate(&mut self, change: PeerChange<'_>) -> Result<(), ApplyError>;
}

struct SystemOps<'a> {
    interface: &'a str,
    #[cfg(feature = "linux-fresh-consume-gate")]
    expected_server_key: Option<&'a str>,
}
impl MutationOps for SystemOps<'_> {
    fn snapshot(&mut self, _store: &LedgerStore) -> Result<Vec<Peer>, ApplyError> {
        #[cfg(feature = "linux-fresh-consume-gate")]
        if let Some(expected) = self.expected_server_key {
            return crate::wg_conf_audit::read_verified_identity_snapshot(
                _store, self.interface, expected
            ).map_err(ApplyError::Readback);
        }
        read_verified_snapshot(self.interface).map_err(ApplyError::Readback)
    }
    fn write(&mut self, store: &LedgerStore, change: PeerChange<'_>) -> Result<bool, ApplyError> {
        write_pinned_config(store, self.interface, change)
            .map_err(ApplyError::Config)
    }
    fn mutate(&mut self, change: PeerChange<'_>) -> Result<(), ApplyError> {
        set_one_peer(self.interface, change).map_err(ApplyError::Live)
    }
}

/// The only finalization path: with the same durable authority lock held,
/// validate the exact pending grant or revoking device, compare pre-state, write config,
/// mutate just the target peer, read back, then finally commit the ledger.
/// Any error leaves a *nonterminal* Pending/Revoking state. A repeat request
/// is NOT permission to redo the update without trusted reconciliation.
fn apply_with_ops(
    store: &mut LedgerStore, grant: &Grant,
    operation: Change, ops: &mut impl MutationOps,
) -> Result<(), ApplyError> {
    apply_with_ops_and_confirm(store, PeerChange::Invitation(grant, operation), ops, |store, after| {
        let id = &grant.claims.invite_id;
        store.update(|ledger| match operation {
            Change::Add => ledger.confirm_consumed(id, Some(after)).map(|_| ()),
            Change::Remove => ledger.confirm_revocation(id, Some(after)),
        }).map_err(ApplyError::Ledger)
    })
}

// One shared protected writer and exact readback path. The finalizer is
// crate-private and cannot be selected by a request or external caller.
fn apply_with_ops_and_confirm(
    store: &mut LedgerStore, change: PeerChange<'_>, ops: &mut impl MutationOps,
    confirm: impl FnOnce(&mut LedgerStore, &[Peer]) -> Result<(), ApplyError>,
) -> Result<(), ApplyError> {
    let ledger = store.view().map_err(ApplyError::Ledger)?;
    if !change.prepared(ledger) { return Err(ApplyError::Live(LiveError::InvalidArguments)); }
    let before = ops.snapshot(store)?;
    let expected = expected_after(&before, change).map_err(ApplyError::Live)?;
    let changed = ops.write(store, change)?;
    if changed { ops.mutate(change)?; }
    let after = ops.snapshot(store)?;
    require_exact_match(&expected, &after).map_err(ApplyError::Readback)?;
    confirm(store, &after)
}

/// A production-capable entrypoint but not wired to the current server:
/// the caller must verify the signed request BEFORE creating the grant, and
/// the existing Python service must be stopped during a trusted migration.
pub fn apply_and_confirm(
    store: &mut LedgerStore, interface: &str,
    grant: &Grant, operation: Change,
) -> Result<(), ApplyError> {
    apply_with_ops(store, grant, operation, &mut SystemOps {
        interface,
        #[cfg(feature = "linux-fresh-consume-gate")]
        expected_server_key: None,
    })
}

/// Used only by the authenticated fresh-consume adapter. No identity
/// downgrade to the older inventory-only snapshot path on either read.
#[cfg(feature = "linux-fresh-consume-gate")]
pub(crate) fn apply_fresh_and_confirm(
    store: &mut LedgerStore, interface: &str, expected_server_key: &str,
    grant: &Grant,
) -> Result<(), ApplyError> {
    apply_with_ops(store, grant, Change::Add, &mut SystemOps {
        interface,
        expected_server_key: Some(expected_server_key),
    })
}

/// The local administrator uses the same pinned identity before and after removing a peer.
#[cfg(feature = "linux-pairing-process")]
pub(crate) fn apply_revocation_and_confirm(
    store: &mut LedgerStore, interface: &str, expected_server_key: &str, grant: &Grant,
) -> Result<(), ApplyError> {
    apply_with_ops(store, grant, Change::Remove, &mut SystemOps {
        interface,
        expected_server_key: Some(expected_server_key),
    })
}

#[cfg(feature = "linux-pairing-process")]
pub(crate) fn apply_existing_revocation_and_confirm(
    store: &mut LedgerStore, interface: &str, expected_server_key: &str,
    device_id: &str, device: &ExistingDevice,
) -> Result<(), ApplyError> {
    let target = PeerChange::ExistingRemoval { device_id, device };
    apply_with_ops_and_confirm(store, target, &mut SystemOps {
        interface,
        expected_server_key: Some(expected_server_key),
    }, |store, peers| {
        store.update(|ledger| ledger.confirm_existing_revocation(device_id, peers))
            .map_err(ApplyError::Ledger)
    })
}

/// Stage 2 finalizes the exact peer and original response in one durable
/// Consumed commit. No success material is returned by the WG writer.
#[cfg(feature = "linux-authorization-response")]
pub(crate) fn apply_fresh_and_confirm_authorized(
    store: &mut LedgerStore, interface: &str, expected_server_key: &str,
    grant: &Grant, material: crate::ledger_disk::AuthorizationMaterial,
) -> Result<(), ApplyError> {
    if material.grant != *grant {
        return Err(ApplyError::Live(LiveError::InvalidArguments));
    }
    apply_with_ops_and_confirm(store, PeerChange::Invitation(grant, Change::Add), &mut SystemOps {
        interface, expected_server_key: Some(expected_server_key),
    }, |store, after| {
        store.confirm_authorized(material, after).map_err(ApplyError::Ledger)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Claims, InviteState};
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

    struct FakeOps {
        live: Vec<Peer>,
        disk: Vec<Peer>,
        writes: usize,
        changes: usize,
        fail_write: bool,
        fail_change: bool,
        fail_readback: bool,
        fail_post_change_readback: bool,
    }
    impl FakeOps {
        fn new() -> Self {
            Self {
                live:vec![], disk:vec![], writes:0, changes:0,
                fail_write:false, fail_change:false, fail_readback:false,
                fail_post_change_readback:false
            }
        }
    }
    impl MutationOps for FakeOps {
        fn snapshot(&mut self, _store: &LedgerStore) -> Result<Vec<Peer>, ApplyError> {
            if self.fail_readback || (self.fail_post_change_readback && self.changes > 0) {
                return Err(ApplyError::Live(LiveError::TimedOut));
            }
            require_exact_match(&self.live,&self.disk).map_err(ApplyError::Readback)?;
            Ok(self.live.clone())
        }
        fn write(&mut self, store: &LedgerStore, change: PeerChange<'_>)
            -> Result<bool, ApplyError>
        {
            let (grant, op) = match change {
                PeerChange::Invitation(grant, op) => (grant, op),
                #[cfg(feature = "linux-pairing-process")]
                PeerChange::ExistingRemoval { .. } => panic!("invitation fixture received an existing device"),
            };
            let state = store.view().map_err(ApplyError::Ledger)?
                .state(&grant.claims.invite_id);
            assert!(matches!(
                (op,state),
                (Change::Add,Some(InviteState::Pending(g))) if g == grant
            ) || matches!(
                (op,state),
                (Change::Remove,Some(InviteState::Revoking(g))) if g == grant
            ), "external write must only occur AFTER the durable deny state");
            self.writes += 1;
            if self.fail_write { return Err(ApplyError::Config(AtomicError::Io)); }
            let next = expected_after(&self.disk,change).map_err(ApplyError::Live)?;
            let changed = next != self.disk;
            self.disk = next;
            Ok(changed)
        }
        fn mutate(&mut self, change: PeerChange<'_>) -> Result<(), ApplyError> {
            self.changes += 1;
            if self.fail_change { return Err(ApplyError::Live(LiveError::CommandFailed)); }
            self.live = expected_after(&self.live,change).map_err(ApplyError::Live)?;
            Ok(())
        }
    }
    fn temp_ledger(tag: &str) -> (std::path::PathBuf, LedgerStore, Grant) {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;
        let path=std::env::temp_dir().join(format!(
            "spidervpn-sec01-mutops-{tag}-{}",std::process::id()));
        let _=std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path,
            std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::ledger_disk::bootstrap_for_test(&path).unwrap();
        let mut store=LedgerStore::open_existing(&path,Duration::ZERO).unwrap();
        let g=grant();
        store.update(|l|l.insert_open(&g.claims.invite_id,600)).unwrap();
        store.update(|l|l.reserve(g.claims.clone(),100,
            crate::AddressPool{
                network:Ipv4Addr::new(10,66,0,0),prefix:24,
            },Some(&[]))).unwrap();
        (path,store,g)
    }
    #[test]
    fn complete_add_then_revoke_commits_ledger_only_after_successful_readback() {
        let (p,mut store,g)=temp_ledger("complete");
        let mut ops=FakeOps::new();
        apply_with_ops(&mut store,&g,Change::Add,&mut ops).unwrap();
        assert!(matches!(store.view().unwrap().state(&g.claims.invite_id),
            Some(InviteState::Consumed(_))));
        assert_eq!((ops.writes,ops.changes),(1,1));
        let no_replay=apply_with_ops(&mut store,&g,Change::Add,&mut ops);
        assert!(matches!(no_replay,Err(ApplyError::Live(LiveError::InvalidArguments))));
        assert_eq!(ops.changes,1);
        store.update(|l|l.begin_revocation(&g.claims.invite_id)).unwrap();
        apply_with_ops(&mut store,&g,Change::Remove,&mut ops).unwrap();
        assert!(matches!(store.view().unwrap().state(&g.claims.invite_id),
            Some(InviteState::Revoked(_))));
        assert!(ops.live.is_empty());
        assert!(ops.disk.is_empty());
        drop(store);std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn config_write_failure_prevents_kernel_mutation_and_ledger_finalization() {
        let (p,mut store,g)=temp_ledger("writefail");
        let mut ops=FakeOps::new();
        ops.fail_write=true;
        assert!(matches!(apply_with_ops(&mut store,&g,Change::Add,&mut ops),
            Err(ApplyError::Config(AtomicError::Io))));
        assert_eq!(ops.changes,0);
        assert!(matches!(store.view().unwrap().state(&g.claims.invite_id),
            Some(InviteState::Pending(_))));
        drop(store);std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn kernel_error_after_disk_write_keeps_deny_ledger_and_requires_recovery() {
        let (p,mut store,g)=temp_ledger("setfail");
        let mut ops=FakeOps::new();
        ops.fail_change=true;
        assert!(matches!(apply_with_ops(&mut store,&g,Change::Add,&mut ops),
            Err(ApplyError::Live(LiveError::CommandFailed))));
        assert_eq!(ops.writes,1);
        assert_ne!(ops.live,ops.disk);
        assert!(matches!(store.view().unwrap().state(&g.claims.invite_id),
            Some(InviteState::Pending(_))));
        assert!(apply_with_ops(&mut store,&g,Change::Add,&mut ops).is_err());
        assert_eq!(ops.changes,1, "never blindly retry failed kernel changes");
        drop(store);std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn revocation_failure_does_not_clear_tombstone_or_regrant_device() {
        let (p,mut store,g)=temp_ledger("revokefail");
        let mut ops=FakeOps::new();
        apply_with_ops(&mut store,&g,Change::Add,&mut ops).unwrap();
        store.update(|l|l.begin_revocation(&g.claims.invite_id)).unwrap();
        ops.fail_change=true;
        assert!(matches!(apply_with_ops(&mut store,&g,Change::Remove,&mut ops),
            Err(ApplyError::Live(LiveError::CommandFailed))));
        assert!(matches!(store.view().unwrap().state(&g.claims.invite_id),
            Some(InviteState::Revoking(_))));
        assert!(store.view().unwrap().retry(&g.claims,Some(&ops.live)).is_err());
        drop(store);std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn live_readback_error_after_successful_kernel_change_keeps_pending() {
        let (p,mut store,g)=temp_ledger("readbackfail");
        let mut ops=FakeOps::new();
        ops.fail_post_change_readback=true;
        assert!(matches!(apply_with_ops(&mut store,&g,Change::Add,&mut ops),
            Err(ApplyError::Live(LiveError::TimedOut))));
        assert_eq!((ops.writes,ops.changes),(1,1));
        assert_eq!(ops.live,ops.disk);
        assert!(matches!(store.view().unwrap().state(&g.claims.invite_id),
            Some(InviteState::Pending(_))));
        drop(store);std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn revoking_after_partial_removal_can_be_confirmed_without_new_wg_call() {
        let (p,mut store,g)=temp_ledger("resume-removed");
        let mut ops=FakeOps::new();
        apply_with_ops(&mut store,&g,Change::Add,&mut ops).unwrap();
        store.update(|l|l.begin_revocation(&g.claims.invite_id)).unwrap();
        // Simulate a crash after the peer disappeared from both config
        // and kernel, before the final Revoked ledger fsync.
        ops.live.clear();
        ops.disk.clear();
        let prior_calls=ops.changes;
        apply_with_ops(&mut store,&g,Change::Remove,&mut ops).unwrap();
        assert_eq!(ops.changes,prior_calls, "never issue a second remove");
        assert!(matches!(store.view().unwrap().state(&g.claims.invite_id),
            Some(InviteState::Revoked(_))));
        drop(store);std::fs::remove_dir_all(p).unwrap();
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
        let expected=expected_after(&[unrelated.clone()],PeerChange::Invitation(&g,Change::Add)).unwrap();
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
        assert_eq!(expected_after(&[current],PeerChange::Invitation(&g,Change::Remove)).unwrap(),vec![]);
        assert_eq!(expected_after(&[],PeerChange::Invitation(&g,Change::Remove)).unwrap(),vec![]);
    }
    #[test]
    fn revoke_wrong_ip_or_add_duplicate_target_is_refused() {
        let g=grant();
        let wrong=Peer{public_key:g.claims.public_key.clone(),
            address:Ipv4Addr::new(10,66,0,9)};
        assert_eq!(expected_after(&[wrong.clone()],PeerChange::Invitation(&g,Change::Remove)),
            Err(LiveError::InvalidArguments));
        assert_eq!(expected_after(&[wrong],PeerChange::Invitation(&g,Change::Add)),
            Err(LiveError::InvalidArguments));
        let wrong_key=Peer{public_key:format!("{}=","B".repeat(43)),
            address:g.address};
        assert_eq!(expected_after(&[wrong_key],PeerChange::Invitation(&g,Change::Remove)),
            Err(LiveError::InvalidArguments));
    }
}

//! SEC-01 S03: transaction choreography for the future Linux Rust service.
//!
//! PeerControl is an injected interface. This is NOT a live WireGuard adapter
//! and the existing Python receiver remains unchanged. Callers MUST verify
//! JWS signature and all request bindings before creating Claims.
//!
//! A LedgerStore lock covers all steps: durable Pending/Revoking first,
//! external peer mutation second, fresh readback third, final state last.
//! Errors keep a deny-state for explicit recovery, never roll back to Open.

#![cfg(target_os = "linux")]

use crate::{AddressPool, Claims, Grant, Peer, Refusal};
use crate::ledger_disk::{LedgerStore, StoreError};

#[derive(Debug)]
pub enum TransactionError {
    Store(StoreError),
    WireGuard(String),
    Readback(Refusal),
}
impl From<StoreError> for TransactionError {
    fn from(value: StoreError) -> Self { Self::Store(value) }
}

/// A real adapter must supply a complete fresh inventory. Unknown or stale
/// data is Err, not an empty list; otherwise revocations can be falsely
/// confirmed and address conflicts may be hidden.
pub trait PeerControl {
    fn snapshot(&mut self) -> Result<Vec<Peer>, String>;
    fn add(&mut self, grant: &Grant) -> Result<(), String>;
    fn remove(&mut self, grant: &Grant) -> Result<(), String>;
}

/// Persist Pending BEFORE any peer creation, then confirm from live WG.
pub fn enroll(
    store: &mut LedgerStore,
    peers: &mut impl PeerControl,
    verified: Claims,
    now_unix: i64,
    pool: AddressPool,
) -> Result<Grant, TransactionError> {
    let before = peers.snapshot().map_err(TransactionError::WireGuard)?;
    let grant = store.update(|l| l.reserve(verified, now_unix, pool, Some(&before)))?;
    peers.add(&grant).map_err(TransactionError::WireGuard)?;
    let after = peers.snapshot().map_err(TransactionError::WireGuard)?;
    store.update(|l| l.confirm_consumed(&grant.claims.invite_id, Some(&after)))
        .map_err(TransactionError::Store)
}

/// Even when identical signed claims are replayed, never call add() here.
pub fn retry_read_only(
    store: &LedgerStore,
    peers: &mut impl PeerControl,
    verified: &Claims,
) -> Result<Grant, TransactionError> {
    let observed = peers.snapshot().map_err(TransactionError::WireGuard)?;
    store.view().retry(verified, Some(&observed)).cloned()
        .map_err(TransactionError::Readback)
}

/// Commit the Revoking deny-state BEFORE deleting any WG peer.
pub fn revoke(
    store: &mut LedgerStore,
    peers: &mut impl PeerControl,
    invite_id: &str,
) -> Result<(), TransactionError> {
    let grant = store.update(|l| l.begin_revocation(invite_id))?;
    peers.remove(&grant).map_err(TransactionError::WireGuard)?;
    let after = peers.snapshot().map_err(TransactionError::WireGuard)?;
    store.update(|l| l.confirm_revocation(invite_id, Some(&after)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InviteState;
    use crate::ledger_disk;
    use serde_json::Value;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const I: &str = "11111111-1111-4111-8111-111111111111";
    const I2: &str = "22222222-2222-4222-8222-222222222222";
    const DEV: &str = "33333333-3333-4333-8333-333333333333";
    const REQ: &str = "44444444-4444-4444-8444-444444444444";

    fn root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("spidervpn-sec01-flow-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        ledger_disk::bootstrap_for_test(&p).unwrap();
        p
    }
    fn open(p: &Path) -> LedgerStore {
        LedgerStore::open_existing(p, Duration::from_secs(1)).unwrap()
    }
    fn claim(inv: &str) -> Claims {
        Claims {
            invite_id: inv.into(), request_id: REQ.into(),
            device_id: DEV.into(), public_key: format!("{}=", "A".repeat(43)),
            request_digest: "a".repeat(64), recipient_jwk_digest: "b".repeat(64),
        }
    }
    fn pool() -> AddressPool {
        AddressPool { network: Ipv4Addr::new(10, 9, 8, 0), prefix: 29 }
    }

    struct FakeWg {
        root: PathBuf,
        peers: Vec<Peer>,
        fail_snapshot: bool,
        fail_add: bool,
        fail_remove: bool,
        wrong_readback: bool,
        add_calls: usize,
        remove_calls: usize,
    }
    impl FakeWg {
        fn new(root: &Path) -> Self {
            Self {
                root: root.to_path_buf(), peers: Vec::new(),
                fail_snapshot: false, fail_add: false, fail_remove: false,
                wrong_readback: false, add_calls: 0, remove_calls: 0
            }
        }
        fn assert_disk_state(&self, expected: &str) {
            let raw = fs::read(self.root.join("authority-ledger.json")).unwrap();
            let parsed: Value = serde_json::from_slice(&raw).unwrap();
            let state = &parsed["ledger"]["invitations"][I]["state"];
            assert!(state.get(expected).is_some(),
                "expected persisted {expected} BEFORE external WG change: {state}");
        }
    }
    impl PeerControl for FakeWg {
        fn snapshot(&mut self) -> Result<Vec<Peer>, String> {
            if self.fail_snapshot {
                Err("live WG inventory unavailable".into())
            } else if self.wrong_readback {
                Ok(Vec::new())
            } else {
                Ok(self.peers.clone())
            }
        }
        fn add(&mut self, grant: &Grant) -> Result<(), String> {
            self.add_calls += 1;
            self.assert_disk_state("Pending");
            if self.fail_add { return Err("wg syncconf rejected".into()); }
            self.peers.push(Peer {
                public_key: grant.claims.public_key.clone(), address: grant.address
            });
            Ok(())
        }
        fn remove(&mut self, grant: &Grant) -> Result<(), String> {
            self.remove_calls += 1;
            self.assert_disk_state("Revoking");
            if self.fail_remove { return Err("wg syncconf failed".into()); }
            self.peers.retain(|p| p.public_key != grant.claims.public_key);
            Ok(())
        }
    }

    #[test]
    fn enrollment_and_revocation_enforce_durable_write_before_wg_order() {
        let p = root("success");
        let mut store = open(&p);
        store.update(|l| l.insert_open(I, 600)).unwrap();
        let mut wg = FakeWg::new(&p);
        let grant = enroll(&mut store, &mut wg, claim(I), 100, pool()).unwrap();
        assert_eq!(grant.address, Ipv4Addr::new(10,9,8,2));
        assert_eq!(wg.add_calls, 1);
        assert_eq!(retry_read_only(&store, &mut wg, &claim(I)).unwrap(), grant);
        assert_eq!(wg.add_calls, 1, "retry must never add a peer");
        revoke(&mut store, &mut wg, I).unwrap();
        assert_eq!(wg.remove_calls, 1);
        assert!(matches!(store.view().state(I), Some(InviteState::Revoked(_))));
        drop(store);
        let restarted = open(&p);
        assert!(matches!(restarted.view().state(I), Some(InviteState::Revoked(_))));
        assert!(matches!(retry_read_only(&restarted, &mut wg, &claim(I)),
            Err(TransactionError::Readback(Refusal::Revoked))));
        assert_eq!(wg.add_calls, 1);
        drop(restarted);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn failed_peer_creation_leaves_pending_after_restart() {
        let p = root("add-fail");
        let mut store = open(&p);
        store.update(|l| l.insert_open(I, 600)).unwrap();
        let mut wg = FakeWg::new(&p);
        wg.fail_add = true;
        assert!(matches!(enroll(&mut store, &mut wg, claim(I), 100, pool()),
            Err(TransactionError::WireGuard(_))));
        drop(store);
        let mut restarted = open(&p);
        assert!(matches!(restarted.view().state(I), Some(InviteState::Pending(_))));
        wg.fail_add = false;
        assert!(matches!(enroll(&mut restarted, &mut wg, claim(I), 101, pool()),
            Err(TransactionError::Store(StoreError::Policy(Refusal::RecoveryRequired)))));
        assert_eq!(wg.add_calls, 1);
        drop(restarted);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn failed_peer_removal_remains_revoking_and_never_reattaches() {
        let p = root("remove-fail");
        let mut store = open(&p);
        store.update(|l| l.insert_open(I, 600)).unwrap();
        let mut wg = FakeWg::new(&p);
        enroll(&mut store, &mut wg, claim(I), 100, pool()).unwrap();
        wg.fail_remove = true;
        assert!(matches!(revoke(&mut store, &mut wg, I),
            Err(TransactionError::WireGuard(_))));
        drop(store);
        let mut restarted = open(&p);
        assert!(matches!(restarted.view().state(I), Some(InviteState::Revoking(_))));
        assert!(matches!(retry_read_only(&restarted, &mut wg, &claim(I)),
            Err(TransactionError::Readback(Refusal::Revoked))));
        wg.fail_remove = false;
        revoke(&mut restarted, &mut wg, I).unwrap();
        assert!(matches!(restarted.view().state(I), Some(InviteState::Revoked(_))));
        assert_eq!(wg.add_calls, 1);
        drop(restarted);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn unknown_or_incorrect_wg_readback_fails_closed() {
        let p = root("readback");
        let mut store = open(&p);
        store.update(|l| l.insert_open(I, 600)).unwrap();
        let mut wg = FakeWg::new(&p);
        wg.fail_snapshot = true;
        assert!(matches!(enroll(&mut store, &mut wg, claim(I), 100, pool()),
            Err(TransactionError::WireGuard(_))));
        assert_eq!(wg.add_calls, 0);
        assert!(matches!(store.view().state(I), Some(InviteState::Open)));
        wg.fail_snapshot = false;
        wg.wrong_readback = true;
        assert!(matches!(enroll(&mut store, &mut wg, claim(I), 100, pool()),
            Err(TransactionError::Store(StoreError::Policy(Refusal::PeerMissing)))));
        assert!(matches!(store.view().state(I), Some(InviteState::Pending(_))));
        assert_eq!(wg.add_calls, 1);
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn revoked_device_cannot_be_authorized_via_fresh_invitation() {
        let p = root("deny-new");
        let mut store = open(&p);
        store.update(|l| l.insert_open(I, 600)).unwrap();
        store.update(|l| l.insert_open(I2, 600)).unwrap();
        let mut wg = FakeWg::new(&p);
        enroll(&mut store, &mut wg, claim(I), 100, pool()).unwrap();
        revoke(&mut store, &mut wg, I).unwrap();
        let mut other = claim(I2);
        other.public_key = format!("{}=", "B".repeat(43));
        assert!(matches!(enroll(&mut store, &mut wg, other, 101, pool()),
            Err(TransactionError::Store(StoreError::Policy(Refusal::RevokedIdentity)))));
        assert_eq!(wg.add_calls, 1);
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }
}

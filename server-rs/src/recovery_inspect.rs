//! SEC-01 pre-integration recovery INSPECTION (no WG, IO or ledger mutation).
//!
//! Recover only persisted Pending or Revoking states. Normal invitation
//! retry, Open, Consumed and Revoked may NOT enter this path. A future
//! local administrator must separately approve each correction after
//! collecting complete fresh kernel and durable config snapshots under
//! the long-lived authority flock. This is not an HTTP recovery endpoint.
//!
//! This inspect-only module does not implement the corrective operations.

#![cfg(target_os = "linux")]

use crate::{claims_valid, Grant, InviteState, Peer};
use crate::ledger_disk::{LedgerStore, StoreError};
use crate::wg_conf_audit::{require_exact_match, ConfigError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStage { PendingAdd, RevokingRemove }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Operator can finalize after fresh inspection; no WG write needed.
    VerifyAndFinalize,
    RepairConfigWithApproval,
    RepairKernelWithApproval,
    RepairBothWithApproval,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryInspection {
    pub stage: RecoveryStage,
    pub action: RecoveryAction,
    pub config_has_peer: bool,
    pub kernel_has_peer: bool,
}
#[derive(Debug)]
pub enum RecoveryError {
    Ledger(StoreError),
    UnknownInvitation,
    NotRecoverableState,
    InvalidGrant,
    InvalidInventory(ConfigError),
    IdentityCollision,
    UnrelatedDrift,
    ExpiredPending,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presence { Absent, Exact }

fn presence(grant: &Grant, peers: &[Peer]) -> Result<Presence, RecoveryError> {
    let key = &grant.claims.public_key;
    let ip = grant.address;
    let matches: Vec<_> = peers.iter()
        .filter(|p| p.public_key == *key || p.address == ip).collect();
    match matches.as_slice() {
        [] => Ok(Presence::Absent),
        [candidate] if candidate.public_key == *key && candidate.address == ip =>
            Ok(Presence::Exact),
        _ => Err(RecoveryError::IdentityCollision),
    }
}

/// Pure audit of two previously authenticated, fresh inventories. The
/// input must be obtained by trusted live and protected config readers,
/// never supplied by an HTTP client. The store holds the authority lock.
pub fn inspect_recovery(
    store: &LedgerStore, invite_id: &str, live: &[Peer], durable: &[Peer], now_unix: i64,
) -> Result<RecoveryInspection, RecoveryError> {
    let ledger = store.view().map_err(RecoveryError::Ledger)?;
    let inv = ledger.invitations.get(invite_id).ok_or(RecoveryError::UnknownInvitation)?;
    let (stage, grant) = match &inv.state {
        InviteState::Pending(grant) => (RecoveryStage::PendingAdd, grant),
        InviteState::Revoking(grant) => (RecoveryStage::RevokingRemove, grant),
        _ => return Err(RecoveryError::NotRecoverableState),
    };
    if !claims_valid(&grant.claims) || grant.claims.invite_id != invite_id
        || !grant.address.is_private()
    {
        return Err(RecoveryError::InvalidGrant);
    }

    // Inspect the FULL inventories before hiding the target peer; malformed
    // or duplicated unrelated records are not a legitimate empty snapshot.
    require_exact_match(live, live).map_err(RecoveryError::InvalidInventory)?;
    require_exact_match(durable, durable).map_err(RecoveryError::InvalidInventory)?;
    let kernel = presence(grant, live)?;
    let config = presence(grant, durable)?;
    let other_live: Vec<Peer> = live.iter()
        .filter(|p| p.public_key != grant.claims.public_key && p.address != grant.address)
        .cloned().collect();
    let other_disk: Vec<Peer> = durable.iter()
        .filter(|p| p.public_key != grant.claims.public_key && p.address != grant.address)
        .cloned().collect();
    require_exact_match(&other_live, &other_disk)
        .map_err(|_| RecoveryError::UnrelatedDrift)?;

    // Expired Pending cannot justify *recreating* missing peer records.
    if stage == RecoveryStage::PendingAdd && now_unix >= inv.expires_unix
        && !(kernel == Presence::Exact && config == Presence::Exact)
    {
        return Err(RecoveryError::ExpiredPending);
    }

    let action = match (stage, config, kernel) {
        (RecoveryStage::PendingAdd, Presence::Exact, Presence::Exact)
        | (RecoveryStage::RevokingRemove, Presence::Absent, Presence::Absent) =>
            RecoveryAction::VerifyAndFinalize,
        (RecoveryStage::PendingAdd, Presence::Absent, Presence::Exact)
        | (RecoveryStage::RevokingRemove, Presence::Exact, Presence::Absent) =>
            RecoveryAction::RepairConfigWithApproval,
        (RecoveryStage::PendingAdd, Presence::Exact, Presence::Absent)
        | (RecoveryStage::RevokingRemove, Presence::Absent, Presence::Exact) =>
            RecoveryAction::RepairKernelWithApproval,
        (RecoveryStage::PendingAdd, Presence::Absent, Presence::Absent)
        | (RecoveryStage::RevokingRemove, Presence::Exact, Presence::Exact) =>
            RecoveryAction::RepairBothWithApproval,
    };
    Ok(RecoveryInspection {
        stage, action,
        config_has_peer: config == Presence::Exact,
        kernel_has_peer: kernel == Presence::Exact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddressPool, Claims, InviteState};
    use crate::ledger_disk;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    const INV: &str = "11111111-1111-4111-8111-111111111111";
    const DEV: &str = "33333333-3333-4333-8333-333333333333";
    const REQ: &str = "44444444-4444-4444-8444-444444444444";

    fn fixture(tag: &str, revoking: bool) -> (std::path::PathBuf, LedgerStore, Grant) {
        let dir=std::env::temp_dir().join(format!(
            "spidervpn-sec01-inspect-{tag}-{}", std::process::id()));
        let _=std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        ledger_disk::bootstrap_for_test(&dir).unwrap();
        let mut store=LedgerStore::open_existing(&dir,Duration::ZERO).unwrap();
        store.update(|l| l.insert_open(INV,600)).unwrap();
        let grant=store.update(|l| l.reserve(Claims {
            invite_id:INV.into(),request_id:REQ.into(),device_id:DEV.into(),
            public_key:format!("{}=","A".repeat(43)),
            request_digest:"a".repeat(64), recipient_jwk_digest:"b".repeat(64),
        },100,AddressPool{
            network:Ipv4Addr::new(10,66,0,0),prefix:24,
        },Some(&[]))).unwrap();
        if revoking {
            store.update(|l|l.confirm_consumed(INV,Some(&[peer(&grant)]))).unwrap();
            store.update(|l|l.begin_revocation(INV)).unwrap();
        }
        (dir,store,grant)
    }
    fn peer(g: &Grant)->Peer {
        Peer{public_key:g.claims.public_key.clone(),address:g.address}
    }
    fn finish(dir: std::path::PathBuf, store: LedgerStore){
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn pending_all_four_partially_applied_cases_require_distinct_actions(){
        let (dir,store,g)=fixture("add",false);
        let target=[peer(&g)];
        for (disk,live,action) in [
            (false,false,RecoveryAction::RepairBothWithApproval),
            (true,false,RecoveryAction::RepairKernelWithApproval),
            (false,true,RecoveryAction::RepairConfigWithApproval),
            (true,true,RecoveryAction::VerifyAndFinalize),
        ] {
            let disk=if disk {&target[..]} else {&[][..]};
            let live=if live {&target[..]} else {&[][..]};
            let report=inspect_recovery(&store,INV,live,disk,200).unwrap();
            assert_eq!(report.action,action);
            assert_eq!(report.stage,RecoveryStage::PendingAdd);
        }
        assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Pending(_))));
        finish(dir,store);
    }
    #[test]
    fn revoking_all_four_cases_never_offer_new_peer_authorization(){
        let (dir,store,g)=fixture("remove",true);
        let target=[peer(&g)];
        for (disk,live,action) in [
            (false,false,RecoveryAction::VerifyAndFinalize),
            (true,false,RecoveryAction::RepairConfigWithApproval),
            (false,true,RecoveryAction::RepairKernelWithApproval),
            (true,true,RecoveryAction::RepairBothWithApproval),
        ]{
            let disk=if disk {&target[..]}else{&[][..]};
            let live=if live {&target[..]}else{&[][..]};
            let report=inspect_recovery(&store,INV,live,disk,700).unwrap();
            assert_eq!(report.action,action);
            assert_eq!(report.stage,RecoveryStage::RevokingRemove);
        }
        assert!(store.view().unwrap().retry(&g.claims,Some(&target)).is_err());
        finish(dir,store);
    }
    #[test]
    fn target_address_owned_by_different_key_is_denied(){
        let (dir,store,g)=fixture("ip-collision",false);
        let other=Peer{public_key:format!("{}=","B".repeat(43)),address:g.address};
        assert!(matches!(inspect_recovery(&store,INV,&[other],&[],200),
            Err(RecoveryError::IdentityCollision)));
        finish(dir,store);
    }
    #[test]
    fn target_key_mapped_to_wrong_ip_is_denied(){
        let (dir,store,g)=fixture("key-collision",true);
        let other=Peer{public_key:g.claims.public_key.clone(),
            address:Ipv4Addr::new(10,66,0,99)};
        assert!(matches!(inspect_recovery(&store,INV,&[other],&[],200),
            Err(RecoveryError::IdentityCollision)));
        finish(dir,store);
    }
    #[test]
    fn unrelated_identity_drift_cannot_be_masked_by_target_filter(){
        let (dir,store,g)=fixture("other-drift",true);
        let other=Peer{public_key:format!("{}=","B".repeat(43)),
            address:Ipv4Addr::new(10,66,0,3)};
        assert!(matches!(inspect_recovery(&store,INV,&[other],&[peer(&g)],200),
            Err(RecoveryError::UnrelatedDrift)));
        finish(dir,store);
    }
    #[test]
    fn duplicate_or_invalid_peer_in_one_inventory_is_rejected(){
        let (dir,store,_g)=fixture("invalid-inventory",true);
        let other=Peer{public_key:format!("{}=","B".repeat(43)),
            address:Ipv4Addr::new(10,66,0,3)};
        assert!(matches!(inspect_recovery(&store,INV,&[other.clone(),other],&[],200),
            Err(RecoveryError::InvalidInventory(_))));
        let malformed=Peer{public_key:"broken key".into(),
            address:Ipv4Addr::new(10,66,0,3)};
        assert!(matches!(inspect_recovery(&store,INV,&[malformed],&[],200),
            Err(RecoveryError::InvalidInventory(_))));
        finish(dir,store);
    }
    #[test]
    fn terminal_revoked_and_wrong_invitation_are_not_recoverable(){
        let (dir,mut store,_g)=fixture("terminal",true);
        store.update(|l|l.confirm_revocation(INV,Some(&[]))).unwrap();
        assert!(matches!(inspect_recovery(&store,INV,&[],&[],200),
            Err(RecoveryError::NotRecoverableState)));
        assert!(matches!(inspect_recovery(
            &store,"99999999-9999-4999-8999-999999999999",&[],&[],200),
            Err(RecoveryError::UnknownInvitation)));
        finish(dir,store);
    }
    #[test]
    fn expired_incomplete_pending_cannot_recreate_peer(){
        let (dir,store,g)=fixture("expired",false);
        assert!(matches!(inspect_recovery(&store,INV,&[],&[],600),
            Err(RecoveryError::ExpiredPending)));
        let target=[peer(&g)];
        assert_eq!(inspect_recovery(&store,INV,&target,&target,600).unwrap().action,
            RecoveryAction::VerifyAndFinalize);
        finish(dir,store);
    }
    #[test]
    fn inspection_never_modifies_ledger_bytes_or_generation(){
        let (dir,store,g)=fixture("read-only",false);
        let original=std::fs::read(dir.join("authority-ledger.json")).unwrap();
        let version=store.generation().unwrap();
        assert_eq!(inspect_recovery(&store,INV,&[peer(&g)],&[],200)
            .unwrap().action, RecoveryAction::RepairConfigWithApproval);
        assert_eq!(store.generation().unwrap(),version);
        assert_eq!(std::fs::read(dir.join("authority-ledger.json")).unwrap(),original);
        finish(dir,store);
    }
}

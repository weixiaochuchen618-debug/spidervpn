//! SEC-01 pre-integration privileged recovery transaction.
//!
//! There is deliberately NO production approval issuer, CLI or HTTP route.
//! The only approval constructor is cfg(test); untrusted invitation retries
//! cannot construct this sealed token or cause a peer to be reattached.
//! Future root-only tooling must review and confirm an exact generation-
//! bound live/config snapshot, with mandatory fresh reads before each action.
//! The backend is injected; CI only uses fake WG/config, never real devices.

#![cfg(target_os = "linux")]

use crate::{Grant, InviteState, Peer};
use crate::ledger_disk::{LedgerStore, StoreError};
use crate::recovery_inspect::{inspect_recovery, RecoveryAction, RecoveryError, RecoveryInspection, RecoveryStage};
use crate::wg_conf_audit::{require_exact_match, ConfigError};

#[derive(Debug)]
pub enum RecoveryApplyError {
    Store(StoreError),
    Inspection(RecoveryError),
    Snapshot(ConfigError),
    Backend(&'static str),
    StaleReview,
    WrongApproval,
    InvalidState,
}

/// A real root-owned backend must refuse races at filesystem rename and
/// kernel mutation boundaries. No such backend is enabled in this release.
pub trait RecoveryIo {
    fn live(&mut self) -> Result<Vec<Peer>, &'static str>;
    fn disk(&mut self) -> Result<Vec<Peer>, &'static str>;
    fn repair_disk(&mut self, grant: &Grant, stage: RecoveryStage) -> Result<(), &'static str>;
    fn repair_kernel(&mut self, grant: &Grant, stage: RecoveryStage) -> Result<(), &'static str>;
}

#[derive(Clone, Debug)]
pub struct RecoveryReview {
    invite_id: String,
    generation: u64,
    inspection: RecoveryInspection,
    live: Vec<Peer>,
    disk: Vec<Peer>,
}

/// Deliberately opaque; only tests can issue one. Adding a real issuer
/// requires an independently reviewed local authenticated admin CLI.
pub struct AdministratorApproval {
    generation: u64,
    invite_id: String,
    action: RecoveryAction,
}

impl RecoveryReview {
    /// Only public, non-secret fields are exposed for future local admin UI.
    pub fn invite_id(&self) -> &str { &self.invite_id }
    pub fn generation(&self) -> u64 { self.generation }
    pub fn inspection(&self) -> RecoveryInspection { self.inspection }
}


#[cfg(test)]
fn approve_for_test(review: &RecoveryReview) -> AdministratorApproval {
    AdministratorApproval {
        generation:review.generation, invite_id:review.invite_id.clone(),
        action:review.inspection.action
    }
}

fn same(a: &[Peer], b: &[Peer]) -> bool { require_exact_match(a,b).is_ok() }
fn target(g: &Grant) -> Peer {
    Peer { public_key:g.claims.public_key.clone(), address:g.address }
}
fn result_peers(before: &[Peer], grant: &Grant, present: bool) -> Vec<Peer> {
    let mut out: Vec<_> = before.iter()
        .filter(|p|p.public_key!=grant.claims.public_key && p.address!=grant.address)
        .cloned().collect();
    if present { out.push(target(grant)); }
    out
}
fn snapshot(io: &mut impl RecoveryIo) -> Result<(Vec<Peer>,Vec<Peer>),RecoveryApplyError>{
    let before=io.live().map_err(RecoveryApplyError::Backend)?;
    let disk=io.disk().map_err(RecoveryApplyError::Backend)?;
    let after=io.live().map_err(RecoveryApplyError::Backend)?;
    require_exact_match(&before,&after).map_err(RecoveryApplyError::Snapshot)?;
    require_exact_match(&disk,&disk).map_err(RecoveryApplyError::Snapshot)?;
    Ok((after,disk))
}

/// Review has no side effects and cannot serve as a capability or identity.
pub fn prepare_review(
    store: &LedgerStore, invite_id: &str, now: i64,
    io: &mut impl RecoveryIo,
) -> Result<RecoveryReview,RecoveryApplyError> {
    let (live,disk)=snapshot(io)?;
    let inspection=inspect_recovery(store,invite_id,&live,&disk,now)
        .map_err(RecoveryApplyError::Inspection)?;
    Ok(RecoveryReview {
        invite_id:invite_id.into(),
        generation:store.generation().map_err(RecoveryApplyError::Store)?,
        inspection,live,disk,
    })
}

/// All updates are performed under the SAME LedgerStore cross-process lock.
/// A retry must prepare a new review and seek a new approval; there is no
/// implicit rollback, blind retry or silent re-add after partial failure.
pub fn apply_approved(
    store: &mut LedgerStore, review: &RecoveryReview,
    approval: AdministratorApproval, now: i64,
    io: &mut impl RecoveryIo,
) -> Result<RecoveryStage,RecoveryApplyError> {
    if approval.generation!=review.generation
        || approval.invite_id!=review.invite_id
        || approval.action!=review.inspection.action {
        return Err(RecoveryApplyError::WrongApproval);
    }
    if store.generation().map_err(RecoveryApplyError::Store)?!=review.generation {
        return Err(RecoveryApplyError::StaleReview);
    }
    let grant={
        let l=store.view().map_err(RecoveryApplyError::Store)?;
        match (review.inspection.stage,l.state(&review.invite_id)) {
            (RecoveryStage::PendingAdd,Some(InviteState::Pending(g)))
            | (RecoveryStage::RevokingRemove,Some(InviteState::Revoking(g)))=>g.clone(),
            _=>return Err(RecoveryApplyError::InvalidState),
        }
    };
    let (mut live,mut disk)=snapshot(io)?;
    if !same(&live,&review.live) || !same(&disk,&review.disk) {
        return Err(RecoveryApplyError::StaleReview);
    }
    let check=inspect_recovery(store,&review.invite_id,&live,&disk,now)
        .map_err(RecoveryApplyError::Inspection)?;
    if check!=review.inspection { return Err(RecoveryApplyError::StaleReview); }

    let want_present=check.stage==RecoveryStage::PendingAdd;
    let expected=result_peers(&live,&grant,want_present);
    let write_disk=!same(&expected,&disk);
    let write_kernel=!same(&expected,&live);
    let expected_action=match (write_disk,write_kernel) {
        (false,false)=>RecoveryAction::VerifyAndFinalize,
        (true,false)=>RecoveryAction::RepairConfigWithApproval,
        (false,true)=>RecoveryAction::RepairKernelWithApproval,
        (true,true)=>RecoveryAction::RepairBothWithApproval,
    };
    if check.action!=expected_action { return Err(RecoveryApplyError::StaleReview); }

    if write_disk {
        io.repair_disk(&grant,check.stage).map_err(RecoveryApplyError::Backend)?;
        let (current_live,current_disk)=snapshot(io)?;
        require_exact_match(&live,&current_live).map_err(RecoveryApplyError::Snapshot)?;
        require_exact_match(&expected,&current_disk).map_err(RecoveryApplyError::Snapshot)?;
        live=current_live;
        disk=current_disk;
    }
    if write_kernel {
        io.repair_kernel(&grant,check.stage).map_err(RecoveryApplyError::Backend)?;
        let (current_live,current_disk)=snapshot(io)?;
        require_exact_match(&disk,&current_disk).map_err(RecoveryApplyError::Snapshot)?;
        require_exact_match(&expected,&current_live).map_err(RecoveryApplyError::Snapshot)?;
        live=current_live;
    }
    require_exact_match(&expected,&live).map_err(RecoveryApplyError::Snapshot)?;
    require_exact_match(&expected,&disk).map_err(RecoveryApplyError::Snapshot)?;
    let finished=inspect_recovery(store,&review.invite_id,&live,&disk,now)
        .map_err(RecoveryApplyError::Inspection)?;
    if finished.stage!=check.stage || finished.action!=RecoveryAction::VerifyAndFinalize {
        return Err(RecoveryApplyError::InvalidState);
    }
    match check.stage {
        RecoveryStage::PendingAdd => {
            store.update(|l|l.confirm_consumed(&review.invite_id,Some(&live)))
                .map_err(RecoveryApplyError::Store)?;
        }
        RecoveryStage::RevokingRemove => {
            store.update(|l|l.confirm_revocation(&review.invite_id,Some(&live)))
                .map_err(RecoveryApplyError::Store)?;
        }
    }
    Ok(check.stage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddressPool,Claims};
    use crate::ledger_disk;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    const INV:&str="11111111-1111-4111-8111-111111111111";
    const REQ:&str="22222222-2222-4222-8222-222222222222";
    const DEV:&str="33333333-3333-4333-8333-333333333333";
    fn fixture(tag:&str,revoking:bool)->(std::path::PathBuf,LedgerStore,Grant) {
        let p=std::env::temp_dir().join(format!(
            "spidervpn-recovery-approval-{tag}-{}",std::process::id()));
        let _=std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p,std::fs::Permissions::from_mode(0o700)).unwrap();
        ledger_disk::bootstrap_for_test(&p).unwrap();
        let mut store=LedgerStore::open_existing(&p,Duration::ZERO).unwrap();
        store.update(|l|l.insert_open(INV,600)).unwrap();
        let grant=store.update(|l|l.reserve(Claims {
            invite_id:INV.into(),request_id:REQ.into(),device_id:DEV.into(),
            public_key:format!("{}=","A".repeat(43)),
            request_digest:"a".repeat(64),recipient_jwk_digest:"b".repeat(64)
        },100,AddressPool{network:Ipv4Addr::new(10,66,0,0),prefix:24},Some(&[]))).unwrap();
        if revoking {
            store.update(|l|l.confirm_consumed(INV,Some(&[target(&grant)]))).unwrap();
            store.update(|l|l.begin_revocation(INV)).unwrap();
        }
        (p,store,grant)
    }
    struct Fake {
        live:Vec<Peer>,disk:Vec<Peer>,disk_calls:usize,kernel_calls:usize,
        fail_disk:bool,fail_kernel:bool,fail_snapshot:bool,
    }
    impl Fake {
        fn new(live:Vec<Peer>,disk:Vec<Peer>)->Self {
            Self {live,disk,disk_calls:0,kernel_calls:0,
                fail_disk:false,fail_kernel:false,fail_snapshot:false}
        }
    }
    impl RecoveryIo for Fake {
        fn live(&mut self)->Result<Vec<Peer>,&'static str>{
            if self.fail_snapshot{return Err("readback unavailable");}
            Ok(self.live.clone())
        }
        fn disk(&mut self)->Result<Vec<Peer>,&'static str>{
            if self.fail_snapshot{return Err("durable read unavailable");}
            Ok(self.disk.clone())
        }
        fn repair_disk(&mut self,g:&Grant,stage:RecoveryStage)->Result<(),&'static str>{
            self.disk_calls+=1;
            if self.fail_disk{return Err("disk fsync failed");}
            self.disk=result_peers(&self.disk,g,stage==RecoveryStage::PendingAdd);
            Ok(())
        }
        fn repair_kernel(&mut self,g:&Grant,stage:RecoveryStage)->Result<(),&'static str>{
            self.kernel_calls+=1;
            if self.fail_kernel{return Err("wg set failed");}
            self.live=result_peers(&self.live,g,stage==RecoveryStage::PendingAdd);
            Ok(())
        }
    }
    fn cleanup(p:std::path::PathBuf,store:LedgerStore) {
        drop(store); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn pending_four_cases_modify_exactly_expected_side(){
        for (name,l,d,expect_disk,expect_kernel) in [
            ("both",false,false,1,1),("disk",true,false,1,0),
            ("kernel",false,true,0,1),("done",true,true,0,0)
        ] {
            let (p,mut store,g)=fixture(name,false);
            let mut ops=Fake::new(
                if l{vec![target(&g)]}else{vec![]},
                if d{vec![target(&g)]}else{vec![]});
            let review=prepare_review(&store,INV,200,&mut ops).unwrap();
            let approval=approve_for_test(&review);
            assert_eq!(apply_approved(&mut store,&review,approval,200,&mut ops).unwrap(),
                RecoveryStage::PendingAdd);
            assert_eq!((ops.disk_calls,ops.kernel_calls),(expect_disk,expect_kernel));
            assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Consumed(_))));
            cleanup(p,store);
        }
    }
    #[test]
    fn revoking_four_cases_never_create_peer(){
        for (name,l,d,expect_disk,expect_kernel) in [
            ("both",true,true,1,1),("disk",false,true,1,0),
            ("kernel",true,false,0,1),("done",false,false,0,0)
        ] {
            let (p,mut store,g)=fixture(name,true);
            let mut ops=Fake::new(
                if l{vec![target(&g)]}else{vec![]},
                if d{vec![target(&g)]}else{vec![]});
            let review=prepare_review(&store,INV,800,&mut ops).unwrap();
            let approval=approve_for_test(&review);
            apply_approved(&mut store,&review,approval,800,&mut ops).unwrap();
            assert_eq!((ops.disk_calls,ops.kernel_calls),(expect_disk,expect_kernel));
            assert!(ops.live.is_empty()&&ops.disk.is_empty());
            assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Revoked(_))));
            assert!(store.view().unwrap().retry(&g.claims,Some(&[])).is_err());
            cleanup(p,store);
        }
    }
    #[test]
    fn stale_generation_and_wrong_approval_cause_zero_mutations(){
        let (p,mut store,g)=fixture("reject",false);
        let mut ops=Fake::new(vec![],vec![]);
        let review=prepare_review(&store,INV,200,&mut ops).unwrap();
        let mut approval=approve_for_test(&review);
        approval.action=RecoveryAction::RepairKernelWithApproval;
        assert!(matches!(apply_approved(&mut store,&review,approval,200,&mut ops),
            Err(RecoveryApplyError::WrongApproval)));
        approval=approve_for_test(&review);
        ops.live.push(target(&g));
        assert!(matches!(apply_approved(&mut store,&review,approval,200,&mut ops),
            Err(RecoveryApplyError::StaleReview)));
        ops.live.clear();
        store.update(|l|l.insert_open("99999999-9999-4999-8999-999999999999",600)).unwrap();
        // Each attempt requires a fresh, single-use approval.
        approval=approve_for_test(&review);
        assert!(matches!(apply_approved(&mut store,&review,approval,200,&mut ops),
            Err(RecoveryApplyError::StaleReview)));
        assert_eq!((ops.disk_calls,ops.kernel_calls),(0,0));
        cleanup(p,store);
    }
    #[test]
    fn file_failure_stops_kernel_and_keeps_pending(){
        let (p,mut store,_)=fixture("disk-fail",false);
        let mut ops=Fake::new(vec![],vec![]);ops.fail_disk=true;
        let review=prepare_review(&store,INV,200,&mut ops).unwrap();
        let approval=approve_for_test(&review);
        assert!(matches!(apply_approved(&mut store,&review,approval,200,&mut ops),
            Err(RecoveryApplyError::Backend(_))));
        assert_eq!(ops.kernel_calls,0);
        assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Pending(_))));
        cleanup(p,store);
    }
    #[test]
    fn kernel_failure_after_config_change_leaves_revoking(){
        let (p,mut store,g)=fixture("kernel-fail",true);
        let mut ops=Fake::new(vec![target(&g)],vec![target(&g)]);
        ops.fail_kernel=true;
        let review=prepare_review(&store,INV,800,&mut ops).unwrap();
        let approval=approve_for_test(&review);
        assert!(matches!(apply_approved(&mut store,&review,approval,800,&mut ops),
            Err(RecoveryApplyError::Backend(_))));
        assert_eq!((ops.disk_calls,ops.kernel_calls),(1,1));
        assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Revoking(_))));
        cleanup(p,store);
    }
    #[test]
    fn expired_pending_does_not_issue_recovery_review(){
        let (p,store,_)=fixture("expired",false);
        let mut ops=Fake::new(vec![],vec![]);
        assert!(matches!(prepare_review(&store,INV,600,&mut ops),
            Err(RecoveryApplyError::Inspection(RecoveryError::ExpiredPending))));
        cleanup(p,store);
    }
}

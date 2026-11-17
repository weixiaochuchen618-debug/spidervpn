//! SEC-01 / SEC-08: portable, dependency-free Rust authority policy for the
//! future Linux pairing daemon.
//!
//! This core DOES NOT replace the currently deployed Python service. It has no
//! SSH, TLS, signing, persistence or WireGuard side effects. Callers must:
//! 1. authenticate PairRequest JWS (including digest/server binding) BEFORE
//!    constructing Claims and invoking this module;
//! 2. hold an exclusive, cross-process Linux lock while reading/writing the
//!    durable ledger and WireGuard state;
//! 3. persist Pending/Revoking BEFORE mutating WireGuard, and only commit
//!    Consumed/Revoked after actual WG readback proves the corresponding state;
//! 4. fail closed on an unknown/missing peer snapshot.
//!
//! The old service reattached a Consumed invitation's peer when replayed even
//! after the operator had removed it. A previously signed grant is not a
//! standing right to recreate a revoked tunnel peer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub mod lock;

pub mod legacy;

/// Offline legacy RS256 verification ONLY, not a runtime authorization path.
pub mod legacy_signed;

#[cfg(target_os = "linux")]
pub mod ledger_disk;

#[cfg(target_os = "linux")]
pub mod transaction;

#[cfg(target_os = "linux")]
pub mod wg_readonly;

#[cfg(target_os = "linux")]
pub mod wg_conf_audit;

#[cfg(target_os = "linux")]
pub mod wg_peer_plan;

#[cfg(target_os = "linux")]
pub mod wg_atomic;

#[cfg(target_os = "linux")]
pub mod wg_live_set;

#[cfg(target_os = "linux")]
pub mod recovery_inspect;

#[cfg(target_os = "linux")]
pub mod recovery_apply;

#[cfg(all(target_os = "linux", feature = "linux-admin-finalize"))]
pub mod admin_terminal;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub invite_id: String,
    pub request_id: String,
    pub device_id: String,
    pub public_key: String,
    pub request_digest: String,
    pub recipient_jwk_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub claims: Claims,
    pub address: Ipv4Addr,
}

/// The inventory must come from a freshly verified WireGuard observation,
/// not from an optimistic/in-memory projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub public_key: String,
    pub address: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteState {
    Open,
    /// Durable reservation written before any WireGuard changes.
    Pending(Grant),
    /// Peer exists and its exact identity/address were observed.
    Consumed(Grant),
    /// Durable deny-state written BEFORE deleting the peer from WireGuard.
    Revoking(Grant),
    /// Peer absence was read back; NEVER reattach on retry.
    Revoked(Grant),
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub expires_unix: i64,
    pub state: InviteState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    UnknownInvitation,
    DuplicateInvitation,
    InvalidRequest,
    Expired,
    Cancelled,
    Revoked,
    RevokedIdentity,
    ConsumedByAnotherRequest,
    RecoveryRequired,
    PeerStateUnknown,
    PeerMissing,
    PeerMismatch,
    AddressExhausted,
    Conflict,
    InvalidSubnet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressPool {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl AddressPool {
    /// Restrict the pool to an RFC1918 network address with room for a server
    /// (+1) and at least one client (+2), matching the existing protocol.
    fn range(self) -> Result<std::ops::RangeInclusive<u32>, Refusal> {
        if !(16..=30).contains(&self.prefix) {
            return Err(Refusal::InvalidSubnet);
        }
        let width = 1u32 << (32 - u32::from(self.prefix));
        let base = u32::from(self.network);
        if base & (width - 1) != 0
            || !self.network.is_private()
            || !Ipv4Addr::from(base + width - 1).is_private()
        {
            return Err(Refusal::InvalidSubnet);
        }
        Ok((base + 2)..=(base + width - 2))
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub(crate) invitations: BTreeMap<String, Invitation>,
    pub(crate) revoked_devices: BTreeSet<String>,
    pub(crate) revoked_keys: BTreeSet<String>,
}

pub(crate) fn lower_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
    })
}
pub(crate) fn wg_key(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 44 && b[43] == b'=' && b[..43].iter().all(|c|
        c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
}
pub(crate) fn hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn claims_valid(c: &Claims) -> bool {
    lower_uuid(&c.invite_id)
        && lower_uuid(&c.request_id)
        && lower_uuid(&c.device_id)
        && wg_key(&c.public_key)
        && hex_sha256(&c.request_digest)
        && hex_sha256(&c.recipient_jwk_digest)
}

/// Never infer that an absent peer in a local cached projection is genuine.
/// All calls below accept a verified live snapshot or return PeerStateUnknown.
fn observed(peers: Option<&[Peer]>) -> Result<&[Peer], Refusal> {
    peers.ok_or(Refusal::PeerStateUnknown)
}

fn exact_peer(grant: &Grant, peers: &[Peer]) -> Result<(), Refusal> {
    let matches: Vec<_> = peers.iter().filter(|p| {
        p.public_key == grant.claims.public_key || p.address == grant.address
    }).collect();
    if matches.is_empty() {
        return Err(Refusal::PeerMissing);
    }
    if matches.len() != 1
        || matches[0].public_key != grant.claims.public_key
        || matches[0].address != grant.address
    {
        return Err(Refusal::PeerMismatch);
    }
    Ok(())
}

impl Ledger {
    pub fn insert_open(&mut self, id: &str, expires_unix: i64) -> Result<(), Refusal> {
        if !lower_uuid(id) {
            return Err(Refusal::InvalidRequest);
        }
        if self.invitations.contains_key(id) {
            return Err(Refusal::DuplicateInvitation);
        }
        self.invitations.insert(
            id.to_string(),
            Invitation { expires_unix, state: InviteState::Open },
        );
        Ok(())
    }

    /// SEC-01 migration: old "Consumed" entries MUST be imported, never
    /// silently converted to Open. Their first retry must still prove an
    /// exact live peer; importing the ledger itself never attaches a peer.
    pub fn import_consumed(&mut self, grant: Grant, expires_unix: i64) -> Result<(), Refusal> {
        if !claims_valid(&grant.claims) {
            return Err(Refusal::InvalidRequest);
        }
        if self.invitations.contains_key(&grant.claims.invite_id) {
            return Err(Refusal::DuplicateInvitation);
        }
        self.invitations.insert(grant.claims.invite_id.clone(),
            Invitation { expires_unix, state: InviteState::Consumed(grant) });
        Ok(())
    }

    pub fn state(&self, id: &str) -> Option<&InviteState> {
        self.invitations.get(id).map(|inv| &inv.state)
    }

    fn denied_identity(&self, req: &Claims) -> bool {
        self.revoked_devices.contains(&req.device_id)
            || self.revoked_keys.contains(&req.public_key)
            || self.invitations.values().any(|inv| match &inv.state {
                InviteState::Revoking(g) | InviteState::Revoked(g) => {
                    g.claims.device_id == req.device_id
                        || g.claims.public_key == req.public_key
                }
                _ => false,
            })
    }

    /// Prepare a single-use invitation. The caller must durably commit
    /// Pending while holding the cross-process lock BEFORE touching WG.
    /// This reserves both the key and address until explicit reconciliation.
    pub fn reserve(
        &mut self,
        req: Claims,
        now_unix: i64,
        pool: AddressPool,
        live_peers: Option<&[Peer]>,
    ) -> Result<Grant, Refusal> {
        if !claims_valid(&req) {
            return Err(Refusal::InvalidRequest);
        }
        let peers = observed(live_peers)?;
        let invitation = self.invitations.get(&req.invite_id).ok_or(Refusal::UnknownInvitation)?;
        match &invitation.state {
            InviteState::Open => {}
            InviteState::Cancelled => return Err(Refusal::Cancelled),
            InviteState::Expired => return Err(Refusal::Expired),
            InviteState::Revoked(_) | InviteState::Revoking(_) => return Err(Refusal::Revoked),
            InviteState::Consumed(_) => return Err(Refusal::ConsumedByAnotherRequest),
            InviteState::Pending(_) => return Err(Refusal::RecoveryRequired),
        }
        if now_unix >= invitation.expires_unix {
            return Err(Refusal::Expired);
        }
        if self.denied_identity(&req) {
            return Err(Refusal::RevokedIdentity);
        }
        if peers.iter().any(|p| p.public_key == req.public_key) {
            return Err(Refusal::Conflict);
        }

        let mut reserved_ips = BTreeSet::new();
        let mut reserved_keys = BTreeSet::new();
        let mut reserved_devices = BTreeSet::new();
        for inv in self.invitations.values() {
            match &inv.state {
                InviteState::Pending(g) | InviteState::Consumed(g) | InviteState::Revoking(g) => {
                    reserved_ips.insert(u32::from(g.address));
                    reserved_keys.insert(g.claims.public_key.as_str());
                    reserved_devices.insert(g.claims.device_id.as_str());
                }
                _ => {}
            }
        }
        if reserved_keys.contains(req.public_key.as_str())
            || reserved_devices.contains(req.device_id.as_str())
        {
            return Err(Refusal::Conflict);
        }
        for peer in peers {
            reserved_ips.insert(u32::from(peer.address));
        }
        let address = pool.range()?
            .find(|candidate| !reserved_ips.contains(candidate))
            .map(Ipv4Addr::from)
            .ok_or(Refusal::AddressExhausted)?;
        let grant = Grant { claims: req.clone(), address };
        let Some(record) = self.invitations.get_mut(&req.invite_id) else {
            return Err(Refusal::UnknownInvitation);
        };
        record.state = InviteState::Pending(grant.clone());
        Ok(grant)
    }

    /// Only a confirmed exact WG peer can promote a pending reservation.
    pub fn confirm_consumed(
        &mut self,
        invite_id: &str,
        live_peers: Option<&[Peer]>,
    ) -> Result<Grant, Refusal> {
        let peers = observed(live_peers)?;
        let inv = self.invitations.get_mut(invite_id).ok_or(Refusal::UnknownInvitation)?;
        let InviteState::Pending(grant) = &inv.state else {
            return Err(Refusal::RecoveryRequired);
        };
        exact_peer(grant, peers)?;
        let done = grant.clone();
        inv.state = InviteState::Consumed(done.clone());
        Ok(done)
    }

    /// An authenticated retry is **read-only**. In particular it MUST NOT
    /// call attach_client/syncconf. A consumed ledger entry alone cannot
    /// resurrect a peer manually removed by an administrator.
    pub fn retry(
        &self,
        req: &Claims,
        live_peers: Option<&[Peer]>,
    ) -> Result<&Grant, Refusal> {
        if !claims_valid(req) {
            return Err(Refusal::InvalidRequest);
        }
        let inv = self.invitations.get(&req.invite_id).ok_or(Refusal::UnknownInvitation)?;
        match &inv.state {
            InviteState::Consumed(grant) => {
                if grant.claims != *req {
                    return Err(Refusal::ConsumedByAnotherRequest);
                }
                exact_peer(grant, observed(live_peers)?)?;
                Ok(grant)
            }
            InviteState::Revoking(_) | InviteState::Revoked(_) => Err(Refusal::Revoked),
            InviteState::Pending(_) => Err(Refusal::RecoveryRequired),
            InviteState::Cancelled => Err(Refusal::Cancelled),
            InviteState::Expired => Err(Refusal::Expired),
            InviteState::Open => Err(Refusal::RecoveryRequired),
        }
    }

    /// First commit a *durable* Revoking deny-state. The actual peer removal
    /// happens afterward; restart/replay must never see Consumed again.
    pub fn begin_revocation(&mut self, invite_id: &str) -> Result<Grant, Refusal> {
        let inv = self.invitations.get_mut(invite_id).ok_or(Refusal::UnknownInvitation)?;
        match &inv.state {
            InviteState::Consumed(grant) | InviteState::Pending(grant) => {
                let old = grant.clone();
                inv.state = InviteState::Revoking(old.clone());
                Ok(old)
            }
            InviteState::Revoking(grant) => Ok(grant.clone()),
            InviteState::Revoked(_) => Err(Refusal::Revoked),
            _ => Err(Refusal::RecoveryRequired),
        }
    }

    /// Only readback-confirmed absence of BOTH the old key and its address
    /// transitions to Revoked. A failed WG removal leaves Revoking and
    /// indefinitely denies replay until an administrator reconciles it.
    pub fn confirm_revocation(
        &mut self,
        invite_id: &str,
        live_peers: Option<&[Peer]>,
    ) -> Result<(), Refusal> {
        let peers = observed(live_peers)?;
        let inv = self.invitations.get_mut(invite_id).ok_or(Refusal::UnknownInvitation)?;
        let InviteState::Revoking(grant) = &inv.state else {
            return Err(Refusal::RecoveryRequired);
        };
        if peers.iter().any(|p| p.public_key == grant.claims.public_key || p.address == grant.address) {
            return Err(Refusal::PeerMismatch);
        }
        let old = grant.clone();
        self.revoked_devices.insert(old.claims.device_id.clone());
        self.revoked_keys.insert(old.claims.public_key.clone());
        inv.state = InviteState::Revoked(old);
        Ok(())
    }

    pub fn cancel_open(&mut self, invite_id: &str) -> Result<(), Refusal> {
        let inv = self.invitations.get_mut(invite_id).ok_or(Refusal::UnknownInvitation)?;
        if !matches!(inv.state, InviteState::Open | InviteState::Cancelled) {
            return Err(Refusal::RecoveryRequired);
        }
        inv.state = InviteState::Cancelled;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INV: &str = "11111111-1111-4111-8111-111111111111";
    const INV2: &str = "22222222-2222-4222-8222-222222222222";
    const DEV: &str = "33333333-3333-4333-8333-333333333333";
    const REQ: &str = "44444444-4444-4444-8444-444444444444";

    fn claim(invite: &str) -> Claims {
        Claims {
            invite_id: invite.into(),
            request_id: REQ.into(),
            device_id: DEV.into(),
            public_key: format!("{}=", "A".repeat(43)),
            request_digest: "a".repeat(64),
            recipient_jwk_digest: "b".repeat(64),
        }
    }
    fn pool() -> AddressPool {
        AddressPool { network: Ipv4Addr::new(10, 9, 8, 0), prefix: 29 }
    }
    fn peer(grant: &Grant) -> Peer {
        Peer { public_key: grant.claims.public_key.clone(), address: grant.address }
    }
    fn consumed() -> (Ledger, Grant) {
        let mut ledger = Ledger::default();
        ledger.insert_open(INV, 600).unwrap();
        let grant = ledger.reserve(claim(INV), 100, pool(), Some(&[])).unwrap();
        assert_eq!(grant.address, Ipv4Addr::new(10, 9, 8, 2));
        ledger.confirm_consumed(INV, Some(&[peer(&grant)])).unwrap();
        (ledger, grant)
    }

    #[test]
    fn successful_idempotent_retry_requires_exact_live_peer() {
        let (ledger, grant) = consumed();
        assert_eq!(ledger.retry(&claim(INV), Some(&[peer(&grant)])), Ok(&grant));
        assert_eq!(ledger.retry(&claim(INV), None), Err(Refusal::PeerStateUnknown));
        assert_eq!(ledger.retry(&claim(INV), Some(&[])), Err(Refusal::PeerMissing));
        let wrong = Peer { public_key: grant.claims.public_key.clone(), address: Ipv4Addr::new(10, 9, 8, 3) };
        assert_eq!(ledger.retry(&claim(INV), Some(&[wrong])), Err(Refusal::PeerMismatch));
    }

    #[test]
    fn revoked_peer_cannot_be_resurrected_with_original_or_changed_key() {
        let (mut ledger, grant) = consumed();
        ledger.begin_revocation(INV).unwrap();
        assert_eq!(ledger.retry(&claim(INV), Some(&[peer(&grant)])), Err(Refusal::Revoked));
        assert_eq!(ledger.confirm_revocation(INV, Some(&[peer(&grant)])), Err(Refusal::PeerMismatch));
        assert!(matches!(ledger.state(INV), Some(InviteState::Revoking(_))));
        // A failed WG removal must NOT reactivate retry on the old invite.
        assert_eq!(ledger.retry(&claim(INV), Some(&[])), Err(Refusal::Revoked));
        ledger.confirm_revocation(INV, Some(&[])).unwrap();
        assert!(matches!(ledger.state(INV), Some(InviteState::Revoked(_))));
        let mut old = claim(INV);
        old.public_key = format!("{}=", "B".repeat(43));
        assert_eq!(ledger.retry(&old, Some(&[])), Err(Refusal::Revoked));
        ledger.insert_open(INV2, 600).unwrap();
        let mut fresh = claim(INV2);
        fresh.public_key = format!("{}=", "C".repeat(43));
        assert_eq!(ledger.reserve(fresh, 101, pool(), Some(&[])), Err(Refusal::RevokedIdentity));
    }

    #[test]
    fn original_jwk_and_request_id_do_not_allow_key_or_device_swap() {
        let (ledger, grant) = consumed();
        for swapped in [
            { let mut c = claim(INV); c.public_key = format!("{}=", "B".repeat(43)); c },
            { let mut c = claim(INV); c.device_id = INV2.into(); c },
            { let mut c = claim(INV); c.request_digest = "c".repeat(64); c },
        ] {
            assert_eq!(ledger.retry(&swapped, Some(&[peer(&grant)])),
                Err(Refusal::ConsumedByAnotherRequest));
        }
    }

    #[test]
    fn pending_prevents_duplicate_address_and_recovery_is_explicit() {
        let mut ledger = Ledger::default();
        ledger.insert_open(INV, 600).unwrap();
        ledger.insert_open(INV2, 600).unwrap();
        let first = ledger.reserve(claim(INV), 100, pool(), Some(&[])).unwrap();
        assert_eq!(ledger.reserve(claim(INV), 100, pool(), Some(&[])), Err(Refusal::RecoveryRequired));
        assert_eq!(ledger.retry(&claim(INV), Some(&[])), Err(Refusal::RecoveryRequired));
        let mut second_claim = claim(INV2);
        second_claim.device_id = INV2.into();
        second_claim.public_key = format!("{}=", "B".repeat(43));
        let second = ledger.reserve(second_claim, 100, pool(), Some(&[])).unwrap();
        assert_ne!(first.address, second.address);
        assert_eq!(ledger.confirm_consumed(INV, Some(&[])), Err(Refusal::PeerMissing));
        assert!(matches!(ledger.state(INV), Some(InviteState::Pending(_))));
        ledger.confirm_consumed(INV, Some(&[peer(&first)])).unwrap();
    }

    #[test]
    fn legacy_consumed_without_peer_never_automatically_reattaches() {
        let (_, grant) = consumed();
        let mut ledger = Ledger::default();
        ledger.import_consumed(grant.clone(), 1).unwrap();
        assert_eq!(ledger.retry(&grant.claims, Some(&[])), Err(Refusal::PeerMissing));
        assert_eq!(ledger.retry(&grant.claims, None), Err(Refusal::PeerStateUnknown));
        ledger.begin_revocation(INV).unwrap();
        ledger.confirm_revocation(INV, Some(&[])).unwrap();
        assert_eq!(ledger.retry(&grant.claims, Some(&[peer(&grant)])), Err(Refusal::Revoked));
    }

    #[test]
    fn live_duplicate_key_and_unknown_peer_inventory_are_rejected() {
        let mut ledger = Ledger::default();
        ledger.insert_open(INV, 600).unwrap();
        assert_eq!(ledger.reserve(claim(INV), 100, pool(), None), Err(Refusal::PeerStateUnknown));
        let external = Peer { public_key: claim(INV).public_key, address: Ipv4Addr::new(10, 9, 8, 3) };
        assert_eq!(ledger.reserve(claim(INV), 100, pool(), Some(&[external])), Err(Refusal::Conflict));
        assert!(matches!(ledger.state(INV), Some(InviteState::Open)));
    }

    #[test]
    fn invalid_identity_and_subnet_are_fail_closed() {
        let mut ledger = Ledger::default();
        ledger.insert_open(INV, 600).unwrap();
        let mut bad = claim(INV);
        bad.device_id = "你好".into();
        assert_eq!(ledger.reserve(bad, 100, pool(), Some(&[])), Err(Refusal::InvalidRequest));
        let mut bad = claim(INV);
        bad.public_key = format!("{}😀=", "A".repeat(39));
        assert_eq!(ledger.reserve(bad, 100, pool(), Some(&[])), Err(Refusal::InvalidRequest));
        let bad_pool = AddressPool { network: Ipv4Addr::new(10, 9, 8, 1), prefix: 29 };
        assert_eq!(ledger.reserve(claim(INV), 100, bad_pool, Some(&[])), Err(Refusal::InvalidSubnet));
        let bad_pool = AddressPool { network: Ipv4Addr::new(8, 8, 8, 0), prefix: 24 };
        assert_eq!(ledger.reserve(claim(INV), 100, bad_pool, Some(&[])), Err(Refusal::InvalidSubnet));
        assert_eq!(ledger.reserve(claim(INV), 600, pool(), Some(&[])), Err(Refusal::Expired));
    }

    #[test]
    fn a_revoking_identity_is_blocked_on_other_invitations_before_wg_removal() {
        let (mut ledger, grant) = consumed();
        ledger.begin_revocation(INV).unwrap();
        ledger.insert_open(INV2, 600).unwrap();
        let mut next = claim(INV2);
        next.public_key = format!("{}=", "C".repeat(43));
        assert_eq!(ledger.reserve(next, 200, pool(), Some(&[peer(&grant)])), Err(Refusal::RevokedIdentity));
        assert_eq!(ledger.confirm_revocation(INV, Some(&[peer(&grant)])), Err(Refusal::PeerMismatch));
    }
}

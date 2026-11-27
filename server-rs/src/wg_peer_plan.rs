//! SEC-01 S03: prepare ONE WireGuard peer config change without side effects.
//!
//! This pre-integration Rust planner never executes a command or writes files.
//! Its input is a previously authenticated grant or registered-device
//! removal plus verified wg-quick config.
//! It preserves every byte of unrelated peer/interface sections (including
//! comments and secrets) and revalidates the resulting complete peer set.
//!
//! For revocation, a peer absent from BOTH live and durable config is a
//! safe no-op, allowing a Revoking operation to resume after an interrupted
//! filesystem update. The caller must still verify WG live/disk readback.
//! This is not an authorization service and is not wired to Python.

#![cfg(target_os = "linux")]

use crate::{claims_valid, Grant, InviteState, Ledger, Peer};
#[cfg(feature = "linux-pairing-process")]
use crate::existing_devices::{ExistingDevice, ExistingDeviceState};
use crate::wg_conf_audit::{parse_wg_quick_conf, require_exact_match, ConfigError};
use std::net::Ipv4Addr;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Add,
    Remove,
}

#[derive(Clone, Copy)]
pub(crate) enum PeerChange<'a> {
    Invitation(&'a Grant, Change),
    #[cfg(feature = "linux-pairing-process")]
    ExistingRemoval { device_id: &'a str, device: &'a ExistingDevice },
}

impl<'a> PeerChange<'a> {
    pub(crate) fn target(self) -> (&'a str, Ipv4Addr, Change) {
        match self {
            Self::Invitation(grant, operation) => (&grant.claims.public_key, grant.address, operation),
            #[cfg(feature = "linux-pairing-process")]
            Self::ExistingRemoval { device, .. } => (&device.public_key, device.address, Change::Remove),
        }
    }

    pub(crate) fn valid(self) -> bool {
        match self {
            Self::Invitation(grant, _) => claims_valid(&grant.claims) && grant.address.is_private(),
            #[cfg(feature = "linux-pairing-process")]
            Self::ExistingRemoval { device_id, device } => device.valid(device_id),
        }
    }

    pub(crate) fn prepared(self, ledger: &Ledger) -> bool {
        match self {
            Self::Invitation(grant, operation) => match (operation, ledger.state(&grant.claims.invite_id)) {
                (Change::Add, Some(InviteState::Pending(saved)))
                | (Change::Remove, Some(InviteState::Revoking(saved))) => saved == grant,
                _ => false,
            },
            #[cfg(feature = "linux-pairing-process")]
            Self::ExistingRemoval { device_id, device } => {
                device.state == ExistingDeviceState::Revoking
                    && ledger.existing_device(device_id) == Some(device)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    InvalidGrant,
    InvalidConfig,
    MissingPeer,
    PeerConflict,
    AddressConflict,
    InconsistentConfig,
    ResultTooLarge,
}

#[derive(Clone)]
pub struct Plan {
    /// Contains the server PRIVATE KEY copied from the original config.
    /// Never log, serialize to an API response, or derive Debug for this.
    pub(crate) bytes: Vec<u8>,
    pub(crate) expected_peers: Vec<Peer>,
    pub(crate) changed: bool,
}
impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The raw config includes PrivateKey/PresharedKey. Never emit it.
        f.debug_struct("Plan")
            .field("changed", &self.changed)
            .field("config_bytes", &"<redacted>")
            .field("expected_peer_count", &self.expected_peers.len())
            .finish()
    }
}
impl Plan {
    /// Full config bytes including server secrets. Only pass to the future
    /// owner-only atomic writer; never print or send to an HTTP response.
    pub(crate) fn config_bytes(&self) -> &[u8] { &self.bytes }
    pub fn changed(&self) -> bool { self.changed }
    pub fn expected_peers(&self) -> &[Peer] { &self.expected_peers }
}

fn peer_sections(text: &str) -> Vec<(usize, usize)> {
    let mut starts = Vec::new();
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if line.trim() == "[Peer]" { starts.push(offset); }
        offset += line.len();
    }
    starts.iter().enumerate().map(|(i, start)| {
        (*start, starts.get(i + 1).copied().unwrap_or(text.len()))
    }).collect()
}

/// Called only after the caller checked the existing live WG/config snapshot
/// under the long-held authority transaction lock. This planner itself also
/// verifies the complete original config, but cannot attest the live kernel.
pub fn plan_change(
    current: &[u8], grant: &Grant, change: Change,
) -> Result<Plan, PlanError> {
    plan_peer_change(current, PeerChange::Invitation(grant, change))
}

pub(crate) fn plan_peer_change(current: &[u8], change: PeerChange<'_>) -> Result<Plan, PlanError> {
    if !change.valid() {
        return Err(PlanError::InvalidGrant);
    }
    let (public_key, address, operation) = change.target();
    if current.len() > MAX_CONFIG_BYTES { return Err(PlanError::ResultTooLarge); }
    let original = parse_wg_quick_conf(current).map_err(|_| PlanError::InvalidConfig)?;
    let input = std::str::from_utf8(current).map_err(|_| PlanError::InvalidConfig)?;
    let spans = peer_sections(input);
    if spans.len() != original.len() {
        return Err(PlanError::InconsistentConfig);
    }
    let existing_key = original.iter().position(|p| p.public_key == public_key);
    let existing_ip = original.iter().position(|p| p.address == address);
    let (result, expected, changed) = match operation {
        Change::Add => {
            let PeerChange::Invitation(grant, Change::Add) = change else {
                return Err(PlanError::InvalidGrant);
            };
            if existing_key.is_some() { return Err(PlanError::PeerConflict); }
            if existing_ip.is_some() { return Err(PlanError::AddressConflict); }
            let mut data = current.to_vec();
            if !data.is_empty() && !data.ends_with(b"\n") { data.push(b'\n'); }
            data.extend_from_slice(format!(
                "\n[Peer]\n# tc-pair request={} device={}\nPublicKey = {}\nAllowedIPs = {}/32\n",
                grant.claims.request_id, grant.claims.device_id,
                public_key, address
            ).as_bytes());
            let mut peers = original.clone();
            peers.push(Peer {
                public_key: public_key.to_owned(), address,
            });
            (data, peers, true)
        }
        Change::Remove => match (existing_key, existing_ip) {
            (None, None) => (current.to_vec(), original.clone(), false),
            (Some(k), Some(ip)) if k == ip => {
                let (start, end) = spans[k];
                let mut data = Vec::with_capacity(current.len() - (end-start));
                data.extend_from_slice(&current[..start]);
                data.extend_from_slice(&current[end..]);
                let mut peers = original.clone();
                peers.remove(k);
                (data, peers, true)
            }
            _ => return Err(PlanError::PeerConflict),
        },
    };
    if result.len() > MAX_CONFIG_BYTES { return Err(PlanError::ResultTooLarge); }
    let reparsed = parse_wg_quick_conf(&result)
        .map_err(|_: ConfigError| PlanError::InconsistentConfig)?;
    require_exact_match(&expected, &reparsed)
        .map_err(|_| PlanError::InconsistentConfig)?;
    Ok(Plan { bytes: result, expected_peers: expected, changed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Claims;
    use std::net::Ipv4Addr;
    const INV: &str = "11111111-1111-4111-8111-111111111111";
    const REQ: &str = "22222222-2222-4222-8222-222222222222";
    const DEV: &str = "33333333-3333-4333-8333-333333333333";

    fn key(c: char) -> String { format!("{}=", c.to_string().repeat(43)) }
    fn grant(k: char, ip: [u8;4]) -> Grant {
        Grant {
            claims: Claims {
                invite_id: INV.into(), request_id: REQ.into(),
                device_id: DEV.into(), public_key: key(k),
                request_digest: "a".repeat(64),
                recipient_jwk_digest: "b".repeat(64)
            },
            address: Ipv4Addr::from(ip),
        }
    }
    fn conf() -> Vec<u8> {
        format!(
            "# existing server comment\n[Interface]\nPrivateKey = NEVER_EXPOSE_THIS_SECRET\nAddress = 10.66.0.1/24\nPostUp = echo keep-this\n\n[Peer]\n# existing peer A\nPublicKey = {}\nAllowedIPs = 10.66.0.2/32\nPersistentKeepalive = 25\n\n[Peer]\n# existing peer B\nPublicKey = {}\nAllowedIPs = 10.66.0.3/32\n",
            key('A'), key('B')
        ).into_bytes()
    }
    #[test]
    fn add_preserves_existing_config_bytes_and_private_key() {
        let old = conf();
        let plan = plan_change(&old, &grant('C', [10,66,0,4]), Change::Add).unwrap();
        assert!(plan.changed());
        assert!(plan.bytes.starts_with(&old));
        assert_eq!(plan.expected_peers().len(),3);
        assert!(plan.bytes.windows(b"NEVER_EXPOSE_THIS_SECRET".len())
            .any(|w| w == b"NEVER_EXPOSE_THIS_SECRET"));
        assert!(!format!("{plan:?}").contains("NEVER_EXPOSE_THIS_SECRET"));
    }
    #[test]
    fn remove_exact_peer_preserves_unrelated_sections_unchanged() {
        let old = conf();
        let plan = plan_change(&old, &grant('A',[10,66,0,2]), Change::Remove).unwrap();
        assert!(plan.changed());
        assert_eq!(plan.expected_peers().len(), 1);
        let rendered = std::str::from_utf8(&plan.bytes).unwrap();
        assert!(rendered.contains("PostUp = echo keep-this"));
        assert!(rendered.contains("# existing peer B"));
        assert!(rendered.contains(&key('B')));
        assert!(!rendered.contains(&key('A')));
    }
    #[test]
    fn revoke_missing_peer_is_safe_noop_only_when_key_and_ip_both_absent() {
        let old = conf();
        let plan = plan_change(&old, &grant('C',[10,66,0,4]), Change::Remove).unwrap();
        assert!(!plan.changed());
        assert_eq!(plan.bytes, old);
        assert_eq!(plan.expected_peers().len(),2);
        assert_eq!(plan_change(&old, &grant('A',[10,66,0,9]), Change::Remove).err(),
            Some(PlanError::PeerConflict));
        assert_eq!(plan_change(&old, &grant('C',[10,66,0,2]), Change::Remove).err(),
            Some(PlanError::PeerConflict));
    }
    #[test]
    fn conflicting_key_or_ip_is_not_overwritten_during_add() {
        let old=conf();
        assert_eq!(plan_change(&old,&grant('A',[10,66,0,10]),Change::Add).err(),
            Some(PlanError::PeerConflict));
        assert_eq!(plan_change(&old,&grant('C',[10,66,0,2]),Change::Add).err(),
            Some(PlanError::AddressConflict));
    }
    #[test]
    fn malformed_or_unsupported_old_config_is_not_modified() {
        let invalid = b"[Interface]\nPrivateKey=xxx\n[Peer]\nPublicKey=xxx\n";
        assert_eq!(plan_change(invalid,&grant('C',[10,66,0,4]),Change::Add).err(),
            Some(PlanError::InvalidConfig));
        assert_eq!(plan_change(&conf(),&grant('C',[1,2,3,4]),Change::Add).err(),
            Some(PlanError::InvalidGrant));
    }
    #[test]
    fn add_then_remove_round_trip_preserves_original_peers() {
        let old=conf();
        let added=plan_change(&old,&grant('C',[10,66,0,4]),Change::Add).unwrap();
        let removed=plan_change(&added.bytes,&grant('C',[10,66,0,4]),Change::Remove).unwrap();
        assert!(removed.changed());
        let original=parse_wg_quick_conf(&old).unwrap();
        assert_eq!(removed.expected_peers(), original);
        assert!(!std::str::from_utf8(&removed.bytes).unwrap().contains(&key('C')));
    }
    #[test]
    fn empty_interface_with_valid_header_allows_one_peer() {
        let old=b"[Interface]\nPrivateKey = NEVER_LOG\nAddress=10.66.0.1/24\n";
        let added=plan_change(old,&grant('A',[10,66,0,2]),Change::Add).unwrap();
        assert_eq!(added.expected_peers().len(),1);
        assert_eq!(parse_wg_quick_conf(&added.bytes).unwrap(), added.expected_peers);
    }
}

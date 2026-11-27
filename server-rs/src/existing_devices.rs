//! Devices carried forward from independently verified TradeChannel history.

#[cfg(target_os = "linux")]
use crate::{hex_sha256, lower_uuid};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::Ipv4Addr};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExistingHistory {
    pub(crate) snapshot_sha256: String,
    pub(crate) devices: BTreeMap<String, ExistingDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExistingDevice {
    pub(crate) request_id: String,
    pub(crate) request_digest: String,
    pub(crate) public_key: String,
    pub(crate) address: Ipv4Addr,
    pub(crate) origin: DeviceOrigin,
    pub(crate) state: ExistingDeviceState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DeviceOrigin {
    Deployment {
        plan_id: String,
    },
    SignedV2 {
        invite_id: String,
        authorization_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExistingDeviceState {
    Active,
    Revoking,
    Revoked,
}

#[cfg(target_os = "linux")]
impl ExistingDevice {
    pub(crate) fn valid(&self, device_id: &str) -> bool {
        lower_uuid(device_id)
            && lower_uuid(&self.request_id)
            && hex_sha256(&self.request_digest)
            && crate::wg_readonly::canonical_key(&self.public_key)
            && self.address.is_private()
            && match &self.origin {
                DeviceOrigin::Deployment { plan_id } => lower_uuid(plan_id),
                DeviceOrigin::SignedV2 {
                    invite_id,
                    authorization_sha256,
                } => lower_uuid(invite_id) && hex_sha256(authorization_sha256),
            }
    }
}

#[cfg(feature = "linux-fresh-provisioning")]
#[cfg(target_os = "linux")]
pub(crate) mod provisioning {
    use super::*;
    use crate::fresh_consume_gate::unique_json;
    use crate::{AddressPool, Invitation, InviteState, Ledger, Peer, Refusal};
    use ring::digest;
    use serde_json::Value;
    use std::collections::BTreeSet;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Snapshot {
        schema_version: u32,
        server_binding: Value,
        config_revision: u64,
        management_revision: u64,
        devices: Vec<Device>,
        invitations: Vec<OldInvitation>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Device {
        request: Value,
        address: Ipv4Addr,
        revoked: bool,
        origin: Origin,
    }

    #[derive(Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Origin {
        Deployment { plan_id: String },
        SignedV2 { authorization: String },
    }

    #[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
    enum OldState {
        Open,
        Consumed,
        Cancelled,
        Expired,
        Revoked,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OldInvitation {
        id: String,
        expires_unix: i64,
        state: OldState,
    }

    fn text<'a>(object: &'a Value, field: &str) -> Result<&'a str, Refusal> {
        object[field].as_str().ok_or(Refusal::InvalidRequest)
    }

    fn sha256(bytes: &[u8]) -> String {
        digest::digest(&digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The pin covers the operator's verified snapshot, including the original
    /// deployment and revocation decisions. Recheck every signed V2 registration
    /// against the independently pinned signer and the exact saved request.
    pub(crate) fn load(
        raw: &[u8],
        pin: &str,
        binding: &Value,
        management: &Value,
        pool: AddressPool,
        now: i64,
    ) -> Result<(Ledger, Vec<Peer>), Refusal> {
        let invalid = Refusal::InvalidRequest;
        if !hex_sha256(pin) || sha256(raw) != pin {
            return Err(invalid);
        }
        let snapshot: Snapshot =
            serde_json::from_value(unique_json(raw).ok_or(invalid)?).map_err(|_| invalid)?;
        if snapshot.schema_version != 1
            || snapshot.server_binding != *binding
            || snapshot.config_revision == 0
            || snapshot.management_revision == 0
            || snapshot.devices.is_empty()
            || snapshot.devices.len() > 4096
            || snapshot.invitations.len() >= 4096
        {
            return Err(invalid);
        }

        let mut ledger = Ledger::default();
        let mut original_states = BTreeMap::new();
        for old in snapshot.invitations {
            if !lower_uuid(&old.id)
                || old.expires_unix <= 0
                || original_states.insert(old.id.clone(), old.state).is_some()
            {
                return Err(invalid);
            }
            let state = match old.state {
                OldState::Open if now < old.expires_unix => return Err(invalid),
                OldState::Open | OldState::Expired => InviteState::Expired,
                OldState::Consumed | OldState::Cancelled | OldState::Revoked => {
                    InviteState::Cancelled
                }
            };
            ledger.invitations.insert(
                old.id,
                Invitation {
                    expires_unix: old.expires_unix,
                    state,
                },
            );
        }

        let peer_range = pool.range()?;
        let mut devices = BTreeMap::new();
        let mut signed_invites = BTreeSet::new();
        let mut initial_deployment = false;
        let mut peers = Vec::new();
        for item in snapshot.devices {
            let request_digest =
                crate::legacy_request_proof::client_digest(&item.request).map_err(|_| invalid)?;
            let request_id = text(&item.request, "RequestId")?;
            let device_id = text(&item.request, "DeviceId")?;
            let public_key = text(&item.request, "ClientPublicKey")?;
            if !peer_range.contains(&u32::from(item.address)) {
                return Err(invalid);
            }
            let origin = match item.origin {
                Origin::Deployment { plan_id } => {
                    if initial_deployment || !lower_uuid(&plan_id) {
                        return Err(invalid);
                    }
                    initial_deployment = true;
                    DeviceOrigin::Deployment { plan_id }
                }
                Origin::SignedV2 { authorization } => {
                    let signed = crate::legacy_signed::verify_jws(&authorization, management)
                        .map_err(|_| invalid)?;
                    let id = text(&signed, "InviteId")?;
                    let known_state = original_states.get(id);
                    let revision = signed["ConfigRevision"].as_u64().ok_or(invalid)?;
                    if !(known_state == Some(&OldState::Consumed)
                        || item.revoked && known_state == Some(&OldState::Revoked))
                        || !signed_invites.insert(id.to_owned())
                        || signed["SchemaVersion"] != 2
                        || signed["Kind"] != "TradeChannel.PairAuthorization"
                        || !signed["ExitEvidence"].is_object()
                        || !(1..=snapshot.config_revision).contains(&revision)
                        || signed["ServerBinding"] != *binding
                        || signed["RemoteOwnerId"] != binding["RemoteOwnerId"]
                        || signed["NodeId"] != binding["NodeId"]
                        || signed["RequestId"] != request_id
                        || signed["DeviceId"] != device_id
                        || signed["ClientPublicKey"] != public_key
                        || signed["ClientAddress"] != format!("{}/32", item.address)
                        || signed["RequestDigestAlgorithm"] != "TC-ClientRequest-v1"
                        || signed["RequestDigest"] != request_digest
                    {
                        return Err(invalid);
                    }
                    DeviceOrigin::SignedV2 {
                        invite_id: id.to_owned(),
                        authorization_sha256: sha256(authorization.as_bytes()),
                    }
                }
            };
            let state = if item.revoked {
                ledger.revoked_devices.insert(device_id.to_owned());
                ledger.revoked_keys.insert(public_key.to_owned());
                ExistingDeviceState::Revoked
            } else {
                peers.push(Peer {
                    public_key: public_key.to_owned(),
                    address: item.address,
                });
                ExistingDeviceState::Active
            };
            let device = ExistingDevice {
                request_id: request_id.to_owned(),
                request_digest,
                public_key: public_key.to_owned(),
                address: item.address,
                origin,
                state,
            };
            if devices.insert(device_id.to_owned(), device).is_some() {
                return Err(invalid);
            }
        }
        if original_states
            .iter()
            .any(|(id, state)| *state == OldState::Consumed && !signed_invites.contains(id))
        {
            return Err(invalid);
        }
        ledger.existing_history = Some(ExistingHistory {
            snapshot_sha256: pin.to_owned(),
            devices,
        });
        crate::ledger_disk::validate(&ledger).map_err(|_| invalid)?;
        Ok((ledger, peers))
    }
}

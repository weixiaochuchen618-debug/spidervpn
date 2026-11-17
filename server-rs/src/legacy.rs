//! SEC-01 stage S01: read-only audit of legacy tc-pair.py invites.json.
//!
//! This is NOT an authorization endpoint. JSON values are not trusted merely
//! because the Python service previously wrote them. In particular, legacy
//! Consumed records generally lack RequestDigest, and SignedAuthorization
//! must be cryptographically verified against the server identity before any
//! pending/consumed grant can be imported. Never synthesize missing digests.
//!
//! The API never returns the bearer Token, plaintext JWS, or private material.

use serde_json::Value;
use std::net::Ipv4Addr;

const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_INVITATIONS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditError {
    TooLarge,
    Malformed,
    WrongSchema,
    InvalidLedger,
    TooManyInvitations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyState {
    Open,
    Consumed,
    Cancelled,
    Expired,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Blocker {
    InvalidInviteId,
    InvalidRecord,
    MissingExpiresAt,
    MissingToken,
    InvalidIdentity,
    InvalidAddress,
    MissingRequestDigest,
    MissingRecipientDigest,
    MissingSignedAuthorization,
    NeedsSignatureVerification,
    NeedsLiveWireGuardReadback,
    UnknownState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Only validated lower-case UUIDs are copied here; malformed keys are
    /// redacted as a literal marker rather than returned to logs.
    pub invite_id: String,
    pub legacy_state: LegacyState,
    pub blockers: Vec<Blocker>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReport {
    pub rows: Vec<Row>,
}

impl AuditReport {
    /// No active legacy invitation is auto-importable. It MUST first pass
    /// cryptographic verification and a real WG peer inventory check.
    pub fn requires_manual_migration_gate(&self) -> bool {
        self.rows.iter().any(|row|
            !matches!(row.legacy_state, LegacyState::Cancelled | LegacyState::Expired)
                || !row.blockers.is_empty())
    }
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn valid_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
    })
}

fn valid_key(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 44 && b[43] == b'='
        && b[..43].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
}

fn valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn valid_client_address(s: &str) -> bool {
    let Some((address, mask)) = s.split_once('/') else { return false; };
    mask == "32"
        && address.parse::<Ipv4Addr>()
            .map(|ip| ip.to_string() == address && ip.is_private())
            .unwrap_or(false)
}

fn state_of(record: &Value) -> LegacyState {
    match str_field(record, "State") {
        Some("Open") => LegacyState::Open,
        Some("Consumed") => LegacyState::Consumed,
        Some("Cancelled") => LegacyState::Cancelled,
        Some("Expired") => LegacyState::Expired,
        _ => LegacyState::Unknown,
    }
}

fn audit_row(id: &str, record: &Value) -> Row {
    let mut blockers = Vec::new();
    let valid_id = valid_uuid(id);
    if !valid_id {
        blockers.push(Blocker::InvalidInviteId);
    }
    let safe_id = if valid_id { id.to_string() } else { "(invalid id)".to_string() };
    if !record.is_object() {
        blockers.push(Blocker::InvalidRecord);
        return Row {
            invite_id: safe_id,
            legacy_state: LegacyState::Unknown,
            blockers,
        };
    }

    let state = state_of(record);
    match state {
        LegacyState::Open => {
            if str_field(record, "ExpiresAtUtc").is_none() {
                blockers.push(Blocker::MissingExpiresAt);
            }
            if str_field(record, "Token").is_none() {
                blockers.push(Blocker::MissingToken);
            }
            // Open still needs server signature and expiry verification.
            blockers.push(Blocker::NeedsSignatureVerification);
        }
        LegacyState::Consumed => {
            let ids_ok = ["RequestId", "DeviceId"].iter().all(|name|
                str_field(record, name).map(valid_uuid).unwrap_or(false));
            let pubkey_ok = str_field(record, "ClientPublicKey")
                .map(valid_key).unwrap_or(false);
            if !ids_ok || !pubkey_ok {
                blockers.push(Blocker::InvalidIdentity);
            }
            if !str_field(record, "ClientAddress")
                .map(valid_client_address).unwrap_or(false)
            {
                blockers.push(Blocker::InvalidAddress);
            }
            if !str_field(record, "RequestDigest")
                .map(valid_digest).unwrap_or(false)
            {
                // The original Python consume path does not store it.
                // It MUST be recovered via a VERIFIED signed authorization,
                // never guessed or copied from an unauthenticated field.
                blockers.push(Blocker::MissingRequestDigest);
            }
            if !str_field(record, "RecipientJwkDigest")
                .map(valid_digest).unwrap_or(false)
            {
                blockers.push(Blocker::MissingRecipientDigest);
            }
            if !str_field(record, "SignedAuthorization")
                .map(|value| value.len() <= 131072 && value.split('.').count() == 3)
                .unwrap_or(false)
            {
                blockers.push(Blocker::MissingSignedAuthorization);
            }
            blockers.push(Blocker::NeedsSignatureVerification);
            blockers.push(Blocker::NeedsLiveWireGuardReadback);
        }
        LegacyState::Cancelled | LegacyState::Expired => {
            // Preserve the terminal state. Don't revive these as Open on
            // migration, even if their serialized fields look complete.
        }
        LegacyState::Unknown => blockers.push(Blocker::UnknownState),
    }

    blockers.sort();
    blockers.dedup();
    Row { invite_id: safe_id, legacy_state: state, blockers }
}

/// No I/O and no side effects. Reject unknown top-level schemas and oversized
/// records before attempting a migration. The report only describes hazards;
/// it never returns a token or trusts a signed grant without verification.
pub fn audit_legacy_json(bytes: &[u8]) -> Result<AuditReport, AuditError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(AuditError::TooLarge);
    }
    let root: Value = serde_json::from_slice(bytes).map_err(|_| AuditError::Malformed)?;
    if root.get("SchemaVersion").and_then(Value::as_u64) != Some(1) {
        return Err(AuditError::WrongSchema);
    }
    let records = root.get("Invites").and_then(Value::as_object)
        .ok_or(AuditError::InvalidLedger)?;
    if records.len() > MAX_INVITATIONS {
        return Err(AuditError::TooManyInvitations);
    }
    Ok(AuditReport {
        rows: records.iter().map(|(id, rec)| audit_row(id, rec)).collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "11111111-1111-4111-8111-111111111111";

    fn old_consumed() -> Value {
        json!({
            "State": "Consumed",
            "RequestId": "22222222-2222-4222-8222-222222222222",
            "DeviceId": "33333333-3333-4333-8333-333333333333",
            "ClientPublicKey": format!("{}=", "A".repeat(43)),
            "ClientAddress": "10.9.8.2/32",
            "RecipientJwkDigest": "a".repeat(64),
            "SignedAuthorization": "header.payload.signature",
            "Token": "MUST-NEVER-APPEAR-IN-AUDIT-RESULT"
        })
    }

    #[test]
    fn old_consumed_never_silently_gets_a_fake_request_digest() {
        let json = json!({"SchemaVersion": 1, "Invites": {"11111111-1111-4111-8111-111111111111": old_consumed()}});
        let report = audit_legacy_json(json.to_string().as_bytes()).unwrap();
        assert_eq!(report.rows.len(), 1);
        let row = &report.rows[0];
        assert_eq!(row.legacy_state, LegacyState::Consumed);
        assert_eq!(row.invite_id, ID);
        assert!(row.blockers.contains(&Blocker::MissingRequestDigest));
        assert!(row.blockers.contains(&Blocker::NeedsSignatureVerification));
        assert!(row.blockers.contains(&Blocker::NeedsLiveWireGuardReadback));
        assert!(report.requires_manual_migration_gate());
        assert!(!format!("{report:?}").contains("MUST-NEVER-APPEAR"));
    }

    #[test]
    fn consumed_digest_in_json_still_does_not_imply_cryptographic_trust() {
        let mut record = old_consumed();
        record["RequestDigest"] = json!("b".repeat(64));
        let json = json!({"SchemaVersion": 1, "Invites": {"11111111-1111-4111-8111-111111111111": record}});
        let report = audit_legacy_json(json.to_string().as_bytes()).unwrap();
        assert!(!report.rows[0].blockers.contains(&Blocker::MissingRequestDigest));
        assert!(report.rows[0].blockers.contains(&Blocker::NeedsSignatureVerification));
        assert!(report.rows[0].blockers.contains(&Blocker::NeedsLiveWireGuardReadback));
    }

    #[test]
    fn malformed_key_address_or_id_is_reported_without_secrets() {
        let mut record = old_consumed();
        record["ClientPublicKey"] = json!("😈");
        record["ClientAddress"] = json!("10.9.8.2/0");
        let json = json!({"SchemaVersion": 1, "Invites": {"../escape": record}});
        let report = audit_legacy_json(json.to_string().as_bytes()).unwrap();
        assert_eq!(report.rows[0].invite_id, "(invalid id)");
        assert!(report.rows[0].blockers.contains(&Blocker::InvalidInviteId));
        assert!(report.rows[0].blockers.contains(&Blocker::InvalidIdentity));
        assert!(report.rows[0].blockers.contains(&Blocker::InvalidAddress));
    }

    #[test]
    fn cancelled_stays_cancelled_and_unknown_state_never_becomes_open() {
        let j = json!({"SchemaVersion": 1, "Invites": {
            "11111111-1111-4111-8111-111111111111": {"State": "Cancelled"},
            "22222222-2222-4222-8222-222222222222": {"State": "Replayed"}
        }});
        let report = audit_legacy_json(j.to_string().as_bytes()).unwrap();
        assert!(report.rows.iter().any(|r| r.legacy_state == LegacyState::Cancelled));
        assert!(report.rows.iter().any(|r| r.blockers.contains(&Blocker::UnknownState)));
        assert!(report.requires_manual_migration_gate());
    }

    #[test]
    fn overlarge_invalid_json_and_wrong_schema_are_rejected() {
        assert_eq!(audit_legacy_json(&vec![b' '; MAX_FILE_BYTES + 1]), Err(AuditError::TooLarge));
        assert_eq!(audit_legacy_json(b"{malformed"), Err(AuditError::Malformed));
        assert_eq!(audit_legacy_json(br#"{"SchemaVersion":999,"Invites":{}}"#), Err(AuditError::WrongSchema));
        assert_eq!(audit_legacy_json(br#"{"SchemaVersion":1,"Invites":[]}"#), Err(AuditError::InvalidLedger));
    }

    #[test]
    fn empty_legacy_state_is_read_only_and_not_auto_migrated() {
        let json = br#"{"SchemaVersion":1,"Invites":{}}"#;
        let report = audit_legacy_json(json).unwrap();
        assert_eq!(report.rows.len(), 0);
        assert!(!report.requires_manual_migration_gate());
    }
}

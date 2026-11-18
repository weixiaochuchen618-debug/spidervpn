//! SEC-01 offline original-request evidence cross-check (NOT migration).
//!
//! The existing legacy Consumed record and the original signed PairRequest
//! MUST be independently supplied by a trusted offline operator. An old
//! signed management authorization does not sign RecipientJwkDigest, and a
//! client self-signature is NOT an authorization. Therefore an independently
//! authenticated recipient-JWK digest is mandatory: callers may NOT infer
//! it from the mutable legacy record or from the self-signed request.
//!
//! This module never creates Claims/Grant, reads or writes LedgerStore,
//! invokes WireGuard, or enables an HTTP pairing endpoint. A passing report
//! still needs separately audited revocation history and WG kernel/config
//! state before any future importer may be considered.

use crate::legacy_signed::{audit_signed_consumed, b64u, verify_jws, ProofError};
use crate::{hex_sha256, lower_uuid, wg_key};
use ring::digest::{digest, SHA256};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestProofError {
    OldGrant(ProofError),
    MissingOriginalRequest,
    InvalidOriginalRequest,
    InvalidRecipientAttestation,
    WrongRecipient,
    WrongRequestDigest,
    WrongIdentity,
    WrongServerBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestProofReport {
    invite_id: String,
    record_missing_digest: bool,
}
impl RequestProofReport {
    pub fn invite_id(&self) -> &str { &self.invite_id }
    pub fn record_missing_digest(&self) -> bool { self.record_missing_digest }
    /// No authenticated revoke history or live WireGuard snapshot is supplied.
    pub fn blocks_any_authorization_import(&self) -> bool { true }
}

fn text<'a>(object: &'a Value, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str).filter(|s| !s.is_empty())
}
fn sha256_lower(bytes: &[u8]) -> String {
    digest(&SHA256, bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn recipient_digest(recipient: &Value) -> Result<String, RequestProofError> {
    let o = recipient.as_object().ok_or(RequestProofError::InvalidOriginalRequest)?;
    if o.len() != 3 || text(recipient,"kty") != Some("RSA") {
        return Err(RequestProofError::InvalidOriginalRequest);
    }
    let n = text(recipient,"n").ok_or(RequestProofError::InvalidOriginalRequest)?;
    let e = text(recipient,"e").ok_or(RequestProofError::InvalidOriginalRequest)?;
    // Same canonical base64url bounds as the real RSA verifier. Neither
    // modulus nor exponent may be ambiguously encoded in the JWK digest.
    let modulus = b64u(n,1024).map_err(|_| RequestProofError::InvalidOriginalRequest)?;
    let exponent = b64u(e,8).map_err(|_| RequestProofError::InvalidOriginalRequest)?;
    if !(256..=1024).contains(&modulus.len()) || modulus[0] == 0
        || exponent.is_empty() || exponent[0] == 0 || (exponent[exponent.len()-1] & 1) == 0 {
        return Err(RequestProofError::InvalidOriginalRequest);
    }
    // Python tc-pair.py compact(value): sort_keys=True, ensure_ascii=True,
    // separators=(',',':'). An RSA JWK with exactly e/kty/n is all ASCII.
    let json = format!("{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}");
    Ok(sha256_lower(json.as_bytes()))
}
pub(crate) fn client_digest(inner: &Value) -> Result<String, RequestProofError> {
    if inner.get("SchemaVersion").and_then(Value::as_u64)!=Some(1)
        || text(inner,"Kind")!=Some("TradeChannel.ClientRequest")
        || inner.get("AddressFamilies") != Some(&serde_json::json!(["IPv4"])) {
        return Err(RequestProofError::InvalidOriginalRequest);
    }
    let request = text(inner,"RequestId").ok_or(RequestProofError::InvalidOriginalRequest)?;
    let device = text(inner,"DeviceId").ok_or(RequestProofError::InvalidOriginalRequest)?;
    let created = text(inner,"CreatedAtUtc").ok_or(RequestProofError::InvalidOriginalRequest)?;
    let wg = text(inner,"ClientPublicKey").ok_or(RequestProofError::InvalidOriginalRequest)?;
    if !lower_uuid(request) || !lower_uuid(device) || !wg_key(wg)
        || created.len() > 64 || !created.is_ascii() || created.chars().any(char::is_control)
    {
        return Err(RequestProofError::InvalidOriginalRequest);
    }
    // Exact Python TC-ClientRequest-v1: 7 lines, no terminal newline.
    let signed_bytes = format!("1\nTradeChannel.ClientRequest\n{request}\n{device}\n{created}\n{wg}\nIPv4");
    Ok(sha256_lower(signed_bytes.as_bytes()))
}

/// Offline double-signature audit. The trusted management JWK/server binding
/// and the independently pinned recipient JWK digest MUST be separate
/// authenticated operator inputs. Never pass the legacy record's digest as
/// the independent trust anchor.
///
/// A positive result only says the signed grant and the independently
/// attested client-signed request have matching identities/digests. It is
/// NEVER permission to add a peer, import a grant or revive a revoked device.
pub fn audit_original_signed_request(
    invite_id: &str,
    old_consumed: &Value,
    original_signed_request: &str,
    trusted_management_jwk: &Value,
    trusted_server_binding: &Value,
    independently_pinned_recipient_digest: &str,
) -> Result<RequestProofReport, RequestProofError> {
    let old_report = audit_signed_consumed(
        invite_id,old_consumed,trusted_management_jwk,trusted_server_binding,
    ).map_err(RequestProofError::OldGrant)?;
    if !hex_sha256(independently_pinned_recipient_digest) {
        return Err(RequestProofError::InvalidRecipientAttestation);
    }
    if original_signed_request.is_empty() {
        return Err(RequestProofError::MissingOriginalRequest);
    }
    if original_signed_request.len() > 131072 {
        return Err(RequestProofError::InvalidOriginalRequest);
    }
    let segments: Vec<&str> = original_signed_request.split('.').collect();
    if segments.len() != 3 {
        return Err(RequestProofError::InvalidOriginalRequest);
    }
    // RecipientJwk is read only as a candidate verifier. It cannot establish
    // its own identity; both separately pinned recipient digest and the
    // management-signed RequestDigest are checked below.
    let raw = b64u(segments[1],65536).map_err(|_|RequestProofError::InvalidOriginalRequest)?;
    let untrusted: Value = serde_json::from_slice(&raw)
        .map_err(|_|RequestProofError::InvalidOriginalRequest)?;
    let candidate = untrusted.get("RecipientJwk")
        .ok_or(RequestProofError::InvalidOriginalRequest)?;
    let body = verify_jws(original_signed_request,candidate)
        .map_err(|_|RequestProofError::InvalidOriginalRequest)?;
    let actual_recipient = recipient_digest(
        body.get("RecipientJwk").ok_or(RequestProofError::InvalidOriginalRequest)?,
    )?;
    if actual_recipient != independently_pinned_recipient_digest
        || text(old_consumed,"RecipientJwkDigest") != Some(actual_recipient.as_str()) {
        return Err(RequestProofError::WrongRecipient);
    }
    if body.get("SchemaVersion").and_then(Value::as_u64)!=Some(1)
        || text(&body,"Kind")!=Some("TradeChannel.PairRequest")
        || text(&body,"RequestDigestAlgorithm")!=Some("TC-ClientRequest-v1")
        || text(&body,"CreatedAtUtc").is_none()
        || text(&body,"DeviceName").is_none()
        || text(&body,"DeviceName").is_some_and(|s|
            s.chars().count()>64 || s.chars().any(char::is_control))
    {
        return Err(RequestProofError::InvalidOriginalRequest);
    }
    if text(&body,"InviteId")!=Some(invite_id) {
        return Err(RequestProofError::WrongIdentity);
    }
    if body.get("ServerBinding")!=Some(trusted_server_binding) {
        return Err(RequestProofError::WrongServerBinding);
    }
    let inner = body.get("ClientRequest")
        .ok_or(RequestProofError::InvalidOriginalRequest)?;
    let computed = client_digest(inner)?;
    if text(&body,"RequestDigest") != Some(computed.as_str()) {
        return Err(RequestProofError::WrongRequestDigest);
    }
    // Read management-signed grant AGAIN, do not grant authority to an old
    // record digest (which can be absent or modified).
    let signed_grant = text(old_consumed,"SignedAuthorization")
        .ok_or(RequestProofError::OldGrant(ProofError::Record))?;
    let grant = verify_jws(signed_grant,trusted_management_jwk)
        .map_err(RequestProofError::OldGrant)?;
    if text(&grant,"RequestDigest") != Some(computed.as_str()) {
        return Err(RequestProofError::WrongRequestDigest);
    }
    for (grant_name,inner_name) in [
        ("RequestId","RequestId"),("DeviceId","DeviceId"),
        ("ClientPublicKey","ClientPublicKey"),
    ] {
        if text(&grant,grant_name) != text(inner,inner_name)
            || text(&grant,grant_name) != text(old_consumed,grant_name) {
            return Err(RequestProofError::WrongIdentity);
        }
    }
    Ok(RequestProofReport {
        invite_id:invite_id.to_owned(),
        record_missing_digest:old_report.record_missing_digest(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/legacy_request_proof.json")).unwrap()
    }
    fn run(f:&Value)->Result<RequestProofReport,RequestProofError>{
        audit_original_signed_request(
            f["inviteId"].as_str().unwrap(),
            &f["legacyRecord"],
            f["originalSignedPairRequest"].as_str().unwrap(),
            &f["pinnedJwk"],
            &f["expectedServerBinding"],
            f["independentlyPinnedRecipientDigest"].as_str().unwrap(),
        )
    }
    #[test]
    fn independent_signed_pairrequest_and_grant_agree_but_cannot_authorize_import(){
        let f=fixture();
        let proof=run(&f).unwrap();
        assert_eq!(proof.invite_id(),f["inviteId"].as_str().unwrap());
        assert!(proof.record_missing_digest());
        assert!(proof.blocks_any_authorization_import());
        assert!(!format!("{proof:?}").contains("eyJ"));
    }
    #[test]
    fn original_request_missing_and_corrupted_signature_fail_closed(){
        let mut f=fixture();
        f["originalSignedPairRequest"]=json!("");
        assert_eq!(run(&f),Err(RequestProofError::MissingOriginalRequest));
        f=fixture();
        let signed=f["originalSignedPairRequest"].as_str().unwrap().to_owned();
        let mut p:Vec<String>=signed.split('.').map(str::to_owned).collect();
        let flip = if p[2].as_bytes()[12] == b'A' { "B" } else { "A" };
        p[2].replace_range(12..13, flip);
        f["originalSignedPairRequest"]=json!(p.join("."));
        assert_eq!(run(&f),Err(RequestProofError::InvalidOriginalRequest));
    }
    #[test]
    fn cannot_use_mutable_legacy_digest_as_independent_recipient_attestation(){
        let mut f=fixture();
        f["independentlyPinnedRecipientDigest"]=json!("f".repeat(64));
        assert_eq!(run(&f),Err(RequestProofError::WrongRecipient));
        f=fixture();
        f["legacyRecord"]["RecipientJwkDigest"]=json!("e".repeat(64));
        assert!(run(&f).is_err());
        f=fixture();
        f["independentlyPinnedRecipientDigest"]=json!("bad");
        assert_eq!(run(&f),Err(RequestProofError::InvalidRecipientAttestation));
    }
    #[test]
    fn wrong_management_identity_or_swapped_device_is_denied(){
        let mut f=fixture();
        f["pinnedJwk"]["n"]=json!("AQAB");
        assert!(run(&f).is_err());
        f=fixture();
        f["legacyRecord"]["DeviceId"]=json!("99999999-9999-4999-8999-999999999999");
        assert!(run(&f).is_err());
        f=fixture();
        f["expectedServerBinding"]["NodeId"]=json!("foreign-node");
        assert!(run(&f).is_err());
    }
    #[test]
    fn exact_clientrequest_digest_is_bound_to_management_signed_grant(){
        let f=fixture();
        let original=f["originalSignedPairRequest"].as_str().unwrap();
        let segments:Vec<_>=original.split('.').collect();
        let raw=b64u(segments[1],65536).unwrap();
        let payload:Value=serde_json::from_slice(&raw).unwrap();
        let inner=&payload["ClientRequest"];
        let computed=client_digest(inner).unwrap();
        assert_eq!(computed,payload["RequestDigest"].as_str().unwrap());
        let signed=&f["legacyRecord"]["SignedAuthorization"].as_str().unwrap();
        let grant=verify_jws(signed,&f["pinnedJwk"]).unwrap();
        assert_eq!(computed,grant["RequestDigest"].as_str().unwrap());
    }
}

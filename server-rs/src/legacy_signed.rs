//! SEC-01 read-only proof audit for legacy tc-pair.py Consumed records.
//!
//! A valid JWS is NOT a migration authorization: it cannot establish that
//! the device's original signed request, revocation state or live WireGuard
//! peer are trustworthy. No ledger writer or WG command is reachable here.
//! Pinned management JWK and expected binding MUST originate independently
//! from a trusted operator, never from the legacy JSON or JWS itself.

use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde_json::Value;
use std::net::Ipv4Addr;
use crate::{hex_sha256, lower_uuid, wg_key};

const MAX_JWS: usize = 131_072;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    TooLarge, Encoding, Algorithm, PinnedKey, Signature,
    WrongKind, Binding, Invitation, Record,
}

/// Deliberately NOT a Grant. Cannot call reserve/import or authorize a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofReport {
    invite_id: String,
    record_missing_digest: bool,
}
impl ProofReport {
    pub fn invite_id(&self) -> &str { &self.invite_id }
    pub fn record_missing_digest(&self) -> bool { self.record_missing_digest }
    pub fn requires_original_signed_request(&self) -> bool { true }
    pub fn requires_live_revocation_check(&self) -> bool { true }
}

/// Canonical, unpadded base64url. Reject nonzero final pad bits.
fn b64u(s: &str, max: usize) -> Result<Vec<u8>, ProofError> {
    if s.is_empty() || s.len() > max.saturating_mul(4)/3 + 8 {
        return Err(ProofError::TooLarge);
    }
    let mut out=Vec::with_capacity(s.len().saturating_mul(3)/4);
    let (mut acc, mut bits)=(0u32,0u32);
    for c in s.bytes() {
        let v=match c {
            b'A'..=b'Z' => c-b'A',
            b'a'..=b'z' => c-b'a'+26,
            b'0'..=b'9' => c-b'0'+52,
            b'-'=>62, b'_'=>63, _=>return Err(ProofError::Encoding),
        };
        acc=(acc<<6)|u32::from(v);
        bits+=6;
        if bits>=8 {
            bits-=8;
            out.push((acc>>bits) as u8);
            acc&=(1u32<<bits)-1;
            if out.len()>max {return Err(ProofError::TooLarge);}
        }
    }
    if bits==6 || acc!=0 {return Err(ProofError::Encoding);}
    Ok(out)
}

fn rsa_key(jwk:&Value)->Result<(Vec<u8>,Vec<u8>),ProofError>{
    if jwk.get("kty").and_then(Value::as_str)!=Some("RSA") {
        return Err(ProofError::PinnedKey);
    }
    let n=b64u(jwk.get("n").and_then(Value::as_str).ok_or(ProofError::PinnedKey)?,1024)
        .map_err(|_|ProofError::PinnedKey)?;
    let e=b64u(jwk.get("e").and_then(Value::as_str).ok_or(ProofError::PinnedKey)?,8)
        .map_err(|_|ProofError::PinnedKey)?;
    if !(256..=1024).contains(&n.len()) || n[0]==0 || e.is_empty()
        || e[0]==0 || (e[e.len()-1]&1)==0 || (e.len()==1 && e[0]<3) {
        return Err(ProofError::PinnedKey);
    }
    Ok((n,e))
}

/// Exact RS256 wire format produced by old Python sign_jws: alg+typ only.
fn verify_jws(jws:&str,pinned:&Value)->Result<Value,ProofError>{
    if jws.len()>MAX_JWS {return Err(ProofError::TooLarge);}
    let fields:Vec<_>=jws.split('.').collect();
    if fields.len()!=3 {return Err(ProofError::Encoding);}
    let header:Value=serde_json::from_slice(&b64u(fields[0],2048)?)
        .map_err(|_|ProofError::Encoding)?;
    let h=header.as_object().ok_or(ProofError::Algorithm)?;
    if h.len()!=2 || h.get("alg").and_then(Value::as_str)!=Some("RS256")
        || h.get("typ").and_then(Value::as_str)!=Some("JWT") {
        return Err(ProofError::Algorithm);
    }
    let signature=b64u(fields[2],1024)?;
    let (n,e)=rsa_key(pinned)?;
    let input=format!("{}.{}",fields[0],fields[1]);
    RsaPublicKeyComponents{n:&n,e:&e}
        .verify(&RSA_PKCS1_2048_8192_SHA256,input.as_bytes(),&signature)
        .map_err(|_|ProofError::Signature)?;
    let body:Value=serde_json::from_slice(&b64u(fields[1],65536)?)
        .map_err(|_|ProofError::Encoding)?;
    if !body.is_object() {return Err(ProofError::Encoding);}
    Ok(body)
}

fn text<'a>(v:&'a Value,name:&str)->Option<&'a str>{
    v.get(name).and_then(Value::as_str).filter(|s|!s.is_empty())
}
fn binding_is_valid(b:&Value)->bool{
    let Some(o)=b.as_object()else{return false;};
    o.len()==3 && ["RemoteOwnerId","NodeId","ServerPublicKey"].iter()
        .all(|k|text(b,k).is_some_and(|s|s.len()<=256 && !s.chars().any(char::is_control)))
}
fn private_host32(s:&str)->bool{
    let Some((ip,mask))=s.split_once('/')else{return false;};
    mask=="32" && ip.parse::<Ipv4Addr>().is_ok_and(|x|
        x.is_private() && x.to_string()==ip)
}

/// Verifies signed authorization against independent trusted identity, then
/// ties *all* identity/peer fields to the old record. Audit only; never import.
pub fn audit_signed_consumed(
    invite_id:&str, old:&Value, pinned_jwk:&Value, trusted_binding:&Value,
)->Result<ProofReport,ProofError>{
    if !lower_uuid(invite_id) {return Err(ProofError::Invitation);}
    if !binding_is_valid(trusted_binding) {return Err(ProofError::Binding);}
    if text(old,"State")!=Some("Consumed") {return Err(ProofError::Record);}
    let jws=text(old,"SignedAuthorization").ok_or(ProofError::Record)?;
    let body=verify_jws(jws,pinned_jwk)?;
    if body.get("SchemaVersion").and_then(Value::as_u64)!=Some(1)
        || text(&body,"Kind")!=Some("TradeChannel.PairAuthorization")
        || text(&body,"RequestDigestAlgorithm")!=Some("TC-ClientRequest-v1")
        || body.get("ConfigRevision").and_then(Value::as_u64)!=Some(1)
        || !body.get("ClientResponse").is_some_and(Value::is_object)
        || text(&body,"IssuedAtUtc").is_none()
        || text(&body,"ExpiresAtUtc").is_none() {
        return Err(ProofError::WrongKind);
    }
    if text(&body,"InviteId")!=Some(invite_id) {return Err(ProofError::Invitation);}
    if body.get("ServerBinding")!=Some(trusted_binding)
        || text(&body,"RemoteOwnerId")!=text(trusted_binding,"RemoteOwnerId")
        || text(&body,"NodeId")!=text(trusted_binding,"NodeId") {
        return Err(ProofError::Binding);
    }
    for f in ["RequestId","DeviceId","ClientPublicKey","ClientAddress"]{
        if text(&body,f)!=text(old,f) {return Err(ProofError::Record);}
    }
    if !["RequestId","DeviceId"].iter()
            .all(|f|text(&body,f).is_some_and(lower_uuid))
        || !text(&body,"ClientPublicKey").is_some_and(wg_key)
        || !text(&body,"ClientAddress").is_some_and(private_host32)
        || !text(&body,"RequestDigest").is_some_and(hex_sha256)
        || !text(old,"RecipientJwkDigest").is_some_and(hex_sha256) {
        return Err(ProofError::Record);
    }
    let old_digest=text(old,"RequestDigest");
    if old_digest.is_some() && old_digest!=text(&body,"RequestDigest") {
        return Err(ProofError::Record);
    }
    Ok(ProofReport{
        invite_id:invite_id.to_owned(),record_missing_digest:old_digest.is_none(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture()->Value{
        serde_json::from_str(include_str!("../tests/fixtures/legacy_signed_auth.json")).unwrap()
    }
    fn run(f:&Value)->Result<ProofReport,ProofError>{
        audit_signed_consumed(f["inviteId"].as_str().unwrap(),
            &f["legacyRecord"],&f["pinnedJwk"],&f["expectedServerBinding"])
    }
    #[test]
    fn external_rs256_signature_verifies_but_never_imports_or_recovers_peer(){
        let f=fixture(); let r=run(&f).unwrap();
        assert!(r.record_missing_digest());
        assert!(r.requires_original_signed_request());
        assert!(r.requires_live_revocation_check());
        assert!(!format!("{r:?}").contains("eyJhbGci"));
    }
    #[test]
    fn independent_dotnet_rs256_fixture_verifies_with_pinned_public_jwk(){
        let fixture:Value=serde_json::from_str(
            include_str!("../../tests/fixtures/pairing/dotnet-jwt-1.json")).unwrap();
        let payload=verify_jws(fixture["compact"].as_str().unwrap(),&fixture["publicJwk"]).unwrap();
        assert_eq!(payload["InviteId"],fixture["payload"]["InviteId"]);
    }
    #[test]
    fn tampered_signed_message_or_foreign_signer_is_denied(){
        let mut f=fixture();
        let original=f["legacyRecord"]["SignedAuthorization"].as_str().unwrap().to_owned();
        let mut p:Vec<String>=original.split('.').map(str::to_owned).collect();
        let replacement=if p[1].as_bytes()[12]==b'A'{"B"}else{"A"};
        p[1].replace_range(12..13,replacement);
        f["legacyRecord"]["SignedAuthorization"]=json!(p.join("."));
        assert!(run(&f).is_err());
        f=fixture(); f["pinnedJwk"]["n"]=json!("AQAB");
        assert_eq!(run(&f),Err(ProofError::PinnedKey));
        // A different but fully valid RSA signer must also fail; this is
        // distinct from simply rejecting a malformed pinned modulus.
        let foreign:Value=serde_json::from_str(
            include_str!("../../tests/fixtures/pairing/dotnet-jwt-1.json")).unwrap();
        f=fixture();
        f["pinnedJwk"]=foreign["publicJwk"].clone();
        assert_eq!(run(&f),Err(ProofError::Signature));
    }
    #[test]
    fn valid_signed_authorization_cannot_be_transplanted_to_other_legacy_device(){
        let mut f=fixture();
        f["legacyRecord"]["DeviceId"]=json!("99999999-9999-4999-8999-999999999999");
        assert_eq!(run(&f),Err(ProofError::Record));
        f=fixture();
        f["legacyRecord"]["RequestDigest"]=json!("c".repeat(64));
        assert_eq!(run(&f),Err(ProofError::Record));
    }
    #[test]
    fn wrong_server_or_state_never_approves_migration(){
        let mut f=fixture();
        f["expectedServerBinding"]["NodeId"]=json!("foreign-node");
        assert_eq!(run(&f),Err(ProofError::Binding));
        f=fixture();
        f["legacyRecord"]["State"]=json!("Revoked");
        assert_eq!(run(&f),Err(ProofError::Record));
    }
    #[test]
    fn none_algorithm_and_noncanonical_base64url_are_rejected(){
        let mut f=fixture();
        let j=f["legacyRecord"]["SignedAuthorization"].as_str().unwrap();
        let p:Vec<&str>=j.split('.').collect();
        f["legacyRecord"]["SignedAuthorization"]=json!(format!("e30.{}.{}",p[1],p[2]));
        assert_eq!(run(&f),Err(ProofError::Algorithm));
        assert_eq!(b64u("Zh",4),Err(ProofError::Encoding));
        assert_eq!(b64u("Zg=",4),Err(ProofError::Encoding));
        assert_eq!(b64u("A",4),Err(ProofError::Encoding));
    }
}

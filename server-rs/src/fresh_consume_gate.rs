//! SEC-01/02 fresh online invitation authentication, pre-integration only.
//! Not a legacy importer, HTTP listener, signing service or WG mutator.
//! Callers must supply independently authenticated invitation metadata and
//! bearer token, BOTH pinned management and server identity, and the SAME
//! exclusively locked current LedgerStore used by any future transaction.
//! A signed descriptor does NOT sign the bearer token or prove that a legacy
//! invitation was never revoked: never construct scope from unverified
//! invites.json, a client body, or a stale snapshot. No production caller yet.
#![cfg(all(target_os = "linux", feature = "linux-fresh-consume-gate"))]

use crate::http_one_request::{Method, ParsedRequest, MAX_BODY_BYTES};
use crate::ledger_disk::LedgerStore;
use crate::legacy_request_proof::{client_digest, recipient_digest};
use crate::legacy_signed::{b64u, verify_jws};
use crate::{hex_sha256, lower_uuid, wg_key, Claims, InviteState, Ledger, Peer};
use ring::{digest, hmac};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::fmt;

/// Deliberately not deserializable from network JSON and no Debug (token).
/// Fields are private: outside this module a scope comes only from an
/// independently pinned metadata record. This proves metadata/token binding,
/// NOT trusted revocation history or successful legacy migration.
pub struct TrustedOpenInvite<'a> {
    invite_id: &'a str,
    token: &'a str,
    signed_descriptor: &'a str,
    management_jwk: &'a Value,
    management_fingerprint: &'a str,
    server_binding: &'a Value,
    public_host: &'a str,
    port: u16,
    tls_der_pin: &'a str,
    wg_interface: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    NotFound, InviteNotFound, Forbidden, InvalidState, InviteExpired,
    InviteCancelled, InviteConsumed, Revoked, InvalidRequest,
    InvalidPairRequest, InviteMismatch, PairingMismatch,
}

/// Read-only protocol payload (not a proof of network authorization).
#[derive(PartialEq, Eq)]
pub struct OpenDescriptor<'a> {
    pub signed_descriptor: &'a str,
}
impl OpenDescriptor<'_> {
    pub fn legacy_data(&self) -> Value {
        serde_json::json!({
            "Status":"InvitationReady", "SignedDescriptor":self.signed_descriptor
        })
    }
}

/// A verified fresh request, not a Grant; no address allocated or reserved.
/// No public constructor/Deserialize/Clone. Never use it after unlocking
/// or changing ledger state. No authorization reply is created here.
pub struct VerifiedFreshConsume<'a> {
    claims: Claims,
    recipient_jwk: Value,
    // Borrow the locked store until this verified request is discarded.
    _store: &'a LedgerStore,
}
impl VerifiedFreshConsume<'_> {
    pub fn claims(&self) -> &Claims { &self.claims }
    pub fn recipient_jwk(&self) -> &Value { &self.recipient_jwk }
}

/// serde_json Value normally accepts duplicate keys (last wins). Reject
/// duplicates recursively before any field is used for a security decision.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(v).map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(Unique(item)) = a.next_element()? { v.push(item); }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut v = Map::new();
                while let Some((key, Unique(value))) = a.next_entry::<String, Unique>()? {
                    if v.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(Unique(Value::Object(v)))
            }
        }
        d.deserialize_any(V)
    }
}

fn unique_json(raw: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Unique>(raw).ok().map(|v| v.0)
}
fn text<'a>(v: &'a Value, field: &str) -> Option<&'a str> {
    v.get(field).and_then(Value::as_str).filter(|s| !s.is_empty())
}
fn version_kind(v: &Value, kind: &str) -> bool {
    v.get("SchemaVersion").and_then(Value::as_u64) == Some(1)
        && text(v, "Kind") == Some(kind)
}

fn jws_payload(s: &str) -> Option<Value> {
    if s.len() > MAX_BODY_BYTES { return None; }
    let mut p = s.split('.');
    let header = b64u(p.next()?, 2048).ok()?;
    let raw = b64u(p.next()?, 65536).ok()?;
    p.next()?;
    if p.next().is_some() { return None; }
    let h = unique_json(&header)?;
    if h.as_object()?.len() != 2 || text(&h,"alg") != Some("RS256")
        || text(&h,"typ") != Some("JWT") { return None; }
    let body = unique_json(&raw)?;
    body.as_object()?;
    Some(body)
}

fn verify_unique_jws(s: &str, key: &Value) -> Option<Value> {
    let unique = jws_payload(s)?;
    let verified = verify_jws(s, key).ok()?;
    (unique == verified).then_some(verified)
}

fn token_shape(token: &str) -> bool {
    token.len() == 43 && b64u(token, 32).is_ok_and(|v| v.len() == 32)
}
const METADATA_BEARER_DOMAIN: &[u8] = b"SpiderVPN pinned invitation metadata bearer v1";

/// Verified, read-only metadata record. No Debug/Deserialize or public fields;
/// the candidate bearer is borrowed, never stored in the metadata record.
/// This is a pre-integration verifier, not a production file loader.
pub struct AuthenticatedInviteMetadata<'a> {
    record: Value,
    bearer: &'a str,
}
impl AuthenticatedInviteMetadata<'_> {
    pub fn scope(&self) -> Result<TrustedOpenInvite<'_>,GateError> {
        let v=&self.record;
        let invalid=GateError::InvalidState;
        Ok(TrustedOpenInvite {
            invite_id:text(v,"InviteId").ok_or(invalid)?,
            token:self.bearer,
            signed_descriptor:text(v,"SignedDescriptor").ok_or(invalid)?,
            management_jwk:v.get("ManagementSigningPublicKey").ok_or(invalid)?,
            management_fingerprint:text(v,"ManagementFingerprint").ok_or(invalid)?,
            server_binding:v.get("ServerBinding").ok_or(invalid)?,
            public_host:text(v,"PublicHost").ok_or(invalid)?,
            port:v.get("Port").and_then(Value::as_u64)
                .and_then(|n|u16::try_from(n).ok()).filter(|n|*n!=0).ok_or(invalid)?,
            tls_der_pin:text(v,"TlsSha256").ok_or(invalid)?,
            wg_interface:text(v,"WgInterface").filter(|name|crate::wg_readonly::valid_interface(name)).ok_or(invalid)?,
        })
    }
}

fn decode_sha256_hex(s: &str) -> Option<Vec<u8>> {
    if !hex_sha256(s) { return None; }
    (0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).ok()).collect()
}

/// Verify the exact record bytes against an independently provisioned current
/// SHA256 pin (NOT a hash read beside the same untrusted record), then verify
/// the canonical high-entropy bearer against its pinned HMAC tag. The pin
/// is a trust input; do not derive it from HTTP, legacy invites.json, or this
/// record. No signer, pin registry, migration or trusted persistence here.
/// WgInterface names the independently provisioned local target; it is not
/// a legacy signed descriptor field or proof of the current kernel key.
/// All GET/fresh/retry calls still check the signed descriptor and current
/// locked ledger. Authentic metadata alone cannot establish revocation history.
pub fn verify_pinned_invite_metadata<'a>(raw: &[u8], pinned_sha256: &str,
    bearer: &'a str) -> Result<AuthenticatedInviteMetadata<'a>,GateError>
{
    let invalid=GateError::InvalidState;
    if raw.is_empty() || raw.len()>MAX_BODY_BYTES { return Err(invalid); }
    let pin=decode_sha256_hex(pinned_sha256).ok_or(invalid)?;
    // The record digest is a public integrity pin, not the secret bearer.
    if digest::digest(&digest::SHA256,raw).as_ref()!=pin.as_slice() {
        return Err(invalid);
    }
    let record=unique_json(raw).ok_or(invalid)?;
    if !version_kind(&record,"SpiderVPN.InviteMetadata")
        || record.as_object().is_none_or(|o|o.len()!=12) {
        return Err(invalid);
    }
    let tag=decode_sha256_hex(text(&record,"BearerHmacSha256").ok_or(invalid)?)
        .ok_or(invalid)?;
    if !token_shape(bearer)
        || hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256,bearer.as_bytes()),
            METADATA_BEARER_DOMAIN,&tag).is_err() {
        return Err(GateError::Forbidden);
    }
    let metadata=AuthenticatedInviteMetadata { record,bearer };
    let scope=metadata.scope()?;
    if !lower_uuid(scope.invite_id) || !hex_sha256(scope.tls_der_pin)
        || !valid_binding(scope.server_binding)
        || management_fingerprint(scope.management_jwk).as_deref()!=Some(scope.management_fingerprint) {
        return Err(invalid);
    }
    Ok(metadata)
}

fn token_matches(expected: &str, given: &str) -> bool {
    if !token_shape(expected) || !token_shape(given) { return false; }
    // ring's constant-time MAC verification, with the same fixed domain
    // message for each token key. Never log either token or compare via ==.
    let domain = b"SpiderVPN fresh invitation bearer verification v1";
    let provided = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, given.as_bytes()), domain);
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, expected.as_bytes()),
        domain, provided.as_ref()).is_ok()
}

/// UTC legacy time, canonical full seconds or up to six fractional digits.
/// Parse for clocks only; the original signed string remains in the digest.
fn utc_seconds(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b.len() > 27 || !s.is_ascii() || b.last() != Some(&b'Z')
        || b[4] != b'-' || b[7] != b'-' || b[10] != b'T'
        || b[13] != b':' || b[16] != b':' { return None; }
    if b.len() != 20 && (b[19] != b'.' || b.len() < 22
        || !b[20..b.len()-1].iter().all(u8::is_ascii_digit)) { return None; }
    let part = |a: usize, z: usize| -> Option<i64> {
        b[a..z].iter().all(u8::is_ascii_digit).then(|| s[a..z].parse().ok()).flatten()
    };
    let (y,m,d,h,min,sec) = (part(0,4)?,part(5,7)?,part(8,10)?,
        part(11,13)?,part(14,16)?,part(17,19)?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m)
        || h > 23 || min > 59 || sec > 59 { return None; }
    let leap = |n: i64| n%4==0 && (n%100!=0 || n%400==0);
    let months = [31, if leap(y) {29} else {28},31,30,31,30,31,31,30,31,30,31];
    if d < 1 || d > months[(m-1) as usize] { return None; }
    let leaps_through = |n: i64| n/4 - n/100 + n/400;
    let days = 365*(y-1970) + leaps_through(y-1)-leaps_through(1969)
        + months[..(m-1) as usize].iter().sum::<i64>() + d-1;
    Some(days*86400 + h*3600 + min*60 + sec)
}

fn canonical_wg_key(s: &str) -> bool {
    if !wg_key(s) { return false; }
    let url = s[..43].replace('+', "-").replace('/', "_");
    b64u(&url,32).is_ok_and(|b| b.len()==32 && b.iter().any(|x| *x!=0))
}
fn valid_binding(b: &Value) -> bool {
    b.as_object().is_some_and(|o| o.len()==3)
        && text(b,"RemoteOwnerId").is_some_and(lower_uuid)
        && text(b,"NodeId").is_some_and(lower_uuid)
        && text(b,"ServerPublicKey").is_some_and(canonical_wg_key)
}

fn management_fingerprint(jwk: &Value) -> Option<String> {
    let hex=recipient_digest(jwk).ok()?;
    let raw:Vec<u8>=(0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2],16)).collect::<Result<_,_>>().ok()?;
    let alphabet=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut acc,mut bits)=(0u32,0);
    let mut out=String::from("SHA256:");
    for byte in raw {
        acc=(acc<<8)|u32::from(byte);
        bits+=8;
        while bits>=6 {
            bits-=6;
            out.push(char::from(alphabet[((acc>>bits)&63) as usize]));
        }
        acc&=(1<<bits)-1;
    }
    if bits>0 {out.push(char::from(alphabet[((acc<<(6-bits))&63) as usize]));}
    Some(out)
}

fn check_descriptor(scope: &TrustedOpenInvite<'_>, expires: i64, now: i64)
    -> Result<(), GateError>
{
    let invalid = GateError::InvalidState;
    let desc = verify_unique_jws(scope.signed_descriptor, scope.management_jwk)
        .ok_or(invalid)?;
    let exp = text(&desc,"ExpiresAtUtc").and_then(utc_seconds).ok_or(invalid)?;
    let retry = text(&desc,"RetryUntilUtc").and_then(utc_seconds).ok_or(invalid)?;
    if !version_kind(&desc,"TradeChannel.OnlineInvite")
        || text(&desc,"InviteId")!=Some(scope.invite_id)
        || text(&desc,"PublicHost")!=Some(scope.public_host)
        || desc.get("Port").and_then(Value::as_u64)!=Some(u64::from(scope.port))
        || text(&desc,"TlsSha256")!=Some(scope.tls_der_pin)
        || text(&desc,"ManagementFingerprint")!=Some(scope.management_fingerprint)
        || desc.get("ManagementSigningPublicKey")!=Some(scope.management_jwk)
        || exp!=expires || retry!=exp.checked_add(120).ok_or(invalid)?
    { return Err(invalid); }
    let invite = verify_unique_jws(text(&desc,"Invite").ok_or(invalid)?,scope.management_jwk)
        .ok_or(invalid)?;
    let issued = text(&invite,"IssuedAtUtc").and_then(utc_seconds).ok_or(invalid)?;
    if !version_kind(&invite,"TradeChannel.PairInvite")
        || text(&invite,"InviteId")!=Some(scope.invite_id)
        || invite.get("ServerBinding")!=Some(scope.server_binding)
        || invite.get("ManagementSigningPublicKey")!=Some(scope.management_jwk)
        || ["RemoteOwnerId","NodeId","ServerPublicKey"].iter().any(|f|
            text(&invite,f)!=text(scope.server_binding,f))
        || text(&invite,"ExpiresAtUtc").and_then(utc_seconds)!=Some(exp)
        || issued>=exp || issued>now.checked_add(300).ok_or(invalid)?
        || text(&invite,"PublicEndpoint")!=Some(format!("{}:{}",scope.public_host,scope.port).as_str())
        || !invite.get("Capabilities").is_some_and(Value::is_object)
    { return Err(invalid); }
    // The existing descriptor signature binds host/port/pin separately from
    // the trusted binding; do not infer bearer ownership from the signature.
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation { Get, Fresh, Retry }

fn common<'a>(store: &'a LedgerStore, scope: &TrustedOpenInvite<'_>,
    request: &ParsedRequest, now: i64, operation: Operation) -> Result<&'a Ledger, GateError>
{
    if !lower_uuid(scope.invite_id) || !token_shape(scope.token)
        || !hex_sha256(scope.tls_der_pin) || !valid_binding(scope.server_binding)
        || scope.public_host.is_empty() || scope.public_host.len()>253
        || !scope.public_host.bytes().all(|b| b.is_ascii_graphic())
        || !crate::wg_readonly::valid_interface(scope.wg_interface)
        || scope.port==0 || now<0
        || management_fingerprint(scope.management_jwk).as_deref()!=Some(scope.management_fingerprint)
    { return Err(GateError::InvalidState); }
    let consume = operation != Operation::Get;
    let route = format!("/v1/invitations/{}{}",scope.invite_id,
        if consume {"/consume"} else {""});
    if request.target!=route || request.method!=if consume {Method::Post} else {Method::Get}
    { return Err(GateError::NotFound); }
    if request.host != format!("{}:{}", scope.public_host, scope.port) {
        return Err(GateError::InviteMismatch);
    }
    let ledger=store.view().map_err(|_|GateError::InvalidState)?;
    let inv=ledger.invitations.get(scope.invite_id).ok_or(GateError::InviteNotFound)?;
    let presented=request.authorization.as_deref().and_then(|a|a.strip_prefix("Bearer "))
        .ok_or(GateError::Forbidden)?;
    if !token_matches(scope.token,presented) { return Err(GateError::Forbidden); }
    match inv.state {
        InviteState::Open if operation == Operation::Retry => return Err(GateError::InvalidState),
        InviteState::Open if now>=inv.expires_unix => return Err(GateError::InviteExpired),
        InviteState::Open => {},
        InviteState::Cancelled => return Err(GateError::InviteCancelled),
        InviteState::Expired => return Err(GateError::InviteExpired),
        InviteState::Revoking(_) | InviteState::Revoked(_) => return Err(GateError::Revoked),
        InviteState::Consumed(_) if operation == Operation::Retry => {
            // Exclusive upper bound: never extend the signed legacy window.
            if now >= inv.expires_unix.checked_add(120).ok_or(GateError::InvalidState)? {
                return Err(GateError::InviteExpired);
            }
        }
        InviteState::Consumed(_) => return Err(GateError::InviteConsumed),
        InviteState::Pending(_) => return Err(GateError::InvalidState),
    }
    check_descriptor(scope,inv.expires_unix,now)?;
    Ok(ledger)
}

/// Authenticated read-only GET for an independently trusted OPEN invitation.
/// Consumed/retry and migration remain deliberately unavailable here.
pub fn read_open_descriptor<'a>(store: &LedgerStore, scope: &TrustedOpenInvite<'a>,
    request: &ParsedRequest, now: i64) -> Result<OpenDescriptor<'a>,GateError>
{
    common(store,scope,request,now,Operation::Get)?;
    if !request.body.is_empty() { return Err(GateError::InvalidRequest); }
    Ok(OpenDescriptor { signed_descriptor:scope.signed_descriptor })
}

/// Exact POST consume envelope, bearer + independently signed invitation +
/// possession of recipient private key + request digest/binding + durable
/// OPEN/nonrevoked state. No persistence/write/peer mutation here.
pub fn prepare_fresh_consume<'a>(store: &'a LedgerStore, scope: &TrustedOpenInvite<'_>,
    request: &ParsedRequest, now: i64) -> Result<VerifiedFreshConsume<'a>,GateError>
{
    let ledger=common(store,scope,request,now,Operation::Fresh)?;
    let (claims, recipient_jwk)=verify_consume_claims(scope,request,now)?;
    check_history(ledger,&claims)?;
    // No address allocation is attempted without real peer inventory.
    // A future transaction must recheck policy under this same lock before
    // persisting Pending; a verified self-signature is not an approval.
    Ok(VerifiedFreshConsume { claims,recipient_jwk,_store:store })
}

fn verify_consume_claims(scope: &TrustedOpenInvite<'_>, request: &ParsedRequest,
    now: i64) -> Result<(Claims, Value),GateError>
{
    if request.body.is_empty() || request.body.len()>MAX_BODY_BYTES {
        return Err(GateError::InvalidRequest);
    }
    let env=unique_json(&request.body).ok_or(GateError::InvalidRequest)?;
    if env.as_object().is_none_or(|o|o.len()!=1) { return Err(GateError::InvalidRequest); }
    let compact=text(&env,"PairRequest").ok_or(GateError::InvalidRequest)?;
    let invalid=GateError::InvalidPairRequest;
    let unsigned=jws_payload(compact).ok_or(invalid)?;
    let recipient=unsigned.get("RecipientJwk").ok_or(invalid)?;
    let body=verify_unique_jws(compact,recipient).ok_or(invalid)?;
    let recipient=body.get("RecipientJwk").ok_or(invalid)?;
    let recipient_jwk_digest=recipient_digest(recipient).map_err(|_|invalid)?;
    if !version_kind(&body,"TradeChannel.PairRequest")
        || body.as_object().is_none_or(|o|o.len()!=10)
        || text(&body,"RequestDigestAlgorithm")!=Some("TC-ClientRequest-v1")
        || !text(&body,"DeviceName").is_some_and(|s|s.chars().count()<=64
            && s.trim()==s && !s.chars().any(char::is_control))
    { return Err(invalid); }
    if text(&body,"InviteId")!=Some(scope.invite_id)
        || body.get("ServerBinding")!=Some(scope.server_binding)
    { return Err(GateError::InviteMismatch); }
    let inner=body.get("ClientRequest").ok_or(invalid)?;
    if inner.as_object().is_none_or(|o|o.len()!=7) { return Err(invalid); }
    let latest=now.checked_add(300).ok_or(invalid)?;
    for obj in [&body,inner] {
        if text(obj,"CreatedAtUtc").and_then(utc_seconds).is_none_or(|t|t>latest) {
            return Err(invalid);
        }
    }
    let computed=client_digest(inner).map_err(|_|invalid)?;
    if text(&body,"RequestDigest")!=Some(computed.as_str()) {
        return Err(GateError::PairingMismatch);
    }
    let key=text(inner,"ClientPublicKey").filter(|s|canonical_wg_key(s)).ok_or(invalid)?;
    let claims=Claims {
        invite_id:scope.invite_id.to_owned(),
        request_id:text(inner,"RequestId").ok_or(invalid)?.to_owned(),
        device_id:text(inner,"DeviceId").ok_or(invalid)?.to_owned(),
        public_key:key.to_owned(),request_digest:computed,recipient_jwk_digest,
    };
    if !crate::claims_valid(&claims) { return Err(invalid); }
    Ok((claims,recipient.clone()))
}

fn check_history(ledger: &Ledger, claims: &Claims) -> Result<(),GateError> {
    // Old shape-only validation admitted noncanonical aliases, including
    // grants in Revoking before they have durable tombstones. Fail closed
    // until that history can be independently reconciled.
    if ledger.revoked_keys.iter().any(|k| !canonical_wg_key(k))
        || ledger.invitations.values().any(|inv| match &inv.state {
            InviteState::Pending(g) | InviteState::Consumed(g)
            | InviteState::Revoking(g) | InviteState::Revoked(g) =>
                !canonical_wg_key(&g.claims.public_key),
            _ => false,
        })
    {
        return Err(GateError::InvalidState);
    }
    if ledger.denied_identity(claims) { return Err(GateError::Revoked); }
    Ok(())
}

/// Read-only, lock-borrowing retry evidence, NOT a new Grant or response.
/// Cannot be constructed by network deserialization or used to add a peer.
pub struct VerifiedConsumedRetry<'a> {
    claims: Claims,
    _store: &'a LedgerStore,
}
impl VerifiedConsumedRetry<'_> {
    pub fn claims(&self) -> &Claims { &self.claims }
}

/// Verify the local selector against the independently pinned invitation
/// metadata, not merely its syntax. The actual kernel server public key
/// and protected config identity must still be independently verified
/// before production integration; a name is not proof of key ownership.
fn check_retry_interface(scope: &TrustedOpenInvite<'_>, interface: &str)
    -> Result<(),GateError>
{
    if !crate::wg_readonly::valid_interface(interface) || interface!=scope.wg_interface {
        return Err(GateError::InvalidState);
    }
    Ok(())
}

/// Read-only retry under the CURRENT locked store. The local service
/// selector must exactly match independently pinned WgInterface metadata.
/// The existing adapter reads kernel inventory, protected wg.conf and kernel
/// inventory again, rejecting disagreements. No public API accepts cached
/// or projected rows. Kernel/config server-key identity and writer exclusion
/// are still integration gates. No production caller or reply here.
pub fn prepare_consumed_retry<'a>(store: &'a LedgerStore, scope: &TrustedOpenInvite<'_>,
    request: &ParsedRequest, interface: &str) -> Result<VerifiedConsumedRetry<'a>,GateError>
{
    check_retry_interface(scope,interface)?;
    prepare_retry_with_observation(store,scope,request,system_utc_seconds,||
        crate::wg_conf_audit::read_verified_snapshot(interface)
            .map_err(|_|GateError::InvalidState))
}

fn system_utc_seconds() -> Result<i64,GateError> {
    let seconds=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|_|GateError::InvalidState)?.as_secs();
    i64::try_from(seconds).map_err(|_|GateError::InvalidState)
}

/// Private injection seam for deterministic tests. In the public path
/// only the concrete system reader and clock are reachable.
fn prepare_retry_with_observation<'a>(store: &'a LedgerStore, scope: &TrustedOpenInvite<'_>,
    request: &ParsedRequest, mut clock: impl FnMut() -> Result<i64,GateError>,
    observe: impl FnOnce() -> Result<Vec<Peer>,GateError>)
    -> Result<VerifiedConsumedRetry<'a>,GateError>
{
    let now=clock()?;
    let generation=store.generation().map_err(|_|GateError::InvalidState)?;
    let ledger=common(store,scope,request,now,Operation::Retry)?;
    let (claims,_)=verify_consume_claims(scope,request,now)?;
    check_history(ledger,&claims)?;
    // Authenticate and reject mismatched consumed claims before privileged IO.
    let Some(InviteState::Consumed(grant))=ledger.state(scope.invite_id) else {
        return Err(GateError::InvalidState);
    };
    if grant.claims!=claims { return Err(GateError::PairingMismatch); }
    let peers=observe()?;
    let after=clock()?;
    // Never extend the signed retry window while reading a slow snapshot,
    // and do not accept a backward clock jump during this operation.
    if after<now || store.generation().map_err(|_|GateError::InvalidState)?!=generation {
        return Err(GateError::InvalidState);
    }
    let ledger=common(store,scope,request,after,Operation::Retry)?;
    // Reject ambiguous keys and any duplicate inventory row or address,
    // even if unrelated to the requested peer.
    let mut keys=std::collections::BTreeSet::new();
    let mut addresses=std::collections::BTreeSet::new();
    if peers.iter().any(|p| !canonical_wg_key(&p.public_key)
        || !p.address.is_private() || !keys.insert(&p.public_key)
        || !addresses.insert(p.address)) {
        return Err(GateError::InvalidState);
    }
    ledger.retry(&claims,Some(&peers)).map_err(|err| match err {
        crate::Refusal::ConsumedByAnotherRequest => GateError::PairingMismatch,
        crate::Refusal::Revoked | crate::Refusal::RevokedIdentity => GateError::Revoked,
        _ => GateError::InvalidState,
    })?;
    Ok(VerifiedConsumedRetry { claims,_store:store })
}

#[cfg(test)]
mod tests;

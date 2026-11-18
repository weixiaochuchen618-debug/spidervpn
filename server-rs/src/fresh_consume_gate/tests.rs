use super::*;
use crate::http_one_request::read_one_request;
use crate::ledger_disk::bootstrap_for_test;
use crate::{AddressPool, Peer};
use serde_json::json;
use std::fs::{self, DirBuilder};
use std::io::{Cursor, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const INV: &str = "11111111-1111-4111-8111-111111111111";
const DEV: &str = "22222222-2222-4222-8222-222222222222";
const REQ: &str = "33333333-3333-4333-8333-333333333333";
const OTHER_INV: &str = "44444444-4444-4444-8444-444444444444";
const NOW: &str = "2026-11-18T07:00:00Z";
const EXP: &str = "2026-11-18T08:00:00Z";
const RETRY: &str = "2026-11-18T08:02:00Z";
const HOST: &str = "pair.example.test";
const PORT: u16 = 18443;

fn encode(raw: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let (mut acc,mut bits) = (0u32,0);
    for x in raw {
        acc = (acc<<8) | u32::from(*x);
        bits+=8;
        while bits>=6 {
            bits-=6;
            out.push(char::from(alphabet[((acc>>bits)&63) as usize]));
        }
        acc&=(1<<bits)-1;
    }
    if bits>0 {out.push(char::from(alphabet[((acc<<(6-bits))&63) as usize]));}
    out
}
fn wg(byte: u8) -> String { encode(&[byte;32]).replace('-',"+").replace('_',"/")+"=" }

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static ID:AtomicUsize=AtomicUsize::new(0);
        let path=std::env::temp_dir().join(format!("spider-fresh-gate-{}-{}",
            std::process::id(),ID.fetch_add(1,Ordering::Relaxed)));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}

struct TestKey { path:PathBuf, jwk:Value }
impl TestKey {
    fn generate(dir:&Path,name:&str)->Self {
        let path=dir.join(name);
        let status=Command::new("openssl").args(["genpkey","-algorithm","RSA",
            "-pkeyopt","rsa_keygen_bits:2048","-out"]).arg(&path)
            .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert!(status.success());
        let modulus=Command::new("openssl").args(["rsa","-in"]).arg(&path)
            .args(["-modulus","-noout"]).output().unwrap();
        assert!(modulus.status.success());
        let hex=String::from_utf8(modulus.stdout).unwrap();
        let hex=hex.trim().strip_prefix("Modulus=").unwrap();
        let bytes:Vec<u8>=(0..hex.len()).step_by(2)
            .map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
        Self{path,jwk:json!({"kty":"RSA","e":"AQAB","n":encode(&bytes)})}
    }
    fn sign_raw(&self,header:&[u8],body:&[u8])->String {
        let input=format!("{}.{}",encode(header),encode(body));
        let mut child=Command::new("openssl").args(["dgst","-sha256","-sign"])
            .arg(&self.path).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let output=child.wait_with_output().unwrap();
        assert!(output.status.success());
        format!("{input}.{}",encode(&output.stdout))
    }
    fn sign(&self,body:&Value)->String {
        self.sign_raw(br#"{"alg":"RS256","typ":"JWT"}"#,
            &serde_json::to_vec(body).unwrap())
    }
}

struct Fixture {
    store:LedgerStore,
    management:TestKey,
    recipient:TestKey,
    binding:Value,
    token:String,
    pin:String,
    fingerprint:String,
    body:Value,
    invite:Value,
    descriptor:Value,
    signed_descriptor:String,
    _dir:Directory,
}
impl Fixture {
    fn new()->Self {
        let dir=Directory::new();
        bootstrap_for_test(&dir.0).unwrap();
        let mut store=LedgerStore::open_existing(&dir.0,Duration::from_secs(1)).unwrap();
        store.update(|l|l.insert_open(INV,utc_seconds(EXP).unwrap())).unwrap();
        let management=TestKey::generate(&dir.0,"management.pem");
        let recipient=TestKey::generate(&dir.0,"recipient.pem");
        let binding=json!({"RemoteOwnerId":"55555555-5555-4555-8555-555555555555",
            "NodeId":"66666666-6666-4666-8666-666666666666","ServerPublicKey":wg(2)});
        let token=encode(&[77;32]);
        let pin="a".repeat(64);
        let fingerprint=management_fingerprint(&management.jwk).unwrap();
        let invite=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairInvite","InviteId":INV,
            "RemoteOwnerId":binding["RemoteOwnerId"],"NodeId":binding["NodeId"],
            "ServerPublicKey":binding["ServerPublicKey"],"ServerBinding":binding,
            "ManagementSigningPublicKey":management.jwk,"IssuedAtUtc":NOW,"ExpiresAtUtc":EXP,
            "PublicEndpoint":format!("{HOST}:{PORT}"),"DeviceName":"交易电脑",
            "Capabilities":{"PairingVersion":1,"ManagementApiVersion":2,"Transport":"udp"}});
        let descriptor=json!({"SchemaVersion":1,"Kind":"TradeChannel.OnlineInvite",
            "InviteId":INV,"Invite":management.sign(&invite),"PublicHost":HOST,"Port":PORT,
            "TlsSha256":pin,"ManagementFingerprint":fingerprint,
            "ManagementSigningPublicKey":management.jwk,"ExpiresAtUtc":EXP,"RetryUntilUtc":RETRY});
        let signed_descriptor=management.sign(&descriptor);
        let inner=json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientRequest",
            "RequestId":REQ,"DeviceId":DEV,"CreatedAtUtc":"2026-11-18T07:00:00.123456Z",
            "ClientPublicKey":wg(1),"AddressFamilies":["IPv4"]});
        let body=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest","InviteId":INV,
            "ServerBinding":binding,"ClientRequest":inner,"DeviceName":"交易电脑",
            "RecipientJwk":recipient.jwk,"RequestDigest":client_digest(&inner).unwrap(),
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":NOW});
        Self{store,management,recipient,binding,token,pin,fingerprint,body,invite,descriptor,
            signed_descriptor,_dir:dir}
    }
    fn scope(&self)->TrustedOpenInvite<'_> {
        TrustedOpenInvite{invite_id:INV,token:&self.token,signed_descriptor:&self.signed_descriptor,
            management_jwk:&self.management.jwk,management_fingerprint:&self.fingerprint,
            server_binding:&self.binding,public_host:HOST,port:PORT,tls_der_pin:&self.pin}
    }
    fn request(&self,compact:&str)->ParsedRequest {
        let body=serde_json::to_vec(&json!({"PairRequest":compact})).unwrap();
        let header=format!("POST /v1/invitations/{INV}/consume HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",self.token,body.len());
        let mut wire=header.into_bytes();
        wire.extend(body);
        read_one_request(&mut Cursor::new(wire)).unwrap()
    }
    fn get(&self)->ParsedRequest {
        read_one_request(&mut Cursor::new(format!("GET /v1/invitations/{INV} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nAuthorization: Bearer {}\r\n\r\n",self.token))).unwrap()
    }
    fn post(&self)->ParsedRequest {self.request(&self.recipient.sign(&self.body))}
    fn error(&self,req:&ParsedRequest)->Option<GateError> {
        prepare_fresh_consume(&self.store,&self.scope(),req,utc_seconds(NOW).unwrap()).err()
    }
}

#[test]
fn signed_get_and_fresh_post_match_legacy_protocol_without_writing_ledger() {
    let f=Fixture::new();
    let generation=f.store.generation().unwrap();
    let descriptor=read_open_descriptor(&f.store,&f.scope(),&f.get(),utc_seconds(NOW).unwrap()).unwrap();
    assert_eq!(descriptor.legacy_data(),json!({"Status":"InvitationReady","SignedDescriptor":f.signed_descriptor}));
    let prepared=prepare_fresh_consume(&f.store,&f.scope(),&f.post(),utc_seconds(NOW).unwrap()).unwrap();
    assert_eq!(prepared.claims().request_id,REQ);
    assert_eq!(prepared.claims().device_id,DEV);
    assert_eq!(prepared.claims().public_key,wg(1));
    assert_eq!(prepared.claims().request_digest,f.body["RequestDigest"].as_str().unwrap());
    assert_eq!(prepared.recipient_jwk(),&f.recipient.jwk);
    assert_eq!(f.store.generation().unwrap(),generation);
    assert_eq!(f.store.view().unwrap().state(INV),Some(&InviteState::Open));
}

#[test]
fn wrong_token_host_route_expiry_and_unknown_invitation_fail_closed() {
    let f=Fixture::new();
    let mut req=f.post();
    req.authorization=Some(format!("Bearer {}",encode(&[78;32])));
    assert_eq!(f.error(&req),Some(GateError::Forbidden));
    req.authorization=None;
    assert_eq!(f.error(&req),Some(GateError::Forbidden));
    req=f.post();
    req.host="foreign.example.test:18443".into();
    assert_eq!(f.error(&req),Some(GateError::InviteMismatch));
    req=f.post();
    req.target.push_str("?extra=1");
    assert_eq!(f.error(&req),Some(GateError::NotFound));
    assert_eq!(prepare_fresh_consume(&f.store,&f.scope(),&f.post(),utc_seconds(EXP).unwrap()).err(),Some(GateError::InviteExpired));
    let mut other=f.scope();
    other.invite_id=OTHER_INV;
    req=f.post();
    req.target=format!("/v1/invitations/{OTHER_INV}/consume");
    assert_eq!(prepare_fresh_consume(&f.store,&other,&req,utc_seconds(NOW).unwrap()).err(),Some(GateError::InviteNotFound));
}

#[test]
fn actual_signed_descriptor_and_nested_invite_must_bind_to_independent_scope() {
    let f=Fixture::new();
    let req=f.post();
    let mut scope=f.scope();
    let mut foreign=f.descriptor.clone();
    foreign["TlsSha256"]=json!("b".repeat(64));
    let signed=f.management.sign(&foreign);
    scope.signed_descriptor=&signed;
    assert_eq!(prepare_fresh_consume(&f.store,&scope,&req,utc_seconds(NOW).unwrap()).err(),Some(GateError::InvalidState));
    let mut inner=f.invite.clone();
    inner["ServerBinding"]["NodeId"]=json!(OTHER_INV);
    foreign=f.descriptor.clone();
    foreign["Invite"]=json!(f.management.sign(&inner));
    let signed=f.management.sign(&foreign);
    scope.signed_descriptor=&signed;
    assert_eq!(prepare_fresh_consume(&f.store,&scope,&req,utc_seconds(NOW).unwrap()).err(),Some(GateError::InvalidState));
    scope=f.scope();
    scope.management_jwk=&f.recipient.jwk;
    assert_eq!(prepare_fresh_consume(&f.store,&scope,&req,utc_seconds(NOW).unwrap()).err(),Some(GateError::InvalidState));
}

#[test]
fn signed_request_requires_correct_proof_digest_identity_and_time() {
    let f=Fixture::new();
    let wrong_signer=f.management.sign(&f.body);
    assert_eq!(f.error(&f.request(&wrong_signer)),Some(GateError::InvalidPairRequest));
    let mut body=f.body.clone();
    body["RequestDigest"]=json!("f".repeat(64));
    assert_eq!(f.error(&f.request(&f.recipient.sign(&body))),Some(GateError::PairingMismatch));
    body=f.body.clone();
    body["ServerBinding"]["NodeId"]=json!(OTHER_INV);
    assert_eq!(f.error(&f.request(&f.recipient.sign(&body))),Some(GateError::InviteMismatch));
    body=f.body.clone();
    body["CreatedAtUtc"]=json!("2026-11-18T07:05:01Z");
    assert_eq!(f.error(&f.request(&f.recipient.sign(&body))),Some(GateError::InvalidPairRequest));
    body=f.body.clone();
    body["ClientRequest"]["ClientPublicKey"]=json!(wg(0));
    body["RequestDigest"]=json!(client_digest(&body["ClientRequest"]).unwrap());
    assert_eq!(f.error(&f.request(&f.recipient.sign(&body))),Some(GateError::InvalidPairRequest));
}

#[test]
fn duplicate_json_keys_rejected_even_with_valid_signature() {
    let f=Fixture::new();
    let raw=serde_json::to_string(&f.body).unwrap();
    let ambiguous=format!("{{\"Kind\":\"Other\",{}", &raw[1..]);
    let jws=f.recipient.sign_raw(br#"{"alg":"RS256","typ":"JWT"}"#,ambiguous.as_bytes());
    assert_eq!(f.error(&f.request(&jws)),Some(GateError::InvalidPairRequest));
    let mut req=f.post();
    req.body=format!("{{\"PairRequest\":\"x\",\"PairRequest\":\"{}\"}}",f.recipient.sign(&f.body)).into_bytes();
    assert_eq!(f.error(&req),Some(GateError::InvalidRequest));
    assert!(unique_json(br#"{"a":{"b":1,"b":2}}"#).is_none());
}

#[test]
fn consumed_pending_revocation_and_other_invite_tombstones_cannot_reenroll() {
    let mut f=Fixture::new();
    let claims=prepare_fresh_consume(&f.store,&f.scope(),&f.post(),utc_seconds(NOW).unwrap())
        .unwrap().claims().clone();
    let pool=AddressPool{network:Ipv4Addr::new(10,44,0,0),prefix:24};
    let grant=f.store.update(|l|l.reserve(claims.clone(),utc_seconds(NOW).unwrap(),pool,Some(&[]))).unwrap();
    assert_eq!(f.error(&f.post()),Some(GateError::InvalidState));
    let peer=Peer{public_key:claims.public_key.clone(),address:grant.address};
    f.store.update(|l|l.confirm_consumed(INV,Some(&[peer]))).unwrap();
    assert_eq!(f.error(&f.post()),Some(GateError::InviteConsumed));
    f.store.update(|l|l.begin_revocation(INV)).unwrap();
    assert_eq!(f.error(&f.post()),Some(GateError::Revoked));
    f.store.update(|l|l.confirm_revocation(INV,Some(&[]))).unwrap();
    assert_eq!(f.error(&f.post()),Some(GateError::Revoked));
    // Separate invitation with a correctly signed new request and token
    // cannot revive the same revoked device or public key.
    f.store.update(|l|l.insert_open(OTHER_INV,utc_seconds(EXP).unwrap())).unwrap();
    let mut invite=f.invite.clone();
    invite["InviteId"]=json!(OTHER_INV);
    let mut descriptor=f.descriptor.clone();
    descriptor["InviteId"]=json!(OTHER_INV);
    descriptor["Invite"]=json!(f.management.sign(&invite));
    let signed=f.management.sign(&descriptor);
    let mut scope=f.scope();
    scope.invite_id=OTHER_INV;
    scope.signed_descriptor=&signed;
    let mut body=f.body.clone();
    body["InviteId"]=json!(OTHER_INV);
    body["ClientRequest"]["ClientPublicKey"]=json!(wg(3));
    body["RequestDigest"]=json!(client_digest(&body["ClientRequest"]).unwrap());
    let mut req=f.request(&f.recipient.sign(&body));
    req.target=format!("/v1/invitations/{OTHER_INV}/consume");
    assert_eq!(prepare_fresh_consume(&f.store,&scope,&req,utc_seconds(NOW).unwrap()).err(),Some(GateError::Revoked));
    assert_eq!(f.store.view().unwrap().state(OTHER_INV),Some(&InviteState::Open));
}

#[test]
fn utc_clock_validates_calendar_and_preserves_fractional_digest_bytes() {
    assert_eq!(utc_seconds("1970-01-01T00:00:00Z"),Some(0));
    assert_eq!(utc_seconds("2000-02-29T00:00:00.123456Z"),Some(951782400));
    assert_eq!(utc_seconds("2100-02-29T00:00:00Z"),None);
    for invalid in ["2026-11-18T24:00:00Z","2026-11-18T00:60:00Z",
        "2026-11-18T00:00:60Z","2026-11-18T00:00:00.Z","2026-11-18T00:00:00.1234567Z",
        "2026-11-18T00:00:00+00:00","2026-11-18T00:00:00中"] {
        assert_eq!(utc_seconds(invalid),None);
    }
}

#[test]
fn legacy_golden_original_request_digest_and_recipient_proof_still_agree() {
    let fixture:Value=serde_json::from_str(include_str!("../../tests/fixtures/legacy_request_proof.json")).unwrap();
    let compact=fixture["originalSignedPairRequest"].as_str().unwrap();
    let unsigned=jws_payload(compact).unwrap();
    let verified=verify_unique_jws(compact,&unsigned["RecipientJwk"]).unwrap();
    assert_eq!(client_digest(&verified["ClientRequest"]).unwrap(),verified["RequestDigest"].as_str().unwrap());
    assert_eq!(recipient_digest(&verified["RecipientJwk"]).unwrap(),
        fixture["independentlyPinnedRecipientDigest"].as_str().unwrap());
}

#[test]
fn authenticated_consumed_retry_is_bounded_exact_and_read_only() {
    let mut f=Fixture::new();
    let now=utc_seconds(NOW).unwrap();
    let exp=utc_seconds(EXP).unwrap();
    let req=f.post();
    let claims=prepare_fresh_consume(&f.store,&f.scope(),&req,now).unwrap().claims().clone();
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,Some(&[])).err(),Some(GateError::InvalidState));
    let pool=AddressPool{network:Ipv4Addr::new(10,44,0,0),prefix:24};
    let grant=f.store.update(|l|l.reserve(claims.clone(),now,pool,Some(&[]))).unwrap();
    let peer=Peer{public_key:claims.public_key.clone(),address:grant.address};
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,Some(std::slice::from_ref(&peer))).err(),Some(GateError::InvalidState));
    f.store.update(|l|l.confirm_consumed(INV,Some(std::slice::from_ref(&peer)))).unwrap();
    let gen=f.store.generation().unwrap();
    let live=std::slice::from_ref(&peer);
    for instant in [now,exp,exp+119] {
        let retry=prepare_consumed_retry(&f.store,&f.scope(),&req,instant,Some(live)).unwrap();
        assert_eq!(retry.claims(),&claims);
    }
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,exp+120,Some(live)).err(),Some(GateError::InviteExpired));
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,None).err(),Some(GateError::InvalidState));
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,Some(&[])).err(),Some(GateError::InvalidState));
    let wrong=Peer{public_key:wg(3),address:peer.address};
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,Some(&[wrong])).err(),Some(GateError::InvalidState));
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,Some(&[peer.clone(),peer.clone()])).err(),Some(GateError::InvalidState));
    let mut body=f.body.clone();
    body["ClientRequest"]["RequestId"]=json!(OTHER_INV);
    body["RequestDigest"]=json!(client_digest(&body["ClientRequest"]).unwrap());
    let changed=f.request(&f.recipient.sign(&body));
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&changed,now,Some(live)).err(),Some(GateError::PairingMismatch));
    let mut wrong_token=f.post();
    wrong_token.authorization=Some(format!("Bearer {}",encode(&[78;32])));
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&wrong_token,now,Some(live)).err(),Some(GateError::Forbidden));
    assert_eq!(f.store.generation().unwrap(),gen);
    assert_eq!(f.store.view().unwrap().state(INV),Some(&InviteState::Consumed(grant)));
    f.store.update(|l|l.begin_revocation(INV)).unwrap();
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,Some(live)).err(),Some(GateError::Revoked));
    f.store.update(|l|l.confirm_revocation(INV,Some(&[]))).unwrap();
    assert_eq!(prepare_consumed_retry(&f.store,&f.scope(),&req,now,Some(live)).err(),Some(GateError::Revoked));
}

#[test]
fn noncanonical_historical_revoking_key_cannot_evade_fresh_gate() {
    let mut f=Fixture::new();
    let now=utc_seconds(NOW).unwrap();
    let mut claims=prepare_fresh_consume(&f.store,&f.scope(),&f.post(),now).unwrap().claims().clone();
    // Change only unused base64 pad bits: old wg_key shape accepts it.
    let mut alias=wg(1);
    assert_eq!(&alias[42..43],"E");
    alias.replace_range(42..43,"F");
    assert!(wg_key(&alias));
    assert!(!canonical_wg_key(&alias));
    claims.invite_id=OTHER_INV.into();
    claims.device_id=OTHER_INV.into();
    claims.public_key=alias;
    let pool=AddressPool{network:Ipv4Addr::new(10,44,0,0),prefix:24};
    f.store.update(|l|l.insert_open(OTHER_INV,utc_seconds(EXP).unwrap())).unwrap();
    f.store.update(|l|l.reserve(claims,now,pool,Some(&[]))).unwrap();
    f.store.update(|l|l.begin_revocation(OTHER_INV)).unwrap();
    let gen=f.store.generation().unwrap();
    assert_eq!(f.error(&f.post()),Some(GateError::InvalidState));
    assert_eq!(f.store.generation().unwrap(),gen);
}

#[test]
fn independent_metadata_pin_binds_bearer_descriptor_and_scope() {
    let f=Fixture::new();
    let now=utc_seconds(NOW).unwrap();
    let tag=hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256,f.token.as_bytes()),METADATA_BEARER_DOMAIN);
    let tag_hex:String=tag.as_ref().iter().map(|b|format!("{b:02x}")).collect();
    let record=json!({"SchemaVersion":1,"Kind":"SpiderVPN.InviteMetadata",
        "InviteId":INV,"BearerHmacSha256":tag_hex,"SignedDescriptor":f.signed_descriptor,
        "ManagementSigningPublicKey":f.management.jwk,"ManagementFingerprint":f.fingerprint,
        "ServerBinding":f.binding,"PublicHost":HOST,"Port":PORT,"TlsSha256":f.pin});
    let pin_for=|raw:&[u8]| -> String {
        digest::digest(&digest::SHA256,raw).as_ref().iter().map(|b|format!("{b:02x}")).collect()
    };
    let raw=serde_json::to_vec(&record).unwrap();
    let pin=pin_for(&raw);
    let authenticated=verify_pinned_invite_metadata(&raw,&pin,&f.token).unwrap();
    let scope=authenticated.scope().unwrap();
    assert!(read_open_descriptor(&f.store,&scope,&f.get(),now).is_ok());
    assert!(prepare_fresh_consume(&f.store,&scope,&f.post(),now).is_ok());
    let other=encode(&[78;32]);
    assert_eq!(verify_pinned_invite_metadata(&raw,&pin,&other).err(),Some(GateError::Forbidden));
    assert_eq!(verify_pinned_invite_metadata(&raw,&"f".repeat(64),&f.token).err(),Some(GateError::InvalidState));
    for field in ["BearerHmacSha256","SignedDescriptor","InviteId","PublicHost","TlsSha256","ServerBinding"] {
        let mut altered=record.clone();
        altered[field]=json!("attacker controlled");
        assert_eq!(verify_pinned_invite_metadata(&serde_json::to_vec(&altered).unwrap(),&pin,&f.token).err(),Some(GateError::InvalidState));
    }
    // Even if independently pinned, ambiguous JSON must never become a scope.
    let body=String::from_utf8(raw.clone()).unwrap();
    let duplicate=format!("{{\"InviteId\":\"other\",{}",&body[1..]);
    assert_eq!(verify_pinned_invite_metadata(duplicate.as_bytes(),&pin_for(duplicate.as_bytes()),&f.token).err(),Some(GateError::InvalidState));
    assert_eq!(f.store.view().unwrap().state(INV),Some(&InviteState::Open));
}

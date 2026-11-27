//! Opt-in non-listening authorization response codec. The only signer caller
//! is the authenticated consume transaction; no public raw Grant signing API.
use crate::{AddressPool, Grant};
use crate::fresh_consume_gate::{GateError, unique_json, valid_binding};
use crate::ledger_disk::AuthorizationMaterial;
use crate::legacy_request_proof::recipient_digest;
use crate::legacy_signed::{b64u, verify_jws};
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, Mac};
use rsa::{traits::PublicKeyParts, BigUint, Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use rsa::rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::net::{IpAddr, Ipv4Addr};
use zeroize::Zeroizing;

const INVALID: GateError = GateError::InvalidState;
const MAX_WIRE: usize = 131_072;

// This record is supplied by trusted local service provisioning, not HTTP or
// legacy JSON. The pin must be independently provisioned, not derived from
// the untrusted bytes at the call site. No secret-bearing Debug implementation.
pub struct TrustedResponseConfig {
    binding: Value,
    interface: String,
    pool: AddressPool,
    endpoint: String,
    node_name: String,
    transport: Value,
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, GateError> {
    v.get(k).and_then(Value::as_str).ok_or(INVALID)
}
fn host(s: &str) -> bool {
    if s.parse::<IpAddr>().is_ok() { return true; }
    s.len() <= 253 && s.contains('.') && s.split('.').all(|p|
        !p.is_empty() && p.len() <= 63 && !p.starts_with('-') && !p.ends_with('-')
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}
fn transport_valid(v: &Value) -> bool {
    if v.as_str() == Some("udp") { return true; }
    let Some(o) = v.as_object() else { return false; };
    o.len() == 7 && text(v, "Type") == Ok("tcp-reality")
        && text(v, "Server").is_ok_and(host)
        && text(v, "ServerName").is_ok_and(host)
        && matches!(v.get("Port").and_then(Value::as_u64), Some(443 | 8443 | 2443))
        && text(v, "Uuid").is_ok_and(crate::lower_uuid)
        && text(v, "RealityPublicKey").is_ok_and(|s| b64u(s, 32).is_ok_and(|b|
            b.len() == 32 && b.iter().any(|n| *n != 0)))
        && text(v, "RealityShortId").is_ok_and(|s|
            s.len() <= 16 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
impl TrustedResponseConfig {
    pub fn verify_pinned(raw: &[u8], pin: &str) -> Result<Self, GateError> {
        if raw.is_empty() || raw.len() > 16_384 || !crate::hex_sha256(pin) {
            return Err(INVALID);
        }
        let actual: String = Sha256::digest(raw).iter().map(|b| format!("{b:02x}")).collect();
        if actual != pin { return Err(INVALID); }
        let v = unique_json(raw).ok_or(INVALID)?;
        if v.as_object().is_none_or(|o| o.len() != 9)
            || v.get("SchemaVersion").and_then(Value::as_u64) != Some(1)
            || text(&v, "Kind")? != "SpiderVPN.AuthorizationConfig" { return Err(INVALID); }
        let binding = v.get("ServerBinding").filter(|b| valid_binding(b)).ok_or(INVALID)?;
        let interface = text(&v, "WgInterface")?;
        if !crate::wg_readonly::valid_interface(interface) { return Err(INVALID); }
        let subnet = text(&v, "TunnelSubnet")?;
        let (network, prefix) = subnet.split_once('/').ok_or(INVALID)?;
        let pool = AddressPool {
            network: network.parse().map_err(|_| INVALID)?,
            prefix: prefix.parse().map_err(|_| INVALID)?,
        };
        pool.range().map_err(|_| INVALID)?;
        if subnet != format!("{}/{}", pool.network, pool.prefix)
            || text(&v, "ServerAddress")? != format!("{}/{}",
                Ipv4Addr::from(u32::from(pool.network) + 1), pool.prefix) { return Err(INVALID); }
        let endpoint = text(&v, "PublicEndpoint")?;
        let (ip, port) = endpoint.rsplit_once(':').ok_or(INVALID)?;
        let addr: Ipv4Addr = ip.parse().map_err(|_| INVALID)?;
        let port: u16 = port.parse().map_err(|_| INVALID)?;
        if addr.is_unspecified() || addr.is_loopback() || addr.is_multicast()
            || addr.is_broadcast() || port < 1024 || endpoint != format!("{addr}:{port}") {
            return Err(INVALID);
        }
        let node_name = text(&v, "NodeName")?;
        if node_name.trim() != node_name || node_name.chars().count() > 64
            || node_name.chars().any(char::is_control) { return Err(INVALID); }
        let transport = v.get("Transport").filter(|v| transport_valid(v)).ok_or(INVALID)?;
        Ok(Self { binding: binding.clone(), interface: interface.to_owned(), pool,
            endpoint: endpoint.to_owned(), node_name: node_name.to_owned(), transport: transport.clone() })
    }
    pub(crate) fn matches_scope(&self, binding: &Value, interface: &str) -> bool {
        self.binding == *binding && self.interface == interface
    }
    pub(crate) fn pool(&self) -> AddressPool { self.pool }
    #[cfg(feature = "linux-fresh-provisioning")]
    pub(crate) fn binding(&self)->&Value { &self.binding }
}
fn public_key(jwk: &Value) -> Result<RsaPublicKey, GateError> {
    recipient_digest(jwk).map_err(|_| INVALID)?;
    let n = b64u(text(jwk, "n")?, 1024).map_err(|_| INVALID)?;
    let e = b64u(text(jwk, "e")?, 8).map_err(|_| INVALID)?;
    RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).map_err(|_| INVALID)
}
pub(crate) fn check_signer(key: &RsaPrivateKey, management: &Value) -> Result<(), GateError> {
    let pinned = public_key(management)?;
    if key.n() != pinned.n() || key.e() != pinned.e() { return Err(INVALID); }
    key.validate().map_err(|_| INVALID)
}
pub(crate) fn stamp(unix: i64) -> Result<String, GateError> {
    let t = time::OffsetDateTime::from_unix_timestamp(unix).map_err(|_| INVALID)?;
    if !(1970..=9999).contains(&t.year()) { return Err(INVALID); }
    Ok(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(), u8::from(t.month()), t.day(), t.hour(), t.minute(), t.second()))
}
fn body(grant: &Grant, config: &TrustedResponseConfig, issued: i64, expires: i64)
    -> Result<Value, GateError>
{
    if issued.checked_add(3600) != Some(expires)
        || !config.pool.range().map_err(|_| INVALID)?.contains(&u32::from(grant.address)) {
        return Err(INVALID);
    }
    let c = &grant.claims;
    let address = format!("{}/32", grant.address);
    let response = json!({
        "SchemaVersion":1, "Kind":"TradeChannel.ClientResponse", "Status":"Authorized",
        "RequestId":c.request_id, "DeviceId":c.device_id, "NodeId":config.binding["NodeId"],
        "NodeName":config.node_name, "ClientPublicKey":c.public_key,
        "ServerPublicKey":config.binding["ServerPublicKey"], "ClientAddress":address,
        "ServerAddress":format!("{}/{}",Ipv4Addr::from(u32::from(config.pool.network)+1),config.pool.prefix),
        "TunnelSubnet":format!("{}/{}",config.pool.network,config.pool.prefix),
        "AllowedIPs":["0.0.0.0/0"], "AddressFamilies":["IPv4"],
        "PublicEndpoint":config.endpoint, "PersistentKeepalive":25, "ConfigRevision":1,
        "Transport":config.transport
    });
    Ok(json!({
        "SchemaVersion":1, "Kind":"TradeChannel.PairAuthorization", "InviteId":c.invite_id,
        "ServerBinding":config.binding, "RemoteOwnerId":config.binding["RemoteOwnerId"],
        "NodeId":config.binding["NodeId"], "RequestId":c.request_id, "DeviceId":c.device_id,
        "ClientPublicKey":c.public_key, "RequestDigest":c.request_digest,
        "RequestDigestAlgorithm":"TC-ClientRequest-v1", "RecipientJwkDigest":c.recipient_jwk_digest,
        "ClientAddress":address, "ConfigRevision":1,
        "IssuedAtUtc":stamp(issued)?, "ExpiresAtUtc":stamp(expires)?, "ClientResponse":response
    }))
}
pub(crate) fn sign(body: &Value, key: &RsaPrivateKey) -> Result<String, GateError> {
    let input = format!("{}.{}", B64.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        B64.encode(serde_json::to_vec(body).map_err(|_| INVALID)?));
    let signature = key.sign_with_rng(&mut OsRng, Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(input.as_bytes())).map_err(|_| INVALID)?;
    Ok(format!("{input}.{}", B64.encode(signature)))
}
fn seal(signed: &str, recipient: &RsaPublicKey) -> Result<String, GateError> {
    let header = B64.encode(br#"{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","cty":"TC-Pairing-v1"}"#);
    let mut cek = Zeroizing::new([0u8; 64]);
    let mut iv = [0u8; 16];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut *cek).map_err(|_| INVALID)?;
    rng.try_fill_bytes(&mut iv).map_err(|_| INVALID)?;
    let wrapped = recipient.encrypt(&mut rng, Oaep::new::<Sha256>(), &*cek).map_err(|_| INVALID)?;
    let mut buffer = Zeroizing::new(vec![0u8; signed.len().checked_add(16).ok_or(INVALID)?]);
    buffer[..signed.len()].copy_from_slice(signed.as_bytes());
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(&cek[32..], &iv)
        .map_err(|_| INVALID)?.encrypt_padded_mut::<Pkcs7>(&mut buffer, signed.len()).map_err(|_| INVALID)?;
    let mut mac = Hmac::<Sha512>::new_from_slice(&cek[..32]).map_err(|_| INVALID)?;
    mac.update(header.as_bytes());
    mac.update(&iv);
    mac.update(ciphertext);
    mac.update(&((header.len() as u64) * 8).to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let wire = format!("{header}.{}.{}.{}.{}", B64.encode(wrapped), B64.encode(iv),
        B64.encode(ciphertext), B64.encode(&tag[..32]));
    if wire.len() > MAX_WIRE { return Err(INVALID); }
    Ok(wire)
}
fn reply(grant: &Grant, signed: &str, recipient: &Value) -> Result<Value, GateError> {
    if recipient_digest(recipient).map_err(|_| INVALID)? != grant.claims.recipient_jwk_digest {
        return Err(GateError::PairingMismatch);
    }
    let encrypted = seal(signed, &public_key(recipient)?)?;
    let data = json!({"Status":"Authorized", "RequestId":grant.claims.request_id,
        "RequestDigest":grant.claims.request_digest, "EncryptedAuthorization":encrypted});
    // Include headroom for the existing outer JSON HTTP response envelope.
    if serde_json::to_vec(&data).map_err(|_| INVALID)?.len() > MAX_WIRE - 1024 { return Err(INVALID); }
    Ok(data)
}
/// Only called after verified request and exact address preview. Both signing
/// and sealing are fallible and happen before Pending/WG mutation.
pub(crate) fn prepare(grant: &Grant, recipient: &Value, config: &TrustedResponseConfig,
    management: &Value, key: &RsaPrivateKey, now: i64)
    -> Result<(AuthorizationMaterial, Value), GateError>
{
    check_signer(key, management)?;
    let expires = now.checked_add(3600).ok_or(INVALID)?;
    let payload = body(grant, config, now, expires)?;
    let signed = sign(&payload, key)?;
    if verify_jws(&signed, management).map_err(|_| INVALID)? != payload { return Err(INVALID); }
    let data = reply(grant, &signed, recipient)?;
    Ok((AuthorizationMaterial { grant:grant.clone(), signed, issued_unix:now,
        expires_unix:expires }, data))
}
/// A retry validates the original signed body against the exact persisted
/// grant, independently pinned management/config and verified recipient.
pub(crate) fn retry(material: &AuthorizationMaterial, grant: &Grant, recipient: &Value,
    config: &TrustedResponseConfig, management: &Value, now: i64) -> Result<Value, GateError>
{
    if material.grant != *grant || now < material.issued_unix || now >= material.expires_unix {
        return Err(INVALID);
    }
    let expected = body(grant, config, material.issued_unix, material.expires_unix)?;
    let verified = verify_jws(&material.signed, management).map_err(|_| INVALID)?;
    if verified != expected { return Err(INVALID); }
    reply(grant, &material.signed, recipient)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pin(raw: &[u8]) -> String {
        Sha256::digest(raw).iter().map(|b| format!("{b:02x}")).collect()
    }
    fn record() -> Value {
        json!({
            "SchemaVersion":1, "Kind":"SpiderVPN.AuthorizationConfig",
            "ServerBinding":{"RemoteOwnerId":"11111111-1111-4111-8111-111111111111",
                "NodeId":"22222222-2222-4222-8222-222222222222",
                "ServerPublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
            "WgInterface":"spiderci0", "TunnelSubnet":"10.66.0.0/24",
            "ServerAddress":"10.66.0.1/24", "PublicEndpoint":"203.0.113.10:51820",
            "NodeName":"fixture", "Transport":"udp"
        })
    }
    fn config(v: &Value) -> Result<TrustedResponseConfig, GateError> {
        let raw = serde_json::to_vec(v).unwrap();
        TrustedResponseConfig::verify_pinned(&raw, &pin(&raw))
    }
    #[test]
    fn response_configuration_pin_and_client_contract_are_checked() {
        let valid = record();
        let c = config(&valid).unwrap();
        assert!(c.matches_scope(&valid["ServerBinding"], "spiderci0"));
        assert!(!c.matches_scope(&valid["ServerBinding"], "otherci0"));
        assert_eq!(c.pool(), AddressPool { network:Ipv4Addr::new(10,66,0,0), prefix:24 });
        let raw = serde_json::to_vec(&valid).unwrap();
        assert!(TrustedResponseConfig::verify_pinned(&raw, &"0".repeat(64)).is_err());
        for (field, value) in [
            ("TunnelSubnet", json!("10.66.0.1/24")),
            ("ServerAddress", json!("10.66.0.2/24")),
            ("PublicEndpoint", json!("example.test:51820")),
            ("PublicEndpoint", json!("203.0.113.10:80")),
            ("Transport", json!("tcp")),
            ("Transport", json!({"Type":"tcp-reality"})),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            assert!(config(&bad).is_err(), "invalid {field} must not authorize");
        }
        let mut compatible = valid;
        compatible["Transport"] = json!({"Type":"tcp-reality", "Server":"198.51.100.9",
            "Port":8443, "Uuid":"33333333-3333-4333-8333-333333333333",
            "ServerName":"gate.example.test", "RealityPublicKey":B64.encode([7u8;32]),
            "RealityShortId":"aabbccdd"});
        assert!(config(&compatible).is_ok());
        compatible["Transport"]["Port"] = json!(80);
        assert!(config(&compatible).is_err());
    }
}

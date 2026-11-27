//! First Rust authority creation for a new node or verified TradeChannel
//! history. Operator-provided identity and exclusive writers are trust inputs.
#![cfg(all(target_os = "linux", feature = "linux-fresh-provisioning"))]

use crate::authorization_response::{TrustedResponseConfig,check_signer,sign,stamp};
use crate::existing_devices::provisioning as existing_history;
use crate::fresh_consume_gate::{management_fingerprint,verify_pinned_invite_metadata,
    check_descriptor,METADATA_BEARER_DOMAIN};
use crate::tls_identity::{open_service_root,read_service_file,read_service_identity,
    create_fresh_service_root,create_fresh_service_file};
use crate::wg_conf_audit::require_initial_inventory;
use crate::Ledger;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64,Engine};
use ring::{digest,hmac,rand::{SecureRandom,SystemRandom}};
use rsa::{pkcs8::DecodePrivateKey,traits::PublicKeyParts,RsaPrivateKey};
use serde_json::json;
use std::{io,net::Ipv4Addr,path::PathBuf,time::{SystemTime,UNIX_EPOCH}};
use std::os::fd::AsRawFd;
use zeroize::Zeroizing;

fn refused()->io::Error { io::Error::new(io::ErrorKind::PermissionDenied,"fresh authority refused") }
fn hex(b:&[u8])->String { b.iter().map(|x|format!("{x:02x}")).collect() }
fn sha(b:&[u8])->String { hex(digest::digest(&digest::SHA256,b).as_ref()) }
fn now()->io::Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|refused())?.as_secs())
        .map_err(|_|refused())
}
fn uuid(rng:&SystemRandom)->io::Result<String> {
    let mut b=[0u8;16];
    rng.fill(&mut b).map_err(|_|refused())?;
    b[6]=(b[6]&0x0f)|0x40;
    b[8]=(b[8]&0x3f)|0x80;
    Ok(format!("{}-{}-{}-{}-{}",hex(&b[..4]),hex(&b[4..6]),hex(&b[6..8]),
        hex(&b[8..10]),hex(&b[10..])))
}

const HISTORY_FILE: &str = "existing-history.json";

pub enum NodeHistory<'a> {
    New,
    VerifiedTradeChannel { snapshot_pin: &'a str },
}

/// Only explicit init-fresh with operator new-node attestation. Never
/// called by serve. No old authority, generic signing or legacy input.
pub fn initialize_new_node(source:PathBuf,root:PathBuf,interface:&str,host:&str,port:u16,
    config_pin:&str,management_pin:&str,tls_pin:&str,lifetime:i64,name:&str)->io::Result<()>
{
    initialize_node(source, root, interface, host, port, config_pin, management_pin, tls_pin,
        lifetime, name, NodeHistory::New)
}

/// Build a new, protected Rust data root from independently pinned inputs.
pub fn initialize_node(source: PathBuf, root: PathBuf, interface: &str, host: &str, port: u16,
    config_pin: &str, management_pin: &str, tls_pin: &str, lifetime: i64, name: &str,
    history: NodeHistory<'_>,
) -> io::Result<()> {
    let ip:Ipv4Addr=host.parse().map_err(|_|refused())?;
    if ip.to_string()!=host || ip.is_loopback() || ip.is_unspecified()
        || ip.is_multicast() || ip.is_broadcast() || port<1024
        || !(60..=86400).contains(&lifetime) || name.trim()!=name || name.is_empty()
        || name.chars().count()>64 || name.chars().any(|c|c.is_control()||c=='\u{2028}'||c=='\u{2029}')
        || !crate::wg_readonly::valid_interface(interface)
        || !source.is_absolute() || !root.is_absolute() || source.starts_with(&root) || root.starts_with(&source)
    {return Err(refused());}
    match std::fs::symlink_metadata(&root) {
        Err(e) if e.kind()==io::ErrorKind::NotFound=>{},
        _=>return Err(refused()),
    }
    let input=open_service_root(&source).map_err(|_|refused())?;
    // Refuse source state. Absence of these files does not prove provenance.
    for n in ["authority-ledger.json",".fresh-init-incomplete",".pairing-authority.lock",
        "invite-metadata.json","invitation-code.txt","metadata-pin.txt","invites.json","clients.json"] {
        match std::fs::symlink_metadata(source.join(n)) {
            Err(e) if e.kind()==io::ErrorKind::NotFound=>{},
            _=>return Err(refused()),
        }
    }
    let raw=read_service_file(&input,"authorization-config.json",16_384).map_err(|_|refused())?;
    let config=TrustedResponseConfig::verify_pinned(&raw,config_pin).map_err(|_|refused())?;
    let binding=config.binding();
    if !config.matches_scope(binding,interface) {return Err(refused());}
    let expected=binding["ServerPublicKey"].as_str().ok_or_else(refused)?;
    let pem=Zeroizing::new(read_service_file(&input,"management.key",32*1024).map_err(|_|refused())?);
    let key=RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(&pem).map_err(|_|refused())?)
        .map_err(|_|refused())?;
    let jwk=json!({"e":B64.encode(key.e().to_bytes_be()),"kty":"RSA","n":B64.encode(key.n().to_bytes_be())});
    let fingerprint=management_fingerprint(&jwk).ok_or_else(refused)?;
    if fingerprint!=management_pin {return Err(refused());}
    check_signer(&key,&jwk).map_err(|_|refused())?;
    let identity=read_service_identity(&input,tls_pin).map_err(|_|refused())?;
    if identity.leaf_der_sha256!=tls_pin {return Err(refused());}
    let cert=read_service_file(&input,"tls.crt",128*1024).map_err(|_|refused())?;
    let tls_key=Zeroizing::new(read_service_file(&input,"tls.key",32*1024).map_err(|_|refused())?);
    let issued = now()?;
    let (mut ledger, initial_peers, archive) = match history {
        NodeHistory::New => {
            match std::fs::symlink_metadata(source.join(HISTORY_FILE)) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(refused()),
            }
            (Ledger::default(), Vec::new(), None)
        }
        NodeHistory::VerifiedTradeChannel { snapshot_pin } => {
            let bytes = read_service_file(&input, HISTORY_FILE, 4 * 1024 * 1024)
                .map_err(|_| refused())?;
            let (ledger, peers) = existing_history::load(
                &bytes, snapshot_pin, binding, &jwk, config.pool(), issued,
            ).map_err(|_| refused())?;
            (ledger, peers, Some(bytes))
        }
    };
    require_initial_inventory(interface, expected, &initial_peers).map_err(|_| refused())?;
    let rng=SystemRandom::new();
    let id=uuid(&rng)?;
    let mut secret=Zeroizing::new([0u8;32]);
    rng.fill(&mut *secret).map_err(|_|refused())?;
    let token=Zeroizing::new(B64.encode(&*secret));
    let expires=issued.checked_add(lifetime).ok_or_else(refused)?;
    ledger.insert_open(&id, expires).map_err(|_| refused())?;
    let issued_at=stamp(issued).map_err(|_|refused())?;
    let expires_at=stamp(expires).map_err(|_|refused())?;
    let retry_at=stamp(expires.checked_add(120).ok_or_else(refused)?).map_err(|_|refused())?;
    let invite=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairInvite","InviteId":id,
        "RemoteOwnerId":binding["RemoteOwnerId"],"NodeId":binding["NodeId"],
        "ServerPublicKey":expected,"ServerBinding":binding,"ManagementSigningPublicKey":jwk,
        "PublicEndpoint":format!("{host}:{port}"),"IssuedAtUtc":issued_at,"ExpiresAtUtc":expires_at,
        "Capabilities":{"PairingVersion":1},"DeviceName":name});
    let signed_invite=sign(&invite,&key).map_err(|_|refused())?;
    let desc=json!({"SchemaVersion":1,"Kind":"TradeChannel.OnlineInvite","InviteId":id,
        "Invite":signed_invite,"PublicHost":host,"Port":port,"TlsSha256":tls_pin,
        "ManagementFingerprint":fingerprint,"ManagementSigningPublicKey":jwk,
        "ExpiresAtUtc":expires_at,"RetryUntilUtc":retry_at});
    let signed_desc=sign(&desc,&key).map_err(|_|refused())?;
    let tag=hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256,token.as_bytes()),METADATA_BEARER_DOMAIN);
    let metadata=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.InviteMetadata",
        "InviteId":id,"BearerHmacSha256":hex(tag.as_ref()),"SignedDescriptor":signed_desc,
        "ManagementSigningPublicKey":jwk,"ManagementFingerprint":fingerprint,
        "ServerBinding":binding,"PublicHost":host,"Port":port,"TlsSha256":tls_pin,
        "WgInterface":interface})).map_err(|_|refused())?;
    let meta_pin=sha(&metadata);
    let authenticated=verify_pinned_invite_metadata(&metadata,&meta_pin,&token).map_err(|_|refused())?;
    let scope=authenticated.scope().map_err(|_|refused())?;
    check_descriptor(&scope,expires,issued).map_err(|_|refused())?;
    // Fixed eight legacy fields. No generic payload or caller signing.
    let code_json=Zeroizing::new(format!("{{\"v\":1,\"h\":\"{host}\",\"p\":{port},\"i\":\"{id}\",\"k\":\"{}\",\"t\":\"{tls_pin}\",\"m\":\"{fingerprint}\",\"e\":{expires}}}",&*token));
    let payload=Zeroizing::new(B64.encode(code_json.as_bytes()));
    let code=Zeroizing::new(format!("TCI1.{}\n",&*payload));
    if code.len()>2049 {return Err(refused());}
    let dir=create_fresh_service_root(&root).map_err(|_|refused())?;
    create_fresh_service_file(&dir,".fresh-init-incomplete",b"fresh initialization not published\n")?;
    dir.sync_all()?;
    for (name,bytes) in [("authorization-config.json",raw.as_slice()),("management.key",pem.as_slice()),
        ("tls.crt",cert.as_slice()),("tls.key",tls_key.as_slice()),("invite-metadata.json",metadata.as_slice()),
        ("metadata-pin.txt",meta_pin.as_bytes()),("invitation-code.txt",code.as_bytes())] {
        create_fresh_service_file(&dir,name,bytes)?;
    }
    if let Some(bytes) = archive {
        create_fresh_service_file(&dir, HISTORY_FILE, &bytes)?;
    }
    // Verify copied identity and current WG again before publishing ledger.
    read_service_identity(&dir,tls_pin).map_err(|_|refused())?;
    require_initial_inventory(interface, expected, &initial_peers).map_err(|_| refused())?;
    let after=now()?;
    if after<issued || after>=expires {return Err(refused());}
    dir.sync_all()?;
    crate::ledger_disk::publish_initial_ledger(&root, &dir, ledger).map_err(|_| refused())?;
    let store=crate::ledger_disk::LedgerStore::open_existing(&root,std::time::Duration::ZERO)
        .map_err(|_|refused())?;
    crate::fresh_consume_gate::preflight_service_metadata(&store,&metadata,&meta_pin,interface,
        tls_pin,&config,&key).map_err(|_|refused())?;
    let marker=std::ffi::CString::new(".fresh-init-incomplete").unwrap();
    if unsafe {libc::unlinkat(dir.as_raw_fd(),marker.as_ptr(),0)}!=0 {return Err(refused());}
    dir.sync_all()?;
    Ok(())
}

//! SEC-01 isolated Linux WireGuard kernel integration regression.
//! Feature-gated; executed only in a dedicated privileged netns CI job.

#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use spidervpn_pairing_authority::{AddressPool, Claims, InviteState, Refusal};
use spidervpn_pairing_authority::ledger_disk::LedgerStore;
use spidervpn_pairing_authority::wg_conf_audit::read_verified_snapshot;
use spidervpn_pairing_authority::wg_readonly::LiveWgReader;

const INV: &str = "11111111-1111-4111-8111-111111111111";
const REQ: &str = "22222222-2222-4222-8222-222222222222";
const DEV: &str = "33333333-3333-4333-8333-333333333333";
const IFACE: &str = "spiderci0";

unsafe extern "C" { fn geteuid() -> u32; }

fn test_ledger() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("spidervpn-sec01-realwg-{}", std::process::id()));
    fs::create_dir(&dir).expect("create isolated test ledger dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(dir.join("authority-ledger.json")).unwrap();
    file.write_all(br#"{"schema_version":1,"generation":1,"ledger":{"invitations":{},"revoked_devices":[],"revoked_keys":[]}}"#).unwrap();
    file.sync_all().unwrap();
    fs::File::open(&dir).unwrap().sync_all().unwrap();
    dir
}
fn open(dir: &Path) -> LedgerStore {
    LedgerStore::open_existing(dir, Duration::from_secs(2)).unwrap()
}
fn claims(key: &str) -> Claims {
    Claims { invite_id:INV.into(), request_id:REQ.into(), device_id:DEV.into(),
        public_key:key.into(), request_digest:"a".repeat(64),
        recipient_jwk_digest:"b".repeat(64) }
}
fn cli(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-audit"))
        .args(["inspect", root.to_str().unwrap(), IFACE, INV]).output().unwrap()
}
fn expect_report(root: &Path, stage: &str, action: &str, key: &str) {
    let before_ledger=fs::read(root.join("authority-ledger.json")).unwrap();
    let before_live=LiveWgReader::new(IFACE).unwrap().snapshot().unwrap();
    let output=cli(root);
    assert!(output.status.success(), "protected root-only CLI should accept real kernel snapshot");
    let stdout=String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("stage={stage}")), "unexpected stage");
    assert!(stdout.contains(&format!("action={action}")), "unexpected action");
    assert!(!stdout.contains(key) && !stdout.contains("PrivateKey"), "secret leaked");
    assert!(output.stderr.is_empty(), "unexpected diagnostic error");
    assert_eq!(before_ledger,fs::read(root.join("authority-ledger.json")).unwrap(),
        "CLI must not update authority");
    assert_eq!(before_live,LiveWgReader::new(IFACE).unwrap().snapshot().unwrap(),
        "CLI must not mutate kernel peers");
}
#[cfg(feature = "linux-admin-finalize")]
fn expect_finalize_requires_real_root_tty(root: &Path) {
    let before = fs::read(root.join("authority-ledger.json")).unwrap();
    let before_live = LiveWgReader::new(IFACE).unwrap().snapshot().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-audit"))
        .args(["finalize",root.to_str().unwrap(),IFACE,INV])
        .output().unwrap();
    assert_eq!(output.status.code(),Some(2),"non-interactive root must not authorize finalize");
    assert!(output.stdout.is_empty(),"no status success output without TTY");
    assert!(String::from_utf8_lossy(&output.stderr).contains("terminal confirmation or finalization denied"));
    assert_eq!(before,fs::read(root.join("authority-ledger.json")).unwrap());
    assert_eq!(before_live,LiveWgReader::new(IFACE).unwrap().snapshot().unwrap());
}
#[cfg(feature = "linux-admin-finalize")]
fn expect_pty_finalizes_exact_terminal_state(root: &Path, stage: &str, key: &str) {
    let generation = {
        let store = open(root);
        store.generation().unwrap()
    };
    let expected = format!("FINALIZE {INV} {generation} {stage}\n");
    let cli = env!("CARGO_BIN_EXE_spidervpn-pair-audit");
    // CI-only PTY driver: exercises a genuine controlling /dev/tty for the
    // Rust child, not a production approval issuer. Local root can script a
    // PTY; the security principal is root, not proof of a human at keyboard.
    let command = format!("{cli} finalize {} {IFACE} {INV}",root.display());
    let mut child = Command::new("/usr/bin/script")
        .args(["-qec",&command,"/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn().expect("open a CI-only pseudo-terminal");
    std::thread::sleep(Duration::from_millis(120));
    {
        let mut stdin=child.stdin.take().unwrap();
        stdin.write_all(expected.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }
    let output=child.wait_with_output().unwrap();
    let text=String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(),"authorized root PTY finalization should succeed: {text}");
    assert!(text.contains("ledger finalized at"),"terminal finalizer emitted no success");
    assert!(!text.contains(key),"never print WireGuard public keys in CLI transcript");
}

fn expect_denied(root: &Path) {
    let output=cli(root);
    assert_eq!(output.status.code(),Some(2));
    assert!(output.stdout.is_empty(), "denied CLI must not emit partial report");
    assert!(String::from_utf8_lossy(&output.stderr).contains("inspection denied"));
}
fn write_conf(conf: &Path, base: &str, key: Option<&str>) {
    let mut body=base.to_string();
    if let Some(k)=key {
        body.push_str("\n[Peer]\nPublicKey = ");
        body.push_str(k);
        body.push_str("\nAllowedIPs = 10.66.0.2/32\n");
    }
    let mut file=OpenOptions::new().write(true).truncate(true).open(conf).unwrap();
    file.write_all(body.as_bytes()).unwrap();
    file.sync_all().unwrap();
    let meta=fs::symlink_metadata(conf).unwrap();
    assert_eq!(meta.uid(),0);
    assert_eq!(meta.mode() & 0o777,0o600);
}
fn set_peer(key: &str, present: bool) {
    let mut command=Command::new("/usr/bin/wg");
    command.args(["set",IFACE,"peer",key]);
    if present {command.args(["allowed-ips","10.66.0.2/32"]);}
    else {command.arg("remove");}
    assert!(command.output().unwrap().status.success(), "actual netns wg set failed");
}
#[test]
fn root_audit_observes_real_wireguard_and_refuses_revoked_replay() {
    assert_eq!(unsafe {geteuid()},0,"dedicated test must execute as root");
    assert_eq!(std::env::var("SPIDERVPN_SEC01_NS_INTERFACE").unwrap(),IFACE);
    let key=std::env::var("SPIDERVPN_SEC01_NS_CLIENT_PUBLIC_KEY").unwrap();
    assert_eq!(key.len(),44);
    assert!(key.ends_with('='));
    let conf=Path::new("/etc/wireguard").join(format!("{IFACE}.conf"));
    let base=fs::read_to_string(&conf).expect("real root-protected test wg.conf");
    assert!(!base.contains("[Peer]"));
    assert!(LiveWgReader::new(IFACE).unwrap().snapshot().unwrap().is_empty());

    // Test-only seeded ledger: never production Python invitations.json.
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("valid wall-clock time").as_secs()).expect("valid i64 epoch");
    let root=test_ledger();
    let original=claims(&key);
    let mut store=open(&root);
    store.update(|l|l.insert_open(INV,now+600)).unwrap();
    let grant=store.update(|l|l.reserve(original.clone(),now,
        AddressPool {network:Ipv4Addr::new(10,66,0,0),prefix:24},Some(&[]))).unwrap();
    assert_eq!(grant.address,Ipv4Addr::new(10,66,0,2));
    drop(store);

    expect_report(&root,"PendingAdd","RepairBothWithApproval",&key);
    write_conf(&conf,&base,Some(&key));
    expect_report(&root,"PendingAdd","RepairKernelWithApproval",&key);
    set_peer(&key,true);
    expect_report(&root,"PendingAdd","VerifyAndFinalize",&key);
    #[cfg(feature = "linux-admin-finalize")]
    expect_finalize_requires_real_root_tty(&root);
    #[cfg(feature = "linux-admin-finalize")]
    expect_pty_finalizes_exact_terminal_state(&root,"PendingAdd",&key);
    let store=open(&root);
    assert_eq!(read_verified_snapshot(IFACE).unwrap().len(),1);
    assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Consumed(_))));
    assert!(store.view().unwrap().retry(&original,Some(&read_verified_snapshot(IFACE).unwrap())).is_ok());
    drop(store);
    expect_denied(&root);
    #[cfg(feature = "linux-admin-finalize")]
    expect_finalize_requires_real_root_tty(&root);

    let mut store=open(&root);
    store.update(|l|l.begin_revocation(INV)).unwrap();
    assert_eq!(store.view().unwrap().retry(&original,Some(&[])),Err(Refusal::Revoked));
    drop(store);
    expect_report(&root,"RevokingRemove","RepairBothWithApproval",&key);
    set_peer(&key,false);
    expect_report(&root,"RevokingRemove","RepairConfigWithApproval",&key);
    write_conf(&conf,&base,None);
    expect_report(&root,"RevokingRemove","VerifyAndFinalize",&key);
    #[cfg(feature = "linux-admin-finalize")]
    expect_finalize_requires_real_root_tty(&root);

    #[cfg(feature = "linux-admin-finalize")]
    expect_pty_finalizes_exact_terminal_state(&root,"RevokingRemove",&key);
    let store=open(&root);
    assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Revoked(_))));
    assert_eq!(store.view().unwrap().retry(&original,Some(&[])),Err(Refusal::Revoked));
    drop(store);
    expect_denied(&root);
    #[cfg(feature = "linux-admin-finalize")]
    expect_finalize_requires_real_root_tty(&root);
    assert!(LiveWgReader::new(IFACE).unwrap().snapshot().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "linux-fresh-consume-gate")]
mod identity_gate {
    use super::*;
    use ring::{digest, hmac};
    use serde_json::{json, Value};
    use std::io::Cursor;
    use std::process::Stdio;
    use spidervpn_pairing_authority::fresh_consume_gate::{
        enroll_fresh_consume, prepare_fresh_consume, prepare_consumed_retry,
        verify_pinned_invite_metadata, FreshEnrollError, GateError,
    };
    use spidervpn_pairing_authority::http_one_request::{read_one_request, ParsedRequest};
    use spidervpn_pairing_authority::wg_conf_audit::{read_verified_identity_snapshot, ConfigError};
    use zeroize::Zeroizing;

    fn b64(raw: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let (mut acc, mut bits) = (0u32, 0);
        for byte in raw {
            acc = (acc << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(char::from(alphabet[((acc >> bits) & 63) as usize]));
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(char::from(alphabet[((acc << (6-bits)) & 63) as usize]));
        }
        out
    }
    fn hex(raw: &[u8]) -> String {
        raw.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn sha(raw: &[u8]) -> String { hex(digest::digest(&digest::SHA256, raw).as_ref()) }
    fn utc_at(epoch: i64) -> String {
        let output = Command::new("/usr/bin/date").args(["-u","-d",
            &format!("@{epoch}"),"+%Y-%m-%dT%H:%M:%SZ"]).output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
    struct Rsa { path: PathBuf, jwk: Value }
    impl Rsa {
        fn new(root: &Path, name: &str) -> Self {
            let path=root.join(name);
            let status=Command::new("/usr/bin/openssl").args(["genpkey","-algorithm","RSA",
                "-pkeyopt","rsa_keygen_bits:2048","-out"]).arg(&path)
                .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert!(status.success());
            let output=Command::new("/usr/bin/openssl").args(["rsa","-in"]).arg(&path)
                .args(["-modulus","-noout"]).stderr(Stdio::null()).output().unwrap();
            assert!(output.status.success());
            let modulus=String::from_utf8(output.stdout).unwrap();
            let modulus=modulus.trim().strip_prefix("Modulus=").unwrap();
            let bytes:Vec<u8>=(0..modulus.len()).step_by(2)
                .map(|i|u8::from_str_radix(&modulus[i..i+2],16).unwrap()).collect();
            Self{path,jwk:json!({"e":"AQAB","kty":"RSA","n":b64(&bytes)})}
        }
        fn sign(&self, body:&Value) -> String {
            let input=format!("{}.{}",b64(br#"{"alg":"RS256","typ":"JWT"}"#),
                b64(&serde_json::to_vec(body).unwrap()));
            let mut child=Command::new("/usr/bin/openssl").args(["dgst","-sha256","-sign"])
                .arg(&self.path).stdin(Stdio::piped()).stdout(Stdio::piped())
                .stderr(Stdio::null()).spawn().unwrap();
            child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
            let output=child.wait_with_output().unwrap();
            assert!(output.status.success());
            format!("{input}.{}",b64(&output.stdout))
        }
    }
    fn request(token:&str, signed:&str) -> ParsedRequest {
        request_at(token,signed,"pair.example.test:18443")
    }
    fn request_at(token:&str, signed:&str, host:&str) -> ParsedRequest {
        let body=serde_json::to_vec(&json!({"PairRequest":signed})).unwrap();
        let mut wire=format!("POST /v1/invitations/{INV}/consume HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
        wire.extend(body);
        read_one_request(&mut Cursor::new(wire)).unwrap()
    }
    fn write_key_file(path:&Path, key:&str) {
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
        file.write_all(key.as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
    }
    fn set_server_key(path:&Path) {
        assert!(Command::new("/usr/bin/wg").args(["set",IFACE,"private-key"])
            .arg(path).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
    }
    #[test]
    fn authenticated_retry_rejects_wrong_real_kernel_and_config_server_identity() {
        assert_eq!(unsafe {geteuid()},0);
        assert_eq!(std::env::var("SPIDERVPN_SEC01_NS_INTERFACE").unwrap(),IFACE);
        let expected=std::env::var("SPIDERVPN_SEC01_NS_SERVER_PUBLIC_KEY").unwrap();
        let key=std::env::var("SPIDERVPN_SEC01_NS_CLIENT_PUBLIC_KEY").unwrap();
        let reader=LiveWgReader::new(IFACE).unwrap();
        assert_eq!(reader.server_public_key().unwrap(),expected);
        assert!(reader.snapshot().unwrap().is_empty());
        let conf=Path::new("/etc/wireguard").join(format!("{IFACE}.conf"));
        let base=Zeroizing::new(fs::read_to_string(&conf).unwrap());
        let original_key=base.lines().find_map(|line|line.strip_prefix("PrivateKey = ")).unwrap();
        let root=test_ledger();
        let original_key_file=root.join("original.wg");
        write_key_file(&original_key_file,original_key);
        let new_key_file=root.join("replacement.wg");
        let generated=Command::new("/usr/bin/wg").arg("genkey").stderr(Stdio::null()).output().unwrap();
        assert!(generated.status.success());
        let new_key=Zeroizing::new(String::from_utf8(generated.stdout).unwrap());
        write_key_file(&new_key_file,new_key.trim());
        let replacement=Zeroizing::new(base.replace(original_key,new_key.trim()));

        let now=i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
        let issued=utc_at(now-60);
        let expires=utc_at(now+3600);
        let retry=utc_at(now+3720);
        let mgmt=Rsa::new(&root,"management.pem");
        let recipient=Rsa::new(&root,"recipient.pem");
        let binding=json!({"RemoteOwnerId":"55555555-5555-4555-8555-555555555555",
            "NodeId":"66666666-6666-4666-8666-666666666666","ServerPublicKey":expected});
        let fingerprint=format!("SHA256:{}",b64(digest::digest(&digest::SHA256,
            &serde_json::to_vec(&mgmt.jwk).unwrap()).as_ref()).replace('-',"+").replace('_',"/"));
        let pin="a".repeat(64);
        let token=b64(&[77;32]);
        let invite=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairInvite","InviteId":INV,
            "RemoteOwnerId":binding["RemoteOwnerId"],"NodeId":binding["NodeId"],
            "ServerPublicKey":expected,"ServerBinding":binding,
            "ManagementSigningPublicKey":mgmt.jwk,"IssuedAtUtc":issued,"ExpiresAtUtc":expires,
            "PublicEndpoint":"pair.example.test:18443","DeviceName":"netns fixture",
            "Capabilities":{"PairingVersion":1}});
        let descriptor=mgmt.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.OnlineInvite",
            "InviteId":INV,"Invite":mgmt.sign(&invite),"PublicHost":"pair.example.test","Port":18443,
            "TlsSha256":pin,"ManagementFingerprint":fingerprint,"ManagementSigningPublicKey":mgmt.jwk,
            "ExpiresAtUtc":expires,"RetryUntilUtc":retry}));
        let tag=hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256,token.as_bytes()),
            b"SpiderVPN pinned invitation metadata bearer v1");
        let metadata=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.InviteMetadata",
            "InviteId":INV,"BearerHmacSha256":hex(tag.as_ref()),"SignedDescriptor":descriptor,
            "ManagementSigningPublicKey":mgmt.jwk,"ManagementFingerprint":fingerprint,
            "ServerBinding":binding,"PublicHost":"pair.example.test","Port":18443,
            "TlsSha256":pin,"WgInterface":IFACE})).unwrap();
        let authenticated=verify_pinned_invite_metadata(&metadata,&sha(&metadata),&token).unwrap();
        let scope=authenticated.scope().unwrap();
        let inner=json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientRequest","RequestId":REQ,
            "DeviceId":DEV,"ClientPublicKey":key,"CreatedAtUtc":issued,"AddressFamilies":["IPv4"]});
        let request_digest=sha(format!("1\nTradeChannel.ClientRequest\n{REQ}\n{DEV}\n{issued}\n{key}\nIPv4").as_bytes());
        let signed=recipient.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest",
            "InviteId":INV,"ServerBinding":binding,"ClientRequest":inner,
            "DeviceName":"netns fixture","RecipientJwk":recipient.jwk,"RequestDigest":request_digest,
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued}));
        let req=request(&token,&signed);
        let mut store=open(&root);
        store.update(|l|l.insert_open(INV,now+3600)).unwrap();
        let claims=prepare_fresh_consume(&store,&scope,&req).unwrap().claims().clone();
        let grant=store.update(|l|l.reserve(claims.clone(),now,
            AddressPool{network:Ipv4Addr::new(10,66,0,0),prefix:24},Some(&[]))).unwrap();
        assert_eq!(grant.address,Ipv4Addr::new(10,66,0,2));
        write_conf(&conf,&base,Some(&key));
        set_peer(&key,true);
        let peers=read_verified_identity_snapshot(&store,IFACE,&expected).unwrap();
        store.update(|l|l.confirm_consumed(INV,Some(&peers))).unwrap();
        let generation=store.generation().unwrap();
        let ledger_before=fs::read(root.join("authority-ledger.json")).unwrap();
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).unwrap().claims(),&claims);
        assert!(LedgerStore::open_existing(&root,Duration::from_millis(25)).is_err());

        // Old inventory-only API passes identical peers even if the durable
        // interface key is replaced. New gate must deny the very same request.
        write_conf(&conf,&replacement,Some(&key));
        assert_eq!(read_verified_snapshot(IFACE).unwrap(),peers);
        assert_eq!(read_verified_identity_snapshot(&store,IFACE,&expected).err(),Some(ConfigError::IdentityMismatch));
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).err(),Some(GateError::InvalidState));

        // Rotate the actual same-named interface to match the replacement
        // config. Peer inventory remains correct but pinned key is wrong.
        set_server_key(&new_key_file);
        assert_ne!(reader.server_public_key().unwrap(),expected);
        assert_eq!(read_verified_snapshot(IFACE).unwrap(),peers);
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).err(),Some(GateError::InvalidState));
        set_server_key(&original_key_file);
        write_conf(&conf,&base,Some(&key));

        // Protected config key absence, duplicate and malformed values must
        // deny; no key is ever used as an assertion diagnostic.
        for bad in [
            Zeroizing::new("[Interface]\nAddress = 10.66.0.1/24\n".to_owned()),
            Zeroizing::new(format!("{}PrivateKey = {original_key}\n",base.as_str())),
            Zeroizing::new("[Interface]\nPrivateKey = not-a-key\n".to_owned()),
        ] {
            write_conf(&conf,&bad,Some(&key));
            assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).err(),Some(GateError::InvalidState));
        }
        write_conf(&conf,&base,Some(&key));
        set_server_key(Path::new("/dev/null"));
        assert!(reader.server_public_key().is_err());
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).err(),Some(GateError::InvalidState));
        set_server_key(&original_key_file);
        // Removing the interface key can remove peers on some kernels.
        set_peer(&key,true);

        // Correct identity is insufficient if even one peer view differs.
        write_conf(&conf,&base,None);
        assert_eq!(read_verified_identity_snapshot(&store,IFACE,&expected).err(),Some(ConfigError::SnapshotMismatch));
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).err(),Some(GateError::InvalidState));
        let bad_token=request(&b64(&[78;32]),&signed);
        assert_eq!(prepare_consumed_retry(&store,&scope,&bad_token,IFACE).err(),Some(GateError::Forbidden));
        write_conf(&conf,&base,Some(&key));
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).unwrap().claims(),&claims);
        assert_eq!(store.generation().unwrap(),generation);
        assert_eq!(fs::read(root.join("authority-ledger.json")).unwrap(),ledger_before);
        assert_eq!(reader.snapshot().unwrap(),peers);
        drop(store);
        set_peer(&key,false);
        write_conf(&conf,&base,None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authenticated_fresh_enrollment_commits_real_peer_and_denies_replay_or_failed_reservation() {
        assert_eq!(unsafe {geteuid()}, 0);
        assert_eq!(std::env::var("SPIDERVPN_SEC01_NS_INTERFACE").unwrap(), IFACE);
        let expected=std::env::var("SPIDERVPN_SEC01_NS_SERVER_PUBLIC_KEY").unwrap();
        let key=std::env::var("SPIDERVPN_SEC01_NS_CLIENT_PUBLIC_KEY").unwrap();
        let reader=LiveWgReader::new(IFACE).unwrap();
        assert_eq!(reader.server_public_key().unwrap(), expected);
        assert!(reader.snapshot().unwrap().is_empty());
        let conf=Path::new("/etc/wireguard").join(format!("{IFACE}.conf"));
        let base=Zeroizing::new(fs::read_to_string(&conf).unwrap());
        assert!(!base.contains("[Peer]"));
        let root=test_ledger();
        let now=i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
        let issued=utc_at(now-60);
        let expires=utc_at(now+3600);
        let retry=utc_at(now+3720);
        let mgmt=Rsa::new(&root,"management.pem");
        let recipient=Rsa::new(&root,"recipient.pem");
        let binding=json!({"RemoteOwnerId":"55555555-5555-4555-8555-555555555555",
            "NodeId":"66666666-6666-4666-8666-666666666666","ServerPublicKey":expected});
        let fingerprint=format!("SHA256:{}",b64(digest::digest(&digest::SHA256,
            &serde_json::to_vec(&mgmt.jwk).unwrap()).as_ref()).replace('-',"+").replace('_',"/"));
        let pin="a".repeat(64);
        let token=b64(&[77;32]);
        let invite=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairInvite","InviteId":INV,
            "RemoteOwnerId":binding["RemoteOwnerId"],"NodeId":binding["NodeId"],
            "ServerPublicKey":expected,"ServerBinding":binding,
            "ManagementSigningPublicKey":mgmt.jwk,"IssuedAtUtc":issued,"ExpiresAtUtc":expires,
            "PublicEndpoint":"pair.example.test:18443","DeviceName":"netns fixture",
            "Capabilities":{"PairingVersion":1}});
        let descriptor=mgmt.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.OnlineInvite",
            "InviteId":INV,"Invite":mgmt.sign(&invite),"PublicHost":"pair.example.test","Port":18443,
            "TlsSha256":pin,"ManagementFingerprint":fingerprint,"ManagementSigningPublicKey":mgmt.jwk,
            "ExpiresAtUtc":expires,"RetryUntilUtc":retry}));
        let tag=hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256,token.as_bytes()),
            b"SpiderVPN pinned invitation metadata bearer v1");
        let metadata=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.InviteMetadata",
            "InviteId":INV,"BearerHmacSha256":hex(tag.as_ref()),"SignedDescriptor":descriptor,
            "ManagementSigningPublicKey":mgmt.jwk,"ManagementFingerprint":fingerprint,
            "ServerBinding":binding,"PublicHost":"pair.example.test","Port":18443,
            "TlsSha256":pin,"WgInterface":IFACE})).unwrap();
        let authenticated=verify_pinned_invite_metadata(&metadata,&sha(&metadata),&token).unwrap();
        let scope=authenticated.scope().unwrap();
        let inner=json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientRequest","RequestId":REQ,
            "DeviceId":DEV,"ClientPublicKey":key,"CreatedAtUtc":issued,"AddressFamilies":["IPv4"]});
        let request_digest=sha(format!("1\nTradeChannel.ClientRequest\n{REQ}\n{DEV}\n{issued}\n{key}\nIPv4").as_bytes());
        let signed=recipient.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest",
            "InviteId":INV,"ServerBinding":binding,"ClientRequest":inner,
            "DeviceName":"netns fixture","RecipientJwk":recipient.jwk,"RequestDigest":request_digest,
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued}));
        let req=request(&token,&signed);
        let pool=AddressPool{network:Ipv4Addr::new(10,66,0,0),prefix:24};
        let mut store=open(&root);
        store.update(|l|l.insert_open(INV,now+3600)).unwrap();
        let ledger_file=root.join("authority-ledger.json");
        let initial=fs::read(&ledger_file).unwrap();
        let generation=store.generation().unwrap();
        let bad_token=request(&b64(&[78;32]),&signed);
        assert!(matches!(enroll_fresh_consume(&mut store,&scope,&bad_token,IFACE,pool),
            Err(FreshEnrollError::Gate(GateError::Forbidden))));
        assert!(matches!(enroll_fresh_consume(&mut store,&scope,&req,"otherci0",pool),
            Err(FreshEnrollError::Gate(GateError::InvalidState))));
        // Real config identity denial before reserve: keep live inventory
        // empty while replacing only the protected test config key.
        let wrong_key=Command::new("/usr/bin/wg").arg("genkey")
            .stderr(Stdio::null()).output().unwrap();
        assert!(wrong_key.status.success());
        let wrong_key=Zeroizing::new(String::from_utf8(wrong_key.stdout).unwrap());
        let private=base.lines().find_map(|line|line.strip_prefix("PrivateKey = ")).unwrap();
        let wrong_conf=Zeroizing::new(base.replace(private,wrong_key.trim()));
        write_conf(&conf,&wrong_conf,None);
        assert!(matches!(enroll_fresh_consume(&mut store,&scope,&req,IFACE,pool),
            Err(FreshEnrollError::Apply(
                spidervpn_pairing_authority::wg_live_set::ApplyError::Readback(ConfigError::IdentityMismatch)))));
        write_conf(&conf,&base,None);
        assert_eq!(store.generation().unwrap(),generation);
        assert_eq!(fs::read(&ledger_file).unwrap(),initial);
        assert!(reader.snapshot().unwrap().is_empty());
        assert!(fs::read(&conf).unwrap().as_slice()==base.as_bytes());

        // Actual store_atomic destination validation failure AFTER the
        // existing store is locked and authenticated, not a fake ops hook.
        // A noncooperating fixture actor changes mode only in this temp root.
        fs::set_permissions(&ledger_file,fs::Permissions::from_mode(0o644)).unwrap();
        let failed=enroll_fresh_consume(&mut store,&scope,&req,IFACE,pool);
        fs::set_permissions(&ledger_file,fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(failed,Err(FreshEnrollError::Ledger(
            spidervpn_pairing_authority::ledger_disk::StoreError::Invalid(_)))));
        assert!(matches!(store.view(),Err(spidervpn_pairing_authority::ledger_disk::StoreError::Poisoned)));
        assert_eq!(fs::read(&ledger_file).unwrap(),initial);
        assert!(reader.snapshot().unwrap().is_empty());
        assert!(fs::read(&conf).unwrap().as_slice()==base.as_bytes());
        drop(store);
        let mut store=open(&root);
        assert_eq!(store.generation().unwrap(),generation);
        assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Open)));
        assert!(LedgerStore::open_existing(&root,Duration::from_millis(25)).is_err());

        // No manual config/peer provisioning or direct reserve/confirm in
        // this success control: the real adapter owns all three writes.
        let grant=enroll_fresh_consume(&mut store,&scope,&req,IFACE,pool).unwrap();
        assert_eq!(grant.claims.public_key,key);
        assert_eq!(grant.address,Ipv4Addr::new(10,66,0,2));
        assert_eq!(store.generation().unwrap(),generation+2);
        assert_eq!(store.view().unwrap().state(INV),Some(&InviteState::Consumed(grant.clone())));
        let observed=read_verified_identity_snapshot(&store,IFACE,&expected).unwrap();
        assert_eq!(observed,vec![spidervpn_pairing_authority::Peer {
            public_key:key.clone(),address:grant.address
        }]);
        let committed=fs::read(&ledger_file).unwrap();
        let committed_conf=Zeroizing::new(fs::read(&conf).unwrap());
        assert!(matches!(enroll_fresh_consume(&mut store,&scope,&req,IFACE,pool),
            Err(FreshEnrollError::Gate(GateError::InviteConsumed))));
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).unwrap().claims(),&grant.claims);
        #[cfg(feature = "linux-authorization-response")]
        {
            use rsa::pkcs8::DecodePrivateKey;
            use spidervpn_pairing_authority::authorization_response::TrustedResponseConfig;
            use spidervpn_pairing_authority::fresh_consume_gate::consume_authorization;
            let management_private=rsa::RsaPrivateKey::from_pkcs8_pem(
                &Zeroizing::new(fs::read_to_string(&mgmt.path).unwrap())).unwrap();
            let raw=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.AuthorizationConfig",
                "ServerBinding":binding,"WgInterface":IFACE,"TunnelSubnet":"10.66.0.0/24",
                "ServerAddress":"10.66.0.1/24","PublicEndpoint":"203.0.113.10:51820",
                "NodeName":"netns fixture","Transport":"udp"})).unwrap();
            let config=TrustedResponseConfig::verify_pinned(&raw,&sha(&raw)).unwrap();
            assert!(consume_authorization(&mut store,&scope,&req,IFACE,&config,&management_private).is_err());
        }
        assert_eq!(fs::read(&ledger_file).unwrap(),committed);
        assert!(fs::read(&conf).unwrap().as_slice()==committed_conf.as_slice());
        assert_eq!(reader.snapshot().unwrap(),observed);
        drop(store);
        let mut store=open(&root);
        assert_eq!(store.view().unwrap().state(INV),Some(&InviteState::Consumed(grant.clone())));
        assert_eq!(store.generation().unwrap(),generation+2);
        let revoking=store.update(|l|l.begin_revocation(INV)).unwrap();
        assert!(matches!(enroll_fresh_consume(&mut store,&scope,&req,IFACE,pool),
            Err(FreshEnrollError::Gate(GateError::Revoked))));
        spidervpn_pairing_authority::wg_live_set::apply_and_confirm(
            &mut store,IFACE,&revoking,spidervpn_pairing_authority::wg_peer_plan::Change::Remove
        ).unwrap();
        let revoked=fs::read(&ledger_file).unwrap();
        assert!(matches!(store.view().unwrap().state(INV),Some(InviteState::Revoked(_))));
        assert!(matches!(enroll_fresh_consume(&mut store,&scope,&req,IFACE,pool),
            Err(FreshEnrollError::Gate(GateError::Revoked))));
        assert_eq!(prepare_consumed_retry(&store,&scope,&req,IFACE).err(),Some(GateError::Revoked));
        assert_eq!(fs::read(&ledger_file).unwrap(),revoked);
        assert!(read_verified_identity_snapshot(&store,IFACE,&expected).unwrap().is_empty());
        drop(store);
        write_conf(&conf,&base,None);
        fs::remove_dir_all(root).unwrap();
    }

    // Independent consumer of the actual compact wire. Production uses
    // Hmac<Sha512> to seal and the client-compatible checks below use ring
    // for the RFC 7518 AAD/IV/ciphertext/AL tag and legacy RS256 verifier.
    // This is not an invocation of the Windows client executable.
    #[cfg(feature = "linux-authorization-response")]
    fn open_authorization(data:&Value, key:&rsa::RsaPrivateKey) -> Option<String> {
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
        let wire=data.get("EncryptedAuthorization")?.as_str()?;
        let parts:Vec<_>=wire.split('.').collect();
        if parts.len()!=5 || parts.iter().any(|s|s.is_empty()) { return None; }
        let header:Value=serde_json::from_slice(&B64.decode(parts[0]).ok()?).ok()?;
        if header!=json!({"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","cty":"TC-Pairing-v1"}) {
            return None;
        }
        let cek=Zeroizing::new(key.decrypt_blinded(&mut rsa::rand_core::OsRng,
            rsa::Oaep::new::<sha2::Sha256>(),&B64.decode(parts[1]).ok()?).ok()?);
        let iv=B64.decode(parts[2]).ok()?;
        let mut ciphertext=B64.decode(parts[3]).ok()?;
        let tag=B64.decode(parts[4]).ok()?;
        if cek.len()!=64 || iv.len()!=16 || tag.len()!=32
            || ciphertext.is_empty() || ciphertext.len()%16!=0 { return None; }
        let mac_key=hmac::Key::new(hmac::HMAC_SHA512,&cek[..32]);
        let mut mac=hmac::Context::with_key(&mac_key);
        mac.update(parts[0].as_bytes());
        mac.update(&iv);
        mac.update(&ciphertext);
        mac.update(&((parts[0].len() as u64)*8).to_be_bytes());
        if &mac.sign().as_ref()[..32]!=tag.as_slice() { return None; }
        let plaintext=cbc::Decryptor::<aes::Aes256>::new_from_slices(&cek[32..],&iv)
            .ok()?.decrypt_padded_mut::<Pkcs7>(&mut ciphertext).ok()?;
        String::from_utf8(plaintext.to_vec()).ok()
    }

    #[cfg(feature = "linux-authorization-response")]
    #[test]
    fn actual_signed_encrypted_consume_and_original_authorization_survive_reopen() {
        assert_eq!(unsafe {geteuid()}, 0);
        assert_eq!(std::env::var("SPIDERVPN_SEC01_NS_INTERFACE").unwrap(), IFACE);
        let expected=std::env::var("SPIDERVPN_SEC01_NS_SERVER_PUBLIC_KEY").unwrap();
        let key=std::env::var("SPIDERVPN_SEC01_NS_CLIENT_PUBLIC_KEY").unwrap();
        let reader=LiveWgReader::new(IFACE).unwrap();
        assert_eq!(reader.server_public_key().unwrap(), expected);
        assert!(reader.snapshot().unwrap().is_empty());
        let conf=Path::new("/etc/wireguard").join(format!("{IFACE}.conf"));
        let base=Zeroizing::new(fs::read_to_string(&conf).unwrap());
        assert!(!base.contains("[Peer]"));
        let root=test_ledger();
        let now=i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
        let issued=utc_at(now-60);
        let expires=utc_at(now+3600);
        let retry=utc_at(now+3720);
        let mgmt=Rsa::new(&root,"management.pem");
        let recipient=Rsa::new(&root,"recipient.pem");
        let binding=json!({"RemoteOwnerId":"55555555-5555-4555-8555-555555555555",
            "NodeId":"66666666-6666-4666-8666-666666666666","ServerPublicKey":expected});
        let fingerprint=format!("SHA256:{}",b64(digest::digest(&digest::SHA256,
            &serde_json::to_vec(&mgmt.jwk).unwrap()).as_ref()).replace('-',"+").replace('_',"/"));
        let pin="a".repeat(64);
        let token=b64(&[77;32]);
        let invite=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairInvite","InviteId":INV,
            "RemoteOwnerId":binding["RemoteOwnerId"],"NodeId":binding["NodeId"],
            "ServerPublicKey":expected,"ServerBinding":binding,
            "ManagementSigningPublicKey":mgmt.jwk,"IssuedAtUtc":issued,"ExpiresAtUtc":expires,
            "PublicEndpoint":"203.0.113.10:18443","DeviceName":"netns fixture",
            "Capabilities":{"PairingVersion":1}});
        let descriptor=mgmt.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.OnlineInvite",
            "InviteId":INV,"Invite":mgmt.sign(&invite),"PublicHost":"203.0.113.10","Port":18443,
            "TlsSha256":pin,"ManagementFingerprint":fingerprint,"ManagementSigningPublicKey":mgmt.jwk,
            "ExpiresAtUtc":expires,"RetryUntilUtc":retry}));
        let tag=hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256,token.as_bytes()),
            b"SpiderVPN pinned invitation metadata bearer v1");
        let metadata=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.InviteMetadata",
            "InviteId":INV,"BearerHmacSha256":hex(tag.as_ref()),"SignedDescriptor":descriptor,
            "ManagementSigningPublicKey":mgmt.jwk,"ManagementFingerprint":fingerprint,
            "ServerBinding":binding,"PublicHost":"203.0.113.10","Port":18443,
            "TlsSha256":pin,"WgInterface":IFACE})).unwrap();
        let authenticated=verify_pinned_invite_metadata(&metadata,&sha(&metadata),&token).unwrap();
        let scope=authenticated.scope().unwrap();
        let inner=json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientRequest","RequestId":REQ,
            "DeviceId":DEV,"ClientPublicKey":key,"CreatedAtUtc":issued,"AddressFamilies":["IPv4"]});
        let request_digest=sha(format!("1\nTradeChannel.ClientRequest\n{REQ}\n{DEV}\n{issued}\n{key}\nIPv4").as_bytes());
        let signed=recipient.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest",
            "InviteId":INV,"ServerBinding":binding,"ClientRequest":inner,
            "DeviceName":"netns fixture","RecipientJwk":recipient.jwk,"RequestDigest":request_digest,
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued}));
        let req=request_at(&token,&signed,"203.0.113.10:18443");
        let mut store=open(&root);
        store.update(|l|l.insert_open(INV,now+3600)).unwrap();
        let ledger_file=root.join("authority-ledger.json");
        let initial=fs::read(&ledger_file).unwrap();
        let generation=store.generation().unwrap();

        use rsa::pkcs8::DecodePrivateKey;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
        use spidervpn_pairing_authority::authorization_response::TrustedResponseConfig;
        use spidervpn_pairing_authority::fresh_consume_gate::consume_authorization;
        let management_private=rsa::RsaPrivateKey::from_pkcs8_pem(
            &Zeroizing::new(fs::read_to_string(&mgmt.path).unwrap())).unwrap();
        let recipient_private=rsa::RsaPrivateKey::from_pkcs8_pem(
            &Zeroizing::new(fs::read_to_string(&recipient.path).unwrap())).unwrap();
        let transport=json!({"Type":"tcp-reality","Server":"198.51.100.9","Port":8443,
            "Uuid":"77777777-7777-4777-8777-777777777777","ServerName":"gate.example.test",
            "RealityPublicKey":b64(&[7;32]),"RealityShortId":"aabbccdd"});
        let config_record=json!({"SchemaVersion":1,"Kind":"SpiderVPN.AuthorizationConfig",
            "ServerBinding":binding,"WgInterface":IFACE,"TunnelSubnet":"10.66.0.0/24",
            "ServerAddress":"10.66.0.1/24","PublicEndpoint":"203.0.113.10:51820",
            "NodeName":"netns fixture","Transport":transport});
        let raw=serde_json::to_vec(&config_record).unwrap();
        let config=TrustedResponseConfig::verify_pinned(&raw,&sha(&raw)).unwrap();
        assert!(TrustedResponseConfig::verify_pinned(&raw,&"0".repeat(64)).is_err());
        let mut wrong_binding=config_record.clone();
        wrong_binding["ServerBinding"]["NodeId"]=json!("88888888-8888-4888-8888-888888888888");
        let wrong=serde_json::to_vec(&wrong_binding).unwrap();
        let wrong=TrustedResponseConfig::verify_pinned(&wrong,&sha(&wrong)).unwrap();
        assert!(consume_authorization(&mut store,&scope,&req,IFACE,&wrong,&management_private).is_err());
        assert!(consume_authorization(&mut store,&scope,&req,IFACE,&config,&recipient_private).is_err());
        let bad_token=request_at(&b64(&[78;32]),&signed,"203.0.113.10:18443");
        assert!(matches!(consume_authorization(&mut store,&scope,&bad_token,IFACE,&config,&management_private),
            Err(FreshEnrollError::Gate(GateError::Forbidden))));
        let wrong_request=recipient.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest",
            "InviteId":INV,"ServerBinding":binding,"ClientRequest":inner,
            "DeviceName":"netns fixture","RecipientJwk":recipient.jwk,"RequestDigest":"0".repeat(64),
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued}));
        let wrong_request=request_at(&token,&wrong_request,"203.0.113.10:18443");
        assert!(consume_authorization(&mut store,&scope,&wrong_request,IFACE,&config,&management_private).is_err());
        // Actual protected config identity denial; no peer or grant written.
        let missing_key=Zeroizing::new("[Interface]\nAddress = 10.66.0.1/24\n".to_owned());
        write_conf(&conf,&missing_key,None);
        assert!(consume_authorization(&mut store,&scope,&req,IFACE,&config,&management_private).is_err());
        write_conf(&conf,&base,None);
        assert_eq!(store.generation().unwrap(),generation);
        assert!(fs::read(&ledger_file).unwrap()==initial);
        assert!(reader.snapshot().unwrap().is_empty());
        assert!(fs::read(&conf).unwrap().as_slice()==base.as_bytes());

        // Real atomic reservation failure after successful authentication and
        // encryption feasibility. Neither the response nor a peer may escape.
        fs::set_permissions(&ledger_file,fs::Permissions::from_mode(0o644)).unwrap();
        let failed=consume_authorization(&mut store,&scope,&req,IFACE,&config,&management_private);
        fs::set_permissions(&ledger_file,fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(failed,Err(FreshEnrollError::Ledger(
            spidervpn_pairing_authority::ledger_disk::StoreError::Invalid(_)))));
        assert!(store.view().is_err());
        assert!(fs::read(&ledger_file).unwrap()==initial);
        assert!(reader.snapshot().unwrap().is_empty());
        assert!(fs::read(&conf).unwrap().as_slice()==base.as_bytes());
        drop(store);
        let mut store=open(&root);

        let data=consume_authorization(&mut store,&scope,&req,IFACE,&config,&management_private).unwrap();
        assert!(data.as_object().unwrap().len()==4 && data["Status"]=="Authorized"
            && data["RequestId"]==REQ && data["RequestDigest"]==request_digest);
        let original=open_authorization(&data,&recipient_private).expect("recipient opens actual wire");
        assert!(open_authorization(&data,&management_private).is_none());
        let Some(InviteState::Consumed(grant))=store.view().unwrap().state(INV) else {
            panic!("actual response requires durable Consumed");
        };
        let grant=grant.clone();
        assert_eq!(grant.address,Ipv4Addr::new(10,66,0,2));
        assert_eq!(store.generation().unwrap(),generation+2);
        let observed=read_verified_identity_snapshot(&store,IFACE,&expected).unwrap();
        assert_eq!(observed,vec![spidervpn_pairing_authority::Peer {
            public_key:key.clone(),address:grant.address
        }]);
        // Existing independent RS256 and legacy record/binding verifier,
        // not a self-only test of the new sign/seal code.
        let old=json!({"State":"Consumed","SignedAuthorization":original,
            "RequestId":REQ,"DeviceId":DEV,"ClientPublicKey":key,
            "ClientAddress":"10.66.0.2/32","RequestDigest":request_digest,
            "RecipientJwkDigest":grant.claims.recipient_jwk_digest});
        assert!(spidervpn_pairing_authority::legacy_signed::audit_signed_consumed(
            INV,&old,&mgmt.jwk,&binding).is_ok());
        let body:Value=serde_json::from_slice(&B64.decode(original.split('.').nth(1).unwrap()).unwrap()).unwrap();
        let committed=fs::read(&ledger_file).unwrap();
        let doc:Value=serde_json::from_slice(&committed).unwrap();
        let material=&doc["authorization_material"][INV];
        let issued_unix=material["issued_unix"].as_i64().unwrap();
        let expires_unix=material["expires_unix"].as_i64().unwrap();
        assert!(issued_unix>=now && expires_unix==issued_unix+3600);
        assert!(material["signed"]==original);
        assert!(body["IssuedAtUtc"]==utc_at(issued_unix) && body["ExpiresAtUtc"]==utc_at(expires_unix));
        assert!(body["InviteId"]==INV && body["RequestId"]==REQ && body["DeviceId"]==DEV
            && body["ClientPublicKey"]==key && body["RequestDigest"]==request_digest
            && body["ServerBinding"]==binding && body["RemoteOwnerId"]==binding["RemoteOwnerId"]
            && body["NodeId"]==binding["NodeId"] && body["ConfigRevision"]==1
            && body["RecipientJwkDigest"]==grant.claims.recipient_jwk_digest);
        let response=&body["ClientResponse"];
        assert!(response==&json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientResponse",
            "Status":"Authorized","RequestId":REQ,"DeviceId":DEV,"NodeId":binding["NodeId"],
            "NodeName":"netns fixture","ClientPublicKey":key,"ServerPublicKey":expected,
            "ClientAddress":"10.66.0.2/32","ServerAddress":"10.66.0.1/24","TunnelSubnet":"10.66.0.0/24",
            "AllowedIPs":["0.0.0.0/0"],"AddressFamilies":["IPv4"],"PublicEndpoint":"203.0.113.10:51820",
            "PersistentKeepalive":25,"ConfigRevision":1,"Transport":transport}));
        let committed_conf=Zeroizing::new(fs::read(&conf).unwrap());
        drop(store);
        let mut store=open(&root);
        let retried=consume_authorization(&mut store,&scope,&req,IFACE,&config,&management_private).unwrap();
        assert!(open_authorization(&retried,&recipient_private).as_deref()==Some(original.as_str()));
        assert!(retried["EncryptedAuthorization"]!=data["EncryptedAuthorization"]);
        let changed_recipient=mgmt.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest",
            "InviteId":INV,"ServerBinding":binding,"ClientRequest":inner,
            "DeviceName":"netns fixture","RecipientJwk":mgmt.jwk,"RequestDigest":request_digest,
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued}));
        let changed_recipient=request_at(&token,&changed_recipient,"203.0.113.10:18443");
        assert!(matches!(consume_authorization(&mut store,&scope,&changed_recipient,IFACE,&config,&management_private),
            Err(FreshEnrollError::Gate(GateError::PairingMismatch))));
        let mut changed_config=config_record.clone();
        changed_config["PublicEndpoint"]=json!("203.0.113.10:51821");
        let changed=serde_json::to_vec(&changed_config).unwrap();
        let changed=TrustedResponseConfig::verify_pinned(&changed,&sha(&changed)).unwrap();
        assert!(consume_authorization(&mut store,&scope,&req,IFACE,&changed,&management_private).is_err());
        assert_eq!(store.generation().unwrap(),generation+2);
        assert!(fs::read(&ledger_file).unwrap()==committed);
        assert!(fs::read(&conf).unwrap().as_slice()==committed_conf.as_slice());
        assert_eq!(reader.snapshot().unwrap(),observed);

        let revoking=store.update(|l|l.begin_revocation(INV)).unwrap();
        assert!(matches!(consume_authorization(&mut store,&scope,&req,IFACE,&config,&management_private),
            Err(FreshEnrollError::Gate(GateError::Revoked))));
        spidervpn_pairing_authority::wg_live_set::apply_and_confirm(
            &mut store,IFACE,&revoking,spidervpn_pairing_authority::wg_peer_plan::Change::Remove
        ).unwrap();
        let revoked=fs::read(&ledger_file).unwrap();
        assert!(matches!(consume_authorization(&mut store,&scope,&req,IFACE,&config,&management_private),
            Err(FreshEnrollError::Gate(GateError::Revoked))));
        assert!(fs::read(&ledger_file).unwrap()==revoked);
        assert!(reader.snapshot().unwrap().is_empty());
        drop(store);
        write_conf(&conf,&base,None);
        fs::remove_dir_all(root).unwrap();
    }

}

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

    // One actual Stage 3 service integration test. Reuse the Stage 2
    // independently implemented JWE/RS256 reader and real netns fixture.
    #[cfg(feature = "linux-pairing-service")]
    #[test]
    fn actual_tls_get_consume_and_lost_reply_retry_use_same_authority() {
        use rsa::pkcs8::DecodePrivateKey;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
        use spidervpn_pairing_authority::authorization_response::TrustedResponseConfig;
        use spidervpn_pairing_authority::pairing_service::{
            PairingAuthority, ServiceReport, run_loopback_pairing_service,
        };
        use std::io::{BufRead, BufReader, Read};
        use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread::{self, JoinHandle};

        struct Running {
            stop: Arc<AtomicBool>,
            worker: Option<JoinHandle<std::io::Result<ServiceReport>>>,
            address: SocketAddr,
        }
        impl Running {
            fn start(authority: PairingAuthority) -> Self {
                let listener=TcpListener::bind("127.0.0.1:0").unwrap();
                let address=listener.local_addr().unwrap();
                let stop=Arc::new(AtomicBool::new(false));
                let signal=Arc::clone(&stop);
                let worker=thread::spawn(move ||
                    run_loopback_pairing_service(listener,authority,8,4,&signal));
                Self {stop,worker:Some(worker),address}
            }
            fn stop(mut self) -> ServiceReport {
                self.stop.store(true,Ordering::Release);
                self.worker.take().unwrap().join().unwrap().unwrap()
            }
        }
        impl Drop for Running {
            fn drop(&mut self) {
                self.stop.store(true,Ordering::Release);
                if let Some(worker)=self.worker.take() { let _=worker.join(); }
            }
        }
        fn client(address: SocketAddr, ca:&[u8], leaf:&[u8])
            -> StreamOwned<ClientConnection,TcpStream>
        {
            let mut roots=RootCertStore::empty();
            roots.add(CertificateDer::from(ca.to_vec())).unwrap();
            let config=Arc::new(ClientConfig::builder_with_provider(
                Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS12]).unwrap()
                .with_root_certificates(roots).with_no_client_auth());
            let mut connection=ClientConnection::new(config,
                ServerName::try_from("203.0.113.10").unwrap()).unwrap();
            let mut socket=TcpStream::connect_timeout(&address,Duration::from_secs(3)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(35))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            while connection.is_handshaking() { connection.complete_io(&mut socket).unwrap(); }
            assert!(connection.protocol_version()==Some(rustls::ProtocolVersion::TLSv1_2));
            // Independently validate trust chain + exact pinned leaf before
            // any request is written, not just a successful TLS handshake.
            assert!(connection.peer_certificates().unwrap()[0].as_ref()==leaf);
            StreamOwned::new(connection,socket)
        }
        fn wire(method:&str, host:&str, token:&str, body:Option<&[u8]>) -> Vec<u8> {
            let suffix=if method=="POST" {"/consume"} else {""};
            let mut head=format!("{method} /v1/invitations/{INV}{suffix} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n");
            if let Some(body)=body {
                head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n",body.len()));
            }
            head.push_str("\r\n");
            let mut bytes=head.into_bytes();
            if let Some(body)=body { bytes.extend_from_slice(body); }
            bytes
        }
        fn exchange(address:SocketAddr, ca:&[u8], leaf:&[u8], wire:&[u8]) -> (u16,Value) {
            let mut tls=client(address,ca,leaf);
            tls.write_all(wire).unwrap();
            tls.flush().unwrap();
            let mut response=Vec::new();
            tls.read_to_end(&mut response).unwrap();
            assert!(response.len()<=131_072+1024);
            let text=String::from_utf8(response).unwrap();
            let (head,body)=text.split_once("\r\n\r\n").unwrap();
            let mut lines=head.split("\r\n");
            let status=lines.next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
            assert!(head.contains("\r\nContent-Type: application/json\r\n"));
            assert!(head.ends_with("\r\nConnection: close"));
            let lengths:Vec<_>=lines.filter_map(|s|s.strip_prefix("Content-Length: ")).collect();
            assert!(lengths.len()==1 && lengths[0].parse::<usize>().unwrap()==body.len());
            (status,serde_json::from_str(body).unwrap())
        }

        assert_eq!(unsafe {geteuid()},0);
        assert_eq!(std::env::var("SPIDERVPN_SEC01_NS_INTERFACE").unwrap(),IFACE);
        let expected=std::env::var("SPIDERVPN_SEC01_NS_SERVER_PUBLIC_KEY").unwrap();
        let key=std::env::var("SPIDERVPN_SEC01_NS_CLIENT_PUBLIC_KEY").unwrap();
        let reader=LiveWgReader::new(IFACE).unwrap();
        assert!(reader.snapshot().unwrap().is_empty());
        assert!(reader.server_public_key().unwrap()==expected);
        let conf=Path::new("/etc/wireguard").join(format!("{IFACE}.conf"));
        let base=Zeroizing::new(fs::read_to_string(&conf).unwrap());
        let root=test_ledger();
        // Test-only CA and leaf, not a production identity or signer.
        let openssl=|args:&[&str]| {
            assert!(Command::new("/usr/bin/openssl").args(args).current_dir(&root)
                .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
        };
        openssl(&["req","-x509","-newkey","rsa:2048","-nodes","-days","1",
            "-subj","/CN=SpiderVPN-Stage3-Fixture-CA","-addext","basicConstraints=critical,CA:TRUE",
            "-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout","ca.key","-out","ca.pem"]);
        openssl(&["req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=203.0.113.10",
            "-keyout","tls.key","-out","tls.csr"]);
        fs::write(root.join("tls.ext"),"subjectAltName=IP:203.0.113.10\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        openssl(&["x509","-req","-in","tls.csr","-CA","ca.pem","-CAkey","ca.key","-CAcreateserial",
            "-days","1","-sha256","-extfile","tls.ext","-out","tls.pem"]);
        openssl(&["x509","-in","ca.pem","-outform","DER","-out","ca.der"]);
        openssl(&["x509","-in","tls.pem","-outform","DER","-out","tls.der"]);
        openssl(&["pkcs8","-topk8","-nocrypt","-in","tls.key","-outform","DER","-out","tls.key.der"]);
        let ca=fs::read(root.join("ca.der")).unwrap();
        let leaf=fs::read(root.join("tls.der")).unwrap();
        let tls_key=Zeroizing::new(fs::read(root.join("tls.key.der")).unwrap());
        let pin=sha(&leaf);
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
        let meta_pin=sha(&metadata);
        let config_record=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.AuthorizationConfig",
            "ServerBinding":binding,"WgInterface":IFACE,"TunnelSubnet":"10.66.0.0/24",
            "ServerAddress":"10.66.0.1/24","PublicEndpoint":"203.0.113.10:51820",
            "NodeName":"netns fixture","Transport":"udp"})).unwrap();
        let management_private=rsa::RsaPrivateKey::from_pkcs8_pem(
            &Zeroizing::new(fs::read_to_string(&mgmt.path).unwrap())).unwrap();
        let recipient_private=rsa::RsaPrivateKey::from_pkcs8_pem(
            &Zeroizing::new(fs::read_to_string(&recipient.path).unwrap())).unwrap();
        let authority=|tls_pin:&str| PairingAuthority::new(
            root.clone(),IFACE.to_owned(),metadata.clone(),meta_pin.clone(),
            TrustedResponseConfig::verify_pinned(&config_record,&sha(&config_record)).unwrap(),
            management_private.clone(),vec![CertificateDer::from(leaf.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls_key.to_vec())),tls_pin.to_owned());
        assert!(authority(&"0".repeat(64)).is_err());

        let inner=json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientRequest","RequestId":REQ,
            "DeviceId":DEV,"ClientPublicKey":key,"CreatedAtUtc":issued,"AddressFamilies":["IPv4"]});
        let request_digest=sha(format!("1\nTradeChannel.ClientRequest\n{REQ}\n{DEV}\n{issued}\n{key}\nIPv4").as_bytes());
        let pair_request=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest",
            "InviteId":INV,"ServerBinding":binding,"ClientRequest":inner,
            "DeviceName":"netns fixture","RecipientJwk":recipient.jwk,"RequestDigest":request_digest,
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued});
        let body=serde_json::to_vec(&json!({"PairRequest":recipient.sign(&pair_request)})).unwrap();
        let host="203.0.113.10:18443";
        let get=wire("GET",host,&token,None);
        let post=wire("POST",host,&token,Some(&body));
        let mut store=open(&root);
        store.update(|l|l.insert_open(INV,now+3600)).unwrap();
        let generation=store.generation().unwrap();
        let ledger=root.join("authority-ledger.json");
        let initial=fs::read(&ledger).unwrap();
        drop(store);

        let service=Running::start(authority(&pin).unwrap());
        let addr=service.address;
        let send=|w:&[u8]| exchange(addr,&ca,&leaf,w);
        // Real TLS refusal for invalid bearer and malformed HTTP.
        let wrong_token=b64(&[78;32]);
        assert!(send(&wire("GET",host,&wrong_token,None))==(403,json!({"Ok":false,"Code":"Forbidden"})));
        assert!(send(&wire("POST",host,&wrong_token,Some(&body)))==(403,json!({"Ok":false,"Code":"Forbidden"})));
        let mut malformed=get.clone();
        malformed[..3].copy_from_slice(b"BAD");
        assert!(send(&malformed)==(400,json!({"Ok":false,"Code":"InvalidRequest"})));
        let mut wrong=pair_request.clone();
        wrong["ServerBinding"]["NodeId"]=json!("88888888-8888-4888-8888-888888888888");
        let wrong_body=serde_json::to_vec(&json!({"PairRequest":recipient.sign(&wrong)})).unwrap();
        let (status,denial)=send(&wire("POST",host,&token,Some(&wrong_body)));
        assert!(status!=200 && denial["Ok"]==false && denial.get("Data").is_none());
        assert!(send(&wire("GET","wrong.example:18443",&token,None))==
            (409,json!({"Ok":false,"Code":"InviteMismatch"})));
        // Plaintext sent to the actual TLS listener can never reach dispatch.
        let mut plaintext=TcpStream::connect(addr).unwrap();
        plaintext.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        plaintext.write_all(&get).unwrap();
        plaintext.shutdown(Shutdown::Write).unwrap();
        let mut rejected=Vec::new();
        let _=plaintext.read_to_end(&mut rejected);
        assert!(!rejected.windows(b"HTTP/1.1".len()).any(|w|w==b"HTTP/1.1"));
        drop(plaintext);
        // Cross-process authority exclusion is fail-fast, not queued work.
        let busy=open(&root);
        assert!(send(&get)==(500,json!({"Ok":false,"Code":"InvalidState"})));
        drop(busy);
        let (status,descriptor_reply)=send(&get);
        assert!(status==200 && descriptor_reply==json!({"Ok":true,
            "Data":{"Status":"InvitationReady","SignedDescriptor":descriptor}}));
        assert!(fs::read(&ledger).unwrap()==initial);
        assert!(fs::read(&conf).unwrap().as_slice()==base.as_bytes());
        assert!(reader.snapshot().unwrap().is_empty());

        // Actual GET -> POST success through encrypted HTTP, not a direct
        // call to the Stage 2 adapter. Verify independent wire decryption,
        // legacy signature/binding and actual committed kernel peer.
        let (status,reply)=send(&post);
        assert!(status==200 && reply["Ok"]==true && reply.as_object().unwrap().len()==2);
        let data=&reply["Data"];
        assert!(data["Status"]=="Authorized" && data["RequestId"]==REQ
            && data["RequestDigest"]==request_digest);
        let original=open_authorization(data,&recipient_private).expect("TLS authorization decrypts");
        let store=open(&root);
        let Some(InviteState::Consumed(grant))=store.view().unwrap().state(INV) else {
            panic!("TLS reply without durable consumed grant");
        };
        let grant=grant.clone();
        assert_eq!(store.generation().unwrap(),generation+2);
        assert_eq!(grant.address,Ipv4Addr::new(10,66,0,2));
        let observed=read_verified_identity_snapshot(&store,IFACE,&expected).unwrap();
        assert_eq!(observed,vec![spidervpn_pairing_authority::Peer{
            public_key:key.clone(),address:grant.address}]);
        assert!(spidervpn_pairing_authority::legacy_signed::audit_signed_consumed(INV,
            &json!({"State":"Consumed","SignedAuthorization":original,
                "RequestId":REQ,"DeviceId":DEV,"ClientPublicKey":key,
                "ClientAddress":"10.66.0.2/32","RequestDigest":request_digest,
                "RecipientJwkDigest":grant.claims.recipient_jwk_digest}),&mgmt.jwk,&binding).is_ok());
        let committed=fs::read(&ledger).unwrap();
        let material:Value=serde_json::from_slice(&committed).unwrap();
        assert!(material["authorization_material"][INV]["signed"]==original);
        let committed_conf=Zeroizing::new(fs::read(&conf).unwrap());
        drop(store);

        // Client disconnects after an authorized retry's status line,
        // discarding its response payload. Drain and reopen the real service.
        let mut lost=client(addr,&ca,&leaf);
        lost.write_all(&post).unwrap();
        lost.flush().unwrap();
        let mut lost=BufReader::new(lost);
        let mut status_line=String::new();
        lost.read_line(&mut status_line).unwrap();
        assert!(status_line.starts_with("HTTP/1.1 200 "));
        let _=lost.get_mut().sock.shutdown(Shutdown::Both);
        drop(lost);
        let report=service.stop();
        assert!(report.peak_workers<=4 && report.completed>=8 && report.failed>=1);
        assert!(TcpStream::connect_timeout(&addr,Duration::from_millis(200)).is_err());

        let reopened=Running::start(authority(&pin).unwrap());
        let (status,retried)=exchange(reopened.address,&ca,&leaf,&post);
        assert!(status==200 && retried["Ok"]==true);
        assert!(open_authorization(&retried["Data"],&recipient_private).as_deref()==Some(original.as_str()));
        assert!(retried["Data"]["EncryptedAuthorization"]!=data["EncryptedAuthorization"]);
        assert!(fs::read(&ledger).unwrap()==committed);
        assert!(fs::read(&conf).unwrap().as_slice()==committed_conf.as_slice());
        assert_eq!(reader.snapshot().unwrap(),observed);
        let mut store=open(&root);
        assert_eq!(store.generation().unwrap(),generation+2);
        let revoking=store.update(|l|l.begin_revocation(INV)).unwrap();
        spidervpn_pairing_authority::wg_live_set::apply_and_confirm(
            &mut store,IFACE,&revoking,spidervpn_pairing_authority::wg_peer_plan::Change::Remove).unwrap();
        let revoked=fs::read(&ledger).unwrap();
        drop(store);
        assert!(exchange(reopened.address,&ca,&leaf,&post)==(403,json!({"Ok":false,"Code":"Revoked"})));
        assert!(exchange(reopened.address,&ca,&leaf,&get)==(403,json!({"Ok":false,"Code":"Revoked"})));
        assert!(fs::read(&ledger).unwrap()==revoked);
        assert!(reader.snapshot().unwrap().is_empty());
        let report=reopened.stop();
        assert!(report.completed==3);
        // The actual service keeps one kernel-source cap across TLS and
        // request phases. Start a fresh accept loop, with no prior worker
        // racing the saturation control. Four silent connections consume
        // this source's slots; a fifth is closed rather than queued.
        let limited=Running::start(authority(&pin).unwrap());
        let slow:Vec<_>=(0..4).map(|_|TcpStream::connect(limited.address).unwrap()).collect();
        let mut saturated=TcpStream::connect(limited.address).unwrap();
        saturated.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut byte=[0u8;1];
        let denied=saturated.read(&mut byte);
        assert!(matches!(denied,Ok(0)) || denied.is_err_and(|e|
            matches!(e.kind(),std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::ConnectionAborted)));
        drop(saturated);
        drop(slow);
        let report=limited.stop();
        assert!(report.completed==0 && report.source_rejected>=1 && report.peak_workers==4);
        write_conf(&conf,&base,None);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "linux-pairing-process")]
    #[test]
    fn actual_pair_service_process_get_first_retry_after_term_and_restart() {
        use rsa::pkcs8::DecodePrivateKey;
        use rustls::pki_types::{CertificateDer, ServerName};
        use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
        use std::io::Read;
        use std::net::{SocketAddr,TcpStream};
        use std::process::Child;
        use std::sync::Arc;
        use std::time::Instant;

        // Only this test creates fresh disposable authority state. The
        // actual executable cannot bootstrap, restore or import a ledger.
        fn fixture_root(root:&Path) {
            fs::create_dir(root).unwrap();
            fs::set_permissions(root,fs::Permissions::from_mode(0o700)).unwrap();
            protected(root,"authority-ledger.json",
                br#"{"schema_version":1,"generation":1,"ledger":{"invitations":{},"revoked_devices":[],"revoked_keys":[]}}"#);
            fs::File::open(root).unwrap().sync_all().unwrap();
        }
        fn protected(root:&Path,name:&str,bytes:&[u8]) {
            let mut file=OpenOptions::new().create_new(true).write(true).mode(0o600)
                .open(root.join(name)).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        struct Process(Option<Child>);
        impl Drop for Process {
            fn drop(&mut self) {
                if let Some(mut child)=self.0.take() {
                    let _=child.kill();
                    let _=child.wait();
                }
            }
        }
        impl Process {
            fn spawn(root:&Path,meta:&str,config:&str,tls:&str) -> Self {
                Self(Some(Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-service"))
                    .env_clear().args(["serve",root.to_str().unwrap(),"18443",IFACE,meta,config,tls])
                    .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
                    .spawn().unwrap()))
            }
            fn ready(&mut self,addr:SocketAddr) {
                let deadline=Instant::now()+Duration::from_secs(10);
                loop {
                    assert!(self.0.as_mut().unwrap().try_wait().unwrap().is_none(),"service exited before bind");
                    if TcpStream::connect_timeout(&addr,Duration::from_millis(100)).is_ok() { break; }
                    assert!(Instant::now()<deadline,"service startup timed out");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            fn finish(mut self,timeout:Duration) -> Output {
                let deadline=Instant::now()+timeout;
                while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
                    assert!(Instant::now()<deadline,"process did not exit");
                    std::thread::sleep(Duration::from_millis(20));
                }
                self.0.take().unwrap().wait_with_output().unwrap()
            }
            fn stop(self,signal:libc::c_int) {
                let pid=self.0.as_ref().unwrap().id();
                assert_eq!(unsafe {libc::kill(pid as libc::pid_t,signal)},0);
                let out=self.finish(Duration::from_secs(35));
                assert!(out.status.success() && out.stderr.is_empty());
                assert!(out.stdout==b"PAIR_SERVICE_READY\nPAIR_SERVICE_STOPPED\n");
            }
            fn refused(self) {
                let out=self.finish(Duration::from_secs(10));
                assert!(out.status.code()==Some(2) && out.stdout.is_empty());
                assert!(out.stderr==b"spidervpn-pair-service: protected provisioning refused\n");
            }
        }
        fn client(address: SocketAddr, ca:&[u8], leaf:&[u8])
            -> StreamOwned<ClientConnection,TcpStream>
        {
            let mut roots=RootCertStore::empty();
            roots.add(CertificateDer::from(ca.to_vec())).unwrap();
            let config=Arc::new(ClientConfig::builder_with_provider(
                Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS12]).unwrap()
                .with_root_certificates(roots).with_no_client_auth());
            let mut connection=ClientConnection::new(config,
                ServerName::try_from("203.0.113.10").unwrap()).unwrap();
            let mut socket=TcpStream::connect_timeout(&address,Duration::from_secs(3)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(35))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            while connection.is_handshaking() { connection.complete_io(&mut socket).unwrap(); }
            assert!(connection.protocol_version()==Some(rustls::ProtocolVersion::TLSv1_2));
            // Independently validate trust chain + exact pinned leaf before
            // any request is written, not just a successful TLS handshake.
            assert!(connection.peer_certificates().unwrap()[0].as_ref()==leaf);
            StreamOwned::new(connection,socket)
        }
        fn wire(method:&str, host:&str, token:&str, body:Option<&[u8]>) -> Vec<u8> {
            let suffix=if method=="POST" {"/consume"} else {""};
            let mut head=format!("{method} /v1/invitations/{INV}{suffix} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n");
            if let Some(body)=body {
                head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n",body.len()));
            }
            head.push_str("\r\n");
            let mut bytes=head.into_bytes();
            if let Some(body)=body { bytes.extend_from_slice(body); }
            bytes
        }
        fn exchange(address:SocketAddr, ca:&[u8], leaf:&[u8], wire:&[u8]) -> (u16,Value) {
            let mut tls=client(address,ca,leaf);
            tls.write_all(wire).unwrap();
            tls.flush().unwrap();
            let mut response=Vec::new();
            tls.read_to_end(&mut response).unwrap();
            assert!(response.len()<=131_072+1024);
            let text=String::from_utf8(response).unwrap();
            let (head,body)=text.split_once("\r\n\r\n").unwrap();
            let mut lines=head.split("\r\n");
            let status=lines.next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
            assert!(head.contains("\r\nContent-Type: application/json\r\n"));
            assert!(head.ends_with("\r\nConnection: close"));
            let lengths:Vec<_>=lines.filter_map(|s|s.strip_prefix("Content-Length: ")).collect();
            assert!(lengths.len()==1 && lengths[0].parse::<usize>().unwrap()==body.len());
            (status,serde_json::from_str(body).unwrap())
        }

        assert_eq!(unsafe {geteuid()},0);
        assert_eq!(std::env::var("SPIDERVPN_SEC01_NS_INTERFACE").unwrap(),IFACE);
        let expected=std::env::var("SPIDERVPN_SEC01_NS_SERVER_PUBLIC_KEY").unwrap();
        let key=std::env::var("SPIDERVPN_SEC01_NS_CLIENT_PUBLIC_KEY").unwrap();
        let reader=LiveWgReader::new(IFACE).unwrap();
        assert!(reader.snapshot().unwrap().is_empty());
        assert!(reader.server_public_key().unwrap()==expected);
        let conf=Path::new("/etc/wireguard").join(format!("{IFACE}.conf"));
        let base=Zeroizing::new(fs::read_to_string(&conf).unwrap());
        let root=PathBuf::from(format!("/run/spidervpn-pair-service-ci-{}",std::process::id()));
        fixture_root(&root);
        // Test-only CA and leaf, not a production identity or signer.
        let openssl=|args:&[&str]| {
            assert!(Command::new("/usr/bin/openssl").args(args).current_dir(&root)
                .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
        };
        openssl(&["req","-x509","-newkey","rsa:2048","-nodes","-days","1",
            "-subj","/CN=SpiderVPN-Stage4A-Fixture-CA","-addext","basicConstraints=critical,CA:TRUE",
            "-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout","ca.key","-out","ca.pem"]);
        openssl(&["req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=203.0.113.10",
            "-keyout","tls.key","-out","tls.csr"]);
        fs::write(root.join("tls.ext"),"subjectAltName=IP:203.0.113.10\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        openssl(&["x509","-req","-in","tls.csr","-CA","ca.pem","-CAkey","ca.key","-CAcreateserial",
            "-days","1","-sha256","-extfile","tls.ext","-out","tls.pem"]);
        openssl(&["x509","-in","ca.pem","-outform","DER","-out","ca.der"]);
        openssl(&["x509","-in","tls.pem","-outform","DER","-out","tls.der"]);
        let ca=fs::read(root.join("ca.der")).unwrap();
        let leaf=fs::read(root.join("tls.der")).unwrap();
        let pin=sha(&leaf);
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
        let meta_pin=sha(&metadata);
        let config_record=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.AuthorizationConfig",
            "ServerBinding":binding,"WgInterface":IFACE,"TunnelSubnet":"10.66.0.0/24",
            "ServerAddress":"10.66.0.1/24","PublicEndpoint":"203.0.113.10:51820",
            "NodeName":"netns fixture","Transport":"udp"})).unwrap();
        fs::rename(root.join("tls.pem"),root.join("tls.crt")).unwrap();
        fs::set_permissions(root.join("tls.key"),fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&mgmt.path,root.join("management.key")).unwrap();
        fs::set_permissions(root.join("management.key"),fs::Permissions::from_mode(0o600)).unwrap();
        protected(&root,"invite-metadata.json",&metadata);
        protected(&root,"authorization-config.json",&config_record);
        let config_pin=sha(&config_record);
        // Establish the trusted current Open record before startup denial
        // controls, so their failures cannot be attributed to no invite.
        let mut store=open(&root);
        store.update(|l|l.insert_open(INV,now+3600)).unwrap();
        let generation=store.generation().unwrap();
        let ledger=root.join("authority-ledger.json");
        let initial=fs::read(&ledger).unwrap();
        drop(store);
        let recipient_private=rsa::RsaPrivateKey::from_pkcs8_pem(
            &Zeroizing::new(fs::read_to_string(&recipient.path).unwrap())).unwrap();
        let addr:SocketAddr="127.0.0.1:18443".parse().unwrap();
        let start=||Process::spawn(&root,&meta_pin,&config_pin,&pin);
        // Bad independent pin and absent ledger must fail before bind.
        Process::spawn(&root,&meta_pin,&config_pin,&"0".repeat(64)).refused();
        let ledger_path=root.join("authority-ledger.json");
        let absent=root.join("fixture-ledger-not-present");
        fs::rename(&ledger_path,&absent).unwrap();
        start().refused();
        assert!(!ledger_path.exists());
        fs::rename(&absent,&ledger_path).unwrap();
        assert!(TcpStream::connect_timeout(&addr,Duration::from_millis(100)).is_err());

        // Expired invite on a separate disposable fixture; never rewind the
        // state of the process that will perform the real enrollment.
        let expired_root=PathBuf::from(format!("{}-expired",root.display()));
        fixture_root(&expired_root);
        for name in ["tls.crt","tls.key","management.key","authorization-config.json"] {
            protected(&expired_root,name,&Zeroizing::new(fs::read(root.join(name)).unwrap()));
        }
        let expired_at=now-121;
        let mut expired_invite=invite.clone();
        expired_invite["IssuedAtUtc"]=json!(utc_at(now-300));
        expired_invite["ExpiresAtUtc"]=json!(utc_at(expired_at));
        // The same independent management fixture signer is now at its
        // protected service basename.
        let signer=Rsa{path:root.join("management.key"),jwk:mgmt.jwk.clone()};
        let expired_descriptor=signer.sign(&json!({"SchemaVersion":1,"Kind":"TradeChannel.OnlineInvite",
            "InviteId":INV,"Invite":signer.sign(&expired_invite),"PublicHost":"203.0.113.10","Port":18443,
            "TlsSha256":pin,"ManagementFingerprint":fingerprint,"ManagementSigningPublicKey":mgmt.jwk,
            "ExpiresAtUtc":utc_at(expired_at),"RetryUntilUtc":utc_at(expired_at+120)}));
        let mut expired_metadata:Value=serde_json::from_slice(&metadata).unwrap();
        expired_metadata["SignedDescriptor"]=json!(expired_descriptor);
        let expired_raw=serde_json::to_vec(&expired_metadata).unwrap();
        protected(&expired_root,"invite-metadata.json",&expired_raw);
        let mut expired_store=open(&expired_root);
        expired_store.update(|l|l.insert_open(INV,expired_at)).unwrap();
        drop(expired_store);
        let expired_ledger=fs::read(expired_root.join("authority-ledger.json")).unwrap();
        let mut expired_service=Process::spawn(&expired_root,&sha(&expired_raw),&config_pin,&pin);
        expired_service.ready(addr);
        assert!(exchange(addr,&ca,&leaf,&wire("GET","203.0.113.10:18443",&token,None))==
            (410,json!({"Ok":false,"Code":"InviteExpired"})));
        expired_service.stop(libc::SIGTERM);
        assert!(fs::read(expired_root.join("authority-ledger.json")).unwrap()==expired_ledger);
        assert!(reader.snapshot().unwrap().is_empty());
        fs::remove_dir_all(expired_root).unwrap();

        let inner=json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientRequest","RequestId":REQ,
            "DeviceId":DEV,"ClientPublicKey":key,"CreatedAtUtc":issued,"AddressFamilies":["IPv4"]});
        let request_digest=sha(format!("1\nTradeChannel.ClientRequest\n{REQ}\n{DEV}\n{issued}\n{key}\nIPv4").as_bytes());
        let pair_request=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest",
            "InviteId":INV,"ServerBinding":binding,"ClientRequest":inner,
            "DeviceName":"netns fixture","RecipientJwk":recipient.jwk,"RequestDigest":request_digest,
            "RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued});
        let body=serde_json::to_vec(&json!({"PairRequest":recipient.sign(&pair_request)})).unwrap();
        let host="203.0.113.10:18443";
        let get=wire("GET",host,&token,None);
        let post=wire("POST",host,&token,Some(&body));
        assert!(fs::read(&ledger).unwrap()==initial);

        let mut service=start();
        service.ready(addr);
        let send=|w:&[u8]|exchange(addr,&ca,&leaf,w);
        let wrong_token=b64(&[78;32]);
        assert!(send(&wire("GET",host,&wrong_token,None))==(403,json!({"Ok":false,"Code":"Forbidden"})));
        assert!(send(&get)==(200,json!({"Ok":true,"Data":{
            "Status":"InvitationReady","SignedDescriptor":descriptor}})));
        assert!(fs::read(&ledger).unwrap()==initial && reader.snapshot().unwrap().is_empty());
        let (status,reply)=send(&post);
        assert!(status==200 && reply["Ok"]==true && reply.as_object().unwrap().len()==2);
        let data=&reply["Data"];
        assert!(data["Status"]=="Authorized" && data["RequestId"]==REQ
            && data["RequestDigest"]==request_digest);
        let original=open_authorization(data,&recipient_private).expect("TLS authorization decrypts");
        let store=open(&root);
        let Some(InviteState::Consumed(grant))=store.view().unwrap().state(INV) else {
            panic!("TLS reply without durable consumed grant");
        };
        let grant=grant.clone();
        assert_eq!(store.generation().unwrap(),generation+2);
        assert_eq!(grant.address,Ipv4Addr::new(10,66,0,2));
        let observed=read_verified_identity_snapshot(&store,IFACE,&expected).unwrap();
        assert_eq!(observed,vec![spidervpn_pairing_authority::Peer{
            public_key:key.clone(),address:grant.address}]);
        assert!(spidervpn_pairing_authority::legacy_signed::audit_signed_consumed(INV,
            &json!({"State":"Consumed","SignedAuthorization":original,
                "RequestId":REQ,"DeviceId":DEV,"ClientPublicKey":key,
                "ClientAddress":"10.66.0.2/32","RequestDigest":request_digest,
                "RecipientJwkDigest":grant.claims.recipient_jwk_digest}),&mgmt.jwk,&binding).is_ok());
        let committed=fs::read(&ledger).unwrap();
        let material:Value=serde_json::from_slice(&committed).unwrap();
        assert!(material["authorization_material"][INV]["signed"]==original);
        let committed_conf=Zeroizing::new(fs::read(&conf).unwrap());
        drop(store);

        service.stop(libc::SIGTERM);
        assert!(TcpStream::connect_timeout(&addr,Duration::from_millis(100)).is_err());

        // Exactly the client GET-first resume order on a new executable
        // instance, same root, same pins, no new grant or renewal.
        let mut restarted=start();
        restarted.ready(addr);
        assert!(send(&get)==(200,json!({"Ok":true,"Data":{
            "Status":"RetryOnly","SignedDescriptor":descriptor}})));
        assert!(send(&wire("GET",host,&wrong_token,None))==(403,json!({"Ok":false,"Code":"Forbidden"})));
        let (status,retried)=send(&post);
        assert!(status==200 && retried["Ok"]==true);
        assert!(open_authorization(&retried["Data"],&recipient_private).as_deref()==Some(original.as_str()));
        assert!(retried["Data"]["EncryptedAuthorization"]!=data["EncryptedAuthorization"]);
        assert!(fs::read(&ledger).unwrap()==committed);
        assert!(fs::read(&conf).unwrap().as_slice()==committed_conf.as_slice());
        assert_eq!(reader.snapshot().unwrap(),observed);
        let mut store=open(&root);
        assert_eq!(store.generation().unwrap(),generation+2);
        let revoking=store.update(|l|l.begin_revocation(INV)).unwrap();
        spidervpn_pairing_authority::wg_live_set::apply_and_confirm(&mut store,IFACE,&revoking,
            spidervpn_pairing_authority::wg_peer_plan::Change::Remove).unwrap();
        let revoked=fs::read(&ledger).unwrap();
        drop(store);
        assert!(send(&get)==(403,json!({"Ok":false,"Code":"Revoked"})));
        assert!(send(&post)==(403,json!({"Ok":false,"Code":"Revoked"})));
        restarted.stop(libc::SIGINT);
        assert!(TcpStream::connect_timeout(&addr,Duration::from_millis(100)).is_err());
        assert!(fs::read(&ledger).unwrap()==revoked && reader.snapshot().unwrap().is_empty());
        write_conf(&conf,&base,None);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "linux-fresh-provisioning")]
    #[test]
    fn actual_fresh_init_tci1_to_native_service_and_real_peer() {
        use spidervpn_pairing_authority::wg_conf_audit::require_exact_match;
        use rsa::pkcs8::DecodePrivateKey;
        use rustls::pki_types::{CertificateDer, ServerName};
        use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64,Engine};
        use std::io::Read;
        use std::net::{SocketAddr,TcpStream};
        use std::process::Child;
        use std::sync::Arc;
        use std::time::Instant;
        // Independent legacy RS256 wire verification with the fixture's
        // independently supplied public JWK, not the server's private helper.
        fn verify_legacy(s:&str,jwk:&Value)->Value {
            let parts:Vec<_>=s.split('.').collect();
            assert_eq!(parts.len(),3);
            let head:Value=serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
            assert!(head==json!({"alg":"RS256","typ":"JWT"}));
            let n=B64.decode(jwk["n"].as_str().unwrap()).unwrap();
            let e=B64.decode(jwk["e"].as_str().unwrap()).unwrap();
            let sig=B64.decode(parts[2]).unwrap();
            let input=format!("{}.{}",parts[0],parts[1]);
            ring::signature::RsaPublicKeyComponents{n:&n,e:&e}
                .verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256,input.as_bytes(),&sig).unwrap();
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap()
        }
        fn protected(root:&Path,name:&str,bytes:&[u8]) {
            let mut file=OpenOptions::new().create_new(true).write(true).mode(0o600)
                .open(root.join(name)).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        struct Process(Option<Child>);
        impl Drop for Process {
            fn drop(&mut self) {
                if let Some(mut child)=self.0.take() {
                    let _=child.kill();
                    let _=child.wait();
                }
            }
        }
        impl Process {
            fn spawn(root:&Path,meta:&str,config:&str,tls:&str) -> Self {
                Self(Some(Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-service"))
                    .env_clear().args(["serve",root.to_str().unwrap(),"18443",IFACE,meta,config,tls])
                    .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
                    .spawn().unwrap()))
            }
            fn ready(&mut self,addr:SocketAddr) {
                let deadline=Instant::now()+Duration::from_secs(10);
                loop {
                    assert!(self.0.as_mut().unwrap().try_wait().unwrap().is_none(),"service exited before bind");
                    if TcpStream::connect_timeout(&addr,Duration::from_millis(100)).is_ok() { break; }
                    assert!(Instant::now()<deadline,"service startup timed out");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            fn finish(mut self,timeout:Duration) -> Output {
                let deadline=Instant::now()+timeout;
                while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
                    assert!(Instant::now()<deadline,"process did not exit");
                    std::thread::sleep(Duration::from_millis(20));
                }
                self.0.take().unwrap().wait_with_output().unwrap()
            }
            fn stop(self,signal:libc::c_int) {
                let pid=self.0.as_ref().unwrap().id();
                assert_eq!(unsafe {libc::kill(pid as libc::pid_t,signal)},0);
                let out=self.finish(Duration::from_secs(35));
                assert!(out.status.success() && out.stderr.is_empty());
                assert!(out.stdout==b"PAIR_SERVICE_READY\nPAIR_SERVICE_STOPPED\n");
            }
            fn refused(self) {
                let out=self.finish(Duration::from_secs(10));
                assert!(out.status.code()==Some(2) && out.stdout.is_empty());
                assert!(out.stderr==b"spidervpn-pair-service: protected provisioning refused\n");
            }
        }
        fn client(address: SocketAddr, ca:&[u8], leaf:&[u8])
            -> StreamOwned<ClientConnection,TcpStream>
        {
            let mut roots=RootCertStore::empty();
            roots.add(CertificateDer::from(ca.to_vec())).unwrap();
            let config=Arc::new(ClientConfig::builder_with_provider(
                Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS12]).unwrap()
                .with_root_certificates(roots).with_no_client_auth());
            let mut connection=ClientConnection::new(config,
                ServerName::try_from("203.0.113.10").unwrap()).unwrap();
            let mut socket=TcpStream::connect_timeout(&address,Duration::from_secs(3)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(35))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            while connection.is_handshaking() { connection.complete_io(&mut socket).unwrap(); }
            assert!(connection.protocol_version()==Some(rustls::ProtocolVersion::TLSv1_2));
            // Independently validate trust chain + exact pinned leaf before
            // any request is written, not just a successful TLS handshake.
            assert!(connection.peer_certificates().unwrap()[0].as_ref()==leaf);
            StreamOwned::new(connection,socket)
        }
        fn wire(id:&str,method:&str, host:&str, token:&str, body:Option<&[u8]>) -> Vec<u8> {
            let suffix=if method=="POST" {"/consume"} else {""};
            let mut head=format!("{method} /v1/invitations/{id}{suffix} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n");
            if let Some(body)=body {
                head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n",body.len()));
            }
            head.push_str("\r\n");
            let mut bytes=head.into_bytes();
            if let Some(body)=body { bytes.extend_from_slice(body); }
            bytes
        }
        fn exchange(address:SocketAddr, ca:&[u8], leaf:&[u8], wire:&[u8]) -> (u16,Value) {
            let mut tls=client(address,ca,leaf);
            tls.write_all(wire).unwrap();
            tls.flush().unwrap();
            let mut response=Vec::new();
            tls.read_to_end(&mut response).unwrap();
            assert!(response.len()<=131_072+1024);
            let text=String::from_utf8(response).unwrap();
            let (head,body)=text.split_once("\r\n\r\n").unwrap();
            let mut lines=head.split("\r\n");
            let status=lines.next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
            assert!(head.contains("\r\nContent-Type: application/json\r\n"));
            assert!(head.ends_with("\r\nConnection: close"));
            let lengths:Vec<_>=lines.filter_map(|s|s.strip_prefix("Content-Length: ")).collect();
            assert!(lengths.len()==1 && lengths[0].parse::<usize>().unwrap()==body.len());
            (status,serde_json::from_str(body).unwrap())
        }


        assert_eq!(unsafe {geteuid()},0);
        assert_eq!(std::env::var("SPIDERVPN_SEC01_NS_INTERFACE").unwrap(),IFACE);
        let reader=LiveWgReader::new(IFACE).unwrap();
        let old_public=reader.server_public_key().unwrap();
        assert!(reader.snapshot().unwrap().is_empty());
        let conf=Path::new("/etc/wireguard").join(format!("{IFACE}.conf"));
        let base=Zeroizing::new(fs::read_to_string(&conf).unwrap());
        let original_key=base.lines().find_map(|line|line.strip_prefix("PrivateKey = ")).unwrap();
        let parent=PathBuf::from(format!("/run/spidervpn-fresh-init-ci-{}",std::process::id()));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent,fs::Permissions::from_mode(0o700)).unwrap();
        let source=parent.join("materials");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source,fs::Permissions::from_mode(0o700)).unwrap();
        let root=parent.join("authority");
        let old_file=parent.join("original.wg");
        write_key_file(&old_file,original_key);
        let fresh_file=parent.join("fresh.wg");
        let generated=Command::new("/usr/bin/wg").arg("genkey").stderr(Stdio::null()).output().unwrap();
        assert!(generated.status.success());
        let fresh_key=Zeroizing::new(String::from_utf8(generated.stdout).unwrap());
        write_key_file(&fresh_file,fresh_key.trim());
        let fresh_base=Zeroizing::new(base.replace(original_key,fresh_key.trim()));
        // Fresh WG key in the disposable namespace, not reused from earlier
        // tests. Provisioning command itself performs no WG/config writes.
        set_server_key(&fresh_file);
        write_conf(&conf,&fresh_base,None);
        let expected=reader.server_public_key().unwrap();
        assert!(expected!=old_public);
        let client_key=std::env::var("SPIDERVPN_SEC01_NS_CLIENT_PUBLIC_KEY").unwrap();
        // Test-only CA and leaf, not a production identity or signer.
        let openssl=|args:&[&str]| {
            assert!(Command::new("/usr/bin/openssl").args(args).current_dir(&source)
                .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
        };
        openssl(&["req","-x509","-newkey","rsa:2048","-nodes","-days","1",
            "-subj","/CN=SpiderVPN-Stage4B-Fixture-CA","-addext","basicConstraints=critical,CA:TRUE",
            "-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout","ca.key","-out","ca.pem"]);
        openssl(&["req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=203.0.113.10",
            "-keyout","tls.key","-out","tls.csr"]);
        fs::write(source.join("tls.ext"),"subjectAltName=IP:203.0.113.10\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        openssl(&["x509","-req","-in","tls.csr","-CA","ca.pem","-CAkey","ca.key","-CAcreateserial",
            "-days","1","-sha256","-extfile","tls.ext","-out","tls.pem"]);
        openssl(&["x509","-in","ca.pem","-outform","DER","-out","ca.der"]);
        openssl(&["x509","-in","tls.pem","-outform","DER","-out","tls.der"]);
        let ca=fs::read(source.join("ca.der")).unwrap();
        let leaf=fs::read(source.join("tls.der")).unwrap();
        let pin=sha(&leaf);

        let mgmt=Rsa::new(&source,"management.key");
        let recipient=Rsa::new(&parent,"recipient.pem");
        let binding=json!({"RemoteOwnerId":"55555555-5555-4555-8555-555555555555",
            "NodeId":"66666666-6666-4666-8666-666666666666","ServerPublicKey":expected});
        let fingerprint=format!("SHA256:{}",b64(digest::digest(&digest::SHA256,
            &serde_json::to_vec(&mgmt.jwk).unwrap()).as_ref()).replace('-',"+").replace('_',"/"));
        let config_record=serde_json::to_vec(&json!({"SchemaVersion":1,"Kind":"SpiderVPN.AuthorizationConfig",
            "ServerBinding":binding,"WgInterface":IFACE,"TunnelSubnet":"10.66.0.0/24",
            "ServerAddress":"10.66.0.1/24","PublicEndpoint":"203.0.113.10:51820",
            "NodeName":"fresh netns fixture","Transport":"udp"})).unwrap();
        fs::rename(source.join("tls.pem"),source.join("tls.crt")).unwrap();
        for name in ["tls.crt","tls.key","management.key"] {
            fs::set_permissions(source.join(name),fs::Permissions::from_mode(0o600)).unwrap();
        }
        protected(&source,"authorization-config.json",&config_record);
        let config_pin=sha(&config_record);
        let init=|target:&Path,cp:&str| {
            Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-service")).env_clear()
                .args(["init-fresh","attest-new-node-no-history",source.to_str().unwrap(),
                    target.to_str().unwrap(),IFACE,"203.0.113.10","18443",cp,&fingerprint,&pin,
                    "3600","fresh netns fixture"])
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
        };
        let refused=|out:Output| {
            assert!(out.status.code()==Some(2) && out.stdout.is_empty());
            assert!(out.stderr==b"spidervpn-pair-service: fresh provisioning refused; do not retry or recreate existing state\n");
        };
        let conf_before=Zeroizing::new(fs::read(&conf).unwrap());
        refused(init(&root,&"0".repeat(64)));
        assert!(!root.exists());
        // Existing partial root is never reused or deleted.
        let partial=parent.join("partial");
        fs::create_dir(&partial).unwrap();
        fs::set_permissions(&partial,fs::Permissions::from_mode(0o700)).unwrap();
        protected(&partial,".fresh-init-incomplete",b"partial fixture\n");
        refused(init(&partial,&config_pin));
        assert!(!partial.join("authority-ledger.json").exists());
        assert!(fs::read(partial.join(".fresh-init-incomplete")).unwrap()==b"partial fixture\n");
        assert!(!root.exists());
        let before=i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
        let output=init(&root,&config_pin);
        assert!(output.status.success() && output.stderr.is_empty());
        assert!(output.stdout==b"FRESH_AUTHORITY_READY\n");
        assert!(!root.join(".fresh-init-incomplete").exists());
        assert!(fs::read(&conf).unwrap().as_slice()==conf_before.as_slice());
        assert!(reader.snapshot().unwrap().is_empty());
        // No fixture-written ledger or metadata. Independently decode the
        // produced TCI1 contract, verify both signatures and actual HMAC.
        let code_path=root.join("invitation-code.txt");
        let attrs=fs::symlink_metadata(&code_path).unwrap();
        assert!(attrs.is_file() && attrs.uid()==0 && attrs.nlink()==1 && attrs.mode()&0o7777==0o600);
        let code=Zeroizing::new(fs::read_to_string(&code_path).unwrap());
        assert!(code.trim().len()<=2048);
        let encoded=code.trim().strip_prefix("TCI1.").unwrap();
        let bytes=Zeroizing::new(B64.decode(encoded).unwrap());
        assert!(B64.encode(&*bytes)==encoded);
        let cv:Value=serde_json::from_slice(&bytes).unwrap();
        assert!(cv.as_object().unwrap().len()==8 && ["v","h","p","i","k","t","m","e"].iter().all(|k|cv.get(k).is_some()));
        assert!(cv["v"]==1 && cv["h"]=="203.0.113.10" && cv["p"]==18443
            && cv["t"]==pin && cv["m"]==fingerprint);
        let id=cv["i"].as_str().unwrap();
        assert!(id.len()==36 && id.as_bytes()[14]==b'4' && b"89ab".contains(&id.as_bytes()[19]));
        assert!(id.split('-').map(str::len).eq([8,4,4,4,12]));
        let token=cv["k"].as_str().unwrap();
        assert!(token.len()==43 && B64.decode(token).unwrap().len()==32);
        let expires=cv["e"].as_i64().unwrap();
        assert!(expires>=before+3600 && expires<=before+3660);
        let meta=fs::read(root.join("invite-metadata.json")).unwrap();
        let mp=fs::read_to_string(root.join("metadata-pin.txt")).unwrap();
        assert!(mp==sha(&meta) && !String::from_utf8_lossy(&meta).contains(token));
        let md:Value=serde_json::from_slice(&meta).unwrap();
        let tag=hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256,token.as_bytes()),
            b"SpiderVPN pinned invitation metadata bearer v1");
        assert!(md["BearerHmacSha256"]==hex(tag.as_ref()) && md["InviteId"]==id);
        let signed=md["SignedDescriptor"].as_str().unwrap();
        let descriptor=verify_legacy(signed,&mgmt.jwk);
        assert!(descriptor["Kind"]=="TradeChannel.OnlineInvite" && descriptor["InviteId"]==id
            && descriptor["PublicHost"]==cv["h"] && descriptor["Port"]==cv["p"]
            && descriptor["TlsSha256"]==cv["t"] && descriptor["ManagementFingerprint"]==cv["m"]
            && descriptor["ExpiresAtUtc"]==utc_at(expires) && descriptor["RetryUntilUtc"]==utc_at(expires+120));
        let invite=verify_legacy(
            descriptor["Invite"].as_str().unwrap(),&mgmt.jwk);
        assert!(invite["Kind"]=="TradeChannel.PairInvite" && invite["InviteId"]==id
            && invite["ServerBinding"]==binding && invite["ManagementSigningPublicKey"]==mgmt.jwk
            && invite["ExpiresAtUtc"]==utc_at(expires) && invite["IssuedAtUtc"]==utc_at(expires-3600));
        let store=open(&root);
        assert!(matches!(store.view().unwrap().state(id),Some(InviteState::Open)));
        assert_eq!(store.generation().unwrap(),1);
        drop(store);
        let ledger=root.join("authority-ledger.json");
        let initial=fs::read(&ledger).unwrap();
        refused(init(&root,&config_pin));
        assert!(fs::read(&ledger).unwrap()==initial && fs::read(&code_path).unwrap()==code.as_bytes());
        // A partially published root with otherwise valid state must not
        // be opened by serve. This is a disposable test-only marker.
        protected(&root,".fresh-init-incomplete",b"test marker\n");
        Process::spawn(&root,&mp,&config_pin,&pin).refused();
        fs::remove_file(root.join(".fresh-init-incomplete")).unwrap();
        let addr:SocketAddr="127.0.0.1:18443".parse().unwrap();
        let mut service=Process::spawn(&root,&mp,&config_pin,&pin);
        service.ready(addr);
        let host="203.0.113.10:18443";
        let get=wire(id,"GET",host,token,None);
        let (status,ready)=exchange(addr,&ca,&leaf,&get);
        assert!(status==200 && ready["Ok"]==true && ready["Data"]["Status"]=="InvitationReady"
            && ready["Data"]["SignedDescriptor"]==signed);
        let issued=utc_at(expires-3600);
        let inner=json!({"SchemaVersion":1,"Kind":"TradeChannel.ClientRequest","RequestId":REQ,
            "DeviceId":DEV,"ClientPublicKey":client_key,"CreatedAtUtc":issued,"AddressFamilies":["IPv4"]});
        let request_digest=sha(format!("1\nTradeChannel.ClientRequest\n{REQ}\n{DEV}\n{issued}\n{client_key}\nIPv4").as_bytes());
        let request=json!({"SchemaVersion":1,"Kind":"TradeChannel.PairRequest","InviteId":id,
            "ServerBinding":binding,"ClientRequest":inner,"DeviceName":"fresh fixture","RecipientJwk":recipient.jwk,
            "RequestDigest":request_digest,"RequestDigestAlgorithm":"TC-ClientRequest-v1","CreatedAtUtc":issued});
        let body=serde_json::to_vec(&json!({"PairRequest":recipient.sign(&request)})).unwrap();
        let post=wire(id,"POST",host,token,Some(&body));
        let (status,reply)=exchange(addr,&ca,&leaf,&post);
        assert!(status==200 && reply["Ok"]==true);
        let private=rsa::RsaPrivateKey::from_pkcs8_pem(
            &Zeroizing::new(fs::read_to_string(&recipient.path).unwrap())).unwrap();
        let original=open_authorization(&reply["Data"],&private).expect("authorization decrypts");
        let mut store=open(&root);
        let Some(InviteState::Consumed(grant))=store.view().unwrap().state(id) else {
            panic!("missing durable consumed grant");
        };
        let grant=grant.clone();
        assert_eq!(store.generation().unwrap(),3);
        assert_eq!(grant.address,Ipv4Addr::new(10,66,0,2));
        let observed=read_verified_identity_snapshot(&store,IFACE,&expected).unwrap();
        assert_eq!(observed,vec![spidervpn_pairing_authority::Peer{
            public_key:client_key.clone(),address:grant.address}]);
        assert!(spidervpn_pairing_authority::legacy_signed::audit_signed_consumed(id,
            &json!({"State":"Consumed","SignedAuthorization":original,
                "RequestId":REQ,"DeviceId":DEV,"ClientPublicKey":client_key,
                "ClientAddress":"10.66.0.2/32","RequestDigest":request_digest,
                "RecipientJwkDigest":grant.claims.recipient_jwk_digest}),&mgmt.jwk,&binding).is_ok());
        let committed=fs::read(&ledger).unwrap();
        let durable_conf=Zeroizing::new(fs::read(&conf).unwrap());
        drop(store);
        refused(init(&root,&config_pin));
        let another=parent.join("nonempty-peer-refused");
        refused(init(&another,&config_pin));
        assert!(!another.exists());
        assert!(fs::read(&ledger).unwrap()==committed && fs::read(&code_path).unwrap()==code.as_bytes());
        assert!(fs::read(&conf).unwrap().as_slice()==durable_conf.as_slice());
        assert_eq!(reader.snapshot().unwrap(),observed);

        let revoke = |metadata_pin: &str, device_id: &str| {
            Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-service")).env_clear()
                .args(["revoke", root.to_str().unwrap(), IFACE, metadata_pin, &config_pin, &pin, device_id])
                .stdin(Stdio::null()).output().unwrap()
        };
        let wrong_device = revoke(&mp, "77777777-7777-4777-8777-777777777777");
        assert!(wrong_device.status.code() == Some(2) && wrong_device.stdout.is_empty());
        assert!(fs::read(&ledger).unwrap() == committed);
        assert!(fs::read(&conf).unwrap().as_slice() == durable_conf.as_slice());
        assert_eq!(reader.snapshot().unwrap(), observed);

        let succeeded = |out: Output| {
            assert!(out.status.success() && out.stderr.is_empty());
            assert!(out.stdout == b"PAIR_DEVICE_REVOKED\n");
        };
        succeeded(revoke(&mp, DEV));
        store=open(&root);
        assert_eq!(store.generation().unwrap(), 5);
        assert!(matches!(store.view().unwrap().state(id), Some(InviteState::Revoked(saved)) if *saved == grant));
        assert!(read_verified_identity_snapshot(&store, IFACE, &expected).unwrap().is_empty());
        drop(store);
        let revoked_ledger = fs::read(&ledger).unwrap();
        let revoked_conf = Zeroizing::new(fs::read(&conf).unwrap());
        succeeded(revoke(&mp, DEV));
        assert!(exchange(addr,&ca,&leaf,&get)==(403,json!({"Ok":false,"Code":"Revoked"})));
        assert!(exchange(addr,&ca,&leaf,&post)==(403,json!({"Ok":false,"Code":"Revoked"})));
        service.stop(libc::SIGTERM);

        let mut restarted = Process::spawn(&root, &mp, &config_pin, &pin);
        restarted.ready(addr);
        assert!(exchange(addr,&ca,&leaf,&get)==(403,json!({"Ok":false,"Code":"Revoked"})));
        assert!(exchange(addr,&ca,&leaf,&post)==(403,json!({"Ok":false,"Code":"Revoked"})));
        restarted.stop(libc::SIGTERM);
        assert!(fs::read(&ledger).unwrap() == revoked_ledger);
        assert!(fs::read(&conf).unwrap().as_slice() == revoked_conf.as_slice());
        assert!(reader.snapshot().unwrap().is_empty());

        // Issue another operational code with the same protected authority.
        let issuance = Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-service"))
            .env_clear()
            .args(["issue-invite", root.to_str().unwrap(), IFACE, &mp, &config_pin,
                &pin, "3600", "second authorized device"])
            .stdin(Stdio::null()).output().unwrap();
        assert!(issuance.status.success() && issuance.stderr.is_empty());
        let output = String::from_utf8(issuance.stdout).unwrap();
        let second_pin = output.strip_prefix("PAIR_INVITATION_READY ").unwrap().trim_end();
        let second_slot = root.join(format!("invite-{second_pin}"));
        let second_metadata = fs::read(second_slot.join("invite-metadata.json")).unwrap();
        assert!(second_pin == sha(&second_metadata) && second_pin != mp);
        assert!(fs::read(root.join("invite-metadata.json")).unwrap() == meta);
        assert!(fs::read(&code_path).unwrap() == code.as_bytes());
        assert!(fs::read(&conf).unwrap().as_slice() == revoked_conf.as_slice());
        assert!(reader.snapshot().unwrap().is_empty());

        let second_path = second_slot.join("invitation-code.txt");
        assert_eq!(fs::metadata(&second_path).unwrap().mode() & 0o7777, 0o600);
        let second_code = Zeroizing::new(fs::read_to_string(&second_path).unwrap());
        let second_bytes = Zeroizing::new(B64.decode(second_code.trim().strip_prefix("TCI1.").unwrap()).unwrap());
        let second: Value = serde_json::from_slice(&second_bytes).unwrap();
        let second_id = second["i"].as_str().unwrap();
        let second_token = second["k"].as_str().unwrap();
        assert!(second_id != id && second_token != token);
        assert!(second["h"] == cv["h"] && second["p"] == cv["p"] && second["t"] == pin);
        let store = open(&root);
        assert_eq!(store.generation().unwrap(), 6);
        assert!(matches!(store.view().unwrap().state(second_id), Some(InviteState::Open)));
        assert!(matches!(store.view().unwrap().state(id), Some(InviteState::Revoked(saved)) if *saved == grant));
        drop(store);

        // A committed row without published metadata cannot start its listener.
        let pending = root.join(format!(".invite-{second_id}.pending"));
        fs::rename(&second_slot, &pending).unwrap();
        Process::spawn(&root, second_pin, &config_pin, &pin).refused();
        fs::rename(&pending, &second_slot).unwrap();

        let mut second_service = Process::spawn(&root, second_pin, &config_pin, &pin);
        second_service.ready(addr);
        let second_get = wire(second_id, "GET", host, second_token, None);
        let (status, response) = exchange(addr, &ca, &leaf, &second_get);
        assert!(status == 200 && response["Data"]["Status"] == "InvitationReady");

        let second_device = "34000000-0000-4000-8000-000000000001";
        let second_request = "34000000-0000-4000-8000-000000000002";
        let second_key = base64::engine::general_purpose::STANDARD.encode([42; 32]);
        let second_issued = utc_at(second["e"].as_i64().unwrap() - 3600);
        let mut request = request.clone();
        request["InviteId"] = json!(second_id);
        request["ClientRequest"]["RequestId"] = json!(second_request);
        request["ClientRequest"]["DeviceId"] = json!(second_device);
        request["ClientRequest"]["ClientPublicKey"] = json!(second_key);
        request["ClientRequest"]["CreatedAtUtc"] = json!(second_issued);
        request["CreatedAtUtc"] = json!(second_issued);
        request["RequestDigest"] = json!(sha(format!(
            "1\nTradeChannel.ClientRequest\n{second_request}\n{second_device}\n{second_issued}\n{second_key}\nIPv4",
        ).as_bytes()));
        let second_body = serde_json::to_vec(&json!({"PairRequest": recipient.sign(&request)})).unwrap();
        let second_post = wire(second_id, "POST", host, second_token, Some(&second_body));
        let (status, response) = exchange(addr, &ca, &leaf, &second_post);
        assert!(status == 200 && response["Ok"] == true);
        let store = open(&root);
        assert_eq!(store.generation().unwrap(), 8);
        assert!(matches!(store.view().unwrap().state(second_id), Some(InviteState::Consumed(saved))
            if saved.claims.device_id == second_device));
        let peers = read_verified_identity_snapshot(&store, IFACE, &expected).unwrap();
        assert!(peers.len() == 1 && peers[0].public_key == second_key);
        drop(store);
        succeeded(revoke(second_pin, second_device));
        second_service.stop(libc::SIGTERM);

        let mut restarted = Process::spawn(&root, &mp, &config_pin, &pin);
        restarted.ready(addr);
        assert!(exchange(addr, &ca, &leaf, &get) == (403, json!({"Ok":false,"Code":"Revoked"})));
        assert!(exchange(addr, &ca, &leaf, &post) == (403, json!({"Ok":false,"Code":"Revoked"})));
        restarted.stop(libc::SIGTERM);
        assert!(reader.snapshot().unwrap().is_empty());
        println!("Second invitation verified: same ledger, real enrollment and revocation, original invite still revoked");

        // Reuse the protected materials and TLS client for a separate Rust
        // root over the four-peer legacy shape: deployment plus three V2 grants.
        let existing_root = parent.join("existing-authority");
        let mut legacy_conf = Zeroizing::new(fresh_base.to_string());
        let mut devices = Vec::new();
        let mut old_invites = Vec::new();
        let mut old_peers = Vec::new();
        let deployed_device = "37000000-0000-4000-8000-000000000000";
        let expired_ids = [
            "39000000-0000-4000-8000-000000000001",
            "39000000-0000-4000-8000-000000000002",
        ];
        let expired_at = before - 120;
        for id in expired_ids {
            old_invites.push(json!({"id": id, "expires_unix": expired_at, "state": "Open"}));
        }
        for index in 0..4u8 {
            let device_id = format!("37000000-0000-4000-8000-{index:012x}");
            let request_id = format!("38000000-0000-4000-8000-{index:012x}");
            let key = base64::engine::general_purpose::STANDARD.encode([index + 1; 32]);
            let address = Ipv4Addr::new(10, 66, 0, index + 2);
            let cidr = format!("{address}/32");
            let original = json!({"SchemaVersion":1, "Kind":"TradeChannel.ClientRequest",
                "RequestId":request_id, "DeviceId":device_id, "ClientPublicKey":key,
                "CreatedAtUtc":issued, "AddressFamilies":["IPv4"]});
            let origin = if index == 0 {
                json!({"kind":"deployment", "plan_id":"36000000-0000-4000-8000-000000000001"})
            } else {
                let old_id = format!("32000000-0000-4000-8000-{index:012x}");
                old_invites.push(json!({"id":old_id, "expires_unix":expired_at, "state":"Consumed"}));
                let digest = sha(format!("1\nTradeChannel.ClientRequest\n{request_id}\n{device_id}\n{issued}\n{key}\nIPv4").as_bytes());
                let authorization = mgmt.sign(&json!({"SchemaVersion":2,
                    "Kind":"TradeChannel.PairAuthorization", "InviteId":old_id,
                    "ServerBinding":binding, "RemoteOwnerId":binding["RemoteOwnerId"],
                    "NodeId":binding["NodeId"], "RequestId":request_id, "DeviceId":device_id,
                    "ClientPublicKey":key, "ClientAddress":cidr, "ConfigRevision":u64::from(index)+2,
                    "RequestDigestAlgorithm":"TC-ClientRequest-v1", "RequestDigest":digest,
                    "ExitEvidence":{"Source":"ServerVerifiedTlsTrace"}}));
                json!({"kind":"signed_v2", "authorization":authorization})
            };
            devices.push(json!({"request":original, "address":address, "revoked":false, "origin":origin}));
            legacy_conf.push_str(&format!("\n[Peer]\nPublicKey = {key}\nAllowedIPs = {cidr}\n"));
            assert!(Command::new("/usr/bin/wg")
                .args(["set", IFACE, "peer", &key, "allowed-ips", &cidr])
                .status().unwrap().success());
            old_peers.push(spidervpn_pairing_authority::Peer { public_key: key, address });
        }
        fs::write(&conf, legacy_conf.as_bytes()).unwrap();
        let snapshot = serde_json::to_vec(&json!({"schema_version":1, "server_binding":binding,
            "config_revision":5, "management_revision":9, "devices":devices, "invitations":old_invites}))
            .unwrap();
        protected(&source, "existing-history.json", &snapshot);
        let snapshot_pin = sha(&snapshot);
        let adopt = |snapshot_pin: &str| {
            Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-service")).env_clear()
                .args(["init-existing", "attest-verified-frozen-tradechannel", snapshot_pin,
                    source.to_str().unwrap(), existing_root.to_str().unwrap(), IFACE,
                    "203.0.113.10", "18443", &config_pin, &fingerprint, &pin,
                    "3600", "existing netns fixture"])
                .stdin(Stdio::null()).output().unwrap()
        };
        let bad_pin = adopt(&"0".repeat(64));
        assert!(bad_pin.status.code() == Some(2) && !existing_root.exists());
        let adopted = adopt(&snapshot_pin);
        assert!(adopted.status.success() && adopted.stderr.is_empty(),
            "existing-node initialization failed");
        assert!(adopted.stdout == b"EXISTING_AUTHORITY_READY\n");
        assert!(fs::read(&conf).unwrap() == legacy_conf.as_bytes());
        assert!(fs::read(existing_root.join("existing-history.json")).unwrap() == snapshot);
        let retained_ledger = existing_root.join("authority-ledger.json");
        let adopted_bytes = fs::read(&retained_ledger).unwrap();
        let document: Value = serde_json::from_slice(&adopted_bytes).unwrap();
        let registered = &document["ledger"]["existing_history"]["devices"];
        assert!(registered.as_object().unwrap().len() == 4 &&
            registered[deployed_device]["origin"]["kind"] == "deployment");
        assert!(registered.as_object().unwrap().values().filter(|d|
            d["origin"]["kind"] == "signed_v2" && d["state"] == "Active").count() == 3);
        let adopted_store = open(&existing_root);
        assert_eq!(adopted_store.generation().unwrap(), 1);
        for id in expired_ids {
            assert_eq!(adopted_store.view().unwrap().state(id), Some(&InviteState::Expired));
        }
        require_exact_match(
            &old_peers, &read_verified_identity_snapshot(&adopted_store, IFACE, &expected).unwrap(),
        ).unwrap();
        drop(adopted_store);

        let new_meta = fs::read_to_string(existing_root.join("metadata-pin.txt")).unwrap();
        let new_code = Zeroizing::new(fs::read_to_string(existing_root.join("invitation-code.txt")).unwrap());
        let new_wire = Zeroizing::new(B64.decode(new_code.trim().strip_prefix("TCI1.").unwrap()).unwrap());
        let new_invite: Value = serde_json::from_slice(&new_wire).unwrap();
        let fresh_token = new_invite["k"].as_str().unwrap();
        let fresh_id = new_invite["i"].as_str().unwrap();
        let mut migrated = Process::spawn(&existing_root, &new_meta, &config_pin, &pin);
        migrated.ready(addr);
        assert_eq!(exchange(addr, &ca, &leaf, &wire(fresh_id, "GET", host, fresh_token, None)).0, 200);
        for id in expired_ids {
            let old_get = wire(id, "GET", host, fresh_token, None);
            assert_eq!(exchange(addr, &ca, &leaf, &old_get).0, 404);
        }
        migrated.stop(libc::SIGTERM);
        let mut migrated = Process::spawn(&existing_root, &new_meta, &config_pin, &pin);
        migrated.ready(addr);
        assert!(fs::read(&retained_ledger).unwrap() == adopted_bytes);
        let revoke_existing = || {
            Command::new(env!("CARGO_BIN_EXE_spidervpn-pair-service")).env_clear()
                .args(["revoke", existing_root.to_str().unwrap(), IFACE, &new_meta,
                    &config_pin, &pin, deployed_device])
                .stdin(Stdio::null()).output().unwrap()
        };
        succeeded(revoke_existing());
        let remaining = &old_peers[1..];
        let complete = fs::read(&retained_ledger).unwrap();
        let final_document: Value = serde_json::from_slice(&complete).unwrap();
        let ledger_body = &final_document["ledger"];
        assert_eq!(final_document["generation"], 3);
        assert_eq!(ledger_body["existing_history"]["devices"][deployed_device]["state"], "Revoked");
        assert_eq!(ledger_body["revoked_devices"], json!([deployed_device]));
        assert_eq!(ledger_body["revoked_keys"], json!([old_peers[0].public_key]));
        succeeded(revoke_existing());
        migrated.stop(libc::SIGTERM);
        let mut migrated = Process::spawn(&existing_root, &new_meta, &config_pin, &pin);
        migrated.ready(addr);
        let adopted_store = open(&existing_root);
        require_exact_match(
            remaining, &read_verified_identity_snapshot(&adopted_store, IFACE, &expected).unwrap(),
        ).unwrap();
        let mut copied = adopted_store.view().unwrap().clone();
        let replay = Claims {
            invite_id: fresh_id.to_owned(),
            device_id: deployed_device.to_owned(),
            ..claims(&client_key)
        };
        let pool = AddressPool { network: Ipv4Addr::new(10, 66, 0, 0), prefix: 24 };
        assert_eq!(copied.reserve(replay, before, pool, Some(remaining)), Err(Refusal::RevokedIdentity));
        drop(adopted_store);
        assert!(fs::read(&retained_ledger).unwrap() == complete);
        migrated.stop(libc::SIGTERM);
        for peer in remaining {
            assert!(Command::new("/usr/bin/wg")
                .args(["set", IFACE, "peer", &peer.public_key, "remove"])
                .status().unwrap().success());
        }
        println!("Existing authority verified: four peers retained, two expired invitations refused, one peer durably revoked");
        set_server_key(&old_file);
        write_conf(&conf,&base,None);
        assert!(reader.server_public_key().unwrap()==old_public);
        fs::remove_dir_all(parent).unwrap();
    }

}

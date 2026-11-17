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

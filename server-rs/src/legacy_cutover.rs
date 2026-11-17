//! SEC-01/SEC-08: a fail-closed, root-only **read-only** observation of the
//! previously deployed Python pairing receiver's shutdown state.
//!
//! This is NOT an exclusive writer lock: old Python ignores the Rust flock,
//! root can manually restart the script, and a process may start after this
//! snapshot. Even a successful report NEVER authorizes ledger migration,
//! revocation import, HTTP cutover, or WireGuard changes.
//!
//! The only recognized old unit is the name/path installed by pairhost.rs.
//! No unit, script, path, command or verification result is accepted from a
//! network caller or a legacy JSON document.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const UNIT: &str = "tc-pair.service";
const PERSISTENT_MASK: &str = "/etc/systemd/system/tc-pair.service";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MAX_SHOW: usize = 4096;
const MAX_CMDLINE: u64 = 65536;
const TIMEOUT: Duration = Duration::from_secs(3);
const LEGACY_ROOT: &str = "/var/lib/tradechannel/pairing-rs";
const LEGACY_SERVER: &str = "/var/lib/tradechannel/pairing-rs/server.json";
const MAX_SERVER_BYTES: u64 = 65536;
const MAX_SOCKET_BYTES: u64 = 1024 * 1024;
const O_NOFOLLOW: i32 = 0o400000; // Linux x86_64; no symlinked old config


unsafe extern "C" { fn geteuid() -> u32; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CutoverError {
    RootRequired,
    PersistentMaskAbsent,
    UnsafeSystemctl,
    SystemctlUnavailable,
    UnitNotStopped,
    ProcessInventoryUnavailable,
    OldReceiverRunning,
    UnstableObservation,
    TrustedPortUnavailable,
    SocketInventoryUnavailable,
    OldPairingPortListening,
}

/// A report intentionally has no conversion to Grant/Claims/Approval.
/// The machine is NOT proven safe for migration even on success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownObservation {
    pub persistent_unit_mask_observed: bool,
    pub stopped_systemd_unit_observed: bool,
    pub old_script_process_not_observed: bool,
    pub old_listener_not_observed: bool,
}
impl ShutdownObservation {
    pub fn authorizes_legacy_import(&self) -> bool { false }
    pub fn authorizes_new_pairing_listener(&self) -> bool { false }
}

fn root_required(uid: u32) -> Result<(), CutoverError> {
    if uid == 0 { Ok(()) } else { Err(CutoverError::RootRequired) }
}

fn check_root_owned_directory(path: &Path) -> Result<(), CutoverError> {
    let meta=fs::symlink_metadata(path).map_err(|_|CutoverError::PersistentMaskAbsent)?;
    if !meta.file_type().is_dir() || meta.uid()!=0 || meta.mode() & 0o022 != 0 {
        return Err(CutoverError::PersistentMaskAbsent);
    }
    Ok(())
}

/// Only an actual persistent /etc mask is acceptable. A runtime mask under
/// /run disappears on restart and is insufficient for cutover preparation.
fn persistent_mask() -> Result<(), CutoverError> {
    for path in ["/etc","/etc/systemd","/etc/systemd/system"] {
        check_root_owned_directory(Path::new(path))?;
    }
    let meta=fs::symlink_metadata(PERSISTENT_MASK)
        .map_err(|_|CutoverError::PersistentMaskAbsent)?;
    if !meta.file_type().is_symlink() || meta.uid()!=0
        || fs::read_link(PERSISTENT_MASK)
           .map_err(|_|CutoverError::PersistentMaskAbsent)?
           != Path::new("/dev/null")
    {
        return Err(CutoverError::PersistentMaskAbsent);
    }
    Ok(())
}

fn trusted_systemctl() -> Result<(), CutoverError> {
    let meta=fs::symlink_metadata(SYSTEMCTL).map_err(|_|CutoverError::UnsafeSystemctl)?;
    if !meta.file_type().is_file() || meta.uid()!=0
        || meta.mode() & 0o022 != 0 || meta.mode() & 0o111 == 0 {
        return Err(CutoverError::UnsafeSystemctl);
    }
    Ok(())
}

/// Bounded, timeout-controlled, shell-free systemctl observation.
fn systemctl_show() -> Result<String, CutoverError> {
    trusted_systemctl()?;
    let mut child=Command::new(SYSTEMCTL)
        .args(["show",UNIT,"--no-pager",
            "--property=LoadState,UnitFileState,ActiveState,SubState,MainPID,ControlPID,Job"])
        .env_clear().env("PATH","/usr/bin:/bin")
        .stdin(Stdio::null()).stderr(Stdio::null()).stdout(Stdio::piped())
        .spawn().map_err(|_|CutoverError::SystemctlUnavailable)?;
    let stdout=child.stdout.take().ok_or(CutoverError::SystemctlUnavailable)?;
    let reader=thread::spawn(move || {
        let mut output=Vec::new();
        let status=stdout.take((MAX_SHOW+1) as u64).read_to_end(&mut output);
        (status,output)
    });
    let started=Instant::now();
    let status=loop {
        match child.try_wait() {
            Ok(Some(code)) => break Ok(code),
            Ok(None) if started.elapsed()<TIMEOUT => thread::sleep(Duration::from_millis(10)),
            Ok(None)|Err(_) => {
                let _=child.kill();let _=child.wait();
                break Err(CutoverError::SystemctlUnavailable);
            }
        }
    };
    let (read,bytes)=reader.join().map_err(|_|CutoverError::SystemctlUnavailable)?;
    read.map_err(|_|CutoverError::SystemctlUnavailable)?;
    if bytes.len()>MAX_SHOW || !status?.success() {
        return Err(CutoverError::SystemctlUnavailable);
    }
    String::from_utf8(bytes).map_err(|_|CutoverError::SystemctlUnavailable)
}

fn unit_is_stopped(show:&str) -> Result<(),CutoverError> {
    if show.len()>MAX_SHOW || !show.ends_with('\n') {
        return Err(CutoverError::UnitNotStopped);
    }
    let mut fields=BTreeMap::new();
    for line in show.lines() {
        let (key,value)=line.split_once('=').ok_or(CutoverError::UnitNotStopped)?;
        if !["LoadState","UnitFileState","ActiveState","SubState","MainPID","ControlPID","Job"]
            .contains(&key) || fields.insert(key,value).is_some() {
            return Err(CutoverError::UnitNotStopped);
        }
    }
    if fields.len()!=7
        || fields.get("LoadState")!=Some(&"masked")
        || fields.get("UnitFileState")!=Some(&"masked")
        || fields.get("ActiveState")!=Some(&"inactive")
        || fields.get("SubState")!=Some(&"dead")
        || fields.get("MainPID")!=Some(&"0")
        || fields.get("ControlPID")!=Some(&"0")
        || !matches!(fields.get("Job"),Some(&"0")|Some(&"")) {
        return Err(CutoverError::UnitNotStopped);
    }
    Ok(())
}

/// Reject any visible invocation of tc-pair.py, not merely the "serve" verb:
/// old Python create/cancel/authorize-request also write the same legacy
/// ledger and do not obey Rust's SEC-08 cross-process file lock.
fn old_python_command(bytes:&[u8]) -> Result<bool,CutoverError> {
    if bytes.len() as u64 > MAX_CMDLINE {
        return Err(CutoverError::ProcessInventoryUnavailable);
    }
    let args=bytes.split(|b|*b==0).filter(|arg|!arg.is_empty());
    Ok(args.into_iter().any(|arg|arg.windows(b"tc-pair.py".len())
        .any(|window|window==b"tc-pair.py")))
}

/// The old Python receiver binds the Port stored in server.json. Checking
/// only the default 18443 could miss a legitimate nondefault deployment.
/// Neither an old JSON record nor this port is migration authority: it is
/// merely a source for a conservative *denial* check.
fn parse_old_server_port(raw: &[u8]) -> Result<u16,CutoverError> {
    let value:serde_json::Value=serde_json::from_slice(raw)
        .map_err(|_|CutoverError::TrustedPortUnavailable)?;
    if value.get("SchemaVersion").and_then(serde_json::Value::as_u64)!=Some(1) {
        return Err(CutoverError::TrustedPortUnavailable);
    }
    let port=value.get("Port").and_then(serde_json::Value::as_u64)
        .and_then(|p|u16::try_from(p).ok())
        .filter(|p| (1024..=65535).contains(p))
        .ok_or(CutoverError::TrustedPortUnavailable)?;
    let host=value.get("PublicHost").and_then(serde_json::Value::as_str)
        .ok_or(CutoverError::TrustedPortUnavailable)?;
    let addr=host.parse::<Ipv4Addr>()
        .map_err(|_|CutoverError::TrustedPortUnavailable)?;
    if addr.to_string()!=host
        || value.get("Endpoint").and_then(serde_json::Value::as_str)
            != Some(format!("{host}:{port}").as_str()) {
        return Err(CutoverError::TrustedPortUnavailable);
    }
    Ok(port)
}

/// Fail closed unless the old installation's server.json is a root-owned,
/// non-symlink single-link 0600 file inside root-controlled directories.
/// Reject unexpected TC_PAIR_ROOT overrides: the current known deployment
/// installs exactly this location and cannot attest arbitrary alternatives.
fn trusted_old_server_port()->Result<u16,CutoverError>{
    for parent in ["/var","/var/lib","/var/lib/tradechannel",LEGACY_ROOT] {
        check_root_owned_directory(Path::new(parent))
            .map_err(|_|CutoverError::TrustedPortUnavailable)?;
    }
    let file=OpenOptions::new().read(true).custom_flags(O_NOFOLLOW)
        .open(LEGACY_SERVER).map_err(|_|CutoverError::TrustedPortUnavailable)?;
    let meta=file.metadata().map_err(|_|CutoverError::TrustedPortUnavailable)?;
    if !meta.file_type().is_file() || meta.uid()!=0 || meta.nlink()!=1
        || meta.mode() & 0o777 != 0o600 || meta.len()>MAX_SERVER_BYTES {
        return Err(CutoverError::TrustedPortUnavailable);
    }
    let mut contents=Vec::new();
    file.take(MAX_SERVER_BYTES+1).read_to_end(&mut contents)
        .map_err(|_|CutoverError::TrustedPortUnavailable)?;
    if contents.len() as u64>MAX_SERVER_BYTES {
        return Err(CutoverError::TrustedPortUnavailable);
    }
    parse_old_server_port(&contents)
}

/// Bounded parser of Linux /proc/net/tcp and tcp6. Any listening socket
/// on the old configured port (regardless of owning process's name) denies.
/// Missing, malformed or truncated kernel inventory is NOT an empty set.
fn reject_listener_table(table: &[u8], port: u16, v6:bool)
    ->Result<(),CutoverError>
{
    if table.is_empty() || table.len() as u64>MAX_SOCKET_BYTES
        || table.last()!=Some(&b'\n') {
        return Err(CutoverError::SocketInventoryUnavailable);
    }
    let content=std::str::from_utf8(table)
        .map_err(|_|CutoverError::SocketInventoryUnavailable)?;
    let mut lines=content.lines();
    let header=lines.next().ok_or(CutoverError::SocketInventoryUnavailable)?;
    let header:Vec<&str>=header.split_whitespace().collect();
    if header.len()<4 || header[0]!="sl"
        || header[1]!="local_address" || header[2]!="rem_address" || header[3]!="st" {
        return Err(CutoverError::SocketInventoryUnavailable);
    }
    for line in lines {
        let cols:Vec<&str>=line.split_whitespace().collect();
        if cols.len()<4 || !cols[0].ends_with(':') {
            return Err(CutoverError::SocketInventoryUnavailable);
        }
        let (addr,hexport)=cols[1].rsplit_once(':')
            .ok_or(CutoverError::SocketInventoryUnavailable)?;
        if addr.len()!=if v6 {32} else {8} || hexport.len()!=4
            || !addr.bytes().all(|b|b.is_ascii_hexdigit())
            || cols[3].len()!=2 || !cols[3].bytes().all(|b|b.is_ascii_hexdigit()) {
            return Err(CutoverError::SocketInventoryUnavailable);
        }
        let found=u16::from_str_radix(hexport,16)
            .map_err(|_|CutoverError::SocketInventoryUnavailable)?;
        if cols[3]=="0A" && found==port {
            return Err(CutoverError::OldPairingPortListening);
        }
    }
    Ok(())
}
fn socket_table(path:&str,port:u16,v6:bool)->Result<(),CutoverError>{
    let input=File::open(path).map_err(|_|CutoverError::SocketInventoryUnavailable)?;
    let mut buf=Vec::new();
    input.take(MAX_SOCKET_BYTES+1).read_to_end(&mut buf)
        .map_err(|_|CutoverError::SocketInventoryUnavailable)?;
    reject_listener_table(&buf,port,v6)
}
fn no_old_listener(port:u16)->Result<(),CutoverError>{
    socket_table("/proc/net/tcp",port,false)?;
    socket_table("/proc/net/tcp6",port,true)?;
    Ok(())
}

fn scan_proc_for_python_writer() -> Result<(),CutoverError> {
    let processes=fs::read_dir("/proc")
        .map_err(|_|CutoverError::ProcessInventoryUnavailable)?;
    for entry in processes {
        let entry=entry.map_err(|_|CutoverError::ProcessInventoryUnavailable)?;
        let name=entry.file_name();
        let Some(name)=name.to_str() else {return Err(CutoverError::ProcessInventoryUnavailable);};
        if name.is_empty() || !name.bytes().all(|b|b.is_ascii_digit()) {continue;}
        let file=fs::File::open(entry.path().join("cmdline"))
            .map_err(|_|CutoverError::ProcessInventoryUnavailable)?;
        let mut limited=Vec::new();
        file.take(MAX_CMDLINE+1).read_to_end(&mut limited)
            .map_err(|_|CutoverError::ProcessInventoryUnavailable)?;
        if old_python_command(&limited)? {return Err(CutoverError::OldReceiverRunning);}
    }
    Ok(())
}

#[derive(Clone,Debug,PartialEq,Eq)]
struct Readback {
    unit: String,
}

/// Injection boundary is PRIVATE: tests cannot use invented observations to
/// authorize any action; this only determines a read-only report.
fn assess_with<M,S,P>(uid:u32,mut mask:M,mut show:S,mut processes:P)
    -> Result<ShutdownObservation,CutoverError>
where M:FnMut()->Result<(),CutoverError>,
      S:FnMut()->Result<String,CutoverError>,
      P:FnMut()->Result<(),CutoverError>
{
    root_required(uid)?;
    mask()?;
    let first=Readback{unit:show()?};
    unit_is_stopped(&first.unit)?;
    processes()?;
    mask()?;
    let second=Readback{unit:show()?};
    unit_is_stopped(&second.unit)?;
    processes()?;
    mask()?;
    if first!=second {return Err(CutoverError::UnstableObservation);}
    Ok(ShutdownObservation{
        persistent_unit_mask_observed:true,
        stopped_systemd_unit_observed:true,
        old_script_process_not_observed:true,
        old_listener_not_observed:false, // only the real port-inspection entry can assert this
    })
}

/// The only real-system API, read-only and root-only. This is a snapshot,
/// never a cutover authorization: scripts invoked by a renamed interpreter,
/// separate PID namespaces, or uncooperative root writers may evade it.
pub fn observe_old_python_shutdown() -> Result<ShutdownObservation,CutoverError> {
    // Root first, before reading any legacy config, service or kernel paths.
    root_required(unsafe{geteuid()})?;
    let port_before=trusted_old_server_port()?;
    no_old_listener(port_before)?;
    let mut report=assess_with(0,persistent_mask,systemctl_show,scan_proc_for_python_writer)?;
    let port_after=trusted_old_server_port()?;
    if port_before!=port_after {return Err(CutoverError::UnstableObservation);}
    no_old_listener(port_after)?;
    // Still a momentary observation, NEVER a start-listener/import permit.
    report.old_listener_not_observed=true;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOOD:&str="LoadState=masked\nUnitFileState=masked\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=0\n";
    fn pass()->Result<(),CutoverError>{Ok(())}
    fn good()->Result<String,CutoverError>{Ok(GOOD.to_owned())}

    #[test]
    fn other_users_denied_before_files_or_process_reads(){
        let mut called=false;
        let answer=assess_with(1001,||{called=true;pass()},good,pass);
        assert_eq!(answer,Err(CutoverError::RootRequired));
        assert!(!called);
    }
    #[test]
    fn all_safety_evidence_still_cannot_authorize_import_or_pairing(){
        let result=assess_with(0,pass,good,pass).unwrap();
        assert!(result.persistent_unit_mask_observed);
        assert!(result.stopped_systemd_unit_observed);
        assert!(result.old_script_process_not_observed);
        assert!(!result.authorizes_legacy_import());
        assert!(!result.authorizes_new_pairing_listener());
    }
    #[test]
    fn requires_persistent_mask_not_temporary_or_missing_mask(){
        let x=assess_with(0,||Err(CutoverError::PersistentMaskAbsent),good,pass);
        assert_eq!(x,Err(CutoverError::PersistentMaskAbsent));
        let runtime=GOOD.replace("UnitFileState=masked","UnitFileState=masked-runtime");
        assert_eq!(unit_is_stopped(&runtime),Err(CutoverError::UnitNotStopped));
    }
    #[test]
    fn running_or_pending_service_is_rejected(){
        for (key,value) in [
            ("ActiveState=inactive","ActiveState=active"),
            ("SubState=dead","SubState=running"),
            ("MainPID=0","MainPID=123"),
            ("ControlPID=0","ControlPID=22"),
            ("Job=0","Job=3"),
            ("LoadState=masked","LoadState=loaded"),
        ] {
            assert_eq!(unit_is_stopped(&GOOD.replace(key,value)),
                Err(CutoverError::UnitNotStopped));
        }
    }
    #[test]
    fn unknown_or_duplicate_unit_properties_are_not_silent(){
        for body in [
            GOOD.replace("UnitFileState=masked\n",""),
            format!("{GOOD}ActiveState=inactive\n"),
            format!("{GOOD}Unknown=ok\n"),
            GOOD.trim_end().to_string(),
            GOOD.replace("Job=0","Job=1"),
        ] {
            assert_eq!(unit_is_stopped(&body),Err(CutoverError::UnitNotStopped));
        }
    }
    #[test]
    fn any_old_python_writing_verb_is_detected(){
        for args in [
            b"python3\0-I\0/var/lib/tradechannel/pairing-rs/tc-pair.py\0serve\0".as_slice(),
            b"python3\0/var/lib/tradechannel/pairing-rs/tc-pair.py\0revoke\0",
            b"python3\0/home/local/tc-pair.py\0authorize-request\0",
        ] {
            assert_eq!(old_python_command(args),Ok(true));
        }
        assert_eq!(old_python_command(b"python3\0-I\0/some/other.py\0"),Ok(false));
        assert_eq!(old_python_command(&vec![b'x';MAX_CMDLINE as usize+1]),
            Err(CutoverError::ProcessInventoryUnavailable));
    }
    #[test]
    fn unexpected_process_failure_and_drift_abort_preflight(){
        assert_eq!(assess_with(0,pass,good,||Err(CutoverError::OldReceiverRunning)),
            Err(CutoverError::OldReceiverRunning));
        assert_eq!(assess_with(0,pass,good,||Err(CutoverError::ProcessInventoryUnavailable)),
            Err(CutoverError::ProcessInventoryUnavailable));
        let mut checks=0u32;
        let state=assess_with(0,pass,||{
            checks+=1;
            if checks==1 {good()}
            else {Ok(GOOD.replace("Job=0","Job="))}
        },pass);
        assert_eq!(state,Err(CutoverError::UnstableObservation));
    }

    #[test]
    fn rejects_invented_or_mismatched_old_server_port(){
        let good=br#"{"SchemaVersion":1,"PublicHost":"203.0.113.10","Port":18443,"Endpoint":"203.0.113.10:18443"}"#;
        assert_eq!(parse_old_server_port(good),Ok(18443));
        for invalid in [
            br#"{"SchemaVersion":1,"PublicHost":"203.0.113.10","Port":18443,"Endpoint":"203.0.113.10:18444"}"#.as_slice(),
            br#"{"SchemaVersion":1,"PublicHost":"203.0.113.10","Port":22,"Endpoint":"203.0.113.10:22"}"#,
            br#"{"SchemaVersion":1,"PublicHost":"203.0.113.10","Port":"18443","Endpoint":"203.0.113.10:18443"}"#,
            br#"{"SchemaVersion":2,"PublicHost":"203.0.113.10","Port":18443,"Endpoint":"203.0.113.10:18443"}"#,
            br#"{}"#,
        ] {
            assert_eq!(parse_old_server_port(invalid),Err(CutoverError::TrustedPortUnavailable));
        }
    }
    #[test]
    fn listening_socket_on_actual_old_port_denies_even_when_process_name_changed(){
        let header=b"  sl  local_address rem_address   st tx_queue\n";
        let ipv4=b"  0: 00000000:480B 00000000:0000 0A 0:0\n";
        let ipv6=b"  0: 00000000000000000000000000000000:480B 00000000000000000000000000000000:0000 0A 0:0\n";
        for (body,v6) in [(ipv4.as_slice(),false),(ipv6.as_slice(),true)] {
            let mut table=header.to_vec();
            table.extend_from_slice(body);
            assert_eq!(reject_listener_table(&table,18443,v6),
                Err(CutoverError::OldPairingPortListening));
            assert_eq!(reject_listener_table(&table,18555,v6),Ok(()));
            table.pop();
            assert_eq!(reject_listener_table(&table,18443,v6),
                Err(CutoverError::SocketInventoryUnavailable));
        }
    }
    #[test]
    fn real_kernel_ipv4_listener_is_observed_without_executing_old_python(){
        let socket=std::net::TcpListener::bind(("127.0.0.1",0)).unwrap();
        let port=socket.local_addr().unwrap().port();
        assert_eq!(socket_table("/proc/net/tcp",port,false),
            Err(CutoverError::OldPairingPortListening));
        drop(socket);
        assert_eq!(socket_table("/proc/net/tcp",port,false),Ok(()));
    }
    #[test]
    fn untrusted_socket_inventory_never_looks_like_absence(){
        for data in [b"".as_slice(),b"garbage\n",b"sl local_address rem_address st\n0: BAD\n",
            b"sl local_address rem_address st\n0: 00000000:ZZZZ 00000000:0000 0A\n"] {
            assert_eq!(reject_listener_table(data,18443,false),
                Err(CutoverError::SocketInventoryUnavailable));
        }
    }
}

//! Explicit loopback pairing service and local device revocation. The WG
//! adapter requires effective root and the protected local authority.
#![cfg(target_os = "linux")]

use spidervpn_pairing_authority::pairing_service::run_loopback_pairing_service;
use spidervpn_pairing_authority::service_provisioning::{load_local_authority, revoke_local_device};
use std::io;
use std::net::{Ipv4Addr,TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool,Ordering};

static STOP: AtomicBool=AtomicBool::new(false);
extern "C" fn stop_signal(_: libc::c_int) { STOP.store(true,Ordering::Release); }

fn install_stop_handlers() -> io::Result<()> {
    // Single-threaded startup; handler does only a lock-free atomic store.
    unsafe {
        let mut action:libc::sigaction=std::mem::zeroed();
        action.sa_sigaction=stop_signal as *const () as usize;
        if libc::sigemptyset(&mut action.sa_mask)!=0
            || libc::sigaction(libc::SIGTERM,&action,std::ptr::null_mut())!=0
            || libc::sigaction(libc::SIGINT,&action,std::ptr::null_mut())!=0
        { return Err(io::Error::last_os_error()); }
        let mut signals:libc::sigset_t=std::mem::zeroed();
        if libc::sigemptyset(&mut signals)!=0
            || libc::sigaddset(&mut signals,libc::SIGTERM)!=0
            || libc::sigaddset(&mut signals,libc::SIGINT)!=0
            || libc::sigprocmask(libc::SIG_UNBLOCK,&signals,std::ptr::null_mut())!=0
        { return Err(io::Error::last_os_error()); }
    }
    Ok(())
}

fn protect_local_process(privilege_error: &'static str) -> Result<(), &'static str> {
    // No added privileges or core dumps of in-memory credentials. The
    // WG adapter still needs root and CAP_NET_ADMIN in its namespace.
    unsafe {
        if libc::geteuid()!=0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1 as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong)!=0
            || libc::prctl(libc::PR_SET_DUMPABLE,0 as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong)!=0
        { return Err(privilege_error); }
        libc::umask(0o077);
    }
    std::env::set_current_dir("/").map_err(|_|"startup directory refused")
}

fn run() -> Result<(), &'static str> {
    let args:Vec<_>=std::env::args_os().skip(1).collect();
    #[cfg(feature = "linux-fresh-provisioning")]
    if args.first().and_then(|s|s.to_str())==Some("init-fresh") {
        return init_fresh(&args);
    }
    if args.first().and_then(|s|s.to_str())==Some("revoke") {
        return revoke(&args);
    }
    let [mode,root,port,interface,metadata_pin,config_pin,tls_pin]=args.as_slice() else {
        return Err("usage: serve ROOT PORT INTERFACE METADATA_SHA256 CONFIG_SHA256 TLS_SHA256");
    };
    if mode.to_str()!=Some("serve") { return Err("explicit serve mode required"); }
    let port=port.to_str().and_then(|s|s.parse::<u16>().ok())
        .filter(|p|*p>=1024).ok_or("invalid loopback port")?;
    let interface=interface.to_str().ok_or("invalid interface")?;
    let metadata_pin=metadata_pin.to_str().ok_or("invalid pin")?;
    let config_pin=config_pin.to_str().ok_or("invalid pin")?;
    let tls_pin=tls_pin.to_str().ok_or("invalid pin")?;
    protect_local_process("privileged startup refused")?;
    install_stop_handlers().map_err(|_|"stop handlers refused")?;
    let authority=load_local_authority(PathBuf::from(root.as_os_str()),interface.to_owned(),
        metadata_pin.to_owned(),config_pin,tls_pin).map_err(|_|"protected provisioning refused")?;
    if STOP.load(Ordering::Acquire) { return Ok(()); }
    let listener=TcpListener::bind((Ipv4Addr::LOCALHOST,port)).map_err(|_|"loopback bind refused")?;
    println!("PAIR_SERVICE_READY");
    run_loopback_pairing_service(listener,authority,16,4,&STOP)
        .map_err(|_|"pairing listener failed")?;
    println!("PAIR_SERVICE_STOPPED");
    Ok(())
}

fn revoke(args: &[std::ffi::OsString]) -> Result<(), &'static str> {
    let [_, root, interface, metadata_pin, config_pin, tls_pin, device_id] = args else {
        return Err("usage: revoke ROOT INTERFACE METADATA_SHA256 CONFIG_SHA256 TLS_SHA256 DEVICE_ID");
    };
    let interface = interface.to_str().ok_or("invalid interface")?;
    let metadata_pin = metadata_pin.to_str().ok_or("invalid pin")?;
    let config_pin = config_pin.to_str().ok_or("invalid pin")?;
    let tls_pin = tls_pin.to_str().ok_or("invalid pin")?;
    let device_id = device_id.to_str().ok_or("invalid device ID")?;
    protect_local_process("revoke privileged startup refused")?;
    revoke_local_device(PathBuf::from(root), interface.to_owned(), metadata_pin.to_owned(),
        config_pin, tls_pin, device_id).map_err(|_|"device revocation refused; inspect current authority and peer state")?;
    println!("PAIR_DEVICE_REVOKED");
    Ok(())
}

#[cfg(feature = "linux-fresh-provisioning")]
fn init_fresh(args:&[std::ffi::OsString])->Result<(),&'static str> {
    let values:Vec<&str>=args.iter().map(|s|s.to_str().ok_or("invalid fresh arguments"))
        .collect::<Result<_,_>>()?;
    let ["init-fresh","attest-new-node-no-history",source,root,interface,host,port,
        config_pin,management_pin,tls_pin,lifetime,name]=values.as_slice() else {
        return Err("usage: init-fresh attest-new-node-no-history MATERIAL_ROOT NEW_ROOT INTERFACE IPV4 PORT CONFIG_SHA256 MANAGEMENT_FINGERPRINT TLS_SHA256 LIFETIME_SECONDS NAME");
    };
    protect_local_process("fresh privileged startup refused")?;
    spidervpn_pairing_authority::fresh_provisioning::initialize_new_node(
        PathBuf::from(*source),PathBuf::from(*root),interface,host,
        port.parse().map_err(|_|"invalid port")?,config_pin,management_pin,tls_pin,
        lifetime.parse().map_err(|_|"invalid lifetime")?,name)
        .map_err(|_|"fresh provisioning refused; do not retry or recreate existing state")?;
    println!("FRESH_AUTHORITY_READY");
    Ok(())
}

fn main() {
    if let Err(e)=run() {
        eprintln!("spidervpn-pair-service: {e}");
        std::process::exit(2);
    }
}

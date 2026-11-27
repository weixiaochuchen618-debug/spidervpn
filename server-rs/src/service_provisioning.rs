//! Stage 4A explicit root-owned local provisioning. No initialization,
//! migration, automatic trust discovery or public listener.
#![cfg(all(target_os = "linux", feature = "linux-pairing-process"))]

use crate::authorization_response::TrustedResponseConfig;
use crate::pairing_service::PairingAuthority;
use crate::tls_identity::{open_service_root,read_service_file,read_service_identity};
use rsa::pkcs8::DecodePrivateKey;
use std::io;
use std::path::PathBuf;
use zeroize::Zeroizing;

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied,"protected pairing provisioning refused")
}

/// Pins originate independently from the operator's trusted provisioning,
/// not from files beside the records, a request, environment or legacy JSON.
/// All file basenames are fixed. No secret-bearing diagnostic is returned.
pub fn load_local_authority(root: PathBuf, interface: String, metadata_pin: String,
    config_pin: &str, tls_pin: &str) -> io::Result<PairingAuthority>
{
    let dir=open_service_root(&root).map_err(|_|refused())?;
    // A failed/interrupted fresh init cannot be opened by serve, even if
    // its ledger rename was already visible. Never remove this marker here.
    match std::fs::symlink_metadata(root.join(".fresh-init-incomplete")) {
        Err(e) if e.kind()==io::ErrorKind::NotFound => {},
        _ => return Err(refused()),
    }
    // Bounded nonblocking inode check before the existing ledger opener.
    // Never create an empty ledger. The existing lock/transaction validates
    // the actual current document again; privileged competing writers must
    // already be excluded by the operator.
    let _ledger=Zeroizing::new(read_service_file(&dir,"authority-ledger.json",4*1024*1024)
        .map_err(|_|refused())?);
    let metadata=read_service_file(&dir,"invite-metadata.json",131_072).map_err(|_|refused())?;
    let raw=read_service_file(&dir,"authorization-config.json",16_384).map_err(|_|refused())?;
    let config=TrustedResponseConfig::verify_pinned(&raw,config_pin).map_err(|_|refused())?;
    let pem=Zeroizing::new(read_service_file(&dir,"management.key",32*1024)
        .map_err(|_|refused())?);
    let management=rsa::RsaPrivateKey::from_pkcs8_pem(
        std::str::from_utf8(&pem).map_err(|_|refused())?).map_err(|_|refused())?;
    let identity=read_service_identity(&dir,tls_pin).map_err(|_|refused())?;
    PairingAuthority::from_protected_local(root,interface,metadata,metadata_pin,
        config,management,identity).map_err(|_|refused())
}

/// Revoke the registered device for the independently pinned local invitation.
pub fn revoke_local_device(root: PathBuf, interface: String, metadata_pin: String,
    config_pin: &str, tls_pin: &str, device_id: &str) -> io::Result<()>
{
    if !crate::lower_uuid(device_id) {
        return Err(refused());
    }
    let authority = load_local_authority(root, interface, metadata_pin, config_pin, tls_pin)?;
    authority.revoke_registered_device(device_id)
}

//! Stage 4A explicit root-owned local provisioning. No initialization,
//! migration, automatic trust discovery or public listener.
#![cfg(all(target_os = "linux", feature = "linux-pairing-process"))]

use crate::authorization_response::TrustedResponseConfig;
use crate::pairing_service::PairingAuthority;
use crate::tls_identity::{open_service_root, read_service_file, read_service_identity, VerifiedTlsIdentity};
use rsa::pkcs8::DecodePrivateKey;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied,"protected pairing provisioning refused")
}

struct LocalProvisioning {
    metadata: Vec<u8>,
    config: TrustedResponseConfig,
    management: rsa::RsaPrivateKey,
    identity: VerifiedTlsIdentity,
}

fn read_local_provisioning(
    root: &Path, metadata_pin: &str, config_pin: &str, tls_pin: &str,
) -> io::Result<LocalProvisioning> {
    if !crate::hex_sha256(metadata_pin) {
        return Err(refused());
    }
    let dir = open_service_root(root).map_err(|_| refused())?;
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
    // Issued invitations become visible only after the locked ledger commit.
    // The original pinned record remains at the root for existing callers.
    let issued = open_service_root(&root.join(format!("invite-{metadata_pin}")));
    let metadata = match issued {
        Ok(child) => read_service_file(&child, "invite-metadata.json", 131_072),
        Err(error) if error.kind() == io::ErrorKind::NotFound =>
            read_service_file(&dir, "invite-metadata.json", 131_072),
        Err(error) => Err(error),
    }.map_err(|_| refused())?;
    let raw=read_service_file(&dir,"authorization-config.json",16_384).map_err(|_|refused())?;
    let config=TrustedResponseConfig::verify_pinned(&raw,config_pin).map_err(|_|refused())?;
    let pem=Zeroizing::new(read_service_file(&dir,"management.key",32*1024)
        .map_err(|_|refused())?);
    let management=rsa::RsaPrivateKey::from_pkcs8_pem(
        std::str::from_utf8(&pem).map_err(|_|refused())?).map_err(|_|refused())?;
    let identity=read_service_identity(&dir,tls_pin).map_err(|_|refused())?;
    Ok(LocalProvisioning { metadata, config, management, identity })
}

/// Pins originate independently from the operator's trusted provisioning.
/// No secret-bearing diagnostic is returned.
pub fn load_local_authority(root: PathBuf, interface: String, metadata_pin: String,
    config_pin: &str, tls_pin: &str) -> io::Result<PairingAuthority>
{
    let local = read_local_provisioning(&root, &metadata_pin, config_pin, tls_pin)?;
    PairingAuthority::from_protected_local(root, interface, local.metadata, metadata_pin,
        local.config, local.management, local.identity).map_err(|_| refused())
}

/// Issue a new invitation using the pinned endpoint and signer of an
/// existing Rust authority, with the same ledger and WireGuard interface.
#[cfg(feature = "linux-fresh-provisioning")]
pub fn issue_local_invite(
    root: &Path, interface: &str, metadata_pin: &str, config_pin: &str, tls_pin: &str,
    lifetime: i64, name: &str,
) -> io::Result<String> {
    use crate::fresh_provisioning::{append_invitation, InvitationEndpoint};
    use crate::ledger_disk::LedgerStore;
    use std::time::Duration;

    let local = read_local_provisioning(root, metadata_pin, config_pin, tls_pin)?;
    let mut store = LedgerStore::open_existing(root, Duration::ZERO).map_err(|_| refused())?;
    let scope = crate::fresh_consume_gate::preflight_service_metadata(
        &store, &local.metadata, metadata_pin, interface, &local.identity.leaf_der_sha256,
        &local.config, &local.management,
    ).map_err(|_| refused())?;
    let (host, port) = &scope.advertised_endpoint;
    let endpoint = InvitationEndpoint {
        interface, host, port: *port, tls_pin: &local.identity.leaf_der_sha256,
    };
    append_invitation(root, &mut store, &local.config, &local.management, endpoint, lifetime, name)
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

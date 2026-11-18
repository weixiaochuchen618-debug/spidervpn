//! SEC-02: trusted, read-only legacy TLS certificate identity candidate.
//!
//! This does NOT switch the deployed Python server, load arbitrary untrusted
//! TC_PAIR_ROOT or create/rotate any certificate. The fixed production path
//! and operator-trusted expected SHA-256 DER pin MUST agree before rustls
//! ServerConfig can be constructed. There is no public listener/HTTP route.
//!
//! Security contract:
//! * real effective UID=0 in the production entry point, never env-based;
//! * openat() from "/" through fixed path components, O_NOFOLLOW/O_CLOEXEC;
//! * every directory root-owned & neither group/world writable; final 0700;
//! * openat(O_NOFOLLOW|O_NONBLOCK) regular, root-owned, SINGLE-link files;
//! * tls.key strict 0600, cert not group/world writable, bounded byte reads;
//! * rustls-pki-types PEM parser (no ad-hoc base64); zeroized PEM key buffer;
//! * SHA-256 of *leaf DER*, not PEM text: exactly same as Python cert_sha256()
//!   and the Windows client's certificate pin verifier. Never write to disk.
//!
//! Cannot establish that a given production server actually has secure files,
//! or that a caller-provided expected pin is authentic: that must come from an
//! independently verified existing invitation/administrator witness. Until
//! all SEC-01/02/08 cutover gates pass the module is default-OFF and unused.
#![cfg(all(target_os = "linux", feature = "linux-tls-identity-lab"))]

use crate::tls_wire::tls12_server_config;
use ring::digest::{digest, SHA256};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const PRODUCTION_TLS_DIR: &str = "/var/lib/tradechannel/pairing-rs";
const COMPONENTS: [&str; 4] = ["var", "lib", "tradechannel", "pairing-rs"];
const CERT_NAME: &str = "tls.crt";
const KEY_NAME: &str = "tls.key";
const MAX_CERT_PEM_BYTES: usize = 128 * 1024;
const MAX_KEY_PEM_BYTES: usize = 32 * 1024;
const MAX_CHAIN_CERTS: usize = 8;

// Linux O_* constants, matching the target's existing Linux-only code.
// openat() with one path component and O_NOFOLLOW prevents symlink traversal.
// O_NONBLOCK ensures a swapped-in FIFO never stalls before metadata checks.
const O_RDONLY: i32 = 0;
const O_NONBLOCK: i32 = 0o4000;
const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const O_CLOEXEC: i32 = 0o2000000;

unsafe extern "C" {
    fn openat(dirfd: i32, pathname: *const i8, flags: i32) -> i32;
    fn geteuid() -> u32;
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn open_child(dir: &File, name: &str, extra_flags: i32) -> io::Result<File> {
    if name.is_empty() || name == "." || name == ".."
        || name.bytes().any(|b| b == b'/' || b == 0)
    {
        return Err(denied("SEC-02 invalid trusted path component"));
    }
    let c_name = CString::new(name).map_err(|_| denied("SEC-02 invalid path name"))?;
    let fd = unsafe {
        openat(dir.as_raw_fd(), c_name.as_ptr(),
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | extra_flags)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the preceding successful openat returned a fresh owned FD.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn check_dir(dir: &File, uid: u32, final_dir: bool) -> io::Result<()> {
    let m = dir.metadata()?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o022 != 0
        || (final_dir && m.mode() & 0o7777 != 0o700)
    {
        return Err(denied("SEC-02 untrusted TLS directory ownership or mode"));
    }
    Ok(())
}

fn open_trusted_tree(start: &File, names: &[&str], uid: u32) -> io::Result<File> {
    check_dir(start, uid, false)?;
    if names.is_empty() {
        return Err(denied("SEC-02 empty root certificate path"));
    }
    let mut current = start.try_clone()?;
    for (index, name) in names.iter().enumerate() {
        let child = open_child(&current, name, O_DIRECTORY)?;
        check_dir(&child, uid, index + 1 == names.len())?;
        current = child;
    }
    Ok(current)
}

fn secure_file(dir: &File, name: &str, uid: u32, max: usize, key: bool)
    -> io::Result<Vec<u8>>
{
    let file = open_child(dir, name, 0)?;
    let m = file.metadata()?;
    if !m.file_type().is_file() || m.uid() != uid || m.nlink() != 1
        || m.mode() & 0o7000 != 0
        || (key && m.mode() & 0o777 != 0o600)
        || (!key && m.mode() & 0o022 != 0)
    {
        return Err(denied("SEC-02 unsafe TLS certificate/key inode"));
    }
    if m.len() == 0 || m.len() > max as u64 {
        return Err(invalid("SEC-02 empty or oversized TLS identity"));
    }
    let mut bytes = Vec::new();
    let result = file.take(max as u64 + 1).read_to_end(&mut bytes);
    if let Err(err) = result {
        if key { bytes.fill(0); }
        return Err(err);
    }
    if bytes.is_empty() || bytes.len() > max {
        if key { bytes.fill(0); }
        return Err(invalid("SEC-02 TLS identity changed size during read"));
    }
    Ok(bytes)
}

fn is_valid_pin(pin: &str) -> bool {
    pin.len() == 64
        && pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Compute the exact legacy certificate SHA-256 over DER, lowercase hex.
/// Intentionally never hashes PEM whitespace, RSA private key or chain CA.
pub fn legacy_leaf_der_sha256(leaf: &[u8]) -> String {
    let hash = digest(&SHA256, leaf);
    let mut output = String::with_capacity(64);
    for byte in hash.as_ref() {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("hex rendering to String");
    }
    output
}

/// A server identity whose original DER fingerprint matched the separately
/// provided expected pin. Does NOT authorize a pairing request.
pub struct VerifiedTlsIdentity {
    pub server_config: Arc<ServerConfig>,
    pub leaf_der_sha256: String,
}
impl std::fmt::Debug for VerifiedTlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedTlsIdentity")
            .field("pin_verified", &true)
            .finish_non_exhaustive()
    }
}

fn read_from_verified_dir(dir: &File, uid: u32, expected_pin: &str)
    -> io::Result<VerifiedTlsIdentity>
{
    if !is_valid_pin(expected_pin) {
        return Err(invalid("SEC-02 trusted TLS pin must be 64 lowercase hex digits"));
    }
    check_dir(dir, uid, true)?;
    let cert_pem = secure_file(dir, CERT_NAME, uid, MAX_CERT_PEM_BYTES, false)?;
    let key_pem = Zeroizing::new(
        secure_file(dir, KEY_NAME, uid, MAX_KEY_PEM_BYTES, true)?);

    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("SEC-02 invalid PEM certificate chain"))?;
    if certificates.is_empty() || certificates.len() > MAX_CHAIN_CERTS {
        return Err(invalid("SEC-02 invalid certificate chain count"));
    }
    let calculated = legacy_leaf_der_sha256(certificates[0].as_ref());
    if calculated != expected_pin {
        return Err(denied("SEC-02 original TLS DER certificate pin mismatch"));
    }

    let mut keys: Vec<PrivateKeyDer<'static>> =
        PrivateKeyDer::pem_slice_iter(&key_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("SEC-02 invalid PEM private key"))?;
    if keys.len() != 1 {
        return Err(invalid("SEC-02 multiple or missing private key"));
    }
    let key = keys.remove(0);
    let server_config = tls12_server_config(certificates, key)?;
    Ok(VerifiedTlsIdentity { server_config, leaf_der_sha256: calculated })
}

/// Production path is FIXED and verified component-by-component, never taken
/// from TC_PAIR_ROOT, server.json, SSH config, a caller-provided directory,
/// or an untrusted network input. Requires effective root UID and an
/// independently TRUSTED existing invite/operator pin. Read-only; NO writes.
pub fn read_existing_production_identity(expected_pin: &str)
    -> io::Result<VerifiedTlsIdentity>
{
    if unsafe { geteuid() } != 0 {
        return Err(denied("SEC-02 root required to load original TLS identity"));
    }
    if !is_valid_pin(expected_pin) {
        return Err(invalid("SEC-02 no trusted existing certificate pin"));
    }
    let slash = File::open("/")?;
    let root = open_trusted_tree(&slash, &COMPONENTS, 0)?;
    read_from_verified_dir(&root, 0, expected_pin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::ClientConnection;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore, StreamOwned};
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;
    use crate::handshake_admission::{HandshakeAdmission, RequestAdmission};
    use crate::tls_wire::spawn_tls12_decrypted_one_request;

    struct Fixture {
        cert: Vec<u8>,
        key: Vec<u8>,
        der: Vec<u8>,
    }

    fn fixture() -> &'static Fixture {
        static FIX: OnceLock<Fixture> = OnceLock::new();
        FIX.get_or_init(|| {
            let p = std::env::temp_dir().join(format!(
                "spidervpn-sec02-pem-fixture-{}", std::process::id()));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            let status = Command::new("openssl")
                .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-sha256", "-subj", "/CN=localhost",
                    "-keyout", "tls.key", "-out", "tls.crt"])
                .current_dir(&p).stdout(Stdio::null()).stderr(Stdio::null())
                .status().expect("missing Linux OpenSSL fixture generator");
            assert!(status.success(), "test PEM fixture generator failed");
            let status = Command::new("openssl")
                .args(["x509", "-in", "tls.crt", "-outform", "DER",
                    "-out", "tls.der"])
                .current_dir(&p).stdout(Stdio::null()).stderr(Stdio::null())
                .status().unwrap();
            assert!(status.success(), "test leaf DER export failed");
            let out = Fixture {
                cert: fs::read(p.join(CERT_NAME)).unwrap(),
                key: fs::read(p.join(KEY_NAME)).unwrap(),
                der: fs::read(p.join("tls.der")).unwrap(),
            };
            fs::remove_dir_all(p).unwrap();
            out
        })
    }

    struct TempRoot { path: PathBuf }
    impl TempRoot {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(1);
            let path = std::env::temp_dir().join(format!(
                "spidervpn-sec02-identity-{}-{}", std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }
        fn write(&self, name: &str, bytes: &[u8], mode: u32) {
            fs::write(self.path.join(name), bytes).unwrap();
            fs::set_permissions(self.path.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        fn initialized(&self) -> String {
            let fixture = fixture();
            self.write(CERT_NAME, &fixture.cert, 0o644);
            self.write(KEY_NAME, &fixture.key, 0o600);
            legacy_leaf_der_sha256(&fixture.der)
        }
        fn file(&self) -> File { File::open(&self.path).unwrap() }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) { fs::remove_dir_all(&self.path).unwrap(); }
    }
    fn uid() -> u32 { unsafe { geteuid() } }
    fn check(root: &TempRoot, pin: &str) -> io::Result<VerifiedTlsIdentity> {
        read_from_verified_dir(&root.file(), uid(), pin)
    }

    #[test]
    fn original_leaf_der_pin_matches_exact_legacy_python_and_client_semantics() {
        let root = TempRoot::new();
        let pin = root.initialized();
        assert_eq!(pin.len(), 64);
        assert_eq!(legacy_leaf_der_sha256(&fixture().der), pin);
        assert_ne!(legacy_leaf_der_sha256(&fixture().cert), pin,
            "the legacy pin hashes certificate DER, NEVER PEM text");
        let identity = check(&root, &pin).unwrap();
        assert_eq!(identity.leaf_der_sha256, pin);
        assert_eq!(identity.server_config.versions.len(), 1);
        assert_eq!(identity.server_config.versions[0].version,
            rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn existing_identity_is_real_tls12_keypair_and_serves_only_untrusted_http() {
        let root = TempRoot::new();
        let pin = root.initialized();
        let identity = check(&root, &pin).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (server, _) = listener.accept().unwrap();
        let hand = HandshakeAdmission::new(1, Duration::from_secs(2)).unwrap();
        let requests = RequestAdmission::new(1, Duration::from_secs(2)).unwrap();
        let work = spawn_tls12_decrypted_one_request(
            &hand, &requests, server, identity.server_config).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(fixture().der.clone())).unwrap();
        let client_cfg = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS12]).unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth());
        let tls = ClientConnection::new(
            client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
        let mut stream = StreamOwned::new(tls, client);
        stream.write_all(b"GET /v1/invitations/id HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        stream.flush().unwrap();
        let parsed = work.join().unwrap().unwrap();
        assert_eq!(parsed.target, "/v1/invitations/id");
        assert!(parsed.authorization.is_none(), "no implicit pairing authorization");
        assert_eq!(hand.active_handshakes(), 0);
        assert_eq!(requests.active_requests(), 0);
    }

    #[test]
    fn wrong_missing_or_uppercase_pin_refused_without_network_io() {
        let root = TempRoot::new();
        let correct = root.initialized();
        assert!(check(&root, &"0".repeat(64)).is_err());
        assert!(check(&root, "").is_err());
        assert!(check(&root, &correct.to_uppercase()).is_err());
        assert!(check(&root, "abcd").is_err());
    }

    #[test]
    fn root_only_directory_and_cert_key_modes_are_enforced() {
        let root = TempRoot::new();
        let pin = root.initialized();
        let setmode = |p: &Path, mode| {
            fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap()
        };
        setmode(&root.path, 0o777);
        assert!(check(&root, &pin).is_err());
        setmode(&root.path, 0o700);
        setmode(&root.path.join(KEY_NAME), 0o644);
        assert!(check(&root, &pin).is_err());
        setmode(&root.path.join(KEY_NAME), 0o600);
        setmode(&root.path.join(CERT_NAME), 0o666);
        assert!(check(&root, &pin).is_err());
        setmode(&root.path.join(CERT_NAME), 0o644);
        assert!(check(&root, &pin).is_ok());
        assert!(read_from_verified_dir(&root.file(), uid().wrapping_add(1), &pin).is_err());
    }

    #[test]
    fn symlink_and_hardlink_cert_key_are_rejected_without_following() {
        let root = TempRoot::new();
        let pin = root.initialized();
        let cert = root.path.join(CERT_NAME);
        let key = root.path.join(KEY_NAME);
        fs::rename(&cert, root.path.join("real.crt")).unwrap();
        symlink("real.crt", &cert).unwrap();
        assert!(check(&root, &pin).is_err());
        fs::remove_file(&cert).unwrap();
        fs::rename(root.path.join("real.crt"), &cert).unwrap();
        fs::rename(&key, root.path.join("real.key")).unwrap();
        symlink("real.key", &key).unwrap();
        assert!(check(&root, &pin).is_err());
        fs::remove_file(&key).unwrap();
        fs::rename(root.path.join("real.key"), &key).unwrap();
        fs::hard_link(&key, root.path.join("duplicate.key")).unwrap();
        assert!(check(&root, &pin).is_err());
        fs::remove_file(root.path.join("duplicate.key")).unwrap();
        fs::hard_link(&cert, root.path.join("duplicate.crt")).unwrap();
        assert!(check(&root, &pin).is_err());
        fs::remove_file(root.path.join("duplicate.crt")).unwrap();
        assert!(check(&root, &pin).is_ok());
    }

    #[test]
    fn every_untrusted_ancestor_or_symlinked_root_component_is_rejected() {
        let top = TempRoot::new();
        let child = top.path.join("child");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        let good = open_trusted_tree(&top.file(), &["child"], uid()).unwrap();
        check_dir(&good, uid(), true).unwrap();
        symlink("child", top.path.join("alias")).unwrap();
        assert!(open_trusted_tree(&top.file(), &["alias"], uid()).is_err());
        assert!(open_trusted_tree(&top.file(), &[".."], uid()).is_err());
        fs::set_permissions(&top.path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_trusted_tree(&top.file(), &["child"], uid()).is_err());
        fs::set_permissions(&top.path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(open_trusted_tree(&top.file(), &["child"], uid()).is_err());
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_trusted_tree(&top.file(), &["child"], uid()).is_ok());
    }

    #[test]
    fn missing_corrupt_or_oversized_identity_fails_closed() {
        let root = TempRoot::new();
        let pin = root.initialized();
        fs::remove_file(root.path.join(KEY_NAME)).unwrap();
        assert!(check(&root, &pin).is_err());
        root.write(KEY_NAME, &vec![b'X'; MAX_KEY_PEM_BYTES + 1], 0o600);
        assert!(check(&root, &pin).is_err());
        root.write(KEY_NAME, &fixture().key, 0o600);
        root.write(CERT_NAME, &vec![b'Z'; MAX_CERT_PEM_BYTES + 1], 0o644);
        assert!(check(&root, &pin).is_err());
        root.write(CERT_NAME, b"-----BEGIN CERTIFICATE-----\ninvalid!\n", 0o644);
        assert!(check(&root, &pin).is_err());
        root.write(CERT_NAME, &fixture().cert, 0o644);
        assert!(check(&root, &pin).is_ok());
    }

    #[test]
    fn production_path_is_fixed_never_from_tc_pair_root_or_external_config() {
        assert_eq!(PRODUCTION_TLS_DIR, "/var/lib/tradechannel/pairing-rs");
        assert_eq!(COMPONENTS, ["var", "lib", "tradechannel", "pairing-rs"]);
        assert_eq!(CERT_NAME, "tls.crt");
        assert_eq!(KEY_NAME, "tls.key");
        assert!(is_valid_pin(&"a".repeat(64)));
        assert!(!is_valid_pin(&"A".repeat(64)));
        if uid() != 0 {
            let err = read_existing_production_identity(&"a".repeat(64))
                .err().expect("nonroot production cert access unexpectedly succeeded");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
    }
}

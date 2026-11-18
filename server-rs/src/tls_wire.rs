//! SEC-02 real TLS1.2 encrypted-loopback interoperability candidate.
//!
//! Unlike the earlier plaintext TCP harness, all real HTTP bytes here are
//! decrypted by rustls before they reach the strict HTTP/1.1 decoder. The
//! encrypted wire still goes through the one monotonic DeadlineIo read/write
//! budget and independently capped handshake/one-request worker permits.
//!
//! NOT a production receiver: no real accept loop/public listener, no PEM
//! loading from server secrets, no legacy token/Revoked authorization, no
//! production HTTP JSON response/authorization, no WireGuard mutation, no cutover or restart.
//! An independent default-OFF feature exercises only a fail-closed JSON
//! denial envelope over REAL encrypted TLS1.2 application data.
//! This feature is OFF by default and only activated for Linux tests.
//!
//! The TLS server authenticates ITSELF to the client with a certificate,
//! but does NOT authenticate the client. Every ParsedRequest remains fully
//! untrusted and MUST NOT be used to authorize an invitation.
#![cfg(all(target_os = "linux", feature = "linux-tls-wire-lab"))]

use crate::handshake_admission::{DeadlineIo, HandshakeAdmission, RequestAdmission};
use crate::http_one_request::{read_one_request, ParsedRequest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ProtocolVersion, ServerConfig, ServerConnection, Stream};
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread::JoinHandle;

/// Build a TLS 1.2 ONLY test candidate: no opportunistic TLS 1.3 upgrade,
/// old-client cipher downgrade or encryption fallback. Reject invalid keys.
/// Caller supplies verified DER from its own trusted provisioning; this
/// function neither reads user-writable files nor rotates live certificates.
pub fn tls12_server_config(
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> io::Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SEC-02 TLS1.2 provider mismatch"))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SEC-02 invalid TLS identity"))?;
    Ok(Arc::new(config))
}

/// One shared real TLS1.2 handshake implementation for both read-only
/// candidate and denial-only JSON wire test. Never authenticate a pairing
/// request from handshake success (TLS here authenticates server, not client).
fn finish_tls12_handshake(
    config: Arc<ServerConfig>,
    transport: &mut DeadlineIo,
) -> io::Result<ServerConnection> {
    let mut tls = ServerConnection::new(config)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SEC-02 TLS config refused"))?;
    while tls.is_handshaking() {
        let (read, _written) = tls.complete_io(transport)?;
        if read == 0 && tls.is_handshaking() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                "SEC-02 TLS handshake terminated before authentication"));
        }
    }
    if tls.protocol_version() != Some(ProtocolVersion::TLSv1_2) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "SEC-02 TLS protocol must be exactly 1.2"));
    }
    Ok(tls)
}

/// Server-side REAL encrypted handshake and ONE decrypted HTTP/1.1 message.
///
/// It uses exactly the same bounded shared worker/reservation policy as
/// PR #20. TLS1.2 handshake must finish before any application parsing;
/// a failed TLS handshake never invokes the HTTP callback. The resulting
/// ParsedRequest is UNAUTHENTICATED and the worker closes its TCP stream.
/// No HTTP response is emitted (including success/error) by this lab.
pub fn spawn_tls12_decrypted_one_request(
    handshakes: &HandshakeAdmission,
    requests: &RequestAdmission,
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> io::Result<JoinHandle<io::Result<ParsedRequest>>> {
    handshakes.spawn_one_request(
        requests,
        stream,
        move |transport: &mut DeadlineIo| {
            finish_tls12_handshake(config, transport)
        },
        |transport, mut tls| {
            // The HTTP parser MUST see the DECRYPTED TLS stream, not the
            // DeadlineIo ciphertext bytes. Underlying socket reads/writes
            // remain bound by the absolute HTTP-stage deadline.
            let mut decrypted = Stream::new(&mut tls, transport);
            read_one_request(&mut decrypted)
        },
    )
}


/// REAL rustls TLS1.2 encrypted HTTP JSON **DENY-ONLY** lab.
/// It is intentionally incapable of authorizing an invitation or mutating
/// server state. Every syntactically valid GET/POST gets a legacy-shaped
/// `500 {"Code":"InvalidState","Ok":false}`, even with bearer tokens.
/// Invalid framing gets 400 InvalidRequest. TLS errors/timeouts close.
/// A trusted ledger and authorizer have NOT been installed.
#[cfg(feature = "linux-http-deny-response-lab")]
pub fn spawn_tls12_denial_only_response(
    handshakes: &HandshakeAdmission,
    requests: &RequestAdmission,
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> io::Result<JoinHandle<io::Result<()>>> {
    handshakes.spawn_one_request(
        requests,
        stream,
        move |transport| finish_tls12_handshake(config, transport),
        |transport, mut tls| {
            let result = {
                let mut decrypted = Stream::new(&mut tls, transport);
                crate::http_fail_closed::serve_denial_only(&mut decrypted)
            };
            if result.is_ok() {
                // A bounded TLS close_notify prevents clients from mistaking
                // EOF for a truncated HTTP JSON envelope. Do not read more
                // requests or accept TLS early data / keep-alive.
                tls.send_close_notify();
                while tls.wants_write() {
                    if tls.write_tls(transport)? == 0 {
                        return Err(io::Error::new(io::ErrorKind::WriteZero,
                            "SEC-02 TLS close_notify not flushed"));
                    }
                }
            }
            result
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::ClientConnection;
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, StreamOwned};
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;
    use std::time::Duration;

    struct TestIdentity {
        ca: Vec<u8>,
        leaf: Vec<u8>,
        pkcs8_key: Vec<u8>,
    }

    /// A fresh ephemeral localhost test CA and leaf generated by openssl
    /// ONLY for test fixtures. OpenSSL never implements TLS on the server:
    /// rustls performs every real encrypted handshake over loopback TCP.
    fn fixture() -> &'static TestIdentity {
        static MATERIAL: OnceLock<TestIdentity> = OnceLock::new();
        MATERIAL.get_or_init(|| {
            let dir = std::env::temp_dir().join(
                format!("spidervpn-sec02-wire-fixture-{}", std::process::id()));
            fs::create_dir(&dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fn run(dir: &Path, args: &[&str]) {
                let status = Command::new("openssl").args(args)
                    .current_dir(dir)
                    .stdout(Stdio::null()).stderr(Stdio::null())
                    .status().expect("SEC-02 Linux openssl fixture generator absent");
                assert!(status.success(), "SEC-02 test certificate fixture generation failed");
            }
            run(&dir, &["req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=SpiderVPN-SEC02-Test-CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", "ca.key", "-out", "ca.pem"]);
            run(&dir, &["req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=localhost", "-keyout", "server.key",
                "-out", "server.csr"]);
            fs::write(dir.join("extensions.txt"),
                "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
            run(&dir, &["x509", "-req", "-in", "server.csr", "-CA",
                "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days",
                "1", "-sha256", "-extfile", "extensions.txt", "-out", "server.pem"]);
            run(&dir, &["x509", "-in", "server.pem", "-outform", "DER", "-out", "server.der"]);
            run(&dir, &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]);
            run(&dir, &["pkcs8", "-topk8", "-nocrypt", "-in",
                "server.key", "-outform", "DER", "-out", "server.key.der"]);
            let identity = TestIdentity {
                ca: fs::read(dir.join("ca.der")).unwrap(),
                leaf: fs::read(dir.join("server.der")).unwrap(),
                pkcs8_key: fs::read(dir.join("server.key.der")).unwrap(),
            };
            fs::remove_dir_all(dir).unwrap();
            identity
        })
    }

    fn server_config() -> Arc<ServerConfig> {
        let material = fixture();
        tls12_server_config(
            vec![CertificateDer::from(material.leaf.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.pkcs8_key.clone())),
        ).unwrap()
    }

    fn client_config(versions: &[&'static rustls::SupportedProtocolVersion])
        -> Arc<ClientConfig>
    {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(fixture().ca.clone())).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions).unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth())
    }

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    fn client_on(socket: TcpStream, config: Arc<ClientConfig>, name: &str)
        -> StreamOwned<ClientConnection, TcpStream>
    {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let session = ClientConnection::new(config, name).unwrap();
        StreamOwned::new(session, socket)
    }

    fn policy(handshake_millis: u64, request_millis: u64)
        -> (HandshakeAdmission, RequestAdmission)
    {
        (HandshakeAdmission::new(2, Duration::from_millis(handshake_millis)).unwrap(),
         RequestAdmission::new(2, Duration::from_millis(request_millis)).unwrap())
    }

    #[test]
    fn tls12_real_encrypted_get_and_post_reach_only_decrypted_http_parser() {
        let (hand, req) = policy(2_000, 2_000);
        for (wire, method) in [
            (&b"GET /v1/invitations/abc HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\n\r\n"[..],
             crate::http_one_request::Method::Get),
            (&b"POST /v1/invitations/abc/consume HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nABCD"[..],
             crate::http_one_request::Method::Post),
        ] {
            let (server, client) = pair();
            let job = spawn_tls12_decrypted_one_request(
                &hand, &req, server, server_config()).unwrap();
            let mut secure_client = client_on(
                client, client_config(&[&rustls::version::TLS12]), "localhost");
            secure_client.write_all(wire).unwrap();
            secure_client.flush().unwrap();
            let result = job.join().unwrap().unwrap();
            assert_eq!(result.method, method);
            if method == crate::http_one_request::Method::Post {
                assert_eq!(result.body, b"ABCD");
            } else {
                assert_eq!(result.authorization.as_deref(), Some("Bearer test-secret"));
                assert!(!format!("{result:?}").contains("test-secret"));
            }
        }
        assert_eq!(hand.active_handshakes(), 0);
        assert_eq!(req.active_requests(), 0);
    }

    #[test]
    fn tls13_only_client_rejected_without_http_request_handler() {
        let (hand, req) = policy(1_000, 1_000);
        let (server, client) = pair();
        let job = spawn_tls12_decrypted_one_request(
            &hand, &req, server, server_config()).unwrap();
        let mut secure_client = client_on(
            client, client_config(&[&rustls::version::TLS13]), "localhost");
        let result = secure_client.write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(result.is_err() || secure_client.flush().is_err(),
            "TLS1.3 client must not negotiate with TLS1.2-only server");
        assert!(job.join().unwrap().is_err());
        assert_eq!(req.active_requests(), 0);
        assert_eq!(hand.active_handshakes(), 0);
    }

    #[test]
    fn tls12_wrong_server_name_fails_certificate_validation() {
        let (hand, req) = policy(1_000, 1_000);
        let (server, client) = pair();
        let job = spawn_tls12_decrypted_one_request(
            &hand, &req, server, server_config()).unwrap();
        let mut secure_client = client_on(
            client, client_config(&[&rustls::version::TLS12]), "not-localhost");
        let result = secure_client.write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(result.is_err() || secure_client.flush().is_err(),
            "wrong TLS server name must not verify");
        assert!(job.join().unwrap().is_err());
        assert_eq!(req.active_requests(), 0);
        assert_eq!(hand.active_handshakes(), 0);
    }

    #[test]
    fn idle_tls_client_times_out_but_healthy_tls12_peer_is_independent() {
        let (hand, req) = policy(700, 1_000);
        let (idle_server, _idle_client) = pair();
        let idle = spawn_tls12_decrypted_one_request(
            &hand, &req, idle_server, server_config()).unwrap();
        let (healthy_server, healthy_client) = pair();
        let good = spawn_tls12_decrypted_one_request(
            &hand, &req, healthy_server, server_config()).unwrap();
        let mut tls = client_on(
            healthy_client, client_config(&[&rustls::version::TLS12]), "localhost");
        tls.write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        tls.flush().unwrap();
        assert_eq!(good.join().unwrap().unwrap().target, "/ready");
        assert_eq!(idle.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(hand.active_handshakes(), 0);
        assert_eq!(req.active_requests(), 0);
    }

    #[test]
    fn tls12_decrypted_slow_header_trickle_cannot_extend_request_deadline() {
        use std::thread;
        let (hand, req) = policy(2_000, 190);
        let (server, socket) = pair();
        let job = spawn_tls12_decrypted_one_request(
            &hand, &req, server, server_config()).unwrap();
        let mut tls = client_on(socket, client_config(&[&rustls::version::TLS12]), "localhost");
        // First write performs a real encrypted TLS handshake; subsequent
        // tiny encrypted application records deliberately drip over >190ms.
        tls.write_all(b"G").unwrap();
        tls.flush().unwrap();
        for _ in 0..12 {
            thread::sleep(Duration::from_millis(30));
            if tls.write_all(b"E").is_err() || tls.flush().is_err() {
                break;
            }
        }
        assert_eq!(job.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(hand.active_handshakes(), 0);
        assert_eq!(req.active_requests(), 0);
    }

    #[test]
    fn tls12_malformed_content_length_is_rejected_after_decryption() {
        let (hand, req) = policy(1_500, 1_500);
        let (server, socket) = pair();
        let job = spawn_tls12_decrypted_one_request(
            &hand, &req, server, server_config()).unwrap();
        let mut tls = client_on(socket, client_config(&[&rustls::version::TLS12]), "localhost");
        tls.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nAB").unwrap();
        tls.flush().unwrap();
        assert_eq!(job.join().unwrap().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(req.active_requests(), 0);
        assert_eq!(hand.active_handshakes(), 0);
    }

    #[test]
    fn invalid_empty_certificate_and_key_rejected_before_network_accept() {
        let bad = tls12_server_config(
            vec![CertificateDer::from(vec![0u8; 3])],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0u8; 3])),
        );
        assert!(bad.is_err());
    }
}

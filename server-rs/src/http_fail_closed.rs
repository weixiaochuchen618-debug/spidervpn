//! SEC-02 strict legacy-compatible JSON error envelopes over decrypted TLS.
//!
//! CRITICAL: this is not an authorized pairing receiver. It never consults
//! invitation files, never returns Ok:true and never mutates WireGuard.
//! An untrusted valid request MUST NOT advance the pairing state.
//! In the absence of a trusted SEC-01/08 Revoked/Consumed authority,
//! every parsed request returns the same fail-closed InvalidState envelope.
//! The caller must run this on a real decrypted, deadline-bound rustls Stream,
//! permit only ONE request and close the TLS connection thereafter.
//! Feature OFF by default; no public listener/service entry point.
#![cfg(all(target_os = "linux", feature = "linux-http-deny-response-lab"))]

use crate::http_one_request::read_one_request;
use std::io::{self, Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// Valid request, but no trusted revoke-aware authority is available.
    MissingAuthority,
    /// Invalid HTTP framing: no request was authorized or executed.
    MalformedRequest,
}

impl Denial {
    fn status(self) -> (&'static str, &'static [u8]) {
        match self {
            Denial::MissingAuthority => (
                "500 Internal Server Error",
                br#"{"Code":"InvalidState","Ok":false}"#,
            ),
            Denial::MalformedRequest => (
                "400 Bad Request",
                br#"{"Code":"InvalidRequest","Ok":false}"#,
            ),
        }
    }
}

/// Emit exactly one bounded legacy-shaped JSON error, never success data.
/// Header/body lengths are computed from fixed Rust byte strings, not remote
/// Content-Length, Host, token or user-controlled error text.
pub fn write_denial<W: Write>(stream: &mut W, denial: Denial) -> io::Result<()> {
    let (status, body) = denial.status();
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Decode one HTTP/1.1 message, then DENY it. Read timeouts and transport
/// failures cannot become a 400/500 success: they propagate and close socket.
/// Only explicit invalid-data framing is translated to a 400 envelope.
pub fn serve_denial_only<S: Read + Write>(stream: &mut S) -> io::Result<()> {
    let denial = match read_one_request(stream) {
        Ok(_) => Denial::MissingAuthority,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Denial::MalformedRequest,
        Err(e) => return Err(e),
    };
    write_denial(stream, denial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_admission::{HandshakeAdmission, RequestAdmission};
    use crate::tls_wire::{spawn_tls12_denial_only_response, tls12_server_config};
    use rustls::client::ClientConnection;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, StreamOwned};
    use serde_json::Value;
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use std::fs;
    use std::process::{Command, Stdio};

    struct Fixture { ca: Vec<u8>, leaf: Vec<u8>, key: Vec<u8> }

    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            // Independent, temporary localhost fixture only; never a
            // production certificate or a replacement for an existing pin.
            let tmp = std::env::temp_dir().join(format!(
                "spidervpn-sec02-deny-fixture-{}", std::process::id()));
            fs::create_dir(&tmp).unwrap();
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let run = |args: &[&str]| {
                let result = Command::new("openssl").args(args).current_dir(&tmp)
                    .stdout(Stdio::null()).stderr(Stdio::null())
                    .status().expect("OpenSSL fixture tool missing");
                assert!(result.success(), "TLS fixture creation failed");
            };
            run(&["req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=SpiderVPN-Denial-Fixture-CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", "ca.key", "-out", "ca.pem"]);
            run(&["req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=localhost", "-keyout", "leaf.key",
                "-out", "leaf.csr"]);
            fs::write(tmp.join("extensions.txt"),
                "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
            run(&["x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem",
                "-CAkey", "ca.key", "-CAcreateserial", "-days", "1",
                "-sha256", "-extfile", "extensions.txt", "-out", "leaf.pem"]);
            run(&["x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der"]);
            run(&["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]);
            run(&["pkcs8", "-topk8", "-nocrypt", "-in", "leaf.key",
                "-outform", "DER", "-out", "leaf.key.der"]);
            let f = Fixture {
                ca: fs::read(tmp.join("ca.der")).unwrap(),
                leaf: fs::read(tmp.join("leaf.der")).unwrap(),
                key: fs::read(tmp.join("leaf.key.der")).unwrap(),
            };
            fs::remove_dir_all(&tmp).unwrap();
            f
        })
    }

    fn server_config() -> Arc<rustls::ServerConfig> {
        let f = fixture();
        tls12_server_config(
            vec![CertificateDer::from(f.leaf.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(f.key.clone())),
        ).unwrap()
    }

    fn client_config() -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(fixture().ca.clone())).unwrap();
        Arc::new(ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider()
        )).with_protocol_versions(&[&rustls::version::TLS12]).unwrap()
            .with_root_certificates(roots).with_no_client_auth())
    }

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        (l.accept().unwrap().0, c)
    }

    fn wire_once(request: &[u8]) -> io::Result<(Vec<u8>, io::Result<()>)> {
        let hand = HandshakeAdmission::new(1, Duration::from_secs(2)).unwrap();
        let slots = RequestAdmission::new(1, Duration::from_secs(2)).unwrap();
        let (server, client) = pair();
        let work = spawn_tls12_denial_only_response(&hand, &slots, server, server_config())?;
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let conn = ClientConnection::new(client_config(),
            ServerName::try_from("localhost").unwrap()).unwrap();
        let mut tls = StreamOwned::new(conn, client);
        tls.write_all(request)?;
        tls.flush()?;
        let mut data = Vec::new();
        tls.read_to_end(&mut data)?;
        let result = work.join().unwrap();
        assert_eq!(hand.active_handshakes(), 0);
        assert_eq!(slots.active_requests(), 0);
        Ok((data, result))
    }

    fn parse_envelope(wire: &[u8]) -> (String, Value) {
        let raw = std::str::from_utf8(wire).unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 "));
        assert!(head.contains("\r\nContent-Type: application/json\r\n"));
        assert!(head.contains("\r\nConnection: close"));
        let actual = head.lines().find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap().trim().parse::<usize>().unwrap();
        assert_eq!(actual, body.len(), "Content-Length mismatch");
        (head.to_owned(), serde_json::from_str(body).unwrap())
    }

    #[test]
    fn standalone_response_follows_old_json_envelope_and_never_returns_ok_true() {
        for denial in [Denial::MissingAuthority, Denial::MalformedRequest] {
            let mut out = Vec::new();
            write_denial(&mut out, denial).unwrap();
            let (head, json) = parse_envelope(&out);
            assert_eq!(json["Ok"], false);
            assert!(json.get("Data").is_none());
            assert_eq!(json["Code"],
                if denial == Denial::MissingAuthority { "InvalidState" }
                else { "InvalidRequest" });
            assert!(head.starts_with(if denial == Denial::MissingAuthority {
                "HTTP/1.1 500 " } else { "HTTP/1.1 400 " }));
            assert!(!head.contains("Transfer-Encoding"));
        }
    }

    #[test]
    fn valid_get_with_bearer_and_valid_post_with_body_are_both_denied_over_real_tls12() {
        for request in [
            &b"GET /v1/invitations/11111111-1111-4111-8111-111111111111 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer PRIVATE-SECRET-DO-NOT-ECHO\r\n\r\n"[..],
            &b"POST /v1/invitations/11111111-1111-4111-8111-111111111111/consume HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nAuthorization: Bearer PRIVATE-SECRET-DO-NOT-ECHO\r\n\r\nTEST"[..],
        ] {
            let (wire, result) = wire_once(request).unwrap();
            result.unwrap();
            let (head, json) = parse_envelope(&wire);
            assert!(head.starts_with("HTTP/1.1 500 "));
            assert_eq!(json, serde_json::json!({"Code":"InvalidState","Ok":false}));
            assert!(!String::from_utf8_lossy(&wire).contains("PRIVATE-SECRET"));
        }
    }

    #[test]
    fn malformed_duplicate_length_gets_400_without_authority_or_data_leak() {
        let request = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nA";
        let (wire, result) = wire_once(request).unwrap();
        result.unwrap();
        let (head, json) = parse_envelope(&wire);
        assert!(head.starts_with("HTTP/1.1 400 "));
        assert_eq!(json, serde_json::json!({"Code":"InvalidRequest","Ok":false}));
    }

    #[test]
    fn pipelined_second_message_never_has_second_response_or_success() {
        let wire = b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\nGET /two HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (response, result) = wire_once(wire).unwrap();
        // An unconsumed pipelined record may provoke a TCP RST; when the
        // TLS close_notify was delivered, it must still never be a second
        // HTTP response. A separate TLS test checks this actual wire.
        result.unwrap();
        let content = String::from_utf8_lossy(&response);
        assert_eq!(content.matches("HTTP/1.1").count(), 1);
        assert!(!content.contains("Ok\":true"));
    }

    #[test]
    fn a_short_or_idle_request_never_produces_a_success_envelope() {
        let mut stream = Cursor::new(b"GET / HTTP/1.1\r\nHost: local".to_vec());
        let mut output = Vec::new();
        let result = read_one_request(&mut stream);
        assert!(result.is_err());
        write_denial(&mut output, Denial::MissingAuthority).unwrap();
        let (_, json) = parse_envelope(&output);
        assert_eq!(json["Ok"], false);
    }
}

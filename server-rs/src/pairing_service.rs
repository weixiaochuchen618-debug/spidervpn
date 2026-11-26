//! MVP-04 Stage 3 opt-in actual TLS1.2 pairing service, loopback only.
//! One explicitly provisioned invitation and authority root per listener.
//! Not a CLI, systemd unit, public service, legacy importer or writer fence.
//! Provisioning must exclude non-cooperating privileged writers.
#![cfg(all(target_os = "linux", feature = "linux-pairing-service"))]

use crate::authorization_response::TrustedResponseConfig;
use crate::fresh_consume_gate::{
    check_service_scope, consume_authorization, read_open_descriptor,
    verify_pinned_invite_metadata, FreshEnrollError, GateError,
};
use crate::handshake_admission::{HandshakeAdmission, RequestAdmission};
use crate::http_one_request::{Method, ParsedRequest, MAX_BODY_BYTES};
use crate::ledger_disk::LedgerStore;
use crate::tls_wire::{spawn_tls12_pairing_response, tls12_server_config};
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use serde_json::{json, Value};
use std::io;
use std::net::{IpAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_CONNECTIONS: usize = 64;
const POLL: Duration = Duration::from_millis(5);
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(5);
const REQUEST_BUDGET: Duration = Duration::from_secs(30);

/// Owned trusted provisioning, deliberately not deserializable or Debug.
/// Neither a caller-supplied ServerConfig nor request fields may select
/// the TLS key, ledger root, binding, interface or response config.
pub struct PairingAuthority {
    root: PathBuf,
    interface: String,
    metadata: Vec<u8>,
    metadata_pin: String,
    tls_pin: String,
    config: TrustedResponseConfig,
    management: rsa::RsaPrivateKey,
    tls: Arc<ServerConfig>,
}

fn sha256(raw: &[u8]) -> String {
    digest::digest(&digest::SHA256, raw).as_ref().iter()
        .map(|b| format!("{b:02x}")).collect()
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "pairing service provisioning refused")
}

impl PairingAuthority {
    /// All pins and the root/interface must originate from trusted local
    /// provisioning, NOT from the presented bearer, HTTP or legacy JSON.
    /// The leaf pin is the exact DER SHA256 used by the legacy client.
    /// Metadata HMAC and descriptor are checked against the actual request
    /// later, so no plaintext bearer is stored in the service.
    pub fn new(root: PathBuf, interface: String,
        metadata: Vec<u8>, metadata_pin: String,
        config: TrustedResponseConfig, management: rsa::RsaPrivateKey,
        certificates: Vec<CertificateDer<'static>>, private_key: PrivateKeyDer<'static>,
        tls_pin: String) -> io::Result<Self>
    {
        if !root.is_absolute() || !crate::wg_readonly::valid_interface(&interface)
            || metadata.is_empty() || metadata.len() > MAX_BODY_BYTES
            || !crate::hex_sha256(&metadata_pin) || sha256(&metadata) != metadata_pin
            || !crate::hex_sha256(&tls_pin)
            || certificates.first().is_none_or(|c| sha256(c.as_ref()) != tls_pin)
        { return Err(invalid()); }
        let tls = tls12_server_config(certificates, private_key)?;
        Ok(Self { root, interface, metadata, metadata_pin, tls_pin, config, management, tls })
    }

    pub(crate) fn tls_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.tls)
    }

    fn dispatch(&self, request: &ParsedRequest) -> Result<Value, GateError> {
        let bearer = request.authorization.as_deref()
            .and_then(|a| a.strip_prefix("Bearer ")).ok_or(GateError::Forbidden)?;
        let metadata = verify_pinned_invite_metadata(&self.metadata, &self.metadata_pin, bearer)?;
        let scope = metadata.scope()?;
        check_service_scope(&scope, request, &self.interface, &self.tls_pin,
            &self.config, &self.management)?;
        // No waiting queue, no lock while reading unauthenticated network
        // data, no state copied outside this exclusive transaction. Busy
        // or invalid storage fails closed. The lock is released before
        // writing the response to the network.
        let mut store = LedgerStore::open_existing(&self.root, Duration::ZERO)
            .map_err(|_| GateError::InvalidState)?;
        match request.method {
            Method::Get => read_open_descriptor(&store, &scope, request)
                .map(|d| d.legacy_data()),
            Method::Post => consume_authorization(&mut store, &scope, request,
                &self.interface, &self.config, &self.management).map_err(|e| match e {
                    FreshEnrollError::Gate(g) => g,
                    FreshEnrollError::Ledger(_) | FreshEnrollError::Apply(_) => GateError::InvalidState,
                }),
        }
    }

    /// Only the concrete TLS worker can reach this crate-private method.
    /// Return a bounded, single HTTP response, not arbitrary error text.
    pub(crate) fn reply(&self, request: io::Result<ParsedRequest>) -> io::Result<Vec<u8>> {
        let data = match request {
            Ok(request) => self.dispatch(&request),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(GateError::InvalidRequest),
            Err(e) => return Err(e),
        };
        encode_reply(data)
    }
}

fn refusal(error: GateError) -> (&'static str, &'static str) {
    match error {
        GateError::NotFound => ("404 Not Found", "NotFound"),
        GateError::InviteNotFound => ("404 Not Found", "InviteNotFound"),
        GateError::Forbidden => ("403 Forbidden", "Forbidden"),
        GateError::InvalidState => ("500 Internal Server Error", "InvalidState"),
        GateError::InviteExpired => ("410 Gone", "InviteExpired"),
        GateError::InviteCancelled => ("410 Gone", "InviteCancelled"),
        GateError::InviteConsumed => ("409 Conflict", "InviteConsumed"),
        GateError::Revoked => ("403 Forbidden", "Revoked"),
        GateError::InvalidRequest => ("400 Bad Request", "InvalidRequest"),
        GateError::InvalidPairRequest => ("400 Bad Request", "InvalidPairRequest"),
        GateError::InviteMismatch => ("409 Conflict", "InviteMismatch"),
        GateError::PairingMismatch => ("409 Conflict", "PairingMismatch"),
    }
}

fn encode_reply(result: Result<Value, GateError>) -> io::Result<Vec<u8>> {
    let (mut status, envelope) = match result {
        Ok(data) => ("200 OK", json!({"Ok":true,"Data":data})),
        Err(e) => {
            let (status, code) = refusal(e);
            (status, json!({"Ok":false,"Code":code}))
        }
    };
    let mut body = serde_json::to_vec(&envelope).map_err(|_| invalid())?;
    if body.len() > MAX_BODY_BYTES {
        status = "500 Internal Server Error";
        body = br#"{"Ok":false,"Code":"InvalidState"}"#.to_vec();
    }
    let mut wire = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    wire.extend(body);
    Ok(wire)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ServiceReport {
    pub accepted: u64,
    pub global_rejected: u64,
    pub source_rejected: u64,
    pub admission_rejected: u64,
    pub completed: u64,
    pub failed: u64,
    pub peak_workers: usize,
}

type Worker = (IpAddr, JoinHandle<io::Result<()>>);

fn bump(n: &mut u64) { *n = n.saturating_add(1); }
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
fn finish(worker: Worker, report: &mut ServiceReport) {
    // Completed is transport completion only, NOT authorization success.
    match worker.1.join() {
        Ok(Ok(())) => bump(&mut report.completed),
        Ok(Err(_)) | Err(_) => bump(&mut report.failed),
    }
}

/// Actual bounded TCP accept loop, owned listener and one-way stop flag.
/// No detached work, caller must not clone the listening FD. The global
/// and kernel-source cap spans both handshake and request phases. Drain
/// existing workers only after closing the listening socket. Network IO
/// is absolutely bounded; protected local disk operations and existing
/// WG transaction execution are not forcibly interrupted at a deadline.
pub fn run_loopback_pairing_service(listener: TcpListener, authority: PairingAuthority,
    max_connections: usize, max_per_source: usize, stop: &AtomicBool)
    -> io::Result<ServiceReport>
{
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "pairing service refuses non-loopback listener"));
    }
    if !(1..=MAX_CONNECTIONS).contains(&max_connections)
        || !(1..=max_connections).contains(&max_per_source) { return Err(invalid()); }
    let handshakes = HandshakeAdmission::new(max_connections, HANDSHAKE_BUDGET)?;
    let requests = RequestAdmission::new(max_connections, REQUEST_BUDGET)?;
    let authority = Arc::new(authority);
    listener.set_nonblocking(true)?;
    let mut report = ServiceReport::default();
    let mut workers: Vec<Worker> = Vec::with_capacity(max_connections);
    let mut fatal = None;
    while !stop.load(Ordering::Acquire) {
        let mut i = 0;
        while i < workers.len() {
            if workers[i].1.is_finished() { finish(workers.swap_remove(i), &mut report); }
            else { i += 1; }
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                bump(&mut report.accepted);
                if stop.load(Ordering::Acquire) { break; }
                let source = source_key(peer.ip());
                if workers.len() >= max_connections {
                    bump(&mut report.global_rejected);
                    continue;
                }
                if workers.iter().filter(|w| w.0 == source).count() >= max_per_source {
                    bump(&mut report.source_rejected);
                    continue;
                }
                if let Err(e) = stream.set_nonblocking(false) {
                    bump(&mut report.failed);
                    fatal = Some(e);
                    break;
                }
                match spawn_tls12_pairing_response(&handshakes, &requests, stream,
                    Arc::clone(&authority)) {
                    Ok(worker) => {
                        workers.push((source, worker));
                        report.peak_workers = report.peak_workers.max(workers.len());
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock =>
                        bump(&mut report.admission_rejected),
                    Err(e) => {
                        bump(&mut report.failed);
                        fatal = Some(e);
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => { fatal = Some(e); break; }
        }
    }
    drop(listener);
    for worker in workers { finish(worker, &mut report); }
    match fatal { Some(e) => Err(e), None => Ok(report) }
}

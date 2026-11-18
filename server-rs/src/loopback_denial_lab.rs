//! SEC-02: finite real TCP accept loop, only for the default-OFF TLS denial lab.
//!
//! This is NOT a pairing daemon, cutover, public listener or authorization API.
//! The caller supplies a pre-bound LOOPBACK listener: this module will reject
//! wildcard/public addresses before accepting. It never binds a network port.
//! Each accepted socket goes to the existing bounded Rustls TLS1.2 handshake,
//! one strict decrypted HTTP/1.1 request and ONE fail-closed JSON denial.
//! Saturated connections are closed, not queued or given unbounded workers.
//! No WireGuard, invitation ledger, Python receiver or Windows code is touched.
#![cfg(all(target_os = "linux", feature = "linux-bounded-accept-lab"))]

use crate::handshake_admission::{HandshakeAdmission, RequestAdmission};
use crate::tls_wire::spawn_tls12_denial_only_response;
use rustls::ServerConfig;
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_LAB_CONNECTIONS: usize = 64;
const MIN_ACCEPT_WINDOW: Duration = Duration::from_millis(100);
const MAX_ACCEPT_WINDOW: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LabReport {
    pub accepted: usize,
    /// Connections closed immediately due to exhausted handshake capacity.
    pub saturated: usize,
    /// Exactly one denied HTTP message over a verified TLS1.2 session.
    pub denied: usize,
    /// Failed handshakes, malformed/idle requests, or worker failures.
    pub failed: usize,
}

/// Exercise a finite accept loop on a disposable localhost listener.
///
/// The trusted caller owns/binds the socket, and must use a test certificate.
/// All deadlines and capacities still come from HandshakeAdmission and
/// RequestAdmission; the accept window is an ADDITIONAL finite upper bound.
/// This function has no binary or systemd entry point and is feature-OFF.
/// A production daemon will require a separately reviewed root-only identity,
/// authenticated revocation-aware authority, lifecycle and rollback.
pub fn run_loopback_denial_lab(
    listener: TcpListener,
    handshakes: &HandshakeAdmission,
    requests: &RequestAdmission,
    config: Arc<ServerConfig>,
    connections: usize,
    accept_window: Duration,
) -> io::Result<LabReport> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "SEC-02 denial lab refuses public/wildcard listeners"));
    }
    if !(1..=MAX_LAB_CONNECTIONS).contains(&connections)
        || !(MIN_ACCEPT_WINDOW..=MAX_ACCEPT_WINDOW).contains(&accept_window)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "SEC-02 accept count/deadline must be finite and bounded"));
    }
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + accept_window;
    let mut report = LabReport::default();
    let mut workers: Vec<JoinHandle<io::Result<()>>> = Vec::new();
    let mut accept_error = None;

    while report.accepted < connections {
        if Instant::now() >= deadline {
            accept_error = Some(io::Error::new(io::ErrorKind::TimedOut,
                "SEC-02 bounded lab accept window expired"));
            break;
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                report.accepted += 1;
                // On Linux accept() normally returns a blocking socket even
                // when the listening FD is nonblocking; set it explicitly.
                if let Err(error) = stream.set_nonblocking(false) {
                    report.failed += 1;
                    accept_error = Some(error);
                    break;
                }
                match spawn_tls12_denial_only_response(
                    handshakes, requests, stream, Arc::clone(&config),
                ) {
                    Ok(worker) => workers.push(worker),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        // spawn_* consumes/drops the rejected TcpStream.
                        report.saturated += 1;
                    }
                    Err(error) => {
                        report.failed += 1;
                        accept_error = Some(error);
                        break;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                accept_error = Some(error);
                break;
            }
        }
    }
    // Even when accept stops early, let bounded workers release permits.
    // No detached handler may be counted as a successful completed denial.
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => report.denied += 1,
            Ok(Err(_)) | Err(_) => report.failed += 1,
        }
    }
    match accept_error {
        Some(error) => Err(error),
        None => Ok(report),
    }
}

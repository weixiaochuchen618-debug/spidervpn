//! SEC-02 long-lived, bounded, STOPPABLE listener candidate. Default OFF.
//! Only a caller-owned loopback listener and denial-only TLS are allowed.
//! No service installation, public bind, ledger, authentication or WG access.
//! The accept owner retains at most max_connections worker handles, reaps
//! completed workers continuously and counts a source through BOTH TLS/HTTP
//! phases. There is no per-address history or unbounded pending work queue.
//! The kernel's TCP backlog is separate; this is not DDoS protection.
#![cfg(all(target_os = "linux", feature = "linux-persistent-listener-lab"))]

use crate::handshake_admission::{HandshakeAdmission, RequestAdmission};
use crate::tls_wire::spawn_tls12_denial_only_response;
use rustls::ServerConfig;
use std::io;
use std::net::{IpAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_CONNECTIONS: usize = 64;
const POLL: Duration = Duration::from_millis(5);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ServiceReport {
    pub accepted: u64,
    pub global_rejected: u64,
    pub source_rejected: u64,
    pub handshake_rejected: u64,
    pub stopped_before_admission: u64,
    pub denied: u64,
    pub failed: u64,
    pub peak_workers: usize,
}

type Worker = (IpAddr, JoinHandle<io::Result<()>>);

fn increment(value: &mut u64) {
    *value = value.saturating_add(1);
}

// An IPv4-mapped IPv6 address represents the SAME source, not a separate
// allowance. The actual kernel peer address is used, never HTTP headers,
// Host, forwarded-for, ports or token contents.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

fn finish(worker: Worker, report: &mut ServiceReport) {
    match worker.1.join() {
        Ok(Ok(())) => increment(&mut report.denied),
        Ok(Err(_)) | Err(_) => increment(&mut report.failed),
    }
}

fn reap(workers: &mut Vec<Worker>, report: &mut ServiceReport) {
    let mut i = 0;
    while i < workers.len() {
        if workers[i].1.is_finished() {
            finish(workers.swap_remove(i), report);
        } else {
            i += 1;
        }
    }
}

/// Serve until the caller sets the stop flag (one-way false -> true).
/// At shutdown/fatal accept or spawn error, close the listener BEFORE
/// draining admitted workers. Worker I/O has the existing independent
/// monotonic handshake and request deadlines; this is graceful drain, not
/// immediate cancellation of a currently executing worker. No user-space
/// queued connections, detached workers or retained completed handles.
/// This API is a lab, not a systemd/signal integration or public listener.
/// Caller must not clone the listening FD or share admission objects with
/// another listener. The global cap here spans both worker phases.
pub fn run_persistent_denial_lab(
    listener: TcpListener,
    handshakes: &HandshakeAdmission,
    requests: &RequestAdmission,
    config: Arc<ServerConfig>,
    max_connections: usize,
    max_per_source: usize,
    stop: &AtomicBool,
) -> io::Result<ServiceReport> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "SEC-02 persistent lab refuses public/wildcard listeners"));
    }
    if !(1..=MAX_CONNECTIONS).contains(&max_connections)
        || !(1..=max_connections).contains(&max_per_source)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "SEC-02 invalid global or source connection capacity"));
    }
    listener.set_nonblocking(true)?;
    let mut report = ServiceReport::default();
    let mut workers: Vec<Worker> = Vec::with_capacity(max_connections);
    let mut fatal = None;
    while !stop.load(Ordering::Acquire) {
        reap(&mut workers, &mut report);
        match listener.accept() {
            Ok((stream, peer)) => {
                increment(&mut report.accepted);
                if stop.load(Ordering::Acquire) {
                    increment(&mut report.stopped_before_admission);
                    break;
                }
                let source = source_key(peer.ip());
                if workers.len() >= max_connections {
                    increment(&mut report.global_rejected);
                    continue;
                }
                if workers.iter().filter(|w| w.0 == source).count() >= max_per_source {
                    increment(&mut report.source_rejected);
                    continue;
                }
                if let Err(e) = stream.set_nonblocking(false) {
                    increment(&mut report.failed);
                    fatal = Some(e);
                    break;
                }
                match spawn_tls12_denial_only_response(
                    handshakes, requests, stream, Arc::clone(&config),
                ) {
                    Ok(worker) => {
                        workers.push((source, worker));
                        report.peak_workers = report.peak_workers.max(workers.len());
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock =>
                        increment(&mut report.handshake_rejected),
                    Err(e) => {
                        increment(&mut report.failed);
                        fatal = Some(e);
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                fatal = Some(e);
                break;
            }
        }
    }
    // Refuse new TCP connections while the admitted workers drain. Do not
    // leave a bound listener idle for the remainder of the worker budget.
    drop(listener);
    for worker in workers {
        finish(worker, &mut report);
    }
    match fatal {
        Some(e) => Err(e),
        None => Ok(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ipv4_and_source_ports_cannot_create_a_second_identity() {
        assert_eq!(source_key("::ffff:127.0.0.1".parse().unwrap()),
            source_key("127.0.0.1".parse().unwrap()));
        assert_ne!(source_key("127.0.0.2".parse().unwrap()),
            source_key("127.0.0.1".parse().unwrap()));
        assert_eq!(source_key("::1".parse().unwrap()), "::1".parse::<IpAddr>().unwrap());
        let a: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let b: std::net::SocketAddr = "127.0.0.1:5678".parse().unwrap();
        assert_eq!(source_key(a.ip()), source_key(b.ip()));
    }
}

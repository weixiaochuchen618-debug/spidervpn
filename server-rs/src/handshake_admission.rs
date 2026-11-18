//! SEC-02 pre-integration Linux handshake admission policy (NOT a TLS server).
//!
//! Old Python tc-pair.py wraps the *listening* socket with TLS before accept.
//! A client that never completes the TLS handshake can therefore stall
//! unrelated HTTPS clients. A future Rust listener MUST accept sockets first,
//! reserve a bounded worker slot, and perform each TLS handshake independently
//! through DeadlineIo. This policy alone neither authenticates nor parses TLS.
//!
//! Security limits:
//! - No unbounded thread creation: a permit is reserved BEFORE spawn.
//! - No slow-drip extensions: all reads/writes share ONE absolute deadline.
//! - No occupied capacity after success, failure or worker panic.
//! - Over capacity is a fail-fast denial; under attack some healthy clients
//!   may also be refused. Fairness and TLS-level acceptance are NOT proven.
//! - A handshake callback MUST perform all TLS socket IO through DeadlineIo;
//!   CPU loops, external blocking calls, and code bypassing the wrapper are
//!   outside this enforcement and require additional production controls.
//!
//! No production pairing handler, listener, WireGuard or Python path uses
//! this module. It is compiled only with the explicit opt-in Cargo feature.

#![cfg(all(target_os = "linux", feature = "linux-handshake-admission"))]

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_WORKERS: usize = 64;
const MIN_DEADLINE: Duration = Duration::from_millis(100);
const MAX_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct HandshakeAdmission {
    active: Arc<AtomicUsize>,
    max_active: usize,
    deadline: Duration,
}

struct Permit {
    active: Arc<AtomicUsize>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

impl HandshakeAdmission {
    /// A nonzero finite maximum and absolute handshake budget are mandatory.
    /// There is deliberately no "unlimited" mode, even for root callers.
    pub fn new(max_active: usize, deadline: Duration) -> io::Result<Self> {
        if !(1..=MAX_WORKERS).contains(&max_active)
            || !(MIN_DEADLINE..=MAX_DEADLINE).contains(&deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SEC-02 handshake capacity or total deadline out of bounds",
            ));
        }
        Ok(Self {
            active: Arc::new(AtomicUsize::new(0)),
            max_active,
            deadline,
        })
    }

    pub fn active_handshakes(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn reserve(&self) -> io::Result<Permit> {
        let mut observed = self.active.load(Ordering::Acquire);
        loop {
            if observed >= self.max_active {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "SEC-02 all handshake slots occupied; reject this connection",
                ));
            }
            match self.active.compare_exchange_weak(
                observed, observed + 1, Ordering::AcqRel, Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Permit { active: Arc::clone(&self.active) }),
                Err(actual) => observed = actual,
            }
        }
    }

    /// Admission is reserved before the OS worker is created. Caller must
    /// close/reject the socket if this returns WouldBlock or a spawn error.
    ///
    /// Only handshake IO is bounded. An accepted and fully authenticated TLS
    /// connection needs a separate HTTP request limit, lifecycle and handler.
    pub fn spawn<R, F>(
        &self, stream: TcpStream, handshake: F,
    ) -> io::Result<JoinHandle<io::Result<R>>>
    where
        F: FnOnce(&mut DeadlineIo) -> io::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let permit = self.reserve()?;
        // The budget begins at admission, never when the OS schedules the
        // worker. Delayed scheduling cannot silently refresh the deadline.
        let absolute_deadline = Instant::now() + self.deadline;
        thread::Builder::new()
            .name("spider-pair-handshake".to_owned())
            .spawn(move || {
                // Dropped on normal exit, error, or unwind; no leaked slot.
                let _permit = permit;
                let mut timed = DeadlineIo::new(stream, absolute_deadline);
                let result = handshake(&mut timed);
                // TLS verification may finish with CPU-only work after the
                // final socket read. A late callback must not return success
                // merely because it performed no more network IO.
                timed.remaining()?;
                result
            })
    }
}

/// Owned connected socket wrapper with one monotonic absolute handshake
/// deadline, not a timeout that resets whenever a peer sends another byte.
pub struct DeadlineIo {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineIo {
    fn new(stream: TcpStream, absolute_deadline: Instant) -> Self {
        Self { stream, deadline: absolute_deadline }
    }

    fn remaining(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SEC-02 total handshake deadline expired",
            ));
        }
        Ok(left)
    }
}

impl Read for DeadlineIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_read_timeout(Some(left))?;
        let outcome = self.stream.read(buf);
        // A successful single read must not make late TLS completion valid.
        self.remaining()?;
        outcome
    }
}

impl Write for DeadlineIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_write_timeout(Some(left))?;
        let outcome = self.stream.write(buf);
        self.remaining()?;
        outcome
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()?;
        self.remaining().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    #[test]
    fn policy_has_no_unbounded_or_zero_capacity_deadline_configuration() {
        for workers in [0, MAX_WORKERS + 1, usize::MAX] {
            assert_eq!(
                HandshakeAdmission::new(workers, Duration::from_secs(1))
                    .unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
            );
        }
        for deadline in [
            Duration::ZERO, Duration::from_millis(99),
            Duration::from_secs(31),
        ] {
            assert_eq!(
                HandshakeAdmission::new(2, deadline)
                    .unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
            );
        }
        HandshakeAdmission::new(1, MIN_DEADLINE).unwrap();
        HandshakeAdmission::new(MAX_WORKERS, MAX_DEADLINE).unwrap();
    }

    #[test]
    fn slow_idle_connection_does_not_block_an_independent_healthy_handshake() {
        let gate = HandshakeAdmission::new(2, Duration::from_millis(600)).unwrap();
        let (idle_server, _idle_client) = pair();
        let idle = gate.spawn(idle_server, |io| {
            let mut one = [0u8; 1];
            io.read_exact(&mut one)
        }).unwrap();
        // The first client's socket stays idle; its own worker must not
        // block scheduling a different accepted client.
        let (healthy_server, mut healthy_client) = pair();
        let healthy = gate.spawn(healthy_server, |io| {
            let mut one = [0u8; 1];
            io.read_exact(&mut one)?;
            Ok(one[0])
        }).unwrap();
        healthy_client.write_all(b"A").unwrap();
        assert_eq!(healthy.join().unwrap().unwrap(), b'A');
        assert_eq!(idle.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(gate.active_handshakes(), 0);
    }

    #[test]
    fn exhaustion_is_immediate_and_slots_recover_after_timeout() {
        let gate = HandshakeAdmission::new(2, Duration::from_millis(180)).unwrap();
        let (a, _client_a) = pair();
        let (b, _client_b) = pair();
        let first = gate.spawn(a, |io| {
            let mut one = [0u8; 1];
            io.read_exact(&mut one)
        }).unwrap();
        let second = gate.spawn(b, |io| {
            let mut one = [0u8; 1];
            io.read_exact(&mut one)
        }).unwrap();
        assert_eq!(gate.active_handshakes(), 2);
        let (overloaded, _client_c) = pair();
        let start = Instant::now();
        let denied = gate.spawn(overloaded, |_io| Ok::<(), io::Error>(()));
        assert_eq!(denied.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(first.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(second.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(gate.active_handshakes(), 0);
        let (allowed, mut client) = pair();
        let finished = gate.spawn(allowed, |io| {
            let mut one = [0u8; 1];
            io.read_exact(&mut one)?;
            Ok(one[0])
        }).unwrap();
        client.write_all(b"B").unwrap();
        assert_eq!(finished.join().unwrap().unwrap(), b'B');
    }

    #[test]
    fn delayed_worker_start_cannot_reset_the_admission_deadline() {
        let (socket, mut client) = pair();
        let admission_deadline = Instant::now() + Duration::from_millis(100);
        // Simulate delayed scheduling after admission. Even queued inbound
        // bytes must not make an expired handshake valid.
        thread::sleep(Duration::from_millis(130));
        client.write_all(b"late").unwrap();
        let mut io = DeadlineIo::new(socket, admission_deadline);
        let mut buf = [0u8; 4];
        assert_eq!(io.read_exact(&mut buf).unwrap_err().kind(),
            io::ErrorKind::TimedOut);
        assert_eq!(io.write_all(b"reply").unwrap_err().kind(),
            io::ErrorKind::TimedOut);
    }

    #[test]
    fn slow_byte_drip_cannot_extend_absolute_deadline() {
        let gate = HandshakeAdmission::new(1, Duration::from_millis(260)).unwrap();
        let (server, mut client) = pair();
        let read = gate.spawn(server, |io| {
            let mut full = [0u8; 40];
            io.read_exact(&mut full)
        }).unwrap();
        let writer = thread::spawn(move || {
            // Keep trying to send a byte before each per-operation timeout.
            // An incorrect *rolling* deadline would never expire.
            for _ in 0..18 {
                thread::sleep(Duration::from_millis(25));
                if client.write_all(b"x").is_err() { break; }
            }
        });
        let start = Instant::now();
        let reason = read.join().unwrap().unwrap_err();
        assert_eq!(reason.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
        writer.join().unwrap();
        assert_eq!(gate.active_handshakes(), 0);
    }

    #[test]
    fn callback_cannot_report_success_after_deadline_without_more_io() {
        let gate = HandshakeAdmission::new(1, Duration::from_millis(100)).unwrap();
        let (socket, _client) = pair();
        let completed = gate.spawn(socket, |_io| {
            // Simulates cryptographic verification after the last TLS read.
            thread::sleep(Duration::from_millis(140));
            Ok::<(), io::Error>(())
        }).unwrap();
        assert_eq!(completed.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut);
        assert_eq!(gate.active_handshakes(), 0);
    }

    #[test]
    fn expired_deadline_refuses_subsequent_write_after_previous_read() {
        let gate = HandshakeAdmission::new(1, Duration::from_millis(100)).unwrap();
        let (server, mut client) = pair();
        let h = gate.spawn(server, |io| {
            let mut x = [0u8; 1];
            io.read_exact(&mut x)?;
            thread::sleep(Duration::from_millis(140));
            io.write_all(b"late")
        }).unwrap();
        client.write_all(b"R").unwrap();
        assert_eq!(h.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(gate.active_handshakes(), 0);
    }

    #[test]
    fn failed_or_panicking_handshakes_cannot_permanently_consume_a_slot() {
        let gate = HandshakeAdmission::new(1, Duration::from_secs(1)).unwrap();
        let (first, _client1) = pair();
        let failed = gate.spawn(first, |_io| {
            Err::<(), io::Error>(io::Error::other("bad handshake"))
        }).unwrap();
        assert!(failed.join().unwrap().is_err());
        assert_eq!(gate.active_handshakes(), 0);
        let (second, _client2) = pair();
        let panics = gate.spawn(second, |_io| -> io::Result<()> {
            panic!("simulated TLS parser panic");
        }).unwrap();
        assert!(panics.join().is_err());
        assert_eq!(gate.active_handshakes(), 0);
    }
}

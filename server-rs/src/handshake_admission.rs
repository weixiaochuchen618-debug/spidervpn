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
//! - A separate opt-in one-request handoff holds a second shared capacity
//!   permit through exactly one bounded post-handshake request, then closes.
//!   It never returns a live socket to caller or authorizes authentication.
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

fn check_bounds(max_active: usize, deadline: Duration) -> io::Result<()> {
    if !(1..=MAX_WORKERS).contains(&max_active)
        || !(MIN_DEADLINE..=MAX_DEADLINE).contains(&deadline)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SEC-02 worker capacity or absolute deadline out of bounds",
        ));
    }
    Ok(())
}

fn reserve_slot(active: &Arc<AtomicUsize>, max_active: usize, message: &'static str)
    -> io::Result<Permit>
{
    let mut observed = active.load(Ordering::Acquire);
    loop {
        if observed >= max_active {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, message));
        }
        match active.compare_exchange_weak(
            observed, observed + 1, Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_) => return Ok(Permit { active: Arc::clone(active) }),
            Err(actual) => observed = actual,
        }
    }
}

/// A separate shared post-handshake **single request** capacity. The
/// eventual Rust TLS service must create one instance per daemon, not one
/// per connection. This is NOT an HTTP parser or a TLS authorization token.
#[derive(Clone, Debug)]
pub struct RequestAdmission {
    active: Arc<AtomicUsize>,
    max_active: usize,
    deadline: Duration,
}

impl RequestAdmission {
    pub fn new(max_active: usize, request_deadline: Duration) -> io::Result<Self> {
        check_bounds(max_active, request_deadline)?;
        Ok(Self {
            active: Arc::new(AtomicUsize::new(0)),
            max_active,
            deadline: request_deadline,
        })
    }

    pub fn active_requests(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn reserve(&self) -> io::Result<Permit> {
        reserve_slot(
            &self.active, self.max_active,
            "SEC-02 post-handshake request capacity exhausted; close socket",
        )
    }
}


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
        check_bounds(max_active, deadline)?;
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
        reserve_slot(
            &self.active, self.max_active,
            "SEC-02 all handshake slots occupied; reject this connection",
        )
    }

    /// Runs one finite authenticated handshake and then exactly one finite
    /// post-handshake request in the SAME worker. The request callback only
    /// runs after the caller's handshake callback returned Ok before the
    /// original absolute deadline. It obtains a separate shared request
    /// permit BEFORE freeing the handshake permit, preventing an unchecked
    /// handoff that could spawn unbounded HTTP workers.
    ///
    /// On overloaded request capacity, this fails closed and closes the
    /// socket. No keepalive loop or live socket escapes. Request timeouts
    /// start at transfer to the request phase, use the same absolute I/O
    /// wrapper, and are checked AGAIN after handler return (even CPU-only).
    /// This function does NOT cryptographically verify TLS: `handshake`
    /// must eventually be a genuine, independently reviewed TLS callback.
    /// A separate future Rust daemon must create ONE globally shared
    /// RequestAdmission and invoke only this bounded route.
    pub fn spawn_one_request<T, R, H, F>(
        &self,
        requests: &RequestAdmission,
        stream: TcpStream,
        handshake: H,
        handle_one_request: F,
    ) -> io::Result<JoinHandle<io::Result<R>>>
    where
        H: FnOnce(&mut DeadlineIo) -> io::Result<T> + Send + 'static,
        F: FnOnce(&mut DeadlineIo, T) -> io::Result<R> + Send + 'static,
        T: Send + 'static,
        R: Send + 'static,
    {
        let handshake_permit = self.reserve()?;
        let handshake_deadline = Instant::now() + self.deadline;
        let requests = requests.clone();
        thread::Builder::new()
            .name("spider-pair-one-request".to_owned())
            .spawn(move || {
                let mut io = DeadlineIo::new(stream, handshake_deadline);
                let verified = handshake(&mut io)?;
                io.remaining()?;
                // Even if the handshake succeeds, request saturation is
                // a denial, NOT a reason to spawn an unrestricted handler.
                let _request_permit = requests.reserve()?;
                drop(handshake_permit);
                let mut request_io = DeadlineIo::new(
                    io.stream, Instant::now() + requests.deadline,
                );
                let outcome = handle_one_request(&mut request_io, verified);
                request_io.remaining()?;
                outcome
            })
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
        for capacity in [0, MAX_WORKERS + 1] {
            assert_eq!(RequestAdmission::new(capacity, Duration::from_secs(1))
                .unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
        for invalid in [Duration::ZERO, Duration::from_secs(31)] {
            assert_eq!(RequestAdmission::new(1, invalid)
                .unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
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
    fn one_connection_runs_one_handshake_then_one_bounded_request_and_closes() {
        let handshakes = HandshakeAdmission::new(1, Duration::from_secs(1)).unwrap();
        let requests = RequestAdmission::new(1, Duration::from_secs(1)).unwrap();
        let (server, mut client) = pair();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let task = handshakes.spawn_one_request(
            &requests, server,
            |io| {
                let mut hello = [0u8; 1];
                io.read_exact(&mut hello)?;
                if hello != *b"H" {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                        "not an authorized handshake"));
                }
                Ok(7u32)
            },
            |io, identity| {
                let mut request = [0u8; 1];
                io.read_exact(&mut request)?;
                io.write_all(b"Y")?;
                Ok((identity, request[0]))
            },
        ).unwrap();
        client.write_all(b"HR").unwrap();
        let mut response = [0u8; 1];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response, *b"Y");
        assert_eq!(task.join().unwrap().unwrap(), (7, b'R'));
        assert_eq!(handshakes.active_handshakes(), 0);
        assert_eq!(requests.active_requests(), 0);
        assert_eq!(client.read(&mut response).unwrap(), 0);
    }

    #[test]
    fn slow_http_stage_does_not_hold_handshake_slot_and_saturated_handoff_denies() {
        use std::sync::mpsc;
        let handshakes = HandshakeAdmission::new(1, Duration::from_secs(1)).unwrap();
        let requests = RequestAdmission::new(1, Duration::from_secs(1)).unwrap();
        let (tx, rx) = mpsc::channel();
        let (first, mut first_client) = pair();
        let slow = handshakes.spawn_one_request(
            &requests, first,
            |io| { let mut b = [0]; io.read_exact(&mut b)?; Ok(()) },
            move |io, ()| {
                tx.send(()).unwrap();
                let mut byte = [0];
                io.read_exact(&mut byte)?;
                Ok(byte[0])
            },
        ).unwrap();
        first_client.write_all(b"H").unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(requests.active_requests(), 1);
        assert_eq!(handshakes.active_handshakes(), 0);
        let (second, mut second_client) = pair();
        let no_second_handler = handshakes.spawn_one_request(
            &requests, second,
            |io| { let mut b = [0]; io.read_exact(&mut b)?; Ok(()) },
            |_io, ()| -> io::Result<()> {
                panic!("saturated post-handshake admission must never run handler");
            },
        ).unwrap();
        second_client.write_all(b"H").unwrap();
        assert_eq!(no_second_handler.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::WouldBlock);
        assert_eq!(requests.active_requests(), 1);
        first_client.write_all(b"R").unwrap();
        assert_eq!(slow.join().unwrap().unwrap(), b'R');
        assert_eq!(requests.active_requests(), 0);
        assert_eq!(handshakes.active_handshakes(), 0);

        let (third, mut third_client) = pair();
        let recovery = handshakes.spawn_one_request(
            &requests, third,
            |io| { let mut b = [0]; io.read_exact(&mut b)?; Ok(()) },
            |_io, ()| Ok::<u8, io::Error>(99),
        ).unwrap();
        third_client.write_all(b"H").unwrap();
        assert_eq!(recovery.join().unwrap().unwrap(), 99);
        assert_eq!(requests.active_requests(), 0);
    }

    #[test]
    fn unauthenticated_or_failed_handshake_never_reaches_request_callback() {
        use std::sync::atomic::AtomicBool;
        let handshakes = HandshakeAdmission::new(1, Duration::from_secs(1)).unwrap();
        let requests = RequestAdmission::new(1, Duration::from_secs(1)).unwrap();
        let reached = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&reached);
        let (server, mut client) = pair();
        let task = handshakes.spawn_one_request(
            &requests, server,
            |io| {
                let mut byte = [0];
                io.read_exact(&mut byte)?;
                Err::<(), io::Error>(io::Error::new(
                    io::ErrorKind::PermissionDenied, "bad TLS proof"))
            },
            move |_io, ()| { flag.store(true, Ordering::SeqCst); Ok(()) },
        ).unwrap();
        client.write_all(b"X").unwrap();
        assert_eq!(task.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied);
        assert!(!reached.load(Ordering::SeqCst));
        assert_eq!(handshakes.active_handshakes(), 0);
        assert_eq!(requests.active_requests(), 0);
    }

    #[test]
    fn slow_post_handshake_request_has_its_own_nonextensible_deadline() {
        let handshakes = HandshakeAdmission::new(1, Duration::from_secs(1)).unwrap();
        let requests = RequestAdmission::new(1, Duration::from_millis(180)).unwrap();
        let (server, mut client) = pair();
        let task = handshakes.spawn_one_request(
            &requests, server,
            |io| { let mut b = [0]; io.read_exact(&mut b)?; Ok(()) },
            |io, ()| {
                let mut bytes = [0u8; 40];
                io.read_exact(&mut bytes)
            },
        ).unwrap();
        client.write_all(b"H").unwrap();
        let writer = thread::spawn(move || {
            for _ in 0..10 {
                thread::sleep(Duration::from_millis(30));
                if client.write_all(b"x").is_err() { break; }
            }
        });
        assert_eq!(task.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        writer.join().unwrap();
        assert_eq!(requests.active_requests(), 0);
        assert_eq!(handshakes.active_handshakes(), 0);
    }

    #[test]
    fn late_or_panicking_http_handler_cannot_leak_request_slots() {
        let handshakes = HandshakeAdmission::new(1, Duration::from_secs(1)).unwrap();
        let requests = RequestAdmission::new(1, Duration::from_millis(100)).unwrap();
        let (server, mut client) = pair();
        let late = handshakes.spawn_one_request(
            &requests, server,
            |io| { let mut b = [0]; io.read_exact(&mut b)?; Ok(()) },
            |_io, ()| {
                // Post-TLS crypto or HTTP work without further socket I/O.
                thread::sleep(Duration::from_millis(145));
                Ok::<(), io::Error>(())
            },
        ).unwrap();
        client.write_all(b"H").unwrap();
        assert_eq!(late.join().unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(requests.active_requests(), 0);
        let (server, mut client) = pair();
        let panicked = handshakes.spawn_one_request(
            &requests, server,
            |io| { let mut b = [0]; io.read_exact(&mut b)?; Ok(()) },
            |_io, ()| -> io::Result<()> { panic!("simulated handler crash"); },
        ).unwrap();
        client.write_all(b"H").unwrap();
        assert!(panicked.join().is_err());
        assert_eq!(requests.active_requests(), 0);
        assert_eq!(handshakes.active_handshakes(), 0);
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

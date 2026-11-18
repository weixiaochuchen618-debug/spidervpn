//! Real child-process integration on a disposable Linux CI VM ONLY.
//! Explicit feature and root required; never skip a missing prerequisite.
//! The fixed directory must not exist before the test. No production files,
//! actual pairing service, WireGuard interface or external network are used.
#![cfg(target_os = "linux")]

use spidervpn_pairing_authority::tls_identity::legacy_leaf_der_sha256;
use std::fs::{self, DirBuilder};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const LAB: &str = "/run/spidervpn-pair-denial-lab";
const BIN: &str = env!("CARGO_BIN_EXE_spidervpn-pair-denial-lab");

struct Fixture;
impl Fixture {
    fn create() -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run only on disposable root CI");
        // Never remove a pre-existing directory or reuse its keys.
        DirBuilder::new().mode(0o700).create(LAB).unwrap();
        let fixture = Self;
        let status = Command::new("/usr/bin/openssl").current_dir(LAB)
            .args(["req", "-x509", "-newkey", "rsa:2048", "-sha256",
                "-days", "1", "-nodes", "-keyout", "tls.key",
                "-out", "tls.crt", "-subj", "/CN=127.0.0.1"])
            .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert!(status.success());
        fs::set_permissions(Path::new(LAB).join("tls.key"),
            fs::Permissions::from_mode(0o600)).unwrap();
        fixture
    }

    fn pin(&self) -> String {
        let output = Command::new("/usr/bin/openssl").current_dir(LAB)
            .args(["x509", "-in", "tls.crt", "-outform", "DER"])
            .output().unwrap();
        assert!(output.status.success());
        legacy_leaf_der_sha256(&output.stdout)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(LAB).unwrap();
    }
}

struct ChildGuard {
    child: Child,
    lines: Receiver<String>,
}
impl ChildGuard {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(BIN).args(args)
            // Deliberately set hostile path/port overrides; neither is used.
            .env("TC_PAIR_ROOT", "/tmp/attacker")
            .env("SPIDERVPN_PAIR_PORT", "443")
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if let Ok(line) = line {
                    if tx.send(line).is_err() { break; }
                } else { break; }
            }
        });
        Self { child, lines }
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "lab child did not exit within its budget");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stderr(&mut self) -> String {
        let mut text = String::new();
        self.child.stderr.take().unwrap().read_to_string(&mut text).unwrap();
        text
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_denied(args: &[&str], message: &str) {
    let mut child = ChildGuard::start(args);
    assert_eq!(child.wait().code(), Some(2));
    assert!(child.stderr().contains(message));
    assert!(child.lines.recv_timeout(Duration::from_secs(1)).is_err(),
        "failed startup emitted a ready or success message");
}

fn status_field<'a>(status: &'a str, field: &str) -> &'a str {
    status.lines().find_map(|line| line.strip_prefix(field)).unwrap().trim()
}

fn readback_dropped_credentials(pid: u32) {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    for field in ["Uid:", "Gid:"] {
        assert_eq!(status_field(&status, field).split_whitespace().collect::<Vec<_>>(),
            vec!["65534"; 4], "{field}");
    }
    assert_eq!(status_field(&status, "Groups:"), "");
    assert_eq!(status_field(&status, "NoNewPrivs:"), "1");
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        assert_eq!(u64::from_str_radix(status_field(&status, field), 16).unwrap(), 0);
    }
}

fn real_tls_denial(addr: SocketAddr) {
    let mut client = Command::new("/usr/bin/openssl").current_dir(LAB)
        .args(["s_client", "-connect", &addr.to_string(), "-tls1_2",
            "-quiet", "-verify_return_error", "-CAfile", "tls.crt",
            "-no-CApath", "-no-CAstore"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    client.stdin.take().unwrap().write_all(
        b"GET /v1/invitations/id HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer TEST-SECRET\r\n\r\n"
    ).unwrap();
    let output = client.wait_with_output().unwrap();
    assert!(output.status.success(), "independent TLS peer: {}",
        String::from_utf8_lossy(&output.stderr));
    let wire = String::from_utf8(output.stdout).unwrap();
    let (head, body) = wire.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 500 "));
    assert_eq!(body, r#"{"Code":"InvalidState","Ok":false}"#);
    assert!(!wire.contains("TEST-SECRET"));
}

fn run_and_signal(pin: &str, signal: libc::c_int) {
    let mut child = ChildGuard::start(&["serve-denial-lab", pin]);
    let ready = child.lines.recv_timeout(Duration::from_secs(5)).unwrap();
    let address: SocketAddr = ready.strip_prefix("READY_DENIAL_ONLY ").unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    assert!(address.port() >= 1024);
    readback_dropped_credentials(child.child.id());
    real_tls_denial(address);

    // Hold a real incomplete handshake until the process exits. Observe
    // an existing worker via the kernel, not a fixed sleep.
    let _idle = TcpStream::connect(address).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let tasks = format!("/proc/{}/task", child.child.id());
    while fs::read_dir(&tasks).unwrap().count() < 2 {
        assert!(Instant::now() < deadline, "no admitted TLS worker");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(unsafe { libc::kill(child.child.id() as libc::pid_t, signal) }, 0);
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if matches!(TcpStream::connect_timeout(&address, Duration::from_millis(100)),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused) { break; }
        assert!(Instant::now() < until, "signal did not close listener");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(child.wait().success(), "signal should cause clean exit");
    let stopped = child.lines.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(stopped.starts_with("STOPPED_DENIAL_ONLY "));
    assert!(stopped.contains("denied=1"));
    assert!(stopped.contains("failed=1"));
    assert!(child.stderr().is_empty());
    assert_eq!(TcpStream::connect(address).unwrap_err().kind(),
        std::io::ErrorKind::ConnectionRefused);
}

#[test]
fn real_root_startup_refuses_unsafe_identity_and_term_int_drain_after_privilege_drop() {
    let fixture = Fixture::create();
    let pin = fixture.pin();
    let mut wrong = pin.clone();
    wrong.replace_range(..1, if pin.starts_with('0') { "1" } else { "0" });
    assert_denied(&["serve-denial-lab", &wrong], "identity or pin refused");
    assert_denied(&["serve-denial-lab", &pin, "0.0.0.0:443"], "exact command");

    let key = Path::new(LAB).join("tls.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert_denied(&["serve-denial-lab", &pin], "identity or pin refused");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let moved = Path::new(LAB).join("real.key");
    fs::rename(&key, &moved).unwrap();
    std::os::unix::fs::symlink("real.key", &key).unwrap();
    assert_denied(&["serve-denial-lab", &pin], "identity or pin refused");
    fs::remove_file(&key).unwrap();
    fs::rename(&moved, &key).unwrap();
    run_and_signal(&pin, libc::SIGTERM);
    run_and_signal(&pin, libc::SIGINT);
}

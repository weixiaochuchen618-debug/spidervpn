//! SEC-02: explicit DISPOSABLE denial-only Linux process, NOT a deployed daemon.
//! Root opens only the separate lab TLS identity, permanently drops to the
//! lab's numeric unprivileged UID/GID, then binds 127.0.0.1:0. Never access
//! a production certificate, ledger, WireGuard, systemd unit or public port.
//! UID 65534 is deliberately for a disposable host, not a production service
//! account selection. No setuid installation, path override or auto-start.
#![cfg(target_os = "linux")]

use spidervpn_pairing_authority::handshake_admission::{HandshakeAdmission, RequestAdmission};
use spidervpn_pairing_authority::persistent_listener_lab::run_persistent_denial_lab;
use spidervpn_pairing_authority::tls_identity::read_disposable_process_identity;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const LAB_UID: libc::uid_t = 65534;
const LAB_GID: libc::gid_t = 65534;
const GLOBAL_LIMIT: usize = 16;
const SOURCE_LIMIT: usize = 4;
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(3);
const REQUEST_BUDGET: Duration = Duration::from_secs(3);
static STOP: AtomicBool = AtomicBool::new(false);

// Lock-free AtomicBool on supported Linux targets. No allocation, locking,
// logging, I/O, or unwinding inside the asynchronous signal handler.
extern "C" fn stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Release);
}

fn install_stop_handlers() -> io::Result<()> {
    // SAFETY: the zeroed sigaction and sigset_t are initialized below by libc;
    // the handler is a C-ABI function of the correct signature and lives
    // for the duration of this process.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = stop_signal as *const () as usize;
        if libc::sigemptyset(&mut action.sa_mask) != 0
            || libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            return Err(io::Error::last_os_error());
        }
        // A parent can inherit a blocked mask. Unblock both only after
        // both stop handlers are installed, before creating any workers.
        let mut signals: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut signals) != 0
            || libc::sigaddset(&mut signals, libc::SIGTERM) != 0
            || libc::sigaddset(&mut signals, libc::SIGINT) != 0
            || libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn parse_pin(args: &[String]) -> Option<&str> {
    match args {
        [mode, pin] if mode == "serve-denial-lab"
            && pin.len() == 64
            && pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            => Some(pin),
        _ => None,
    }
}

fn check_zero_capabilities() -> io::Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for prefix in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status.lines().find_map(|line| line.strip_prefix(prefix))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok());
        if value != Some(0) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "SEC-02 nonzero or unverified capabilities"));
        }
    }
    Ok(())
}

fn permanently_drop_lab_privileges() -> io::Result<()> {
    // No workers exist yet; these credential transitions apply to the whole
    // single-threaded process. Disallow retaining capabilities across UID
    // change; remove supplementary groups BEFORE GID/UID drop; set all
    // real/effective/saved IDs. No-new-privileges prevents later exec gains.
    // No inherited privileged file descriptors beyond trusted stdio survive.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong,
            0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) != 0
            || libc::prctl(libc::PR_SET_KEEPCAPS, 0 as libc::c_ulong,
                0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) != 0
            || libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(LAB_GID, LAB_GID, LAB_GID) != 0
            || libc::setresuid(LAB_UID, LAB_UID, LAB_UID) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong,
                0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        let (mut gr, mut ge, mut gs) = (0, 0, 0);
        if libc::getresuid(&mut r, &mut e, &mut s) != 0
            || libc::getresgid(&mut gr, &mut ge, &mut gs) != 0
            || (r, e, s) != (LAB_UID, LAB_UID, LAB_UID)
            || (gr, ge, gs) != (LAB_GID, LAB_GID, LAB_GID)
            || libc::getgroups(0, std::ptr::null_mut()) != 0
            || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0 as libc::c_ulong,
                0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) != 1
            || libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong,
                0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) != 0
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "SEC-02 privilege drop readback failed"));
        }
    }
    check_zero_capabilities()?;
    std::env::set_current_dir("/")?;
    Ok(())
}

// The disposable lab supervisor must deliberately supply anonymous capture
// pipes for BOTH outputs. File type alone does not authenticate the reader:
// never treat this policy as a production log endpoint trust decision.
// No application diagnostic may be emitted until all stdio checks pass.
#[derive(PartialEq, Eq)]
struct FdState {
    device: libc::dev_t,
    inode: libc::ino_t,
    kind: libc::mode_t,
    rdev: libc::dev_t,
    flags: libc::c_int,
}

fn refused_stdio() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe lab stdio")
}

fn inspect_fd(fd: RawFd) -> io::Result<FdState> {
    // SAFETY: fstat initializes the provided stat on success; F_GETFL
    // only reads the current open-file-description flags.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || flags & libc::O_PATH != 0 {
            return Err(refused_stdio());
        }
        Ok(FdState { device: st.st_dev, inode: st.st_ino,
            kind: st.st_mode & libc::S_IFMT, rdev: st.st_rdev, flags })
    }
}

fn anonymous_pipe(fd: RawFd, state: &FdState, direction: libc::c_int) -> io::Result<()> {
    if state.kind != libc::S_IFIFO
        || state.flags & libc::O_ACCMODE != direction
        || state.flags & (libc::O_NONBLOCK | libc::O_ASYNC | libc::O_DIRECT) != 0
    {
        return Err(refused_stdio());
    }
    // A filesystem FIFO also has S_IFIFO. Require the Linux anonymous pipe
    // identity for the same inode, not a filesystem pathname or socket.
    let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))?;
    if target != std::path::PathBuf::from(format!("pipe:[{}]", state.inode)) {
        return Err(refused_stdio());
    }
    Ok(())
}

fn readonly_null(state: &FdState) -> bool {
    state.kind == libc::S_IFCHR
        && libc::major(state.rdev) == 1 && libc::minor(state.rdev) == 3
        && state.flags & libc::O_ACCMODE == libc::O_RDONLY
}

struct LabStdio {
    input: FdState,
    output: FdState,
    error: FdState,
}

impl LabStdio {
    fn isolate() -> io::Result<Self> {
        let input = inspect_fd(libc::STDIN_FILENO)?;
        let output = inspect_fd(libc::STDOUT_FILENO)?;
        let error = inspect_fd(libc::STDERR_FILENO)?;
        anonymous_pipe(libc::STDOUT_FILENO, &output, libc::O_WRONLY)?;
        anonymous_pipe(libc::STDERR_FILENO, &error, libc::O_WRONLY)?;
        if !readonly_null(&input) {
            anonymous_pipe(libc::STDIN_FILENO, &input, libc::O_RDONLY)?;
        }

        // Do not retain even an allowed inherited input capability. Open a
        // fixed non-following, non-controlling, nonblocking device and
        // prove its device identity and direction before installing it.
        let null = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_NONBLOCK)
            .open("/dev/null")?;
        let fd = null.as_raw_fd();
        let input = inspect_fd(fd)?;
        if fd <= libc::STDERR_FILENO || !readonly_null(&input) {
            return Err(refused_stdio());
        }
        // SAFETY: single-threaded startup, valid owned source and existing
        // stdio number; dup2 atomically replaces the inherited input.
        if unsafe { libc::dup2(fd, libc::STDIN_FILENO) } != libc::STDIN_FILENO {
            return Err(io::Error::last_os_error());
        }
        drop(null);
        let stdio = Self { input, output, error };
        stdio.verify()?;
        Ok(stdio)
    }

    fn verify(&self) -> io::Result<()> {
        // No worker or other local descriptor owner exists when called
        // across the credential transition. Compare actual fd identities
        // AND access flags, without needing privileged proc symlink access
        // after setting dumpable=0. A shared pipe's reader is still not an
        // authenticated peer.
        if inspect_fd(libc::STDIN_FILENO)? != self.input
            || inspect_fd(libc::STDOUT_FILENO)? != self.output
            || inspect_fd(libc::STDERR_FILENO)? != self.error
        {
            return Err(refused_stdio());
        }
        Ok(())
    }
}

fn run(stdio: &LabStdio) -> Result<(), &'static str> {
    // Require ordinary root invocation, not a setuid launcher.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err("root startup required for isolated lab identity");
    }
    let args: Vec<String> = std::env::args_os().skip(1)
        .map(|arg| arg.into_string().map_err(|_| "invalid lab arguments"))
        .collect::<Result<_, _>>()?;
    let pin = parse_pin(&args).ok_or("exact command serve-denial-lab and lowercase DER pin required")?;
    install_stop_handlers().map_err(|_| "cannot install stop handlers")?;
    // Linux 5.9+; refuse startup if the kernel does not support closing all
    // inherited non-stdio FDs. Do this BEFORE opening the lab TLS material.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        return Err("cannot close inherited descriptors");
    }
    let identity = read_disposable_process_identity(pin)
        .map_err(|_| "isolated TLS identity or pin refused")?;
    permanently_drop_lab_privileges().map_err(|_| "privilege drop refused")?;
    stdio.verify().map_err(|_| "stdio readback after privilege drop refused")?;
    if STOP.load(Ordering::Acquire) {
        return Ok(());
    }
    let hand = HandshakeAdmission::new(GLOBAL_LIMIT, HANDSHAKE_BUDGET)
        .map_err(|_| "invalid handshake budget")?;
    let requests = RequestAdmission::new(GLOBAL_LIMIT, REQUEST_BUDGET)
        .map_err(|_| "invalid request budget")?;
    // No command-line host/port, inherited socket activation or environment
    // override: no way to bind an existing production receiver port.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "cannot bind ephemeral loopback")?;
    let addr = listener.local_addr().map_err(|_| "cannot observe loopback address")?;
    // Report readiness only AFTER trusted identity + permanent credential
    // transition + real bind. This is NOT readiness to authorize pairing.
    {
        let mut out = io::stdout().lock();
        writeln!(out, "READY_DENIAL_ONLY {addr}").map_err(|_| "cannot report lab readiness")?;
        out.flush().map_err(|_| "cannot flush lab readiness")?;
    }
    let report = run_persistent_denial_lab(listener, &hand, &requests,
        identity.server_config, GLOBAL_LIMIT, SOURCE_LIMIT, &STOP)
        .map_err(|_| "lab listener failed; no pairing authorization")?;
    if hand.active_handshakes() != 0 || requests.active_requests() != 0 {
        return Err("admission permits not drained");
    }
    println!("STOPPED_DENIAL_ONLY accepted={} denied={} failed={} peak_workers={}",
        report.accepted, report.denied, report.failed, report.peak_workers);
    Ok(())
}

fn main() {
    let stdio = match LabStdio::isolate() {
        Ok(stdio) => stdio,
        // In particular, never eprintln to an inherited writable file or
        // socket on a startup error. Even the other output is not assumed
        // trusted when the whole preflight failed.
        Err(_) => std::process::exit(2),
    };
    if let Err(error) = run(&stdio) {
        if stdio.verify().is_ok() {
            eprintln!("spidervpn-pair-denial-lab: {error}");
        }
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_command_with_lowercase_der_pin_is_accepted() {
        let pin = "a".repeat(64);
        assert_eq!(parse_pin(&["serve-denial-lab".into(), pin.clone()]), Some(pin.as_str()));
        for args in [vec![], vec!["serve-denial-lab".into()],
            vec!["serve".into(), pin.clone()],
            vec!["serve-denial-lab".into(), "A".repeat(64)],
            vec!["serve-denial-lab".into(), "g".repeat(64)],
            vec!["serve-denial-lab".into(), pin.clone(), "0.0.0.0:443".into()],
        ] {
            assert!(parse_pin(&args).is_none());
        }
    }
}

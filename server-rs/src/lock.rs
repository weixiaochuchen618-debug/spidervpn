//! SEC-08: one Linux, cross-process lock for invite ledger AND wg.conf.
//!
//! The lock MUST span read ledger -> reserve/revoke -> persist durable
//! Pending/Revoking -> WG change -> WG readback -> persist final state.
//! Merely locking the JSON write is insufficient. This module deliberately
//! never touches actual WireGuard/production files.
//!
//! Initial implementation targets Linux x86_64 deployments. O_NOFOLLOW below
//! is the Linux x86_64 value, not a portable Unix flag.

#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const NAME: &str = ".pairing-authority.lock";
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;
const LOCK_UN: i32 = 8;
const O_NOFOLLOW: i32 = 0o400000;
const WAIT_STEP: Duration = Duration::from_millis(25);

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn geteuid() -> u32;
}

fn fail(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// RAII scope for one coordinated transaction. The guarded file is never
/// unlinked: unlinking a lock file allows other processes to acquire a NEW
/// inode and run concurrently with a still-locked old one.
pub struct AuthorityLock {
    file: File,
}

impl Drop for AuthorityLock {
    fn drop(&mut self) {
        let _ = unsafe { flock(self.file.as_raw_fd(), LOCK_UN) };
    }
}

fn trusted_root(root: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(root)?;
    let uid = unsafe { geteuid() };
    if !root.is_absolute() || !meta.file_type().is_dir() || meta.uid() != uid
        || meta.mode() & 0o077 != 0
    {
        return Err(fail("pairing authority root must be an owner-only directory"));
    }
    Ok(())
}

fn secure_lock_file(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    let uid = unsafe { geteuid() };
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
    {
        return Err(fail("pairing authority lock must be an owner-only, single-link file"));
    }
    Ok(())
}

/// Acquire an exclusive cross-process lock with a bounded wait. If another
/// command is updating the ledger/WG, callers fail (not silently continue).
pub fn acquire_for(root: &Path, timeout: Duration) -> io::Result<AuthorityLock> {
    trusted_root(root)?;
    let file = OpenOptions::new()
        .read(true).write(true).create(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(root.join(NAME))?;
    secure_lock_file(&file)?;

    let start = Instant::now();
    loop {
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
        if rc == 0 {
            return Ok(AuthorityLock { file });
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::WouldBlock => {
                if start.elapsed() >= timeout {
                    return Err(io::Error::new(io::ErrorKind::TimedOut,
                        "pairing authority transaction already held by another process"));
                }
                thread::sleep(WAIT_STEP);
            }
            _ => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(
            format!("spidervpn-sec08-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn separate_file_descriptors_cannot_hold_same_transaction_lock() {
        let dir = root("exclusion");
        let guard = acquire_for(&dir, Duration::from_millis(100)).unwrap();
        assert_eq!(
            acquire_for(&dir, Duration::from_millis(35)).err().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        drop(guard);
        acquire_for(&dir, Duration::from_millis(100)).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn root_and_lock_acl_downgrade_or_preseeded_link_fail_closed() {
        let dir = root("acl");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(acquire_for(&dir, Duration::ZERO).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let target = dir.join("attacker-controlled");
        std::fs::write(&target, b"unchanged").unwrap();
        symlink(&target, dir.join(NAME)).unwrap();
        assert!(acquire_for(&dir, Duration::ZERO).is_err(),
            "O_NOFOLLOW must refuse a symlinked lock");
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hardlinked_lock_refused_without_modifying_target() {
        let dir = root("hardlink");
        let external = dir.join("target");
        std::fs::write(&external, b"keep").unwrap();
        std::fs::hard_link(&external, dir.join(NAME)).unwrap();
        assert_eq!(acquire_for(&dir, Duration::ZERO).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&external).unwrap(), b"keep");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

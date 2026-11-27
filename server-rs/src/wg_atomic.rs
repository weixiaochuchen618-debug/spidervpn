//! SEC-01 S03: protected, atomic WireGuard config replacement under a
//! durable Pending/Revoking authority ledger. NOT connected to production.
//!
//! This module deliberately DOES NOT invoke wg syncconf yet; an unsynced
//! config must NEVER advance Pending -> Consumed or Revoking -> Revoked.
//! Synchronization and live+disk readback belong to the next adapter stage.
//!
//! Only root-owned fixed /etc/wireguard may be written by the production
//! entrypoint. Tests use a private directory with the same ownership rules.
//! A failed directory fsync after rename yields CommitUncertain: do not
//! retry authorization blindly or revert the durable ledger state.

#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ledger_disk::{LedgerStore, StoreError};
use crate::wg_conf_audit::{read_verified_snapshot, ConfigError};
use crate::wg_peer_plan::{plan_peer_change, PeerChange, Plan, PlanError};
use crate::wg_readonly::valid_interface;

const WG_ROOT: &str = "/etc/wireguard";
const O_NOFOLLOW: i32 = 0o400000; // Linux x86_64
const MAX_CONF: usize = 1024 * 1024;
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

unsafe extern "C" { fn geteuid() -> u32; }

#[derive(Debug)]
pub enum AtomicError {
    InvalidIdentity,
    UnsafeDirectory,
    UnsafeConfig,
    UntrustedOriginal,
    ReadOnlyValidation(ConfigError),
    Ledger(StoreError),
    Plan(PlanError),
    Io,
    /// rename may have succeeded but sync of the parent failed. Stop.
    CommitUncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64, ino: u64, len: u64, uid: u32, mode: u32, nlink: u64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}
fn stamp(meta: &fs::Metadata) -> Stamp {
    Stamp {
        dev: meta.dev(), ino: meta.ino(), len: meta.len(),
        uid: meta.uid(), mode: meta.mode() & 0o777, nlink: meta.nlink(),
        mtime: meta.mtime(), mtime_ns: meta.mtime_nsec(),
        ctime: meta.ctime(), ctime_ns: meta.ctime_nsec(),
    }
}
fn root_check(root: &Path, require_root: bool) -> Result<(), AtomicError> {
    if !root.is_absolute() { return Err(AtomicError::UnsafeDirectory); }
    if require_root && (root != Path::new(WG_ROOT) || unsafe { geteuid() } != 0) {
        return Err(AtomicError::UnsafeDirectory);
    }
    let meta = fs::symlink_metadata(root).map_err(|_| AtomicError::UnsafeDirectory)?;
    if !meta.file_type().is_dir()
        || meta.uid() != unsafe { geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(AtomicError::UnsafeDirectory);
    }
    Ok(())
}
fn verify_file(file: &File) -> Result<Stamp, AtomicError> {
    let meta = file.metadata().map_err(|_| AtomicError::Io)?;
    if !meta.file_type().is_file() || meta.uid() != unsafe { geteuid() }
        || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600
        || meta.len() > MAX_CONF as u64
    {
        return Err(AtomicError::UnsafeConfig);
    }
    Ok(stamp(&meta))
}
fn read_current(path: &Path) -> Result<(Vec<u8>, Stamp), AtomicError> {
    let mut file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW)
        .open(path).map_err(|_| AtomicError::UnsafeConfig)?;
    let before = verify_file(&file)?;
    let mut buf = Vec::new();
    std::io::Read::by_ref(&mut file).take((MAX_CONF+1) as u64)
        .read_to_end(&mut buf).map_err(|_| AtomicError::Io)?;
    if buf.len() > MAX_CONF { return Err(AtomicError::UnsafeConfig); }
    if stamp(&file.metadata().map_err(|_| AtomicError::Io)?) != before {
        return Err(AtomicError::UntrustedOriginal);
    }
    let other = fs::symlink_metadata(path).map_err(|_| AtomicError::Io)?;
    if stamp(&other) != before { return Err(AtomicError::UntrustedOriginal); }
    Ok((buf, before))
}
fn next_temporary(root: &Path) -> Result<std::path::PathBuf, AtomicError> {
    let ns = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| AtomicError::Io)?.as_nanos();
    let c = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    Ok(root.join(format!(".spidervpn-wg-{}-{ns}-{c}.tmp", std::process::id())))
}
fn replace_verified(
    root: &Path, path: &Path, original: &[u8], start: &Stamp,
    plan: &Plan,
) -> Result<(), AtomicError> {
    if !plan.changed() { return Ok(()); }
    if plan.config_bytes().len() > MAX_CONF { return Err(AtomicError::UnsafeConfig); }
    // The lock covers all operations in the same Rust daemon, but another
    // root process could ignore it. Detect changed source before the swap.
    let (again, now) = read_current(path)?;
    if now != *start || again != original {
        return Err(AtomicError::UntrustedOriginal);
    }
    let temporary = next_temporary(root)?;
    let mut file = OpenOptions::new().create_new(true).write(true)
        .mode(0o600).custom_flags(O_NOFOLLOW).open(&temporary)
        .map_err(|_| AtomicError::Io)?;
    let operation = (|| {
        verify_file(&file)?;
        file.write_all(plan.config_bytes()).map_err(|_| AtomicError::Io)?;
        file.sync_all().map_err(|_| AtomicError::Io)?;
        root_check(root, false)?;
        let (last, meta) = read_current(path)?;
        if meta != *start || last != original {
            return Err(AtomicError::UntrustedOriginal);
        }
        fs::rename(&temporary, path).map_err(|_| AtomicError::Io)?;
        #[cfg(test)]
        if FAIL_AFTER_RENAME.with(|flag| flag.get()) {
            return Err(AtomicError::CommitUncertain);
        }
        File::open(root).and_then(|dir| dir.sync_all())
            .map_err(|_| AtomicError::CommitUncertain)?;
        Ok(())
    })();
    // Only a protected temporary is removed, never the original config.
    let _ = fs::remove_file(&temporary);
    operation
}
fn expected_status(
    store: &LedgerStore, change: PeerChange<'_>,
) -> Result<(), AtomicError> {
    if !change.prepared(store.view().map_err(AtomicError::Ledger)?) {
        return Err(AtomicError::InvalidIdentity);
    }
    Ok(())
}

/// This entrypoint is deliberately not invoked from production Python. A
/// future Rust adapter MUST invoke it only after durable authorization and
/// MUST execute syncconf and verify live+disk state before final ledger commit.
pub(crate) fn write_pinned_config(
    store: &LedgerStore, interface: &str, change: PeerChange<'_>,
) -> Result<bool, AtomicError> {
    if !valid_interface(interface) { return Err(AtomicError::UnsafeConfig); }
    expected_status(store, change)?;
    root_check(Path::new(WG_ROOT), true)?;
    // Stable before-view is mandatory; cannot add/revoke from conflicting
    // live and durable config inventories.
    read_verified_snapshot(interface).map_err(AtomicError::ReadOnlyValidation)?;
    let target = Path::new(WG_ROOT).join(format!("{interface}.conf"));
    let (original, identity) = read_current(&target)?;
    let plan = plan_peer_change(&original, change).map_err(AtomicError::Plan)?;
    replace_verified(Path::new(WG_ROOT), &target, &original, &identity, &plan)?;
    Ok(plan.changed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddressPool, Claims, Grant, InviteState};
    use crate::ledger_disk;
    use crate::wg_peer_plan::{plan_change, Change};
    use std::net::Ipv4Addr;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::Duration;

    const INV: &str = "11111111-1111-4111-8111-111111111111";
    const REQ: &str = "22222222-2222-4222-8222-222222222222";
    const DEV: &str = "33333333-3333-4333-8333-333333333333";

    fn setup(tag: &str) -> (std::path::PathBuf, LedgerStore, Grant) {
        let path = std::env::temp_dir().join(format!(
            "spidervpn-atomic-wg-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let ledger_root = path.join("ledger");
        fs::create_dir_all(&ledger_root).unwrap();
        fs::set_permissions(&ledger_root, fs::Permissions::from_mode(0o700)).unwrap();
        ledger_disk::bootstrap_for_test(&ledger_root).unwrap();
        let mut store=LedgerStore::open_existing(&ledger_root,Duration::ZERO).unwrap();
        store.update(|l|l.insert_open(INV,600)).unwrap();
        let claim=Claims{
            invite_id:INV.into(),request_id:REQ.into(),device_id:DEV.into(),
            public_key:format!("{}=","A".repeat(43)),
            request_digest:"a".repeat(64),recipient_jwk_digest:"b".repeat(64),
        };
        let grant=store.update(|l|l.reserve(
            claim,100,AddressPool{network:Ipv4Addr::new(10,66,0,0),prefix:24},
            Some(&[]))).unwrap();
        (path,store,grant)
    }
    fn conf() -> &'static [u8] {
        b"[Interface]\nPrivateKey = DO_NOT_PRINT_THIS\nAddress=10.66.0.1/24\n"
    }
    #[test]
    fn atomic_write_only_after_durable_pending_and_original_file_unchanged_before_commit() {
        let (p,store,g)=setup("persist");
        let target=p.join("wg0.conf");
        fs::write(&target,conf()).unwrap();
        fs::set_permissions(&target,fs::Permissions::from_mode(0o600)).unwrap();
        let (original,meta)=read_current(&target).unwrap();
        let plan=plan_change(&original,&g,Change::Add).unwrap();
        expected_status(&store,PeerChange::Invitation(&g,Change::Add)).unwrap();
        assert!(!String::from_utf8_lossy(&original).contains(&g.claims.public_key));
        replace_verified(&p,&target,&original,&meta,&plan).unwrap();
        let new=fs::read(&target).unwrap();
        assert!(String::from_utf8_lossy(&new).contains(&g.claims.public_key));
        assert!(new.starts_with(conf()));
        assert!(!format!("{plan:?}").contains("DO_NOT_PRINT_THIS"));
        drop(store);fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn tampered_source_does_not_get_overwritten() {
        let (p,store,g)=setup("tamper");
        let target=p.join("wg0.conf");
        fs::write(&target,conf()).unwrap();
        fs::set_permissions(&target,fs::Permissions::from_mode(0o600)).unwrap();
        let (original,meta)=read_current(&target).unwrap();
        let plan=plan_change(&original,&g,Change::Add).unwrap();
        let modified=b"[Interface]\nPrivateKey=MODIFIED\n";
        fs::write(&target,modified).unwrap();
        assert!(matches!(
            replace_verified(&p,&target,&original,&meta,&plan),
            Err(AtomicError::UntrustedOriginal)
        ));
        assert_eq!(fs::read(&target).unwrap(),modified);
        drop(store);fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn symlink_and_world_writable_peer_config_fail_closed() {
        let (p,store,g)=setup("links");
        let target=p.join("wg0.conf");
        let original=p.join("unchanged");
        fs::write(&original,conf()).unwrap();
        symlink(&original,&target).unwrap();
        assert!(read_current(&target).is_err());
        fs::remove_file(&target).unwrap();
        fs::write(&target,conf()).unwrap();
        fs::set_permissions(&target,fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_current(&target).is_err());
        let _=g;
        drop(store);fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn after_rename_sync_failure_leaves_new_config_and_pending_grant() {
        let (p,store,g)=setup("uncertain");
        let target=p.join("wg0.conf");
        fs::write(&target,conf()).unwrap();
        fs::set_permissions(&target,fs::Permissions::from_mode(0o600)).unwrap();
        let (original,meta)=read_current(&target).unwrap();
        let plan=plan_change(&original,&g,Change::Add).unwrap();
        FAIL_AFTER_RENAME.with(|flag|flag.set(true));
        let error=replace_verified(&p,&target,&original,&meta,&plan);
        FAIL_AFTER_RENAME.with(|flag|flag.set(false));
        assert!(matches!(error,Err(AtomicError::CommitUncertain)));
        assert!(String::from_utf8_lossy(&fs::read(&target).unwrap())
            .contains(&g.claims.public_key), "rename may have happened");
        assert!(matches!(store.view().unwrap().state(INV),
            Some(InviteState::Pending(_))), "never mark consumed on uncertain fsync");
        drop(store);fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn wrong_ledger_phase_or_grant_cannot_write() {
        let (p,mut store,g)=setup("phase");
        assert!(expected_status(&store,PeerChange::Invitation(&g,Change::Remove)).is_err());
        let mut changed=g.clone();
        changed.address=Ipv4Addr::new(10,66,0,12);
        assert!(expected_status(&store,PeerChange::Invitation(&changed,Change::Add)).is_err());
        store.update(|l|l.begin_revocation(INV)).unwrap();
        assert!(expected_status(&store,PeerChange::Invitation(&g,Change::Add)).is_err());
        expected_status(&store,PeerChange::Invitation(&g,Change::Remove)).unwrap();
        drop(store);fs::remove_dir_all(p).unwrap();
    }
}

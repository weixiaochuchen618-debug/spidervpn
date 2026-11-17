//! SEC-01/SEC-08: experimental *offline*, root-only retired Python
//! entrypoint primitive. This module is compiled ONLY with the explicit
//! linux-legacy-retire feature; no CLI, production service, or Windows UI
//! calls it.
//!
//! SECURITY GOAL: the legacy Windows SSH deployer writes to tc-pair.py with
//! shell redirection. A simple symlink to /dev/null is UNSAFE because its
//! subsequent chmod 600 could change /dev/null permissions. Instead place a
//! root-only EMPTY DIRECTORY at the old pathname: Python cannot interpret
//! it as a script and shell '>' cannot overwrite it.
//!
//! Linux renameat2(RENAME_EXCHANGE) swaps a prepared empty directory with the
//! old file ATOMICALLY. In the running kernel there is no intermediate
//! missing-path window for an old SSH '>' upload. Durability requires the
//! subsequent parent-directory fsync; a power loss before that fsync may
//! revert the exchange. Never authorize migration without re-observing the
//! retired path after restart. Original bytes go to protected quarantine.
//!
//! This is NOT a global writer fence: uncooperative root may bypass any
//! filesystem state, invoke a copied script, or race before the swap; old
//! SSH callers remain outside the Rust flock until a full supervisor cutover.
//! The witness has no migration/import/authorization interface.

#![cfg(all(target_os="linux", feature="linux-legacy-retire"))]

use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::legacy_cutover::observe_old_python_shutdown;

const OLD_ROOT: &str = "/var/lib/tradechannel/pairing-rs";
const SCRIPT: &str = "tc-pair.py";
const STAGING: &str = ".tc-pair.py.stage";
const QUARANTINE: &str = ".tc-pair.py.retired";
const NOFOLLOW: i32 = 0o400000; // Linux x86_64
const AT_FDCWD: i32 = -100;
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

unsafe extern "C" {
    fn geteuid() -> u32;
    fn renameat2(oldfd: i32, oldpath: *const c_char,
        newfd: i32, newpath: *const c_char, flags: u32) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementError {
    RootRequired,
    OldReceiverNotProvenStopped,
    UnsafeParent,
    UnsafeScript,
    ExistingStagingOrBackup,
    AtomicExchangeFailed,
    PersistFailed,
    IncompleteRetirement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetirementWitness {
    pub legacy_script_path_is_directory: bool,
    pub original_script_preserved: bool,
}
impl RetirementWitness {
    pub fn authorizes_migration(&self) -> bool { false }
    pub fn authorizes_new_listener(&self) -> bool { false }
}

fn root_uid() -> u32 { unsafe { geteuid() } }
fn secure_root(parent:&Path,owner:u32)->Result<(),RetirementError>{
    let m=fs::symlink_metadata(parent).map_err(|_|RetirementError::UnsafeParent)?;
    if !parent.is_absolute() || !m.file_type().is_dir()
        || m.uid()!=owner || m.mode() & 0o777 != 0o700 {
        return Err(RetirementError::UnsafeParent);
    }
    Ok(())
}
fn secure_script(path:&Path,owner:u32)->Result<(),RetirementError>{
    let m=fs::symlink_metadata(path).map_err(|_|RetirementError::UnsafeScript)?;
    if !m.file_type().is_file() || m.uid()!=owner || m.nlink()!=1
        || m.mode() & 0o777 != 0o600 {
        return Err(RetirementError::UnsafeScript);
    }
    // Ensure the file is not replaced by a symlink between metadata check
    // and the planned exchange. A cooperating root must respect this gate.
    let handle=OpenOptions::new().read(true).custom_flags(NOFOLLOW)
        .open(path).map_err(|_|RetirementError::UnsafeScript)?;
    let actual=handle.metadata().map_err(|_|RetirementError::UnsafeScript)?;
    if actual.ino()!=m.ino() || actual.dev()!=m.dev() {
        return Err(RetirementError::UnsafeScript);
    }
    Ok(())
}
fn empty_private_directory(path:&Path,owner:u32)->Result<(),RetirementError>{
    let m=fs::symlink_metadata(path).map_err(|_|RetirementError::IncompleteRetirement)?;
    if !m.file_type().is_dir() || m.uid()!=owner
        || m.mode() & 0o777 != 0o700 {
        return Err(RetirementError::IncompleteRetirement);
    }
    let mut entries=fs::read_dir(path).map_err(|_|RetirementError::IncompleteRetirement)?;
    if entries.next().is_some() {return Err(RetirementError::IncompleteRetirement);}
    Ok(())
}
fn absent(path:&Path)->Result<bool,RetirementError>{
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind()==io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(RetirementError::UnsafeParent),
    }
}
fn rename_with(old:&Path,new:&Path,flags:u32)->Result<(),RetirementError>{
    let old=CString::new(old.as_os_str().as_bytes())
        .map_err(|_|RetirementError::UnsafeParent)?;
    let new=CString::new(new.as_os_str().as_bytes())
        .map_err(|_|RetirementError::UnsafeParent)?;
    let result=unsafe{renameat2(AT_FDCWD,old.as_ptr(),AT_FDCWD,new.as_ptr(),flags)};
    if result!=0 {return Err(RetirementError::AtomicExchangeFailed);}
    Ok(())
}
fn sync_parent(parent:&Path)->Result<(),RetirementError>{
    File::open(parent).and_then(|dir|dir.sync_all())
        .map_err(|_|RetirementError::PersistFailed)
}
fn script(parent:&Path)->PathBuf {parent.join(SCRIPT)}
fn staged(parent:&Path)->PathBuf {parent.join(STAGING)}
fn backup(parent:&Path)->PathBuf {parent.join(QUARANTINE)}

fn stage_at(parent:&Path,owner:u32)->Result<RetirementWitness,RetirementError>{
    secure_root(parent,owner)?;
    let original=script(parent);
    let prepared=staged(parent);
    let preserved=backup(parent);
    secure_script(&original,owner)?;
    // Never overwrite an old backup or an unknown interrupted staging path.
    if !absent(&prepared)? || !absent(&preserved)? {
        return Err(RetirementError::ExistingStagingOrBackup);
    }
    DirBuilder::new().mode(0o700).create(&prepared)
        .map_err(|_|RetirementError::UnsafeParent)?;
    empty_private_directory(&prepared,owner)?;
    sync_parent(parent)?; // stage dir must survive an interruption pre-swap
    // CRITICAL atomic swap: while running, there is no missing-path
    // interval for SSH redirection. Power-loss durability is NOT guaranteed
    // until the parent directory fsync succeeds; any uncertain state must
    // be re-inspected after reboot before authorizing future cutover.
    rename_with(&original,&prepared,RENAME_EXCHANGE)?;
    sync_parent(parent)?;
    empty_private_directory(&original,owner)?;
    secure_script(&prepared,owner)?;
    // No-replace rename prevents deleting an unrelated existing backup.
    rename_with(&prepared,&preserved,RENAME_NOREPLACE)?;
    sync_parent(parent)?;
    witness_at(parent,owner)
}
fn witness_at(parent:&Path,owner:u32)
    ->Result<RetirementWitness,RetirementError>
{
    secure_root(parent,owner)?;
    empty_private_directory(&script(parent),owner)?;
    if !absent(&staged(parent))? {return Err(RetirementError::IncompleteRetirement);}
    secure_script(&backup(parent),owner)
        .map_err(|_|RetirementError::IncompleteRetirement)?;
    Ok(RetirementWitness{
        legacy_script_path_is_directory:true,
        original_script_preserved:true,
    })
}

/// Root-only RETIRE PRIMITIVE, not wired to an application or CLI. Calls the
/// existing read-only mask/systemd/process/listener denial check BEFORE and
/// AFTER the atomic swap. An error after the swap must NOT auto-restore the
/// old runnable entrypoint; manual root rollback and new approval required.
pub fn stage_offline_legacy_retirement()->Result<RetirementWitness,RetirementError>{
    if root_uid()!=0 {return Err(RetirementError::RootRequired);}
    observe_old_python_shutdown()
        .map_err(|_|RetirementError::OldReceiverNotProvenStopped)?;
    let report=stage_at(Path::new(OLD_ROOT),0)?;
    observe_old_python_shutdown()
        .map_err(|_|RetirementError::OldReceiverNotProvenStopped)?;
    witness_at(Path::new(OLD_ROOT),0)?;
    Ok(report)
}

/// Read-only proof that the **known script path** has been replaced by a
/// non-overwritable 0700 directory, and its bytes survive in quarantine.
/// Does not prevent execution of copies or privileged root intervention.
pub fn observe_offline_retired_entrypoint()->Result<RetirementWitness,RetirementError>{
    if root_uid()!=0 {return Err(RetirementError::RootRequired);}
    observe_old_python_shutdown()
        .map_err(|_|RetirementError::OldReceiverNotProvenStopped)?;
    witness_at(Path::new(OLD_ROOT),0)
}

#[cfg(test)]
mod tests{
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const CODE: &[u8]=b"print('old pairing writer')\n";
    fn make_root(tag:&str)->PathBuf{
        let parent=std::env::temp_dir().join(
            format!("spider-retire-{tag}-{}",std::process::id()));
        let _=fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent,fs::Permissions::from_mode(0o700)).unwrap();
        parent
    }
    fn put_script(parent:&Path){
        let mut f=OpenOptions::new().create_new(true).write(true).mode(0o600)
            .open(script(parent)).unwrap();
        f.write_all(CODE).unwrap();
        f.sync_all().unwrap();
    }
    fn clean(parent:&Path){fs::remove_dir_all(parent).unwrap();}
    #[test]
    fn atomic_exchange_retires_legacy_path_and_preserves_original_bytes(){
        let root=make_root("atomic");
        put_script(&root);
        let witness=stage_at(&root,root_uid()).unwrap();
        assert!(witness.legacy_script_path_is_directory);
        assert!(witness.original_script_preserved);
        assert!(!witness.authorizes_migration());
        assert!(!witness.authorizes_new_listener());
        assert_eq!(fs::read(backup(&root)).unwrap(),CODE);
        assert!(OpenOptions::new().write(true).truncate(true)
            .open(script(&root)).is_err(),
            "legacy Windows SSH '>' upload must fail against directory tombstone");
        assert!(fs::File::open(script(&root)).unwrap().metadata().unwrap().is_dir());
        assert_eq!(stage_at(&root,root_uid()),Err(RetirementError::UnsafeScript));
        clean(&root);
    }
    #[test]
    fn interrupted_after_swap_keeps_old_path_blocked_not_recreatable(){
        let root=make_root("after-swap");
        put_script(&root);
        let prepared=staged(&root);
        DirBuilder::new().mode(0o700).create(&prepared).unwrap();
        rename_with(&script(&root),&prepared,RENAME_EXCHANGE).unwrap();
        sync_parent(&root).unwrap();
        empty_private_directory(&script(&root),root_uid()).unwrap();
        assert!(OpenOptions::new().write(true).create(true).truncate(true)
            .open(script(&root)).is_err());
        assert_eq!(fs::read(prepared).unwrap(),CODE);
        assert_eq!(witness_at(&root,root_uid()),Err(RetirementError::IncompleteRetirement));
        clean(&root);
    }
    #[test]
    fn interrupted_before_swap_is_not_falsely_considered_retired(){
        let root=make_root("before-swap");
        put_script(&root);
        DirBuilder::new().mode(0o700).create(staged(&root)).unwrap();
        assert_eq!(stage_at(&root,root_uid()),
            Err(RetirementError::ExistingStagingOrBackup));
        assert_eq!(witness_at(&root,root_uid()),
            Err(RetirementError::IncompleteRetirement));
        assert_eq!(fs::read(script(&root)).unwrap(),CODE);
        clean(&root);
    }
    #[test]
    fn unsafe_symlink_hardlink_and_existing_backup_are_rejected(){
        let root=make_root("malformed");
        fs::write(root.join("target"),CODE).unwrap();
        symlink("target",script(&root)).unwrap();
        assert_eq!(stage_at(&root,root_uid()),Err(RetirementError::UnsafeScript));
        fs::remove_file(script(&root)).unwrap();
        put_script(&root);
        fs::hard_link(script(&root),root.join("hard-link")).unwrap();
        assert_eq!(stage_at(&root,root_uid()),Err(RetirementError::UnsafeScript));
        fs::remove_file(root.join("hard-link")).unwrap();
        fs::write(backup(&root),b"preexisting backup").unwrap();
        assert_eq!(stage_at(&root,root_uid()),
            Err(RetirementError::ExistingStagingOrBackup));
        assert_eq!(fs::read(backup(&root)).unwrap(),b"preexisting backup");
        clean(&root);
    }
    #[test]
    fn weak_permissions_and_modified_tombstone_are_denied(){
        let root=make_root("permissions");
        put_script(&root);
        fs::set_permissions(script(&root),fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(stage_at(&root,root_uid()),Err(RetirementError::UnsafeScript));
        fs::set_permissions(script(&root),fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root,fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(stage_at(&root,root_uid()),Err(RetirementError::UnsafeParent));
        fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
        stage_at(&root,root_uid()).unwrap();
        fs::write(script(&root).join("unexpected"),b"X").unwrap();
        assert_eq!(witness_at(&root,root_uid()),
            Err(RetirementError::IncompleteRetirement));
        clean(&root);
    }
}

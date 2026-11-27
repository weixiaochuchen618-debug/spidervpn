//! SEC-01 S01: **pre-integration** crash-consistent Rust authority ledger.
//!
//! Not used by the deployed Python receiver. A future Rust transaction must
//! hold this lock for read ledger -> persist Pending/Revoking -> modify WG ->
//! verify live WG -> persist Consumed/Revoked. This module never invokes WG.
//!
//! Security invariants:
//! - Never interpret a missing, corrupt or unknown-version ledger as empty.
//! - Owner-only Linux directory and regular 0600, single-link ledger file;
//!   O_NOFOLLOW refuses symlinked ledgers. The immutable lock file is held
//!   from open through each commit, including parent-directory fsync.
//! - Serialise and fsync a create_new 0600 temporary file, rename atomically,
//!   fsync the directory. The old generation survives failures before rename.
//! - Validate all IDs, claims, revoked tombstones and active allocations on
//!   every load AND every commit. Mutating in-memory state never authorizes
//!   an unpersisted transition.
//! - Missing file requires explicit offline bootstrap, which is deliberately
//!   test-only until legacy import and anti-rollback controls are implemented.
//!
//! Limitations: not an anti-rollback store (a privileged actor can replace an
//! old, internally valid ledger). No live WG inventory, crypto trust or legacy
//! import is performed here. Do not promote SEC-01 to fixed on these tests.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{claims_valid, lower_uuid, wg_key, Grant, InviteState, Ledger, Refusal};
use crate::lock::{self, AuthorityLock};

const LEDGER_NAME: &str = "authority-ledger.json";
const SCHEMA: u32 = 1;
const MAX_BYTES: u64 = 4 * 1024 * 1024;
// Linux x86_64 O_NOFOLLOW. A symlink must never be opened as a ledger.
const O_NOFOLLOW: i32 = 0o400000;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Json(serde_json::Error),
    Missing,
    Invalid(&'static str),
    Policy(Refusal),
    GenerationExhausted,
    /// An I/O error may occur AFTER rename. This object can no longer
    /// authorize reads or writes until it is closed and freshly reopened.
    Poisoned,
}
impl From<io::Error> for StoreError {
    fn from(err: io::Error) -> Self { Self::Io(err) }
}
impl From<serde_json::Error> for StoreError {
    fn from(err: serde_json::Error) -> Self { Self::Json(err) }
}

/// Original response material is part of the same protected atomic document
/// as the exact grant. It is never reconstructed from an old Consumed record.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizationMaterial {
    pub(crate) grant: Grant,
    pub(crate) signed: String,
    pub(crate) issued_unix: i64,
    pub(crate) expires_unix: i64,
}
impl std::fmt::Debug for AuthorizationMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizationMaterial([redacted])")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    generation: u64,
    ledger: Ledger,
    // Version-1 documents without response material remain readable and
    // byte-compatible on ordinary writes. Missing material denies a reply.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    authorization_material: BTreeMap<String, AuthorizationMaterial>,
}

pub struct LedgerStore {
    root: PathBuf,
    // The guard is held even during filesystem I/O, not just while calling
    // Ledger::reserve or Ledger::begin_revocation.
    _guard: AuthorityLock,
    generation: u64,
    value: Ledger,
    authorization_material: BTreeMap<String, AuthorizationMaterial>,
    poisoned: bool,
}

/// Reject both stale and internally impossible states, without attempting
/// silent recovery that might resurrect a previously revoked peer.
pub(crate) fn validate(ledger: &Ledger) -> Result<(), StoreError> {
    use crate::existing_devices::{DeviceOrigin, ExistingDeviceState};

    let mut seen_keys = BTreeSet::new();
    let mut seen_devices = BTreeSet::new();
    let mut active_addresses = BTreeSet::new();

    if ledger.invitations.len() > 4096
        || ledger.revoked_keys.len() > 4096
        || ledger.revoked_devices.len() > 4096
    {
        return Err(StoreError::Invalid("authority ledger exceeds record count limit"));
    }

    if !ledger.revoked_keys.iter().all(|s| wg_key(s))
        || !ledger.revoked_devices.iter().all(|s| lower_uuid(s))
    {
        return Err(StoreError::Invalid("invalid durable revocation tombstone"));
    }

    if let Some(history) = &ledger.existing_history {
        if !crate::hex_sha256(&history.snapshot_sha256)
            || history.devices.is_empty() || history.devices.len() > 4096
        {
            return Err(StoreError::Invalid("invalid existing device history"));
        }
    }
    let mut original_invites = BTreeSet::new();
    for (id, device) in ledger.existing_devices() {
        if !device.valid(id) || !seen_keys.insert(device.public_key.as_str())
            || !seen_devices.insert(id.as_str())
        {
            return Err(StoreError::Invalid("invalid or duplicate existing device"));
        }
        if let DeviceOrigin::SignedV2 { invite_id, .. } = &device.origin {
            if !original_invites.insert(invite_id)
                || !matches!(ledger.state(invite_id), Some(InviteState::Cancelled))
            {
                return Err(StoreError::Invalid("existing device lost closed invitation"));
            }
        }
        let revoked = device.state == ExistingDeviceState::Revoked;
        if ledger.revoked_keys.contains(&device.public_key) != revoked
            || ledger.revoked_devices.contains(id) != revoked
            || (!revoked && !active_addresses.insert(device.address))
        {
            return Err(StoreError::Invalid("existing device conflicts with durable peer history"));
        }
    }

    for (id, inv) in &ledger.invitations {
        if !lower_uuid(id) { return Err(StoreError::Invalid("malformed invitation key")); }
        let grant: Option<&Grant> = match &inv.state {
            InviteState::Open | InviteState::Cancelled | InviteState::Expired => None,
            InviteState::Pending(grant)
            | InviteState::Consumed(grant)
            | InviteState::Revoking(grant)
            | InviteState::Revoked(grant) => Some(grant),
        };
        if let Some(grant) = grant {
            let claims = &grant.claims;
            if !claims_valid(claims) || claims.invite_id != *id
                || !grant.address.is_private()
            {
                return Err(StoreError::Invalid("untrusted grant claims, key or address"));
            }
            if !seen_keys.insert(claims.public_key.as_str())
                || !seen_devices.insert(claims.device_id.as_str())
            {
                return Err(StoreError::Invalid("duplicate grant key or device"));
            }
            if matches!(inv.state, InviteState::Revoked(_)) {
                if !ledger.revoked_keys.contains(&claims.public_key)
                    || !ledger.revoked_devices.contains(&claims.device_id)
                {
                    return Err(StoreError::Invalid("revoked grant lost durable tombstone"));
                }
            } else {
                if ledger.revoked_keys.contains(&claims.public_key)
                    || ledger.revoked_devices.contains(&claims.device_id)
                {
                    return Err(StoreError::Invalid("active grant collides with revocation tombstone"));
                }
                if !active_addresses.insert(grant.address) {
                    return Err(StoreError::Invalid("duplicate active peer address"));
                }
            }
        }
    }
    Ok(())
}

fn validate_document(doc: &Document) -> Result<(), StoreError> {
    validate(&doc.ledger)?;
    if doc.authorization_material.len() > doc.ledger.invitations.len() {
        return Err(StoreError::Invalid("unbound authorization material"));
    }
    for (id, m) in &doc.authorization_material {
        let grant = match doc.ledger.state(id) {
            Some(InviteState::Consumed(g) | InviteState::Revoking(g) | InviteState::Revoked(g)) => g,
            _ => return Err(StoreError::Invalid("authorization material without terminal grant")),
        };
        if m.grant != *grant || m.issued_unix < 0
            || m.issued_unix.checked_add(3600) != Some(m.expires_unix)
            || m.signed.is_empty() || m.signed.len() > 131_072
            || m.signed.split('.').count() != 3
            || !m.signed.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
            return Err(StoreError::Invalid("invalid bound authorization material"));
        }
    }
    Ok(())
}

fn assert_private(file: &File) -> Result<(), StoreError> {
    let meta = file.metadata()?;
    let owner = unsafe { geteuid() };
    if !meta.file_type().is_file() || meta.uid() != owner
        || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600
    {
        return Err(StoreError::Invalid("authority ledger must be owner-only regular single-link file"));
    }
    Ok(())
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

fn secure_read(root: &Path) -> Result<Document, StoreError> {
    read_validated_document(root).map(|(doc, _)| doc)
}

// One open and one bounded read for both the parsed document and the exact
// bytes that passed all existing validations. No reserialization or reopen.
fn read_validated_document(root: &Path) -> Result<(Document, Vec<u8>), StoreError> {
    let path = root.join(LEDGER_NAME);
    let file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(&path)
        .map_err(|e| if e.kind() == io::ErrorKind::NotFound {
            StoreError::Missing
        } else { StoreError::Io(e) })?;
    assert_private(&file)?;
    if file.metadata()?.len() > MAX_BYTES {
        return Err(StoreError::Invalid("authority ledger exceeds input bound"));
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(StoreError::Invalid("authority ledger expanded while reading"));
    }
    let doc: Document = serde_json::from_slice(&bytes)?;
    if doc.schema_version != SCHEMA || doc.generation == 0 {
        return Err(StoreError::Invalid("unknown ledger schema or impossible generation"));
    }
    validate_document(&doc)?;
    // On reopen, a prior rename may have been visible before a failed
    // directory fsync. Do not expose original response material until this
    // exact protected file and its directory have both synced successfully.
    // This does not repair Pending or establish anti-rollback history.
    if !doc.authorization_material.is_empty() {
        file.sync_all()?;
        File::open(root)?.sync_all()?;
    }
    Ok((doc, bytes))
}

/// L1 isolated experiment ONLY: an observation of validated local bytes,
/// NOT an independently current checkpoint or permission. Own the same
/// exclusive lock as LedgerStore, but expose no mutation, conversion to a
/// writable store, detached digest/ledger, or serialization interface.
/// Noncooperating writers, whole-machine rollback and external revocation
/// are outside this local evidence boundary. Compiled only for tests.
#[cfg(test)]
pub(crate) struct ReadOnlyLedgerEvidence {
    doc: Document,
    sha256: ring::digest::Digest,
    _guard: AuthorityLock,
}

#[cfg(test)]
impl ReadOnlyLedgerEvidence {
    pub(crate) fn open(root: &Path, timeout: Duration) -> Result<Self, StoreError> {
        let guard = lock::acquire_for(root, timeout)?;
        let (doc, bytes) = read_validated_document(root)?;
        let sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes);
        Ok(Self { doc, sha256, _guard: guard })
    }

    /// The expected tuple is only comparison input, not trusted history.
    /// Borrow the parsed value from this exact still-locked observation.
    pub(crate) fn compare(&self, generation: u64, sha256: &[u8; 32])
        -> Result<&Ledger, StoreError>
    {
        if self.doc.generation != generation || self.sha256.as_ref() != sha256 {
            return Err(StoreError::Invalid("local ledger evidence mismatch"));
        }
        Ok(&self.doc.ledger)
    }
}

fn temporary_path(root: &Path) -> Result<PathBuf, StoreError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::Invalid("system clock unavailable"))?
        .as_nanos();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(root.join(format!(".authority-ledger-{}-{now}-{counter}.tmp", std::process::id())))
}

fn store_atomic(root: &Path, doc: &Document) -> Result<(), StoreError> {
    validate_document(doc)?;
    if doc.schema_version != SCHEMA || doc.generation == 0 {
        return Err(StoreError::Invalid("invalid ledger commit generation"));
    }
    let bytes = serde_json::to_vec(doc)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(StoreError::Invalid("serialized authority ledger too large"));
    }

    // Create inside the same protected directory: rename() is an atomic
    // replacement on one filesystem. Fail rather than overwrite a preseeded
    // temp path or a symlink, and never truncate the current ledger.
    let temporary = temporary_path(root)?;
    let mut new_file = OpenOptions::new()
        .write(true).create_new(true).mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&temporary)?;
    let written = (|| -> Result<(), StoreError> {
        assert_private(&new_file)?;
        new_file.write_all(&bytes)?;
        new_file.sync_all()?;
        // Recheck the existing destination. A missing ledger can only be
        // introduced through a separate, test-only bootstrap path.
        assert_private(&OpenOptions::new().read(true)
            .custom_flags(O_NOFOLLOW).open(root.join(LEDGER_NAME))?)?;
        fs::rename(&temporary, root.join(LEDGER_NAME))?;
        #[cfg(test)]
        if FAIL_AFTER_RENAME.with(|cell| cell.get()) {
            return Err(StoreError::Io(io::Error::other(
                "injected post-rename pre-directory-fsync failure"
            )));
        }
        // An fsync on the parent is necessary for the name replacement to
        // survive power loss. Failure is NOT permission to proceed to WG.
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

impl LedgerStore {
    /// Production-facing: only an already-initialized, validated, locked
    /// authority ledger may be opened. Missing != empty.
    pub fn open_existing(root: &Path, timeout: Duration) -> Result<Self, StoreError> {
        let guard = lock::acquire_for(root, timeout)?;
        let doc = secure_read(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            _guard: guard,
            generation: doc.generation,
            value: doc.ledger,
            authorization_material: doc.authorization_material,
            poisoned: false,
        })
    }

    pub fn view(&self) -> Result<&Ledger, StoreError> {
        if self.poisoned { return Err(StoreError::Poisoned); }
        Ok(&self.value)
    }

    pub fn generation(&self) -> Result<u64, StoreError> {
        if self.poisoned { return Err(StoreError::Poisoned); }
        Ok(self.generation)
    }

    /// Make a defensive copy, validate and *durably commit* it before
    /// exposing new in-memory state or authorizing a WireGuard operation.
    /// The caller must keep this store alive while applying WG + readback
    /// and committing the final state; any failed commit means STOP.
    pub fn update<T>(
        &mut self,
        f: impl FnOnce(&mut Ledger) -> Result<T, Refusal>,
    ) -> Result<T, StoreError> {
        self.update_inner(f, None)
    }

    #[cfg(feature = "linux-authorization-response")]
    pub(crate) fn authorization_material(&self, id: &str) -> Result<&AuthorizationMaterial, StoreError> {
        if self.poisoned { return Err(StoreError::Poisoned); }
        self.authorization_material.get(id)
            .ok_or(StoreError::Invalid("original authorization material unavailable"))
    }

    /// The readback-confirmed Consumed transition and original signed
    /// material are committed together, never as two separate updates.
    #[cfg(feature = "linux-authorization-response")]
    pub(crate) fn confirm_authorized(&mut self, material: AuthorizationMaterial,
        peers: &[crate::Peer]) -> Result<Grant, StoreError>
    {
        let grant = material.grant.clone();
        self.update_inner(|ledger| {
            let confirmed = ledger.confirm_consumed(&grant.claims.invite_id, Some(peers))?;
            if confirmed != grant { return Err(Refusal::Conflict); }
            Ok(confirmed)
        }, Some(material))
    }

    fn update_inner<T>(
        &mut self, f: impl FnOnce(&mut Ledger) -> Result<T, Refusal>,
        material: Option<AuthorizationMaterial>,
    ) -> Result<T, StoreError> {
        if self.poisoned { return Err(StoreError::Poisoned); }
        let mut next = self.value.clone();
        let output = f(&mut next).map_err(StoreError::Policy)?;
        validate(&next)?;
        let generation = self.generation.checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        let mut next_material = self.authorization_material.clone();
        if let Some(m) = material {
            if next_material.contains_key(&m.grant.claims.invite_id) {
                return Err(StoreError::Invalid("cannot replace original authorization"));
            }
            next_material.insert(m.grant.claims.invite_id.clone(), m);
        }
        if let Err(error) = store_atomic(&self.root, &Document {
            schema_version: SCHEMA,
            generation,
            ledger: next.clone(),
            authorization_material: next_material.clone(),
        }) {
            // The atomic rename may have happened even if the final fsync
            // failed. Treat the in-memory copy as stale, block ALL further
            // decisions, and require closing/reopening after investigation.
            self.poisoned = true;
            return Err(error);
        }
        self.value = next;
        self.authorization_material = next_material;
        self.generation = generation;
        Ok(output)
    }
}

/// Only explicit provisioning to a newly created protected root may use this.
#[cfg(feature = "linux-fresh-provisioning")]
pub(crate) fn publish_initial_ledger(root: &Path, dir: &File, ledger: Ledger)
    -> Result<(), StoreError>
{
    use std::os::fd::AsRawFd;
    let _guard=lock::acquire_for(root,Duration::ZERO)?;
    let doc=Document {schema_version:SCHEMA,generation:1,ledger,
        authorization_material:BTreeMap::new()};
    validate_document(&doc)?;
    let bytes=serde_json::to_vec(&doc)?;
    crate::tls_identity::create_fresh_service_file(dir,".fresh-ledger-staging",&bytes)?;
    let from=std::ffi::CString::new(".fresh-ledger-staging").unwrap();
    let to=std::ffi::CString::new(LEDGER_NAME).unwrap();
    if unsafe {libc::renameat2(dir.as_raw_fd(),from.as_ptr(),dir.as_raw_fd(),
        to.as_ptr(),libc::RENAME_NOREPLACE)}!=0 {
        return Err(StoreError::Io(io::Error::last_os_error()));
    }
    dir.sync_all()?;
    Ok(())
}

/// Test-only bootstrap: the production importer must verify signatures,
/// old tombstones, and WG inventory before creating any production ledger.
#[cfg(test)]
pub(crate) fn bootstrap_for_test(root: &Path) -> Result<(), StoreError> {
    let _lock = lock::acquire_for(root, Duration::from_secs(1))?;
    let path = root.join(LEDGER_NAME);
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(O_NOFOLLOW).open(path)?;
    let data = serde_json::to_vec(&Document {
        schema_version: SCHEMA, generation: 1, ledger: Ledger::default(),
        authorization_material: BTreeMap::new(),
    })?;
    file.write_all(&data)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddressPool, Claims, InviteState, Peer};
    use std::net::Ipv4Addr;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const INV: &str = "11111111-1111-4111-8111-111111111111";
    const INV2: &str = "22222222-2222-4222-8222-222222222222";
    const DEV: &str = "33333333-3333-4333-8333-333333333333";
    const REQ: &str = "44444444-4444-4444-8444-444444444444";

    fn dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "spidervpn-sec01-ledger-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    fn claim(inv: &str) -> Claims {
        Claims { invite_id: inv.into(), request_id: REQ.into(),
            device_id: DEV.into(), public_key: format!("{}=", "A".repeat(43)),
            request_digest: "a".repeat(64), recipient_jwk_digest: "b".repeat(64) }
    }
    fn pool() -> AddressPool {
        AddressPool { network: Ipv4Addr::new(10, 9, 8, 0), prefix: 29 }
    }
    fn peer(g: &Grant) -> Peer {
        Peer { public_key: g.claims.public_key.clone(), address: g.address }
    }

    #[test]
    fn missing_ledger_must_not_be_treated_as_empty() {
        let p = dir("missing");
        assert!(matches!(LedgerStore::open_existing(&p, Duration::ZERO), Err(StoreError::Missing)));
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn pending_and_revoking_survive_restart_and_refuse_replay() {
        let p = dir("restart");
        bootstrap_for_test(&p).unwrap();
        let (grant, before);
        {
            let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
            store.update(|l| l.insert_open(INV, 600)).unwrap();
            grant = store.update(|l| l.reserve(claim(INV), 100, pool(), Some(&[]))).unwrap();
            before = store.generation().unwrap();
            assert!(matches!(store.view().unwrap().state(INV), Some(InviteState::Pending(_))));
        }
        {
            let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
            assert_eq!(store.generation().unwrap(), before);
            assert_eq!(store.view().unwrap().retry(&claim(INV), Some(&[peer(&grant)])),
                Err(Refusal::RecoveryRequired));
            store.update(|l| l.confirm_consumed(INV, Some(&[peer(&grant)]))).unwrap();
            store.update(|l| l.begin_revocation(INV)).unwrap();
        }
        {
            let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
            assert!(matches!(store.view().unwrap().state(INV), Some(InviteState::Revoking(_))));
            assert_eq!(store.view().unwrap().retry(&claim(INV), Some(&[])), Err(Refusal::Revoked));
            store.update(|l| l.confirm_revocation(INV, Some(&[]))).unwrap();
        }
        {
            let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
            assert!(matches!(store.view().unwrap().state(INV), Some(InviteState::Revoked(_))));
            store.update(|l| l.insert_open(INV2, 600)).unwrap();
            let mut reused = claim(INV2);
            reused.public_key = format!("{}=", "B".repeat(43));
            assert!(matches!(store.update(|l| l.reserve(reused, 100, pool(), Some(&[]))),
                Err(StoreError::Policy(Refusal::RevokedIdentity))));
        }
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn failed_policy_update_keeps_file_and_generation_byte_identical() {
        let p = dir("failed");
        bootstrap_for_test(&p).unwrap();
        let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        store.update(|l| l.insert_open(INV, 600)).unwrap();
        let original = fs::read(p.join(LEDGER_NAME)).unwrap();
        let generation = store.generation().unwrap();
        let res = store.update(|l| l.insert_open(INV, 900));
        assert!(matches!(res, Err(StoreError::Policy(Refusal::DuplicateInvitation))));
        assert_eq!(fs::read(p.join(LEDGER_NAME)).unwrap(), original);
        assert_eq!(store.generation().unwrap(), generation);
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn post_rename_fsync_failure_poisoned_store_cannot_reauthorize_stale_state() {
        let p = dir("uncertain-fsync");
        bootstrap_for_test(&p).unwrap();
        let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        store.update(|l| l.insert_open(INV, 600)).unwrap();
        FAIL_AFTER_RENAME.with(|cell| cell.set(true));
        let failure = store.update(|l| l.reserve(claim(INV), 100, pool(), Some(&[])));
        FAIL_AFTER_RENAME.with(|cell| cell.set(false));
        assert!(matches!(failure, Err(StoreError::Io(_))));
        assert!(matches!(store.view(), Err(StoreError::Poisoned)));
        assert!(matches!(store.generation(), Err(StoreError::Poisoned)));
        assert!(matches!(
            store.update(|l| l.cancel_open(INV)),
            Err(StoreError::Poisoned)
        ));
        // The replacement may already be visible. Stale "Open" in memory
        // must never override the persisted "Pending" after a failed fsync.
        let current = secure_read(&p).unwrap();
        assert!(matches!(current.ledger.state(INV), Some(InviteState::Pending(_))));
        drop(store);
        let reopened = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        assert!(matches!(
            reopened.view().unwrap().retry(&claim(INV), Some(&[])),
            Err(Refusal::RecoveryRequired)
        ));
        drop(reopened);
        fs::remove_dir_all(p).unwrap();
    }

    #[cfg(feature = "linux-authorization-response")]
    #[test]
    fn uncertain_final_authorization_commit_poisoned_store_exposes_no_reply_material() {
        let p = dir("authorization-uncertain");
        bootstrap_for_test(&p).unwrap();
        let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        store.update(|l| l.insert_open(INV, 600)).unwrap();
        let g = store.update(|l| l.reserve(claim(INV), 100, pool(), Some(&[]))).unwrap();
        // Storage-only marker, deliberately not a valid signed response.
        // The response handler must additionally verify the actual JWS.
        let material = AuthorizationMaterial { grant:g.clone(), signed:"a.b.c".into(),
            issued_unix:100, expires_unix:3700 };
        assert!(store.authorization_material(INV).is_err());
        FAIL_AFTER_RENAME.with(|cell| cell.set(true));
        let failure = store.confirm_authorized(material, &[peer(&g)]);
        FAIL_AFTER_RENAME.with(|cell| cell.set(false));
        assert!(matches!(failure, Err(StoreError::Io(_))));
        assert!(matches!(store.view(), Err(StoreError::Poisoned)));
        assert!(matches!(store.authorization_material(INV), Err(StoreError::Poisoned)));
        assert!(matches!(store.generation(), Err(StoreError::Poisoned)));
        drop(store);
        // The actual post-rename failure leaves the complete new document
        // visible. Reopening re-syncs it; neither half may appear alone.
        let store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        assert_eq!(store.view().unwrap().state(INV), Some(&InviteState::Consumed(g.clone())));
        let saved=store.authorization_material(INV).unwrap();
        assert!(saved.grant==g && saved.signed=="a.b.c" && saved.issued_unix==100
            && saved.expires_unix==3700);
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn damaged_unknown_schema_or_missing_tombstone_fails_closed() {
        let p = dir("corrupt");
        bootstrap_for_test(&p).unwrap();
        fs::write(p.join(LEDGER_NAME), b"{malformed").unwrap();
        assert!(LedgerStore::open_existing(&p, Duration::ZERO).is_err());
        fs::write(p.join(LEDGER_NAME), br#"{"schema_version":9,"generation":1,"ledger":{}}"#).unwrap();
        assert!(matches!(LedgerStore::open_existing(&p, Duration::ZERO),
            Err(StoreError::Invalid(_)) | Err(StoreError::Json(_))));
        // Even a valid-looking Revoked record without its durable tombstones
        // must never silently downgrade to an active state.
        let mut bad = Ledger::default();
        bad.insert_open(INV, 600).unwrap();
        let g = bad.reserve(claim(INV), 100, pool(), Some(&[])).unwrap();
        bad.confirm_consumed(INV, Some(&[peer(&g)])).unwrap();
        bad.begin_revocation(INV).unwrap();
        bad.invitations.get_mut(INV).unwrap().state = InviteState::Revoked(g);
        let json = serde_json::to_vec(&Document {schema_version:SCHEMA, generation:2, ledger:bad, authorization_material:BTreeMap::new()}).unwrap();
        fs::write(p.join(LEDGER_NAME), json).unwrap();
        assert!(matches!(LedgerStore::open_existing(&p, Duration::ZERO),
            Err(StoreError::Invalid(_))));
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn symlink_hardlink_and_loose_acl_ledger_are_all_rejected() {
        let p = dir("tamper");
        bootstrap_for_test(&p).unwrap();
        let path = p.join(LEDGER_NAME);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(LedgerStore::open_existing(&p, Duration::ZERO),
            Err(StoreError::Invalid(_))));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let external = p.join("external-contents");
        fs::write(&external, b"unchanged").unwrap();
        fs::rename(&path, p.join("ledger-copy")).unwrap();
        symlink(&external, &path).unwrap();
        assert!(LedgerStore::open_existing(&p, Duration::ZERO).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(p.join("ledger-copy"), &path).unwrap();
        assert!(matches!(LedgerStore::open_existing(&p, Duration::ZERO),
            Err(StoreError::Invalid(_))));
        assert_eq!(fs::read(&external).unwrap(), b"unchanged");
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn mutated_grant_and_duplicate_allocation_cannot_be_committed() {
        let p = dir("invariants");
        bootstrap_for_test(&p).unwrap();
        let mut store = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        store.update(|l| l.insert_open(INV, 600)).unwrap();
        let g = store.update(|l| l.reserve(claim(INV), 100, pool(), Some(&[]))).unwrap();
        let orig = fs::read(p.join(LEDGER_NAME)).unwrap();
        let result = store.update(|l| {
            l.invitations.get_mut(INV).unwrap().state =
                InviteState::Consumed(Grant {
                    claims: Claims { public_key: format!("{}=", "B".repeat(43)), ..g.claims.clone() },
                    address: Ipv4Addr::new(1, 1, 1, 1),
                });
            Ok(())
        });
        assert!(matches!(result, Err(StoreError::Invalid(_))));
        assert_eq!(fs::read(p.join(LEDGER_NAME)).unwrap(), orig);
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn live_mutex_held_across_disk_update_until_store_is_dropped() {
        let p = dir("mutex");
        bootstrap_for_test(&p).unwrap();
        let mut owner = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        owner.update(|l| l.insert_open(INV, 600)).unwrap();
        assert!(matches!(LedgerStore::open_existing(&p, Duration::from_millis(40)),
            Err(StoreError::Io(ref err)) if err.kind() == io::ErrorKind::TimedOut));
        drop(owner);
        LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        fs::remove_dir_all(p).unwrap();
    }

    fn exact_digest(bytes: &[u8]) -> [u8; 32] {
        ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().try_into().unwrap()
    }

    #[test]
    fn l1_exact_original_bytes_generation_and_exclusive_lock() {
        let p = dir("l1-exact");
        bootstrap_for_test(&p).unwrap();
        let path = p.join(LEDGER_NAME);
        let mut writer = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        writer.update(|l| l.insert_open(INV, 600)).unwrap();
        let generation = writer.generation().unwrap();
        drop(writer);
        let canonical = fs::read(&path).unwrap();
        let mut raw = canonical.clone();
        raw.extend_from_slice(b" \n\t");
        fs::write(&path, &raw).unwrap();
        let exact = exact_digest(&raw);
        let evidence = ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).unwrap();
        let ledger = evidence.compare(generation, &exact).unwrap();
        assert!(matches!(ledger.state(INV), Some(InviteState::Open)));
        assert!(evidence.compare(generation, &exact_digest(&canonical)).is_err());
        assert!(evidence.compare(generation + 1, &exact).is_err());
        assert!(matches!(LedgerStore::open_existing(&p, Duration::from_millis(40)),
            Err(StoreError::Io(ref err)) if err.kind() == io::ErrorKind::TimedOut));
        assert!(ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).is_err());
        assert_eq!(fs::read(&path).unwrap(), raw);
        drop(evidence);
        let mut writer = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        writer.update(|l| l.cancel_open(INV)).unwrap();
        let next_generation = writer.generation().unwrap();
        drop(writer);
        let next = fs::read(&path).unwrap();
        let evidence = ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).unwrap();
        assert!(evidence.compare(generation, &exact).is_err());
        assert!(evidence.compare(next_generation, &exact).is_err());
        assert!(matches!(evidence.compare(next_generation, &exact_digest(&next))
            .unwrap().state(INV), Some(InviteState::Cancelled)));
        drop(evidence);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn l1_same_generation_other_valid_ledger_and_unsafe_bytes_are_rejected() {
        let p = dir("l1-foreign");
        let q = dir("l1-other");
        for (root, id) in [(&p, INV), (&q, INV2)] {
            bootstrap_for_test(root).unwrap();
            let mut writer = LedgerStore::open_existing(root, Duration::ZERO).unwrap();
            writer.update(|l| l.insert_open(id, 600)).unwrap();
        }
        let path = p.join(LEDGER_NAME);
        let raw = fs::read(&path).unwrap();
        let other = fs::read(q.join(LEDGER_NAME)).unwrap();
        let expected = exact_digest(&raw);
        let e = ReadOnlyLedgerEvidence::open(&q, Duration::ZERO).unwrap();
        assert!(e.compare(2, &expected).is_err());
        assert!(e.compare(2, &exact_digest(&other)).unwrap().state(INV2).is_some());
        drop(e);
        // Same generation and valid schema, different parsed ledger.
        fs::write(&path, &other).unwrap();
        let e = ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).unwrap();
        assert!(e.compare(2, &expected).is_err());
        drop(e);
        fs::write(&path, b"{malformed").unwrap();
        assert!(ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).is_err());
        fs::write(&path, &raw).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let moved = p.join("copy");
        fs::rename(&path, &moved).unwrap();
        assert!(matches!(ReadOnlyLedgerEvidence::open(&p, Duration::ZERO), Err(StoreError::Missing)));
        symlink(&moved, &path).unwrap();
        assert!(ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&moved, &path).unwrap();
        assert!(ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).is_err());
        fs::remove_dir_all(p).unwrap();
        fs::remove_dir_all(q).unwrap();
    }

    #[test]
    fn l1_cannot_share_poisoned_writer_or_reuse_its_old_evidence() {
        let p = dir("l1-poison");
        bootstrap_for_test(&p).unwrap();
        let mut writer = LedgerStore::open_existing(&p, Duration::ZERO).unwrap();
        writer.update(|l| l.insert_open(INV, 600)).unwrap();
        let old_generation = writer.generation().unwrap();
        let old = exact_digest(&fs::read(p.join(LEDGER_NAME)).unwrap());
        FAIL_AFTER_RENAME.with(|cell| cell.set(true));
        let failed = writer.update(|l| l.cancel_open(INV));
        FAIL_AFTER_RENAME.with(|cell| cell.set(false));
        assert!(failed.is_err());
        assert!(matches!(writer.view(), Err(StoreError::Poisoned)));
        assert!(ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).is_err());
        drop(writer);
        let e = ReadOnlyLedgerEvidence::open(&p, Duration::ZERO).unwrap();
        assert!(e.compare(old_generation, &old).is_err());
        let new = exact_digest(&fs::read(p.join(LEDGER_NAME)).unwrap());
        assert!(matches!(e.compare(old_generation + 1, &new).unwrap().state(INV),
            Some(InviteState::Cancelled)));
        drop(e);
        fs::remove_dir_all(p).unwrap();
    }
}

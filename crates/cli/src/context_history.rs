//! Private, owner-qualified compaction archives and request accounting.
//!
//! Callers hold the session lease, or a validated AgentRun lease belonging to
//! the supplied root owner and stable child, for the entire provider operation.
//! This store takes only its short owner lock; it never takes another session,
//! agent, configuration or authentication lock and never performs provider I/O.

use crate::customization::{Directory, Error, Lock, publish, read_regular};
use orbit_adapter::types::{ChatMessage, ChatRole, ProviderUsage};
use orbit_engine::compaction::{
    AccountingBaseline, AccountingCheckpoint, AccountingDelta, AccountingKnownness,
    AccountingRevision, AccountingTotals, AttemptIntent, AttemptPurpose, AttemptRef,
    CompactionCandidate, CompactionCoverage, CompactionJournal, CompactionReceipt,
    CompactionRecordRef, HistoryError, KnownPricedSubtotals, MAX_ACCOUNTING_CHECKPOINT_BYTES,
    MAX_COMPACTION_SOURCE_BYTES, MAX_SUMMARY_CHUNKS, PendingAttempt, RequestAccountingReceipt,
    SettledAttempt,
};
use orbit_engine::context_budget::BudgetIdentity;
use orbit_engine::retry::{
    DetailedAccountingCheckpoint, DetailedLastSettlement, OrdinaryAttemptBinding,
    OrdinaryAttemptBindingRecord, RefusedOrdinarySettlement, RefusedSettlementAck,
};

mod refusal;
use refusal::{Binding as RetryBinding, Record as RefusalRecord, Rollup as RefusalRollup};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ACCOUNTING: &str = "accounting.json";
const LOCK: &str = ".history.lock";
const MAX_RECORDS: usize = 64;
const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const SUMMARY_MARKER: &str = "[Earlier conversation summary: historical data]";

/// Bind storage to an already leased root session or validated stable child.
/// A fresh baseline is never inferred by opening an empty or legacy store.
pub fn context_journal(
    home: &Path,
    owner_session_id: &str,
    child_id: Option<&str>,
) -> Result<Arc<dyn CompactionJournal>, HistoryError> {
    Ok(Arc::new(Journal::open(home, owner_session_id, child_id)?))
}

/// The inspected canonical bytes were visible and validated during this read.
/// This does not establish a prior fsync or a remote provider's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionQualification {
    VisibleValidated,
}

/// Inert metadata for one exact namespace. Observed uncertain usage remains
/// separate from known totals; this value grants no admission or settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingInspection {
    pub checkpoint: AccountingCheckpoint,
    pub pending_receipt: Option<RequestAccountingReceipt>,
    pub last_receipt: Option<RequestAccountingReceipt>,
    /// Opaque SHA-256 over the exact canonical container and selected scope.
    pub inspection_digest: String,
    pub qualification: InspectionQualification,
}

/// Inspect existing accounting without creating storage, taking a session/agent
/// lease, syncing files or reading archives, snapshots, configuration or auth.
/// Missing is positive absence, Busy is the existing short history writer lock,
/// and Uncertain denotes an observed staging entry. Success proves only visible
/// validated metadata, never prior publication durability or request outcome.
pub fn inspect_accounting(
    home: &Path,
    owner_session_id: &str,
    child_id: Option<&str>,
) -> Result<AccountingInspection, HistoryError> {
    inspect_accounting_with(home, owner_session_id, child_id, inspection_from_container)
}

/// Visible checked metadata, including independently qualified final refusals.
/// Snapshot validation does not establish a durable acknowledgement or replay authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedAccountingInspection {
    pub checkpoint: DetailedAccountingCheckpoint,
    pub pending_receipt: Option<RequestAccountingReceipt>,
    pub last_legacy_receipt: Option<RequestAccountingReceipt>,
    pub inspection_digest: String,
    pub qualification: InspectionQualification,
}

/// Inert companion to inspect_accounting for qualified refusal metadata.
pub fn inspect_accounting_detailed(
    home: &Path,
    owner_session_id: &str,
    child_id: Option<&str>,
) -> Result<DetailedAccountingInspection, HistoryError> {
    inspect_accounting_with(
        home,
        owner_session_id,
        child_id,
        inspection_detailed_from_container,
    )
}

fn inspect_accounting_with<T>(
    home: &Path,
    owner_session_id: &str,
    child_id: Option<&str>,
    project: fn(&Container, &str, Option<&str>) -> Result<T, HistoryError>,
) -> Result<T, HistoryError> {
    scope(owner_session_id, child_id)?;
    inspection_home_presence(home)?;
    let layout = recovery_layout(home, owner_session_id)?;
    let lock_path = layout.owner.io().map_err(storage_error)?.join(LOCK);
    match std::fs::symlink_metadata(&lock_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            inspect_owner_metadata(&layout.owner)?;
            let accounting = layout.owner.io().map_err(storage_error)?.join(ACCOUNTING);
            let missing = matches!(std::fs::symlink_metadata(accounting),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound);
            layout.check()?;
            return Err(if missing {
                HistoryError::Missing
            } else {
                HistoryError::Unsafe
            });
        }
        Err(_) => return Err(HistoryError::Unsafe),
    }
    let lock = Lock::read_existing(&layout.owner, LOCK).map_err(storage_error)?;
    inspect_owner_metadata(&layout.owner)?;
    let finish = || {
        inspect_owner_metadata(&layout.owner)?;
        lock.check_existing(&layout.owner, LOCK)
            .map_err(storage_error)?;
        layout.check()
    };
    let Some(container) = load_container(&layout.owner, owner_session_id)? else {
        finish()?;
        return Err(HistoryError::Missing);
    };
    let inspection = match project(&container, owner_session_id, child_id) {
        Ok(inspection) => inspection,
        Err(HistoryError::Missing) => {
            finish()?;
            return Err(HistoryError::Missing);
        }
        Err(error) => return Err(error),
    };
    finish()?;
    Ok(inspection)
}

// Pure projection shared with root recovery capture. Disk reads stay with each
// caller, and the inspection domain/length prefixes remain exactly unchanged.
fn inspection_from_container(
    container: &Container,
    owner_session_id: &str,
    child_id: Option<&str>,
) -> Result<AccountingInspection, HistoryError> {
    let detailed = inspection_detailed_from_container(container, owner_session_id, child_id)?;
    let entry = selected_entry(container, child_id)?;
    if entry.has_retry_metadata() {
        return Err(HistoryError::InvalidRecord);
    }
    Ok(AccountingInspection {
        checkpoint: detailed.checkpoint.to_legacy()?,
        pending_receipt: detailed.pending_receipt,
        last_receipt: detailed.last_legacy_receipt,
        inspection_digest: detailed.inspection_digest,
        qualification: detailed.qualification,
    })
}

fn selected_entry<'a>(
    container: &'a Container,
    child: Option<&str>,
) -> Result<&'a Entry, HistoryError> {
    container
        .entries
        .iter()
        .find(|entry| entry.namespace.child() == child)
        .ok_or(HistoryError::Missing)
}

fn inspection_detailed_from_container(
    container: &Container,
    owner_session_id: &str,
    child_id: Option<&str>,
) -> Result<DetailedAccountingInspection, HistoryError> {
    let entry = selected_entry(container, child_id)?;
    let checkpoint = entry.checkpoint_detailed(owner_session_id)?;
    let canonical = encode(
        container,
        MAX_ACCOUNTING_CHECKPOINT_BYTES,
        HistoryError::Full,
    )?;
    let mut digest = Sha256::new();
    digest.update(b"orbit-accounting-inspection-private-codec-v1\0");
    for field in [
        owner_session_id.as_bytes(),
        child_id.unwrap_or("").as_bytes(),
        canonical.as_slice(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Ok(DetailedAccountingInspection {
        checkpoint,
        pending_receipt: entry
            .pending
            .as_ref()
            .and_then(|pending| pending.uncertain_receipt.as_ref())
            .map(Receipt::to_public),
        last_legacy_receipt: entry
            .last
            .as_ref()
            .and_then(|last| last.receipt.as_ref())
            .map(Receipt::to_public),
        inspection_digest: hex::encode(digest.finalize()),
        qualification: InspectionQualification::VisibleValidated,
    })
}

/// Exact root evidence; all payloads remain inert and bound to the held lease.
#[cfg(test)]
pub(crate) struct RecoveryHistoryCapture<'lease> {
    captured: CapturedHistory<'lease>,
    inspection: AccountingInspection,
}

pub(crate) struct DetailedRecoveryHistoryCapture<'lease> {
    captured: CapturedHistory<'lease>,
    inspection: DetailedAccountingInspection,
}

struct CapturedHistory<'lease> {
    lease: &'lease crate::sessions::SessionLease,
    layout: Layout,
    lock_stamp: RecoveryFileStamp,
    accounting: RecoveryHistoryFile,
    archives: Vec<RecoveryArchiveCapture>,
}

pub(crate) struct RecoveryArchiveCapture {
    record_id: String,
    source_digest: String,
    candidate_digest: String,
    file: RecoveryHistoryFile,
}

impl RecoveryArchiveCapture {
    pub(crate) fn record_id(&self) -> &str {
        &self.record_id
    }
    pub(crate) fn source_digest(&self) -> &str {
        &self.source_digest
    }
    pub(crate) fn candidate_digest(&self) -> &str {
        &self.candidate_digest
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.file.bytes
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.file.sha256
    }
}

#[cfg(test)]
impl RecoveryHistoryCapture<'_> {
    pub(crate) fn inspection(&self) -> &AccountingInspection {
        &self.inspection
    }
    pub(crate) fn accounting_bytes(&self) -> &[u8] {
        &self.captured.accounting.bytes
    }
    pub(crate) fn accounting_sha256(&self) -> &str {
        &self.captured.accounting.sha256
    }
    pub(crate) fn archives(&self) -> &[RecoveryArchiveCapture] {
        &self.captured.archives
    }
    pub(crate) fn verify_unchanged(
        &self,
        lease: &crate::sessions::SessionLease,
    ) -> Result<(), HistoryError> {
        self.captured
            .verify_unchanged(lease, &self.inspection, inspection_from_container)
    }
}

/// Capture root metadata using the exact held lease and selected inspection.
#[cfg(test)]
pub(crate) fn capture_for_recovery<'lease>(
    lease: &'lease crate::sessions::SessionLease,
    expected_revision: AccountingRevision,
    expected_inspection: &str,
) -> Result<RecoveryHistoryCapture<'lease>, HistoryError> {
    let (captured, inspection) = capture_history(
        lease,
        expected_revision,
        expected_inspection,
        inspection_from_container,
        |inspection| inspection.checkpoint.revision,
        |inspection| inspection.inspection_digest.as_str(),
    )?;
    Ok(RecoveryHistoryCapture {
        captured,
        inspection,
    })
}

impl DetailedRecoveryHistoryCapture<'_> {
    pub(crate) fn inspection(&self) -> &DetailedAccountingInspection {
        &self.inspection
    }
    pub(crate) fn accounting_bytes(&self) -> &[u8] {
        &self.captured.accounting.bytes
    }
    pub(crate) fn accounting_sha256(&self) -> &str {
        &self.captured.accounting.sha256
    }
    pub(crate) fn archives(&self) -> &[RecoveryArchiveCapture] {
        &self.captured.archives
    }
    pub(crate) fn verify_unchanged(
        &self,
        lease: &crate::sessions::SessionLease,
    ) -> Result<(), HistoryError> {
        self.captured
            .verify_unchanged(lease, &self.inspection, inspection_detailed_from_container)
    }
}

/// Capture root metadata using the exact held lease and selected inspection.
pub(crate) fn capture_for_recovery_detailed<'lease>(
    lease: &'lease crate::sessions::SessionLease,
    expected_revision: AccountingRevision,
    expected_inspection: &str,
) -> Result<DetailedRecoveryHistoryCapture<'lease>, HistoryError> {
    let (captured, inspection) = capture_history(
        lease,
        expected_revision,
        expected_inspection,
        inspection_detailed_from_container,
        |inspection| inspection.checkpoint.revision(),
        |inspection| inspection.inspection_digest.as_str(),
    )?;
    Ok(DetailedRecoveryHistoryCapture {
        captured,
        inspection,
    })
}

impl CapturedHistory<'_> {
    fn verify_unchanged<T: PartialEq>(
        &self,
        lease: &crate::sessions::SessionLease,
        expected: &T,
        project: fn(&Container, &str, Option<&str>) -> Result<T, HistoryError>,
    ) -> Result<(), HistoryError> {
        if !std::ptr::eq(self.lease, lease) {
            return Err(HistoryError::Unsafe);
        }
        lease
            .verify_for_recovery()
            .map_err(|_| HistoryError::Unsafe)?;
        self.layout.check()?;
        let lock = Lock::read_existing(&self.layout.owner, LOCK).map_err(storage_error)?;
        if recovery_lock_stamp(&self.layout)? != self.lock_stamp {
            return Err(HistoryError::Conflict);
        }
        inspect_owner_metadata(&self.layout.owner)?;
        let current = recovery_history_file(
            &self
                .layout
                .owner
                .io()
                .map_err(storage_error)?
                .join(ACCOUNTING),
            MAX_ACCOUNTING_CHECKPOINT_BYTES,
        )?;
        if !self.accounting.same_capture(&current)? {
            return Err(HistoryError::Conflict);
        }
        let container = decode_container(&current.bytes, lease.session_id())?;
        let inspection = project(&container, lease.session_id(), None)?;
        if inspection != *expected {
            return Err(HistoryError::Conflict);
        }
        scan_recovery_archives(&self.layout, lease.session_id(), Some(&self.archives))?;
        finish_history_capture(&self.layout, &lock, &self.lock_stamp)?;
        self.accounting.check_path(
            &self
                .layout
                .owner
                .io()
                .map_err(storage_error)?
                .join(ACCOUNTING),
        )?;
        for archive in &self.archives {
            archive.file.check_path(
                &self
                    .layout
                    .archives
                    .io()
                    .map_err(storage_error)?
                    .join(record_name(&archive.record_id)),
            )?;
        }
        lease
            .verify_for_recovery()
            .map_err(|_| HistoryError::Unsafe)
    }
}

fn capture_history<'lease, T>(
    lease: &'lease crate::sessions::SessionLease,
    expected_revision: AccountingRevision,
    expected_inspection: &str,
    project: fn(&Container, &str, Option<&str>) -> Result<T, HistoryError>,
    revision: fn(&T) -> AccountingRevision,
    digest: fn(&T) -> &str,
) -> Result<(CapturedHistory<'lease>, T), HistoryError> {
    scope(lease.session_id(), None)?;
    if !digest_ok(expected_inspection) {
        return Err(HistoryError::InvalidRecord);
    }
    lease
        .verify_for_recovery()
        .map_err(|_| HistoryError::Unsafe)?;
    let layout = recovery_layout(lease.home(), lease.session_id())?;
    let lock = Lock::read_existing(&layout.owner, LOCK).map_err(storage_error)?;
    let lock_stamp = recovery_lock_stamp(&layout)?;
    inspect_owner_metadata(&layout.owner)?;
    let accounting = recovery_history_file(
        &layout.owner.io().map_err(storage_error)?.join(ACCOUNTING),
        MAX_ACCOUNTING_CHECKPOINT_BYTES,
    )?;
    let container = decode_container(&accounting.bytes, lease.session_id())?;
    let inspection = project(&container, lease.session_id(), None)?;
    if revision(&inspection) != expected_revision || digest(&inspection) != expected_inspection {
        return Err(HistoryError::Conflict);
    }
    let archives = scan_recovery_archives(&layout, lease.session_id(), None)?;
    finish_history_capture(&layout, &lock, &lock_stamp)?;
    accounting.check_path(&layout.owner.io().map_err(storage_error)?.join(ACCOUNTING))?;
    for archive in &archives {
        archive.file.check_path(
            &layout
                .archives
                .io()
                .map_err(storage_error)?
                .join(record_name(&archive.record_id)),
        )?;
    }
    lease
        .verify_for_recovery()
        .map_err(|_| HistoryError::Unsafe)?;
    drop(lock);
    Ok((
        CapturedHistory {
            lease,
            layout,
            lock_stamp,
            accounting,
            archives,
        },
        inspection,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveryFileStamp {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl RecoveryFileStamp {
    fn of(value: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: value.dev(),
            inode: value.ino(),
            mode: value.mode(),
            uid: value.uid(),
            gid: value.gid(),
            links: value.nlink(),
            bytes: value.len(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
    fn private(value: &std::fs::Metadata, maximum: usize) -> Result<Self, HistoryError> {
        use std::os::unix::fs::MetadataExt;
        if !value.is_file()
            || value.nlink() != 1
            || value.uid() != rustix::process::geteuid().as_raw()
            || value.mode() & 0o077 != 0
        {
            return Err(HistoryError::Unsafe);
        }
        if value.len() > maximum as u64 {
            return Err(HistoryError::TooLarge);
        }
        Ok(Self::of(value))
    }
}

struct RecoveryHistoryFile {
    file: std::fs::File,
    stamp: RecoveryFileStamp,
    bytes: Vec<u8>,
    sha256: String,
}
impl RecoveryHistoryFile {
    fn check_path(&self, path: &Path) -> Result<(), HistoryError> {
        let held = self.file.metadata().map_err(|_| HistoryError::Unsafe)?;
        let current = std::fs::symlink_metadata(path).map_err(|_| HistoryError::Conflict)?;
        if RecoveryFileStamp::of(&held) != self.stamp
            || RecoveryFileStamp::of(&current) != self.stamp
        {
            return Err(HistoryError::Conflict);
        }
        Ok(())
    }
    fn same_capture(&self, current: &Self) -> Result<bool, HistoryError> {
        let held = self.file.metadata().map_err(|_| HistoryError::Unsafe)?;
        Ok(RecoveryFileStamp::of(&held) == self.stamp
            && self.stamp == current.stamp
            && self.sha256 == current.sha256
            && self.bytes == current.bytes)
    }
}

fn recovery_history_file(path: &Path, maximum: usize) -> Result<RecoveryHistoryFile, HistoryError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let before = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(HistoryError::Missing);
        }
        Err(_) => return Err(HistoryError::Unsafe),
    };
    let stamp = RecoveryFileStamp::private(&before, maximum)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| HistoryError::Unsafe)?;
    if RecoveryFileStamp::private(&file.metadata().map_err(|_| HistoryError::Unsafe)?, maximum)?
        != stamp
    {
        return Err(HistoryError::Conflict);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HistoryError::Unsafe)?;
    if bytes.len() > maximum {
        return Err(HistoryError::TooLarge);
    }
    if bytes.len() as u64 != stamp.bytes {
        return Err(HistoryError::Conflict);
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let result = RecoveryHistoryFile {
        file,
        stamp,
        bytes,
        sha256,
    };
    result.check_path(path)?;
    Ok(result)
}

fn recovery_lock_stamp(layout: &Layout) -> Result<RecoveryFileStamp, HistoryError> {
    let path = layout.owner.io().map_err(storage_error)?.join(LOCK);
    RecoveryFileStamp::private(
        &std::fs::symlink_metadata(path).map_err(|_| HistoryError::Unsafe)?,
        MAX_ACCOUNTING_CHECKPOINT_BYTES,
    )
}

fn finish_history_capture(
    layout: &Layout,
    lock: &Lock,
    stamp: &RecoveryFileStamp,
) -> Result<(), HistoryError> {
    inspect_owner_metadata(&layout.owner)?;
    lock.check_existing(&layout.owner, LOCK)
        .map_err(storage_error)?;
    if recovery_lock_stamp(layout)? != *stamp {
        return Err(HistoryError::Conflict);
    }
    layout.check()
}

// One bounded owner-wide pass per capture/verification. Filename cannot select
// scope: every private canonical archive is validated before filtering root.
fn scan_recovery_archives(
    layout: &Layout,
    owner: &str,
    expected: Option<&[RecoveryArchiveCapture]>,
) -> Result<Vec<RecoveryArchiveCapture>, HistoryError> {
    layout.archives.check().map_err(storage_error)?;
    let before = RecoveryFileStamp::of(
        &std::fs::symlink_metadata(layout.archives.path()).map_err(|_| HistoryError::Unsafe)?,
    );
    let directory = layout.archives.io().map_err(storage_error)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&directory).map_err(|_| HistoryError::Unsafe)? {
        let entry = entry.map_err(|_| HistoryError::Unsafe)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HistoryError::Unsafe)?;
        if name.starts_with(".stage-") {
            return Err(HistoryError::Uncertain);
        }
        if names.len() >= MAX_RECORDS {
            return Err(HistoryError::Full);
        }
        let record_id = name.strip_suffix(".json").ok_or(HistoryError::Unsafe)?;
        valid_record_id(record_id).map_err(|_| HistoryError::Unsafe)?;
        names.push(name);
    }
    names.sort();
    let mut total = 0u64;
    let mut selected = 0usize;
    let mut result = Vec::new();
    for name in names {
        let file = recovery_history_file(&directory.join(&name), MAX_COMPACTION_SOURCE_BYTES)?;
        total = total
            .checked_add(file.bytes.len() as u64)
            .ok_or(HistoryError::TooLarge)?;
        if total > MAX_ARCHIVE_BYTES {
            return Err(HistoryError::Full);
        }
        let archive = decode_archive(&file.bytes, owner)?;
        if record_name(&archive.operation_id) != name {
            return Err(HistoryError::InvalidRecord);
        }
        if archive.child.is_none() {
            if let Some(expected) = expected {
                let old = expected.get(selected).ok_or(HistoryError::Conflict)?;
                if old.record_id != archive.operation_id || !old.file.same_capture(&file)? {
                    return Err(HistoryError::Conflict);
                }
            } else {
                result.push(RecoveryArchiveCapture {
                    record_id: archive.operation_id,
                    source_digest: archive.source_digest,
                    candidate_digest: archive.candidate_digest,
                    file,
                });
            }
            selected += 1;
        }
    }
    if expected.is_some_and(|expected| expected.len() != selected) {
        return Err(HistoryError::Conflict);
    }
    layout.archives.check().map_err(storage_error)?;
    if RecoveryFileStamp::of(
        &std::fs::symlink_metadata(layout.archives.path()).map_err(|_| HistoryError::Unsafe)?,
    ) != before
    {
        return Err(HistoryError::Conflict);
    }
    Ok(result)
}

// Check each existing component before treating a missing home/ancestor as
// absent. A dangling intermediate symlink must never turn into Missing.
fn inspection_home_presence(home: &Path) -> Result<(), HistoryError> {
    use std::path::Component;
    let absolute = if home.is_absolute() {
        home.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| HistoryError::Unsafe)?
            .join(home)
    };
    let mut parent = Directory::open(Path::new("/"), false).map_err(storage_error)?;
    for component in absolute.components() {
        let Component::Normal(part) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(HistoryError::Unsafe);
        };
        let path = parent.io().map_err(storage_error)?.join(part);
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(HistoryError::Unsafe),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                parent.check().map_err(storage_error)?;
                Directory::open(parent.path(), false).map_err(storage_error)?;
                parent.check().map_err(storage_error)?;
                return Err(HistoryError::Missing);
            }
            Err(_) => return Err(HistoryError::Unsafe),
        }
        let next = Directory::open(&parent.path().join(part), false).map_err(storage_error)?;
        parent.check().map_err(storage_error)?;
        parent = next;
    }
    parent.check().map_err(storage_error)
}

// Reader-only counterpart of inspect_owner: same bounded entry set and stage
// refusal, but no body read. load_container alone reads at most 128 KiB once.
fn inspect_owner_metadata(dir: &Directory) -> Result<(), HistoryError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut count = 0;
    for item in
        std::fs::read_dir(dir.io().map_err(storage_error)?).map_err(|_| HistoryError::Unsafe)?
    {
        count += 1;
        if count > 4 {
            return Err(HistoryError::Unsafe);
        }
        let item = item.map_err(|_| HistoryError::Unsafe)?;
        let name = item.file_name();
        let name = name.to_str().ok_or(HistoryError::Unsafe)?;
        if name.starts_with(".stage-") {
            return Err(HistoryError::Uncertain);
        }
        match name {
            ACCOUNTING | LOCK => {
                let metadata =
                    std::fs::symlink_metadata(item.path()).map_err(|_| HistoryError::Unsafe)?;
                if !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(HistoryError::Unsafe);
                }
                if metadata.len() > MAX_ACCOUNTING_CHECKPOINT_BYTES as u64 {
                    return Err(HistoryError::TooLarge);
                }
            }
            "archives" => {
                Directory::open(&dir.path().join(name), true).map_err(storage_error)?;
            }
            _ => return Err(HistoryError::Unsafe),
        }
    }
    dir.check().map_err(storage_error)
}

/// Read inert recovery data. This does not restore grants, replace a session,
/// replay provider work, or execute any archived tool call.
pub fn load_compaction_source(
    home: &Path,
    owner_session_id: &str,
    child_id: Option<&str>,
    record_id: &str,
) -> Result<Vec<ChatMessage>, HistoryError> {
    scope(owner_session_id, child_id)?;
    valid_record_id(record_id)?;
    let layout = recovery_layout(home, owner_session_id)?;
    let path = layout
        .archives
        .io()
        .map_err(storage_error)?
        .join(record_name(record_id));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            inspect_owner(&layout.owner)?;
            scan_archives(&layout.archives, owner_session_id)?;
            layout.check()?;
            return Err(HistoryError::Missing);
        }
        Err(_) => return Err(HistoryError::Unsafe),
    }
    let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
    inspect_owner(&layout.owner)?;
    scan_archives(&layout.archives, owner_session_id)?;
    let bytes = optional_file(&path, MAX_COMPACTION_SOURCE_BYTES)?.ok_or(HistoryError::Missing)?;
    let record = decode_archive(&bytes, owner_session_id)?;
    if record.child.as_deref() != child_id || record.operation_id != record_id {
        return Err(HistoryError::InvalidRecord);
    }
    layout.check()?;
    Ok(record.source)
}

struct Journal {
    home: PathBuf,
    owner: String,
    child: Option<String>,
    identity: Layout,
}
impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContextHistoryJournal")
    }
}
struct Layout {
    home: Directory,
    root: Directory,
    owner: Directory,
    archives: Directory,
}
impl Layout {
    fn check(&self) -> Result<(), HistoryError> {
        for dir in [&self.home, &self.root, &self.owner, &self.archives] {
            dir.check().map_err(storage_error)?;
            Directory::open(dir.path(), true).map_err(storage_error)?;
        }
        Ok(())
    }
}
impl Journal {
    fn open(home: &Path, owner: &str, child: Option<&str>) -> Result<Self, HistoryError> {
        scope(owner, child)?;
        let layout = storage_layout(home, owner, true)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        layout.check()?;
        inspect_owner(&layout.owner)?;
        scan_archives(&layout.archives, owner)?;
        load_container(&layout.owner, owner)?;
        Ok(Self {
            home: layout.home.path().to_path_buf(),
            owner: owner.to_owned(),
            child: child.map(str::to_owned),
            identity: layout,
        })
    }

    fn layout(&self, create: bool) -> Result<Layout, HistoryError> {
        // These descriptors belong to the lifetime of this journal, rather
        // than to the replacement currently occupying a checked path.
        self.identity.check()?;
        let layout = storage_layout(&self.home, &self.owner, create)?;
        self.identity.check()?;
        Ok(layout)
    }
    fn namespace(&self) -> Namespace {
        match &self.child {
            Some(id) => Namespace::Child { id: id.clone() },
            None => Namespace::Owner,
        }
    }
    fn validate_scope(&self, owner: &str, child: Option<&str>) -> Result<(), HistoryError> {
        scope(owner, child)?;
        if owner != self.owner || child != self.child.as_deref() {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(())
    }
    fn container(&self, layout: &Layout) -> Result<Container, HistoryError> {
        inspect_owner(&layout.owner)?;
        // Reconcile a visible replacement with the held directory before
        // allowing another mutation. This never replays or reapplies a bill.
        layout.owner.sync().map_err(|_| HistoryError::Uncertain)?;
        Ok(
            load_container(&layout.owner, &self.owner)?.unwrap_or(Container {
                version: 1,
                owner: self.owner.clone(),
                entries: Vec::new(),
            }),
        )
    }
    fn save(&self, layout: &Layout, container: &Container) -> Result<(), HistoryError> {
        validate_container(container, &self.owner)?;
        reservation_size(container, MAX_ACCOUNTING_CHECKPOINT_BYTES)?;
        let bytes = encode(
            container,
            MAX_ACCOUNTING_CHECKPOINT_BYTES,
            HistoryError::Full,
        )?;
        layout.check()?;
        publish(&layout.owner, ACCOUNTING, &bytes, false).map_err(storage_error)?;
        layout.check().map_err(|_| HistoryError::Uncertain)
    }
}

fn storage_layout(home: &Path, owner: &str, create: bool) -> Result<Layout, HistoryError> {
    let home = Directory::open(home, true).map_err(storage_error)?;
    let root = home
        .child("context-history", create)
        .map_err(storage_error)?;
    let owner = root.child(owner, create).map_err(storage_error)?;
    let archives = owner.child("archives", create).map_err(storage_error)?;
    let layout = Layout {
        home,
        root,
        owner,
        archives,
    };
    layout.check()?;
    Ok(layout)
}

fn recovery_layout(home: &Path, owner: &str) -> Result<Layout, HistoryError> {
    let home = Directory::open(home, true).map_err(storage_error)?;
    let root = recovery_child(&home, "context-history")?;
    let owner = recovery_child(&root, owner)?;
    let archives = recovery_child(&owner, "archives")?;
    let layout = Layout {
        home,
        root,
        owner,
        archives,
    };
    layout.check()?;
    Ok(layout)
}

fn recovery_child(parent: &Directory, name: &str) -> Result<Directory, HistoryError> {
    let path = parent.io().map_err(storage_error)?.join(name);
    match std::fs::symlink_metadata(path) {
        Ok(_) => parent.child(name, false).map_err(storage_error),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Only a positively absent entry below the still-checked private
            // parent is Missing. A dangling link is present to lstat and goes
            // through the normal no-follow checks instead.
            parent.check().map_err(storage_error)?;
            Directory::open(parent.path(), true).map_err(storage_error)?;
            parent.check().map_err(storage_error)?;
            Err(HistoryError::Missing)
        }
        Err(_) => Err(HistoryError::Unsafe),
    }
}

impl CompactionJournal for Journal {
    fn initialize_accounting(
        &self,
        baseline: AccountingBaseline,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        self.initialize_operation(baseline)?.to_legacy()
    }
    fn initialize_accounting_detailed(
        &self,
        baseline: AccountingBaseline,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        self.initialize_operation(baseline)
    }
    fn accounting_checkpoint(&self) -> Result<AccountingCheckpoint, HistoryError> {
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        let container = self.container(&layout)?;
        let entry = container
            .entries
            .iter()
            .find(|e| e.namespace == self.namespace())
            .ok_or(HistoryError::Missing)?;
        layout.check()?;
        entry.checkpoint(&self.owner)
    }

    fn accounting_checkpoint_detailed(&self) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        let container = self.container(&layout)?;
        let entry = selected_entry(&container, self.child.as_deref())?;
        let checkpoint = entry.checkpoint_detailed(&self.owner)?;
        layout.check()?;
        Ok(checkpoint)
    }

    fn begin_attempt(
        &self,
        expected_revision: AccountingRevision,
        intent: &AttemptIntent,
    ) -> Result<AttemptRef, HistoryError> {
        self.begin_operation(expected_revision, intent, None, true)
    }
    fn begin_attempt_detailed(
        &self,
        expected_revision: AccountingRevision,
        intent: &AttemptIntent,
        binding: Option<&OrdinaryAttemptBinding>,
    ) -> Result<AttemptRef, HistoryError> {
        let record = binding.map(OrdinaryAttemptBinding::to_record);
        self.begin_operation(expected_revision, intent, record.as_ref(), false)
    }
    fn settle_attempt(
        &self,
        attempt: &AttemptRef,
        receipt: &RequestAccountingReceipt,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        self.settle_receipt_operation(attempt, receipt, true)?
            .to_legacy()
    }
    fn settle_attempt_detailed(
        &self,
        attempt: &AttemptRef,
        receipt: &RequestAccountingReceipt,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        self.settle_receipt_operation(attempt, receipt, false)
    }
    fn settle_refused_ordinary(
        &self,
        attempt: &AttemptRef,
        settlement: &RefusedOrdinarySettlement,
    ) -> Result<RefusedSettlementAck, HistoryError> {
        self.settle_refusal_record(attempt, &settlement.to_record())
    }

    fn check_archive_capacity(&self, minimum_record_bytes: u64) -> Result<(), HistoryError> {
        if minimum_record_bytes > MAX_COMPACTION_SOURCE_BYTES as u64 {
            return Err(HistoryError::TooLarge);
        }
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        inspect_owner(&layout.owner)?;
        let (count, used) = scan_archives(&layout.archives, &self.owner)?;
        if count >= MAX_RECORDS
            || used
                .checked_add(minimum_record_bytes)
                .ok_or(HistoryError::TooLarge)?
                > MAX_ARCHIVE_BYTES
        {
            return Err(HistoryError::Full);
        }
        layout.check()
    }

    fn publish(
        &self,
        source: &[ChatMessage],
        candidate: &CompactionCandidate,
        receipt: &CompactionReceipt,
    ) -> Result<CompactionRecordRef, HistoryError> {
        self.validate_scope(&receipt.owner_session_id, receipt.child_id.as_deref())?;
        valid_record_id(&receipt.operation_id)?;
        validate_budget(&receipt.conversation_budget)?;
        validate_budget(&receipt.summary_budget)?;
        if receipt.attempts.is_empty() || receipt.attempts.len() > MAX_SUMMARY_CHUNKS + 1 {
            return Err(HistoryError::InvalidRecord);
        }
        if typed_digest(b"orbit-compaction-source-v1\0", source)? != candidate.source_digest()
            || typed_digest(b"orbit-compaction-candidate-v1\0", candidate.messages())?
                != candidate.candidate_digest()
            || candidate.source_digest() != receipt.source_digest
            || candidate.candidate_digest() != receipt.candidate_digest
        {
            return Err(HistoryError::InvalidRecord);
        }
        let record = Archive::from_public(source, candidate, receipt);
        self.publish_record(&record)
    }
}

impl Journal {
    fn initialize_operation(
        &self,
        baseline: AccountingBaseline,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        let mut container = self.container(&layout)?;
        let namespace = self.namespace();
        if container
            .entries
            .iter()
            .any(|entry| entry.namespace == namespace)
        {
            return Err(HistoryError::Conflict);
        }
        let entry = Entry {
            namespace,
            revision: 0,
            baseline: Baseline::from_public(baseline),
            totals: Delta::from_public(&match baseline {
                AccountingBaseline::FreshKnownZero => AccountingDelta::known_zero(),
                AccountingBaseline::UnknownLegacy => AccountingDelta::unknown_legacy(),
            }),
            pending: None,
            last: None,
            refusals: None,
            known_priced_subtotals: Some(PricedSubtotals::from_public(
                KnownPricedSubtotals::known_zero(),
            )),
        };
        let checkpoint = entry.checkpoint_detailed(&self.owner)?;
        container.entries.push(entry);
        self.save(&layout, &container)?;
        Ok(checkpoint)
    }

    fn begin_operation(
        &self,
        expected_revision: AccountingRevision,
        intent: &AttemptIntent,
        binding: Option<&OrdinaryAttemptBindingRecord>,
        legacy_only: bool,
    ) -> Result<AttemptRef, HistoryError> {
        self.validate_scope(&intent.owner_session_id, intent.child_id.as_deref())?;
        let digest = intent.digest()?;
        if let Some(binding) = binding {
            binding.validate()?;
            if intent.purpose != AttemptPurpose::Ordinary
                || binding.request_id() != intent.request_id
            {
                return Err(HistoryError::InvalidRecord);
            }
        }
        let revision = expected_revision
            .0
            .checked_add(1)
            .ok_or(HistoryError::TooLarge)?;
        revision.checked_add(1).ok_or(HistoryError::TooLarge)?;
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        let mut container = self.container(&layout)?;
        let entry = container
            .entries
            .iter_mut()
            .find(|e| e.namespace == self.namespace())
            .ok_or(HistoryError::Missing)?;
        if legacy_only && entry.has_retry_metadata() {
            return Err(HistoryError::InvalidRecord);
        }
        if entry.revision != expected_revision.0 || entry.pending.is_some() {
            return Err(HistoryError::Conflict);
        }
        if binding.is_some()
            && let Some(rollup) = &entry.refusals
        {
            rollup
                .to_public()?
                .count()
                .checked_add(1)
                .ok_or(HistoryError::TooLarge)?;
        }
        let reference = AttemptRef {
            revision: AccountingRevision(revision),
            request_id: intent.request_id.clone(),
            intent_digest: digest,
        };
        entry.revision = revision;
        entry.pending = Some(Pending {
            reference: Reference::from_public(&reference),
            intent: Intent::from_public(intent),
            uncertain_receipt: None,
            retry_binding: binding.map(RetryBinding::from_public),
        });
        self.save(&layout, &container)?;
        Ok(reference)
    }

    fn settle_receipt_operation(
        &self,
        attempt: &AttemptRef,
        receipt: &RequestAccountingReceipt,
        legacy_only: bool,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        validate_reference(attempt)?;
        receipt.validate()?;
        if attempt.request_id != receipt.request_id {
            return Err(HistoryError::InvalidRecord);
        }
        let digest = receipt.digest()?;
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        let mut container = self.container(&layout)?;
        let entry = container
            .entries
            .iter_mut()
            .find(|e| e.namespace == self.namespace())
            .ok_or(HistoryError::Missing)?;
        if legacy_only && entry.has_retry_metadata() {
            return Err(HistoryError::InvalidRecord);
        }
        if let Some(last) = &entry.last {
            if last.reference.to_public() == *attempt {
                return if last
                    .receipt
                    .as_ref()
                    .ok_or(HistoryError::Conflict)?
                    .to_public()
                    .digest()?
                    == digest
                {
                    layout.check()?;
                    entry.checkpoint_detailed(&self.owner)
                } else {
                    Err(HistoryError::Conflict)
                };
            }
            if attempt.revision.0 < last.reference.revision {
                return Err(HistoryError::StaleNonApplying);
            }
        }
        let pending = entry.pending.as_ref().ok_or(HistoryError::Conflict)?;
        if pending.reference.to_public() != *attempt
            || pending.intent.to_public().digest()? != attempt.intent_digest
            || pending.intent.request_id != receipt.request_id
            || pending.intent.purpose.to_public() != receipt.purpose
        {
            return Err(HistoryError::Conflict);
        }
        if let Some(previous) = &pending.uncertain_receipt {
            return if previous.to_public().digest()? == digest {
                layout.check()?;
                entry.checkpoint_detailed(&self.owner)
            } else {
                Err(HistoryError::Conflict)
            };
        }
        let totals = entry.totals.to_public().checked_with(receipt)?;
        let known_priced_subtotals = entry
            .known_priced_subtotals
            .as_ref()
            .map(|subtotals| subtotals.to_public().checked_with(receipt))
            .transpose()?
            .map(PricedSubtotals::from_public);
        let revision = attempt
            .revision
            .0
            .checked_add(1)
            .ok_or(HistoryError::TooLarge)?;
        entry.totals = Delta::from_public(&totals);
        entry.known_priced_subtotals = known_priced_subtotals;
        entry.revision = revision;
        if receipt.knownness == AccountingKnownness::Uncertain {
            entry
                .pending
                .as_mut()
                .ok_or(HistoryError::Conflict)?
                .uncertain_receipt = Some(Receipt::from_public(receipt));
        } else {
            entry.pending = None;
            entry.last = Some(Settlement {
                reference: Reference::from_public(attempt),
                receipt: Some(Receipt::from_public(receipt)),
                refused: None,
            });
        }
        let checkpoint = entry.checkpoint_detailed(&self.owner)?;
        if legacy_only {
            checkpoint.to_legacy()?;
        }
        self.save(&layout, &container)?;
        Ok(checkpoint)
    }

    /// Complete storage operation shared by the live wrapper and private
    /// record-level component tests. Records alone never authorize dispatch.
    fn settle_refusal_record(
        &self,
        attempt: &AttemptRef,
        record: &orbit_engine::retry::RefusalRecord,
    ) -> Result<RefusedSettlementAck, HistoryError> {
        validate_reference(attempt)?;
        record.validate()?;
        self.validate_scope(
            &record.intent().owner_session_id,
            record.intent().child_id.as_deref(),
        )?;
        if record.attempt() != attempt {
            return Err(HistoryError::InvalidRecord);
        }
        let settled_revision = attempt
            .revision
            .0
            .checked_add(1)
            .ok_or(HistoryError::TooLarge)?;
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        let mut container = self.container(&layout)?;
        let entry = container
            .entries
            .iter_mut()
            .find(|entry| entry.namespace == self.namespace())
            .ok_or(HistoryError::Missing)?;
        if entry.revision > settled_revision {
            return Err(HistoryError::StaleNonApplying);
        }
        if entry.revision == settled_revision && entry.pending.is_none() {
            let last = entry.last.as_ref().ok_or(HistoryError::Conflict)?;
            if last.reference.to_public() != *attempt {
                return Err(HistoryError::Conflict);
            }
            let current = last
                .refused
                .as_ref()
                .ok_or(HistoryError::Conflict)?
                .to_public()?;
            if &current != record {
                return Err(HistoryError::Conflict);
            }
            layout.check()?;
            return refusal_ack(entry.checkpoint_detailed(&self.owner)?, record);
        }
        let pending = entry.pending.as_ref().ok_or(HistoryError::Conflict)?;
        if entry.revision != attempt.revision.0
            || pending.reference.to_public() != *attempt
            || pending.intent.to_public() != *record.intent()
            || pending.uncertain_receipt.is_some()
            || pending
                .retry_binding
                .as_ref()
                .map(RetryBinding::to_public)
                .transpose()?
                .as_ref()
                != Some(record.binding())
        {
            return Err(HistoryError::Conflict);
        }
        let rollup = match &entry.refusals {
            Some(previous) => previous.to_public()?.appended(record.clone())?,
            None => orbit_engine::retry::RefusalRollup::first(record.clone())?,
        };
        entry.totals = Delta::from_public(&record.totals_after(&entry.totals.to_public()));
        entry.revision = settled_revision;
        entry.pending = None;
        entry.last = Some(Settlement {
            reference: Reference::from_public(attempt),
            receipt: None,
            refused: Some(RefusalRecord::from_public(record)),
        });
        entry.refusals = Some(RefusalRollup::from_public(&rollup));
        let checkpoint = entry.checkpoint_detailed(&self.owner)?;
        self.save(&layout, &container)?;
        refusal_ack(checkpoint, record)
    }

    fn publish_record(&self, record: &Archive) -> Result<CompactionRecordRef, HistoryError> {
        self.validate_scope(&record.owner, record.child.as_deref())?;
        validate_archive(record, &self.owner)?;
        let bytes = encode(record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge)?;
        let reference = CompactionRecordRef {
            owner_session_id: self.owner.clone(),
            child_id: self.child.clone(),
            record_id: record.operation_id.clone(),
            source_digest: record.source_digest.clone(),
            candidate_digest: record.candidate_digest.clone(),
        };
        let layout = self.layout(false)?;
        let _lock = Lock::acquire(&layout.owner, LOCK).map_err(storage_error)?;
        inspect_owner(&layout.owner)?;
        let (count, used) = scan_archives(&layout.archives, &self.owner)?;
        let path = layout
            .archives
            .io()
            .map_err(storage_error)?
            .join(record_name(&record.operation_id));
        // The shared publisher checks existing files using its128KiB profile
        // bound. Archive idempotence deliberately uses this checked32MiB read
        // before create-only publication, without widening that helper.
        if let Some(previous) = optional_file(&path, MAX_COMPACTION_SOURCE_BYTES)? {
            if previous != bytes {
                return Err(HistoryError::Conflict);
            }
            layout
                .archives
                .sync()
                .map_err(|_| HistoryError::Uncertain)?;
            layout.check().map_err(|_| HistoryError::Uncertain)?;
            return Ok(reference);
        }
        let container = self.container(&layout)?;
        let entry = container
            .entries
            .iter()
            .find(|e| e.namespace == self.namespace())
            .ok_or(HistoryError::Missing)?;
        if entry.pending.is_some() {
            return Err(HistoryError::Uncertain);
        }
        let last = entry.last.as_ref().ok_or(HistoryError::InvalidRecord)?;
        let last_receipt = record
            .attempts
            .last()
            .ok_or(HistoryError::InvalidRecord)?
            .to_public();
        let expected_intent = AttemptIntent {
            owner_session_id: self.owner.clone(),
            child_id: self.child.clone(),
            request_id: last_receipt.request_id.clone(),
            purpose: last_receipt.purpose,
            budget: record.summary_budget.to_public(),
        };
        let subtotal = entry.totals.to_public().housekeeping;
        let recorded = record.accounting.to_public().housekeeping;
        if last.refused.is_some()
            || last
                .receipt
                .as_ref()
                .ok_or(HistoryError::InvalidRecord)?
                .to_public()
                .digest()?
                != last_receipt.digest()?
            || last.reference.intent_digest != expected_intent.digest()?
            || subtotal.input_tokens < recorded.input_tokens
            || subtotal.output_tokens < recorded.output_tokens
            || matches!((subtotal.cost_microcents,recorded.cost_microcents),(Some(a),Some(b)) if a < b)
        {
            return Err(HistoryError::InvalidRecord);
        }
        if count >= MAX_RECORDS
            || used
                .checked_add(bytes.len() as u64)
                .ok_or(HistoryError::TooLarge)?
                > MAX_ARCHIVE_BYTES
        {
            return Err(HistoryError::Full);
        }
        layout.check()?;
        publish(
            &layout.archives,
            &record_name(&record.operation_id),
            &bytes,
            true,
        )
        .map_err(storage_error)?;
        layout.check().map_err(|_| HistoryError::Uncertain)?;
        Ok(reference)
    }
}

fn refusal_ack(
    checkpoint: DetailedAccountingCheckpoint,
    record: &orbit_engine::retry::RefusalRecord,
) -> Result<RefusedSettlementAck, HistoryError> {
    RefusedSettlementAck::new(
        checkpoint,
        record.attempt().clone(),
        record.binding().clone(),
        record.digest().into(),
        record.observation_digest().into(),
        record.binding().policy_digest().into(),
    )
}

fn storage_error(error: Error) -> HistoryError {
    match error {
        Error::Busy => HistoryError::Busy,
        Error::PublicationUncertain(_) => HistoryError::Uncertain,
        Error::Invalid(_) | Error::UnsafePath(_) | Error::Io(_) => HistoryError::Unsafe,
    }
}
fn id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn scope(owner: &str, child: Option<&str>) -> Result<(), HistoryError> {
    if !id(owner, 128) || child.is_some_and(|s| !canonical_ulid(s)) {
        return Err(HistoryError::InvalidRecord);
    }
    Ok(())
}
fn canonical_ulid(value: &str) -> bool {
    value.len() == 26 && ulid::Ulid::from_string(value).is_ok_and(|u| u.to_string() == value)
}
fn valid_record_id(value: &str) -> Result<(), HistoryError> {
    if value.strip_prefix("compact-").is_some_and(canonical_ulid) {
        Ok(())
    } else {
        Err(HistoryError::InvalidRecord)
    }
}
fn record_name(record: &str) -> String {
    format!("{record}.json")
}
fn digest_ok(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_budget(budget: &BudgetIdentity) -> Result<(), HistoryError> {
    if !digest_ok(&budget.binding_digest)
        || [&budget.metadata_revision, &budget.policy_revision]
            .iter()
            .any(|s| s.len() > 256 || s.chars().any(char::is_control))
    {
        return Err(HistoryError::InvalidRecord);
    }
    Ok(())
}
fn validate_reference(reference: &AttemptRef) -> Result<(), HistoryError> {
    if reference.revision.0 == 0
        || !id(&reference.request_id, 256)
        || !digest_ok(&reference.intent_digest)
    {
        return Err(HistoryError::InvalidRecord);
    }
    Ok(())
}

struct BoundedEncoder {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}
impl Write for BoundedEncoder {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.maximum.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("bounded history encoding"));
        }
        let needed = self.bytes.len() + data.len();
        if needed > self.bytes.capacity() {
            let target = needed
                .checked_next_power_of_two()
                .unwrap_or(self.maximum)
                .min(self.maximum);
            self.bytes.reserve_exact(target - self.bytes.len());
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize + ?Sized>(
    value: &T,
    maximum: usize,
    full: HistoryError,
) -> Result<Vec<u8>, HistoryError> {
    let mut writer = BoundedEncoder {
        bytes: Vec::new(),
        maximum,
        exceeded: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            full
        } else {
            HistoryError::InvalidRecord
        }
    })?;
    Ok(writer.bytes)
}
fn typed_digest(domain: &[u8], messages: &[ChatMessage]) -> Result<String, HistoryError> {
    let bytes = encode(
        messages,
        MAX_COMPACTION_SOURCE_BYTES,
        HistoryError::TooLarge,
    )?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}
fn optional_file(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>, HistoryError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.len() > maximum as u64 {
                return Err(HistoryError::TooLarge);
            }
            read_regular(path, maximum, true)
                .map(Some)
                .map_err(storage_error)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(HistoryError::Unsafe),
    }
}
fn inspect_owner(dir: &Directory) -> Result<(), HistoryError> {
    let mut count = 0usize;
    for item in
        std::fs::read_dir(dir.io().map_err(storage_error)?).map_err(|_| HistoryError::Unsafe)?
    {
        count += 1;
        if count > 4 {
            return Err(HistoryError::Unsafe);
        }
        let item = item.map_err(|_| HistoryError::Unsafe)?;
        let name = item.file_name();
        let name = name.to_str().ok_or(HistoryError::Unsafe)?;
        if name.starts_with(".stage-") {
            return Err(HistoryError::Uncertain);
        }
        match name {
            ACCOUNTING => {
                optional_file(&item.path(), MAX_ACCOUNTING_CHECKPOINT_BYTES)?;
            }
            LOCK => {
                optional_file(&item.path(), MAX_ACCOUNTING_CHECKPOINT_BYTES)?;
            }
            "archives" => {
                Directory::open(&dir.path().join(name), true).map_err(storage_error)?;
            }
            _ => return Err(HistoryError::Unsafe),
        }
    }
    dir.check().map_err(storage_error)
}
fn scan_archives(dir: &Directory, owner: &str) -> Result<(usize, u64), HistoryError> {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for item in
        std::fs::read_dir(dir.io().map_err(storage_error)?).map_err(|_| HistoryError::Unsafe)?
    {
        let item = item.map_err(|_| HistoryError::Unsafe)?;
        let name = item.file_name();
        let name = name.to_str().ok_or(HistoryError::Unsafe)?;
        if name.starts_with(".stage-") {
            return Err(HistoryError::Uncertain);
        }
        count += 1;
        if count > MAX_RECORDS {
            return Err(HistoryError::Full);
        }
        let record_id = name.strip_suffix(".json").ok_or(HistoryError::Unsafe)?;
        valid_record_id(record_id).map_err(|_| HistoryError::Unsafe)?;
        let data = optional_file(&item.path(), MAX_COMPACTION_SOURCE_BYTES)?
            .ok_or(HistoryError::Unsafe)?;
        bytes = bytes
            .checked_add(data.len() as u64)
            .ok_or(HistoryError::TooLarge)?;
        if bytes > MAX_ARCHIVE_BYTES {
            return Err(HistoryError::Full);
        }
        let record = decode_archive(&data, owner)?;
        if record.operation_id != record_id {
            return Err(HistoryError::InvalidRecord);
        }
    }
    dir.check().map_err(storage_error)?;
    Ok((count, bytes))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Namespace {
    Owner,
    Child { id: String },
}
impl Namespace {
    fn child(&self) -> Option<&str> {
        match self {
            Self::Owner => None,
            Self::Child { id } => Some(id),
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Baseline {
    FreshKnownZero,
    UnknownLegacy,
}
impl Baseline {
    fn from_public(v: AccountingBaseline) -> Self {
        match v {
            AccountingBaseline::FreshKnownZero => Self::FreshKnownZero,
            AccountingBaseline::UnknownLegacy => Self::UnknownLegacy,
        }
    }
    fn to_public(self) -> AccountingBaseline {
        match self {
            Self::FreshKnownZero => AccountingBaseline::FreshKnownZero,
            Self::UnknownLegacy => AccountingBaseline::UnknownLegacy,
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Knownness {
    Known,
    UnknownLegacy,
    UnknownUsage,
    Uncertain,
}
impl Knownness {
    fn from_public(v: AccountingKnownness) -> Self {
        match v {
            AccountingKnownness::Known => Self::Known,
            AccountingKnownness::UnknownLegacy => Self::UnknownLegacy,
            AccountingKnownness::UnknownUsage => Self::UnknownUsage,
            AccountingKnownness::Uncertain => Self::Uncertain,
        }
    }
    fn to_public(self) -> AccountingKnownness {
        match self {
            Self::Known => AccountingKnownness::Known,
            Self::UnknownLegacy => AccountingKnownness::UnknownLegacy,
            Self::UnknownUsage => AccountingKnownness::UnknownUsage,
            Self::Uncertain => AccountingKnownness::Uncertain,
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Purpose {
    Ordinary,
    Chunk,
    Merge,
}
impl Purpose {
    fn from_public(v: AttemptPurpose) -> Self {
        match v {
            AttemptPurpose::Ordinary => Self::Ordinary,
            AttemptPurpose::Chunk => Self::Chunk,
            AttemptPurpose::Merge => Self::Merge,
        }
    }
    fn to_public(self) -> AttemptPurpose {
        match self {
            Self::Ordinary => AttemptPurpose::Ordinary,
            Self::Chunk => AttemptPurpose::Chunk,
            Self::Merge => AttemptPurpose::Merge,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Totals {
    input_tokens: u64,
    output_tokens: u64,
    cost_microcents: Option<u64>,
}
impl Totals {
    fn from_public(v: AccountingTotals) -> Self {
        Self {
            input_tokens: v.input_tokens,
            output_tokens: v.output_tokens,
            cost_microcents: v.cost_microcents,
        }
    }
    fn to_public(&self) -> AccountingTotals {
        AccountingTotals {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cost_microcents: self.cost_microcents,
        }
    }
    fn maximum() -> Self {
        Self {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cost_microcents: Some(u64::MAX),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delta {
    ordinary: Totals,
    housekeeping: Totals,
    knownness: Knownness,
}
impl Delta {
    fn from_public(v: &AccountingDelta) -> Self {
        Self {
            ordinary: Totals::from_public(v.ordinary),
            housekeeping: Totals::from_public(v.housekeeping),
            knownness: Knownness::from_public(v.knownness),
        }
    }
    fn to_public(&self) -> AccountingDelta {
        AccountingDelta {
            ordinary: self.ordinary.to_public(),
            housekeeping: self.housekeeping.to_public(),
            knownness: self.knownness.to_public(),
        }
    }
    fn maximum() -> Self {
        Self {
            ordinary: Totals::maximum(),
            housekeeping: Totals::maximum(),
            knownness: Knownness::UnknownLegacy,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PricedSubtotals {
    ordinary_microcents: u64,
    housekeeping_microcents: u64,
}
impl PricedSubtotals {
    fn from_public(v: KnownPricedSubtotals) -> Self {
        Self {
            ordinary_microcents: v.ordinary_microcents,
            housekeeping_microcents: v.housekeeping_microcents,
        }
    }
    fn to_public(&self) -> KnownPricedSubtotals {
        KnownPricedSubtotals {
            ordinary_microcents: self.ordinary_microcents,
            housekeeping_microcents: self.housekeeping_microcents,
        }
    }
    fn maximum() -> Self {
        Self {
            ordinary_microcents: u64::MAX,
            housekeeping_microcents: u64::MAX,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    binding_digest: String,
    metadata_revision: String,
    policy_revision: String,
}
impl Budget {
    fn from_public(v: &BudgetIdentity) -> Self {
        Self {
            binding_digest: v.binding_digest.clone(),
            metadata_revision: v.metadata_revision.clone(),
            policy_revision: v.policy_revision.clone(),
        }
    }
    fn to_public(&self) -> BudgetIdentity {
        BudgetIdentity {
            binding_digest: self.binding_digest.clone(),
            metadata_revision: self.metadata_revision.clone(),
            policy_revision: self.policy_revision.clone(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    revision: u64,
    request_id: String,
    intent_digest: String,
}
impl Reference {
    fn from_public(v: &AttemptRef) -> Self {
        Self {
            revision: v.revision.0,
            request_id: v.request_id.clone(),
            intent_digest: v.intent_digest.clone(),
        }
    }
    fn to_public(&self) -> AttemptRef {
        AttemptRef {
            revision: AccountingRevision(self.revision),
            request_id: self.request_id.clone(),
            intent_digest: self.intent_digest.clone(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    owner: String,
    child: Option<String>,
    request_id: String,
    purpose: Purpose,
    budget: Budget,
}
impl Intent {
    fn from_public(v: &AttemptIntent) -> Self {
        Self {
            owner: v.owner_session_id.clone(),
            child: v.child_id.clone(),
            request_id: v.request_id.clone(),
            purpose: Purpose::from_public(v.purpose),
            budget: Budget::from_public(&v.budget),
        }
    }
    fn to_public(&self) -> AttemptIntent {
        AttemptIntent {
            owner_session_id: self.owner.clone(),
            child_id: self.child.clone(),
            request_id: self.request_id.clone(),
            purpose: self.purpose.to_public(),
            budget: self.budget.to_public(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Usage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    reasoning_tokens: u64,
}
impl Usage {
    fn from_public(v: ProviderUsage) -> Self {
        Self {
            input_tokens: v.input_tokens,
            output_tokens: v.output_tokens,
            cache_read_tokens: v.cache_read_tokens,
            cache_write_tokens: v.cache_write_tokens,
            reasoning_tokens: v.reasoning_tokens,
        }
    }
    fn to_public(&self) -> ProviderUsage {
        ProviderUsage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cache_read_tokens: self.cache_read_tokens,
            cache_write_tokens: self.cache_write_tokens,
            reasoning_tokens: self.reasoning_tokens,
        }
    }
    fn maximum() -> Self {
        Self {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cache_read_tokens: u64::MAX,
            cache_write_tokens: u64::MAX,
            reasoning_tokens: u64::MAX,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    request_id: String,
    purpose: Purpose,
    totals: Totals,
    usage: Option<Usage>,
    knownness: Knownness,
    completed: bool,
}
impl Receipt {
    fn from_public(v: &RequestAccountingReceipt) -> Self {
        Self {
            request_id: v.request_id.clone(),
            purpose: Purpose::from_public(v.purpose),
            totals: Totals::from_public(v.totals),
            usage: v.usage.map(Usage::from_public),
            knownness: Knownness::from_public(v.knownness),
            completed: v.completed,
        }
    }
    fn to_public(&self) -> RequestAccountingReceipt {
        RequestAccountingReceipt {
            request_id: self.request_id.clone(),
            purpose: self.purpose.to_public(),
            totals: self.totals.to_public(),
            usage: self.usage.as_ref().map(Usage::to_public),
            knownness: self.knownness.to_public(),
            completed: self.completed,
        }
    }
    fn maximum(request: &str, purpose: Purpose) -> Self {
        Self {
            request_id: request.into(),
            purpose,
            totals: Totals::maximum(),
            usage: Some(Usage::maximum()),
            knownness: Knownness::UnknownLegacy,
            completed: false,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    reference: Reference,
    intent: Intent,
    uncertain_receipt: Option<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_binding: Option<RetryBinding>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settlement {
    reference: Reference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refused: Option<RefusalRecord>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    namespace: Namespace,
    revision: u64,
    baseline: Baseline,
    totals: Delta,
    pending: Option<Pending>,
    last: Option<Settlement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    known_priced_subtotals: Option<PricedSubtotals>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refusals: Option<RefusalRollup>,
}
impl Entry {
    fn has_retry_metadata(&self) -> bool {
        self.refusals.is_some()
            || self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.retry_binding.is_some())
            || self
                .last
                .as_ref()
                .is_some_and(|last| last.refused.is_some())
    }
    fn checkpoint(&self, owner: &str) -> Result<AccountingCheckpoint, HistoryError> {
        if self.has_retry_metadata() {
            return Err(HistoryError::InvalidRecord);
        }
        self.checkpoint_detailed(owner)?.to_legacy()
    }
    fn checkpoint_detailed(
        &self,
        owner: &str,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        let last = self
            .last
            .as_ref()
            .map(|last| match (&last.receipt, &last.refused) {
                (Some(receipt), None) => {
                    let receipt = receipt.to_public();
                    if receipt.request_id != last.reference.request_id {
                        return Err(HistoryError::InvalidRecord);
                    }
                    Ok(DetailedLastSettlement::Legacy(SettledAttempt {
                        reference: last.reference.to_public(),
                        receipt_digest: receipt.digest()?,
                    }))
                }
                (None, Some(record)) => {
                    let record = record.to_public()?;
                    if record.attempt() != &last.reference.to_public() {
                        return Err(HistoryError::InvalidRecord);
                    }
                    Ok(DetailedLastSettlement::FinalRefusal(record))
                }
                _ => Err(HistoryError::InvalidRecord),
            })
            .transpose()?;
        DetailedAccountingCheckpoint::new(
            owner.into(),
            self.namespace.child().map(str::to_owned),
            AccountingRevision(self.revision),
            self.baseline.to_public(),
            self.totals.to_public(),
            self.pending.as_ref().map(|pending| PendingAttempt {
                reference: pending.reference.to_public(),
                intent: pending.intent.to_public(),
                uncertain: pending.uncertain_receipt.is_some(),
            }),
            last,
            self.known_priced_subtotals
                .as_ref()
                .map(PricedSubtotals::to_public),
            self.refusals
                .as_ref()
                .map(RefusalRollup::to_public)
                .transpose()?,
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Container {
    version: u8,
    owner: String,
    entries: Vec<Entry>,
}

fn load_container(dir: &Directory, owner: &str) -> Result<Option<Container>, HistoryError> {
    let path = dir.io().map_err(storage_error)?.join(ACCOUNTING);
    let Some(bytes) = optional_file(&path, MAX_ACCOUNTING_CHECKPOINT_BYTES)? else {
        return Ok(None);
    };
    let container = decode_container(&bytes, owner)?;
    dir.check().map_err(storage_error)?;
    Ok(Some(container))
}
// The original load_container validation block, shared without additional I/O.
fn decode_container(bytes: &[u8], owner: &str) -> Result<Container, HistoryError> {
    let container: Container =
        serde_json::from_slice(bytes).map_err(|_| HistoryError::InvalidRecord)?;
    validate_container(&container, owner)?;
    if encode(
        &container,
        MAX_ACCOUNTING_CHECKPOINT_BYTES,
        HistoryError::Full,
    )?
    .as_slice()
        != bytes
    {
        return Err(HistoryError::InvalidRecord);
    }
    reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES)?;
    Ok(container)
}
fn validate_container(container: &Container, owner: &str) -> Result<(), HistoryError> {
    scope(owner, None)?;
    if container.version != 1 || container.owner != owner {
        return Err(HistoryError::InvalidRecord);
    }
    let mut seen = BTreeSet::new();
    for entry in &container.entries {
        scope(owner, entry.namespace.child())?;
        if !seen.insert(entry.namespace.child()) {
            return Err(HistoryError::InvalidRecord);
        }
        let totals = entry.totals.to_public();
        if let Some(subtotals) = &entry.known_priced_subtotals
            && ((entry.revision == 0
                && subtotals.to_public() != KnownPricedSubtotals::known_zero())
                || totals
                    .ordinary
                    .cost_microcents
                    .is_some_and(|cost| cost != subtotals.ordinary_microcents)
                || totals
                    .housekeeping
                    .cost_microcents
                    .is_some_and(|cost| cost != subtotals.housekeeping_microcents))
        {
            return Err(HistoryError::InvalidRecord);
        }
        if entry.baseline.to_public() == AccountingBaseline::UnknownLegacy
            && !matches!(
                totals.knownness,
                AccountingKnownness::UnknownLegacy | AccountingKnownness::Uncertain
            )
        {
            return Err(HistoryError::InvalidRecord);
        }
        if (entry.baseline.to_public() == AccountingBaseline::FreshKnownZero
            && totals.knownness == AccountingKnownness::UnknownLegacy)
            || (totals.knownness == AccountingKnownness::Uncertain
                && entry
                    .pending
                    .as_ref()
                    .is_none_or(|p| p.uncertain_receipt.is_none()))
            || (matches!(
                totals.knownness,
                AccountingKnownness::UnknownUsage
                    | AccountingKnownness::UnknownLegacy
                    | AccountingKnownness::Uncertain
            ) && totals.ordinary.cost_microcents.is_some()
                && totals.housekeeping.cost_microcents.is_some())
        {
            return Err(HistoryError::InvalidRecord);
        }
        if entry.revision == 0 {
            let expected = match entry.baseline.to_public() {
                AccountingBaseline::FreshKnownZero => AccountingDelta::known_zero(),
                AccountingBaseline::UnknownLegacy => AccountingDelta::unknown_legacy(),
            };
            if entry.pending.is_some() || entry.last.is_some() || totals != expected {
                return Err(HistoryError::InvalidRecord);
            }
        } else if entry.pending.is_none() && entry.last.is_none() {
            return Err(HistoryError::InvalidRecord);
        }
        if let Some(last) = &entry.last {
            let reference = last.reference.to_public();
            validate_reference(&reference)?;
            if let (Some(stored), None) = (&last.receipt, &last.refused) {
                let receipt = stored.to_public();
                receipt.validate()?;
                if receipt.knownness == AccountingKnownness::Uncertain
                    || receipt.request_id != reference.request_id
                    || reference
                        .revision
                        .0
                        .checked_add(1)
                        .is_none_or(|r| r > entry.revision)
                {
                    return Err(HistoryError::InvalidRecord);
                }
                let bucket = if receipt.purpose == AttemptPurpose::Ordinary {
                    totals.ordinary
                } else {
                    totals.housekeeping
                };
                if bucket.input_tokens < receipt.totals.input_tokens
                    || bucket.output_tokens < receipt.totals.output_tokens
                    || matches!((bucket.cost_microcents, receipt.totals.cost_microcents), (Some(a),Some(b)) if a < b)
                {
                    return Err(HistoryError::InvalidRecord);
                }
                if let Some(subtotals) = &entry.known_priced_subtotals {
                    let priced = if receipt.purpose == AttemptPurpose::Ordinary {
                        subtotals.ordinary_microcents
                    } else {
                        subtotals.housekeeping_microcents
                    };
                    if receipt
                        .totals
                        .cost_microcents
                        .is_some_and(|cost| priced < cost)
                    {
                        return Err(HistoryError::InvalidRecord);
                    }
                }
            } else if let (None, Some(stored)) = (&last.receipt, &last.refused) {
                let record = stored.to_public()?;
                if record.attempt() != &reference {
                    return Err(HistoryError::InvalidRecord);
                }
            } else {
                return Err(HistoryError::InvalidRecord);
            }
        }
        if let Some(pending) = &entry.pending {
            let reference = pending.reference.to_public();
            validate_reference(&reference)?;
            reference
                .revision
                .0
                .checked_add(1)
                .ok_or(HistoryError::InvalidRecord)?;
            let intent = pending.intent.to_public();
            if intent.owner_session_id != owner
                || intent.child_id.as_deref() != entry.namespace.child()
                || intent.request_id != reference.request_id
                || intent.digest()? != reference.intent_digest
            {
                return Err(HistoryError::InvalidRecord);
            }
            let expected_revision = if pending.uncertain_receipt.is_some() {
                reference
                    .revision
                    .0
                    .checked_add(1)
                    .ok_or(HistoryError::InvalidRecord)?
            } else {
                reference.revision.0
            };
            if entry.revision != expected_revision
                || entry
                    .last
                    .as_ref()
                    .is_some_and(|last| last.reference.revision >= reference.revision.0)
            {
                return Err(HistoryError::InvalidRecord);
            }
            if let Some(binding) = &pending.retry_binding {
                let binding = binding.to_public()?;
                if intent.purpose != AttemptPurpose::Ordinary
                    || binding.request_id() != intent.request_id
                {
                    return Err(HistoryError::InvalidRecord);
                }
            }
            if let Some(receipt) = &pending.uncertain_receipt {
                let receipt = receipt.to_public();
                receipt.validate()?;
                if receipt.knownness != AccountingKnownness::Uncertain
                    || receipt.request_id != intent.request_id
                    || receipt.purpose != intent.purpose
                    || totals.knownness != AccountingKnownness::Uncertain
                {
                    return Err(HistoryError::InvalidRecord);
                }
            }
        } else if entry
            .last
            .as_ref()
            .is_some_and(|last| last.reference.revision.checked_add(1) != Some(entry.revision))
        {
            return Err(HistoryError::InvalidRecord);
        }
        entry.checkpoint_detailed(owner)?;
    }
    Ok(())
}

/// Charge each pending namespace for its largest complete future entry, not
/// only for its receipt. Reservation encodings are size-only, never decoded or
/// published as accounting evidence. All identity strings keep their actual
/// validated lengths for old unqualified attempts. Explicit retry bindings also
/// reserve the complete bounded refusal/rollup shape with maximum legal fields.
fn reservation_size(container: &Container, maximum: usize) -> Result<usize, HistoryError> {
    let actual = encode(container, maximum, HistoryError::Full)?.len();
    let mut reserved = actual;
    for entry in &container.entries {
        let Some(pending) = &entry.pending else {
            continue;
        };
        let actual_entry = encode(entry, maximum, HistoryError::Full)?.len();
        let mut future = entry.clone();
        future.revision = u64::MAX;
        future.totals = Delta::maximum();
        if let Some(subtotals) = &mut future.known_priced_subtotals {
            *subtotals = PricedSubtotals::maximum();
        }
        let maximum_receipt = Receipt::maximum(&pending.intent.request_id, pending.intent.purpose);
        future
            .pending
            .as_mut()
            .ok_or(HistoryError::InvalidRecord)?
            .uncertain_receipt = Some(maximum_receipt.clone());
        let pending_size = encode(&future, maximum, HistoryError::Full)?.len();
        future.pending = None;
        future.last = Some(Settlement {
            reference: pending.reference.clone(),
            receipt: Some(maximum_receipt),
            refused: None,
        });
        let settled_size = encode(&future, maximum, HistoryError::Full)?.len();
        let mut future_maximum = pending_size.max(settled_size).max(actual_entry);
        if pending.retry_binding.is_some() {
            // A future qualified transition must remain representable before
            // any send; a full chain counter cannot admit another refusal.
            if let Some(rollup) = &entry.refusals {
                rollup
                    .to_public()?
                    .count()
                    .checked_add(1)
                    .ok_or(HistoryError::Full)?;
            }
            // Size-only maximum record/rollup deliberately uses the longest legal
            // IDs, escaped budget revisions and decimal counters, never evidence.
            future_maximum = future_maximum.max(refusal::maximum_entry_size(&future, maximum)?);
        }
        let additional = future_maximum - actual_entry;
        reserved = reserved.checked_add(additional).ok_or(HistoryError::Full)?;
        if reserved > maximum {
            return Err(HistoryError::Full);
        }
    }
    Ok(reserved)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    source_messages: usize,
    immutable_start: usize,
    immutable_end: usize,
    summarized_start: usize,
    summarized_end: usize,
    retained_start: usize,
    retained_end: usize,
    current_user_index: usize,
}
impl Coverage {
    fn from_public(v: &CompactionCoverage) -> Self {
        Self {
            source_messages: v.source_messages,
            immutable_start: v.immutable_prefix.start,
            immutable_end: v.immutable_prefix.end,
            summarized_start: v.summarized_prefix.start,
            summarized_end: v.summarized_prefix.end,
            retained_start: v.retained_suffix.start,
            retained_end: v.retained_suffix.end,
            current_user_index: v.current_user_index,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    version: u8,
    owner: String,
    child: Option<String>,
    operation_id: String,
    source_digest: String,
    candidate_digest: String,
    source: Vec<ChatMessage>,
    candidate: Vec<ChatMessage>,
    coverage: Coverage,
    conversation_budget: Budget,
    summary_budget: Budget,
    accounting: Delta,
    attempts: Vec<Receipt>,
}
impl Archive {
    fn from_public(
        source: &[ChatMessage],
        candidate: &CompactionCandidate,
        receipt: &CompactionReceipt,
    ) -> Self {
        Self {
            version: 1,
            owner: receipt.owner_session_id.clone(),
            child: receipt.child_id.clone(),
            operation_id: receipt.operation_id.clone(),
            source_digest: receipt.source_digest.clone(),
            candidate_digest: receipt.candidate_digest.clone(),
            source: source.to_vec(),
            candidate: candidate.messages().to_vec(),
            coverage: Coverage::from_public(candidate.coverage()),
            conversation_budget: Budget::from_public(&receipt.conversation_budget),
            summary_budget: Budget::from_public(&receipt.summary_budget),
            accounting: Delta::from_public(&receipt.accounting),
            attempts: receipt.attempts.iter().map(Receipt::from_public).collect(),
        }
    }
}
fn decode_archive(bytes: &[u8], owner: &str) -> Result<Archive, HistoryError> {
    if bytes.len() > MAX_COMPACTION_SOURCE_BYTES {
        return Err(HistoryError::TooLarge);
    }
    let record: Archive = serde_json::from_slice(bytes).map_err(|_| HistoryError::InvalidRecord)?;
    validate_archive(&record, owner)?;
    // Only this version's canonical typed codec is accepted. Besides detecting
    // malformed framing, this rejects unknown nested ChatMessage/block fields
    // that the shared backward-compatible message decoder otherwise ignores.
    if encode(&record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge)? != bytes {
        return Err(HistoryError::InvalidRecord);
    }
    Ok(record)
}
fn validate_archive(record: &Archive, owner: &str) -> Result<(), HistoryError> {
    scope(owner, record.child.as_deref())?;
    valid_record_id(&record.operation_id)?;
    validate_budget(&record.conversation_budget.to_public())?;
    validate_budget(&record.summary_budget.to_public())?;
    if record.version != 1
        || record.owner != owner
        || !digest_ok(&record.source_digest)
        || !digest_ok(&record.candidate_digest)
        || typed_digest(b"orbit-compaction-source-v1\0", &record.source)? != record.source_digest
        || typed_digest(b"orbit-compaction-candidate-v1\0", &record.candidate)?
            != record.candidate_digest
    {
        return Err(HistoryError::InvalidRecord);
    }
    let c = &record.coverage;
    if c.source_messages != record.source.len()
        || c.immutable_start != 0
        || c.immutable_end != c.summarized_start
        || c.summarized_start >= c.summarized_end
        || c.summarized_end != c.retained_start
        || c.retained_start > c.current_user_index
        || c.retained_end != record.source.len()
        || c.current_user_index >= record.source.len()
        || record.source.iter().rposition(|m| m.role == ChatRole::User)
            != Some(c.current_user_index)
    {
        return Err(HistoryError::InvalidRecord);
    }
    let candidate_count = c
        .immutable_end
        .checked_add(2)
        .and_then(|v| v.checked_add(record.source.len().checked_sub(c.retained_start)?))
        .ok_or(HistoryError::InvalidRecord)?;
    if record.candidate.len() != candidate_count
        || record.candidate[..c.immutable_end] != record.source[..c.immutable_end]
        || record.candidate[c.immutable_end] != orbit_engine::user_message(SUMMARY_MARKER)
        || record.candidate[c.immutable_end + 1].role != ChatRole::Assistant
        || record.candidate[c.immutable_end + 1]
            .content
            .trim()
            .is_empty()
        || record.candidate[c.immutable_end + 1]
            != orbit_engine::assistant_message(&record.candidate[c.immutable_end + 1].content)
        || record.candidate[c.immutable_end + 2..] != record.source[c.retained_start..]
    {
        return Err(HistoryError::InvalidRecord);
    }
    if record.attempts.is_empty() || record.attempts.len() > MAX_SUMMARY_CHUNKS + 1 {
        return Err(HistoryError::InvalidRecord);
    }
    let mut aggregate = AccountingDelta::known_zero();
    let mut seen = BTreeSet::new();
    for receipt in &record.attempts {
        let receipt = receipt.to_public();
        receipt.validate()?;
        if receipt.purpose == AttemptPurpose::Ordinary
            || !receipt.completed
            || !seen.insert(receipt.request_id.clone())
        {
            return Err(HistoryError::InvalidRecord);
        }
        aggregate = aggregate.checked_with(&receipt)?;
    }
    if aggregate != record.accounting.to_public() {
        return Err(HistoryError::InvalidRecord);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::customization::{PublicationPoint, with_test_hook};
    use crate::sessions::SessionLease;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Tree {
        home: PathBuf,
        _lease: SessionLease,
    }
    impl Tree {
        fn new() -> Self {
            let home =
                std::env::temp_dir().join(format!("orbit-context-codec-{}", ulid::Ulid::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&home)
                .unwrap();
            let lease = SessionLease::acquire(&home, "owner", "context-test").unwrap();
            Self {
                home,
                _lease: lease,
            }
        }
        fn journal(&self) -> Journal {
            Journal::open(&self.home, "owner", None).unwrap()
        }
        fn owner(&self) -> PathBuf {
            self.home.join("context-history/owner")
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }
    fn budget() -> BudgetIdentity {
        BudgetIdentity {
            binding_digest: "a".repeat(64),
            metadata_revision: "metadata-v1".into(),
            policy_revision: "policy-v1".into(),
        }
    }
    fn intent(request: &str, purpose: AttemptPurpose) -> AttemptIntent {
        AttemptIntent {
            owner_session_id: "owner".into(),
            child_id: None,
            request_id: request.into(),
            purpose,
            budget: budget(),
        }
    }
    fn receipt(request: &str, purpose: AttemptPurpose) -> RequestAccountingReceipt {
        RequestAccountingReceipt {
            request_id: request.into(),
            purpose,
            totals: AccountingTotals {
                input_tokens: 8,
                output_tokens: 3,
                cost_microcents: Some(17),
            },
            usage: Some(ProviderUsage {
                input_tokens: 8,
                output_tokens: 3,
                cache_read_tokens: 5,
                cache_write_tokens: 7,
                reasoning_tokens: 2,
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        }
    }
    fn prepare_archive(journal: &Journal, old: String) -> Archive {
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let intent = intent("summary-request", AttemptPurpose::Chunk);
        let attempt = journal
            .begin_attempt(AccountingRevision(0), &intent)
            .unwrap();
        let receipt = receipt("summary-request", AttemptPurpose::Chunk);
        journal.settle_attempt(&attempt, &receipt).unwrap();
        let source = vec![
            orbit_engine::user_message(old),
            orbit_engine::assistant_message("earlier answer"),
            orbit_engine::user_message("current task"),
        ];
        let candidate = vec![
            orbit_engine::user_message(SUMMARY_MARKER),
            orbit_engine::assistant_message("Retain the current task and decisions."),
            source[2].clone(),
        ];
        Archive {
            version: 1,
            owner: "owner".into(),
            child: None,
            operation_id: format!("compact-{}", ulid::Ulid::new()),
            source_digest: typed_digest(b"orbit-compaction-source-v1\0", &source).unwrap(),
            candidate_digest: typed_digest(b"orbit-compaction-candidate-v1\0", &candidate).unwrap(),
            source,
            candidate,
            coverage: Coverage {
                source_messages: 3,
                immutable_start: 0,
                immutable_end: 0,
                summarized_start: 0,
                summarized_end: 2,
                retained_start: 2,
                retained_end: 3,
                current_user_index: 2,
            },
            conversation_budget: Budget::from_public(&budget()),
            summary_budget: Budget::from_public(&budget()),
            accounting: Delta::from_public(
                &AccountingDelta::known_zero()
                    .checked_with(&receipt)
                    .unwrap(),
            ),
            attempts: vec![Receipt::from_public(&receipt)],
        }
    }
    fn displace<T>(path: PathBuf, at: PublicationPoint, work: impl FnOnce() -> T) -> T {
        let moved = path.with_extension("displaced");
        let hook_path = path.clone();
        let hook_moved = moved.clone();
        let fired = Arc::new(AtomicBool::new(false));
        let hook_fired = fired.clone();
        let result = with_test_hook(
            move |point, directory| {
                if point == at && directory == hook_path && !hook_fired.swap(true, Ordering::SeqCst)
                {
                    std::fs::rename(&hook_path, &hook_moved).unwrap();
                }
            },
            work,
        );
        assert!(
            fired.load(Ordering::SeqCst),
            "selected publication point was not reached"
        );
        std::fs::rename(&moved, &path).unwrap();
        result
    }

    #[test]
    fn staged_begin_failure_keeps_old_checkpoint_and_removes_stage() {
        let tree = Tree::new();
        let journal = tree.journal();
        let before = journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let bytes = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let result = displace(tree.owner(), PublicationPoint::Staged, || {
            journal.begin_attempt(before.revision, &intent("staged", AttemptPurpose::Ordinary))
        });
        assert_eq!(result, Err(HistoryError::Unsafe));
        assert_eq!(std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(), bytes);
        assert_eq!(journal.accounting_checkpoint().unwrap(), before);
        assert!(!std::fs::read_dir(tree.owner()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".stage-")
        }));
    }

    #[test]
    fn published_begin_uncertainty_reopens_as_pending_without_readmission() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let request = intent("uncertain-begin", AttemptPurpose::Ordinary);
        let result = displace(tree.owner(), PublicationPoint::Published, || {
            journal.begin_attempt(AccountingRevision(0), &request)
        });
        assert_eq!(result, Err(HistoryError::Uncertain));
        let reopened = context_journal(&tree.home, "owner", None).unwrap();
        let checkpoint = reopened.accounting_checkpoint().unwrap();
        assert_eq!(checkpoint.revision, AccountingRevision(1));
        assert!(checkpoint.pending.is_some());
        assert_eq!(checkpoint.totals, AccountingDelta::known_zero());
        assert_eq!(
            reopened.begin_attempt(AccountingRevision(0), &request),
            Err(HistoryError::Conflict)
        );
        assert_eq!(
            reopened.initialize_accounting(AccountingBaseline::FreshKnownZero),
            Err(HistoryError::Conflict)
        );
    }

    #[test]
    fn published_settlement_uncertainty_reconciles_once_after_restart() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let attempt = journal
            .begin_attempt(
                AccountingRevision(0),
                &intent("uncertain-settle", AttemptPurpose::Ordinary),
            )
            .unwrap();
        let receipt = receipt("uncertain-settle", AttemptPurpose::Ordinary);
        let result = displace(tree.owner(), PublicationPoint::Published, || {
            journal.settle_attempt(&attempt, &receipt)
        });
        assert_eq!(result, Err(HistoryError::Uncertain));
        let reopened = context_journal(&tree.home, "owner", None).unwrap();
        let checkpoint = reopened.accounting_checkpoint().unwrap();
        assert_eq!(checkpoint.revision, AccountingRevision(2));
        assert_eq!(checkpoint.totals.ordinary, receipt.totals);
        assert!(checkpoint.pending.is_none());
        assert_eq!(
            reopened.settle_attempt(&attempt, &receipt).unwrap(),
            checkpoint
        );
    }

    #[test]
    fn archive_staging_failure_keeps_source_unpublished_and_accounting_intact() {
        let tree = Tree::new();
        let journal = tree.journal();
        let record = prepare_archive(&journal, "historical source".into());
        let checkpoint = journal.accounting_checkpoint().unwrap();
        let result = displace(
            tree.owner().join("archives"),
            PublicationPoint::Staged,
            || journal.publish_record(&record),
        );
        assert_eq!(result, Err(HistoryError::Unsafe));
        assert_eq!(journal.accounting_checkpoint().unwrap(), checkpoint);
        assert!(
            std::fs::read_dir(tree.owner().join("archives"))
                .unwrap()
                .next()
                .is_none()
        );
        assert_eq!(
            load_compaction_source(&tree.home, "owner", None, &record.operation_id),
            Err(HistoryError::Missing)
        );
    }

    #[test]
    fn published_archive_uncertainty_is_an_inert_recoverable_orphan() {
        let tree = Tree::new();
        let journal = tree.journal();
        let record = prepare_archive(&journal, "recoverable original".into());
        let checkpoint = journal.accounting_checkpoint().unwrap();
        let result = displace(
            tree.owner().join("archives"),
            PublicationPoint::Published,
            || journal.publish_record(&record),
        );
        assert_eq!(result, Err(HistoryError::Uncertain));
        assert_eq!(
            load_compaction_source(&tree.home, "owner", None, &record.operation_id).unwrap(),
            record.source
        );
        assert_eq!(journal.accounting_checkpoint().unwrap(), checkpoint);
        let first = journal.publish_record(&record).unwrap();
        assert_eq!(journal.publish_record(&record).unwrap(), first);
        assert_eq!(
            std::fs::read_dir(tree.owner().join("archives"))
                .unwrap()
                .count(),
            1
        );
        assert!(!tree.home.join("sessions/owner.json").exists());
    }

    #[test]
    fn large_archive_idempotence_uses_archive_bound_and_exact_equality() {
        let tree = Tree::new();
        let journal = tree.journal();
        let mut record = prepare_archive(&journal, "old full content ".repeat(12_000));
        let encoded = encode(&record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge).unwrap();
        assert!(encoded.len() > MAX_ACCOUNTING_CHECKPOINT_BYTES);
        let reference = journal.publish_record(&record).unwrap();
        assert_eq!(journal.publish_record(&record).unwrap(), reference);
        record
            .conversation_budget
            .policy_revision
            .push_str("-changed");
        assert_eq!(journal.publish_record(&record), Err(HistoryError::Conflict));
    }

    #[test]
    fn private_codec_retains_all_uncertain_usage_counters_and_latest_receipt() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let previous = receipt("known-first", AttemptPurpose::Ordinary);
        let first = journal
            .begin_attempt(
                AccountingRevision(0),
                &intent("known-first", AttemptPurpose::Ordinary),
            )
            .unwrap();
        journal.settle_attempt(&first, &previous).unwrap();
        let second = journal
            .begin_attempt(
                AccountingRevision(2),
                &intent("provisional", AttemptPurpose::Chunk),
            )
            .unwrap();
        let uncertain = RequestAccountingReceipt {
            request_id: "provisional".into(),
            purpose: AttemptPurpose::Chunk,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(ProviderUsage {
                input_tokens: 101,
                output_tokens: 103,
                cache_read_tokens: 107,
                cache_write_tokens: 109,
                reasoning_tokens: 113,
            }),
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        };
        let settled = journal.settle_attempt(&second, &uncertain).unwrap();
        let layout = journal.layout(false).unwrap();
        let container = load_container(&layout.owner, "owner").unwrap().unwrap();
        let entry = &container.entries[0];
        assert_eq!(
            entry
                .last
                .as_ref()
                .unwrap()
                .receipt
                .as_ref()
                .unwrap()
                .to_public(),
            previous
        );
        assert_eq!(
            entry
                .pending
                .as_ref()
                .unwrap()
                .uncertain_receipt
                .as_ref()
                .unwrap()
                .to_public(),
            uncertain
        );
        let reopened = context_journal(&tree.home, "owner", None).unwrap();
        assert_eq!(reopened.accounting_checkpoint().unwrap(), settled);
        assert_eq!(
            reopened.settle_attempt(&second, &uncertain).unwrap(),
            settled
        );
        assert_eq!(
            reopened.begin_attempt(
                settled.revision,
                &intent("blocked", AttemptPurpose::Ordinary)
            ),
            Err(HistoryError::Conflict)
        );
    }

    fn empty_entry(child: String) -> Entry {
        Entry {
            namespace: Namespace::Child { id: child },
            revision: 0,
            baseline: Baseline::FreshKnownZero,
            totals: Delta::from_public(&AccountingDelta::known_zero()),
            pending: None,
            last: None,
            refusals: None,
            known_priced_subtotals: Some(PricedSubtotals::from_public(
                KnownPricedSubtotals::known_zero(),
            )),
        }
    }

    #[test]
    fn exact_container_cap_reserves_whole_pending_entry_against_sibling_initialization() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let mut request = intent(&"r".repeat(256), AttemptPurpose::Ordinary);
        request.budget.metadata_revision = "\\\"".repeat(128);
        request.budget.policy_revision = "\\\"".repeat(128);
        let reference = journal
            .begin_attempt(AccountingRevision(0), &request)
            .unwrap();
        let layout = journal.layout(false).unwrap();
        let mut container = load_container(&layout.owner, "owner").unwrap().unwrap();
        let mut tuner = empty_entry(ulid::Ulid::new().to_string());
        let zero = RequestAccountingReceipt {
            request_id: "t".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals::known_zero(),
            usage: Some(ProviderUsage::default()),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        tuner.revision = 2;
        tuner.last = Some(Settlement {
            reference: Reference {
                revision: 1,
                request_id: "t".into(),
                intent_digest: "b".repeat(64),
            },
            receipt: Some(Receipt::from_public(&zero)),
            refused: None,
        });
        container.entries.push(tuner);
        loop {
            let filler = empty_entry(ulid::Ulid::new().to_string());
            container.entries.push(filler);
            if reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES).is_err() {
                container.entries.pop();
                break;
            }
        }
        let current = reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES).unwrap();
        let remainder = MAX_ACCOUNTING_CHECKPOINT_BYTES - current;
        let tuner = &mut container.entries[1];
        if !remainder.is_multiple_of(2) {
            tuner.totals.ordinary.input_tokens = 10;
        }
        let pad = remainder / 2;
        assert!(pad < 256);
        let last = tuner.last.as_mut().unwrap();
        last.reference.request_id.push_str(&"t".repeat(pad));
        last.receipt.as_mut().unwrap().request_id = last.reference.request_id.clone();
        validate_container(&container, "owner").unwrap();
        assert_eq!(
            reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES).unwrap(),
            MAX_ACCOUNTING_CHECKPOINT_BYTES
        );
        let actual = encode(
            &container,
            MAX_ACCOUNTING_CHECKPOINT_BYTES,
            HistoryError::Full,
        )
        .unwrap();
        assert!(actual.len() < MAX_ACCOUNTING_CHECKPOINT_BYTES);
        journal.save(&layout, &container).unwrap();
        let original = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let child_id = ulid::Ulid::new().to_string();
        let child = Journal::open(&tree.home, "owner", Some(&child_id)).unwrap();
        assert_eq!(
            child.initialize_accounting(AccountingBaseline::FreshKnownZero),
            Err(HistoryError::Full)
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            original
        );
        let mut over = container.clone();
        // One extra decimal digit consumes exactly one extra encoded byte.
        over.entries[1].totals.ordinary.output_tokens = 10;
        assert_eq!(
            reservation_size(&over, MAX_ACCOUNTING_CHECKPOINT_BYTES),
            Err(HistoryError::Full)
        );
        assert_eq!(journal.save(&layout, &over), Err(HistoryError::Full));
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            original
        );
        let maximum = RequestAccountingReceipt {
            request_id: request.request_id.clone(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: u64::MAX,
                output_tokens: u64::MAX,
                cost_microcents: Some(u64::MAX),
            },
            usage: Some(Usage::maximum().to_public()),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        let final_checkpoint = journal.settle_attempt(&reference, &maximum).unwrap();
        assert_eq!(final_checkpoint.totals.ordinary, maximum.totals);
        assert!(final_checkpoint.pending.is_none());
        assert!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap().len()
                <= MAX_ACCOUNTING_CHECKPOINT_BYTES
        );
        let reopened = context_journal(&tree.home, "owner", None).unwrap();
        assert_eq!(reopened.accounting_checkpoint().unwrap(), final_checkpoint);
    }

    #[test]
    fn strict_codec_rejects_unknown_fields_version_and_noncanonical_record() {
        let tree = Tree::new();
        let journal = tree.journal();
        let record = prepare_archive(&journal, "unchanged historical source".into());
        let bytes = encode(&record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge).unwrap();
        assert!(decode_archive(&bytes, "owner").is_ok());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["source"][0]["unrecognized"] = serde_json::json!(true);
        assert!(matches!(
            decode_archive(&serde_json::to_vec(&value).unwrap(), "owner"),
            Err(HistoryError::InvalidRecord)
        ));
        value["version"] = serde_json::json!(2);
        assert!(matches!(
            decode_archive(&serde_json::to_vec(&value).unwrap(), "owner"),
            Err(HistoryError::InvalidRecord)
        ));
        let mut framed = bytes.clone();
        framed.push(b'\n');
        assert!(matches!(
            decode_archive(&framed, "owner"),
            Err(HistoryError::InvalidRecord)
        ));
    }

    #[test]
    fn exact_record_and_shared_byte_quota_include_full_encoded_orphan_records() {
        let tree = Tree::new();
        let journal = tree.journal();
        let mut record = prepare_archive(&journal, "x".into());
        let base = encode(&record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge)
            .unwrap()
            .len();
        record.source[0].content = "x".repeat(MAX_COMPACTION_SOURCE_BYTES - base + 1);
        record.source_digest =
            typed_digest(b"orbit-compaction-source-v1\0", &record.source).unwrap();
        assert_eq!(
            encode(&record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge)
                .unwrap()
                .len(),
            MAX_COMPACTION_SOURCE_BYTES
        );
        record.source[0].content.push('x');
        record.source_digest =
            typed_digest(b"orbit-compaction-source-v1\0", &record.source).unwrap();
        assert_eq!(journal.publish_record(&record), Err(HistoryError::TooLarge));
        assert!(
            std::fs::read_dir(tree.owner().join("archives"))
                .unwrap()
                .next()
                .is_none()
        );
        record.source[0].content.pop();
        record.source_digest =
            typed_digest(b"orbit-compaction-source-v1\0", &record.source).unwrap();
        for _ in 0..4 {
            record.operation_id = format!("compact-{}", ulid::Ulid::new());
            journal.publish_record(&record).unwrap();
        }
        let layout = journal.layout(false).unwrap();
        assert_eq!(
            scan_archives(&layout.archives, "owner").unwrap(),
            (4, MAX_ARCHIVE_BYTES)
        );
        let child_id = ulid::Ulid::new().to_string();
        let child = Journal::open(&tree.home, "owner", Some(&child_id)).unwrap();
        assert_eq!(child.check_archive_capacity(1), Err(HistoryError::Full));
        record.operation_id = format!("compact-{}", ulid::Ulid::new());
        record.source[0].content = "small additional original".into();
        record.source_digest =
            typed_digest(b"orbit-compaction-source-v1\0", &record.source).unwrap();
        assert_eq!(journal.publish_record(&record), Err(HistoryError::Full));
        assert_eq!(
            std::fs::read_dir(tree.owner().join("archives"))
                .unwrap()
                .count(),
            4
        );
    }

    #[test]
    fn orphan_stages_block_new_writes_without_accumulation_or_eviction() {
        let tree = Tree::new();
        let journal = tree.journal();
        let before = journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let stage = tree.owner().join(format!(".stage-{}", ulid::Ulid::new()));
        std::fs::write(&stage, b"incomplete private state").unwrap();
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o600)).unwrap();
        for _ in 0..3 {
            assert_eq!(
                journal.begin_attempt(
                    before.revision,
                    &intent("no-replay", AttemptPurpose::Ordinary)
                ),
                Err(HistoryError::Uncertain)
            );
        }
        assert_eq!(std::fs::read_dir(tree.owner()).unwrap().count(), 4);
        assert_eq!(std::fs::read(stage).unwrap(), b"incomplete private state");
    }

    fn recovery_tree_fingerprints(
        home: &Path,
    ) -> std::collections::BTreeMap<PathBuf, (RecoveryFileStamp, Vec<u8>)> {
        let mut found = std::collections::BTreeMap::new();
        let mut pending = vec![home.to_owned()];
        while let Some(path) = pending.pop() {
            assert!(found.len() < 100);
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let bytes = if metadata.is_file() {
                Sha256::digest(std::fs::read(&path).unwrap()).to_vec()
            } else {
                assert!(metadata.is_dir());
                for entry in std::fs::read_dir(&path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
                Vec::new()
            };
            found.insert(
                path.strip_prefix(home).unwrap().to_owned(),
                (RecoveryFileStamp::of(&metadata), bytes),
            );
        }
        found
    }

    #[test]
    fn recovery_root_capture_preserves_exact_container_and_validated_inert_archives() {
        let tree = Tree::new();
        let journal = tree.journal();
        let record = prepare_archive(&journal, "complete saved historical original".into());
        journal.publish_record(&record).unwrap();
        let inspection = inspect_accounting(&tree.home, "owner", None).unwrap();
        let raw = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let archive_raw = std::fs::read(
            tree.owner()
                .join("archives")
                .join(record_name(&record.operation_id)),
        )
        .unwrap();
        let before = recovery_tree_fingerprints(&tree.home);
        let capture = capture_for_recovery(
            &tree._lease,
            inspection.checkpoint.revision,
            &inspection.inspection_digest,
        )
        .unwrap();
        assert_eq!(capture.inspection(), &inspection);
        assert_eq!(capture.accounting_bytes(), raw);
        assert_eq!(
            capture.accounting_sha256(),
            hex::encode(Sha256::digest(&raw))
        );
        assert_eq!(capture.archives().len(), 1);
        let archive = &capture.archives()[0];
        assert_eq!(archive.record_id(), record.operation_id);
        assert_eq!(archive.source_digest(), record.source_digest);
        assert_eq!(archive.candidate_digest(), record.candidate_digest);
        assert_eq!(archive.bytes(), archive_raw);
        assert_eq!(archive.sha256(), hex::encode(Sha256::digest(&archive_raw)));
        capture.verify_unchanged(&tree._lease).unwrap();
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
        assert!(!tree.home.join("sessions/owner.json").exists());
    }

    #[test]
    fn recovery_root_capture_requires_both_revision_and_owner_container_digest() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let original = inspect_accounting(&tree.home, "owner", None).unwrap();
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                AccountingRevision(1),
                &original.inspection_digest
            ),
            Err(HistoryError::Conflict)
        ));
        let other_digest = if original.inspection_digest == "a".repeat(64) {
            "b".repeat(64)
        } else {
            "a".repeat(64)
        };
        assert!(matches!(
            capture_for_recovery(&tree._lease, original.checkpoint.revision, &other_digest),
            Err(HistoryError::Conflict)
        ));
        assert!(matches!(
            capture_for_recovery(&tree._lease, original.checkpoint.revision, "bad"),
            Err(HistoryError::InvalidRecord)
        ));
        // This is a real sibling accounting namespace fixture, not an AgentRun
        // or a claim that a child recovery ownership guard exists.
        let child = ulid::Ulid::new().to_string();
        let sibling = Journal::open(&tree.home, "owner", Some(&child)).unwrap();
        sibling
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let current = inspect_accounting(&tree.home, "owner", None).unwrap();
        assert_eq!(current.checkpoint.revision, original.checkpoint.revision);
        assert_ne!(current.inspection_digest, original.inspection_digest);
        let before = recovery_tree_fingerprints(&tree.home);
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                original.checkpoint.revision,
                &original.inspection_digest
            ),
            Err(HistoryError::Conflict)
        ));
        let capture = capture_for_recovery(
            &tree._lease,
            current.checkpoint.revision,
            &current.inspection_digest,
        )
        .unwrap();
        assert_eq!(
            capture.accounting_bytes(),
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap()
        );
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
    }

    #[test]
    fn recovery_history_verification_reacquires_shared_lock_and_detects_new_pending_work() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let inspection = inspect_accounting(&tree.home, "owner", None).unwrap();
        let capture = capture_for_recovery(
            &tree._lease,
            inspection.checkpoint.revision,
            &inspection.inspection_digest,
        )
        .unwrap();
        // A retained capture must not hold the history lock across destination
        // work: the actual accepted writer can acquire it after capture returns.
        let reference = journal
            .begin_attempt(
                inspection.checkpoint.revision,
                &intent("later-work", AttemptPurpose::Ordinary),
            )
            .unwrap();
        let before = recovery_tree_fingerprints(&tree.home);
        assert!(matches!(
            capture.verify_unchanged(&tree._lease),
            Err(HistoryError::Conflict)
        ));
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
        assert_eq!(
            journal
                .accounting_checkpoint()
                .unwrap()
                .pending
                .unwrap()
                .reference,
            reference
        );
    }

    #[test]
    fn recovery_scan_validates_sibling_scope_before_filtering_and_refuses_bounds_and_stages() {
        use std::os::unix::fs::OpenOptionsExt;
        let tree = Tree::new();
        let journal = tree.journal();
        let record = prepare_archive(&journal, "scoped original".into());
        journal.publish_record(&record).unwrap();
        let raw = encode(&record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge).unwrap();
        let mut sibling = decode_archive(&raw, "owner").unwrap();
        sibling.child = Some(ulid::Ulid::new().to_string());
        sibling.operation_id = format!("compact-{}", ulid::Ulid::new());
        let sibling_raw = encode(
            &sibling,
            MAX_COMPACTION_SOURCE_BYTES,
            HistoryError::TooLarge,
        )
        .unwrap();
        decode_archive(&sibling_raw, "owner").unwrap();
        let path = tree
            .owner()
            .join("archives")
            .join(record_name(&sibling.operation_id));
        std::fs::write(&path, &sibling_raw).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let inspection = inspect_accounting(&tree.home, "owner", None).unwrap();
        let capture = capture_for_recovery(
            &tree._lease,
            inspection.checkpoint.revision,
            &inspection.inspection_digest,
        )
        .unwrap();
        assert_eq!(capture.archives().len(), 1);
        assert_eq!(capture.archives()[0].record_id(), record.operation_id);
        capture.verify_unchanged(&tree._lease).unwrap();
        std::fs::write(&path, b"corrupt sibling cannot be skipped by guessed scope").unwrap();
        let before = recovery_tree_fingerprints(&tree.home);
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                inspection.checkpoint.revision,
                &inspection.inspection_digest
            ),
            Err(HistoryError::InvalidRecord)
        ));
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        file.set_len(MAX_COMPACTION_SOURCE_BYTES as u64 + 1)
            .unwrap();
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                inspection.checkpoint.revision,
                &inspection.inspection_digest
            ),
            Err(HistoryError::TooLarge)
        ));
        assert_eq!(
            file.metadata().unwrap().len(),
            MAX_COMPACTION_SOURCE_BYTES as u64 + 1
        );
        drop(file);
        std::fs::remove_file(&path).unwrap();
        let stage = tree.owner().join("archives/.stage-recovery-control");
        std::fs::write(&stage, b"inert stage").unwrap();
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                inspection.checkpoint.revision,
                &inspection.inspection_digest
            ),
            Err(HistoryError::Uncertain)
        ));
        assert_eq!(std::fs::read(stage).unwrap(), b"inert stage");
    }

    #[test]
    fn recovery_verification_detects_archive_replacement_and_selected_set_changes() {
        let tree = Tree::new();
        let journal = tree.journal();
        let record = prepare_archive(&journal, "held original".into());
        journal.publish_record(&record).unwrap();
        let inspection = inspect_accounting(&tree.home, "owner", None).unwrap();
        let capture = capture_for_recovery(
            &tree._lease,
            inspection.checkpoint.revision,
            &inspection.inspection_digest,
        )
        .unwrap();
        let path = tree
            .owner()
            .join("archives")
            .join(record_name(&record.operation_id));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::rename(&path, tree.home.join("original-archive")).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            capture.verify_unchanged(&tree._lease),
            Err(HistoryError::Conflict)
        ));
        let current = capture_for_recovery(
            &tree._lease,
            inspection.checkpoint.revision,
            &inspection.inspection_digest,
        )
        .unwrap();
        let mut added = decode_archive(&bytes, "owner").unwrap();
        added.operation_id = format!("compact-{}", ulid::Ulid::new());
        journal.publish_record(&added).unwrap();
        assert_eq!(
            inspect_accounting(&tree.home, "owner", None).unwrap(),
            inspection
        );
        assert!(matches!(
            current.verify_unchanged(&tree._lease),
            Err(HistoryError::Conflict)
        ));
        assert_eq!(
            std::fs::read(tree.home.join("original-archive")).unwrap(),
            bytes
        );
    }

    #[test]
    fn recovery_capture_enforces_shared_writer_exclusion_and_owner_record_count() {
        let tree = Tree::new();
        let journal = tree.journal();
        let record = prepare_archive(&journal, "bounded inert original".into());
        journal.publish_record(&record).unwrap();
        let inspection = inspect_accounting(&tree.home, "owner", None).unwrap();
        let layout = recovery_layout(&tree.home, "owner").unwrap();
        let writer = Lock::acquire(&layout.owner, LOCK).unwrap();
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                inspection.checkpoint.revision,
                &inspection.inspection_digest
            ),
            Err(HistoryError::Busy)
        ));
        drop(writer);
        let raw = encode(&record, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge).unwrap();
        // Canonical published-record fixtures include inert unapplied records;
        // no provider, candidate application or extra billing is inferred.
        for _ in 1..MAX_RECORDS {
            let mut copy = decode_archive(&raw, "owner").unwrap();
            copy.operation_id = format!("compact-{}", ulid::Ulid::new());
            let path = tree
                .owner()
                .join("archives")
                .join(record_name(&copy.operation_id));
            std::fs::write(
                &path,
                encode(&copy, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge).unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let capture = capture_for_recovery(
            &tree._lease,
            inspection.checkpoint.revision,
            &inspection.inspection_digest,
        )
        .unwrap();
        assert_eq!(capture.archives().len(), MAX_RECORDS);
        capture.verify_unchanged(&tree._lease).unwrap();
        let mut extra = decode_archive(&raw, "owner").unwrap();
        extra.operation_id = format!("compact-{}", ulid::Ulid::new());
        let path = tree
            .owner()
            .join("archives")
            .join(record_name(&extra.operation_id));
        std::fs::write(
            &path,
            encode(&extra, MAX_COMPACTION_SOURCE_BYTES, HistoryError::TooLarge).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = recovery_tree_fingerprints(&tree.home);
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                inspection.checkpoint.revision,
                &inspection.inspection_digest
            ),
            Err(HistoryError::Full)
        ));
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
    }
    // These fixtures are checked snapshot metadata only. They never create a
    // transport observation, trusted live binding, settlement or durable ACK.
    fn snapshot_binding(request: &str) -> orbit_engine::retry::OrdinaryAttemptBindingRecord {
        orbit_engine::retry::OrdinaryAttemptBindingRecord::new(
            request.into(),
            "decision".into(),
            "attempt".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        )
        .unwrap()
    }

    fn snapshot_refusal(request: &str, revision: u64) -> orbit_engine::retry::RefusalRecord {
        let intent = intent(request, AttemptPurpose::Ordinary);
        let reference = AttemptRef {
            revision: AccountingRevision(revision),
            request_id: request.into(),
            intent_digest: intent.digest().unwrap(),
        };
        orbit_engine::retry::RefusalRecord::new(
            intent,
            reference,
            snapshot_binding(request),
            "9".repeat(64),
            503,
            65_536,
        )
        .unwrap()
    }

    fn snapshot_container() -> Container {
        let record = snapshot_refusal("refused", 1);
        let rollup = orbit_engine::retry::RefusalRollup::first(record.clone()).unwrap();
        Container {
            version: 1,
            owner: "owner".into(),
            entries: vec![Entry {
                namespace: Namespace::Owner,
                revision: 2,
                baseline: Baseline::FreshKnownZero,
                totals: Delta::from_public(&record.totals_after(&AccountingDelta::known_zero())),
                pending: None,
                last: Some(Settlement {
                    reference: Reference::from_public(record.attempt()),
                    receipt: None,
                    refused: Some(RefusalRecord::from_public(&record)),
                }),
                known_priced_subtotals: Some(PricedSubtotals::from_public(
                    KnownPricedSubtotals::known_zero(),
                )),
                refusals: Some(RefusalRollup::from_public(&rollup)),
            }],
        }
    }

    fn snapshot_bytes(container: &Container) -> Vec<u8> {
        encode(
            container,
            MAX_ACCOUNTING_CHECKPOINT_BYTES,
            HistoryError::Full,
        )
        .unwrap()
    }

    fn assert_bad_snapshot(value: serde_json::Value) {
        // Re-encode through the strict private structs to restore canonical key
        // order. Failure therefore proves validation, not just map key ordering.
        match serde_json::from_value::<Container>(value) {
            Err(_) => {}
            Ok(container) => {
                assert!(decode_container(&snapshot_bytes(&container), "owner").is_err())
            }
        }
    }

    #[test]
    fn detailed_legacy_projection_preserves_exact_private_bytes_and_inspection_domain() {
        let tree = Tree::new();
        let journal = tree.journal();
        let checkpoint = journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let raw = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        assert_eq!(
            String::from_utf8(raw.clone()).unwrap(),
            "{\"version\":1,\"owner\":\"owner\",\"entries\":[{\"namespace\":{\"kind\":\"owner\"},\"revision\":0,\"baseline\":\"fresh_known_zero\",\"totals\":{\"ordinary\":{\"input_tokens\":0,\"output_tokens\":0,\"cost_microcents\":0},\"housekeeping\":{\"input_tokens\":0,\"output_tokens\":0,\"cost_microcents\":0},\"knownness\":\"known\"},\"pending\":null,\"last\":null,\"known_priced_subtotals\":{\"ordinary_microcents\":0,\"housekeeping_microcents\":0}}]}"
        );
        let before = recovery_tree_fingerprints(&tree.home);
        let legacy = inspect_accounting(&tree.home, "owner", None).unwrap();
        let detailed = inspect_accounting_detailed(&tree.home, "owner", None).unwrap();
        assert!(detailed.checkpoint.legacy_equivalent(&checkpoint));
        assert_eq!(detailed.inspection_digest, legacy.inspection_digest);
        assert_eq!(detailed.pending_receipt, legacy.pending_receipt);
        assert_eq!(detailed.last_legacy_receipt, legacy.last_receipt);
        assert_eq!(
            detailed.qualification,
            InspectionQualification::VisibleValidated
        );
        let mut hash = Sha256::new();
        hash.update(b"orbit-accounting-inspection-private-codec-v1\0");
        for field in [b"owner".as_slice(), b"".as_slice(), raw.as_slice()] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
        assert_eq!(detailed.inspection_digest, hex::encode(hash.finalize()));
        assert_eq!(
            journal.accounting_checkpoint_detailed().unwrap(),
            detailed.checkpoint
        );
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
    }

    #[test]
    fn qualified_pending_is_detailed_only_and_legacy_sibling_keeps_working() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let request = intent("qualified", AttemptPurpose::Ordinary);
        let reference = journal
            .begin_attempt(AccountingRevision(0), &request)
            .unwrap();
        let layout = journal.layout(false).unwrap();
        let mut container = load_container(&layout.owner, "owner").unwrap().unwrap();
        container.entries[0].pending.as_mut().unwrap().retry_binding =
            Some(RetryBinding::from_public(&snapshot_binding("qualified")));
        let child = ulid::Ulid::new().to_string();
        container.entries.push(empty_entry(child.clone()));
        journal.save(&layout, &container).unwrap();
        let before = recovery_tree_fingerprints(&tree.home);
        assert_eq!(
            inspect_accounting(&tree.home, "owner", None),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            journal.accounting_checkpoint(),
            Err(HistoryError::InvalidRecord)
        );
        let detailed = inspect_accounting_detailed(&tree.home, "owner", None).unwrap();
        assert_eq!(detailed.checkpoint.pending().unwrap().reference, reference);
        assert!(detailed.checkpoint.refusals().is_none());
        assert!(detailed.last_legacy_receipt.is_none());
        assert!(inspect_accounting(&tree.home, "owner", Some(&child)).is_ok());
        assert!(
            inspect_accounting_detailed(&tree.home, "owner", Some(&child))
                .unwrap()
                .checkpoint
                .legacy_equivalent(
                    &inspect_accounting(&tree.home, "owner", Some(&child))
                        .unwrap()
                        .checkpoint
                )
        );
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                detailed.checkpoint.revision(),
                &detailed.inspection_digest
            ),
            Err(HistoryError::InvalidRecord)
        ));
        let capture = capture_for_recovery_detailed(
            &tree._lease,
            detailed.checkpoint.revision(),
            &detailed.inspection_digest,
        )
        .unwrap();
        capture.verify_unchanged(&tree._lease).unwrap();
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
    }

    #[test]
    fn refusal_union_keeps_unknown_bill_and_latest_proof_after_legacy_success() {
        let mut container = snapshot_container();
        let bytes = snapshot_bytes(&container);
        let decoded = decode_container(&bytes, "owner").unwrap();
        let inspected = inspection_detailed_from_container(&decoded, "owner", None).unwrap();
        assert!(matches!(
            inspected.checkpoint.last_settlement(),
            Some(DetailedLastSettlement::FinalRefusal(_))
        ));
        assert_eq!(
            inspected.checkpoint.totals().knownness,
            AccountingKnownness::UnknownUsage
        );
        assert_eq!(
            inspected.checkpoint.totals().ordinary,
            AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None
            }
        );
        assert_eq!(
            inspected.checkpoint.known_priced_subtotals(),
            Some(KnownPricedSubtotals::known_zero())
        );
        assert!(inspected.last_legacy_receipt.is_none());
        assert_eq!(
            inspection_from_container(&decoded, "owner", None),
            Err(HistoryError::InvalidRecord)
        );
        let receipt = RequestAccountingReceipt {
            request_id: "success".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 7,
                output_tokens: 11,
                cost_microcents: Some(13),
            },
            usage: Some(ProviderUsage {
                input_tokens: 7,
                output_tokens: 11,
                ..Default::default()
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        let entry = &mut container.entries[0];
        entry.revision = 4;
        entry.totals =
            Delta::from_public(&entry.totals.to_public().checked_with(&receipt).unwrap());
        entry.known_priced_subtotals = Some(PricedSubtotals::from_public(
            entry
                .known_priced_subtotals
                .as_ref()
                .unwrap()
                .to_public()
                .checked_with(&receipt)
                .unwrap(),
        ));
        entry.last = Some(Settlement {
            reference: Reference {
                revision: 3,
                request_id: "success".into(),
                intent_digest: "1".repeat(64),
            },
            receipt: Some(Receipt::from_public(&receipt)),
            refused: None,
        });
        let decoded = decode_container(&snapshot_bytes(&container), "owner").unwrap();
        let later = inspection_detailed_from_container(&decoded, "owner", None).unwrap();
        assert!(matches!(
            later.checkpoint.last_settlement(),
            Some(DetailedLastSettlement::Legacy(_))
        ));
        assert_eq!(later.last_legacy_receipt, Some(receipt));
        assert_eq!(later.checkpoint.totals().ordinary.cost_microcents, None);
        assert_eq!(
            later
                .checkpoint
                .known_priced_subtotals()
                .unwrap()
                .ordinary_microcents,
            13
        );
        assert_eq!(later.checkpoint.refusals(), inspected.checkpoint.refusals());
    }

    #[test]
    fn strict_refusal_codec_rejects_union_scope_binding_chain_and_qualification_tampering() {
        let canonical = serde_json::to_value(snapshot_container()).unwrap();
        let mutate = |pointer: &str, replacement: serde_json::Value| {
            let mut value = canonical.clone();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert_bad_snapshot(value);
        };
        let zero = RequestAccountingReceipt {
            request_id: "refused".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals::known_zero(),
            usage: None,
            knownness: AccountingKnownness::Known,
            completed: false,
        };
        let mut both = canonical.clone();
        both["entries"][0]["last"]["receipt"] =
            serde_json::to_value(Receipt::from_public(&zero)).unwrap();
        assert_bad_snapshot(both);
        let mut neither = canonical.clone();
        neither["entries"][0]["last"]
            .as_object_mut()
            .unwrap()
            .remove("refused");
        assert_bad_snapshot(neither);
        let mut missing = canonical.clone();
        missing["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("refusals");
        assert_bad_snapshot(missing);
        mutate(
            "/entries/0/last/refused/binding/body_digest",
            serde_json::json!("0".repeat(64)),
        );
        mutate(
            "/entries/0/last/refused/intent/owner_session_id",
            serde_json::json!("foreign"),
        );
        mutate(
            "/entries/0/last/refused/attempt/revision",
            serde_json::json!(2),
        );
        mutate("/entries/0/last/refused/status", serde_json::json!(401));
        mutate(
            "/entries/0/last/refused/response_body_bytes",
            serde_json::json!(65_537),
        );
        mutate("/entries/0/refusals/count", serde_json::json!(0));
        // Count-only tampering is an invalid digest control, not execution of
        // the valid-MAX-chain admission branch guarded before qualified begin.
        mutate("/entries/0/refusals/count", serde_json::json!(u64::MAX));
        mutate(
            "/entries/0/refusals/chain_digest",
            serde_json::json!("0".repeat(64)),
        );
        mutate(
            "/entries/0/refusals/latest/binding/policy_digest",
            serde_json::json!("0".repeat(64)),
        );
        mutate("/entries/0/totals/knownness", serde_json::json!("known"));
        mutate(
            "/entries/0/totals/ordinary/cost_microcents",
            serde_json::json!(0),
        );
        let raw = String::from_utf8(snapshot_bytes(&snapshot_container())).unwrap();
        let duplicate = raw.replacen("\"status\":503", "\"status\":503,\"status\":503", 1);
        assert!(decode_container(duplicate.as_bytes(), "owner").is_err());
        let extension = raw.replacen("\"status\":503", "\"status\":503,\"retry\":true", 1);
        assert!(decode_container(extension.as_bytes(), "owner").is_err());
        assert!(decode_container(format!(" {raw}").as_bytes(), "owner").is_err());
        let original = snapshot_refusal("foreign", 1);
        let mut foreign_intent = original.intent().clone();
        foreign_intent.owner_session_id = "other-owner".into();
        let foreign_ref = AttemptRef {
            revision: AccountingRevision(1),
            request_id: "foreign".into(),
            intent_digest: foreign_intent.digest().unwrap(),
        };
        let foreign = orbit_engine::retry::RefusalRecord::new(
            foreign_intent,
            foreign_ref.clone(),
            snapshot_binding("foreign"),
            "9".repeat(64),
            503,
            0,
        )
        .unwrap();
        let foreign_rollup = orbit_engine::retry::RefusalRollup::first(foreign.clone()).unwrap();
        let mut wrong_scope = snapshot_container();
        wrong_scope.entries[0].last = Some(Settlement {
            reference: Reference::from_public(&foreign_ref),
            receipt: None,
            refused: Some(RefusalRecord::from_public(&foreign)),
        });
        wrong_scope.entries[0].refusals = Some(RefusalRollup::from_public(&foreign_rollup));
        assert!(decode_container(&snapshot_bytes(&wrong_scope), "owner").is_err());
    }

    #[test]
    fn checked_refusal_dto_bounds_and_maximum_size_model_are_separate() {
        use orbit_engine::retry::{
            MAX_ATTEMPT_BINDING_RECORD_BYTES, MAX_REFUSAL_RECORD_BYTES, MAX_REFUSAL_ROLLUP_BYTES,
            OrdinaryAttemptBindingRecord, RefusalRecord as CheckedRecord,
        };
        let mut request = intent(&"r".repeat(256), AttemptPurpose::Ordinary);
        request.owner_session_id = "o".repeat(128);
        request.child_id = Some("00000000000000000000000001".into());
        request.budget.metadata_revision = "\\".repeat(256);
        request.budget.policy_revision = "\"".repeat(256);
        let binding = OrdinaryAttemptBindingRecord::new(
            request.request_id.clone(),
            "d".repeat(256),
            "a".repeat(256),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        )
        .unwrap();
        let reference = AttemptRef {
            revision: AccountingRevision(u64::MAX - 1),
            request_id: request.request_id.clone(),
            intent_digest: request.digest().unwrap(),
        };
        let record = CheckedRecord::new(
            request.clone(),
            reference,
            binding.clone(),
            "9".repeat(64),
            529,
            65_536,
        )
        .unwrap();
        let stored = RefusalRecord::from_public(&record);
        assert_eq!(stored.to_public().unwrap(), record);
        assert!(
            encode(
                &stored,
                MAX_REFUSAL_RECORD_BYTES,
                HistoryError::InvalidRecord
            )
            .unwrap()
            .len()
                <= MAX_REFUSAL_RECORD_BYTES
        );
        assert!(
            encode(
                &RetryBinding::from_public(&binding),
                MAX_ATTEMPT_BINDING_RECORD_BYTES,
                HistoryError::InvalidRecord
            )
            .is_ok()
        );
        let rollup = orbit_engine::retry::RefusalRollup::first(record).unwrap();
        let stored_rollup = RefusalRollup::from_public(&rollup);
        assert_eq!(stored_rollup.to_public().unwrap(), rollup);
        assert!(
            encode(
                &stored_rollup,
                MAX_REFUSAL_ROLLUP_BYTES,
                HistoryError::InvalidRecord
            )
            .is_ok()
        );
        let mut value = serde_json::to_value(stored).unwrap();
        value["binding"]["decision_id"] = serde_json::json!("d".repeat(257));
        assert!(
            serde_json::from_value::<RefusalRecord>(value)
                .unwrap()
                .to_public()
                .is_err()
        );
        let base = snapshot_container();
        assert!(
            refusal::maximum_entry_size(&base.entries[0], MAX_ACCOUNTING_CHECKPOINT_BYTES).unwrap()
                > encode(
                    &base.entries[0],
                    MAX_ACCOUNTING_CHECKPOINT_BYTES,
                    HistoryError::Full
                )
                .unwrap()
                .len()
        );
    }

    #[test]
    fn detailed_refusal_capture_is_inert_held_source_bound_and_rechecks_both_projections() {
        let tree = Tree::new();
        let journal = tree.journal();
        let layout = journal.layout(false).unwrap();
        journal.save(&layout, &snapshot_container()).unwrap();
        let raw = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let inspected = inspect_accounting_detailed(&tree.home, "owner", None).unwrap();
        let before = recovery_tree_fingerprints(&tree.home);
        let capture = capture_for_recovery_detailed(
            &tree._lease,
            inspected.checkpoint.revision(),
            &inspected.inspection_digest,
        )
        .unwrap();
        assert_eq!(capture.inspection(), &inspected);
        assert_eq!(capture.accounting_bytes(), raw);
        assert_eq!(
            capture.accounting_sha256(),
            hex::encode(Sha256::digest(&raw))
        );
        assert!(capture.archives().is_empty());
        capture.verify_unchanged(&tree._lease).unwrap();
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
        assert!(matches!(
            capture_for_recovery(
                &tree._lease,
                inspected.checkpoint.revision(),
                &inspected.inspection_digest
            ),
            Err(HistoryError::InvalidRecord)
        ));
        let other = Tree::new();
        assert_eq!(
            capture.verify_unchanged(&other._lease),
            Err(HistoryError::Unsafe)
        );
        assert!(matches!(
            capture_for_recovery_detailed(
                &tree._lease,
                AccountingRevision(3),
                &inspected.inspection_digest
            ),
            Err(HistoryError::Conflict)
        ));
        assert!(matches!(
            capture_for_recovery_detailed(
                &tree._lease,
                inspected.checkpoint.revision(),
                &"0".repeat(64)
            ),
            Err(HistoryError::Conflict)
        ));
        assert!(matches!(
            capture_for_recovery_detailed(&tree._lease, inspected.checkpoint.revision(), "bad"),
            Err(HistoryError::InvalidRecord)
        ));
        // Same valid payload through a replacement inode still invalidates a
        // held source. Verification must not just compare parsed counters.
        publish(&layout.owner, ACCOUNTING, &raw, false).unwrap();
        assert_eq!(
            capture.verify_unchanged(&tree._lease),
            Err(HistoryError::Conflict)
        );
    }

    #[test]
    fn detailed_reader_preserves_unknown_legacy_and_actual_uncertain_precedence() {
        let mut container = snapshot_container();
        container.entries[0].baseline = Baseline::UnknownLegacy;
        container.entries[0].totals = Delta::from_public(
            &snapshot_refusal("refused", 1).totals_after(&AccountingDelta::unknown_legacy()),
        );
        let decoded = decode_container(&snapshot_bytes(&container), "owner").unwrap();
        assert_eq!(
            decoded.entries[0]
                .checkpoint_detailed("owner")
                .unwrap()
                .totals()
                .knownness,
            AccountingKnownness::UnknownLegacy
        );
        let request = intent("pending", AttemptPurpose::Ordinary);
        let reference = AttemptRef {
            revision: AccountingRevision(3),
            request_id: request.request_id.clone(),
            intent_digest: request.digest().unwrap(),
        };
        let receipt = RequestAccountingReceipt {
            request_id: request.request_id.clone(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: None,
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        };
        container.entries[0].revision = 4;
        container.entries[0].totals = Delta::from_public(
            &container.entries[0]
                .totals
                .to_public()
                .checked_with(&receipt)
                .unwrap(),
        );
        container.entries[0].pending = Some(Pending {
            reference: Reference::from_public(&reference),
            intent: Intent::from_public(&request),
            uncertain_receipt: Some(Receipt::from_public(&receipt)),
            retry_binding: None,
        });
        let decoded = decode_container(&snapshot_bytes(&container), "owner").unwrap();
        let inspected = inspection_detailed_from_container(&decoded, "owner", None).unwrap();
        assert_eq!(
            inspected.checkpoint.totals().knownness,
            AccountingKnownness::Uncertain
        );
        assert!(inspected.checkpoint.pending().unwrap().uncertain);
        assert_eq!(inspected.pending_receipt, Some(receipt));
        assert_eq!(inspected.checkpoint.refusals().unwrap().count(), 1);
    }

    #[test]
    fn legacy_mutations_refuse_selected_retry_metadata_without_changing_disk() {
        let tree = Tree::new();
        let journal = tree.journal();
        let layout = journal.layout(false).unwrap();
        let container = snapshot_container();
        journal.save(&layout, &container).unwrap();
        let original = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        assert_eq!(
            journal.begin_attempt(
                AccountingRevision(2),
                &intent("new", AttemptPurpose::Ordinary)
            ),
            Err(HistoryError::InvalidRecord)
        );
        let receipt = RequestAccountingReceipt {
            request_id: "refused".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals::known_zero(),
            usage: None,
            knownness: AccountingKnownness::Known,
            completed: false,
        };
        assert_eq!(
            journal.settle_attempt(snapshot_refusal("refused", 1).attempt(), &receipt),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            original
        );
        assert!(journal.accounting_checkpoint_detailed().is_ok());
    }
    #[test]
    fn qualified_pending_reserves_maximum_whole_refusal_entry_and_siblings_before_send() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let mut request = intent(&"r".repeat(256), AttemptPurpose::Ordinary);
        request.budget.metadata_revision = "\\\"".repeat(128);
        request.budget.policy_revision = "\\\"".repeat(128);
        let _reference = journal
            .begin_attempt(AccountingRevision(0), &request)
            .unwrap();
        let layout = journal.layout(false).unwrap();
        let mut container = load_container(&layout.owner, "owner").unwrap().unwrap();
        container.entries[0].pending.as_mut().unwrap().retry_binding = Some(
            RetryBinding::from_public(&snapshot_binding(&request.request_id)),
        );
        let mut sibling_intent = request.clone();
        let sibling_id = ulid::Ulid::new().to_string();
        sibling_intent.child_id = Some(sibling_id.clone());
        sibling_intent.request_id = "sibling".into();
        let mut sibling = empty_entry(sibling_id);
        sibling.revision = 1;
        sibling.pending = Some(Pending {
            reference: Reference {
                revision: 1,
                request_id: sibling_intent.request_id.clone(),
                intent_digest: sibling_intent.digest().unwrap(),
            },
            intent: Intent::from_public(&sibling_intent),
            uncertain_receipt: None,
            retry_binding: Some(RetryBinding::from_public(&snapshot_binding("sibling"))),
        });
        container.entries.push(sibling);
        let mut tuner = empty_entry(ulid::Ulid::new().to_string());
        let zero = RequestAccountingReceipt {
            request_id: "t".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals::known_zero(),
            usage: Some(ProviderUsage::default()),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        tuner.revision = 2;
        tuner.last = Some(Settlement {
            reference: Reference {
                revision: 1,
                request_id: "t".into(),
                intent_digest: "b".repeat(64),
            },
            receipt: Some(Receipt::from_public(&zero)),
            refused: None,
        });
        container.entries.push(tuner);
        loop {
            let filler = empty_entry(ulid::Ulid::new().to_string());
            container.entries.push(filler);
            if reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES).is_err() {
                container.entries.pop();
                break;
            }
        }
        let current = reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES).unwrap();
        let remainder = MAX_ACCOUNTING_CHECKPOINT_BYTES - current;
        let tuner = &mut container.entries[2];
        if !remainder.is_multiple_of(2) {
            tuner.totals.ordinary.input_tokens = 10;
        }
        let pad = remainder / 2;
        assert!(pad < 256);
        let last = tuner.last.as_mut().unwrap();
        last.reference.request_id.push_str(&"t".repeat(pad));
        last.receipt.as_mut().unwrap().request_id = last.reference.request_id.clone();
        validate_container(&container, "owner").unwrap();
        assert_eq!(
            reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES).unwrap(),
            MAX_ACCOUNTING_CHECKPOINT_BYTES
        );
        let actual = encode(
            &container,
            MAX_ACCOUNTING_CHECKPOINT_BYTES,
            HistoryError::Full,
        )
        .unwrap();
        assert!(actual.len() < MAX_ACCOUNTING_CHECKPOINT_BYTES);
        journal.save(&layout, &container).unwrap();
        let original = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let child_id = ulid::Ulid::new().to_string();
        let child = Journal::open(&tree.home, "owner", Some(&child_id)).unwrap();
        assert_eq!(
            child.initialize_accounting(AccountingBaseline::FreshKnownZero),
            Err(HistoryError::Full)
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            original
        );
        let mut over = container.clone();
        // One extra decimal digit consumes exactly one extra encoded byte.
        over.entries[2].totals.ordinary.output_tokens = 10;
        assert_eq!(
            reservation_size(&over, MAX_ACCOUNTING_CHECKPOINT_BYTES),
            Err(HistoryError::Full)
        );
        assert_eq!(journal.save(&layout, &over), Err(HistoryError::Full));
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            original
        );
        let decoded = decode_container(&original, "owner").unwrap();
        assert_eq!(snapshot_bytes(&decoded), original);
        assert!(
            journal
                .accounting_checkpoint_detailed()
                .unwrap()
                .pending()
                .is_some()
        );
        assert_eq!(
            journal.accounting_checkpoint(),
            Err(HistoryError::InvalidRecord)
        );
        let mut unqualified = container.clone();
        unqualified.entries[0]
            .pending
            .as_mut()
            .unwrap()
            .retry_binding = None;
        unqualified.entries[1]
            .pending
            .as_mut()
            .unwrap()
            .retry_binding = None;
        assert!(
            reservation_size(&unqualified, MAX_ACCOUNTING_CHECKPOINT_BYTES).unwrap()
                < MAX_ACCOUNTING_CHECKPOINT_BYTES
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            original
        );
    }
    // Complete real Journal operations with checked snapshot RECORD input only.
    // These component fixtures do not mint live engine or transport authority.
    fn begin_checked_component(
        journal: &Journal,
        request: &AttemptIntent,
        revision: u64,
    ) -> (AttemptRef, orbit_engine::retry::RefusalRecord) {
        let binding = snapshot_binding(&request.request_id);
        let reference = journal
            .begin_operation(AccountingRevision(revision), request, Some(&binding), false)
            .unwrap();
        let record = orbit_engine::retry::RefusalRecord::new(
            request.clone(),
            reference.clone(),
            binding,
            "9".repeat(64),
            503,
            0,
        )
        .unwrap();
        (reference, record)
    }

    #[test]
    fn real_qualified_refusal_operation_reacks_only_current_full_record_without_publication() {
        let tree = Tree::new();
        let journal = tree.journal();
        let initial = journal
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let (attempt, record) = begin_checked_component(
            &journal,
            &intent("refused-real", AttemptPurpose::Ordinary),
            initial.revision().0,
        );
        let pending = journal.accounting_checkpoint_detailed().unwrap();
        assert_eq!(pending.pending().unwrap().reference, attempt);
        assert_eq!(
            journal.accounting_checkpoint(),
            Err(HistoryError::InvalidRecord)
        );
        let ack = journal.settle_refusal_record(&attempt, &record).unwrap();
        assert_eq!(ack.attempt(), &attempt);
        assert_eq!(ack.binding(), record.binding());
        assert_eq!(ack.settlement_digest(), record.digest());
        assert_eq!(ack.observation_digest(), record.observation_digest());
        assert_eq!(ack.checkpoint().refusals().unwrap().count(), 1);
        assert_eq!(
            ack.checkpoint().totals().ordinary,
            AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None
            }
        );
        assert_eq!(
            ack.checkpoint().totals().knownness,
            AccountingKnownness::UnknownUsage
        );
        assert_eq!(
            ack.checkpoint().known_priced_subtotals(),
            initial.known_priced_subtotals()
        );
        let before = recovery_tree_fingerprints(&tree.home);
        let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = published.clone();
        let repeated = with_test_hook(
            move |_, _| {
                observed.fetch_add(1, Ordering::SeqCst);
            },
            || journal.settle_refusal_record(&attempt, &record),
        )
        .unwrap();
        assert_eq!(repeated, ack);
        assert_eq!(published.load(Ordering::SeqCst), 0);
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
        let mismatch = orbit_engine::retry::RefusalRecord::new(
            record.intent().clone(),
            attempt.clone(),
            record.binding().clone(),
            "8".repeat(64),
            503,
            1,
        )
        .unwrap();
        assert_eq!(
            journal.settle_refusal_record(&attempt, &mismatch),
            Err(HistoryError::Conflict)
        );
        assert_eq!(recovery_tree_fingerprints(&tree.home), before);
        let next = journal
            .begin_attempt_detailed(
                AccountingRevision(2),
                &intent("new-explicit-prompt", AttemptPurpose::Ordinary),
                None,
            )
            .unwrap();
        assert_eq!(
            journal.settle_refusal_record(&attempt, &record),
            Err(HistoryError::StaleNonApplying)
        );
        let receipt = receipt("new-explicit-prompt", AttemptPurpose::Ordinary);
        let settled = journal.settle_attempt_detailed(&next, &receipt).unwrap();
        assert_eq!(
            settled.totals().ordinary.input_tokens,
            receipt.totals.input_tokens
        );
        assert_eq!(
            settled.totals().ordinary.output_tokens,
            receipt.totals.output_tokens
        );
        assert_eq!(settled.totals().ordinary.cost_microcents, None);
        assert_eq!(
            settled
                .known_priced_subtotals()
                .unwrap()
                .ordinary_microcents,
            receipt.totals.cost_microcents.unwrap()
        );
        assert_eq!(settled.refusals(), ack.checkpoint().refusals());
        assert_eq!(
            journal.settle_attempt_detailed(&next, &receipt).unwrap(),
            settled
        );
        assert_eq!(
            journal.settle_refusal_record(&attempt, &record),
            Err(HistoryError::StaleNonApplying)
        );
        let layout = journal.layout(false).unwrap();
        let stored = load_container(&layout.owner, "owner").unwrap().unwrap();
        assert_eq!(
            stored.entries[0]
                .last
                .as_ref()
                .unwrap()
                .receipt
                .as_ref()
                .unwrap()
                .usage
                .as_ref()
                .unwrap()
                .to_public(),
            receipt.usage.unwrap()
        );
        let (third, third_record) = begin_checked_component(
            &journal,
            &intent("second-refusal", AttemptPurpose::Ordinary),
            4,
        );
        let repeated_refusal = journal
            .settle_refusal_record(&third, &third_record)
            .unwrap();
        assert_eq!(repeated_refusal.checkpoint().refusals().unwrap().count(), 2);
        assert_eq!(repeated_refusal.checkpoint().totals(), settled.totals());
        assert_eq!(
            repeated_refusal.checkpoint().known_priced_subtotals(),
            settled.known_priced_subtotals()
        );
    }

    #[test]
    fn qualified_begin_and_refusal_require_exact_scope_cas_intent_binding_and_pending() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let original = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let request = intent("qualified-real", AttemptPurpose::Ordinary);
        let binding = snapshot_binding("qualified-real");
        assert_eq!(
            journal.begin_operation(AccountingRevision(1), &request, Some(&binding), false),
            Err(HistoryError::Conflict)
        );
        assert_eq!(
            journal.begin_operation(
                AccountingRevision(u64::MAX - 1),
                &request,
                Some(&binding),
                false
            ),
            Err(HistoryError::TooLarge)
        );
        assert_eq!(
            journal.begin_operation(
                AccountingRevision(0),
                &request,
                Some(&snapshot_binding("wrong-request")),
                false
            ),
            Err(HistoryError::InvalidRecord)
        );
        let mut wrong = request.clone();
        wrong.owner_session_id = "foreign".into();
        assert_eq!(
            journal.begin_operation(AccountingRevision(0), &wrong, Some(&binding), false),
            Err(HistoryError::InvalidRecord)
        );
        wrong = request.clone();
        wrong.purpose = AttemptPurpose::Chunk;
        assert_eq!(
            journal.begin_operation(AccountingRevision(0), &wrong, Some(&binding), false),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            original
        );
        let (attempt, record) = begin_checked_component(&journal, &request, 0);
        let pending = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let other_binding = OrdinaryAttemptBindingRecord::new(
            request.request_id.clone(),
            "decision".into(),
            "attempt".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "1".repeat(64),
        )
        .unwrap();
        let mismatch = orbit_engine::retry::RefusalRecord::new(
            request.clone(),
            attempt.clone(),
            other_binding,
            "9".repeat(64),
            503,
            0,
        )
        .unwrap();
        assert_eq!(
            journal.settle_refusal_record(&attempt, &mismatch),
            Err(HistoryError::Conflict)
        );
        let mut different_intent = request.clone();
        different_intent.budget.policy_revision.push_str("-changed");
        let different_reference = AttemptRef {
            intent_digest: different_intent.digest().unwrap(),
            ..attempt.clone()
        };
        let different_record = orbit_engine::retry::RefusalRecord::new(
            different_intent,
            different_reference.clone(),
            binding.clone(),
            "9".repeat(64),
            503,
            0,
        )
        .unwrap();
        assert_eq!(
            journal.settle_refusal_record(&different_reference, &different_record),
            Err(HistoryError::Conflict)
        );
        assert_eq!(
            journal.settle_refusal_record(&different_reference, &record),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            pending
        );
        assert_eq!(
            journal.begin_attempt_detailed(AccountingRevision(1), &request, None),
            Err(HistoryError::Conflict)
        );
        journal.settle_refusal_record(&attempt, &record).unwrap();
        let unqualified = journal
            .begin_attempt_detailed(
                AccountingRevision(2),
                &intent("old-unqualified", AttemptPurpose::Ordinary),
                None,
            )
            .unwrap();
        let raw = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let record = orbit_engine::retry::RefusalRecord::new(
            intent("old-unqualified", AttemptPurpose::Ordinary),
            unqualified.clone(),
            snapshot_binding("old-unqualified"),
            "9".repeat(64),
            503,
            0,
        )
        .unwrap();
        assert_eq!(
            journal.settle_refusal_record(&unqualified, &record),
            Err(HistoryError::Conflict)
        );
        assert_eq!(std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(), raw);
    }

    #[test]
    fn detailed_uncertain_receipt_keeps_exact_qualified_binding_and_cannot_be_refused_later() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let (attempt, record) = begin_checked_component(
            &journal,
            &intent("uncertain-qualified", AttemptPurpose::Ordinary),
            0,
        );
        let receipt = RequestAccountingReceipt {
            request_id: attempt.request_id.clone(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(ProviderUsage {
                input_tokens: 19,
                output_tokens: 5,
                cache_read_tokens: 3,
                cache_write_tokens: 2,
                reasoning_tokens: 4,
            }),
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        };
        let checkpoint = journal.settle_attempt_detailed(&attempt, &receipt).unwrap();
        assert!(checkpoint.pending().unwrap().uncertain);
        assert!(checkpoint.refusals().is_none());
        let before = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        assert_eq!(
            journal.settle_attempt_detailed(&attempt, &receipt).unwrap(),
            checkpoint
        );
        assert_eq!(
            journal.settle_refusal_record(&attempt, &record),
            Err(HistoryError::Conflict)
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            before
        );
        let layout = journal.layout(false).unwrap();
        let container = load_container(&layout.owner, "owner").unwrap().unwrap();
        let pending = container.entries[0].pending.as_ref().unwrap();
        assert_eq!(
            pending.retry_binding.as_ref().unwrap().to_public().unwrap(),
            *record.binding()
        );
        assert_eq!(
            pending.uncertain_receipt.as_ref().unwrap().to_public(),
            receipt
        );
        let reopened = Journal::open(&tree.home, "owner", None).unwrap();
        assert_eq!(
            reopened.accounting_checkpoint_detailed().unwrap(),
            checkpoint
        );
        assert_eq!(
            reopened.begin_attempt_detailed(
                AccountingRevision(2),
                &intent("must-not-admit", AttemptPurpose::Ordinary),
                None
            ),
            Err(HistoryError::Conflict)
        );
    }

    #[test]
    fn qualified_begin_faults_keep_old_or_exact_pending_state_without_synthetic_settlement() {
        for point in [PublicationPoint::Staged, PublicationPoint::Published] {
            let tree = Tree::new();
            let journal = tree.journal();
            let before = journal
                .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
                .unwrap();
            let bytes = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
            let request = intent("begin-fault", AttemptPurpose::Ordinary);
            let binding = snapshot_binding("begin-fault");
            let result = displace(tree.owner(), point, || {
                journal.begin_operation(AccountingRevision(0), &request, Some(&binding), false)
            });
            let reopened = Journal::open(&tree.home, "owner", None).unwrap();
            let checkpoint = reopened.accounting_checkpoint_detailed().unwrap();
            if point == PublicationPoint::Staged {
                assert_eq!(result, Err(HistoryError::Unsafe));
                assert_eq!(checkpoint, before);
                assert_eq!(std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(), bytes);
            } else {
                assert_eq!(result, Err(HistoryError::Uncertain));
                assert_eq!(checkpoint.revision(), AccountingRevision(1));
                assert_eq!(checkpoint.pending().unwrap().intent, request);
                let layout = reopened.layout(false).unwrap();
                let loaded = load_container(&layout.owner, "owner").unwrap().unwrap();
                assert_eq!(
                    loaded.entries[0]
                        .pending
                        .as_ref()
                        .unwrap()
                        .retry_binding
                        .as_ref()
                        .unwrap()
                        .to_public()
                        .unwrap(),
                    binding
                );
                assert!(checkpoint.last_settlement().is_none());
                assert!(checkpoint.refusals().is_none());
                assert_eq!(
                    reopened.begin_operation(
                        AccountingRevision(0),
                        &request,
                        Some(&binding),
                        false
                    ),
                    Err(HistoryError::Conflict)
                );
            }
            assert!(!std::fs::read_dir(tree.owner()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".stage-")
            }));
        }
    }

    #[test]
    fn real_refusal_publication_faults_reopen_pending_or_settled_and_reack_without_doublefold() {
        for point in [PublicationPoint::Staged, PublicationPoint::Published] {
            let tree = Tree::new();
            let journal = tree.journal();
            journal
                .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
                .unwrap();
            let (attempt, record) = begin_checked_component(
                &journal,
                &intent("settle-fault", AttemptPurpose::Ordinary),
                0,
            );
            let pending_bytes = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
            let result = displace(tree.owner(), point, || {
                journal.settle_refusal_record(&attempt, &record)
            });
            let reopened = Journal::open(&tree.home, "owner", None).unwrap();
            let checkpoint = reopened.accounting_checkpoint_detailed().unwrap();
            if point == PublicationPoint::Staged {
                assert_eq!(result, Err(HistoryError::Unsafe));
                assert!(checkpoint.pending().is_some());
                assert!(checkpoint.refusals().is_none());
                assert_eq!(
                    std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
                    pending_bytes
                );
            } else {
                assert_eq!(result, Err(HistoryError::Uncertain));
                assert!(checkpoint.pending().is_none());
                assert_eq!(checkpoint.refusals().unwrap().latest(), &record);
                assert_eq!(checkpoint.refusals().unwrap().count(), 1);
            }
            let ack = reopened.settle_refusal_record(&attempt, &record).unwrap();
            let settled_bytes = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
            assert_eq!(
                reopened.settle_refusal_record(&attempt, &record).unwrap(),
                ack
            );
            assert_eq!(ack.checkpoint().refusals().unwrap().count(), 1);
            assert_eq!(ack.checkpoint().totals().ordinary.input_tokens, 0);
            assert_eq!(
                ack.checkpoint().known_priced_subtotals(),
                Some(KnownPricedSubtotals::known_zero())
            );
            assert_eq!(
                std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
                settled_bytes
            );
            assert!(!std::fs::read_dir(tree.owner()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".stage-")
            }));
        }
    }

    #[test]
    fn later_detailed_receipt_publication_uncertainty_keeps_refusal_and_exact_counter_fold() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let (attempt, record) = begin_checked_component(
            &journal,
            &intent("earlier-refusal", AttemptPurpose::Ordinary),
            0,
        );
        journal.settle_refusal_record(&attempt, &record).unwrap();
        let later = journal
            .begin_attempt_detailed(
                AccountingRevision(2),
                &intent("later-success", AttemptPurpose::Ordinary),
                None,
            )
            .unwrap();
        let receipt = receipt("later-success", AttemptPurpose::Ordinary);
        let result = displace(tree.owner(), PublicationPoint::Published, || {
            journal.settle_attempt_detailed(&later, &receipt)
        });
        assert_eq!(result, Err(HistoryError::Uncertain));
        let reopened = Journal::open(&tree.home, "owner", None).unwrap();
        let checkpoint = reopened.accounting_checkpoint_detailed().unwrap();
        assert_eq!(
            checkpoint.totals().ordinary.input_tokens,
            receipt.totals.input_tokens
        );
        assert_eq!(
            checkpoint
                .known_priced_subtotals()
                .unwrap()
                .ordinary_microcents,
            17
        );
        assert_eq!(checkpoint.refusals().unwrap().latest(), &record);
        assert_eq!(
            reopened.settle_attempt_detailed(&later, &receipt).unwrap(),
            checkpoint
        );
    }

    #[test]
    fn actual_qualified_begin_reserves_whole_entry_before_save_and_counter_overflow_keeps_pending()
    {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let layout = journal.layout(false).unwrap();
        let mut container = load_container(&layout.owner, "owner").unwrap().unwrap();
        for _ in 0..1024 {
            container
                .entries
                .push(empty_entry(ulid::Ulid::new().to_string()));
            if reservation_size(&container, MAX_ACCOUNTING_CHECKPOINT_BYTES).is_err() {
                container.entries.pop();
                break;
            }
        }
        journal.save(&layout, &container).unwrap();
        let before = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        let request = intent("quota-before-send", AttemptPurpose::Ordinary);
        assert_eq!(
            journal.begin_operation(
                AccountingRevision(0),
                &request,
                Some(&snapshot_binding(&request.request_id)),
                false
            ),
            Err(HistoryError::Full)
        );
        assert_eq!(
            std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(),
            before
        );
        let other = Tree::new();
        let journal = other.journal();
        journal
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let first = journal
            .begin_attempt_detailed(
                AccountingRevision(0),
                &intent("maximum", AttemptPurpose::Ordinary),
                None,
            )
            .unwrap();
        let maximum = RequestAccountingReceipt {
            request_id: "maximum".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: u64::MAX,
                output_tokens: u64::MAX,
                cost_microcents: Some(u64::MAX),
            },
            usage: Some(ProviderUsage {
                input_tokens: u64::MAX,
                output_tokens: u64::MAX,
                ..Default::default()
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        journal.settle_attempt_detailed(&first, &maximum).unwrap();
        let (attempt, record) = begin_checked_component(
            &journal,
            &intent("refuse-after-maximum", AttemptPurpose::Ordinary),
            2,
        );
        let ack = journal.settle_refusal_record(&attempt, &record).unwrap();
        assert_eq!(
            ack.checkpoint()
                .known_priced_subtotals()
                .unwrap()
                .ordinary_microcents,
            u64::MAX
        );
        let next = journal
            .begin_attempt_detailed(
                AccountingRevision(4),
                &intent("overflows", AttemptPurpose::Ordinary),
                None,
            )
            .unwrap();
        let before = std::fs::read(other.owner().join(ACCOUNTING)).unwrap();
        assert_eq!(
            journal.settle_attempt_detailed(&next, &receipt("overflows", AttemptPurpose::Ordinary)),
            Err(HistoryError::TooLarge)
        );
        assert_eq!(
            std::fs::read(other.owner().join(ACCOUNTING)).unwrap(),
            before
        );
        assert!(
            journal
                .accounting_checkpoint_detailed()
                .unwrap()
                .pending()
                .is_some()
        );
    }

    #[test]
    fn actual_refusal_root_reconcile_restart_preserves_fresh_and_legacy_numeric_prefixes() {
        use crate::session_accounting::{
            AccountingError, FullCostStatus, NamespaceSpendPolicy, RootOrigin, prepare_root,
        };
        use crate::sessions::SessionFile;
        for legacy in [false, true] {
            let tree = Tree::new();
            let (input, output, price) = if legacy { (100, 40, 60) } else { (0, 0, 0) };
            let mut saved = SessionFile::from_chat(
                "owner",
                "synthetic",
                "http://127.0.0.1:9",
                "provider",
                &[],
                0,
                input,
                output,
                price,
            );
            let accounting = prepare_root(
                &tree._lease,
                &mut saved,
                if legacy {
                    RootOrigin::RestoredOrLegacy
                } else {
                    RootOrigin::FreshCandidate
                },
            )
            .unwrap();
            let journal = tree.journal();
            let (attempt, record) = begin_checked_component(
                &journal,
                &intent("retained-before-restart", AttemptPurpose::Ordinary),
                0,
            );
            journal.settle_refusal_record(&attempt, &record).unwrap();
            let view = accounting.persist(&tree._lease, &mut saved).unwrap();
            assert_eq!(
                (
                    view.input_tokens,
                    view.output_tokens,
                    view.known_cost_microcents
                ),
                (input, output, price)
            );
            assert_eq!(
                view.full_cost_status,
                if legacy {
                    FullCostStatus::UnknownLegacy
                } else {
                    FullCostStatus::UnknownUsage
                }
            );
            assert!(accounting.namespace().checkpoint().is_err());
            let mut options = orbit_engine::TurnOptions {
                session_id: "owner".into(),
                ..Default::default()
            };
            assert!(
                accounting
                    .namespace()
                    .apply_options(&mut options, None)
                    .is_err()
            );
            assert!(options.journal.is_none());
            accounting
                .namespace()
                .apply_options_detailed(&mut options, None, None)
                .unwrap();
            assert!(options.journal.is_some() && options.spend_allowance.is_none());
            let held = options.journal.clone();
            assert!(matches!(
                accounting.namespace().apply_options_detailed(
                    &mut options,
                    Some(NamespaceSpendPolicy {
                        maximum_microcents: 1000,
                        allow_unpriced_housekeeping: true
                    }),
                    None
                ),
                Err(AccountingError::SpendRefused(_))
            ));
            assert!(Arc::ptr_eq(
                options.journal.as_ref().unwrap(),
                held.as_ref().unwrap()
            ));
            assert!(options.spend_allowance.is_none());
            drop(accounting);
            let restored =
                prepare_root(&tree._lease, &mut saved, RootOrigin::RestoredOrLegacy).unwrap();
            assert_eq!(
                restored
                    .namespace()
                    .checkpoint_detailed()
                    .unwrap()
                    .refusals()
                    .unwrap()
                    .latest(),
                &record
            );
            let later = journal
                .begin_attempt_detailed(
                    AccountingRevision(2),
                    &intent("post-restart-success", AttemptPurpose::Ordinary),
                    None,
                )
                .unwrap();
            journal
                .settle_attempt_detailed(
                    &later,
                    &receipt("post-restart-success", AttemptPurpose::Ordinary),
                )
                .unwrap();
            let view = restored.persist(&tree._lease, &mut saved).unwrap();
            assert_eq!(
                (
                    view.input_tokens,
                    view.output_tokens,
                    view.known_cost_microcents
                ),
                (input + 8, output + 3, price + 17)
            );
            assert_eq!(
                view.full_cost_status,
                if legacy {
                    FullCostStatus::UnknownLegacy
                } else {
                    FullCostStatus::UnknownUsage
                }
            );
        }
    }

    #[test]
    fn actual_near_maximum_revision_qualified_transition_settles_once_and_refuses_next_begin() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let layout = journal.layout(false).unwrap();
        let mut container = load_container(&layout.owner, "owner").unwrap().unwrap();
        let anchor = intent("bounded-revision-anchor", AttemptPurpose::Ordinary);
        let not_sent = RequestAccountingReceipt {
            request_id: anchor.request_id.clone(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals::known_zero(),
            usage: None,
            knownness: AccountingKnownness::Known,
            completed: false,
        };
        container.entries[0].revision = u64::MAX - 2;
        container.entries[0].last = Some(Settlement {
            reference: Reference {
                revision: u64::MAX - 3,
                request_id: anchor.request_id.clone(),
                intent_digest: anchor.digest().unwrap(),
            },
            receipt: Some(Receipt::from_public(&not_sent)),
            refused: None,
        });
        journal.save(&layout, &container).unwrap();
        let (attempt, record) = begin_checked_component(
            &journal,
            &intent("last-representable", AttemptPurpose::Ordinary),
            u64::MAX - 2,
        );
        assert_eq!(attempt.revision.0, u64::MAX - 1);
        let ack = journal.settle_refusal_record(&attempt, &record).unwrap();
        assert_eq!(ack.checkpoint().revision().0, u64::MAX);
        assert_eq!(
            journal.settle_refusal_record(&attempt, &record).unwrap(),
            ack
        );
        let bytes = std::fs::read(tree.owner().join(ACCOUNTING)).unwrap();
        assert_eq!(
            journal.begin_attempt_detailed(
                AccountingRevision(u64::MAX),
                &intent("must-overflow", AttemptPurpose::Ordinary),
                None
            ),
            Err(HistoryError::TooLarge)
        );
        assert_eq!(std::fs::read(tree.owner().join(ACCOUNTING)).unwrap(), bytes);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod accounting_inspection_tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

    type FileMetadata = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
    struct Tree {
        root: PathBuf,
        home: PathBuf,
    }
    impl Tree {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("orbit-accounting-inspection-{}", ulid::Ulid::new()));
            private_dir(&root);
            let home = root.join("home");
            private_dir(&home);
            Self { root, home }
        }
        fn owner(&self) -> PathBuf {
            self.home.join("context-history/owner")
        }
        fn journal(&self) -> Journal {
            Journal::open(&self.home, "owner", None).unwrap()
        }
        fn inspect(&self) -> Result<AccountingInspection, HistoryError> {
            inspect_accounting(&self.home, "owner", None)
        }
        fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.owner().join(ACCOUNTING)).unwrap()
        }
        fn file_state(&self) -> Vec<(Vec<u8>, FileMetadata)> {
            [ACCOUNTING, LOCK]
                .map(|name| {
                    let path = self.owner().join(name);
                    let metadata = std::fs::symlink_metadata(&path).unwrap();
                    (
                        std::fs::read(path).unwrap(),
                        (
                            metadata.dev(),
                            metadata.ino(),
                            metadata.mode(),
                            metadata.uid(),
                            metadata.gid(),
                            metadata.nlink(),
                            metadata.len(),
                            metadata.mtime(),
                            metadata.mtime_nsec(),
                            metadata.ctime(),
                            metadata.ctime_nsec(),
                        ),
                    )
                })
                .into_iter()
                .collect()
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn private_dir(path: &Path) {
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    fn private_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn intent(request: &str, purpose: AttemptPurpose) -> AttemptIntent {
        AttemptIntent {
            owner_session_id: "owner".into(),
            child_id: None,
            request_id: request.into(),
            purpose,
            budget: BudgetIdentity {
                binding_digest: "a".repeat(64),
                metadata_revision: "metadata-v1".into(),
                policy_revision: "policy-v1".into(),
            },
        }
    }
    fn known_receipt(request: &str) -> RequestAccountingReceipt {
        RequestAccountingReceipt {
            request_id: request.into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 8,
                output_tokens: 3,
                cost_microcents: Some(17),
            },
            usage: Some(ProviderUsage {
                input_tokens: 8,
                output_tokens: 3,
                cache_read_tokens: 5,
                cache_write_tokens: 7,
                reasoning_tokens: 2,
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        }
    }

    #[test]
    fn inspection_missing_components_and_namespace_are_positive_and_noncreating() {
        let tree = Tree::new();
        let absent = tree.root.join("missing/nested");
        assert_eq!(
            inspect_accounting(&absent, "owner", None),
            Err(HistoryError::Missing)
        );
        assert!(!tree.root.join("missing").exists());
        assert_eq!(tree.inspect(), Err(HistoryError::Missing));
        assert_eq!(std::fs::read_dir(&tree.home).unwrap().count(), 0);
        private_dir(&tree.home.join("context-history"));
        assert_eq!(tree.inspect(), Err(HistoryError::Missing));
        private_dir(&tree.owner());
        assert_eq!(tree.inspect(), Err(HistoryError::Missing));
        private_dir(&tree.owner().join("archives"));
        assert_eq!(tree.inspect(), Err(HistoryError::Missing));
        assert!(!tree.owner().join(LOCK).exists());
        assert_eq!(std::fs::read_dir(tree.owner()).unwrap().count(), 1);
        let dir = Directory::open(&tree.owner(), true).unwrap();
        drop(Lock::acquire(&dir, LOCK).unwrap());
        assert_eq!(tree.inspect(), Err(HistoryError::Missing));
        assert!(!tree.owner().join(ACCOUNTING).exists());
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let before = tree.file_state();
        let child = ulid::Ulid::new().to_string();
        assert_eq!(
            inspect_accounting(&tree.home, "owner", Some(&child)),
            Err(HistoryError::Missing)
        );
        assert_eq!(tree.file_state(), before);
    }

    #[test]
    fn inspection_validates_scope_before_access_and_rejects_dangling_components() {
        let tree = Tree::new();
        let absent = tree.root.join("absent");
        for owner in ["", "../owner", "invalid/id"] {
            assert_eq!(
                inspect_accounting(&absent, owner, None),
                Err(HistoryError::InvalidRecord)
            );
        }
        for child in ["", "not-a-child", "01abcdefghjkmnpqrstvwxyz123"] {
            assert_eq!(
                inspect_accounting(&absent, "owner", Some(child)),
                Err(HistoryError::InvalidRecord)
            );
        }
        assert!(!absent.exists());
        let alias = tree.root.join("alias");
        symlink(&absent, &alias).unwrap();
        assert_eq!(
            inspect_accounting(&alias.join("nested"), "owner", None),
            Err(HistoryError::Unsafe)
        );
        symlink(&absent, tree.home.join("context-history")).unwrap();
        assert_eq!(tree.inspect(), Err(HistoryError::Unsafe));
        assert!(!absent.exists());
    }

    #[test]
    fn inspection_rejects_missing_unsafe_lock_and_staging_without_repair() {
        for kind in ["missing", "dangling", "public", "hardlink", "stage"] {
            let tree = Tree::new();
            let journal = tree.journal();
            journal
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
            let before = tree.bytes();
            let lock = tree.owner().join(LOCK);
            match kind {
                "missing" => std::fs::remove_file(&lock).unwrap(),
                "dangling" => {
                    std::fs::remove_file(&lock).unwrap();
                    symlink(tree.root.join("absent"), &lock).unwrap();
                }
                "public" => {
                    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "hardlink" => std::fs::hard_link(&lock, tree.root.join("retained-lock")).unwrap(),
                "stage" => private_file(
                    &tree.owner().join(".stage-unfinished"),
                    b"inert incomplete publication",
                ),
                _ => unreachable!(),
            }
            assert_eq!(
                tree.inspect(),
                Err(if kind == "stage" {
                    HistoryError::Uncertain
                } else {
                    HistoryError::Unsafe
                }),
                "{kind}"
            );
            assert_eq!(tree.bytes(), before);
            assert!(!tree.root.join("absent").exists());
            if kind == "missing" {
                assert!(!lock.exists());
            }
            if kind == "stage" {
                assert_eq!(
                    std::fs::read(tree.owner().join(".stage-unfinished")).unwrap(),
                    b"inert incomplete publication"
                );
            }
        }
    }

    #[test]
    fn inspection_preserves_known_and_legacy_metadata_without_requiring_session_ownership() {
        for baseline in [
            AccountingBaseline::FreshKnownZero,
            AccountingBaseline::UnknownLegacy,
        ] {
            let tree = Tree::new();
            let lease = crate::sessions::SessionLease::acquire(
                &tree.home,
                "owner",
                "inspection-held-owner",
            )
            .unwrap();
            let journal = tree.journal();
            let checkpoint = journal.initialize_accounting(baseline).unwrap();
            let before = tree.file_state();
            let inspected = tree.inspect().unwrap();
            assert_eq!(inspected.checkpoint, checkpoint);
            assert_eq!(
                inspected.qualification,
                InspectionQualification::VisibleValidated
            );
            assert!(digest_ok(&inspected.inspection_digest));
            assert!(inspected.pending_receipt.is_none() && inspected.last_receipt.is_none());
            assert_eq!(tree.file_state(), before);
            assert!(matches!(
                crate::sessions::SessionLease::acquire(&tree.home, "owner", "must-stay-owned"),
                Err(crate::sessions::SessionLeaseError::Busy { .. })
            ));
            drop(lease);
        }
    }

    #[test]
    fn inspection_uses_shared_existing_lock_and_reports_actual_writer_busy() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let dir = Directory::open(&tree.owner(), true).unwrap();
        let before = tree.file_state();
        let writer = Lock::acquire(&dir, LOCK).unwrap();
        assert_eq!(tree.inspect(), Err(HistoryError::Busy));
        drop(writer);
        let shared = Lock::read_existing(&dir, LOCK).unwrap();
        let inspected = tree.inspect().unwrap();
        assert_eq!(inspected.checkpoint.revision, AccountingRevision(0));
        assert!(matches!(Lock::acquire(&dir, LOCK), Err(Error::Busy)));
        drop(shared);
        assert_eq!(tree.inspect().unwrap(), inspected);
        assert_eq!(tree.file_state(), before);
    }

    #[test]
    fn inspection_retains_begun_and_provisional_receipts_separately_from_known_totals() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let first = journal
            .begin_attempt(
                AccountingRevision(0),
                &intent("known-first", AttemptPurpose::Ordinary),
            )
            .unwrap();
        let known = known_receipt("known-first");
        journal.settle_attempt(&first, &known).unwrap();
        let pending = journal
            .begin_attempt(
                AccountingRevision(2),
                &intent("provisional", AttemptPurpose::Chunk),
            )
            .unwrap();
        let before = tree.file_state();
        let begun = tree.inspect().unwrap();
        assert_eq!(tree.file_state(), before);
        assert_eq!(begun.checkpoint.revision, AccountingRevision(3));
        assert!(!begun.checkpoint.pending.as_ref().unwrap().uncertain);
        assert!(begun.pending_receipt.is_none());
        assert_eq!(begun.last_receipt, Some(known.clone()));
        let uncertain = RequestAccountingReceipt {
            request_id: "provisional".into(),
            purpose: AttemptPurpose::Chunk,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(ProviderUsage {
                input_tokens: 101,
                output_tokens: 103,
                cache_read_tokens: 107,
                cache_write_tokens: 109,
                reasoning_tokens: 113,
            }),
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        };
        let checkpoint = journal.settle_attempt(&pending, &uncertain).unwrap();
        let before = tree.file_state();
        let inspected = tree.inspect().unwrap();
        assert_eq!(tree.file_state(), before);
        assert_eq!(inspected.checkpoint, checkpoint);
        assert_eq!(inspected.pending_receipt, Some(uncertain));
        assert_eq!(inspected.last_receipt, Some(known.clone()));
        assert_eq!(inspected.checkpoint.revision, AccountingRevision(4));
        assert!(inspected.checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(
            inspected.checkpoint.totals.knownness,
            AccountingKnownness::Uncertain
        );
        assert_eq!(inspected.checkpoint.totals.ordinary, known.totals);
        assert_eq!(inspected.checkpoint.totals.housekeeping.input_tokens, 0);
        assert_eq!(inspected.checkpoint.totals.housekeeping.output_tokens, 0);
        assert_eq!(
            inspected.checkpoint.totals.housekeeping.cost_microcents,
            None
        );
        let subset = inspected.checkpoint.known_priced_subtotals.unwrap();
        assert_eq!(
            (subset.ordinary_microcents, subset.housekeeping_microcents),
            (17, 0)
        );
        assert_ne!(begun.inspection_digest, inspected.inspection_digest);
    }

    #[test]
    fn inspection_retains_final_unknown_usage_and_incomplete_known_zero_presence() {
        for known in [false, true] {
            let tree = Tree::new();
            let journal = tree.journal();
            journal
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
            let reference = journal
                .begin_attempt(
                    AccountingRevision(0),
                    &intent("presence", AttemptPurpose::Ordinary),
                )
                .unwrap();
            let receipt = RequestAccountingReceipt {
                request_id: "presence".into(),
                purpose: AttemptPurpose::Ordinary,
                totals: AccountingTotals {
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: known.then_some(0),
                },
                usage: None,
                knownness: if known {
                    AccountingKnownness::Known
                } else {
                    AccountingKnownness::UnknownUsage
                },
                completed: !known,
            };
            let checkpoint = journal.settle_attempt(&reference, &receipt).unwrap();
            let before = tree.file_state();
            let inspected = tree.inspect().unwrap();
            assert_eq!(inspected.checkpoint, checkpoint);
            assert_eq!(inspected.last_receipt, Some(receipt));
            assert!(inspected.pending_receipt.is_none());
            assert_eq!(tree.file_state(), before);
        }
    }

    #[test]
    fn inspection_digest_binds_selected_namespace_and_exact_container_revision() {
        let tree = Tree::new();
        let journal = tree.journal();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let child_id = ulid::Ulid::new().to_string();
        let child = Journal::open(&tree.home, "owner", Some(&child_id)).unwrap();
        child
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let before = tree.bytes();
        let root = tree.inspect().unwrap();
        let selected = inspect_accounting(&tree.home, "owner", Some(&child_id)).unwrap();
        assert_eq!(tree.bytes(), before);
        assert_ne!(root.inspection_digest, selected.inspection_digest);
        assert!(digest_ok(&selected.inspection_digest));
        assert_eq!(tree.inspect().unwrap(), root);
        journal
            .begin_attempt(
                AccountingRevision(0),
                &intent("new-revision", AttemptPurpose::Ordinary),
            )
            .unwrap();
        let changed = tree.inspect().unwrap();
        assert_eq!(changed.checkpoint.revision, AccountingRevision(1));
        assert_ne!(changed.inspection_digest, root.inspection_digest);
        let child_changed = inspect_accounting(&tree.home, "owner", Some(&child_id)).unwrap();
        assert_eq!(child_changed.checkpoint, selected.checkpoint);
        assert_ne!(child_changed.inspection_digest, selected.inspection_digest);
    }

    #[test]
    fn inspection_reads_only_bounded_canonical_accounting_and_no_archive_bodies() {
        let tree = Tree::new();
        let journal = tree.journal();
        let checkpoint = journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let archive = tree
            .owner()
            .join("archives")
            .join(format!("compact-{}.json", ulid::Ulid::new()));
        private_file(&archive, &vec![b'x'; 1024 * 1024]);
        let before = tree.file_state();
        assert_eq!(tree.inspect().unwrap().checkpoint, checkpoint);
        assert_eq!(tree.file_state(), before);
        assert_eq!(std::fs::metadata(archive).unwrap().len(), 1024 * 1024);
        let path = tree.owner().join(ACCOUNTING);
        let canonical = tree.bytes();
        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        private_file(&path, &noncanonical);
        assert_eq!(tree.inspect(), Err(HistoryError::InvalidRecord));
        assert_eq!(tree.bytes(), noncanonical);
        private_file(&path, &vec![b'x'; MAX_ACCOUNTING_CHECKPOINT_BYTES + 1]);
        assert_eq!(tree.inspect(), Err(HistoryError::TooLarge));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (MAX_ACCOUNTING_CHECKPOINT_BYTES + 1) as u64
        );
        private_file(&path, &canonical);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(tree.inspect(), Err(HistoryError::Unsafe));
        assert_eq!(tree.bytes(), canonical);
    }
}

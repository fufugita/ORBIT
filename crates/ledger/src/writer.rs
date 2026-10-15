//! Ledger single-writer protocol (DR-06 §1, §3-4; A5-A6).
//!
//! - `writer.lock` (flock) is mandatory; one writer per session.
//! - Records are appended length-prefixed (u32 BE) then canonical bytes.
//! - `fsync` before ACK for security-gating records (`EgressIntent`,
//!   `AuthorityGrant`, `Refused`, etc.); periodic 250ms economic fsync otherwise.
//! - Recovery truncates to the last crc/self-hash-valid frame (E0709 if a
//!   *committed* tail is lost — the fsync boundary is the truth).

use crate::canonical;
use crate::error::LedgerError;
use crate::event::{LedgerEvent, LedgerRecord, SegmentHeader};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Security-gating record kinds that require fsync-before-ACK (DR-06 §1.3).
fn requires_sync(event: &LedgerEvent) -> bool {
    matches!(
        event,
        LedgerEvent::EgressIntent(_)
            | LedgerEvent::SubagentCall(_)
            | LedgerEvent::AuthorityGrant(_)
            | LedgerEvent::AuthorityRevoke(_)
            | LedgerEvent::Refused(_)
            | LedgerEvent::SessionStart(_)
            | LedgerEvent::SessionEnd(_)
            | LedgerEvent::PhaseTransition(_)
            | LedgerEvent::PluginInstall(_)
    )
}

/// A checked-in, hash-validated record read back from disk.
#[derive(Debug, Clone)]
pub struct ReadRecord {
    pub record: LedgerRecord,
    pub self_hash: String,
}

/// The single-writer Ledger.
pub struct LedgerWriter {
    dir: PathBuf,
    requested_path: PathBuf,
    storage_path: PathBuf,
    parent_path: PathBuf,
    parent_directory: File,
    root_directory: File,
    segments_directory: File,
    segment: File,
    segment_path: PathBuf,
    segment_ordinal: u64,
    head: String, // last committed self-hash
    writer_id: String,
    /// Held open for the writer's lifetime to keep the flock (E0719).
    #[allow(dead_code)]
    lock_file: File,
    dirty_since_sync: bool,
    failed: bool,
}

impl LedgerWriter {
    /// Open (or create) the ledger at `dir` under the single-writer lock.
    /// Returns E0719 if the lock cannot be acquired (another writer holds it).
    pub fn open(dir: &Path, writer_id: String, writer_version: &str) -> Result<Self, LedgerError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("mkdir {dir:?}: {e}")))?;
        let requested_path = std::env::current_dir()
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("current directory: {e}")))?
            .join(dir);
        let root_directory = open_directory(&requested_path, "ledger directory")?;
        require_owned(&root_directory, "ledger directory")?;
        let storage_path = std::fs::canonicalize(&requested_path)
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("ledger path: {e}")))?;
        let parent_path = storage_path
            .parent()
            .ok_or_else(|| LedgerError::LedgerUnavailableAtBoot("ledger has no parent".into()))?
            .to_path_buf();
        let parent_directory = open_directory(&parent_path, "ledger parent directory")?;
        // Security posture (DR-06 §1.2): dir 0700, files 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            root_directory
                .set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("chmod 0700: {e}")))?;
        }
        let root_io = directory_handle_path(&root_directory)?;

        // writer.lock — flock exclusive, non-blocking.
        let lock_file = open_private_file(&root_io.join("writer.lock"), false)?;
        #[cfg(unix)]
        {
            if !try_lock_exclusive(&lock_file) {
                return Err(LedgerError::LedgerUnavailableAtBoot(
                    "writer.lock held by another writer (E0719 ledger_unavailable_at_boot)".into(),
                ));
            }
        }

        // Find current segment ordinal + head.
        let segments_path = root_io.join("segments");
        match std::fs::create_dir(&segments_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(LedgerError::LedgerUnavailableAtBoot(format!(
                    "mkdir segments: {e}"
                )));
            }
        }
        let segments_directory = open_directory(&segments_path, "segment directory")?;
        require_owned(&segments_directory, "segment directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            segments_directory
                .set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| {
                    LedgerError::LedgerUnavailableAtBoot(format!("segments chmod: {e}"))
                })?;
        }
        let segments_dir = directory_handle_path(&segments_directory)?;
        let ordinal = next_segment_ordinal(&segments_dir);
        let segment_name = format!("{ordinal:016x}.log");
        let segment_path = dir.join("segments").join(&segment_name);

        // Re-derive the chain head from the segments — never trust the HEAD
        // cache verbatim (a torn/corrupt HEAD must not wedge the ledger; the
        // chain on disk is the truth). Frames are length-framed and
        // self-hash-validated; the last verified self-hash is the head.
        // Recovery truncates a torn tail (E0709) and refuses a mid-chain
        // break (E0602). This is the durability/authority invariant
        // exercised by the fault-injection suite (torn HEAD, torn tail,
        // bit-flip).
        let head = crate::reader::recover_head(&segments_dir)?;

        let segment = open_private_file(&segments_dir.join(segment_name), true)?;

        let mut writer = Self {
            dir: dir.to_path_buf(),
            requested_path,
            storage_path,
            parent_path,
            parent_directory,
            root_directory,
            segments_directory,
            segment,
            segment_path,
            segment_ordinal: ordinal,
            head,
            writer_id,
            lock_file,
            dirty_since_sync: false,
            failed: false,
        };
        writer.validate_storage_identity()?;
        writer.ensure_segment_header(writer_version)?;
        Ok(writer)
    }

    fn ensure_segment_header(&mut self, writer_version: &str) -> Result<(), LedgerError> {
        // If the segment is empty, write the SegmentHeader (DR-06 §1.5).
        let meta = self
            .segment
            .metadata()
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("segment stat: {e}")))?;
        if meta.len() == 0 {
            let header = LedgerEvent::SegmentHeader(SegmentHeader {
                v: "ledger/segment-header/v1".into(),
                segment_ordinal: self.segment_ordinal,
                wall_clock_open_ms: chrono::Utc::now().timestamp_millis(),
                writer_id: self.writer_id.clone(),
                writer_version: writer_version.into(),
                ledger_hash_prev: self.head.clone(),
            });
            let record = LedgerRecord {
                v: "ledger/record/v1".into(),
                event: header,
                ledger_hash_prev: self.head.clone(),
                ledger_hash_self: None,
            };
            let finalized = record
                .finalized()
                .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("header hash: {e}")))?;
            self.append_record(&finalized, true)?;
        }
        Ok(())
    }

    /// Append a record; fsync-before-ACK for security-gating records.
    /// Updates HEAD; returns the self-hash.
    pub fn append(&mut self, event: LedgerEvent) -> Result<String, LedgerError> {
        if self.failed {
            return Err(LedgerError::LedgerRequiredForMutation(
                "writer must be reopened after an uncertain append".into(),
            ));
        }
        let sync = requires_sync(&event);
        let record = LedgerRecord {
            v: "ledger/record/v1".into(),
            event,
            ledger_hash_prev: self.head.clone(),
            ledger_hash_self: None,
        };
        let finalized = record
            .finalized()
            .map_err(|e| LedgerError::LedgerRequiredForMutation(e.to_string()))?;
        self.append_record(&finalized, sync)
    }

    fn append_record(&mut self, record: &LedgerRecord, sync: bool) -> Result<String, LedgerError> {
        let result = self.append_record_inner(record, sync);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn append_record_inner(
        &mut self,
        record: &LedgerRecord,
        sync: bool,
    ) -> Result<String, LedgerError> {
        self.validate_storage_identity()?;
        let bytes = canonical::canonical_bytes(record)
            .map_err(|e| LedgerError::LedgerRequiredForMutation(e.to_string()))?;
        let len = (bytes.len() as u32).to_be_bytes();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&len);
        frame.extend_from_slice(&bytes);

        self.segment
            .write_all(&frame)
            .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("append write: {e}")))?;

        let self_hash = record
            .ledger_hash_self
            .clone()
            .ok_or_else(|| LedgerError::LedgerRequiredForMutation("missing self hash".into()))?;

        if sync {
            self.fsync()?;
        } else {
            self.dirty_since_sync = true;
        }
        self.write_head(&self_hash)?;
        self.validate_storage_identity()?;
        self.head = self_hash.clone();
        Ok(self_hash)
    }

    /// fsync the segment file + parent dir (durability boundary).
    pub fn fsync(&mut self) -> Result<(), LedgerError> {
        if self.failed {
            return Err(LedgerError::LedgerRequiredForMutation(
                "writer must be reopened after an uncertain append".into(),
            ));
        }
        let result = self.fsync_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn fsync_inner(&mut self) -> Result<(), LedgerError> {
        self.validate_storage_identity()?;
        self.segment
            .sync_all()
            .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("fsync: {e}")))?;
        // A file sync alone cannot persist its new segment directory entry.
        // Every required directory sync must succeed before an ACK is returned.
        sync_directory_handle(&self.segments_directory, "segment directory")?;
        sync_directory_handle(&self.root_directory, "ledger directory")?;
        sync_directory_handle(&self.parent_directory, "ledger parent directory")?;
        self.validate_storage_identity()?;
        self.dirty_since_sync = false;
        Ok(())
    }

    fn validate_storage_identity(&self) -> Result<(), LedgerError> {
        check_entry(
            &self.parent_path,
            &self.parent_directory,
            "ledger parent directory",
            true,
            false,
        )?;
        check_entry(
            &self.requested_path,
            &self.root_directory,
            "ledger directory",
            true,
            true,
        )?;
        check_entry(
            &self.storage_path,
            &self.root_directory,
            "ledger directory",
            true,
            true,
        )?;
        let root = directory_handle_path(&self.root_directory)?;
        check_entry(
            &root.join("segments"),
            &self.segments_directory,
            "segment directory",
            true,
            true,
        )?;
        check_entry(
            &root.join("writer.lock"),
            &self.lock_file,
            "writer lock",
            false,
            true,
        )?;
        let segments = directory_handle_path(&self.segments_directory)?;
        check_entry(
            &segments.join(format!("{:016x}.log", self.segment_ordinal)),
            &self.segment,
            "active segment",
            false,
            true,
        )
    }

    fn write_head(&self, head: &str) -> Result<(), LedgerError> {
        self.validate_storage_identity()?;
        let root = directory_handle_path(&self.root_directory)?;
        let temporary = root.join(format!("HEAD.{}.tmp", ulid::Ulid::new()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let mut file = options
                .open(&temporary)
                .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("HEAD open: {e}")))?;
            file.write_all(head.as_bytes())
                .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("HEAD write: {e}")))?;
            file.sync_all()
                .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("HEAD fsync: {e}")))?;
            self.validate_storage_identity()?;
            std::fs::rename(&temporary, root.join("HEAD"))
                .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("HEAD rename: {e}")))?;
            sync_directory_handle(&self.root_directory, "HEAD parent directory")?;
            self.validate_storage_identity()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// Close: fsync + release lock.
    pub fn close(mut self) -> Result<(), LedgerError> {
        if self.failed {
            return Err(LedgerError::LedgerRequiredForMutation(
                "writer must be reopened after an uncertain append".into(),
            ));
        }
        if self.dirty_since_sync {
            self.fsync()?;
        }
        Ok(())
    }

    /// Current head (last committed self-hash).
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Directory backing this ledger.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Path of the currently active segment file.
    pub fn active_segment_path(&self) -> &Path {
        &self.segment_path
    }
}

/// Try to take an exclusive non-blocking flock on `file`.
/// Returns true if the lock was acquired (caller keeps `file` open).
#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `file` is an open File (valid fd); LOCK_EX|LOCK_NB never blocks;
    // a return of 0 means we hold the lock, which we release on drop/close.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    rc == 0
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> bool {
    true // v0.1 is Linux-only (DR-13 §1); non-unix is a no-op stub
}

fn next_segment_ordinal(segments_dir: &Path) -> u64 {
    let mut max = 0u64;
    if let Ok(rd) = std::fs::read_dir(segments_dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if let Some(hexpart) = s.strip_suffix(".log")
                && let Ok(n) = u64::from_str_radix(hexpart, 16)
            {
                max = max.max(n + 1);
            }
        }
    }
    max
}

fn open_directory(path: &Path, label: &str) -> Result<File, LedgerError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let directory = options
        .open(path)
        .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("{label} open: {e}")))?;
    if !directory.metadata().is_ok_and(|meta| meta.is_dir()) {
        return Err(LedgerError::LedgerUnavailableAtBoot(format!(
            "{label}: expected a directory"
        )));
    }
    Ok(directory)
}

fn open_private_file(path: &Path, append: bool) -> Result<File, LedgerError> {
    let mut options = OpenOptions::new();
    options
        .create(true)
        .read(true)
        .write(true)
        .append(append)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| {
        LedgerError::LedgerUnavailableAtBoot(format!("private ledger file open: {e}"))
    })?;
    let metadata = file.metadata().map_err(|e| {
        LedgerError::LedgerUnavailableAtBoot(format!("private ledger file stat: {e}"))
    })?;
    if !metadata.is_file() {
        return Err(LedgerError::LedgerUnavailableAtBoot(
            "expected a regular ledger file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            return Err(LedgerError::LedgerUnavailableAtBoot(
                "ledger file has multiple links".into(),
            ));
        }
        require_owned(&file, "private ledger file")?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("file chmod 0600: {e}")))?;
    }
    Ok(file)
}

fn require_owned(file: &File, label: &str) -> Result<(), LedgerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments, pointers, or memory side effects.
        #[allow(unsafe_code)]
        let owner = unsafe { libc::geteuid() };
        let metadata = file
            .metadata()
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("{label} stat: {e}")))?;
        if metadata.uid() != owner {
            return Err(LedgerError::LedgerUnavailableAtBoot(format!(
                "{label} owner changed"
            )));
        }
    }
    Ok(())
}

/// Linux exposes a stable directory FD as a path without re-resolving its
/// mutable public ancestors. Children use O_NOFOLLOW and are checked by inode.
fn directory_handle_path(directory: &File) -> Result<PathBuf, LedgerError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::{fs::MetadataExt, io::AsRawFd};
        let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let actual = std::fs::metadata(&path).map_err(|e| {
            LedgerError::LedgerRequiredForMutation(format!("directory FD path unavailable: {e}"))
        })?;
        let held = directory.metadata().map_err(|e| {
            LedgerError::LedgerRequiredForMutation(format!("directory FD stat: {e}"))
        })?;
        if !actual.is_dir() || actual.dev() != held.dev() || actual.ino() != held.ino() {
            return Err(LedgerError::LedgerRequiredForMutation(
                "directory FD path identity changed".into(),
            ));
        }
        Ok(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        Err(LedgerError::LedgerUnavailableAtBoot(
            "identity-bound ledger IO requires Linux directory FDs".into(),
        ))
    }
}

fn check_entry(
    path: &Path,
    held: &File,
    label: &str,
    directory: bool,
    private: bool,
) -> Result<(), LedgerError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            libc::O_NOFOLLOW | libc::O_NONBLOCK | if directory { libc::O_DIRECTORY } else { 0 },
        );
    }
    let current = options.open(path).map_err(|e| {
        LedgerError::LedgerRequiredForMutation(format!("{label} identity open: {e}"))
    })?;
    let actual = current.metadata().map_err(|e| {
        LedgerError::LedgerRequiredForMutation(format!("{label} identity stat: {e}"))
    })?;
    let original = held
        .metadata()
        .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("{label} held stat: {e}")))?;
    if (directory && !actual.is_dir()) || (!directory && !actual.is_file()) {
        return Err(LedgerError::LedgerRequiredForMutation(format!(
            "{label} type changed"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if actual.dev() != original.dev() || actual.ino() != original.ino() {
            return Err(LedgerError::LedgerRequiredForMutation(format!(
                "{label} identity changed"
            )));
        }
        if private && (actual.mode() & 0o077 != 0 || (!directory && actual.nlink() != 1)) {
            return Err(LedgerError::LedgerRequiredForMutation(format!(
                "{label} private identity changed"
            )));
        }
        if private {
            require_owned(&current, label)
                .map_err(|e| LedgerError::LedgerRequiredForMutation(e.to_string()))?;
        }
    }
    Ok(())
}

fn sync_directory_handle(directory: &File, label: &str) -> Result<(), LedgerError> {
    directory
        .sync_all()
        .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("sync {label}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{LedgerEvent, Phase, PhaseTransition};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("orbit-ledger-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_and_chain() {
        let d = tmpdir("append");
        let mut w = LedgerWriter::open(&d, "w1".into(), "0.1.0").unwrap();
        let ev = LedgerEvent::PhaseTransition(PhaseTransition {
            session_id: "s".into(),
            from: Phase::Init,
            to: Phase::Plan,
            checkpoint_seq: None,
        });
        let h = w.append(ev).unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(w.head(), &h);
        w.close().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn second_writer_fails_lock() {
        let d = tmpdir("lock");
        let w1 = LedgerWriter::open(&d, "w1".into(), "0.1.0").unwrap();
        let r = LedgerWriter::open(&d, "w2".into(), "0.1.0");
        assert!(r.is_err(), "second writer must fail (E0719)");
        drop(w1);
        let _ = std::fs::remove_dir_all(&d);
    }
}

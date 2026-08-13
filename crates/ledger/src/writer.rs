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
    segment: File,
    segment_path: PathBuf,
    segment_ordinal: u64,
    head: String, // last committed self-hash
    writer_id: String,
    /// Held open for the writer's lifetime to keep the flock (E0719).
    #[allow(dead_code)]
    lock_file: File,
    dirty_since_sync: bool,
}

impl LedgerWriter {
    /// Open (or create) the ledger at `dir` under the single-writer lock.
    /// Returns E0719 if the lock cannot be acquired (another writer holds it).
    pub fn open(dir: &Path, writer_id: String, writer_version: &str) -> Result<Self, LedgerError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("mkdir {dir:?}: {e}")))?;
        // Security posture (DR-06 §1.2): dir 0700, files 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("chmod 0700: {e}")))?;
        }

        // writer.lock — flock exclusive, non-blocking.
        let lock_path = dir.join("writer.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("lock open: {e}")))?;
        #[cfg(unix)]
        {
            if !try_lock_exclusive(&lock_file) {
                return Err(LedgerError::LedgerUnavailableAtBoot(
                    "writer.lock held by another writer (E0719 ledger_unavailable_at_boot)".into(),
                ));
            }
        }

        // Find current segment ordinal + head.
        let segments_dir = dir.join("segments");
        std::fs::create_dir_all(&segments_dir)
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("mkdir segments: {e}")))?;
        let ordinal = next_segment_ordinal(&segments_dir);
        let segment_path = segments_dir.join(format!("{ordinal:016x}.log"));

        // Re-derive the chain head from the segments — never trust the HEAD
        // cache verbatim (a torn/corrupt HEAD must not wedge the ledger; the
        // chain on disk is the truth). Frames are length-framed and
        // self-hash-validated; the last verified self-hash is the head.
        // Recovery truncates a torn tail (E0709) and refuses a mid-chain
        // break (E0602). This is the durability/authority invariant
        // exercised by the fault-injection suite (torn HEAD, torn tail,
        // bit-flip).
        let head = crate::reader::recover_head(&segments_dir)?;

        // NEW P2 #1: open the segment, then force 0600 — the process umask
        // (default 0o022) would otherwise make new segments group/world
        // readable, leaking frame contents to local users.
        let segment = File::options()
            .create(true)
            .append(true)
            .truncate(false)
            .open(&segment_path)
            .map_err(|e| LedgerError::LedgerUnavailableAtBoot(format!("segment open: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            segment
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    LedgerError::LedgerUnavailableAtBoot(format!("segment chmod 0600: {e}"))
                })?;
        }

        let mut writer = Self {
            dir: dir.to_path_buf(),
            segment,
            segment_path,
            segment_ordinal: ordinal,
            head,
            writer_id,
            lock_file,
            dirty_since_sync: false,
        };
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
        self.head = self_hash.clone();
        write_head(&self.dir.join("HEAD"), &self.head)?;
        Ok(self_hash)
    }

    /// fsync the segment file + parent dir (durability boundary).
    pub fn fsync(&mut self) -> Result<(), LedgerError> {
        self.segment
            .sync_all()
            .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("fsync: {e}")))?;
        // fsync the directory to persist the rename/entry.
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        self.dirty_since_sync = false;
        Ok(())
    }

    /// Close: fsync + release lock.
    pub fn close(mut self) -> Result<(), LedgerError> {
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
            if let Some(hexpart) = s.strip_suffix(".log") {
                if let Ok(n) = u64::from_str_radix(hexpart, 16) {
                    max = max.max(n + 1);
                }
            }
        }
    }
    max
}

fn write_head(path: &Path, head: &str) -> Result<(), LedgerError> {
    // Atomic: write tmp then rename, so a crash never leaves a torn HEAD.
    let tmp = path.with_extension("head.tmp");
    std::fs::write(&tmp, head)
        .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("HEAD write: {e}")))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| LedgerError::LedgerRequiredForMutation(format!("HEAD rename: {e}")))?;
    // P1-1 fix: fsync the parent dir so the rename entry is durable. Without
    // this, a power loss between segment-fsync and HEAD-dirfsync could make
    // the HEAD cache revert while the chain has the new durable record.
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
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

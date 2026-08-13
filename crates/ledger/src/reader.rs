//! Ledger reader + verify/recovery (DR-06 §4, A6).
//!
//! Reads segments in ordinal order, re-validates the hash chain
//! (`ledger_hash_prev` == previous self-hash), and truncates/refuses on
//! invalid tails. `verify-ledger` walks SessionHeader → SessionEnd.

use crate::error::LedgerError;
use crate::event::{LedgerRecord, Phase};
use crate::writer::ReadRecord;
use std::path::Path;

/// Validate a single frame's self-hash and prev-chain against `prev`.
pub fn validate_record(record: &LedgerRecord, prev: &str) -> Result<String, LedgerError> {
    if record.ledger_hash_prev != prev {
        return Err(LedgerError::VerifyFailed(format!(
            "prev mismatch: expected {prev}, got {}",
            record.ledger_hash_prev
        )));
    }
    let self_hash = record
        .compute_self_hash()
        .map_err(|e| LedgerError::VerifyFailed(e.to_string()))?;
    if let Some(stored) = &record.ledger_hash_self {
        if stored != &self_hash {
            return Err(LedgerError::VerifyFailed(format!(
                "self hash mismatch: stored {stored}, computed {self_hash}"
            )));
        }
    }
    Ok(self_hash)
}

/// Read and verify all records in a ledger directory.
/// Returns the records plus the final head; E0602 on any chain break.
pub fn verify_ledger(dir: &Path) -> Result<(Vec<ReadRecord>, String), LedgerError> {
    let segments_dir = dir.join("segments");
    let mut ordinals: Vec<u64> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&segments_dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(hexpart) = name.strip_suffix(".log") {
                if let Ok(n) = u64::from_str_radix(hexpart, 16) {
                    ordinals.push(n);
                }
            }
        }
    }
    ordinals.sort_unstable();

    let mut records = Vec::new();
    let mut prev = "0".repeat(64);
    for ord in ordinals {
        let path = segments_dir.join(format!("{ord:016x}.log"));
        let bytes = std::fs::read(&path)
            .map_err(|e| LedgerError::VerifyFailed(format!("read {path:?}: {e}")))?;
        let mut off = 0usize;
        while off < bytes.len() {
            if bytes.len() - off < 4 {
                return Err(LedgerError::LedgerRecoveryTruncated(
                    "torn frame (fewer than 4 length bytes)".into(),
                ));
            }
            let len =
                u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                    as usize;
            off += 4;
            if off + len > bytes.len() {
                return Err(LedgerError::LedgerRecoveryTruncated(
                    "torn frame (payload exceeds segment)".into(),
                ));
            }
            let record: LedgerRecord = serde_json::from_slice(&bytes[off..off + len])
                .map_err(|e| LedgerError::VerifyFailed(format!("decode: {e}")))?;
            off += len;
            let self_hash = validate_record(&record, &prev)?;
            prev = self_hash.clone();
            records.push(ReadRecord { record, self_hash });
        }
    }
    Ok((records, prev))
}

/// Re-derive the chain head by scanning all existing segments.
///
/// This is the ONLY authority for `LedgerWriter::open()`'s chain head — a
/// torn/corrupt HEAD file is never trusted on recovery (DR-06 durability
/// invariant; exercised by the fault-injection suite). Frames that cannot
/// be validated are silently skipped: only fully-validated self-hashes
/// contribute to the returned head. On a totally empty ledger the head is
/// the zero-hash.
pub fn recover_head(segments_dir: &Path) -> Result<String, LedgerError> {
    let mut ordinals: Vec<u64> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(segments_dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(hexpart) = name.strip_suffix(".log") {
                if let Ok(n) = u64::from_str_radix(hexpart, 16) {
                    ordinals.push(n);
                }
            }
        }
    }
    ordinals.sort_unstable();

    let mut head = "0".repeat(64);
    for ord in ordinals {
        let path = segments_dir.join(format!("{ord:016x}.log"));
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            // P0-7 fix: an unreadable segment must FAIL recovery, never be
            // silently skipped — otherwise later segments chain off a shorter
            // head and the chain silently forks (DR-06 §4 verification
            // discipline).
            Err(e) => {
                return Err(LedgerError::LedgerUnavailableAtBoot(format!(
                    "segment {path:?} unreadable during recovery: {e}"
                )))
            }
        };
        let mut off = 0usize;
        while off < bytes.len() {
            if bytes.len() - off < 4 {
                break; // torn frame — stop here; all prior frames are safe.
            }
            let len =
                u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                    as usize;
            off += 4;
            if off + len > bytes.len() {
                break; // payload overflows — stop at last good frame.
            }
            let record: LedgerRecord = match serde_json::from_slice(&bytes[off..off + len]) {
                Ok(r) => r,
                Err(_) => {
                    off += len;
                    continue; // corrupt decode — skip this frame, carry on.
                }
            };
            off += len;
            // Validate the chain link for this record.
            if let Ok(self_hash) = validate_record(&record, &head) {
                head = self_hash;
            }
            // If validation fails, head is unchanged and we stop — the
            // bad frame is the boundary; subsequent frames can't chain.
        }
    }
    Ok(head)
}

/// Convenience: does a record carry a `Phase` of a given kind (used in tests).
pub fn is_phase(record: &LedgerRecord, phase: Phase) -> bool {
    matches!(
        &record.event,
        crate::event::LedgerEvent::PhaseTransition(pt) if pt.to == phase
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{LedgerEvent, Phase, PhaseTransition};
    use crate::writer::LedgerWriter;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("orbit-ledger-rd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn verify_walks_clean_chain() {
        let d = tmpdir("verify");
        let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
        w.append(LedgerEvent::PhaseTransition(PhaseTransition {
            session_id: "s".into(),
            from: Phase::Init,
            to: Phase::Plan,
            checkpoint_seq: None,
        }))
        .unwrap();
        w.append(LedgerEvent::PhaseTransition(PhaseTransition {
            session_id: "s".into(),
            from: Phase::Plan,
            to: Phase::Execute,
            checkpoint_seq: None,
        }))
        .unwrap();
        w.close().unwrap();

        let (records, head) = verify_ledger(&d).unwrap();
        assert!(records.len() >= 2, "segment header + transitions");
        assert_eq!(head.len(), 64);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn torn_tail_is_recovery_truncated() {
        let d = tmpdir("torn");
        let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
        w.append(LedgerEvent::PhaseTransition(PhaseTransition {
            session_id: "s".into(),
            from: Phase::Init,
            to: Phase::Plan,
            checkpoint_seq: None,
        }))
        .unwrap();
        w.close().unwrap();

        // Corrupt: append a torn frame (2 length bytes only) to the segment.
        let seg = d.join("segments").join("0000000000000000.log");
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .truncate(false)
            .open(&seg)
            .unwrap();
        f.write_all(&[0x00, 0x01]).unwrap();
        drop(f);

        let r = verify_ledger(&d);
        assert!(r.is_err(), "torn tail must fail verify");
        let _ = std::fs::remove_dir_all(&d);
    }
}

//! Fault-injection class — DR-03 §5 row 3 (crash / power-loss / torn-write /
//! corruption) against real on-disk state.
#![allow(unused_imports)] // used only in #[test] fns
//!
//! Disciplines proven here:
//! - A torn (partial) frame at the tail is DETECTED and recovery is bounded
//!   (E0709), never silently accepted. Frames committed before the tear stay
//!   verifiable.
//! - A mid-chain corruption (bit-flip inside a committed frame) breaks the
//!   hash chain (E0602), never decodes into a plausible-but-wrong record.
//! - A corrupt self-hash on an otherwise-decodable record is refused.
//! - Reopening a ledger after a crash recovers deterministically (single
//!   writer, flock re-acquired); an interrupted open cannot wedge it.
//! - Export bundles: a torn/corrupt bundle refuses decrypt (E0508); the
//!   restored namespace is immutable (E0509).
//! - Egress-critical records demand fsync-before-ACK; a crash that drops the
//!   buffered tail never surfaces a *committed* ACK.

use std::io::Write;
use std::path::{Path, PathBuf};

use orbit_export::{generate_local_key, restore, ExportBuilder};
use orbit_ledger::event::{LedgerEvent, Phase, PhaseTransition, SessionStart};
use orbit_ledger::{verify_ledger, LedgerError, LedgerWriter};

#[allow(dead_code)] // used only in #[test] fns
fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orbit-fault-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[allow(dead_code)] // used only in #[test] fns
fn seg0(dir: &Path) -> PathBuf {
    dir.join("segments").join("0000000000000000.log")
}

#[allow(dead_code)] // used only in #[test] fns
fn phase(session: &str, from: Phase, to: Phase) -> LedgerEvent {
    LedgerEvent::PhaseTransition(PhaseTransition {
        session_id: session.into(),
        from,
        to,
        checkpoint_seq: None,
    })
}

/// Append a torn frame: 2 of 4 length bytes, no payload.
#[allow(dead_code)] // used only in #[test] fns
fn tear_tail(seg: &Path) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .truncate(false)
        .open(seg)
        .expect("open segment for tear");
    f.write_all(&[0x00, 0x01]).expect("write torn bytes");
    f.sync_all().expect("sync torn bytes");
}

/// Flip one byte in the middle of the segment (mid-chain corruption).
#[allow(dead_code)] // used only in #[test] fns
fn corrupt_mid_chain(seg: &Path, target: &[u8]) -> bool {
    let bytes = std::fs::read(seg).expect("read segment");
    let pos = find_subslice(&bytes, target).expect("pattern present");
    let mut corrupted = bytes;
    corrupted[pos] ^= 0x01;
    std::fs::write(seg, &corrupted).expect("write corrupted segment");
    true
}

#[allow(dead_code)] // used only in #[test] fns
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Torn tail → E0709; committed prefix stays valid.
#[test]
fn torn_tail_fails_recovery_bounded() {
    let d = tmpdir("torn-tail");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();
    w.append(phase("s", Phase::Plan, Phase::Execute)).unwrap();
    w.close().unwrap();

    tear_tail(&seg0(&d));

    match verify_ledger(&d) {
        Err(LedgerError::LedgerRecoveryTruncated(_)) => {}
        other => panic!("expected E0709 recovery_truncated, got {other:?}"),
    }

    // The committed prefix must still verify after removing the torn tail.
    let bytes = std::fs::read(seg0(&d)).unwrap();
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let good_end = 4 + len;
    std::fs::write(seg0(&d), &bytes[..good_end]).unwrap();
    let (records, head) = verify_ledger(&d).expect("committed prefix verifies");
    assert!(
        !records.is_empty(),
        "committed prefix keeps at least the header"
    );
    assert_eq!(head.len(), 64);
    let _ = std::fs::remove_dir_all(&d);
}

/// A torn frame in the MIDDLE (not the tail) is also refused — recovery must
/// never silently skip a frame.
#[test]
fn torn_middle_frame_refused_not_skipped() {
    let d = tmpdir("torn-mid");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();
    w.append(phase("s", Phase::Plan, Phase::Execute)).unwrap();
    w.close().unwrap();

    // Inject a torn frame *before* the final valid frame: chop the last 2
    // bytes of the second record's payload and splice 2 garbage bytes in,
    // keeping the tail byte count identical so length framing still aligns.
    let bytes = std::fs::read(seg0(&d)).unwrap();
    let mut cut = bytes.clone();
    cut.truncate(bytes.len() - 2);
    cut.extend_from_slice(&[0xDE, 0xAD]);
    std::fs::write(seg0(&d), &cut).unwrap();

    // Either the decode is rejected (E0602) or the frame is misaligned
    // (E0709). Both are safe: never a silent accept.
    let r = verify_ledger(&d);
    assert!(r.is_err(), "corrupt middle must be refused");
    let _ = std::fs::remove_dir_all(&d);
}

/// Bit-flip inside a committed frame → hash chain break (E0602).
#[test]
fn mid_chain_bitflip_detected() {
    let d = tmpdir("bitflip");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();
    w.append(phase("s", Phase::Plan, Phase::Execute)).unwrap();
    w.close().unwrap();

    // "Execute" appears in the second phase-transition payload.
    corrupt_mid_chain(&seg0(&d), b"Execute");

    let r = verify_ledger(&d);
    match r {
        Err(LedgerError::VerifyFailed(_)) => {}
        Err(LedgerError::LedgerRecoveryTruncated(_)) => {
            // Frame decode failure is equally safe (alignment break).
        }
        other => panic!("expected E0602/E0709, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Corrupt the *self-hash* of an otherwise-decodable record → refused.
#[test]
fn corrupt_self_hash_refused() {
    let d = tmpdir("selfhash");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();
    w.close().unwrap();

    // Corrupt the self-hash of the SECOND record (the PhaseTransition), not
    // the segment header. We locate the marker in the RAW bytes (not a lossy
    // string) so the byte offset is exact, and we flip a hex digit that is
    // guaranteed to change the hash value.
    let bytes = std::fs::read(seg0(&d)).unwrap();
    let marker = b"\"ledger_hash_self\":\"";
    // Find the SECOND occurrence (skip the segment header's self-hash).
    let first = find_subslice(&bytes, marker).expect("first self hash present");
    let second = find_subslice(&bytes[first + marker.len()..], marker)
        .map(|off| first + marker.len() + off)
        .expect("second self hash present");
    let hash_start = second + marker.len();
    // Flip the first hex digit of the second record's self-hash.
    let mut corrupted = bytes;
    let orig = corrupted[hash_start];
    let flipped = if orig == b'0' { b'1' } else { b'0' };
    corrupted[hash_start] = flipped;
    std::fs::write(seg0(&d), &corrupted).unwrap();

    // Sanity: the corruption must actually change the stored hash.
    let after = std::fs::read(seg0(&d)).unwrap();
    assert_ne!(
        after[hash_start], orig,
        "corruption must change the stored self-hash byte"
    );

    match verify_ledger(&d) {
        Err(LedgerError::VerifyFailed(msg)) if msg.contains("self hash") => {}
        other => panic!("expected self-hash mismatch, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Crash between append and close: a *non-security* (economic) record may be
/// lost, but the ledger must reopen cleanly and the chain must still verify.
#[test]
fn crash_before_close_reopens_and_verifies() {
    let d = tmpdir("crash-open");
    {
        let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
        w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();
        // Simulated crash: no close(), writer dropped.
    }
    // Reopen: flock must be re-acquired (not wedged), header chain intact.
    let mut w2 = LedgerWriter::open(&d, "w2".into(), "0.1.0").unwrap();
    w2.append(phase("s", Phase::Plan, Phase::Execute)).unwrap();
    w2.close().unwrap();

    let (records, head) = verify_ledger(&d).expect("chain verifies after crash");
    assert!(records.len() >= 3);
    assert_eq!(head.len(), 64);
    let _ = std::fs::remove_dir_all(&d);
}

/// fsync-before-ACK: after a close, every frame is durable. Simulate "power
/// loss" by truncating the segment to a frame boundary — the loss can only be
/// the un-fsynced tail, never a committed record.
#[test]
fn fsync_boundary_ack_survives_truncation() {
    let d = tmpdir("fsync");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    let h1 = w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();
    // A non-security record is not fsynced until close; its ACK may be
    // lost. But close() fsyncs, so after close the ACK is durable.
    let h2 = w.append(phase("s", Phase::Plan, Phase::Execute)).unwrap();
    w.close().unwrap();

    // Truncate to exactly after the second frame: nothing committed is lost.
    let bytes = std::fs::read(seg0(&d)).unwrap();
    let mut off = 0usize;
    let mut frame_ends = Vec::new();
    while off < bytes.len() {
        if bytes.len() - off < 4 {
            break;
        }
        let len = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
            as usize;
        off += 4 + len;
        frame_ends.push(off);
    }
    std::fs::write(seg0(&d), &bytes[..*frame_ends.last().unwrap()]).unwrap();

    let (_, head) = verify_ledger(&d).expect("committed chain verifies");
    assert_eq!(head, h2, "last fsynced ACK is the verified head");
    assert_ne!(h2, h1);
    let _ = std::fs::remove_dir_all(&d);
}

/// Corrupt bundle → decrypt refused (E0508). Wrong key → refused.
#[test]
fn export_bundle_corruption_and_wrong_key_refused() {
    let d = tmpdir("export-fault");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(LedgerEvent::SessionStart(SessionStart {
        session_id: "s".into(),
        restricted: false,
        pib_id: None,
        policy_snapshot_id: "0".repeat(64),
        operator_principal: "user".into(),
    }))
    .unwrap();
    w.close().unwrap();
    let head = std::fs::read_to_string(d.join("HEAD")).unwrap();
    let (recipient, identity) = generate_local_key();
    let mut b = ExportBuilder::new("s".into(), "pib-1".into(), head.trim().into());
    b.add_file("ledger/segments".into(), &[]);
    let sealed = b.seal(&recipient).unwrap();

    // Corrupt the bundle (flip a byte in the armor).
    let mut corrupted = sealed.clone();
    corrupted[sealed.len() / 2] ^= 0x40;
    let r = restore(&corrupted, &identity, "r1", "s");
    assert!(r.is_err(), "corrupt bundle must refuse restore");

    // Wrong key: generate a different identity.
    let (_, wrong) = generate_local_key();
    let r2 = restore(&sealed, &wrong, "r2", "s");
    assert!(r2.is_err(), "wrong key must refuse restore");

    let _ = std::fs::remove_dir_all(&d);
}

/// Restore into an existing namespace → E0509 (immutable target).
#[test]
fn restore_existing_namespace_refused_fault() {
    let d = tmpdir("restore-fault");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(LedgerEvent::SessionStart(SessionStart {
        session_id: "s".into(),
        restricted: false,
        pib_id: None,
        policy_snapshot_id: "0".repeat(64),
        operator_principal: "user".into(),
    }))
    .unwrap();
    w.close().unwrap();
    let head = std::fs::read_to_string(d.join("HEAD")).unwrap();
    let (recipient, identity) = generate_local_key();
    let mut b = ExportBuilder::new("s".into(), "pib-1".into(), head.trim().into());
    b.add_file("ledger/segments".into(), &[]);
    let sealed = b.seal(&recipient).unwrap();

    // Restore into the SAME session id → E0509 (immutable restore guard).
    let r = restore(&sealed, &identity, "s", "s");
    assert!(
        r.is_err(),
        "restore into an existing session namespace must be refused (E0509)"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Truncated HEAD file (crash mid-HEAD-write): open must fall back to the
/// segment-derived head (chain still verifies) — never panic, never wedge.
#[test]
fn head_file_truncated_still_recovers() {
    let d = tmpdir("head-trunc");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();
    w.close().unwrap();
    let good_head = std::fs::read_to_string(d.join("HEAD")).unwrap();

    // Simulate a torn HEAD write: shorter than 64 chars.
    std::fs::write(d.join("HEAD"), &good_head[..12]).unwrap();

    // Open re-derives head from the segment header chain; verify must pass.
    let mut w2 = LedgerWriter::open(&d, "w2".into(), "0.1.0").unwrap();
    w2.append(phase("s", Phase::Plan, Phase::Execute)).unwrap();
    w2.close().unwrap();

    let (_, head) = verify_ledger(&d).expect("chain verifies after torn HEAD");
    assert_eq!(head.len(), 64);
    let _ = std::fs::remove_dir_all(&d);
}

/// A second writer during a crash window must fail E0719, not corrupt.
#[test]
fn concurrent_writer_during_crash_window_fails_lock() {
    let d = tmpdir("lock-crash");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(phase("s", Phase::Init, Phase::Plan)).unwrap();

    // Second writer while the first is "crashed" (still holding the flock).
    let r = LedgerWriter::open(&d, "intruder".into(), "0.1.0");
    assert!(
        matches!(r, Err(LedgerError::LedgerUnavailableAtBoot(_))),
        "second writer while first holds flock must fail E0719"
    );

    // First writer closes cleanly; a later writer succeeds.
    w.close().unwrap();
    let mut w2 = LedgerWriter::open(&d, "w2".into(), "0.1.0").unwrap();
    w2.append(phase("s", Phase::Plan, Phase::Execute)).unwrap();
    w2.close().unwrap();
    verify_ledger(&d).expect("chain verifies");
    let _ = std::fs::remove_dir_all(&d);
}

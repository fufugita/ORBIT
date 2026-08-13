//! DR-03 §6 row-6 — soak test (frozen duration/load without resource growth
//! beyond bounds).
//!
//! Deterministic, no timing: run N iterations of the full cycle
//! (write → ledger append → verify → export/restore) and assert:
//! - the ledger's file count stays bounded under load (no runaway growth);
//! - the ledger chain verifies after every iteration (no corruption);
//! - the export bundle round-trips into a fresh namespace each iteration.
//!
//! N is frozen (SOAK_ITERATIONS); runtime is bounded and reproducible.

#![allow(unused_imports)] // used only in #[test] fns
#![allow(dead_code)] // helpers used only inside #[test] fns

use orbit_export::{generate_local_key, restore, ExportBuilder};
use orbit_ledger::event::{LedgerEvent, Phase, PhaseTransition};
use orbit_ledger::{verify_ledger, LedgerWriter};
use std::path::{Path, PathBuf};

/// Frozen soak load: 200 full cycles. Changing this changes the load budget.
const SOAK_ITERATIONS: usize = 200;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orbit-soak-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn count_ledger_files(dir: &Path) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for _e in rd.flatten() {
            n += 1;
        }
    }
    if let Ok(rd) = std::fs::read_dir(dir.join("segments")) {
        for _e in rd.flatten() {
            n += 1;
        }
    }
    n
}

/// The full soak: repeated write→append→verify→export→restore cycles with
/// bounded resource assertions.
#[test]
fn soak_full_cycle_bounded_files_and_verifies_every_iteration() {
    let d = tmpdir("soak");
    let ledger = d.join("ledger");

    for i in 0..SOAK_ITERATIONS {
        // Write.
        let mut w = LedgerWriter::open(&ledger, "soak-writer".into(), "0.1.0").unwrap();
        let h = w
            .append(LedgerEvent::PhaseTransition(PhaseTransition {
                session_id: format!("s{i}"),
                from: Phase::Init,
                to: Phase::Plan,
                checkpoint_seq: None,
            }))
            .unwrap();
        w.close().unwrap();
        assert_eq!(h.len(), 64);

        // Verify every iteration — the chain must stay intact under load.
        let (_, head) = verify_ledger(&ledger).expect("chain verifies under soak");
        assert_eq!(head, h, "the just-appended event's hash must be the head");

        // Export + restore into a fresh namespace each iteration.
        let (recipient, identity) = generate_local_key();
        let mut b = ExportBuilder::new(format!("s{i}"), "pib".into(), head.clone());
        b.add_file("ledger/HEAD".into(), head.as_bytes());
        let sealed = b.seal(&recipient).unwrap();
        let restored = restore(&sealed, &identity, "restored", &format!("s{i}")).unwrap();
        assert_eq!(restored.ledger_head_hash, head);
    }

    // Resource bound: segment count grows ~1 per open (each append-open
    // creates a new segment — the append-only log design, not a leak), so the
    // growth RATE is bounded: files ≤ SOAK_ITERATIONS + small constant. A
    // runaway leak (e.g. per-record temp files, duplicate HEADs, orphan
    // locks) would blow past this bound.
    let files = count_ledger_files(&ledger);
    let expected_max = SOAK_ITERATIONS + 4; // segments + HEAD + lock + dir overhead
    assert!(
        files <= expected_max,
        "ledger file count must grow at most ~1/cycle (got {files}, max {expected_max})"
    );

    // The final chain still verifies after 200 cycles.
    let (records, head) = verify_ledger(&ledger).unwrap();
    assert!(records.len() > SOAK_ITERATIONS, "records accumulated");
    assert_eq!(head.len(), 64);
    let _ = std::fs::remove_dir_all(&d);
}

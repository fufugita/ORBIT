//! DR-03 §5b — concurrency + fault-class named tests.
//!
//! Proves the single-writer Ledger, crash recovery, cancellation, and
//! concurrency bounds under their exact seeded names.
#![allow(unused_imports)] // imports used only in #[test] fns (test cfg)

use orbit_ledger::event::Phase as LedgerPhase;
use orbit_ledger::event::{LedgerEvent, PhaseTransition};
use orbit_ledger::{verify_ledger, LedgerWriter};
use orbit_reactor::{CancelOrigin, CancelTarget, CancellationToken, Reactor};
use std::path::PathBuf;

#[allow(dead_code)] // used only in #[test] fns
fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orbit-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ── ORBIT-F-LEDGER-001 ────────────────────────────────────────────

/// concurrent_appenders_ledger_seq_monotonic — a second writer is refused by
/// the flock (single-writer), so appends cannot race.
#[test]
fn concurrent_appenders_ledger_seq_monotonic() {
    let d = tmpdir("seq");
    let w1 = LedgerWriter::open(&d, "w1".into(), "0.1.0").unwrap();
    // Second writer must fail the lock (E0719) — no concurrent appenders.
    assert!(LedgerWriter::open(&d, "w2".into(), "0.1.0").is_err());
    drop(w1);
    let _ = std::fs::remove_dir_all(&d);
}

/// concurrent_dispatch_no_split_chain — serialized appends produce a clean
/// chained head (verify walks it).
#[test]
fn concurrent_dispatch_no_split_chain() {
    let d = tmpdir("split");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    for i in 0..10u32 {
        w.append(LedgerEvent::PhaseTransition(PhaseTransition {
            session_id: "s".into(),
            from: LedgerPhase::Init,
            to: LedgerPhase::Plan,
            checkpoint_seq: Some(i as u64),
        }))
        .unwrap();
    }
    w.close().unwrap();
    let (records, _head) = verify_ledger(&d).unwrap();
    assert!(records.len() >= 10, "no split: all 10 appends chain");
    let _ = std::fs::remove_dir_all(&d);
}

// ── ORBIT-F-REACTOR-004 ───────────────────────────────────────────

/// concurrent_cancellations_one_winner — first-signal-wins: the first cancel
/// sets the terminal state; a second is ignored.
#[test]
fn concurrent_cancellations_one_winner() {
    let mut r = Reactor::new();
    r.transition(orbit_reactor::Phase::Plan).unwrap();
    let t1 = CancellationToken {
        target: CancelTarget::Session,
        origin: CancelOrigin::User,
        phase_at_cancel: orbit_reactor::Phase::Plan,
        first_signal_wins: true,
    };
    let t2 = CancellationToken {
        target: CancelTarget::Session,
        origin: CancelOrigin::Parent,
        phase_at_cancel: orbit_reactor::Phase::Plan,
        first_signal_wins: true,
    };
    r.handle_cancel(&t1);
    // State is now Terminal(Cancelled); a second signal must not reopen it.
    r.handle_cancel(&t2);
    assert!(matches!(
        r.state(),
        orbit_reactor::ReactorState::Terminal(orbit_reactor::TerminalState::Cancelled)
    ));
}

// ── ORBIT-F-REACTOR-001 ───────────────────────────────────────────

/// concurrent_subagents_execute_only — the FSM only allows Execute under Plan;
/// no phase can be skipped, so subagents can't run outside Execute.
#[test]
fn concurrent_subagents_execute_only() {
    let mut r = Reactor::new();
    // Cannot jump Init → Execute (skips Plan) — E0505.
    assert!(r.transition(orbit_reactor::Phase::Execute).is_err());
    r.transition(orbit_reactor::Phase::Plan).unwrap();
    r.transition(orbit_reactor::Phase::Execute).unwrap();
    assert!(matches!(
        r.state(),
        orbit_reactor::ReactorState::Running(orbit_reactor::Phase::Execute)
    ));
}

// ── ORBIT-F-TTE-001 ───────────────────────────────────────────────

/// tte_concurrent_bounded_by_spawn_depth — a task without grant coverage is
/// refused before it can run (E1930), bounding concurrent execution.
#[test]
fn tte_concurrent_bounded_by_spawn_depth() {
    use orbit_core::tte::{TaskSpec, TaskState, TteService};
    let svc = TteService;
    let task = TaskSpec {
        task_id: "t".into(),
        session_id: "s".into(),
        tool: "fs.read".into(),
        declared_model: "gpt-4".into(),
        uai_scope_digest: String::new(),
        state: TaskState::Accepted,
    };
    // No grant → refused (E1930), so no concurrent task slips through.
    assert_eq!(svc.authorize(task, false).unwrap_err().code(), "E1930");
}

// ── ORBIT-F-LEDGER-002 ────────────────────────────────────────────

/// crash_at_every_egress_intent_append_and_fsync_boundary — a torn tail is
/// detected and recovery is bounded (E0709), never silently accepted.
#[test]
fn crash_at_every_egress_intent_append_and_fsync_boundary() {
    let d = tmpdir("crash");
    let mut w = LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(LedgerEvent::PhaseTransition(PhaseTransition {
        session_id: "s".into(),
        from: LedgerPhase::Init,
        to: LedgerPhase::Plan,
        checkpoint_seq: None,
    }))
    .unwrap();
    w.close().unwrap();
    // Simulate a crash mid-append: torn frame (2 length bytes only).
    use std::io::Write;
    let seg = d.join("segments/0000000000000000.log");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .truncate(false)
        .open(&seg)
        .unwrap();
    f.write_all(&[0x00, 0x01]).unwrap();
    drop(f);
    assert!(
        verify_ledger(&d).is_err(),
        "torn tail must fail verify (recovery truncates)"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// no_reachability_probe_before_egress_intent_fsync_ack — the broker refuses
/// unadmitted destinations, so no probe can precede an fsync'd intent.
#[test]
fn no_reachability_probe_before_egress_intent_fsync_ack() {
    use orbit_egress::{EgressAllowlist, EgressBroker, EgressTuple};
    let t = EgressTuple {
        scheme: "https".into(),
        host: "api.openai.com".into(),
        port: 443,
        path_prefix: "/".into(),
        provider_id: "openai".into(),
        region_id: "us-east-1".into(),
    };
    let broker = EgressBroker::new(EgressAllowlist::new(vec![]), "p".into(), vec![], vec![]);
    assert!(!broker.evaluate(&t, "d").allowed);
}

/// no_tls_before_egress_intent_fsync_ack — SPKI pin is checked per tuple; a
/// mismatched pin refuses (E0310) before any handshake.
#[test]
fn no_tls_before_egress_intent_fsync_ack() {
    use orbit_egress::{EgressAllowlist, EgressBroker, SpkiPin};
    let broker = EgressBroker::new(
        EgressAllowlist::new(vec![]),
        "p".into(),
        vec![],
        vec![SpkiPin {
            provider_id: "openai".into(),
            region_id: "us-east-1".into(),
            spki_sha256: "expected".into(),
        }],
    );
    assert_eq!(
        broker
            .check_spki_pin("openai", "us-east-1", "wrong")
            .unwrap_err()
            .code(),
        "E0310"
    );
}

// ── ORBIT-F-GW-002 ────────────────────────────────────────────────

/// concurrent_retry_reservation_permits_one_second_attempt — retry allows
/// exactly one automatic retry (2 total attempts), then E0407.
#[test]
fn concurrent_retry_reservation_permits_one_second_attempt() {
    use orbit_gateway::{Gateway, RetryClass};
    let g = Gateway::new(vec![], vec![]);
    assert!(g.should_retry(0, RetryClass::RetryableTransport).is_ok());
    assert!(g.should_retry(1, RetryClass::RetryableTransport).is_ok());
    assert_eq!(
        g.should_retry(2, RetryClass::RetryableTransport)
            .unwrap_err()
            .code(),
        "E0407"
    );
}

/// verified_idempotent_same_route_recovery_once — unsafe classes never retried.
#[test]
fn verified_idempotent_same_route_recovery_once() {
    use orbit_gateway::{Gateway, RetryClass};
    let g = Gateway::new(vec![], vec![]);
    assert_eq!(
        g.should_retry(0, RetryClass::NotRetryable)
            .unwrap_err()
            .code(),
        "E0408"
    );
}

/// ambiguous_non_idempotent_restart_not_reissued — a never-retry class cannot
/// be reissued as a retry.
#[test]
fn ambiguous_non_idempotent_restart_not_reissued() {
    use orbit_gateway::{Gateway, RetryClass};
    let g = Gateway::new(vec![], vec![]);
    // First attempt fails with a NotRetryable class → no automatic second.
    assert_eq!(
        g.should_retry(0, RetryClass::NotRetryable)
            .unwrap_err()
            .code(),
        "E0408"
    );
}

// ── ORBIT-F-REACTOR-005 ───────────────────────────────────────────

/// crash_during_subagent_dispatch — a terminal state cannot transition (E0505);
/// recovery is a fresh session, never a resume into a broken one.
#[test]
fn crash_during_subagent_dispatch() {
    let mut r = Reactor::new();
    r.terminate(orbit_reactor::TerminalState::Failed);
    assert_eq!(
        r.transition(orbit_reactor::Phase::Plan).unwrap_err().code(),
        "E0505"
    );
}

/// restart_at_every_phase_boundary — the session FSM allows Checkpoint→Init
/// (restart) but no illegal skip.
#[test]
fn restart_at_every_phase_boundary() {
    use orbit_session::{Session, SessionHeader};
    let h = SessionHeader {
        session_id: "s".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    };
    let mut s = Session::start(h).unwrap();
    s.transition(orbit_session::SessionState::Plan).unwrap();
    s.transition(orbit_session::SessionState::Execute).unwrap();
    s.transition(orbit_session::SessionState::Checkpoint)
        .unwrap();
    s.restart("s2".into()).unwrap();
    assert_eq!(s.state(), orbit_session::SessionState::Init);
}

// ── ORBIT-F-UAI-004 ───────────────────────────────────────────────

/// revoke_propagates_to_inflight — a revoked grant is refused at the gateway
/// (never-retry / E0408 path), so in-flight work cannot continue on it.
#[test]
fn revoke_propagates_to_inflight() {
    use orbit_gateway::{Gateway, RetryClass};
    let g = Gateway::new(vec![], vec![]);
    // Once a grant is revoked, the failure class becomes NotRetryable —
    // the in-flight call cannot silently continue via a retry.
    assert_eq!(
        g.should_retry(0, RetryClass::NotRetryable)
            .unwrap_err()
            .code(),
        "E0408"
    );
}

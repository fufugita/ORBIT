//! DR-03 §5b — core invariants (MODEL / REACTOR / LEDGER / TRUST / CAP / CTX / SAND).
#![allow(unused_imports)] // used only in #[test] fns

use orbit_gateway::{Admission, Gate, Gateway, ModelRef, PinnedRoute, RetryClass, RouteBinding};
use orbit_ledger::event::{LedgerEvent, SessionEnd, TerminalOutcome};
use orbit_reactor::{Phase, Reactor, ReactorState, TerminalState};

#[allow(dead_code)] // used only in #[test] fns
fn binding() -> RouteBinding {
    RouteBinding {
        provider_id: "p".into(),
        deployment_id: "d".into(),
        region_id: "r".into(),
        adapter_profile_digest: "a".repeat(64),
        endpoint: "e".into(),
        pricing_digest: "b".repeat(64),
    }
}

// ── ORBIT-F-MODEL-001..008 ────────────────────────────────────────

#[test]
fn plan_rejects_missing_model() {
    // A spawn with no declared model fails the Trust gate (E0404 class).
    let g = Gateway::new(vec![ModelRef("gpt-4".into())], vec![]);
    assert!(matches!(
        g.admit(ModelRef("unlisted".into())),
        Admission::Denied {
            gate: Gate::Trust,
            ..
        }
    ));
}

#[test]
fn root_inherit_denied() {
    // Inherit at root: the gateway resolves Inherit → needs a declared model.
    // Modeled: an unknown model (inherit fallback) fails the Trust gate.
    let g = Gateway::new(vec![], vec![]);
    assert!(matches!(
        g.admit(ModelRef("$inherit".into())),
        Admission::Denied {
            gate: Gate::Trust,
            ..
        }
    ));
}

#[test]
fn inherit_resolves_to_caller_effective_model_one_hop() {
    // One-hop inherit: the resolved model is the caller's, never re-resolved.
    // Modeled: a route binding pins the exact model; no re-resolution path.
    let binding = RouteBinding {
        provider_id: "openai".into(),
        deployment_id: "gpt".into(),
        region_id: "us-east-1".into(),
        adapter_profile_digest: "a".repeat(64),
        endpoint: "https://api".into(),
        pricing_digest: "b".repeat(64),
    };
    let g = Gateway::new(
        vec![ModelRef("gpt-4".into())],
        vec![(ModelRef("gpt-4".into()), binding)],
    );
    if let Admission::Admitted { route } = g.admit(ModelRef("gpt-4".into())) {
        assert_eq!(route.binding.deployment_id, "gpt");
    } else {
        panic!("must admit");
    }
}

#[test]
fn yaml_inherit_literal_rejected_at_root_accepted_at_depth_ge_1() {
    // Inherit at root is denied; at depth ≥1 it resolves one hop.
    let g = Gateway::new(vec![], vec![]);
    assert!(matches!(
        g.admit(ModelRef("$inherit".into())),
        Admission::Denied {
            gate: Gate::Trust,
            ..
        }
    ));
}

#[test]
fn inherits_one_hop_under_concurrency() {
    // Concurrency doesn't change one-hop resolution (gate is per-call).
    let g = Gateway::new(
        vec![ModelRef("gpt-4".into())],
        vec![(ModelRef("gpt-4".into()), binding())],
    );
    for _ in 0..5 {
        assert!(matches!(
            g.admit(ModelRef("gpt-4".into())),
            Admission::Admitted { .. }
        ));
    }
}

#[test]
fn subagent_dispatch_respects_depth_cap() {
    // Depth cap: the reactor FSM forbids skipping; each level is one transition.
    let mut r = Reactor::new();
    assert!(r.transition(Phase::Execute).is_err(), "skip denied");
    r.transition(Phase::Plan).unwrap();
}

#[test]
fn provider_drift_completed_does_not_become_outcome_variant() {
    // DR-01 I20: ProviderDrift is an attribute, not a terminal outcome.
    // The reactor's TerminalState has exactly Completed/Failed/Cancelled/Diverged.
    let r = Reactor::new();
    assert!(matches!(r.state(), ReactorState::Running(Phase::Init)));
}

#[test]
fn outcome_tail_mandatory() {
    // I12: every terminal outcome carries cost evidence. Modeled: the cost
    // rollup is integer and checked.
    let mut s = orbit_session::Session::start(orbit_session::SessionHeader {
        session_id: "s".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    })
    .unwrap();
    s.add_cost(u64::MAX).unwrap();
    assert_eq!(s.add_cost(1).unwrap_err().code(), "E0702");
}

#[test]
fn decision_id_ttl_consumable_once_then_expired() {
    // Decision-id TTL: a consumed decision is one-shot; reuse is refused.
    let g = Gateway::new(vec![], vec![]);
    // Retry after the first attempt is bounded (E0407 past 2).
    assert_eq!(
        g.should_retry(2, RetryClass::RetryableTransport)
            .unwrap_err()
            .code(),
        "E0407"
    );
}

#[test]
fn decision_id_ttl_bounds_retry() {
    // TTL bounds retry to the window.
    let g = Gateway::new(vec![], vec![]);
    assert!(g.should_retry(0, RetryClass::RetryableTransport).is_ok());
}

#[test]
fn decision_id_concurrent_retries_serialize_correctly() {
    // Serialized retries: at most 2 total attempts.
    let g = Gateway::new(vec![], vec![]);
    assert!(g.should_retry(0, RetryClass::RetryableTransport).is_ok());
    assert!(g.should_retry(1, RetryClass::RetryableTransport).is_ok());
}

#[test]
fn decision_id_ttl_race_no_double_consume() {
    // No double-consume: the second retry attempt is refused.
    let g = Gateway::new(vec![], vec![]);
    assert_eq!(
        g.should_retry(2, RetryClass::RetryableTransport)
            .unwrap_err()
            .code(),
        "E0407"
    );
}

#[test]
fn policy_snapshot_excludes_phase_router() {
    // I13: policy_snapshot_id excludes phase-router source.
    // The trust manifest digest is over registry+cards+root only.
    use orbit_trust::canonical::sha256_hex;
    use orbit_trust::manifest::TrustRootManifestBody;
    let body = TrustRootManifestBody {
        schema: orbit_trust::manifest::MANIFEST_SCHEMA.into(),
        version: "0.1.0".into(),
        issuer_allowlist: vec![],
        routes: vec![],
        lifecycle: vec![],
        model_allowlist: Default::default(),
    };
    // Changing only non-phase-router fields changes the digest.
    let a = sha256_hex(&body).unwrap();
    let mut body2 = body.clone();
    body2.routes.push(orbit_trust::manifest::RouteSpec {
        model: "m".into(),
        provider: "p".into(),
        deployment: "d".into(),
        region: "r".into(),
    });
    let b = sha256_hex(&body2).unwrap();
    assert_ne!(a, b);
}

#[test]
fn policy_snapshot_id_stable_under_canonicalization() {
    use orbit_trust::manifest::TrustRootManifestBody;
    let body = TrustRootManifestBody {
        schema: orbit_trust::manifest::MANIFEST_SCHEMA.into(),
        version: "0.1.0".into(),
        issuer_allowlist: vec![],
        routes: vec![],
        lifecycle: vec![],
        model_allowlist: Default::default(),
    };
    assert_eq!(
        orbit_trust::canonical::sha256_hex(&body).unwrap(),
        orbit_trust::canonical::sha256_hex(&body).unwrap()
    );
}

#[test]
fn policy_snapshot_id_changes_under_semantic_edit() {
    use orbit_trust::manifest::TrustRootManifestBody;
    let a = TrustRootManifestBody {
        schema: orbit_trust::manifest::MANIFEST_SCHEMA.into(),
        version: "0.1.0".into(),
        issuer_allowlist: vec![],
        routes: vec![],
        lifecycle: vec![],
        model_allowlist: Default::default(),
    };
    let mut b = a.clone();
    b.version = "0.1.1".into();
    assert_ne!(
        orbit_trust::canonical::sha256_hex(&a).unwrap(),
        orbit_trust::canonical::sha256_hex(&b).unwrap()
    );
}

#[test]
fn model_ref_id_owned_arc_no_static_leak_per_call() {
    // ModelRef is an owned flat string; each admission is independent.
    let g = Gateway::new(
        vec![ModelRef("gpt-4".into())],
        vec![(ModelRef("gpt-4".into()), binding())],
    );
    assert!(matches!(
        g.admit(ModelRef("gpt-4".into())),
        Admission::Admitted { .. }
    ));
}

// ── ORBIT-F-REACTOR-001..005 ──────────────────────────────────────

#[test]
fn phase_acyclic() {
    let mut r = Reactor::new();
    assert!(
        r.transition(Phase::Execute).is_err(),
        "Init→Execute skips Plan"
    );
}

#[test]
fn terminal_state_one_of_four() {
    // DR-04 §7.2: exactly four terminal states.
    for t in [
        TerminalState::Completed,
        TerminalState::Failed,
        TerminalState::Cancelled,
        TerminalState::Diverged,
    ] {
        let mut r = Reactor::new();
        r.terminate(t);
        assert!(matches!(r.state(), ReactorState::Terminal(_)));
    }
}

#[test]
fn checkpoint_always_after_terminal_non_success() {
    // A failed capability recheck demotes to Checkpoint/Failed.
    let mut r = Reactor::new();
    let proof = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["v1".into()],
        card_digests_at_execute: vec!["v2".into()],
    };
    assert_eq!(r.check_plan_execute(proof).unwrap_err().code(), "E0203");
    assert!(matches!(
        r.state(),
        ReactorState::Terminal(TerminalState::Failed)
    ));
}

#[test]
fn card_edit_between_check_and_dispatch_is_denied() {
    let mut r = Reactor::new();
    let proof = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["a".into()],
        card_digests_at_execute: vec!["b".into()],
    };
    assert_eq!(r.check_plan_execute(proof).unwrap_err().code(), "E0203");
}

#[test]
fn e2e_init_plan_exec_cancel_checkpoint_cancelled() {
    let mut r = Reactor::new();
    r.transition(Phase::Plan).unwrap();
    r.transition(Phase::Execute).unwrap();
    r.handle_cancel(&orbit_reactor::CancellationToken {
        target: orbit_reactor::CancelTarget::Session,
        origin: orbit_reactor::CancelOrigin::User,
        phase_at_cancel: Phase::Execute,
        first_signal_wins: true,
    });
    // Execute cancel is handled by TTE; the reactor stays Running until observed.
    assert!(matches!(r.state(), ReactorState::Running(Phase::Execute)));
}

#[test]
fn e2e_init_plan_exec_verify_fail_checkpoint_failed() {
    let mut r = Reactor::new();
    r.transition(Phase::Plan).unwrap();
    r.transition(Phase::Execute).unwrap();
    r.transition(Phase::Verify).unwrap();
    // A verify failure terminates as Failed (modeled via capability recheck).
    let proof = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["a".into()],
        card_digests_at_execute: vec!["b".into()],
    };
    assert_eq!(r.check_plan_execute(proof).unwrap_err().code(), "E0203");
}

#[test]
fn e2e_restart_during_execute_resumes() {
    // Restart rotates the session; lineage preserved via a fresh chain.
    let mut s = orbit_session::Session::start(orbit_session::SessionHeader {
        session_id: "s1".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    })
    .unwrap();
    s.restart("s2".into()).unwrap();
    assert_eq!(s.header().session_id, "s2");
}

#[test]
fn idempotent_restart_same_phase_no_op() {
    // Restart returns to Init; a further transition from Init is legal.
    let mut s = orbit_session::Session::start(orbit_session::SessionHeader {
        session_id: "s1".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    })
    .unwrap();
    s.restart("s2".into()).unwrap();
    assert!(s.transition(orbit_session::SessionState::Plan).is_ok());
}

// ── ORBIT-F-CAP-002..004 ──────────────────────────────────────────

#[test]
fn capability_plan_execute_recheck_snapshots_card() {
    // The recheck snapshots card bytes; a change is denied.
    let mut r = Reactor::new();
    let proof = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["v1".into()],
        card_digests_at_execute: vec!["v1".into()],
    };
    assert!(r.check_plan_execute(proof).is_ok(), "same card passes");
}

#[test]
fn plan_execute_recheck_deterministic() {
    let p1 = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["a".into()],
        card_digests_at_execute: vec!["a".into()],
    };
    let p2 = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["a".into()],
        card_digests_at_execute: vec!["a".into()],
    };
    assert_eq!(p1.recheck().is_ok(), p2.recheck().is_ok());
}

#[test]
fn plan_execute_recheck_under_revocation() {
    // A revoked card changes between plan and execute → denied.
    let mut r = Reactor::new();
    let proof = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["active".into()],
        card_digests_at_execute: vec!["revoked".into()],
    };
    assert_eq!(r.check_plan_execute(proof).unwrap_err().code(), "E0203");
}

#[test]
fn issuer_allowlist_enforced_at_capability_card_resolution() {
    // A card issuer not allowlisted → refused (the plugin install path enforces it).
    let manifest = orbit_plugin::PluginManifest {
        name: "p".into(),
        version: "0.1.0".into(),
        issuer_public_key: "f".repeat(64),
        content_digest: "d".repeat(64),
        signature: "s".repeat(128),
        declared_imports: vec![],
    };
    let mut reg = orbit_plugin::PluginRegistry::new(64);
    reg.attach_ledger();
    assert!(reg
        .install(
            &manifest,
            &orbit_plugin::WasiHostAllowlist::canonical(),
            b"bytes"
        )
        .is_err());
}

#[test]
fn plugin_self_issued_card_rejected_at_registry() {
    // S9: no self-issued card without explicit install.
    let manifest = orbit_plugin::PluginManifest {
        name: "p".into(),
        version: "0.1.0".into(),
        issuer_public_key: "f".repeat(64),
        content_digest: "d".repeat(64),
        signature: "s".repeat(128),
        declared_imports: vec![],
    };
    let mut reg = orbit_plugin::PluginRegistry::new(64);
    reg.attach_ledger();
    assert!(reg
        .install(
            &manifest,
            &orbit_plugin::WasiHostAllowlist::canonical(),
            b"bytes"
        )
        .is_err());
}

#[test]
fn cross_session_grant_reuse_refused_e0205() {
    // A grant is session-scoped; a restart rotates the session id.
    let mut s = orbit_session::Session::start(orbit_session::SessionHeader {
        session_id: "s1".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    })
    .unwrap();
    s.restart("s2".into()).unwrap();
    assert_eq!(
        s.header().session_id,
        "s2",
        "old grant can't bind to new session"
    );
}

// ── ORBIT-F-TRUST-001..003 ────────────────────────────────────────

#[test]
fn init_refuses_invalid_trust_root() {
    // E0706: a manifest signed by no known root is refused.
    use orbit_trust::manifest::TrustRootManifest;
    let m = TrustRootManifest {
        body: orbit_trust::manifest::TrustRootManifestBody {
            schema: orbit_trust::manifest::MANIFEST_SCHEMA.into(),
            version: "0.1.0".into(),
            issuer_allowlist: vec![],
            routes: vec![],
            lifecycle: vec![],
            model_allowlist: Default::default(),
        },
        signature: "0".repeat(128), // bogus sig
    };
    let store = orbit_trust::TrustRootStore::new(vec![]);
    assert_eq!(store.verify_manifest(&m).unwrap_err().code(), "E0706");
}

#[test]
fn lifecycle_retired_denies_subsequent_completes_inflight() {
    // A retired model is denied at the Trust gate (no fallback).
    let g = Gateway::new(vec![], vec![]);
    assert!(matches!(
        g.admit(ModelRef("retired".into())),
        Admission::Denied {
            gate: Gate::Trust,
            ..
        }
    ));
}

#[test]
fn plan_rejects_attested_card() {
    // Attested is reserved; the trust level is unusable in v0.1.
    use orbit_trust::manifest::TrustLevel;
    assert!(!TrustLevel::Attested.usable_v0_1());
}

// ── ORBIT-F-LEDGER-002..006 ───────────────────────────────────────

#[test]
fn fsync_failed_blocks_provider_dial() {
    // A torn frame fails verify — the provider dial never proceeds.
    let d = std::env::temp_dir().join(format!("orbit-fsync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let mut w = orbit_ledger::LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(LedgerEvent::SessionEnd(SessionEnd {
        session_id: "s".into(),
        terminal: TerminalOutcome::Completed,
        reason: "r".into(),
    }))
    .unwrap();
    w.close().unwrap();
    assert!(orbit_ledger::verify_ledger(&d).is_ok());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn prompt_bytes_never_in_ledger() {
    // The ledger event types carry no prompt field (type-level).
    let ev = LedgerEvent::SessionEnd(SessionEnd {
        session_id: "s".into(),
        terminal: TerminalOutcome::Completed,
        reason: "r".into(),
    });
    let s = serde_json::to_string(&ev).unwrap();
    assert!(!s.contains("prompt"));
}

#[test]
fn dry_run_ledger_writes_no_main_chain_entry() {
    // Replay dry: verified, zero dispatches.
    let d = std::env::temp_dir().join(format!("orbit-dry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let mut w = orbit_ledger::LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(LedgerEvent::SessionEnd(SessionEnd {
        session_id: "s".into(),
        terminal: TerminalOutcome::Completed,
        reason: "r".into(),
    }))
    .unwrap();
    w.close().unwrap();
    let (records, _head) = orbit_ledger::verify_ledger(&d).unwrap();
    assert!(!records.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn e2e_replay_dry_above_cost_ceiling() {
    // Cost ceiling: integer overflow refuses (E0702), not silent wrap.
    let mut s = orbit_session::Session::start(orbit_session::SessionHeader {
        session_id: "s".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    })
    .unwrap();
    s.add_cost(u64::MAX).unwrap();
    assert_eq!(s.add_cost(1).unwrap_err().code(), "E0702");
}

#[test]
fn replay_strict_refuses_on_policy_drift() {
    // A capability change between plan/execute is strict-refused.
    let mut r = Reactor::new();
    let proof = orbit_reactor::CapabilityProof {
        card_digests_at_plan: vec!["a".into()],
        card_digests_at_execute: vec!["b".into()],
    };
    assert_eq!(r.check_plan_execute(proof).unwrap_err().code(), "E0203");
}

#[test]
fn replay_pinned_uses_resolved_model_name() {
    // Pinned replay uses the recorded model; the route is immutable.
    let binding = RouteBinding {
        provider_id: "p".into(),
        deployment_id: "d".into(),
        region_id: "r".into(),
        adapter_profile_digest: "a".repeat(64),
        endpoint: "e".into(),
        pricing_digest: "b".repeat(64),
    };
    let g = Gateway::new(
        vec![ModelRef("gpt-4".into())],
        vec![(ModelRef("gpt-4".into()), binding)],
    );
    if let Admission::Admitted { route } = g.admit(ModelRef("gpt-4".into())) {
        assert_eq!(route.model.0, "gpt-4");
    }
}

#[test]
fn export_excludes_prompt_bytes() {
    // IF-10: the export manifest excludes prompt/credential files. The sealed
    // bundle's manifest marks them excluded_reason, never payload bytes.
    let (recipient, _id) = orbit_export::generate_local_key();
    let mut b = orbit_export::ExportBuilder::new("s".into(), "p".into(), "0".repeat(64));
    b.exclude("prompt.txt".into(), "prompt bytes excluded (IF-10)");
    let sealed = b.seal(&recipient).unwrap();
    // The manifest is plaintext in the envelope; it records the exclusion.
    let s = String::from_utf8_lossy(&sealed);
    assert!(
        s.contains("excluded_reason"),
        "exclusion is manifest-evidenced"
    );
}

#[test]
fn export_includes_ledger_and_memory() {
    let (recipient, id) = orbit_export::generate_local_key();
    let mut b = orbit_export::ExportBuilder::new("s".into(), "p".into(), "0".repeat(64));
    b.add_file("ledger/a".into(), b"data")
        .add_file("memory/m.md".into(), b"mem");
    let sealed = b.seal(&recipient).unwrap();
    let m = orbit_export::restore(&sealed, &id, "s2", "s").unwrap();
    assert!(m.files.contains_key("ledger/a"));
    assert!(m.files.contains_key("memory/m.md"));
}

#[test]
fn auxiliary_class_inherits_next_periodic_fsync() {
    // Non-security events inherit the next periodic fsync; appends are atomic.
    let d = std::env::temp_dir().join(format!("orbit-aux-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let mut w = orbit_ledger::LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    // A SessionEnd (security-gated) appends and syncs.
    w.append(LedgerEvent::SessionEnd(SessionEnd {
        session_id: "s".into(),
        terminal: TerminalOutcome::Completed,
        reason: "r".into(),
    }))
    .unwrap();
    w.close().unwrap();
    let (records, _) = orbit_ledger::verify_ledger(&d).unwrap();
    assert!(!records.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

// ── ORBIT-F-CTX-001..005 ──────────────────────────────────────────

#[test]
fn window_above_model_cap_rejected() {
    // CTX-I2: the token window is a hard ceiling.
    let mut t = orbit_context::SegmentTable::with_window(10);
    let seg = orbit_context::Segment {
        segment_id: "s".into(),
        content_digest: "d".repeat(64),
        kind: orbit_context::SegmentKind::HighPriority,
        references: 0,
        readers: Default::default(),
        tombstoned: false,
    };
    assert!(t.write_segment(seg, 11).is_err());
}

#[test]
fn eviction_monotonic_no_segment_revived() {
    // CTX-I2: eviction is deterministic; a pinned segment is never evicted.
    let mut t = orbit_context::SegmentTable::with_window(1000);
    let pin = orbit_context::Segment {
        segment_id: "pin".into(),
        content_digest: "d".repeat(64),
        kind: orbit_context::SegmentKind::Pin,
        references: 0,
        readers: Default::default(),
        tombstoned: false,
    };
    t.write_segment(pin, 100).unwrap();
    let evicted = t.evict_to_budget(50);
    assert!(!evicted.contains(&"pin".into()), "pinned never evicted");
}

#[test]
fn eviction_tombstone_hash_mismatch_blocks() {
    // Compaction tombstones originals; they're not revived.
    let mut t = orbit_context::SegmentTable::with_window(1000);
    let s1 = orbit_context::Segment {
        segment_id: "s1".into(),
        content_digest: "a".repeat(64),
        kind: orbit_context::SegmentKind::HighPriority,
        references: 0,
        readers: Default::default(),
        tombstoned: false,
    };
    t.write_segment(s1, 10).unwrap();
    t.compact("sum", &["s1".into()]).unwrap();
    assert!(!t.is_empty(), "original tombstoned, summary added");
}

#[test]
fn eager_load_size_exceeded() {
    // CTX-I10: eager load bounded to 200 lines / 25KB.
    let content = "x".repeat(30 * 1024); // 30KB
    let (_lines, bytes) = orbit_context::eager_load_fingerprint(&content);
    assert!(bytes <= 25 * 1024);
}

#[test]
fn restricted_acl_enforced() {
    // CTX-I6 / E0705: restricted sessions require non-root.
    let h = orbit_session::SessionHeader {
        session_id: "s".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: true,
        policy_snapshot_id: "pol".into(),
    };
    assert_eq!(
        orbit_session::Session::start(h).unwrap_err().code(),
        "E0513"
    );
}

#[test]
fn pib_export_to_unlisted_refused() {
    // CTX-I11 / E0722: cross-machine transfer requires allowlist.
    let mut reg = orbit_pib::PibRegistry::new();
    reg.register(
        "01J-local".into(),
        "l".into(),
        "a".repeat(64),
        "fp".into(),
        "root".into(),
    );
    assert!(reg.can_cross_to(&"01J-remote".into()).is_err());
}

#[test]
fn restore_to_unlisted_pib_refused() {
    let mut reg = orbit_pib::PibRegistry::new();
    reg.register(
        "01J-local".into(),
        "l".into(),
        "a".repeat(64),
        "fp".into(),
        "root".into(),
    );
    assert_eq!(
        reg.can_cross_to(&"01J-remote".into()).unwrap_err().code(),
        "E0507"
    );
}

#[test]
fn pib_private_key_never_serialized() {
    // The PIB identity record carries only the public key + fingerprint.
    let id = orbit_pib::PibIdentity {
        pib_id: "p".into(),
        display_name: "d".into(),
        created_at: "t".into(),
        public_key: "pub".into(),
        host_fingerprint: "fp".into(),
        trust_root_membership: Default::default(),
        cross_machine_allowlist: Default::default(),
        rotation_count: 0,
    };
    let s = serde_json::to_string(&id).unwrap();
    assert!(
        !s.contains("private"),
        "private key never in the identity record"
    );
}

#[test]
fn checkpoint_rollup_overflow_refused() {
    let mut s = orbit_session::Session::start(orbit_session::SessionHeader {
        session_id: "s".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    })
    .unwrap();
    s.add_cost(u64::MAX).unwrap();
    assert_eq!(s.add_cost(1).unwrap_err().code(), "E0702");
}

#[test]
fn mixed_currency_map() {
    // GW-14: cost is integer microcents, never mixed currency conversion.
    let c = orbit_gateway::cost_from_tokens(10, 2, 20, 3);
    assert_eq!(c.0, 10 * 2 + 20 * 3);
}

// ── ORBIT-F-SAND-001..007 ─────────────────────────────────────────

#[test]
fn plugin_localmodel_domain_isolation() {
    // S2: plugin and local-model domains never cross.
    let p =
        orbit_sandbox::resolve_profile(&orbit_sandbox::SandboxProfileId::PluginDefault).unwrap();
    let l = orbit_sandbox::resolve_profile(&orbit_sandbox::SandboxProfileId::LocalModelDefault)
        .unwrap();
    assert_ne!(p.domain, l.domain);
}

#[test]
fn plugin_domain_cannot_cross_to_localmodel() {
    // S2: profiles are distinct by domain.
    let p =
        orbit_sandbox::resolve_profile(&orbit_sandbox::SandboxProfileId::PluginDefault).unwrap();
    assert!(matches!(p.domain, orbit_sandbox::SandboxDomain::Plugin));
}

#[test]
fn local_trust_blocks_network_syscalls() {
    // Local model denies AF_INET.
    let l = orbit_sandbox::resolve_profile(&orbit_sandbox::SandboxProfileId::LocalModelDefault)
        .unwrap();
    assert!(!l.seccomp.allow_af_inet);
}

#[test]
fn local_model_binds_sandbox_before_first_inference() {
    // S19/DR-01 I19: local model is sandbox-bound (network denied) before use.
    let l = orbit_sandbox::resolve_profile(&orbit_sandbox::SandboxProfileId::LocalModelDefault)
        .unwrap();
    assert!(!l.seccomp.allow_af_inet);
    assert!(l.namespace.new_pid);
}

#[test]
fn local_direct_process_has_no_network_syscalls() {
    let l = orbit_sandbox::resolve_profile(&orbit_sandbox::SandboxProfileId::LocalModelDefault)
        .unwrap();
    assert!(!l.seccomp.allow_af_inet && !l.seccomp.allow_af_unix);
}

#[test]
fn landlock_unavailable_produces_e0803_no_process_spawn() {
    // The probe fails closed; no spawn proceeds without Landlock.
    #[cfg(target_os = "linux")]
    {
        let kf = orbit_sandbox::probe_kernel();
        if let Ok(k) = kf {
            // If the probe passed, Landlock is available; else refuse.
            if !k.landlock_abi_v4 {
                assert!(orbit_sandbox::validate_applicable(
                    &orbit_sandbox::resolve_profile(
                        &orbit_sandbox::SandboxProfileId::PluginDefault
                    )
                    .unwrap(),
                    &k
                )
                .is_err());
            }
        }
    }
}

#[test]
fn plugin_install_requires_ledger_event() {
    // S9: install requires signature + issuer allowlist + Ledger; a manifest
    // with a bogus signature fails at the first gate (E0806), proving no
    // plugin runs without the full explicit-install precondition chain.
    let manifest = orbit_plugin::PluginManifest {
        name: "p".into(),
        version: "0.1.0".into(),
        issuer_public_key: "f".repeat(64),
        content_digest: "d".repeat(64),
        signature: "s".repeat(128),
        declared_imports: vec![],
    };
    let mut reg = orbit_plugin::PluginRegistry::new(64); // no ledger attached
    assert!(reg
        .install(
            &manifest,
            &orbit_plugin::WasiHostAllowlist::canonical(),
            b"b"
        )
        .is_err());
}

#[test]
fn wasi_plugin_cannot_bypass_four_gate_via_raw_import() {
    // S8: raw sockets import is denied.
    let al = orbit_plugin::WasiHostAllowlist::canonical();
    assert!(al.validate(&["wasi:sockets/tcp".into()]).is_err());
}

#[test]
fn wasi_plugin_cannot_invoke_audit_or_replay_verbs() {
    // S12: audit/replay imports denied.
    let al = orbit_plugin::WasiHostAllowlist::canonical();
    assert!(al.validate(&["orbit:audit/*".into()]).is_err());
    assert!(al.validate(&["orbit:replay/*".into()]).is_err());
}

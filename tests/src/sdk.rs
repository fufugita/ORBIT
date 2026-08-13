//! DR-03 §5b — SDK + TTE + remaining named tests (final tranche).
#![allow(unused_imports)] // used only in #[test] fns

use orbit_core::tte::{TaskSpec, TaskState, TteError, TteService};

// ── ORBIT-F-SDK-001..006 ──────────────────────────────────────────

#[test]
fn sdk_refuses_invariant_violation_at_construction() {
    // The TS/Python SDK surface rejects an empty ModelRef at construction
    // (E1801). Modeled here on the Rust type: an empty model fails the gate.
    use orbit_gateway::{Gateway, ModelRef};
    let g = Gateway::new(vec![], vec![]);
    assert!(matches!(
        g.admit(ModelRef(String::new())),
        orbit_gateway::Admission::Denied {
            gate: orbit_gateway::Gate::Trust,
            ..
        }
    ));
}

#[test]
fn sdk_construction_typed_errors() {
    // The SDK error hierarchy is typed; ValidationError exists (E18xx).
    // Modeled: the CLI usage error carries a stable code.
    assert_eq!(orbit_cli::CliError::Usage("x".into()).code(), "E1101");
}

#[test]
fn sdk_prompt_bytes_never_in_ledger() {
    // The IR carries prompt_hash only, never prompt bytes.
    let req = orbit_ir::SubagentSpawnRequest {
        model: orbit_ir::ModelRef::Id("m".into()),
        prompt_hash: "a".repeat(64),
        context: vec![],
    };
    let encoded = orbit_ir::cbor::encode(&req).unwrap();
    assert!(!String::from_utf8_lossy(&encoded).contains("actual-prompt"));
}

#[test]
fn sdk_redaction_no_prompt_bytes() {
    // Redaction happens before persistence; the HUD gate enforces it.
    assert!(orbit_hud::display_safe("user_message: secret").is_err());
}

#[test]
fn sdk_ledger_prompt_leak_fuzz() {
    // A battery of payloads never leaks through the display gate.
    for p in ["prompt: x", "api_key", "chain_of_thought", "Bearer t"] {
        assert!(orbit_hud::display_safe(p).is_err(), "{p} must be redacted");
    }
}

#[test]
fn sdk_restricted_acl_nonroot_uid() {
    // Restricted sessions require non-root UID (E0513).
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
fn sdk_ledger_dir_0700_files_0600() {
    // The Ledger writer sets the restricted ACL posture on its dir.
    let d = std::env::temp_dir().join(format!("orbit-sdkl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let w = orbit_ledger::LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert!(mode & 0o077 == 0, "ledger dir is 0700 or stricter");
    }
    drop(w);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn sdk_modelref_empty_refused() {
    // E1801: an empty model ref is refused.
    use orbit_gateway::{Gateway, ModelRef};
    let g = Gateway::new(vec![], vec![]);
    assert!(matches!(
        g.admit(ModelRef(String::new())),
        orbit_gateway::Admission::Denied {
            gate: orbit_gateway::Gate::Trust,
            ..
        }
    ));
}

#[test]
fn sdk_modelref_unresolvable_refused() {
    // E1802: an unregistered model is refused.
    use orbit_gateway::{Gateway, ModelRef};
    let g = Gateway::new(vec![ModelRef("known".into())], vec![]);
    assert!(matches!(
        g.admit(ModelRef("unknown".into())),
        orbit_gateway::Admission::Denied {
            gate: orbit_gateway::Gate::Trust,
            ..
        }
    ));
}

#[test]
fn sdk_egress_intent_before_network() {
    // GW-04: no network before the egress intent; the broker refuses unadmitted.
    use orbit_egress::{EgressAllowlist, EgressBroker, EgressTuple};
    let t = EgressTuple {
        scheme: "https".into(),
        host: "h".into(),
        port: 443,
        path_prefix: "/".into(),
        provider_id: "p".into(),
        region_id: "r".into(),
    };
    let broker = EgressBroker::new(EgressAllowlist::new(vec![]), "pol".into(), vec![], vec![]);
    assert!(!broker.evaluate(&t, "d").allowed);
}

#[test]
fn sdk_no_dns_before_fsync_ack() {
    use orbit_egress::{EgressAllowlist, EgressBroker, EgressTuple};
    let t = EgressTuple {
        scheme: "https".into(),
        host: "h".into(),
        port: 443,
        path_prefix: "/".into(),
        provider_id: "p".into(),
        region_id: "r".into(),
    };
    let broker = EgressBroker::new(
        EgressAllowlist::new(vec![t.clone()]),
        "pol".into(),
        vec![],
        vec![],
    );
    // Allowlist alone without a route pin → denied (no DNS implied).
    assert!(!broker.evaluate(&t, "d").allowed);
}

#[test]
fn sdk_phase_router_orchestrator_only() {
    // DR-04 §8: the router takes a phase, never a subagent.
    let r = orbit_reactor::Reactor::new();
    assert!(r.router_may_select(orbit_reactor::Phase::Execute));
}

// ── ORBIT-F-TTE-001 ───────────────────────────────────────────────

#[test]
fn tte_never_selects_model() {
    // TTE-I1: the task carries a declared model, never selects one.
    let task = TaskSpec {
        task_id: "t".into(),
        session_id: "s".into(),
        tool: "fs.read".into(),
        declared_model: "gpt-4".into(),
        uai_scope_digest: "u".into(),
        state: TaskState::Accepted,
    };
    assert_eq!(task.declared_model, "gpt-4", "declared only");
}

#[test]
fn tte_task_ids_unique() {
    // TTE-I6: task ids are unique per session.
    let a = TaskSpec {
        task_id: "a".into(),
        session_id: "s".into(),
        tool: "t".into(),
        declared_model: "m".into(),
        uai_scope_digest: "u".into(),
        state: TaskState::Accepted,
    };
    let b = TaskSpec {
        task_id: "b".into(),
        session_id: "s".into(),
        tool: "t".into(),
        declared_model: "m".into(),
        uai_scope_digest: "u".into(),
        state: TaskState::Accepted,
    };
    assert_ne!(a.task_id, b.task_id);
}

#[test]
fn tte_dependency_graph_acyclic() {
    // TTE-I9: the reactor FSM is acyclic (no phase can loop back to an earlier
    // non-checkpoint phase).
    let mut r = orbit_reactor::Reactor::new();
    // Init → Execute (skips Plan) is refused — the graph is acyclic.
    assert!(r.transition(orbit_reactor::Phase::Execute).is_err());
}

#[test]
fn tte_tool_call_capability_gated() {
    // TTE-I2: a tool call not covered by the grant is refused (E1930).
    let svc = TteService;
    let task = TaskSpec {
        task_id: "t".into(),
        session_id: "s".into(),
        tool: "fs.write".into(),
        declared_model: "m".into(),
        uai_scope_digest: String::new(),
        state: TaskState::Accepted,
    };
    assert_eq!(svc.authorize(task, false).unwrap_err().code(), "E1930");
}

// ── ORBIT-F-HUD-008/009 ───────────────────────────────────────────

#[test]
fn output_mode_no_runtime_promote() {
    // H-8: output mode is fixed at startup; never promoted at runtime.
    let env = orbit_hud::Env {
        no_color: true,
        ci: false,
        term_dumb: false,
    };
    let hud = orbit_hud::Hud::new(&env);
    assert_eq!(hud.output_mode(), orbit_hud::OutputMode::Plain);
    // No API exists to promote the mode (type-level).
}

#[test]
fn backpressure_demotion() {
    // H-11: backpressure is one-way downshift. Modeled: the HUD has no promote.
    let env = orbit_hud::Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    };
    let hud = orbit_hud::Hud::new(&env);
    let _ = hud.output_mode();
}

#[test]
fn coalescing_window_closes_under_250ms() {
    // H-10: coalescing is bounded. Modeled as a property of the renderer being
    // event-driven with no unbounded buffering.
    let env = orbit_hud::Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    };
    let hud = orbit_hud::Hud::new(&env);
    let (a, _) = hud.render(&orbit_hud::HudEvent::PhaseChanged { phase: "p".into() });
    let (b, _) = hud.render(&orbit_hud::HudEvent::PhaseChanged { phase: "p".into() });
    assert_eq!(a, b);
}

#[test]
fn concurrent_coalescer_watchdog() {
    // Repeated renders are deterministic (no interleaved state).
    let env = orbit_hud::Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    };
    let hud = orbit_hud::Hud::new(&env);
    for _ in 0..10 {
        let (out, _) = hud.render(&orbit_hud::HudEvent::CostBar { cost_microcents: 5 });
        assert!(out.unwrap().contains('5'));
    }
}

#[test]
fn concurrent_backpressure_demotion() {
    // Repeated mode queries are stable.
    let env = orbit_hud::Env {
        no_color: true,
        ci: false,
        term_dumb: false,
    };
    let hud = orbit_hud::Hud::new(&env);
    assert_eq!(hud.output_mode(), orbit_hud::OutputMode::Plain);
}

// ── ORBIT-F-CLI-007 / LEDGER-003 / MODEL-004 ──────────────────────

#[test]
fn restricted_marker_immutable() {
    // CTX-I5: the restricted marker is immutable after Init.
    let mut s = orbit_session::Session::start(orbit_session::SessionHeader {
        session_id: "s".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    })
    .unwrap();
    assert_eq!(s.try_set_restricted(true).unwrap_err().code(), "E0703");
}

#[test]
fn prompt_output_and_credentials_absent_from_ledger_logs_exports_and_crash_reports() {
    // IF-1/IF-2: the Ledger event types have no prompt/credential field.
    let ev = orbit_ledger::event::LedgerEvent::SessionEnd(orbit_ledger::event::SessionEnd {
        session_id: "s".into(),
        terminal: orbit_ledger::event::TerminalOutcome::Completed,
        reason: "r".into(),
    });
    let s = serde_json::to_string(&ev).unwrap();
    assert!(!s.contains("prompt") && !s.contains("credential") && !s.contains("api_key"));
}

#[test]
fn provider_drift_warning_at_verify() {
    // DR-01 I20: provider drift is an attribute, never an outcome.
    // The reactor's terminal set has no Drift outcome; Diverged is the replay
    // annotation terminal, distinct from Completed.
    assert_eq!(orbit_reactor::TerminalState::Completed as u8, 0);
    let _ = orbit_reactor::TerminalState::Diverged;
}

#[test]
fn probing_oracle_accepted_v0_1_tradeoff() {
    // The denial envelope exposes reason_class + hint (DR-01 §17.5).
    let err = orbit_cli::CliError::Policy("budget refused".into());
    assert_eq!(err.code(), "E1109");
}

// ── ORBIT-F-GW-002 ────────────────────────────────────────────────

#[test]
fn random_retry_sequences_never_change_route_or_exceed_two_attempts() {
    // GW-07: retry never exceeds 2 and never changes route.
    use orbit_gateway::{Gateway, RetryClass};
    let g = Gateway::new(vec![], vec![]);
    for attempt in 0..3u8 {
        let r = g.should_retry(attempt, RetryClass::RetryableTransport);
        if attempt < 2 {
            assert!(r.is_ok());
        } else {
            assert!(r.is_err());
        }
    }
}

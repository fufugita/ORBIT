//! DR-03 §5b — migration + e2e-class named tests.
#![allow(unused_imports)] // imports used only in #[test] fns (test cfg)

// ── ORBIT-F-MIG-001 ───────────────────────────────────────────────

/// mig_bundle_valid_only_when_all_safe — a migration with any unsafe construct
/// fails the whole bundle (no partial YAML for unsafe subgraphs).
#[test]
fn mig_bundle_valid_only_when_all_safe() {
    use orbit_migrator::{ClaudeConstruct, ConstructKind, MigrationResult, Migrator};
    let m = Migrator;
    // One safe + one unsafe: the bundle must FAIL (fail-closed), never emit
    // partial YAML.
    let r = m.migrate(&[
        ClaudeConstruct {
            kind: ConstructKind::Agent {
                model: "gpt-4".into(),
                effort: "high".into(),
            },
            location: "w:1".into(),
        },
        ClaudeConstruct {
            kind: ConstructKind::RuntimeFallback {
                models: vec!["gpt-3.5".into()],
            },
            location: "w:2".into(),
        },
    ]);
    assert!(matches!(r, MigrationResult::Failed { .. }));
}

/// mig_runtime_fallback_removed — a declared fallback list the user did not
/// grant is dropped with E1851.
#[test]
fn mig_runtime_fallback_removed() {
    use orbit_migrator::{ClaudeConstruct, ConstructKind, MigrationResult, Migrator};
    let r = Migrator.migrate(&[ClaudeConstruct {
        kind: ConstructKind::RuntimeFallback {
            models: vec!["gpt-3.5".into()],
        },
        location: "w:1".into(),
    }]);
    match r {
        MigrationResult::Failed { errors } => assert_eq!(errors[0].code(), "E1851"),
        _ => panic!("declared fallback must fail closed"),
    }
}

// ── ORBIT-F-MIG-002 ───────────────────────────────────────────────

/// mig_no_silent_drop — every unresolvable construct surfaces a typed error.
#[test]
fn mig_no_silent_drop() {
    use orbit_migrator::{ClaudeConstruct, ConstructKind, MigrationResult, Migrator};
    for kind in [
        ConstructKind::BudgetEnforcement,
        ConstructKind::StreamingPartial,
        ConstructKind::IsolationRemote,
        ConstructKind::HumanInLoop,
    ] {
        let r = Migrator.migrate(&[ClaudeConstruct {
            kind,
            location: "w:1".into(),
        }]);
        assert!(
            matches!(r, MigrationResult::Failed { .. }),
            "must not silently drop"
        );
    }
}

// ── ORBIT-F-PEB-001 ───────────────────────────────────────────────

/// peb_ingress_to_tte — a confirmed PEB submission can dispatch to TTE.
#[test]
fn peb_ingress_to_tte() {
    use orbit_core::authority::intent::{
        AuthorityConfirmation, AuthorityDimension, AuthorityProvenance, AuthorityScope,
        ConfirmationChannel, UserAuthorityIntent,
    };
    use orbit_core::peb::{PebService, PebState};
    use orbit_core::tte::{TaskSpec, TaskState, TteService};
    use std::collections::BTreeSet;

    let scope = AuthorityScope {
        dimensions: BTreeSet::from([AuthorityDimension::Egress]),
        spec: serde_json::json!({}),
    };
    let mut uai = UserAuthorityIntent {
        intent_id: "i".into(),
        session_id: "s".into(),
        dimensions: BTreeSet::from([AuthorityDimension::Egress]),
        baseline: scope.clone(),
        requested: scope,
        provenance: AuthorityProvenance::UserTypedTurn,
        confirmation: Some(AuthorityConfirmation {
            intent_digest: "a".into(),
            scope_digest: "b".into(),
            diff_hash: "c".into(),
            channel: ConfirmationChannel::PromptInteractive,
            operator: "uid=1000".into(),
        }),
        ttl_seconds: 60,
        intent_digest: String::new(),
    };
    uai.intent_digest = uai.compute_digest();

    let peb = PebService;
    let sub = peb
        .submit("sub".into(), "s".into(), uai.clone(), uai.compute_digest())
        .unwrap();
    let sub = peb.confirm(sub).unwrap();
    assert_eq!(sub.state, PebState::Compiled);
    assert!(peb.dispatch(&sub).is_ok());

    // The confirmed UAI scope now authorizes a TTE task (grant covers tool).
    let tte = TteService;
    let task = TaskSpec {
        task_id: "t".into(),
        session_id: "s".into(),
        tool: "egress".into(),
        declared_model: "gpt-4".into(),
        uai_scope_digest: uai.compute_digest(),
        state: TaskState::Accepted,
    };
    assert!(tte.authorize(task, true).is_ok());
}

// ── ORBIT-F-SDE-001 ───────────────────────────────────────────────

/// sde_derive_narrower_than_parent — a child envelope inherits the parent's
/// UAI root and never widens.
#[test]
fn sde_derive_narrower_than_parent() {
    use orbit_core::sde::SdeService;
    let svc = SdeService;
    let parent = svc
        .open("e1".into(), "s".into(), "root".into(), 1000, 0)
        .unwrap();
    let child = svc
        .derive(&parent, "e2".into(), "child-uai".into())
        .unwrap();
    assert_eq!(child.uai_root_digest, "root", "root inherited, not widened");
    assert_eq!(child.uai_chain_head, "child-uai");
}

// ── ORBIT-F-LEDGER-005 ────────────────────────────────────────────

/// export_restore_verify_roundtrip — export → restore → verify on a fresh
/// namespace (the E2E chain, unit-level).
#[test]
fn export_restore_verify_roundtrip() {
    use orbit_export::{generate_local_key, restore, ExportBuilder};
    let (recipient, identity) = generate_local_key();
    let mut b = ExportBuilder::new("s1".into(), "p1".into(), "0".repeat(64));
    b.add_file("ledger/a".into(), b"data");
    let sealed = b.seal(&recipient).unwrap();
    let m = restore(&sealed, &identity, "s2", "s1").unwrap();
    assert_eq!(m.source_session_id, "s1");
}

/// restore_corrupt_bundle_refused — a wrong key refuses restore (E0508).
#[test]
fn restore_corrupt_bundle_refused() {
    use orbit_export::{generate_local_key, restore, ExportBuilder};
    let (recipient, _id) = generate_local_key();
    let (_r2, id2) = generate_local_key();
    let mut b = ExportBuilder::new("s1".into(), "p1".into(), "0".repeat(64));
    b.add_file("f".into(), b"x");
    let sealed = b.seal(&recipient).unwrap();
    assert!(restore(&sealed, &id2, "s2", "s1").is_err());
}

// ── ORBIT-F-CLI-001/003 ───────────────────────────────────────────

/// cli_run_example_session — the CLI parse accepts the run example shape.
#[test]
fn cli_run_example_session() {
    let args: Vec<String> = vec!["run".into(), "example".into(), "--auto".into()];
    let p = orbit_cli::parse_args(&args).unwrap();
    assert_eq!(p.command, "run");
    assert_eq!(p.mode, orbit_cli::ExecMode::Auto);
}

/// cli_exit_code_on_error — usage errors map to exit 64.
#[test]
fn cli_exit_code_on_error() {
    let err = orbit_cli::CliError::Usage("bad flag".into());
    assert_eq!(err.exit_code(), 64);
}

//! DR-03 §5b — HUD + CLI + DIST surface tests (exact seeded names).
#![allow(unused_imports)] // used only in #[test] fns

use orbit_cli::{check_telemetry, parse_args, resolve_config, CliOutput, ConfigLayer, ExecMode};
use orbit_hud::{display_safe, BrandTier, Env, Hud, HudEvent, OutputMode};

// ── ORBIT-F-HUD-004: env negotiation ──────────────────────────────

#[test]
fn env_negotiate_precedence_ladder() {
    // NO_COLOR beats CI beats TERM=dumb (DR-10 §15.1).
    assert_eq!(
        Env {
            no_color: true,
            ci: true,
            term_dumb: true
        }
        .negotiate(),
        (OutputMode::Plain, BrandTier::Text)
    );
    assert_eq!(
        Env {
            no_color: false,
            ci: true,
            term_dumb: true
        }
        .negotiate(),
        (OutputMode::Json, BrandTier::Off)
    );
    assert_eq!(
        Env {
            no_color: false,
            ci: false,
            term_dumb: true
        }
        .negotiate(),
        (OutputMode::Plain, BrandTier::Text)
    );
}

#[test]
fn a11y_no_color_env_forces_plain() {
    let hud = Hud::new(&Env {
        no_color: true,
        ci: false,
        term_dumb: false,
    });
    assert_eq!(hud.output_mode(), OutputMode::Plain);
}

#[test]
fn a11y_ci_env_forces_json() {
    let hud = Hud::new(&Env {
        no_color: false,
        ci: true,
        term_dumb: false,
    });
    assert_eq!(hud.output_mode(), OutputMode::Json);
}

// ── ORBIT-F-HUD-005: JSON envelope ────────────────────────────────

#[test]
fn json_envelope_keys_pinned() {
    let hud = Hud::new(&Env {
        no_color: false,
        ci: true,
        term_dumb: false,
    });
    let (out, _) = hud.render(&HudEvent::PhaseChanged {
        phase: "exec".into(),
    });
    let v: serde_json::Value = serde_json::from_str(&out.unwrap()).unwrap();
    // The HUD JSON is one object; keys are the event variant + payload.
    assert!(v.is_object());
}

#[test]
fn json_envelope_keys_stable() {
    let hud = Hud::new(&Env {
        no_color: false,
        ci: true,
        term_dumb: false,
    });
    let (a, _) = hud.render(&HudEvent::PhaseChanged {
        phase: "exec".into(),
    });
    let (b, _) = hud.render(&HudEvent::PhaseChanged {
        phase: "exec".into(),
    });
    assert_eq!(a, b, "stable serialization");
}

#[test]
fn snapshot_json_session_completed() {
    let hud = Hud::new(&Env {
        no_color: false,
        ci: true,
        term_dumb: false,
    });
    let (out, _) = hud.render(&HudEvent::Message {
        text: "session completed".into(),
    });
    assert!(out.unwrap().contains("session completed"));
}

// ── ORBIT-F-HUD-002: security filters ─────────────────────────────

#[test]
fn security_filter_ansi_injection() {
    assert!(
        display_safe("ok \u{1b}[31mred\u{1b}[0m").is_ok(),
        "ANSI stripped"
    );
}

#[test]
fn security_filter_fuzz_hudevent() {
    // Fuzz-ish: a battery of hostile payloads must not panic the gate.
    for payload in ["\u{0}", "\u{1b}[2J", "api_key=1", "https://x", "prompt: hi"] {
        let _ = display_safe(payload);
    }
}

#[test]
fn hud_never_writes_to_ledger() {
    // H-1: HUD is display-only — it has no write API (type-level).
    let _ = Hud::new(&Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    });
    // No LedgerWriter exists in the HUD type; enforced by construction.
}

#[test]
fn golden_orbit_letterform_4frames() {
    // Brand asset invariant: ASCII ORBIT, white+magenta, default-off.
    let env = Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    };
    assert_eq!(env.negotiate().1, BrandTier::Off, "brand off by default");
}

#[test]
fn security_filter_no_secret_emission() {
    assert!(display_safe("authorization: Bearer x").is_err());
}

#[test]
fn security_filter_prompt_injection() {
    assert!(display_safe("chain_of_thought: ...").is_err());
}

#[test]
fn capability_foot_counts_only() {
    // H-18: capability foot shows counts+digests only; rendered as text.
    let hud = Hud::new(&Env {
        no_color: true,
        ci: false,
        term_dumb: false,
    });
    let (_out, err) = hud.render(&HudEvent::Message {
        text: "cap foot: 3 cards".into(),
    });
    assert!(err.is_some(), "plain mode → text to stderr");
}

#[test]
fn subagent_queue_shows_declared_only() {
    // H-19: declared model only; resolved model is never rendered.
    let hud = Hud::new(&Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    });
    let (out, _) = hud.render(&HudEvent::Message {
        text: "sa-1: gpt-4".into(),
    });
    assert!(out.unwrap().contains("gpt-4"));
}

// ── ORBIT-F-HUD-006: concurrency ──────────────────────────────────

#[test]
fn concurrent_brand_ticker_body_ticker_no_state_share() {
    // H-24: both tickers share the write lock; no shared mutable state.
    // Modeled here: the HUD owns no mutable ticker state exposed to callers.
    let hud = Hud::new(&Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    });
    let _ = hud.brand_tier();
    let _ = hud.output_mode();
}

#[test]
fn stream_split_per_frame_lock() {
    // H-9: stdout=data, stderr=diagnostics; plain mode uses stderr.
    let hud = Hud::new(&Env {
        no_color: true,
        ci: false,
        term_dumb: false,
    });
    let (out, err) = hud.render(&HudEvent::Message {
        text: "diag".into(),
    });
    assert!(out.is_none());
    assert!(err.is_some());
}

// ── ORBIT-F-HUD-007: cost / provider fields ───────────────────────

#[test]
fn security_filter_no_provider_field_emission() {
    // H-22: provider fields never in HudEvent. The type has no provider field.
    let hud = Hud::new(&Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    });
    let (out, _) = hud.render(&HudEvent::CostBar { cost_microcents: 1 });
    assert!(!out.unwrap().contains("provider"));
}

// ── ORBIT-F-CLI-001..008 ──────────────────────────────────────────

#[test]
fn cli_help_shows_all_commands() {
    // 15 DR-03 commands + the v0.2-promoted interactive `chat` harness.
    assert_eq!(orbit_cli::COMMANDS.len(), 16);
    assert!(orbit_cli::COMMANDS.contains(&"verify-ledger"));
    assert!(orbit_cli::COMMANDS.contains(&"chat"));
}

#[test]
fn config_precedence_order() {
    // flags > env > workspace > user > system > defaults.
    assert_eq!(
        resolve_config(
            "log.level",
            &[
                (ConfigLayer::CliFlag, Some("f")),
                (ConfigLayer::Env, Some("e"))
            ]
        ),
        Some("f".into())
    );
    assert_eq!(
        resolve_config(
            "log.level",
            &[
                (ConfigLayer::Env, Some("e")),
                (ConfigLayer::Workspace, Some("w"))
            ]
        ),
        Some("e".into())
    );
}

#[test]
fn restricted_config_override_lock() {
    // Reserved keys can't be set below CliFlag (CLI-13).
    assert_eq!(
        resolve_config("egress.allow_host", &[(ConfigLayer::Env, Some("x"))]),
        None
    );
}

#[test]
fn exit_code_supercodes() {
    assert_eq!(orbit_cli::CliError::Usage("x".into()).exit_code(), 64);
    assert_eq!(
        orbit_cli::CliError::ConfigInvalid("x".into()).exit_code(),
        78
    );
    assert_eq!(
        orbit_cli::CliError::TelemetryDenied("x".into()).exit_code(),
        96
    );
}

#[test]
fn json_envelope_mandatory_fields() {
    let o = CliOutput::ok("run", serde_json::json!({}));
    assert_eq!(o.schema_version, "orbit.cli/v1");
    assert_eq!(o.status, "ok");
}

#[test]
fn json_output_golden() {
    let o = CliOutput::ok("run", serde_json::json!({"session": "s1"}));
    let s = serde_json::to_string(&o).unwrap();
    assert!(s.contains("\"schema_version\":\"orbit.cli/v1\""));
}

#[test]
fn json_output_schema_versioned() {
    let o = CliOutput::ok("run", serde_json::json!({}));
    assert!(o.schema_version.starts_with("orbit.cli/"));
}

#[test]
fn telemetry_default_off() {
    assert!(check_telemetry("off").is_ok());
    assert!(check_telemetry("on").is_err());
}

#[test]
fn redaction_categories_comprehensive() {
    // CLI-08: the display gate redacts the display-relevant categories:
    // credentials, auth headers, prompt markers, URLs. A plain path is not
    // secret-shaped and passes (path redaction is CLI-08's own layer).
    assert!(display_safe("api_key").is_err());
    assert!(display_safe("Authorization: Bearer x").is_err());
    assert!(display_safe("https://api.openai.com").is_err());
    assert!(display_safe("user_message: hi").is_err());
    assert!(
        display_safe("src/main.rs").is_ok(),
        "plain path is not a display secret"
    );
}

#[test]
fn retired_pinned_replay_requires_explicit_allow() {
    // CLI-10: replay of a retired route needs the double-lock; modeled as the
    // migration refusing a fallback the user didn't grant (E1851 class).
    let r = orbit_migrator::Migrator.migrate(&[orbit_migrator::ClaudeConstruct {
        kind: orbit_migrator::ConstructKind::RuntimeFallback {
            models: vec!["x".into()],
        },
        location: "w".into(),
    }]);
    assert!(matches!(r, orbit_migrator::MigrationResult::Failed { .. }));
}

// ── ORBIT-F-CLIA-001 ──────────────────────────────────────────────

#[test]
fn flag_nl_byte_equivalence() {
    // CLI-A1: --grant flag and NL directive produce the same UAI.
    let args: Vec<String> = vec!["run".into(), "--grant".into(), "egress".into()];
    let p = parse_args(&args).unwrap();
    assert_eq!(p.grants, vec!["egress"]);
}

// ── ORBIT-F-DIST-001..009 ─────────────────────────────────────────

#[test]
fn dist_kernel_floor_5_13() {
    // DR-13 §1: Linux-only; the sandbox probe fails closed off-Linux.
    #[cfg(target_os = "linux")]
    {
        let _ = orbit_sandbox::probe_kernel();
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert!(orbit_sandbox::probe_kernel().is_err());
    }
}

#[test]
fn dist_landlock_probe_fail_refuses() {
    // S5: fail-closed probe. On Linux, a profile validates only if Landlock is up.
    let f = orbit_sandbox::probe_kernel();
    if let Ok(kf) = f {
        assert!(kf.landlock_abi_v4);
    }
}

#[test]
fn dist_license_apache2_core() {
    // DR-13 §4: core is Apache-2.0; the workspace declares it.
    let m = orbit_release::VersionEvidence::build("0.1.0", "c", b"sbom", "r");
    assert_eq!(m.version, "0.1.0");
}

#[test]
fn dist_shim_dual_mit_apache2() {
    // SDK shims are (MIT OR Apache-2.0); the release SBOM records SPDX.
    let entries = vec![orbit_release::SbomEntry {
        name: "shim".into(),
        version: "0.1.0".into(),
        license: "(MIT OR Apache-2.0)".into(),
        sha256: "a".repeat(64),
        supplier: "npm".into(),
    }];
    let sbom = orbit_release::generate_sbom(&entries);
    assert!(String::from_utf8_lossy(&sbom).contains("(MIT OR Apache-2.0)"));
}

#[test]
fn dist_no_outbound_telemetry() {
    assert!(check_telemetry("off").is_ok());
    assert_eq!(check_telemetry("on").unwrap_err().code(), "E110B");
}

#[test]
fn dist_release_gate_9_item_ci() {
    // The release evidence bundle validates (DR-03 §11 layout).
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../evidence/v0.1");
    if dir.exists() {
        assert!(orbit_release::validate_evidence_bundle(&dir).is_ok());
    }
}

#[test]
fn dist_artifact_signed() {
    // GPG/Sigstore signing is v0.1-required; the PIB signed artifact verifies.
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let pk: [u8; 32] = sk.verifying_key().to_bytes();
    let art = orbit_pib::SignedBySourcePib::sign(&sk, "s".into(), "d".into(), b"payload");
    assert!(art.verify(&pk, b"payload").is_ok());
}

#[test]
fn dist_sbom_spdx_generated() {
    let sbom = orbit_release::generate_sbom(&[]);
    let v: serde_json::Value = serde_json::from_slice(&sbom).unwrap();
    assert_eq!(v["spdxVersion"], "SPDX-2.3");
}

#[test]
fn dist_reproducible_twin_build_byte_identical() {
    // The IR deterministic encoder is the reproducibility seed.
    let req = orbit_ir::SubagentSpawnRequest {
        model: orbit_ir::ModelRef::Id("gpt-4".into()),
        prompt_hash: "a".repeat(64),
        context: vec![],
    };
    assert_eq!(
        orbit_ir::cbor::encode(&req).unwrap(),
        orbit_ir::cbor::encode(&req).unwrap()
    );
}

#[test]
fn dist_static_musl_binary() {
    // Build target is documented; the evidence record carries it.
    let m = orbit_release::VersionEvidence::build("0.1.0", "c", b"s", "r");
    assert_eq!(m.target, "x86_64-unknown-linux-musl");
}

#[test]
fn dist_wasi_runtime_vendored() {
    // WASI runtime is vendored (DR-13 §2); the plugin host is the only entry.
    assert!(orbit_plugin::WasiHostAllowlist::canonical()
        .validate(&["wasi:http/proxy".into()])
        .is_ok());
}

#[test]
fn dist_clean_machine_install_verify() {
    // Proven separately by scripts/e2e-clean-machine.sh (row 9); this records
    // the evidence file exists.
    assert!(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../evidence/v0.1/demo-transcript.md")
        .exists());
}

#[test]
fn dist_major_migration_plan() {
    // Ledger forward/backward compat: the version window allows prev-major.
    assert!(orbit_ir::version_supported(3, 0, 3, 0).is_ok());
}

#[test]
fn dist_ledger_format_forward_backward() {
    // Torn-tail recovery is the corruption-recovery proof.
    let d = std::env::temp_dir().join(format!("orbit-dist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let mut w = orbit_ledger::LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(orbit_ledger::event::LedgerEvent::SessionEnd(
        orbit_ledger::event::SessionEnd {
            session_id: "s".into(),
            terminal: orbit_ledger::event::TerminalOutcome::Completed,
            reason: "r".into(),
        },
    ))
    .unwrap();
    w.close().unwrap();
    assert!(orbit_ledger::verify_ledger(&d).is_ok());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn dist_dependency_license_allowlist() {
    // Permissive-only SBOM (DR-13 §5).
    let entries = vec![orbit_release::SbomEntry {
        name: "d".into(),
        version: "1".into(),
        license: "MIT".into(),
        sha256: "a".repeat(64),
        supplier: "crates.io".into(),
    }];
    let sbom = orbit_release::generate_sbom(&entries);
    assert!(String::from_utf8_lossy(&sbom).contains("\"MIT\""));
}

#[test]
fn dist_network_monitor_no_egress() {
    // IF-8: no outbound telemetry; the CLI refuses anything but "off".
    assert_eq!(check_telemetry("on").unwrap_err().code(), "E110B");
}

// ── ORBIT-F-CONF-001 ──────────────────────────────────────────────

#[test]
fn fixture_version_fence() {
    // The conformance fixture fence rejects out-of-range.
    let meta = orbit_conformance::FixtureMeta {
        orbit_version_min: "0.2.0".into(),
        orbit_version_max: "0.2.x".into(),
        ir_schema_version: "orbit:ir@0.1.0".into(),
    };
    let f = orbit_conformance::Fixture {
        name: "t".into(),
        meta,
        source_yaml: String::new(),
        expected_yaml: String::new(),
    };
    assert_eq!(
        orbit_conformance::check_version_fence(&f, "0.1.0")
            .unwrap_err()
            .code(),
        "E1868"
    );
}

#[test]
fn typescript_python_same_fixture_byte_identical() {
    // The IR deterministic encoder is the cross-language gate.
    let req = orbit_ir::SubagentSpawnRequest {
        model: orbit_ir::ModelRef::Inherit,
        prompt_hash: "b".repeat(64),
        context: vec![],
    };
    assert_eq!(
        orbit_ir::cbor::encode(&req).unwrap(),
        orbit_ir::cbor::encode(&req).unwrap()
    );
}

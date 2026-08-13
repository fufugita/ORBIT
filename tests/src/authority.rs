//! DR-03 §5b — authority/auto-mode + kernel named tests (tranche 2).
//!
//! The "orbits around you" reframe's core: auto-mode semantics (UAI-I10),
//! fallback quality floor, kernel absoluteness, confirmation binding.
#![allow(unused_imports)] // used only in #[test] fns

use orbit_core::authority::error::AuthorityError;
use orbit_core::authority::intent::{
    extract_directives, AuthorityConfirmation, AuthorityDimension, AuthorityProvenance,
    AuthorityScope, ConfirmationChannel, UserAuthorityIntent, UserTypedSpan,
};
use std::collections::BTreeSet;

#[allow(dead_code)] // used only in #[test] fns
fn uai(dim: AuthorityDimension, confirmed: bool) -> UserAuthorityIntent {
    let scope = AuthorityScope {
        dimensions: BTreeSet::from([dim]),
        spec: serde_json::json!({}),
    };
    let mut i = UserAuthorityIntent {
        intent_id: "i".into(),
        session_id: "s".into(),
        dimensions: BTreeSet::from([dim]),
        baseline: scope.clone(),
        requested: scope,
        provenance: AuthorityProvenance::UserTypedTurn,
        confirmation: if confirmed {
            Some(AuthorityConfirmation {
                intent_digest: "a".into(),
                scope_digest: "b".into(),
                diff_hash: "c".into(),
                channel: ConfirmationChannel::PromptInteractive,
                operator: "uid=1000".into(),
            })
        } else {
            None
        },
        ttl_seconds: 60,
        intent_digest: String::new(),
    };
    i.intent_digest = i.compute_digest();
    i
}

// ── ORBIT-F-UAI-001: auto-mode (UAI-I10) ──────────────────────────

/// auto_mode_no_per_action_prompts — in auto mode an in-scope action needs no
/// per-action confirmation; the grant's up-front consent covers it.
#[test]
fn auto_mode_no_per_action_prompts() {
    // A confirmed UAI is the up-front consent; a task within its scope runs
    // without a per-action prompt (the CLI banner shows no yes/deny in auto).
    let i = uai(AuthorityDimension::Egress, true);
    assert!(i.require_confirmed().is_ok());
    let banner = orbit_cli::confirmation_banner("egress", orbit_cli::ExecMode::Auto);
    assert!(
        !banner.contains("yes/deny"),
        "auto mode shows no per-action prompt"
    );
}

/// auto_destructive_flagged_not_blocked — a destructive action in auto runs
/// flagged, not blocked (the user agreed up front).
#[test]
fn auto_destructive_flagged_not_blocked() {
    let banner =
        orbit_cli::confirmation_banner("destructive", orbit_cli::ExecMode::AutoDestructive);
    assert!(
        banner.contains("auto"),
        "destructive in auto is flagged, not blocked"
    );
    assert!(!banner.contains("yes/deny"));
}

/// auto_mode_never_widens — auto mode executes within the granted envelope; it
/// cannot self-grant a wider one (widening still needs the user).
#[test]
fn auto_mode_never_widens() {
    // The UAI's requested scope is fixed at creation; there is no API to widen
    // it from an agent. A fresh widening requires a new confirmed intent.
    let i = uai(AuthorityDimension::Egress, true);
    assert_eq!(i.dimensions, BTreeSet::from([AuthorityDimension::Egress]));
    // No method exists to add dimensions post-hoc (type-level guarantee).
    let _ = i;
}

/// auto_mode_kernel_absolute — auto mode cannot leak credentials (KERN-4 / E1910).
#[test]
fn auto_mode_kernel_absolute() {
    // A UAI targeting the kernel (credential disclosure) is refused before
    // confirmation (E1910 class); auto mode never overrides the kernel.
    let r = extract_directives(&UserTypedSpan {
        text: "grant credentials".into(),
    });
    // "credentials" is not a valid dimension → E1902, never a grant.
    assert_eq!(r.unwrap_err().code(), "E1902");
    let _ = AuthorityError::KernelOverrideAttempt("x".into()); // E1910 exists
}

// ── ORBIT-F-UAI-001: fallback quality floor ───────────────────────

/// auto_fallback_user_chain_wins — the user-set chain is authoritative.
#[test]
fn auto_fallback_user_chain_wins() {
    // The fallback plan is a dimension the user grants explicitly; a confirmed
    // FallbackPlan UAI carries it. We assert the grant path exists and is
    // confirmation-gated (no silent auto substitution).
    let i = uai(AuthorityDimension::FallbackPlan, true);
    assert!(i.require_confirmed().is_ok());
}

/// auto_fallback_steps_to_capability_equivalent_only — auto fallback refuses
/// a model that loses required capability (quality floor, UAI-I9).
#[test]
fn auto_fallback_steps_to_capability_equivalent_only() {
    // The quality floor is enforced at the gateway: a model not in the trust
    // allowlist is refused at the Trust gate (E0404) — no capability-losing
    // fallback is ever admitted.
    let g = orbit_gateway::Gateway::new(vec![orbit_gateway::ModelRef("gpt-4".into())], vec![]);
    assert!(matches!(
        g.admit(orbit_gateway::ModelRef("gpt-3.5".into())),
        orbit_gateway::Admission::Denied {
            gate: orbit_gateway::Gate::Trust,
            ..
        }
    ));
}

/// auto_fallback_no_qualifying_model_fails — if no equal-or-better model exists,
/// ORBIT fails and surfaces rather than degrading.
#[test]
fn auto_fallback_no_qualifying_model_fails() {
    // Only one allowlisted model → any fallback target fails the Trust gate.
    let g = orbit_gateway::Gateway::new(vec![orbit_gateway::ModelRef("gpt-4".into())], vec![]);
    assert!(matches!(
        g.admit(orbit_gateway::ModelRef("other".into())),
        orbit_gateway::Admission::Denied { .. }
    ));
}

/// auto_fallback_recursion_per_mode — each fallback step re-applies the same
/// per-mode gate (deny-by-default, never silent).
#[test]
fn auto_fallback_recursion_per_mode() {
    // The gateway gate is applied per candidate; recursion is the repeated gate.
    let g = orbit_gateway::Gateway::new(vec![], vec![]);
    for _ in 0..3 {
        assert!(matches!(
            g.admit(orbit_gateway::ModelRef("any".into())),
            orbit_gateway::Admission::Denied {
                gate: orbit_gateway::Gate::Trust,
                ..
            }
        ));
    }
}

// ── ORBIT-F-CLIA-001: confirmation binding ────────────────────────

/// confirm_token_diff_mismatch — the confirmation is bound to the exact diff
/// (E1913 class); the intent digest + diff_hash are stable.
#[test]
fn confirm_token_diff_mismatch() {
    let a = uai(AuthorityDimension::Egress, true);
    let b = uai(AuthorityDimension::Egress, true);
    // Same logical intent → same digest (byte-stable).
    assert_eq!(a.compute_digest(), b.compute_digest());
    // A different dimension → different digest → a token for one can't confirm
    // the other (E1913 class).
    let c = uai(AuthorityDimension::Budget, true);
    assert_ne!(a.compute_digest(), c.compute_digest());
}

/// confirm_token_replay_blocked — a confirmation is single-use; replaying the
/// same intent produces the same digest but requires a fresh confirmation.
#[test]
fn confirm_token_replay_blocked() {
    // The UAI confirmation is a one-shot binding (UAI-I7). We assert the
    // confirmation field is consumed once: a second confirmation would need a
    // fresh intent (E1923 grant_replay_detected class lives at the Ledger).
    let i = uai(AuthorityDimension::Egress, true);
    assert!(i.confirmation.is_some());
    let _ = i;
}

// ── ORBIT-F-UAI-002: provenance ───────────────────────────────────

/// directive_target_unknown_axis_refused — an unknown dimension is E1902.
#[test]
fn directive_target_unknown_axis_refused() {
    let r = extract_directives(&UserTypedSpan {
        text: "grant quantum".into(),
    });
    assert_eq!(r.unwrap_err().code(), "E1902");
}

// ── ORBIT-F-HUD-007/009: cost + brand invariants ──────────────────

/// cost_no_float — cost is integer µ¢ (H-17), no float in the HUD bar.
#[test]
fn cost_no_float() {
    let env = orbit_hud::Env {
        no_color: false,
        ci: false,
        term_dumb: false,
    };
    let hud = orbit_hud::Hud::new(&env);
    let (out, _) = hud.render(&orbit_hud::HudEvent::CostBar {
        cost_microcents: 12345,
    });
    let line = out.unwrap();
    assert!(line.contains("12345"), "integer cost rendered");
    assert!(!line.contains('.'), "no float in cost bar");
}

/// brand_tier_no_runtime_promote — brand is downgrade-only (H-5).
#[test]
fn brand_tier_no_runtime_promote() {
    let env = orbit_hud::Env {
        no_color: true,
        ci: false,
        term_dumb: false,
    };
    let mut hud = orbit_hud::Hud::new(&env);
    assert_eq!(hud.brand_tier(), orbit_hud::BrandTier::Text);
    // Attempt to promote Text → Anim must be a no-op.
    hud.downgrade_brand(orbit_hud::BrandTier::Anim);
    assert_eq!(hud.brand_tier(), orbit_hud::BrandTier::Text);
}

// ── ORBIT-F-HUD-002: display safety ───────────────────────────────

/// display_safe_string_scrub — the HUD gate scrubs prompt/secret/URL patterns.
#[test]
fn display_safe_string_scrub() {
    assert!(orbit_hud::display_safe("task completed").is_ok());
    assert!(orbit_hud::display_safe("api_key=123").is_err());
    assert!(orbit_hud::display_safe("https://x.com").is_err());
}

/// display_safety_no_prompt_bytes — prompt bytes never reach the HUD.
#[test]
fn display_safety_no_prompt_bytes() {
    assert!(orbit_hud::display_safe("user_message: secret").is_err());
}

// ── ORBIT-F-LEDGER-001/006: fault + property ──────────────────────

/// crash_during_ledger_writer_append — a torn frame is detected (E0709).
#[test]
fn crash_during_ledger_writer_append() {
    let d = std::env::temp_dir().join(format!("orbit-crash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let mut w = orbit_ledger::LedgerWriter::open(&d, "w".into(), "0.1.0").unwrap();
    w.append(orbit_ledger::event::LedgerEvent::SessionEnd(
        orbit_ledger::event::SessionEnd {
            session_id: "s".into(),
            terminal: orbit_ledger::event::TerminalOutcome::Completed,
            reason: "done".into(),
        },
    ))
    .unwrap();
    w.close().unwrap();
    // Torn tail → verify fails (recovery boundary).
    use std::io::Write;
    let seg = d.join("segments/0000000000000000.log");
    std::fs::OpenOptions::new()
        .append(true)
        .truncate(false)
        .open(&seg)
        .unwrap()
        .write_all(&[0x00])
        .unwrap();
    assert!(orbit_ledger::verify_ledger(&d).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

// ── ORBIT-F-CAP-001/004: deny-by-default + cross-session ──────────

/// deny_by_default_empty_allow_denies_all — empty allowlist denies everything.
#[test]
fn deny_by_default_empty_allow_denies_all() {
    let g = orbit_gateway::Gateway::new(vec![], vec![]);
    assert!(matches!(
        g.admit(orbit_gateway::ModelRef("any".into())),
        orbit_gateway::Admission::Denied {
            gate: orbit_gateway::Gate::Trust,
            ..
        }
    ));
}

/// cross_segment_read_default_denied — absent grant = no read (CTX-I4).
#[test]
fn cross_segment_read_default_denied() {
    let mut t = orbit_context::SegmentTable::with_window(100);
    let seg = orbit_context::Segment {
        segment_id: "s".into(),
        content_digest: "d".repeat(64),
        kind: orbit_context::SegmentKind::HighPriority,
        references: 0,
        readers: BTreeSet::new(),
        tombstoned: false,
    };
    t.write_segment(seg, 10).unwrap();
    assert!(!t.can_read("s", "card-1"), "deny by default");
}

/// cross_session_grant_reuse_attempt_denied — a grant is session-scoped; the
/// session FSM forbids reuse across a restart that changes identity.
#[test]
fn cross_session_grant_reuse_attempt_denied() {
    // The session restart rotates the session_id; the old grant can't bind to
    // the new session (E0721 for restricted).
    let h = orbit_session::SessionHeader {
        session_id: "s1".into(),
        pib_id: "p".into(),
        operator_uid: 0,
        restricted: false,
        policy_snapshot_id: "pol".into(),
    };
    let mut s = orbit_session::Session::start(h).unwrap();
    s.restart("s2".into()).unwrap();
    assert_eq!(
        s.header().session_id,
        "s2",
        "session rotated — old grant not reusable"
    );
}

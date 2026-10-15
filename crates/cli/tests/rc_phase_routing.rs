#![cfg(unix)]
pub mod config {
    pub use orbit_cli::config::*;
}
#[path = "../src/phase_routing.rs"]
mod phase_routing;

use config::ProvidersConfig;
use orbit_engine::routing::{Difficulty, TaskPhase};
use phase_routing::*;
use std::net::TcpListener;

struct Fixture {
    server: TcpListener,
    config: ProvidersConfig,
    raw: String,
    settings: PhaseRoutingConfig,
}
impl Fixture {
    fn new() -> Self {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let raw = format!(
            r#"
[[provider]]
name='local'
url='http://{}'
env='FIXTURE_TOKEN'
[[provider.models]]
id='base'
supported_efforts=['low','high']
default_effort='low'
[[provider.models]]
id='vendor/model-a'
max_output_tokens=777
context_window=9999
supported_efforts=['low']
default_effort='low'
[provider.models.pricing]
input_per_million_microdollars=123
[[provider.models]]
id='small'
[[provider]]
name='other'
url='http://{}'
[[provider.models]]
id='base'
[[provider.models]]
id='strong'
[routing]
hard='other/strong'
easy='local/small'
[routing.phases.coding]
hard='local/vendor/model-a'
default='local/base'
[routing.phases.pentest]
default='other/strong'
"#,
            server.local_addr().unwrap(),
            server.local_addr().unwrap()
        );
        let config = ProvidersConfig::load_from_str(&raw).unwrap();
        let settings = parse_settings(&raw).unwrap();
        Self {
            server,
            config,
            raw,
            settings,
        }
    }
    fn base(&self) -> ResolvedModel {
        resolve_model(&self.config, "base", Some("local")).unwrap()
    }
    fn route(&self, prompt: &str) -> RouteDecision {
        preview(
            &self.config,
            &self.settings,
            &self.base(),
            SelectionOrigin::Default,
            prompt,
            None,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(
                matches!(self.server.accept(),Err(e)if e.kind()==std::io::ErrorKind::WouldBlock),
                "offline routing contacted fixture provider"
            );
        }
    }
}

#[test]
fn phase_identity_coding_hard_has_exact_caps_and_offline_preview() {
    let f = Fixture::new();
    let d = f.route("implement comprehensive parser");
    assert_eq!(
        (d.phase, d.difficulty, d.source),
        (
            TaskPhase::Coding,
            Difficulty::Hard,
            RouteSource::PhaseDifficulty
        )
    );
    assert_eq!(d.provider_id, "local");
    assert_eq!(d.raw_model, "vendor/model-a");
    assert_eq!(d.model.caps.max_output_tokens, Some(777));
    assert_eq!(d.model.pricing.input_per_million_microdollars, 123);
    assert_eq!(d.model.credential_env.as_deref(), Some("FIXTURE_TOKEN"));
    assert_eq!(
        d,
        preview(
            &f.config,
            &f.settings,
            &f.base(),
            SelectionOrigin::Default,
            "implement comprehensive parser",
            None
        )
        .unwrap()
    );
}
#[test]
fn phase_identity_explicit_default_equality_is_still_pinned() {
    let f = Fixture::new();
    let d = preview(
        &f.config,
        &f.settings,
        &f.base(),
        SelectionOrigin::Flag,
        "implement comprehensive parser",
        None,
    )
    .unwrap();
    assert_eq!(d.raw_model, "base");
    assert_eq!(d.source, RouteSource::Explicit);
    assert!(d.suppressed_reason.unwrap().contains("/route auto"));
}
#[test]
fn phase_identity_domain_only_pentest_does_not_become_hard() {
    let f = Fixture::new();
    let d = f.route("pentest vulnerability audit");
    assert_eq!(
        (d.phase, d.difficulty, d.source),
        (
            TaskPhase::Pentest,
            Difficulty::Normal,
            RouteSource::PhaseDefault
        )
    );
    assert!(d.matched.hard_hits.is_empty());
    assert_eq!(d.matched.phase_hits[&TaskPhase::Pentest].len(), 3);
}
#[test]
fn phase_identity_qualified_raw_slashes_survive() {
    let f = Fixture::new();
    let m = resolve_model(&f.config, "local/vendor/model-a", None).unwrap();
    assert_eq!(m.raw_model, "vendor/model-a");
    assert_eq!(m.qualified(), "local/vendor/model-a");
}
#[test]
fn phase_identity_ambiguous_bare_id_requires_provider() {
    let f = Fixture::new();
    assert!(
        resolve_model(&f.config, "base", None)
            .unwrap_err()
            .contains("ambiguous")
    );
    assert_eq!(
        resolve_model(&f.config, "other/base", None)
            .unwrap()
            .provider_id,
        "other"
    );
}
#[test]
fn phase_identity_unknown_selected_model_cannot_fall_back() {
    let f = Fixture::new();
    assert!(resolve_model(&f.config, "local/missing", None).is_err());
    assert!(resolve_model(&f.config, "unknown/model", None).is_err());
    assert!(resolve_model(&f.config, "base", Some("missing")).is_err());
}
#[test]
fn first_substring_does_not_hide_later_valid_keyword() {
    let f = Fixture::new();
    let d = f.route("reimplement implement refactorization refactor");
    assert_eq!(d.phase, TaskPhase::Coding);
    assert_eq!(d.difficulty, Difficulty::Hard);
    assert_eq!(
        d.matched.phase_hits[&TaskPhase::Coding]
            .iter()
            .find(|h| h.keyword == "implement")
            .unwrap()
            .occurrences,
        1
    );
}
#[test]
fn unicode_word_boundaries_and_case_are_respected() {
    let mut f = Fixture::new();
    f.settings.phase_keywords = Some(PhaseKeywords {
        clear: true,
        coding: vec!["ÉTUDIER".into()],
        ..Default::default()
    });
    assert_eq!(
        f.route("préétudier étudier ÉTUDIER").matched.phase_hits[&TaskPhase::Coding][0].occurrences,
        2
    );
    assert_eq!(f.route("préétudier").phase, TaskPhase::General);
}
#[test]
fn combining_marks_do_not_create_false_word_boundaries() {
    let f = Fixture::new();
    assert_eq!(f.route("e\u{301}implement").phase, TaskPhase::General);
    assert_eq!(f.route("implement\u{301}").phase, TaskPhase::General);
    assert_eq!(
        f.route("implement, implement").matched.phase_hits[&TaskPhase::Coding][0].occurrences,
        2
    );
}

#[test]
fn phase_precedence_reports_all_domains() {
    let f = Fixture::new();
    let d = f.route("analyze coordinate implement plan design pentest");
    assert_eq!(d.phase, TaskPhase::Pentest);
    for p in TaskPhase::PRECEDENCE {
        assert!(d.matched.phase_hits.contains_key(&p));
    }
}
#[test]
fn general_phase_retains_base_without_signals() {
    let f = Fixture::new();
    let d = f.route("hello there");
    assert_eq!(
        (d.phase, d.difficulty, d.source),
        (TaskPhase::General, Difficulty::Normal, RouteSource::Base)
    );
    assert_eq!(d.model, f.base());
    assert!(d.model.same_identity(&f.base()));
}
#[test]
fn thinking_phase_uses_legacy_easy_target() {
    let f = Fixture::new();
    let d = f.route("briefly explain mutex");
    assert_eq!(
        (d.phase, d.difficulty, d.source),
        (
            TaskPhase::Thinking,
            Difficulty::Easy,
            RouteSource::LegacyDifficulty
        )
    );
    assert_eq!(d.raw_model, "small");
}
#[test]
fn planning_is_independent_from_normal_difficulty() {
    let f = Fixture::new();
    let d = f.route("plan next milestone");
    assert_eq!(
        (d.phase, d.difficulty),
        (TaskPhase::Planning, Difficulty::Normal)
    );
}
#[test]
fn design_does_not_force_hard_but_redesign_can() {
    let f = Fixture::new();
    assert_eq!(f.route("design interface").difficulty, Difficulty::Normal);
    assert_eq!(f.route("redesign interface").difficulty, Difficulty::Hard);
}
#[test]
fn orchestration_phase_does_not_depend_on_tool_inventory() {
    let f = Fixture::new();
    assert_eq!(
        f.route("spawn agents to coordinate").phase,
        TaskPhase::Orchestration
    );
}
#[test]
fn hard_wins_over_easy_with_both_match_lists() {
    let f = Fixture::new();
    let d = f.route("briefly implement comprehensive solution");
    assert_eq!(d.difficulty, Difficulty::Hard);
    assert!(!d.matched.hard_hits.is_empty());
    assert!(!d.matched.easy_hits.is_empty());
}
#[test]
fn explicit_phase_override_does_not_override_difficulty() {
    let f = Fixture::new();
    let d = preview(
        &f.config,
        &f.settings,
        &f.base(),
        SelectionOrigin::Default,
        "implement comprehensive parser",
        Some(TaskPhase::Design),
    )
    .unwrap();
    assert_eq!(
        (d.phase, d.difficulty),
        (TaskPhase::Design, Difficulty::Hard)
    );
    assert!(d.matched.phase_override);
}
#[test]
fn every_explicit_origin_suppresses_routing() {
    let f = Fixture::new();
    for origin in [
        SelectionOrigin::Flag,
        SelectionOrigin::Environment,
        SelectionOrigin::Interactive,
        SelectionOrigin::SavedExplicit,
        SelectionOrigin::AgentExplicit,
    ] {
        let d = preview(&f.config, &f.settings, &f.base(), origin, "refactor", None).unwrap();
        assert_eq!(d.source, RouteSource::Explicit);
        assert_eq!(d.model, f.base());
    }
}
#[test]
fn role_origin_permits_routing_and_restored_legacy_is_explicit() {
    let f = Fixture::new();
    assert_eq!(
        preview(
            &f.config,
            &f.settings,
            &f.base(),
            SelectionOrigin::Role,
            "refactor",
            None
        )
        .unwrap()
        .source,
        RouteSource::PhaseDifficulty
    );
    assert_eq!(
        SelectionOrigin::restored(None),
        SelectionOrigin::SavedExplicit
    );
    assert_eq!(
        SelectionOrigin::restored(Some(SelectionOrigin::Role)),
        SelectionOrigin::Role
    );
    let encoded = serde_json::to_string(&SelectionOrigin::AgentExplicit).unwrap();
    assert_eq!(encoded, "\"agent_explicit\"");
}
#[test]
fn absent_phase_tables_preserve_legacy_domain_hard() {
    let mut f = Fixture::new();
    f.settings = PhaseRoutingConfig::default();
    let d = f.route("pentest vulnerability audit");
    assert_eq!(
        (d.phase, d.difficulty, d.source),
        (
            TaskPhase::General,
            Difficulty::Hard,
            RouteSource::LegacyDifficulty
        )
    );
    assert_eq!(d.raw_model, "strong");
}
#[test]
fn phase_target_absence_uses_legacy_then_base() {
    let mut f = Fixture::new();
    assert_eq!(
        f.route("comprehensive plan").source,
        RouteSource::LegacyDifficulty
    );
    f.config.routing.hard.clear();
    assert_eq!(f.route("comprehensive plan").source, RouteSource::Base);
}
#[test]
fn unknown_configured_target_errors_even_when_pinned() {
    let mut f = Fixture::new();
    f.settings.phases.get_mut(&TaskPhase::Coding).unwrap().hard = "local/nope".into();
    assert!(
        preview(
            &f.config,
            &f.settings,
            &f.base(),
            SelectionOrigin::Flag,
            "hello",
            None
        )
        .is_err()
    );
}
#[test]
fn stale_qualified_prefix_never_becomes_foreign_raw_id() {
    let mut f = Fixture::new();
    let mut m = f.config.provider[1].models[0].clone();
    m.id = "local/stale".into();
    f.config.provider[1].models.push(m);
    assert!(resolve_model(&f.config, "local/stale", None).is_err());
    assert_eq!(
        resolve_model(&f.config, "local/stale", Some("other"))
            .unwrap()
            .raw_model,
        "local/stale"
    );
}
#[test]
fn duplicate_provider_or_raw_model_is_refused() {
    let mut f = Fixture::new();
    f.config.provider.push(f.config.provider[0].clone());
    assert!(validate_providers(&f.config).is_err());
    f.config.provider.pop();
    let duplicate = f.config.provider[0].models[0].clone();
    f.config.provider[0].models.push(duplicate);
    assert!(validate_providers(&f.config).is_err());
}
#[test]
fn metadata_change_requires_checked_reresolution() {
    let mut f = Fixture::new();
    let old = f.base();
    f.config.provider[0].url = "http://127.0.0.1:9".into();
    assert!(
        preview(
            &f.config,
            &f.settings,
            &old,
            SelectionOrigin::Default,
            "hello",
            None
        )
        .is_err()
    );
}
#[test]
fn changed_identity_uses_own_effort_and_preserves_base() {
    let f = Fixture::new();
    let base = f.base();
    let mut turn = base.turn_config(None).unwrap();
    turn.effort = Some(orbit_adapter::types::EffortValue::Level("high".into()));
    let routed = f.route("refactor").model.turn_config(Some(&turn)).unwrap();
    assert_eq!(
        routed.effort,
        Some(orbit_adapter::types::EffortValue::Level("low".into()))
    );
    assert_eq!(
        turn.effort,
        Some(orbit_adapter::types::EffortValue::Level("high".into()))
    );
    assert_eq!(routed.model, "vendor/model-a");
}
#[test]
fn same_identity_retains_explicit_effort() {
    let f = Fixture::new();
    let model = f.base();
    let mut turn = model.turn_config(None).unwrap();
    turn.effort = Some(orbit_adapter::types::EffortValue::Level("high".into()));
    assert_eq!(model.turn_config(Some(&turn)).unwrap().effort, turn.effort);
}
#[test]
fn preview_serialization_contains_no_prompt_or_credentials() {
    let f = Fixture::new();
    let d = f.route("implement comprehensive private-sentinel");
    let text = serde_json::to_string(&d).unwrap();
    assert!(!text.contains("private-sentinel"));
    assert!(!text.contains("FIXTURE_TOKEN"));
    assert!(!text.contains("127.0.0.1"));
    assert!(text.contains("vendor/model-a"));
}
#[test]
fn keyword_clear_and_extensions_are_bounded() {
    let mut f = Fixture::new();
    f.settings.phase_keywords = Some(PhaseKeywords {
        clear: true,
        thinking: vec!["ponder".into()],
        ..Default::default()
    });
    assert_eq!(f.route("implement").phase, TaskPhase::General);
    assert_eq!(f.route("ponder").phase, TaskPhase::Thinking);
    f.settings.phase_keywords.as_mut().unwrap().thinking = vec!["x".into(); 129];
    assert!(f.settings.keywords().is_err());
}
#[test]
fn overlong_keyword_and_prompt_are_refused() {
    let mut f = Fixture::new();
    f.settings.phase_keywords = Some(PhaseKeywords {
        coding: vec!["x".repeat(97)],
        ..Default::default()
    });
    assert!(f.settings.keywords().is_err());
    f.settings.phase_keywords = None;
    assert!(
        preview(
            &f.config,
            &f.settings,
            &f.base(),
            SelectionOrigin::Default,
            &"x".repeat(256 * 1024 + 1),
            None
        )
        .is_err()
    );
}
#[test]
fn malformed_phase_schema_is_not_ignored() {
    for raw in [
        "[routing.phases.unknown]\nhard='x'",
        "[routing.phases.coding]\nsecret='x'",
        "[routing.phase_keywords]\ncoding='x'",
        "routing=3",
    ] {
        assert!(parse_settings(raw).is_err(), "{raw}");
    }
}
#[test]
fn setup_candidate_preserves_unrelated_config_and_fills_all_phases() {
    let f = Fixture::new();
    let raw = format!("{}\n[unrelated]\nlabel='preserve'\n", f.raw);
    let candidate = config_candidate(
        &raw,
        RouteMutation::Setup {
            easy: "local/small".into(),
            hard: "other/strong".into(),
        },
    )
    .unwrap();
    let v: toml::Value = toml::from_str(&candidate).unwrap();
    assert_eq!(v["unrelated"]["label"].as_str(), Some("preserve"));
    let settings = parse_settings(&candidate).unwrap();
    assert_eq!(settings.phases.len(), 7);
    for phase in TaskPhase::ALL {
        assert_eq!(settings.phases[&phase].hard, "other/strong");
    }
}
#[test]
fn set_reset_candidate_validates_without_touching_original() {
    let f = Fixture::new();
    let original = f.raw.clone();
    let candidate = config_candidate(
        &f.raw,
        RouteMutation::Set {
            phase: TaskPhase::Design,
            difficulty: None,
            model: "local/small".into(),
        },
    )
    .unwrap();
    assert_eq!(
        parse_settings(&candidate).unwrap().phases[&TaskPhase::Design].default,
        "local/small"
    );
    let cleared = config_candidate(
        &candidate,
        RouteMutation::Reset {
            phase: Some(TaskPhase::Design),
        },
    )
    .unwrap();
    assert!(
        !parse_settings(&cleared)
            .unwrap()
            .phases
            .contains_key(&TaskPhase::Design)
    );
    assert!(
        config_candidate(
            &f.raw,
            RouteMutation::Set {
                phase: TaskPhase::Design,
                difficulty: None,
                model: "missing".into()
            }
        )
        .is_err()
    );
    assert_eq!(f.raw, original);
    let reset = config_candidate(&candidate, RouteMutation::Reset { phase: None }).unwrap();
    assert!(!parse_settings(&reset).unwrap().enabled());
}
#[test]
fn invalid_urls_kinds_and_env_names_are_rejected() {
    let mut f = Fixture::new();
    for url in [
        "https://user:pass@example.invalid",
        "file:///tmp/provider",
        "https://example.invalid/#secret",
    ] {
        f.config.provider[0].url = url.into();
        assert!(validate_providers(&f.config).is_err());
    }
    f.config.provider[0].url = "http://127.0.0.1:9".into();
    f.config.provider[0].kind = "typo".into();
    assert!(validate_providers(&f.config).is_err());
    f.config.provider[0].kind = "openai-compatible".into();
    f.config.provider[0].env = Some("TOKEN=secret".into());
    assert!(validate_providers(&f.config).is_err());
}
#[test]
fn oversized_document_or_invalid_existing_shape_cannot_mutate() {
    assert!(
        config_candidate(
            &"x".repeat(MAX_CONFIG_BYTES + 1),
            RouteMutation::Reset { phase: None }
        )
        .is_err()
    );
    assert!(
        config_candidate(
            "routing=[]",
            RouteMutation::Setup {
                easy: "x".into(),
                hard: "y".into()
            }
        )
        .is_err()
    );
}

#[test]
fn legacy_target_candidate_is_checked_and_can_be_disabled() {
    let f = Fixture::new();
    let candidate = config_candidate(
        &f.raw,
        RouteMutation::LegacyTarget {
            difficulty: Difficulty::Hard,
            model: "local/small".into(),
        },
    )
    .unwrap();
    assert_eq!(
        ProvidersConfig::load_from_str(&candidate)
            .unwrap()
            .routing
            .hard,
        "local/small"
    );
    let cleared = config_candidate(
        &candidate,
        RouteMutation::LegacyTarget {
            difficulty: Difficulty::Hard,
            model: String::new(),
        },
    )
    .unwrap();
    assert!(
        ProvidersConfig::load_from_str(&cleared)
            .unwrap()
            .routing
            .hard
            .is_empty()
    );
    assert!(
        config_candidate(
            &candidate,
            RouteMutation::LegacyTarget {
                difficulty: Difficulty::Easy,
                model: "missing".into()
            }
        )
        .is_err()
    );
}
#[test]
fn legacy_keyword_candidates_add_remove_and_clear_without_dropping_other_values() {
    let f = Fixture::new();
    let added = config_candidate(
        &f.raw,
        RouteMutation::EditKeywords {
            difficulty: Difficulty::Hard,
            word: "bespoke".into(),
            remove: false,
        },
    )
    .unwrap();
    assert!(
        ProvidersConfig::load_from_str(&added)
            .unwrap()
            .routing_table()
            .hard_keywords
            .contains(&"bespoke".into())
    );
    let removed = config_candidate(
        &added,
        RouteMutation::EditKeywords {
            difficulty: Difficulty::Hard,
            word: "BESPOKE".into(),
            remove: true,
        },
    )
    .unwrap();
    assert!(
        !ProvidersConfig::load_from_str(&removed)
            .unwrap()
            .routing_table()
            .hard_keywords
            .contains(&"bespoke".into())
    );
    let cleared = config_candidate(&added, RouteMutation::ClearKeywords).unwrap();
    let cfg = ProvidersConfig::load_from_str(&cleared).unwrap();
    assert!(cfg.routing_table().hard_keywords.is_empty());
    assert!(cfg.routing_table().easy_keywords.is_empty());
    assert_eq!(cfg.provider, f.config.provider);
    assert_eq!(parse_settings(&cleared).unwrap().phases, f.settings.phases);
}
#[test]
fn off_candidate_removes_all_targets_but_retains_keyword_preferences() {
    let f = Fixture::new();
    let raw = format!(
        "{}\n[routing.keywords]\nclear=true\nhard=['bespoke']\n",
        f.raw
    );
    let disabled = config_candidate(&raw, RouteMutation::Disable).unwrap();
    assert!(!parse_settings(&disabled).unwrap().enabled());
    let cfg = ProvidersConfig::load_from_str(&disabled).unwrap();
    assert!(!cfg.routing_table().enabled());
    assert_eq!(cfg.routing.keywords.hard, vec!["bespoke"]);
}

#[test]
fn credential_query_cannot_enter_resolved_identity_but_benign_query_is_preserved() {
    let mut f = Fixture::new();
    for key in [
        "api_key",
        "%61Pi%2DKey",
        "token",
        "Access.Token",
        "refresh_token",
        "password",
        "secret",
        "client_secret",
        "authorization",
        "auth",
        "key",
    ] {
        f.config.provider[0].url =
            format!("https://example.invalid/v1?{key}=PRIVATE_QUERY_CREDENTIAL");
        let error = resolve_model(&f.config, "local/base", None).unwrap_err();
        assert!(error.contains("credential query"));
        assert!(!error.contains("PRIVATE_QUERY_CREDENTIAL"));
        assert!(validate_settings(&f.config, &f.settings).is_err());
    }
    f.config.provider[0].url = "https://example.invalid/v1?api-version=2026-01-01".into();
    let resolved = resolve_model(&f.config, "local/base", None).unwrap();
    assert_eq!(resolved.url, f.config.provider[0].url);
    validate_settings(&f.config, &f.settings).unwrap();
}

use orbit_cli::config::ProvidersConfig;
use serde_json::json;

const RAW_MODEL: &str = "family/raw:stable";

fn document(first: &str, second: &str) -> String {
    let table = |fields: &str| {
        if fields.is_empty() {
            String::new()
        } else {
            format!("[provider.models.context_limits]\n{fields}\n")
        }
    };
    let first = table(first);
    let second = table(second);
    format!(
        r#"[[provider]]
name = "fixture-a"
kind = "openai-compatible"
url = "https://fixture-a.invalid/v1"
env = "ORBIT_CONTEXT_TEST_KEY_A"

[[provider.models]]
id = "{RAW_MODEL}"
label = "Fixture A"
max_output_tokens = 2048
context_window = 8192
supported_efforts = ["low", "high"]
default_effort = "high"
[provider.models.sampling]
temperature = 0.25
top_p = 0.8
[provider.models.pricing]
input_per_million_microdollars = 123
output_per_million_microdollars = 456
{first}
[[provider.models]]
id = "family/other"
context_window = 12345

[[provider]]
name = "fixture-b"
kind = "openai-compatible"
url = "https://fixture-b.invalid/v1"
env = "ORBIT_CONTEXT_TEST_KEY_B"
[[provider.models]]
id = "{RAW_MODEL}"
max_output_tokens = 1024
context_window = 65536
{second}"#
    )
}

fn saved_document(source: &str) -> toml::Value {
    let config = ProvidersConfig::load_from_str(source).expect("valid provider configuration");
    let serialized = toml::to_string(&config).expect("serialize provider configuration");
    let reloaded = ProvidersConfig::load_from_str(&serialized).expect("reload serialized config");
    assert_eq!(reloaded, config);
    toml::from_str(&serialized).expect("serialized TOML document")
}

fn model<'a>(document: &'a toml::Value, provider: &str, raw: &str) -> &'a toml::Value {
    document["provider"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"].as_str() == Some(provider))
        .unwrap()["models"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"].as_str() == Some(raw))
        .unwrap()
}

fn assert_retained(fields: &str) {
    let saved = saved_document(&document(fields, ""));
    let expected: toml::Table = toml::from_str(fields).unwrap();
    let actual = model(&saved, "fixture-a", RAW_MODEL)
        .get("context_limits")
        .and_then(toml::Value::as_table)
        .expect("context_limits must survive the actual config parser and serializer");
    for (name, value) in expected {
        assert_eq!(actual.get(&name), Some(&value), "retain {name} exactly");
    }
    assert!(
        model(&saved, "fixture-a", "family/other")
            .get("context_limits")
            .is_none()
    );
    assert!(
        model(&saved, "fixture-b", RAW_MODEL)
            .get("context_limits")
            .is_none()
    );
}

fn assert_refused(fields: &str) {
    assert!(
        ProvidersConfig::load_from_str(&document(fields, "")).is_err(),
        "invalid context_limits must not be silently accepted: {fields}"
    );
}

#[test]
fn context_limits_roundtrip_retains_exact_provider_and_raw_model() {
    let first = r#"input_tokens = 16000
combined_tokens = 24000
fallback_input_tokens = 12000
fallback_combined_tokens = 20000
unknown_policy = "fallback"
media_policy = "allow-with-warning"
max_age_seconds = 3600"#;
    let second = r#"input_tokens = 48000
combined_tokens = 64000
fallback_input_tokens = 32000
fallback_combined_tokens = 48000
unknown_policy = "require-limit"
media_policy = "refuse"
max_age_seconds = 604800"#;
    let source = document(first, second);
    let expected: toml::Value = toml::from_str(&source).unwrap();
    let saved = saved_document(&source);
    for provider in ["fixture-a", "fixture-b"] {
        assert_eq!(
            model(&saved, provider, RAW_MODEL).get("context_limits"),
            model(&expected, provider, RAW_MODEL).get("context_limits"),
            "limits belong to the exact provider/raw-model pair: {provider}"
        );
    }
    assert!(
        model(&saved, "fixture-a", "family/other")
            .get("context_limits")
            .is_none()
    );
}

#[test]
fn absent_context_limits_preserves_existing_model_serialization() {
    let source = document("", "");
    let config = ProvidersConfig::load_from_str(&source).unwrap();
    let (_, selected) = config.model_entry("fixture-a", RAW_MODEL).unwrap();
    assert_eq!(
        serde_json::to_value(selected).unwrap(),
        json!({
            "id": RAW_MODEL,
            "label": "Fixture A",
            "pricing": {
                "input_per_million_microdollars": 123,
                "output_per_million_microdollars": 456,
                "cache_read_per_million_microdollars": null,
                "cache_write_per_million_microdollars": null,
                "reasoning_per_million_microdollars": null,
                "request_flat_microdollars": 0
            },
            "max_output_tokens": 2048,
            "context_window": 8192,
            "sampling": { "temperature": 0.25, "top_p": 0.8 },
            "supported_efforts": ["low", "high"],
            "default_effort": "high"
        })
    );
    let saved = saved_document(&source);
    for provider in ["fixture-a", "fixture-b"] {
        assert!(
            model(&saved, provider, RAW_MODEL)
                .get("context_limits")
                .is_none()
        );
    }
}

#[test]
fn input_and_combined_ceilings_are_independent_valid_controls() {
    // A tighter combined ceiling is meaningful; request feasibility is checked at runtime.
    assert_retained("input_tokens = 10000\ncombined_tokens = 1024");
}

#[test]
fn require_limit_preserves_dormant_fallback_controls() {
    assert_retained(
        "unknown_policy = \"require-limit\"\nfallback_input_tokens = 10000\nfallback_combined_tokens = 1",
    );
}

#[test]
fn context_limits_policy_only_overrides_remain_valid() {
    assert_retained("unknown_policy = \"fallback\"\nmedia_policy = \"refuse\"");
}

#[test]
fn context_limit_age_bounds_are_valid_and_retained() {
    for age in [1, 604800] {
        assert_retained(&format!("max_age_seconds = {age}"));
    }
}

#[test]
fn context_limit_positive_and_wide_ceilings_are_retained() {
    assert_retained(
        "input_tokens = 1\ncombined_tokens = 4294967296\nfallback_input_tokens = 4294967296\nfallback_combined_tokens = 9223372036854775807",
    );
}

#[test]
fn context_limit_zero_input_is_refused() {
    assert_refused("input_tokens = 0");
}

#[test]
fn context_limit_zero_combined_is_refused() {
    assert_refused("combined_tokens = 0");
}

#[test]
fn context_limit_zero_fallback_input_is_refused() {
    assert_refused("fallback_input_tokens = 0");
}

#[test]
fn context_limit_zero_fallback_combined_is_refused() {
    assert_refused("fallback_combined_tokens = 0");
}

#[test]
fn context_limit_unknown_text_policy_names_are_refused() {
    for policy in ["", "auto", "FALLBACK", "require_limit"] {
        assert_refused(&format!("unknown_policy = {policy:?}"));
    }
}

#[test]
fn context_limit_unknown_media_policy_names_are_refused() {
    for policy in ["", "allow", "ALLOW-WITH-WARNING", "allow_with_warning"] {
        assert_refused(&format!("media_policy = {policy:?}"));
    }
}

#[test]
fn context_limit_age_outside_declared_bounds_is_refused() {
    for age in ["0", "604801", "-1"] {
        assert_refused(&format!("max_age_seconds = {age}"));
    }
}

#[test]
fn context_limit_wrong_scalar_types_are_refused() {
    for fields in [
        "input_tokens = -1",
        "combined_tokens = -1",
        "fallback_input_tokens = -1",
        "fallback_combined_tokens = -1",
        "input_tokens = \"64000\"",
        "combined_tokens = 1.5",
        "fallback_input_tokens = true",
        "fallback_combined_tokens = []",
        "unknown_policy = 1",
        "media_policy = false",
        "max_age_seconds = \"3600\"",
    ] {
        assert_refused(fields);
    }
}

#[test]
fn context_limit_unknown_inner_keys_are_refused() {
    for fields in [
        "input_token = 64000",
        "combined_token = 64000",
        "max_age_second = 3600",
        "unrecognized = true",
    ] {
        assert_refused(fields);
    }
}

#[cfg(target_os = "linux")]
mod resolver_tests {
    use orbit_adapter::provider_credentials::ProviderAuthIdentity;
    use orbit_adapter::types::EffortValue;
    use orbit_cli::config::{ProviderConfig, ProvidersConfig};
    use orbit_cli::model_limits::{
        BudgetError, BudgetNotice, BudgetReport, LegacyContextStatus, LimitComponent,
        resolve_turn_budget, resolve_turn_budget_detailed, resolve_turn_budgets,
        resolve_turn_budgets_detailed,
    };
    use orbit_cli::provider_discovery::{ModelProvenance, save_model_provenance};
    use orbit_engine::context_budget::{
        BudgetDecision, BudgetSource, EstimateStatus, Freshness, RequestEstimate, assess_request,
    };
    use orbit_engine::{ProviderKind, TurnConfig};
    use serde_json::{Value, json};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const RAW: &str = "family/raw:stable";
    const NOW: u64 = 1_000_000;
    const CONTEXT: u64 = 200_000;
    const OUTPUT: u64 = 4096;

    struct Home(PathBuf);
    impl Home {
        fn new(providers: Vec<ProviderConfig>) -> Self {
            let home =
                Self(std::env::temp_dir().join(format!("orbit-limits-{}", ulid::Ulid::new())));
            std::fs::create_dir(&home.0).unwrap();
            std::fs::set_permissions(&home.0, std::fs::Permissions::from_mode(0o700)).unwrap();
            home.configure(providers);
            home
        }
        fn configure(&self, providers: Vec<ProviderConfig>) {
            let config: ProvidersConfig =
                serde_json::from_value(json!({"provider":providers})).unwrap();
            private_write(
                &self.0.join("providers.toml"),
                toml::to_string(&config).unwrap().as_bytes(),
            );
        }
        fn provenance(&self, provider: &ProviderConfig, record: Value) {
            let record: ModelProvenance = serde_json::from_value(record).unwrap();
            save_model_provenance(&self.0, provider, &[record]).unwrap();
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn private_write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn provider(name: &str, legacy: Option<u64>, limits: Option<Value>) -> ProviderConfig {
        serde_json::from_value(json!({
            "name":name,"kind":"anthropic","url":format!("https://{name}.invalid/v1?tenant=left%2Fright&version=1"),
            "env":format!("ORBIT_LIMITS_{}",name.to_ascii_uppercase().replace('-', "_")),
            "models":[{"id":RAW,"context_window":legacy,"max_output_tokens":OUTPUT,
                "context_limits":limits,"supported_efforts":["low","high"],"default_effort":"low"}]
        })).unwrap()
    }
    fn turn(provider: &ProviderConfig) -> TurnConfig {
        let model = &provider.models[0];
        TurnConfig {
            provider_id: provider.name.clone(),
            gate: provider.url.clone(),
            model: model.id.clone(),
            kind: ProviderKind::from_config(&provider.kind),
            credential_env: provider.env.clone(),
            pricing: None,
            max_output_tokens: u64::from(model.max_output_tokens.unwrap_or(32_000)),
            sampling: None,
            effort: model.default_effort.clone(),
            supported_efforts: model.supported_efforts.clone(),
        }
    }
    fn binding(provider: &ProviderConfig) -> String {
        let url = orbit_cli::config::validate_provider_endpoint(&provider.url).unwrap();
        ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            url.as_str(),
            provider.env.as_deref(),
        )
        .unwrap()
        .binding_id()
    }
    fn record(provider: &ProviderConfig, context_time: u64, output_time: u64) -> Value {
        json!({
            "schema_version":2,"provider_binding":binding(provider),"model_id":RAW,
            "last_applied_context_window":CONTEXT,"last_applied_max_output_tokens":OUTPUT,"last_applied_label":null,
            "observed":{"id":RAW,"label":null,"context_window":CONTEXT,"max_output_tokens":OUTPUT,
                "source":"anthropic_models","metadata_valid":true,"unrecognized_fields":[],
                "evidence":{
                    "context_limit":{"value":CONTEXT,"observed_at_unix":context_time,"source":"anthropic_models", "schema":"anthropic_models_2023_06_01","semantics":"input_tokens","confidence":"documented_limit"},
                    "output_limit":{"value":OUTPUT,"observed_at_unix":output_time,"source":"anthropic_models", "schema":"anthropic_models_2023_06_01","semantics":"output_tokens","confidence":"documented_limit"}
                }
            }
        })
    }
    fn resolve(home: &Home, provider: &ProviderConfig, now: u64) -> BudgetReport {
        resolve_turn_budget_detailed(&home.0, &turn(provider), now).unwrap()
    }
    fn assert_default_fallback(report: &BudgetReport) {
        assert_eq!(report.budget.source, BudgetSource::Fallback);
        assert_eq!(report.budget.freshness, Freshness::Policy);
        assert_eq!(report.budget.ceilings.input_tokens, None);
        assert_eq!(report.budget.ceilings.combined_tokens, Some(64_000));
        assert!(report.notices.iter().any(|notice| matches!(
            notice,
            BudgetNotice::FallbackPolicy {
                input_tokens: None,
                combined_tokens: Some(64_000)
            }
        )));
    }
    fn estimate(
        report: &BudgetReport,
        input: u64,
        output: u64,
        status: EstimateStatus,
    ) -> RequestEstimate {
        RequestEstimate {
            body_bytes: input * 4,
            text_bytes: input * 4,
            system_bytes: 0,
            tools_bytes: 0,
            messages_bytes: input * 4,
            framing_bytes: 0,
            raw_system_bytes: 0,
            raw_tools_bytes: 0,
            raw_messages_bytes: input * 4,
            raw_framing_bytes: 0,
            estimated_input_tokens: input,
            requested_output_tokens: output,
            body_digest: "fixture-body".into(),
            binding_digest: report.budget.identity.binding_digest.clone(),
            status,
        }
    }

    #[test]
    fn resolver_duplicate_raw_ids_keep_exact_provider_limits() {
        let a = provider("fixture-a", None, Some(json!({"input_tokens":180_000})));
        let b = provider("fixture-b", None, Some(json!({"combined_tokens":24_000})));
        let home = Home::new(vec![a.clone(), b.clone()]);
        let both = resolve_turn_budgets_detailed(&home.0, &turn(&a), &turn(&b), NOW).unwrap();
        assert_eq!(both.selected.budget.ceilings.input_tokens, Some(180_000));
        assert_eq!(both.selected.budget.ceilings.combined_tokens, None);
        assert_eq!(both.summary.budget.ceilings.combined_tokens, Some(24_000));
        assert_ne!(
            both.selected.budget.identity.binding_digest,
            both.summary.budget.identity.binding_digest
        );
    }

    #[test]
    fn resolver_simple_wrappers_match_detailed_independent_budgets() {
        let a = provider("fixture-a", None, Some(json!({"input_tokens":180_000})));
        let b = provider("fixture-b", None, Some(json!({"input_tokens":8_000})));
        let home = Home::new(vec![a.clone(), b.clone()]);
        let detailed = resolve_turn_budgets_detailed(&home.0, &turn(&a), &turn(&b), NOW).unwrap();
        let simple = resolve_turn_budgets(&home.0, &turn(&a), &turn(&b), NOW).unwrap();
        assert_eq!(simple.selected, detailed.selected.budget);
        assert_eq!(simple.summary, detailed.summary.budget);
        assert_eq!(
            resolve_turn_budget(&home.0, &turn(&a), NOW).unwrap(),
            simple.selected
        );
    }

    #[test]
    fn resolver_same_provider_summary_raw_model_gets_its_own_budget() {
        let mut p = provider("fixture-a", None, Some(json!({"input_tokens":180_000})));
        let mut summary = serde_json::to_value(&p.models[0]).unwrap();
        summary["id"] = json!("family/summary");
        summary["max_output_tokens"] = json!(1024);
        summary["context_limits"] = json!({"combined_tokens":12_000});
        p.models.push(serde_json::from_value(summary).unwrap());
        let home = Home::new(vec![p.clone()]);
        let selected = turn(&p);
        let mut summary = selected.clone();
        summary.model = "family/summary".into();
        summary.max_output_tokens = 1024;
        let reports = resolve_turn_budgets_detailed(&home.0, &selected, &summary, NOW).unwrap();
        assert_eq!(reports.selected.budget.ceilings.input_tokens, Some(180_000));
        assert_eq!(reports.summary.budget.ceilings.input_tokens, None);
        assert_eq!(
            reports.summary.budget.ceilings.combined_tokens,
            Some(12_000)
        );
        assert_ne!(
            reports.selected.budget.identity.binding_digest,
            reports.summary.budget.identity.binding_digest
        );
    }

    #[test]
    fn resolver_summary_uses_actual_output_and_effort_after_overrides_even_for_same_model() {
        let p = provider("fixture-a", None, None);
        let home = Home::new(vec![p.clone()]);
        let mut selected = turn(&p);
        selected.max_output_tokens = 60_000;
        let mut summary = selected.clone();
        summary.max_output_tokens = 1024;
        summary.effort = Some(EffortValue::Level("high".into()));
        let reports = resolve_turn_budgets_detailed(&home.0, &selected, &summary, NOW).unwrap();
        assert_default_fallback(&reports.selected);
        assert_default_fallback(&reports.summary);
        assert_ne!(
            reports.selected.budget.identity.binding_digest,
            reports.summary.budget.identity.binding_digest
        );
        let ordinary = estimate(
            &reports.selected,
            5000,
            selected.max_output_tokens,
            EstimateStatus::Approximate,
        );
        let compact = estimate(
            &reports.summary,
            5000,
            summary.max_output_tokens,
            EstimateStatus::Approximate,
        );
        assert_eq!(
            assess_request(&ordinary, &reports.selected.budget),
            BudgetDecision::Compact
        );
        assert_eq!(
            assess_request(&compact, &reports.summary.budget),
            BudgetDecision::AdmitEstimated
        );
        assert_eq!(
            assess_request(&compact, &reports.selected.budget),
            BudgetDecision::Refuse
        );
        let mut changed_effort = summary.clone();
        changed_effort.effort = Some(EffortValue::Level("low".into()));
        let changed = resolve_turn_budget_detailed(&home.0, &changed_effort, NOW).unwrap();
        assert_ne!(
            changed.budget.identity.binding_digest,
            reports.summary.budget.identity.binding_digest
        );
    }

    #[test]
    fn resolver_duplicate_declarations_are_invalid_instead_of_first_match() {
        for duplicate_provider in [false, true] {
            let mut p = provider("fixture-a", None, None);
            let providers = if duplicate_provider {
                vec![p.clone(), p.clone()]
            } else {
                p.models.push(p.models[0].clone());
                vec![p.clone()]
            };
            let home = Home::new(providers);
            assert!(matches!(
                resolve_turn_budget_detailed(&home.0, &turn(&p), NOW),
                Err(BudgetError::InvalidConfig)
            ));
        }
    }

    #[test]
    fn resolver_valid_129_model_config_keeps_unknown_policy_without_metadata_limit_expansion() {
        for explicit in [false, true] {
            let limits = explicit.then(|| json!({"input_tokens":1_000_000}));
            let mut p = provider("fixture-a", None, limits);
            for index in 0..128 {
                p.models.push(
                    serde_json::from_value(json!({"id":format!("family/raw-{index}")})).unwrap(),
                );
            }
            let home = Home::new(vec![p.clone()]);
            orbit_cli::phase_routing::validate_providers(&ProvidersConfig::load(&home.0).unwrap())
                .unwrap();
            let report = resolve(&home, &p, NOW);
            if explicit {
                assert_eq!(report.budget.source, BudgetSource::Explicit);
                assert_eq!(report.budget.ceilings.input_tokens, Some(1_000_000));
            } else {
                assert_default_fallback(&report);
            }
        }
    }

    #[test]
    fn resolver_129_model_config_retains_selected_facts_and_valid_sibling_manual_marker() {
        for explicit in [false, true] {
            let limits = explicit.then(|| json!({"input_tokens":1_000_000}));
            let mut p = provider("fixture-a", Some(CONTEXT), limits);
            let mut sibling = serde_json::to_value(&p.models[0]).unwrap();
            sibling["id"] = json!("family/sibling:stable");
            sibling["context_window"] = json!(48_000);
            sibling["context_limits"] = Value::Null;
            p.models.push(serde_json::from_value(sibling).unwrap());
            let home = Home::new(vec![p.clone()]);
            let selected = record(&p, NOW, NOW);
            let mut sibling = record(&p, NOW, NOW);
            sibling["model_id"] = json!("family/sibling:stable");
            sibling["observed"]["id"] = json!("family/sibling:stable");
            sibling["last_applied_context_window"] = Value::Null;
            sibling["manual_input_tokens"] = json!(48_000);
            let records = vec![
                serde_json::from_value(selected).unwrap(),
                serde_json::from_value(sibling).unwrap(),
            ];
            save_model_provenance(&home.0, &p, &records).unwrap();
            for index in p.models.len()..129 {
                p.models.push(
                    serde_json::from_value(json!({"id":format!("family/raw-{index}")})).unwrap(),
                );
            }
            home.configure(vec![p.clone()]);
            let report = resolve(&home, &p, NOW);
            assert_eq!(
                report.budget.source,
                if explicit {
                    BudgetSource::Explicit
                } else {
                    BudgetSource::Discovered
                }
            );
            assert_eq!(
                report.budget.ceilings.input_tokens,
                Some(if explicit { 1_000_000 } else { CONTEXT })
            );
            assert_eq!(report.budget.ceilings.output_tokens, Some(OUTPUT));
        }
    }

    #[test]
    fn resolver_129_model_config_does_not_skip_invalid_sibling_evidence_for_explicit_policy() {
        let mut p = provider(
            "fixture-a",
            Some(CONTEXT),
            Some(json!({"input_tokens":1_000_000})),
        );
        let mut sibling = serde_json::to_value(&p.models[0]).unwrap();
        sibling["id"] = json!("family/sibling:stable");
        p.models.push(serde_json::from_value(sibling).unwrap());
        let home = Home::new(vec![p.clone()]);
        let selected = record(&p, NOW, NOW);
        let mut sibling = record(&p, NOW, NOW);
        sibling["model_id"] = json!("family/sibling:stable");
        sibling["observed"]["id"] = json!("family/sibling:stable");
        let records = vec![
            serde_json::from_value(selected).unwrap(),
            serde_json::from_value(sibling).unwrap(),
        ];
        save_model_provenance(&home.0, &p, &records).unwrap();
        let sidecar = home
            .0
            .join("metadata/providers")
            .join(format!("{}.json", binding(&p)));
        let mut damaged: Value = serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        damaged["models"][1]["observed"]["evidence"]["context_limit"]["value"] = json!(CONTEXT + 1);
        private_write(&sidecar, &serde_json::to_vec(&damaged).unwrap());
        for index in p.models.len()..129 {
            p.models
                .push(serde_json::from_value(json!({"id":format!("family/raw-{index}")})).unwrap());
        }
        home.configure(vec![p.clone()]);
        assert!(matches!(
            resolve_turn_budget_detailed(&home.0, &turn(&p), NOW),
            Err(BudgetError::InvalidMetadata)
        ));
    }

    #[test]
    fn resolver_approved_manual_marker_preserves_input_policy_after_receipt_reload() {
        let p = provider("fixture-a", Some(48_000), None);
        let home = Home::new(vec![p.clone()]);
        let mut receipt = record(&p, NOW, NOW);
        receipt["last_applied_context_window"] = Value::Null;
        receipt["manual_input_tokens"] = json!(48_000);
        home.provenance(&p, receipt);
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.budget.source, BudgetSource::Manual);
        assert_eq!(report.budget.freshness, Freshness::Policy);
        assert_eq!(report.budget.ceilings.input_tokens, Some(48_000));
        assert_eq!(
            report.legacy_context,
            LegacyContextStatus::IdentifiableManual
        );
    }

    #[test]
    fn resolver_unknown_plain_model_uses_visible_combined_policy() {
        let p = provider("fixture-a", None, None);
        let home = Home::new(vec![p.clone()]);
        let report = resolve(&home, &p, NOW);
        assert_default_fallback(&report);
        assert_eq!(report.budget.ceilings.output_tokens, None);
    }

    #[test]
    fn resolver_empty_config_explicit_endpoint_keeps_unknown_compatibility() {
        let p = provider("fixture-a", None, None);
        let home = Home::new(vec![]);
        assert_default_fallback(&resolve(&home, &p, NOW));
    }

    #[test]
    fn resolver_require_limit_is_opt_in_and_dormant_fallback_does_not_enable_it() {
        let p = provider(
            "fixture-a",
            None,
            Some(json!({"unknown_policy":"require-limit","fallback_combined_tokens":9000})),
        );
        let home = Home::new(vec![p.clone()]);
        assert!(matches!(
            resolve_turn_budget_detailed(&home.0, &turn(&p), NOW),
            Err(BudgetError::LimitRequired)
        ));
        let message = BudgetError::LimitRequired.to_string();
        assert!(message.contains("context_limits"));
        assert!(!message.contains("fixture-a.invalid"));
    }

    #[test]
    fn resolver_summary_require_limit_failure_does_not_borrow_selected_capacity() {
        let a = provider("fixture-a", None, Some(json!({"input_tokens":180_000})));
        let b = provider(
            "fixture-b",
            None,
            Some(json!({"unknown_policy":"require-limit"})),
        );
        let home = Home::new(vec![a.clone(), b.clone()]);
        assert!(matches!(
            resolve_turn_budgets_detailed(&home.0, &turn(&a), &turn(&b), NOW),
            Err(BudgetError::LimitRequired)
        ));
    }

    #[test]
    fn resolver_documented_output_alone_does_not_satisfy_require_limit() {
        let p = provider(
            "fixture-a",
            None,
            Some(json!({"unknown_policy":"require-limit"})),
        );
        let home = Home::new(vec![p.clone()]);
        let mut receipt = record(&p, NOW, NOW);
        receipt["last_applied_context_window"] = Value::Null;
        receipt["observed"]["evidence"]["context_limit"] = Value::Null;
        home.provenance(&p, receipt);
        assert!(matches!(
            resolve_turn_budget_detailed(&home.0, &turn(&p), NOW),
            Err(BudgetError::LimitRequired)
        ));
    }

    #[test]
    fn resolver_configured_fallback_replaces_default_without_stacking() {
        let p = provider(
            "fixture-a",
            None,
            Some(json!({"fallback_input_tokens":100_000})),
        );
        let home = Home::new(vec![p.clone()]);
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.budget.ceilings.input_tokens, Some(100_000));
        assert_eq!(report.budget.ceilings.combined_tokens, None);
        assert_eq!(report.budget.source, BudgetSource::Fallback);
    }

    #[test]
    fn resolver_fallback_reserves_actual_requested_output_once() {
        let p = provider("fixture-a", None, None);
        let home = Home::new(vec![p.clone()]);
        for (output, expected) in [
            (32_000, BudgetDecision::AdmitEstimated),
            (60_000, BudgetDecision::Compact),
        ] {
            let mut selected = turn(&p);
            selected.max_output_tokens = output;
            let report = resolve_turn_budget_detailed(&home.0, &selected, NOW).unwrap();
            assert_default_fallback(&report);
            assert_eq!(
                assess_request(
                    &estimate(&report, 5000, output, EstimateStatus::Approximate),
                    &report.budget
                ),
                expected
            );
        }
    }

    #[test]
    fn resolver_explicit_limit_wins_even_when_equal_to_fresh_observation() {
        let p = provider(
            "fixture-a",
            Some(CONTEXT),
            Some(json!({"input_tokens":CONTEXT})),
        );
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.budget.source, BudgetSource::Explicit);
        assert_eq!(report.budget.freshness, Freshness::Policy);
        assert_eq!(
            report.components.input.as_ref().unwrap().source,
            BudgetSource::Explicit
        );
        assert_eq!(report.budget.ceilings.input_tokens, Some(CONTEXT));
        assert_eq!(report.budget.ceilings.combined_tokens, None);
    }

    #[test]
    fn resolver_explicit_limit_does_not_gain_an_implicit_64000_ceiling() {
        let p = provider("fixture-a", None, Some(json!({"input_tokens":1_000_000})));
        let home = Home::new(vec![p.clone()]);
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.budget.ceilings.combined_tokens, None);
        assert_eq!(
            assess_request(
                &estimate(&report, 100_000, OUTPUT, EstimateStatus::Approximate),
                &report.budget
            ),
            BudgetDecision::AdmitEstimated
        );
    }

    #[test]
    fn resolver_exact_fresh_documented_managed_limit_is_used_without_fallback() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.budget.source, BudgetSource::Discovered);
        assert_eq!(report.budget.freshness, Freshness::Fresh);
        assert_eq!(report.budget.ceilings.input_tokens, Some(CONTEXT));
        assert_eq!(report.budget.ceilings.combined_tokens, None);
        assert_eq!(report.budget.ceilings.output_tokens, Some(OUTPUT));
    }

    #[test]
    fn resolver_fresh_observation_without_legacy_value_needs_no_manual_inference() {
        let p = provider("fixture-a", None, None);
        let home = Home::new(vec![p.clone()]);
        let mut receipt = record(&p, NOW, NOW);
        receipt["last_applied_context_window"] = Value::Null;
        home.provenance(&p, receipt);
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.legacy_context, LegacyContextStatus::Absent);
        assert_eq!(report.budget.source, BudgetSource::Discovered);
        assert_eq!(report.budget.ceilings.input_tokens, Some(CONTEXT));
    }

    #[test]
    fn resolver_missing_provenance_never_makes_legacy_value_manual() {
        let p = provider("fixture-a", Some(48_000), None);
        let home = Home::new(vec![p.clone()]);
        let report = resolve(&home, &p, NOW);
        assert_default_fallback(&report);
        assert_eq!(
            report.legacy_context,
            LegacyContextStatus::LegacyUnspecified
        );
        assert!(
            report
                .notices
                .contains(&BudgetNotice::LegacyContextUnspecified)
        );
    }

    #[test]
    fn resolver_fresh_equal_value_without_historical_marker_stays_legacy_unspecified() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        let mut receipt = record(&p, NOW, NOW);
        receipt["last_applied_context_window"] = Value::Null;
        home.provenance(&p, receipt);
        let report = resolve(&home, &p, NOW);
        assert_default_fallback(&report);
        assert_eq!(
            report.legacy_context,
            LegacyContextStatus::LegacyUnspecified
        );
    }

    #[test]
    fn resolver_valid_prior_applied_difference_identifies_manual_input_policy() {
        let p = provider("fixture-a", Some(48_000), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        let report = resolve(&home, &p, NOW);
        assert_eq!(
            report.legacy_context,
            LegacyContextStatus::IdentifiableManual
        );
        assert_eq!(report.budget.source, BudgetSource::Manual);
        assert_eq!(report.budget.freshness, Freshness::Policy);
        assert_eq!(report.budget.ceilings.input_tokens, Some(48_000));
        assert_eq!(report.budget.ceilings.combined_tokens, None);
    }

    #[test]
    fn resolver_unmarked_postrefresh_state_is_ambiguous_not_recovered_by_equality() {
        let p = provider("fixture-a", Some(48_000), None);
        let home = Home::new(vec![p.clone()]);
        let mut receipt = record(&p, NOW, NOW);
        receipt["last_applied_context_window"] = Value::Null;
        home.provenance(&p, receipt);
        let report = resolve(&home, &p, NOW);
        assert_default_fallback(&report);
        assert_eq!(
            report.legacy_context,
            LegacyContextStatus::LegacyUnspecified
        );
        assert!(
            report
                .notices
                .contains(&BudgetNotice::LegacyContextUnspecified)
        );
    }

    #[test]
    fn resolver_historical_marker_mismatch_does_not_invalidate_selected_or_grant_manual_policy() {
        let mut p = provider("fixture-a", Some(CONTEXT), None);
        let mut sibling = p.models[0].clone();
        sibling.id = "family/manual-sibling".into();
        sibling.context_window = Some(42_000);
        p.models.push(sibling);
        let home = Home::new(vec![p.clone()]);
        let selected: ModelProvenance = serde_json::from_value(record(&p, NOW, NOW)).unwrap();
        let mut marker = record(&p, NOW, NOW);
        marker["model_id"] = json!(p.models[1].id);
        marker["observed"]["id"] = json!(p.models[1].id);
        marker["last_applied_context_window"] = Value::Null;
        marker["manual_input_tokens"] = json!(48_000);
        let marker: ModelProvenance = serde_json::from_value(marker).unwrap();
        save_model_provenance(&home.0, &p, &[selected, marker]).unwrap();
        let before = resolve(&home, &p, NOW);
        assert_eq!(before.budget.source, BudgetSource::Discovered);
        let mut sibling_turn = turn(&p);
        sibling_turn.model = p.models[1].id.clone();
        let unmatched = resolve_turn_budget_detailed(&home.0, &sibling_turn, NOW).unwrap();
        assert_default_fallback(&unmatched);
        assert_eq!(
            unmatched.legacy_context,
            LegacyContextStatus::LegacyUnspecified
        );
        p.models[1].context_window = Some(48_000);
        home.configure(vec![p.clone()]);
        assert_eq!(
            resolve(&home, &p, NOW).budget.identity,
            before.budget.identity
        );
        let matched = resolve_turn_budget_detailed(&home.0, &sibling_turn, NOW).unwrap();
        assert_eq!(matched.budget.source, BudgetSource::Manual);
        assert_eq!(matched.budget.ceilings.input_tokens, Some(48_000));
    }

    #[test]
    fn resolver_expiry_and_future_skew_boundaries_use_guarded_subtraction() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        for (now, fresh) in [
            (NOW, true),
            (NOW + 3600, true),
            (NOW + 3601, false),
            (NOW - 300, true),
            (NOW - 301, false),
        ] {
            let report = resolve(&home, &p, now);
            if fresh {
                assert_eq!(report.budget.source, BudgetSource::Discovered);
            } else {
                assert_default_fallback(&report);
            }
        }
    }

    #[test]
    fn resolver_custom_age_one_and_maximum_are_inclusive() {
        for age in [1, 604800] {
            let p = provider(
                "fixture-a",
                Some(CONTEXT),
                Some(json!({"max_age_seconds":age})),
            );
            let home = Home::new(vec![p.clone()]);
            home.provenance(&p, record(&p, NOW, NOW));
            assert_eq!(
                resolve(&home, &p, NOW + age).budget.source,
                BudgetSource::Discovered
            );
            assert_default_fallback(&resolve(&home, &p, NOW + age + 1));
        }
    }

    #[test]
    fn resolver_u64_future_and_expiry_boundaries_do_not_overflow() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, u64::MAX, u64::MAX));
        assert_default_fallback(&resolve(&home, &p, NOW));
        home.provenance(&p, record(&p, u64::MAX - 3600, u64::MAX - 3600));
        assert_eq!(
            resolve(&home, &p, u64::MAX).budget.source,
            BudgetSource::Discovered
        );
        home.provenance(&p, record(&p, u64::MAX - 3601, u64::MAX - 3601));
        assert_default_fallback(&resolve(&home, &p, u64::MAX));
    }

    #[test]
    fn resolver_stale_output_does_not_ride_fresh_context() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW - 3601));
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.budget.ceilings.input_tokens, Some(CONTEXT));
        assert_eq!(report.budget.ceilings.output_tokens, None);
        assert!(report.components.output.is_none());
        assert!(
            report
                .notices
                .contains(&BudgetNotice::StaleObservation(LimitComponent::Output))
        );
    }

    #[test]
    fn resolver_requested_output_edit_cannot_override_fresh_documented_output_ceiling() {
        let mut p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        p.models[0].max_output_tokens = Some(u32::try_from(OUTPUT + 1).unwrap());
        home.configure(vec![p.clone()]);
        let actual = turn(&p);
        assert_eq!(actual.max_output_tokens, OUTPUT + 1);
        let report = resolve_turn_budget_detailed(&home.0, &actual, NOW).unwrap();
        assert_eq!(report.budget.ceilings.output_tokens, Some(OUTPUT));
        let output = report.components.output.as_ref().unwrap();
        assert_eq!(output.source, BudgetSource::Discovered);
        assert_eq!(output.freshness, Freshness::Fresh);
        assert_eq!(
            assess_request(
                &estimate(
                    &report,
                    10,
                    actual.max_output_tokens,
                    EstimateStatus::Approximate
                ),
                &report.budget
            ),
            BudgetDecision::Refuse
        );
    }

    #[test]
    fn resolver_mixed_fallback_context_and_fresh_output_report_separate_sources() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW - 3601, NOW));
        let report = resolve(&home, &p, NOW);
        assert_default_fallback(&report);
        assert_eq!(
            report.components.combined.as_ref().unwrap().source,
            BudgetSource::Fallback
        );
        assert_eq!(
            report.components.output.as_ref().unwrap().source,
            BudgetSource::Discovered
        );
        assert_eq!(
            report.components.output.as_ref().unwrap().freshness,
            Freshness::Fresh
        );
        assert_eq!(report.budget.ceilings.output_tokens, Some(OUTPUT));
        assert_eq!(
            assess_request(
                &estimate(&report, 10, OUTPUT + 1, EstimateStatus::Approximate),
                &report.budget
            ),
            BudgetDecision::Refuse
        );
    }

    #[test]
    fn resolver_openrouter_advertised_values_are_not_documented_ceilings() {
        let mut p = provider("fixture-a", Some(CONTEXT), None);
        p.kind = "openai-compatible".into();
        let home = Home::new(vec![p.clone()]);
        let mut receipt = record(&p, NOW, NOW);
        receipt["observed"]["source"] = json!("open_router_models");
        for component in ["context_limit", "output_limit"] {
            let evidence = &mut receipt["observed"]["evidence"][component];
            evidence["source"] = json!("open_router_models");
            evidence["schema"] = json!("open_router_models_fields_v1");
            evidence["semantics"] = json!("unspecified");
            evidence["confidence"] = json!("advertised_unspecified");
        }
        home.provenance(&p, receipt);
        let report = resolve(&home, &p, NOW);
        assert_default_fallback(&report);
        assert_eq!(report.budget.ceilings.output_tokens, None);
    }

    #[test]
    fn resolver_v1_ownership_only_cannot_become_fresh_after_save() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        let mut receipt = record(&p, NOW, NOW);
        receipt["schema_version"] = json!(1);
        receipt["observed"]
            .as_object_mut()
            .unwrap()
            .remove("evidence");
        home.provenance(&p, receipt);
        let report = resolve(&home, &p, NOW);
        assert_default_fallback(&report);
        assert_eq!(report.budget.ceilings.output_tokens, None);
    }

    #[test]
    fn resolver_full_query_env_kind_or_provider_change_never_inherits_facts() {
        for change in 0..4 {
            let p = provider("fixture-a", Some(CONTEXT), None);
            let home = Home::new(vec![p.clone()]);
            home.provenance(&p, record(&p, NOW, NOW));
            let old_turn = turn(&p);
            let mut changed = p.clone();
            match change {
                0 => changed.url.push_str("&scope=other"),
                1 => changed.env = Some("ORBIT_LIMITS_OTHER".into()),
                2 => changed.kind = "openai-compatible".into(),
                _ => changed.name = "fixture-b".into(),
            }
            home.configure(vec![changed.clone()]);
            assert!(matches!(
                resolve_turn_budget_detailed(&home.0, &old_turn, NOW),
                Err(BudgetError::InvalidBinding)
            ));
            let report = resolve(&home, &changed, NOW);
            assert_default_fallback(&report);
            assert_eq!(
                report.legacy_context,
                LegacyContextStatus::LegacyUnspecified
            );
        }
    }

    #[test]
    fn resolver_raw_slash_id_is_exact_and_removed_id_is_not_selected() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        let mut changed = p.clone();
        changed.models[0].id = "family/other:stable".into();
        home.configure(vec![changed.clone()]);
        assert!(matches!(
            resolve_turn_budget_detailed(&home.0, &turn(&p), NOW),
            Err(BudgetError::InvalidBinding)
        ));
        assert_default_fallback(&resolve(&home, &changed, NOW));
    }

    #[test]
    fn resolver_identity_changes_for_output_effort_and_policy() {
        let p = provider("fixture-a", None, None);
        let home = Home::new(vec![p.clone()]);
        let base = resolve(&home, &p, NOW).budget.identity;
        let mut selected = turn(&p);
        selected.max_output_tokens += 1;
        assert_ne!(
            resolve_turn_budget(&home.0, &selected, NOW)
                .unwrap()
                .identity
                .binding_digest,
            base.binding_digest
        );
        selected = turn(&p);
        selected.effort = Some(EffortValue::Level("high".into()));
        assert_ne!(
            resolve_turn_budget(&home.0, &selected, NOW)
                .unwrap()
                .identity
                .binding_digest,
            base.binding_digest
        );
        let mut changed = p.clone();
        changed.models[0].context_limits =
            Some(serde_json::from_value(json!({"media_policy":"refuse"})).unwrap());
        home.configure(vec![changed.clone()]);
        assert_ne!(
            resolve(&home, &changed, NOW)
                .budget
                .identity
                .policy_revision,
            base.policy_revision
        );
    }

    #[test]
    fn resolver_same_value_refetch_changes_metadata_revision_but_pure_save_does_not() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        let receipt = record(&p, NOW, NOW);
        home.provenance(&p, receipt.clone());
        let original = resolve(&home, &p, NOW + 1);
        home.provenance(&p, receipt);
        assert_eq!(
            resolve(&home, &p, NOW + 1).budget.identity,
            original.budget.identity
        );
        home.provenance(&p, record(&p, NOW + 1, NOW + 1));
        let renewed = resolve(&home, &p, NOW + 1);
        assert_eq!(renewed.budget.ceilings, original.budget.ceilings);
        assert_ne!(
            renewed.budget.identity.metadata_revision,
            original.budget.identity.metadata_revision
        );
    }

    #[test]
    fn resolver_unrelated_record_update_and_order_do_not_change_selected_revision() {
        let mut p = provider("fixture-a", Some(CONTEXT), None);
        let mut sibling = serde_json::to_value(&p.models[0]).unwrap();
        sibling["id"] = json!("family/sibling:stable");
        p.models.push(serde_json::from_value(sibling).unwrap());
        let home = Home::new(vec![p.clone()]);
        let selected = record(&p, NOW, NOW);
        let mut other = record(&p, NOW, NOW);
        other["model_id"] = json!("family/sibling:stable");
        other["observed"]["id"] = json!("family/sibling:stable");
        let records = vec![
            serde_json::from_value(selected.clone()).unwrap(),
            serde_json::from_value(other.clone()).unwrap(),
        ];
        save_model_provenance(&home.0, &p, &records).unwrap();
        let before = resolve(&home, &p, NOW + 1).budget.identity;
        other["observed"]["evidence"]["context_limit"]["observed_at_unix"] = json!(NOW + 1);
        let records = vec![
            serde_json::from_value(other).unwrap(),
            serde_json::from_value(selected).unwrap(),
        ];
        save_model_provenance(&home.0, &p, &records).unwrap();
        assert_eq!(resolve(&home, &p, NOW + 1).budget.identity, before);
    }

    #[test]
    fn resolver_clock_within_interval_is_stable_but_expiry_changes_policy_revision() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        let initial = resolve(&home, &p, NOW);
        let within = resolve(&home, &p, NOW + 3600);
        let expired = resolve(&home, &p, NOW + 3601);
        assert_eq!(initial.budget.identity, within.budget.identity);
        assert_ne!(
            initial.budget.identity.policy_revision,
            expired.budget.identity.policy_revision
        );
    }

    #[test]
    fn resolver_media_policy_preserves_unknown_media_status() {
        for strict in [false, true] {
            let limits = if strict {
                Some(json!({"media_policy":"refuse"}))
            } else {
                None
            };
            let p = provider("fixture-a", None, limits);
            let home = Home::new(vec![p.clone()]);
            let report = resolve(&home, &p, NOW);
            let request = estimate(&report, 10, OUTPUT, EstimateStatus::UnknownMedia);
            let expected = if strict {
                BudgetDecision::Refuse
            } else {
                BudgetDecision::AdmitUnknownMediaWithWarning
            };
            assert_eq!(assess_request(&request, &report.budget), expected);
            assert_eq!(request.status, EstimateStatus::UnknownMedia);
        }
    }

    #[test]
    fn resolver_malformed_metadata_is_not_treated_as_missing_manual_provenance() {
        let p = provider("fixture-a", Some(CONTEXT), None);
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        let path = home
            .0
            .join("metadata/providers")
            .join(format!("{}.json", binding(&p)));
        private_write(&path, b"{\"schema_version\":2,\"models\":\"malformed\"}");
        assert!(matches!(
            resolve_turn_budget_detailed(&home.0, &turn(&p), NOW),
            Err(BudgetError::InvalidMetadata)
        ));
    }

    #[test]
    fn resolver_invalid_config_uses_safe_typed_error_without_endpoint_echo() {
        let p = provider("fixture-a", None, None);
        let home = Home::new(vec![p.clone()]);
        private_write(&home.0.join("providers.toml"), b"[invalid");
        assert!(matches!(
            resolve_turn_budget_detailed(&home.0, &turn(&p), NOW),
            Err(BudgetError::InvalidConfig)
        ));
        assert!(
            !BudgetError::InvalidConfig
                .to_string()
                .contains("fixture-a.invalid")
        );
    }

    struct NetworkTrap {
        url: String,
        count: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
    }
    impl NetworkTrap {
        fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let hits = count.clone();
            let stopped = stop.clone();
            let join = std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(3);
                loop {
                    if Instant::now() >= end {
                        return Err("network fixture deadline expired before acknowledged stop");
                    }
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            hits.fetch_add(1, Ordering::SeqCst);
                            socket
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            socket
                                .set_write_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            let mut bytes = [0u8; 4096];
                            let _ = socket.read(&mut bytes);
                            let _=socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopped.load(Ordering::SeqCst) {
                                return Ok(());
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err("network fixture accept failed"),
                    }
                }
            });
            Self {
                url: format!("http://{address}/v1?scope=fixture"),
                count,
                stop,
                join: Some(join),
            }
        }
        fn finish(mut self) -> usize {
            self.stop.store(true, Ordering::SeqCst);
            self.join
                .take()
                .expect("live network fixture")
                .join()
                .expect("network fixture thread must not panic")
                .expect("network fixture must acknowledge stop after draining");
            self.count.load(Ordering::SeqCst)
        }
    }
    impl Drop for NetworkTrap {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(join) = self.join.take() {
                let result = join.join();
                if !std::thread::panicking() {
                    result
                        .expect("network fixture thread must not panic")
                        .expect("network fixture must acknowledge stop after draining");
                }
            }
        }
    }

    #[test]
    fn resolver_local_snapshot_has_no_provider_or_auth_store_effects() {
        let trap = NetworkTrap::new();
        let mut p = provider("fixture-a", Some(CONTEXT), None);
        p.url = trap.url.clone();
        let home = Home::new(vec![p.clone()]);
        home.provenance(&p, record(&p, NOW, NOW));
        let poison = b"this is a regular file, not credential storage";
        private_write(&home.0.join("auth"), poison);
        let before = std::fs::read(home.0.join("providers.toml")).unwrap();
        let report = resolve(&home, &p, NOW);
        assert_eq!(report.budget.source, BudgetSource::Discovered);
        assert_eq!(trap.finish(), 0);
        assert_eq!(std::fs::read(home.0.join("auth")).unwrap(), poison);
        assert_eq!(
            std::fs::read(home.0.join("providers.toml")).unwrap(),
            before
        );
        assert!(!home.0.join("ledger").exists());
    }
}

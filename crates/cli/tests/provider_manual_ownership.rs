#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::provider_credentials::ProviderAuthIdentity;
use orbit_cli::config::{ProviderConfig, ProvidersConfig};
use orbit_cli::provider_discovery::{
    DiscoveredModel, MetadataSource, ModelProvenance, PROVENANCE_VERSION, load_model_provenance,
    merge_discovered_model, save_model_provenance,
};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

const RAW: &str = "same/raw";
const AUTO: u64 = 2000;
const MANUAL: u64 = 1500;
const NEXT: u64 = 3000;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-manual-policy-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn publish(&self, provider: &ProviderConfig) {
        ProvidersConfig {
            provider: vec![provider.clone()],
            ..Default::default()
        }
        .save_atomic(&self.0)
        .unwrap();
    }
    fn seed(&self, provider: &ProviderConfig, bytes: &[u8]) {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(self.0.join("metadata"))
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(self.0.join("metadata/providers"))
            .unwrap();
        let path = self
            .0
            .join("metadata/providers")
            .join(format!("{}.json", identity(provider).binding_id()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn provider() -> ProviderConfig {
    serde_json::from_value(json!({
        "name":"fixture", "kind":"anthropic",
        "url":"http://127.0.0.1:9/tenant/v1?scope=manual-policy-fixture",
        "env":null, "models":[{"id":RAW}]
    }))
    .unwrap()
}
fn identity(provider: &ProviderConfig) -> ProviderAuthIdentity {
    ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        &provider.url,
        provider.env.as_deref(),
    )
    .unwrap()
}
fn observed(value: Option<u64>) -> DiscoveredModel {
    serde_json::from_value(json!({
        "id":RAW,"label":null,"context_window":value,"max_output_tokens":null,
        "source":"anthropic_models","metadata_valid":true,"unrecognized_fields":[]
    }))
    .unwrap()
}
fn auto_record(provider: &ProviderConfig) -> ModelProvenance {
    let mut empty = provider.models[0].clone();
    empty.context_window = None;
    merge_discovered_model(&empty, &observed(Some(AUTO)), None, &identity(provider))
        .provenance
        .unwrap()
}
fn marked_json(provider: &ProviderConfig) -> Value {
    let mut record = serde_json::to_value(auto_record(provider)).unwrap();
    record["last_applied_context_window"] = Value::Null;
    record["manual_input_tokens"] = json!(MANUAL);
    record
}
fn marked_record(provider: &ProviderConfig) -> ModelProvenance {
    serde_json::from_value(marked_json(provider)).unwrap()
}
fn document(provider: &ProviderConfig, record: Value, version: u32) -> Value {
    json!({"schema_version":version,"provider_binding":identity(provider).binding_id(),"models":[record]})
}
fn reload(
    home: &Home,
    provider: &ProviderConfig,
    records: &[ModelProvenance],
) -> (ProviderConfig, Vec<ModelProvenance>) {
    home.publish(provider);
    save_model_provenance(&home.0, provider, records).unwrap();
    let provider = ProvidersConfig::load(&home.0).unwrap().provider.remove(0);
    let records = load_model_provenance(&home.0, &provider).unwrap();
    (provider, records)
}
fn assert_marker(record: &ModelProvenance, value: u64) {
    assert_eq!(
        serde_json::to_value(record).unwrap()["manual_input_tokens"],
        value,
        "the exact-bound manual input policy must survive independently of the latest fetched number"
    );
}
fn assert_no_marker(record: &ModelProvenance) {
    assert!(
        serde_json::to_value(record)
            .unwrap()
            .get("manual_input_tokens")
            .is_none_or(Value::is_null)
    );
}

// Predicted semantic RED1: old merge drops the only durable manual-policy proof.
#[test]
fn manual_policy_oldapi_edit_refresh_reload_retains_marker_even_when_new_fact_equals_edit() {
    for next in [NEXT, MANUAL] {
        let home = Home::new();
        let mut provider = provider();
        provider.models[0].context_window = Some(AUTO);
        let receipt = auto_record(&provider);
        let (mut provider, _) = reload(&home, &provider, &[receipt]);
        provider.models[0].context_window = Some(MANUAL);
        home.publish(&provider);
        let before = load_model_provenance(&home.0, &provider).unwrap();
        assert_eq!(before[0].last_applied_context_window, Some(AUTO));
        assert_ne!(
            before[0].last_applied_context_window,
            provider.models[0].context_window
        );
        let merged = merge_discovered_model(
            &provider.models[0],
            &observed(Some(next)),
            Some(&before[0]),
            &identity(&provider),
        );
        assert_eq!(merged.model.context_window, Some(MANUAL));
        provider.models[0] = merged.model;
        let (provider, records) = reload(&home, &provider, &[merged.provenance.unwrap()]);
        assert_eq!(provider.models[0].context_window, Some(MANUAL));
        assert_eq!(records[0].last_applied_context_window, None);
        assert_marker(&records[0], MANUAL);
    }
}

// Predicted semantic RED2: public serde/refresh/save currently drops the marker.
#[test]
fn manual_policy_oldapi_matching_marker_survives_repeated_refresh_and_reload() {
    let home = Home::new();
    let mut provider = provider();
    provider.models[0].context_window = Some(MANUAL);
    let mut record = marked_record(&provider);
    for next in [NEXT, MANUAL, AUTO] {
        let merged = merge_discovered_model(
            &provider.models[0],
            &observed(Some(next)),
            Some(&record),
            &identity(&provider),
        );
        provider.models[0] = merged.model;
        let (restarted, mut records) = reload(&home, &provider, &[merged.provenance.unwrap()]);
        provider = restarted;
        record = records.remove(0);
        assert_eq!(provider.models[0].context_window, Some(MANUAL));
        assert_marker(&record, MANUAL);
    }
}

// Predicted semantic RED3 against frozen Task2: strict v2 does not know this key.
#[test]
fn manual_policy_oldapi_private_v2_marker_load_save_reload_preserves_value() {
    let home = Home::new();
    let mut provider = provider();
    provider.models[0].context_window = Some(MANUAL);
    home.publish(&provider);
    home.seed(
        &provider,
        &serde_json::to_vec(&document(
            &provider,
            marked_json(&provider),
            PROVENANCE_VERSION,
        ))
        .unwrap(),
    );
    let loaded = load_model_provenance(&home.0, &provider);
    assert!(
        loaded.is_ok(),
        "a structurally valid strict-v2 manual-policy carrier must be recognized"
    );
    let loaded = loaded.unwrap();
    assert_eq!(loaded.len(), 1);
    let (_, loaded) = reload(&home, &provider, &loaded);
    assert_marker(&loaded[0], MANUAL);
}

// Predicted semantic RED4: policy retention is independent of missing new facts.
#[test]
fn manual_policy_oldapi_absent_fetched_context_keeps_policy_without_inventing_fact() {
    let provider = provider();
    let mut current = provider.models[0].clone();
    current.context_window = Some(MANUAL);
    let previous = marked_record(&provider);
    let merged = merge_discovered_model(
        &current,
        &observed(None),
        Some(&previous),
        &identity(&provider),
    );
    assert_eq!(merged.model.context_window, Some(MANUAL));
    let record = merged.provenance.unwrap();
    assert_eq!(record.observed.context_window, None);
    assert_eq!(record.last_applied_context_window, None);
    assert_marker(&record, MANUAL);
}

// Predicted semantic RED5: a policy is independent of same-kind source profile.
#[test]
fn manual_policy_oldapi_same_binding_profile_change_keeps_policy_without_retaining_fact() {
    let mut provider = provider();
    provider.kind = "openai-compatible".into();
    provider.models[0].context_window = Some(MANUAL);
    let mut previous = marked_json(&provider);
    previous["observed"]["source"] =
        serde_json::to_value(MetadataSource::OpenRouterModels).unwrap();
    let previous: ModelProvenance = serde_json::from_value(previous).unwrap();
    let mut next = serde_json::to_value(observed(None)).unwrap();
    next["source"] = serde_json::to_value(MetadataSource::GenericOpenAiModels).unwrap();
    let next: DiscoveredModel = serde_json::from_value(next).unwrap();
    let merged = merge_discovered_model(
        &provider.models[0],
        &next,
        Some(&previous),
        &identity(&provider),
    );
    assert_eq!(merged.model.context_window, Some(MANUAL));
    let record = merged.provenance.unwrap();
    assert_eq!(record.observed.context_window, None);
    assert_eq!(record.observed.source, MetadataSource::GenericOpenAiModels);
    assert_marker(&record, MANUAL);
}

#[test]
fn manual_policy_oldapi_ambiguous_absent_or_unmanaged_receipt_never_mints_marker() {
    let provider = provider();
    let mut current = provider.models[0].clone();
    current.context_window = Some(MANUAL);
    let mut unknown = serde_json::to_value(auto_record(&provider)).unwrap();
    unknown["last_applied_context_window"] = Value::Null;
    let unknown: ModelProvenance = serde_json::from_value(unknown).unwrap();
    for previous in [None, Some(&unknown)] {
        for next in [NEXT, MANUAL] {
            let merged = merge_discovered_model(
                &current,
                &observed(Some(next)),
                previous,
                &identity(&provider),
            );
            assert_eq!(merged.model.context_window, Some(MANUAL));
            assert_no_marker(&merged.provenance.unwrap());
        }
    }
}

#[test]
fn manual_policy_oldapi_wrong_query_env_kind_or_raw_id_never_mints_marker() {
    let original = provider();
    let previous = auto_record(&original);
    for variant in 0..4 {
        let mut provider = original.clone();
        let mut previous = previous.clone();
        let mut observation = observed(Some(NEXT));
        match variant {
            0 => provider.url.push_str("&different=1"),
            1 => provider.env = Some("FIXTURE_AUTH_REFERENCE".into()),
            2 => {
                provider.kind = "openai-compatible".into();
                let mut value = serde_json::to_value(&observation).unwrap();
                value["source"] = serde_json::to_value(MetadataSource::OpenRouterModels).unwrap();
                observation = serde_json::from_value(value).unwrap();
            }
            _ => {
                previous.model_id = "other/raw".into();
                previous.observed.id = "other/raw".into();
            }
        }
        provider.models[0].context_window = Some(MANUAL);
        let merged = merge_discovered_model(
            &provider.models[0],
            &observation,
            Some(&previous),
            &identity(&provider),
        );
        assert_eq!(merged.model.context_window, Some(MANUAL));
        assert_no_marker(&merged.provenance.unwrap());
    }
}

#[test]
fn manual_policy_oldapi_changed_or_removed_current_value_never_reuses_marker() {
    let provider = provider();
    let previous = marked_record(&provider);
    for current_value in [Some(1400), None] {
        let mut current = provider.models[0].clone();
        current.context_window = current_value;
        let merged = merge_discovered_model(
            &current,
            &observed(Some(NEXT)),
            Some(&previous),
            &identity(&provider),
        );
        let record = merged.provenance.unwrap();
        assert_eq!(merged.model.context_window, current_value.or(Some(NEXT)));
        assert_eq!(
            record.last_applied_context_window,
            current_value.is_none().then_some(NEXT)
        );
        assert_no_marker(&record);
    }
}

#[test]
fn manual_policy_oldapi_managed_value_still_updates_as_automatic() {
    let provider = provider();
    let previous = auto_record(&provider);
    let mut current = provider.models[0].clone();
    current.context_window = Some(AUTO);
    let merged = merge_discovered_model(
        &current,
        &observed(Some(NEXT)),
        Some(&previous),
        &identity(&provider),
    );
    assert_eq!(merged.model.context_window, Some(NEXT));
    let record = merged.provenance.unwrap();
    assert_eq!(record.last_applied_context_window, Some(NEXT));
    assert_no_marker(&record);
}

#[test]
fn manual_policy_oldapi_equal_typed_override_survives_refresh_and_config_reload() {
    for next in [MANUAL, NEXT] {
        let home = Home::new();
        let mut provider = provider();
        let previous = auto_record(&provider);
        let mut model = serde_json::to_value(&provider.models[0]).unwrap();
        model["context_window"] = json!(MANUAL);
        model["context_limits"] = json!({"input_tokens":next,"unknown_policy":"require-limit"});
        provider.models[0] = serde_json::from_value(model).unwrap();
        let before = serde_json::to_value(&provider.models[0]).unwrap()["context_limits"].clone();
        let merged = merge_discovered_model(
            &provider.models[0],
            &observed(Some(next)),
            Some(&previous),
            &identity(&provider),
        );
        provider.models[0] = merged.model;
        let (provider, _) = reload(&home, &provider, &[merged.provenance.unwrap()]);
        assert_eq!(
            serde_json::to_value(&provider.models[0]).unwrap()["context_limits"],
            before
        );
        assert_eq!(provider.models[0].context_window, Some(MANUAL));
    }
}

#[test]
fn manual_policy_oldapi_strict_codec_rejects_malformed_or_v1_marker() {
    for value in [json!(0), json!(-1), json!("1500"), json!([])] {
        let home = Home::new();
        let mut provider = provider();
        provider.models[0].context_window = Some(MANUAL);
        home.publish(&provider);
        let mut record = marked_json(&provider);
        record["manual_input_tokens"] = value;
        home.seed(
            &provider,
            &serde_json::to_vec(&document(&provider, record, PROVENANCE_VERSION)).unwrap(),
        );
        assert!(load_model_provenance(&home.0, &provider).is_err());
    }
    let home = Home::new();
    let mut provider = provider();
    provider.models[0].context_window = Some(MANUAL);
    home.publish(&provider);
    let mut conflict = marked_json(&provider);
    conflict["last_applied_context_window"] = json!(AUTO);
    home.seed(
        &provider,
        &serde_json::to_vec(&document(&provider, conflict, PROVENANCE_VERSION)).unwrap(),
    );
    assert!(
        load_model_provenance(&home.0, &provider).is_err(),
        "one field cannot claim both automatic and manual ownership"
    );
    let home = Home::new();
    home.publish(&provider);
    let mut record = marked_json(&provider);
    record["schema_version"] = json!(1);
    home.seed(
        &provider,
        &serde_json::to_vec(&document(&provider, record, 1)).unwrap(),
    );
    assert!(
        load_model_provenance(&home.0, &provider).is_err(),
        "v1 cannot assert a new manual-policy marker"
    );
}

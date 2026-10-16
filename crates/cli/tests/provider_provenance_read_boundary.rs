#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::provider_credentials::ProviderAuthIdentity;
use orbit_cli::config::{ModelEntry, ProviderConfig, ProvidersConfig};
use orbit_cli::provider_discovery::{
    MetadataError, ModelProvenance, PROVENANCE_VERSION, load_model_provenance,
    save_model_provenance,
};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const SELECTED: &str = "selected-short-id";
const MANUAL_SIBLING: &str = "manual-short-id";
const INPUT: u64 = 2000;
const MANUAL: u64 = 1500;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orbit-provenance-read-boundary-{}",
            ulid::Ulid::new()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn publish_and_reload(&self, provider: &ProviderConfig) -> ProviderConfig {
        ProvidersConfig {
            provider: vec![provider.clone()],
            ..Default::default()
        }
        .save_atomic(&self.0)
        .unwrap();
        let config = fs::read(self.0.join("providers.toml")).unwrap();
        assert!(config.len() < 128 * 1024);
        ProvidersConfig::load(&self.0).unwrap().provider.remove(0)
    }
    fn sidecar(&self, provider: &ProviderConfig) -> PathBuf {
        self.0
            .join("metadata/providers")
            .join(format!("{}.json", identity(provider).binding_id()))
    }
    fn replace_sidecar(&self, provider: &ProviderConfig, bytes: &[u8]) {
        assert!(
            bytes.len() < 128 * 1024,
            "fixture must exercise the record shape/count, not the byte limit"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(self.sidecar(provider))
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
fn identity(provider: &ProviderConfig) -> ProviderAuthIdentity {
    ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        &provider.url,
        provider.env.as_deref(),
    )
    .unwrap()
}
fn declared(id: &str) -> ModelEntry {
    serde_json::from_value(json!({"id":id})).unwrap()
}
fn provider() -> ProviderConfig {
    serde_json::from_value(json!({
        "name":"fixture", "kind":"anthropic",
        "url":"http://127.0.0.1:9/tenant/v1?scope=read-boundary-fixture",
        "env":null,
        "models":[{"id":SELECTED,"context_window":INPUT}, {"id":MANUAL_SIBLING,"context_window":MANUAL}]
    })).unwrap()
}
fn records(provider: &ProviderConfig) -> Vec<ModelProvenance> {
    // Current wall time is fixture data, never inferred from a save/file mtime.
    // These tests prove exact reader retention, not resolver TTL admission.
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let binding = identity(provider).binding_id();
    let selected: ModelProvenance = serde_json::from_value(json!({
        "schema_version":PROVENANCE_VERSION,"provider_binding":binding,"model_id":SELECTED,
        "observed":{"id":SELECTED,"label":null,"context_window":INPUT,"max_output_tokens":null,
            "source":"anthropic_models","metadata_valid":true,"unrecognized_fields":[],
            "evidence":{"context_limit":{"value":INPUT,"observed_at_unix":observed_at,
                "source":"anthropic_models","schema":"anthropic_models_2023_06_01",
                "semantics":"input_tokens","confidence":"documented_limit"}}},
        "last_applied_context_window":INPUT,"last_applied_max_output_tokens":null,"last_applied_label":null
    })).unwrap();
    let manual: ModelProvenance = serde_json::from_value(json!({
        "schema_version":PROVENANCE_VERSION,"provider_binding":binding,"model_id":MANUAL_SIBLING,
        "observed":{"id":MANUAL_SIBLING,"label":null,"context_window":null,"max_output_tokens":null,
            "source":"anthropic_models","metadata_valid":true,"unrecognized_fields":[]},
        "last_applied_context_window":null,"last_applied_max_output_tokens":null,"last_applied_label":null,
        "manual_input_tokens":MANUAL
    })).unwrap();
    assert_eq!(
        serde_json::to_value(&manual).unwrap()["manual_input_tokens"],
        MANUAL,
        "the sibling record must carry its configured manual input policy"
    );
    vec![selected, manual]
}
fn seeded() -> (Home, ProviderConfig, Vec<ModelProvenance>) {
    let home = Home::new();
    let provider = home.publish_and_reload(&provider());
    let records = records(&provider);
    save_model_provenance(&home.0, &provider, &records).unwrap();
    assert_eq!(load_model_provenance(&home.0, &provider).unwrap(), records);
    (home, provider, records)
}
fn assert_two_exact_records(records: &[ModelProvenance], expected: &[ModelProvenance]) {
    assert_eq!(records, expected);
    assert_eq!(records.len(), 2);
    let selected = serde_json::to_value(&records[0]).unwrap();
    assert_eq!(
        selected["observed"]["evidence"]["context_limit"]["value"],
        INPUT
    );
    assert!(
        selected["observed"]["evidence"]["context_limit"]["observed_at_unix"]
            .as_u64()
            .is_some()
    );
    let sibling = serde_json::to_value(&records[1]).unwrap();
    assert_eq!(sibling["manual_input_tokens"], MANUAL);
    assert!(sibling["observed"]["context_window"].is_null());
    assert!(sibling["observed"]["evidence"].is_null());
}

#[test]
fn provenance_read_oldapi_more_than_128_declared_models_keeps_two_exact_records() {
    let (home, mut provider, expected) = seeded();
    let original_binding = identity(&provider).binding_id();
    let before = fs::read(home.sidecar(&provider)).unwrap();
    for index in 0..127 {
        provider
            .models
            .push(declared(&format!("unobserved-{index:03}")));
    }
    assert_eq!(provider.models.len(), 129);
    let provider = home.publish_and_reload(&provider);
    assert_eq!(provider.models.len(), 129);
    assert_eq!(identity(&provider).binding_id(), original_binding);
    let loaded = load_model_provenance(&home.0, &provider);
    assert!(
        loaded.is_ok(),
        "a valid configured model list cannot discard two bounded exact records: {loaded:?}"
    );
    assert_two_exact_records(&loaded.unwrap(), &expected);
    assert_eq!(fs::read(home.sidecar(&provider)).unwrap(), before);
}

#[test]
fn provenance_read_oldapi_unobserved_configured_512_byte_id_keeps_short_records() {
    let (home, mut provider, expected) = seeded();
    let original_binding = identity(&provider).binding_id();
    let before = fs::read(home.sidecar(&provider)).unwrap();
    let long_id = "x".repeat(512);
    provider.models.push(declared(&long_id));
    let provider = home.publish_and_reload(&provider);
    assert_eq!(provider.models[2].id, long_id);
    assert_eq!(provider.models[2].id.len(), 512);
    assert!(expected.iter().all(|record| record.model_id.len() <= 256));
    assert_eq!(identity(&provider).binding_id(), original_binding);
    let loaded = load_model_provenance(&home.0, &provider);
    assert!(
        loaded.is_ok(),
        "an unobserved valid configured ID cannot invalidate bounded stored IDs: {loaded:?}"
    );
    assert_two_exact_records(&loaded.unwrap(), &expected);
    assert_eq!(fs::read(home.sidecar(&provider)).unwrap(), before);
}

#[test]
fn provenance_read_oldapi_malformed_or_129_stored_records_still_refuse() {
    for oversized in [false, true] {
        let (home, provider, _) = seeded();
        let mut document: Value =
            serde_json::from_slice(&fs::read(home.sidecar(&provider)).unwrap()).unwrap();
        let expected = if oversized {
            let template = document["models"][0].clone();
            document["models"] = Value::Array(
                (0..129)
                    .map(|index| {
                        let mut record = template.clone();
                        let id = format!("stored-{index:03}");
                        record["model_id"] = json!(id);
                        record["observed"]["id"] = json!(id);
                        record
                    })
                    .collect(),
            );
            assert_eq!(
                provider.models.len(),
                2,
                "only stored-record count is oversized"
            );
            MetadataError::LimitExceeded
        } else {
            document["models"][0]["observed"]["evidence"]["context_limit"]["value"] = json!(0);
            MetadataError::InvalidDocument
        };
        let bytes = serde_json::to_vec(&document).unwrap();
        home.replace_sidecar(&provider, &bytes);
        assert_eq!(load_model_provenance(&home.0, &provider), Err(expected));
        assert_eq!(fs::read(home.sidecar(&provider)).unwrap(), bytes);
    }
}

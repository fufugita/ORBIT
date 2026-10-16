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

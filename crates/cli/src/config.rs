//! Multi-provider configuration (`$ORBIT_HOME/providers.toml`).
//!
//! Users declare one or more model providers; the CLI aggregates their models
//! (`orbit models` / `/models`) and resolves a provider at dispatch time.
//!
//! Secret policy: credentials are NEVER stored in this file. A provider
//! references its bearer token by environment variable name (`env = "..."`),
//! resolved at dispatch time and never printed or persisted.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Per-million-token pricing in microcents (DR-09 §8). All optional; a model
/// with no pricing block is billed at 0 µ¢ until the user declares rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Pricing {
    #[serde(default)]
    pub input_per_million_microcents: u64,
    #[serde(default)]
    pub output_per_million_microcents: u64,
    #[serde(default)]
    pub cache_read_per_million_microcents: Option<u64>,
    #[serde(default)]
    pub cache_write_per_million_microcents: Option<u64>,
    #[serde(default)]
    pub reasoning_per_million_microcents: Option<u64>,
    #[serde(default)]
    pub request_flat_microcents: u64,
}

impl From<Pricing> for orbit_adapter::types::CostRates {
    fn from(p: Pricing) -> Self {
        orbit_adapter::types::CostRates {
            input_per_million_microcents: p.input_per_million_microcents,
            output_per_million_microcents: p.output_per_million_microcents,
            cache_read_per_million_microcents: p.cache_read_per_million_microcents,
            cache_write_per_million_microcents: p.cache_write_per_million_microcents,
            reasoning_per_million_microcents: p.reasoning_per_million_microcents,
            request_flat_microcents: p.request_flat_microcents,
        }
    }
}

/// A model declared for a provider (id + optional display label + pricing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub pricing: Pricing,
}

/// One declared provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    /// Adapter kind: `openai-compatible` (the only supported kind today).
    #[serde(default = "default_kind")]
    pub kind: String,
    pub url: String,
    /// Environment variable name holding the bearer token (never the value).
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub models: Vec<ModelEntry>,
}

fn default_kind() -> String {
    "openai-compatible".into()
}

/// The full providers config (a TOML array-of-tables).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProvidersConfig {
    #[serde(default)]
    pub provider: Vec<ProviderConfig>,
}

impl ProvidersConfig {
    /// Load from `$ORBIT_HOME/providers.toml`. Missing file = empty config
    /// (the CLI falls back to the single `ORBIT_GATE_URL`/`ORBIT_MODEL` env
    /// contract). Malformed file = an error surfaced to the user.
    pub fn load(home: &Path) -> Result<Self, String> {
        let path = home.join("providers.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let cfg: ProvidersConfig =
            toml::from_str(&raw).map_err(|e| format!("parse {path:?}: {e}"))?;
        Ok(cfg)
    }

    /// Aggregate every declared model across all providers as (provider, model).
    pub fn all_models(&self) -> Vec<(String, String)> {
        self.provider
            .iter()
            .flat_map(|p| {
                p.models
                    .iter()
                    .map(move |m| (p.name.clone(), m.id.clone()))
            })
            .collect()
    }

    /// Find which provider declares a model id (for `--model` resolution).
    pub fn provider_for_model(&self, model: &str) -> Option<&ProviderConfig> {
        self.provider
            .iter()
            .find(|p| p.models.iter().any(|m| m.id == model))
    }

    /// The pricing block declared for a model id, if any.
    pub fn pricing_for_model(&self, model: &str) -> Option<Pricing> {
        self.provider
            .iter()
            .find_map(|p| p.models.iter().find(|m| m.id == model))
            .map(|m| m.pricing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_toml() -> &'static str {
        r#"
[[provider]]
name = "local"
url = "http://127.0.0.1:8088"
env = "LOCAL_TOKEN"
[[provider.models]]
id = "model-a"
[[provider.models]]
id = "model-b"

[[provider]]
name = "remote"
url = "https://example.invalid"
[[provider.models]]
id = "model-c"
"#
    }

    #[test]
    fn parses_multi_provider_config() {
        let cfg: ProvidersConfig = toml::from_str(sample_toml()).unwrap();
        assert_eq!(cfg.provider.len(), 2);
        assert_eq!(cfg.provider[0].name, "local");
        assert_eq!(cfg.provider[0].models.len(), 2);
        assert_eq!(cfg.provider[1].name, "remote");
        // Default kind applies when omitted.
        assert_eq!(cfg.provider[1].kind, "openai-compatible");
    }

    #[test]
    fn aggregates_all_models() {
        let cfg: ProvidersConfig = toml::from_str(sample_toml()).unwrap();
        let all = cfg.all_models();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&("local".into(), "model-a".into())));
        assert!(all.contains(&("remote".into(), "model-c".into())));
    }

    #[test]
    fn finds_provider_for_model() {
        let cfg: ProvidersConfig = toml::from_str(sample_toml()).unwrap();
        let p = cfg.provider_for_model("model-b").expect("found");
        assert_eq!(p.name, "local");
        assert_eq!(cfg.provider_for_model("nope"), None);
    }

    #[test]
    fn missing_file_is_empty_config() {
        let dir = std::env::temp_dir().join("orbit-config-none");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = ProvidersConfig::load(&dir).unwrap();
        assert!(cfg.provider.is_empty());
        assert!(cfg.all_models().is_empty());
    }

    #[test]
    fn malformed_file_errors() {
        let dir = std::env::temp_dir().join("orbit-config-bad");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("providers.toml"), "not = [valid toml").unwrap();
        assert!(ProvidersConfig::load(&dir).is_err());
    }

    #[test]
    fn parses_pricing_block() {
        let cfg: ProvidersConfig = toml::from_str(
            r#"
[[provider]]
name = "p"
url = "http://127.0.0.1:4001"
[[provider.models]]
id = "m"
[provider.models.pricing]
input_per_million_microcents = 200000
output_per_million_microcents = 600000
"#,
        )
        .unwrap();
        let pricing = cfg.pricing_for_model("m").expect("pricing found");
        assert_eq!(pricing.input_per_million_microcents, 200_000);
        assert_eq!(pricing.output_per_million_microcents, 600_000);
        assert_eq!(pricing.cache_read_per_million_microcents, None);
    }

    #[test]
    fn cost_microcents_math() {
        use orbit_adapter::types::{CostRates, ProviderUsage};
        // $0.20/M input + $0.60/M output: 1000 in + 1000 out → 200 + 600 = 800 µ¢
        let rates = CostRates {
            input_per_million_microcents: 200_000,
            output_per_million_microcents: 600_000,
            cache_read_per_million_microcents: None,
            cache_write_per_million_microcents: None,
            reasoning_per_million_microcents: None,
            request_flat_microcents: 0,
        };
        let usage = ProviderUsage {
            input_tokens: 1000,
            output_tokens: 1000,
            ..Default::default()
        };
        assert_eq!(rates.cost_microcents(&usage), Some(800));
    }
}

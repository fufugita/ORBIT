//! Multi-provider configuration (`$ORBIT_HOME/providers.toml`).
//!
//! Users declare one or more model providers; the CLI aggregates their models
//! (`orbit models` / `/models`) and resolves a provider at dispatch time.
//!
//! Secret policy: credentials are NEVER stored in this file. A provider
//! references its bearer token by environment variable name (`env = "..."`),
//! resolved at dispatch time and never printed or persisted.

use orbit_adapter::types::EffortValue;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Provider credentials belong in an environment reference, never in the URL.
/// Errors deliberately contain neither the input URL nor any query value.
pub fn validate_provider_endpoint(raw: &str) -> Result<url::Url, String> {
    orbit_provider_http::endpoint::validate_provider_url(raw).map_err(str::to_owned)
}

/// Per-million-token pricing in microdollars (DR-09 §8; C5: the unit was
/// mislabeled "microcents" — 200000 means $0.20 per million tokens, and the
/// display path divides by 1e6 to print dollars, which is only correct for
/// microdollars). All optional; a model with no pricing block is billed at
/// $0 until the user declares rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Pricing {
    #[serde(
        default,
        alias = "input_per_million_microcents",
        rename = "input_per_million_microdollars"
    )]
    pub input_per_million_microdollars: u64,
    #[serde(
        default,
        alias = "output_per_million_microcents",
        rename = "output_per_million_microdollars"
    )]
    pub output_per_million_microdollars: u64,
    #[serde(
        default,
        alias = "cache_read_per_million_microcents",
        rename = "cache_read_per_million_microdollars"
    )]
    pub cache_read_per_million_microdollars: Option<u64>,
    #[serde(
        default,
        alias = "cache_write_per_million_microcents",
        rename = "cache_write_per_million_microdollars"
    )]
    pub cache_write_per_million_microdollars: Option<u64>,
    #[serde(
        default,
        alias = "reasoning_per_million_microcents",
        rename = "reasoning_per_million_microdollars"
    )]
    pub reasoning_per_million_microdollars: Option<u64>,
    #[serde(
        default,
        alias = "request_flat_microcents",
        rename = "request_flat_microdollars"
    )]
    pub request_flat_microdollars: u64,
}

impl From<Pricing> for orbit_adapter::types::CostRates {
    fn from(p: Pricing) -> Self {
        orbit_adapter::types::CostRates {
            input_per_million_microcents: p.input_per_million_microdollars,
            output_per_million_microcents: p.output_per_million_microdollars,
            cache_read_per_million_microcents: p.cache_read_per_million_microdollars,
            cache_write_per_million_microcents: p.cache_write_per_million_microdollars,
            reasoning_per_million_microcents: p.reasoning_per_million_microdollars,
            request_flat_microcents: p.request_flat_microdollars,
        }
    }
}

/// Operator-declared context ceilings and policy overrides for one exact model.
/// Absent members keep their existing policy defaults; these are not discovery facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLimitOverrides {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_positive_context_limit"
    )]
    pub input_tokens: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_positive_context_limit"
    )]
    pub combined_tokens: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_positive_context_limit"
    )]
    pub fallback_input_tokens: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_positive_context_limit"
    )]
    pub fallback_combined_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_policy: Option<ContextUnknownPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_policy: Option<ContextMediaPolicy>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_context_max_age"
    )]
    pub max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextUnknownPolicy {
    Fallback,
    RequireLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextMediaPolicy {
    AllowWithWarning,
    Refuse,
}

fn deserialize_positive_context_limit<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<u64>::deserialize(deserializer)?;
    if value == Some(0) {
        return Err(serde::de::Error::custom(
            "context token limits must be positive",
        ));
    }
    Ok(value)
}

fn deserialize_context_max_age<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<u64>::deserialize(deserializer)?;
    if value.is_some_and(|seconds| !(1..=604800).contains(&seconds)) {
        return Err(serde::de::Error::custom(
            "context limit max_age_seconds must be within 1..604800",
        ));
    }
    Ok(value)
}

/// A model declared for a provider (id + optional display label + pricing).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub pricing: Pricing,
    /// Maximum output tokens the model accepts. When absent the harness
    /// uses 32,000 — the old hard 2,048 cap silently truncated long
    /// answers and file writes.
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
    /// Legacy context-window metadata retained in the provider configuration.
    /// Existing callers use it as an input-policy ceiling for auto-compaction;
    /// typed selected budgets take precedence when supplied.
    #[serde(default)]
    pub context_window: Option<u64>,
    /// Explicit context policy for this exact provider/model entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_limits: Option<ContextLimitOverrides>,
    /// Optional sampling override (E8): temperature and top_p. Omitted
    /// by default — current Anthropic models reject temperature with
    /// thinking, and OpenAI reasoning models reject temperature
    /// outright, so sampling is opt-in per model, never ambient.
    #[serde(default)]
    pub sampling: Option<SamplingOverride>,
    /// Operator-declared exact choices. None is unknown; an empty list declares no support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_efforts: Option<Vec<EffortValue>>,
    /// Omitted by default, preserving the provider's existing request behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_effort: Option<EffortValue>,
    /// Per-model response-start deadline in milliseconds (E5). Absent
    /// keeps the harness default (30 s); slow upstreams declare a
    /// larger budget here instead of every request timing out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_byte_timeout_ms: Option<u64>,
    /// Per-model stream-gap deadline in milliseconds (E5). Absent keeps
    /// the harness default (90 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_ms: Option<u64>,
}

impl ModelEntry {
    pub fn validate_effort(&self, kind: orbit_engine::ProviderKind) -> Result<(), String> {
        if let Some(choices) = &self.supported_efforts {
            for (index, value) in choices.iter().enumerate() {
                value.validate()?;
                kind.validate_effort_value(value)?;
                if choices[..index].contains(value) {
                    return Err(format!(
                        "model '{}' has duplicate effort '{value}'",
                        self.id
                    ));
                }
            }
        }
        if let Some(value) = &self.default_effort {
            value.validate()?;
            kind.validate_effort_value(value)?;
            if !self
                .supported_efforts
                .as_ref()
                .is_some_and(|choices| choices.contains(value))
            {
                return Err(format!(
                    "model '{}' default effort '{value}' must be among declared supported_efforts",
                    self.id
                ));
            }
        }
        Ok(())
    }
}

/// Per-model sampling (E8): only what is explicitly set is sent.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SamplingOverride {
    /// Temperature, 0.0–2.0.
    #[serde(default)]
    pub temperature: Option<f64>,
    /// Top-p, 0.0–1.0.
    #[serde(default)]
    pub top_p: Option<f64>,
}

/// One declared provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProvidersConfig {
    #[serde(default)]
    pub provider: Vec<ProviderConfig>,
    /// Task roles (the built-in router). Absent = every role falls back
    /// to the session's own model. See [`RolesConfig`].
    #[serde(default)]
    pub roles: RolesConfig,
    /// Difficulty routing (2026-10-10): hard/easy keyword signals pick
    /// the model per prompt. Absent or without models = routing off.
    #[serde(default)]
    pub routing: RoutingConfig,
}

/// Difficulty routing: `[routing]` in providers.toml. `hard` and `easy`
/// name model specs (bare id across providers, `provider/model` to
/// disambiguate) — the same resolution as roles. Keywords extend the
/// built-in defaults; `[routing.keywords] clear = true` replaces them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Model for hard turns ("" = that phase keeps the session model).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hard: String,
    /// Model for easy turns.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub easy: String,
    #[serde(default)]
    pub keywords: RoutingKeywords,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub phases: std::collections::BTreeMap<
        orbit_engine::routing::TaskPhase,
        crate::phase_routing::PhaseTargets,
    >,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_keywords: Option<crate::phase_routing::PhaseKeywords>,
}

/// Keyword lists. Entries are matched case-insensitively on word
/// boundaries; a multi-word entry matches its words adjacently.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RoutingKeywords {
    /// Drop the built-in defaults before applying these.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub clear: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hard: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub easy: Vec<String>,
}

/// Task roles: which model serves each kind of work. This is ORBIT's
/// routing surface — deliberately task-based, not per-prompt. Caches
/// and thinking blocks belong to one model, so switching the main
/// conversation mid-thread costs an uncached turn and drops replayed
/// thinking; routing the *task* (a subagent, a summary) keeps the main
/// conversation on one model (roadmap §Providers).
///
/// Each value is a model id (resolved across every provider) or a
/// `provider/model` pair when the same id is declared twice.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolesConfig {
    /// The main conversation's model. Used when no `--model`/`ORBIT_MODEL`
    /// was given.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub main: String,
    /// Task-tool subagents (the general-purpose path).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subagent: String,
    /// Read-only Explore/Plan subagents and other cheap research.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub explore: String,
    /// Auto-compaction summaries.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compaction: String,
}

impl RolesConfig {
    /// Every declared role as (role name, model spec).
    pub fn entries(&self) -> Vec<(&'static str, &str)> {
        vec![
            ("main", self.main.as_str()),
            ("subagent", self.subagent.as_str()),
            ("explore", self.explore.as_str()),
            ("compaction", self.compaction.as_str()),
        ]
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect()
    }

    /// The declared spec for one role, if set.
    pub fn get(&self, role: &str) -> Option<&str> {
        let v = match role {
            "main" => &self.main,
            "subagent" => &self.subagent,
            "explore" => &self.explore,
            "compaction" => &self.compaction,
            _ => return None,
        };
        (!v.is_empty()).then_some(v.as_str())
    }
}

/// The ONE ORBIT-home resolver (C8): `--home` flag > `ORBIT_HOME` env >
/// `~/.orbit` (when it exists) > a repo-local `.orbit` (only when it
/// already exists — a fresh checkout must not shadow the user config) >
/// `~/.orbit` as the creation default. Every crate and every path through
/// the CLI resolves the home through this function; the old second
/// resolver in tools.rs defaulted to a CWD-relative `.orbit` and silently
/// disagreed with the rest of ORBIT.
pub fn resolve_home(args: &[String]) -> std::path::PathBuf {
    if let Some(h) = args
        .windows(2)
        .find(|w| w[0] == "--home")
        .map(|w| w[1].clone())
    {
        return std::path::PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("ORBIT_HOME")
        && !h.is_empty()
    {
        return std::path::PathBuf::from(h);
    }
    let user = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".orbit"));
    if let Some(u) = &user
        && u.exists()
    {
        return u.clone();
    }
    let local = std::path::PathBuf::from(".orbit");
    if local.exists() {
        return local;
    }
    user.unwrap_or(local)
}

impl ProvidersConfig {
    /// Load from `$ORBIT_HOME/providers.toml`. Missing file = empty config
    /// (the CLI falls back to the single `ORBIT_GATE_URL`/`ORBIT_MODEL` env
    /// contract). Malformed file = an error surfaced to the user.
    pub fn load(home: &Path) -> Result<Self, String> {
        let path = home.join("providers.toml");
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.kind().to_string()),
            Ok(_) => {}
        }
        let directory =
            crate::customization::Directory::open(home, false).map_err(|e| e.to_string())?;
        let bytes = crate::customization::read_regular(
            &directory
                .io()
                .map_err(|e| e.to_string())?
                .join("providers.toml"),
            128 * 1024,
            false,
        )
        .map_err(|e| e.to_string())?;
        let raw =
            std::str::from_utf8(&bytes).map_err(|_| "providers configuration must be UTF-8")?;
        let config = Self::load_from_str(raw)?;
        directory.check().map_err(|e| e.to_string())?;
        Ok(config)
    }

    /// Parse a config from raw TOML (tests and tooling; `load` reads the
    /// home's file).
    pub fn load_from_str(raw: &str) -> Result<Self, String> {
        if raw.len() > 128 * 1024 {
            return Err("providers configuration exceeds 128 KiB".into());
        }
        let cfg: Self = toml::from_str(raw).map_err(|e| format!("parse providers: {e}"))?;
        cfg.validate_efforts()?;
        crate::phase_routing::parse_settings(raw)?;
        Ok(cfg)
    }

    pub fn phase_settings(&self) -> crate::phase_routing::PhaseRoutingConfig {
        crate::phase_routing::PhaseRoutingConfig {
            phases: self.routing.phases.clone(),
            phase_keywords: self.routing.phase_keywords.clone(),
        }
    }

    /// Mutate the current complete document while holding the shared config lock.
    pub fn update_atomic(
        home: &Path,
        update: impl FnOnce(&str) -> Result<String, String>,
    ) -> Result<Self, String> {
        use crate::customization::{Directory, Lock, publish, read_regular};
        let directory = Directory::open(home, true).map_err(|e| e.to_string())?;
        let _lock = Lock::acquire(&directory, ".config.lock").map_err(|e| e.to_string())?;
        let path = directory
            .io()
            .map_err(|e| e.to_string())?
            .join("providers.toml");
        let bytes = match std::fs::symlink_metadata(&path) {
            Ok(_) => read_regular(&path, 128 * 1024, false).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.kind().to_string()),
        };
        let raw =
            std::str::from_utf8(&bytes).map_err(|_| "providers configuration must be UTF-8")?;
        let candidate = update(raw)?;
        let config = Self::load_from_str(&candidate)?;
        crate::phase_routing::validate_settings(&config, &config.phase_settings())?;
        if candidate.as_bytes() != bytes {
            publish(&directory, "providers.toml", candidate.as_bytes(), false)
                .map_err(|e| e.to_string())?;
        }
        Ok(config)
    }

    pub fn validate_efforts(&self) -> Result<(), String> {
        for provider in &self.provider {
            for model in &provider.models {
                for (field, value) in [
                    ("first_byte_timeout_ms", model.first_byte_timeout_ms),
                    ("idle_timeout_ms", model.idle_timeout_ms),
                ] {
                    if value == Some(0) {
                        return Err(format!(
                            "provider '{}' model '{}': {field} must be positive",
                            provider.name, model.id
                        ));
                    }
                }
                model
                    .validate_effort(orbit_engine::ProviderKind::from_config(&provider.kind))
                    .map_err(|error| format!("provider '{}': {error}", provider.name))?;
            }
        }
        Ok(())
    }

    /// Resolve metadata against the actual owning provider, including duplicate model IDs.
    pub fn model_entry(
        &self,
        provider_id: &str,
        model: &str,
    ) -> Option<(&ProviderConfig, &ModelEntry)> {
        self.provider
            .iter()
            .find(|p| p.name == provider_id)
            .and_then(|p| p.models.iter().find(|m| m.id == model).map(|m| (p, m)))
    }

    /// Aggregate every declared model across all providers as (provider, model).
    pub fn all_models(&self) -> Vec<(String, String)> {
        self.provider
            .iter()
            .flat_map(|p| p.models.iter().map(move |m| (p.name.clone(), m.id.clone())))
            .collect()
    }

    /// Find which provider declares a model id (for `--model` resolution).
    pub fn provider_for_model(&self, model: &str) -> Option<&ProviderConfig> {
        self.provider
            .iter()
            .find(|p| p.models.iter().any(|m| m.id == model))
    }

    /// Resolve one role's spec to its owning provider. A bare model id
    /// searches every provider; `provider/model` names its provider
    /// directly (for the same id declared twice). None = the role is not
    /// configured, or names nothing that exists.
    pub fn provider_for_role_spec(&self, spec: &str) -> Option<&ProviderConfig> {
        self.model_entry_for_spec(spec)
            .map(|(provider, _)| provider)
    }

    /// Prefer an exact declared provider/model pair, then the full bare model ID.
    /// A slash inside the actual ID is never discarded during metadata lookup.
    pub fn model_entry_for_spec(&self, spec: &str) -> Option<(&ProviderConfig, &ModelEntry)> {
        if let Some((provider, model)) = spec.split_once('/')
            && let Some(pair) = self.model_entry(provider, model)
        {
            return Some(pair);
        }
        self.provider.iter().find_map(|provider| {
            provider
                .models
                .iter()
                .find(|entry| entry.id == spec)
                .map(|entry| (provider, entry))
        })
    }

    /// The declared max output tokens for a model id, if any.
    pub fn context_window_for(&self, model: &str) -> Option<u64> {
        self.provider
            .iter()
            .find_map(|p| p.models.iter().find(|m| m.id == model))
            .and_then(|m| m.context_window)
    }

    /// The sampling block declared for a model id (E8), if any.
    pub fn sampling_for(&self, model: &str) -> Option<SamplingOverride> {
        self.provider
            .iter()
            .find_map(|p| p.models.iter().find(|m| m.id == model))
            .and_then(|m| m.sampling.clone())
    }

    pub fn max_output_tokens_for(&self, model: &str) -> Option<u32> {
        self.provider
            .iter()
            .find_map(|p| p.models.iter().find(|m| m.id == model))
            .and_then(|m| m.max_output_tokens)
    }

    /// The pricing block declared for a model id, if any.
    pub fn pricing_for_model(&self, model: &str) -> Option<Pricing> {
        self.provider
            .iter()
            .find_map(|p| p.models.iter().find(|m| m.id == model))
            .map(|m| m.pricing)
    }

    /// Append a provider, refusing a duplicate name. Returns an error string
    /// on collision so callers can surface it without partial writes.
    pub fn add_provider(&mut self, p: ProviderConfig) -> Result<(), String> {
        if self.provider.iter().any(|x| x.name == p.name) {
            return Err(format!("provider '{}' already configured", p.name));
        }
        for model in &p.models {
            model.validate_effort(orbit_engine::ProviderKind::from_config(&p.kind))?;
        }
        self.provider.push(p);
        Ok(())
    }

    /// Set one role's model spec. An empty value clears the role.
    /// A spec that names no configured model is refused — a role that
    /// silently falls through to another model is a surprise, not a
    /// convenience.
    /// Set one routing target (`hard` / `easy`); empty clears it. The
    /// spec must name a configured model — the same refusal as roles.
    pub fn set_routing_target(&mut self, phase: &str, spec: &str) -> Result<(), String> {
        if !spec.is_empty() && self.provider_for_role_spec(spec).is_none() {
            return Err(format!(
                "routing '{phase}' names model '{spec}' which no provider declares"
            ));
        }
        let slot = match phase {
            "hard" => &mut self.routing.hard,
            "easy" => &mut self.routing.easy,
            other => return Err(format!("unknown routing phase '{other}' (hard, easy)")),
        };
        *slot = spec.to_string();
        Ok(())
    }

    /// Resolve the configured routing into the engine's table: targets
    /// plus merged keyword lists (defaults + user extensions, unless
    /// `clear = true`). Returns a table even when disabled, so
    /// `orbit route test` can classify against the keywords alone.
    pub fn routing_table(&self) -> orbit_engine::routing::RoutingTable {
        use orbit_engine::routing as r;
        let kw = &self.routing.keywords;
        let merge = |defaults: Vec<String>, extra: &[String]| -> Vec<String> {
            let mut list = if kw.clear { Vec::new() } else { defaults };
            for k in extra {
                let k = k.trim().to_lowercase();
                if !k.is_empty() && !list.iter().any(|x| x == &k) {
                    list.push(k);
                }
            }
            list
        };
        r::RoutingTable {
            hard: self.routing.hard.clone(),
            easy: self.routing.easy.clone(),
            hard_keywords: merge(r::default_hard_keywords(), &kw.hard),
            easy_keywords: merge(r::default_easy_keywords(), &kw.easy),
        }
    }

    pub fn set_role(&mut self, role: &str, spec: &str) -> Result<(), String> {
        if !spec.is_empty() && self.provider_for_role_spec(spec).is_none() {
            return Err(format!(
                "role '{role}' names model '{spec}' which no provider declares"
            ));
        }
        let slot = match role {
            "main" => &mut self.roles.main,
            "subagent" => &mut self.roles.subagent,
            "explore" => &mut self.roles.explore,
            "compaction" => &mut self.roles.compaction,
            other => return Err(format!("unknown role '{other}'")),
        };
        *slot = spec.to_string();
        Ok(())
    }

    /// Validate before writing, then publish under the shared configuration lock.
    /// Missing home components are created privately; existing unsafe storage
    /// is refused. Provider files are published atomically with mode 0600.
    pub fn save_atomic(&self, home: &Path) -> Result<(), String> {
        use crate::customization::{Directory, Lock, publish, read_regular};

        fn private_home(home: &Path) -> Result<Directory, String> {
            use std::path::Component;
            let path = if home.is_absolute() {
                home.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|error| error.to_string())?
                    .join(home)
            };
            if path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            {
                return Err("provider home must use normal path components".into());
            }
            let mut ancestor = path.clone();
            let mut missing = Vec::new();
            loop {
                match std::fs::symlink_metadata(&ancestor) {
                    Ok(_) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        let name = ancestor
                            .file_name()
                            .ok_or("provider home has no existing ancestor")?
                            .to_os_string();
                        missing.push(name);
                        if !ancestor.pop() {
                            return Err("provider home has no existing ancestor".into());
                        }
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            if missing.is_empty() {
                return Directory::open(&path, true).map_err(|error| error.to_string());
            }
            let mut parent =
                Directory::open(&ancestor, false).map_err(|error| error.to_string())?;
            for name in missing.into_iter().rev() {
                parent.check().map_err(|error| error.to_string())?;
                let child = Directory::create(&parent.path().join(name))
                    .map_err(|error| error.to_string())?;
                parent.check().map_err(|error| error.to_string())?;
                parent = child;
            }
            parent.check().map_err(|error| error.to_string())?;
            Ok(parent)
        }

        self.validate_efforts()?;
        let serialized = toml::to_string(self).map_err(|e| format!("serialize providers: {e}"))?;
        if serialized.len() > 128 * 1024 {
            return Err("providers configuration exceeds 128 KiB".into());
        }
        let back: ProvidersConfig =
            toml::from_str(&serialized).map_err(|e| format!("validate roundtrip: {e}"))?;
        if back.provider.len() != self.provider.len() {
            return Err("roundtrip provider count mismatch".into());
        }
        let directory = private_home(home)?;
        let _lock = Lock::acquire(&directory, ".config.lock").map_err(|error| error.to_string())?;
        let path = directory
            .io()
            .map_err(|error| error.to_string())?
            .join("providers.toml");
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                read_regular(&path, 128 * 1024, true).map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        publish(&directory, "providers.toml", serialized.as_bytes(), false)
            .map_err(|error| error.to_string())
    }

    /// The config path for a home dir.
    #[allow(dead_code)] // exposed for tooling and tests
    pub fn config_path(home: &Path) -> std::path::PathBuf {
        home.join("providers.toml")
    }
}

/// Parsed OpenAI-compatible `/v1/models` response: `{data:[{id:"..."}]}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ModelListResponse {
    pub data: Vec<ModelListItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ModelListItem {
    pub id: String,
}

impl ModelListResponse {
    /// Parse a raw `/v1/models` body; missing/empty data is an error so
    /// callers can fall back to manual model entry.
    pub fn parse(raw: &str) -> Result<Vec<String>, String> {
        let parsed: ModelListResponse =
            serde_json::from_str(raw).map_err(|e| format!("parse models response: {e}"))?;
        let ids: Vec<String> = parsed.data.into_iter().map(|m| m.id).collect();
        if ids.is_empty() {
            return Err("models response contained no data".into());
        }
        Ok(ids)
    }
}

/// Parsed Ollama `/api/tags` response: `{models:[{name:"..."}]}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct OllamaTagsResponse {
    pub models: Vec<OllamaTagsItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct OllamaTagsItem {
    pub name: String,
}

impl OllamaTagsResponse {
    /// Parse a raw `/api/tags` body; missing/empty models is an error so
    /// callers can fall back to manual model entry.
    pub fn parse(raw: &str) -> Result<Vec<String>, String> {
        let parsed: OllamaTagsResponse =
            serde_json::from_str(raw).map_err(|e| format!("parse tags response: {e}"))?;
        let ids: Vec<String> = parsed.models.into_iter().map(|m| m.name).collect();
        if ids.is_empty() {
            return Err("tags response contained no models".into());
        }
        Ok(ids)
    }
}

/// The per-model limits an Anthropic `/v1/models/{id}` detail body
/// carries, mapped to the config's own fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnthropicModelLimits {
    pub context_window: Option<u64>,
    pub max_output_tokens: Option<u32>,
}

/// Parse an Anthropic `/v1/models/{id}` body for its limits. Unknown
/// shapes return the empty struct — a detail fetch is best-effort and
/// never blocks model selection.
pub fn parse_anthropic_model_detail(raw: &str) -> AnthropicModelLimits {
    let parsed: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return AnthropicModelLimits::default(),
    };
    AnthropicModelLimits {
        context_window: parsed.pointer("/max_input_tokens").and_then(|v| v.as_u64()),
        max_output_tokens: parsed
            .pointer("/max_tokens")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok()),
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
input_per_million_microdollars = 200000
output_per_million_microdollars = 600000
"#,
        )
        .unwrap();
        let pricing = cfg.pricing_for_model("m").expect("pricing found");
        assert_eq!(pricing.input_per_million_microdollars, 200_000);
        assert_eq!(pricing.output_per_million_microdollars, 600_000);
        assert_eq!(pricing.cache_read_per_million_microdollars, None);
    }

    /// C5: the old (mislabeled) key names still parse — existing
    /// providers.toml files keep working.
    #[test]
    fn parses_pricing_block_legacy_microcents_keys() {
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
        assert_eq!(pricing.input_per_million_microdollars, 200_000);
        assert_eq!(pricing.output_per_million_microdollars, 600_000);
    }

    #[test]
    fn cost_microcents_math() {
        use orbit_adapter::types::{CostRates, ProviderUsage};
        // $0.20/M input + $0.60/M output: 1000 in + 1000 out → 200 + 600 = 800 µ$.
        // (The accumulator field keeps its historical name cost_microcents;
        // the unit is microdollars — C5.)
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

    #[test]
    fn add_provider_refuses_duplicate() {
        let mut cfg = ProvidersConfig::default();
        cfg.add_provider(ProviderConfig {
            name: "a".into(),
            kind: "openai-compatible".into(),
            url: "http://127.0.0.1:4001".into(),
            env: None,
            models: vec![],
        })
        .unwrap();
        let dup = cfg.add_provider(ProviderConfig {
            name: "a".into(),
            kind: "openai-compatible".into(),
            url: "http://other".into(),
            env: None,
            models: vec![],
        });
        assert!(dup.is_err());
    }

    #[test]
    fn save_atomic_roundtrips_and_preserves() {
        let home = std::env::temp_dir().join("orbit-config-save");
        let _ = std::fs::remove_dir_all(&home);
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&home).unwrap();
        let mut cfg = ProvidersConfig::default();
        cfg.add_provider(ProviderConfig {
            name: "local".into(),
            kind: "openai-compatible".into(),
            url: "http://127.0.0.1:4001".into(),
            env: Some("ORBIT_GATE_TOKEN".into()),
            models: vec![ModelEntry {
                context_limits: None,
                supported_efforts: None,
                default_effort: None,
                first_byte_timeout_ms: None,
                idle_timeout_ms: None,
                sampling: None,
                id: "fixture-model".into(),
                label: None,
                pricing: Pricing {
                    input_per_million_microdollars: 200_000,
                    output_per_million_microdollars: 600_000,
                    ..Default::default()
                },
                max_output_tokens: None,
                context_window: None,
            }],
        })
        .unwrap();
        cfg.save_atomic(&home).unwrap();
        let loaded = ProvidersConfig::load(&home).unwrap();
        assert_eq!(loaded.provider.len(), 1);
        assert_eq!(loaded.provider[0].name, "local");
        assert_eq!(
            loaded.provider[0].models[0]
                .pricing
                .output_per_million_microdollars,
            600_000
        );
        // Token VALUE never stored; only the env-var NAME is present.
        let raw = std::fs::read_to_string(ProvidersConfig::config_path(&home)).unwrap();
        assert!(raw.contains("ORBIT_GATE_TOKEN"));
        assert!(!raw.to_lowercase().contains("sk-"));
    }

    #[test]
    fn parses_models_response() {
        let raw = r#"{"data":[{"id":"fixture-model"},{"id":"kimi-k2.7"}]}"#;
        let ids = ModelListResponse::parse(raw).unwrap();
        assert_eq!(
            ids,
            vec!["fixture-model".to_string(), "kimi-k2.7".to_string()]
        );
        assert!(ModelListResponse::parse(r#"{"data":[]}"#).is_err());
    }

    #[test]
    fn parses_ollama_tags_response() {
        let raw = r#"{"models":[{"name":"qwen3.5:9b"},{"name":"llama4:8b"}]}"#;
        let ids = OllamaTagsResponse::parse(raw).unwrap();
        assert_eq!(ids, vec!["qwen3.5:9b".to_string(), "llama4:8b".to_string()]);
        assert!(OllamaTagsResponse::parse(r#"{"models":[]}"#).is_err());
        assert!(OllamaTagsResponse::parse("not json").is_err());
    }

    #[test]
    fn parses_anthropic_model_detail_limits() {
        let raw = r#"{"id":"claude-opus-5-5","max_input_tokens":200000,"max_tokens":64000}"#;
        let limits = parse_anthropic_model_detail(raw);
        assert_eq!(limits.context_window, Some(200_000));
        assert_eq!(limits.max_output_tokens, Some(64_000));
        // Unknown/absent shapes stay empty, never fail.
        let none = parse_anthropic_model_detail(r#"{"id":"x"}"#);
        assert_eq!(none, AnthropicModelLimits::default());
        assert_eq!(
            parse_anthropic_model_detail("garbage"),
            AnthropicModelLimits::default()
        );
    }

    fn roles_cfg() -> ProvidersConfig {
        let raw = r#"
[[provider]]
name = "anthropic"
url = "https://api.anthropic.com"
kind = "anthropic"
[[provider.models]]
id = "claude-opus-5-5"
[[provider.models]]
id = "claude-haiku-4-5"
[[provider]]
name = "local"
url = "http://127.0.0.1:11434"
kind = "ollama"
[[provider.models]]
id = "claude-haiku-4-5"

[roles]
main = "claude-opus-5-5"
explore = "local/claude-haiku-4-5"
"#;
        ProvidersConfig::load_from_str(raw).unwrap()
    }

    #[test]
    fn roles_parse_and_resolve() {
        let cfg = roles_cfg();
        assert_eq!(cfg.roles.main, "claude-opus-5-5");
        assert_eq!(cfg.roles.explore, "local/claude-haiku-4-5");
        // Bare id finds its (first) owner.
        let owner = cfg.provider_for_role_spec("claude-opus-5-5").unwrap();
        assert_eq!(owner.name, "anthropic");
        // provider/model disambiguates a duplicated id.
        let local = cfg
            .provider_for_role_spec("local/claude-haiku-4-5")
            .unwrap();
        assert_eq!(local.kind, "ollama");
        assert!(cfg.provider_for_role_spec("no-such-model").is_none());
    }

    #[test]
    fn set_role_rejects_unknown_models_and_roles() {
        let mut cfg = roles_cfg();
        assert!(cfg.set_role("main", "ghost-model").is_err());
        assert!(cfg.set_role("warmonger", "claude-opus-5-5").is_err());
        // Clearing is allowed.
        assert!(cfg.set_role("explore", "").is_ok());
        assert!(cfg.roles.explore.is_empty());
    }

    #[test]
    fn roles_survive_the_save_roundtrip() {
        let home = std::env::temp_dir().join(format!("orbit-roles-{}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&home).unwrap();
        let mut cfg = roles_cfg();
        cfg.set_role("subagent", "claude-opus-5-5").unwrap();
        cfg.save_atomic(&home).unwrap();
        let back = ProvidersConfig::load(&home).unwrap();
        assert_eq!(back.roles.subagent, "claude-opus-5-5");
        assert_eq!(back.roles.explore, "local/claude-haiku-4-5");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn providers_without_roles_section_load_clean() {
        let raw = r#"
[[provider]]
name = "solo"
url = "http://127.0.0.1:4001"
[[provider.models]]
id = "m1"
"#;
        let cfg = ProvidersConfig::load_from_str(raw).unwrap();
        assert!(cfg.roles.entries().is_empty());
    }
}

#[cfg(test)]
mod model_timeout_tests {
    use super::*;

    const BASE: &str = "[[provider]]\nname='configured-provider'\nurl='https://example.test'\n[[provider.models]]\nid='configured-model'\n";

    struct Home(std::path::PathBuf);

    impl Home {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("orbit-model-timeouts-{}", ulid::Ulid::new())))
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            if self.0.exists() {
                std::fs::remove_dir_all(&self.0).expect("remove owned config home");
            }
        }
    }

    #[test]
    fn zero_model_timeouts_are_rejected_with_provider_and_model() {
        for field in ["first_byte_timeout_ms", "idle_timeout_ms"] {
            let error = ProvidersConfig::load_from_str(&format!("{BASE}{field}=0\n"))
                .expect_err("zero timeout must fail at config load");
            for expected in ["configured-provider", "configured-model", field, "positive"] {
                assert!(error.contains(expected), "missing {expected}: {error}");
            }
        }
    }

    #[test]
    fn invalid_timeout_save_keeps_existing_file_and_creates_no_partial_file() {
        let home = Home::new();
        let cfg = ProvidersConfig::load_from_str(BASE).unwrap();
        cfg.save_atomic(&home.0).unwrap();
        let original = std::fs::read(home.0.join("providers.toml")).unwrap();
        for field in ["first_byte_timeout_ms", "idle_timeout_ms"] {
            let mut invalid = cfg.clone();
            if field == "first_byte_timeout_ms" {
                invalid.provider[0].models[0].first_byte_timeout_ms = Some(0);
            } else {
                invalid.provider[0].models[0].idle_timeout_ms = Some(0);
            }
            let error = invalid.save_atomic(&home.0).unwrap_err();
            assert!(error.contains(field));
            assert!(error.contains("configured-provider"));
            assert!(error.contains("configured-model"));
            assert_eq!(
                std::fs::read(home.0.join("providers.toml")).unwrap(),
                original
            );
            assert!(!home.0.join(".providers.toml.tmp").exists());
            let missing_home = Home::new();
            assert!(invalid.save_atomic(&missing_home.0).is_err());
            assert!(
                !missing_home.0.exists(),
                "invalid save must perform no writes"
            );
        }
    }

    #[test]
    fn absent_and_large_positive_timeouts_roundtrip() {
        for suffix in [
            String::new(),
            format!(
                "first_byte_timeout_ms={}\nidle_timeout_ms={}\n",
                i64::MAX,
                i64::MAX - 1
            ),
        ] {
            let cfg = ProvidersConfig::load_from_str(&format!("{BASE}{suffix}")).unwrap();
            let model = &cfg.provider[0].models[0];
            if suffix.is_empty() {
                assert_eq!(model.first_byte_timeout_ms, None);
                assert_eq!(model.idle_timeout_ms, None);
            } else {
                assert_eq!(model.first_byte_timeout_ms, Some(i64::MAX as u64));
                assert_eq!(model.idle_timeout_ms, Some((i64::MAX - 1) as u64));
            }
            let home = Home::new();
            cfg.save_atomic(&home.0).unwrap();
            assert_eq!(ProvidersConfig::load(&home.0).unwrap(), cfg);
        }
    }

    #[test]
    fn zero_timeout_update_preserves_the_existing_document() {
        let home = Home::new();
        ProvidersConfig::load_from_str(BASE)
            .unwrap()
            .save_atomic(&home.0)
            .unwrap();
        let original = std::fs::read(home.0.join("providers.toml")).unwrap();
        for field in ["first_byte_timeout_ms", "idle_timeout_ms"] {
            let error =
                ProvidersConfig::update_atomic(&home.0, |_| Ok(format!("{BASE}{field}=0\n")))
                    .unwrap_err();
            assert!(error.contains(field));
            assert_eq!(
                std::fs::read(home.0.join("providers.toml")).unwrap(),
                original
            );
        }
    }
}

#[cfg(test)]
mod effort_metadata_tests {
    use super::*;
    use orbit_adapter::types::EffortValue;

    #[test]
    fn legacy_capabilities_stay_unknown_and_typed_choices_roundtrip() {
        let legacy = ProvidersConfig::load_from_str("[[provider]]\nname='p'\nurl='https://example.test'\n[[provider.models]]\nid='legacy'\n").unwrap();
        assert_eq!(legacy.provider[0].models[0].supported_efforts, None);
        assert_eq!(legacy.provider[0].models[0].default_effort, None);
        let raw = "[[provider]]\nname='p'\nkind='ollama'\nurl='https://example.test'\n[[provider.models]]\nid='typed'\nsupported_efforts=[false,'false','high']\ndefault_effort=false\ncontext_window=4096\n[provider.models.sampling]\ntemperature=0.5\n[roles]\nmain='p/typed'\n";
        let cfg = ProvidersConfig::load_from_str(raw).unwrap();
        let values = cfg.provider[0].models[0]
            .supported_efforts
            .as_ref()
            .unwrap();
        assert_eq!(values[0], EffortValue::Bool(false));
        assert_eq!(values[1], EffortValue::Level("false".into()));
        let home = std::env::temp_dir().join(format!("orbit-effort-config-{}", ulid::Ulid::new()));
        cfg.save_atomic(&home).unwrap();
        assert_eq!(ProvidersConfig::load(&home).unwrap(), cfg);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn malformed_duplicates_and_unverified_defaults_are_rejected() {
        let base =
            "[[provider]]\nname='p'\nurl='https://example.test'\n[[provider.models]]\nid='m'\n";
        for suffix in [
            "supported_efforts=['high','high']\n",
            "supported_efforts=[' high']\n",
            "supported_efforts=['default']\n",
            "supported_efforts=[true]\n",
            "default_effort='high'\n",
            "supported_efforts=[]\ndefault_effort='high'\n",
            "supported_efforts=['low']\ndefault_effort='high'\n",
        ] {
            assert!(
                ProvidersConfig::load_from_str(&format!("{base}{suffix}")).is_err(),
                "{suffix}"
            );
        }
        assert!(ProvidersConfig::load_from_str(&format!("{base}supported_efforts=[]\n")).is_ok());
    }

    #[test]
    fn failed_save_keeps_the_prior_configuration_intact() {
        let mut cfg = ProvidersConfig::load_from_str(
            "[[provider]]\nname='p'\nurl='https://example.test'\n[[provider.models]]\nid='m'\n",
        )
        .unwrap();
        let home = std::env::temp_dir().join(format!("orbit-effort-save-{}", ulid::Ulid::new()));
        cfg.save_atomic(&home).unwrap();
        let old = std::fs::read(home.join("providers.toml")).unwrap();
        cfg.provider[0].models[0].default_effort = Some(EffortValue::Level("high".into()));
        assert!(cfg.save_atomic(&home).is_err());
        assert_eq!(std::fs::read(home.join("providers.toml")).unwrap(), old);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn model_spec_resolution_preserves_full_bare_and_qualified_slash_ids() {
        let cfg = ProvidersConfig::load_from_str("[[provider]]\nname='p'\nurl='https://example.test'\n[[provider.models]]\nid='vendor/reasoner'\nsupported_efforts=['high']\ndefault_effort='high'\n[[provider.models]]\nid='p/incidental-prefix'\n").unwrap();
        for spec in ["vendor/reasoner", "p/vendor/reasoner"] {
            let (provider, entry) = cfg.model_entry_for_spec(spec).unwrap();
            assert_eq!(provider.name, "p");
            assert_eq!(entry.id, "vendor/reasoner");
            assert_eq!(
                entry.default_effort,
                Some(EffortValue::Level("high".into()))
            );
        }
        assert_eq!(
            cfg.model_entry_for_spec("p/incidental-prefix")
                .unwrap()
                .1
                .id,
            "p/incidental-prefix"
        );
        assert_eq!(
            cfg.model_entry_for_spec("p/p/incidental-prefix")
                .unwrap()
                .1
                .id,
            "p/incidental-prefix"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod storage_save_tests {
    use super::*;
    use crate::customization::{Directory, Lock};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

    const BASE: &str = "[[provider]]\nname='fixture'\nurl='https://example.test'\n[[provider.models]]\nid='model-a'\n";

    struct Tree(std::path::PathBuf);
    impl Tree {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("orbit-provider-save-{}", ulid::Ulid::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn home(&self) -> std::path::PathBuf {
            self.0.join("home")
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn config() -> ProvidersConfig {
        ProvidersConfig::load_from_str(BASE).unwrap()
    }
    fn write(path: &Path, raw: &[u8]) {
        std::fs::write(path, raw).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn stamp(path: &Path) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
        let m = std::fs::symlink_metadata(path).unwrap();
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
    fn no_stage(home: &Path) {
        assert!(std::fs::read_dir(home).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".stage-")
        }));
    }

    #[test]
    fn save_creates_private_nested_home_and_joins_load_and_update() {
        let tree = Tree::new();
        let home = tree.0.join("new-parent/nested/home");
        let cfg = config();
        cfg.save_atomic(&home).unwrap();
        for path in [
            tree.0.join("new-parent"),
            tree.0.join("new-parent/nested"),
            home.clone(),
        ] {
            assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o700);
        }
        assert_eq!(
            std::fs::metadata(home.join("providers.toml"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(ProvidersConfig::load(&home).unwrap(), cfg);
        let updated = ProvidersConfig::update_atomic(&home, |raw| {
            let mut candidate = ProvidersConfig::load_from_str(raw)?;
            candidate.provider[0].models[0].idle_timeout_ms = Some(123);
            toml::to_string(&candidate).map_err(|error| error.to_string())
        })
        .unwrap();
        assert_eq!(updated.provider[0].models[0].idle_timeout_ms, Some(123));
        assert_eq!(ProvidersConfig::load(&home).unwrap(), updated);
        assert!(!home.join(".providers.toml.tmp").exists());
        no_stage(&home);
    }

    #[test]
    fn unsafe_home_and_symlink_ancestor_are_refused_without_changes() {
        let tree = Tree::new();
        let home = tree.home();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&home)
            .unwrap();
        let path = home.join("providers.toml");
        write(&path, BASE.as_bytes());
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o775)).unwrap();
        let before_home = stamp(&home);
        let before_file = stamp(&path);
        assert!(config().save_atomic(&home).is_err());
        assert_eq!(stamp(&home), before_home);
        assert_eq!(stamp(&path), before_file);
        assert_eq!(std::fs::read(path).unwrap(), BASE.as_bytes());
        assert!(!home.join(".config.lock").exists());
        let real = tree.0.join("real");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .unwrap();
        let alias = tree.0.join("alias");
        symlink(&real, &alias).unwrap();
        let before_alias = stamp(&alias);
        assert!(config().save_atomic(&alias.join("missing-home")).is_err());
        assert_eq!(stamp(&alias), before_alias);
        assert_eq!(std::fs::read_link(&alias).unwrap(), real);
        assert!(!real.join("missing-home").exists());
    }

    #[test]
    fn existing_unsafe_provider_entries_preserve_their_identity_and_contents() {
        for kind in ["symlink", "dangling", "hardlink", "public"] {
            let tree = Tree::new();
            let home = tree.home();
            let cfg = config();
            cfg.save_atomic(&home).unwrap();
            let path = home.join("providers.toml");
            let original = std::fs::read(&path).unwrap();
            let sentinel = tree.0.join("sentinel");
            write(&sentinel, b"owned sentinel unchanged");
            let absent = tree.0.join("absent");
            match kind {
                "symlink" => {
                    std::fs::remove_file(&path).unwrap();
                    symlink(&sentinel, &path).unwrap();
                }
                "dangling" => {
                    std::fs::remove_file(&path).unwrap();
                    symlink(&absent, &path).unwrap();
                }
                "hardlink" => std::fs::hard_link(&path, tree.0.join("linked-provider")).unwrap(),
                "public" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                _ => unreachable!(),
            }
            let before = stamp(&path);
            let before_sentinel = stamp(&sentinel);
            assert!(cfg.save_atomic(&home).is_err(), "{kind}");
            assert_eq!(stamp(&path), before, "{kind}");
            assert_eq!(stamp(&sentinel), before_sentinel, "{kind}");
            assert_eq!(
                std::fs::read(&sentinel).unwrap(),
                b"owned sentinel unchanged"
            );
            assert!(!absent.exists());
            if kind == "symlink" {
                assert_eq!(std::fs::read_link(&path).unwrap(), sentinel);
            } else if kind == "dangling" {
                assert_eq!(std::fs::read_link(&path).unwrap(), absent);
            } else {
                assert_eq!(std::fs::read(&path).unwrap(), original);
                if kind == "hardlink" {
                    assert_eq!(
                        std::fs::read(tree.0.join("linked-provider")).unwrap(),
                        original
                    );
                }
            }
            no_stage(&home);
        }
    }

    #[test]
    fn obsolete_fixed_temp_symlink_is_never_followed_or_changed() {
        let tree = Tree::new();
        let home = tree.home();
        let mut cfg = config();
        cfg.save_atomic(&home).unwrap();
        let sentinel = tree.0.join("sentinel");
        write(&sentinel, b"never truncate this sentinel");
        let stale = home.join(".providers.toml.tmp");
        symlink(&sentinel, &stale).unwrap();
        let before_stale = stamp(&stale);
        let before_sentinel = stamp(&sentinel);
        cfg.provider[0].models[0].idle_timeout_ms = Some(321);
        cfg.save_atomic(&home).unwrap();
        assert_eq!(ProvidersConfig::load(&home).unwrap(), cfg);
        assert_eq!(stamp(&stale), before_stale);
        assert_eq!(std::fs::read_link(&stale).unwrap(), sentinel);
        assert_eq!(stamp(&sentinel), before_sentinel);
        assert_eq!(
            std::fs::read(sentinel).unwrap(),
            b"never truncate this sentinel"
        );
        no_stage(&home);
    }

    #[test]
    fn save_and_update_share_the_same_nonblocking_writer_lock() {
        let tree = Tree::new();
        let home = tree.home();
        let cfg = config();
        cfg.save_atomic(&home).unwrap();
        let original = std::fs::read(home.join("providers.toml")).unwrap();
        let directory = Directory::open(&home, true).unwrap();
        let lock = Lock::acquire(&directory, ".config.lock").unwrap();
        assert!(cfg.save_atomic(&home).is_err());
        let called = std::cell::Cell::new(false);
        assert!(
            ProvidersConfig::update_atomic(&home, |raw| {
                called.set(true);
                Ok(raw.to_owned())
            })
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(
            std::fs::read(home.join("providers.toml")).unwrap(),
            original
        );
        no_stage(&home);
        drop(lock);
        cfg.save_atomic(&home).unwrap();
        assert_eq!(ProvidersConfig::load(&home).unwrap(), cfg);
        no_stage(&home);
    }
}

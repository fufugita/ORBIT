//! Checked, offline model selection shared by routing preview and live callers.

use crate::config::{ModelEntry, Pricing, ProviderConfig, ProvidersConfig};
use orbit_engine::routing::{self, Difficulty, TaskDecision, TaskPhase};
use orbit_engine::{ProviderKind, TurnConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_CONFIG_BYTES: usize = 128 * 1024;

/// The reason a session selected its base identity. Explicit origins suppress routing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionOrigin {
    #[default]
    Default,
    Role,
    Flag,
    Environment,
    Interactive,
    SavedExplicit,
    AgentExplicit,
}
impl SelectionOrigin {
    pub fn is_explicit(self) -> bool {
        !matches!(self, Self::Default | Self::Role)
    }
    pub fn restored(saved: Option<Self>) -> Self {
        saved.unwrap_or(Self::SavedExplicit)
    }
}

/// Complete owned metadata for one exact declared provider/raw-model pair.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedModel {
    pub provider_id: String,
    pub raw_model: String,
    pub kind: ProviderKind,
    pub url: String,
    pub credential_env: Option<String>,
    pub pricing: Option<Pricing>,
    pub caps: ModelEntry,
}
impl ResolvedModel {
    pub fn qualified(&self) -> String {
        format!("{}/{}", self.provider_id, self.raw_model)
    }
    pub fn same_identity(&self, other: &Self) -> bool {
        self.provider_id == other.provider_id && self.raw_model == other.raw_model
    }
    /// Changed identities receive their own declared default effort and capabilities.
    pub fn turn_config(&self, base: Option<&TurnConfig>) -> Result<TurnConfig, String> {
        let retain =
            base.filter(|b| b.provider_id == self.provider_id && b.model == self.raw_model);
        let out = TurnConfig {
            provider_id: self.provider_id.clone(),
            gate: self.url.clone(),
            model: self.raw_model.clone(),
            kind: self.kind,
            credential_env: self.credential_env.clone(),
            pricing: self.pricing.and_then(Pricing::complete_legacy_cost_rates),
            billing: self
                .caps
                .billing
                .as_ref()
                .map(|billing| billing.contract(&self.provider_id, &self.raw_model))
                .transpose()?,
            max_output_tokens: self.caps.max_output_tokens.unwrap_or(32_000).into(),
            sampling: self
                .caps
                .sampling
                .as_ref()
                .map(|s| (s.temperature, s.top_p)),
            effort: match retain {
                Some(b) => b.effort.clone(),
                None => self.caps.default_effort.clone(),
            },
            supported_efforts: self.caps.supported_efforts.clone(),
            first_byte_timeout_ms: self.caps.first_byte_timeout_ms,
            idle_timeout_ms: self.caps.idle_timeout_ms,
        };
        out.validate_effort()?;
        Ok(out)
    }
}

fn valid_name(value: &str, cap: usize) -> bool {
    !value.is_empty()
        && value.len() <= cap
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn checked_kind(provider: &ProviderConfig) -> Result<ProviderKind, String> {
    match provider.kind.as_str() {
        "openai-compatible" => Ok(ProviderKind::OpenAiCompatible),
        "anthropic" => Ok(ProviderKind::Anthropic),
        "ollama" => Ok(ProviderKind::Ollama),
        _ => Err("unknown configured provider kind".into()),
    }
}
fn checked_provider(provider: &ProviderConfig) -> Result<(), String> {
    if !valid_name(&provider.name, 128) || provider.name.contains('/') {
        return Err(
            "provider identity must be printable, nonempty, at most 128 bytes and contain no slash"
                .into(),
        );
    }
    checked_kind(provider)?;
    crate::config::validate_provider_endpoint(&provider.url)?;
    if let Some(env) = &provider.env
        && (env.is_empty()
            || env.len() > 128
            || !env
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || i > 0 && b.is_ascii_digit()))
    {
        return Err("credential reference must be an environment variable name".into());
    }
    if provider.models.len() > 1024 {
        return Err("provider model count exceeds 1024".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    for model in &provider.models {
        if !valid_name(&model.id, 512) || !ids.insert(&model.id) {
            return Err("model identity must be unique within its provider, printable and at most 512 bytes".into());
        }
        model.validate_effort(checked_kind(provider)?)?;
        if model.max_output_tokens == Some(0) || model.context_window == Some(0) {
            return Err("declared model limits must be positive".into());
        }
        if let Some(sampling) = &model.sampling
            && (sampling
                .temperature
                .is_some_and(|v| !v.is_finite() || !(0.0..=2.0).contains(&v))
                || sampling
                    .top_p
                    .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v)))
        {
            return Err("sampling values are outside their supported range".into());
        }
    }
    Ok(())
}

pub fn validate_providers(config: &ProvidersConfig) -> Result<(), String> {
    if config.provider.len() > 128 {
        return Err("provider count exceeds 128".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for provider in &config.provider {
        if !names.insert(&provider.name) {
            return Err("duplicate provider identity".into());
        }
        checked_provider(provider)?;
    }
    Ok(())
}

/// Resolve a qualified identity only against declared provider names. A hint denotes
/// an exact provider: raw slash-bearing IDs on resume are considered before parsing.
pub fn resolve_model(
    config: &ProvidersConfig,
    spec: &str,
    provider_hint: Option<&str>,
) -> Result<ResolvedModel, String> {
    validate_providers(config)?;
    if !valid_name(spec, 641) {
        return Err("model selection must be a printable declared identity".into());
    }
    let pair = if let Some(hint) = provider_hint {
        let provider = config
            .provider
            .iter()
            .find(|p| p.name == hint)
            .ok_or("unknown selected provider")?;
        let model = provider
            .models
            .iter()
            .find(|m| m.id == spec)
            .or_else(|| {
                spec.strip_prefix(&format!("{hint}/"))
                    .and_then(|raw| provider.models.iter().find(|m| m.id == raw))
            })
            .ok_or("selected provider does not declare this model")?;
        (provider, model)
    } else {
        let qualified: Vec<_> = config
            .provider
            .iter()
            .filter_map(|p| {
                spec.strip_prefix(&format!("{}/", p.name))
                    .and_then(|raw| p.models.iter().find(|m| m.id == raw))
                    .map(|m| (p, m))
            })
            .collect();
        if qualified.len() == 1 {
            qualified[0]
        } else if qualified.len() > 1 {
            return Err("ambiguous qualified model identity".into());
        } else {
            // A declared provider prefix is an explicit qualification, even if stale.
            if config
                .provider
                .iter()
                .any(|p| spec.starts_with(&format!("{}/", p.name)))
            {
                return Err("qualified provider does not declare this model".into());
            }
            let matches: Vec<_> = config
                .provider
                .iter()
                .flat_map(|p| {
                    p.models
                        .iter()
                        .filter(|m| m.id == spec)
                        .map(move |m| (p, m))
                })
                .collect();
            match matches.as_slice() {
                [pair] => *pair,
                [] => return Err("no provider declares the selected model".into()),
                _ => return Err("ambiguous model; select provider/model".into()),
            }
        }
    };
    Ok(ResolvedModel {
        provider_id: pair.0.name.clone(),
        raw_model: pair.1.id.clone(),
        kind: checked_kind(pair.0)?,
        url: pair.0.url.clone(),
        credential_env: pair.0.env.clone(),
        pricing: pair.1.pricing,
        caps: pair.1.clone(),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseTargets {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub easy: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hard: String,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseKeywords {
    #[serde(default)]
    pub clear: bool,
    #[serde(default)]
    pub general: Vec<String>,
    #[serde(default)]
    pub thinking: Vec<String>,
    #[serde(default)]
    pub planning: Vec<String>,
    #[serde(default)]
    pub coding: Vec<String>,
    #[serde(default)]
    pub design: Vec<String>,
    #[serde(default)]
    pub orchestration: Vec<String>,
    #[serde(default)]
    pub pentest: Vec<String>,
}
impl PhaseKeywords {
    pub fn lists(&self) -> [(TaskPhase, &[String]); 7] {
        [
            (TaskPhase::General, &self.general),
            (TaskPhase::Thinking, &self.thinking),
            (TaskPhase::Planning, &self.planning),
            (TaskPhase::Coding, &self.coding),
            (TaskPhase::Design, &self.design),
            (TaskPhase::Orchestration, &self.orchestration),
            (TaskPhase::Pentest, &self.pentest),
        ]
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseRoutingConfig {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub phases: BTreeMap<TaskPhase, PhaseTargets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_keywords: Option<PhaseKeywords>,
}
impl PhaseRoutingConfig {
    pub fn enabled(&self) -> bool {
        !self.phases.is_empty() || self.phase_keywords.is_some()
    }
    pub fn keywords(&self) -> Result<BTreeMap<TaskPhase, Vec<String>>, String> {
        let mut out = if self.phase_keywords.as_ref().is_some_and(|k| k.clear) {
            BTreeMap::new()
        } else {
            routing::default_phase_keywords()
        };
        if let Some(keywords) = &self.phase_keywords {
            for (phase, words) in keywords.lists() {
                routing::validate_keyword_list(words)?;
                let target = out.entry(phase).or_default();
                for word in words {
                    let word = word.trim().to_lowercase();
                    if !target.contains(&word) {
                        target.push(word);
                    }
                }
            }
        }
        for words in out.values() {
            routing::validate_keyword_list(words)?;
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    Explicit,
    PhaseDifficulty,
    PhaseDefault,
    LegacyDifficulty,
    Base,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouteDecision {
    pub phase: TaskPhase,
    pub difficulty: Difficulty,
    pub matched: TaskDecision,
    pub provider_id: String,
    pub raw_model: String,
    pub source: RouteSource,
    pub suppressed_reason: Option<String>,
    #[serde(skip)]
    pub model: ResolvedModel,
}

/// Validate all configured routing/role targets, including currently inactive ones.
pub fn validate_settings(
    config: &ProvidersConfig,
    settings: &PhaseRoutingConfig,
) -> Result<(), String> {
    validate_providers(config)?;
    settings.keywords()?;
    let table = config.routing_table();
    routing::validate_keyword_list(&table.hard_keywords)?;
    routing::validate_keyword_list(&table.easy_keywords)?;
    for (_, spec) in config.roles.entries() {
        resolve_model(config, spec, None)?;
    }
    for spec in [&table.hard, &table.easy]
        .into_iter()
        .filter(|s| !s.is_empty())
    {
        resolve_model(config, spec, None)?;
    }
    for targets in settings.phases.values() {
        for spec in [&targets.default, &targets.easy, &targets.hard]
            .into_iter()
            .filter(|s| !s.is_empty())
        {
            resolve_model(config, spec, None)?;
        }
    }
    Ok(())
}

/// One pure decision serves both preview and dispatch. There is no IO or provider fallback.
pub fn preview(
    config: &ProvidersConfig,
    settings: &PhaseRoutingConfig,
    base: &ResolvedModel,
    origin: SelectionOrigin,
    prompt: &str,
    phase_override: Option<TaskPhase>,
) -> Result<RouteDecision, String> {
    validate_settings(config, settings)?;
    if prompt.len() > routing::MAX_ROUTING_PROMPT_BYTES {
        return Err("routing prompt exceeds 256 KiB".into());
    }
    let current = resolve_model(config, &base.raw_model, Some(&base.provider_id))?;
    if current != *base {
        return Err(
            "base model metadata changed; resolve the current identity before routing".into(),
        );
    }
    let table = config.routing_table();
    let matched = if settings.enabled() {
        routing::classify_task(
            &settings.keywords()?,
            &table.hard_keywords,
            &table.easy_keywords,
            prompt,
            phase_override,
        )?
    } else {
        let legacy = routing::classify(&table, prompt);
        let difficulty = match legacy.phase {
            routing::RoutingPhase::Hard => Difficulty::Hard,
            routing::RoutingPhase::Easy => Difficulty::Easy,
            routing::RoutingPhase::Main => Difficulty::Normal,
        };
        let hits = legacy
            .matched
            .into_iter()
            .map(|keyword| routing::KeywordHit {
                keyword,
                occurrences: 1,
            })
            .collect();
        let (hard_hits, easy_hits) = match difficulty {
            Difficulty::Hard => (hits, Vec::new()),
            Difficulty::Easy => (Vec::new(), hits),
            Difficulty::Normal => (Vec::new(), Vec::new()),
        };
        TaskDecision {
            phase: phase_override.unwrap_or(TaskPhase::General),
            difficulty,
            phase_hits: BTreeMap::new(),
            hard_hits,
            easy_hits,
            phase_override: phase_override.is_some(),
        }
    };
    let mut source = RouteSource::Base;
    let mut target = None;
    let suppressed_reason = if origin.is_explicit() {
        source = RouteSource::Explicit;
        Some(
            "explicit model selection retains its exact identity; /route auto clears the pin"
                .into(),
        )
    } else {
        None
    };
    if !origin.is_explicit() {
        if let Some(targets) = settings.phases.get(&matched.phase) {
            let difficulty = match matched.difficulty {
                Difficulty::Hard => &targets.hard,
                Difficulty::Easy => &targets.easy,
                Difficulty::Normal => "",
            };
            if !difficulty.is_empty() {
                target = Some(difficulty);
                source = RouteSource::PhaseDifficulty;
            } else if !targets.default.is_empty() {
                target = Some(targets.default.as_str());
                source = RouteSource::PhaseDefault;
            }
        }
        if target.is_none() {
            let legacy = match matched.difficulty {
                Difficulty::Hard => &table.hard,
                Difficulty::Easy => &table.easy,
                Difficulty::Normal => "",
            };
            if !legacy.is_empty() {
                target = Some(legacy);
                source = RouteSource::LegacyDifficulty;
            }
        }
    }
    let model = match target {
        Some(spec) => resolve_model(config, spec, None)?,
        None => base.clone(),
    };
    Ok(RouteDecision {
        phase: matched.phase,
        difficulty: matched.difficulty,
        matched,
        provider_id: model.provider_id.clone(),
        raw_model: model.raw_model.clone(),
        source,
        suppressed_reason,
        model,
    })
}

/// Parse only the additive routing fields from a complete providers document.
pub fn parse_settings(raw: &str) -> Result<PhaseRoutingConfig, String> {
    if raw.len() > MAX_CONFIG_BYTES {
        return Err("providers configuration exceeds 128 KiB".into());
    }
    let value: toml::Value = toml::from_str(raw).map_err(|_| "invalid providers TOML")?;
    settings_from_value(&value)
}
fn settings_from_value(value: &toml::Value) -> Result<PhaseRoutingConfig, String> {
    let mut fields = toml::map::Map::new();
    if let Some(table) = value.get("routing") {
        let table = table.as_table().ok_or("routing must be a TOML table")?;
        for field in ["phases", "phase_keywords"] {
            if let Some(v) = table.get(field) {
                fields.insert(field.into(), v.clone());
            }
        }
    }
    toml::Value::Table(fields)
        .try_into()
        .map_err(|_| "invalid phase routing fields".into())
}

#[derive(Debug, Clone)]
pub enum RouteMutation {
    LegacyTarget {
        difficulty: Difficulty,
        model: String,
    },
    EditKeywords {
        difficulty: Difficulty,
        word: String,
        remove: bool,
    },
    ClearKeywords,
    Disable,
    Setup {
        easy: String,
        hard: String,
    },
    Set {
        phase: TaskPhase,
        difficulty: Option<Difficulty>,
        model: String,
    },
    Reset {
        phase: Option<TaskPhase>,
    },
}
/// Preserve the original document outside one explicitly editable section.
/// The complete intended value is checked after encoding, including unknown data.
pub fn encode_candidate_section(
    raw: &str,
    intended: &toml::Value,
    section: &str,
) -> Result<String, String> {
    if !matches!(section, "roles" | "routing") {
        return Err("unsupported provider configuration section".into());
    }
    if raw.len() > MAX_CONFIG_BYTES {
        return Err("providers configuration exceeds 128 KiB".into());
    }
    let mut original = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|_| "invalid providers TOML")?;
    // Canonical serialization is a semantic comparison rather than float
    // PartialEq: valid unknown NaN values must remain editable and preserved.
    let canonical =
        toml::to_string(intended).map_err(|_| "could not serialize providers candidate")?;
    let replacement = canonical
        .parse::<toml_edit::DocumentMut>()
        .map_err(|_| "invalid providers candidate")?;
    if let Some(item) = replacement.as_table().get(section) {
        original.as_table_mut().insert(section, item.clone());
    } else {
        original.as_table_mut().remove(section);
    }
    let candidate = original.to_string();
    if candidate.len() > MAX_CONFIG_BYTES {
        return Err("providers configuration exceeds 128 KiB".into());
    }
    let encoded: toml::Value =
        toml::from_str(&candidate).map_err(|_| "invalid providers candidate")?;
    let encoded =
        toml::to_string(&encoded).map_err(|_| "could not serialize providers candidate")?;
    if encoded != canonical {
        return Err("providers candidate did not preserve intended values".into());
    }
    Ok(candidate)
}

/// Construct and validate the entire candidate. Caller alone owns atomic persistence.
pub fn config_candidate(raw: &str, mutation: RouteMutation) -> Result<String, String> {
    if raw.len() > MAX_CONFIG_BYTES {
        return Err("providers configuration exceeds 128 KiB".into());
    }
    let mut value: toml::Value = toml::from_str(raw).map_err(|_| "invalid providers TOML")?;
    let top = value
        .as_table_mut()
        .ok_or("providers config must be a TOML table")?;
    let routing = top
        .entry("routing")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or("routing must be a table")?;
    match mutation {
        RouteMutation::LegacyTarget { difficulty, model } => {
            let key = match difficulty {
                Difficulty::Hard => "hard",
                Difficulty::Easy => "easy",
                Difficulty::Normal => return Err("legacy targets support hard or easy".into()),
            };
            if model.is_empty() {
                routing.remove(key);
            } else {
                routing.insert(key.into(), model.into());
            }
        }
        RouteMutation::EditKeywords {
            difficulty,
            word,
            remove,
        } => {
            let key = match difficulty {
                Difficulty::Hard => "hard",
                Difficulty::Easy => "easy",
                Difficulty::Normal => return Err("keywords support hard or easy".into()),
            };
            let word = word.trim().to_lowercase();
            routing::validate_keyword_list(std::slice::from_ref(&word))?;
            let keywords = routing
                .entry("keywords")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .ok_or("keywords must be a table")?;
            let list = keywords
                .entry(key)
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or("keywords must be arrays")?;
            if list.iter().any(|v| v.as_str().is_none()) {
                return Err("keywords must contain strings".into());
            }
            if remove {
                list.retain(|v| v.as_str().unwrap().trim().to_lowercase() != word);
            } else if !list
                .iter()
                .any(|v| v.as_str().unwrap().trim().to_lowercase() == word)
            {
                list.push(word.into());
            }
        }
        RouteMutation::ClearKeywords => {
            let keywords = routing
                .entry("keywords")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .ok_or("keywords must be a table")?;
            keywords.insert("clear".into(), true.into());
            keywords.insert("hard".into(), toml::Value::Array(Vec::new()));
            keywords.insert("easy".into(), toml::Value::Array(Vec::new()));
        }
        RouteMutation::Disable => {
            for key in ["phases", "phase_keywords", "hard", "easy"] {
                routing.remove(key);
            }
        }
        RouteMutation::Setup { easy, hard } => {
            if easy.is_empty() || hard.is_empty() {
                return Err("route setup requires both easy and hard targets".into());
            }
            routing.insert("easy".into(), easy.clone().into());
            routing.insert("hard".into(), hard.clone().into());
            let phases = routing
                .entry("phases")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .ok_or("routing phases must be a table")?;
            for phase in TaskPhase::ALL {
                let entry = phases
                    .entry(phase.as_str())
                    .or_insert_with(|| toml::Value::Table(Default::default()))
                    .as_table_mut()
                    .ok_or("phase target must be a table")?;
                entry.insert("easy".into(), easy.clone().into());
                entry.insert("hard".into(), hard.clone().into());
            }
        }
        RouteMutation::Set {
            phase,
            difficulty,
            model,
        } => {
            if model.is_empty() {
                return Err(
                    "route set requires a declared model; use reset to remove targets".into(),
                );
            }
            let phases = routing
                .entry("phases")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .ok_or("routing phases must be a table")?;
            let entry = phases
                .entry(phase.as_str())
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .ok_or("phase target must be a table")?;
            let key = match difficulty {
                Some(Difficulty::Easy) => "easy",
                Some(Difficulty::Hard) => "hard",
                None | Some(Difficulty::Normal) => "default",
            };
            entry.insert(key.into(), model.into());
        }
        RouteMutation::Reset { phase: Some(phase) } => {
            if let Some(phases) = routing.get_mut("phases") {
                phases
                    .as_table_mut()
                    .ok_or("routing phases must be a table")?
                    .remove(phase.as_str());
            }
        }
        RouteMutation::Reset { phase: None } => {
            for key in ["phases", "phase_keywords", "hard", "easy", "keywords"] {
                routing.remove(key);
            }
        }
    }
    let candidate = encode_candidate_section(raw, &value, "routing")?;
    let config: ProvidersConfig =
        toml::from_str(&candidate).map_err(|_| "invalid providers candidate")?;
    validate_settings(&config, &parse_settings(&candidate)?)?;
    Ok(candidate)
}

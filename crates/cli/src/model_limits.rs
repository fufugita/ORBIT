//! Exact local context policy for the final selected and summary requests.
//!
//! Resolution reads one configuration snapshot and bounded checked provenance.
//! It never fetches a catalog or resolves credentials. Callers must finish all
//! model, role, output and effort overrides before resolving these budgets.

use crate::config::{
    ContextLimitOverrides, ContextMediaPolicy, ContextUnknownPolicy, ModelEntry, ProviderConfig,
    ProvidersConfig, validate_provider_endpoint,
};
use crate::provider_discovery::{
    LimitObservation, LimitSemantics, MetadataSource, ModelProvenance, ObservationConfidence,
    ObservationSchema, PROVENANCE_VERSION, load_model_provenance,
};
use orbit_adapter::provider_credentials::ProviderAuthIdentity;
use orbit_engine::context_budget::{
    BudgetCeilings, BudgetIdentity, BudgetPolicy, BudgetSource, Freshness, MediaPolicy,
    SelectedBudget, UnknownTextPolicy,
};
use orbit_engine::{ProviderKind, TurnConfig};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

const DEFAULT_MAX_AGE_SECONDS: u64 = 3600;
const MAX_FUTURE_SKEW_SECONDS: u64 = 300;
const DEFAULT_COMBINED_TOKENS: u64 = 64_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnBudgets {
    pub selected: SelectedBudget,
    pub summary: SelectedBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnBudgetReports {
    pub selected: BudgetReport,
    pub summary: BudgetReport,
}

/// Component provenance is independent: a fallback input policy can coexist
/// with a fresh documented output ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReport {
    pub budget: SelectedBudget,
    pub components: BudgetComponents,
    pub legacy_context: LegacyContextStatus,
    pub notices: Vec<BudgetNotice>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetComponents {
    pub input: Option<ResolvedLimit>,
    pub combined: Option<ResolvedLimit>,
    pub output: Option<ResolvedLimit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedLimit {
    pub value: u64,
    pub source: BudgetSource,
    pub freshness: Freshness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyContextStatus {
    Absent,
    Managed,
    IdentifiableManual,
    LegacyUnspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitComponent {
    Input,
    Combined,
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetNotice {
    FallbackPolicy {
        input_tokens: Option<u64>,
        combined_tokens: Option<u64>,
    },
    LegacyContextUnspecified,
    StaleObservation(LimitComponent),
    UnusableObservation(LimitComponent),
}

/// Safe classifications only; upstream strings and configuration values are
/// intentionally excluded from these errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    InvalidConfig,
    InvalidMetadata,
    InvalidBinding,
    LimitRequired,
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "context budget configuration is invalid",
            Self::InvalidMetadata => "context budget metadata could not be safely validated",
            Self::InvalidBinding => "context budget does not match the selected provider and model",
            Self::LimitRequired => {
                "context limit required: configure context_limits.input_tokens or combined_tokens, or choose fallback policy"
            }
        })
    }
}

impl std::error::Error for BudgetError {}

pub fn resolve_turn_budget(
    home: &Path,
    turn: &TurnConfig,
    now_unix: u64,
) -> Result<SelectedBudget, BudgetError> {
    Ok(resolve_turn_budget_detailed(home, turn, now_unix)?.budget)
}

pub fn resolve_turn_budgets(
    home: &Path,
    selected: &TurnConfig,
    summary: &TurnConfig,
    now_unix: u64,
) -> Result<TurnBudgets, BudgetError> {
    let reports = resolve_turn_budgets_detailed(home, selected, summary, now_unix)?;
    Ok(TurnBudgets {
        selected: reports.selected.budget,
        summary: reports.summary.budget,
    })
}

pub fn resolve_turn_budget_detailed(
    home: &Path,
    turn: &TurnConfig,
    now_unix: u64,
) -> Result<BudgetReport, BudgetError> {
    Snapshot::load(home)?.resolve(home, turn, now_unix)
}

/// Production frontends consume both reports and surface their notices. The
/// supplied configurations must be the same ones subsequently dispatched.
pub fn resolve_turn_budgets_detailed(
    home: &Path,
    selected: &TurnConfig,
    summary: &TurnConfig,
    now_unix: u64,
) -> Result<TurnBudgetReports, BudgetError> {
    let mut snapshot = Snapshot::load(home)?;
    let selected = snapshot.resolve(home, selected, now_unix)?;
    let summary = snapshot.resolve(home, summary, now_unix)?;
    Ok(TurnBudgetReports { selected, summary })
}

struct Snapshot {
    config: ProvidersConfig,
    provenance: HashMap<String, Vec<ModelProvenance>>,
}

impl Snapshot {
    fn load(home: &Path) -> Result<Self, BudgetError> {
        let config = ProvidersConfig::load(home).map_err(|_| BudgetError::InvalidConfig)?;
        crate::phase_routing::validate_providers(&config)
            .map_err(|_| BudgetError::InvalidConfig)?;
        Ok(Self {
            config,
            provenance: HashMap::new(),
        })
    }

    fn resolve(
        &mut self,
        home: &Path,
        turn: &TurnConfig,
        now_unix: u64,
    ) -> Result<BudgetReport, BudgetError> {
        validate_turn(turn)?;
        if self.config.provider.is_empty() {
            return report(turn, None, None, now_unix);
        }
        let (provider, model) = self
            .config
            .model_entry(&turn.provider_id, &turn.model)
            .ok_or(BudgetError::InvalidBinding)?;
        validate_binding(provider, turn)?;
        if !self.provenance.contains_key(&provider.name) {
            let records =
                load_model_provenance(home, provider).map_err(|_| BudgetError::InvalidMetadata)?;
            self.provenance.insert(provider.name.clone(), records);
        }
        let record = self
            .provenance
            .get(&provider.name)
            .and_then(|records| records.iter().find(|record| record.model_id == turn.model));
        report(turn, Some(model), record, now_unix)
    }
}

fn kind_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::OpenAiCompatible => "openai-compatible",
        ProviderKind::Anthropic => "anthropic",
        ProviderKind::Ollama => "ollama",
    }
}

fn validate_turn(turn: &TurnConfig) -> Result<(), BudgetError> {
    let endpoint =
        validate_provider_endpoint(&turn.gate).map_err(|_| BudgetError::InvalidBinding)?;
    // Identity construction only validates names and the canonical endpoint;
    // it does not open a credential store or inspect environment values.
    ProviderAuthIdentity::new(
        &turn.provider_id,
        kind_name(turn.kind),
        endpoint.as_str(),
        turn.credential_env.as_deref(),
    )
    .map_err(|_| BudgetError::InvalidBinding)?;
    if turn.model.is_empty()
        || turn.model.len() > 512
        || turn.model.trim() != turn.model
        || turn.model.chars().any(char::is_control)
        || turn.max_output_tokens == 0
        || turn.sampling.is_some_and(|(temperature, top_p)| {
            temperature.is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value))
                || top_p.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        })
    {
        return Err(BudgetError::InvalidBinding);
    }
    turn.validate_effort()
        .map_err(|_| BudgetError::InvalidBinding)
}

fn validate_binding(provider: &ProviderConfig, turn: &TurnConfig) -> Result<(), BudgetError> {
    let declared =
        validate_provider_endpoint(&provider.url).map_err(|_| BudgetError::InvalidConfig)?;
    let selected =
        validate_provider_endpoint(&turn.gate).map_err(|_| BudgetError::InvalidBinding)?;
    if declared != selected
        || provider.kind != kind_name(turn.kind)
        || provider.env != turn.credential_env
    {
        return Err(BudgetError::InvalidBinding);
    }
    Ok(())
}

fn legacy_status(
    model: Option<&ModelEntry>,
    record: Option<&ModelProvenance>,
) -> LegacyContextStatus {
    let Some(current) = model.and_then(|model| model.context_window) else {
        return LegacyContextStatus::Absent;
    };
    let Some(record) = record else {
        return LegacyContextStatus::LegacyUnspecified;
    };
    if record.manual_input_tokens == Some(current)
        || record.last_applied_context_window.is_some_and(|previous| {
            record.observed.context_window == Some(previous) && previous != current
        })
    {
        LegacyContextStatus::IdentifiableManual
    } else if record.last_applied_context_window == Some(current)
        && record.observed.context_window == Some(current)
    {
        LegacyContextStatus::Managed
    } else {
        LegacyContextStatus::LegacyUnspecified
    }
}

fn local_limit(value: u64, source: BudgetSource) -> ResolvedLimit {
    ResolvedLimit {
        value,
        source,
        freshness: Freshness::Policy,
    }
}

fn observed_limit(
    observation: Option<&LimitObservation>,
    raw_value: Option<u64>,
    component: LimitComponent,
    kind: ProviderKind,
    now_unix: u64,
    max_age: u64,
    notices: &mut Vec<BudgetNotice>,
) -> Option<ResolvedLimit> {
    let Some(observation) = observation else {
        if raw_value.is_some() {
            notices.push(BudgetNotice::UnusableObservation(component));
        }
        return None;
    };
    let semantics = match component {
        LimitComponent::Input => LimitSemantics::InputTokens,
        LimitComponent::Combined => LimitSemantics::CombinedTokens,
        LimitComponent::Output => LimitSemantics::OutputTokens,
    };
    // Only established schemas can supply a runtime ceiling. In particular,
    // advertised OpenRouter context/output values retain unspecified semantics.
    if kind != ProviderKind::Anthropic
        || !matches!(
            observation.source,
            MetadataSource::AnthropicModels | MetadataSource::AnthropicModelDetail
        )
        || observation.schema != ObservationSchema::AnthropicModels20230601
        || observation.confidence != ObservationConfidence::DocumentedLimit
        || observation.semantics != semantics
        || observation.value == 0
        || raw_value != Some(observation.value)
    {
        notices.push(BudgetNotice::UnusableObservation(component));
        return None;
    }
    if observation.observed_at_unix > now_unix {
        if observation.observed_at_unix - now_unix > MAX_FUTURE_SKEW_SECONDS {
            notices.push(BudgetNotice::UnusableObservation(component));
            return None;
        }
    } else if now_unix - observation.observed_at_unix > max_age {
        notices.push(BudgetNotice::StaleObservation(component));
        return None;
    }
    Some(ResolvedLimit {
        value: observation.value,
        source: BudgetSource::Discovered,
        freshness: Freshness::Fresh,
    })
}

fn report(
    turn: &TurnConfig,
    model: Option<&ModelEntry>,
    record: Option<&ModelProvenance>,
    now_unix: u64,
) -> Result<BudgetReport, BudgetError> {
    let overrides = model
        .and_then(|model| model.context_limits)
        .unwrap_or_default();
    validate_overrides(&overrides)?;
    let policy = BudgetPolicy {
        unknown_text_policy: match overrides.unknown_policy {
            Some(ContextUnknownPolicy::RequireLimit) => UnknownTextPolicy::RequireLimit,
            Some(ContextUnknownPolicy::Fallback) | None => UnknownTextPolicy::Fallback,
        },
        media_policy: match overrides.media_policy {
            Some(ContextMediaPolicy::Refuse) => MediaPolicy::Refuse,
            Some(ContextMediaPolicy::AllowWithWarning) | None => MediaPolicy::AllowWithWarning,
        },
    };
    let legacy_context = legacy_status(model, record);
    let mut notices = Vec::new();
    if legacy_context == LegacyContextStatus::LegacyUnspecified {
        notices.push(BudgetNotice::LegacyContextUnspecified);
    }
    let max_age = overrides.max_age_seconds.unwrap_or(DEFAULT_MAX_AGE_SECONDS);
    let evidence = record
        .filter(|record| record.schema_version == PROVENANCE_VERSION)
        .and_then(|record| record.observed.evidence.as_ref());
    let discovered_input = observed_limit(
        evidence.and_then(|evidence| evidence.context_limit.as_ref()),
        record.and_then(|record| record.observed.context_window),
        LimitComponent::Input,
        turn.kind,
        now_unix,
        max_age,
        &mut notices,
    );
    let discovered_output = observed_limit(
        evidence.and_then(|evidence| evidence.output_limit.as_ref()),
        record.and_then(|record| record.observed.max_output_tokens.map(u64::from)),
        LimitComponent::Output,
        turn.kind,
        now_unix,
        max_age,
        &mut notices,
    );
    let mut components = BudgetComponents {
        output: discovered_output,
        ..Default::default()
    };
    let (source, freshness) =
        if overrides.input_tokens.is_some() || overrides.combined_tokens.is_some() {
            components.input = overrides
                .input_tokens
                .map(|value| local_limit(value, BudgetSource::Explicit));
            components.combined = overrides
                .combined_tokens
                .map(|value| local_limit(value, BudgetSource::Explicit));
            (BudgetSource::Explicit, Freshness::Policy)
        } else if legacy_context == LegacyContextStatus::IdentifiableManual {
            components.input = model
                .and_then(|model| model.context_window)
                .map(|value| local_limit(value, BudgetSource::Manual));
            (BudgetSource::Manual, Freshness::Policy)
        } else if let Some(input) = discovered_input.filter(|_| {
            matches!(
                legacy_context,
                LegacyContextStatus::Absent | LegacyContextStatus::Managed
            )
        }) {
            components.input = Some(input);
            (BudgetSource::Discovered, Freshness::Fresh)
        } else {
            if policy.unknown_text_policy == UnknownTextPolicy::RequireLimit {
                return Err(BudgetError::LimitRequired);
            }
            let explicit_fallback = overrides.fallback_input_tokens.is_some()
                || overrides.fallback_combined_tokens.is_some();
            let input = overrides.fallback_input_tokens;
            let combined = if explicit_fallback {
                overrides.fallback_combined_tokens
            } else {
                Some(DEFAULT_COMBINED_TOKENS)
            };
            components.input = input.map(|value| local_limit(value, BudgetSource::Fallback));
            components.combined = combined.map(|value| local_limit(value, BudgetSource::Fallback));
            notices.push(BudgetNotice::FallbackPolicy {
                input_tokens: input,
                combined_tokens: combined,
            });
            (BudgetSource::Fallback, Freshness::Policy)
        };
    let ceilings = BudgetCeilings {
        input_tokens: components.input.map(|limit| limit.value),
        combined_tokens: components.combined.map(|limit| limit.value),
        output_tokens: components.output.map(|limit| limit.value),
    };
    let metadata_revision = metadata_revision(record)?;
    let policy_revision = policy_revision(model, &components, legacy_context, &notices, policy)?;
    let identity = BudgetIdentity::for_config(turn, &metadata_revision, &policy_revision)
        .map_err(|_| BudgetError::InvalidBinding)?;
    Ok(BudgetReport {
        budget: SelectedBudget {
            identity,
            ceilings,
            freshness,
            source,
            policy,
        },
        components,
        legacy_context,
        notices,
    })
}

fn validate_overrides(overrides: &ContextLimitOverrides) -> Result<(), BudgetError> {
    if [
        overrides.input_tokens,
        overrides.combined_tokens,
        overrides.fallback_input_tokens,
        overrides.fallback_combined_tokens,
    ]
    .into_iter()
    .any(|value| value == Some(0))
        || overrides
            .max_age_seconds
            .is_some_and(|age| !(1..=604800).contains(&age))
    {
        return Err(BudgetError::InvalidConfig);
    }
    Ok(())
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn metadata_revision(record: Option<&ModelProvenance>) -> Result<String, BudgetError> {
    let bytes = serde_json::to_vec(&record).map_err(|_| BudgetError::InvalidMetadata)?;
    Ok(digest(b"orbit.context-metadata.v1\0", &bytes))
}

fn source_name(source: BudgetSource) -> &'static str {
    match source {
        BudgetSource::Explicit => "explicit",
        BudgetSource::Manual => "manual",
        BudgetSource::Discovered => "discovered",
        BudgetSource::Fallback => "fallback",
        BudgetSource::LegacyInput => "legacy-input",
    }
}

fn freshness_name(freshness: Freshness) -> &'static str {
    match freshness {
        Freshness::Fresh => "fresh",
        Freshness::Policy => "policy",
        Freshness::Stale => "stale",
        Freshness::Unknown => "unknown",
    }
}

fn component_name(component: LimitComponent) -> &'static str {
    match component {
        LimitComponent::Input => "input",
        LimitComponent::Combined => "combined",
        LimitComponent::Output => "output",
    }
}

fn limit_revision(limit: Option<ResolvedLimit>) -> Value {
    match limit {
        Some(limit) => json!([
            limit.value,
            source_name(limit.source),
            freshness_name(limit.freshness)
        ]),
        None => Value::Null,
    }
}

fn policy_revision(
    model: Option<&ModelEntry>,
    components: &BudgetComponents,
    legacy: LegacyContextStatus,
    notices: &[BudgetNotice],
    policy: BudgetPolicy,
) -> Result<String, BudgetError> {
    let legacy_name = match legacy {
        LegacyContextStatus::Absent => "absent",
        LegacyContextStatus::Managed => "managed",
        LegacyContextStatus::IdentifiableManual => "manual",
        LegacyContextStatus::LegacyUnspecified => "legacy-unspecified",
    };
    let notices: Vec<Value> = notices
        .iter()
        .map(|notice| match notice {
            BudgetNotice::FallbackPolicy {
                input_tokens,
                combined_tokens,
            } => {
                json!(["fallback", input_tokens, combined_tokens])
            }
            BudgetNotice::LegacyContextUnspecified => json!(["legacy-unspecified"]),
            BudgetNotice::StaleObservation(component) => {
                json!(["stale", component_name(*component)])
            }
            BudgetNotice::UnusableObservation(component) => {
                json!(["unusable", component_name(*component)])
            }
        })
        .collect();
    let value = json!([
        "byte4-v1",
        DEFAULT_COMBINED_TOKENS,
        DEFAULT_MAX_AGE_SECONDS,
        MAX_FUTURE_SKEW_SECONDS,
        model.and_then(|model| model.context_limits),
        model.and_then(|model| model.context_window),
        model.and_then(|model| model.max_output_tokens),
        legacy_name,
        limit_revision(components.input),
        limit_revision(components.combined),
        limit_revision(components.output),
        match policy.unknown_text_policy {
            UnknownTextPolicy::Fallback => "fallback",
            UnknownTextPolicy::RequireLimit => "require-limit",
        },
        match policy.media_policy {
            MediaPolicy::AllowWithWarning => "allow-with-warning",
            MediaPolicy::Refuse => "refuse",
        },
        notices,
    ]);
    let bytes = serde_json::to_vec(&value).map_err(|_| BudgetError::InvalidConfig)?;
    Ok(digest(b"orbit.context-policy.v1\0", &bytes))
}

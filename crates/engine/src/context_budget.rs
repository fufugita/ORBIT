//! Local request-capacity policy over the actual rendered provider body.
//!
//! Text uses ceil(serialized UTF-8 bytes / 4), a policy approximation rather
//! than a tokenizer or provider-fit guarantee. Media remains explicitly unknown.

use crate::dispatch::{PreparedProviderRequest, TurnConfig};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetCeilings {
    pub input_tokens: Option<u64>,
    pub combined_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

/// Only hashes/revisions; never a raw endpoint, authentication reference or key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetIdentity {
    pub binding_digest: String,
    pub metadata_revision: String,
    pub policy_revision: String,
}

impl BudgetIdentity {
    pub fn for_config(
        config: &TurnConfig,
        metadata_revision: &str,
        policy_revision: &str,
    ) -> Result<Self, String> {
        let url = orbit_provider_http::endpoint::validate_provider_url(&config.gate)
            .map_err(|_| "context budget provider binding is invalid".to_owned())?;
        let sampling = config
            .sampling
            .map(|(t, p)| (t.map(f64::to_bits), p.map(f64::to_bits)));
        let binding = serde_json::json!([
            config.provider_id,
            url.as_str(),
            config.model,
            match config.kind {
                crate::ProviderKind::OpenAiCompatible => "openai-compatible",
                crate::ProviderKind::Anthropic => "anthropic",
                crate::ProviderKind::Ollama => "ollama",
            },
            config.credential_env,
            config.max_output_tokens,
            config.effort,
            sampling
        ]);
        let bytes = serde_json::to_vec(&binding)
            .map_err(|_| "context budget binding could not be encoded".to_owned())?;
        Ok(Self {
            binding_digest: hex::encode(Sha256::digest(bytes)),
            metadata_revision: metadata_revision.into(),
            policy_revision: policy_revision.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Policy,
    Stale,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSource {
    Explicit,
    Manual,
    Discovered,
    Fallback,
    LegacyInput,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnknownTextPolicy {
    #[default]
    Fallback,
    RequireLimit,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MediaPolicy {
    #[default]
    AllowWithWarning,
    Refuse,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetPolicy {
    pub unknown_text_policy: UnknownTextPolicy,
    pub media_policy: MediaPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedBudget {
    pub identity: BudgetIdentity,
    pub ceilings: BudgetCeilings,
    pub freshness: Freshness,
    pub source: BudgetSource,
    pub policy: BudgetPolicy,
}

impl SelectedBudget {
    pub fn legacy_input(config: &TurnConfig, window: u64) -> Result<Self, String> {
        Ok(Self {
            identity: BudgetIdentity::for_config(config, "legacy-input", "byte4-v1")?,
            ceilings: BudgetCeilings {
                input_tokens: Some(window),
                ..Default::default()
            },
            freshness: Freshness::Policy,
            source: BudgetSource::LegacyInput,
            policy: BudgetPolicy::default(),
        })
    }

    fn effective_ceilings(&self) -> BudgetCeilings {
        let mut ceilings =
            if self.source == BudgetSource::Discovered && self.freshness != Freshness::Fresh {
                BudgetCeilings::default()
            } else {
                self.ceilings
            };
        if ceilings.input_tokens.is_none()
            && ceilings.combined_tokens.is_none()
            && self.policy.unknown_text_policy == UnknownTextPolicy::Fallback
        {
            ceilings.combined_tokens = Some(64_000);
        }
        ceilings
    }
    pub(crate) fn meter_window(&self, output: u64) -> (Option<u64>, u64) {
        let (window, reserve, _) = self.meter_limits(output);
        (window, reserve)
    }

    pub(crate) fn compaction_threshold(&self, output: u64) -> Option<u64> {
        self.meter_limits(output).2
    }

    fn meter_limits(&self, output: u64) -> (Option<u64>, u64, Option<u64>) {
        let ceilings = self.effective_ceilings();
        let threshold = |n: u64| n / 10 * 9 + (n % 10 * 9) / 10;
        match (ceilings.input_tokens, ceilings.combined_tokens) {
            (None, None) => (None, 0, None),
            (Some(input), None) => (Some(input), 0, Some(threshold(input))),
            (None, Some(combined)) => (
                Some(combined),
                output,
                Some(threshold(combined).saturating_sub(output)),
            ),
            (Some(input), Some(combined)) => {
                let soft = threshold(input).min(threshold(combined).saturating_sub(output));
                if combined.saturating_sub(output) <= input {
                    (Some(combined), output, Some(soft))
                } else {
                    (Some(input), 0, Some(soft))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimateStatus {
    Approximate,
    UnknownMedia,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEstimate {
    pub body_bytes: u64,
    pub text_bytes: u64,
    pub system_bytes: u64,
    pub tools_bytes: u64,
    pub messages_bytes: u64,
    pub framing_bytes: u64,
    pub raw_system_bytes: u64,
    pub raw_tools_bytes: u64,
    pub raw_messages_bytes: u64,
    pub raw_framing_bytes: u64,
    pub estimated_input_tokens: u64,
    pub requested_output_tokens: u64,
    pub body_digest: String,
    pub binding_digest: String,
    pub status: EstimateStatus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    InvalidBinding,
    Render,
    Arithmetic,
}
impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidBinding => "context budget does not match the selected provider",
            Self::Render => "context budget request rendering failed",
            Self::Arithmetic => "context budget arithmetic overflow",
        })
    }
}
impl std::error::Error for BudgetError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDecision {
    AdmitEstimated,
    AdmitUnknownMediaWithWarning,
    Compact,
    Refuse,
    Unknown,
}

fn encoded_len(value: &Value) -> Result<u64, BudgetError> {
    u64::try_from(
        serde_json::to_vec(value)
            .map_err(|_| BudgetError::Render)?
            .len(),
    )
    .map_err(|_| BudgetError::Arithmetic)
}

fn components(value: &Value) -> Result<(u64, u64, u64, u64), BudgetError> {
    let mut system = value
        .get("system")
        .map(encoded_len)
        .transpose()?
        .unwrap_or(0);
    let tools = value
        .get("tools")
        .map(encoded_len)
        .transpose()?
        .unwrap_or(0);
    let mut conversation = Vec::new();
    if let Some(messages) = value.get("messages").and_then(Value::as_array) {
        for message in messages {
            if message.get("role").and_then(Value::as_str) == Some("system") {
                system = system
                    .checked_add(encoded_len(message)?)
                    .ok_or(BudgetError::Arithmetic)?;
            } else {
                conversation.push(message.clone());
            }
        }
    }
    let messages = encoded_len(&Value::Array(conversation))?;
    let framing = encoded_len(value)?
        .checked_sub(system)
        .and_then(|n| n.checked_sub(tools))
        .and_then(|n| n.checked_sub(messages))
        .ok_or(BudgetError::Arithmetic)?;
    Ok((system, tools, messages, framing))
}

// Recognize typed dialect fields, never content substrings. Remove media payload
// bytes only from the text policy projection; retain the complete wire evidence.
fn text_projection(
    value: &mut Value,
    dialect: orbit_provider_http::request::HttpDialect,
    opaque: &[(usize, usize)],
) -> bool {
    use orbit_provider_http::request::HttpDialect;
    let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut) else {
        return false;
    };
    let mut unknown = false;
    for (message_index, message) in messages.iter_mut().enumerate() {
        let assistant = message.get("role").and_then(Value::as_str) == Some("assistant");
        if dialect == HttpDialect::Ollama
            && let Some(images) = message.get_mut("images").and_then(Value::as_array_mut)
        {
            unknown |= !images.is_empty();
            for image in images {
                *image = Value::String(String::new());
            }
        }
        let Some(parts) = message.get_mut("content").and_then(Value::as_array_mut) else {
            continue;
        };
        for (part_index, part) in parts.iter_mut().enumerate() {
            if assistant
                && dialect == HttpDialect::AnthropicMessages
                && opaque
                    .iter()
                    .any(|(index, count)| *index == message_index && part_index < *count)
            {
                unknown = true;
                *part = serde_json::json!({"type":"opaque"});
                continue;
            }
            match part.get("type").and_then(Value::as_str) {
                Some("image_url") if dialect == HttpDialect::OpenAiCompatible => {
                    unknown = true;
                    if let Some(url) = part.get_mut("image_url").and_then(|v| v.get_mut("url")) {
                        *url = Value::String(String::new());
                    }
                }
                Some("image") if dialect == HttpDialect::AnthropicMessages => {
                    unknown = true;
                    if let Some(data) = part.get_mut("source").and_then(|v| v.get_mut("data")) {
                        *data = Value::String(String::new());
                    }
                }
                Some("tool_result") if dialect == HttpDialect::AnthropicMessages => {
                    if let Some(parts) = part.get_mut("content").and_then(Value::as_array_mut) {
                        for image in parts {
                            if image.get("type").and_then(Value::as_str) == Some("image") {
                                unknown = true;
                                if let Some(data) =
                                    image.get_mut("source").and_then(|v| v.get_mut("data"))
                                {
                                    *data = Value::String(String::new());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    unknown
}

pub(crate) fn estimate_prepared_request(
    request: &PreparedProviderRequest,
    budget: &SelectedBudget,
) -> Result<RequestEstimate, BudgetError> {
    if request.binding_digest() != budget.identity.binding_digest {
        return Err(BudgetError::InvalidBinding);
    }
    let rendered = request.rendered_body().map_err(|_| BudgetError::Render)?;
    let bytes = serde_json::to_vec(rendered.as_json()).map_err(|_| BudgetError::Render)?;
    let body_bytes = u64::try_from(bytes.len()).map_err(|_| BudgetError::Arithmetic)?;
    let mut text = rendered.as_json().clone();
    let unknown = text_projection(&mut text, rendered.dialect(), &request.opaque_prefixes());
    let text_bytes = encoded_len(&text)?;
    let (system_bytes, tools_bytes, messages_bytes, framing_bytes) = components(&text)?;
    let (raw_system_bytes, raw_tools_bytes, raw_messages_bytes, raw_framing_bytes) =
        components(rendered.as_json())?;
    let estimated_input_tokens = (text_bytes / 4)
        .checked_add(u64::from(text_bytes % 4 != 0))
        .ok_or(BudgetError::Arithmetic)?;
    Ok(RequestEstimate {
        body_bytes,
        text_bytes,
        system_bytes,
        tools_bytes,
        messages_bytes,
        framing_bytes,
        raw_system_bytes,
        raw_tools_bytes,
        raw_messages_bytes,
        raw_framing_bytes,
        estimated_input_tokens,
        requested_output_tokens: rendered.output_cap().value,
        body_digest: hex::encode(Sha256::digest(bytes)),
        binding_digest: request.binding_digest().into(),
        status: if unknown {
            EstimateStatus::UnknownMedia
        } else {
            EstimateStatus::Approximate
        },
    })
}

pub fn assess_request(estimate: &RequestEstimate, budget: &SelectedBudget) -> BudgetDecision {
    if estimate.binding_digest != budget.identity.binding_digest {
        return BudgetDecision::Refuse;
    }
    let ceilings = budget.effective_ceilings();
    if ceilings
        .output_tokens
        .is_some_and(|n| estimate.requested_output_tokens > n)
    {
        return BudgetDecision::Refuse;
    }
    if estimate.status == EstimateStatus::UnknownMedia
        && budget.policy.media_policy == MediaPolicy::Refuse
    {
        return BudgetDecision::Refuse;
    }
    let combined = if ceilings.combined_tokens.is_some() {
        let Some(total) = estimate
            .estimated_input_tokens
            .checked_add(estimate.requested_output_tokens)
        else {
            return BudgetDecision::Refuse;
        };
        total
    } else {
        0
    };
    if ceilings
        .input_tokens
        .is_some_and(|n| estimate.estimated_input_tokens > n)
        || ceilings.combined_tokens.is_some_and(|n| combined > n)
    {
        return BudgetDecision::Compact;
    }
    if ceilings.input_tokens.is_none() && ceilings.combined_tokens.is_none() {
        return BudgetDecision::Unknown;
    }
    if budget
        .compaction_threshold(estimate.requested_output_tokens)
        .is_some_and(|threshold| estimate.estimated_input_tokens >= threshold)
    {
        BudgetDecision::Compact
    } else if estimate.status == EstimateStatus::UnknownMedia {
        BudgetDecision::AdmitUnknownMediaWithWarning
    } else {
        BudgetDecision::AdmitEstimated
    }
}

pub(crate) fn fits(estimate: &RequestEstimate, budget: &SelectedBudget) -> bool {
    let ceilings = budget.effective_ceilings();
    !matches!(
        assess_request(estimate, budget),
        BudgetDecision::Refuse | BudgetDecision::Unknown
    ) && ceilings
        .input_tokens
        .is_none_or(|n| estimate.estimated_input_tokens <= n)
        && ceilings.combined_tokens.is_none_or(|n| {
            estimate
                .estimated_input_tokens
                .checked_add(estimate.requested_output_tokens)
                .is_some_and(|total| total <= n)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{prepare_provider_request, request_preparation_context};
    use orbit_adapter::types::{ContentBlock, Sha256Digest, ToolDefinition};

    fn config(kind: crate::ProviderKind) -> TurnConfig {
        TurnConfig {
            provider_id: "fixture".into(),
            gate: "http://127.0.0.1:12345/tenant/v1?scope=exact".into(),
            model: "raw-model".into(),
            kind,
            credential_env: None,
            billing: None,
            pricing: None,
            max_output_tokens: 73,
            sampling: None,
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        }
    }
    fn prepare(
        config: &TurnConfig,
        system: Option<&str>,
        tools: &[ToolDefinition],
        messages: Vec<orbit_adapter::types::ChatMessage>,
    ) -> PreparedProviderRequest {
        let context = request_preparation_context(config, system, tools).unwrap();
        prepare_provider_request(
            &context,
            "fallback",
            Some(messages),
            "budget-test",
            "session",
        )
        .unwrap()
    }
    fn measure(
        config: &TurnConfig,
        prepared: &PreparedProviderRequest,
    ) -> (RequestEstimate, SelectedBudget) {
        let budget = SelectedBudget::legacy_input(config, 1000).unwrap();
        (
            estimate_prepared_request(prepared, &budget).unwrap(),
            budget,
        )
    }

    #[test]
    fn every_concrete_dialect_fingerprints_the_actual_body_and_selected_output() {
        for kind in [
            crate::ProviderKind::OpenAiCompatible,
            crate::ProviderKind::Anthropic,
            crate::ProviderKind::Ollama,
        ] {
            let config = config(kind);
            let prepared = prepare(
                &config,
                Some("system"),
                &[],
                vec![crate::user_message("question")],
            );
            let (estimate, _) = measure(&config, &prepared);
            let bytes = serde_json::to_vec(prepared.rendered_body().unwrap().as_json()).unwrap();
            assert_eq!(estimate.body_bytes, bytes.len() as u64);
            assert_eq!(estimate.body_digest, hex::encode(Sha256::digest(bytes)));
            assert_eq!(estimate.requested_output_tokens, 73);
            assert_eq!(
                estimate.text_bytes,
                estimate.system_bytes
                    + estimate.tools_bytes
                    + estimate.messages_bytes
                    + estimate.framing_bytes
            );
            assert_eq!(
                estimate.body_bytes,
                estimate.raw_system_bytes
                    + estimate.raw_tools_bytes
                    + estimate.raw_messages_bytes
                    + estimate.raw_framing_bytes
            );
            assert!(estimate.system_bytes > 0);
        }
    }

    #[test]
    fn immutable_directive_and_tool_schema_are_included_monotonically() {
        let config = config(crate::ProviderKind::OpenAiCompatible);
        let base = prepare(&config, None, &[], vec![crate::user_message("question")]);
        let tools = [ToolDefinition {
            name: "inspect".into(),
            description: "x".repeat(2000),
            parameters: serde_json::json!({"type":"object"}),
            schema_digest: Sha256Digest("digest".into()),
        }];
        let large = prepare(
            &config,
            Some(&"s".repeat(2000)),
            &tools,
            vec![crate::user_message("question")],
        );
        let (base, _) = measure(&config, &base);
        let (large, budget) = measure(&config, &large);
        assert!(large.body_bytes > base.body_bytes + 4000);
        assert!(large.system_bytes > 2000 && large.tools_bytes > 2000);
        assert!(!fits(&large, &budget));
    }

    #[test]
    fn flattened_alternatives_and_tool_result_fallback_are_not_double_counted() {
        let config = config(crate::ProviderKind::OpenAiCompatible);
        let mut user = crate::user_message("x".repeat(10000));
        user.blocks = Some(vec![ContentBlock::Text {
            text: "actual text".into(),
        }]);
        let mut result = crate::user_message("y".repeat(10000));
        result.role = orbit_adapter::types::ChatRole::Tool;
        result.tool_call_id = Some("call-1".into());
        result.tool_result = Some("actual result".into());
        let prepared = prepare(&config, None, &[], vec![user, result]);
        let (estimate, _) = measure(&config, &prepared);
        assert!(estimate.body_bytes < 500);
        assert_eq!(estimate.body_bytes, estimate.text_bytes);
    }

    #[test]
    fn input_combined_and_output_ceilings_are_independent() {
        let config = config(crate::ProviderKind::OpenAiCompatible);
        let prepared = prepare(&config, None, &[], vec![crate::user_message("question")]);
        let (mut estimate, mut budget) = measure(&config, &prepared);
        estimate.estimated_input_tokens = 800;
        estimate.requested_output_tokens = 300;
        budget.ceilings.input_tokens = Some(1000);
        assert!(fits(&estimate, &budget));
        budget.ceilings.combined_tokens = Some(1000);
        assert!(!fits(&estimate, &budget));
        budget.ceilings.combined_tokens = Some(1100);
        assert!(fits(&estimate, &budget));
        budget.ceilings.output_tokens = Some(299);
        assert_eq!(assess_request(&estimate, &budget), BudgetDecision::Refuse);
    }

    #[test]
    fn zero_allowance_and_combined_arithmetic_overflow_fail_closed() {
        let config = config(crate::ProviderKind::OpenAiCompatible);
        let prepared = prepare(&config, None, &[], vec![crate::user_message("question")]);
        let (mut estimate, mut budget) = measure(&config, &prepared);
        budget.ceilings.input_tokens = Some(0);
        assert!(!fits(&estimate, &budget));
        estimate.estimated_input_tokens = 1;
        estimate.requested_output_tokens = u64::MAX;
        budget.ceilings.input_tokens = Some(1000);
        assert!(
            fits(&estimate, &budget),
            "input-only policy does not invent a combined sum"
        );
        budget.ceilings.combined_tokens = Some(u64::MAX);
        assert_eq!(assess_request(&estimate, &budget), BudgetDecision::Refuse);
    }

    #[test]
    fn huge_images_remain_unknown_without_a_fictitious_base64_text_price() {
        for kind in [
            crate::ProviderKind::OpenAiCompatible,
            crate::ProviderKind::Anthropic,
            crate::ProviderKind::Ollama,
        ] {
            let config = config(kind);
            let mut user = crate::user_message("image question");
            user.blocks = Some(vec![
                ContentBlock::Text {
                    text: "image question".into(),
                },
                ContentBlock::Image {
                    data: "A".repeat(20000),
                    media_type: "image/png".into(),
                },
            ]);
            let prepared = prepare(&config, None, &[], vec![user]);
            let (estimate, mut budget) = measure(&config, &prepared);
            assert!(estimate.body_bytes > 20000 && estimate.text_bytes < 1000);
            assert!(estimate.raw_messages_bytes > estimate.messages_bytes + 19000);
            assert_eq!(estimate.status, EstimateStatus::UnknownMedia);
            assert_eq!(
                assess_request(&estimate, &budget),
                BudgetDecision::AdmitUnknownMediaWithWarning
            );
            budget.policy.media_policy = MediaPolicy::Refuse;
            assert_eq!(assess_request(&estimate, &budget), BudgetDecision::Refuse);
        }
    }

    #[test]
    fn unknown_media_does_not_authorize_known_text_overflow() {
        let config = config(crate::ProviderKind::OpenAiCompatible);
        let mut user = crate::user_message("image");
        user.blocks = Some(vec![
            ContentBlock::Text {
                text: "x".repeat(8000),
            },
            ContentBlock::Image {
                data: "AAAA".into(),
                media_type: "image/png".into(),
            },
        ]);
        let prepared = prepare(&config, None, &[], vec![user]);
        let (estimate, budget) = measure(&config, &prepared);
        assert_eq!(estimate.status, EstimateStatus::UnknownMedia);
        assert!(!fits(&estimate, &budget));
    }

    #[test]
    fn opaque_unknown_cost_matches_actual_replay_and_ignores_skipped_json() {
        let config = config(crate::ProviderKind::Anthropic);
        let mut assistant = crate::assistant_message("visible text");
        assistant.origin_provider = Some(config.provider_id.clone());
        assistant.origin_model = Some(config.model.clone());
        assistant.blocks = Some(vec![ContentBlock::Opaque {
            json: serde_json::json!({"type":"custom-native-block","data":"A".repeat(20000)})
                .to_string(),
        }]);
        let prepared = prepare(&config, None, &[], vec![assistant.clone()]);
        let (estimate, budget) = measure(&config, &prepared);
        assert!(estimate.body_bytes > 20000 && estimate.text_bytes < 1000);
        assert_eq!(
            assess_request(&estimate, &budget),
            BudgetDecision::AdmitUnknownMediaWithWarning
        );
        assistant.blocks = Some(vec![ContentBlock::Opaque {
            json: "malformed JSON".into(),
        }]);
        let prepared = prepare(&config, None, &[], vec![assistant]);
        let (estimate, _) = measure(&config, &prepared);
        assert_eq!(estimate.status, EstimateStatus::Approximate);
    }

    #[test]
    fn budget_identity_binds_exact_selection_and_refuses_foreign_reuse() {
        let original = config(crate::ProviderKind::OpenAiCompatible);
        let prepared = prepare(&original, None, &[], vec![crate::user_message("question")]);
        for change in 0..6 {
            let mut changed = original.clone();
            match change {
                0 => changed.provider_id = "other".into(),
                1 => changed.gate.push_str("&other=1"),
                2 => changed.model = "other".into(),
                3 => changed.credential_env = Some("OTHER_FIXTURE_KEY".into()),
                4 => changed.max_output_tokens += 1,
                _ => changed.kind = crate::ProviderKind::Anthropic,
            }
            let budget = SelectedBudget::legacy_input(&changed, 1000).unwrap();
            assert_eq!(
                estimate_prepared_request(&prepared, &budget).unwrap_err(),
                BudgetError::InvalidBinding
            );
        }
    }

    #[test]
    fn opaque_equal_to_ordinary_text_cannot_hide_known_text_overflow() {
        let config = config(crate::ProviderKind::Anthropic);
        let text = "known ordinary text ".repeat(500);
        let mut assistant = crate::assistant_message(text.clone());
        assistant.origin_provider = Some(config.provider_id.clone());
        assistant.origin_model = Some(config.model.clone());
        assistant.blocks = Some(vec![ContentBlock::Opaque {
            json: serde_json::json!({"type":"text","text":text}).to_string(),
        }]);
        let prepared = prepare(
            &config,
            None,
            &[],
            vec![crate::user_message("before"), assistant],
        );
        let (estimate, budget) = measure(&config, &prepared);
        assert_eq!(estimate.status, EstimateStatus::UnknownMedia);
        assert!(estimate.text_bytes > 9000);
        assert!(!fits(&estimate, &budget));
    }

    #[test]
    fn unknown_or_stale_facts_use_visible_policy_not_invented_fresh_limits() {
        let config = config(crate::ProviderKind::OpenAiCompatible);
        let prepared = prepare(&config, None, &[], vec![crate::user_message("question")]);
        let (estimate, mut budget) = measure(&config, &prepared);
        budget.ceilings = BudgetCeilings {
            input_tokens: Some(1),
            ..Default::default()
        };
        budget.source = BudgetSource::Discovered;
        budget.freshness = Freshness::Stale;
        assert_eq!(
            assess_request(&estimate, &budget),
            BudgetDecision::AdmitEstimated
        );
        budget.policy.unknown_text_policy = UnknownTextPolicy::RequireLimit;
        assert_eq!(assess_request(&estimate, &budget), BudgetDecision::Unknown);
        budget.source = BudgetSource::Explicit;
        budget.freshness = Freshness::Policy;
        assert!(!fits(&estimate, &budget));
    }

    #[test]
    fn meter_dual_ceilings_and_actual_output_share_the_admission_threshold() {
        let config = config(crate::ProviderKind::OpenAiCompatible);
        let prepared = prepare(&config, None, &[], vec![crate::user_message("question")]);
        let (mut estimate, mut budget) = measure(&config, &prepared);
        budget.ceilings = BudgetCeilings {
            input_tokens: Some(100_000),
            combined_tokens: Some(10_000),
            output_tokens: Some(1000),
        };
        estimate.requested_output_tokens = 1000;
        estimate.estimated_input_tokens = 7999;
        assert_eq!(
            assess_request(&estimate, &budget),
            BudgetDecision::AdmitEstimated
        );
        estimate.estimated_input_tokens = 8000;
        assert_eq!(assess_request(&estimate, &budget), BudgetDecision::Compact);
        assert_eq!(
            budget.meter_window(estimate.requested_output_tokens),
            (Some(10_000), 1000),
            "the combined ceiling binds despite a larger input ceiling"
        );

        budget.ceilings.input_tokens = Some(10_000);
        budget.ceilings.combined_tokens = Some(11_100);
        assert_eq!(budget.meter_window(1000), (Some(10_000), 0));
        assert_eq!(budget.compaction_threshold(1000), Some(8990));
        estimate.estimated_input_tokens = 8989;
        assert_eq!(
            assess_request(&estimate, &budget),
            BudgetDecision::AdmitEstimated
        );
        estimate.estimated_input_tokens = 8990;
        assert_eq!(assess_request(&estimate, &budget), BudgetDecision::Compact);

        budget.ceilings = BudgetCeilings {
            input_tokens: Some(u64::MAX),
            combined_tokens: Some(u64::MAX),
            output_tokens: None,
        };
        let maximum_threshold = ((u128::from(u64::MAX) * 9) / 10) as u64;
        assert_eq!(budget.compaction_threshold(0), Some(maximum_threshold));
        estimate.requested_output_tokens = 0;
        estimate.estimated_input_tokens = maximum_threshold - 1;
        assert_eq!(
            assess_request(&estimate, &budget),
            BudgetDecision::AdmitEstimated
        );
        estimate.estimated_input_tokens = maximum_threshold;
        assert_eq!(assess_request(&estimate, &budget), BudgetDecision::Compact);
    }
}

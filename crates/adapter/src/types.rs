//! DR-09 §2/§3 typed identifiers and request/result/stream surfaces.
//!
//! All identifiers are newtyped `String` (cheap clones, stable identity for
//! hashing). Sampling parameters are fixed-point integers — temperature in
//! milli-units, top-p in millionths — never floats across the persistence
//! boundary (DR-09 §3). Prompt/output bytes live in `SecretBytes` (see
//! `credential.rs`); they never appear in Ledger events (GW-25).

use serde::{Deserialize, Serialize};

/// A provider's exact reasoning control. Boolean toggles and named levels
/// remain distinct; neither is translated into a token budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EffortValue {
    Bool(bool),
    Level(String),
}

impl EffortValue {
    pub fn validate(&self) -> Result<(), String> {
        if let Self::Level(level) = self {
            if level.is_empty()
                || level.len() > 64
                || level.trim() != level
                || level.chars().any(char::is_control)
            {
                return Err("effort levels must contain 1–64 UTF-8 bytes, without surrounding whitespace or control characters".into());
            }
            if level == "default" {
                return Err(
                    "default resets the effort selection; it is not a provider effort level".into(),
                );
            }
        }
        Ok(())
    }

    pub fn validate_for_openai(&self) -> Result<(), String> {
        self.validate()?;
        match self {
            Self::Level(_) => Ok(()),
            Self::Bool(_) => {
                Err("OpenAI-compatible reasoning_effort requires a named level".into())
            }
        }
    }

    pub fn validate_for_anthropic(&self) -> Result<(), String> {
        self.validate()?;
        match self {
            Self::Level(level)
                if matches!(level.as_str(), "low" | "medium" | "high" | "xhigh" | "max") =>
            {
                Ok(())
            }
            _ => Err(
                "Anthropic output_config.effort requires low, medium, high, xhigh or max".into(),
            ),
        }
    }

    pub fn validate_for_ollama(&self) -> Result<(), String> {
        self.validate()
    }
}

impl std::fmt::Display for EffortValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(value) => write!(f, "{value}"),
            Self::Level(level) => f.write_str(level),
        }
    }
}

/// Selection provenance, separate from a resolved optional wire value.
/// An absent setting is legacy/unset; Default is an explicit reset.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", content = "value", rename_all = "snake_case")]
pub enum EffortSetting {
    #[default]
    Default,
    Value(EffortValue),
}

/// Stable SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Sha256Digest(pub String);

impl Sha256Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A flat provider identifier (DR-09 §2). Orchestrators never see this —
/// they name a flat `ModelRef` and the Gateway resolves the route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeploymentId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialRef(pub String);

/// ULID-shaped decision/attempt/request identifier (DR-09 §2). Stored as a
/// string for cross-system portability; the Gateway mints these.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecisionId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub String);

/// The four v0.1 adapter classes (DR-09 §1). `DeterministicTestV1` and
/// `MockHttpV1` are the only kinds shipped in the synchronous v0.1 kernel;
/// real async HTTP adapters are deferred to v0.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterKind {
    OpenAiCompatibleHttpV1,
    DeclarativeHttpJsonV1,
    LocalProcessV1,
    DeterministicTestV1,
    /// v0.1 synchronous mock of OpenAiCompatibleHttpV1 — exercises the full
    /// wire-format + redaction + sequence + cost path without an async runtime.
    MockHttpV1,
}

/// Adapter identity — implementation digest pins the code; profile digest
/// pins the signed route profile (DR-09 §3, GW-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterIdentity {
    pub kind: AdapterKind,
    pub implementation_digest: Sha256Digest,
    pub profile_digest: Sha256Digest,
}

/// Endpoint pin (DR-09 §2). The host/port/path/tls tuple is immutable per
/// call (GW-05); redirects cannot escape it (GW-23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointPin {
    pub scheme: EndpointScheme,
    pub host: String,
    pub port: u16,
    pub path_prefix: String,
    pub tls: TlsPinPolicy,
    pub proxy: Option<ProxyPin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EndpointScheme {
    #[default]
    Https,
    HttpLoopback,
    LocalProcess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPinPolicy {
    pub webpki: bool,
    /// Optional SPKI SHA-256 pin; if set, the peer cert chain must match.
    pub spki_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPin {
    pub host: String,
    pub port: u16,
}

/// What an adapter can do (DR-09 §2). Adapters refuse requests outside this.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub supports_json_schema_output: bool,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
}

/// The immutable route binding pinned per call (DR-09 §3). All digests are
/// SHA-256 hex; the tuple is the authority for `validate_route`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRouteBinding {
    pub provider_id: ProviderId,
    pub deployment_id: DeploymentId,
    pub region_id: RegionId,
    pub adapter_kind: AdapterKind,
    pub adapter_implementation_digest: Sha256Digest,
    pub adapter_profile_digest: Sha256Digest,
    pub endpoint_digest: Sha256Digest,
    pub expected_model: String,
    pub pricing_digest: Sha256Digest,
    /// P1-7 fix: the REAL endpoint host/port — the egress tuple must carry
    /// the actual destination, not a fabrication from the provider id.
    #[serde(default)]
    pub endpoint_host: String,
    #[serde(default = "default_https_port")]
    pub endpoint_port: u16,
    /// Endpoint scheme (v0.2). HttpLoopback is restricted to loopback HTTP;
    /// LocalProcess is not an HTTP transport.
    #[serde(default)]
    pub endpoint_scheme: EndpointScheme,
    /// Base path of the endpoint, from the configured gate URL. Empty means
    /// the historical default: `/v1` for the OpenAI-compatible and Anthropic
    /// adapters. The concrete Ollama adapter requires an explicit API base.
    /// A non-empty gate path (DashScope's
    /// `/compatible-mode/v1`, Z.ai's `/api/paas/v4`, Gemini's
    /// `/v1beta/openai`) is carried verbatim — the adapters append their
    /// method segment to it.
    #[serde(default)]
    pub endpoint_path: String,
    /// Exact canonical raw query, without `?`. Absence retains the serialized
    /// route payload used before queries were represented explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_query: Option<String>,
}

fn default_https_port() -> u16 {
    443
}

/// Fixed-point sampling (DR-09 §3). Temperature in milli-units (0-2000),
/// top-p in millionths (0-1_000_000). Never serialized as floats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingParameters {
    pub temperature_milliunits: u32,
    pub top_p_millionths: u32,
    pub max_output_tokens: u64,
}

impl SamplingParameters {
    /// Render to wire-format JSON numbers (milli/millionth). Never emits floats.
    pub fn to_wire(&self) -> serde_json::Value {
        serde_json::json!({
            "temperature_milliunits": self.temperature_milliunits,
            "top_p_millionths": self.top_p_millionths,
            "max_output_tokens": self.max_output_tokens,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputRequirements {
    Text,
    Json,
    JsonSchema { digest: Sha256Digest },
}

/// A tool definition sent to the provider (tool-calling phase). `schema_digest`
/// is preserved from the pre-tool spec; `description` + `parameters` carry the
/// OpenAI-compatible JSON schema that the model uses to emit calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema (serde Value) for the arguments object.
    pub parameters: serde_json::Value,
    /// SHA-256 of the serialized canonical definition (backwards-compatible).
    pub schema_digest: Sha256Digest,
}

/// Hashes/sizes only — no prompt bytes (DR-09 §3, GW-25).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub input_sha256: Sha256Digest,
    pub input_bytes: u64,
    pub tools_count: u32,
}

/// One structured piece of a message's content (roadmap §Providers).
///
/// The block model is the structured truth for providers that speak it
/// (Anthropic); `ChatMessage.content` stays as the flattened text every
/// other consumer already reads. Adapters that support blocks map them
/// to their own wire format; adapters that do not use `content` and
/// drop the blocks (thinking never round-trips through OpenAI-compatible).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    Image {
        /// Base64-encoded image bytes (the adapter adds source media type).
        data: String,
        #[serde(default = "default_image_media_type")]
        media_type: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: String,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_error: bool,
    },
    /// Opaque provider-native blocks (thinking, redacted thinking,
    /// compaction) — stored and replayed unchanged, never displayed,
    /// never sent to a provider that did not produce them.
    Opaque {
        /// The provider-native JSON, verbatim.
        json: String,
    },
}

fn default_image_media_type() -> String {
    "image/png".into()
}

impl ContentBlock {
    /// The flattened text of this block (empty for images and opaque).
    pub fn text(&self) -> &str {
        match self {
            ContentBlock::Text { text } => text,
            _ => "",
        }
    }
}

/// One turn of a multi-turn conversation transcript (DR-09 §3 extension).
/// Roles mirror the OpenAI-compatible wire set: `system` | `user` | `assistant`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    /// Structured content blocks (phase 2). `None` for every message the
    /// pre-blocks code produced — old session files parse unchanged. When
    /// present, providers that speak blocks use these and ignore `content`
    /// (which still carries the flattened text for display and cost).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<ContentBlock>>,
    /// Tool-call metadata for assistant messages (tool-calling phase).
    /// `None` for plain user/system/assistant text messages (backwards-compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallMessage>>,
    /// Tool-result metadata for a `tool` role message.
    /// `None` for plain messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Raw arguments JSON string for a `tool` role message (already validated
    /// and recorded; the model may receive the sanitized result only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_result: Option<String>,
    /// Which model produced this assistant message (routing, 2026-10-10).
    /// Opaque blocks (thinking, redacted thinking) are model-bound: a
    /// provider rejects another model's signatures. Difficulty routing
    /// uses this to strip foreign thinking before a switched-model
    /// dispatch instead of failing the request. `None` on pre-routing
    /// messages — treated as unknown origin by the stripper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_model: Option<String>,
    /// The exact configured provider that produced opaque assistant blocks.
    /// Absent on older history; raw model equality alone cannot establish that
    /// a signed block belongs to the selected provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_provider: Option<String>,
}

/// A tool call inside an assistant message (OpenAI-compatible wire shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallMessage {
    pub id: String,
    pub name: String,
    /// JSON-encoded arguments (validated JSON, possibly redacted before sending).
    pub arguments: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

impl ChatRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

/// A provider request (DR-09 §3). `input` is SecretBytes (zeroize-on-drop);
/// the adapter borrows it for the call duration only.
/// Not Clone / Serialize — the prompt bytes must never be duplicated into a
/// second sink (GW-25).
#[derive(Debug)]
pub struct ProviderRequest {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub decision_id: DecisionId,
    pub attempt_id: AttemptId,
    pub route: ProviderRouteBinding,
    /// The actual prompt bytes, zeroized on drop. The adapter borrows these
    /// at the final wire boundary — never the metadata hash.
    pub input: crate::credential::SecretBytes,
    /// Multi-turn transcript. `None` (default) keeps the single-turn contract:
    /// the adapter sends `[{role:"user", content: input}]`. `Some(transcript)`
    /// sends the full conversation (the final user turn's bytes are still
    /// `input` for hashing/zeroization; the transcript is the wire payload).
    pub messages: Option<Vec<ChatMessage>>,
    /// Omission retains the provider's existing default request controls.
    pub effort: Option<EffortValue>,
    pub sampling: SamplingParameters,
    pub output: OutputRequirements,
    pub tools: Vec<ToolDefinition>,
    pub metadata: RequestMetadata,
    /// Connection establishment budget, enforced concurrently with response start.
    /// This does not limit healthy waiting for response headers on an established connection.
    pub connect_timeout_ms: u64,
    /// One absolute deadline from the actual HTTP send to the first response body byte.
    /// Headers do not reset it; delayed stream polling consumes the same budget.
    /// Non-success headers begin the separate bounded error-body phase.
    pub first_byte_timeout_ms: u64,
    /// Max gap between stream chunks (E5). A stream may run as long
    /// as it keeps producing bytes; a silent gap longer than this is
    /// a stalled stream and fails as a retryable timeout.
    pub idle_timeout_ms: u64,
}

/// Terminal status of a provider call (DR-09 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderTerminalStatus {
    Completed,
    Cancelled,
    Timeout,
    Partial,
    Failed,
}

/// Token usage (DR-09 §8). All fields are `u64`; cache read/write are
/// distinct non-overlapping categories (GW-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProviderUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
}

/// Whether the usage figure is final, incremental, or missing (DR-09 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsageSource {
    Final,
    Incremental,
    Missing,
}

/// Cost rates per category (DR-09 §8). Microcents per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostRates {
    pub input_per_million_microcents: u64,
    pub output_per_million_microcents: u64,
    pub cache_read_per_million_microcents: Option<u64>,
    pub cache_write_per_million_microcents: Option<u64>,
    pub reasoning_per_million_microcents: Option<u64>,
    pub request_flat_microcents: u64,
}

impl CostRates {
    /// Integer cost: `ceil(tokens × rate / 1_000_000)` per category, checked
    /// u128 → checked u64 (DR-09 §8, GW-14). Returns `None` on overflow.
    pub fn cost_microcents(&self, usage: &ProviderUsage) -> Option<u64> {
        let mut total: u128 = self.request_flat_microcents as u128;
        for (tokens, rate) in [
            (usage.input_tokens, Some(self.input_per_million_microcents)),
            (
                usage.output_tokens,
                Some(self.output_per_million_microcents),
            ),
            (
                usage.cache_read_tokens,
                self.cache_read_per_million_microcents,
            ),
            (
                usage.cache_write_tokens,
                self.cache_write_per_million_microcents,
            ),
            (
                usage.reasoning_tokens,
                self.reasoning_per_million_microcents,
            ),
        ] {
            // A missing rate only makes cost incomplete when that category has
            // non-zero tokens. Zero-token optional categories must not poison
            // otherwise complete input/output pricing.
            if tokens == 0 {
                continue;
            }
            let r = rate?; // missing rate for a non-zero category → None (honest incomplete cost)
            // ceil(tokens × rate / 1_000_000)
            let prod = (tokens as u128).checked_mul(r as u128)?;
            let q = prod / 1_000_000;
            let rem = prod % 1_000_000;
            let cat = if rem > 0 { q + 1 } else { q };
            total = total.checked_add(cat)?;
        }
        u64::try_from(total).ok()
    }
}

/// Numeric reasoning-detail presence in this exact event snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReasoningReportingV1 {
    Reported,
    NotReported,
}

/// Origin of observed numbers, independently of terminal placement or billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSnapshotOriginV1 {
    ProviderReported,
    Synthetic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UsageObservationMetaV1 {
    pub version: u16,
    pub reasoning_reporting: UsageReasoningReportingV1,
    pub snapshot_origin: UsageSnapshotOriginV1,
}

impl<'de> Deserialize<'de> for UsageObservationMetaV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            version: u16,
            reasoning_reporting: UsageReasoningReportingV1,
            snapshot_origin: UsageSnapshotOriginV1,
        }
        let fields = Fields::deserialize(deserializer)?;
        if fields.version != 1 {
            return Err(serde::de::Error::custom(
                "unsupported usage observation version",
            ));
        }
        Ok(Self {
            version: fields.version,
            reasoning_reporting: fields.reasoning_reporting,
            snapshot_origin: fields.snapshot_origin,
        })
    }
}

fn deserialize_present_usage_observation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<UsageObservationMetaV1>, D::Error> {
    // This function runs only for a supplied field: null is not legacy absence.
    UsageObservationMetaV1::deserialize(deserializer).map(Some)
}

/// Distinct identity for the explicitly encoded usage-observation fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UsageObservationDigestV1(pub String);

impl UsageObservationDigestV1 {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReportingPresenceV1 {
    Reported,
    NotReported,
    LegacyUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageObservationOriginV1 {
    ProviderReported,
    Synthetic,
    LegacyUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageObservationSnapshotV1 {
    pub sequence: u64,
    pub raw_usage: ProviderUsage,
    pub source: UsageSource,
    pub reasoning_reporting: UsageReportingPresenceV1,
    pub snapshot_origin: UsageObservationOriginV1,
}

/// Exact reason classification; it does not certify completed content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageObservationDispositionV1 {
    NoTerminal,
    CompleteText,
    CompleteTools,
    Cancelled,
    IncompleteOrOther,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageObservationQualificationV1 {
    CancelledTerminalSnapshot,
    ProviderReportedTerminalSnapshot,
    SyntheticTerminalSnapshot,
    LegacyTerminalSnapshot,
    ProvisionalSnapshot,
    MissingSnapshot,
}

/// Inert inspection data, never a receipt, invoice, or dispatch capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageObservationEvidenceV1 {
    pub encoding_version: u16,
    pub digest: UsageObservationDigestV1,
    pub selected: Option<UsageObservationSnapshotV1>,
    pub disposition: UsageObservationDispositionV1,
    pub qualification: UsageObservationQualificationV1,
}

/// One stream event (DR-09 §4). Sequence starts at 0, increments by 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStreamEvent {
    pub sequence: u64,
    pub event: ProviderEventKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_usage_observation"
    )]
    pub usage_observation: Option<UsageObservationMetaV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderEventKind {
    ResponseStarted {
        upstream_request_id: Option<String>,
    },
    TextDelta {
        bytes: Vec<u8>,
    },
    /// A reasoning/thinking delta (Anthropic thinking blocks, others'
    /// equivalents). Assembled into an opaque block for replay — never
    /// surfaced as display text (CoT defense), never sent to a provider
    /// that did not produce it.
    ThinkingDelta {
        bytes: Vec<u8>,
    },
    /// A signature delta for the thinking block (Anthropic
    /// `signature_delta`). Assembled with ThinkingDelta into the same
    /// opaque replay block; never surfaced as display text, never
    /// counted as delivered output.
    ThinkingSignatureDelta {
        bytes: Vec<u8>,
    },
    ToolCallStarted {
        call_index: u32,
        provider_call_id: Option<String>,
        name: String,
    },
    ToolCallArgumentsDelta {
        call_index: u32,
        bytes: Vec<u8>,
    },
    ToolCallFinished {
        call_index: u32,
    },
    UsageUpdate(ProviderUsage),
    Finished {
        finish_reason: Option<String>,
        final_usage: Option<ProviderUsage>,
    },
}

/// Drift observation (DR-09 §4, GW-18). Evidence only — never changes the
/// terminal status and never triggers rerouting.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DriftObservation {
    pub observed_model: Option<String>,
    pub note: Option<String>,
}

/// Binding result — what the route resolved to + any drift (DR-09 §4).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProviderBindingResult {
    pub expected_model: Option<String>,
    pub drift: Vec<DriftObservation>,
}

/// Output evidence — two hashes (DR-09 §4): raw stream + canonical output.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OutputEvidence {
    pub raw_stream_sha256: Sha256Digest,
    pub canonical_output_sha256: Sha256Digest,
    pub observed_bytes: u64,
    pub delivered_bytes: u64,
}

/// Accounting result — integer cost (DR-09 §8, GW-14).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccountingResult {
    pub cost_microcents: u64,
    pub currency: Option<String>,
    pub usage: ProviderUsage,
    pub usage_source: Option<UsageSource>,
    pub usage_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_observation: Option<Box<UsageObservationEvidenceV1>>,
}

/// Transport result — timing + attempt count (DR-09 §4).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TransportResult {
    pub attempt_count: u8,
    pub connect_ms: u64,
    pub first_byte_ms: u64,
    pub total_ms: u64,
    pub partial: bool,
}

/// The terminal result of a provider invocation (DR-09 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderResult {
    pub status: ProviderTerminalStatus,
    pub binding: ProviderBindingResult,
    pub output: OutputEvidence,
    pub accounting: AccountingResult,
    pub transport: TransportResult,
    pub events: Vec<ProviderStreamEvent>,
}

impl ProviderResult {
    /// Build the canonical "all-good" result for a fixture.
    pub fn completed(
        events: Vec<ProviderStreamEvent>,
        usage: ProviderUsage,
        cost_microcents: u64,
        output: OutputEvidence,
    ) -> Self {
        Self {
            status: ProviderTerminalStatus::Completed,
            binding: ProviderBindingResult::default(),
            output,
            accounting: AccountingResult {
                cost_microcents,
                usage,
                usage_source: Some(UsageSource::Final),
                usage_complete: true,
                ..Default::default()
            },
            transport: TransportResult::default(),
            events,
        }
    }
}

/// Whether prices were explicitly declared, absent, or retained from legacy input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingDeclarationState {
    Absent,
    LegacyFields,
    LegacyZeroUnverified,
    DeclaredV2,
}

/// Presence-aware prices. Numeric zero is a declared price, not missing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingRatesV1 {
    pub input_per_million_microdollars: Option<u64>,
    pub output_per_million_microdollars: Option<u64>,
    pub cache_read_per_million_microdollars: Option<u64>,
    pub cache_write_per_million_microdollars: Option<u64>,
    pub reasoning_per_million_microdollars: Option<u64>,
    pub request_flat_microdollars: Option<u64>,
}

impl BillingRatesV1 {
    fn ordered_values(&self) -> [Option<u64>; 6] {
        [
            self.input_per_million_microdollars,
            self.output_per_million_microdollars,
            self.cache_read_per_million_microdollars,
            self.cache_write_per_million_microdollars,
            self.reasoning_per_million_microdollars,
            self.request_flat_microdollars,
        ]
    }
}

/// Relationship between the two observed counters, not a parser inequality.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningCounterBasis {
    #[default]
    Unknown,
    IncludedInOutput,
    SeparateFromOutput,
}

/// Explicit rate selection; a missing dedicated rate never implies inheritance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningRatePolicy {
    #[default]
    Unknown,
    OutputRate,
    DedicatedRate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingContractError {
    EmptyIdentity,
    IdentityTooLong,
    ControlCharacterIdentity,
    InconsistentDeclaration,
}

impl std::fmt::Display for BillingContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EmptyIdentity => "billing identity must not be empty",
            Self::IdentityTooLong => "billing identity exceeds 4096 UTF-8 bytes",
            Self::ControlCharacterIdentity => "billing identity contains a control character",
            Self::InconsistentDeclaration => "billing declaration contradicts its supplied fields",
        })
    }
}

impl std::error::Error for BillingContractError {}

/// Immutable arithmetic contract. This identity is not a route or budget grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingQuoteContractV1 {
    provider_id: ProviderId,
    raw_model_id: ModelId,
    declaration: PricingDeclarationState,
    rates: BillingRatesV1,
    reasoning_counter_basis: ReasoningCounterBasis,
    reasoning_rate_policy: ReasoningRatePolicy,
    max_reasoning_tokens: Option<u64>,
}

impl BillingQuoteContractV1 {
    pub fn try_new(
        provider_id: ProviderId,
        raw_model_id: ModelId,
        declaration: PricingDeclarationState,
        rates: BillingRatesV1,
        basis: ReasoningCounterBasis,
        policy: ReasoningRatePolicy,
    ) -> Result<Self, BillingContractError> {
        Self::try_new_with_reasoning_bound(
            provider_id,
            raw_model_id,
            declaration,
            rates,
            basis,
            policy,
            None,
        )
    }

    pub fn try_new_with_reasoning_bound(
        provider_id: ProviderId,
        raw_model_id: ModelId,
        declaration: PricingDeclarationState,
        rates: BillingRatesV1,
        basis: ReasoningCounterBasis,
        policy: ReasoningRatePolicy,
        max_reasoning_tokens: Option<u64>,
    ) -> Result<Self, BillingContractError> {
        for identity in [&provider_id.0, &raw_model_id.0] {
            if identity.is_empty() {
                return Err(BillingContractError::EmptyIdentity);
            }
            if identity.len() > 4096 {
                return Err(BillingContractError::IdentityTooLong);
            }
            if identity.chars().any(char::is_control) {
                return Err(BillingContractError::ControlCharacterIdentity);
            }
        }
        let values = rates.ordered_values();
        let supplied = values.iter().any(Option::is_some);
        let nonzero = values.iter().flatten().any(|value| *value != 0);
        let unknown_axes =
            basis == ReasoningCounterBasis::Unknown && policy == ReasoningRatePolicy::Unknown;
        let consistent = match declaration {
            PricingDeclarationState::Absent => {
                !supplied && unknown_axes && max_reasoning_tokens.is_none()
            }
            PricingDeclarationState::LegacyFields => {
                nonzero && unknown_axes && max_reasoning_tokens.is_none()
            }
            PricingDeclarationState::LegacyZeroUnverified => {
                supplied && !nonzero && unknown_axes && max_reasoning_tokens.is_none()
            }
            // Preserve exactly what a V2 block declared, including partial
            // terms. Consumers decide whether those terms suffice for admission
            // or a complete quote.
            PricingDeclarationState::DeclaredV2 => true,
        };
        if !consistent {
            return Err(BillingContractError::InconsistentDeclaration);
        }
        Ok(Self {
            provider_id,
            raw_model_id,
            declaration,
            rates,
            reasoning_counter_basis: basis,
            reasoning_rate_policy: policy,
            max_reasoning_tokens,
        })
    }

    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub fn raw_model_id(&self) -> &ModelId {
        &self.raw_model_id
    }

    pub fn declaration(&self) -> PricingDeclarationState {
        self.declaration
    }

    pub fn rates(&self) -> &BillingRatesV1 {
        &self.rates
    }

    pub fn reasoning_counter_basis(&self) -> ReasoningCounterBasis {
        self.reasoning_counter_basis
    }

    pub fn reasoning_rate_policy(&self) -> ReasoningRatePolicy {
        self.reasoning_rate_policy
    }

    pub fn max_reasoning_tokens(&self) -> Option<u64> {
        self.max_reasoning_tokens
    }

    /// Canonical kernel identity: fixed version/order, explicit numeric presence.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = b"orbit-billing-quote-contract-v1\0".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        for identity in [&self.provider_id.0, &self.raw_model_id.0] {
            let length = u32::try_from(identity.len()).expect("validated billing identity length");
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(identity.as_bytes());
        }
        bytes.push(match self.declaration {
            PricingDeclarationState::Absent => 0,
            PricingDeclarationState::LegacyFields => 1,
            PricingDeclarationState::LegacyZeroUnverified => 2,
            PricingDeclarationState::DeclaredV2 => 3,
        });
        bytes.push(match self.reasoning_counter_basis {
            ReasoningCounterBasis::Unknown => 0,
            ReasoningCounterBasis::IncludedInOutput => 1,
            ReasoningCounterBasis::SeparateFromOutput => 2,
        });
        bytes.push(match self.reasoning_rate_policy {
            ReasoningRatePolicy::Unknown => 0,
            ReasoningRatePolicy::OutputRate => 1,
            ReasoningRatePolicy::DedicatedRate => 2,
        });
        for rate in self.rates.ordered_values() {
            match rate {
                None => bytes.push(0),
                Some(value) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&value.to_be_bytes());
                }
            }
        }
        match self.max_reasoning_tokens {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        bytes
    }

    pub fn digest(&self) -> Sha256Digest {
        use sha2::Digest as _;
        Sha256Digest(hex::encode(sha2::Sha256::digest(self.canonical_bytes())))
    }
}

/// Reporting presence belongs to this snapshot; it does not establish finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningReporting {
    Reported,
    NotReported,
    LegacyUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingObservedUsageV1 {
    pub raw_usage: ProviderUsage,
    pub reasoning_reporting: ReasoningReporting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillableTokenGroupV1 {
    Input,
    CacheRead,
    CacheWrite,
    Output,
    OutputAndReasoning,
    Reasoning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingGroupQuoteV1 {
    pub group: BillableTokenGroupV1,
    pub tokens: u128,
    pub rate_per_million_microdollars: Option<u64>,
    pub cost_microdollars: Option<u128>,
}

/// Declaration order is the stable diagnostic category order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BillingRateCategory {
    Input,
    Output,
    CacheRead,
    CacheWrite,
    Reasoning,
    RequestFlat,
}

/// Bounded typed reasons, sorted by declaration order and deduplicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BillingUnknownReason {
    PricingAbsent,
    LegacyZeroUnverified,
    ReasoningNotReported,
    UnknownCounterBasis,
    UnknownRatePolicy,
    CounterContractMismatch,
    MissingRate(BillingRateCategory),
    ArithmeticOverflow,
}

/// Local arithmetic only; neither amount conveys live admission or settlement authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedBillingQuoteV1 {
    pub contract_encoding_version: u16,
    pub contract_digest: Sha256Digest,
    pub observed: BillingObservedUsageV1,
    pub groups: Vec<BillingGroupQuoteV1>,
    pub request_flat_microdollars: Option<u64>,
    pub full_total_microdollars: Option<u64>,
    pub independent_subtotal_microdollars: Option<u64>,
    pub unknown_reasons: Vec<BillingUnknownReason>,
}

fn billing_push_group(
    quote: &mut QualifiedBillingQuoteV1,
    group: BillableTokenGroupV1,
    category: BillingRateCategory,
    tokens: u128,
    rate: Option<u64>,
) {
    let cost = if tokens == 0 {
        Some(0)
    } else if let Some(rate) = rate {
        let cost = tokens.checked_mul(u128::from(rate)).and_then(|product| {
            let quotient = product / 1_000_000;
            quotient.checked_add(u128::from(product % 1_000_000 != 0))
        });
        if cost.is_none() {
            quote
                .unknown_reasons
                .push(BillingUnknownReason::ArithmeticOverflow);
        }
        cost
    } else {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::MissingRate(category));
        None
    };
    quote.groups.push(BillingGroupQuoteV1 {
        group,
        tokens,
        rate_per_million_microdollars: rate,
        cost_microdollars: cost,
    });
}

/// Quote supplied observed counters without modifying them or asserting finality.
pub fn quote_observed_billing(
    contract: &BillingQuoteContractV1,
    observed: &BillingObservedUsageV1,
) -> QualifiedBillingQuoteV1 {
    let mut quote = QualifiedBillingQuoteV1 {
        contract_encoding_version: 1,
        contract_digest: contract.digest(),
        observed: *observed,
        groups: Vec::new(),
        request_flat_microdollars: contract.rates.request_flat_microdollars,
        full_total_microdollars: None,
        independent_subtotal_microdollars: None,
        unknown_reasons: Vec::new(),
    };
    match contract.declaration {
        PricingDeclarationState::Absent => {
            quote
                .unknown_reasons
                .push(BillingUnknownReason::PricingAbsent);
            return quote;
        }
        PricingDeclarationState::LegacyZeroUnverified => {
            quote
                .unknown_reasons
                .push(BillingUnknownReason::LegacyZeroUnverified);
            return quote;
        }
        PricingDeclarationState::LegacyFields | PricingDeclarationState::DeclaredV2 => {}
    }
    let usage = observed.raw_usage;
    let rates = contract.rates;
    for (group, category, tokens, rate) in [
        (
            BillableTokenGroupV1::Input,
            BillingRateCategory::Input,
            usage.input_tokens,
            rates.input_per_million_microdollars,
        ),
        (
            BillableTokenGroupV1::CacheRead,
            BillingRateCategory::CacheRead,
            usage.cache_read_tokens,
            rates.cache_read_per_million_microdollars,
        ),
        (
            BillableTokenGroupV1::CacheWrite,
            BillingRateCategory::CacheWrite,
            usage.cache_write_tokens,
            rates.cache_write_per_million_microdollars,
        ),
    ] {
        billing_push_group(&mut quote, group, category, u128::from(tokens), rate);
    }
    let basis = contract.reasoning_counter_basis;
    let policy = contract.reasoning_rate_policy;
    let reported = observed.reasoning_reporting == ReasoningReporting::Reported;
    let reported_zero = reported && usage.reasoning_tokens == 0;
    let inherited_included = basis == ReasoningCounterBasis::IncludedInOutput
        && policy == ReasoningRatePolicy::OutputRate;
    let mismatch = (observed.reasoning_reporting == ReasoningReporting::NotReported
        && usage.reasoning_tokens != 0)
        || (reported
            && basis == ReasoningCounterBasis::IncludedInOutput
            && usage.reasoning_tokens > usage.output_tokens);
    let mut output_resolved = !mismatch;
    if mismatch {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::CounterContractMismatch);
    }
    if !reported && !inherited_included && !mismatch {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::ReasoningNotReported);
        output_resolved = false;
    }
    if basis == ReasoningCounterBasis::Unknown {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::UnknownCounterBasis);
        output_resolved = false;
    }
    if policy == ReasoningRatePolicy::Unknown {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::UnknownRatePolicy);
        output_resolved = false;
    }
    // A dedicated-rate declaration is incomplete until that rate is explicit,
    // even when this particular request reports zero reasoning tokens. The
    // independent subtotal can still include categories whose charges are
    // fully known, but a zero observation must not validate the price contract.
    if policy == ReasoningRatePolicy::DedicatedRate
        && rates.reasoning_per_million_microdollars.is_none()
    {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::MissingRate(
                BillingRateCategory::Reasoning,
            ));
    }
    if output_resolved {
        let output = u128::from(usage.output_tokens);
        let reasoning = u128::from(usage.reasoning_tokens);
        if reported_zero || inherited_included {
            billing_push_group(
                &mut quote,
                BillableTokenGroupV1::Output,
                BillingRateCategory::Output,
                output,
                rates.output_per_million_microdollars,
            );
        } else {
            match (basis, policy) {
                (ReasoningCounterBasis::IncludedInOutput, ReasoningRatePolicy::DedicatedRate) => {
                    if let Some(visible) = output.checked_sub(reasoning) {
                        billing_push_group(
                            &mut quote,
                            BillableTokenGroupV1::Output,
                            BillingRateCategory::Output,
                            visible,
                            rates.output_per_million_microdollars,
                        );
                        billing_push_group(
                            &mut quote,
                            BillableTokenGroupV1::Reasoning,
                            BillingRateCategory::Reasoning,
                            reasoning,
                            rates.reasoning_per_million_microdollars,
                        );
                    } else {
                        quote
                            .unknown_reasons
                            .push(BillingUnknownReason::CounterContractMismatch);
                    }
                }
                (ReasoningCounterBasis::SeparateFromOutput, ReasoningRatePolicy::OutputRate) => {
                    if let Some(combined) = output.checked_add(reasoning) {
                        billing_push_group(
                            &mut quote,
                            BillableTokenGroupV1::OutputAndReasoning,
                            BillingRateCategory::Output,
                            combined,
                            rates.output_per_million_microdollars,
                        );
                    } else {
                        quote
                            .unknown_reasons
                            .push(BillingUnknownReason::ArithmeticOverflow);
                    }
                }
                (ReasoningCounterBasis::SeparateFromOutput, ReasoningRatePolicy::DedicatedRate) => {
                    billing_push_group(
                        &mut quote,
                        BillableTokenGroupV1::Output,
                        BillingRateCategory::Output,
                        output,
                        rates.output_per_million_microdollars,
                    );
                    billing_push_group(
                        &mut quote,
                        BillableTokenGroupV1::Reasoning,
                        BillingRateCategory::Reasoning,
                        reasoning,
                        rates.reasoning_per_million_microdollars,
                    );
                }
                // Unknown axes were qualified above; the included inherited case has one group.
                _ => {}
            }
        }
    }
    if rates.request_flat_microdollars.is_none() {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::MissingRate(
                BillingRateCategory::RequestFlat,
            ));
    }
    let known = quote
        .groups
        .iter()
        .filter_map(|group| group.cost_microdollars)
        .try_fold(
            u128::from(rates.request_flat_microdollars.unwrap_or(0)),
            |total, amount| total.checked_add(amount),
        );
    quote.independent_subtotal_microdollars = known.and_then(|total| u64::try_from(total).ok());
    if quote.independent_subtotal_microdollars.is_none() {
        quote
            .unknown_reasons
            .push(BillingUnknownReason::ArithmeticOverflow);
    }
    quote.unknown_reasons.sort_unstable();
    quote.unknown_reasons.dedup();
    if quote.unknown_reasons.is_empty() {
        quote.full_total_microdollars = quote.independent_subtotal_microdollars;
    }
    quote
}

#[cfg(test)]
mod billing_kernel_tests {
    use super::*;

    fn rates() -> BillingRatesV1 {
        BillingRatesV1 {
            input_per_million_microdollars: Some(1_000_000),
            output_per_million_microdollars: Some(1_000_000),
            cache_read_per_million_microdollars: None,
            cache_write_per_million_microdollars: None,
            reasoning_per_million_microdollars: Some(2_000_000),
            request_flat_microdollars: Some(0),
        }
    }

    fn empty_rates() -> BillingRatesV1 {
        BillingRatesV1 {
            input_per_million_microdollars: None,
            output_per_million_microdollars: None,
            cache_read_per_million_microdollars: None,
            cache_write_per_million_microdollars: None,
            reasoning_per_million_microdollars: None,
            request_flat_microdollars: None,
        }
    }

    fn make_contract(
        declaration: PricingDeclarationState,
        prices: BillingRatesV1,
        basis: ReasoningCounterBasis,
        policy: ReasoningRatePolicy,
    ) -> BillingQuoteContractV1 {
        BillingQuoteContractV1::try_new(
            ProviderId("fixture-provider".into()),
            ModelId("fixture/model:α".into()),
            declaration,
            prices,
            basis,
            policy,
        )
        .unwrap()
    }

    fn declared(
        basis: ReasoningCounterBasis,
        policy: ReasoningRatePolicy,
    ) -> BillingQuoteContractV1 {
        make_contract(PricingDeclarationState::DeclaredV2, rates(), basis, policy)
    }

    fn observed(usage: ProviderUsage, reporting: ReasoningReporting) -> BillingObservedUsageV1 {
        BillingObservedUsageV1 {
            raw_usage: usage,
            reasoning_reporting: reporting,
        }
    }

    fn fixture() -> ProviderUsage {
        ProviderUsage {
            input_tokens: 10,
            output_tokens: 100,
            reasoning_tokens: 40,
            ..ProviderUsage::default()
        }
    }

    fn assert_amounts(quote: &QualifiedBillingQuoteV1, full: Option<u64>, subtotal: Option<u64>) {
        assert_eq!(quote.full_total_microdollars, full);
        assert_eq!(quote.independent_subtotal_microdollars, subtotal);
    }

    #[test]
    fn billing_quote_four_reasoning_contracts() {
        for (basis, policy, amount) in [
            (
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::OutputRate,
                110,
            ),
            (
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::DedicatedRate,
                150,
            ),
            (
                ReasoningCounterBasis::SeparateFromOutput,
                ReasoningRatePolicy::OutputRate,
                150,
            ),
            (
                ReasoningCounterBasis::SeparateFromOutput,
                ReasoningRatePolicy::DedicatedRate,
                190,
            ),
        ] {
            let input = observed(fixture(), ReasoningReporting::Reported);
            let quote = quote_observed_billing(&declared(basis, policy), &input);
            assert_amounts(&quote, Some(amount), Some(amount));
            assert!(quote.unknown_reasons.is_empty());
            assert_eq!(quote.observed, input);
            assert_eq!(quote.contract_encoding_version, 1);
        }
    }

    #[test]
    fn billing_quote_raw_counters_unchanged() {
        let mut prices = rates();
        prices.cache_read_per_million_microdollars = Some(1_000_000);
        prices.cache_write_per_million_microdollars = Some(1_000_000);
        let raw = ProviderUsage {
            input_tokens: 11,
            output_tokens: 22,
            cache_read_tokens: 33,
            cache_write_tokens: 44,
            reasoning_tokens: 5,
        };
        for (basis, policy, reporting) in [
            (
                ReasoningCounterBasis::SeparateFromOutput,
                ReasoningRatePolicy::DedicatedRate,
                ReasoningReporting::Reported,
            ),
            (
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
                ReasoningReporting::Reported,
            ),
            (
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::OutputRate,
                ReasoningReporting::NotReported,
            ),
        ] {
            let contract =
                make_contract(PricingDeclarationState::DeclaredV2, prices, basis, policy);
            let input = observed(raw, reporting);
            let quote = quote_observed_billing(&contract, &input);
            assert_eq!(quote.observed, input);
            assert_eq!(input.raw_usage, raw);
            assert_eq!(quote.observed.raw_usage, raw);
            if reporting == ReasoningReporting::NotReported {
                assert_eq!(
                    quote.unknown_reasons,
                    vec![BillingUnknownReason::CounterContractMismatch]
                );
            }
        }
    }

    #[test]
    fn billing_contract_canonical_golden() {
        let contract = declared(
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::DedicatedRate,
        );
        let expected = hex::decode(concat!(
            "6f726269742d62696c6c696e672d71756f74652d636f6e74726163742d763100",
            "000100000010666978747572652d70726f7669646572",
            "00000010666978747572652f6d6f64656c3aceb1030102",
            "0100000000000f42400100000000000f42400000",
            "0100000000001e8480010000000000000000",
            "00",
        ))
        .unwrap();
        assert_eq!(expected.len(), 116);
        assert_eq!(contract.canonical_bytes(), expected);
        assert_eq!(
            contract.digest().as_str(),
            "86d47b6cef1963d77aa6ea01eb1c654af85ccd26d86b98f0272f99ab16a72bd0"
        );
    }

    #[test]
    fn partial_v2_contracts_remain_incomplete_and_bind_spend_ceiling() {
        let mut missing_reasoning_rate = rates();
        missing_reasoning_rate.reasoning_per_million_microdollars = None;
        let incomplete = BillingQuoteContractV1::try_new(
            ProviderId("fixture-provider".into()),
            ModelId("fixture/model:α".into()),
            PricingDeclarationState::DeclaredV2,
            missing_reasoning_rate,
            ReasoningCounterBasis::SeparateFromOutput,
            ReasoningRatePolicy::DedicatedRate,
        )
        .expect("partial V2 terms remain available to receipt accounting");
        let quote = quote_observed_billing(
            &incomplete,
            &observed(fixture(), ReasoningReporting::Reported),
        );
        assert_eq!(quote.full_total_microdollars, None);
        assert!(
            quote
                .unknown_reasons
                .contains(&BillingUnknownReason::MissingRate(
                    BillingRateCategory::Reasoning
                ))
        );

        let mut missing_primary_rates = empty_rates();
        missing_primary_rates.input_per_million_microdollars = Some(0);
        let unknown = make_contract(
            PricingDeclarationState::DeclaredV2,
            missing_primary_rates,
            ReasoningCounterBasis::Unknown,
            ReasoningRatePolicy::Unknown,
        );
        let quote =
            quote_observed_billing(&unknown, &observed(fixture(), ReasoningReporting::Reported));
        assert_eq!(quote.full_total_microdollars, None);
        assert!(
            quote
                .unknown_reasons
                .contains(&BillingUnknownReason::UnknownCounterBasis)
        );
        assert!(
            quote
                .unknown_reasons
                .contains(&BillingUnknownReason::UnknownRatePolicy)
        );

        let mut missing_output_rates = empty_rates();
        missing_output_rates.input_per_million_microdollars = Some(0);
        missing_output_rates.request_flat_microdollars = Some(0);
        let missing_output = make_contract(
            PricingDeclarationState::DeclaredV2,
            missing_output_rates,
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let quote = quote_observed_billing(
            &missing_output,
            &observed(fixture(), ReasoningReporting::Reported),
        );
        assert_eq!(quote.full_total_microdollars, None);
        assert!(
            quote
                .unknown_reasons
                .contains(&BillingUnknownReason::MissingRate(
                    BillingRateCategory::Output
                ))
        );

        assert!(
            BillingQuoteContractV1::try_new_with_reasoning_bound(
                ProviderId("fixture-provider".into()),
                ModelId("fixture/model:α".into()),
                PricingDeclarationState::Absent,
                empty_rates(),
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
                Some(0),
            )
            .is_err()
        );

        let unbounded = declared(
            ReasoningCounterBasis::SeparateFromOutput,
            ReasoningRatePolicy::DedicatedRate,
        );
        let bounded = BillingQuoteContractV1::try_new_with_reasoning_bound(
            ProviderId("fixture-provider".into()),
            ModelId("fixture/model:α".into()),
            PricingDeclarationState::DeclaredV2,
            rates(),
            ReasoningCounterBasis::SeparateFromOutput,
            ReasoningRatePolicy::DedicatedRate,
            Some(12),
        )
        .unwrap();
        assert_ne!(unbounded.digest(), bounded.digest());
    }

    #[test]
    fn billing_legacy_shapes_and_calculator_unchanged() {
        let usage = ProviderUsage {
            input_tokens: 11,
            output_tokens: 22,
            cache_read_tokens: 33,
            cache_write_tokens: 44,
            reasoning_tokens: 5,
        };
        assert_eq!(
            serde_json::to_string(&usage).unwrap(),
            "{\"input_tokens\":11,\"output_tokens\":22,\"cache_read_tokens\":33,\"cache_write_tokens\":44,\"reasoning_tokens\":5}"
        );
        let event = ProviderStreamEvent {
            usage_observation: None,
            sequence: 7,
            event: ProviderEventKind::UsageUpdate(usage),
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            "{\"sequence\":7,\"event\":{\"UsageUpdate\":{\"input_tokens\":11,\"output_tokens\":22,\"cache_read_tokens\":33,\"cache_write_tokens\":44,\"reasoning_tokens\":5}}}"
        );
        let legacy = CostRates {
            input_per_million_microcents: 1_000_000,
            output_per_million_microcents: 1_000_000,
            cache_read_per_million_microcents: None,
            cache_write_per_million_microcents: None,
            reasoning_per_million_microcents: Some(2_000_000),
            request_flat_microcents: 0,
        };
        assert_eq!(legacy.cost_microcents(&fixture()), Some(190));
    }

    #[test]
    fn billing_declaration_presence_and_explicit_free() {
        let zero_usage = observed(ProviderUsage::default(), ReasoningReporting::Reported);
        for (state, prices, reason) in [
            (
                PricingDeclarationState::Absent,
                empty_rates(),
                BillingUnknownReason::PricingAbsent,
            ),
            (
                PricingDeclarationState::LegacyZeroUnverified,
                BillingRatesV1 {
                    input_per_million_microdollars: Some(0),
                    ..empty_rates()
                },
                BillingUnknownReason::LegacyZeroUnverified,
            ),
        ] {
            let contract = make_contract(
                state,
                prices,
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
            );
            let quote = quote_observed_billing(&contract, &zero_usage);
            assert_amounts(&quote, None, None);
            assert_eq!(quote.unknown_reasons, vec![reason]);
        }
        let free = BillingRatesV1 {
            input_per_million_microdollars: Some(0),
            output_per_million_microdollars: Some(0),
            request_flat_microdollars: Some(0),
            ..empty_rates()
        };
        let contract = make_contract(
            PricingDeclarationState::DeclaredV2,
            free,
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let quote = quote_observed_billing(
            &contract,
            &observed(
                ProviderUsage {
                    input_tokens: 17,
                    output_tokens: 23,
                    ..ProviderUsage::default()
                },
                ReasoningReporting::Reported,
            ),
        );
        assert_amounts(&quote, Some(0), Some(0));
        let legacy = BillingRatesV1 {
            input_per_million_microdollars: Some(1),
            ..empty_rates()
        };
        let partial = make_contract(
            PricingDeclarationState::LegacyFields,
            legacy,
            ReasoningCounterBasis::Unknown,
            ReasoningRatePolicy::Unknown,
        );
        assert_eq!(*partial.rates(), legacy);
        for (state, prices, basis, policy) in [
            (
                PricingDeclarationState::Absent,
                free,
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
            ),
            (
                PricingDeclarationState::LegacyZeroUnverified,
                rates(),
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
            ),
            (
                PricingDeclarationState::LegacyZeroUnverified,
                empty_rates(),
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
            ),
            (
                PricingDeclarationState::LegacyFields,
                free,
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
            ),
            (
                PricingDeclarationState::LegacyFields,
                legacy,
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::Unknown,
            ),
            (
                PricingDeclarationState::LegacyZeroUnverified,
                free,
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::OutputRate,
            ),
        ] {
            assert_eq!(
                BillingQuoteContractV1::try_new(
                    ProviderId("p".into()),
                    ModelId("m".into()),
                    state,
                    prices,
                    basis,
                    policy
                ),
                Err(BillingContractError::InconsistentDeclaration)
            );
        }
    }

    #[test]
    fn billing_rate_presence_used_vs_unused() {
        let contract = declared(
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let mut input = observed(fixture(), ReasoningReporting::Reported);
        assert_amounts(
            &quote_observed_billing(&contract, &input),
            Some(110),
            Some(110),
        );
        input.raw_usage.cache_read_tokens = 3;
        let quote = quote_observed_billing(&contract, &input);
        assert_amounts(&quote, None, Some(110));
        assert_eq!(
            quote.unknown_reasons,
            vec![BillingUnknownReason::MissingRate(
                BillingRateCategory::CacheRead
            )]
        );
        let prices = BillingRatesV1 {
            reasoning_per_million_microdollars: None,
            ..rates()
        };
        let split = make_contract(
            PricingDeclarationState::DeclaredV2,
            prices,
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::DedicatedRate,
        );
        let quote =
            quote_observed_billing(&split, &observed(fixture(), ReasoningReporting::Reported));
        assert_amounts(&quote, None, Some(70));
        assert_eq!(
            quote.unknown_reasons,
            vec![BillingUnknownReason::MissingRate(
                BillingRateCategory::Reasoning
            )]
        );
        for basis in [
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningCounterBasis::SeparateFromOutput,
        ] {
            let incomplete = make_contract(
                PricingDeclarationState::DeclaredV2,
                prices,
                basis,
                ReasoningRatePolicy::DedicatedRate,
            );
            let zero_reasoning = observed(
                ProviderUsage {
                    reasoning_tokens: 0,
                    ..fixture()
                },
                ReasoningReporting::Reported,
            );
            let quote = quote_observed_billing(&incomplete, &zero_reasoning);
            assert_amounts(&quote, None, Some(110));
            assert_eq!(
                quote.unknown_reasons,
                vec![BillingUnknownReason::MissingRate(
                    BillingRateCategory::Reasoning
                )]
            );
        }
        let legacy = make_contract(
            PricingDeclarationState::LegacyFields,
            BillingRatesV1 {
                request_flat_microdollars: None,
                ..rates()
            },
            ReasoningCounterBasis::Unknown,
            ReasoningRatePolicy::Unknown,
        );
        let quote = quote_observed_billing(
            &legacy,
            &observed(
                ProviderUsage {
                    reasoning_tokens: 0,
                    ..fixture()
                },
                ReasoningReporting::Reported,
            ),
        );
        assert_amounts(&quote, None, Some(10));
        assert_eq!(
            quote.unknown_reasons,
            vec![
                BillingUnknownReason::UnknownCounterBasis,
                BillingUnknownReason::UnknownRatePolicy,
                BillingUnknownReason::MissingRate(BillingRateCategory::RequestFlat),
            ]
        );
    }

    #[test]
    fn billing_reported_zero_requires_declared_reasoning_contract() {
        let raw = ProviderUsage {
            reasoning_tokens: 0,
            ..fixture()
        };
        for basis in [
            ReasoningCounterBasis::Unknown,
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningCounterBasis::SeparateFromOutput,
        ] {
            for policy in [
                ReasoningRatePolicy::Unknown,
                ReasoningRatePolicy::OutputRate,
                ReasoningRatePolicy::DedicatedRate,
            ] {
                let quote = quote_observed_billing(
                    &declared(basis, policy),
                    &observed(raw, ReasoningReporting::Reported),
                );
                if basis == ReasoningCounterBasis::Unknown || policy == ReasoningRatePolicy::Unknown
                {
                    assert_eq!(quote.full_total_microdollars, None);
                    assert_eq!(quote.independent_subtotal_microdollars, Some(10));
                    if basis == ReasoningCounterBasis::Unknown {
                        assert!(
                            quote
                                .unknown_reasons
                                .contains(&BillingUnknownReason::UnknownCounterBasis)
                        );
                    }
                    if policy == ReasoningRatePolicy::Unknown {
                        assert!(
                            quote
                                .unknown_reasons
                                .contains(&BillingUnknownReason::UnknownRatePolicy)
                        );
                    }
                } else {
                    assert_amounts(&quote, Some(110), Some(110));
                    assert!(quote.unknown_reasons.is_empty());
                }
            }
        }
        for reporting in [
            ReasoningReporting::NotReported,
            ReasoningReporting::LegacyUnknown,
        ] {
            let quote = quote_observed_billing(
                &declared(
                    ReasoningCounterBasis::SeparateFromOutput,
                    ReasoningRatePolicy::DedicatedRate,
                ),
                &observed(raw, reporting),
            );
            assert_amounts(&quote, None, Some(10));
            assert_eq!(
                quote.unknown_reasons,
                vec![BillingUnknownReason::ReasoningNotReported]
            );
            let included = declared(
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::OutputRate,
            );
            assert_amounts(
                &quote_observed_billing(&included, &observed(raw, reporting)),
                Some(110),
                Some(110),
            );
        }
        let included = declared(
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let legacy = observed(fixture(), ReasoningReporting::LegacyUnknown);
        let quote = quote_observed_billing(&included, &legacy);
        assert_amounts(&quote, Some(110), Some(110));
        assert_eq!(quote.observed.raw_usage.reasoning_tokens, 40);
        let legacy = observed(
            ProviderUsage {
                output_tokens: 12,
                reasoning_tokens: 540,
                ..fixture()
            },
            ReasoningReporting::LegacyUnknown,
        );
        let quote = quote_observed_billing(&included, &legacy);
        assert_amounts(&quote, Some(22), Some(22));
        assert_eq!(quote.observed.raw_usage.reasoning_tokens, 540);
    }

    #[test]
    fn billing_counter_contract_mismatches() {
        let raw = ProviderUsage {
            output_tokens: 12,
            reasoning_tokens: 540,
            ..fixture()
        };
        for policy in [
            ReasoningRatePolicy::OutputRate,
            ReasoningRatePolicy::DedicatedRate,
        ] {
            let quote = quote_observed_billing(
                &declared(ReasoningCounterBasis::IncludedInOutput, policy),
                &observed(raw, ReasoningReporting::Reported),
            );
            assert_amounts(&quote, None, Some(10));
            assert_eq!(
                quote.unknown_reasons,
                vec![BillingUnknownReason::CounterContractMismatch]
            );
            assert_eq!(quote.observed.raw_usage, raw);
            assert_eq!(quote.groups.len(), 3);
        }
        for (policy, total) in [
            (ReasoningRatePolicy::OutputRate, 562),
            (ReasoningRatePolicy::DedicatedRate, 1102),
        ] {
            let contract = declared(ReasoningCounterBasis::SeparateFromOutput, policy);
            assert_amounts(
                &quote_observed_billing(&contract, &observed(raw, ReasoningReporting::Reported)),
                Some(total),
                Some(total),
            );
            let quote =
                quote_observed_billing(&contract, &observed(raw, ReasoningReporting::NotReported));
            assert_amounts(&quote, None, Some(10));
            assert_eq!(
                quote.unknown_reasons,
                vec![BillingUnknownReason::CounterContractMismatch]
            );
        }
    }

    #[test]
    fn billing_inherited_vs_dedicated_ceil() {
        let prices = BillingRatesV1 {
            input_per_million_microdollars: Some(1),
            output_per_million_microdollars: Some(1),
            reasoning_per_million_microdollars: Some(1),
            ..rates()
        };
        let raw = ProviderUsage {
            output_tokens: 1,
            reasoning_tokens: 1,
            ..ProviderUsage::default()
        };
        for (policy, amount, groups) in [
            (ReasoningRatePolicy::OutputRate, 1, 4),
            (ReasoningRatePolicy::DedicatedRate, 2, 5),
        ] {
            let contract = make_contract(
                PricingDeclarationState::DeclaredV2,
                prices,
                ReasoningCounterBasis::SeparateFromOutput,
                policy,
            );
            let quote =
                quote_observed_billing(&contract, &observed(raw, ReasoningReporting::Reported));
            assert_amounts(&quote, Some(amount), Some(amount));
            assert_eq!(quote.groups.len(), groups);
        }
    }

    #[test]
    fn billing_ceil_boundaries_and_flat() {
        let prices = BillingRatesV1 {
            input_per_million_microdollars: Some(1),
            output_per_million_microdollars: Some(1),
            cache_read_per_million_microdollars: Some(1),
            reasoning_per_million_microdollars: Some(1),
            ..rates()
        };
        let contract = make_contract(
            PricingDeclarationState::DeclaredV2,
            prices,
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::OutputRate,
        );
        for (tokens, amount) in [(0, 0), (1, 1), (999_999, 1), (1_000_000, 1), (1_000_001, 2)] {
            let quote = quote_observed_billing(
                &contract,
                &observed(
                    ProviderUsage {
                        output_tokens: tokens,
                        ..ProviderUsage::default()
                    },
                    ReasoningReporting::Reported,
                ),
            );
            assert_amounts(&quote, Some(amount), Some(amount));
        }
        let quote = quote_observed_billing(
            &contract,
            &observed(
                ProviderUsage {
                    input_tokens: 1,
                    cache_read_tokens: 1,
                    ..ProviderUsage::default()
                },
                ReasoningReporting::Reported,
            ),
        );
        assert_amounts(&quote, Some(2), Some(2));
        let with_flat = make_contract(
            PricingDeclarationState::DeclaredV2,
            BillingRatesV1 {
                request_flat_microdollars: Some(7),
                ..prices
            },
            ReasoningCounterBasis::SeparateFromOutput,
            ReasoningRatePolicy::DedicatedRate,
        );
        assert_amounts(
            &quote_observed_billing(
                &with_flat,
                &observed(ProviderUsage::default(), ReasoningReporting::Reported),
            ),
            Some(7),
            Some(7),
        );
        assert_amounts(
            &quote_observed_billing(
                &with_flat,
                &observed(
                    ProviderUsage {
                        output_tokens: 1,
                        reasoning_tokens: 1,
                        ..ProviderUsage::default()
                    },
                    ReasoningReporting::Reported,
                ),
            ),
            Some(9),
            Some(9),
        );
    }

    #[test]
    fn billing_normalized_count_exceeds_u64() {
        let contract = make_contract(
            PricingDeclarationState::DeclaredV2,
            BillingRatesV1 {
                output_per_million_microdollars: Some(1),
                ..rates()
            },
            ReasoningCounterBasis::SeparateFromOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let raw = ProviderUsage {
            output_tokens: u64::MAX,
            reasoning_tokens: u64::MAX,
            ..ProviderUsage::default()
        };
        let quote = quote_observed_billing(&contract, &observed(raw, ReasoningReporting::Reported));
        assert_eq!(quote.groups[3].tokens, 36_893_488_147_419_103_230_u128);
        assert_eq!(
            quote.groups[3].group,
            BillableTokenGroupV1::OutputAndReasoning
        );
        assert_amounts(&quote, Some(36_893_488_147_420), Some(36_893_488_147_420));
    }

    #[test]
    fn billing_combined_product_overflow() {
        let contract = make_contract(
            PricingDeclarationState::DeclaredV2,
            BillingRatesV1 {
                output_per_million_microdollars: Some(u64::MAX),
                ..rates()
            },
            ReasoningCounterBasis::SeparateFromOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let raw = ProviderUsage {
            output_tokens: u64::MAX,
            reasoning_tokens: u64::MAX,
            ..ProviderUsage::default()
        };
        let quote = quote_observed_billing(&contract, &observed(raw, ReasoningReporting::Reported));
        assert_amounts(&quote, None, Some(0));
        assert_eq!(quote.groups[3].cost_microdollars, None);
        assert_eq!(
            quote.unknown_reasons,
            vec![BillingUnknownReason::ArithmeticOverflow]
        );
        let mut with_input = raw;
        with_input.input_tokens = 10;
        assert_amounts(
            &quote_observed_billing(
                &contract,
                &observed(with_input, ReasoningReporting::Reported),
            ),
            None,
            Some(10),
        );
    }

    #[test]
    fn billing_money_and_subtotal_overflow() {
        let extreme = make_contract(
            PricingDeclarationState::DeclaredV2,
            BillingRatesV1 {
                input_per_million_microdollars: Some(u64::MAX),
                ..rates()
            },
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let quote = quote_observed_billing(
            &extreme,
            &observed(
                ProviderUsage {
                    input_tokens: u64::MAX,
                    ..ProviderUsage::default()
                },
                ReasoningReporting::Reported,
            ),
        );
        assert_eq!(
            quote.groups[0].cost_microdollars,
            Some(340_282_366_920_938_463_426_481_119_284_350_u128)
        );
        assert_amounts(&quote, None, None);
        assert_eq!(
            quote.unknown_reasons,
            vec![BillingUnknownReason::ArithmeticOverflow]
        );
        let summed = make_contract(
            PricingDeclarationState::DeclaredV2,
            BillingRatesV1 {
                input_per_million_microdollars: Some(1),
                request_flat_microdollars: Some(u64::MAX),
                ..rates()
            },
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::OutputRate,
        );
        let quote = quote_observed_billing(
            &summed,
            &observed(
                ProviderUsage {
                    input_tokens: 1,
                    ..ProviderUsage::default()
                },
                ReasoningReporting::Reported,
            ),
        );
        assert_amounts(&quote, None, None);
        assert_eq!(quote.groups[0].cost_microdollars, Some(1));
        assert_eq!(
            quote.unknown_reasons,
            vec![BillingUnknownReason::ArithmeticOverflow]
        );
    }

    #[test]
    fn billing_unknown_overlap_subtotal() {
        let prices = BillingRatesV1 {
            cache_read_per_million_microdollars: Some(1_000_000),
            cache_write_per_million_microdollars: Some(1_000_000),
            request_flat_microdollars: Some(7),
            ..rates()
        };
        let contract = make_contract(
            PricingDeclarationState::LegacyFields,
            prices,
            ReasoningCounterBasis::Unknown,
            ReasoningRatePolicy::Unknown,
        );
        let raw = ProviderUsage {
            cache_read_tokens: 3,
            cache_write_tokens: 4,
            ..fixture()
        };
        let quote = quote_observed_billing(&contract, &observed(raw, ReasoningReporting::Reported));
        assert_amounts(&quote, None, Some(24));
        assert_eq!(quote.groups.len(), 3);
        assert_eq!(
            quote.unknown_reasons,
            vec![
                BillingUnknownReason::UnknownCounterBasis,
                BillingUnknownReason::UnknownRatePolicy
            ]
        );
    }

    #[test]
    fn billing_unknown_reason_order() {
        let contract = make_contract(
            PricingDeclarationState::LegacyFields,
            BillingRatesV1 {
                input_per_million_microdollars: Some(1_000_000),
                ..empty_rates()
            },
            ReasoningCounterBasis::Unknown,
            ReasoningRatePolicy::Unknown,
        );
        let raw = ProviderUsage {
            cache_read_tokens: 3,
            cache_write_tokens: 4,
            ..fixture()
        };
        let quote = quote_observed_billing(&contract, &observed(raw, ReasoningReporting::Reported));
        assert_amounts(&quote, None, Some(10));
        assert_eq!(
            quote.unknown_reasons,
            vec![
                BillingUnknownReason::UnknownCounterBasis,
                BillingUnknownReason::UnknownRatePolicy,
                BillingUnknownReason::MissingRate(BillingRateCategory::CacheRead),
                BillingUnknownReason::MissingRate(BillingRateCategory::CacheWrite),
                BillingUnknownReason::MissingRate(BillingRateCategory::RequestFlat)
            ]
        );
        let quote = quote_observed_billing(
            &contract,
            &observed(
                ProviderUsage {
                    reasoning_tokens: 0,
                    ..raw
                },
                ReasoningReporting::LegacyUnknown,
            ),
        );
        assert_eq!(
            quote.unknown_reasons[0],
            BillingUnknownReason::ReasoningNotReported
        );
        assert_eq!(quote.groups.len(), 3);
    }

    #[test]
    fn billing_identity_and_presence_distinct() {
        let base = declared(
            ReasoningCounterBasis::IncludedInOutput,
            ReasoningRatePolicy::DedicatedRate,
        );
        let digest = base.digest();
        let changed = [
            BillingQuoteContractV1::try_new(
                ProviderId("another-provider".into()),
                base.raw_model_id().clone(),
                base.declaration(),
                *base.rates(),
                base.reasoning_counter_basis(),
                base.reasoning_rate_policy(),
            )
            .unwrap(),
            BillingQuoteContractV1::try_new(
                base.provider_id().clone(),
                ModelId("another/model".into()),
                base.declaration(),
                *base.rates(),
                base.reasoning_counter_basis(),
                base.reasoning_rate_policy(),
            )
            .unwrap(),
            make_contract(
                PricingDeclarationState::DeclaredV2,
                BillingRatesV1 {
                    cache_read_per_million_microdollars: Some(0),
                    ..rates()
                },
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::DedicatedRate,
            ),
            declared(
                ReasoningCounterBasis::SeparateFromOutput,
                ReasoningRatePolicy::DedicatedRate,
            ),
            declared(
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::OutputRate,
            ),
        ];
        for contract in changed {
            assert_ne!(contract.digest(), digest);
        }
        let explicit = make_contract(
            PricingDeclarationState::DeclaredV2,
            rates(),
            ReasoningCounterBasis::Unknown,
            ReasoningRatePolicy::Unknown,
        );
        let legacy = make_contract(
            PricingDeclarationState::LegacyFields,
            rates(),
            ReasoningCounterBasis::Unknown,
            ReasoningRatePolicy::Unknown,
        );
        assert_ne!(explicit.digest(), legacy.digest());
        for (raw, reporting) in [
            (fixture(), ReasoningReporting::Reported),
            (ProviderUsage::default(), ReasoningReporting::LegacyUnknown),
        ] {
            assert_eq!(
                quote_observed_billing(&base, &observed(raw, reporting)).contract_digest,
                digest
            );
        }
        for (identity, error) in [
            (String::new(), BillingContractError::EmptyIdentity),
            (
                "line\nbreak".into(),
                BillingContractError::ControlCharacterIdentity,
            ),
            ("x".repeat(4097), BillingContractError::IdentityTooLong),
        ] {
            for provider in [true, false] {
                let (p, m) = if provider {
                    (identity.clone(), "m".into())
                } else {
                    ("p".into(), identity.clone())
                };
                assert_eq!(
                    BillingQuoteContractV1::try_new(
                        ProviderId(p),
                        ModelId(m),
                        PricingDeclarationState::DeclaredV2,
                        rates(),
                        ReasoningCounterBasis::Unknown,
                        ReasoningRatePolicy::Unknown
                    ),
                    Err(error)
                );
            }
        }
        for identity in ["x".repeat(4096), "  provider/α:model  ".into()] {
            let contract = BillingQuoteContractV1::try_new(
                ProviderId(identity.clone()),
                ModelId(identity.clone()),
                PricingDeclarationState::DeclaredV2,
                rates(),
                ReasoningCounterBasis::Unknown,
                ReasoningRatePolicy::Unknown,
            )
            .unwrap();
            assert_eq!(contract.provider_id().0, identity);
            assert_eq!(contract.raw_model_id().0, identity);
        }
    }
}

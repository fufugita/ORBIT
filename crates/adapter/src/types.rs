//! DR-09 §2/§3 typed identifiers and request/result/stream surfaces.
//!
//! All identifiers are newtyped `String` (cheap clones, stable identity for
//! hashing). Sampling parameters are fixed-point integers — temperature in
//! milli-units, top-p in millionths — never floats across the persistence
//! boundary (DR-09 §3). Prompt/output bytes live in `SecretBytes` (see
//! `credential.rs`); they never appear in Ledger events (GW-25).

use serde::{Deserialize, Serialize};

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
    /// Endpoint scheme (v0.2): HttpLoopback → http, else https. The adapter
    /// and gateway egress tuple derive the wire scheme from this, so a
    /// homelab mock (HTTP on a LAN IP) is addressable without host sniffing.
    #[serde(default)]
    pub endpoint_scheme: EndpointScheme,
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

/// One turn of a multi-turn conversation transcript (DR-09 §3 extension).
/// Roles mirror the OpenAI-compatible wire set: `system` | `user` | `assistant`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
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
    pub sampling: SamplingParameters,
    pub output: OutputRequirements,
    pub tools: Vec<ToolDefinition>,
    pub metadata: RequestMetadata,
    pub connect_timeout_ms: u64,
    pub first_byte_timeout_ms: u64,
    pub total_timeout_ms: u64,
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

/// One stream event (DR-09 §4). Sequence starts at 0, increments by 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStreamEvent {
    pub sequence: u64,
    pub event: ProviderEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderEventKind {
    ResponseStarted {
        upstream_request_id: Option<String>,
    },
    TextDelta {
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

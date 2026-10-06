//! The dispatch core — one provider round through the four-gate
//! pipeline. Moved bodily from orbit-cli (phase 2): route binding,
//! egress allowlist, ledger write, stream assembly. The CLI keeps
//! thin re-exports so existing callers do not churn.

use orbit_adapter::types::ChatMessage;
use sha2::Digest;
use std::path::Path;

/// One assembled tool call from the provider stream.
#[derive(Debug, Clone)]
pub struct PendingToolCall {
    pub index: u32,
    pub id: String,
    pub name: String,
    pub arguments: Vec<u8>,
}

/// Outcome of one provider round: assembled text + tool calls + usage + cost.
#[derive(Debug, Clone, Default)]
pub struct TurnOutcome {
    pub output: String,
    /// Assembled reasoning (thinking deltas), if the provider sent any.
    /// Attached to the assistant message as an opaque block for replay;
    /// never displayed, never sent to a provider that did not produce it.
    pub thinking: Option<String>,
    /// Signature of the thinking block (Anthropic signature_delta),
    /// replayed verbatim next round.
    pub thinking_signature: Option<String>,
    pub tool_calls: Vec<PendingToolCall>,
    pub finish_reason: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
    /// Context in use after this round (E3): the last request's input
    /// plus cache tokens, provider-normalised. NOT a sum over rounds —
    /// the context meter shows instantaneous occupancy, not traffic.
    pub context_tokens: u64,
}

/// The provider kind selects the adapter: `openai-compatible` (default),
/// `anthropic` or `ollama` (roadmap §Providers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProviderKind {
    #[default]
    OpenAiCompatible,
    Anthropic,
    Ollama,
}

impl ProviderKind {
    /// From the providers.toml `kind` string (unknown → OpenAI-compatible,
    /// the backwards-compatible default).
    pub fn from_config(s: &str) -> Self {
        match s {
            "anthropic" => ProviderKind::Anthropic,
            "ollama" => ProviderKind::Ollama,
            _ => ProviderKind::OpenAiCompatible,
        }
    }
}

/// Per-model output limit (defect fix: the old hard 2,048 silently
/// truncated long answers and file writes). Falls back to 32,000 when
/// the model has no explicit limit. Resolved from the CLI's
/// providers.toml by the caller and passed in `max_output_tokens`.
#[derive(Debug, Clone)]
pub struct TurnConfig {
    pub provider_id: String,
    pub gate: String,
    pub model: String,
    /// Adapter kind from providers.toml (default openai-compatible).
    pub kind: ProviderKind,
    pub credential_env: Option<String>,
    pub pricing: Option<orbit_adapter::types::CostRates>,
    pub max_output_tokens: u64,
    /// Optional sampling override (E8): temperature / top_p as
    /// configured per model in providers.toml. None = omit —
    /// providers apply their own defaults, and several current
    /// model families REJECT explicit sampling parameters.
    pub sampling: Option<(Option<f64>, Option<f64>)>,
}

/// Run one provider round through the four-gate async dispatch
/// pipeline. Shared by every front-end: the TUI worker, the REPL, the
/// web bridge, the Go bridge and `orbit -p` all call this one function.
///
/// - `gate` / `model`: resolved by the caller (flags → env → defaults).
/// - `messages`: `Some(transcript)` for multi-turn chat, `None` for the
///   single-turn `ask` contract.
/// - `observer`: called per streamed event (live TextDelta rendering);
///   `None` = buffered output only.
#[allow(clippy::too_many_arguments)]
pub fn run_dispatch(
    home: &Path,
    config: &TurnConfig,
    prompt: &str,
    messages: Option<Vec<ChatMessage>>,
    observer: orbit_provider_http::stream::StreamObserver<'_>,
    cancel: orbit_provider_http::CancelToken,
    tools: Vec<orbit_adapter::types::ToolDefinition>,
    request_stem: &str,
    session_id: &str,
) -> Result<TurnOutcome, (&'static str, String)> {
    // Parse the gate URL; only http loopback or https is acceptable.
    let url =
        url::Url::parse(&config.gate).map_err(|e| ("ORBIT-E0401", format!("bad gate url: {e}")))?;
    let scheme = match url.scheme() {
        "https" => orbit_adapter::types::EndpointScheme::Https,
        "http" => orbit_adapter::types::EndpointScheme::HttpLoopback,
        other => {
            return Err(("ORBIT-E0301", format!("unsupported scheme {other}")));
        }
    };
    let host = url.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        return Err(("ORBIT-E0401", "gate url missing host".into()));
    }
    let port = url
        .port()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });

    // Build the route binding (generic runtime config — no internal models).
    // The adapter identity + kind follow the configured provider kind.
    let input = orbit_adapter::credential::SecretBytes::new(prompt.as_bytes().to_vec());
    let input_digest =
        orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(prompt.as_bytes())));

    type RegisterAdapter =
        Box<dyn FnOnce(&mut orbit_gateway::ProviderRegistry) -> Result<(), (&'static str, String)>>;
    let (adapter_kind, adapter_identity, register): (
        orbit_adapter::types::AdapterKind,
        orbit_adapter::types::AdapterIdentity,
        RegisterAdapter,
    ) = match config.kind {
        ProviderKind::Anthropic => {
            let identity = orbit_provider_http::anthropic::anthropic_identity();
            let kind = orbit_adapter::types::AdapterKind::DeclarativeHttpJsonV1;
            let register = move |registry: &mut orbit_gateway::ProviderRegistry| {
                let adapter = orbit_provider_http::AnthropicMessagesV1::new(
                    identity,
                    orbit_provider_http::anthropic::anthropic_capabilities(),
                )
                .map_err(|e| ("ORBIT-E0410", e.to_string()))?;
                registry.register_async_adapter(kind, std::sync::Arc::new(adapter));
                Ok(())
            };
            (
                kind,
                orbit_provider_http::anthropic::anthropic_identity(),
                Box::new(register),
            )
        }
        ProviderKind::Ollama => {
            let identity = orbit_adapter::types::AdapterIdentity {
                kind: orbit_adapter::types::AdapterKind::LocalProcessV1,
                implementation_digest: orbit_adapter::types::Sha256Digest("o".repeat(64)),
                profile_digest: orbit_adapter::types::Sha256Digest(
                    "ollama-profile".repeat(8).chars().take(64).collect(),
                ),
            };
            let kind = orbit_adapter::types::AdapterKind::LocalProcessV1;
            let closure_identity = identity.clone();
            let register = move |registry: &mut orbit_gateway::ProviderRegistry| {
                let adapter =
                    orbit_provider_http::OllamaHttpV1::new(closure_identity, ollama_capabilities())
                        .map_err(|e| ("ORBIT-E0410", e.to_string()))?;
                registry.register_async_adapter(kind, std::sync::Arc::new(adapter));
                Ok(())
            };
            (kind, identity, Box::new(register))
        }
        ProviderKind::OpenAiCompatible => {
            let identity = orbit_provider_http::openai::openai_identity();
            let kind = orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1;
            let tls = orbit_adapter::types::TlsPinPolicy {
                webpki: true,
                spki_sha256: None,
            };
            let register = move |registry: &mut orbit_gateway::ProviderRegistry| {
                let adapter = orbit_provider_http::OpenAiCompatibleHttpV1::new(
                    identity,
                    orbit_provider_http::openai::openai_capabilities(),
                    tls,
                )
                .map_err(|e| ("ORBIT-E0410", e.to_string()))?;
                registry.register_async_adapter(kind, std::sync::Arc::new(adapter));
                Ok(())
            };
            (
                kind,
                orbit_provider_http::openai::openai_identity(),
                Box::new(register),
            )
        }
    };

    let route = orbit_adapter::types::ProviderRouteBinding {
        provider_id: orbit_adapter::types::ProviderId(config.provider_id.clone()),
        deployment_id: orbit_adapter::types::DeploymentId(config.provider_id.clone()),
        region_id: orbit_adapter::types::RegionId("local".into()),
        adapter_kind,
        adapter_implementation_digest: adapter_identity.implementation_digest.clone(),
        adapter_profile_digest: adapter_identity.profile_digest.clone(),
        endpoint_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            format!("{}:{}", config.gate, config.model).as_bytes(),
        ))),
        expected_model: config.model.clone(),
        pricing_digest: orbit_adapter::types::Sha256Digest("0".repeat(64)),
        endpoint_host: host,
        endpoint_port: port,
        endpoint_scheme: scheme,
    };

    // Register the model + async adapter in a fresh registry.
    let mut registry = orbit_gateway::ProviderRegistry::new();
    register(&mut registry)?;
    registry.register_model(orbit_gateway::ModelRef(config.model.clone()), route.clone());

    // Egress allowlist: exactly this one gate tuple.
    let tuple = orbit_egress::EgressTuple {
        scheme: if url.scheme() == "https" {
            "https".into()
        } else {
            "http".into()
        },
        host: route.endpoint_host.clone(),
        port,
        path_prefix: "/v1".into(),
        provider_id: config.provider_id.clone(),
        region_id: "local".into(),
    };
    let engine = orbit_gateway::DispatchEngine::new(
        registry,
        home.join("ledger"),
        orbit_egress::EgressAllowlist::new(vec![tuple.clone()]),
        vec![tuple],
        vec![],
    );

    // Build the provider request carrying the REAL prompt bytes.
    // E7: every dispatch mints a fresh ULID request id (unique per
    // round, turn and retry — the old "{stem}-{pid}" was identical
    // for the whole process life, so the ledger could not tie rounds
    // to turns or sessions).
    let request_ulid = ulid::Ulid::new();
    let request = orbit_adapter::types::ProviderRequest {
        schema_version: 1,
        request_id: orbit_adapter::types::RequestId(format!("{request_stem}-{request_ulid}")),
        decision_id: orbit_adapter::types::DecisionId(format!("{request_stem}-{request_ulid}")),
        attempt_id: orbit_adapter::types::AttemptId(format!("{request_stem}-{request_ulid}")),
        route: route.clone(),
        input,
        messages,
        // E8: sampling is opt-in per model. Zero means "not set" —
        // the wire adapters omit a zero temperature/top_p (B7/E8).
        sampling: orbit_adapter::types::SamplingParameters {
            temperature_milliunits: config
                .sampling
                .and_then(|(t, _)| t)
                .and_then(|t| (t >= 0.0).then_some((t * 1000.0) as u32))
                .unwrap_or(0),
            top_p_millionths: config
                .sampling
                .and_then(|(_, p)| p)
                .and_then(|p| (p >= 0.0).then_some((p * 1_000_000.0) as u32))
                .unwrap_or(0),
            max_output_tokens: config.max_output_tokens,
        },
        output: orbit_adapter::types::OutputRequirements::Text,
        tools: tools.clone(),
        metadata: orbit_adapter::types::RequestMetadata {
            input_sha256: input_digest,
            input_bytes: prompt.len() as u64,
            tools_count: tools.len() as u32,
        },
        // E5: 30 s to the first byte, 90 s max gap between chunks.
        // Both overridable for tests (ORBIT_TEST_* never ship in
        // production configs — the scenarios use them to keep the
        // suite fast while proving the timeout fires).
        connect_timeout_ms: 10_000,
        first_byte_timeout_ms: std::env::var("ORBIT_TEST_FIRST_BYTE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30_000),
        idle_timeout_ms: std::env::var("ORBIT_TEST_IDLE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90_000),
    };

    // Gate authentication (never printed/persisted). A provider may require a
    // Bearer token for /v1 chat calls; read it from the provider's declared
    // env var (config `env = "..."`) or, for the legacy single-gate path,
    // `ORBIT_GATE_TOKEN`. No other env vars are consulted — e.g.
    // ANTHROPIC_AUTH_TOKEN is an upstream agent's auth, not this gate's key,
    // so it is deliberately NOT a fallback.
    let credential = config
        .credential_env
        .clone()
        .or_else(|| Some("ORBIT_GATE_TOKEN".to_string()))
        .and_then(|var| std::env::var(var).ok())
        .filter(|t| !t.is_empty())
        .map(|t| orbit_adapter::credential::SecretBytes::new(t.into_bytes()));

    // E7: the session id comes from the front-end (one per chat
    // session, stable across rounds and turns) — not minted per
    // round, which made the ledger unable to tie rounds to sessions.
    let session: orbit_ledger::SessionId = session_id.to_string();
    let decision = orbit_gateway::new_decision_id();

    // Run the full pipeline via tokio.
    // E6: one shared runtime for the process — a round used to spawn
    // its own thread pool every time.
    let result = orbit_provider_http::shared_runtime()
        .block_on(async {
            let mut writer = orbit_ledger::LedgerWriter::open(
                &home.join("ledger"),
                "orbit-engine".into(),
                "0.1.0",
            )
            .map_err(|e| orbit_gateway::DispatchError {
                code: "E0719",
                phase: "ledger",
                message: e.to_string(),
                session_id: session.clone(),
                decision_id: decision.0.clone(),
            })?;
            engine
                .dispatch_async(
                    &config.model,
                    &session,
                    &decision.0,
                    &request,
                    credential.as_ref(),
                    &mut writer,
                    &cancel,
                    observer,
                )
                .await
        })
        .map_err(|e| (e.code, e.message))?;

    let (outcome, _reservation) = result;
    match outcome {
        orbit_gateway::DispatchOutcome::Completed(r) => {
            let output: String = r
                .events
                .iter()
                .filter_map(|e| match &e.event {
                    orbit_adapter::types::ProviderEventKind::TextDelta { bytes } => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    _ => None,
                })
                .collect();
            // Assemble thinking deltas into one opaque string (replay-only).
            let thinking: Option<String> = {
                let t: String = r
                    .events
                    .iter()
                    .filter_map(|e| match &e.event {
                        orbit_adapter::types::ProviderEventKind::ThinkingDelta { bytes } => {
                            Some(String::from_utf8_lossy(bytes).into_owned())
                        }
                        _ => None,
                    })
                    .collect();
                (!t.is_empty()).then_some(t)
            };
            // Assemble the thinking signature the same way (replay-only).
            let thinking_signature: Option<String> = {
                let s: String = r
                    .events
                    .iter()
                    .filter_map(|e| match &e.event {
                        orbit_adapter::types::ProviderEventKind::ThinkingSignatureDelta {
                            bytes,
                        } => Some(String::from_utf8_lossy(bytes).into_owned()),
                        _ => None,
                    })
                    .collect();
                (!s.is_empty()).then_some(s)
            };
            // Assemble tool calls from the streamed events.
            let mut tool_calls: std::collections::BTreeMap<u32, PendingToolCall> =
                std::collections::BTreeMap::new();
            for e in &r.events {
                match &e.event {
                    orbit_adapter::types::ProviderEventKind::ToolCallStarted {
                        call_index,
                        provider_call_id,
                        name,
                    } => {
                        tool_calls
                            .entry(*call_index)
                            .or_insert_with(|| PendingToolCall {
                                index: *call_index,
                                id: provider_call_id
                                    .clone()
                                    .unwrap_or_else(|| format!("call-{call_index}")),
                                name: name.clone(),
                                arguments: Vec::new(),
                            });
                    }
                    orbit_adapter::types::ProviderEventKind::ToolCallArgumentsDelta {
                        call_index,
                        bytes,
                    } => {
                        if let Some(tc) = tool_calls.get_mut(call_index) {
                            tc.arguments.extend_from_slice(bytes);
                        }
                    }
                    _ => {}
                }
            }
            let finish_reason = r.events.iter().rev().find_map(|e| match &e.event {
                orbit_adapter::types::ProviderEventKind::Finished { finish_reason, .. } => {
                    finish_reason.clone()
                }
                _ => None,
            });
            let usage = r.accounting.usage;
            // Cost in microcents from the pricing config (zero if unpriced).
            let cost_microcents = config
                .pricing
                .and_then(|p| p.cost_microcents(&usage))
                .unwrap_or(0);
            Ok(TurnOutcome {
                output,
                thinking,
                thinking_signature,
                tool_calls: tool_calls.into_values().collect(),
                finish_reason,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cost_microcents,
                context_tokens: usage.input_tokens
                    + usage.cache_read_tokens
                    + usage.cache_write_tokens,
            })
        }
        // E1: a refusal without a usable message and without a
        // credential is genuinely an unauthenticated gateway; anything
        // else keeps the provider's own words (a 400's "prompt is too
        // long" must not become "requires authentication").
        orbit_gateway::DispatchOutcome::AdapterRefused {
            code: "E0404",
            message,
        } if credential.is_none() && message.trim() == "status 400" => Err((
            "ORBIT-E0402",
            format!(
                "gateway at {} requires authentication; set ORBIT_GATE_TOKEN",
                config.gate
            ),
        )),
        orbit_gateway::DispatchOutcome::AdapterRefused { code, message } => Err((code, message)),
        other => Err(("ORBIT-E0406", format!("ask failed: {other:?}"))),
    }
}

/// Ollama capabilities: loopback, streaming, tools; no JSON-schema output.
fn ollama_capabilities() -> orbit_adapter::types::ProviderCapabilities {
    orbit_adapter::types::ProviderCapabilities {
        supports_streaming: true,
        supports_tools: true,
        supports_json_schema_output: false,
        max_input_tokens: 262_144,
        max_output_tokens: 32_000,
    }
}

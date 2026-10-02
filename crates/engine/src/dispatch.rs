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
    pub tool_calls: Vec<PendingToolCall>,
    pub finish_reason: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
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
    pub credential_env: Option<String>,
    pub pricing: Option<orbit_adapter::types::CostRates>,
    pub max_output_tokens: u64,
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
    let input = orbit_adapter::credential::SecretBytes::new(prompt.as_bytes().to_vec());
    let input_digest =
        orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(prompt.as_bytes())));
    let adapter_identity = orbit_provider_http::openai::openai_identity();
    let route = orbit_adapter::types::ProviderRouteBinding {
        provider_id: orbit_adapter::types::ProviderId(config.provider_id.clone()),
        deployment_id: orbit_adapter::types::DeploymentId(config.provider_id.clone()),
        region_id: orbit_adapter::types::RegionId("local".into()),
        adapter_kind: orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1,
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
    let adapter = orbit_provider_http::OpenAiCompatibleHttpV1::new(
        adapter_identity,
        orbit_provider_http::openai::openai_capabilities(),
        orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: None,
        },
    )
    .map_err(|e| ("ORBIT-E0410", e.to_string()))?;
    registry.register_model(orbit_gateway::ModelRef(config.model.clone()), route.clone());
    registry.register_async_adapter(
        orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1,
        std::sync::Arc::new(adapter),
    );

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
    let request = orbit_adapter::types::ProviderRequest {
        schema_version: 1,
        request_id: orbit_adapter::types::RequestId(format!(
            "{request_stem}-{}",
            std::process::id()
        )),
        decision_id: orbit_adapter::types::DecisionId(format!(
            "{request_stem}-{}",
            std::process::id()
        )),
        attempt_id: orbit_adapter::types::AttemptId(format!(
            "{request_stem}-{}",
            std::process::id()
        )),
        route: route.clone(),
        input,
        messages,
        sampling: orbit_adapter::types::SamplingParameters {
            temperature_milliunits: 700,
            top_p_millionths: 950_000,
            max_output_tokens: config.max_output_tokens,
        },
        output: orbit_adapter::types::OutputRequirements::Text,
        tools: tools.clone(),
        metadata: orbit_adapter::types::RequestMetadata {
            input_sha256: input_digest,
            input_bytes: prompt.len() as u64,
            tools_count: tools.len() as u32,
        },
        connect_timeout_ms: 10_000,
        first_byte_timeout_ms: 30_000,
        total_timeout_ms: 120_000,
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

    let session = orbit_gateway::new_session_id();
    let decision = orbit_gateway::new_decision_id();

    // Run the full pipeline via tokio.
    let result = tokio::runtime::Runtime::new()
        .map_err(|e| ("ORBIT-E0410", e.to_string()))?
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
                tool_calls: tool_calls.into_values().collect(),
                finish_reason,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cost_microcents,
            })
        }
        orbit_gateway::DispatchOutcome::AdapterRefused { code: "E0404", .. }
            if credential.is_none() =>
        {
            Err((
                "ORBIT-E0402",
                format!(
                    "gateway at {} requires authentication; set ORBIT_GATE_TOKEN",
                    config.gate
                ),
            ))
        }
        orbit_gateway::DispatchOutcome::AdapterRefused { code, message } => Err((code, message)),
        other => Err(("ORBIT-E0406", format!("ask failed: {other:?}"))),
    }
}

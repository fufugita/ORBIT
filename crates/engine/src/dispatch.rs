//! The dispatch core — one provider round through the four-gate
//! pipeline. Moved bodily from orbit-cli (phase 2): route binding,
//! egress allowlist, ledger write, stream assembly. The CLI keeps
//! thin re-exports so existing callers do not churn.

use orbit_adapter::types::{ChatMessage, EffortValue};
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
    /// The hash of the `EgressIntent` ledger record written before this
    /// round left the machine — what the Activity panel shows beside the
    /// request. `None` when the round recorded nothing.
    pub egress_digest: Option<String>,
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
    pub fn validate_effort_value(self, effort: &EffortValue) -> Result<(), String> {
        match self {
            Self::OpenAiCompatible => effort.validate_for_openai(),
            Self::Anthropic => effort.validate_for_anthropic(),
            Self::Ollama => effort.validate_for_ollama(),
        }
    }

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
    /// Resolved request control; selection provenance belongs to the caller.
    pub effort: Option<EffortValue>,
    /// None is unknown, an empty list is unsupported, otherwise exact choices.
    pub supported_efforts: Option<Vec<EffortValue>>,
}

impl TurnConfig {
    pub fn validate_effort(&self) -> Result<(), String> {
        if let Some(choices) = &self.supported_efforts {
            let mut seen = std::collections::HashSet::new();
            for choice in choices {
                self.kind.validate_effort_value(choice)?;
                if !seen.insert(choice) {
                    return Err(format!(
                        "duplicate effort choice {choice} for model {}",
                        self.model
                    ));
                }
            }
        }
        let Some(effort) = &self.effort else {
            return Ok(());
        };
        self.kind.validate_effort_value(effort)?;
        match &self.supported_efforts {
            None => Err(format!(
                "effort support is unknown for model {}; declare supported_efforts before selecting {effort}",
                self.model
            )),
            Some(choices) if choices.is_empty() => Err(format!(
                "model {} declares effort controls unsupported",
                self.model
            )),
            Some(choices) if !choices.contains(effort) => Err(format!(
                "effort {effort} is not supported by model {}",
                self.model
            )),
            Some(_) => Ok(()),
        }
    }
}

pub(crate) type DispatchFailure = (&'static str, String);

// These construction types intentionally have no content-bearing Debug/Serialize.
#[derive(Clone)]
pub(crate) struct RequestPreparationContext {
    config: TurnConfig,
    route: orbit_adapter::types::ProviderRouteBinding,
    dialect: orbit_provider_http::request::HttpDialect,
    directive: Option<String>,
    tools: Vec<orbit_adapter::types::ToolDefinition>,
    binding_digest: String,
}

pub(crate) struct PreparedProviderRequest {
    context: RequestPreparationContext,
    request: orbit_adapter::types::ProviderRequest,
    session_id: String,
}
impl PreparedProviderRequest {
    pub(crate) fn binding_digest(&self) -> &str {
        &self.context.binding_digest
    }
    pub(crate) fn rendered_body(
        &self,
    ) -> Result<orbit_provider_http::request::RenderedRequestBody, orbit_adapter::error::AdapterError>
    {
        orbit_provider_http::request::render_request_body(
            self.context.dialect,
            (&self.request).into(),
        )
    }
    pub(crate) fn opaque_prefixes(&self) -> Vec<(usize, usize)> {
        use orbit_adapter::types::{ChatRole, ContentBlock};
        if self.context.dialect != orbit_provider_http::request::HttpDialect::AnthropicMessages {
            return Vec::new();
        }
        let mut prefixes = Vec::new();
        let mut wire_index = 0;
        for message in self.request.messages.iter().flatten() {
            match message.role {
                ChatRole::System => {}
                ChatRole::Assistant => {
                    let count = message
                        .blocks
                        .iter()
                        .flatten()
                        .filter(|block| match block {
                            ContentBlock::Opaque { json } => {
                                serde_json::from_str::<serde_json::Value>(json).is_ok()
                            }
                            _ => false,
                        })
                        .count();
                    if count > 0
                        || !message.content.is_empty()
                        || message
                            .tool_calls
                            .as_ref()
                            .is_some_and(|calls| !calls.is_empty())
                    {
                        if count > 0 {
                            prefixes.push((wire_index, count));
                        }
                        wire_index += 1;
                    }
                }
                ChatRole::User | ChatRole::Tool => wire_index += 1,
            }
        }
        prefixes
    }
    pub(crate) fn with_messages_for_measurement(&self, messages: Vec<ChatMessage>) -> Self {
        let old = &self.request;
        let prompt = String::from_utf8_lossy(old.input.expose());
        Self {
            context: self.context.clone(),
            session_id: self.session_id.clone(),
            request: orbit_adapter::types::ProviderRequest {
                schema_version: old.schema_version,
                request_id: old.request_id.clone(),
                decision_id: old.decision_id.clone(),
                attempt_id: old.attempt_id.clone(),
                route: old.route.clone(),
                input: orbit_adapter::credential::SecretBytes::new(old.input.expose().to_vec()),
                messages: project_messages(&self.context, &prompt, Some(messages)),
                effort: old.effort.clone(),
                sampling: old.sampling,
                output: old.output.clone(),
                tools: old.tools.clone(),
                metadata: old.metadata.clone(),
                connect_timeout_ms: old.connect_timeout_ms,
                first_byte_timeout_ms: old.first_byte_timeout_ms,
                idle_timeout_ms: old.idle_timeout_ms,
            },
        }
    }
}

fn project_messages(
    context: &RequestPreparationContext,
    prompt: &str,
    mut messages: Option<Vec<ChatMessage>>,
) -> Option<Vec<ChatMessage>> {
    if let Some(directive) = &context.directive {
        let wire = messages.get_or_insert_with(|| vec![crate::user_message(prompt)]);
        let mut system = crate::user_message(directive);
        system.role = orbit_adapter::types::ChatRole::System;
        wire.insert(0, system);
    }
    if let Some(wire) = &mut messages {
        crate::routing::strip_foreign_opaque_blocks_for(
            wire,
            &context.config.provider_id,
            &context.config.model,
        );
    }
    messages
}

pub(crate) fn request_preparation_context(
    config: &TurnConfig,
    system_directive: Option<&str>,
    tools: &[orbit_adapter::types::ToolDefinition],
) -> Result<RequestPreparationContext, DispatchFailure> {
    config.validate_effort().map_err(|e| ("ORBIT-E0401", e))?;
    // Validate the original URL before parsing can discard controls or whitespace.
    // This shared guard runs before credential-store access and ledger creation.
    let url = orbit_provider_http::endpoint::validate_provider_url(&config.gate)
        .map_err(|message| ("ORBIT-E0401", message.to_owned()))?;
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
    // The concrete Ollama HTTP route carries its actual API base. Generic
    // LocalProcess routes retain their own transport and path semantics.
    let endpoint_path = match config.kind {
        ProviderKind::Ollama => {
            if scheme != orbit_adapter::types::EndpointScheme::HttpLoopback {
                return Err(("ORBIT-E0401", "Ollama requires loopback HTTP".into()));
            }
            let base = normalize_endpoint_path(url.path());
            if base == "/api" || base.ends_with("/api") {
                base
            } else {
                format!("{base}/api")
            }
        }
        _ => normalize_endpoint_path(url.path()),
    };

    let (adapter_kind, adapter_identity, dialect) = match config.kind {
        ProviderKind::OpenAiCompatible => (
            orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1,
            orbit_provider_http::openai::openai_identity(),
            orbit_provider_http::request::HttpDialect::OpenAiCompatible,
        ),
        ProviderKind::Anthropic => (
            orbit_adapter::types::AdapterKind::DeclarativeHttpJsonV1,
            orbit_provider_http::anthropic::anthropic_identity(),
            orbit_provider_http::request::HttpDialect::AnthropicMessages,
        ),
        ProviderKind::Ollama => (
            orbit_adapter::types::AdapterKind::LocalProcessV1,
            orbit_adapter::types::AdapterIdentity {
                kind: orbit_adapter::types::AdapterKind::LocalProcessV1,
                implementation_digest: orbit_adapter::types::Sha256Digest("o".repeat(64)),
                profile_digest: orbit_adapter::types::Sha256Digest(
                    "ollama-profile".repeat(8).chars().take(64).collect(),
                ),
            },
            orbit_provider_http::request::HttpDialect::Ollama,
        ),
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
        endpoint_path: endpoint_path.clone(),
        endpoint_query: url.query().map(str::to_owned),
    };

    // Check the actual concrete method endpoint before any credentials or I/O.
    orbit_provider_http::endpoint::provider_method_url(
        &route,
        if config.kind == ProviderKind::Ollama {
            "/api"
        } else {
            "/v1"
        },
        if config.kind == ProviderKind::Anthropic {
            "messages"
        } else if config.kind == ProviderKind::Ollama {
            "chat"
        } else {
            "chat/completions"
        },
    )
    .map_err(|_| ("ORBIT-E0401", "provider endpoint binding is invalid".into()))?;
    let binding_digest = crate::context_budget::BudgetIdentity::for_config(config, "", "")
        .map_err(|e| ("ORBIT-E0401", e))?
        .binding_digest;
    Ok(RequestPreparationContext {
        config: config.clone(),
        route,
        dialect,
        directive: system_directive
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        tools: tools.to_vec(),
        binding_digest,
    })
}

pub(crate) fn prepare_provider_request(
    context: &RequestPreparationContext,
    prompt: &str,
    messages: Option<Vec<ChatMessage>>,
    request_stem: &str,
    session_id: &str,
) -> Result<PreparedProviderRequest, DispatchFailure> {
    let config = &context.config;
    let messages = project_messages(context, prompt, messages);
    let input = orbit_adapter::credential::SecretBytes::new(prompt.as_bytes().to_vec());
    let input_digest =
        orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(prompt.as_bytes())));
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
        route: context.route.clone(),
        input,
        messages,
        effort: config.effort.clone(),
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
        tools: context.tools.clone(),
        metadata: orbit_adapter::types::RequestMetadata {
            input_sha256: input_digest,
            input_bytes: prompt.len() as u64,
            tools_count: u32::try_from(context.tools.len())
                .map_err(|_| ("ORBIT-E0406", "too many provider tools".into()))?,
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

    let prepared = PreparedProviderRequest {
        context: context.clone(),
        request,
        session_id: session_id.into(),
    };
    prepared
        .rendered_body()
        .map_err(|error| (error.code(), error.to_string()))?;
    Ok(prepared)
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
    let context = request_preparation_context(config, None, &tools)?;
    let prepared = prepare_provider_request(&context, prompt, messages, request_stem, session_id)?;
    run_prepared_dispatch(home, config, prepared, observer, cancel, session_id)
}

pub(crate) fn run_prepared_dispatch(
    home: &Path,
    config: &TurnConfig,
    prepared: PreparedProviderRequest,
    observer: orbit_provider_http::stream::StreamObserver<'_>,
    cancel: orbit_provider_http::CancelToken,
    session_id: &str,
) -> Result<TurnOutcome, DispatchFailure> {
    let current = request_preparation_context(config, None, &[])?;
    if current.binding_digest != prepared.context.binding_digest
        || current.route != prepared.request.route
        || config.pricing != prepared.context.config.pricing
        || session_id != prepared.session_id
    {
        return Err(("ORBIT-E0413", "prepared provider binding changed".into()));
    }
    let request = prepared.request;
    let route = request.route.clone();
    let port = route.endpoint_port;
    let endpoint_path = route.endpoint_path.clone();
    let url = orbit_provider_http::endpoint::validate_provider_url(&config.gate)
        .map_err(|_| ("ORBIT-E0401", "provider endpoint binding is invalid".into()))?;
    type RegisterAdapter =
        Box<dyn FnOnce(&mut orbit_gateway::ProviderRegistry) -> Result<(), (&'static str, String)>>;
    let (_adapter_kind, _adapter_identity, register): (
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
        path_prefix: if endpoint_path.is_empty() {
            "/v1".into()
        } else {
            endpoint_path.clone()
        },
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

    // Authentication follows the exact selected provider binding. No declaration
    // means no auth; legacy gate authentication is made explicit by its caller.
    use orbit_adapter::provider_credentials::{ProviderAuthIdentity, ProviderCredentialStore};
    let credential_error = |error: orbit_adapter::provider_credentials::ProviderCredentialError| {
        ("ORBIT-E0401", error.to_string())
    };
    let kind = match config.kind {
        ProviderKind::OpenAiCompatible => "openai-compatible",
        ProviderKind::Anthropic => "anthropic",
        ProviderKind::Ollama => "ollama",
    };
    let identity = ProviderAuthIdentity::new(
        &config.provider_id,
        kind,
        url.as_str(),
        config.credential_env.as_deref(),
    )
    .map_err(credential_error)?;
    // Absolute lexical paths retain no-follow checks, including for --home .orbit.
    let credential_home = std::path::absolute(home).map_err(|_| {
        (
            "ORBIT-E0401",
            "provider credential home could not be resolved".into(),
        )
    })?;
    let credential = ProviderCredentialStore::new(&credential_home)
        .map_err(credential_error)?
        .resolve_with(&identity, |name| {
            Ok(std::env::var_os(name)
                .map(|value| orbit_adapter::SecretBytes::new(value.into_encoded_bytes())))
        })
        .map_err(credential_error)?
        .into_secret();

    // E7: the session id comes from the front-end (one per chat
    // session, stable across rounds and turns) — not minted per
    // round, which made the ledger unable to tie rounds to sessions.
    let session: orbit_ledger::SessionId = session_id.to_string();
    let decision = request.decision_id.clone();

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

    let (outcome, reservation) = result;
    let egress_digest = Some(reservation.intent_digest).filter(|d| !d.is_empty());
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
            let context_tokens = usage
                .input_tokens
                .checked_add(usage.cache_read_tokens)
                .and_then(|total| total.checked_add(usage.cache_write_tokens))
                .ok_or_else(|| {
                    (
                        "ORBIT-E0411",
                        "provider context accounting overflow".to_owned(),
                    )
                })?;
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
                context_tokens,
                egress_digest,
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

#[cfg(test)]
mod preparation_tests {
    use super::*;

    fn config() -> TurnConfig {
        TurnConfig {
            provider_id: "fixture".into(),
            gate: "http://127.0.0.1:12345/tenant/v1?scope=exact".into(),
            model: "raw-model".into(),
            kind: ProviderKind::OpenAiCompatible,
            credential_env: None,
            pricing: None,
            max_output_tokens: 73,
            sampling: None,
            effort: None,
            supported_efforts: None,
        }
    }

    #[test]
    fn preparation_freezes_one_identity_and_body_across_measurements() {
        let config = config();
        let context = request_preparation_context(&config, Some("frozen system"), &[]).unwrap();
        let prepared = prepare_provider_request(
            &context,
            "question",
            Some(vec![crate::user_message("question")]),
            "fixture",
            "session",
        )
        .unwrap();
        let id = prepared.request.request_id.clone();
        let budget = crate::context_budget::SelectedBudget::legacy_input(&config, 1000).unwrap();
        let first = crate::context_budget::estimate_prepared_request(&prepared, &budget).unwrap();
        let second = crate::context_budget::estimate_prepared_request(&prepared, &budget).unwrap();
        assert_eq!(first, second);
        assert_eq!(prepared.request.request_id, id);
        assert_eq!(prepared.request.decision_id.0, id.0);
        assert_eq!(prepared.request.attempt_id.0, id.0);
        let probe = prepared.with_messages_for_measurement(vec![crate::user_message("smaller")]);
        assert_eq!(probe.request.request_id, id);
        assert_eq!(probe.request.decision_id, prepared.request.decision_id);
        assert_eq!(probe.request.attempt_id, prepared.request.attempt_id);
        assert_eq!(
            prepared.rendered_body().unwrap().as_json()["messages"],
            serde_json::json!([
                {"role":"system","content":"frozen system"}, {"role":"user","content":"question"}
            ])
        );
        let another = prepare_provider_request(
            &context,
            "question",
            Some(vec![crate::user_message("question")]),
            "fixture",
            "session",
        )
        .unwrap();
        assert_ne!(another.request.request_id, id);
        assert_eq!(
            another.rendered_body().unwrap().as_json(),
            prepared.rendered_body().unwrap().as_json()
        );
    }

    #[test]
    fn prepared_binding_drift_refuses_before_credentials_or_runtime() {
        let original = config();
        let context = request_preparation_context(&original, None, &[]).unwrap();
        let prepared =
            prepare_provider_request(&context, "question", None, "fixture", "session").unwrap();
        let mut changed = original;
        changed.gate = changed.gate.replace("scope=exact", "scope=different");
        let error = run_prepared_dispatch(
            std::path::Path::new("/nonexistent-context-budget-fixture"),
            &changed,
            prepared,
            None,
            orbit_provider_http::CancelToken::new(),
            "session",
        )
        .unwrap_err();
        assert_eq!(error.0, "ORBIT-E0413");
        assert_eq!(error.1, "prepared provider binding changed");
    }

    #[test]
    fn prepared_pricing_and_owner_drift_refuse_before_effects() {
        for change_pricing in [true, false] {
            let original = config();
            let context = request_preparation_context(&original, None, &[]).unwrap();
            let prepared =
                prepare_provider_request(&context, "question", None, "fixture", "session").unwrap();
            let mut changed = original;
            if change_pricing {
                changed.pricing = Some(orbit_adapter::types::CostRates {
                    input_per_million_microcents: 1,
                    output_per_million_microcents: 1,
                    cache_read_per_million_microcents: None,
                    cache_write_per_million_microcents: None,
                    reasoning_per_million_microcents: None,
                    request_flat_microcents: 1,
                });
            }
            let error = run_prepared_dispatch(
                std::path::Path::new("/nonexistent-context-budget-fixture"),
                &changed,
                prepared,
                None,
                orbit_provider_http::CancelToken::new(),
                if change_pricing {
                    "session"
                } else {
                    "different-owner"
                },
            )
            .unwrap_err();
            assert_eq!(error.0, "ORBIT-E0413");
        }
    }
}

/// The gate URL's path as an endpoint base path: exactly one leading `/`,
/// no trailing `/`. `/` and `` both normalize to `` (the adapters'
/// default — `/v1` for OpenAI-compatible and Anthropic, bare for Ollama).
fn normalize_endpoint_path(raw: &str) -> String {
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

#[cfg(test)]
mod path_tests {
    use super::normalize_endpoint_path;

    #[test]
    fn empty_and_root_stay_empty() {
        assert_eq!(normalize_endpoint_path(""), "");
        assert_eq!(normalize_endpoint_path("/"), "");
    }

    #[test]
    fn verbatim_paths_keep_one_slash_each_side() {
        assert_eq!(normalize_endpoint_path("/v1"), "/v1");
        assert_eq!(
            normalize_endpoint_path("/compatible-mode/v1/"),
            "/compatible-mode/v1"
        );
        assert_eq!(normalize_endpoint_path("/api/paas/v4"), "/api/paas/v4");
        assert_eq!(normalize_endpoint_path("/v1beta/openai"), "/v1beta/openai");
    }
}

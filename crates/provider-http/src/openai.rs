//! OpenAI-compatible HTTP adapter (DR-09 §3, §4) — v0.2.
//!
//! POSTs to `{endpoint}/chat/completions` with `stream: true`, sends the
//! bearer credential, parses the SSE stream, and yields the `ProviderStreamEvent`
//! sequence. Enforces:
//! - GW-07: no hidden retry — failures are classified, never retried here.
//! - GW-16: the credential is used for this call only, never persisted.
//! - GW-11/GW-13: sequence contiguity + usage monotonicity (validated upstream).
//! - GW-23: TLS with SPKI pin (via `tls::client_config`).
//! - Sampling serialized as provider floats ONLY at the wire boundary.

use crate::AsyncProviderAdapter;
use crate::adapter_trait::{DetailedInvokeFailure, HttpRejectionObservation};
use crate::cancel::CancelToken;
use crate::error::TransportError;
use crate::sse::SseParser;
use crate::stream::AsyncProviderEventStream;
use futures::StreamExt;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, ProviderCapabilities, ProviderEventKind, ProviderRequest,
    ProviderRouteBinding, ProviderStreamEvent, ProviderUsage, Sha256Digest,
};

/// The OpenAI-compatible HTTP adapter.
pub struct OpenAiCompatibleHttpV1 {
    identity: AdapterIdentity,
    capabilities: ProviderCapabilities,
    tls_policy: orbit_adapter::types::TlsPinPolicy,
}

impl OpenAiCompatibleHttpV1 {
    /// Build the adapter. `endpoint` is the base URL (e.g. https://api.openai.com/v1);
    /// the route binding carries the real host/port (P1-7).
    pub fn new(
        identity: AdapterIdentity,
        capabilities: ProviderCapabilities,
        tls_policy: orbit_adapter::types::TlsPinPolicy,
    ) -> Result<Self, TransportError> {
        // Validate the default TLS policy at construction. Each invocation
        // selects its exact request connection budget from the shared pool.
        let _ = crate::shared_tls_client(&tls_policy)?;
        Ok(Self {
            identity,
            capabilities,
            tls_policy,
        })
    }

    /// Whether a SPKI verifier is configured (for tests to assert it's armed).
    pub fn spki_pin_armed(&self) -> bool {
        self.tls_policy
            .spki_sha256
            .as_deref()
            .is_some_and(|s| !s.is_empty())
    }

    async fn do_invoke(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, DetailedInvokeFailure> {
        // Validate the route offline (DR-09 §3 — no I/O).
        self.validate_route(&request.route)
            .map_err(DetailedInvokeFailure::unknown)?;
        let timeouts =
            crate::RequestTimeouts::new(request).map_err(DetailedInvokeFailure::unknown)?;
        if let Some(effort) = &request.effort {
            effort
                .validate_for_openai()
                .map_err(AdapterError::ProviderConfigurationInvalid)
                .map_err(DetailedInvokeFailure::unknown)?;
        }

        // URL from the route: scheme (HttpLoopback → http, else https with
        // SPKI pinning) + host/port + the gate URL's base path (empty =
        // the historical `/v1`).
        let url = chat_completions_url(&request.route).map_err(DetailedInvokeFailure::unknown)?;

        let body = crate::request::render_request_body(
            crate::request::HttpDialect::OpenAiCompatible,
            crate::request::RequestBodyInput::from(request),
        )
        .map_err(DetailedInvokeFailure::unknown)?;
        let body_bytes = serde_json::to_vec(body.as_json()).map_err(|_| {
            DetailedInvokeFailure::unknown(AdapterError::RequestInvalidOrTooLarge(
                "request JSON could not be encoded (E0406)".into(),
            ))
        })?;

        let client = crate::tls_client_for_request(&self.tls_policy, &timeouts)
            .map_err(AdapterError::from)
            .map_err(DetailedInvokeFailure::unknown)?;
        let mut req = client
            .post(&url)
            .body(body_bytes.clone())
            .header("content-type", "application/json");
        if let Some(secret) = credential {
            // GW-16: the credential reaches THIS adapter only. The borrow is
            // for the call scope; it is never persisted into any event.
            let token = String::from_utf8_lossy(secret.expose()).into_owned();
            req = req.bearer_auth(token);
        }

        let response_deadline = timeouts
            .response_deadline()
            .map_err(DetailedInvokeFailure::unknown)?;
        let Some(response) = cancel
            .until_cancelled(crate::response_start_wait(response_deadline, req.send()))
            .await
        else {
            return Ok(crate::cancel::cancelled_stream());
        };
        if cancel.is_cancelled() {
            return Ok(crate::cancel::cancelled_stream());
        }
        let mut resp = response
            .map_err(|_| AdapterError::ProviderTimeout("response headers timed out (E0409)".into()))
            .map_err(DetailedInvokeFailure::unknown)?
            .map_err(|error| crate::reqwest_error(error, "response headers"))
            .map_err(DetailedInvokeFailure::unknown)?;

        let status = resp.status();
        if status.is_redirection() {
            return Err(DetailedInvokeFailure::unknown(
                AdapterError::ProtocolOrStreamViolation(
                    "provider redirects are not permitted (E0411)".into(),
                ),
            ));
        }
        if !status.is_success() {
            // One overall deadline bounds the entire error-body read, including
            // a slow drip. Content-Length is never evidence of clean EOF.
            let error_body_deadline = timeouts
                .idle_deadline()
                .map_err(DetailedInvokeFailure::unknown)?;
            let Some(body) = cancel
                .until_cancelled(tokio::time::timeout_at(error_body_deadline, async {
                    let mut bytes = Vec::new();
                    loop {
                        match resp.chunk().await {
                            Ok(Some(chunk)) => {
                                let remaining = 65_537 - bytes.len();
                                bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                                if bytes.len() > 65_536 {
                                    bytes.truncate(65_536);
                                    break (bytes, false);
                                }
                            }
                            Ok(None) => break (bytes, true),
                            // Preserve the old empty fallback's status
                            // class without certifying the partial body.
                            Err(_) => break (Vec::new(), false),
                        }
                    }
                }))
                .await
            else {
                return Ok(crate::cancel::cancelled_stream());
            };
            let (bytes, complete) = body
                .map_err(|_| {
                    AdapterError::ProviderTimeout("error response body stalled (E0409)".into())
                })
                .map_err(DetailedInvokeFailure::unknown)?;
            if cancel.is_cancelled() {
                return Ok(crate::cancel::cancelled_stream());
            }
            let observation = complete
                .then(|| {
                    HttpRejectionObservation::new(
                        request,
                        &self.identity,
                        &url,
                        &body_bytes,
                        status.as_u16(),
                        bytes.len(),
                    )
                })
                .flatten();
            let error =
                crate::error::status_error(status, String::from_utf8_lossy(&bytes).into_owned())
                    .await;
            if cancel.is_cancelled() {
                return Ok(crate::cancel::cancelled_stream());
            }
            return Err(match observation {
                Some(observation) => DetailedInvokeFailure::with_rejection(error, observation),
                None => DetailedInvokeFailure::unknown(error),
            });
        }

        Ok(openai_stream(
            resp.bytes_stream(),
            response_deadline,
            timeouts.idle,
            cancel.clone(),
        ))
    }
}

pub(crate) fn render_body(
    input: crate::request::RequestBodyInput<'_>,
) -> Result<serde_json::Value, AdapterError> {
    // Build the wire body — sampling as provider floats ONLY here.
    // Multi-turn transcript wins when present; otherwise the single
    // user turn (input bytes are always the newest user prompt).
    let messages = match input.messages {
        Some(transcript) => openai_messages(transcript)?,
        None => serde_json::json!([
            {"role": "user", "content": String::from_utf8_lossy(input.fallback_input).into_owned()}
        ]),
    };
    let tools: Vec<serde_json::Value> = input
        .tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                }
            })
        })
        .collect();
    let mut body = serde_json::json!({
        "model": input.model,
        "stream": true,
        "stream_options": { "include_usage": true },
        "max_tokens": input.sampling.max_output_tokens,
        "messages": messages,
    });
    if !tools.is_empty() {
        body["tools"] = serde_json::Value::Array(tools);
        body["tool_choice"] = serde_json::Value::String("auto".into());
    }
    if let Some(effort) = input.effort {
        body["reasoning_effort"] = serde_json::json!(effort);
    }
    // E8: sampling is opt-in per model. Zero means unset — omit it
    // entirely (OpenAI reasoning models reject `temperature`).
    if input.sampling.temperature_milliunits > 0 {
        body["temperature"] =
            serde_json::json!(input.sampling.temperature_milliunits as f64 / 1000.0);
    }
    if input.sampling.top_p_millionths > 0 {
        body["top_p"] = serde_json::json!(input.sampling.top_p_millionths as f64 / 1_000_000.0);
    }
    Ok(body)
}

/// Consume the OpenAI SSE byte stream and emit `ProviderStreamEvent`s.
fn openai_messages(
    transcript: &[orbit_adapter::types::ChatMessage],
) -> Result<serde_json::Value, AdapterError> {
    use orbit_adapter::types::{ChatRole, ContentBlock};
    let mut messages = Vec::with_capacity(transcript.len());
    for message in transcript {
        let content = match &message.blocks {
            None => serde_json::Value::String(message.content.clone()),
            Some(blocks) => {
                let mut parts = Vec::with_capacity(blocks.len());
                for block in blocks {
                    match block {
                        ContentBlock::Text { text } => {
                            parts.push(serde_json::json!({"type":"text","text":text}));
                        }
                        ContentBlock::Image { data, media_type }
                            if message.role == ChatRole::User && supported_image(media_type) =>
                        {
                            parts.push(serde_json::json!({
                                "type":"image_url", "image_url":{"url":format!("data:{media_type};base64,{data}")}
                            }));
                        }
                        _ => {
                            return Err(AdapterError::CapabilityMismatch(
                                "unsupported structured block or role for OpenAI chat (E0414)"
                                    .into(),
                            ));
                        }
                    }
                }
                serde_json::Value::Array(parts)
            }
        };
        let mut wire = serde_json::json!({"role":message.role.as_str(),"content":content});
        if message.role == ChatRole::Tool {
            if message.blocks.is_some() {
                return Err(AdapterError::CapabilityMismatch(
                    "structured OpenAI tool results are unsupported (E0414)".into(),
                ));
            }
            let id = message
                .tool_call_id
                .as_deref()
                .filter(|id| !id.trim().is_empty())
                .ok_or_else(|| {
                    AdapterError::RequestInvalidOrTooLarge(
                        "tool result is missing its call identity (E0412)".into(),
                    )
                })?;
            wire["tool_call_id"] = serde_json::json!(id);
            wire["content"] =
                serde_json::json!(message.tool_result.as_deref().unwrap_or(&message.content));
        } else if let Some(calls) = &message.tool_calls {
            if message.role != ChatRole::Assistant {
                return Err(AdapterError::RequestInvalidOrTooLarge(
                    "tool calls require an assistant message (E0412)".into(),
                ));
            }
            if message.blocks.is_none() && message.content.is_empty() {
                wire["content"] = serde_json::Value::Null;
            }
            wire["tool_calls"] = serde_json::json!(calls.iter().map(|call| serde_json::json!({
                "id":call.id,"type":"function","function":{"name":call.name,"arguments":call.arguments}
            })).collect::<Vec<_>>());
        }
        messages.push(wire);
    }
    Ok(messages.into())
}

pub(crate) fn supported_image(media_type: &str) -> bool {
    matches!(
        media_type,
        "image/png" | "image/jpeg" | "image/webp" | "image/gif"
    )
}

fn openai_usage(value: &serde_json::Value) -> Result<ProviderUsage, AdapterError> {
    use crate::stream::{optional_counter, protocol, required_counter};
    if !value.is_object() {
        return Err(protocol("invalid OpenAI usage object"));
    }
    let prompt = required_counter(value, "prompt_tokens")?;
    let output = required_counter(value, "completion_tokens")?;
    let details = |field: &str| -> Result<Option<&serde_json::Value>, AdapterError> {
        match value.get(field).filter(|value| !value.is_null()) {
            None => Ok(None),
            Some(value) if value.is_object() => Ok(Some(value)),
            Some(_) => Err(protocol("invalid OpenAI usage details")),
        }
    };
    let cached = details("prompt_tokens_details")?
        .map(|value| optional_counter(value, "cached_tokens"))
        .transpose()?
        .flatten()
        .unwrap_or(0);
    let reasoning = details("completion_tokens_details")?
        .map(|value| optional_counter(value, "reasoning_tokens"))
        .transpose()?
        .flatten()
        .unwrap_or(0);
    if cached > prompt || reasoning > output {
        return Err(protocol("OpenAI usage detail exceeds its total"));
    }
    if let Some(total) = optional_counter(value, "total_tokens")?
        && prompt.checked_add(output) != Some(total)
    {
        return Err(protocol("inconsistent OpenAI total usage"));
    }
    Ok(ProviderUsage {
        input_tokens: prompt - cached,
        output_tokens: output,
        cache_read_tokens: cached,
        cache_write_tokens: 0,
        reasoning_tokens: reasoning,
    })
}

fn openai_stream(
    mut bytes: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
    + Unpin
    + Send
    + 'static,
    response_deadline: tokio::time::Instant,
    idle_timeout: std::time::Duration,
    cancel: CancelToken,
) -> AsyncProviderEventStream {
    use crate::stream::{
        MAX_FRAME_BYTES, MAX_TOOL_CALLS, WireCall, append_bounded, count_bytes, incomplete_reason,
        protocol, record_reason, validate_calls,
    };
    Box::pin(async_stream::stream! {
        let mut parser = SseParser::new();
        let mut seq = 0u64;
        let mut usage = None;
        let mut saw_done = false;
        let mut finish_reason = None;
        let mut calls = std::collections::BTreeMap::<u32, WireCall>::new();
        let mut total = 0usize;
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ResponseStarted { upstream_request_id: None } });
        seq += 1;
        let mut first = true;
        // One absolute trailer window, so pings cannot keep a completed
        // reason-only response alive indefinitely while optional usage arrives.
        let mut trailer_deadline: Option<tokio::time::Instant> = None;
        while let Some(chunk) = {
            let waited = if first {
                cancel.until_cancelled(crate::response_start_wait(response_deadline, bytes.next())).await
            } else {
                let idle_deadline = match crate::checked_deadline(tokio::time::Instant::now(), idle_timeout, "stream idle") {
                    Ok(deadline) => deadline,
                    Err(error) => { yield Err(error); return; }
                };
                if let Some(trailer) = trailer_deadline {
                    cancel.until_cancelled(crate::response_start_wait(trailer.min(idle_deadline), bytes.next())).await
                } else {
                    cancel.until_cancelled(async {
                        tokio::time::timeout_at(idle_deadline, bytes.next()).await.map_err(|_| ())
                    }).await
                }
            };
            match waited {
                None => None,
                Some(Ok(item)) => item,
                Some(Err(_)) if finish_reason.is_some() => None,
                Some(Err(_)) => { yield Err(AdapterError::ProviderTimeout("response body stalled (E0409)".into())); return; }
            }
        } {
            if cancel.is_cancelled() { break; }
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) if finish_reason.is_some() && parser.is_clean() && error.is_body() => break,
                Err(error) => { yield Err(crate::reqwest_error(error, "stream")); return; }
            };
            if !chunk.is_empty() { first = false; }
            if let Err(error) = count_bytes(&mut total, chunk.len()) { yield Err(error); return; }
            let events = match parser.feed(&chunk) { Ok(events) => events, Err(error) => { yield Err(error.into()); return; } };
            for event in events {
                if event.data == "[DONE]" { saw_done = true; continue; }
                let value: serde_json::Value = match serde_json::from_str(&event.data) {
                    Ok(value) => value,
                    Err(_) => { yield Err(protocol("malformed SSE JSON")); return; }
                };
                if value.get("error").is_some() { yield Err(protocol("provider sent an error event")); return; }
                if saw_done { yield Err(protocol("provider data follows completion sentinel")); return; }
                if let Some(choices) = value.get("choices") {
                    let Some(choices) = choices.as_array() else { yield Err(protocol("invalid choices array")); return; };
                    if choices.len() > 1 { yield Err(protocol("multiple response choices are unsupported")); return; }
                    if let Some(choice) = choices.first() {
                        if choice.get("index").and_then(|v| v.as_u64()).is_some_and(|index| index != 0) {
                            yield Err(protocol("unexpected response choice index")); return;
                        }
                        let delta = &choice["delta"];
                        if finish_reason.is_some() && (
                            delta.get("content").is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
                            || delta.get("refusal").is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
                            || delta.get("tool_calls").and_then(|value| value.as_array()).is_some_and(|calls| !calls.is_empty())
                        ) {
                            yield Err(protocol("content or tool fragments follow semantic completion")); return;
                        }
                        if let Some(text) = delta.get("content").filter(|v| !v.is_null()) {
                            let Some(text) = text.as_str() else { yield Err(protocol("invalid text delta")); return; };
                            yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::TextDelta { bytes: text.as_bytes().to_vec() } }); seq += 1;
                        }
                        if let Some(refusal) = delta.get("refusal").filter(|v| !v.is_null()) {
                            let Some(refusal) = refusal.as_str() else { yield Err(protocol("invalid refusal delta")); return; };
                            if !refusal.is_empty() { finish_reason = Some("content_filter".into()); }
                        }
                        if let Some(tool_deltas) = delta.get("tool_calls") {
                            let Some(tool_deltas) = tool_deltas.as_array() else { yield Err(protocol("invalid tool call array")); return; };
                            for tool in tool_deltas {
                                let Some(index) = tool.get("index").and_then(|v| v.as_u64()).and_then(|v| u32::try_from(v).ok()) else {
                                    yield Err(protocol("tool delta is missing a valid index")); return;
                                };
                                if !calls.contains_key(&index) && calls.len() >= MAX_TOOL_CALLS { yield Err(protocol("too many tool calls")); return; }
                                let call = calls.entry(index).or_default();
                                for (field, target, limit) in [
                                    (tool.get("id"), &mut call.id, 512),
                                    (tool.pointer("/function/name"), &mut call.name, 256),
                                    (tool.pointer("/function/arguments"), &mut call.arguments, MAX_FRAME_BYTES),
                                ] {
                                    if let Some(field) = field {
                                        let Some(part) = field.as_str() else { yield Err(protocol("invalid tool delta field")); return; };
                                        if let Err(error) = append_bounded(target, part, limit) { yield Err(error); return; }
                                    }
                                }
                            }
                        }
                        if let Some(reason) = choice.get("finish_reason").filter(|v| !v.is_null()) {
                            let Some(reason) = reason.as_str() else { yield Err(protocol("invalid finish reason")); return; };
                            if let Err(error) = record_reason(&mut finish_reason, reason, &["stop","tool_calls","length","max_tokens","content_filter"]) { yield Err(error); return; }
                        }
                    }
                }
                if let Some(value) = value.get("usage").filter(|v| !v.is_null()) {
                    let parsed = match openai_usage(value) { Ok(usage) => usage, Err(error) => { yield Err(error); return; } };
                    usage = Some(parsed);
                    yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::UsageUpdate(parsed) }); seq += 1;
                }
            }
            if saw_done { break; }
            if finish_reason.is_some() && trailer_deadline.is_none() {
                trailer_deadline = match crate::checked_deadline(tokio::time::Instant::now(), idle_timeout, "usage trailer") {
                    Ok(deadline) => Some(deadline),
                    Err(error) => { yield Err(error); return; }
                };
            }
        }
        if cancel.is_cancelled() {
            yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::Finished { finish_reason: Some("cancelled".into()), final_usage: None } });
            return;
        }
        if !parser.is_clean() { yield Err(protocol("unfinished SSE frame")); return; }
        if !saw_done && finish_reason.is_none() { yield Err(protocol("stream ended without completion evidence")); return; }
        let mut reason = finish_reason.unwrap_or_else(|| "stop".into());
        if !incomplete_reason(&reason) {
            if reason == "tool_calls" && calls.is_empty() { yield Err(protocol("tool completion has no calls")); return; }
            if let Err(error) = validate_calls(&calls) { yield Err(error); return; }
            if !calls.is_empty() {
                reason = "tool_calls".into();
                for (index, call) in calls {
                    yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ToolCallStarted { call_index: index, provider_call_id: Some(call.id), name: call.name } }); seq += 1;
                    yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ToolCallArgumentsDelta { call_index: index, bytes: call.arguments.into_bytes() } }); seq += 1;
                    yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ToolCallFinished { call_index: index } }); seq += 1;
                }
            }
        }
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::Finished { finish_reason: Some(reason), final_usage: usage } });
    })
}

#[async_trait::async_trait]
impl AsyncProviderAdapter for OpenAiCompatibleHttpV1 {
    fn identity(&self) -> AdapterIdentity {
        self.identity.clone()
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn validate_route(&self, route: &ProviderRouteBinding) -> Result<(), AdapterError> {
        if route.adapter_kind != AdapterKind::OpenAiCompatibleHttpV1
            && route.adapter_kind != AdapterKind::MockHttpV1
        {
            return Err(AdapterError::CapabilityMismatch(format!(
                "route kind {:?} not OpenAI-compatible (E0414)",
                route.adapter_kind
            )));
        }
        if route.adapter_profile_digest.as_str() != self.identity.profile_digest.as_str() {
            return Err(AdapterError::AdapterProfileDigestMismatch("E0422".into()));
        }
        chat_completions_url(route)?;
        Ok(())
    }
    async fn invoke(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        self.do_invoke(request, credential, cancel)
            .await
            .map_err(DetailedInvokeFailure::into_error)
    }

    async fn invoke_detailed(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, DetailedInvokeFailure> {
        self.do_invoke(request, credential, cancel).await
    }
}

/// Helpers for tests/fixtures.
pub fn openai_identity() -> AdapterIdentity {
    AdapterIdentity {
        kind: AdapterKind::OpenAiCompatibleHttpV1,
        implementation_digest: Sha256Digest("i".repeat(64)),
        profile_digest: Sha256Digest("p".repeat(64)),
    }
}

pub fn openai_capabilities() -> ProviderCapabilities {
    ProviderCapabilities {
        supports_streaming: true,
        supports_tools: true,
        supports_json_schema_output: false,
        max_input_tokens: 1_000_000,
        max_output_tokens: 64_000,
    }
}

/// The chat-completions URL for a route: `{scheme}://{host}:{port}{path}/chat/completions`.
/// An empty `endpoint_path` keeps the historical `/v1` default.
pub fn chat_completions_url(route: &ProviderRouteBinding) -> Result<String, AdapterError> {
    crate::endpoint::provider_method_url(route, "/v1", "chat/completions")
}

#[cfg(test)]
mod url_tests {
    use super::chat_completions_url;
    use super::openai_identity;
    use orbit_adapter::types::{EndpointScheme, ProviderRouteBinding};

    fn route(host: &str, port: u16, path: &str) -> ProviderRouteBinding {
        ProviderRouteBinding {
            provider_id: orbit_adapter::types::ProviderId("p".into()),
            deployment_id: orbit_adapter::types::DeploymentId("p".into()),
            region_id: orbit_adapter::types::RegionId("r".into()),
            adapter_kind: orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1,
            adapter_implementation_digest: openai_identity().implementation_digest,
            adapter_profile_digest: openai_identity().profile_digest,
            endpoint_digest: orbit_adapter::types::Sha256Digest("e".repeat(64)),
            expected_model: "m".into(),
            pricing_digest: orbit_adapter::types::Sha256Digest("0".repeat(64)),
            endpoint_host: host.into(),
            endpoint_port: port,
            endpoint_scheme: EndpointScheme::Https,
            endpoint_path: path.into(),
            endpoint_query: None,
        }
    }

    #[test]
    fn empty_path_keeps_the_v1_default() {
        assert_eq!(
            chat_completions_url(&route("api.openai.com", 443, "")).unwrap(),
            "https://api.openai.com:443/v1/chat/completions"
        );
    }

    #[test]
    fn gate_paths_are_carried_verbatim() {
        // DashScope international
        assert_eq!(
            chat_completions_url(&route(
                "dashscope-intl.aliyuncs.com",
                443,
                "/compatible-mode/v1"
            ))
            .unwrap(),
            "https://dashscope-intl.aliyuncs.com:443/compatible-mode/v1/chat/completions"
        );
        // Z.ai (GLM)
        assert_eq!(
            chat_completions_url(&route("api.z.ai", 443, "/api/paas/v4")).unwrap(),
            "https://api.z.ai:443/api/paas/v4/chat/completions"
        );
        // Gemini's OpenAI-compat surface
        assert_eq!(
            chat_completions_url(&route(
                "generativelanguage.googleapis.com",
                443,
                "/v1beta/openai"
            ))
            .unwrap(),
            "https://generativelanguage.googleapis.com:443/v1beta/openai/chat/completions"
        );
    }
}

#[cfg(test)]
mod trailer_deadline_tests {
    use super::{
        CancelToken, ProviderEventKind, ProviderStreamEvent, ProviderUsage, openai_stream,
    };
    use futures::{FutureExt, StreamExt};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Duration;

    // No socket, thread or clock override: the second chunk is an already
    // buffered usage trailer once the test flips ready and explicitly repolls.
    fn buffered_trailer(
        ready: Arc<AtomicBool>,
        pending: Arc<AtomicBool>,
        usage_polls: Arc<AtomicUsize>,
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin {
        let mut first = true;
        let mut emitted = false;
        futures::stream::poll_fn(move |_| {
            if first {
                first = false;
                return Poll::Ready(Some(Ok(bytes::Bytes::from_static(
                    b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n"
                ))));
            }
            if emitted {
                return Poll::Ready(None);
            }
            if !ready.load(Ordering::SeqCst) {
                pending.store(true, Ordering::SeqCst);
                return Poll::Pending;
            }
            emitted = true;
            usage_polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(bytes::Bytes::from_static(
                b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\ndata: [DONE]\n\n"
            ))))
        })
    }

    fn assert_prefix(events: &[ProviderStreamEvent]) {
        assert!(matches!(
            &events[0].event,
            ProviderEventKind::ResponseStarted {
                upstream_request_id: None
            }
        ));
        assert!(matches!(&events[1].event,
            ProviderEventKind::TextDelta { bytes } if bytes == b"ok"));
        assert!(
            events
                .iter()
                .enumerate()
                .all(|(index, event)| event.sequence == index as u64)
        );
    }

    #[tokio::test]
    async fn buffered_usage_after_expired_trailer_is_not_consumed() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let ready = Arc::new(AtomicBool::new(false));
            let pending = Arc::new(AtomicBool::new(false));
            let usage_polls = Arc::new(AtomicUsize::new(0));
            let idle = Duration::from_millis(25);
            let mut stream = openai_stream(
                buffered_trailer(ready.clone(), pending.clone(), usage_polls.clone()),
                tokio::time::Instant::now() + Duration::from_secs(1),
                idle,
                CancelToken::new(),
            );
            let mut events = vec![stream.next().await.unwrap().unwrap(), stream.next().await.unwrap().unwrap()];
            // This resumes past semantic completion, installs the absolute
            // trailer deadline and leaves its inner wait pending on the body.
            assert!(stream.next().now_or_never().is_none());
            assert!(pending.load(Ordering::SeqCst));
            let pending_at = tokio::time::Instant::now();
            tokio::time::sleep_until(pending_at + idle + Duration::from_millis(25)).await;
            assert!(tokio::time::Instant::now() >= pending_at + idle);
            ready.store(true, Ordering::SeqCst);
            while let Some(event) = stream.next().await { events.push(event.unwrap()); }
            assert_prefix(&events);
            assert_eq!(events.len(), 3);
            assert_eq!(usage_polls.load(Ordering::SeqCst), 0);
            assert!(matches!(&events[2].event,
                ProviderEventKind::Finished { finish_reason: Some(reason), final_usage: None } if reason == "stop"));
        }).await.expect("bounded trailer expiry test completed");
    }

    #[tokio::test]
    async fn buffered_usage_inside_trailer_window_is_preserved() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let ready = Arc::new(AtomicBool::new(true));
            let pending = Arc::new(AtomicBool::new(false));
            let usage_polls = Arc::new(AtomicUsize::new(0));
            let mut stream = openai_stream(
                buffered_trailer(ready, pending.clone(), usage_polls.clone()),
                tokio::time::Instant::now() + Duration::from_secs(5),
                Duration::from_secs(5),
                CancelToken::new(),
            );
            let mut events = Vec::new();
            while let Some(event) = stream.next().await { events.push(event.unwrap()); }
            assert_prefix(&events);
            assert_eq!(events.len(), 4);
            assert!(!pending.load(Ordering::SeqCst));
            assert_eq!(usage_polls.load(Ordering::SeqCst), 1);
            let expected = ProviderUsage { input_tokens: 11, output_tokens: 7, ..ProviderUsage::default() };
            assert!(matches!(&events[2].event,
                ProviderEventKind::UsageUpdate(usage) if *usage == expected));
            assert!(matches!(&events[3].event,
                ProviderEventKind::Finished { finish_reason: Some(reason), final_usage: Some(usage) }
                    if reason == "stop" && *usage == expected));
        }).await.expect("bounded healthy trailer test completed");
    }
}

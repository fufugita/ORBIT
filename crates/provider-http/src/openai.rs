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
    client: reqwest::Client,
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
        // E6: draw from the shared client pool — one TLS config, one
        // connection pool per policy, reused across every round.
        let client = crate::shared_tls_client(&tls_policy)?;
        Ok(Self {
            identity,
            capabilities,
            client,
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
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        // Validate the route offline (DR-09 §3 — no I/O).
        self.validate_route(&request.route)?;
        if let Some(effort) = &request.effort {
            effort
                .validate_for_openai()
                .map_err(AdapterError::ProviderConfigurationInvalid)?;
        }

        // URL from the route: scheme (HttpLoopback → http, else https with
        // SPKI pinning) + host/port + the gate URL's base path (empty =
        // the historical `/v1`).
        let url = chat_completions_url(&request.route)?;

        // Build the wire body — sampling as provider floats ONLY here.
        // Multi-turn transcript wins when present; otherwise the single
        // user turn (input bytes are always the newest user prompt).
        let messages = match &request.messages {
            Some(transcript) => openai_messages(transcript)?,
            None => serde_json::json!([
                {"role": "user", "content": String::from_utf8_lossy(request.input.expose()).into_owned()}
            ]),
        };
        let tools: Vec<serde_json::Value> = request
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
            "model": request.route.expected_model,
            "stream": true,
            "stream_options": { "include_usage": true },
            "max_tokens": request.sampling.max_output_tokens,
            "messages": messages,
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::Value::Array(tools);
            body["tool_choice"] = serde_json::Value::String("auto".into());
        }
        if let Some(effort) = &request.effort {
            body["reasoning_effort"] = serde_json::json!(effort);
        }
        // E8: sampling is opt-in per model. Zero means unset — omit it
        // entirely (OpenAI reasoning models reject `temperature`).
        if request.sampling.temperature_milliunits > 0 {
            body["temperature"] =
                serde_json::json!(request.sampling.temperature_milliunits as f64 / 1000.0);
        }
        if request.sampling.top_p_millionths > 0 {
            body["top_p"] =
                serde_json::json!(request.sampling.top_p_millionths as f64 / 1_000_000.0);
        }

        let mut req = self
            .client
            .post(&url)
            .json(&body)
            .header("content-type", "application/json");
        if let Some(secret) = credential {
            // GW-16: the credential reaches THIS adapter only. The borrow is
            // for the call scope; it is never persisted into any event.
            let token = String::from_utf8_lossy(secret.expose()).into_owned();
            req = req.bearer_auth(token);
        }

        let connect_timeout = std::time::Duration::from_millis(request.connect_timeout_ms);
        let Some(response) = cancel
            .until_cancelled(tokio::time::timeout(connect_timeout, req.send()))
            .await
        else {
            return Ok(crate::cancel::cancelled_stream());
        };
        let resp = response
            .map_err(|_| AdapterError::ProviderTimeout("connect timeout (E0409)".into()))?
            .map_err(|e| AdapterError::ProviderTransportFailure(format!("send: {e}")))?;

        let status = resp.status();
        if status.is_redirection() {
            return Err(AdapterError::ProtocolOrStreamViolation(
                "provider redirects are not permitted (E0411)".into(),
            ));
        }
        if !status.is_success() {
            // E1/E2: read the body, classify precisely, retry 5xx.
            let Some(body) = cancel
                .until_cancelled(tokio::time::timeout(
                    std::time::Duration::from_millis(request.idle_timeout_ms),
                    resp.text(),
                ))
                .await
            else {
                return Ok(crate::cancel::cancelled_stream());
            };
            let body = body
                .map_err(|_| {
                    AdapterError::ProviderTimeout("error response body stalled (E0409)".into())
                })?
                .unwrap_or_default();
            return Err(crate::error::status_error(status, body).await);
        }

        Ok(openai_stream(
            resp.bytes_stream(),
            request.first_byte_timeout_ms,
            request.idle_timeout_ms,
            cancel.clone(),
        ))
    }
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
    first_byte_timeout_ms: u64,
    idle_timeout_ms: u64,
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
            let idle = std::time::Duration::from_millis(if first { first_byte_timeout_ms } else { idle_timeout_ms });
            let budget = trailer_deadline.map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now())).unwrap_or(idle).min(idle);
            if trailer_deadline.is_some() && budget.is_zero() { None } else {
                match cancel.until_cancelled(tokio::time::timeout(budget, bytes.next())).await {
                    None => None,
                    Some(Ok(item)) => item,
                    Some(Err(_)) if finish_reason.is_some() => None,
                    Some(Err(_)) => { yield Err(AdapterError::ProviderTimeout("stream stalled (E0409)".into())); return; }
                }
            }
        } {
            if cancel.is_cancelled() { break; }
            first = false;
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) if finish_reason.is_some() && parser.is_clean() && error.is_body() => break,
                Err(error) => { yield Err(AdapterError::ProviderTransportFailure(error.to_string())); return; }
            };
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
                trailer_deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_millis(idle_timeout_ms));
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

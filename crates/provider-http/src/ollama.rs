//! Ollama HTTP adapter (DR-09 §3, §4) — v0.2.
//!
//! Speaks `/api/chat` NDJSON over HTTP loopback. The route MUST use
//! `HttpLoopback`; no credential is required or persisted.

use crate::{AsyncProviderAdapter, AsyncProviderEventStream, CancelToken};
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, ProviderCapabilities, ProviderRequest, ProviderRouteBinding,
    UsageObservationMetaV1, UsageReasoningReportingV1, UsageSnapshotOriginV1,
};

pub struct OllamaHttpV1 {
    identity: AdapterIdentity,
    capabilities: ProviderCapabilities,
}

impl OllamaHttpV1 {
    pub fn new(
        identity: AdapterIdentity,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, AdapterError> {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let _ = crate::shared_plain_client().map_err(AdapterError::from)?;
        Ok(Self {
            identity,
            capabilities,
        })
    }
}

#[async_trait::async_trait]
impl AsyncProviderAdapter for OllamaHttpV1 {
    fn identity(&self) -> AdapterIdentity {
        self.identity.clone()
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn validate_route(&self, route: &ProviderRouteBinding) -> Result<(), AdapterError> {
        if route.adapter_kind != AdapterKind::LocalProcessV1 {
            return Err(AdapterError::CapabilityMismatch(
                "Ollama route must be LocalProcessV1 (E0414)".into(),
            ));
        }
        if route.adapter_profile_digest != self.identity.profile_digest {
            return Err(AdapterError::AdapterProfileDigestMismatch("E0422".into()));
        }
        if route.endpoint_scheme != orbit_adapter::types::EndpointScheme::HttpLoopback
            || !(route.endpoint_path == "/api" || route.endpoint_path.ends_with("/api"))
        {
            return Err(AdapterError::ProviderConfigurationInvalid(
                "Ollama requires loopback HTTP with an explicit API base (E0401)".into(),
            ));
        }
        crate::endpoint::provider_method_url(route, "/api", "chat")?;
        Ok(())
    }

    async fn invoke(
        &self,
        request: &ProviderRequest,
        _credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        self.validate_route(&request.route)?;
        let timeouts = crate::RequestTimeouts::new(request)?;
        if let Some(effort) = &request.effort {
            effort
                .validate_for_ollama()
                .map_err(AdapterError::ProviderConfigurationInvalid)?;
        }
        let url = crate::endpoint::provider_method_url(&request.route, "/api", "chat")?;
        let body = crate::request::render_request_body(
            crate::request::HttpDialect::Ollama,
            crate::request::RequestBodyInput::from(request),
        )?;

        let client = crate::plain_client_for_request(&timeouts).map_err(AdapterError::from)?;
        let req = client.post(url).json(body.as_json());
        let response_deadline = timeouts.response_deadline()?;
        let Some(response) = cancel
            .until_cancelled(crate::response_start_wait(response_deadline, req.send()))
            .await
        else {
            return Ok(crate::cancel::cancelled_stream());
        };
        if cancel.is_cancelled() {
            return Ok(crate::cancel::cancelled_stream());
        }
        let resp = response
            .map_err(|_| crate::dispatch_deadline_error("response headers"))?
            .map_err(|error| crate::reqwest_dispatch_error(error, "response headers"))?;
        if resp.status().is_redirection() {
            return Err(AdapterError::ProtocolOrStreamViolation(
                "provider redirects are not permitted (E0411)".into(),
            ));
        }
        if !resp.status().is_success() {
            // E1: the body carries the provider's own message; E2:
            // 529/5xx classify retryable.
            let status = resp.status();
            let error_body_deadline = timeouts.idle_deadline()?;
            let Some(body) = cancel
                .until_cancelled(tokio::time::timeout_at(error_body_deadline, resp.text()))
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
        Ok(ollama_stream(
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
    // Full conversation when present; else the single prompt. Ollama's
    // chat API takes tool calls/results natively on messages.
    let messages = match input.messages {
        Some(transcript) => ollama_messages(transcript)?,
        None => serde_json::json!([
            {"role":"user","content":String::from_utf8_lossy(input.fallback_input).into_owned()}
        ]),
    };
    let mut body = serde_json::json!({
        "model": input.model,
        "stream": true,
        "messages": messages,
        "options": {
            "num_predict": input.sampling.max_output_tokens,
        }
    });
    if !input.tools.is_empty() {
        body["tools"] = serde_json::json!(input.tools.iter().map(|tool| serde_json::json!({
            "type":"function", "function":{"name":tool.name,"description":tool.description,"parameters":tool.parameters}
        })).collect::<Vec<_>>());
    }
    // E8: sampling opt-in per model; zero means unset — omitted.
    if let Some(effort) = input.effort {
        body["think"] = serde_json::json!(effort);
    }
    if input.sampling.temperature_milliunits > 0 {
        body["options"]["temperature"] =
            serde_json::json!(input.sampling.temperature_milliunits as f64 / 1000.0);
    }
    if input.sampling.top_p_millionths > 0 {
        body["options"]["top_p"] =
            serde_json::json!(input.sampling.top_p_millionths as f64 / 1_000_000.0);
    }
    Ok(body)
}

fn ollama_messages(
    transcript: &[orbit_adapter::types::ChatMessage],
) -> Result<serde_json::Value, AdapterError> {
    use orbit_adapter::types::{ChatRole, ContentBlock};
    let mut messages = Vec::with_capacity(transcript.len());
    let mut pending = std::collections::BTreeMap::<String, String>::new();
    for message in transcript {
        let mut content = String::new();
        let mut images = Vec::new();
        match &message.blocks {
            None => content = message.content.clone(),
            Some(blocks) => {
                for block in blocks {
                    match block {
                        ContentBlock::Text { text } => content.push_str(text),
                        ContentBlock::Image { data, media_type }
                            if message.role == ChatRole::User
                                && crate::openai::supported_image(media_type) =>
                        {
                            images.push(data.clone())
                        }
                        _ => {
                            return Err(AdapterError::CapabilityMismatch(
                                "unsupported structured block or role for Ollama (E0414)".into(),
                            ));
                        }
                    }
                }
            }
        }
        let mut wire = serde_json::json!({"role":message.role.as_str(),"content":content});
        if !images.is_empty() {
            wire["images"] = serde_json::json!(images);
        }
        if message.role == ChatRole::Tool {
            if message.blocks.is_some() {
                return Err(AdapterError::CapabilityMismatch(
                    "structured Ollama tool results are unsupported (E0414)".into(),
                ));
            }
            let id = message
                .tool_call_id
                .as_deref()
                .ok_or_else(|| crate::stream::protocol("tool result has no call identity"))?;
            let name = pending.remove(id).ok_or_else(|| {
                crate::stream::protocol("tool result has no matching assistant call")
            })?;
            wire["tool_name"] = serde_json::json!(name);
            wire["content"] =
                serde_json::json!(message.tool_result.as_deref().unwrap_or(&message.content));
        } else if let Some(calls) = &message.tool_calls {
            if message.role != ChatRole::Assistant {
                return Err(crate::stream::protocol("tool calls require assistant role"));
            }
            let mut wire_calls = Vec::with_capacity(calls.len());
            for call in calls {
                if call.id.trim().is_empty()
                    || call.name.trim().is_empty()
                    || pending.insert(call.id.clone(), call.name.clone()).is_some()
                {
                    return Err(crate::stream::protocol(
                        "invalid outgoing tool call identity",
                    ));
                }
                let arguments: serde_json::Value = serde_json::from_str(&call.arguments)
                    .map_err(|_| crate::stream::protocol("invalid outgoing tool call arguments"))?;
                if !arguments.is_object() {
                    return Err(crate::stream::protocol(
                        "outgoing arguments must be an object",
                    ));
                }
                wire_calls
                    .push(serde_json::json!({"function":{"name":call.name,"arguments":arguments}}));
            }
            wire["tool_calls"] = wire_calls.into();
        }
        messages.push(wire);
    }
    Ok(messages.into())
}

#[derive(Default)]
struct OllamaState {
    calls: std::collections::BTreeMap<u32, crate::stream::WireCall>,
    done: bool,
    reason: Option<String>,
    usage: Option<orbit_adapter::types::ProviderUsage>,
    next_index: u32,
}

impl OllamaState {
    fn line(&mut self, line: &[u8]) -> Result<Option<String>, AdapterError> {
        use crate::stream::{MAX_FRAME_BYTES, MAX_TOOL_CALLS, WireCall, protocol, record_reason};
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        if self.done {
            return Err(protocol("native data follows done marker"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| protocol("malformed native JSON"))?;
        if !value.is_object() {
            return Err(protocol("native response must be an object"));
        }
        if value.get("error").is_some() {
            return Err(protocol("native provider sent an error"));
        }
        let message = value.get("message");
        if message.is_some_and(|message| !message.is_object()) {
            return Err(protocol("invalid native message"));
        }
        let text = message
            .and_then(|message| message.get("content"))
            .map(|text| {
                text.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| protocol("invalid native content"))
            })
            .transpose()?;
        if let Some(tools) = message.and_then(|message| message.get("tool_calls")) {
            let tools = tools
                .as_array()
                .ok_or_else(|| protocol("invalid native calls"))?;
            for tool in tools {
                if self.calls.len() >= MAX_TOOL_CALLS {
                    return Err(protocol("too many native calls"));
                }
                let function = tool
                    .get("function")
                    .and_then(|function| function.as_object())
                    .ok_or_else(|| protocol("native call has no function"))?;
                let index = match function.get("index") {
                    Some(index) => index
                        .as_u64()
                        .and_then(|index| u32::try_from(index).ok())
                        .ok_or_else(|| protocol("invalid native call index"))?,
                    None => {
                        while self.calls.contains_key(&self.next_index) {
                            self.next_index = self
                                .next_index
                                .checked_add(1)
                                .ok_or_else(|| protocol("native call index overflow"))?;
                        }
                        self.next_index
                    }
                };
                let name = function
                    .get("name")
                    .and_then(|name| name.as_str())
                    .filter(|name| !name.trim().is_empty() && name.len() <= 256)
                    .ok_or_else(|| protocol("native call has no valid name"))?;
                let arguments = function
                    .get("arguments")
                    .filter(|arguments| arguments.is_object())
                    .ok_or_else(|| protocol("native arguments must be an object"))?;
                let arguments = serde_json::to_string(arguments)
                    .map_err(|_| protocol("invalid native arguments"))?;
                if arguments.len() > MAX_FRAME_BYTES {
                    return Err(protocol("native arguments exceed byte limit"));
                }
                let call = WireCall {
                    id: format!("ollama-{index}"),
                    name: name.into(),
                    arguments,
                };
                if self.calls.insert(index, call).is_some() {
                    return Err(protocol("duplicate native call index"));
                }
                self.next_index = self.next_index.max(index.saturating_add(1));
            }
        }
        if let Some(reason) = value.get("done_reason").filter(|reason| !reason.is_null()) {
            let reason = reason
                .as_str()
                .ok_or_else(|| protocol("invalid native done reason"))?;
            record_reason(
                &mut self.reason,
                reason,
                &["stop", "length", "max_tokens", "content_filter", "refusal"],
            )?;
        }
        if let Some(done) = value.get("done") {
            self.done = done
                .as_bool()
                .ok_or_else(|| protocol("invalid native done marker"))?;
        }
        if self.done
            && (value.get("prompt_eval_count").is_some() || value.get("eval_count").is_some())
        {
            self.usage = Some(orbit_adapter::types::ProviderUsage {
                input_tokens: crate::stream::required_counter(&value, "prompt_eval_count")?,
                output_tokens: crate::stream::required_counter(&value, "eval_count")?,
                ..Default::default()
            });
        }
        Ok(text)
    }
}

fn ollama_stream(
    mut bytes: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
    + Unpin
    + Send
    + 'static,
    response_deadline: tokio::time::Instant,
    idle_timeout: std::time::Duration,
    cancel: CancelToken,
) -> AsyncProviderEventStream {
    use crate::stream::{
        MAX_FRAME_BYTES, count_bytes, incomplete_reason, protocol, validate_calls,
    };
    use futures::StreamExt;
    use orbit_adapter::types::{ProviderEventKind, ProviderStreamEvent};
    Box::pin(async_stream::stream! {
        let mut line = Vec::new();
        let mut state = OllamaState::default();
        let mut seq = 0u64;
        let mut total = 0usize;
        yield Ok(ProviderStreamEvent { usage_observation: None, sequence:seq, event:ProviderEventKind::ResponseStarted { upstream_request_id:None } }); seq += 1;
        let mut first = true;
        while let Some(chunk) = {
            let waited = if first {
                cancel.until_cancelled(crate::response_start_wait(response_deadline, bytes.next())).await
            } else {
                let deadline = match crate::checked_deadline(tokio::time::Instant::now(), idle_timeout, "stream idle") {
                    Ok(deadline) => deadline,
                    Err(error) => { yield Err(error); return; }
                };
                cancel.until_cancelled(async {
                    tokio::time::timeout_at(deadline, bytes.next()).await.map_err(|_| ())
                }).await
            };
            match waited {
                None => None,
                Some(Ok(item)) => item,
                Some(Err(_)) => { yield Err(AdapterError::ProviderTimeout("native stream stalled (E0409)".into())); return; }
            }
        } {
            if cancel.is_cancelled() { break; }
            let chunk = match chunk { Ok(chunk) => chunk, Err(error) => { yield Err(crate::reqwest_error(error, "stream")); return; } };
            if !chunk.is_empty() { first = false; }
            if let Err(error) = count_bytes(&mut total, chunk.len()) { yield Err(error); return; }
            for byte in chunk {
                if byte == b'\n' {
                    match state.line(&line) {
                        Ok(Some(text)) if !text.is_empty() => {
                            yield Ok(ProviderStreamEvent { usage_observation: None, sequence:seq, event:ProviderEventKind::TextDelta { bytes:text.into_bytes() } }); seq += 1;
                        }
                        Ok(_) => {},
                        Err(error) => { yield Err(error); return; }
                    }
                    line.clear();
                } else {
                    if line.len() >= MAX_FRAME_BYTES { yield Err(protocol("native JSON line exceeds byte limit")); return; }
                    line.push(byte);
                }
            }
            if state.done { break; }
        }
        if cancel.is_cancelled() {
            yield Ok(ProviderStreamEvent { usage_observation: None, sequence:seq, event:ProviderEventKind::Finished { finish_reason:Some("cancelled".into()), final_usage:None } });
            return;
        }
        if !line.is_empty() {
            match state.line(&line) {
                Ok(Some(text)) if !text.is_empty() => {
                    yield Ok(ProviderStreamEvent { usage_observation: None, sequence:seq, event:ProviderEventKind::TextDelta { bytes:text.into_bytes() } }); seq += 1;
                }
                Ok(_) => {},
                Err(error) => { yield Err(error); return; }
            }
        }
        if !state.done { yield Err(protocol("native stream ended without done marker")); return; }
        let mut reason = state.reason.unwrap_or_else(|| "stop".into());
        if !incomplete_reason(&reason) {
            if let Err(error) = validate_calls(&state.calls) { yield Err(error); return; }
            if !state.calls.is_empty() {
                reason = "tool_calls".into();
                for (index, call) in state.calls {
                    yield Ok(ProviderStreamEvent { usage_observation: None, sequence:seq, event:ProviderEventKind::ToolCallStarted { call_index:index, provider_call_id:Some(call.id), name:call.name } }); seq += 1;
                    yield Ok(ProviderStreamEvent { usage_observation: None, sequence:seq, event:ProviderEventKind::ToolCallArgumentsDelta { call_index:index, bytes:call.arguments.into_bytes() } }); seq += 1;
                    yield Ok(ProviderStreamEvent { usage_observation: None, sequence:seq, event:ProviderEventKind::ToolCallFinished { call_index:index } }); seq += 1;
                }
            }
        }
        yield Ok(ProviderStreamEvent { usage_observation: state.usage.map(|_| UsageObservationMetaV1 { version: 1, reasoning_reporting: UsageReasoningReportingV1::NotReported, snapshot_origin: UsageSnapshotOriginV1::ProviderReported }), sequence:seq, event:ProviderEventKind::Finished { finish_reason:Some(reason), final_usage:state.usage } });
    })
}

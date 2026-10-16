//! Anthropic Messages HTTP adapter (DR-09 §3, §4; roadmap §Providers).
//!
//! Speaks the Messages streaming wire format (`/v1/messages`) with the
//! credential in `x-api-key`. Full conversation support: top-level
//! `system`, messages mapped from content blocks, tools with
//! `input_schema`, adaptive thinking, one explicit `cache_control`
//! breakpoint at the end of the system prompt, and the real stop
//! reasons (`end_turn`, `tool_use`, `max_tokens`, `pause_turn`).
//! Thinking deltas are assembled into opaque blocks for replay — they
//! are never surfaced as text.

use crate::{AsyncProviderAdapter, AsyncProviderEventStream, CancelToken};
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, ChatMessage, ChatRole, ContentBlock, ProviderCapabilities,
    ProviderRequest, ProviderRouteBinding, ToolDefinition,
};

/// Anthropic Messages v1 async HTTP adapter.
pub struct AnthropicMessagesV1 {
    identity: AdapterIdentity,
    capabilities: ProviderCapabilities,
    client: reqwest::Client,
}

impl AnthropicMessagesV1 {
    pub fn new(
        identity: AdapterIdentity,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, AdapterError> {
        // reqwest 0.12 async needs the rustls crypto provider installed
        // once per process (same as the OpenAI adapter's TLS path).
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        // E6: shared client — one connection pool for the process.
        let client = crate::shared_plain_client()
            .map_err(|e| AdapterError::ProviderTransportFailure(e.to_string()))?;
        Ok(Self {
            identity,
            capabilities,
            client,
        })
    }
}

/// The adapter identity for route binding.
pub fn anthropic_identity() -> AdapterIdentity {
    AdapterIdentity {
        kind: AdapterKind::DeclarativeHttpJsonV1,
        implementation_digest: orbit_adapter::types::Sha256Digest("a".repeat(64)),
        profile_digest: orbit_adapter::types::Sha256Digest(
            "anthropic-profile-1".repeat(3).chars().take(64).collect(),
        ),
    }
}

pub fn anthropic_capabilities() -> ProviderCapabilities {
    ProviderCapabilities {
        supports_streaming: true,
        supports_tools: true,
        supports_json_schema_output: false,
        max_input_tokens: 200_000,
        max_output_tokens: 128_000,
    }
}

pub(crate) fn render_body(
    input: crate::request::RequestBodyInput<'_>,
) -> Result<serde_json::Value, AdapterError> {
    // Messages: the transcript when present, else the single prompt.
    let (system, messages) = match input.messages {
        Some(transcript) => anthropic_messages(transcript),
        None => (
            None,
            vec![serde_json::json!({
                "role": "user",
                "content": [{
                    "type": "text",
                    "text": String::from_utf8_lossy(input.fallback_input).into_owned(),
                }],
            })],
        ),
    };

    let mut body = serde_json::json!({
        "model": input.model,
        "stream": true,
        "max_tokens": input.sampling.max_output_tokens,
        "messages": messages,
        // Adaptive thinking: it cannot be disabled on current models;
        // display stays omitted (chain-of-thought never renders).
        // No temperature: the Messages API rejects temperature combined
        // with thinking, and adaptive thinking owns sampling (B7).
        "thinking": { "type": "adaptive" },
    });
    if let Some(effort) = input.effort {
        body["output_config"] = serde_json::json!({ "effort": effort });
    }

    // One explicit cache breakpoint at the end of the system prompt:
    // the stable prefix caches, the growing tail re-caches per round.
    if let Some(sys) = &system {
        body["system"] = serde_json::json!([{
            "type": "text",
            "text": sys,
            "cache_control": { "type": "ephemeral" },
        }]);
    }

    let tools = anthropic_tools(input.tools);
    if !tools.is_empty() {
        body["tools"] = serde_json::Value::Array(tools);
        // tool_choice: auto only — forced tool choice 400s on current
        // Claude models (roadmap §Providers).
        body["tool_choice"] = serde_json::json!({ "type": "auto" });
    }
    Ok(body)
}

/// Map the transcript to Anthropic messages. System messages are
/// extracted (the wire format takes them top-level, not inline); tool
/// results become `tool_result` blocks on user messages; assistant
/// tool calls become `tool_use` blocks.
fn anthropic_messages(messages: &[ChatMessage]) -> (Option<String>, Vec<serde_json::Value>) {
    let mut system_parts: Vec<String> = Vec::new();
    let mut wire: Vec<serde_json::Value> = Vec::new();

    for m in messages {
        match m.role {
            ChatRole::System => {
                if !m.content.is_empty() {
                    system_parts.push(m.content.clone());
                }
            }
            ChatRole::User => {
                let blocks = user_blocks(m);
                wire.push(serde_json::json!({ "role": "user", "content": blocks }));
            }
            ChatRole::Assistant => {
                let mut blocks: Vec<serde_json::Value> = Vec::new();
                // Replay opaque blocks verbatim (thinking, redacted
                // thinking, compaction) — the API requires them intact.
                if let Some(obs) = &m.blocks {
                    for b in obs {
                        if let ContentBlock::Opaque { json } = b
                            && let Ok(v) = serde_json::from_str::<serde_json::Value>(json)
                        {
                            blocks.push(v);
                        }
                    }
                }
                if !m.content.is_empty() {
                    blocks.push(serde_json::json!({ "type": "text", "text": m.content }));
                }
                if let Some(calls) = &m.tool_calls {
                    for tc in calls {
                        blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": serde_json::from_str::<serde_json::Value>(&tc.arguments)
                                .unwrap_or(serde_json::json!({})),
                        }));
                    }
                }
                if !blocks.is_empty() {
                    wire.push(serde_json::json!({ "role": "assistant", "content": blocks }));
                }
            }
            ChatRole::Tool => {
                // A tool result rides on a user message as a tool_result
                // block keyed by the originating tool_use id.
                let id = m.tool_call_id.clone().unwrap_or_default();
                let content = m.tool_result.clone().unwrap_or_else(|| m.content.clone());
                // E4: the typed verdict, shared with the engine and
                // the ledger — never a substring of the content.
                let is_error = orbit_tools::result_is_error(&content);
                // An image Read attached its block: tool_result.content
                // becomes a block array — the text line plus the image,
                // the wire shape Anthropic vision accepts.
                let wire_content: serde_json::Value = if let Some(blocks) =
                    m.blocks.as_ref().filter(|b| !b.is_empty())
                {
                    let mut parts = vec![serde_json::json!({
                        "type": "text",
                        "text": content,
                    })];
                    for b in blocks {
                        if let ContentBlock::Image { data, media_type } = b {
                            parts.push(serde_json::json!({
                                    "type": "image",
                                    "source": { "type": "base64", "media_type": media_type, "data": data },
                                }));
                        }
                    }
                    parts.into()
                } else {
                    serde_json::Value::String(content)
                };
                wire.push(serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": id,
                        "content": wire_content,
                        "is_error": is_error,
                    }],
                }));
            }
        }
    }
    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    (system, wire)
}

/// A user message's wire blocks: structured blocks when present,
/// flattened text otherwise.
fn user_blocks(m: &ChatMessage) -> Vec<serde_json::Value> {
    if let Some(blocks) = &m.blocks {
        let mapped: Vec<serde_json::Value> = blocks
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text { text } => {
                    Some(serde_json::json!({ "type": "text", "text": text }))
                }
                ContentBlock::Image { data, media_type } => Some(serde_json::json!({
                    "type": "image",
                    "source": { "type": "base64", "media_type": media_type, "data": data },
                })),
                // ToolUse/ToolResult/Opaque never appear on user text
                // messages in ORBIT's transcript shape; skip rather than
                // inventing wire data.
                _ => None,
            })
            .collect();
        if !mapped.is_empty() {
            return mapped;
        }
    }
    vec![serde_json::json!({ "type": "text", "text": m.content })]
}

fn anthropic_tools(tools: &[ToolDefinition]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            })
        })
        .collect()
}

#[async_trait::async_trait]
impl AsyncProviderAdapter for AnthropicMessagesV1 {
    fn identity(&self) -> AdapterIdentity {
        self.identity.clone()
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn validate_route(&self, route: &ProviderRouteBinding) -> Result<(), AdapterError> {
        if route.adapter_kind != AdapterKind::DeclarativeHttpJsonV1 {
            return Err(AdapterError::CapabilityMismatch(
                "Anthropic route must be DeclarativeHttpJsonV1 (E0414)".into(),
            ));
        }
        if route.adapter_profile_digest != self.identity.profile_digest {
            return Err(AdapterError::AdapterProfileDigestMismatch("E0422".into()));
        }
        crate::endpoint::provider_method_url(route, "/v1", "messages")?;
        Ok(())
    }

    async fn invoke(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        self.validate_route(&request.route)?;
        if let Some(effort) = &request.effort {
            effort
                .validate_for_anthropic()
                .map_err(AdapterError::ProviderConfigurationInvalid)?;
        }
        let url = crate::endpoint::provider_method_url(&request.route, "/v1", "messages")?;

        let body = crate::request::render_request_body(
            crate::request::HttpDialect::AnthropicMessages,
            crate::request::RequestBodyInput::from(request),
        )?;

        let mut req = self
            .client
            .post(url)
            .header("anthropic-version", "2023-06-01")
            .json(body.as_json());
        if let Some(secret) = credential {
            req = req.header(
                "x-api-key",
                String::from_utf8_lossy(secret.expose()).into_owned(),
            );
        }
        let Some(response) = cancel
            .until_cancelled(tokio::time::timeout(
                std::time::Duration::from_millis(request.connect_timeout_ms),
                req.send(),
            ))
            .await
        else {
            return Ok(crate::cancel::cancelled_stream());
        };
        let resp = response
            .map_err(|_| AdapterError::ProviderTimeout("connect timeout (E0409)".into()))?
            .map_err(|e| AdapterError::ProviderTransportFailure(e.to_string()))?;
        if resp.status().is_redirection() {
            return Err(AdapterError::ProtocolOrStreamViolation(
                "provider redirects are not permitted (E0411)".into(),
            ));
        }
        if !resp.status().is_success() {
            // E1: the body carries the provider's own message; E2:
            // 529/5xx classify retryable.
            let status = resp.status();
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
        Ok(anthropic_stream(
            resp.bytes_stream(),
            request.first_byte_timeout_ms,
            request.idle_timeout_ms,
            cancel.clone(),
        ))
    }
}

#[derive(Default)]
struct AnthropicState {
    started: bool,
    done: bool,
    blocks: std::collections::BTreeMap<u32, (String, bool)>,
    calls: std::collections::BTreeMap<u32, crate::stream::WireCall>,
    partial_arguments: std::collections::BTreeSet<u32>,
    initial_arguments: std::collections::BTreeMap<u32, String>,
    reason: Option<String>,
    usage: orbit_adapter::types::ProviderUsage,
    saw_input_usage: bool,
    saw_final_usage: bool,
    saw_thinking: bool,
}

impl AnthropicState {
    fn event(
        &mut self,
        value: &serde_json::Value,
    ) -> Result<Vec<orbit_adapter::types::ProviderEventKind>, AdapterError> {
        use crate::stream::{
            MAX_FRAME_BYTES, MAX_TOOL_CALLS, WireCall, append_bounded, protocol, record_reason,
        };
        use orbit_adapter::types::ProviderEventKind as Event;
        let kind = value
            .get("type")
            .and_then(|kind| kind.as_str())
            .ok_or_else(|| protocol("Anthropic event has no type"))?;
        if kind == "error" {
            return Err(protocol("Anthropic sent a streamed error"));
        }
        if self.done {
            return Err(protocol("Anthropic data follows message_stop"));
        }
        let mut events = Vec::new();
        match kind {
            "message_start" => {
                if self.started {
                    return Err(protocol("duplicate Anthropic message_start"));
                }
                if !value
                    .get("message")
                    .is_some_and(serde_json::Value::is_object)
                {
                    return Err(protocol("invalid Anthropic message_start"));
                }
                self.started = true;
            }
            "content_block_start" | "content_block_delta" | "content_block_stop" => {
                if !self.started || self.reason.is_some() {
                    return Err(protocol("Anthropic content outside active message"));
                }
                let index = value
                    .get("index")
                    .and_then(|index| index.as_u64())
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or_else(|| protocol("invalid Anthropic block index"))?;
                match kind {
                    "content_block_start" => {
                        if self.blocks.len() >= 4096 || self.blocks.contains_key(&index) {
                            return Err(protocol("duplicate or excessive Anthropic blocks"));
                        }
                        let block = &value["content_block"];
                        let block_kind = block
                            .get("type")
                            .and_then(|kind| kind.as_str())
                            .ok_or_else(|| protocol("Anthropic block has no type"))?;
                        self.blocks.insert(index, (block_kind.into(), false));
                        if block_kind == "redacted_thinking"
                            || (block_kind == "thinking" && self.saw_thinking)
                        {
                            return Err(AdapterError::CapabilityMismatch(
                                "native redacted or multiple thinking blocks require lossless block replay support (E0414)".into(),
                            ));
                        }
                        if block_kind == "thinking" {
                            self.saw_thinking = true;
                        }
                        match block_kind {
                            "tool_use" => {
                                if self.calls.len() >= MAX_TOOL_CALLS {
                                    return Err(protocol("too many Anthropic tool calls"));
                                }
                                let id = block
                                    .get("id")
                                    .and_then(|id| id.as_str())
                                    .filter(|id| !id.trim().is_empty() && id.len() <= 512)
                                    .ok_or_else(|| {
                                        protocol("Anthropic tool block has no valid id")
                                    })?;
                                let name = block
                                    .get("name")
                                    .and_then(|name| name.as_str())
                                    .filter(|name| !name.trim().is_empty() && name.len() <= 256)
                                    .ok_or_else(|| {
                                        protocol("Anthropic tool block has no valid name")
                                    })?;
                                let input = block
                                    .get("input")
                                    .filter(|input| input.is_object())
                                    .ok_or_else(|| {
                                        protocol("Anthropic tool input must be an object")
                                    })?;
                                let arguments = serde_json::to_string(input)
                                    .map_err(|_| protocol("invalid Anthropic input"))?;
                                self.initial_arguments.insert(index, arguments);
                                self.calls.insert(
                                    index,
                                    WireCall {
                                        id: id.into(),
                                        name: name.into(),
                                        arguments: String::new(),
                                    },
                                );
                            }
                            "text" => {
                                if let Some(text) = block.get("text") {
                                    let text = text.as_str().ok_or_else(|| {
                                        protocol("invalid initial Anthropic text")
                                    })?;
                                    if !text.is_empty() {
                                        events.push(Event::TextDelta {
                                            bytes: text.as_bytes().to_vec(),
                                        });
                                    }
                                }
                            }
                            "thinking" => {
                                if let Some(text) = block.get("thinking") {
                                    let text = text
                                        .as_str()
                                        .ok_or_else(|| protocol("invalid initial thinking"))?;
                                    if !text.is_empty() {
                                        events.push(Event::ThinkingDelta {
                                            bytes: text.as_bytes().to_vec(),
                                        });
                                    }
                                }
                                if let Some(signature) = block.get("signature") {
                                    let signature = signature
                                        .as_str()
                                        .ok_or_else(|| protocol("invalid initial signature"))?;
                                    if !signature.is_empty() {
                                        events.push(Event::ThinkingSignatureDelta {
                                            bytes: signature.as_bytes().to_vec(),
                                        });
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    "content_block_delta" => {
                        let (block_kind, closed) = self
                            .blocks
                            .get(&index)
                            .ok_or_else(|| protocol("Anthropic delta has no block start"))?;
                        if *closed {
                            return Err(protocol("Anthropic delta follows block stop"));
                        }
                        let delta = &value["delta"];
                        let delta_kind = delta
                            .get("type")
                            .and_then(|kind| kind.as_str())
                            .ok_or_else(|| protocol("Anthropic delta has no type"))?;
                        match delta_kind {
                            "text_delta" => {
                                if block_kind != "text" {
                                    return Err(protocol("text delta has wrong block kind"));
                                }
                                let text = delta
                                    .get("text")
                                    .and_then(|text| text.as_str())
                                    .ok_or_else(|| protocol("invalid text delta"))?;
                                events.push(Event::TextDelta {
                                    bytes: text.as_bytes().to_vec(),
                                });
                            }
                            "thinking_delta" => {
                                if block_kind != "thinking" {
                                    return Err(protocol("thinking delta has wrong block kind"));
                                }
                                let text = delta
                                    .get("thinking")
                                    .and_then(|text| text.as_str())
                                    .ok_or_else(|| protocol("invalid thinking delta"))?;
                                events.push(Event::ThinkingDelta {
                                    bytes: text.as_bytes().to_vec(),
                                });
                            }
                            "signature_delta" => {
                                if block_kind != "thinking" {
                                    return Err(protocol("signature delta has wrong block kind"));
                                }
                                let signature = delta
                                    .get("signature")
                                    .and_then(|signature| signature.as_str())
                                    .ok_or_else(|| protocol("invalid signature delta"))?;
                                events.push(Event::ThinkingSignatureDelta {
                                    bytes: signature.as_bytes().to_vec(),
                                });
                            }
                            "input_json_delta" => {
                                if block_kind != "tool_use" {
                                    return Err(protocol("input delta has wrong block kind"));
                                }
                                let part = delta
                                    .get("partial_json")
                                    .and_then(|part| part.as_str())
                                    .ok_or_else(|| protocol("invalid input JSON delta"))?;
                                if self
                                    .initial_arguments
                                    .get(&index)
                                    .is_some_and(|arguments| arguments != "{}")
                                {
                                    return Err(protocol(
                                        "conflicting initial and partial tool input",
                                    ));
                                }
                                self.partial_arguments.insert(index);
                                let call = self
                                    .calls
                                    .get_mut(&index)
                                    .ok_or_else(|| protocol("input delta has no tool call"))?;
                                append_bounded(&mut call.arguments, part, MAX_FRAME_BYTES)?;
                            }
                            _ => {}
                        }
                    }
                    "content_block_stop" => {
                        let (_, closed) = self
                            .blocks
                            .get_mut(&index)
                            .ok_or_else(|| protocol("Anthropic stop has no block start"))?;
                        if *closed {
                            return Err(protocol("duplicate Anthropic block stop"));
                        }
                        *closed = true;
                        if !self.partial_arguments.contains(&index)
                            && let Some(call) = self.calls.get_mut(&index)
                        {
                            call.arguments = self
                                .initial_arguments
                                .remove(&index)
                                .unwrap_or_else(|| "{}".into());
                        }
                    }
                    _ => unreachable!(),
                }
            }
            "message_delta" => {
                if !self.started {
                    return Err(protocol("Anthropic message delta has no message start"));
                }
                if self.blocks.values().any(|(_, closed)| !closed) {
                    return Err(protocol("Anthropic message delta precedes block stop"));
                }
                let delta = value
                    .get("delta")
                    .filter(|delta| delta.is_object())
                    .ok_or_else(|| protocol("invalid message delta"))?;
                if let Some(reason) = delta.get("stop_reason").filter(|reason| !reason.is_null()) {
                    let reason = reason
                        .as_str()
                        .ok_or_else(|| protocol("invalid Anthropic stop reason"))?;
                    record_reason(
                        &mut self.reason,
                        reason,
                        &[
                            "end_turn",
                            "stop_sequence",
                            "tool_use",
                            "max_tokens",
                            "refusal",
                            "content_filter",
                        ],
                    )?;
                }
            }
            "message_stop" => {
                if !self.started
                    || self.reason.is_none()
                    || self.blocks.values().any(|(_, closed)| !closed)
                {
                    return Err(protocol("incomplete Anthropic message lifecycle"));
                }
                self.done = true;
            }
            _ => {} // Ping and well-formed future extension events do not complete a message.
        }
        if let Some(usage) = value
            .get("usage")
            .or_else(|| value.pointer("/message/usage"))
        {
            use crate::stream::{optional_counter, required_counter};
            if !usage.is_object() {
                return Err(protocol("invalid Anthropic usage"));
            }
            match kind {
                "message_start" => {
                    self.usage.input_tokens = required_counter(usage, "input_tokens")?;
                    self.saw_input_usage = true;
                    if let Some(output) = optional_counter(usage, "output_tokens")? {
                        self.usage.output_tokens = output;
                    }
                }
                "message_delta" => {
                    self.usage.output_tokens = required_counter(usage, "output_tokens")?;
                    if let Some(input) = optional_counter(usage, "input_tokens")? {
                        self.usage.input_tokens = input;
                        self.saw_input_usage = true;
                    }
                    if !self.saw_input_usage {
                        return Err(protocol("Anthropic final usage has no input total"));
                    }
                    self.saw_final_usage = true;
                }
                _ => return Err(protocol("Anthropic usage has no defined accounting phase")),
            }
            if let Some(cached) = optional_counter(usage, "cache_read_input_tokens")? {
                self.usage.cache_read_tokens = cached;
            }
            if let Some(written) = optional_counter(usage, "cache_creation_input_tokens")? {
                self.usage.cache_write_tokens = written;
            }
            // Initial input/output snapshots are provisional. The gateway's
            // UsageUpdate fallback treats updates as authoritative totals, so
            // emit only a validated final message_delta accounting snapshot.
            if self.saw_final_usage {
                events.push(Event::UsageUpdate(self.usage));
            }
        }
        Ok(events)
    }
}

fn anthropic_stream(
    mut bytes: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
    + Unpin
    + Send
    + 'static,
    first_byte_timeout_ms: u64,
    idle_timeout_ms: u64,
    cancel: CancelToken,
) -> AsyncProviderEventStream {
    use crate::stream::{count_bytes, incomplete_reason, protocol, validate_calls};
    use futures::StreamExt;
    use orbit_adapter::types::{ProviderEventKind, ProviderStreamEvent};
    Box::pin(async_stream::stream! {
        let mut parser = crate::sse::SseParser::new();
        let mut seq = 0u64;
        let mut state = AnthropicState::default();
        let mut total = 0usize;
        yield Ok(ProviderStreamEvent { sequence:seq, event:ProviderEventKind::ResponseStarted { upstream_request_id:None } }); seq += 1;
        let mut first = true;
        while let Some(chunk) = {
            let budget = std::time::Duration::from_millis(if first { first_byte_timeout_ms } else { idle_timeout_ms });
            match cancel.until_cancelled(tokio::time::timeout(budget, bytes.next())).await {
                None => None,
                Some(Ok(item)) => item,
                Some(Err(_)) => { yield Err(AdapterError::ProviderTimeout("Anthropic stream stalled (E0409)".into())); return; }
            }
        } {
            if cancel.is_cancelled() { break; }
            first = false;
            let chunk = match chunk { Ok(chunk) => chunk, Err(error) => { yield Err(AdapterError::ProviderTransportFailure(error.to_string())); return; } };
            if let Err(error) = count_bytes(&mut total, chunk.len()) { yield Err(error); return; }
            let events = match parser.feed(&chunk) { Ok(events) => events, Err(error) => { yield Err(error.into()); return; } };
            for event in events {
                let value = match serde_json::from_str(&event.data) { Ok(value) => value, Err(_) => { yield Err(protocol("malformed Anthropic JSON")); return; } };
                match state.event(&value) {
                    Ok(events) => for event in events {
                        yield Ok(ProviderStreamEvent { sequence:seq, event }); seq += 1;
                    },
                    Err(error) => { yield Err(error); return; }
                }
            }
            if state.done { break; }
        }
        if cancel.is_cancelled() {
            yield Ok(ProviderStreamEvent { sequence:seq, event:ProviderEventKind::Finished { finish_reason:Some("cancelled".into()), final_usage:None } });
            return;
        }
        if !state.done || !parser.is_clean() { yield Err(protocol("Anthropic stream ended before message_stop")); return; }
        let reason = state.reason.expect("message_stop validates reason");
        if !incomplete_reason(&reason) {
            if reason == "tool_use" {
                if state.calls.is_empty() { yield Err(protocol("tool_use terminal has no calls")); return; }
                if let Err(error) = validate_calls(&state.calls) { yield Err(error); return; }
                for (index, call) in state.calls {
                    yield Ok(ProviderStreamEvent { sequence:seq, event:ProviderEventKind::ToolCallStarted { call_index:index, provider_call_id:Some(call.id), name:call.name } }); seq += 1;
                    yield Ok(ProviderStreamEvent { sequence:seq, event:ProviderEventKind::ToolCallArgumentsDelta { call_index:index, bytes:call.arguments.into_bytes() } }); seq += 1;
                    yield Ok(ProviderStreamEvent { sequence:seq, event:ProviderEventKind::ToolCallFinished { call_index:index } }); seq += 1;
                }
            } else if !state.calls.is_empty() { yield Err(protocol("Anthropic text terminal contradicts tool calls")); return; }
        }
        yield Ok(ProviderStreamEvent { sequence:seq, event:ProviderEventKind::Finished { finish_reason:Some(reason), final_usage:state.saw_final_usage.then_some(state.usage) } });
    })
}

#[cfg(test)]
mod tool_result_image_tests {
    use super::*;
    use orbit_adapter::types::{ChatMessage, ChatRole, ContentBlock};

    fn tool_msg(content: &str, blocks: Option<Vec<ContentBlock>>) -> ChatMessage {
        ChatMessage {
            role: ChatRole::Tool,
            content: content.into(),
            tool_calls: None,
            tool_call_id: Some("call-1".into()),
            tool_result: Some(content.into()),
            blocks,
            origin_model: None,
            origin_provider: None,
        }
    }

    /// An image Read rides the tool_result as a block array: the text
    /// line plus the image, the shape Anthropic vision accepts.
    #[test]
    fn a_tool_result_with_an_image_block_carries_the_array() {
        let msg = tool_msg(
            r#"{"ok":true,"content":"[image: shot.png, 40 bytes, image/png]"}"#,
            Some(vec![ContentBlock::Image {
                data: "aGVsbG8=".into(),
                media_type: "image/png".into(),
            }]),
        );
        let (_, wire) = anthropic_messages(&[msg]);
        let tr = &wire[0]["content"][0];
        assert_eq!(tr["type"], "tool_result");
        assert_eq!(tr["tool_use_id"], "call-1");
        let parts = tr["content"].as_array().expect("a block array");
        assert_eq!(parts.len(), 2, "text line + image");
        assert_eq!(parts[0]["type"], "text");
        assert_eq!(parts[1]["type"], "image");
        assert_eq!(parts[1]["source"]["type"], "base64");
        assert_eq!(parts[1]["source"]["media_type"], "image/png");
        assert_eq!(parts[1]["source"]["data"], "aGVsbG8=");
    }

    /// Without a block the tool_result content stays the plain string —
    /// the common case is unchanged on the wire.
    #[test]
    fn a_plain_tool_result_stays_a_string() {
        let msg = tool_msg(r#"{"ok":true,"content":"1 file"}"#, None);
        let (_, wire) = anthropic_messages(&[msg]);
        let tr = &wire[0]["content"][0];
        assert_eq!(tr["type"], "tool_result");
        assert!(
            tr["content"].is_string(),
            "no block, no array: {}",
            tr["content"]
        );
    }
}

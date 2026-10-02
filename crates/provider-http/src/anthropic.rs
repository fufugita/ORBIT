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
        let client = reqwest::Client::builder()
            .build()
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
                        if let ContentBlock::Opaque { json } = b {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
                                blocks.push(v);
                            }
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
                let is_error = content.contains("\"ok\":false");
                wire.push(serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": id,
                        "content": content,
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
        Ok(())
    }

    async fn invoke(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        self.validate_route(&request.route)?;
        // https for the real API; http only for loopback (local gateways,
        // the mock provider). The scheme comes from the route binding,
        // which the egress gate already pinned.
        let scheme = match request.route.endpoint_scheme {
            orbit_adapter::types::EndpointScheme::Https => "https",
            // Loopback (local gateways, the mock); LocalProcess is not an
            // HTTP endpoint — the route kind check above excludes it.
            _ => "http",
        };
        let url = format!(
            "{}://{}:{}/v1/messages",
            scheme, request.route.endpoint_host, request.route.endpoint_port
        );

        // Messages: the transcript when present, else the single prompt.
        let (system, messages) = match &request.messages {
            Some(transcript) => anthropic_messages(transcript),
            None => (
                None,
                vec![serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "text",
                        "text": String::from_utf8_lossy(request.input.expose()).into_owned(),
                    }],
                })],
            ),
        };

        let mut body = serde_json::json!({
            "model": request.route.expected_model,
            "stream": true,
            "max_tokens": request.sampling.max_output_tokens,
            "temperature": request.sampling.temperature_milliunits as f64 / 1000.0,
            "messages": messages,
            // Adaptive thinking: it cannot be disabled on current models;
            // display stays omitted (chain-of-thought never renders).
            "thinking": { "type": "adaptive" },
        });

        // One explicit cache breakpoint at the end of the system prompt:
        // the stable prefix caches, the growing tail re-caches per round.
        if let Some(sys) = &system {
            body["system"] = serde_json::json!([{
                "type": "text",
                "text": sys,
                "cache_control": { "type": "ephemeral" },
            }]);
        }

        let tools = anthropic_tools(&request.tools);
        if !tools.is_empty() {
            body["tools"] = serde_json::Value::Array(tools);
            // tool_choice: auto only — forced tool choice 400s on current
            // Claude models (roadmap §Providers).
            body["tool_choice"] = serde_json::json!({ "type": "auto" });
        }

        let mut req = self
            .client
            .post(url)
            .header("anthropic-version", "2023-06-01")
            .json(&body);
        if let Some(secret) = credential {
            req = req.header(
                "x-api-key",
                String::from_utf8_lossy(secret.expose()).into_owned(),
            );
        }
        let resp = tokio::time::timeout(
            std::time::Duration::from_millis(request.connect_timeout_ms),
            req.send(),
        )
        .await
        .map_err(|_| AdapterError::ProviderTimeout("connect timeout (E0409)".into()))?
        .map_err(|e| AdapterError::ProviderTransportFailure(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AdapterError::RateLimitedExhausted("429 (E0407)".into()));
        }
        if !resp.status().is_success() {
            return Err(AdapterError::ProviderTransportFailure(format!(
                "status {}",
                resp.status()
            )));
        }
        Ok(anthropic_stream(resp.bytes_stream(), cancel.clone()))
    }
}

fn anthropic_stream(
    mut bytes: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
        + Unpin
        + Send
        + 'static,
    cancel: CancelToken,
) -> AsyncProviderEventStream {
    use futures::StreamExt;
    use orbit_adapter::types::{ProviderEventKind, ProviderStreamEvent, ProviderUsage};
    Box::pin(async_stream::stream! {
        let mut parser = crate::sse::SseParser::new();
        let mut seq = 0u64;
        let mut usage = ProviderUsage::default();
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ResponseStarted { upstream_request_id: None } });
        seq += 1;

        // Tool-call assembly: Anthropic streams input_json_delta per block.
        let mut tool_calls: std::collections::BTreeMap<u32, (String, String, String)> =
            std::collections::BTreeMap::new(); // index -> (id, name, partial json)
        let mut finish_reason: Option<String> = None;

        while let Some(chunk) = bytes.next().await {
            if cancel.is_cancelled() { break; }
            let chunk = match chunk { Ok(c) => c, Err(e) => { yield Err(AdapterError::ProviderTransportFailure(e.to_string())); return; } };
            for ev in parser.feed(&chunk).unwrap_or_default() {
                let v: serde_json::Value = match serde_json::from_str(&ev.data) { Ok(v) => v, Err(_) => continue };
                match v.get("type").and_then(|x|x.as_str()) {
                    Some("content_block_start") => {
                        let index = v.pointer("/index").and_then(|x|x.as_u64()).unwrap_or(0) as u32;
                        let block_type = v.pointer("/content_block/type").and_then(|x|x.as_str()).unwrap_or("");
                        if block_type == "tool_use" {
                            let id = v.pointer("/content_block/id").and_then(|x|x.as_str()).unwrap_or("").to_string();
                            let name = v.pointer("/content_block/name").and_then(|x|x.as_str()).unwrap_or("").to_string();
                            tool_calls.insert(index, (id.clone(), name.clone(), String::new()));
                            yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ToolCallStarted {
                                call_index: index,
                                provider_call_id: Some(id),
                                name,
                            }});
                            seq += 1;
                        }
                        // thinking blocks: assembled for replay, never
                        // surfaced as text (CoT defense).
                    }
                    Some("content_block_delta") => {
                        let delta_type = v.pointer("/delta/type").and_then(|x|x.as_str()).unwrap_or("");
                        let index = v.pointer("/index").and_then(|x|x.as_u64()).unwrap_or(0) as u32;
                        match delta_type {
                            "text_delta" => {
                                if let Some(text) = v.pointer("/delta/text").and_then(|x|x.as_str()) {
                                    yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::TextDelta { bytes: text.as_bytes().to_vec() } });
                                    seq += 1;
                                }
                            }
                            "thinking_delta" => {
                                // Reasoning: assembled for replay, never
                                // displayed (CoT defense).
                                if let Some(text) = v.pointer("/delta/thinking").and_then(|x|x.as_str()) {
                                    yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ThinkingDelta { bytes: text.as_bytes().to_vec() } });
                                    seq += 1;
                                }
                            }
                            "input_json_delta" => {
                                if let Some(part) = v.pointer("/delta/partial_json").and_then(|x|x.as_str()) {
                                    if let Some((_, _, json)) = tool_calls.get_mut(&index) {
                                        json.push_str(part);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Some("content_block_stop") => {
                        let index = v.pointer("/index").and_then(|x|x.as_u64()).unwrap_or(0) as u32;
                        if tool_calls.contains_key(&index) {
                            yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ToolCallFinished { call_index: index } });
                            seq += 1;
                        }
                    }
                    Some("message_delta") => {
                        // The real stop reason lives here.
                        if let Some(reason) = v.pointer("/delta/stop_reason").and_then(|x|x.as_str()) {
                            finish_reason = Some(reason.to_string());
                        }
                        if let Some(u) = v.get("usage") {
                            usage.output_tokens = u.get("output_tokens").and_then(|x|x.as_u64()).unwrap_or(usage.output_tokens);
                        }
                    }
                    _ => {}
                }
                if let Some(u) = v.get("usage") {
                    usage.input_tokens = u.get("input_tokens").and_then(|x|x.as_u64()).unwrap_or(usage.input_tokens);
                    // Cache accounting (roadmap: check cache_read in tests).
                    usage.cache_read_tokens = u.get("cache_read_input_tokens").and_then(|x|x.as_u64()).unwrap_or(usage.cache_read_tokens);
                    usage.cache_write_tokens = u.get("cache_creation_input_tokens").and_then(|x|x.as_u64()).unwrap_or(usage.cache_write_tokens);
                }
            }
        }

        // Emit assembled tool calls (arguments complete after block stop).
        for (index, (_id, _name, json)) in &tool_calls {
            yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ToolCallArgumentsDelta {
                call_index: *index,
                bytes: json.as_bytes().to_vec(),
            }});
            seq += 1;
        }

        let reason = finish_reason.unwrap_or_else(|| "end_turn".into());
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::Finished { finish_reason: Some(reason), final_usage: Some(usage) } });
    })
}

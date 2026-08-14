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

use crate::cancel::CancelToken;
use crate::error::TransportError;
use crate::sse::SseParser;
use crate::stream::AsyncProviderEventStream;
use crate::tls;
use crate::AsyncProviderAdapter;
use futures::StreamExt;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, ProviderCapabilities, ProviderEventKind, ProviderRequest,
    ProviderRouteBinding, ProviderStreamEvent, ProviderUsage, Sha256Digest,
};
use std::sync::Arc;

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
        let config = tls::client_config(&tls_policy)?;
        // reqwest's use_preconfigured_tls expects the RAW ClientConfig
        // (it downcasts Option<ClientConfig>), not an Arc.
        let config = Arc::try_unwrap(config).unwrap_or_else(|arc| (*arc).clone());
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .build()
            .map_err(|e| TransportError::Transport(format!("client build: {e}")))?;
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

        // Scheme from the route binding: HttpLoopback → http, else https
        // with SPKI pinning. A homelab mock on a LAN IP uses HttpLoopback.
        let host = &request.route.endpoint_host;
        let scheme = match request.route.endpoint_scheme {
            orbit_adapter::types::EndpointScheme::HttpLoopback => "http",
            _ => "https",
        };
        let base = format!("{scheme}://{host}:{}{}", request.route.endpoint_port, "/v1");
        let url = format!("{base}/chat/completions");

        // Build the wire body — sampling as provider floats ONLY here.
        // Multi-turn transcript wins when present; otherwise the single
        // user turn (input bytes are always the newest user prompt).
        let messages: serde_json::Value = match &request.messages {
            Some(transcript) => transcript
                .iter()
                .map(|m| {
                    if let Some(tool_calls) = m
                        .tool_calls
                        .as_ref()
                        .filter(|_| m.role == orbit_adapter::types::ChatRole::Assistant)
                    {
                        serde_json::json!({
                            "role": "assistant",
                            "content": if m.content.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(m.content.clone()) },
                            "tool_calls": tool_calls.iter().map(|tc| serde_json::json!({
                                "id": tc.id,
                                "type": "function",
                                "function": { "name": tc.name, "arguments": tc.arguments },
                            })).collect::<Vec<_>>(),
                        })
                    } else if m.role == orbit_adapter::types::ChatRole::Tool {
                        serde_json::json!({
                            "role": "tool",
                            "tool_call_id": m.tool_call_id,
                            "content": m.tool_result.as_deref().unwrap_or(&m.content),
                        })
                    } else {
                        serde_json::json!({
                            "role": m.role.as_str(),
                            "content": m.content,
                        })
                    }
                })
                .collect::<Vec<_>>()
                .into(),
            None => serde_json::json!([
                {"role": "user", "content": String::from_utf8_lossy(
                    request.input.expose()
                ).into_owned()}
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
            "temperature": request.sampling.temperature_milliunits as f64 / 1000.0,
            "max_tokens": request.sampling.max_output_tokens,
            "messages": messages,
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::Value::Array(tools);
            body["tool_choice"] = serde_json::Value::String("auto".into());
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
        let resp = tokio::time::timeout(connect_timeout, req.send())
            .await
            .map_err(|_| AdapterError::ProviderTimeout("connect timeout (E0409)".into()))?
            .map_err(|e| AdapterError::ProviderTransportFailure(format!("send: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AdapterError::RateLimitedExhausted("429 (E0407)".into()));
        }
        if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
            return Err(AdapterError::ProviderTransportFailure("500 (E0410)".into()));
        }
        if !status.is_success() {
            return Err(AdapterError::ProviderPermissionDenied(format!(
                "provider status {status}"
            )));
        }

        let bytes = resp
            .bytes_stream()
            .map(|b| b.map_err(|e| AdapterError::ProviderTransportFailure(e.to_string())));
        Ok(openai_stream(bytes, cancel.clone()))
    }
}

/// Consume the OpenAI SSE byte stream and emit `ProviderStreamEvent`s.
fn openai_stream(
    mut bytes: impl futures::Stream<Item = Result<bytes::Bytes, AdapterError>> + Unpin + Send + 'static,
    cancel: CancelToken,
) -> AsyncProviderEventStream {
    Box::pin(async_stream::stream! {
        let mut parser = SseParser::new();
        let mut seq: u64 = 0;
        let mut usage = ProviderUsage::default();
        let mut saw_done = false;
        let mut finish_reason: Option<String> = None;
        let mut open_tool_calls: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();

        // Emit the response-started event.
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ResponseStarted { upstream_request_id: None } });
        seq += 1;

        while let Some(chunk) = bytes.next().await {
            if cancel.is_cancelled() { break; }
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => { yield Err(e); return; }
            };
            let events = match parser.feed(&chunk) {
                Ok(evs) => evs,
                Err(e) => { yield Err(e.into()); return; }
            };
            for ev in events {
                if ev.data == "[DONE]" {
                    saw_done = true;
                    break;
                }
                let json: serde_json::Value = match serde_json::from_str(&ev.data) {
                    Ok(v) => v,
                    Err(_) => {
                        yield Err(AdapterError::ProtocolOrStreamViolation(
                            "malformed SSE JSON (E0411)".into(),
                        ));
                        return;
                    }
                };
                // Delta text.
                if let Some(delta) = json.pointer("/choices/0/delta/content")
                    .and_then(|d| d.as_str())
                {
                    yield Ok(ProviderStreamEvent {
                        sequence: seq,
                        event: ProviderEventKind::TextDelta { bytes: delta.as_bytes().to_vec() },
                    });
                    seq += 1;
                }
                // Streaming tool calls. OpenAI may fragment name/id/arguments
                // across arbitrary SSE chunks. We emit Started on first sight,
                // ArgumentsDelta for every fragment, then Finished when the
                // choice finish_reason becomes `tool_calls` (or at terminal).
                if let Some(calls) = json.pointer("/choices/0/delta/tool_calls")
                    .and_then(|v| v.as_array())
                {
                    for call in calls {
                        let index = call.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        if !open_tool_calls.contains(&index) {
                            let id = call.get("id").and_then(|v| v.as_str()).map(str::to_string);
                            let name = call.pointer("/function/name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            open_tool_calls.insert(index);
                            yield Ok(ProviderStreamEvent {
                                sequence: seq,
                                event: ProviderEventKind::ToolCallStarted {
                                    call_index: index,
                                    provider_call_id: id,
                                    name,
                                },
                            });
                            seq += 1;
                        }
                        if let Some(args) = call.pointer("/function/arguments").and_then(|v| v.as_str()) {
                            if !args.is_empty() {
                                yield Ok(ProviderStreamEvent {
                                    sequence: seq,
                                    event: ProviderEventKind::ToolCallArgumentsDelta {
                                        call_index: index,
                                        bytes: args.as_bytes().to_vec(),
                                    },
                                });
                                seq += 1;
                            }
                        }
                    }
                }
                if let Some(reason) = json.pointer("/choices/0/finish_reason").and_then(|v| v.as_str()) {
                    finish_reason = Some(reason.to_string());
                    if reason == "tool_calls" {
                        let to_finish: Vec<u32> = open_tool_calls.iter().copied().collect();
                        for index in to_finish {
                            yield Ok(ProviderStreamEvent {
                                sequence: seq,
                                event: ProviderEventKind::ToolCallFinished { call_index: index },
                            });
                            seq += 1;
                            open_tool_calls.remove(&index);
                        }
                    }
                }
                // Usage update — full five-field extraction (DR-09 §8).
                // OpenAI nests cache/reasoning under prompt/completion details.
                if let Some(u) = json.get("usage") {
                    let prompt_details = u.get("prompt_tokens_details");
                    let completion_details = u.get("completion_tokens_details");
                    usage = ProviderUsage {
                        input_tokens: u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                        output_tokens: u
                            .get("completion_tokens")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0),
                        cache_read_tokens: prompt_details
                            .and_then(|d| d.get("cached_tokens"))
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0),
                        cache_write_tokens: 0,
                        reasoning_tokens: completion_details
                            .and_then(|d| d.get("reasoning_tokens"))
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0),
                    };
                    yield Ok(ProviderStreamEvent {
                        sequence: seq,
                        event: ProviderEventKind::UsageUpdate(usage),
                    });
                    seq += 1;
                }
            }
            if saw_done { break; }
        }

        // Terminalizer (GW-10): exactly one Finished. Finish any tool calls the
        // stream left open (belt-and-suspenders — a well-formed stream closes
        // them at finish_reason=tool_calls).
        for index in open_tool_calls.iter().copied().collect::<Vec<_>>() {
            yield Ok(ProviderStreamEvent {
                sequence: seq,
                event: ProviderEventKind::ToolCallFinished { call_index: index },
            });
            seq += 1;
        }
        yield Ok(ProviderStreamEvent {
            sequence: seq,
            event: ProviderEventKind::Finished {
                finish_reason,
                final_usage: Some(usage),
            },
        });
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

/// Suppress unused-import lint for types used only in the stream closure.
#[allow(unused_imports)]
use std::convert::Infallible as _Unused;

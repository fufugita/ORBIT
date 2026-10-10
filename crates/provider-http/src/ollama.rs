//! Ollama HTTP adapter (DR-09 §3, §4) — v0.2.
//!
//! Speaks `/api/chat` NDJSON over HTTP loopback. The route MUST use
//! `HttpLoopback`; no credential is required or persisted.

use crate::{AsyncProviderAdapter, AsyncProviderEventStream, CancelToken};
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, ProviderCapabilities, ProviderRequest, ProviderRouteBinding,
};

pub struct OllamaHttpV1 {
    identity: AdapterIdentity,
    capabilities: ProviderCapabilities,
    client: reqwest::Client,
}

impl OllamaHttpV1 {
    pub fn new(
        identity: AdapterIdentity,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, AdapterError> {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        Ok(Self {
            identity,
            capabilities,
            client: reqwest::Client::builder()
                .build()
                .map_err(|e| AdapterError::ProviderTransportFailure(e.to_string()))?,
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
        if route.endpoint_host != "127.0.0.1"
            && route.endpoint_host != "localhost"
            && route.endpoint_host != "::1"
        {
            return Err(AdapterError::ProviderConfigurationInvalid(
                "Ollama must be loopback (E0401)".into(),
            ));
        }
        Ok(())
    }

    async fn invoke(
        &self,
        request: &ProviderRequest,
        _credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        self.validate_route(&request.route)?;
        // Ollama serves at the bare host by default; a configured gate
        // path (a nonstandard reverse-proxy layout) is honored verbatim.
        let base_path = if request.route.endpoint_path.is_empty() {
            ""
        } else {
            request.route.endpoint_path.as_str()
        };
        let url = format!(
            "http://{}:{}{}/api/chat",
            request.route.endpoint_host, request.route.endpoint_port, base_path
        );
        // Full conversation when present; else the single prompt. Ollama's
        // chat API takes tool calls/results natively on messages.
        let messages: serde_json::Value = match &request.messages {
            Some(transcript) => transcript
                .iter()
                .filter_map(|m| {
                    use orbit_adapter::types::ChatRole;
                    match m.role {
                        ChatRole::System => Some(serde_json::json!({
                            "role": "system",
                            "content": m.content,
                        })),
                        ChatRole::User => Some(serde_json::json!({
                            "role": "user",
                            "content": m.content,
                        })),
                        ChatRole::Assistant => {
                            // Ollama carries tool calls natively on the
                            // assistant message.
                            let calls: Vec<serde_json::Value> = m
                                .tool_calls
                                .as_ref()
                                .map(|tcs| {
                                    tcs.iter()
                                        .map(|tc| serde_json::json!({
                                            "function": {
                                                "name": tc.name,
                                                "arguments": serde_json::from_str::<serde_json::Value>(&tc.arguments)
                                                    .unwrap_or(serde_json::json!({})),
                                            }
                                        }))
                                        .collect()
                                })
                                .unwrap_or_default();
                            if !m.content.is_empty() || !calls.is_empty() {
                                let mut msg = serde_json::json!({
                                    "role": "assistant",
                                    "content": m.content,
                                });
                                if !calls.is_empty() {
                                    msg["tool_calls"] = serde_json::Value::Array(calls);
                                }
                                Some(msg)
                            } else {
                                None
                            }
                        }
                        ChatRole::Tool => Some(serde_json::json!({
                            "role": "tool",
                            "content": m.tool_result.as_deref().unwrap_or(&m.content),
                        })),
                    }
                })
                .collect::<Vec<_>>()
                .into(),
            None => serde_json::json!([
                {"role":"user","content": String::from_utf8_lossy(request.input.expose()).into_owned()}
            ]),
        };
        let mut body = serde_json::json!({
            "model": request.route.expected_model,
            "stream": true,
            "messages": messages,
            "options": {
                "num_predict": request.sampling.max_output_tokens,
            }
        });
        // E8: sampling opt-in per model; zero means unset — omitted.
        if request.sampling.temperature_milliunits > 0 {
            body["options"]["temperature"] =
                serde_json::json!(request.sampling.temperature_milliunits as f64 / 1000.0);
        }
        if request.sampling.top_p_millionths > 0 {
            body["options"]["top_p"] =
                serde_json::json!(request.sampling.top_p_millionths as f64 / 1_000_000.0);
        }
        let resp = tokio::time::timeout(
            std::time::Duration::from_millis(request.connect_timeout_ms),
            self.client.post(url).json(&body).send(),
        )
        .await
        .map_err(|_| AdapterError::ProviderTimeout("connect timeout (E0409)".into()))?
        .map_err(|e| AdapterError::ProviderTransportFailure(e.to_string()))?;
        if !resp.status().is_success() {
            // E1: the body carries the provider's own message; E2:
            // 529/5xx classify retryable.
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::status_error(status, body).await);
        }
        Ok(ollama_stream(
            resp.bytes_stream(),
            request.first_byte_timeout_ms,
            request.idle_timeout_ms,
            cancel.clone(),
        ))
    }
}

fn ollama_stream(
    mut bytes: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
        + Unpin
        + Send
        + 'static,
    first_byte_timeout_ms: u64,
    idle_timeout_ms: u64,
    cancel: CancelToken,
) -> AsyncProviderEventStream {
    use futures::StreamExt;
    use orbit_adapter::types::{ProviderEventKind, ProviderStreamEvent, ProviderUsage};
    Box::pin(async_stream::stream! {
        let mut buffer = Vec::new(); let mut seq=0u64; let mut usage=ProviderUsage::default();
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ResponseStarted { upstream_request_id: None }}); seq+=1;
        // E5: a stream that stops sending bytes must fail as a
        // retryable timeout, not hang the turn forever.
        let mut first_chunk = true;
        while let Some(chunk) = {
            let budget = std::time::Duration::from_millis(if first_chunk {
                first_byte_timeout_ms
            } else {
                idle_timeout_ms
            });
            match tokio::time::timeout(budget, bytes.next()).await {
                Ok(item) => item,
                Err(_) => {
                    yield Err(AdapterError::ProviderTimeout(
                        "stream stalled: no bytes within the idle timeout (E0409)".into(),
                    ));
                    return;
                }
            }
        } {
            if cancel.is_cancelled(){break;}
            first_chunk = false;
            let chunk=match chunk{Ok(c)=>c,Err(e)=>{yield Err(AdapterError::ProviderTransportFailure(e.to_string()));return;}};
            buffer.extend_from_slice(&chunk);
            while let Some(pos)=buffer.iter().position(|b|*b==b'\n') {
                let line:Vec<u8>=buffer.drain(..=pos).collect();
                let v:serde_json::Value=match serde_json::from_slice(&line){Ok(v)=>v,Err(_)=>continue};
                if let Some(text)=v.pointer("/message/content").and_then(|x|x.as_str()){
                    if !text.is_empty(){yield Ok(ProviderStreamEvent{sequence:seq,event:ProviderEventKind::TextDelta{bytes:text.as_bytes().to_vec()}});seq+=1;}
                }
                if v.get("done").and_then(|x|x.as_bool())==Some(true){
                    usage.input_tokens=v.get("prompt_eval_count").and_then(|x|x.as_u64()).unwrap_or(0);
                    usage.output_tokens=v.get("eval_count").and_then(|x|x.as_u64()).unwrap_or(0);
                    break;
                }
            }
        }
        yield Ok(ProviderStreamEvent{sequence:seq,event:ProviderEventKind::Finished{finish_reason:Some("stop".into()),final_usage:Some(usage)}});
    })
}

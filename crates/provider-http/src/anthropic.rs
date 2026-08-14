//! Anthropic Messages HTTP adapter (DR-09 §3, §4) — v0.2.
//!
//! Speaks the Messages streaming wire format (`/v1/messages`) with the
//! credential in `x-api-key`. It reuses the async OpenAI event stream shape
//! and the same GW-04..GW-25 invariant set.

use crate::{AsyncProviderAdapter, AsyncProviderEventStream, CancelToken};
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, ProviderCapabilities, ProviderRequest, ProviderRouteBinding,
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
        let url = format!(
            "https://{}:{}/v1/messages",
            request.route.endpoint_host, request.route.endpoint_port
        );
        let body = serde_json::json!({
            "model": request.route.expected_model,
            "stream": true,
            "max_tokens": request.sampling.max_output_tokens,
            "temperature": request.sampling.temperature_milliunits as f64 / 1000.0,
            "messages": [{"role":"user","content": String::from_utf8_lossy(request.input.expose()).into_owned()}],
        });
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
        while let Some(chunk) = bytes.next().await {
            if cancel.is_cancelled() { break; }
            let chunk = match chunk { Ok(c) => c, Err(e) => { yield Err(AdapterError::ProviderTransportFailure(e.to_string())); return; } };
            for ev in parser.feed(&chunk).unwrap_or_default() {
                let v: serde_json::Value = match serde_json::from_str(&ev.data) { Ok(v) => v, Err(_) => continue };
                if v.get("type").and_then(|x|x.as_str()) == Some("content_block_delta") {
                    if let Some(text) = v.pointer("/delta/text").and_then(|x|x.as_str()) {
                        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::TextDelta { bytes: text.as_bytes().to_vec() } });
                        seq += 1;
                    }
                }
                if let Some(u) = v.get("usage") {
                    usage.input_tokens = u.get("input_tokens").and_then(|x|x.as_u64()).unwrap_or(usage.input_tokens);
                    usage.output_tokens = u.get("output_tokens").and_then(|x|x.as_u64()).unwrap_or(usage.output_tokens);
                    yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::UsageUpdate(usage) });
                    seq += 1;
                }
                if v.get("type").and_then(|x|x.as_str()) == Some("message_stop") { break; }
            }
        }
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::Finished { finish_reason: Some("stop".into()), final_usage: Some(usage) } });
    })
}

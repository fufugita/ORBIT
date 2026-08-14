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
        let url = format!(
            "http://{}:{}/api/chat",
            request.route.endpoint_host, request.route.endpoint_port
        );
        let body = serde_json::json!({
            "model": request.route.expected_model,
            "stream": true,
            "messages": [{"role":"user","content":"orbit-request"}],
            "options": {
                "temperature": request.sampling.temperature_milliunits as f64 / 1000.0,
                "top_p": request.sampling.top_p_millionths as f64 / 1_000_000.0,
                "num_predict": request.sampling.max_output_tokens,
            }
        });
        let resp = tokio::time::timeout(
            std::time::Duration::from_millis(request.connect_timeout_ms),
            self.client.post(url).json(&body).send(),
        )
        .await
        .map_err(|_| AdapterError::ProviderTimeout("connect timeout (E0409)".into()))?
        .map_err(|e| AdapterError::ProviderTransportFailure(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AdapterError::ProviderTransportFailure(format!(
                "status {}",
                resp.status()
            )));
        }
        Ok(ollama_stream(resp.bytes_stream(), cancel.clone()))
    }
}

fn ollama_stream(
    mut bytes: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
        + Unpin
        + Send
        + 'static,
    cancel: CancelToken,
) -> AsyncProviderEventStream {
    use futures::StreamExt;
    use orbit_adapter::types::{ProviderEventKind, ProviderStreamEvent, ProviderUsage};
    Box::pin(async_stream::stream! {
        let mut buffer = Vec::new(); let mut seq=0u64; let mut usage=ProviderUsage::default();
        yield Ok(ProviderStreamEvent { sequence: seq, event: ProviderEventKind::ResponseStarted { upstream_request_id: None }}); seq+=1;
        while let Some(chunk)=bytes.next().await {
            if cancel.is_cancelled(){break;}
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

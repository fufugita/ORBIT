//! ORBIT async provider HTTP adapters — v0.2 (DR-09 §3, §4, §7).
//!
//! Promotes the deferred async surface: the `AsyncProviderAdapter` trait,
//! `AsyncProviderEventStream`, `CancelToken`, real HTTPS with SPKI pinning
//! (closing NEW P1 #1 from the v0.1 review), the SSE parser, and the
//! OpenAI-compatible / Anthropic / Ollama HTTP adapters.
//!
//! Every async adapter must pass the same DR-09 invariant set the v0.1 sync
//! adapters prove (GW-04..GW-25); the async conformance harness drives them
//! against the `mock-provider` server over real HTTP.

#![forbid(unsafe_code)]

pub mod adapter_trait;
pub mod anthropic;
pub mod cancel;
pub mod error;
pub mod ollama;
pub mod openai;
pub mod sse;
pub mod stream;
pub mod tls;

pub use adapter_trait::AsyncProviderAdapter;
pub use anthropic::AnthropicMessagesV1;
pub use cancel::CancelToken;
pub use error::TransportError;
pub use ollama::OllamaHttpV1;
pub use openai::OpenAiCompatibleHttpV1;
pub use stream::AsyncProviderEventStream;

/// One shared tokio runtime for the whole process (E6). Every round
/// used to build its own — hundreds of ms of thread spawn per turn,
/// and no thread reuse across rounds. The runtime is created once and
/// leaked; tokio runtimes are expensive and process-lifetime is
/// exactly the right scope for one.
pub fn shared_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build shared tokio runtime")
    })
}

/// The shared TLS client pool (E6): one `reqwest::Client` per TLS
/// policy, reused by every adapter and every round. The client owns
/// the connection pool — reusing it is what turns per-round TLS
/// handshakes into pooled keep-alive connections.
pub fn shared_tls_client(
    policy: &orbit_adapter::types::TlsPinPolicy,
) -> Result<reqwest::Client, TransportError> {
    static POOL: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, reqwest::Client>>,
    > = std::sync::OnceLock::new();
    let pool = POOL.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let key = format!("{:?}+{:?}", policy.webpki, policy.spki_sha256);
    let mut guard = pool.lock().expect("client pool lock");
    if let Some(client) = guard.get(&key) {
        return Ok(client.clone());
    }
    let config = tls::client_config(policy)?;
    let config = std::sync::Arc::try_unwrap(config).unwrap_or_else(|arc| (*arc).clone());
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| TransportError::Transport(format!("client build: {e}")))?;
    guard.insert(key, client.clone());
    Ok(client)
}

/// The shared plain-HTTP client (no TLS policy — ollama loopback,
/// local mocks). Same pooling rationale as `shared_tls_client`.
pub fn shared_plain_client() -> Result<reqwest::Client, TransportError> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    // Building any client needs the process-wide crypto provider; this one
    // used to rely on some other adapter having installed it first.
    tls::ensure_crypto_provider();
    Ok(CLIENT
        .get_or_init(|| reqwest::Client::builder().build().unwrap_or_default())
        .clone())
}

#[cfg(test)]
mod e6_pool_tests {
    use super::*;

    #[test]
    fn tls_pool_keys_distinct_policies() {
        // Same policy key must hit the same pool entry; distinct
        // policies get distinct entries. reqwest::Client hides pool
        // identity, so assert the observable contract: repeated
        // construction with the same policy does not error and the
        // pool map holds both keys (exercised by calling both here).
        let webpki = orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: None,
        };
        let pinned = orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: Some("pin".into()),
        };
        let _a = shared_tls_client(&webpki).expect("webpki client");
        let _b = shared_tls_client(&webpki).expect("webpki client again");
        let _c = shared_tls_client(&pinned).expect("pinned client");
        // No panic + distinct keys is the contract; the map is internal.
    }

    #[test]
    fn shared_runtime_is_one_instance() {
        // The OnceLock guarantees one runtime; calling twice returns
        // the same static reference (pointer identity is observable).
        let a: &'static tokio::runtime::Runtime = shared_runtime();
        assert!(
            std::ptr::eq(a, shared_runtime()),
            "E6: one runtime for the process"
        );
    }

    #[test]
    fn plain_client_builds_repeatably() {
        let _a = shared_plain_client().expect("a");
        let _b = shared_plain_client().expect("b");
    }
}

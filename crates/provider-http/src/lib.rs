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
pub mod endpoint;
pub mod error;
pub mod ollama;
pub mod openai;
pub mod request;
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

const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const RETAINED_CLIENTS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ClientMode {
    Plain,
    Tls(orbit_adapter::types::TlsPinPolicy),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientKey {
    mode: ClientMode,
    connect_timeout_ms: u64,
}

struct ClientPool<T> {
    entries: std::collections::VecDeque<(ClientKey, T)>,
}

impl<T: Clone> ClientPool<T> {
    fn new() -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
        }
    }

    fn get_or_build(
        &mut self,
        key: ClientKey,
        build: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        if let Some((_, client)) = self.entries.iter().find(|(existing, _)| existing == &key) {
            return Ok(client.clone());
        }
        // A failed build leaves both retained clients and FIFO order intact.
        let client = build()?;
        if self.entries.len() == RETAINED_CLIENTS {
            self.entries.pop_front();
        }
        self.entries.push_back((key, client.clone()));
        Ok(client)
    }
}

fn shared_client(key: ClientKey) -> Result<reqwest::Client, TransportError> {
    static POOL: std::sync::OnceLock<std::sync::Mutex<ClientPool<reqwest::Client>>> =
        std::sync::OnceLock::new();
    let mut pool = POOL
        .get_or_init(|| std::sync::Mutex::new(ClientPool::new()))
        .lock()
        .map_err(|_| TransportError::Transport("provider client pool lock poisoned".into()))?;
    pool.get_or_build(key.clone(), || {
        tls::ensure_crypto_provider();
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_millis(key.connect_timeout_ms));
        if let ClientMode::Tls(policy) = &key.mode {
            let config = tls::client_config(policy)?;
            let config = std::sync::Arc::try_unwrap(config).unwrap_or_else(|arc| (*arc).clone());
            builder = builder.use_preconfigured_tls(config);
        }
        builder
            .build()
            .map_err(|error| TransportError::Transport(format!("client build: {error}")))
    })
}

/// Shared exact TLS-policy client with the normal ten-second connection budget.
/// This connection-only timeout does not impose a response/body/total timeout.
pub fn shared_tls_client(
    policy: &orbit_adapter::types::TlsPinPolicy,
) -> Result<reqwest::Client, TransportError> {
    shared_client(ClientKey {
        mode: ClientMode::Tls(policy.clone()),
        connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
    })
}

/// Shared default-policy client with the normal ten-second connection budget.
/// Certificate/root behavior is unchanged; this helper also serves Anthropic HTTPS.
pub fn shared_plain_client() -> Result<reqwest::Client, TransportError> {
    shared_client(ClientKey {
        mode: ClientMode::Plain,
        connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
    })
}

pub(crate) struct RequestTimeouts {
    connect_timeout_ms: u64,
    response: std::time::Duration,
    idle: std::time::Duration,
}

impl RequestTimeouts {
    pub(crate) fn new(
        request: &orbit_adapter::types::ProviderRequest,
    ) -> Result<Self, orbit_adapter::error::AdapterError> {
        Self::from_values(
            request.connect_timeout_ms,
            request.first_byte_timeout_ms,
            request.idle_timeout_ms,
            tokio::time::Instant::now(),
        )
    }

    fn from_values(
        connect: u64,
        response: u64,
        idle: u64,
        now: tokio::time::Instant,
    ) -> Result<Self, orbit_adapter::error::AdapterError> {
        for (millis, phase) in [
            (connect, "connection"),
            (response, "response start"),
            (idle, "stream idle"),
        ] {
            checked_deadline(now, std::time::Duration::from_millis(millis), phase)?;
        }
        Ok(Self {
            connect_timeout_ms: connect,
            response: std::time::Duration::from_millis(response),
            idle: std::time::Duration::from_millis(idle),
        })
    }

    pub(crate) fn response_deadline(
        &self,
    ) -> Result<tokio::time::Instant, orbit_adapter::error::AdapterError> {
        checked_deadline(tokio::time::Instant::now(), self.response, "response start")
    }

    pub(crate) fn idle_deadline(
        &self,
    ) -> Result<tokio::time::Instant, orbit_adapter::error::AdapterError> {
        checked_deadline(tokio::time::Instant::now(), self.idle, "stream idle")
    }
}

pub(crate) fn checked_deadline(
    now: tokio::time::Instant,
    duration: std::time::Duration,
    phase: &str,
) -> Result<tokio::time::Instant, orbit_adapter::error::AdapterError> {
    if duration.is_zero() {
        return Err(
            orbit_adapter::error::AdapterError::ProviderConfigurationInvalid(format!(
                "{phase} timeout must be nonzero (E0401)"
            )),
        );
    }
    now.checked_add(duration).ok_or_else(|| {
        orbit_adapter::error::AdapterError::ProviderConfigurationInvalid(format!(
            "{phase} timeout cannot be represented by the clock (E0401)"
        ))
    })
}

pub(crate) fn tls_client_for_request(
    policy: &orbit_adapter::types::TlsPinPolicy,
    timeouts: &RequestTimeouts,
) -> Result<reqwest::Client, TransportError> {
    shared_client(ClientKey {
        mode: ClientMode::Tls(policy.clone()),
        connect_timeout_ms: timeouts.connect_timeout_ms,
    })
}

pub(crate) fn plain_client_for_request(
    timeouts: &RequestTimeouts,
) -> Result<reqwest::Client, TransportError> {
    shared_client(ClientKey {
        mode: ClientMode::Plain,
        connect_timeout_ms: timeouts.connect_timeout_ms,
    })
}

/// Poll expiry before the supplied future, including when buffered work is ready.
/// Callers retain the existing cancellation-first wrapper around this wait.
pub(crate) async fn response_start_wait<F: std::future::Future>(
    deadline: tokio::time::Instant,
    future: F,
) -> Result<F::Output, ()> {
    use std::future::Future;
    use std::task::Poll;
    let expiry = tokio::time::sleep_until(deadline);
    tokio::pin!(expiry);
    tokio::pin!(future);
    std::future::poll_fn(|context| {
        if tokio::time::Instant::now() >= deadline || expiry.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(()));
        }
        match future.as_mut().poll(context) {
            Poll::Ready(value) if tokio::time::Instant::now() < deadline => Poll::Ready(Ok(value)),
            Poll::Ready(_) => Poll::Ready(Err(())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

pub(crate) fn reqwest_error(
    error: reqwest::Error,
    phase: &str,
) -> orbit_adapter::error::AdapterError {
    use orbit_adapter::error::AdapterError;
    if error.is_timeout() {
        let phase = if error.is_connect() {
            "connection"
        } else {
            phase
        };
        AdapterError::ProviderTimeout(format!("{phase} timeout (E0409)"))
    } else {
        AdapterError::ProviderTransportFailure(format!("{phase}: {error}"))
    }
}

#[cfg(test)]
mod e6_pool_tests {
    use super::*;
    use std::sync::Arc;

    fn key(mode: ClientMode, connect_timeout_ms: u64) -> ClientKey {
        ClientKey {
            mode,
            connect_timeout_ms,
        }
    }

    #[test]
    fn tls_pool_keys_distinct_policies() {
        let policy = |webpki, spki| {
            ClientMode::Tls(orbit_adapter::types::TlsPinPolicy {
                webpki,
                spki_sha256: spki,
            })
        };
        let keys = [
            key(ClientMode::Plain, 10),
            key(policy(false, None), 10),
            key(policy(true, None), 10),
            key(policy(true, Some(String::new())), 10),
            key(policy(true, Some("pin".into())), 10),
            key(ClientMode::Plain, 11),
        ];
        let mut pool = ClientPool::new();
        let mut live = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            live.push(
                pool.get_or_build(key.clone(), || Ok(Arc::new(index)))
                    .unwrap(),
            );
        }
        assert_eq!(pool.entries.len(), keys.len());
        for (index, key) in keys.iter().enumerate() {
            let hit = pool
                .get_or_build(key.clone(), || panic!("exact key should hit"))
                .unwrap();
            assert!(Arc::ptr_eq(&live[index], &hit));
            for prior in &live[..index] {
                assert!(!Arc::ptr_eq(prior, &hit));
            }
        }
    }

    #[test]
    fn pool_fifo_bounds_retained_clients_without_invalidating_live_clones() {
        let mut pool = ClientPool::new();
        let first_key = key(ClientMode::Plain, 1);
        let first = pool
            .get_or_build(first_key.clone(), || Ok(Arc::new(1)))
            .unwrap();
        for value in 2..=128 {
            pool.get_or_build(key(ClientMode::Plain, value), || Ok(Arc::new(value)))
                .unwrap();
        }
        let before = pool
            .entries
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        pool.get_or_build(first_key.clone(), || panic!("hit must not build"))
            .unwrap();
        assert_eq!(
            before,
            pool.entries
                .iter()
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
        );
        let failed = pool.get_or_build(key(ClientMode::Plain, 129), || {
            Err(TransportError::Transport("controlled build failure".into()))
        });
        assert!(failed.is_err());
        assert_eq!(
            before,
            pool.entries
                .iter()
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
        );
        pool.get_or_build(key(ClientMode::Plain, 129), || Ok(Arc::new(129)))
            .unwrap();
        assert_eq!(pool.entries.len(), 128);
        assert_eq!(pool.entries.front().unwrap().0.connect_timeout_ms, 2);
        assert_eq!(pool.entries.back().unwrap().0.connect_timeout_ms, 129);
        assert!(!pool.entries.iter().any(|(key, _)| key == &first_key));
        assert_eq!(*first, 1);
        assert_eq!(Arc::strong_count(&first), 1);
    }

    #[test]
    fn checked_timeouts_reject_zero_without_assuming_u64_max_overflows() {
        let now = tokio::time::Instant::now();
        for values in [(0, 30, 90), (10, 0, 90), (10, 30, 0)] {
            assert!(matches!(
                RequestTimeouts::from_values(values.0, values.1, values.2, now),
                Err(orbit_adapter::error::AdapterError::ProviderConfigurationInvalid(_))
            ));
        }
        let duration = std::time::Duration::from_millis(u64::MAX);
        assert_eq!(
            checked_deadline(now, duration, "response start").is_ok(),
            now.checked_add(duration).is_some()
        );
        assert!(RequestTimeouts::from_values(10, 30, 90, now).is_ok());
    }

    #[test]
    fn unrepresentable_deadline_and_explicit_clock_request_are_configuration_errors() {
        let now = tokio::time::Instant::now();
        let duration = std::time::Duration::MAX;
        assert!(
            now.checked_add(duration).is_none(),
            "target clock must reject Duration::MAX"
        );
        assert!(matches!(
            checked_deadline(now, duration, "response start"),
            Err(orbit_adapter::error::AdapterError::ProviderConfigurationInvalid(_))
        ));

        // Find this target clock's actual largest representable whole-second
        // addition; this is test data, not a production timeout upper bound.
        let mut low = 0u64;
        let mut high = u64::MAX;
        while low < high {
            let middle = low + (high - low) / 2 + 1;
            if now
                .checked_add(std::time::Duration::from_secs(middle))
                .is_some()
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let near_limit = now
            .checked_add(std::time::Duration::from_secs(low))
            .unwrap();
        assert!(
            near_limit
                .checked_add(std::time::Duration::from_secs(1))
                .is_none()
        );
        assert!(matches!(
            RequestTimeouts::from_values(1_000, 1_000, 1_000, near_limit),
            Err(orbit_adapter::error::AdapterError::ProviderConfigurationInvalid(_))
        ));
    }

    #[tokio::test]
    async fn expired_response_deadline_does_not_poll_buffered_work() {
        let mut polls = 0;
        let result = response_start_wait(tokio::time::Instant::now(), async {
            polls += 1;
            "buffered"
        })
        .await;
        assert!(result.is_err());
        assert_eq!(polls, 0);
    }

    #[tokio::test]
    async fn cancellation_wins_when_response_deadline_is_already_ready() {
        let cancel = CancelToken::new();
        cancel.cancel();
        let mut polls = 0;
        let result = cancel
            .until_cancelled(response_start_wait(tokio::time::Instant::now(), async {
                polls += 1;
                "buffered"
            }))
            .await;
        assert!(result.is_none());
        assert_eq!(polls, 0);
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

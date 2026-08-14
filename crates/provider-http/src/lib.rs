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

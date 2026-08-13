//! The two v0.1 concrete adapters: DeterministicTestV1 and MockHttpV1.
//!
//! Both are fully synchronous and hermetic (no network). They exercise the
//! entire adapter contract — route validation, capability gating, secret
//! borrow, sequence/hash/cost evidence — so the conformance harness can
//! prove the invariants without an async runtime.

use crate::credential::SecretBytes;
use crate::error::AdapterError;
use crate::provider_adapter::ProviderAdapter;
use crate::stream::output_evidence;
use crate::types::{
    AdapterIdentity, AdapterKind, ProviderCapabilities, ProviderEventKind, ProviderRequest,
    ProviderResult, ProviderRouteBinding, ProviderStreamEvent, ProviderTerminalStatus,
    ProviderUsage, Sha256Digest,
};
use std::sync::Arc;

/// A pre-baked terminal result (from a fixture). The DeterministicTestV1
/// adapter returns it verbatim — the canonical "always passes" baseline.
pub struct DeterministicTestV1 {
    identity: AdapterIdentity,
    capabilities: ProviderCapabilities,
    result: ProviderResult,
}

impl DeterministicTestV1 {
    pub fn new(
        identity: AdapterIdentity,
        capabilities: ProviderCapabilities,
        result: ProviderResult,
    ) -> Self {
        Self {
            identity,
            capabilities,
            result,
        }
    }
}

impl ProviderAdapter for DeterministicTestV1 {
    fn identity(&self) -> AdapterIdentity {
        self.identity.clone()
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn validate_route(&self, route: &ProviderRouteBinding) -> Result<(), AdapterError> {
        if route.adapter_kind != AdapterKind::DeterministicTestV1 {
            return Err(AdapterError::CapabilityMismatch(format!(
                "route kind {:?} != DeterministicTestV1 (E0414)",
                route.adapter_kind
            )));
        }
        if route.adapter_profile_digest.as_str() != self.identity.profile_digest.as_str() {
            return Err(AdapterError::AdapterProfileDigestMismatch(
                "profile digest mismatch (E0422)".to_string(),
            ));
        }
        Ok(())
    }

    fn invoke(
        &self,
        _request: &ProviderRequest,
        _credential: Option<&SecretBytes>,
    ) -> Result<ProviderResult, AdapterError> {
        Ok(self.result.clone())
    }
}

/// A scripted failure the MockHttpV1 adapter returns for a fixture.
#[derive(Debug, Clone)]
pub enum MockScript {
    Success(ProviderResult),
    /// A partial stream: events that end WITHOUT a `Finished` event. The
    /// result's status is `Partial`.
    Partial {
        events: Vec<ProviderStreamEvent>,
        usage: ProviderUsage,
    },
    Error(AdapterError),
}

/// The v0.1 synchronous mock of `OpenAiCompatibleHttpV1`. Captures the
/// wire-format request (for the conformance harness to assert against) and
/// returns a scripted result. NO network, NO hidden retry (GW-07).
pub struct MockHttpV1 {
    identity: AdapterIdentity,
    capabilities: ProviderCapabilities,
    script: MockScript,
    /// Set when a credential is delivered — lets tests prove GW-16 delivery.
    credential_received: Arc<std::sync::atomic::AtomicBool>,
}

impl MockHttpV1 {
    pub fn new(
        identity: AdapterIdentity,
        capabilities: ProviderCapabilities,
        script: MockScript,
    ) -> Self {
        Self {
            identity,
            capabilities,
            script,
            credential_received: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Build with a shared credential-receipt probe — lets tests assert the
    /// credential was DELIVERED to this adapter (GW-16 proof, P1-3 fix).
    pub fn with_credential_probe(
        identity: AdapterIdentity,
        capabilities: ProviderCapabilities,
        script: MockScript,
        probe: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            identity,
            capabilities,
            script,
            credential_received: probe,
        }
    }

    /// Whether this adapter has received a credential (for test assertions).
    pub fn credential_received(&self) -> bool {
        self.credential_received
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ProviderAdapter for MockHttpV1 {
    fn identity(&self) -> AdapterIdentity {
        self.identity.clone()
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn validate_route(&self, route: &ProviderRouteBinding) -> Result<(), AdapterError> {
        if route.adapter_kind != AdapterKind::MockHttpV1 {
            return Err(AdapterError::CapabilityMismatch(format!(
                "route kind {:?} != MockHttpV1 (E0414)",
                route.adapter_kind
            )));
        }
        if route.adapter_profile_digest.as_str() != self.identity.profile_digest.as_str() {
            return Err(AdapterError::AdapterProfileDigestMismatch(
                "profile digest mismatch (E0422)".to_string(),
            ));
        }
        Ok(())
    }

    fn invoke(
        &self,
        _request: &ProviderRequest,
        credential: Option<&SecretBytes>,
    ) -> Result<ProviderResult, AdapterError> {
        // GW-16: the credential must never be persisted or returned in any
        // event. The adapter can inspect it (borrow) but must not copy it out.
        if let Some(secret) = credential {
            // Record delivery for test assertions (P1-3), then drop it.
            self.credential_received
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let _len = secret.len();
        }

        match &self.script {
            MockScript::Success(result) => Ok(result.clone()),
            MockScript::Partial { events, usage } => {
                // A partial stream: no Finished event → status Partial with
                // the last valid usage retained (DR-09 §4).
                let evidence = output_evidence(events)?;
                Ok(ProviderResult {
                    status: ProviderTerminalStatus::Partial,
                    binding: Default::default(),
                    output: evidence,
                    accounting: crate::types::AccountingResult {
                        cost_microcents: 0,
                        currency: None,
                        usage: *usage,
                        usage_source: Some(crate::types::UsageSource::Incremental),
                        usage_complete: false,
                    },
                    transport: Default::default(),
                    events: events.clone(),
                })
            }
            MockScript::Error(e) => Err(e.clone()),
        }
    }
}

/// Build a canonical `AdapterIdentity` for tests/fixtures.
pub fn identity(kind: AdapterKind, impl_digest: &str, profile_digest: &str) -> AdapterIdentity {
    AdapterIdentity {
        kind,
        implementation_digest: Sha256Digest(impl_digest.into()),
        profile_digest: Sha256Digest(profile_digest.into()),
    }
}

/// A canonical capabilities set for a text-completion adapter.
pub fn text_capabilities() -> ProviderCapabilities {
    ProviderCapabilities {
        supports_streaming: true,
        supports_tools: false,
        supports_json_schema_output: false,
        max_input_tokens: 1_000_000,
        max_output_tokens: 64_000,
    }
}

/// A canonical "hello" completion result for the baseline fixture.
pub fn canonical_success_result() -> ProviderResult {
    let events = vec![
        ProviderStreamEvent {
            sequence: 0,
            event: ProviderEventKind::ResponseStarted {
                upstream_request_id: Some(String::from("req-1")),
            },
        },
        ProviderStreamEvent {
            sequence: 1,
            event: ProviderEventKind::TextDelta {
                bytes: b"Hello, ORBIT".to_vec(),
            },
        },
        ProviderStreamEvent {
            sequence: 2,
            event: ProviderEventKind::UsageUpdate(ProviderUsage {
                input_tokens: 12,
                output_tokens: 2,
                ..Default::default()
            }),
        },
        ProviderStreamEvent {
            sequence: 3,
            event: ProviderEventKind::Finished {
                finish_reason: Some(String::from("stop")),
                final_usage: Some(ProviderUsage {
                    input_tokens: 12,
                    output_tokens: 2,
                    ..Default::default()
                }),
            },
        },
    ];
    let evidence = output_evidence(&events).expect("canonical stream valid");
    let usage = ProviderUsage {
        input_tokens: 12,
        output_tokens: 2,
        ..Default::default()
    };
    ProviderResult::completed(events, usage, 14, evidence)
}

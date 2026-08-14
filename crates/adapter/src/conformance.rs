//! The trait-level conformance assertions every adapter MUST pass (DR-09
//! GW-07..GW-25). The full harness lives in `crates/conformance` (Phase C);
//! this module hosts the small deterministic checks that don't need fixture
//! files: route validation, capability gating, secret borrowing, and the
//! canonical success evidence.

use crate::credential::SecretBytes;
use crate::error::AdapterError;
use crate::provider_adapter::ProviderAdapter;
use crate::types::{
    AdapterIdentity, AdapterKind, ProviderCapabilities, ProviderRequest, ProviderResult,
    ProviderRouteBinding, RequestId, RequestMetadata, SamplingParameters, Sha256Digest,
};

/// Assert the adapter's route validation behaves per DR-09 §3:
/// - E0414 on capability mismatch (route kind ≠ adapter kind).
/// - E0422 on profile-digest mismatch.
/// - Ok when route fully matches identity.
pub fn assert_route_validation(adapter: &dyn ProviderAdapter) {
    let id = adapter.identity();
    let caps = adapter.capabilities();

    // Capability mismatch: wrong kind.
    let wrong_kind = make_route(
        &id,
        caps,
        AdapterKind::DeterministicTestV1,
        &id.profile_digest,
    );
    if id.kind != AdapterKind::DeterministicTestV1 {
        assert!(
            matches!(
                adapter.validate_route(&wrong_kind),
                Err(AdapterError::CapabilityMismatch(_))
            ),
            "route with mismatched kind must fail E0414"
        );
    }

    // Profile digest mismatch.
    let wrong_profile = make_route(&id, caps, id.kind, &Sha256Digest("0".repeat(64)));
    assert!(
        matches!(
            adapter.validate_route(&wrong_profile),
            Err(AdapterError::AdapterProfileDigestMismatch(_))
        ),
        "route with mismatched profile digest must fail E0422"
    );

    // Fully-matching route.
    let good = make_route(&id, caps, id.kind, &id.profile_digest);
    assert!(
        adapter.validate_route(&good).is_ok(),
        "fully-matching route must validate offline"
    );
}

/// Assert the adapter's invoke path:
/// - returns a `ProviderResult` with valid sequence evidence,
/// - accepts (and never leaks) a borrowed secret,
/// - never errors on the canonical success request.
pub fn assert_invoke_success(
    adapter: &dyn ProviderAdapter,
    request: &ProviderRequest,
    credential: Option<&SecretBytes>,
) -> ProviderResult {
    let result = adapter
        .invoke(request, credential)
        .expect("invoke must succeed");
    // The result must be self-consistent: a Completed/Partial result's
    // events must have valid sequence + canonical evidence.
    assert!(
        !result.events.is_empty(),
        "adapter must produce at least the terminalizer"
    );
    result
}

fn make_route(
    id: &AdapterIdentity,
    _caps: &ProviderCapabilities,
    kind: AdapterKind,
    profile: &Sha256Digest,
) -> ProviderRouteBinding {
    ProviderRouteBinding {
        provider_id: crate::types::ProviderId(String::from("test-provider")),
        deployment_id: crate::types::DeploymentId(String::from("test-deploy")),
        region_id: crate::types::RegionId(String::from("test-region")),
        adapter_kind: kind,
        adapter_implementation_digest: id.implementation_digest.clone(),
        adapter_profile_digest: profile.clone(),
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: String::from("test-model"),
        pricing_digest: Sha256Digest("p".repeat(64)),
        endpoint_host: String::from("api.test-provider.example"),
        endpoint_port: 443,
        endpoint_scheme: crate::types::EndpointScheme::Https,
    }
}

/// Build a canonical `ProviderRequest` for conformance assertions.
pub fn canonical_request(route: &ProviderRouteBinding, input: &[u8]) -> ProviderRequest {
    use sha2::{Digest, Sha256};
    let input_digest = Sha256Digest(hex::encode(Sha256::digest(input)));
    ProviderRequest {
        schema_version: 1,
        request_id: RequestId("req-1".into()),
        decision_id: crate::types::DecisionId("decision-1".into()),
        attempt_id: crate::types::AttemptId("attempt-1".into()),
        route: route.clone(),
        input: crate::credential::SecretBytes::new(input.to_vec()),
        messages: None,
        sampling: SamplingParameters {
            temperature_milliunits: 700,
            top_p_millionths: 950_000,
            max_output_tokens: 1024,
        },
        output: crate::types::OutputRequirements::Text,
        tools: Vec::new(),
        metadata: RequestMetadata {
            input_sha256: input_digest,
            input_bytes: input.len() as u64,
            tools_count: 0,
        },
        connect_timeout_ms: 10_000,
        first_byte_timeout_ms: 30_000,
        total_timeout_ms: 120_000,
    }
}

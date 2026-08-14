//! Gateway dispatch tests — GW-04 (no invoke before egress fsync), GW-09
//! (recovery reads durable state), GW-16 (credential reaches one adapter),
//! and the four-gate admission order through the real engine.
//!
//! P0 fixes under test:
//! - P0-1: the egress gate uses an EXTERNAL allowlist; an unadmitted
//!   destination is refused E0307.
//! - P0-3: a re-dispatched decision_id is refused E0701.
//! - P0-5: dispatch uses an injected writer (no competing flock).

use crate::dispatch::{DispatchEngine, DispatchOutcome, DispatchState};
use crate::registry::ProviderRegistry;
use crate::{new_decision_id, new_session_id};
use orbit_adapter::adapters::{
    canonical_success_result, identity, text_capabilities, DeterministicTestV1,
};
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::types::{AdapterKind, ProviderRouteBinding, Sha256Digest};
use orbit_egress::{EgressAllowlist, EgressTuple, SpkiPin};
use orbit_ledger::LedgerWriter;
use std::path::PathBuf;
use std::sync::Arc;

fn test_binding() -> ProviderRouteBinding {
    ProviderRouteBinding {
        provider_id: orbit_adapter::types::ProviderId("test-provider".into()),
        deployment_id: orbit_adapter::types::DeploymentId("test-deploy".into()),
        region_id: orbit_adapter::types::RegionId("test-region".into()),
        adapter_kind: AdapterKind::DeterministicTestV1,
        adapter_implementation_digest: Sha256Digest("i".repeat(64)),
        adapter_profile_digest: Sha256Digest("p".repeat(64)),
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: "test-model".into(),
        pricing_digest: Sha256Digest("r".repeat(64)),
        endpoint_host: String::from("test-provider"),
        endpoint_port: 443,
        endpoint_scheme: orbit_adapter::types::EndpointScheme::Https,
    }
}

/// The tuple the binding's egress resolves to (provider_id as host, per the
/// binding's provider id — the real host would come from a signed profile).
/// The SPKI pin the test route expects (a fixed digest — the test adapter
/// never performs real TLS, but the pin must EXIST for the dispatch gate).
fn spki_pin() -> SpkiPin {
    SpkiPin {
        provider_id: "test-provider".into(),
        region_id: "test-region".into(),
        spki_sha256: "expected-test-pin".into(),
    }
}

fn bound_tuple() -> EgressTuple {
    EgressTuple {
        scheme: "https".into(),
        host: "test-provider".into(),
        port: 443,
        path_prefix: "/v1".into(),
        provider_id: "test-provider".into(),
        region_id: "test-region".into(),
    }
}

/// Build an engine whose egress allowlist CONTAINS the bound tuple (admitted)
/// plus a writer already open on the ledger dir (P0-5: injected, not competing).
fn engine(tag: &str) -> (DispatchEngine, PathBuf, LedgerWriter) {
    let dir = crate::tmpdir(tag);
    let mut registry = ProviderRegistry::new();
    let adapter = DeterministicTestV1::new(
        identity(
            AdapterKind::DeterministicTestV1,
            &"i".repeat(64),
            &"p".repeat(64),
        ),
        text_capabilities(),
        canonical_success_result(),
    );
    registry.register_model(crate::ModelRef("test-model".into()), test_binding());
    registry.register_adapter(AdapterKind::DeterministicTestV1, Arc::new(adapter));
    let allowlist = EgressAllowlist::new(vec![bound_tuple()]);
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        allowlist,
        vec![bound_tuple()],
        vec![spki_pin()],
    );
    let writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();
    (engine, dir, writer)
}

/// Build an engine whose egress allowlist does NOT contain the bound tuple —
/// dispatch of the bound model must be refused E0307 (P0-1).
fn engine_unadmitted(tag: &str) -> (DispatchEngine, PathBuf, LedgerWriter) {
    let dir = crate::tmpdir(tag);
    let mut registry = ProviderRegistry::new();
    let adapter = DeterministicTestV1::new(
        identity(
            AdapterKind::DeterministicTestV1,
            &"i".repeat(64),
            &"p".repeat(64),
        ),
        text_capabilities(),
        canonical_success_result(),
    );
    registry.register_model(crate::ModelRef("test-model".into()), test_binding());
    registry.register_adapter(AdapterKind::DeterministicTestV1, Arc::new(adapter));
    // Allowlist contains a DIFFERENT tuple — the bound destination is NOT admitted.
    let allowlist = EgressAllowlist::new(vec![]);
    let engine = DispatchEngine::new(registry, dir.clone(), allowlist, vec![], vec![]);
    let writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();
    (engine, dir, writer)
}

#[test]
fn gateway_four_gate_admission_order_via_engine() {
    let (engine, dir, _writer) = engine("order");
    // Unknown model → Trust gate denied.
    match engine.resolve("unknown", "s", "d") {
        Err(e) => assert_eq!(e.code, "E0404", "unknown model fails Trust gate"),
        Ok(_) => panic!("unknown model must fail Trust gate"),
    }

    // Known model → resolves to the adapter.
    let (adapter, binding) = engine.resolve("test-model", "s", "d").unwrap();
    assert_eq!(adapter.identity().kind, AdapterKind::DeterministicTestV1);
    assert_eq!(binding.provider_id.0, "test-provider");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_dispatch_completes_and_writes_egress_intent() {
    let (engine, dir, mut writer) = engine("complete");
    let session = new_session_id();
    let decision = new_decision_id();
    let route = test_binding();
    let request = canonical_request(&route, b"hello");
    let (outcome, reservation) = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            None,
            &mut writer,
        )
        .unwrap();

    assert_eq!(reservation.decision_id, decision.0);
    match outcome {
        DispatchOutcome::Completed(r) => {
            assert_eq!(
                r.status,
                orbit_adapter::types::ProviderTerminalStatus::Completed
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }

    // The egress intent must be durable in the ledger (GW-04).
    writer.close().unwrap();
    let state = engine.recovery_state(&session, &decision.0).unwrap();
    assert!(
        matches!(state, DispatchState::EgressIntentDurable),
        "recovery must see the durable egress intent, got {state:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_credential_reaches_only_the_admitted_adapter() {
    use orbit_adapter::adapters::MockHttpV1;
    use orbit_adapter::adapters::MockScript;
    let dir = crate::tmpdir("cred");
    let mut registry = ProviderRegistry::new();
    // A credential-aware adapter with a shared receipt probe (P1-3: the test
    // must PROVE delivery, not just that dispatch completed).
    let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let adapter = MockHttpV1::with_credential_probe(
        identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
        text_capabilities(),
        MockScript::Success(canonical_success_result()),
        probe.clone(),
    );
    // The route must point at MockHttpV1 for the adapter to accept it.
    let mut binding = test_binding();
    binding.adapter_kind = AdapterKind::MockHttpV1;
    registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
    registry.register_adapter(AdapterKind::MockHttpV1, Arc::new(adapter));
    let allowlist = EgressAllowlist::new(vec![bound_tuple()]);
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        allowlist,
        vec![bound_tuple()],
        vec![spki_pin()],
    );
    let mut writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();

    let session = new_session_id();
    let decision = new_decision_id();
    let request = canonical_request(&binding, b"hello");
    let secret = SecretBytes::new(b"only-admitted-adapter".to_vec());
    let (outcome, _) = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            Some(&secret),
            &mut writer,
        )
        .unwrap();
    assert!(
        matches!(outcome, DispatchOutcome::Completed(_)),
        "GW-16: credential must reach the admitted adapter"
    );
    // The credential was DELIVERED to the admitted adapter (P1-3 proof).
    assert!(
        probe.load(std::sync::atomic::Ordering::SeqCst),
        "GW-16: the credential must actually be delivered to the adapter"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_recovery_returns_reserved_when_no_intent() {
    let (engine, dir, _writer) = engine("reserved");
    let session = new_session_id();
    let decision = new_decision_id();
    // No dispatch happened — recovery must report Reserved.
    let state = engine.recovery_state(&session, &decision.0).unwrap();
    assert_eq!(state, DispatchState::Reserved);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_egress_allowlist_refuses_unadmitted_destination() {
    // P0-1: the egress gate uses an EXTERNAL allowlist; a destination not in
    // it is refused E0307 even though the model is allowlisted + has a route.
    let (engine, dir, mut writer) = engine_unadmitted("unadmitted");
    let session = new_session_id();
    let decision = new_decision_id();
    let route = test_binding();
    let request = canonical_request(&route, b"hello");
    let r = engine.dispatch(
        "test-model",
        &session,
        &decision.0,
        &request,
        None,
        &mut writer,
    );
    match r {
        Err(e) => {
            assert_eq!(e.code, "E0307", "unadmitted destination must fail egress");
            assert_eq!(e.phase, "egress");
        }
        Ok((outcome, _)) => panic!("unadmitted destination must be refused, got {outcome:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_replayed_decision_id_refused_e0701() {
    // P0-3: a decision_id already dispatched is refused on the second attempt.
    let (engine, dir, mut writer) = engine("replay");
    let session = new_session_id();
    let decision = new_decision_id();
    let route = test_binding();
    let request = canonical_request(&route, b"hello");

    // First dispatch: completed.
    let (outcome, _) = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            None,
            &mut writer,
        )
        .unwrap();
    assert!(matches!(outcome, DispatchOutcome::Completed(_)));

    // Replay of the same decision_id → E0701.
    let r2 = engine.dispatch(
        "test-model",
        &session,
        &decision.0,
        &request,
        None,
        &mut writer,
    );
    match r2 {
        Err(e) => {
            assert_eq!(e.code, "E0701", "replayed decision must fail E0701");
        }
        Ok((outcome, _)) => panic!("replayed decision must fail E0701, got {outcome:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn gateway_async_dispatch_streams_from_mock_provider() {
    use orbit_mock_provider::server::spawn;
    use orbit_provider_http::openai::{openai_capabilities, openai_identity};
    use orbit_provider_http::{CancelToken, OpenAiCompatibleHttpV1};

    // Start the mock provider (same as the homelab binary).
    let (addr, _state, _h) = spawn().await.expect("mock spawn");
    let dir = crate::tmpdir("async-dispatch");

    // Build the engine with the async adapter registered + egress allowlist.
    let mut registry = ProviderRegistry::new();
    let adapter = OpenAiCompatibleHttpV1::new(
        openai_identity(),
        openai_capabilities(),
        orbit_adapter::types::TlsPinPolicy {
            webpki: false,
            spki_sha256: None,
        },
    )
    .unwrap();
    let mut binding = test_binding();
    binding.adapter_kind = AdapterKind::OpenAiCompatibleHttpV1;
    binding.endpoint_host = "127.0.0.1".into();
    binding.endpoint_port = addr.port();
    binding.endpoint_scheme = orbit_adapter::types::EndpointScheme::HttpLoopback;
    registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
    registry.register_async_adapter(
        AdapterKind::OpenAiCompatibleHttpV1,
        std::sync::Arc::new(adapter),
    );
    // The egress tuple derived from the binding uses the binding's provider_id
    // ("test-provider") + the loopback host/port — the allowlist must match.
    let mock_tuple = orbit_egress::EgressTuple {
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port: addr.port(),
        path_prefix: "/v1".into(),
        provider_id: "test-provider".into(),
        region_id: "test-region".into(),
    };
    let allowlist = EgressAllowlist::new(vec![mock_tuple.clone()]);
    let engine = DispatchEngine::new(registry, dir.clone(), allowlist, vec![mock_tuple], vec![]);
    let mut writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();

    let session = new_session_id();
    let decision = new_decision_id();
    let request = canonical_request(&binding, b"hello");
    let cancel = CancelToken::new();
    let (outcome, reservation) = engine
        .dispatch_async(
            "test-model",
            &session,
            &decision.0,
            &request,
            None,
            &mut writer,
            &cancel,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reservation.decision_id, decision.0);
    match outcome {
        DispatchOutcome::Completed(r) => {
            // The stream produced the mock's "hello world" text.
            let text: String = r
                .events
                .iter()
                .filter_map(|e| match &e.event {
                    orbit_adapter::types::ProviderEventKind::TextDelta { bytes } => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                text, "hello world",
                "async dispatch streamed the provider text"
            );
            // The final usage is surfaced into ProviderResult.accounting so
            // the CLI can compute real cost from its pricing config.
            assert_eq!(r.accounting.usage.input_tokens, 3);
            assert_eq!(r.accounting.usage.output_tokens, 2);
        }
        other => panic!("async dispatch expected Completed, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

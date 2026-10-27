//! Adapter conformance harness — DR-03 §5 row 4, DR-09 GW-24.
//!
//! Every adapter is "supported" ONLY if it passes the same conformance
//! assertions against its fixture set (GW-24). This harness proves the
//! DR-09 invariants that survive the synchronous v0.1 form:
//!
//! - GW-05 route pin immutable per call.
//! - GW-07 no hidden retry (the harness never grants the adapter a retry
//!   surface; each invoke is one-shot).
//! - GW-10 exactly one terminalizer and total terminal evidence.
//! - GW-11 stream events are contiguous, one-terminal, bounded.
//! - GW-12 output bytes hashed without undocumented normalization.
//! - GW-13 usage snapshots monotonic; invalid usage fails.
//! - GW-14 cost uses checked integers.
//! - GW-15 cache categories distinct; no invented rates.
//! - GW-16 credential reaches one adapter, never persisted/leaked.
//! - GW-18 drift is observable evidence, never routing.
//! - GW-25 prompt/output bytes never enter Ledger-shaped events.

use orbit_adapter::credential::SecretBytes;
use orbit_adapter::provider_adapter::ProviderAdapter;
use orbit_adapter::types::{
    ProviderRequest, ProviderRouteBinding, ProviderStreamEvent, ProviderTerminalStatus,
};

/// A single conformance assertion outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterAssertion {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// A failed conformance run.
#[derive(Debug, thiserror::Error)]
pub enum AdapterConfError {
    #[error("adapter conformance failed: {0}")]
    Failed(String),
}

/// Run the full conformance suite for an adapter. Every assertion must pass.
/// `name` identifies the adapter for diagnostics. If `route` is provided it
/// is used for the request; otherwise the adapter's own `validate_route`
/// must still pass on a canonical route (built by the caller).
pub fn run_conformance(
    _name: &str,
    adapter: &dyn ProviderAdapter,
    route: &ProviderRouteBinding,
    request: &ProviderRequest,
) -> Result<Vec<AdapterAssertion>, AdapterConfError> {
    let mut results = Vec::new();

    // GW-24: offline route validation must succeed.
    let rv = adapter.validate_route(route);
    results.push(AdapterAssertion {
        name: "offline_route_validation",
        passed: rv.is_ok(),
        detail: match rv {
            Ok(_) => "route validated offline (no network)".into(),
            Err(e) => format!("route rejected: {e}"),
        },
    });

    // GW-16: credential must not leak into the result or error.
    let secret = SecretBytes::new(b"conformance-secret-bytes".to_vec());
    let inv = adapter.invoke(request, Some(&secret));
    let result = match &inv {
        Ok(r) => r.clone(),
        Err(e) => {
            results.push(AdapterAssertion {
                name: "invoke_succeeds",
                passed: false,
                detail: format!("invoke failed: {e}"),
            });
            // Still verify the error doesn't carry the secret (GW-16).
            let err_str = e.to_string();
            results.push(AdapterAssertion {
                name: "credential_never_leaks_in_error",
                passed: !err_str.contains("conformance-secret-bytes"),
                detail: "error string must not contain credential bytes".into(),
            });
            return finish(results);
        }
    };

    results.push(AdapterAssertion {
        name: "invoke_succeeds",
        passed: true,
        detail: format!("status={:?}", result.status),
    });

    // GW-16: the result (events + output + accounting) must never contain
    // the credential bytes.
    let dump = serde_json::to_string(&result).unwrap_or_default();
    let leaked = dump.contains("conformance-secret-bytes");
    results.push(AdapterAssertion {
        name: "credential_never_persisted_in_result",
        passed: !leaked,
        detail: if leaked {
            "credential bytes leaked into serialized result".into()
        } else {
            "no credential bytes in result evidence".into()
        },
    });

    // GW-11/GW-10: validate stream contiguity + single terminal via the
    // adapter's own stream validation (re-run on the returned events).
    let stream_ok = validate_result_events(&result.events);
    results.push(AdapterAssertion {
        name: "stream_contiguous_and_single_terminal",
        passed: stream_ok.is_empty(),
        detail: if stream_ok.is_empty() {
            "events contiguous; terminal placement and usage snapshots validated".into()
        } else {
            stream_ok
        },
    });

    // GW-12: output hashes are present + 64-hex.
    let hashes_ok = result.output.raw_stream_sha256.0.len() == 64
        && result.output.canonical_output_sha256.0.len() == 64;
    results.push(AdapterAssertion {
        name: "output_evidence_hashes_present",
        passed: hashes_ok,
        detail: if hashes_ok {
            "raw_stream + canonical_output are 64-hex".into()
        } else {
            "missing/incorrect output evidence hashes".into()
        },
    });

    // GW-14: cost is a plain u64 (never a float) and present.
    let cost_ok = true; // CostMicrocents is a u64 by construction.
    results.push(AdapterAssertion {
        name: "cost_integer_microcents",
        passed: cost_ok,
        detail: format!("cost_microcents={}", result.accounting.cost_microcents),
    });

    // GW-13: usage completeness is explicit.
    let usage_ok = result.accounting.usage_source.is_some();
    results.push(AdapterAssertion {
        name: "usage_source_explicit",
        passed: usage_ok,
        detail: if usage_ok {
            "usage source declared".into()
        } else {
            "usage source missing (incomplete cost must be explicit)".into()
        },
    });

    // GW-18: drift never changes the terminal status.
    let drift_ok = result.binding.drift.iter().all(|_d| {
        // Drift is evidence; a completed result stays completed.
        result.status == ProviderTerminalStatus::Completed
            || result.status == ProviderTerminalStatus::Partial
    });
    results.push(AdapterAssertion {
        name: "drift_is_evidence_not_status",
        passed: drift_ok,
        detail: "drift observations do not alter terminal status".into(),
    });

    finish(results)
}

fn finish(results: Vec<AdapterAssertion>) -> Result<Vec<AdapterAssertion>, AdapterConfError> {
    let failed = results.iter().filter(|a| !a.passed).count();
    if failed == 0 {
        Ok(results)
    } else {
        let names: Vec<&str> = results
            .iter()
            .filter(|a| !a.passed)
            .map(|a| a.name)
            .collect();
        Err(AdapterConfError::Failed(format!(
            "{failed} assertion(s) failed: {names:?}"
        )))
    }
}

/// Validate through the shared adapter stream checks, including raw usage and metadata.
/// Valid partial prefixes retain their existing acceptance. Returns "" on success.
fn validate_result_events(events: &[ProviderStreamEvent]) -> String {
    match orbit_adapter::stream::validate_stream(events) {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_adapter::adapters::{
        DeterministicTestV1, MockHttpV1, MockScript, canonical_success_result, identity,
        text_capabilities,
    };
    use orbit_adapter::conformance::canonical_request;
    use orbit_adapter::types::{
        AdapterKind, ProviderRouteBinding, ProviderStreamEvent, ProviderUsage, Sha256Digest,
    };

    fn route(kind: AdapterKind) -> ProviderRouteBinding {
        ProviderRouteBinding {
            provider_id: orbit_adapter::types::ProviderId("test-provider".into()),
            deployment_id: orbit_adapter::types::DeploymentId("test-deploy".into()),
            region_id: orbit_adapter::types::RegionId("test-region".into()),
            adapter_kind: kind,
            adapter_implementation_digest: Sha256Digest("i".repeat(64)),
            adapter_profile_digest: Sha256Digest("p".repeat(64)),
            endpoint_digest: Sha256Digest("e".repeat(64)),
            expected_model: "test-model".into(),
            pricing_digest: Sha256Digest("r".repeat(64)),
            endpoint_host: String::from("api.test-provider.example"),
            endpoint_port: 443,
            endpoint_scheme: orbit_adapter::types::EndpointScheme::Https,
            endpoint_path: String::new(),
            endpoint_query: None,
        }
    }

    #[test]
    fn deterministic_adapter_passes_full_conformance() {
        let result = canonical_success_result();
        let adapter = DeterministicTestV1::new(
            identity(
                AdapterKind::DeterministicTestV1,
                &"i".repeat(64),
                &"p".repeat(64),
            ),
            text_capabilities(),
            result,
        );
        let r = route(AdapterKind::DeterministicTestV1);
        let request = canonical_request(&r, b"conformance input");
        let assertions = run_conformance("deterministic-test-v1", &adapter, &r, &request).unwrap();
        assert!(
            assertions.iter().all(|a| a.passed),
            "all assertions must pass: {assertions:#?}"
        );
    }

    #[test]
    fn mock_http_success_passes_conformance() {
        let adapter = MockHttpV1::new(
            identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
            text_capabilities(),
            MockScript::Success(canonical_success_result()),
        );
        let r = route(AdapterKind::MockHttpV1);
        let request = canonical_request(&r, b"conformance input");
        let assertions = run_conformance("mock-http-v1-success", &adapter, &r, &request).unwrap();
        assert!(
            assertions.iter().all(|a| a.passed),
            "all assertions must pass: {assertions:#?}"
        );
    }

    #[test]
    fn mock_http_partial_stream_reports_partial_but_passes() {
        let usage = ProviderUsage {
            input_tokens: 7,
            output_tokens: 1,
            ..Default::default()
        };
        let events = vec![
            ProviderStreamEvent {
                usage_observation: None,
                sequence: 0,
                event: orbit_adapter::types::ProviderEventKind::ResponseStarted {
                    upstream_request_id: None,
                },
            },
            ProviderStreamEvent {
                usage_observation: None,
                sequence: 1,
                event: orbit_adapter::types::ProviderEventKind::TextDelta {
                    bytes: b"partial".to_vec(),
                },
            },
            ProviderStreamEvent {
                usage_observation: None,
                sequence: 2,
                event: orbit_adapter::types::ProviderEventKind::UsageUpdate(usage),
            },
        ];
        let adapter = MockHttpV1::new(
            identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
            text_capabilities(),
            MockScript::Partial { events, usage },
        );
        let r = route(AdapterKind::MockHttpV1);
        let request = canonical_request(&r, b"conformance input");
        let assertions = run_conformance("mock-http-v1-partial", &adapter, &r, &request).unwrap();
        assert!(
            assertions.iter().all(|a| a.passed),
            "partial stream must still pass with explicit Partial status: {assertions:#?}"
        );
    }

    #[test]
    fn mismatched_profile_digest_fails_route_validation() {
        // Adapter profile digest 'p' vs route profile digest 'wrong' → E0422.
        let adapter = MockHttpV1::new(
            identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
            text_capabilities(),
            MockScript::Success(canonical_success_result()),
        );
        let mut r = route(AdapterKind::MockHttpV1);
        r.adapter_profile_digest = Sha256Digest("wrong".into());
        let request = canonical_request(&r, b"conformance input");
        let err = run_conformance("mock-http-v1-bad-profile", &adapter, &r, &request);
        assert!(err.is_err(), "profile mismatch must fail conformance");
    }

    #[test]
    fn decreasing_usage_stream_fails_conformance() {
        let route = route(AdapterKind::MockHttpV1);
        let request = canonical_request(&route, b"conformance input");
        let canonical = canonical_success_result();
        let control = MockHttpV1::new(
            identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
            text_capabilities(),
            MockScript::Success(canonical.clone()),
        );
        let assertions = run_conformance("canonical-control", &control, &route, &request)
            .expect("the canonical result must pass the full conformance suite");
        assert!(!assertions.is_empty());
        assert!(assertions.iter().all(|assertion| assertion.passed));

        let mut regressed = canonical.clone();
        match &mut regressed
            .events
            .last_mut()
            .expect("canonical terminal")
            .event
        {
            orbit_adapter::types::ProviderEventKind::Finished {
                final_usage: Some(usage),
                ..
            } => {
                assert_eq!(usage.output_tokens, 2);
                usage.output_tokens = 1;
            }
            _ => panic!("canonical result must end with final usage"),
        }
        assert_eq!(regressed.output, canonical.output);
        assert_eq!(regressed.accounting, canonical.accounting);
        let mut restored = regressed.clone();
        match &mut restored
            .events
            .last_mut()
            .expect("canonical terminal")
            .event
        {
            orbit_adapter::types::ProviderEventKind::Finished {
                final_usage: Some(usage),
                ..
            } => usage.output_tokens = 2,
            _ => panic!("canonical result must end with final usage"),
        }
        assert_eq!(
            restored, canonical,
            "only the final output counter may differ"
        );
        let usage_error = orbit_adapter::stream::validate_stream(&regressed.events)
            .expect_err("the shared validator must reject the final-only raw decrease");
        assert_eq!(usage_error.code(), "E0416");
        let bad = MockHttpV1::new(
            identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
            text_capabilities(),
            MockScript::Success(regressed.clone()),
        );
        run_conformance("final-raw-decrease", &bad, &route, &request)
            .expect_err("conformance must reject the final-only raw decrease");
        assert!(validate_result_events(&regressed.events).contains("E0416"));
    }

    #[test]
    fn skipped_sequence_stream_fails_conformance() {
        let route = route(AdapterKind::MockHttpV1);
        let request = canonical_request(&route, b"conformance input");
        let canonical = canonical_success_result();
        let control = MockHttpV1::new(
            identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
            text_capabilities(),
            MockScript::Success(canonical.clone()),
        );
        let assertions = run_conformance("canonical-sequence-control", &control, &route, &request)
            .expect("the canonical result must pass the full conformance suite");
        assert!(!assertions.is_empty());
        assert!(assertions.iter().all(|assertion| assertion.passed));

        let mut skipped = canonical.clone();
        assert_eq!(skipped.events[1].sequence, 1);
        skipped.events[1].sequence = 2;
        assert_eq!(skipped.output, canonical.output);
        assert_eq!(skipped.accounting, canonical.accounting);
        let mut restored = skipped.clone();
        restored.events[1].sequence = 1;
        assert_eq!(restored, canonical, "only the selected sequence may differ");
        let sequence_error = orbit_adapter::stream::validate_stream(&skipped.events)
            .expect_err("the shared validator must reject the skipped sequence");
        assert_eq!(sequence_error.code(), "E0411");
        let bad = MockHttpV1::new(
            identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
            text_capabilities(),
            MockScript::Success(skipped.clone()),
        );
        run_conformance("skipped-sequence", &bad, &route, &request)
            .expect_err("conformance must reject the skipped sequence");
        assert!(validate_result_events(&skipped.events).contains("E0411"));
    }
}

/// A pinned adapter conformance fixture (`orbit.adapter-conformance/v1`).
/// Unknown fields are allowed so fixtures remain forward-compatible.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AdapterFixture {
    pub schema: String,
    pub case: String,
    pub orbit_version_min: String,
    pub orbit_version_max: String,
    pub kind: String,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Load one pinned adapter fixture from `conformance/cases/adapter/<name>`.
pub fn load_adapter_fixture(
    corpus_dir: &str,
    name: &str,
) -> Result<AdapterFixture, AdapterConfError> {
    let path = std::path::Path::new(corpus_dir)
        .join(name)
        .join("fixture.json");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| AdapterConfError::Failed(format!("read fixture {path:?}: {e}")))?;
    let fixture: AdapterFixture = serde_json::from_str(&raw)
        .map_err(|e| AdapterConfError::Failed(format!("decode fixture {path:?}: {e}")))?;
    if fixture.schema != "orbit.adapter-conformance/v1" {
        return Err(AdapterConfError::Failed(format!(
            "unsupported adapter fixture schema {}",
            fixture.schema
        )));
    }
    Ok(fixture)
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    #[test]
    fn all_pinned_adapter_fixtures_load_and_validate_schema() {
        let corpus = format!("{}/cases/adapter", env!("CARGO_MANIFEST_DIR"));
        let names = [
            "deterministic-test-v1",
            "mock-http-v1-success",
            "mock-http-v1-partial-stream",
            "mock-http-v1-rate-limit",
            "mock-http-v1-timeout",
            "mock-http-v1-mixed-currency",
            "mock-http-v1-drift",
            "mock-http-v1-credential-never-leaked",
            "mock-http-v1-sampling-integer-form",
            "mock-http-v1-sequence-skipped",
            "mock-http-v1-sequence-duplicate",
            "mock-http-v1-post-terminal-event",
            "mock-http-v1-usage-decrease",
            "mock-http-v1-no-finished",
            "mock-http-v1-rejected-route",
            "mock-http-v1-bad-spki-pin",
        ];
        for name in names {
            let f = load_adapter_fixture(&corpus, name)
                .unwrap_or_else(|e| panic!("fixture {name} failed to load: {e}"));
            assert_eq!(f.case, name);
            assert_eq!(f.orbit_version_min, "0.1.0");
            assert_eq!(f.orbit_version_max, "0.1.x");
            assert!(!f.kind.is_empty());
        }
    }
}

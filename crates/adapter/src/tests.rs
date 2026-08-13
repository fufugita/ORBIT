use crate::adapters::{
    canonical_success_result, identity, text_capabilities, DeterministicTestV1, MockHttpV1,
    MockScript,
};
use crate::conformance::{assert_invoke_success, assert_route_validation, canonical_request};
use crate::credential::SecretBytes;
use crate::error::{AdapterError, AdapterRetryClass};
use crate::provider_adapter::ProviderAdapter;
use crate::redaction::{
    classify_sensitive_name, redact_pair, scrub_secret_bytes, RedactionCategory,
};
use crate::stream::{canonical_output_sha256, output_evidence, validate_stream};
use crate::types::*;

fn test_route(kind: AdapterKind) -> ProviderRouteBinding {
    ProviderRouteBinding {
        provider_id: ProviderId(String::from("test-provider")),
        deployment_id: DeploymentId(String::from("test-deploy")),
        region_id: RegionId(String::from("test-region")),
        adapter_kind: kind,
        adapter_implementation_digest: Sha256Digest("i".repeat(64)),
        adapter_profile_digest: Sha256Digest("p".repeat(64)),
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: String::from("test-model"),
        pricing_digest: Sha256Digest("r".repeat(64)),
        endpoint_host: String::from("api.test-provider.example"),
        endpoint_port: 443,
    }
}

#[test]
fn deterministic_adapter_route_and_invoke() {
    let result = canonical_success_result();
    let adapter = DeterministicTestV1::new(
        identity(
            AdapterKind::DeterministicTestV1,
            &"i".repeat(64),
            &"p".repeat(64),
        ),
        text_capabilities(),
        result.clone(),
    );
    assert_route_validation(&adapter);
    let route = test_route(AdapterKind::DeterministicTestV1);
    let request = canonical_request(&route, b"hello");
    let got = assert_invoke_success(&adapter, &request, None);
    assert_eq!(got, result);
}

#[test]
fn mock_adapter_partial_stream_retains_usage() {
    let usage = ProviderUsage {
        input_tokens: 7,
        output_tokens: 1,
        ..Default::default()
    };
    let events = vec![
        ProviderStreamEvent {
            sequence: 0,
            event: ProviderEventKind::ResponseStarted {
                upstream_request_id: None,
            },
        },
        ProviderStreamEvent {
            sequence: 1,
            event: ProviderEventKind::TextDelta {
                bytes: b"partial".to_vec(),
            },
        },
        ProviderStreamEvent {
            sequence: 2,
            event: ProviderEventKind::UsageUpdate(usage),
        },
    ];
    let adapter = MockHttpV1::new(
        identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
        text_capabilities(),
        MockScript::Partial {
            events: events.clone(),
            usage,
        },
    );
    let route = test_route(AdapterKind::MockHttpV1);
    let request = canonical_request(&route, b"hello");
    let credential = SecretBytes::new(b"secret".to_vec());
    let result = adapter.invoke(&request, Some(&credential)).unwrap();
    assert_eq!(result.status, ProviderTerminalStatus::Partial);
    assert_eq!(result.accounting.usage, usage);
    assert!(!result.accounting.usage_complete);
    assert_eq!(result.events, events);
}

#[test]
fn stream_sequence_and_usage_violations_refused() {
    let skipped = vec![
        ProviderStreamEvent {
            sequence: 0,
            event: ProviderEventKind::ResponseStarted {
                upstream_request_id: None,
            },
        },
        ProviderStreamEvent {
            sequence: 2,
            event: ProviderEventKind::Finished {
                finish_reason: None,
                final_usage: None,
            },
        },
    ];
    assert_eq!(validate_stream(&skipped).unwrap_err().code(), "E0411");

    let decreasing = vec![
        ProviderStreamEvent {
            sequence: 0,
            event: ProviderEventKind::UsageUpdate(ProviderUsage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            }),
        },
        ProviderStreamEvent {
            sequence: 1,
            event: ProviderEventKind::UsageUpdate(ProviderUsage {
                input_tokens: 10,
                output_tokens: 4,
                ..Default::default()
            }),
        },
    ];
    assert_eq!(validate_stream(&decreasing).unwrap_err().code(), "E0416");
}

#[test]
fn output_hashes_preserve_bytes_exactly() {
    let events = vec![
        ProviderStreamEvent {
            sequence: 0,
            event: ProviderEventKind::TextDelta {
                bytes: b"a\r\n".to_vec(),
            },
        },
        ProviderStreamEvent {
            sequence: 1,
            event: ProviderEventKind::TextDelta {
                bytes: "é".as_bytes().to_vec(),
            },
        },
        ProviderStreamEvent {
            sequence: 2,
            event: ProviderEventKind::Finished {
                finish_reason: Some(String::from("stop")),
                final_usage: None,
            },
        },
    ];
    let evidence = output_evidence(&events).unwrap();
    assert_eq!(
        evidence.canonical_output_sha256,
        canonical_output_sha256(&events)
    );
    assert_eq!(evidence.observed_bytes, 5);
}

#[test]
fn sampling_wire_format_is_integer_only() {
    let sampling = SamplingParameters {
        temperature_milliunits: 700,
        top_p_millionths: 950_000,
        max_output_tokens: 2048,
    };
    let wire = sampling.to_wire();
    assert!(wire["temperature_milliunits"].is_u64());
    assert!(wire["top_p_millionths"].is_u64());
    assert!(wire["max_output_tokens"].is_u64());
    assert!(wire.get("temperature").is_none());
    assert!(wire.get("top_p").is_none());
}

#[test]
fn checked_integer_cost_rounds_categories_independently() {
    let rates = CostRates {
        input_per_million_microcents: 1,
        output_per_million_microcents: 2,
        cache_read_per_million_microcents: Some(3),
        cache_write_per_million_microcents: Some(4),
        reasoning_per_million_microcents: Some(5),
        request_flat_microcents: 7,
    };
    let usage = ProviderUsage {
        input_tokens: 1,
        output_tokens: 1,
        cache_read_tokens: 1,
        cache_write_tokens: 1,
        reasoning_tokens: 1,
    };
    // Each nonzero category ceil-rounds to 1, plus the flat cost of 7.
    assert_eq!(rates.cost_microcents(&usage), Some(12));
}

#[test]
fn redaction_catalog_and_secret_scrubber_never_leak() {
    assert_eq!(
        classify_sensitive_name("Authorization"),
        Some(RedactionCategory::AuthorizationHeader)
    );
    let (redacted, evidence) = redact_pair("X-API-Key", b"super-secret");
    assert_eq!(redacted, b"[REDACTED]");
    assert_eq!(evidence.unwrap().category, RedactionCategory::ApiKeyHeader);

    let (scrubbed, evidence) = scrub_secret_bytes(
        b"prefix super-secret middle super-secret suffix",
        b"super-secret",
    );
    assert!(!scrubbed.windows(12).any(|w| w == b"super-secret"));
    assert_eq!(evidence.unwrap().count, 2);
}

#[test]
fn scrub_secret_bytes_is_output_bounded_not_oom() {
    // P1-5: a 1-byte secret on a large all-matching diagnostic must NOT blow
    // the output beyond the cap — the scrubber truncates, never OOMs.
    let secret = b"a";
    let huge = vec![b'a'; 5_000_000]; // 5 MiB of the secret
    let (out, evidence) = scrub_secret_bytes(&huge, secret);
    assert!(
        out.len() <= (1 << 20) + 64,
        "output must stay bounded (got {} bytes)",
        out.len()
    );
    // The evidence still records that matches were found.
    assert!(evidence.is_some());
    assert!(evidence.unwrap().count > 0);
    // A truncation marker was appended.
    assert!(out.ends_with(b"...[TRUNCATED]"));
}

#[test]
fn adapter_error_retry_classification_is_closed() {
    assert_eq!(
        AdapterError::ProviderTransportFailure("x".into()).retry_class(),
        AdapterRetryClass::RetryableTransport
    );
    assert_eq!(
        AdapterError::RateLimitedExhausted("x".into()).retry_class(),
        AdapterRetryClass::RetryableRate
    );
    assert_eq!(
        AdapterError::CredentialRejected("x".into()).retry_class(),
        AdapterRetryClass::NotRetryable
    );
}

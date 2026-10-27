use crate::adapters::{
    DeterministicTestV1, MockHttpV1, MockScript, canonical_success_result, identity,
    text_capabilities,
};
use crate::conformance::{assert_invoke_success, assert_route_validation, canonical_request};
use crate::credential::SecretBytes;
use crate::error::{AdapterError, AdapterRetryClass};
use crate::provider_adapter::ProviderAdapter;
use crate::redaction::{
    RedactionCategory, classify_sensitive_name, redact_pair, scrub_secret_bytes,
};
use crate::stream::{
    UsageObservationAccumulatorV1, canonical_output_sha256, output_evidence,
    usage_observation_evidence_v1, validate_stream,
};
use crate::types::*;

#[test]
fn effort_values_preserve_typed_wire_values_and_validate_shape() {
    for value in [
        EffortValue::Bool(false),
        EffortValue::Bool(true),
        EffortValue::Level("high".into()),
    ] {
        assert_eq!(
            serde_json::from_value::<EffortValue>(serde_json::to_value(&value).unwrap()).unwrap(),
            value
        );
        assert!(value.validate().is_ok());
    }
    assert_eq!(
        serde_json::to_value(EffortValue::Bool(false)).unwrap(),
        serde_json::json!(false)
    );
    assert_eq!(
        serde_json::to_value(EffortValue::Level("false".into())).unwrap(),
        serde_json::json!("false")
    );
    for invalid in ["", " high", "high ", "hi\ngh", "default"] {
        assert!(EffortValue::Level(invalid.into()).validate().is_err());
    }
    assert!(EffortValue::Level("x".repeat(65)).validate().is_err());
    assert!(EffortValue::Level("é".repeat(33)).validate().is_err());
    assert!(EffortValue::Level("é".repeat(32)).validate().is_ok());
    for invalid in [
        serde_json::json!(3),
        serde_json::json!(null),
        serde_json::json!({}),
    ] {
        assert!(serde_json::from_value::<EffortValue>(invalid).is_err());
    }
}

#[test]
fn effort_setting_preserves_explicit_default_and_value() {
    assert_eq!(
        serde_json::to_value(EffortSetting::Default).unwrap(),
        serde_json::json!({"mode":"default"})
    );
    for setting in [
        EffortSetting::Default,
        EffortSetting::Value(EffortValue::Bool(false)),
        EffortSetting::Value(EffortValue::Level("high".into())),
    ] {
        assert_eq!(
            serde_json::from_value::<EffortSetting>(serde_json::to_value(&setting).unwrap())
                .unwrap(),
            setting
        );
    }
}

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
        endpoint_scheme: crate::types::EndpointScheme::Https,
        endpoint_path: String::new(),
        endpoint_query: None,
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
            usage_observation: None,
            sequence: 0,
            event: ProviderEventKind::ResponseStarted {
                upstream_request_id: None,
            },
        },
        ProviderStreamEvent {
            usage_observation: None,
            sequence: 1,
            event: ProviderEventKind::TextDelta {
                bytes: b"partial".to_vec(),
            },
        },
        ProviderStreamEvent {
            usage_observation: None,
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
            usage_observation: None,
            sequence: 0,
            event: ProviderEventKind::ResponseStarted {
                upstream_request_id: None,
            },
        },
        ProviderStreamEvent {
            usage_observation: None,
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
            usage_observation: None,
            sequence: 0,
            event: ProviderEventKind::UsageUpdate(ProviderUsage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            }),
        },
        ProviderStreamEvent {
            usage_observation: None,
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
            usage_observation: None,
            sequence: 0,
            event: ProviderEventKind::TextDelta {
                bytes: b"a\r\n".to_vec(),
            },
        },
        ProviderStreamEvent {
            usage_observation: None,
            sequence: 1,
            event: ProviderEventKind::TextDelta {
                bytes: "é".as_bytes().to_vec(),
            },
        },
        ProviderStreamEvent {
            usage_observation: None,
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

#[test]
fn endpoint_query_serde_roundtrip_retains_exact_raw_query() {
    let mut encoded = serde_json::to_value(test_route(AdapterKind::MockHttpV1)).unwrap();
    encoded["endpoint_query"] =
        serde_json::json!("scope=synthetic&escaped=a%2Fb%26c%3Dd%2Be&space=a+b");
    let decoded: ProviderRouteBinding = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
}

#[test]
fn endpoint_query_absent_serialization_keeps_existing_route_bytes() {
    let route = test_route(AdapterKind::MockHttpV1);
    let expected = format!(
        concat!(
            "{{\"provider_id\":\"test-provider\",\"deployment_id\":\"test-deploy\",",
            "\"region_id\":\"test-region\",\"adapter_kind\":\"MockHttpV1\",",
            "\"adapter_implementation_digest\":\"{}\",\"adapter_profile_digest\":\"{}\",",
            "\"endpoint_digest\":\"{}\",\"expected_model\":\"test-model\",",
            "\"pricing_digest\":\"{}\",\"endpoint_host\":\"api.test-provider.example\",",
            "\"endpoint_port\":443,\"endpoint_scheme\":\"Https\",\"endpoint_path\":\"\"}}"
        ),
        "i".repeat(64),
        "p".repeat(64),
        "e".repeat(64),
        "r".repeat(64),
    );
    let serialized = serde_json::to_vec(&route).unwrap();
    assert_eq!(serialized, expected.as_bytes());
    let decoded: ProviderRouteBinding = serde_json::from_slice(expected.as_bytes()).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), serialized);
    assert!(
        !String::from_utf8(serialized)
            .unwrap()
            .contains("endpoint_query")
    );
}

#[test]
fn endpoint_query_is_part_of_full_route_equality() {
    let route = test_route(AdapterKind::MockHttpV1);
    let mut encoded = serde_json::to_value(&route).unwrap();
    encoded["endpoint_query"] = serde_json::json!("scope=one");
    let one: ProviderRouteBinding = serde_json::from_value(encoded.clone()).unwrap();
    encoded["endpoint_query"] = serde_json::json!("scope=two");
    let two: ProviderRouteBinding = serde_json::from_value(encoded.clone()).unwrap();
    assert_ne!(
        one, two,
        "changing only query must change the admitted route"
    );
    assert_ne!(
        route, one,
        "absent query must differ from an explicitly bound query"
    );
    encoded["endpoint_query"] = serde_json::json!("");
    let empty: ProviderRouteBinding = serde_json::from_value(encoded).unwrap();
    assert_ne!(
        route, empty,
        "empty query must not silently collapse to absence"
    );
}

fn assert_final_raw_usage_regression_refused(regress: fn(&mut ProviderUsage)) {
    let last_usage = ProviderUsage {
        input_tokens: 10,
        output_tokens: 20,
        cache_read_tokens: 3,
        cache_write_tokens: 4,
        reasoning_tokens: 5,
    };
    let mut events = [
        ProviderStreamEvent {
            usage_observation: None,
            sequence: 0,
            event: ProviderEventKind::ResponseStarted {
                upstream_request_id: None,
            },
        },
        ProviderStreamEvent {
            usage_observation: None,
            sequence: 1,
            event: ProviderEventKind::UsageUpdate(last_usage),
        },
        ProviderStreamEvent {
            usage_observation: None,
            sequence: 2,
            event: ProviderEventKind::Finished {
                finish_reason: Some("stop".into()),
                final_usage: Some(last_usage),
            },
        },
    ];
    assert!(
        validate_stream(&events).is_ok(),
        "the unchanged final snapshot must form a valid control stream"
    );
    let mut final_usage = last_usage;
    regress(&mut final_usage);
    events[2].event = ProviderEventKind::Finished {
        finish_reason: Some("stop".into()),
        final_usage: Some(final_usage),
    };
    let error = validate_stream(&events)
        .expect_err("a final raw counter below its last UsageUpdate must be refused");
    assert!(matches!(&error, AdapterError::ProviderUsageInvalid(_)));
    assert_eq!(error.code(), "E0416");
}

#[test]
fn stream_final_input_usage_regression_is_refused() {
    assert_final_raw_usage_regression_refused(|usage| usage.input_tokens = 9);
}

#[test]
fn stream_final_output_usage_regression_is_refused() {
    assert_final_raw_usage_regression_refused(|usage| usage.output_tokens = 19);
}

#[test]
fn stream_final_cache_read_usage_regression_is_refused() {
    assert_final_raw_usage_regression_refused(|usage| usage.cache_read_tokens = 2);
}

#[test]
fn stream_final_cache_write_usage_regression_is_refused() {
    assert_final_raw_usage_regression_refused(|usage| usage.cache_write_tokens = 3);
}

#[test]
fn stream_final_reasoning_usage_regression_is_refused() {
    assert_final_raw_usage_regression_refused(|usage| usage.reasoning_tokens = 4);
}

fn observation_fixture_usage(values: [u64; 5]) -> ProviderUsage {
    ProviderUsage {
        input_tokens: values[0],
        output_tokens: values[1],
        cache_read_tokens: values[2],
        cache_write_tokens: values[3],
        reasoning_tokens: values[4],
    }
}

fn observation_fixture_event(
    sequence: u64,
    event: ProviderEventKind,
    usage_observation: Option<UsageObservationMetaV1>,
) -> ProviderStreamEvent {
    ProviderStreamEvent {
        sequence,
        event,
        usage_observation,
    }
}

fn observation_fixture_metadata(
    reporting: UsageReasoningReportingV1,
    origin: UsageSnapshotOriginV1,
) -> UsageObservationMetaV1 {
    UsageObservationMetaV1 {
        version: 1,
        reasoning_reporting: reporting,
        snapshot_origin: origin,
    }
}

#[test]
fn usage_observation_absence_retains_exact_legacy_json() {
    let usage = observation_fixture_usage([0; 5]);
    let legacy = r#"{"sequence":0,"event":{"UsageUpdate":{"input_tokens":0,"output_tokens":0,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":0}}}"#;
    let event = observation_fixture_event(0, ProviderEventKind::UsageUpdate(usage), None);
    assert_eq!(serde_json::to_string(&event).unwrap(), legacy);
    assert_eq!(
        serde_json::from_str::<ProviderStreamEvent>(legacy).unwrap(),
        event
    );
    let accounting = AccountingResult {
        cost_microcents: 0,
        currency: None,
        usage,
        usage_source: Some(UsageSource::Final),
        usage_complete: true,
        usage_observation: None,
    };
    let expected = r#"{"cost_microcents":0,"currency":null,"usage":{"input_tokens":0,"output_tokens":0,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":0},"usage_source":"Final","usage_complete":true}"#;
    assert_eq!(serde_json::to_string(&accounting).unwrap(), expected);
    assert_eq!(
        serde_json::from_str::<AccountingResult>(expected).unwrap(),
        accounting
    );
    let metadata = observation_fixture_metadata(
        UsageReasoningReportingV1::Reported,
        UsageSnapshotOriginV1::ProviderReported,
    );
    let with_metadata =
        observation_fixture_event(0, ProviderEventKind::UsageUpdate(usage), Some(metadata));
    let expected = r#"{"sequence":0,"event":{"UsageUpdate":{"input_tokens":0,"output_tokens":0,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":0}},"usage_observation":{"version":1,"reasoning_reporting":"reported","snapshot_origin":"provider_reported"}}"#;
    assert_eq!(serde_json::to_string(&with_metadata).unwrap(), expected);
    assert_eq!(
        serde_json::from_str::<ProviderStreamEvent>(expected).unwrap(),
        with_metadata
    );
}

#[test]
fn usage_observation_present_metadata_requires_a_strict_complete_object() {
    let base = serde_json::to_string(&observation_fixture_event(
        0,
        ProviderEventKind::UsageUpdate(ProviderUsage::default()),
        None,
    ))
    .unwrap();
    for metadata in [
        "null",
        "{}",
        r#"{"version":2,"reasoning_reporting":"reported","snapshot_origin":"provider_reported"}"#,
        r#"{"version":0,"reasoning_reporting":"reported","snapshot_origin":"provider_reported"}"#,
        r#"{"reasoning_reporting":"reported","snapshot_origin":"provider_reported"}"#,
        r#"{"version":1,"snapshot_origin":"provider_reported"}"#,
        r#"{"version":1,"reasoning_reporting":"reported"}"#,
        r#"{"version":1,"reasoning_reporting":"legacy_unknown","snapshot_origin":"provider_reported"}"#,
        r#"{"version":1,"reasoning_reporting":"reported","snapshot_origin":"legacy_unknown"}"#,
        r#"{"version":1,"version":1,"reasoning_reporting":"reported","snapshot_origin":"provider_reported"}"#,
        r#"{"version":1,"reasoning_reporting":"reported","reasoning_reporting":"not_reported","snapshot_origin":"provider_reported"}"#,
        r#"{"version":1,"reasoning_reporting":"reported","snapshot_origin":"provider_reported","snapshot_origin":"synthetic"}"#,
        r#"{"version":1,"reasoning_reporting":"reported","snapshot_origin":"provider_reported","extra":0}"#,
    ] {
        let document = format!(
            "{},\"usage_observation\":{metadata}}}",
            &base[..base.len() - 1]
        );
        assert!(
            serde_json::from_str::<ProviderStreamEvent>(&document).is_err(),
            "{metadata}"
        );
    }
    let metadata =
        r#"{"version":1,"reasoning_reporting":"reported","snapshot_origin":"provider_reported"}"#;
    let duplicated = format!(
        "{},\"usage_observation\":{metadata},\"usage_observation\":{metadata}}}",
        &base[..base.len() - 1]
    );
    assert!(serde_json::from_str::<ProviderStreamEvent>(&duplicated).is_err());
}

#[test]
fn usage_observation_metadata_faults_latch_and_cannot_yield_evidence() {
    let metadata = observation_fixture_metadata(
        UsageReasoningReportingV1::Reported,
        UsageSnapshotOriginV1::ProviderReported,
    );
    for kind in [
        ProviderEventKind::ResponseStarted {
            upstream_request_id: None,
        },
        ProviderEventKind::TextDelta {
            bytes: b"text".to_vec(),
        },
        ProviderEventKind::ThinkingDelta {
            bytes: b"private".to_vec(),
        },
        ProviderEventKind::ThinkingSignatureDelta {
            bytes: b"signature".to_vec(),
        },
        ProviderEventKind::ToolCallStarted {
            call_index: 0,
            provider_call_id: None,
            name: "tool".into(),
        },
        ProviderEventKind::ToolCallArgumentsDelta {
            call_index: 0,
            bytes: b"{}".to_vec(),
        },
        ProviderEventKind::ToolCallFinished { call_index: 0 },
        ProviderEventKind::Finished {
            finish_reason: Some("stop".into()),
            final_usage: None,
        },
    ] {
        let event = observation_fixture_event(0, kind, Some(metadata));
        let mut accumulator = UsageObservationAccumulatorV1::new();
        assert!(accumulator.observe(&event).is_err());
        assert!(accumulator.provisional().is_invalid());
        assert!(
            accumulator
                .observe(&observation_fixture_event(
                    0,
                    ProviderEventKind::UsageUpdate(ProviderUsage::default()),
                    None
                ))
                .is_err()
        );
        assert!(usage_observation_evidence_v1(&[event]).is_err());
    }
    let contradiction = observation_fixture_event(
        0,
        ProviderEventKind::UsageUpdate(observation_fixture_usage([0, 12, 0, 0, 540])),
        Some(observation_fixture_metadata(
            UsageReasoningReportingV1::NotReported,
            UsageSnapshotOriginV1::ProviderReported,
        )),
    );
    assert!(matches!(
        usage_observation_evidence_v1(&[contradiction]),
        Err(AdapterError::ProviderUsageInvalid(_))
    ));
    let wrong_version = observation_fixture_event(
        0,
        ProviderEventKind::UsageUpdate(ProviderUsage::default()),
        Some(UsageObservationMetaV1 {
            version: 2,
            ..metadata
        }),
    );
    assert!(usage_observation_evidence_v1(&[wrong_version]).is_err());
}

#[test]
fn usage_observation_sequence_faults_and_post_terminal_capture_remain_invalid() {
    let start = observation_fixture_event(
        0,
        ProviderEventKind::ResponseStarted {
            upstream_request_id: None,
        },
        None,
    );
    let finish = observation_fixture_event(
        1,
        ProviderEventKind::Finished {
            finish_reason: Some("stop".into()),
            final_usage: Some(ProviderUsage::default()),
        },
        Some(observation_fixture_metadata(
            UsageReasoningReportingV1::Reported,
            UsageSnapshotOriginV1::ProviderReported,
        )),
    );
    for events in [
        vec![observation_fixture_event(
            1,
            ProviderEventKind::TextDelta { bytes: vec![] },
            None,
        )],
        vec![start.clone(), start.clone()],
        vec![
            start.clone(),
            observation_fixture_event(2, ProviderEventKind::TextDelta { bytes: vec![] }, None),
        ],
        vec![
            start.clone(),
            finish.clone(),
            observation_fixture_event(2, ProviderEventKind::TextDelta { bytes: vec![] }, None),
        ],
    ] {
        assert!(validate_stream(&events).is_err());
        assert!(usage_observation_evidence_v1(&events).is_err());
    }
    let mut accumulator = UsageObservationAccumulatorV1::new();
    accumulator.observe(&start).unwrap();
    accumulator.observe(&finish).unwrap();
    let before = accumulator.provisional();
    assert!(!before.is_invalid());
    assert!(
        accumulator
            .observe(&observation_fixture_event(
                2,
                ProviderEventKind::TextDelta {
                    bytes: b"late".to_vec()
                },
                None
            ))
            .is_err()
    );
    let after = accumulator.provisional();
    assert!(after.is_invalid());
    assert_eq!(after.selected(), before.selected());
    assert_eq!(after.digest(), before.digest());
    assert_eq!(after.raw_stream_sha256(), before.raw_stream_sha256());
}

#[test]
fn usage_observation_legacy_mock_and_fresh_accumulator_stay_qualified() {
    let result = canonical_success_result();
    assert!(result.accounting.usage_observation.is_none());
    assert!(
        result
            .events
            .iter()
            .all(|event| event.usage_observation.is_none())
    );
    let evidence = usage_observation_evidence_v1(&result.events).unwrap();
    assert_eq!(
        evidence.qualification,
        UsageObservationQualificationV1::LegacyTerminalSnapshot
    );
    assert_eq!(
        evidence.selected.unwrap().snapshot_origin,
        UsageObservationOriginV1::LegacyUnknown
    );
    let prefix = observation_fixture_event(
        0,
        ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 20, 0, 0, 0])),
        None,
    );
    let mut attempt_a = UsageObservationAccumulatorV1::new();
    attempt_a.observe(&prefix).unwrap();
    assert!(attempt_a.observe(&prefix).is_err());
    assert!(attempt_a.provisional().is_invalid());
    let mut attempt_b = UsageObservationAccumulatorV1::new();
    for event in &result.events {
        attempt_b.observe(event).unwrap();
    }
    let mut standalone_b = UsageObservationAccumulatorV1::default();
    for event in &result.events {
        standalone_b.observe(event).unwrap();
    }
    assert_eq!(attempt_b.provisional(), standalone_b.provisional());
    assert!(!attempt_b.provisional().is_invalid());
    let provisional = usage_observation_evidence_v1(&[prefix]).unwrap();
    assert_eq!(
        provisional.disposition,
        UsageObservationDispositionV1::NoTerminal
    );
    assert_eq!(
        provisional.qualification,
        UsageObservationQualificationV1::ProvisionalSnapshot
    );
}

#[test]
fn usage_observation_independent_stream_goldens() {
    let cases = [
        (
            "empty_prefix",
            vec![],
            (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "e5ae6c3911b9602dea5d3a3f8e4b305a5cd36490cf29144936b8f8e1a7ab9cac",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            None,
            UsageObservationDispositionV1::NoTerminal,
            UsageObservationQualificationV1::MissingSnapshot,
        ),
        (
            "legacy_positive_text",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 20, 3, 4, 5])),
                    None,
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::TextDelta {
                        bytes: hex::decode("6f6b0a").unwrap(),
                    },
                    None,
                ),
                observation_fixture_event(
                    3,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([10, 20, 3, 4, 5])),
                    },
                    None,
                ),
            ],
            (
                "4a0f534b254c67245f19cb0d63c3119c05ac812c6af692ec053912380aeb5e14",
                "c163a37ae4bd836383ef3a00bb1861913bc53eeca8563f3954d710c068bf08f7",
                "dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 3,
                raw_usage: observation_fixture_usage([10, 20, 3, 4, 5]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::LegacyUnknown,
                snapshot_origin: UsageObservationOriginV1::LegacyUnknown,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::LegacyTerminalSnapshot,
        ),
        (
            "reported_zero",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([0, 0, 0, 0, 0])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "5024c3060c4e5eb4d2005990b09e54cb6fce81631aba527b22ce57ae98bdfc06",
                "5b6043b3ffb7de55346fb4f6893c9d9791d546c5f5cc100c2fc323b7db83fd20",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 2,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "not_reported_zero",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([0, 0, 0, 0, 0])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::NotReported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::NotReported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "5024c3060c4e5eb4d2005990b09e54cb6fce81631aba527b22ce57ae98bdfc06",
                "fb9beb0822437d2360f075a817bc4aaa16c03ad1bbb3ed150ed059f6fa9cc5ee",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 2,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::NotReported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "absent_legacy_zero",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([0, 0, 0, 0, 0])),
                    None,
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    None,
                ),
            ],
            (
                "5024c3060c4e5eb4d2005990b09e54cb6fce81631aba527b22ce57ae98bdfc06",
                "fd096508c517d11544421cca77f7fdda2134a2cb028e86a0b8506b6d9a7035ac",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 2,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::LegacyUnknown,
                snapshot_origin: UsageObservationOriginV1::LegacyUnknown,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::LegacyTerminalSnapshot,
        ),
        (
            "mixed_legacy_reported_not_reported",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 20, 3, 4, 0])),
                    None,
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([12, 25, 4, 5, 0])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    3,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([14, 30, 4, 6, 0])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::NotReported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    4,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([14, 30, 4, 6, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::NotReported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "241745da5dcabb26eec6230dbb9d26b96b833b9fa9f374c8e694a4f350e02e4b",
                "a8219465f8c2538efde763a6908411c2c6bd4a7c1dd07242e3eb74d3c85426be",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 4,
                raw_usage: observation_fixture_usage([14, 30, 4, 6, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::NotReported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "synthetic_cancel_zero",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::NotReported,
                        UsageSnapshotOriginV1::Synthetic,
                    )),
                ),
            ],
            (
                "9c13bd927b6a37b3f5999fce30c91b7b37e9df42841ff17e626cee9cbbaa18a2",
                "1dfcb5ddc306e861f76ccc26bea28fb0834245f09f84536a1ce9189901059aeb",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::NotReported,
                snapshot_origin: UsageObservationOriginV1::Synthetic,
            }),
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::CancelledTerminalSnapshot,
        ),
        (
            "provider_cancel_reported_zero",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "9c13bd927b6a37b3f5999fce30c91b7b37e9df42841ff17e626cee9cbbaa18a2",
                "102b59e1d19eb0b0ce8f99607610717b022ed402ebef69a37325fad36289fd33",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::CancelledTerminalSnapshot,
        ),
        (
            "provider_cancel_reported_positive",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: Some(observation_fixture_usage([10, 20, 3, 4, 5])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "9c13bd927b6a37b3f5999fce30c91b7b37e9df42841ff17e626cee9cbbaa18a2",
                "07d1b3282f32bda7413b3dad47d716394712803a51e0a49a67cd4bc29f034afa",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([10, 20, 3, 4, 5]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::CancelledTerminalSnapshot,
        ),
        (
            "legacy_cancel_positive",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: Some(observation_fixture_usage([10, 20, 3, 4, 5])),
                    },
                    None,
                ),
            ],
            (
                "9c13bd927b6a37b3f5999fce30c91b7b37e9df42841ff17e626cee9cbbaa18a2",
                "11a08cc7eaf8eba36d8aa55ce448bc5324e40afccbe8ffa169e1c3d61434c417",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([10, 20, 3, 4, 5]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::LegacyUnknown,
                snapshot_origin: UsageObservationOriginV1::LegacyUnknown,
            }),
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::CancelledTerminalSnapshot,
        ),
        (
            "cancel_none_after_reported_positive",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 20, 3, 4, 5])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: None,
                    },
                    None,
                ),
            ],
            (
                "5a547da7ad3b2cf9487c13d04750f56bce16934ec637155b940e3c69d9e1a027",
                "a53956ac0eb29be520a48bc9206758a562e8081feed7b3e643f2240bd99b38a0",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([10, 20, 3, 4, 5]),
                source: UsageSource::Incremental,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::ProvisionalSnapshot,
        ),
        (
            "cancel_none_after_reported_zero",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([0, 0, 0, 0, 0])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: None,
                    },
                    None,
                ),
            ],
            (
                "812a32c0e3064abc641913a0f722cc4055fe315f4d475e6a3b0d43fdc91c9c5d",
                "0a2893cbe8be134965039179a405efe725ab26314e012adf11e8a5f2196dd5e9",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Incremental,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::ProvisionalSnapshot,
        ),
        (
            "cancel_none_without_usage",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: None,
                    },
                    None,
                ),
            ],
            (
                "9c13bd927b6a37b3f5999fce30c91b7b37e9df42841ff17e626cee9cbbaa18a2",
                "9aa277e258237392e6e03afa2defa793eb390e88be3af56c70ac0a7ba7b0198c",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            None,
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::MissingSnapshot,
        ),
        (
            "cancel_none_after_legacy",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 20, 3, 4, 5])),
                    None,
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("cancelled".into()),
                        final_usage: None,
                    },
                    None,
                ),
            ],
            (
                "5a547da7ad3b2cf9487c13d04750f56bce16934ec637155b940e3c69d9e1a027",
                "b8db1149b658bcbe6cbe2fcfcb09c25bdb51c64c92ab6242ce8a12db8aaf989a",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([10, 20, 3, 4, 5]),
                source: UsageSource::Incremental,
                reasoning_reporting: UsageReportingPresenceV1::LegacyUnknown,
                snapshot_origin: UsageObservationOriginV1::LegacyUnknown,
            }),
            UsageObservationDispositionV1::Cancelled,
            UsageObservationQualificationV1::ProvisionalSnapshot,
        ),
        (
            "synthetic_noncancel_zero",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::NotReported,
                        UsageSnapshotOriginV1::Synthetic,
                    )),
                ),
            ],
            (
                "8a846198c6871f2b4f2e9a81c72338fccb6923d3f40e79ef2501573907a62abc",
                "4c1f2d2b914218f51bf602c9a4700a687af5771209efa9b4636e7c9987613603",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::NotReported,
                snapshot_origin: UsageObservationOriginV1::Synthetic,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::SyntheticTerminalSnapshot,
        ),
        (
            "stop_none_after_reported_positive",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 20, 3, 4, 5])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: None,
                    },
                    None,
                ),
            ],
            (
                "c457cabe1768d70a0827802fc45b73763243cb54f329b568ffa75f055063675a",
                "c622f6ad7f949afa06c1f1e7f82a27ebe640be2e6e554ee71c7cb075481eca44",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([10, 20, 3, 4, 5]),
                source: UsageSource::Incremental,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProvisionalSnapshot,
        ),
        (
            "reported_positive_prefix",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 20, 3, 4, 5])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "e5f6a7bbc6466362fb453f0a173594cb444166c58e44a1a9e8396b59589fb441",
                "b01b1cac7d93e4566cccb8855321b8f7e8b5048d26883dd44f17399d90ba5326",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([10, 20, 3, 4, 5]),
                source: UsageSource::Incremental,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::NoTerminal,
            UsageObservationQualificationV1::ProvisionalSnapshot,
        ),
        (
            "reasoning_exceeds_output",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 12, 3, 4, 540])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([10, 12, 3, 4, 540])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "a0daef63acf6f2dcfd30bbded5d726a1bd599c87b976e79ee7cbdeb9235eb8f0",
                "456b20fa17f6a308312c5473d7c2825acd73ac6e8f314bd5a98b9b362dc30a4b",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 2,
                raw_usage: observation_fixture_usage([10, 12, 3, 4, 540]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "derived_visible_output_decreases",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::UsageUpdate(observation_fixture_usage([10, 100, 3, 4, 40])),
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([10, 110, 3, 4, 60])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "cb7dfbcd39a9ef878df5fee8f55309198dd5d1b958b8583d686594e813c3ffc6",
                "01743c2b2dbfa6b735c0c52c1108d972662a47e8008c80d9da7d82eea8a00b98",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 2,
                raw_usage: observation_fixture_usage([10, 110, 3, 4, 60]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "terminal_counter_only_mutation",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([7, 9, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::NotReported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "8a846198c6871f2b4f2e9a81c72338fccb6923d3f40e79ef2501573907a62abc",
                "6829a2f7a3e5b9b3dd3824f0e95c17bf2f07e4f10fe553598180df41507d6643",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([7, 9, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::NotReported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "finished_reason_none",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: None,
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    None,
                ),
            ],
            (
                "d8e107bf0766c98b1669f1fe806baf05f513a4781cbfbf140fb5f386101daa3c",
                "86fbdbedbeded0286bb6f8e10f02e004beec9931b038d0bf92d83183edac8a2f",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::LegacyUnknown,
                snapshot_origin: UsageObservationOriginV1::LegacyUnknown,
            }),
            UsageObservationDispositionV1::IncompleteOrOther,
            UsageObservationQualificationV1::LegacyTerminalSnapshot,
        ),
        (
            "finished_reason_empty",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    None,
                ),
            ],
            (
                "d8e107bf0766c98b1669f1fe806baf05f513a4781cbfbf140fb5f386101daa3c",
                "86fbdbedbeded0286bb6f8e10f02e004beec9931b038d0bf92d83183edac8a2f",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 1,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::LegacyUnknown,
                snapshot_origin: UsageObservationOriginV1::LegacyUnknown,
            }),
            UsageObservationDispositionV1::IncompleteOrOther,
            UsageObservationQualificationV1::LegacyTerminalSnapshot,
        ),
        (
            "tool_history_text_stop",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::ToolCallStarted {
                        call_index: 0,
                        provider_call_id: Some("bc".into()),
                        name: "a".into(),
                    },
                    None,
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::ToolCallArgumentsDelta {
                        call_index: 0,
                        bytes: hex::decode("7b7d").unwrap(),
                    },
                    None,
                ),
                observation_fixture_event(
                    3,
                    ProviderEventKind::ToolCallFinished { call_index: 0 },
                    None,
                ),
                observation_fixture_event(
                    4,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "e4f811b2b3eef107394da0ef0b868a5826c8419319b8e79230e0ff5e2f1e55be",
                "d753e685c2bc1bd5dcba1bc52b2a1e3eacc3c0c061e47b267c7bcd4df0f8d85b",
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 4,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "legacy_tool_identity_equivalent",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::ToolCallStarted {
                        call_index: 7,
                        provider_call_id: Some("c".into()),
                        name: "ab".into(),
                    },
                    None,
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::ToolCallArgumentsDelta {
                        call_index: 7,
                        bytes: hex::decode("7b7d").unwrap(),
                    },
                    None,
                ),
                observation_fixture_event(
                    3,
                    ProviderEventKind::ToolCallFinished { call_index: 7 },
                    None,
                ),
                observation_fixture_event(
                    4,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "e4f811b2b3eef107394da0ef0b868a5826c8419319b8e79230e0ff5e2f1e55be",
                "d753e685c2bc1bd5dcba1bc52b2a1e3eacc3c0c061e47b267c7bcd4df0f8d85b",
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 4,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "text_history_tool_reason",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::TextDelta {
                        bytes: hex::decode("74657874206f6e6c79").unwrap(),
                    },
                    None,
                ),
                observation_fixture_event(
                    2,
                    ProviderEventKind::Finished {
                        finish_reason: Some("tool_calls".into()),
                        final_usage: Some(observation_fixture_usage([0, 0, 0, 0, 0])),
                    },
                    Some(observation_fixture_metadata(
                        UsageReasoningReportingV1::Reported,
                        UsageSnapshotOriginV1::ProviderReported,
                    )),
                ),
            ],
            (
                "e6626732bef94dbe4a548f3b4a1905c773472998a58afebf409c69262995adaf",
                "9069417f1457df936bf8dd292dda3cf09173383ff2c61ada8eb20a05e80d4d07",
                "3c8249cff04275cf5a1056321d7cd37b79d97001835a1d01d09cd181d58f639a",
            ),
            Some(UsageObservationSnapshotV1 {
                sequence: 2,
                raw_usage: observation_fixture_usage([0, 0, 0, 0, 0]),
                source: UsageSource::Final,
                reasoning_reporting: UsageReportingPresenceV1::Reported,
                snapshot_origin: UsageObservationOriginV1::ProviderReported,
            }),
            UsageObservationDispositionV1::CompleteTools,
            UsageObservationQualificationV1::ProviderReportedTerminalSnapshot,
        ),
        (
            "response_id_none",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: None,
                    },
                    None,
                ),
            ],
            (
                "8a846198c6871f2b4f2e9a81c72338fccb6923d3f40e79ef2501573907a62abc",
                "891f28ec8eaefcc9d6a7d3362816f894a559c31ee3cd03b02a55cf440539c4ea",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            None,
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::MissingSnapshot,
        ),
        (
            "response_id_empty",
            vec![
                observation_fixture_event(
                    0,
                    ProviderEventKind::ResponseStarted {
                        upstream_request_id: Some("".into()),
                    },
                    None,
                ),
                observation_fixture_event(
                    1,
                    ProviderEventKind::Finished {
                        finish_reason: Some("stop".into()),
                        final_usage: None,
                    },
                    None,
                ),
            ],
            (
                "8a846198c6871f2b4f2e9a81c72338fccb6923d3f40e79ef2501573907a62abc",
                "891f28ec8eaefcc9d6a7d3362816f894a559c31ee3cd03b02a55cf440539c4ea",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            None,
            UsageObservationDispositionV1::CompleteText,
            UsageObservationQualificationV1::MissingSnapshot,
        ),
    ];
    for (
        name,
        events,
        (raw_hash, observation_hash, output_hash),
        selected,
        disposition,
        qualification,
    ) in cases
    {
        let (_, raw) = validate_stream(&events).unwrap();
        let evidence = usage_observation_evidence_v1(&events).unwrap();
        assert_eq!(raw.as_str(), raw_hash, "{name}");
        assert_eq!(
            canonical_output_sha256(&events).as_str(),
            output_hash,
            "{name}"
        );
        assert_eq!(evidence.digest.as_str(), observation_hash, "{name}");
        assert_eq!(evidence.encoding_version, 1, "{name}");
        assert_eq!(evidence.selected, selected, "{name}");
        assert_eq!(evidence.disposition, disposition, "{name}");
        assert_eq!(evidence.qualification, qualification, "{name}");
    }
}

#[test]
fn usage_observation_total_reason_mapping_has_fixed_hashes() {
    let cases = [
        (
            None,
            UsageObservationDispositionV1::IncompleteOrOther,
            "d8e107bf0766c98b1669f1fe806baf05f513a4781cbfbf140fb5f386101daa3c",
            "add3cc166bbec2766a0814e26f710ede50fe5bab766a7f5e89bdc608a24d08bc",
        ),
        (
            Some("".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "d8e107bf0766c98b1669f1fe806baf05f513a4781cbfbf140fb5f386101daa3c",
            "add3cc166bbec2766a0814e26f710ede50fe5bab766a7f5e89bdc608a24d08bc",
        ),
        (
            Some("stop".into()),
            UsageObservationDispositionV1::CompleteText,
            "8a846198c6871f2b4f2e9a81c72338fccb6923d3f40e79ef2501573907a62abc",
            "891f28ec8eaefcc9d6a7d3362816f894a559c31ee3cd03b02a55cf440539c4ea",
        ),
        (
            Some("end_turn".into()),
            UsageObservationDispositionV1::CompleteText,
            "d1fcce47a322ce0fd127cd49fb2dd437546b35a39041cee3579e1fca4854ed4e",
            "99b7e244a993153d2b6d4b5e78de5283122ab1c3979c7ccd90cd52c878fd4c28",
        ),
        (
            Some("stop_sequence".into()),
            UsageObservationDispositionV1::CompleteText,
            "92eeb252bc3f4bc512360ba216455982846d7ba3d27ac084e3e4b6ff273e21fc",
            "a390d8d1c68c0cb5fd37d53ad8cb11342ba03cc394f20f164df276aa901bf89d",
        ),
        (
            Some("tool_calls".into()),
            UsageObservationDispositionV1::CompleteTools,
            "b24fd38b343da0f20784b3a0ba01b5ec171eaa0ebb5e6f4712e090ffc64b0774",
            "9cbce1982e7d6c9dba757a95c57b8bcf4664e41a6f1e98013e26466ea7fdfaaa",
        ),
        (
            Some("tool_use".into()),
            UsageObservationDispositionV1::CompleteTools,
            "6d9e6ce396318a4c87f065a41547741474af284e93f45235ef76b884a1f88e67",
            "bd4469b33f396734b5e3e501134f9b8e95587d9c40f15e8fb2122433d465e82f",
        ),
        (
            Some("cancelled".into()),
            UsageObservationDispositionV1::Cancelled,
            "9c13bd927b6a37b3f5999fce30c91b7b37e9df42841ff17e626cee9cbbaa18a2",
            "9aa277e258237392e6e03afa2defa793eb390e88be3af56c70ac0a7ba7b0198c",
        ),
        (
            Some("length".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "f4e89307ded4efb9f009808753b6edfbd6dcd3f21ffac9070bb96bfebe4c2382",
            "1827f711154da0ffdce5c6dbe6b8de443d15f288d5368226bfc530834dae8796",
        ),
        (
            Some("max_tokens".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "7872c89f8cc6b4733e3160090890ff54c088905ed9d709253f5acc93634fe9e6",
            "c72d9e952b28d6ae2b3f86cb50ce55271a08ab8acd5cae3e8658c73317dfaa10",
        ),
        (
            Some("content_filter".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "9c21b4bfca75448ac50fc8d69600374242ef74663a066e2026cda69b2119c421",
            "ae8c55cf47c6efc9a0a50b0f742a14b199dbbe3732b81632978d19f7f820112b",
        ),
        (
            Some("pause_turn".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "1ecbe134b1809da8921f61c1de39f9bd6f2f7112a255b7c50c68a1bc960eb164",
            "93e508595b688d8a8817d16baaeab9a8542324a49059257ebba4826311089b20",
        ),
        (
            Some("done".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "3ca4286077dd4d3258ffbea392c1eff3958c100bfc4c1063c02d28e3bab018d2",
            "719b632f4cf1fe582eb789a53af275ff4dd3733daf537b8cc14ae0549ae753a9",
        ),
        (
            Some("future_reason".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "fc3b7384a49fe0876e8b1c5b594425c15286c861b44b70782a21002eabe57f78",
            "5611669dfe49c3d0311326356c0e8ab3b25e735e37b35e93167b7f5dc7763a2c",
        ),
        (
            Some("STOP".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "4b1b3b86e6d2511c91b0840fc35952056118bec396087a3eaf0b9861b7da37b2",
            "2a0f827051b048e7248cde9c65f5b20b275a309b2e911aa16dd4778073e9abd6",
        ),
        (
            Some("Stop".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "3a6449f0b092d5b780c950927e47904ddf0c3a9c55cd23c54b4967dd15f6aab6",
            "80a7eb94cd2e062a1d00dec59cad3f57151912362afb40b4963d5d2a01f566e4",
        ),
        (
            Some("stop ".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "899f53acdabe5b7f5be266e4251602fa558b2cbb85aca9157af5e3f1f212ce0c",
            "686d2c464131fe05dca6e13d48797cb664cd705e63433383a29d4db29d7c51de",
        ),
        (
            Some(" stop".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "e9c7d4cf39f22be37a9c7682cf942a7ee17228c7d1907e3549b727e3b0194b80",
            "a7f8a289bc359799b03c8c4b16b09623bb0b4d84b0f68d4ec5ff88f6fd46482c",
        ),
        (
            Some("stop\n".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "17b77a4edd7a0752e7d56f01302c307932ad22702cb7706e3bbca9d9c404dca0",
            "e4b57bfac9aba80fdc98920571afe055e595dfac200e733318923116e968e7a4",
        ),
        (
            Some("TOOL_CALLS".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "77c360990f0e43e8399b581718808f1b68bc42e9291ebf118567f204d54593ef",
            "37b21177b6076d5910514f34d4b8b7856c43b3745500912ad330e58f3f22528d",
        ),
        (
            Some("tool_calls ".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "bade9f9e4fe283869b80dc2318cc405255d8b47d25214fccbe3be4e5a6cc713d",
            "4a49b507e3ee42e7be7bb0975512c6e63b727712853e90c08fa0b98a1e773fad",
        ),
        (
            Some("Cancelled".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "02ebe94fb9fddddecc5308f7ce3e0a3bafe0e7cf355562cd559bdfa820902cca",
            "fbff3ae63f3025c508753a4c5d6acb96a0d7abc6921344b0f91a1aa56896b20a",
        ),
        (
            Some("cancelled ".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "ceda8ca434313c1e34f30ca5481de6ab3b954b993819e5a0c914f5e644d3a806",
            "fc7c7a08db596200e7da1be75e65b54d8b010c392089a023ae4b9d2dd3bd2c14",
        ),
        (
            Some("\tcancelled".into()),
            UsageObservationDispositionV1::IncompleteOrOther,
            "e0967b7f5b5d269ab18116f802db14a3a8f2a31470b3d7b8cf92114f85df86aa",
            "a50caf1ffde838fdc386db5c6b1a3453036dc964032375fbe1d514d92ff1cf61",
        ),
    ];
    for (reason, expected, raw_hash, observation_hash) in cases {
        let events = [
            observation_fixture_event(
                0,
                ProviderEventKind::ResponseStarted {
                    upstream_request_id: None,
                },
                None,
            ),
            observation_fixture_event(
                1,
                ProviderEventKind::Finished {
                    finish_reason: reason,
                    final_usage: None,
                },
                None,
            ),
        ];
        assert_eq!(validate_stream(&events).unwrap().1.as_str(), raw_hash);
        let evidence = usage_observation_evidence_v1(&events).unwrap();
        assert_eq!(evidence.disposition, expected);
        assert_eq!(evidence.digest.as_str(), observation_hash);
        assert_eq!(
            evidence.qualification,
            UsageObservationQualificationV1::MissingSnapshot
        );
    }
}

use futures::StreamExt;
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::*;
use orbit_provider_http::{AsyncProviderAdapter, CancelToken};

fn adapters() -> Vec<Box<dyn AsyncProviderAdapter>> {
    vec![
        Box::new(
            orbit_provider_http::OpenAiCompatibleHttpV1::new(
                orbit_provider_http::openai::openai_identity(),
                orbit_provider_http::openai::openai_capabilities(),
                TlsPinPolicy {
                    webpki: false,
                    spki_sha256: None,
                },
            )
            .unwrap(),
        ),
        Box::new(
            orbit_provider_http::AnthropicMessagesV1::new(
                orbit_provider_http::anthropic::anthropic_identity(),
                orbit_provider_http::anthropic::anthropic_capabilities(),
            )
            .unwrap(),
        ),
        Box::new(
            orbit_provider_http::OllamaHttpV1::new(
                AdapterIdentity {
                    kind: AdapterKind::LocalProcessV1,
                    implementation_digest: Sha256Digest("i".repeat(64)),
                    profile_digest: Sha256Digest("p".repeat(64)),
                },
                orbit_provider_http::openai::openai_capabilities(),
            )
            .unwrap(),
        ),
    ]
}

fn request(adapter: &dyn AsyncProviderAdapter, port: u16) -> ProviderRequest {
    let identity = adapter.identity();
    canonical_request(
        &ProviderRouteBinding {
            provider_id: ProviderId("fixture".into()),
            deployment_id: DeploymentId("fixture".into()),
            region_id: RegionId("local".into()),
            adapter_kind: identity.kind,
            adapter_implementation_digest: identity.implementation_digest,
            adapter_profile_digest: identity.profile_digest,
            endpoint_digest: Sha256Digest("e".repeat(64)),
            expected_model: "fixture-model".into(),
            pricing_digest: Sha256Digest("r".repeat(64)),
            endpoint_host: "127.0.0.1".into(),
            endpoint_port: port,
            endpoint_scheme: EndpointScheme::HttpLoopback,
            endpoint_path: if identity.kind == AdapterKind::LocalProcessV1 {
                "/api".into()
            } else {
                String::new()
            },
            endpoint_query: None,
        },
        b"hello",
    )
}

async fn send(adapter: &dyn AsyncProviderAdapter, request: &ProviderRequest) {
    let mut stream = adapter
        .invoke(request, None, &CancelToken::new())
        .await
        .unwrap();
    while let Some(event) = stream.next().await {
        event.unwrap();
    }
}

#[tokio::test]
async fn exact_effort_fields_and_omission_preserve_existing_controls() {
    let (addr, state, handle) = orbit_mock_provider::spawn().await.unwrap();
    for adapter in adapters() {
        let mut req = request(adapter.as_ref(), addr.port());
        send(adapter.as_ref(), &req).await;
        let omitted = state.last_body.lock().unwrap().clone().unwrap();
        assert!(omitted.get("reasoning_effort").is_none());
        assert!(omitted.get("output_config").is_none());
        assert!(omitted.get("think").is_none());

        let values = if adapter.identity().kind == AdapterKind::LocalProcessV1 {
            vec![
                EffortValue::Bool(false),
                EffortValue::Bool(true),
                EffortValue::Level("high".into()),
            ]
        } else {
            vec![
                EffortValue::Level("high".into()),
                EffortValue::Level("xhigh".into()),
            ]
        };
        for value in values {
            req.effort = Some(value.clone());
            send(adapter.as_ref(), &req).await;
            let mut selected = state.last_body.lock().unwrap().clone().unwrap();
            match adapter.identity().kind {
                AdapterKind::OpenAiCompatibleHttpV1 => {
                    assert_eq!(selected["reasoning_effort"], serde_json::json!(value));
                    selected.as_object_mut().unwrap().remove("reasoning_effort");
                }
                AdapterKind::DeclarativeHttpJsonV1 => {
                    assert_eq!(
                        selected["output_config"],
                        serde_json::json!({"effort": value})
                    );
                    assert_eq!(selected["thinking"], serde_json::json!({"type":"adaptive"}));
                    selected.as_object_mut().unwrap().remove("output_config");
                }
                AdapterKind::LocalProcessV1 => {
                    assert_eq!(selected["think"], serde_json::json!(value));
                    selected.as_object_mut().unwrap().remove("think");
                }
                _ => unreachable!(),
            }
            assert_eq!(
                selected, omitted,
                "effort leaves all existing controls intact"
            );
        }
    }
    handle.abort();
}

#[tokio::test]
async fn invalid_wire_effort_is_rejected_before_http() {
    let (addr, state, handle) = orbit_mock_provider::spawn().await.unwrap();
    for adapter in adapters() {
        let mut values = vec![
            EffortValue::Level("default".into()),
            EffortValue::Level(" high".into()),
        ];
        if adapter.identity().kind != AdapterKind::LocalProcessV1 {
            values.push(EffortValue::Bool(false));
        }
        if adapter.identity().kind == AdapterKind::DeclarativeHttpJsonV1 {
            values.push(EffortValue::Level("off".into()));
        }
        let mut req = request(adapter.as_ref(), addr.port());
        for invalid in values {
            req.effort = Some(invalid);
            let error = match adapter.invoke(&req, None, &CancelToken::new()).await {
                Ok(_) => panic!("invalid effort reached HTTP"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                AdapterError::ProviderConfigurationInvalid(_)
            ));
        }
    }
    assert_eq!(state.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    handle.abort();
}

//! Live homelab conformance — drives the REAL async adapter against the
//! mock provider deployed on the operator's homelab over the network.
//!
//! Hermetic by default: this test only runs when `ORBIT_HOMELAB_URL` is set
//! (e.g. `http://<homelab-host>:8088`). CI and default runs skip it.

use futures::StreamExt;
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::types::{AdapterKind, ProviderEventKind, ProviderRouteBinding, Sha256Digest};
use orbit_provider_http::openai::{openai_capabilities, openai_identity};
use orbit_provider_http::{AsyncProviderAdapter, CancelToken, OpenAiCompatibleHttpV1};

fn route_for(host: &str, port: u16) -> ProviderRouteBinding {
    ProviderRouteBinding {
        provider_id: orbit_adapter::types::ProviderId("homelab-mock".into()),
        deployment_id: orbit_adapter::types::DeploymentId("mock-deploy".into()),
        region_id: orbit_adapter::types::RegionId("mock-region".into()),
        adapter_kind: AdapterKind::OpenAiCompatibleHttpV1,
        adapter_implementation_digest: Sha256Digest("i".repeat(64)),
        adapter_profile_digest: Sha256Digest("p".repeat(64)),
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: "mock-model".into(),
        pricing_digest: Sha256Digest("r".repeat(64)),
        endpoint_host: host.into(),
        endpoint_port: port,
        endpoint_scheme: orbit_adapter::types::EndpointScheme::HttpLoopback,
    }
}

#[tokio::test]
async fn live_homelab_openai_streams() {
    let url = match std::env::var("ORBIT_HOMELAB_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("ORBIT_HOMELAB_URL not set — skipping live homelab test");
            return;
        }
    };
    // Parse host:port from the URL (http://host:port).
    let rest = url.trim_start_matches("http://");
    let mut parts = rest.splitn(2, ':');
    let host = parts.next().expect("host");
    let port: u16 = parts.next().and_then(|p| p.parse().ok()).expect("port");

    let adapter = OpenAiCompatibleHttpV1::new(
        openai_identity(),
        openai_capabilities(),
        orbit_adapter::types::TlsPinPolicy {
            webpki: false,
            spki_sha256: None,
        },
    )
    .expect("adapter build");

    let route = route_for(host, port);
    let request = canonical_request(&route, b"live");
    let cancel = CancelToken::new();
    let mut stream = adapter
        .invoke(&request, None, &cancel)
        .await
        .expect("invoke");

    let mut events = Vec::new();
    while let Some(item) = stream.next().await {
        events.push(item.expect("stream item"));
    }
    let text: String = events
        .iter()
        .filter_map(|e| match &e.event {
            ProviderEventKind::TextDelta { bytes } => {
                Some(String::from_utf8_lossy(bytes).into_owned())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        text, "hello world",
        "live homelab stream must yield provider text"
    );
    let finished = events
        .iter()
        .filter(|e| matches!(e.event, ProviderEventKind::Finished { .. }))
        .count();
    assert_eq!(finished, 1, "exactly one terminal");
    println!("LIVE HOMELAB CONFORMANCE PASS: streamed {text:?} from {host}:{port}");
}

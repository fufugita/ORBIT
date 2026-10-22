use futures::StreamExt;
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    DeploymentId, EndpointScheme, ProviderEventKind, ProviderId, ProviderRequest,
    ProviderRouteBinding, ProviderStreamEvent, ProviderUsage, RegionId, Sha256Digest, TlsPinPolicy,
};
use orbit_provider_http::{
    AnthropicMessagesV1, AsyncProviderAdapter, CancelToken, OpenAiCompatibleHttpV1,
    anthropic::{anthropic_capabilities, anthropic_identity},
    openai::{openai_capabilities, openai_identity},
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy)]
enum Family {
    Anthropic,
    OpenAi,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    fn response(self) -> &'static str {
        match self {
            Self::Anthropic => concat!(
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"owned-tls\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":11}}}\n\n",
                "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"trusted\"}}\n\n",
                "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
                "data: {\"type\":\"message_stop\"}\n\n"
            ),
            Self::OpenAi => concat!(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"trusted\"},\"finish_reason\":null}]}\n\n",
                "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n",
                "data: [DONE]\n\n"
            ),
        }
    }
}

#[derive(Clone, Copy)]
enum Case {
    Trusted,
    UnrelatedCa,
    WrongHost,
    MatchingPin,
    WrongPin,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::UnrelatedCa => "unrelated-ca",
            Self::WrongHost => "wrong-host",
            Self::MatchingPin => "matching-pin",
            Self::WrongPin => "wrong-pin",
        }
    }

    fn succeeds(self) -> bool {
        matches!(self, Self::Trusted | Self::MatchingPin)
    }
}

struct PrivateHome(PathBuf);

impl PrivateHome {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "orbit-tls-trust-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_dir(&path);
        Self(path)
    }
}

impl Drop for PrivateHome {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove owned TLS fixture home");
    }
}

fn private_dir(path: &Path) {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).unwrap();
}

fn private_file(path: &Path) -> std::fs::File {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap()
}

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            child.wait().expect("reap owned TLS child");
        }
    }
}

struct ServerTask(Option<tokio::task::JoinHandle<(usize, usize)>>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

fn ca() -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    (params.self_signed(&key).unwrap(), key)
}

async fn trust_case(family: Family, case: Case) {
    orbit_provider_http::tls::ensure_crypto_provider();
    let home = PrivateHome::new();
    let roots_dir = home.0.join("empty-roots");
    private_dir(&roots_dir);
    let (issuer, issuer_key) = ca();
    let unrelated = if matches!(case, Case::UnrelatedCa) {
        Some(ca().0)
    } else {
        None
    };
    let root = unrelated.as_ref().unwrap_or(&issuer);
    let roots_file = home.0.join("roots.pem");
    private_file(&roots_file)
        .write_all(root.pem().as_bytes())
        .unwrap();
    let host = if matches!(case, Case::WrongHost) {
        "unrelated.invalid"
    } else {
        "127.0.0.1"
    };
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![host.to_owned()])
        .unwrap()
        .signed_by(&key, &issuer, &issuer_key)
        .unwrap();
    let pin = match case {
        Case::MatchingPin => orbit_provider_http::tls::spki_sha256_of(leaf.der()).unwrap(),
        Case::WrongPin => "0".repeat(64),
        _ => String::new(),
    };
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), issuer.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let mut server = ServerTask(Some(tokio::spawn(async move {
        let mut connections = 0;
        let mut posts = 0;
        loop {
            let socket = tokio::select! {
                _ = &mut stopped => break,
                accepted = listener.accept() => accepted.unwrap().0,
            };
            connections += 1;
            assert!(connections <= 2, "bounded fixture connections");
            let tls = tokio::time::timeout(Duration::from_secs(2), acceptor.accept(socket))
                .await
                .expect("TLS handshake deadline");
            let Ok(mut tls) = tls else {
                continue;
            };
            let mut raw = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 2048];
                let count = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut chunk))
                    .await
                    .expect("HTTP header deadline")
                    .expect("read HTTP headers");
                assert!(count > 0, "complete request headers");
                raw.extend_from_slice(&chunk[..count]);
                assert!(raw.len() <= 64 * 1024, "bounded request capture");
                if let Some(end) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = std::str::from_utf8(&raw[..header_end]).unwrap();
            let target = match family {
                Family::Anthropic => "POST /v1/messages HTTP/1.1",
                Family::OpenAi => "POST /v1/chat/completions HTTP/1.1",
            };
            assert_eq!(headers.lines().next(), Some(target));
            posts += 1;
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .expect("request content length");
            assert!(length <= 64 * 1024 - header_end, "bounded request body");
            while raw.len() < header_end + length {
                let mut chunk = [0u8; 2048];
                let count = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut chunk))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(count > 0);
                raw.extend_from_slice(&chunk[..count]);
                assert!(raw.len() <= 64 * 1024);
            }
            let body: serde_json::Value =
                serde_json::from_slice(&raw[header_end..header_end + length]).unwrap();
            assert_eq!(body["model"], "tls-fixture-model");
            let body = family.response();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tokio::time::timeout(Duration::from_secs(2), tls.write_all(response.as_bytes()))
                .await
                .unwrap()
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(1), tls.shutdown()).await;
        }
        (connections, posts)
    })));
    // A fresh executable gets only this fixture's CA policy. No process-wide
    // environment mutation or cached client can borrow another case's roots.
    let log = home.0.join("child.log");
    let output = private_file(&log);
    let mut child = OwnedChild(Some(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tls_trust_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("HOME", &home.0)
            .env("TMPDIR", &home.0)
            .env("XDG_CONFIG_HOME", &home.0)
            .env("XDG_CACHE_HOME", &home.0)
            .env("XDG_DATA_HOME", &home.0)
            .env("SSL_CERT_FILE", &roots_file)
            .env("SSL_CERT_DIR", &roots_dir)
            .env("ORBIT_TLS_FAMILY", family.name())
            .env("ORBIT_TLS_CASE", case.name())
            .env("ORBIT_TLS_PORT", port.to_string())
            .env("ORBIT_TLS_PIN", pin)
            .env(
                "ORBIT_TLS_ROOT_SHA256",
                hex::encode(Sha256::digest(root.der())),
            )
            .current_dir(&home.0)
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "TLS child watchdog");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let _ = stop.send(());
    let counts = tokio::time::timeout(Duration::from_secs(3), server.0.as_mut().unwrap())
        .await
        .expect("owned server cleanup deadline")
        .expect("owned server task");
    let _ = server.0.take();
    let mut output = String::new();
    std::fs::File::open(log)
        .unwrap()
        .take(32 * 1024 + 1)
        .read_to_string(&mut output)
        .unwrap();
    assert!(output.len() <= 32 * 1024, "bounded child log");
    assert!(status.success(), "TLS child failed: {output}");
    assert!(
        output.contains(&format!(
            "ORBIT_TLS_TRUST_CHILD_OK {} {}",
            family.name(),
            case.name()
        )),
        "child must execute assertions: {output}"
    );
    assert_eq!(
        counts,
        (1, usize::from(case.succeeds())),
        "exact connection/POST count; no retry"
    );
}

fn request(adapter: &dyn AsyncProviderAdapter, port: u16) -> ProviderRequest {
    let identity = adapter.identity();
    let route = ProviderRouteBinding {
        provider_id: ProviderId("tls-fixture".into()),
        deployment_id: DeploymentId("tls-fixture".into()),
        region_id: RegionId("tls-fixture".into()),
        adapter_kind: identity.kind,
        adapter_implementation_digest: identity.implementation_digest,
        adapter_profile_digest: identity.profile_digest,
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: "tls-fixture-model".into(),
        pricing_digest: Sha256Digest("p".repeat(64)),
        endpoint_host: "127.0.0.1".into(),
        endpoint_port: port,
        endpoint_scheme: EndpointScheme::Https,
        endpoint_path: String::new(),
        endpoint_query: None,
    };
    let mut request = canonical_request(&route, b"owned TLS fixture");
    request.connect_timeout_ms = 1500;
    request.first_byte_timeout_ms = 3000;
    request.idle_timeout_ms = 1000;
    request
}

async fn collect(
    adapter: &dyn AsyncProviderAdapter,
    port: u16,
) -> Result<Vec<ProviderStreamEvent>, AdapterError> {
    let credential = SecretBytes::new(b"synthetic-tls-fixture-key".to_vec());
    let cancel = CancelToken::new();
    let mut stream = adapter
        .invoke(&request(adapter, port), Some(&credential), &cancel)
        .await?;
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event?);
    }
    orbit_adapter::stream::validate_stream(&events)?;
    Ok(events)
}

#[test]
#[ignore = "fresh-process helper; invoked by the TLS trust cases"]
fn tls_trust_child() {
    let family = std::env::var("ORBIT_TLS_FAMILY").expect("owned TLS child family");
    let case = std::env::var("ORBIT_TLS_CASE").expect("owned TLS child case");
    assert!(matches!(family.as_str(), "anthropic" | "openai"));
    assert!(matches!(
        case.as_str(),
        "trusted" | "unrelated-ca" | "wrong-host" | "matching-pin" | "wrong-pin"
    ));
    let port: u16 = std::env::var("ORBIT_TLS_PORT").unwrap().parse().unwrap();
    let native = rustls_native_certs::load_native_certs();
    assert!(native.errors.is_empty(), "isolated roots must load");
    assert_eq!(
        native.certs.len(),
        1,
        "no operator roots may enter the fixture"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&native.certs[0])),
        std::env::var("ORBIT_TLS_ROOT_SHA256").unwrap()
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let adapter: Box<dyn AsyncProviderAdapter> = match family.as_str() {
            "anthropic" => Box::new(
                AnthropicMessagesV1::new(anthropic_identity(), anthropic_capabilities()).unwrap(),
            ),
            "openai" => {
                let pin = std::env::var("ORBIT_TLS_PIN").unwrap();
                let policy = TlsPinPolicy {
                    webpki: true,
                    spki_sha256: (!pin.is_empty()).then_some(pin),
                };
                let adapter =
                    OpenAiCompatibleHttpV1::new(openai_identity(), openai_capabilities(), policy)
                        .unwrap();
                assert_eq!(
                    adapter.spki_pin_armed(),
                    matches!(case.as_str(), "matching-pin" | "wrong-pin")
                );
                Box::new(adapter)
            }
            _ => unreachable!(),
        };
        tokio::time::timeout(Duration::from_secs(6), collect(adapter.as_ref(), port))
            .await
            .expect("provider call deadline")
    });
    if matches!(case.as_str(), "trusted" | "matching-pin") {
        let events = result.expect("trusted native-root HTTPS must complete");
        let text: Vec<u8> = events
            .iter()
            .flat_map(|event| match &event.event {
                ProviderEventKind::TextDelta { bytes } => bytes.as_slice(),
                _ => &[],
            })
            .copied()
            .collect();
        assert_eq!(text, b"trusted");
        let usage = events
            .iter()
            .find_map(|event| match event.event {
                ProviderEventKind::Finished { final_usage, .. } => final_usage,
                _ => None,
            })
            .expect("complete known final usage");
        assert_eq!(
            usage,
            ProviderUsage {
                input_tokens: 11,
                output_tokens: 7,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0
            }
        );
    } else {
        assert_eq!(
            result.expect_err("untrusted HTTPS must fail closed").code(),
            "E0410"
        );
    }
    println!("ORBIT_TLS_TRUST_CHILD_OK {family} {case}");
}

#[tokio::test]
async fn anthropic_trusts_owned_native_ca() {
    trust_case(Family::Anthropic, Case::Trusted).await;
}

#[tokio::test]
async fn openai_trusts_owned_native_ca() {
    trust_case(Family::OpenAi, Case::Trusted).await;
}

#[tokio::test]
async fn anthropic_rejects_unrelated_ca_before_post() {
    trust_case(Family::Anthropic, Case::UnrelatedCa).await;
}

#[tokio::test]
async fn openai_rejects_unrelated_ca_before_post() {
    trust_case(Family::OpenAi, Case::UnrelatedCa).await;
}

#[tokio::test]
async fn anthropic_rejects_wrong_host_before_post() {
    trust_case(Family::Anthropic, Case::WrongHost).await;
}

#[tokio::test]
async fn openai_rejects_wrong_host_before_post() {
    trust_case(Family::OpenAi, Case::WrongHost).await;
}

#[tokio::test]
async fn openai_accepts_matching_spki_pin() {
    trust_case(Family::OpenAi, Case::MatchingPin).await;
}

#[tokio::test]
async fn openai_rejects_wrong_spki_pin_before_post() {
    trust_case(Family::OpenAi, Case::WrongPin).await;
}

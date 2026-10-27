use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{ProviderAuthIdentity, ProviderCredentialSource};
use orbit_cli::config::{ModelEntry, ProviderConfig};
use orbit_cli::provider_discovery::*;
use orbit_provider_http::CancelToken;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// The listener is numeric loopback, nonblocking, finitely lived, and joined on drop.
struct Fixture {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(responses: Vec<String>) -> Self {
        let mut responses: VecDeque<_> = responses.into();
        Self::with_handler(move |_| responses.pop_front().unwrap_or_else(|| http(500, "{}")))
    }

    fn with_handler(mut handler: impl FnMut(&str) -> String + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_millis(500)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let mut buffer = [0_u8; 4096];
                        while bytes.len() < 32768 && !bytes.ends_with(b"\r\n\r\n") {
                            match stream.read(&mut buffer) {
                                Ok(0) | Err(_) => break,
                                Ok(length) => bytes.extend_from_slice(&buffer[..length]),
                            }
                        }
                        if bytes.is_empty() {
                            continue;
                        }
                        let request = String::from_utf8(bytes).unwrap();
                        captured.lock().unwrap().push(request.clone());
                        let response = handler(&request);
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            requests,
            stop,
            join: Some(join),
        }
    }

    fn provider(&self, kind: &str) -> ProviderConfig {
        ProviderConfig {
            name: "fixture".into(),
            kind: kind.into(),
            url: format!("http://{}/tenant/v1?scope=synthetic", self.addr),
            env: None,
            models: vec![],
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}

fn http(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn model(id: &str) -> ModelEntry {
    ModelEntry {
        context_limits: None,
        id: id.into(),
        label: None,
        pricing: None,
        billing: None,
        max_output_tokens: None,
        context_window: None,
        sampling: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
        default_effort: None,
    }
}

fn session(provider: &ProviderConfig, profile: DiscoveryProfile) -> DiscoverySession {
    DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        provider,
        profile,
        None,
        CancelToken::new(),
        |_| Ok(None),
    )
    .unwrap()
}

#[tokio::test]
async fn selected_raw_slash_id_and_exact_base_query() {
    let fixture = Fixture::new(vec![http(200, r#"{"data":[{"id":"vendor/model:free"}]}"#)]);
    let session = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    );
    let catalog = session.catalog().await;
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
    assert_eq!(catalog.models[0].id, "vendor/model:free");
    assert_eq!(catalog.models[0].context_window, None);
    assert!(fixture.requests()[0].starts_with("GET /tenant/v1/models?scope=synthetic HTTP/1.1"));
}

#[tokio::test]
async fn candidate_env_overrides_draft() {
    let fixture = Fixture::new(vec![http(200, r#"{"data":[{"id":"fixture-model"}]}"#)]);
    let mut provider = fixture.provider("openai-compatible");
    provider.env = Some("ORBIT_AUTH_CANDIDATE".into());
    let identity = ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        &provider.url,
        provider.env.as_deref(),
    )
    .unwrap();
    let draft = SecretBytes::new(b"synthetic-draft".to_vec());
    let session = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        &provider,
        DiscoveryProfile::GenericOpenAi,
        Some((&identity, &draft)),
        CancelToken::new(),
        |name| {
            assert_eq!(name, "ORBIT_AUTH_CANDIDATE");
            Ok(Some(SecretBytes::new(b"synthetic-env".to_vec())))
        },
    )
    .unwrap();
    assert_eq!(
        session.credential_source(),
        ProviderCredentialSource::Environment
    );
    assert_eq!(
        session.catalog().await.completeness,
        DiscoveryCompleteness::Complete
    );
    let request = fixture.requests()[0].to_lowercase();
    assert!(request.contains("authorization: bearer synthetic-env\r\n"));
    assert!(!request.contains("synthetic-draft"));
}

#[tokio::test]
async fn private_candidate_ignores_old_env() {
    let fixture = Fixture::new(vec![http(200, r#"{"data":[{"id":"fixture-model"}]}"#)]);
    let mut provider = fixture.provider("openai-compatible");
    provider.env = Some("ORBIT_AUTH_FRESH".into());
    let identity = ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        &provider.url,
        provider.env.as_deref(),
    )
    .unwrap();
    let draft = SecretBytes::new(b"synthetic-fresh".to_vec());
    let session = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        &provider,
        DiscoveryProfile::GenericOpenAi,
        Some((&identity, &draft)),
        CancelToken::new(),
        |name| {
            assert_eq!(name, "ORBIT_AUTH_FRESH");
            Ok(None)
        },
    )
    .unwrap();
    assert_eq!(session.credential_source(), ProviderCredentialSource::Draft);
    assert_eq!(
        session.catalog().await.completeness,
        DiscoveryCompleteness::Complete
    );
    assert!(
        fixture.requests()[0]
            .to_lowercase()
            .contains("authorization: bearer synthetic-fresh\r\n")
    );
}

fn observed(
    id: &str,
    source: MetadataSource,
    context: Option<u64>,
    output: Option<u32>,
) -> DiscoveredModel {
    DiscoveredModel {
        id: id.into(),
        label: None,
        context_window: context,
        max_output_tokens: output,
        source,
        metadata_valid: true,
        unrecognized_fields: vec![],
        evidence: None,
    }
}

fn has_issue(issues: &[DiscoveryIssue], kind: DiscoveryIssueKind) -> bool {
    issues.iter().any(|issue| issue.kind == kind)
}

fn identity() -> ProviderAuthIdentity {
    ProviderAuthIdentity::new(
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:1/v1",
        None,
    )
    .unwrap()
}

#[test]
fn manual_construction_sends_zero_requests() {
    let fixture = Fixture::new(vec![]);
    let _session = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    );
    assert!(fixture.requests().is_empty());
}

#[test]
fn explicit_no_auth_never_reads_ambient_env() {
    let fixture = Fixture::new(vec![]);
    let provider = fixture.provider("openai-compatible");
    let session = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        &provider,
        DiscoveryProfile::GenericOpenAi,
        None,
        CancelToken::new(),
        |_| panic!("an unauthenticated candidate has no ENV reference"),
    )
    .unwrap();
    assert_eq!(session.credential_source(), ProviderCredentialSource::None);
    assert!(fixture.requests().is_empty());
}

#[test]
fn declared_missing_auth_fails_before_io() {
    let fixture = Fixture::new(vec![]);
    let mut provider = fixture.provider("openai-compatible");
    provider.env = Some("ORBIT_SYNTHETIC_UNAVAILABLE".into());
    let result = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-nonexistent-missing"),
        &provider,
        DiscoveryProfile::GenericOpenAi,
        None,
        CancelToken::new(),
        |_| Ok(None),
    );
    assert!(matches!(result, Err(DiscoveryError::Credential(_))));
    assert!(fixture.requests().is_empty());
}

#[test]
fn draft_from_a_different_exact_endpoint_is_refused() {
    let fixture = Fixture::new(vec![]);
    let mut provider = fixture.provider("openai-compatible");
    provider.env = Some("ORBIT_SYNTHETIC_UNAVAILABLE".into());
    let wrong = ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        "http://127.0.0.1:1/different?scope=synthetic",
        provider.env.as_deref(),
    )
    .unwrap();
    let draft = SecretBytes::new(b"synthetic-wrong".to_vec());
    let result = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-nonexistent-mismatch"),
        &provider,
        DiscoveryProfile::GenericOpenAi,
        Some((&wrong, &draft)),
        CancelToken::new(),
        |_| Ok(None),
    );
    assert!(matches!(result, Err(DiscoveryError::Credential(_))));
    assert!(fixture.requests().is_empty());
}

#[test]
fn session_debug_never_contains_url_query_or_header_secret() {
    let fixture = Fixture::new(vec![]);
    let mut provider = fixture.provider("openai-compatible");
    provider.env = Some("ORBIT_AUTH_SYNTHETIC_DEBUG".into());
    let session = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        &provider,
        DiscoveryProfile::GenericOpenAi,
        None,
        CancelToken::new(),
        |_| Ok(Some(SecretBytes::new(b"synthetic-debug-secret".to_vec()))),
    )
    .unwrap();
    let debug = format!("{session:?}");
    assert!(!debug.contains(&provider.url));
    assert!(!debug.contains("synthetic-debug-secret"));
    assert!(!debug.contains("scope=synthetic"));
}

#[tokio::test]
async fn generic_unknown_metadata_does_not_infer_limits_or_effort() {
    let fixture = Fixture::new(vec![http(
        200,
        r#"{"data":[{"id":"reasoning-million-vision","context_length":999999,"max_tokens":8000,"capabilities":{"effort":["high"]}}]}"#,
    )]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    )
    .catalog()
    .await;
    assert_eq!(catalog.models[0].context_window, None);
    assert_eq!(catalog.models[0].max_output_tokens, None);
    assert!(
        catalog.models[0]
            .unrecognized_fields
            .contains(&"capabilities".to_owned())
    );
    let merged = merge_discovered_model(
        &model(&catalog.models[0].id),
        &catalog.models[0],
        None,
        &identity(),
    );
    assert_eq!(merged.model.supported_efforts, None);
    assert_eq!(merged.model.default_effort, None);
}

#[tokio::test]
async fn selected_openrouter_documented_fields_and_safe_label() {
    let fixture = Fixture::new(vec![http(
        200,
        r#"{"data":[{"id":"vendor/raw:model","name":"Visible\u001b[31m\nLabel","context_length":200000,"top_provider":{"max_completion_tokens":16000},"pricing":{"prompt":"1"}}]}"#,
    )]);
    let session = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::OpenRouter,
    );
    let catalog = session.catalog().await;
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
    let found = &catalog.models[0];
    assert_eq!(found.context_window, Some(200000));
    assert_eq!(found.max_output_tokens, Some(16000));
    assert!(!found.label.as_ref().unwrap().chars().any(char::is_control));
    let merged = merge_discovered_model(&model(&found.id), found, None, session.identity());
    assert_eq!(merged.model.pricing, Default::default());
}

#[tokio::test]
async fn documented_limits_reject_zero_float_string_negative_and_u32_overflow() {
    for (context, output) in [
        ("0", "1"),
        ("1.5", "1"),
        ("\"100\"", "1"),
        ("-1", "1"),
        ("100", "4294967296"),
    ] {
        let body = format!(
            r#"{{"data":[{{"id":"raw","context_length":{context},"top_provider":{{"max_completion_tokens":{output}}}}}]}}"#
        );
        let fixture = Fixture::new(vec![http(200, &body)]);
        let catalog = session(
            &fixture.provider("openai-compatible"),
            DiscoveryProfile::OpenRouter,
        )
        .catalog()
        .await;
        assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
        assert!(!catalog.models[0].metadata_valid);
        assert!(has_issue(
            &catalog.issues,
            DiscoveryIssueKind::InvalidMetadata
        ));
    }
}

#[tokio::test]
async fn anthropic_documented_cursor_preserves_exact_base_query() {
    let fixture = Fixture::new(vec![
        http(
            200,
            r#"{"data":[{"id":"raw/first","max_input_tokens":100,"max_tokens":10}],"has_more":true,"last_id":"raw/first"}"#,
        ),
        http(
            200,
            r#"{"data":[{"id":"raw/second","max_input_tokens":200,"max_tokens":20}],"has_more":false,"last_id":"raw/second"}"#,
        ),
    ]);
    let catalog = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic)
        .catalog()
        .await;
    assert_eq!(catalog.models.len(), 2);
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1]
            .starts_with("GET /tenant/v1/models?scope=synthetic&after_id=raw%2Ffirst HTTP/1.1")
    );
    assert!(
        requests[0]
            .to_lowercase()
            .contains("anthropic-version: 2023-06-01")
    );
}

#[tokio::test]
async fn pagination_cycle_is_incomplete_and_stops_requests() {
    let body = r#"{"data":[{"id":"repeated"}],"has_more":true,"last_id":"repeated"}"#;
    let fixture = Fixture::new(vec![http(200, body), http(200, body)]);
    let catalog = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic)
        .catalog()
        .await;
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::PaginationCycle
    ));
    assert_eq!(fixture.requests().len(), 2);
}

#[tokio::test]
async fn unknown_off_origin_continuation_never_contacts_trap() {
    let trap = Fixture::new(vec![]);
    let body = format!(
        r#"{{"data":[{{"id":"raw"}}],"next":"http://{}/steal"}}"#,
        trap.addr
    );
    let fixture = Fixture::new(vec![http(200, &body)]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    )
    .catalog()
    .await;
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::UnsupportedPagination
    ));
    assert_eq!(fixture.requests().len(), 1);
    assert!(trap.requests().is_empty());
}

#[tokio::test]
async fn authenticated_redirect_never_contacts_trap() {
    let trap = Fixture::new(vec![]);
    let fixture = Fixture::new(vec![format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        trap.addr
    )]);
    let mut provider = fixture.provider("openai-compatible");
    provider.env = Some("ORBIT_AUTH_REDIRECT".into());
    let session = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        &provider,
        DiscoveryProfile::GenericOpenAi,
        None,
        CancelToken::new(),
        |_| {
            Ok(Some(SecretBytes::new(
                b"synthetic-redirect-secret".to_vec(),
            )))
        },
    )
    .unwrap();
    let catalog = session.catalog().await;
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::HttpStatus(302)
    ));
    assert_eq!(fixture.requests().len(), 1);
    assert!(fixture.requests()[0].contains("synthetic-redirect-secret"));
    assert!(trap.requests().is_empty());
    assert!(!format!("{catalog:?}").contains("synthetic-redirect-secret"));
}

#[tokio::test]
async fn catalog_above_128_is_complete_and_selection_stays_bounded() {
    let data: Vec<_> = (0..257)
        .map(|index| serde_json::json!({"id":format!("vendor/raw-{index}")}))
        .collect();
    let fixture = Fixture::new(vec![http(
        200,
        &serde_json::json!({"data":data}).to_string(),
    )]);
    let session = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    );
    let catalog = session.catalog().await;
    assert_eq!(catalog.models.len(), 257);
    assert_eq!(catalog.models[256].id, "vendor/raw-256");
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
    let details = session.details(&catalog.models[..129], false).await;
    assert_eq!(details.completeness, DiscoveryCompleteness::Incomplete);
    assert!(has_issue(
        &details.issues,
        DiscoveryIssueKind::SelectionLimit
    ));
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn catalog_over_8192_refuses_complete_claim() {
    let data: Vec<_> = (0..8193)
        .map(|index| serde_json::json!({"id":format!("raw-{index}")}))
        .collect();
    let fixture = Fixture::new(vec![http(
        200,
        &serde_json::json!({"data":data}).to_string(),
    )]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    )
    .catalog()
    .await;
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::CatalogEntryLimit
    ));
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn declared_oversized_page_refused_before_body_read() {
    let fixture = Fixture::new(vec![format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_PAGE_BYTES + 1
    )]);
    let session = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    );
    let catalog = session.catalog().await;
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::PageByteLimit
    ));
    assert_eq!(session.consumed_bytes(), 0);
}

#[tokio::test]
async fn chunked_oversized_page_is_bounded() {
    let chunk = "x".repeat(MAX_PAGE_BYTES + 1);
    let fixture = Fixture::new(vec![format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
        chunk.len()
    )]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    )
    .catalog()
    .await;
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::PageByteLimit
    ));
}

#[tokio::test]
async fn catalog_and_details_share_aggregate_byte_budget() {
    let filler = "x".repeat(3_500_000);
    let responses = (0..5)
        .map(|index| {
            http(
                200,
                &serde_json::json!({
                    "data":[{"id":format!("raw-{index}")}], "has_more":true,
                    "last_id":format!("raw-{index}"), "padding":filler,
                })
                .to_string(),
            )
        })
        .collect();
    let fixture = Fixture::new(responses);
    let session = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic);
    let catalog = session.catalog().await;
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::AggregateByteLimit
    ));
    assert_eq!(session.consumed_bytes(), MAX_SESSION_BYTES);
    let before = fixture.requests().len();
    let details = session.details(&catalog.models, true).await;
    assert_eq!(details.attempted, 0);
    assert_eq!(fixture.requests().len(), before);
}

#[tokio::test]
async fn thirty_two_page_limit_never_requests_page_thirty_three() {
    let responses = (0..32)
        .map(|index| {
            http(
                200,
                &serde_json::json!({
                    "data":[{"id":format!("raw-{index}")}], "has_more":true,
                    "last_id":format!("raw-{index}"),
                })
                .to_string(),
            )
        })
        .collect();
    let fixture = Fixture::new(responses);
    let catalog = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic)
        .catalog()
        .await;
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::CatalogPageLimit
    ));
    assert_eq!(catalog.pages_fetched, 32);
    assert_eq!(fixture.requests().len(), 32);
}

#[tokio::test]
async fn consistent_duplicate_is_deduplicated() {
    let fixture = Fixture::new(vec![http(200, r#"{"data":[{"id":"raw"},{"id":"raw"}]}"#)]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    )
    .catalog()
    .await;
    assert_eq!(catalog.models.len(), 1);
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
}

#[tokio::test]
async fn conflicting_duplicate_refuses_complete_catalog() {
    let fixture = Fixture::new(vec![http(
        200,
        r#"{"data":[{"id":"raw","context_length":100},{"id":"raw","context_length":200}]}"#,
    )]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::OpenRouter,
    )
    .catalog()
    .await;
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::ConflictingDuplicate
    ));
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
    assert_eq!(catalog.models[0].context_window, Some(100));
}

#[tokio::test]
async fn malformed_body_is_never_echoed_in_result() {
    let fixture = Fixture::new(vec![http(200, "synthetic-sensitive-body-not-json")]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    )
    .catalog()
    .await;
    assert!(has_issue(&catalog.issues, DiscoveryIssueKind::InvalidJson));
    assert!(!format!("{catalog:?}").contains("synthetic-sensitive-body"));
}

#[tokio::test]
async fn control_bearing_raw_id_is_refused_and_marked_incomplete() {
    let fixture = Fixture::new(vec![http(200, r#"{"data":[{"id":"raw\u001bsecret"}]}"#)]);
    let catalog = session(
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
    )
    .catalog()
    .await;
    assert!(catalog.models.is_empty());
    assert!(has_issue(
        &catalog.issues,
        DiscoveryIssueKind::InvalidModelId
    ));
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
}

#[tokio::test]
async fn every_selected_unknown_anthropic_model_gets_detail() {
    let fixture = Fixture::with_handler(|request| {
        let path = request.split_whitespace().nth(1).unwrap();
        let id = path.split('?').next().unwrap().rsplit('/').next().unwrap();
        http(
            200,
            &serde_json::json!({"id":id,"max_input_tokens":200000,"max_tokens":16000}).to_string(),
        )
    });
    let session = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic);
    let selected: Vec<_> = (0..12)
        .map(|index| {
            observed(
                &format!("raw-{index}"),
                MetadataSource::AnthropicModels,
                None,
                None,
            )
        })
        .collect();
    let details = session.details(&selected, false).await;
    assert_eq!(details.considered, 12);
    assert_eq!(details.attempted, 12);
    assert_eq!(details.completeness, DiscoveryCompleteness::Complete);
    assert_eq!(fixture.requests().len(), 12);
    for (index, found) in details.models.iter().enumerate() {
        assert_eq!(found.id, format!("raw-{index}"));
        assert_eq!(found.context_window, Some(200000));
        assert_eq!(found.max_output_tokens, Some(16000));
    }
}

#[tokio::test]
async fn refresh_revisits_previously_known_anthropic_models() {
    let fixture = Fixture::with_handler(|request| {
        let id = request
            .split_whitespace()
            .nth(1)
            .unwrap()
            .split('?')
            .next()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        http(
            200,
            &serde_json::json!({"id":id,"max_input_tokens":300000,"max_tokens":32000}).to_string(),
        )
    });
    let session = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic);
    let selected = vec![
        observed(
            "known-a",
            MetadataSource::AnthropicModels,
            Some(100000),
            Some(10000),
        ),
        observed(
            "known-b",
            MetadataSource::AnthropicModels,
            Some(100000),
            Some(10000),
        ),
    ];
    assert_eq!(session.details(&selected, false).await.attempted, 0);
    let refreshed = session.details(&selected, true).await;
    assert_eq!(refreshed.attempted, 2);
    assert_eq!(fixture.requests().len(), 2);
    assert!(
        refreshed
            .models
            .iter()
            .all(|model| model.context_window == Some(300000))
    );
}

#[tokio::test]
async fn detail_response_must_match_exact_selected_raw_id() {
    let fixture = Fixture::new(vec![http(
        200,
        r#"{"id":"different","max_input_tokens":200000,"max_tokens":16000}"#,
    )]);
    let session = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic);
    let selected = vec![observed(
        "vendor/raw",
        MetadataSource::AnthropicModels,
        None,
        None,
    )];
    let details = session.details(&selected, false).await;
    assert!(has_issue(
        &details.issues,
        DiscoveryIssueKind::DetailIdentityMismatch
    ));
    assert_eq!(details.models, selected);
    assert!(
        fixture.requests()[0]
            .starts_with("GET /tenant/v1/models/vendor%2Fraw?scope=synthetic HTTP/1.1")
    );
}

#[tokio::test]
async fn ollama_tags_never_claim_architecture_is_active_context() {
    let fixture = Fixture::new(vec![http(
        200,
        r#"{"models":[{"name":"raw:latest","model":"raw:latest","details":{"context_length":1048576},"num_ctx":4096}]}"#,
    )]);
    let session = session(&fixture.provider("ollama"), DiscoveryProfile::Ollama);
    let catalog = session.catalog().await;
    assert_eq!(catalog.models[0].context_window, None);
    let details = session.details(&catalog.models, true).await;
    assert!(has_issue(
        &details.issues,
        DiscoveryIssueKind::UnsupportedDetailSchema
    ));
    assert_eq!(fixture.requests().len(), 1);
    assert!(fixture.requests()[0].starts_with("GET /tenant/v1/api/tags?scope=synthetic HTTP/1.1"));
}

#[tokio::test]
async fn pre_cancelled_catalog_and_details_send_zero_requests() {
    let fixture = Fixture::new(vec![]);
    let cancel = CancelToken::new();
    cancel.cancel();
    let session = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        &fixture.provider("anthropic"),
        DiscoveryProfile::Anthropic,
        None,
        cancel,
        |_| Ok(None),
    )
    .unwrap();
    assert!(has_issue(
        &session.catalog().await.issues,
        DiscoveryIssueKind::Cancelled
    ));
    let selected = vec![observed("raw", MetadataSource::AnthropicModels, None, None)];
    assert!(has_issue(
        &session.details(&selected, false).await.issues,
        DiscoveryIssueKind::Cancelled
    ));
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn cancellation_drops_waiting_request_promptly() {
    let fixture = Fixture::with_handler(|_| {
        thread::sleep(Duration::from_millis(200));
        http(200, r#"{"data":[{"id":"too-late"}]}"#)
    });
    let cancel = CancelToken::new();
    let session = DiscoverySession::new_with_lookup(
        Path::new("/tmp/orbit-discovery-unused"),
        &fixture.provider("openai-compatible"),
        DiscoveryProfile::GenericOpenAi,
        None,
        cancel.clone(),
        |_| Ok(None),
    )
    .unwrap();
    let started = Instant::now();
    let (catalog, ()) = tokio::join!(session.catalog(), async {
        let deadline = Instant::now() + Duration::from_secs(1);
        while fixture.requests().is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(fixture.requests().len(), 1);
        cancel.cancel();
    });
    assert!(has_issue(&catalog.issues, DiscoveryIssueKind::Cancelled));
    assert!(started.elapsed() < Duration::from_millis(180));
}

#[test]
fn missing_effort_stays_unknown_after_merge_and_roundtrip() {
    let observed = observed("raw", MetadataSource::GenericOpenAiModels, None, None);
    let merged = merge_discovered_model(&model("raw"), &observed, None, &identity());
    let restarted: ModelEntry =
        serde_json::from_str(&serde_json::to_string(&merged.model).unwrap()).unwrap();
    assert_eq!(restarted.supported_efforts, None);
    assert_eq!(restarted.default_effort, None);
}

#[test]
fn explicit_effort_survives_refresh_including_explicit_empty() {
    use orbit_adapter::types::EffortValue;
    for (choices, selected) in [
        (
            Some(vec![EffortValue::Level("high".into())]),
            Some(EffortValue::Level("high".into())),
        ),
        (Some(vec![]), None),
    ] {
        let mut current = model("raw");
        current.supported_efforts = choices;
        current.default_effort = selected;
        let first = observed("raw", MetadataSource::OpenRouterModels, Some(100), Some(10));
        let applied = merge_discovered_model(&current, &first, None, &identity());
        let second = observed("raw", MetadataSource::OpenRouterModels, Some(200), Some(20));
        let refreshed = merge_discovered_model(
            &applied.model,
            &second,
            applied.provenance.as_ref(),
            &identity(),
        );
        let restarted: ModelEntry =
            serde_json::from_str(&serde_json::to_string(&refreshed.model).unwrap()).unwrap();
        assert_eq!(restarted.supported_efforts, current.supported_efforts);
        assert_eq!(restarted.default_effort, current.default_effort);
    }
}

#[test]
fn numeric_values_with_missing_provenance_are_preserved() {
    let mut current = model("raw");
    current.context_window = Some(777);
    current.max_output_tokens = Some(77);
    let observed = observed(
        "raw",
        MetadataSource::OpenRouterModels,
        Some(1000),
        Some(100),
    );
    let merged = merge_discovered_model(&current, &observed, None, &identity());
    assert_eq!(merged.model, current);
}

#[test]
fn refresh_updates_auto_values_and_preserves_different_manual_override() {
    let first = observed(
        "raw",
        MetadataSource::OpenRouterModels,
        Some(1000),
        Some(100),
    );
    let applied = merge_discovered_model(&model("raw"), &first, None, &identity());
    let mut manual = applied.model;
    manual.max_output_tokens = Some(77);
    let second = observed(
        "raw",
        MetadataSource::OpenRouterModels,
        Some(2000),
        Some(200),
    );
    let merged = merge_discovered_model(&manual, &second, applied.provenance.as_ref(), &identity());
    assert_eq!(merged.model.context_window, Some(2000));
    assert_eq!(merged.model.max_output_tokens, Some(77));
    assert_eq!(
        merged.provenance.unwrap().last_applied_max_output_tokens,
        None
    );
}

#[test]
fn stale_version_binding_or_last_applied_provenance_preserves_existing() {
    let first = observed(
        "raw",
        MetadataSource::OpenRouterModels,
        Some(1000),
        Some(100),
    );
    let applied = merge_discovered_model(&model("raw"), &first, None, &identity());
    let second = observed(
        "raw",
        MetadataSource::OpenRouterModels,
        Some(2000),
        Some(200),
    );
    for variant in 0..3 {
        let mut previous = applied.provenance.clone().unwrap();
        match variant {
            0 => previous.schema_version += 1,
            1 => previous.provider_binding = "wrong-exact-identity".into(),
            _ => previous.observed.context_window = Some(999),
        }
        let merged = merge_discovered_model(&applied.model, &second, Some(&previous), &identity());
        assert_eq!(merged.model, applied.model);
    }
}

#[test]
fn vanished_advertised_limit_clears_only_previously_auto_value() {
    let first = observed(
        "raw",
        MetadataSource::OpenRouterModels,
        Some(1000),
        Some(100),
    );
    let applied = merge_discovered_model(&model("raw"), &first, None, &identity());
    let vanished = observed("raw", MetadataSource::OpenRouterModels, None, None);
    let merged = merge_discovered_model(
        &applied.model,
        &vanished,
        applied.provenance.as_ref(),
        &identity(),
    );
    assert_eq!(merged.model.context_window, None);
    assert_eq!(merged.model.max_output_tokens, None);
}

#[test]
fn invalid_metadata_or_different_raw_identity_preserves_every_field() {
    let mut current = model("raw");
    current.context_window = Some(1000);
    let mut invalid = observed(
        "raw",
        MetadataSource::OpenRouterModels,
        Some(2000),
        Some(100),
    );
    invalid.metadata_valid = false;
    assert_eq!(
        merge_discovered_model(&current, &invalid, None, &identity()).model,
        current
    );
    invalid.metadata_valid = true;
    invalid.id = "different".into();
    let merged = merge_discovered_model(&current, &invalid, None, &identity());
    assert_eq!(merged.model, current);
    assert!(merged.provenance.is_none());
}

// Separate finite fixture for measuring actual simultaneous HTTP exchanges.
// A sequential fixture cannot establish the client's concurrency ceiling.
struct ConcurrencyFixture {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    peak: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl ConcurrencyFixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let peak = Arc::new(AtomicUsize::new(0));
        let measured = peak.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut workers = Vec::new();
            while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline && workers.len() < 16
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let captured = captured.clone();
                        let active = active.clone();
                        let measured = measured.clone();
                        workers.push(thread::spawn(move || {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(500)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_millis(500)))
                                .unwrap();
                            let mut bytes = Vec::new();
                            let mut buffer = [0_u8; 4096];
                            while bytes.len() < 32768 && !bytes.ends_with(b"\r\n\r\n") {
                                match stream.read(&mut buffer) {
                                    Ok(0) | Err(_) => break,
                                    Ok(length) => bytes.extend_from_slice(&buffer[..length]),
                                }
                            }
                            if bytes.is_empty() {
                                return;
                            }
                            let request = String::from_utf8(bytes).unwrap();
                            captured.lock().unwrap().push(request.clone());
                            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                            measured.fetch_max(current, Ordering::SeqCst);
                            let wait = Instant::now() + Duration::from_millis(500);
                            while active.load(Ordering::SeqCst) < 4 && Instant::now() < wait {
                                thread::sleep(Duration::from_millis(2));
                            }
                            thread::sleep(Duration::from_millis(30));
                            let id = request
                                .split_whitespace()
                                .nth(1)
                                .unwrap()
                                .split('?')
                                .next()
                                .unwrap()
                                .rsplit('/')
                                .next()
                                .unwrap();
                            let response = http(
                                200,
                                &serde_json::json!({
                                    "id":id,"max_input_tokens":100000,"max_tokens":10000,
                                })
                                .to_string(),
                            );
                            active.fetch_sub(1, Ordering::SeqCst);
                            let _ = stream.write_all(response.as_bytes());
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            addr,
            requests,
            peak,
            stop,
            join: Some(join),
        }
    }
}

impl Drop for ConcurrencyFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}

#[tokio::test]
async fn selected_details_make_progress_with_at_most_four_real_concurrent_requests() {
    let fixture = ConcurrencyFixture::new();
    let provider = ProviderConfig {
        name: "fixture".into(),
        kind: "anthropic".into(),
        url: format!("http://{}/v1", fixture.addr),
        env: None,
        models: vec![],
    };
    let session = session(&provider, DiscoveryProfile::Anthropic);
    let selected: Vec<_> = (0..12)
        .map(|index| {
            observed(
                &format!("raw-{index}"),
                MetadataSource::AnthropicModels,
                None,
                None,
            )
        })
        .collect();
    let details = session.details(&selected, false).await;
    assert_eq!(details.attempted, 12);
    assert_eq!(details.completeness, DiscoveryCompleteness::Complete);
    assert_eq!(fixture.requests.lock().unwrap().len(), 12);
    assert_eq!(fixture.peak.load(Ordering::SeqCst), MAX_DETAIL_CONCURRENCY);
}

#[tokio::test]
async fn overlapping_detail_calls_share_the_four_request_ceiling() {
    let fixture = ConcurrencyFixture::new();
    let provider = ProviderConfig {
        name: "fixture".into(),
        kind: "anthropic".into(),
        url: format!("http://{}/v1", fixture.addr),
        env: None,
        models: vec![],
    };
    let session = session(&provider, DiscoveryProfile::Anthropic);
    let one: Vec<_> = (0..6)
        .map(|index| {
            observed(
                &format!("one-{index}"),
                MetadataSource::AnthropicModels,
                None,
                None,
            )
        })
        .collect();
    let two: Vec<_> = (0..6)
        .map(|index| {
            observed(
                &format!("two-{index}"),
                MetadataSource::AnthropicModels,
                None,
                None,
            )
        })
        .collect();
    let (first, second) = tokio::join!(session.details(&one, false), session.details(&two, false));
    assert_eq!(first.completeness, DiscoveryCompleteness::Complete);
    assert_eq!(second.completeness, DiscoveryCompleteness::Complete);
    assert_eq!(fixture.requests.lock().unwrap().len(), 12);
    assert_eq!(fixture.peak.load(Ordering::SeqCst), MAX_DETAIL_CONCURRENCY);
}

#[tokio::test]
async fn detail_request_allowance_is_shared_across_calls() {
    let fixture = Fixture::with_handler(|request| {
        let id = request
            .split_whitespace()
            .nth(1)
            .unwrap()
            .split('?')
            .next()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        http(
            200,
            &serde_json::json!({"id":id,"max_input_tokens":100000,"max_tokens":10000}).to_string(),
        )
    });
    let session = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic);
    let selected: Vec<_> = (0..128)
        .map(|index| {
            observed(
                &format!("raw-{index}"),
                MetadataSource::AnthropicModels,
                None,
                None,
            )
        })
        .collect();
    let first = session.details(&selected, false).await;
    assert_eq!(first.attempted, 128);
    assert_eq!(first.completeness, DiscoveryCompleteness::Complete);
    let second = session.details(&selected, true).await;
    assert_eq!(second.attempted, 0);
    assert!(has_issue(
        &second.issues,
        DiscoveryIssueKind::SelectionLimit
    ));
    assert_eq!(fixture.requests().len(), 128);
}

#[tokio::test]
async fn expired_session_deadline_refuses_io_before_catalog_and_details() {
    let fixture = Fixture::new(vec![]);
    let session = session(&fixture.provider("anthropic"), DiscoveryProfile::Anthropic);
    tokio::time::sleep(SESSION_TIMEOUT + Duration::from_millis(20)).await;
    assert!(has_issue(
        &session.catalog().await.issues,
        DiscoveryIssueKind::DeadlineExceeded
    ));
    let selected = vec![observed("raw", MetadataSource::AnthropicModels, None, None)];
    let details = session.details(&selected, false).await;
    assert_eq!(details.attempted, 0);
    assert!(has_issue(
        &details.issues,
        DiscoveryIssueKind::DeadlineExceeded
    ));
    assert!(fixture.requests().is_empty());
}

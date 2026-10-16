use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbit_adapter::SecretBytes;
use orbit_cli::config::ProviderConfig;
use orbit_cli::onboarding::provider_login::*;
use orbit_provider_http::CancelToken;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

struct Fixture {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(responses: Vec<String>) -> Self {
        Self::delayed(responses, Duration::ZERO)
    }

    fn delayed(responses: Vec<String>, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let join = thread::spawn(move || {
            let mut responses: VecDeque<_> = responses.into();
            let deadline = Instant::now() + Duration::from_secs(15);
            while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(750)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_millis(750)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let mut chunk = [0u8; 2048];
                        loop {
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(count) => bytes.extend_from_slice(&chunk[..count]),
                            }
                            if bytes.len() > 32768 {
                                break;
                            }
                            if let Some(end) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                                let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                                let length = headers
                                    .lines()
                                    .find_map(|line| {
                                        let (name, value) = line.split_once(':')?;
                                        name.eq_ignore_ascii_case("content-length")
                                            .then(|| value.trim().parse::<usize>().unwrap())
                                    })
                                    .unwrap_or(0);
                                if bytes.len() >= end + 4 + length {
                                    break;
                                }
                            }
                        }
                        if bytes.is_empty() {
                            continue;
                        }
                        captured
                            .lock()
                            .unwrap()
                            .push(String::from_utf8(bytes).unwrap());
                        if !delay.is_zero() {
                            thread::sleep(delay);
                        }
                        let response = responses.pop_front().unwrap_or_else(|| http(500, "{}"));
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

    fn transport(&self) -> LoopbackTestTransport {
        LoopbackTestTransport::new(Url::parse(&format!("http://{}/", self.addr)).unwrap())
            .unwrap()
            .with_timeouts(
                Duration::from_secs(3),
                Duration::from_secs(1),
                Duration::from_millis(150),
            )
            .unwrap()
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

fn provider() -> ProviderConfig {
    ProviderConfig {
        name: "custom display name".into(),
        kind: "openai-compatible".into(),
        url: OPENROUTER_PROVIDER_URL.into(),
        env: None,
        models: vec![],
    }
}

async fn login(fixture: &Fixture, mode: LoginMode) -> ProviderLogin {
    ProviderLogin::start_with_loopback_test_transport(
        &provider(),
        mode,
        "ORBIT test",
        CancelToken::new(),
        fixture.transport(),
    )
    .await
    .unwrap()
}

fn parameter(login: &ProviderLogin, name: &str) -> String {
    login
        .authorization_url()
        .query_pairs()
        .find(|(key, _)| key == name)
        .unwrap()
        .1
        .into_owned()
}

fn target(login: &ProviderLogin, code: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", code)
        .append_pair("state", &parameter(login, "state"))
        .finish();
    format!("/callback?{query}")
}

fn request(callback: &Url, method: &str, target: &str, host: Option<&str>) -> String {
    let expected = format!("localhost:{}", callback.port().unwrap());
    format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host.unwrap_or(&expected)
    )
}

async fn send(callback: &Url, request: &str) -> Vec<u8> {
    let mut stream =
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, callback.port().unwrap()))
            .await
            .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    if let Err(error) =
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
    {
        // Refusing an oversized HTTP request can close with unread inbound
        // bytes. Preserve any fixed response received before that TCP reset.
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    response
}

async fn callback_code(login: &mut ProviderLogin, code: &str) -> AuthorizationCode {
    let callback = login.callback_url().unwrap().clone();
    let request = request(&callback, "GET", &target(login, code), None);
    let (code, response) = tokio::join!(login.wait_for_callback(), send(&callback, &request));
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Cache-Control: no-store"));
    assert!(response.contains("Referrer-Policy: no-referrer"));
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert_eq!(length, body.len());
    code.unwrap()
}

async fn rejected_then_valid(mutator: impl FnOnce(&ProviderLogin, &Url) -> String) {
    let fixture = Fixture::new(vec![]);
    let mut login = login(&fixture, LoginMode::Loopback).await;
    let callback = login.callback_url().unwrap().clone();
    let poison = mutator(&login, &callback);
    let valid = request(&callback, "GET", &target(&login, "fixture-code"), None);
    let sender = async {
        let rejected = send(&callback, &poison).await;
        assert!(rejected.starts_with(b"HTTP/1.1 400"));
        assert!(
            !rejected
                .windows(b"fixture-code".len())
                .any(|w| w == b"fixture-code")
        );
        let accepted = send(&callback, &valid).await;
        assert!(accepted.starts_with(b"HTTP/1.1 200"));
    };
    let (result, ()) = tokio::join!(login.wait_for_callback(), sender);
    assert!(result.is_ok());
    assert!(fixture.requests().is_empty());
}

#[test]
fn official_origin_eligibility_is_exact_and_display_name_independent() {
    assert!(supports_browser_login(&provider()));
    let mut candidate = provider();
    candidate.url.push('/');
    assert!(supports_browser_login(&candidate));
    for url in [
        "https://openrouter.ai.evil.invalid/api/v1",
        "http://openrouter.ai/api/v1",
        "https://openrouter.ai/api/v1?scope=other",
        "https://openrouter.ai/api/v1/extra",
        "https://openrouter.ai:444/api/v1",
        "https://user@openrouter.ai/api/v1",
        "http://127.0.0.1:5000/api/v1",
        "https://openrouter.ai/api/v1#fragment",
    ] {
        candidate.url = url.into();
        assert!(!supports_browser_login(&candidate));
    }
    candidate.url = OPENROUTER_PROVIDER_URL.into();
    candidate.kind = "anthropic".into();
    assert!(!supports_browser_login(&candidate));
}

#[test]
fn test_transport_accepts_only_explicit_numeric_loopback_origin_and_shorter_budgets() {
    for endpoint in [
        "https://127.0.0.1:5000/",
        "http://localhost:5000/",
        "http://[::1]:5000/",
        "http://192.0.2.1:5000/",
        "http://127.0.0.1/",
        "http://127.0.0.1:5000/path",
        "http://127.0.0.1:5000/?query=1",
        "http://127.0.0.1:5000/#fragment",
        "http://user@127.0.0.1:5000/",
    ] {
        assert_eq!(
            LoopbackTestTransport::new(Url::parse(endpoint).unwrap()).unwrap_err(),
            LoginError::InvalidTestTransport
        );
    }
    let make =
        || LoopbackTestTransport::new(Url::parse("http://127.0.0.1:5000/").unwrap()).unwrap();
    assert!(
        make()
            .with_timeouts(
                Duration::ZERO,
                EXCHANGE_TIMEOUT,
                CALLBACK_CONNECTION_TIMEOUT
            )
            .is_err()
    );
    assert!(
        make()
            .with_timeouts(
                LOGIN_TIMEOUT + Duration::from_secs(1),
                EXCHANGE_TIMEOUT,
                CALLBACK_CONNECTION_TIMEOUT
            )
            .is_err()
    );
    assert!(
        make()
            .with_timeouts(
                LOGIN_TIMEOUT,
                EXCHANGE_TIMEOUT + Duration::from_secs(1),
                CALLBACK_CONNECTION_TIMEOUT
            )
            .is_err()
    );
}

#[tokio::test]
async fn loopback_authorization_uses_s256_random_state_and_ephemeral_localhost_callback() {
    let fixture = Fixture::new(vec![]);
    let first = login(&fixture, LoginMode::Loopback).await;
    let second = login(&fixture, LoginMode::Loopback).await;
    assert_eq!(first.authorization_url().path(), "/auth");
    assert_eq!(parameter(&first, "code_challenge_method"), "S256");
    assert_eq!(parameter(&first, "key_label"), "ORBIT test");
    assert_eq!(parameter(&first, "state").len(), 43);
    assert_eq!(parameter(&first, "code_challenge").len(), 43);
    assert!(parameter(&first, "state") != parameter(&second, "state"));
    assert!(parameter(&first, "code_challenge") != parameter(&second, "code_challenge"));
    let callback = first.callback_url().unwrap();
    assert_eq!(callback.host_str(), Some("localhost"));
    assert_eq!(callback.scheme(), "http");
    assert_eq!(callback.path(), "/callback");
    assert!(callback.port().unwrap() > 0);
    assert_eq!(parameter(&first, "callback_url"), callback.as_str());
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn headless_authorization_omits_callback_and_state_and_keeps_s256() {
    let fixture = Fixture::new(vec![]);
    let login = login(&fixture, LoginMode::Headless).await;
    assert_eq!(login.mode(), LoginMode::Headless);
    assert!(login.callback_url().is_none());
    assert!(
        login
            .authorization_url()
            .query_pairs()
            .all(|(key, _)| key != "state" && key != "callback_url" && key != "code_verifier")
    );
    assert_eq!(parameter(&login, "code_challenge_method"), "S256");
    assert_eq!(parameter(&login, "code_challenge").len(), 43);
}

#[tokio::test]
async fn loopback_success_exchanges_exact_code_verifier_and_method_without_ambient_auth() {
    let fixture = Fixture::new(vec![http(
        200,
        r#"{"key":"synthetic-login-key","extra":{"ignored":true}}"#,
    )]);
    let mut login = login(&fixture, LoginMode::Loopback).await;
    let challenge = parameter(&login, "code_challenge");
    let callback = login.callback_url().unwrap().clone();
    let code = callback_code(&mut login, "fixture/code+with=punctuation").await;
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, callback.port().unwrap()))
            .await
            .is_err()
    );
    let key = login.exchange(code).await.unwrap();
    assert!(key.expose() == b"synthetic-login-key");
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /api/v1/auth/keys HTTP/1.1\r\n"));
    let (headers, body) = requests[0].split_once("\r\n\r\n").unwrap();
    assert!(!headers.to_lowercase().contains("authorization:"));
    assert!(!headers.to_lowercase().contains("cookie:"));
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert!(value["code"].as_str() == Some("fixture/code+with=punctuation"));
    assert!(value["code_challenge_method"].as_str() == Some("S256"));
    let verifier = value["code_verifier"].as_str().unwrap();
    assert_eq!(verifier.len(), 43);
    assert!(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge);
    assert!(!format!("{login:?}").contains(verifier));
}

#[tokio::test]
async fn headless_success_exchanges_private_code_with_original_verifier() {
    let fixture = Fixture::new(vec![http(200, r#"{"key":"synthetic-headless-key"}"#)]);
    let mut login = login(&fixture, LoginMode::Headless).await;
    let challenge = parameter(&login, "code_challenge");
    let code = login
        .accept_headless_code(SecretBytes::new(b"headless-fixture-code".to_vec()))
        .unwrap();
    assert!(!format!("{code:?}").contains("headless-fixture-code"));
    assert!(login.exchange(code).await.unwrap().expose() == b"synthetic-headless-key");
    let requests = fixture.requests();
    let value: serde_json::Value =
        serde_json::from_str(requests[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert!(value["code"].as_str() == Some("headless-fixture-code"));
    let verifier = value["code_verifier"].as_str().unwrap();
    assert!(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge);
}

#[tokio::test]
async fn loopback_wrong_state_is_refused_before_a_matching_callback() {
    rejected_then_valid(|_, callback| {
        request(
            callback,
            "GET",
            "/callback?code=fixture-code&state=wrong",
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_wrong_host_is_refused_before_a_matching_callback() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &target(login, "fixture-code"),
            Some("evil.invalid"),
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_wrong_path_is_refused_without_url_normalization() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &target(login, "fixture-code").replacen("/callback?", "/other/../callback?", 1),
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_wrong_method_is_refused() {
    rejected_then_valid(|login, callback| {
        request(callback, "POST", &target(login, "fixture-code"), None)
    })
    .await;
}

#[tokio::test]
async fn loopback_duplicate_code_query_is_refused() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &format!("{}&code=second", target(login, "fixture-code")),
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_percent_encoded_duplicate_state_query_is_refused() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &format!("{}&%73tate=second", target(login, "fixture-code")),
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_control_character_code_is_refused_after_decoding() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &format!(
                "/callback?code=fixture-code%0D%0Ainjected&state={}",
                parameter(login, "state")
            ),
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_invalid_percent_encoding_is_refused() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &format!(
                "/callback?code=fixture-code%ZZ&state={}",
                parameter(login, "state")
            ),
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_absolute_request_target_is_refused() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &format!(
                "http://localhost:{}{}",
                callback.port().unwrap(),
                target(login, "fixture-code")
            ),
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_wrong_host_port_is_refused() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &target(login, "fixture-code"),
            Some("localhost:1"),
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_unknown_query_parameter_is_refused() {
    rejected_then_valid(|login, callback| {
        request(
            callback,
            "GET",
            &format!(
                "{}&redirect_url=http%3A%2F%2Fevil.invalid",
                target(login, "fixture-code")
            ),
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_duplicate_host_is_refused() {
    rejected_then_valid(|login, callback| {
        request(callback, "GET", &target(login, "fixture-code"), None).replacen(
            "Connection:",
            "Host: evil.invalid\r\nConnection:",
            1,
        )
    })
    .await;
}

#[tokio::test]
async fn loopback_request_body_and_transfer_encoding_are_refused() {
    rejected_then_valid(|login, callback| {
        request(callback, "GET", &target(login, "fixture-code"), None).replacen(
            "Connection:",
            "Transfer-Encoding: chunked\r\nConnection:",
            1,
        )
    })
    .await;
    rejected_then_valid(|login, callback| {
        let mut request = request(callback, "GET", &target(login, "fixture-code"), None).replacen(
            "Connection:",
            "Content-Length: 1\r\nConnection:",
            1,
        );
        request.push('x');
        request
    })
    .await;
}

#[tokio::test]
async fn loopback_oversized_request_is_refused_and_next_callback_can_succeed() {
    let fixture = Fixture::new(vec![]);
    let mut login = login(&fixture, LoginMode::Loopback).await;
    let callback = login.callback_url().unwrap().clone();
    let oversized = request(
        &callback,
        "GET",
        &format!(
            "/callback?code={}&state={}",
            "x".repeat(MAX_CALLBACK_BYTES),
            parameter(&login, "state")
        ),
        None,
    );
    let valid = request(&callback, "GET", &target(&login, "fixture-code"), None);
    let sender = async {
        let response = send(&callback, &oversized).await;
        assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 400"));
        assert!(send(&callback, &valid).await.starts_with(b"HTTP/1.1 200"));
    };
    let (result, ()) = tokio::join!(login.wait_for_callback(), sender);
    assert!(result.is_ok());
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn loopback_invalid_connection_budget_is_finite_and_closes_listener() {
    let fixture = Fixture::new(vec![]);
    let mut login = login(&fixture, LoginMode::Loopback).await;
    let callback = login.callback_url().unwrap().clone();
    let invalid = request(
        &callback,
        "GET",
        "/callback?code=fixture-code&state=wrong",
        None,
    );
    let sender = async {
        for _ in 0..MAX_INVALID_CALLBACKS {
            assert!(send(&callback, &invalid).await.starts_with(b"HTTP/1.1 400"));
        }
    };
    let (result, ()) = tokio::join!(login.wait_for_callback(), sender);
    assert_eq!(result.unwrap_err(), LoginError::CallbackLimit);
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, callback.port().unwrap()))
            .await
            .is_err()
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn loopback_denial_without_state_never_exchanges_or_reflects_description() {
    let fixture = Fixture::new(vec![]);
    let mut login = login(&fixture, LoginMode::Loopback).await;
    let callback = login.callback_url().unwrap().clone();
    let request = request(
        &callback,
        "GET",
        "/callback?error=access_denied&error_description=private-denial-marker",
        None,
    );
    let (result, response) = tokio::join!(login.wait_for_callback(), send(&callback, &request));
    assert_eq!(result.unwrap_err(), LoginError::Denied);
    assert!(
        !response
            .windows(b"private-denial-marker".len())
            .any(|w| w == b"private-denial-marker")
    );
    assert!(fixture.requests().is_empty());
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, callback.port().unwrap()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn loopback_denial_with_foreign_state_is_invalid_not_account_information() {
    rejected_then_valid(|_, callback| {
        request(
            callback,
            "GET",
            "/callback?error=access_denied&state=wrong",
            None,
        )
    })
    .await;
}

#[tokio::test]
async fn canceled_before_initialization_performs_no_protocol_io() {
    let fixture = Fixture::new(vec![]);
    let cancel = CancelToken::new();
    cancel.cancel();
    assert_eq!(
        ProviderLogin::start_with_loopback_test_transport(
            &provider(),
            LoginMode::Loopback,
            "ORBIT",
            cancel,
            fixture.transport()
        )
        .await
        .unwrap_err(),
        LoginError::Canceled
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn loopback_cancellation_closes_listener_and_waits_for_no_callback() {
    let fixture = Fixture::new(vec![]);
    let cancel = CancelToken::new();
    let mut login = ProviderLogin::start_with_loopback_test_transport(
        &provider(),
        LoginMode::Loopback,
        "ORBIT",
        cancel.clone(),
        fixture.transport(),
    )
    .await
    .unwrap();
    let callback = login.callback_url().unwrap().clone();
    let cancellation = async {
        tokio::time::sleep(Duration::from_millis(15)).await;
        cancel.cancel();
    };
    let (result, ()) = tokio::join!(login.wait_for_callback(), cancellation);
    assert_eq!(result.unwrap_err(), LoginError::Canceled);
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, callback.port().unwrap()))
            .await
            .is_err()
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn canceled_after_callback_never_sends_exchange() {
    let fixture = Fixture::new(vec![]);
    let cancel = CancelToken::new();
    let mut login = ProviderLogin::start_with_loopback_test_transport(
        &provider(),
        LoginMode::Loopback,
        "ORBIT",
        cancel.clone(),
        fixture.transport(),
    )
    .await
    .unwrap();
    let code = callback_code(&mut login, "fixture-code").await;
    cancel.cancel();
    assert_eq!(
        login.exchange(code).await.unwrap_err(),
        LoginError::Canceled
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn loopback_absolute_deadline_closes_listener() {
    let fixture = Fixture::new(vec![]);
    let transport = fixture
        .transport()
        .with_timeouts(
            Duration::from_millis(40),
            Duration::from_millis(20),
            Duration::from_millis(15),
        )
        .unwrap();
    let mut login = ProviderLogin::start_with_loopback_test_transport(
        &provider(),
        LoginMode::Loopback,
        "ORBIT",
        CancelToken::new(),
        transport,
    )
    .await
    .unwrap();
    let callback = login.callback_url().unwrap().clone();
    assert_eq!(
        login.wait_for_callback().await.unwrap_err(),
        LoginError::DeadlineExceeded
    );
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, callback.port().unwrap()))
            .await
            .is_err()
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn loopback_slow_connection_has_a_shorter_bound_than_the_session() {
    let fixture = Fixture::new(vec![]);
    let mut login = login(&fixture, LoginMode::Loopback).await;
    let callback = login.callback_url().unwrap().clone();
    let valid = request(&callback, "GET", &target(&login, "fixture-code"), None);
    let sender = async {
        let mut slow = tokio::net::TcpStream::connect((
            std::net::Ipv4Addr::LOCALHOST,
            callback.port().unwrap(),
        ))
        .await
        .unwrap();
        slow.write_all(b"GET /callback?code=partial").await.unwrap();
        let mut closed = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), slow.read_to_end(&mut closed))
            .await
            .unwrap()
            .unwrap();
        assert!(send(&callback, &valid).await.starts_with(b"HTTP/1.1 200"));
    };
    let (result, ()) = tokio::join!(login.wait_for_callback(), sender);
    assert!(result.is_ok());
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn exchange_rejects_invalid_key_schemas_without_echoing_the_response() {
    for body in [
        "{}",
        r#"{"key":""}"#,
        r#"{"key":123}"#,
        r#"{"key":"white space"}"#,
        r#"{"key":"value\r\nheader"}"#,
        r#"{"key":"first","key":"second"}"#,
        r#"[{"key":"array-value"}]"#,
        r#"{"key":"first"}{"key":"second"}"#,
    ] {
        let fixture = Fixture::new(vec![http(200, body)]);
        let mut login = login(&fixture, LoginMode::Headless).await;
        let code = login
            .accept_headless_code(SecretBytes::new(b"fixture-code".to_vec()))
            .unwrap();
        let error = login.exchange(code).await.unwrap_err();
        assert_eq!(error, LoginError::InvalidResponse);
        assert!(!format!("{error:?} {error}").contains(body));
        assert_eq!(fixture.requests().len(), 1);
    }
}

#[tokio::test]
async fn exchange_known_oversize_response_is_refused() {
    let body = format!("{{\"key\":\"{}\"}}", "x".repeat(MAX_EXCHANGE_BYTES));
    let fixture = Fixture::new(vec![http(200, &body)]);
    let mut login = login(&fixture, LoginMode::Headless).await;
    let code = login
        .accept_headless_code(SecretBytes::new(b"fixture-code".to_vec()))
        .unwrap();
    assert_eq!(
        login.exchange(code).await.unwrap_err(),
        LoginError::ResponseLimit
    );
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn exchange_unknown_length_oversize_response_is_refused() {
    let body = format!("{{\"key\":\"{}\"}}", "x".repeat(MAX_EXCHANGE_BYTES));
    let fixture = Fixture::new(vec![format!(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}"
    )]);
    let mut login = login(&fixture, LoginMode::Headless).await;
    let code = login
        .accept_headless_code(SecretBytes::new(b"fixture-code".to_vec()))
        .unwrap();
    assert_eq!(
        login.exchange(code).await.unwrap_err(),
        LoginError::ResponseLimit
    );
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn exchange_redirect_is_not_followed_or_forwarded_to_another_origin() {
    let trap = Fixture::new(vec![http(200, r#"{"key":"must-not-be-read"}"#)]);
    let fixture = Fixture::new(vec![format!(
        "HTTP/1.1 307 Redirect\r\nLocation: http://{}/trap\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        trap.addr
    )]);
    let mut login = login(&fixture, LoginMode::Headless).await;
    let code = login
        .accept_headless_code(SecretBytes::new(b"fixture-code".to_vec()))
        .unwrap();
    assert_eq!(
        login.exchange(code).await.unwrap_err(),
        LoginError::HttpStatus(307)
    );
    assert_eq!(fixture.requests().len(), 1);
    assert!(trap.requests().is_empty());
}

#[tokio::test]
async fn exchange_http_error_never_exposes_provider_response_or_request_secrets() {
    let fixture = Fixture::new(vec![http(403, "private-exchange-response-marker")]);
    let mut login = login(&fixture, LoginMode::Headless).await;
    let code = login
        .accept_headless_code(SecretBytes::new(b"private-code-marker".to_vec()))
        .unwrap();
    let error = login.exchange(code).await.unwrap_err();
    assert_eq!(error, LoginError::HttpStatus(403));
    let safe = format!("{error:?} {error} {login:?}");
    assert!(!safe.contains("private-exchange-response-marker"));
    assert!(!safe.contains("private-code-marker"));
}

#[tokio::test]
async fn loopback_callback_and_exchange_are_one_time_only() {
    let fixture = Fixture::new(vec![http(200, r#"{"key":"synthetic-once-key"}"#)]);
    let mut login = login(&fixture, LoginMode::Loopback).await;
    let code = callback_code(&mut login, "fixture-code").await;
    assert_eq!(
        login.wait_for_callback().await.unwrap_err(),
        LoginError::InvalidState
    );
    assert!(login.exchange(code).await.is_ok());
    assert_eq!(
        login.wait_for_callback().await.unwrap_err(),
        LoginError::InvalidState
    );
    assert_eq!(
        login
            .accept_headless_code(SecretBytes::new(b"again".to_vec()))
            .unwrap_err(),
        LoginError::InvalidState
    );
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn authorization_code_cannot_cross_login_sessions_before_network_io() {
    let fixture = Fixture::new(vec![]);
    let mut first = login(&fixture, LoginMode::Headless).await;
    let mut second = login(&fixture, LoginMode::Headless).await;
    let foreign = first
        .accept_headless_code(SecretBytes::new(b"first-code".to_vec()))
        .unwrap();
    let _second = second
        .accept_headless_code(SecretBytes::new(b"second-code".to_vec()))
        .unwrap();
    assert_eq!(
        second.exchange(foreign).await.unwrap_err(),
        LoginError::InvalidState
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn headless_mode_and_bounded_code_validation_are_explicit() {
    let fixture = Fixture::new(vec![]);
    let mut login = login(&fixture, LoginMode::Headless).await;
    assert_eq!(
        login.wait_for_callback().await.unwrap_err(),
        LoginError::InvalidState
    );
    for invalid in [
        vec![],
        b"line\ncode".to_vec(),
        b"code with space".to_vec(),
        vec![0xff],
        vec![b'x'; MAX_AUTHORIZATION_CODE_BYTES + 1],
    ] {
        assert_eq!(
            login
                .accept_headless_code(SecretBytes::new(invalid))
                .unwrap_err(),
            LoginError::InvalidCode
        );
    }
    assert!(
        login
            .accept_headless_code(SecretBytes::new(vec![b'x'; MAX_AUTHORIZATION_CODE_BYTES]))
            .is_ok()
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn exchange_timeout_does_not_retry_a_potentially_consumed_code() {
    let fixture = Fixture::delayed(
        vec![http(200, r#"{"key":"late-private-key"}"#)],
        Duration::from_millis(120),
    );
    let transport = fixture
        .transport()
        .with_timeouts(
            Duration::from_secs(1),
            Duration::from_millis(30),
            Duration::from_millis(20),
        )
        .unwrap();
    let mut login = ProviderLogin::start_with_loopback_test_transport(
        &provider(),
        LoginMode::Headless,
        "ORBIT",
        CancelToken::new(),
        transport,
    )
    .await
    .unwrap();
    let code = login
        .accept_headless_code(SecretBytes::new(b"fixture-code".to_vec()))
        .unwrap();
    assert_eq!(
        login.exchange(code).await.unwrap_err(),
        LoginError::ExchangeTimeout
    );
    assert_eq!(
        login
            .accept_headless_code(SecretBytes::new(b"again".to_vec()))
            .unwrap_err(),
        LoginError::InvalidState
    );
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn cancellation_during_exchange_drops_request_without_key_or_retry() {
    let fixture = Fixture::delayed(
        vec![http(200, r#"{"key":"late-private-key"}"#)],
        Duration::from_millis(120),
    );
    let cancel = CancelToken::new();
    let mut login = ProviderLogin::start_with_loopback_test_transport(
        &provider(),
        LoginMode::Headless,
        "ORBIT",
        cancel.clone(),
        fixture.transport(),
    )
    .await
    .unwrap();
    let code = login
        .accept_headless_code(SecretBytes::new(b"fixture-code".to_vec()))
        .unwrap();
    let cancellation = async {
        tokio::time::sleep(Duration::from_millis(25)).await;
        cancel.cancel();
    };
    let (result, ()) = tokio::join!(login.exchange(code), cancellation);
    assert_eq!(result.unwrap_err(), LoginError::Canceled);
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn invalid_provider_and_label_fail_before_fixture_requests() {
    let fixture = Fixture::new(vec![]);
    let mut custom = provider();
    custom.name = "openrouter".into();
    custom.url = format!("http://{}/api/v1", fixture.addr);
    assert_eq!(
        ProviderLogin::start_with_loopback_test_transport(
            &custom,
            LoginMode::Loopback,
            "ORBIT",
            CancelToken::new(),
            fixture.transport()
        )
        .await
        .unwrap_err(),
        LoginError::UnsupportedProvider
    );
    for label in ["", "invalid\nlabel", "invalid?label"] {
        assert_eq!(
            ProviderLogin::start_with_loopback_test_transport(
                &provider(),
                LoginMode::Loopback,
                label,
                CancelToken::new(),
                fixture.transport()
            )
            .await
            .unwrap_err(),
            LoginError::InvalidLabel
        );
    }
    assert!(fixture.requests().is_empty());
}

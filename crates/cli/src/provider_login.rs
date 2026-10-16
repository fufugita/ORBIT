//! Provider-owned PKCE login with scoped secrets and no configuration writes.

use crate::config::{ProviderConfig, validate_provider_endpoint};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbit_adapter::SecretBytes;
use orbit_provider_http::CancelToken;
use rand::RngCore;
use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use url::Url;
use zeroize::Zeroizing;

pub const OPENROUTER_PROVIDER_URL: &str = "https://openrouter.ai/api/v1";
pub const OPENROUTER_AUTH_URL: &str = "https://openrouter.ai/auth";
pub const OPENROUTER_EXCHANGE_URL: &str = "https://openrouter.ai/api/v1/auth/keys";
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(600);
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
pub const CALLBACK_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 4096;
pub const MAX_CALLBACK_BYTES: usize = 16 * 1024;
pub const MAX_EXCHANGE_BYTES: usize = 64 * 1024;
pub const MAX_INVALID_CALLBACKS: usize = 64;
const MAX_KEY_BYTES: usize = 16 * 1024;
const CALLBACK_PATH: &str = "/callback";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMode {
    Loopback,
    Headless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserOpenOutcome {
    Opened,
    ManualOpenRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LoginError {
    #[error(
        "Browser login is unavailable for this provider endpoint; use an API key or ENV reference"
    )]
    UnsupportedProvider,
    #[error("Login label is invalid")]
    InvalidLabel,
    #[error("Login was canceled; no configuration was changed")]
    Canceled,
    #[error("Login expired; start a new authorization")]
    DeadlineExceeded,
    #[error("Authorization was denied; no configuration was changed")]
    Denied,
    #[error("Login is already used or does not match this login mode")]
    InvalidState,
    #[error("Authorization code is invalid")]
    InvalidCode,
    #[error("Login randomness is unavailable")]
    Randomness,
    #[error("Local callback listener is unavailable")]
    Listener,
    #[error("Too many invalid local callback requests")]
    CallbackLimit,
    #[error("Login HTTP initialization failed")]
    HttpInitialization,
    #[error("Authorization exchange failed")]
    Transport,
    #[error("Authorization exchange timed out; start a new authorization")]
    ExchangeTimeout,
    #[error("Authorization exchange was refused (HTTP {0})")]
    HttpStatus(u16),
    #[error("Authorization exchange response exceeded its byte limit")]
    ResponseLimit,
    #[error("Authorization exchange returned an invalid key response")]
    InvalidResponse,
    #[error("Local login test transport is invalid")]
    InvalidTestTransport,
}

/// An exact supported API origin is required even if the display name differs.
pub fn supports_browser_login(provider: &ProviderConfig) -> bool {
    if provider.kind != "openai-compatible" {
        return false;
    }
    validate_provider_endpoint(&provider.url).is_ok_and(|endpoint| {
        matches!(
            endpoint.as_str(),
            OPENROUTER_PROVIDER_URL | "https://openrouter.ai/api/v1/"
        )
    })
}

/// Explicit fixture capability: numeric IPv4 loopback only, never an ENV or
/// command-line endpoint override. Production constructors do not accept it.
#[derive(Debug)]
pub struct LoopbackTestTransport {
    authorization: Url,
    exchange: Url,
    total_timeout: Duration,
    exchange_timeout: Duration,
    connection_timeout: Duration,
}

impl LoopbackTestTransport {
    pub fn new(origin: Url) -> Result<Self, LoginError> {
        if origin.scheme() != "http"
            || origin.host_str() != Some("127.0.0.1")
            || origin.port().is_none_or(|port| port == 0)
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
        {
            return Err(LoginError::InvalidTestTransport);
        }
        Ok(Self {
            authorization: origin
                .join("auth")
                .map_err(|_| LoginError::InvalidTestTransport)?,
            exchange: origin
                .join("api/v1/auth/keys")
                .map_err(|_| LoginError::InvalidTestTransport)?,
            total_timeout: LOGIN_TIMEOUT,
            exchange_timeout: EXCHANGE_TIMEOUT,
            connection_timeout: CALLBACK_CONNECTION_TIMEOUT,
        })
    }

    /// Fixtures may shorten, never extend, the same production deadlines.
    pub fn with_timeouts(
        mut self,
        total: Duration,
        exchange: Duration,
        connection: Duration,
    ) -> Result<Self, LoginError> {
        if total.is_zero()
            || total > LOGIN_TIMEOUT
            || exchange.is_zero()
            || exchange > EXCHANGE_TIMEOUT
            || connection.is_zero()
            || connection > CALLBACK_CONNECTION_TIMEOUT
        {
            return Err(LoginError::InvalidTestTransport);
        }
        self.total_timeout = total;
        self.exchange_timeout = exchange;
        self.connection_timeout = connection;
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitingCode,
    CodeReady,
    Finished,
}

/// Not cloneable or serializable. Debug deliberately reveals no code or state.
pub struct AuthorizationCode {
    bytes: SecretBytes,
    session: [u8; 32],
}

impl std::fmt::Debug for AuthorizationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizationCode[redacted]")
    }
}

/// Dropping the session closes its owned callback listener and wipes the
/// verifier. No task, callback server or credential record is detached.
pub struct ProviderLogin {
    mode: LoginMode,
    authorization: Url,
    exchange_endpoint: Url,
    callback: Option<Url>,
    listener: Option<TcpListener>,
    verifier: SecretBytes,
    state: SecretBytes,
    session: [u8; 32],
    client: reqwest::Client,
    cancel: CancelToken,
    deadline: Instant,
    exchange_timeout: Duration,
    connection_timeout: Duration,
    phase: Phase,
}

impl std::fmt::Debug for ProviderLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderLogin")
            .field("mode", &self.mode)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl ProviderLogin {
    pub async fn start(
        provider: &ProviderConfig,
        mode: LoginMode,
        key_label: &str,
        cancel: CancelToken,
    ) -> Result<Self, LoginError> {
        let authorization =
            Url::parse(OPENROUTER_AUTH_URL).map_err(|_| LoginError::HttpInitialization)?;
        let exchange =
            Url::parse(OPENROUTER_EXCHANGE_URL).map_err(|_| LoginError::HttpInitialization)?;
        Self::initialize(
            provider,
            mode,
            key_label,
            cancel,
            authorization,
            exchange,
            LOGIN_TIMEOUT,
            EXCHANGE_TIMEOUT,
            CALLBACK_CONNECTION_TIMEOUT,
        )
        .await
    }

    /// Inject an owned local protocol service explicitly. Still requires an
    /// eligible provider declaration; the capability never changes eligibility.
    pub async fn start_with_loopback_test_transport(
        provider: &ProviderConfig,
        mode: LoginMode,
        key_label: &str,
        cancel: CancelToken,
        transport: LoopbackTestTransport,
    ) -> Result<Self, LoginError> {
        Self::initialize(
            provider,
            mode,
            key_label,
            cancel,
            transport.authorization,
            transport.exchange,
            transport.total_timeout,
            transport.exchange_timeout,
            transport.connection_timeout,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn initialize(
        provider: &ProviderConfig,
        mode: LoginMode,
        key_label: &str,
        cancel: CancelToken,
        mut authorization: Url,
        exchange_endpoint: Url,
        total_timeout: Duration,
        exchange_timeout: Duration,
        connection_timeout: Duration,
    ) -> Result<Self, LoginError> {
        if !supports_browser_login(provider) {
            return Err(LoginError::UnsupportedProvider);
        }
        if key_label.is_empty()
            || key_label.len() > 64
            || !key_label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b" ._-".contains(&byte))
        {
            return Err(LoginError::InvalidLabel);
        }
        if cancel.is_cancelled() {
            return Err(LoginError::Canceled);
        }
        let deadline = Instant::now() + total_timeout;
        let mut random = Zeroizing::new([0u8; 96]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut *random)
            .map_err(|_| LoginError::Randomness)?;
        let verifier = SecretBytes::new(URL_SAFE_NO_PAD.encode(&random[..32]).into_bytes());
        let state = SecretBytes::new(URL_SAFE_NO_PAD.encode(&random[32..64]).into_bytes());
        let mut session = [0u8; 32];
        session.copy_from_slice(&random[64..]);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose()));
        let (listener, callback) = if mode == LoginMode::Loopback {
            let listener = bounded(&cancel, deadline, LoginError::DeadlineExceeded, async {
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .map_err(|_| LoginError::Listener)
            })
            .await?;
            let port = listener
                .local_addr()
                .map_err(|_| LoginError::Listener)?
                .port();
            let callback = Url::parse(&format!("http://localhost:{port}{CALLBACK_PATH}"))
                .map_err(|_| LoginError::Listener)?;
            (Some(listener), Some(callback))
        } else {
            (None, None)
        };
        {
            let mut query = authorization.query_pairs_mut();
            if let Some(callback) = &callback {
                query.append_pair("callback_url", callback.as_str());
                query.append_pair(
                    "state",
                    std::str::from_utf8(state.expose()).map_err(|_| LoginError::Randomness)?,
                );
            }
            query.append_pair("code_challenge", &challenge);
            query.append_pair("code_challenge_method", "S256");
            query.append_pair("key_label", key_label);
        }
        let tls = orbit_provider_http::tls::client_config(&orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: None,
        })
        .map_err(|_| LoginError::HttpInitialization)?;
        let tls = std::sync::Arc::try_unwrap(tls).unwrap_or_else(|tls| (*tls).clone());
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(exchange_timeout)
            .build()
            .map_err(|_| LoginError::HttpInitialization)?;
        if cancel.is_cancelled() {
            return Err(LoginError::Canceled);
        }
        if Instant::now() >= deadline {
            return Err(LoginError::DeadlineExceeded);
        }
        Ok(Self {
            mode,
            authorization,
            exchange_endpoint,
            callback,
            listener,
            verifier,
            state,
            session,
            client,
            cancel,
            deadline,
            exchange_timeout,
            connection_timeout,
            phase: Phase::AwaitingCode,
        })
    }

    /// Intended for user presentation or an argv-only browser opener. This URL
    /// contains a challenge and callback state, never a verifier, code or key.
    pub fn authorization_url(&self) -> &Url {
        &self.authorization
    }

    pub fn callback_url(&self) -> Option<&Url> {
        self.callback.as_ref()
    }

    pub fn mode(&self) -> LoginMode {
        self.mode
    }

    pub fn deadline(&self) -> std::time::Instant {
        self.deadline.into_std()
    }

    /// The terminal runner must use this remaining budget while privately
    /// waiting for a headless code; accepting the code rechecks the deadline.
    pub fn remaining(&self) -> Result<Duration, LoginError> {
        self.ready()?;
        Ok(self.deadline.saturating_duration_since(Instant::now()))
    }

    /// Explicit user action only. Failure leaves the same authorization URL
    /// usable for manual opening; it never chooses a different account flow.
    pub async fn open_browser(&self) -> Result<BrowserOpenOutcome, LoginError> {
        self.ready()?;
        open_system_browser(&self.authorization, &self.cancel, self.deadline).await
    }

    fn ready(&self) -> Result<(), LoginError> {
        if self.cancel.is_cancelled() {
            Err(LoginError::Canceled)
        } else if Instant::now() >= self.deadline {
            Err(LoginError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }

    /// Wait for one matching callback. Invalid requests receive a fixed response
    /// without reflected parameters, and cannot trigger an exchange.
    pub async fn wait_for_callback(&mut self) -> Result<AuthorizationCode, LoginError> {
        if let Err(error) = self.ready() {
            self.listener.take();
            self.phase = Phase::Finished;
            return Err(error);
        }
        if self.mode != LoginMode::Loopback || self.phase != Phase::AwaitingCode {
            return Err(LoginError::InvalidState);
        }
        // Taking ownership guarantees closure on cancellation, timeout, future
        // drop or any terminal protocol failure, without a detached server.
        let listener = self.listener.take().ok_or(LoginError::InvalidState)?;
        self.phase = Phase::Finished;
        let callback = self.callback.as_ref().ok_or(LoginError::InvalidState)?;
        let host = format!(
            "localhost:{}",
            callback.port().ok_or(LoginError::InvalidState)?
        );
        let outcome = async {
            let mut invalid = 0;
            loop {
                self.ready()?;
                let (mut stream, peer) =
                    listener.accept().await.map_err(|_| LoginError::Listener)?;
                if !peer.ip().is_loopback() {
                    invalid += 1;
                } else {
                    let connection_deadline =
                        self.deadline.min(Instant::now() + self.connection_timeout);
                    let request = bounded(
                        &self.cancel,
                        connection_deadline,
                        LoginError::Listener,
                        read_callback(&mut stream, &host, self.state.expose()),
                    )
                    .await;
                    match request {
                        Ok(CallbackResult::Code(code)) => {
                            // A disconnected browser does not revoke an already
                            // accepted code; response delivery is best effort.
                            let _ = bounded(
                                &self.cancel,
                                connection_deadline,
                                LoginError::Listener,
                                send_callback_response(&mut stream, true),
                            )
                            .await;
                            return Ok(code);
                        }
                        Ok(CallbackResult::Denied) => {
                            let _ = bounded(
                                &self.cancel,
                                connection_deadline,
                                LoginError::Listener,
                                send_callback_response(&mut stream, false),
                            )
                            .await;
                            return Err(LoginError::Denied);
                        }
                        Err(LoginError::Canceled) => return Err(LoginError::Canceled),
                        Err(_) => {
                            let _ = bounded(
                                &self.cancel,
                                connection_deadline,
                                LoginError::Listener,
                                send_callback_response(&mut stream, false),
                            )
                            .await;
                            invalid += 1;
                        }
                    }
                }
                if invalid >= MAX_INVALID_CALLBACKS {
                    return Err(LoginError::CallbackLimit);
                }
            }
        };
        let result = bounded(
            &self.cancel,
            self.deadline,
            LoginError::DeadlineExceeded,
            outcome,
        )
        .await;
        // listener closes before the caller can start an exchange.
        drop(listener);
        match result {
            Ok(bytes) => {
                self.ready()?;
                self.phase = Phase::CodeReady;
                Ok(AuthorizationCode {
                    bytes,
                    session: self.session,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// The caller obtains these bytes from the same hidden, bounded terminal
    /// reader used for API keys. Headless authorization has no callback state.
    pub fn accept_headless_code(
        &mut self,
        bytes: SecretBytes,
    ) -> Result<AuthorizationCode, LoginError> {
        self.ready()?;
        if self.mode != LoginMode::Headless || self.phase != Phase::AwaitingCode {
            return Err(LoginError::InvalidState);
        }
        if !valid_code(bytes.expose()) {
            return Err(LoginError::InvalidCode);
        }
        self.phase = Phase::CodeReady;
        Ok(AuthorizationCode {
            bytes,
            session: self.session,
        })
    }

    /// Exactly one exchange attempt. A timeout may have minted an API key at the
    /// provider, so it never retries the code or claims remote rollback.
    pub async fn exchange(&mut self, code: AuthorizationCode) -> Result<SecretBytes, LoginError> {
        self.ready()?;
        if self.phase != Phase::CodeReady || !constant_time_equal(&code.session, &self.session) {
            return Err(LoginError::InvalidState);
        }
        self.phase = Phase::Finished;
        let code_text =
            std::str::from_utf8(code.bytes.expose()).map_err(|_| LoginError::InvalidCode)?;
        let verifier =
            std::str::from_utf8(self.verifier.expose()).map_err(|_| LoginError::Randomness)?;
        let request_deadline = self.deadline.min(Instant::now() + self.exchange_timeout);
        let timeout_error = if request_deadline == self.deadline {
            LoginError::DeadlineExceeded
        } else {
            LoginError::ExchangeTimeout
        };
        let operation = async {
            let mut response = self
                .client
                .post(self.exchange_endpoint.clone())
                .json(&ExchangeRequest {
                    code: code_text,
                    code_verifier: verifier,
                    code_challenge_method: "S256",
                })
                .send()
                .await
                .map_err(map_http_error)?;
            if !response.status().is_success() {
                return Err(LoginError::HttpStatus(response.status().as_u16()));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_EXCHANGE_BYTES as u64)
            {
                return Err(LoginError::ResponseLimit);
            }
            let mut body = Zeroizing::new(Vec::with_capacity(MAX_EXCHANGE_BYTES));
            while let Some(chunk) = response.chunk().await.map_err(map_http_error)? {
                if chunk.len() > MAX_EXCHANGE_BYTES.saturating_sub(body.len()) {
                    return Err(LoginError::ResponseLimit);
                }
                body.extend_from_slice(&chunk);
            }
            let response: ExchangeResponse =
                serde_json::from_slice(&body).map_err(|_| LoginError::InvalidResponse)?;
            Ok(response.key)
        };
        let key = bounded(&self.cancel, request_deadline, timeout_error, operation).await?;
        self.ready()?;
        Ok(key)
    }
}

#[derive(Serialize)]
struct ExchangeRequest<'a> {
    code: &'a str,
    code_verifier: &'a str,
    code_challenge_method: &'static str,
}

#[derive(Deserialize)]
struct ExchangeResponse {
    #[serde(deserialize_with = "deserialize_key")]
    key: SecretBytes,
}

fn deserialize_key<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SecretBytes, D::Error> {
    struct KeyVisitor;
    impl Visitor<'_> for KeyVisitor {
        type Value = SecretBytes;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a nonempty header-safe API key")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if !valid_key(value.as_bytes()) {
                return Err(E::custom("invalid API key"));
            }
            Ok(SecretBytes::new(value.as_bytes().to_vec()))
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
            let mut value = Zeroizing::new(value);
            if !valid_key(value.as_bytes()) {
                return Err(E::custom("invalid API key"));
            }
            Ok(SecretBytes::new(std::mem::take(&mut *value).into_bytes()))
        }
    }
    deserializer.deserialize_string(KeyVisitor)
}

fn valid_code(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= MAX_AUTHORIZATION_CODE_BYTES
        && bytes.iter().all(u8::is_ascii_graphic)
}

fn valid_key(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len() <= MAX_KEY_BYTES && bytes.iter().all(u8::is_ascii_graphic)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |different, (left, right)| different | (left ^ right))
        == 0
}

fn map_http_error(error: reqwest::Error) -> LoginError {
    if error.is_timeout() {
        LoginError::ExchangeTimeout
    } else {
        LoginError::Transport
    }
}

async fn bounded<T>(
    cancel: &CancelToken,
    deadline: Instant,
    timeout: LoginError,
    future: impl Future<Output = Result<T, LoginError>>,
) -> Result<T, LoginError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(LoginError::Canceled),
        result = tokio::time::timeout_at(deadline, future) => {
            result.map_err(|_| timeout)?
        }
    }
}

enum CallbackResult {
    Code(SecretBytes),
    Denied,
}

async fn read_callback(
    stream: &mut TcpStream,
    expected_host: &str,
    expected_state: &[u8],
) -> Result<CallbackResult, LoginError> {
    let mut bytes = Zeroizing::new(vec![0u8; MAX_CALLBACK_BYTES]);
    let mut used = 0;
    loop {
        if used == bytes.len() {
            return Err(LoginError::InvalidCode);
        }
        let length = stream
            .read(&mut bytes[used..])
            .await
            .map_err(|_| LoginError::Listener)?;
        if length == 0 {
            return Err(LoginError::InvalidCode);
        }
        used += length;
        if let Some(end) = bytes[..used]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            if end + 4 != used {
                return Err(LoginError::InvalidCode);
            }
            let request =
                std::str::from_utf8(&bytes[..end]).map_err(|_| LoginError::InvalidCode)?;
            return parse_callback(request, expected_host, expected_state);
        }
    }
}

fn parse_callback(
    request: &str,
    expected_host: &str,
    expected_state: &[u8],
) -> Result<CallbackResult, LoginError> {
    let mut lines = request.split("\r\n");
    let mut first = lines.next().ok_or(LoginError::InvalidCode)?.split(' ');
    let method = first.next();
    let target = first.next().ok_or(LoginError::InvalidCode)?;
    if method != Some("GET")
        || first.next() != Some("HTTP/1.1")
        || first.next().is_some()
        || target.len() > MAX_CALLBACK_BYTES - 256
        || target.contains('#')
        || !target.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(LoginError::InvalidCode);
    }
    let (path, query) = target.split_once('?').ok_or(LoginError::InvalidCode)?;
    if path != CALLBACK_PATH {
        return Err(LoginError::InvalidCode);
    }
    let mut host = false;
    let mut header_count = 0;
    for line in lines {
        header_count += 1;
        if header_count > 32 || !line.is_ascii() || line.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(LoginError::InvalidCode);
        }
        let (name, value) = line.split_once(':').ok_or(LoginError::InvalidCode)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(LoginError::InvalidCode);
        }
        let value = value.trim_matches(' ');
        if name.eq_ignore_ascii_case("host") {
            if host || value != expected_host {
                return Err(LoginError::InvalidCode);
            }
            host = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value != "0")
        {
            return Err(LoginError::InvalidCode);
        }
    }
    if !host {
        return Err(LoginError::InvalidCode);
    }
    let mut code = None;
    let mut state = None;
    let mut denial = None;
    let mut description = None;
    let mut count = 0;
    for pair in query.split('&') {
        count += 1;
        if count > 4 {
            return Err(LoginError::InvalidCode);
        }
        let (name, value) = pair.split_once('=').ok_or(LoginError::InvalidCode)?;
        let name = decode_query(name)?;
        let value = decode_query(value)?;
        let slot = match name.as_slice() {
            b"code" => &mut code,
            b"state" => &mut state,
            b"error" => &mut denial,
            b"error_description" => &mut description,
            _ => return Err(LoginError::InvalidCode),
        };
        if slot.is_some() {
            return Err(LoginError::InvalidCode);
        }
        *slot = Some(value);
    }
    if let Some(error) = denial {
        // The provider does not promise state on denial. Treat a denial-shaped
        // callback only as refusal, never as authenticated account information.
        if code.is_some()
            || error.is_empty()
            || error.len() > 128
            || !error.iter().all(u8::is_ascii_graphic)
            || state
                .as_ref()
                .is_some_and(|value| !constant_time_equal(value, expected_state))
            || description.as_ref().is_some_and(|value| {
                value.len() > 1024
                    || value
                        .iter()
                        .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
            })
        {
            return Err(LoginError::InvalidCode);
        }
        return Ok(CallbackResult::Denied);
    }
    if description.is_some() {
        return Err(LoginError::InvalidCode);
    }
    let code = code.ok_or(LoginError::InvalidCode)?;
    let state = state.ok_or(LoginError::InvalidCode)?;
    if !valid_code(&code) || !constant_time_equal(&state, expected_state) {
        return Err(LoginError::InvalidCode);
    }
    let mut code = code;
    Ok(CallbackResult::Code(SecretBytes::new(std::mem::take(
        &mut *code,
    ))))
}

fn decode_query(raw: &str) -> Result<Zeroizing<Vec<u8>>, LoginError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(raw.len()));
    let raw = raw.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let byte = match raw[index] {
            b'+' => b' ',
            b'%' => {
                if index + 2 >= raw.len() {
                    return Err(LoginError::InvalidCode);
                }
                let high = (raw[index + 1] as char)
                    .to_digit(16)
                    .ok_or(LoginError::InvalidCode)?;
                let low = (raw[index + 2] as char)
                    .to_digit(16)
                    .ok_or(LoginError::InvalidCode)?;
                index += 2;
                (high * 16 + low) as u8
            }
            byte => byte,
        };
        bytes.push(byte);
        index += 1;
    }
    Ok(bytes)
}

async fn send_callback_response(stream: &mut TcpStream, success: bool) -> Result<(), LoginError> {
    let response: &[u8] = if success {
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 48\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\nAuthorization received. Return to your terminal."
    } else {
        b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 46\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\nAuthorization not accepted. Use your terminal."
    };
    stream
        .write_all(response)
        .await
        .map_err(|_| LoginError::Listener)?;
    stream.shutdown().await.map_err(|_| LoginError::Listener)
}

#[cfg(target_os = "linux")]
async fn open_system_browser(
    authorization: &Url,
    cancel: &CancelToken,
    deadline: Instant,
) -> Result<BrowserOpenOutcome, LoginError> {
    use std::os::unix::fs::MetadataExt;
    use std::process::{Child, Command, Stdio};

    // Do not search a user-controlled PATH or evaluate a shell command. The
    // distribution's root-owned helper delegates to the configured browser.
    let executable = std::path::Path::new("/usr/bin/xdg-open");
    let Ok(metadata) = executable.metadata() else {
        return Ok(BrowserOpenOutcome::ManualOpenRequired);
    };
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Ok(BrowserOpenOutcome::ManualOpenRequired);
    }
    struct BrowserChild(Child);
    impl Drop for BrowserChild {
        fn drop(&mut self) {
            // Reap the helper even if this future is canceled or dropped. A
            // browser it successfully launches is intentionally user-owned.
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let mut command = Command::new(executable);
    command
        .arg(authorization.as_str())
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in [
        "HOME",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "LANG",
        "LC_CTYPE",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let Ok(child) = command.spawn() else {
        return Ok(BrowserOpenOutcome::ManualOpenRequired);
    };
    let mut child = BrowserChild(child);
    let helper_deadline = deadline.min(Instant::now() + Duration::from_secs(2));
    let wait = async {
        loop {
            match child.0.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(BrowserOpenOutcome::Opened),
                Ok(Some(_)) | Err(_) => return Ok(BrowserOpenOutcome::ManualOpenRequired),
                Ok(None) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    };
    let timeout = if helper_deadline == deadline {
        LoginError::DeadlineExceeded
    } else {
        LoginError::Transport
    };
    match bounded(cancel, helper_deadline, timeout, wait).await {
        Err(LoginError::Transport) => Ok(BrowserOpenOutcome::ManualOpenRequired),
        result => result,
    }
}

#[cfg(not(target_os = "linux"))]
async fn open_system_browser(
    _authorization: &Url,
    _cancel: &CancelToken,
    _deadline: Instant,
) -> Result<BrowserOpenOutcome, LoginError> {
    Ok(BrowserOpenOutcome::ManualOpenRequired)
}

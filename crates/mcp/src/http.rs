//! Bounded Streamable HTTP transport for MCP sessions.

use crate::{MAX_FRAME_BYTES, McpCallOptions, POLL_INTERVAL, encode_frame};
use futures::Future;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::{Duration, Instant};
use url::{Host, Url};

const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_EVENTS: usize = 1024;
const CANCEL_CLEANUP_BUDGET: Duration = Duration::from_millis(75);
const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";
type RpcResult<T> = Result<T, (String, bool)>;

#[derive(Clone)]
pub(super) struct HttpState {
    pub(super) client: reqwest::Client,
    pub(super) endpoint: Url,
    headers: HeaderMap,
    session_id: Option<HeaderValue>,
    protocol_version: Option<HeaderValue>,
}

/// Protocol state is mutated only after the owned HTTP task has completed.
pub(crate) struct HttpTransport {
    state: HttpState,
    alive: bool,
}

impl HttpTransport {
    pub(crate) fn new(url: &str, headers: &BTreeMap<String, String>) -> Result<Self, String> {
        Ok(Self {
            state: HttpState::new(url, headers)?,
            alive: true,
        })
    }

    pub(crate) fn exchange(
        &mut self,
        id: u64,
        method: &str,
        params: Value,
        options: &McpCallOptions,
    ) -> RpcResult<Value> {
        let mut attempted = false;
        let result = (|| {
            options.check().map_err(fatal)?;
            if !self.alive {
                return Err(fatal("mcp transport is retired"));
            }
            let body = encode_frame(&json!({
                "jsonrpc":"2.0", "id":id, "method":method, "params":params
            }))
            .map_err(fatal)?;
            let state = self.state.clone();
            let task_options = options.clone();
            let sent = Arc::new(AtomicBool::new(false));
            let task_sent = sent.clone();
            let response = run_owned(options, async move {
                state.exchange(id, body, &task_options, &task_sent).await
            });
            attempted = sent.load(Ordering::Acquire);
            let cancelled = match &response {
                Err(error) | Ok(Err((error, _))) => {
                    error == "mcp request cancelled" || error == "mcp request timed out"
                }
                _ => false,
            };
            if cancelled && method != "initialize" && attempted {
                // Sending may have reached a server that has not yet returned
                // headers. Unknown request IDs may safely be ignored by it.
                self.cancel_attempted_request(id);
            }
            let (value, session_id) = response.map_err(fatal)??;
            if method == "initialize" {
                let version = value
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fatal("mcp initialize result has no protocol version"))?;
                self.state.set_protocol_version(version).map_err(fatal)?;
                self.state.session_id = session_id;
            }
            Ok(value)
        })();
        if result.as_ref().is_err_and(|(_, fatal)| *fatal) {
            self.retire();
        }
        result.map_err(|(error, fatal)| {
            if fatal && method == "tools/call" {
                let context = if attempted {
                    "tool outcome is unknown; inspect external effects before retrying"
                } else {
                    "no tool request was sent"
                };
                (format!("{error}; {context}"), fatal)
            } else {
                (error, fatal)
            }
        })
    }

    pub(crate) fn notify(
        &mut self,
        method: &str,
        params: Value,
        options: &McpCallOptions,
    ) -> Result<(), String> {
        options.check()?;
        if !self.alive {
            return Err("mcp transport is retired".into());
        }
        let body = encode_frame(&json!({"jsonrpc":"2.0","method":method,"params":params}))?;
        let state = self.state.clone();
        let task_options = options.clone();
        let result = run_owned(options, async move {
            state
                .send_accepted(body, &task_options, &AtomicBool::new(false))
                .await
        })
        .and_then(std::convert::identity);
        if result.is_err() {
            self.retire();
        }
        result
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive
    }

    pub(crate) fn retire(&mut self) {
        self.alive = false;
    }

    fn cancel_attempted_request(&self, id: u64) {
        let Ok(body) = encode_frame(&json!({
            "jsonrpc":"2.0", "method":"notifications/cancelled",
            "params":{"requestId":id,"reason":"caller cancelled or deadline elapsed"}
        })) else {
            return;
        };
        // Cleanup has a separate small budget, including connection and response
        // reads. It does not inherit an already-fired caller cancellation flag.
        // The original request task is drained before this task is started.
        let options = McpCallOptions::new(CANCEL_CLEANUP_BUDGET);
        let task_options = options.clone();
        let state = self.state.clone();
        let _ = run_owned(&options, async move {
            state
                .send_accepted(body, &task_options, &AtomicBool::new(false))
                .await
        });
    }

    /// Explicit teardown obeys the caller's budget; Drop never starts network work.
    pub(crate) fn close(&mut self, options: &McpCallOptions) -> Result<(), String> {
        self.retire();
        if self.state.session_id.is_none() {
            return Ok(());
        }
        options.check()?;
        let state = self.state.clone();
        let task_options = options.clone();
        run_owned(options, async move {
            let response = state
                .request(reqwest::Method::DELETE, state.endpoint.clone())
                .send()
                .await
                .map_err(|_| "mcp HTTP session teardown failed".to_string())?;
            task_options.check()?;
            if response.status().is_success()
                || response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
                || response.status() == reqwest::StatusCode::NOT_FOUND
            {
                Ok(())
            } else {
                Err(status_error(response.status()))
            }
        })?
    }
}

impl HttpState {
    pub(super) fn set_protocol_version(&mut self, version: &str) -> Result<(), String> {
        if !supported_version(version) {
            return Err("mcp server selected an unsupported protocol version".into());
        }
        self.protocol_version = Some(
            HeaderValue::from_str(version)
                .map_err(|_| "mcp initialize result has invalid protocol version")?,
        );
        Ok(())
    }

    pub(super) fn new(url: &str, headers: &BTreeMap<String, String>) -> Result<Self, String> {
        let endpoint = validated_endpoint(url)?;
        let headers = validated_headers(headers)?;
        let tls = orbit_provider_http::tls::client_config(&orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: None,
        })
        .map_err(|_| "mcp HTTP TLS configuration failed".to_string())?;
        let tls = Arc::try_unwrap(tls).unwrap_or_else(|tls| (*tls).clone());
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "mcp HTTP client configuration failed".to_string())?;
        Ok(Self {
            client,
            endpoint,
            headers,
            session_id: None,
            protocol_version: None,
        })
    }

    pub(super) fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .request(method, url)
            .headers(self.headers.clone());
        if let Some(session) = &self.session_id {
            request = request.header(SESSION_HEADER, session.clone());
        }
        if let Some(version) = &self.protocol_version {
            request = request.header(VERSION_HEADER, version.clone());
        }
        request
    }

    async fn exchange(
        mut self,
        id: u64,
        body: Vec<u8>,
        options: &McpCallOptions,
        attempted: &AtomicBool,
    ) -> RpcResult<(Value, Option<HeaderValue>)> {
        let response = self.post(body, options, attempted).await.map_err(fatal)?;
        if !response.status().is_success() {
            return Err(fatal(status_error(response.status())));
        }
        let session = response.headers().get(SESSION_HEADER).cloned();
        if let Some(session) = &session {
            if session.is_empty()
                || session.len() > 4096
                || !session.as_bytes().iter().all(|b| (0x21..=0x7e).contains(b))
            {
                return Err(fatal("mcp HTTP server sent an invalid session identifier"));
            }
            if self
                .session_id
                .as_ref()
                .is_some_and(|current| current != session)
            {
                return Err(fatal("mcp HTTP server changed the session identifier"));
            }
            self.session_id = Some(session.clone());
        }
        match media_type(&response)? {
            kind if kind.eq_ignore_ascii_case("application/json") => {
                let body = bounded_body(response, options).await.map_err(fatal)?;
                let value = parse_message(&body)?;
                match classify_message(value, id)? {
                    Message::Response(result) => result.map(|value| (value, session)),
                    _ => Err(fatal("mcp HTTP JSON response does not match the request")),
                }
            }
            kind if kind.eq_ignore_ascii_case("text/event-stream") => {
                let mut stream = EventStream::new(response);
                while let Some(event) = stream.next(options).await.map_err(fatal)? {
                    if !event.kind.is_empty() && event.kind != "message" {
                        return Err(fatal("mcp HTTP response has an unexpected SSE event type"));
                    }
                    match classify_message(parse_message(&event.data)?, id)? {
                        Message::Response(result) => return result.map(|value| (value, session)),
                        Message::Reply(reply) => {
                            self.send_accepted(
                                encode_frame(&reply).map_err(fatal)?,
                                options,
                                attempted,
                            )
                            .await
                            .map_err(fatal)?;
                        }
                        Message::Ignore => {}
                    }
                }
                Err(fatal("mcp HTTP event stream ended before the response"))
            }
            _ => Err(fatal("mcp HTTP response has an unsupported content type")),
        }
    }

    pub(super) async fn post(
        &self,
        body: Vec<u8>,
        options: &McpCallOptions,
        attempted: &AtomicBool,
    ) -> Result<reqwest::Response, String> {
        options.check()?;
        let request = self
            .request(reqwest::Method::POST, self.endpoint.clone())
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        // Once send is polled the server may have received bytes, even if the
        // HTTP stack never returns response headers. Never retry this operation.
        attempted.store(true, Ordering::Release);
        let response = request
            .send()
            .await
            .map_err(|_| "mcp HTTP request failed".to_string())?;
        options.check()?;
        Ok(response)
    }

    pub(super) async fn send_accepted(
        &self,
        body: Vec<u8>,
        options: &McpCallOptions,
        attempted: &AtomicBool,
    ) -> Result<(), String> {
        let response = self.post(body, options, attempted).await?;
        if response.status() != reqwest::StatusCode::ACCEPTED {
            return Err(if response.status().is_success() {
                "mcp HTTP notification was not accepted with status 202".into()
            } else {
                status_error(response.status())
            });
        }
        if !bounded_body(response, options).await?.is_empty() {
            return Err("mcp HTTP notification response has an unexpected body".into());
        }
        Ok(())
    }
}

pub(super) fn validate_config(url: &str, headers: &BTreeMap<String, String>) -> Result<(), String> {
    validated_endpoint(url)?;
    validated_headers(headers)?;
    Ok(())
}

pub(super) fn validated_endpoint(input: &str) -> Result<Url, String> {
    if input.len() > 8192 {
        return Err("mcp HTTP endpoint exceeds the URL limit".into());
    }
    let url = Url::parse(input).map_err(|_| "mcp HTTP endpoint is invalid".to_string())?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("mcp HTTP endpoint cannot contain user information or a fragment".into());
    }
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(host)) => host == "localhost",
        None => false,
    };
    if !matches!(url.scheme(), "http" | "https") || (url.scheme() == "http" && !loopback) {
        return Err("mcp HTTP endpoint requires HTTPS or explicit loopback HTTP".into());
    }
    if url.host().is_none() {
        return Err("mcp HTTP endpoint has no host".into());
    }
    Ok(url)
}

fn validated_headers(input: &BTreeMap<String, String>) -> Result<HeaderMap, String> {
    if input.len() > MAX_HEADERS {
        return Err("mcp HTTP configuration has too many headers".into());
    }
    let mut headers = HeaderMap::new();
    let mut bytes = 0_usize;
    for (name, value) in input {
        bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
        if bytes > MAX_HEADER_BYTES || name.len() > 128 || value.len() > 8192 {
            return Err("mcp HTTP configuration exceeds the header limit".into());
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "mcp HTTP configuration has an invalid header name".to_string())?;
        if matches!(
            name.as_str(),
            "host"
                | "accept"
                | "content-type"
                | "content-length"
                | "connection"
                | "transfer-encoding"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "upgrade"
                | SESSION_HEADER
                | VERSION_HEADER
        ) {
            return Err("mcp HTTP configuration overrides a transport-owned header".into());
        }
        let mut value = HeaderValue::from_str(value)
            .map_err(|_| "mcp HTTP configuration has an invalid header value".to_string())?;
        value.set_sensitive(true);
        if headers.insert(name, value).is_some() {
            return Err("mcp HTTP configuration repeats a header name".into());
        }
    }
    Ok(headers)
}

pub(super) fn supported_version(version: &str) -> bool {
    matches!(version, PROTOCOL_VERSION | "2025-03-26" | "2024-11-05")
}

pub(super) fn status_error(status: reqwest::StatusCode) -> String {
    match status.as_u16() {
        401 => "mcp HTTP authentication required (401); configure server credentials".into(),
        403 => "mcp HTTP authorization refused (403)".into(),
        404 => "mcp HTTP endpoint or session expired (404)".into(),
        405 => "mcp HTTP method is not supported (405)".into(),
        300..=399 => "mcp HTTP redirect refused".into(),
        code => format!("mcp HTTP server returned status {code}"),
    }
}

pub(super) fn media_type(response: &reqwest::Response) -> RpcResult<&str> {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or("").trim())
        .ok_or_else(|| fatal("mcp HTTP response has no valid content type"))
}

pub(super) async fn bounded_body(
    mut response: reqwest::Response,
    options: &McpCallOptions,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_FRAME_BYTES as u64)
    {
        return Err("mcp HTTP response exceeds 1 MiB".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "mcp HTTP response body failed".to_string())?
    {
        options.check()?;
        if chunk.len() > MAX_FRAME_BYTES.saturating_sub(body.len()) {
            return Err("mcp HTTP response exceeds 1 MiB".into());
        }
        body.extend_from_slice(&chunk);
    }
    options.check()?;
    Ok(body)
}

pub(super) fn fatal(message: impl Into<String>) -> (String, bool) {
    (message.into(), true)
}

pub(super) fn parse_message(bytes: &[u8]) -> RpcResult<Value> {
    serde_json::from_slice(bytes).map_err(|_| fatal("malformed mcp HTTP JSON-RPC frame"))
}

pub(super) enum Message {
    Response(RpcResult<Value>),
    Reply(Value),
    Ignore,
}

pub(super) fn classify_message(value: Value, id: u64) -> RpcResult<Message> {
    let object = value
        .as_object()
        .ok_or_else(|| fatal("mcp frame is not an object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(fatal("mcp frame has invalid jsonrpc version"));
    }
    if let Some(method) = object.get("method") {
        let method = method
            .as_str()
            .ok_or_else(|| fatal("mcp frame has invalid method"))?;
        if object.contains_key("result") || object.contains_key("error") {
            return Err(fatal("mcp request contains response fields"));
        }
        return match object.get("id") {
            None => Ok(Message::Ignore),
            Some(request_id) if valid_id(request_id) => Ok(Message::Reply(if method == "ping" {
                json!({"jsonrpc":"2.0","id":request_id,"result":{}})
            } else {
                json!({"jsonrpc":"2.0","id":request_id,"error":{
                    "code":-32601,"message":"client method not supported"
                }})
            })),
            _ => Err(fatal("mcp server request has invalid id")),
        };
    }
    let response_id = object
        .get("id")
        .filter(|value| valid_id(value))
        .ok_or_else(|| fatal("mcp response has invalid id"))?;
    let result = object.get("result");
    let error = object.get("error");
    if result.is_some() == error.is_some() {
        return Err(fatal("mcp response requires exactly one result or error"));
    }
    if error.is_some_and(|error| {
        error.get("code").and_then(Value::as_i64).is_none()
            || error.get("message").and_then(Value::as_str).is_none()
    }) {
        return Err(fatal("mcp response has invalid error"));
    }
    if response_id.as_u64() != Some(id) {
        return Ok(Message::Ignore);
    }
    Ok(Message::Response(match (result, error) {
        (Some(result), _) => Ok(result.clone()),
        (_, Some(error)) => Err((format!("mcp server error: code {}", error["code"]), false)),
        _ => unreachable!(),
    }))
}

fn valid_id(value: &Value) -> bool {
    value.is_string() || value.is_i64() || value.is_u64()
}

/// The synchronous MCP facade can be called inside any existing Tokio runtime.
/// Its I/O lives on one independent runtime and never uses blocking read tasks.
pub(super) fn run_owned<T: Send + 'static>(
    options: &McpCallOptions,
    future: impl Future<Output = T> + Send + 'static,
) -> Result<T, String> {
    options.check()?;
    static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("orbit-mcp-http")
            .enable_all()
            .build()
            .map_err(|_| "mcp HTTP runtime could not start".to_string())
    });
    let runtime = runtime.as_ref().map_err(Clone::clone)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let task_options = options.clone();
    let task = runtime.spawn(async move {
        let result = {
            let work = future;
            tokio::pin!(work);
            let deadline =
                tokio::time::sleep_until(tokio::time::Instant::from_std(task_options.deadline));
            tokio::pin!(deadline);
            let mut poll = tokio::time::interval(POLL_INTERVAL);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut deadline => break Err("mcp request timed out".to_string()),
                    _ = poll.tick() => {
                        if let Err(error) = task_options.check() { break Err(error); }
                    }
                    result = &mut work => break Ok(result),
                }
            }
        };
        // The work scope drops in-flight responses before sending completion.
        let _ = sender.send(result);
    });
    loop {
        match receiver.recv_timeout(POLL_INTERVAL) {
            Ok(result) => {
                // The sender is the last operation, but allow its enclosing task
                // to release all owned I/O before the synchronous facade returns.
                drain_task(&task);
                return result;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                drain_task(&task);
                return Err("mcp HTTP runtime task stopped".into());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(error) = options.check() {
                    task.abort();
                    drain_task(&task);
                    return Err(error);
                }
            }
        }
    }
}

fn drain_task<T>(task: &tokio::task::JoinHandle<T>) {
    // All task work is async I/O or bounded frame parsing. Abort prevents any
    // subsequent poll; this short drain releases buffers and sockets promptly.
    let limit = Instant::now() + Duration::from_millis(100);
    while !task.is_finished() && Instant::now() < limit {
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub(super) struct SseEvent {
    pub(super) kind: String,
    pub(super) data: Vec<u8>,
}

pub(super) struct EventStream {
    response: reqwest::Response,
    decoder: SseDecoder,
}

impl EventStream {
    pub(super) fn new(response: reqwest::Response) -> Self {
        Self {
            response,
            decoder: SseDecoder::default(),
        }
    }

    /// A persistent legacy stream has one response budget per request. Carry
    /// every already-buffered byte and event into the next request's budget.
    pub(super) fn reset_budget(&mut self) {
        self.decoder.total = self.decoder.events.iter().fold(
            self.decoder
                .buffer
                .len()
                .saturating_add(self.decoder.data.len())
                .saturating_add(self.decoder.kind.len()),
            |total, event| {
                total
                    .saturating_add(event.kind.len())
                    .saturating_add(event.data.len())
            },
        );
        self.decoder.event_count = self.decoder.events.len();
    }

    pub(super) async fn next(
        &mut self,
        options: &McpCallOptions,
    ) -> Result<Option<SseEvent>, String> {
        loop {
            options.check()?;
            if let Some(event) = self.decoder.events.pop_front() {
                return Ok(Some(event));
            }
            match self.response.chunk().await {
                Ok(Some(chunk)) => self.decoder.feed(&chunk)?,
                Ok(None) => {
                    if !self.decoder.buffer.is_empty() || self.decoder.has_data {
                        return Err("mcp SSE stream ended inside an event".into());
                    }
                    return Ok(None);
                }
                Err(_) => return Err("mcp SSE response body failed".into()),
            }
        }
    }
}

#[derive(Default)]
struct SseDecoder {
    buffer: Vec<u8>,
    data: Vec<u8>,
    kind: String,
    has_data: bool,
    skip_next_lf: bool,
    first_line: bool,
    total: usize,
    event_count: usize,
    events: VecDeque<SseEvent>,
}

impl SseDecoder {
    fn feed(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_FRAME_BYTES.saturating_sub(self.total) {
            return Err("mcp SSE response exceeds 1 MiB".into());
        }
        self.total += bytes.len();
        self.buffer.extend_from_slice(bytes);
        let mut start = 0;
        loop {
            if start == self.buffer.len() {
                break;
            }
            if self.skip_next_lf {
                self.skip_next_lf = false;
                if self.buffer[start] == b'\n' {
                    start += 1;
                    continue;
                }
            }
            let Some(relative_end) = self.buffer[start..]
                .iter()
                .position(|b| matches!(b, b'\r' | b'\n'))
            else {
                break;
            };
            let end = start + relative_end;
            self.skip_next_lf = self.buffer[end] == b'\r';
            let line = self.buffer[start..end].to_vec();
            self.line(&line)?;
            start = end + 1;
        }
        self.buffer.drain(..start);
        Ok(())
    }

    fn line(&mut self, bytes: &[u8]) -> Result<(), String> {
        let bytes = if !self.first_line {
            self.first_line = true;
            bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)
        } else {
            bytes
        };
        let line =
            std::str::from_utf8(bytes).map_err(|_| "mcp SSE event is not UTF-8".to_string())?;
        if line.is_empty() {
            if self.has_data {
                self.event_count += 1;
                if self.event_count > MAX_EVENTS {
                    return Err("mcp SSE response contains too many events".into());
                }
                self.data.pop();
                self.events.push_back(SseEvent {
                    kind: std::mem::take(&mut self.kind),
                    data: std::mem::take(&mut self.data),
                });
                self.has_data = false;
            } else {
                self.kind.clear();
            }
            return Ok(());
        }
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                self.has_data = true;
                self.data.extend_from_slice(value.as_bytes());
                self.data.push(b'\n');
            }
            "event" => self.kind = value.into(),
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_sse_decoder_preserves_utf8_multiline_and_split_crlf() {
        let mut decoder = SseDecoder::default();
        decoder.feed(b"\xef\xbb\xbfevent: message\r").unwrap();
        decoder
            .feed("\ndata: {\"word\":\"é\",\r\ndata: \"n\":1}\r\n\r".as_bytes())
            .unwrap();
        assert_eq!(decoder.events.len(), 1);
        decoder.feed(b"\n").unwrap();
        let event = decoder.events.pop_front().unwrap();
        assert_eq!(event.kind, "message");
        assert_eq!(
            serde_json::from_slice::<Value>(&event.data).unwrap(),
            json!({"word":"é","n":1})
        );
        assert!(decoder.events.is_empty());
    }

    #[test]
    fn bounded_sse_decoder_dispatches_cr_only_without_a_later_byte() {
        let mut decoder = SseDecoder::default();
        decoder.feed(b"data: first\r\r").unwrap();
        assert_eq!(decoder.events.pop_front().unwrap().data, b"first");
        assert!(decoder.buffer.is_empty());
        assert!(!decoder.has_data);
        decoder.feed(b"\ndata: second\r").unwrap();
        assert!(decoder.events.is_empty());
        decoder.feed(b"\n\r").unwrap();
        assert_eq!(decoder.events.pop_front().unwrap().data, b"second");
        decoder.feed(b"\n").unwrap();
        assert!(decoder.events.is_empty());
    }

    #[test]
    fn bounded_sse_decoder_rejects_large_and_invalid_utf8_events() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.feed(&vec![b'x'; MAX_FRAME_BYTES + 1]).is_err());
        let mut decoder = SseDecoder::default();
        assert!(decoder.feed(b"data: \xff\n\n").is_err());
    }

    #[test]
    fn endpoint_and_header_validation_do_not_echo_secrets() {
        for endpoint in [
            "http://example.com/mcp",
            "https://secret@example.com/mcp",
            "https://example.com/mcp#secret",
            "file:///secret",
        ] {
            let error = validated_endpoint(endpoint).unwrap_err();
            assert!(!error.contains("secret"));
        }
        assert!(validated_endpoint("http://127.0.0.1:1234/mcp").is_ok());
        assert!(validated_endpoint("http://[::1]:1234/mcp").is_ok());
        assert!(
            validated_headers(&BTreeMap::from([(
                "MCP-Session-Id".into(),
                "secret".into()
            )]))
            .is_err()
        );
        assert!(
            validated_headers(&BTreeMap::from([(
                "Authorization".into(),
                "secret\r\ninjected".into()
            )]))
            .is_err()
        );
        assert!(
            validated_headers(&BTreeMap::from([
                ("X-Test".into(), "a".into()),
                ("x-test".into(), "b".into())
            ]))
            .is_err()
        );
    }
}

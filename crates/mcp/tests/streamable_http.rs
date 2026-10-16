use orbit_mcp::{McpCallOptions, McpPool, McpServerConfig, McpSession, McpTransport};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(handler: impl Fn(&Request, &mut TcpStream) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_millis(500)))
                            .unwrap();
                        if let Some(request) = read_request(&mut stream) {
                            captured.lock().unwrap().push(request.clone());
                            handler(&request, &mut stream);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture listener failed: {error}"),
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/mcp", self.address)
    }

    fn config(&self) -> McpServerConfig {
        serde_json::from_value(json!({
            "transport":"streamable-http", "url":self.url(),
            "headers":{"Authorization":"Bearer fixture-token"},
            "timeout_ms":2000, "initialize_timeout_ms":1500
        }))
        .unwrap()
    }

    fn captured(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut bytes = Vec::new();
    let mut part = [0_u8; 4096];
    let end = loop {
        let count = stream.read(&mut part).ok()?;
        if count == 0 {
            return None;
        }
        bytes.extend_from_slice(&part[..count]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        assert!(bytes.len() <= 16 * 1024, "fixture request header limit");
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap().split_ascii_whitespace();
    let method = first.next().unwrap().to_string();
    let target = first.next().unwrap().to_string();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let size = headers
        .get("content-length")
        .map_or(0, |value| value.parse::<usize>().unwrap());
    assert!(size <= orbit_mcp::MAX_FRAME_BYTES);
    while bytes.len() - end < size {
        let count = stream.read(&mut part).ok()?;
        if count == 0 {
            return None;
        }
        bytes.extend_from_slice(&part[..count]);
    }
    let body = if size == 0 {
        Value::Null
    } else {
        serde_json::from_slice(&bytes[end..end + size]).unwrap()
    };
    Some(Request {
        method,
        target,
        headers,
        body,
    })
}

fn response(stream: &mut TcpStream, status: &str, content_type: &str, headers: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    );
    if stream.write_all(head.as_bytes()).is_ok() {
        // Invalid-size/cancel fixtures deliberately let the client close early.
        let _ = stream.write_all(body);
    }
}

fn open_event_stream(stream: &mut TcpStream, content_type: &str, event: &[u8]) -> TcpStream {
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n", event.len()).unwrap();
    stream.write_all(event).unwrap();
    stream.write_all(b"\r\n").unwrap();
    stream.try_clone().unwrap()
}

fn rpc_response(stream: &mut TcpStream, request: &Request, result: Value) {
    let headers = if request.body["method"] == "initialize" {
        "Mcp-Session-Id: fixture-session\r\n"
    } else {
        ""
    };
    response(
        stream,
        "200 OK",
        "application/json",
        headers,
        &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request.body["id"],"result":result}))
            .unwrap(),
    );
}

fn usual_response(request: &Request, stream: &mut TcpStream) {
    match request.body["method"].as_str() {
        Some("initialize") => rpc_response(
            stream,
            request,
            json!({
                "protocolVersion":"2025-06-18","capabilities":{"tools":{}},
                "serverInfo":{"name":"fixture","version":"1"}
            }),
        ),
        Some("notifications/initialized" | "notifications/cancelled") => {
            response(stream, "202 Accepted", "application/json", "", b"")
        }
        Some("tools/list") => rpc_response(
            stream,
            request,
            json!({"tools":[{
                "name":"echo","description":"fixture echo","inputSchema":{"type":"object"}
            }]}),
        ),
        Some("tools/call") => rpc_response(
            stream,
            request,
            json!({"content":[{
                "type":"text","text":request.body["params"]["arguments"]["text"]
            }]}),
        ),
        _ if request.method == "DELETE" => {
            response(stream, "405 Method Not Allowed", "text/plain", "", b"")
        }
        _ => panic!("unexpected fixture message: {:?}", request.body),
    }
}

#[test]
fn json_tool_call_and_pagination_share_negotiated_session_headers() {
    let server = Server::new(|request, stream| {
        if request.body["method"] == "tools/list" && request.body["params"]["cursor"].is_null() {
            rpc_response(
                stream,
                request,
                json!({"tools":[{"name":"first","inputSchema":{"type":"object"}}],"nextCursor":"next"}),
            );
        } else {
            usual_response(request, stream);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    let tools = pool.list_tools("remote", &config).unwrap();
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "echo"]
    );
    let result = pool
        .call_tool("remote", &config, "echo", json!({"text":"hello"}))
        .unwrap();
    assert_eq!(result["content"][0]["text"], "hello");
    let requests = server.captured();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].body["params"]["protocolVersion"], "2025-06-18");
    assert!(!requests[0].headers.contains_key("mcp-session-id"));
    for request in &requests {
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/mcp");
        assert_eq!(request.headers["authorization"], "Bearer fixture-token");
        assert_eq!(
            request.headers["accept"],
            "application/json, text/event-stream"
        );
    }
    for request in &requests[1..] {
        assert_eq!(request.headers["mcp-session-id"], "fixture-session");
        assert_eq!(request.headers["mcp-protocol-version"], "2025-06-18");
    }
    assert_eq!(requests[1].body["method"], "notifications/initialized");
}

#[test]
fn sse_tool_response_answers_server_request_without_confusing_request_ids() {
    let server = Server::new(|request, stream| {
        if request.body["method"] == "tools/call" {
            let id = &request.body["id"];
            let frames = format!(
                "\u{feff}: keep alive\r\nevent: message\r\ndata: {}\r\n\r\nevent: message\r\ndata: {}\r\n\r\nevent: message\r\ndata: {}\r\n\r\n",
                json!({"jsonrpc":"2.0","id":id,"method":"ping"}),
                json!({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}),
                json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"streamed é"}]}})
            );
            response(
                stream,
                "200 OK",
                "text/event-stream; charset=utf-8",
                "",
                frames.as_bytes(),
            );
        } else if request.body.get("method").is_none() && request.body.get("result").is_some() {
            response(stream, "202 Accepted", "application/json", "", b"");
        } else {
            usual_response(request, stream);
        }
    });
    let result = McpPool::new()
        .call_tool("remote", &server.config(), "echo", json!({}))
        .unwrap();
    assert_eq!(result["content"][0]["text"], "streamed é");
    let requests = server.captured();
    assert_eq!(requests.len(), 4);
    assert!(requests[3].body["result"].is_object());
    assert_eq!(requests[3].body["id"], requests[2].body["id"]);
}

#[test]
fn mixed_case_media_types_and_open_cr_only_stream_complete_without_eof() {
    for sse in [false, true] {
        let held = Arc::new(Mutex::new(None));
        let pending = held.clone();
        let server = Server::new(move |request, stream| {
            if request.body["method"] == "initialize" {
                response(
                    stream,
                    "200 OK",
                    "Application/JSON; Charset=UTF-8",
                    "Mcp-Session-Id: fixture-session\r\n",
                    &serde_json::to_vec(&json!({
                        "jsonrpc":"2.0","id":request.body["id"],"result":{
                            "protocolVersion":"2025-06-18","capabilities":{},
                            "serverInfo":{"name":"fixture","version":"1"}
                        }
                    }))
                    .unwrap(),
                );
            } else if request.body["method"] == "tools/call" {
                let message = json!({"jsonrpc":"2.0","id":request.body["id"],"result":{"content":[{"type":"text","text":"complete"}]}});
                if sse {
                    let event = format!("event: message\rdata: {message}\r\r");
                    *pending.lock().unwrap() = Some(stream.try_clone().unwrap());
                    let _ = open_event_stream(
                        stream,
                        "Text/Event-Stream; charset=UTF-8",
                        event.as_bytes(),
                    );
                } else {
                    response(
                        stream,
                        "200 OK",
                        "aPpLiCaTiOn/JsOn",
                        "",
                        &serde_json::to_vec(&message).unwrap(),
                    );
                }
            } else {
                usual_response(request, stream);
            }
        });
        let start = Instant::now();
        let result = McpPool::new()
            .call_tool_with_options(
                "remote",
                &server.config(),
                "echo",
                json!({}),
                &McpCallOptions::new(Duration::from_millis(500)),
            )
            .unwrap();
        assert_eq!(result["content"][0]["text"], "complete");
        assert!(start.elapsed() < Duration::from_millis(400));
        assert_eq!(server.captured().len(), 3);
        if sse {
            // The server still owns an open chunked response. No EOF or later
            // byte was available to flush the final CR delimiter.
            assert!(held.lock().unwrap().is_some());
            held.lock().unwrap().take();
        }
    }
}

#[test]
fn denied_cancelled_and_expired_calls_send_no_http_requests() {
    let server = Server::new(usual_response);
    let pool = McpPool::new();
    let config = server.config();
    let cancelled = McpCallOptions::new(Duration::from_secs(1)).with_cancel(Arc::new(|| true));
    assert!(
        pool.call_tool_with_options("remote", &config, "echo", json!({}), &cancelled)
            .unwrap_err()
            .contains("no tool request was sent")
    );
    let mut expired = McpCallOptions::new(Duration::from_secs(1));
    expired.deadline = Instant::now() - Duration::from_millis(1);
    assert!(
        pool.call_tool_with_options("remote", &config, "echo", json!({}), &expired)
            .is_err()
    );
    let mut denied = config;
    denied.tools = Some(Vec::new());
    assert!(
        pool.call_tool("remote", &denied, "echo", json!({}))
            .is_err()
    );
    assert!(server.captured().is_empty());
}

#[test]
fn sent_call_with_lost_result_is_not_replayed_and_explicit_next_call_reconnects() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = Server::new(move |request, stream| {
        if request.body["method"] == "tools/call" && observed.fetch_add(1, Ordering::AcqRel) == 0 {
            return;
        }
        usual_response(request, stream);
    });
    let pool = McpPool::new();
    let config = server.config();
    let error = pool
        .call_tool("remote", &config, "echo", json!({"text":"first"}))
        .unwrap_err();
    assert!(error.contains("tool outcome is unknown"), "{error}");
    thread::sleep(Duration::from_millis(30));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(server.captured().len(), 3);
    assert_eq!(
        pool.call_tool("remote", &config, "echo", json!({"text":"second"}))
            .unwrap()["content"][0]["text"],
        "second"
    );
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(
        server
            .captured()
            .iter()
            .filter(|request| request.body["method"] == "initialize")
            .count(),
        2
    );
}

#[test]
fn inflight_cancel_and_timeout_abort_owned_stream_without_replay() {
    for cancel in [true, false] {
        let received = Arc::new(AtomicBool::new(false));
        let observed = received.clone();
        let server = Server::new(move |request, stream| {
            if request.body["method"] == "tools/call" {
                observed.store(true, Ordering::Release);
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
                thread::sleep(Duration::from_millis(250));
            } else {
                usual_response(request, stream);
            }
        });
        let pool = McpPool::new();
        let config = server.config();
        pool.get("remote", &config).unwrap();
        let options = if cancel {
            let received = received.clone();
            McpCallOptions::new(Duration::from_secs(1))
                .with_cancel(Arc::new(move || received.load(Ordering::Acquire)))
        } else {
            McpCallOptions::new(Duration::from_millis(75))
        };
        let started = Instant::now();
        let error = pool
            .call_tool_with_options("remote", &config, "echo", json!({}), &options)
            .unwrap_err();
        assert!(
            error.contains(if cancel { "cancelled" } else { "timed out" }),
            "{error}"
        );
        assert!(error.contains("tool outcome is unknown"));
        assert!(started.elapsed() < Duration::from_millis(225));
        assert!(received.load(Ordering::Acquire));
        assert_eq!(
            server
                .captured()
                .iter()
                .filter(|request| request.body["method"] == "tools/call")
                .count(),
            1
        );
    }
}

fn assert_cancellation_stops_pending_effect(cancel: bool, response_headers: bool) {
    let held = Arc::new(Mutex::new(None));
    let pending_stream = held.clone();
    let pending_effect = Arc::new(AtomicBool::new(false));
    let effect = pending_effect.clone();
    let cancellation_ready = Arc::new(AtomicBool::new(false));
    let observed = cancellation_ready.clone();
    let original_id = Arc::new(Mutex::new(None));
    let request_id = original_id.clone();
    let cancellations = Arc::new(AtomicUsize::new(0));
    let notices = cancellations.clone();
    let server = Server::new(move |request, stream| {
        match request.body["method"].as_str() {
            Some("tools/call") => {
                *request_id.lock().unwrap() = Some(request.body["id"].clone());
                effect.store(true, Ordering::Release);
                if response_headers {
                    let ping = format!(
                        "data: {}\n\n",
                        json!({"jsonrpc":"2.0","id":"pending-proof","method":"ping"})
                    );
                    *pending_stream.lock().unwrap() = Some(open_event_stream(
                        stream,
                        "text/event-stream",
                        ping.as_bytes(),
                    ));
                } else {
                    // Retain the original JSON-handler socket without
                    // sending any HTTP response header or body byte.
                    *pending_stream.lock().unwrap() = Some(stream.try_clone().unwrap());
                    observed.store(true, Ordering::Release);
                }
            }
            Some("notifications/cancelled") => {
                assert_eq!(
                    Some(&request.body["params"]["requestId"]),
                    request_id.lock().unwrap().as_ref()
                );
                notices.fetch_add(1, Ordering::AcqRel);
                effect.store(false, Ordering::Release);
                pending_stream.lock().unwrap().take();
                response(stream, "202 Accepted", "application/json", "", b"");
            }
            None if request.body["id"] == "pending-proof" && request.body["result"].is_object() => {
                response(stream, "202 Accepted", "application/json", "", b"");
                // A client reply proves it received the original response
                // headers and SSE frame before cancellation is requested.
                observed.store(true, Ordering::Release);
            }
            _ => usual_response(request, stream),
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    pool.get("remote", &config).unwrap();
    let options = if cancel {
        let observed = cancellation_ready.clone();
        McpCallOptions::new(Duration::from_secs(1))
            .with_cancel(Arc::new(move || observed.load(Ordering::Acquire)))
    } else {
        McpCallOptions::new(Duration::from_millis(100))
    };
    let started = Instant::now();
    let error = pool
        .call_tool_with_options("remote", &config, "echo", json!({}), &options)
        .unwrap_err();
    assert!(
        error.contains(if cancel { "cancelled" } else { "timed out" }),
        "{error}"
    );
    assert!(error.contains("tool outcome is unknown"));
    assert!(started.elapsed() < Duration::from_millis(300));
    assert!(cancellation_ready.load(Ordering::Acquire));
    assert_eq!(cancellations.load(Ordering::Acquire), 1);
    assert!(!pending_effect.load(Ordering::Acquire));
    assert!(held.lock().unwrap().is_none());
    let requests = server.captured();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.body["method"] == "tools/call")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.body["method"] == "notifications/cancelled")
            .count(),
        1
    );
    let notice = requests
        .iter()
        .find(|request| request.body["method"] == "notifications/cancelled")
        .unwrap();
    assert_eq!(notice.headers["mcp-session-id"], "fixture-session");
    assert_eq!(notice.headers["mcp-protocol-version"], "2025-06-18");
    assert_eq!(notice.headers["authorization"], "Bearer fixture-token");
    assert_eq!(notice.target, "/mcp");
}

#[test]
fn cancellation_notifies_matching_sent_request_and_stops_controlled_pending_effect() {
    for cancel in [true, false] {
        assert_cancellation_stops_pending_effect(cancel, true);
    }
}

#[test]
fn cancellation_reaches_pending_json_handler_before_any_response_headers() {
    for cancel in [true, false] {
        assert_cancellation_stops_pending_effect(cancel, false);
    }
}

#[test]
fn cancelled_initialization_never_sends_a_cancel_notification() {
    let held = Arc::new(Mutex::new(None));
    let pending = held.clone();
    let received = Arc::new(AtomicBool::new(false));
    let observed = received.clone();
    let server = Server::new(move |request, stream| {
        assert_eq!(request.body["method"], "initialize");
        *pending.lock().unwrap() = Some(open_event_stream(
            stream,
            "text/event-stream",
            b": pending\n\n",
        ));
        observed.store(true, Ordering::Release);
    });
    let options = McpCallOptions::new(Duration::from_secs(1))
        .with_cancel(Arc::new(move || received.load(Ordering::Acquire)));
    let error = McpPool::new()
        .get_with_options("remote", &server.config(), &options)
        .unwrap_err();
    assert!(error.contains("cancelled"), "{error}");
    assert_eq!(server.captured().len(), 1);
    held.lock().unwrap().take();
}

#[test]
fn redirects_never_forward_credentials_to_another_endpoint() {
    let destination = Server::new(|_, _| panic!("redirect destination must not be contacted"));
    let target = destination.url();
    let server = Server::new(move |_, stream| {
        response(
            stream,
            "307 Temporary Redirect",
            "text/plain",
            &format!("Location: {target}\r\n"),
            b"fixture-token",
        )
    });
    let error = McpPool::new()
        .call_tool("remote", &server.config(), "echo", json!({}))
        .unwrap_err();
    assert!(error.contains("redirect refused"), "{error}");
    assert!(!error.contains("fixture-token"));
    assert!(destination.captured().is_empty());
    assert_eq!(server.captured().len(), 1);
}

#[test]
fn authentication_and_session_http_errors_are_bounded_and_redacted() {
    for (status, expected) in [
        ("401 Unauthorized", "authentication required"),
        ("403 Forbidden", "authorization refused"),
        ("404 Not Found", "expired"),
        ("405 Method Not Allowed", "not supported"),
    ] {
        let server = Server::new(move |_, stream| {
            response(
                stream,
                status,
                "application/json",
                "WWW-Authenticate: Bearer resource_metadata=\"https://example.invalid/resource\"\r\n",
                b"fixture-token",
            )
        });
        let error = McpPool::new().get("remote", &server.config()).unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("fixture-token"));
        assert_eq!(server.captured().len(), 1);
    }
}

#[test]
fn valid_json_rpc_error_keeps_session_and_does_not_echo_server_secrets() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = Server::new(move |request, stream| {
        if request.body["method"] == "tools/call" && observed.fetch_add(1, Ordering::AcqRel) == 0 {
            response(stream, "200 OK", "application/json", "", &serde_json::to_vec(&json!({
                "jsonrpc":"2.0","id":request.body["id"],"error":{"code":-32602,"message":"fixture-token","data":{"token":"fixture-token"}}
            })).unwrap());
        } else {
            usual_response(request, stream);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    let error = pool
        .call_tool("remote", &config, "echo", json!({}))
        .unwrap_err();
    assert!(error.starts_with("mcp server error:"));
    assert!(!error.contains("fixture-token"));
    assert!(!error.contains("unknown"));
    pool.call_tool("remote", &config, "echo", json!({}))
        .unwrap();
    assert_eq!(
        server
            .captured()
            .iter()
            .filter(|request| request.body["method"] == "initialize")
            .count(),
        1
    );
}

#[test]
fn response_framing_and_protocol_limits_retire_without_replay() {
    for scenario in [
        "large",
        "utf8",
        "wrong-id",
        "batch",
        "partial-sse",
        "wrong-event",
        "case-event",
    ] {
        let server = Server::new(move |request, stream| {
            if request.body["method"] != "tools/call" {
                return usual_response(request, stream);
            }
            match scenario {
                "large" => response(
                    stream,
                    "200 OK",
                    "application/json",
                    "",
                    &vec![b'x'; orbit_mcp::MAX_FRAME_BYTES + 1],
                ),
                "utf8" => response(stream, "200 OK", "text/event-stream", "", b"data: \xff\n\n"),
                "wrong-id" => response(
                    stream,
                    "200 OK",
                    "application/json",
                    "",
                    b"{\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{}}",
                ),
                "batch" => response(stream, "200 OK", "application/json", "", b"[]"),
                "partial-sse" => response(stream, "200 OK", "text/event-stream", "", b"data: {}"),
                "wrong-event" => response(
                    stream,
                    "200 OK",
                    "text/event-stream",
                    "",
                    b"event: endpoint\ndata: /other\n\n",
                ),
                "case-event" => response(
                    stream,
                    "200 OK",
                    "text/event-stream",
                    "",
                    b"event: Message\ndata: {}\n\n",
                ),
                _ => unreachable!(),
            }
        });
        let error = McpPool::new()
            .call_tool("remote", &server.config(), "echo", json!({}))
            .unwrap_err();
        assert!(
            error.contains("tool outcome is unknown"),
            "{scenario}: {error}"
        );
        assert_eq!(server.captured().len(), 3);
    }
}

#[test]
fn synchronous_mcp_facade_can_run_inside_an_existing_tokio_runtime() {
    let server = Server::new(usual_response);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let result = McpPool::new()
            .call_tool(
                "remote",
                &server.config(),
                "echo",
                json!({"text":"nested runtime"}),
            )
            .unwrap();
        assert_eq!(result["content"][0]["text"], "nested runtime");
    });
}

#[test]
fn initialization_rejects_invalid_session_and_unsupported_version() {
    for scenario in ["session", "version"] {
        let server = Server::new(move |request, stream| {
            let headers = if scenario == "session" {
                "Mcp-Session-Id: invalid session\r\n"
            } else {
                ""
            };
            response(stream, "200 OK", "application/json", headers, &serde_json::to_vec(&json!({
                "jsonrpc":"2.0","id":request.body["id"],"result":{"protocolVersion":if scenario == "version" {"2099-01-01"} else {"2025-06-18"}}
            })).unwrap());
        });
        let error = McpPool::new().get("remote", &server.config()).unwrap_err();
        assert!(
            error.contains(if scenario == "session" {
                "invalid session"
            } else {
                "unsupported protocol"
            }),
            "{error}"
        );
        assert_eq!(server.captured().len(), 1);
    }
}

#[test]
fn typed_transport_configuration_preserves_stdio_and_rejects_mixed_fields() {
    let stdio: McpServerConfig =
        serde_json::from_value(json!({"command":"fixture-command"})).unwrap();
    assert_eq!(stdio.transport, McpTransport::Stdio);
    assert!(stdio.url.is_none());
    assert!(stdio.headers.is_empty());
    stdio.validate().unwrap();
    for value in [
        json!({}),
        json!({"command":"fixture-command","url":"https://example.invalid/mcp"}),
        json!({"command":"fixture-command","headers":{"Authorization":"fixture-secret"}}),
        json!({"transport":"streamable-http","url":"https://example.invalid/mcp","command":"fixture-command"}),
        json!({"transport":"streamable-http","url":"https://example.invalid/mcp","args":["--flag"]}),
        json!({"transport":"streamable-http","url":"https://example.invalid/mcp","env":{"TOKEN":"fixture-secret"}}),
        json!({"transport":"streamable-http"}),
        json!({"transport":"streamable-http","url":"http://example.invalid/mcp"}),
        json!({"transport":"streamable-http","url":"https://fixture-secret@example.invalid/mcp"}),
        json!({"transport":"streamable-http","url":"https://example.invalid/mcp","headers":{"Mcp-Session-Id":"fixture-secret"}}),
    ] {
        let config: McpServerConfig = serde_json::from_value(value).unwrap();
        let error = config.validate().unwrap_err();
        assert!(!error.contains("fixture-secret"));
    }
    let legacy: McpServerConfig =
        serde_json::from_value(json!({"transport":"sse","url":"https://example.invalid/events"}))
            .unwrap();
    assert_eq!(legacy.transport, McpTransport::Sse);
    legacy.validate().unwrap();
    assert!(serde_json::from_value::<McpServerConfig>(json!({"transport":"other"})).is_err());
}

#[test]
fn remote_sessions_ignore_process_working_directory() {
    let server = Server::new(usual_response);
    let mut options = McpCallOptions::new(Duration::from_secs(2));
    options.working_dir =
        Some(std::env::temp_dir().join(format!("orbit-absent-{}", ulid::Ulid::new())));
    let result = McpPool::new()
        .call_tool_with_options(
            "remote",
            &server.config(),
            "echo",
            json!({"text":"remote"}),
            &options,
        )
        .unwrap();
    assert_eq!(result["content"][0]["text"], "remote");
}

#[test]
fn explicit_teardown_sends_one_delete_with_session_headers_and_drop_sends_nothing() {
    let server = Server::new(usual_response);
    let mut session = McpSession::spawn("remote", &server.config()).unwrap();
    session
        .close_with_options(&McpCallOptions::new(Duration::from_secs(1)))
        .unwrap();
    assert!(!session.is_alive());
    drop(session);
    let requests = server.captured();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].method, "DELETE");
    assert_eq!(requests[2].headers["mcp-session-id"], "fixture-session");
    assert_eq!(requests[2].headers["mcp-protocol-version"], "2025-06-18");
    assert_eq!(requests[2].headers["authorization"], "Bearer fixture-token");
}

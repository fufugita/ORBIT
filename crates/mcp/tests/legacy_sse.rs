use orbit_mcp::{McpCallOptions, McpPool, McpServerConfig, McpSession};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type Events = Arc<Mutex<Option<TcpStream>>>;

#[derive(Clone)]
struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
    events: Events,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(handler: impl Fn(&Request, &mut TcpStream, &Events) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let events = Arc::new(Mutex::new(None));
        let stream = events.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut connection, _)) => {
                        connection
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .unwrap();
                        connection
                            .set_write_timeout(Some(Duration::from_millis(500)))
                            .unwrap();
                        if let Some(request) = read_request(&mut connection) {
                            captured.lock().unwrap().push(request.clone());
                            handler(&request, &mut connection, &stream);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("legacy fixture listener failed: {error}"),
                }
            }
        });
        Self {
            address,
            requests,
            events,
            stop,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/events", self.address)
    }

    fn config(&self) -> McpServerConfig {
        serde_json::from_value(json!({
            "transport":"sse","url":self.url(),
            "headers":{"Authorization":"Bearer fixture-token"},
            "timeout_ms":2000,"initialize_timeout_ms":1500
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
        self.events.lock().unwrap().take();
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
        assert!(bytes.len() <= 16 * 1024);
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

fn response(stream: &mut TcpStream, status: &str, headers: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    );
    if stream.write_all(head.as_bytes()).is_ok() {
        let _ = stream.write_all(body);
    }
}

fn accepted(stream: &mut TcpStream) {
    response(stream, "202 Accepted", "", b"Accepted");
}

fn write_chunk(stream: &mut TcpStream, bytes: &[u8]) {
    if write!(stream, "{:x}\r\n", bytes.len()).is_ok() && stream.write_all(bytes).is_ok() {
        let _ = stream.write_all(b"\r\n");
    }
}

fn event(events: &Events, kind: &str, data: &str) {
    let message = if kind.is_empty() {
        format!("data: {data}\n\n")
    } else {
        format!("event: {kind}\ndata: {data}\n\n")
    };
    if let Some(stream) = events.lock().unwrap().as_mut() {
        write_chunk(stream, message.as_bytes());
    }
}

fn open_stream(stream: &mut TcpStream, events: &Events) {
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: Text/Event-Stream; charset=UTF-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
    *events.lock().unwrap() = Some(stream.try_clone().unwrap());
}

fn advertise(stream: &mut TcpStream, events: &Events, endpoint: &str) {
    open_stream(stream, events);
    // A final CR must dispatch while the persistent GET stream stays open.
    let advertisement = format!("event: endpoint\rdata: {endpoint}\r\r");
    write_chunk(stream, advertisement.as_bytes());
}

fn rpc_result(events: &Events, request: &Request, result: Value) {
    event(
        events,
        "message",
        &json!({"jsonrpc":"2.0","id":request.body["id"],"result":result}).to_string(),
    );
}

fn usual_response(request: &Request, stream: &mut TcpStream, events: &Events) {
    if request.method == "GET" {
        advertise(stream, events, "/messages?session=fixture");
        return;
    }
    accepted(stream);
    match request.body["method"].as_str() {
        Some("initialize") => rpc_result(
            events,
            request,
            json!({
                "protocolVersion":"2024-11-05","capabilities":{"tools":{}},
                "serverInfo":{"name":"legacy-fixture","version":"1"}
            }),
        ),
        Some("notifications/initialized" | "notifications/cancelled") => {}
        Some("tools/list") => rpc_result(
            events,
            request,
            json!({"tools":[{
                "name":"echo","description":"legacy echo","inputSchema":{"type":"object"}
            }]}),
        ),
        Some("tools/call") => rpc_result(
            events,
            request,
            json!({"content":[{
                "type":"text","text":request.body["params"]["arguments"]["text"]
            }]}),
        ),
        _ => panic!("unexpected legacy fixture message"),
    }
}

#[test]
fn persistent_get_and_validated_post_execute_paginated_tools() {
    let server = Server::new(|request, stream, events| {
        if request.body["method"] == "tools/list" && request.body["params"]["cursor"].is_null() {
            accepted(stream);
            rpc_result(
                events,
                request,
                json!({"tools":[{"name":"first","inputSchema":{"type":"object"}}],"nextCursor":"next"}),
            );
        } else {
            usual_response(request, stream, events);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    let tools = pool.list_tools("legacy", &config).unwrap();
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "echo"]
    );
    for text in ["first", "second"] {
        assert_eq!(
            pool.call_tool("legacy", &config, "echo", json!({"text":text}))
                .unwrap()["content"][0]["text"],
            text
        );
    }
    let requests = server.captured();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        1
    );
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[0].target, "/events");
    for request in &requests {
        assert_eq!(request.headers["authorization"], "Bearer fixture-token");
    }
    for request in &requests[1..] {
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/messages?session=fixture");
    }
    assert!(!requests[1].headers.contains_key("mcp-protocol-version"));
    for request in &requests[2..] {
        assert_eq!(request.headers["mcp-protocol-version"], "2024-11-05");
    }
}

#[test]
fn advertised_cross_origin_userinfo_and_fragment_endpoints_receive_no_post() {
    for scenario in ["origin", "userinfo", "fragment", "scheme"] {
        let destination = Server::new(|_, _, _| panic!("unvalidated endpoint contacted"));
        let endpoint = match scenario {
            "origin" => destination.url(),
            "userinfo" => destination
                .url()
                .replacen("http://", "http://fixture-secret@", 1),
            "fragment" => "/messages#fixture-secret".into(),
            "scheme" => destination.url().replacen("http://", "https://", 1),
            _ => unreachable!(),
        };
        let source = Server::new(move |_, stream, events| advertise(stream, events, &endpoint));
        let error = McpPool::new().get("legacy", &source.config()).unwrap_err();
        assert!(!error.contains("fixture-secret"));
        assert!(destination.captured().is_empty());
        let requests = source.captured();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
    }
}

#[test]
fn get_and_post_redirects_never_forward_authentication() {
    for redirect_get in [true, false] {
        let destination = Server::new(|_, _, _| panic!("redirect followed"));
        let target = destination.url();
        let source = Server::new(move |request, stream, events| {
            if request.method == "GET" && !redirect_get {
                advertise(stream, events, "/messages");
            } else {
                response(
                    stream,
                    "307 Temporary Redirect",
                    &format!("Location: {target}\r\n"),
                    b"fixture-token",
                );
            }
        });
        let error = McpPool::new().get("legacy", &source.config()).unwrap_err();
        assert!(error.contains("redirect refused"), "{error}");
        assert!(!error.contains("fixture-token"));
        assert!(destination.captured().is_empty());
        assert_eq!(source.captured().len(), if redirect_get { 1 } else { 2 });
    }
}

#[test]
fn sent_call_losing_get_stream_is_not_replayed_and_next_explicit_call_reconnects() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = Server::new(move |request, stream, events| {
        if request.body["method"] == "tools/call" && observed.fetch_add(1, Ordering::AcqRel) == 0 {
            accepted(stream);
            events.lock().unwrap().take();
        } else {
            usual_response(request, stream, events);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    let error = pool
        .call_tool("legacy", &config, "echo", json!({"text":"first"}))
        .unwrap_err();
    assert!(error.contains("tool outcome is unknown"), "{error}");
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(
        server
            .captured()
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        1
    );
    assert_eq!(
        pool.call_tool("legacy", &config, "echo", json!({"text":"second"}))
            .unwrap()["content"][0]["text"],
        "second"
    );
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(
        server
            .captured()
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        2
    );
}

#[test]
fn cancellation_and_timeout_notify_once_and_stop_controlled_pending_effect() {
    for cancel in [true, false] {
        let pending = Arc::new(AtomicBool::new(false));
        let effect = pending.clone();
        let received = Arc::new(AtomicBool::new(false));
        let ready = received.clone();
        let id = Arc::new(Mutex::new(None));
        let expected_id = id.clone();
        let server =
            Server::new(
                move |request, stream, events| match request.body["method"].as_str() {
                    Some("tools/call") => {
                        *expected_id.lock().unwrap() = Some(request.body["id"].clone());
                        effect.store(true, Ordering::Release);
                        accepted(stream);
                        ready.store(true, Ordering::Release);
                    }
                    Some("notifications/cancelled") => {
                        assert_eq!(
                            Some(&request.body["params"]["requestId"]),
                            expected_id.lock().unwrap().as_ref()
                        );
                        effect.store(false, Ordering::Release);
                        accepted(stream);
                    }
                    _ => usual_response(request, stream, events),
                },
            );
        let pool = McpPool::new();
        let config = server.config();
        pool.get("legacy", &config).unwrap();
        let options = if cancel {
            let ready = received.clone();
            McpCallOptions::new(Duration::from_secs(1))
                .with_cancel(Arc::new(move || ready.load(Ordering::Acquire)))
        } else {
            McpCallOptions::new(Duration::from_millis(100))
        };
        let started = Instant::now();
        let error = pool
            .call_tool_with_options("legacy", &config, "echo", json!({}), &options)
            .unwrap_err();
        assert!(
            error.contains(if cancel { "cancelled" } else { "timed out" }),
            "{error}"
        );
        assert!(error.contains("tool outcome is unknown"));
        assert!(started.elapsed() < Duration::from_millis(300));
        assert!(!pending.load(Ordering::Acquire));
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
        assert_eq!(notice.target, "/messages?session=fixture");
        assert_eq!(notice.headers["authorization"], "Bearer fixture-token");
        assert_eq!(notice.headers["mcp-protocol-version"], "2024-11-05");
    }
}

#[test]
fn presend_cancel_expiry_and_denied_tools_make_no_connection() {
    let server = Server::new(usual_response);
    let pool = McpPool::new();
    let config = server.config();
    let cancelled = McpCallOptions::new(Duration::from_secs(1)).with_cancel(Arc::new(|| true));
    assert!(
        pool.call_tool_with_options("legacy", &config, "echo", json!({}), &cancelled)
            .is_err()
    );
    let mut expired = McpCallOptions::new(Duration::from_secs(1));
    expired.deadline = Instant::now() - Duration::from_millis(1);
    assert!(
        pool.call_tool_with_options("legacy", &config, "echo", json!({}), &expired)
            .is_err()
    );
    let mut denied = config;
    denied.tools = Some(Vec::new());
    assert!(
        pool.call_tool("legacy", &denied, "echo", json!({}))
            .is_err()
    );
    assert!(server.captured().is_empty());
}

#[test]
fn initialization_cancellation_never_sends_cancel_notification() {
    let ready = Arc::new(AtomicBool::new(false));
    let received = ready.clone();
    let server = Server::new(move |request, stream, events| {
        if request.body["method"] == "initialize" {
            accepted(stream);
            received.store(true, Ordering::Release);
        } else {
            usual_response(request, stream, events);
        }
    });
    let options = McpCallOptions::new(Duration::from_secs(1))
        .with_cancel(Arc::new(move || ready.load(Ordering::Acquire)));
    let error = McpPool::new()
        .get_with_options("legacy", &server.config(), &options)
        .unwrap_err();
    assert!(error.contains("cancelled"), "{error}");
    let requests = server.captured();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].body["method"], "initialize");
}

#[test]
fn malformed_missing_and_repeated_endpoint_advertisements_fail_boundedly() {
    for scenario in ["wrong-first", "missing", "large", "repeat"] {
        let server = Server::new(move |request, stream, events| {
            if request.method == "GET" {
                match scenario {
                    "wrong-first" => {
                        open_stream(stream, events);
                        event(events, "message", "{}");
                    }
                    "missing" => open_stream(stream, events),
                    "large" => advertise(stream, events, &format!("/{}", "x".repeat(8192))),
                    "repeat" => {
                        advertise(stream, events, "/messages");
                        event(events, "endpoint", "/other");
                    }
                    _ => unreachable!(),
                }
            } else {
                usual_response(request, stream, events);
            }
        });
        let options = McpCallOptions::new(Duration::from_millis(150));
        let error = McpPool::new()
            .get_with_options("legacy", &server.config(), &options)
            .unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(
            server
                .captured()
                .iter()
                .filter(|request| request.method == "GET")
                .count(),
            1
        );
    }
}

#[test]
fn persistent_stream_has_per_request_bounds_without_a_lifetime_cutoff() {
    let server = Server::new(|request, stream, events| {
        if request.body["method"] == "tools/call" {
            accepted(stream);
            rpc_result(
                events,
                request,
                json!({"content":[{"type":"text","text":"x".repeat(600 * 1024)}]}),
            );
        } else {
            usual_response(request, stream, events);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    for _ in 0..2 {
        let result = pool
            .call_tool("legacy", &config, "echo", json!({}))
            .unwrap();
        assert_eq!(
            result["content"][0]["text"].as_str().unwrap().len(),
            600 * 1024
        );
    }
    assert_eq!(
        server
            .captured()
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        1
    );
}

#[test]
fn invalid_and_oversized_message_events_retire_without_replay() {
    for scenario in ["utf8", "json", "large", "case"] {
        let server = Server::new(move |request, stream, events| {
            if request.body["method"] == "tools/call" {
                accepted(stream);
                match scenario {
                    "utf8" => {
                        if let Some(stream) = events.lock().unwrap().as_mut() {
                            write_chunk(stream, b"event: message\ndata: \xff\n\n");
                        }
                    }
                    "json" => event(events, "message", "{"),
                    "large" => event(
                        events,
                        "message",
                        &"x".repeat(orbit_mcp::MAX_FRAME_BYTES + 1),
                    ),
                    "case" => event(events, "Message", "{}"),
                    _ => unreachable!(),
                }
            } else {
                usual_response(request, stream, events);
            }
        });
        let error = McpPool::new()
            .call_tool("legacy", &server.config(), "echo", json!({}))
            .unwrap_err();
        assert!(
            error.contains("tool outcome is unknown"),
            "{scenario}: {error}"
        );
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

#[test]
fn server_ping_ids_do_not_alias_client_responses_and_default_message_events_work() {
    let server = Server::new(|request, stream, events| {
        if request.body["method"] == "tools/call" {
            accepted(stream);
            event(
                events,
                "message",
                &json!({"jsonrpc":"2.0","id":request.body["id"],"method":"ping"}).to_string(),
            );
            event(events, "", &json!({"jsonrpc":"2.0","id":request.body["id"],"result":{"content":[{"type":"text","text":"actual result"}]}}).to_string());
        } else if request.body.get("method").is_none() && request.body["result"].is_object() {
            accepted(stream);
        } else {
            usual_response(request, stream, events);
        }
    });
    let result = McpPool::new()
        .call_tool("legacy", &server.config(), "echo", json!({}))
        .unwrap();
    assert_eq!(result["content"][0]["text"], "actual result");
    let requests = server.captured();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[4].body["id"], requests[3].body["id"]);
    assert!(requests[4].body["result"].is_object());
}

#[test]
fn server_ping_before_original_post_acknowledgement_does_not_deadlock() {
    let pending = Arc::new(Mutex::new(None));
    let held = pending.clone();
    let server = Server::new(move |request, stream, events| {
        if request.body["method"] == "tools/call" {
            *held.lock().unwrap() = Some((stream.try_clone().unwrap(), request.body["id"].clone()));
            event(
                events,
                "message",
                &json!({"jsonrpc":"2.0","id":"ack-proof","method":"ping"}).to_string(),
            );
        } else if request.body.get("method").is_none() && request.body["id"] == "ack-proof" {
            assert!(request.body["result"].is_object());
            accepted(stream);
            let (mut original, id) = held.lock().unwrap().take().unwrap();
            accepted(&mut original);
            event(events, "message", &json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"completed after ping"}]}}).to_string());
        } else {
            usual_response(request, stream, events);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    pool.get("legacy", &config).unwrap();
    let result = pool
        .call_tool_with_options(
            "legacy",
            &config,
            "echo",
            json!({}),
            &McpCallOptions::new(Duration::from_millis(500)),
        )
        .unwrap();
    assert_eq!(result["content"][0]["text"], "completed after ping");
    assert!(pending.lock().unwrap().is_none());
    assert_eq!(
        server
            .captured()
            .iter()
            .filter(|request| request.body["method"] == "tools/call")
            .count(),
        1
    );
}

#[test]
fn initialized_notification_services_server_ping_before_its_post_acknowledgement() {
    let pending = Arc::new(Mutex::new(None));
    let held = pending.clone();
    let server = Server::new(move |request, stream, events| {
        if request.body["method"] == "notifications/initialized" {
            *held.lock().unwrap() = Some(stream.try_clone().unwrap());
            event(
                events,
                "message",
                &json!({"jsonrpc":"2.0","id":"initialized-ping","method":"ping"}).to_string(),
            );
        } else if request.body.get("method").is_none() && request.body["id"] == "initialized-ping" {
            assert!(request.body["result"].is_object());
            accepted(stream);
            let mut notification = held.lock().unwrap().take().unwrap();
            accepted(&mut notification);
        } else {
            usual_response(request, stream, events);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    pool.get_with_options(
        "legacy",
        &config,
        &McpCallOptions::new(Duration::from_millis(500)),
    )
    .unwrap();
    assert!(pending.lock().unwrap().is_none());
    assert_eq!(
        pool.call_tool(
            "legacy",
            &config,
            "echo",
            json!({"text":"after initialization"})
        )
        .unwrap()["content"][0]["text"],
        "after initialization"
    );
    let requests = server.captured();
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.body["method"] == "initialize")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.body["method"] == "notifications/initialized")
            .count(),
        1
    );
    let reply = requests
        .iter()
        .find(|request| request.body["id"] == "initialized-ping")
        .unwrap();
    assert!(reply.body["result"].is_object());
}

#[test]
fn two_server_ping_replies_progress_when_first_acknowledgement_depends_on_second() {
    let replies = Arc::new(Mutex::new(BTreeMap::new()));
    let held = replies.clone();
    let original = Arc::new(Mutex::new(None));
    let original_id = original.clone();
    let server = Server::new(move |request, stream, events| {
        if request.body["method"] == "tools/call" {
            *original_id.lock().unwrap() = Some(request.body["id"].clone());
            accepted(stream);
            for id in ["pipeline-a", "pipeline-b"] {
                event(
                    events,
                    "message",
                    &json!({"jsonrpc":"2.0","id":id,"method":"ping"}).to_string(),
                );
            }
        } else if request.body.get("method").is_none() && request.body["result"].is_object() {
            let id = request.body["id"].as_str().unwrap();
            assert!(matches!(id, "pipeline-a" | "pipeline-b"));
            let mut pending = held.lock().unwrap();
            assert!(
                pending
                    .insert(id.to_string(), stream.try_clone().unwrap())
                    .is_none()
            );
            if pending.len() == 2 {
                for (_, mut reply) in std::mem::take(&mut *pending) {
                    accepted(&mut reply);
                }
                let id = original_id.lock().unwrap().take().unwrap();
                event(events, "message", &json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"duplex complete"}]}}).to_string());
            }
        } else {
            usual_response(request, stream, events);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    pool.get("legacy", &config).unwrap();
    let result = pool
        .call_tool_with_options(
            "legacy",
            &config,
            "echo",
            json!({}),
            &McpCallOptions::new(Duration::from_millis(500)),
        )
        .unwrap();
    assert_eq!(result["content"][0]["text"], "duplex complete");
    assert!(replies.lock().unwrap().is_empty());
    let requests = server.captured();
    let mut ids: Vec<&str> = requests
        .iter()
        .filter(|request| {
            request.body.get("method").is_none() && request.body["result"].is_object()
        })
        .map(|request| request.body["id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, ["pipeline-a", "pipeline-b"]);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.body["method"] == "initialize")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.body["method"] == "tools/call")
            .count(),
        1
    );
}

#[test]
fn valid_rpc_error_keeps_the_stream_and_redacts_server_error_data() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = Server::new(move |request, stream, events| {
        if request.body["method"] == "tools/call" && observed.fetch_add(1, Ordering::AcqRel) == 0 {
            accepted(stream);
            event(events, "message", &json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-32602,"message":"fixture-secret"}}).to_string());
        } else {
            usual_response(request, stream, events);
        }
    });
    let pool = McpPool::new();
    let config = server.config();
    let error = pool
        .call_tool("legacy", &config, "echo", json!({}))
        .unwrap_err();
    assert!(error.starts_with("mcp server error:"));
    assert!(!error.contains("fixture-secret"));
    pool.call_tool("legacy", &config, "echo", json!({}))
        .unwrap();
    assert_eq!(
        server
            .captured()
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        1
    );
}

#[test]
fn explicit_close_and_drop_only_close_the_get_stream() {
    let server = Server::new(usual_response);
    let mut session = McpSession::spawn("legacy", &server.config()).unwrap();
    session
        .close_with_options(&McpCallOptions::new(Duration::from_secs(1)))
        .unwrap();
    assert!(!session.is_alive());
    drop(session);
    let requests = server.captured();
    assert_eq!(requests.len(), 3);
    assert!(!requests.iter().any(|request| request.method == "DELETE"));
}

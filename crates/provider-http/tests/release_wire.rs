use futures::StreamExt;
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, ChatMessage, ChatRole, ContentBlock, DeploymentId,
    EndpointScheme, ProviderEventKind, ProviderId, ProviderRequest, ProviderRouteBinding,
    ProviderStreamEvent, RegionId, Sha256Digest, TlsPinPolicy, ToolCallMessage,
};
use orbit_provider_http::{
    AnthropicMessagesV1, AsyncProviderAdapter, CancelToken, OllamaHttpV1, OpenAiCompatibleHttpV1,
    anthropic::{anthropic_capabilities, anthropic_identity},
    openai::{openai_capabilities, openai_identity},
    sse::SseParser,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a9X8AAAAASUVORK5CYII=";
const MAX_CAPTURE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum Family {
    OpenAi,
    Anthropic,
    Ollama,
}

fn adapter(family: Family) -> Box<dyn AsyncProviderAdapter> {
    match family {
        Family::OpenAi => Box::new(
            OpenAiCompatibleHttpV1::new(
                openai_identity(),
                openai_capabilities(),
                TlsPinPolicy {
                    webpki: false,
                    spki_sha256: None,
                },
            )
            .unwrap(),
        ),
        Family::Anthropic => Box::new(
            AnthropicMessagesV1::new(anthropic_identity(), anthropic_capabilities()).unwrap(),
        ),
        Family::Ollama => Box::new(
            OllamaHttpV1::new(
                AdapterIdentity {
                    kind: AdapterKind::LocalProcessV1,
                    implementation_digest: Sha256Digest("o".repeat(64)),
                    profile_digest: Sha256Digest("l".repeat(64)),
                },
                openai_capabilities(),
            )
            .unwrap(),
        ),
    }
}

fn request(adapter: &dyn AsyncProviderAdapter, port: u16) -> ProviderRequest {
    let identity = adapter.identity();
    let route = ProviderRouteBinding {
        provider_id: ProviderId("wire-fixture".into()),
        deployment_id: DeploymentId("wire-fixture".into()),
        region_id: RegionId("wire-fixture".into()),
        adapter_kind: identity.kind,
        adapter_implementation_digest: identity.implementation_digest,
        adapter_profile_digest: identity.profile_digest,
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: "raw-model/unchanged".into(),
        pricing_digest: Sha256Digest("p".repeat(64)),
        endpoint_host: "127.0.0.1".into(),
        endpoint_port: port,
        endpoint_scheme: EndpointScheme::HttpLoopback,
        endpoint_path: String::new(),
    };
    let mut request = canonical_request(&route, b"original input");
    request.connect_timeout_ms = 1000;
    request.first_byte_timeout_ms = 1000;
    request.idle_timeout_ms = 1000;
    request
}

fn message(role: ChatRole, content: &str) -> ChatMessage {
    ChatMessage {
        role,
        content: content.into(),
        blocks: None,
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
        origin_model: None,
        origin_provider: None,
    }
}

// Own one loopback listener and one bounded request. Dropping the test aborts
// its task; no host accounts, environment credentials or external endpoints.
struct Mock {
    port: u16,
    task: tokio::task::JoinHandle<Option<Value>>,
}

impl Mock {
    async fn new(body: String, family: Family) -> Self {
        Self::scripted(body, family, None).await
    }

    async fn held(body: String, trailer: Option<String>) -> Self {
        Self::scripted(body, Family::OpenAi, Some(trailer)).await
    }

    async fn scripted(body: String, family: Family, held: Option<Option<String>>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_millis(400), listener.accept()).await
            else {
                return None;
            };
            let mut raw = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 2048];
                let count = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut chunk))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(count > 0, "request headers must complete");
                assert!(raw.len() + count <= MAX_CAPTURE, "bounded request capture");
                raw.extend_from_slice(&chunk[..count]);
                if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = std::str::from_utf8(&raw[..header_end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .expect("JSON POST content length");
            assert!(header_end + length <= MAX_CAPTURE);
            while raw.len() < header_end + length {
                let mut chunk = [0u8; 2048];
                let count = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut chunk))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(count > 0, "request body must complete");
                raw.extend_from_slice(&chunk[..count]);
                assert!(raw.len() <= MAX_CAPTURE);
            }
            let captured = serde_json::from_slice(&raw[header_end..header_end + length]).unwrap();
            let media = match family {
                Family::Ollama => "application/x-ndjson",
                _ => "text/event-stream",
            };
            let headers = if held.is_some() {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                )
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
            };
            socket.write_all(headers.as_bytes()).await.unwrap();
            if let Some(trailer) = held {
                let frame = format!("{:x}\r\n{body}\r\n", body.len());
                if socket.write_all(frame.as_bytes()).await.is_ok() {
                    if let Some(trailer) = trailer {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        let frame = format!("{:x}\r\n{trailer}\r\n", trailer.len());
                        let _ = socket.write_all(frame.as_bytes()).await;
                    }
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    let _ = socket.write_all(b"0\r\n\r\n").await;
                }
                let _ = socket.shutdown().await;
                return Some(captured);
            }
            // Small writes exercise real HTTP collection while deterministic
            // parser tests below force every individual byte boundary.
            for part in body.as_bytes().chunks(19) {
                if socket.write_all(part).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let _ = socket.shutdown().await;
            Some(captured)
        });
        Self { port, task }
    }

    async fn captured(&mut self) -> Option<Value> {
        tokio::time::timeout(Duration::from_secs(4), &mut self.task)
            .await
            .expect("fixture deadline")
            .expect("fixture task")
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn drain(
    adapter: &dyn AsyncProviderAdapter,
    request: &ProviderRequest,
) -> Result<Vec<ProviderStreamEvent>, AdapterError> {
    let cancel = CancelToken::new();
    let mut stream = adapter.invoke(request, None, &cancel).await?;
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event?);
    }
    orbit_adapter::stream::validate_stream(&events)?;
    Ok(events)
}

fn sse(value: Value) -> String {
    format!("data: {value}\n\n")
}

fn openai_delta(delta: Value) -> String {
    sse(json!({"choices":[{"index":0,"delta":delta,"finish_reason":null}]}))
}

fn openai_reason(reason: &str) -> String {
    sse(json!({"choices":[{"index":0,"delta":{},"finish_reason":reason}]}))
}

fn terminal(events: &[ProviderStreamEvent]) -> Option<&str> {
    events.iter().find_map(|event| match &event.event {
        ProviderEventKind::Finished { finish_reason, .. } => finish_reason.as_deref(),
        _ => None,
    })
}

fn final_usage(events: &[ProviderStreamEvent]) -> Option<orbit_adapter::types::ProviderUsage> {
    events.iter().find_map(|event| match event.event {
        ProviderEventKind::Finished { final_usage, .. } => final_usage,
        _ => None,
    })
}

fn anthropic_response(
    initial_usage: Option<Value>,
    final_usage: Option<Value>,
    blocks: Vec<Value>,
) -> String {
    let mut start = json!({"type":"message_start","message":{"id":"message-fixture","role":"assistant","content":[]}});
    if let Some(usage) = initial_usage {
        start["message"]["usage"] = usage;
    }
    let mut body = sse(start);
    for (index, block) in blocks.into_iter().enumerate() {
        body.push_str(&sse(
            json!({"type":"content_block_start","index":index,"content_block":block}),
        ));
        body.push_str(&sse(json!({"type":"content_block_stop","index":index})));
    }
    let mut delta = json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}});
    if let Some(usage) = final_usage {
        delta["usage"] = usage;
    }
    body.push_str(&sse(delta));
    body.push_str(&sse(json!({"type":"message_stop"})));
    body
}

fn text(events: &[ProviderStreamEvent]) -> String {
    let bytes: Vec<u8> = events
        .iter()
        .flat_map(|event| match &event.event {
            ProviderEventKind::TextDelta { bytes } => bytes.as_slice(),
            _ => &[],
        })
        .copied()
        .collect();
    String::from_utf8(bytes).unwrap()
}

fn calls(events: &[ProviderStreamEvent]) -> Vec<(u32, String, String, Value)> {
    let mut calls = std::collections::BTreeMap::new();
    let mut finished = std::collections::BTreeSet::new();
    for event in events {
        match &event.event {
            ProviderEventKind::ToolCallStarted {
                call_index,
                provider_call_id,
                name,
            } => {
                assert!(
                    calls
                        .insert(
                            *call_index,
                            (
                                provider_call_id.clone().unwrap_or_default(),
                                name.clone(),
                                Vec::new()
                            )
                        )
                        .is_none(),
                    "one start per call"
                );
            }
            ProviderEventKind::ToolCallArgumentsDelta { call_index, bytes } => {
                calls
                    .get_mut(call_index)
                    .expect("start before arguments")
                    .2
                    .extend_from_slice(bytes);
            }
            ProviderEventKind::ToolCallFinished { call_index } => {
                assert!(calls.contains_key(call_index), "start before finish");
                assert!(finished.insert(*call_index), "one finish per call");
            }
            _ => {}
        }
    }
    assert_eq!(calls.len(), finished.len(), "every call completes");
    calls
        .into_iter()
        .map(|(index, (id, name, bytes))| {
            assert!(!id.is_empty());
            assert!(!name.is_empty());
            let args: Value = serde_json::from_slice(&bytes).expect("complete JSON arguments");
            assert!(args.is_object());
            (index, id, name, args)
        })
        .collect()
}

#[tokio::test]
async fn content_openai_preserves_original_mixed_blocks() {
    let adapter = adapter(Family::OpenAi);
    let mut mock = Mock::new(openai_reason("stop"), Family::OpenAi).await;
    let mut request = request(adapter.as_ref(), mock.port);
    let mut user = message(ChatRole::User, "flattened display must not replace blocks");
    user.blocks = Some(vec![
        ContentBlock::Text {
            text: "before λ".into(),
        },
        ContentBlock::Image {
            data: PNG.into(),
            media_type: "image/png".into(),
        },
        ContentBlock::Text {
            text: "after".into(),
        },
    ]);
    request.messages = Some(vec![user]);
    let original = request.messages.clone();
    drain(adapter.as_ref(), &request).await.unwrap();
    let body = mock.captured().await.unwrap();
    assert_eq!(body["model"], "raw-model/unchanged");
    assert_eq!(
        body["messages"][0]["content"],
        json!([
            {"type":"text","text":"before λ"},
            {"type":"image_url","image_url":{"url":format!("data:image/png;base64,{PNG}")}},
            {"type":"text","text":"after"},
        ])
    );
    assert_eq!(request.messages, original);
}

#[tokio::test]
async fn content_ollama_preserves_original_mixed_blocks() {
    let adapter = adapter(Family::Ollama);
    let mut mock = Mock::new(
        "{\"message\":{\"content\":\"ok\"},\"done\":true}\n".into(),
        Family::Ollama,
    )
    .await;
    let mut request = request(adapter.as_ref(), mock.port);
    let mut user = message(ChatRole::User, "flattened display must not replace blocks");
    user.blocks = Some(vec![
        ContentBlock::Text {
            text: "before λ".into(),
        },
        ContentBlock::Image {
            data: PNG.into(),
            media_type: "image/png".into(),
        },
        ContentBlock::Text {
            text: "after".into(),
        },
    ]);
    request.messages = Some(vec![user]);
    let original = request.messages.clone();
    drain(adapter.as_ref(), &request).await.unwrap();
    let body = mock.captured().await.unwrap();
    let content = body["messages"][0]["content"].as_str().unwrap();
    assert!(content.starts_with("before λ") && content.ends_with("after"));
    assert!(!content.contains("flattened display"));
    assert_eq!(body["messages"][0]["images"], json!([PNG]));
    assert_eq!(request.messages, original);
}

#[tokio::test]
async fn content_unsupported_blocks_refuse_before_post() {
    for family in [Family::OpenAi, Family::Ollama] {
        for role in [ChatRole::User, ChatRole::System] {
            let adapter = adapter(family);
            let mut mock = Mock::new(openai_reason("stop"), family).await;
            let mut request = request(adapter.as_ref(), mock.port);
            let mut user = message(role, "visible");
            user.blocks = Some(vec![ContentBlock::ToolUse {
                id: "foreign-call".into(),
                name: "foreign-tool".into(),
                input: "{}".into(),
            }]);
            request.messages = Some(vec![user]);
            let original = request.messages.clone();
            let result = drain(adapter.as_ref(), &request).await;
            let captured = mock.captured().await;
            assert!(
                result.is_err(),
                "unsupported {family:?}/{role:?} must refuse"
            );
            assert!(captured.is_none(), "unsupported blocks must never POST");
            assert_eq!(request.messages, original);
        }
    }
}

#[tokio::test]
async fn openai_terminal_complete_reason_and_sentinel_variants() {
    for suffix in [
        openai_reason("stop"),
        "data: [DONE]\n\n".into(),
        format!("{}data: [DONE]\n\n", openai_reason("stop")),
    ] {
        let adapter = adapter(Family::OpenAi);
        let mut mock = Mock::new(
            format!("{}{suffix}", openai_delta(json!({"content":"complete λ"}))),
            Family::OpenAi,
        )
        .await;
        let request = request(adapter.as_ref(), mock.port);
        let events = drain(adapter.as_ref(), &request).await.unwrap();
        mock.captured().await.unwrap();
        assert_eq!(text(&events), "complete λ");
        assert_eq!(terminal(&events), Some("stop"));
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e.event, ProviderEventKind::Finished { .. }))
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn openai_terminal_empty_refusal_does_not_change_completed_text_or_tools() {
    for tool in [false, true] {
        let delta = if tool {
            json!({"tool_calls":[{"index":0,"id":"empty-refusal-call","function":{"name":"lookup","arguments":"{}"}}]})
        } else {
            json!({"content":"complete"})
        };
        let reason = if tool { "tool_calls" } else { "stop" };
        let adapter = adapter(Family::OpenAi);
        let mut mock = Mock::new(
            format!(
                "{}{}{}data: [DONE]\n\n",
                openai_delta(delta),
                openai_reason(reason),
                openai_delta(json!({"refusal":""}))
            ),
            Family::OpenAi,
        )
        .await;
        let events = drain(adapter.as_ref(), &request(adapter.as_ref(), mock.port))
            .await
            .unwrap();
        assert_eq!(terminal(&events), Some(reason));
        assert_eq!(calls(&events).len(), usize::from(tool));
        mock.captured().await.unwrap();
    }
}

#[tokio::test]
async fn openai_terminal_reason_only_held_open_completes_without_eof() {
    for tool in [false, true] {
        let delta = if tool {
            json!({"tool_calls":[{"index":0,"id":"held-call","function":{"name":"lookup","arguments":"{}"}}]})
        } else {
            json!({"content":"complete held text"})
        };
        let reason = if tool { "tool_calls" } else { "stop" };
        let adapter = adapter(Family::OpenAi);
        let mut mock = Mock::held(
            format!("{}{}", openai_delta(delta), openai_reason(reason)),
            None,
        )
        .await;
        let mut request = request(adapter.as_ref(), mock.port);
        request.idle_timeout_ms = 80;
        let started = std::time::Instant::now();
        let events = tokio::time::timeout(
            Duration::from_millis(400),
            drain(adapter.as_ref(), &request),
        )
        .await
        .expect("completion must precede the server's 600ms hold")
        .expect("recognized reason is completion evidence");
        assert!(started.elapsed() < Duration::from_millis(400));
        assert_eq!(terminal(&events), Some(reason));
        assert_eq!(
            final_usage(&events),
            None,
            "missing trailer is unknown accounting"
        );
        if tool {
            assert_eq!(calls(&events).len(), 1);
        } else {
            assert_eq!(text(&events), "complete held text");
        }
        mock.captured().await.unwrap();
    }
}

#[tokio::test]
async fn openai_terminal_reason_only_preserves_delayed_usage_trailer() {
    let adapter = adapter(Family::OpenAi);
    let trailer = sse(
        json!({"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":4,"prompt_tokens_details":{"cached_tokens":3}}}),
    );
    let mut mock = Mock::held(
        format!(
            "{}{}",
            openai_delta(json!({"content":"ok"})),
            openai_reason("stop")
        ),
        Some(trailer),
    )
    .await;
    let mut request = request(adapter.as_ref(), mock.port);
    request.idle_timeout_ms = 80;
    let events = tokio::time::timeout(
        Duration::from_millis(400),
        drain(adapter.as_ref(), &request),
    )
    .await
    .expect("bounded trailer collection")
    .unwrap();
    let usage = final_usage(&events).expect("real trailer must survive");
    assert_eq!(
        (
            usage.input_tokens,
            usage.cache_read_tokens,
            usage.output_tokens
        ),
        (6, 3, 4)
    );
    mock.captured().await.unwrap();
}

#[tokio::test]
async fn openai_usage_rejects_malformed_empty_partial_and_inconsistent_totals() {
    for usage in [
        json!("bad"),
        json!({}),
        json!({"prompt_tokens":1}),
        json!({"completion_tokens":1}),
        json!({"prompt_tokens":-1,"completion_tokens":1}),
        json!({"prompt_tokens":"1","completion_tokens":1}),
        json!({"prompt_tokens":1,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":2}}),
        json!({"prompt_tokens":1,"completion_tokens":1,"completion_tokens_details":{"reasoning_tokens":"bad"}}),
    ] {
        let adapter = adapter(Family::OpenAi);
        let body = format!(
            "{}{}data: [DONE]\n\n",
            openai_reason("stop"),
            sse(json!({"choices":[],"usage":usage}))
        );
        let mut mock = Mock::new(body, Family::OpenAi).await;
        let request = request(adapter.as_ref(), mock.port);
        let result = drain(adapter.as_ref(), &request).await;
        mock.captured().await.unwrap();
        assert!(
            result.is_err(),
            "invalid usage must not become complete accounting: {usage}"
        );
    }
}

#[tokio::test]
async fn ollama_usage_rejects_malformed_or_missing_final_counter() {
    for fields in [
        json!({"prompt_eval_count":"bad","eval_count":1}),
        json!({"prompt_eval_count":1}),
        json!({"eval_count":1}),
        json!({"prompt_eval_count":-1,"eval_count":1}),
        json!({"prompt_eval_count":1,"eval_count":null}),
    ] {
        let adapter = adapter(Family::Ollama);
        let mut body = fields.clone();
        body["done"] = json!(true);
        let mut mock = Mock::new(format!("{body}\n"), Family::Ollama).await;
        let request = request(adapter.as_ref(), mock.port);
        let result = drain(adapter.as_ref(), &request).await;
        mock.captured().await.unwrap();
        assert!(
            result.is_err(),
            "native final counters must be complete integers: {fields}"
        );
    }
}

#[tokio::test]
async fn anthropic_usage_rejects_malformed_empty_or_missing_final_counter() {
    for (initial, final_counter) in [
        (json!({"input_tokens":2}), json!("bad")),
        (json!({"input_tokens":2}), json!({})),
        (json!({"input_tokens":2}), json!({"output_tokens":"bad"})),
        (json!({"input_tokens":2}), json!({"output_tokens":-1})),
        (
            json!({"input_tokens":2,"cache_read_input_tokens":"bad"}),
            json!({"output_tokens":1}),
        ),
        (json!({}), json!({"output_tokens":1})),
    ] {
        let adapter = adapter(Family::Anthropic);
        let mut mock = Mock::new(
            anthropic_response(Some(initial.clone()), Some(final_counter.clone()), vec![]),
            Family::Anthropic,
        )
        .await;
        let request = request(adapter.as_ref(), mock.port);
        let result = drain(adapter.as_ref(), &request).await;
        mock.captured().await.unwrap();
        assert!(
            result.is_err(),
            "invalid native usage must refuse: initial={initial}, final={final_counter}"
        );
    }
}

#[tokio::test]
async fn anthropic_usage_initial_snapshot_alone_is_not_final_accounting() {
    let adapter = adapter(Family::Anthropic);
    let mut mock = Mock::new(
        anthropic_response(
            Some(json!({"input_tokens":7,"output_tokens":0})),
            None,
            vec![],
        ),
        Family::Anthropic,
    )
    .await;
    let request = request(adapter.as_ref(), mock.port);
    let result = drain(adapter.as_ref(), &request).await;
    mock.captured().await.unwrap();
    match result {
        Err(_) => {} // Current event DTO cannot truthfully label intermediate totals.
        Ok(events) => {
            assert_eq!(final_usage(&events), None);
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event.event, ProviderEventKind::UsageUpdate(_))),
                "gateway must not promote an initial snapshot to final totals"
            );
        }
    }
}

#[tokio::test]
async fn usage_missing_on_all_adapters_remains_unknown() {
    for (family, body) in [
        (
            Family::OpenAi,
            format!("{}data: [DONE]\n\n", openai_reason("stop")),
        ),
        (Family::Anthropic, anthropic_response(None, None, vec![])),
        (Family::Ollama, "{\"done\":true}\n".into()),
    ] {
        let adapter = adapter(family);
        let mut mock = Mock::new(body, family).await;
        let request = request(adapter.as_ref(), mock.port);
        let events = drain(adapter.as_ref(), &request).await.unwrap();
        mock.captured().await.unwrap();
        assert_eq!(
            final_usage(&events),
            None,
            "{family:?} absent usage is unknown"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.event, ProviderEventKind::UsageUpdate(_)))
        );
    }
}

#[tokio::test]
async fn anthropic_native_redacted_thinking_refuses_before_completion() {
    let adapter = adapter(Family::Anthropic);
    let body = anthropic_response(
        None,
        None,
        vec![json!({"type":"redacted_thinking","data":"opaque-fixture-data"})],
    );
    let mut mock = Mock::new(body, Family::Anthropic).await;
    let request = request(adapter.as_ref(), mock.port);
    let result = drain(adapter.as_ref(), &request).await;
    mock.captured().await.unwrap();
    assert_eq!(
        result.unwrap_err().code(),
        "E0414",
        "unrepresentable opaque content must be explicit"
    );
}

#[tokio::test]
async fn anthropic_two_signed_thinking_blocks_refuse_before_corrupt_replay() {
    let adapter = adapter(Family::Anthropic);
    let body = anthropic_response(
        None,
        None,
        vec![
            json!({"type":"thinking","thinking":"first private reasoning","signature":"first-signature"}),
            json!({"type":"thinking","thinking":"second private reasoning","signature":"second-signature"}),
        ],
    );
    let mut mock = Mock::new(body, Family::Anthropic).await;
    let request = request(adapter.as_ref(), mock.port);
    let result = drain(adapter.as_ref(), &request).await;
    mock.captured().await.unwrap();
    assert_eq!(
        result.unwrap_err().code(),
        "E0414",
        "separate signatures cannot be merged"
    );
}

#[tokio::test]
async fn openai_terminal_unmarked_eof_is_not_completion() {
    let adapter = adapter(Family::OpenAi);
    let mut mock = Mock::new(openai_delta(json!({"content":"partial"})), Family::OpenAi).await;
    let request = request(adapter.as_ref(), mock.port);
    let result = drain(adapter.as_ref(), &request).await;
    mock.captured().await.unwrap();
    assert_eq!(result.unwrap_err().code(), "E0411");
}

#[tokio::test]
async fn openai_terminal_rejects_tool_identity_completed_after_finish_reason() {
    let body = [
        openai_delta(json!({"tool_calls":[{"index":0,"id":"call_","function":{"name":"","arguments":"{}"}}]})),
        openai_reason("tool_calls"),
        openai_delta(json!({"tool_calls":[{"index":0,"id":"late","function":{"name":"effect"}}]})),
        "data: [DONE]\n\n".into(),
    ].concat();
    let adapter = adapter(Family::OpenAi);
    let mut mock = Mock::new(body, Family::OpenAi).await;
    let request = request(adapter.as_ref(), mock.port);
    let result = drain(adapter.as_ref(), &request).await;
    mock.captured().await.unwrap();
    assert_eq!(
        result.unwrap_err().code(),
        "E0411",
        "later fragments cannot complete an invalid call set"
    );
}

#[tokio::test]
async fn openai_terminal_rejects_content_after_finish_reason() {
    for delta in [
        json!({"content":"late text"}),
        json!({"refusal":"late refusal"}),
    ] {
        let body = format!(
            "{}{}data: [DONE]\n\n",
            openai_reason("stop"),
            openai_delta(delta.clone())
        );
        let adapter = adapter(Family::OpenAi);
        let mut mock = Mock::new(body, Family::OpenAi).await;
        let request = request(adapter.as_ref(), mock.port);
        let result = drain(adapter.as_ref(), &request).await;
        mock.captured().await.unwrap();
        assert_eq!(
            result.unwrap_err().code(),
            "E0411",
            "post-terminal delta must fail: {delta}"
        );
    }
}

#[tokio::test]
async fn openai_terminal_later_negative_reason_overrides_positive_without_tool_effects() {
    let body = [
        openai_delta(json!({"tool_calls":[{"index":0,"id":"call_a","function":{"name":"effect","arguments":"{}"}}]})),
        openai_reason("tool_calls"),
        openai_reason("length"),
        "data: [DONE]\n\n".into(),
    ].concat();
    let adapter = adapter(Family::OpenAi);
    let mut mock = Mock::new(body, Family::OpenAi).await;
    let request = request(adapter.as_ref(), mock.port);
    let events = drain(adapter.as_ref(), &request).await.unwrap();
    mock.captured().await.unwrap();
    assert_eq!(terminal(&events), Some("length"));
    assert!(!events.iter().any(|event| matches!(
        event.event,
        ProviderEventKind::ToolCallStarted { .. } | ProviderEventKind::ToolCallFinished { .. }
    )));
}

#[tokio::test]
async fn openai_fragmented_id_name_arguments_are_one_coherent_call() {
    let body = [
        openai_delta(json!({"tool_calls":[{"index":0,"id":"call_","function":{"name":"file_","arguments":"{\"path\":"}},{"index":1,"id":"other_","function":{"name":"file_","arguments":"{\"path\":"}}]})),
        openai_delta(json!({"tool_calls":[{"index":1,"id":"b","function":{"name":"read","arguments":"\"β\"}"}},{"index":0,"id":"a","function":{"name":"read","arguments":"\"α\"}"}}]})),
        openai_reason("tool_calls"),
        "data: [DONE]\n\n".into(),
    ].concat();
    let adapter = adapter(Family::OpenAi);
    let mut mock = Mock::new(body, Family::OpenAi).await;
    let request = request(adapter.as_ref(), mock.port);
    let events = drain(adapter.as_ref(), &request).await.unwrap();
    mock.captured().await.unwrap();
    assert_eq!(
        calls(&events),
        vec![
            (0, "call_a".into(), "file_read".into(), json!({"path":"α"})),
            (1, "other_b".into(), "file_read".into(), json!({"path":"β"})),
        ]
    );
    assert_eq!(terminal(&events), Some("tool_calls"));
}

#[tokio::test]
async fn openai_terminal_negative_reason_never_finishes_tools() {
    for reason in ["length", "content_filter"] {
        let body = format!(
            "{}{}data: [DONE]\n\n",
            openai_delta(
                json!({"tool_calls":[{"index":0,"id":"call_a","function":{"name":"effect","arguments":"{}"}}]})
            ),
            openai_reason(reason)
        );
        let adapter = adapter(Family::OpenAi);
        let mut mock = Mock::new(body, Family::OpenAi).await;
        let request = request(adapter.as_ref(), mock.port);
        let events = drain(adapter.as_ref(), &request).await.unwrap();
        mock.captured().await.unwrap();
        assert_eq!(terminal(&events), Some(reason));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.event, ProviderEventKind::ToolCallFinished { .. })),
            "{reason} cannot complete executable calls"
        );
    }
}

#[tokio::test]
async fn ollama_native_calls_have_stable_distinct_ids() {
    let body = format!(
        "{}\n{}\n",
        json!({"message":{"role":"assistant","content":"","tool_calls":[{"function":{"index":0,"name":"lookup","arguments":{"key":"a"}}},{"function":{"index":1,"name":"lookup","arguments":{"key":"b"}}}]},"done":false}),
        json!({"done":true,"done_reason":"stop"})
    );
    let adapter = adapter(Family::Ollama);
    let mut mock = Mock::new(body, Family::Ollama).await;
    let request = request(adapter.as_ref(), mock.port);
    let events = drain(adapter.as_ref(), &request).await.unwrap();
    mock.captured().await.unwrap();
    let calls = calls(&events);
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].1, calls[1].1);
    assert_eq!(
        (&calls[0].2, &calls[0].3),
        (&"lookup".to_string(), &json!({"key":"a"}))
    );
    assert_eq!(
        (&calls[1].2, &calls[1].3),
        (&"lookup".to_string(), &json!({"key":"b"}))
    );
    assert_eq!(terminal(&events), Some("tool_calls"));
}

#[tokio::test]
async fn ollama_native_result_names_follow_call_ids() {
    let adapter = adapter(Family::Ollama);
    let mut mock = Mock::new(
        "{\"done\":true,\"done_reason\":\"stop\"}\n".into(),
        Family::Ollama,
    )
    .await;
    let mut request = request(adapter.as_ref(), mock.port);
    let mut assistant = message(ChatRole::Assistant, "");
    assistant.tool_calls = Some(vec![
        ToolCallMessage {
            id: "native-a".into(),
            name: "first".into(),
            arguments: "{\"key\":\"a\"}".into(),
        },
        ToolCallMessage {
            id: "native-b".into(),
            name: "second".into(),
            arguments: "{\"key\":\"b\"}".into(),
        },
    ]);
    let mut b = message(ChatRole::Tool, "");
    b.tool_call_id = Some("native-b".into());
    b.tool_result = Some("result-b".into());
    let mut a = message(ChatRole::Tool, "");
    a.tool_call_id = Some("native-a".into());
    a.tool_result = Some("result-a".into());
    request.messages = Some(vec![assistant, b, a]);
    drain(adapter.as_ref(), &request).await.unwrap();
    let body = mock.captured().await.unwrap();
    assert_eq!(
        body["messages"][0]["tool_calls"][0]["function"]["arguments"],
        json!({"key":"a"})
    );
    assert_eq!(body["messages"][1]["tool_name"], "second");
    assert_eq!(body["messages"][1]["content"], "result-b");
    assert_eq!(body["messages"][2]["tool_name"], "first");
    assert_eq!(body["messages"][2]["content"], "result-a");
}

#[tokio::test]
async fn ollama_terminal_requires_done_and_rejects_invalid_ndjson() {
    for body in [
        "{\"message\":{\"content\":\"partial\"}}\n",
        "broken\n{\"done\":true}\n",
        "{\"error\":\"fixture overload\"}\n",
    ] {
        let adapter = adapter(Family::Ollama);
        let mut mock = Mock::new(body.into(), Family::Ollama).await;
        let request = request(adapter.as_ref(), mock.port);
        let result = drain(adapter.as_ref(), &request).await;
        mock.captured().await.unwrap();
        assert!(result.is_err(), "invalid native stream must fail: {body}");
    }
}

#[tokio::test]
async fn ollama_terminal_final_object_without_newline_is_complete() {
    let adapter = adapter(Family::Ollama);
    let mut mock = Mock::new(
        "{\"message\":{\"content\":\"final\"},\"done\":true}".into(),
        Family::Ollama,
    )
    .await;
    let request = request(adapter.as_ref(), mock.port);
    let events = drain(adapter.as_ref(), &request).await.unwrap();
    mock.captured().await.unwrap();
    assert_eq!(text(&events), "final");
    assert_eq!(terminal(&events), Some("stop"));
}

#[tokio::test]
async fn anthropic_terminal_missing_stop_and_streamed_error_fail() {
    for body in [
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fixture\",\"role\":\"assistant\"}}\n\n".to_string(),
        "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"fixture overload\"}}\n\n".into(),
    ] {
        let adapter = adapter(Family::Anthropic);
        let mut mock = Mock::new(body, Family::Anthropic).await;
        let request = request(adapter.as_ref(), mock.port);
        let result = drain(adapter.as_ref(), &request).await;
        mock.captured().await.unwrap();
        assert!(result.is_err(), "missing lifecycle/error cannot become end_turn");
    }
}

#[test]
fn sse_content_framing_preserves_whitespace_and_utf8_at_every_split() {
    let input = "\u{feff}: comment\r\nevent: extension\r\ndata:  α\r\ndata: β\r\n\r\n";
    for split in 0..=input.len() {
        let mut parser = SseParser::new();
        let mut events = parser.feed(&input.as_bytes()[..split]).unwrap();
        events.extend(parser.feed(&input.as_bytes()[split..]).unwrap());
        assert_eq!(events.len(), 1, "split={split}");
        assert_eq!(
            events[0].data, " α\nβ",
            "one optional field space, split={split}"
        );
        assert!(parser.is_clean(), "split={split}");
    }
}

#[test]
fn sse_content_cr_delimiters_and_incomplete_frame() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: complete\r\r").unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "complete");
    let mut parser = SseParser::new();
    assert!(parser.feed(b"data: pending\n").unwrap().is_empty());
    assert!(!parser.is_clean());
}

#[tokio::test]
async fn openai_terminal_malformed_or_unframed_sse_fails() {
    for body in [
        "data: broken\n\ndata: [DONE]\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"pending\"}}]}\n",
    ] {
        let adapter = adapter(Family::OpenAi);
        let mut mock = Mock::new(body.into(), Family::OpenAi).await;
        let request = request(adapter.as_ref(), mock.port);
        let result = drain(adapter.as_ref(), &request).await;
        mock.captured().await.unwrap();
        assert_eq!(result.unwrap_err().code(), "E0411");
    }
}

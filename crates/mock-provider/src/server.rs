//! Mock provider HTTP server — OpenAI / Anthropic / Ollama wire formats.
//!
//! Scriptable via `x-orbit-behavior`: `success` (default), `partial`, `rate-limit`,
//! `server-error`, `malformed`, `slow`, `tool-calls`. The same binary can run in
//! the homelab or in-process for the conformance tests.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8088".parse().expect("literal socket address"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerState {
    pub requests: Arc<std::sync::atomic::AtomicU64>,
    /// The last request JSON captured (for prompt-delivery assertions).
    pub last_body: Arc<std::sync::Mutex<Option<Value>>>,
}

pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(openai))
        .route("/v1/messages", post(anthropic))
        .route("/api/chat", post(ollama))
        .with_state(state)
}

fn behavior(headers: &HeaderMap) -> &str {
    headers
        .get("x-orbit-behavior")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("success")
}

async fn openai(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    *state.last_body.lock().unwrap() = Some(body.clone());
    // If the request advertises tools, exercise a real fragmented calculator
    // call on the first round. If a tool result is already in messages, return
    // the final text response. Explicit x-orbit-behavior still wins.
    let implicit_tool_behavior = if headers.get("x-orbit-behavior").is_none()
        && body
            .get("tools")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    {
        let has_result = body
            .get("messages")
            .and_then(|v| v.as_array())
            .map(|msgs| {
                msgs.iter()
                    .any(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
            })
            .unwrap_or(false);
        Some(if has_result { "success" } else { "tool-calls" })
    } else {
        None
    };
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // Model-name conventions for the gate scenarios: *-slow streams
    // slowly, *-notools never emits tool calls, *-fat replies huge.
    // Round-local statefulness: the LAST message decides. A tool
    // result as the final message means the previous round's call was
    // executed (or cancelled) — answer with final text. Earlier rounds'
    // results (a long session) must not suppress a fresh tool call.
    let last_is_tool_result = || {
        body.get("messages")
            .and_then(|v| v.as_array())
            .and_then(|msgs| msgs.last())
            .map(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
            .unwrap_or(false)
    };
    let model_behavior = if model.contains("slowbash") && !last_is_tool_result() {
        // A long-running Bash call (sleep): the Esc-during-a-tool
        // scenario (MD gate 2). After the tool result (cancelled)
        // arrives, fall through to the final text.
        Some("slow-bash-tool-calls")
    } else if model.contains("slowbash") {
        None
    } else if model.contains("slow") {
        Some("slow-stream")
    } else if model.contains("notools") {
        Some("success")
    } else if model.contains("fat") {
        Some("fat-responses")
    } else if model.contains("bash") && !last_is_tool_result() {
        Some("bash-tool-calls")
    } else {
        None
    };
    let selected = model_behavior
        .or(implicit_tool_behavior)
        .unwrap_or_else(|| behavior(&headers));
    match selected {
        "rate-limit" => (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            "rate limited",
        )
            .into_response(),
        "server-error" => (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response(),
        "malformed" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            "data: not-json\n\n",
        )
            .into_response(),
        "partial" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            openai_partial(),
        )
            .into_response(),
        "tool-calls" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            openai_tool_calls(),
        )
            .into_response(),
        "bash-tool-calls" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            openai_bash_tool_calls(),
        )
            .into_response(),
        "slow-bash-tool-calls" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            openai_slow_bash_tool_calls(),
        )
            .into_response(),
        "slow" => {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            (
                StatusCode::OK,
                [("content-type", "text/event-stream")],
                openai_success(),
            )
                .into_response()
        }
        "slow-stream" => {
            // Yield chunks with 200ms delays so Ctrl+C cancel is testable.
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);
            tokio::spawn(async move {
                let chunks = [
                    r#"data: {"id":"r1","choices":[{"delta":{"content":"Hello "}}]}"#,
                    r#"data: {"id":"r1","choices":[{"delta":{"content":"from "}}]}"#,
                    r#"data: {"id":"r1","choices":[{"delta":{"content":"the "}}]}"#,
                    r#"data: {"id":"r1","choices":[{"delta":{"content":"slow "}}]}"#,
                    r#"data: {"id":"r1","choices":[{"delta":{"content":"stream."}}]}"#,
                    r#"data: {"id":"r1","choices":[{"delta":{}}],"usage":{"prompt_tokens":3,"completion_tokens":5}}"#,
                    "data: [DONE]",
                ];
                for chunk in chunks {
                    let _ = tx
                        .send(Ok(bytes::Bytes::from(format!("{chunk}\n\n"))))
                        .await;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            });
            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
            (
                StatusCode::OK,
                [("content-type", "text/event-stream")],
                Body::from_stream(stream),
            )
                .into_response()
        }
        _ => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            openai_success(),
        )
            .into_response(),
    }
}

async fn anthropic(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    *state.last_body.lock().unwrap() = Some(body.clone());
    match behavior(&headers) {
        "rate-limit" => (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            "rate limited",
        )
            .into_response(),
        "server-error" => (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response(),
        "tool-calls" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            anthropic_tool_calls(),
        )
            .into_response(),
        "bash-tool-calls" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            anthropic_bash_tool_calls(),
        )
            .into_response(),
        "slow-bash-tool-calls" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            anthropic_slow_bash_tool_calls(),
        )
            .into_response(),
        "fat-responses" => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            anthropic_fat(),
        )
            .into_response(),
        _ => {
            // Implicit script: tools advertised and no tool_result yet →
            // round 0 returns a tool_use block; tool_result present →
            // final text (mirrors the OpenAI implicit behavior).
            let implicit = if headers.get("x-orbit-behavior").is_none() {
                let has_tools = body
                    .get("tools")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                let has_result = body
                    .get("messages")
                    .and_then(|v| v.as_array())
                    .map(|msgs| {
                        msgs.iter().any(|m| {
                            m.get("content")
                                .and_then(|c| c.as_array())
                                .map(|blocks| {
                                    blocks.iter().any(|b| {
                                        b.get("type").and_then(|t| t.as_str())
                                            == Some("tool_result")
                                    })
                                })
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                has_tools && !has_result
            } else {
                false
            };
            if implicit {
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    anthropic_tool_calls(),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    anthropic_success(),
                )
                    .into_response()
            }
        }
    }
}

async fn ollama(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Response {
    state
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    match behavior(&headers) {
        "server-error" => (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response(),
        _ => (
            StatusCode::OK,
            [("content-type", "application/x-ndjson")],
            ollama_success(),
        )
            .into_response(),
    }
}

fn openai_success() -> String {
    [
        r#"data: {"id":"r1","choices":[{"delta":{"content":"hello "}}]}"#,
        r#"data: {"id":"r1","choices":[{"delta":{"content":"world"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
        "data: [DONE]",
        "",
    ].join("\n\n")
}
fn openai_partial() -> String {
    r#"data: {"id":"r1","choices":[{"delta":{"content":"partial"}}]}\n\n"#.replace("\\n", "\n")
}
fn openai_tool_calls() -> String {
    [
        r#"data: {"id":"r1","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"calculator","arguments":"{\"expression\":"}}]},"finish_reason":null}]}"#,
        r#"data: {"id":"r1","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"2*(3+4)\"}"}}]},"finish_reason":null}]}"#,
        r#"data: {"id":"r1","choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#,
        "data: [DONE]",
        "",
    ]
    .join("\n\n")
}

/// A Bash tool call (touch — not read-only, so the approval card
/// fires). Used by the web/TUI harnesses' approval scenarios.
fn openai_bash_tool_calls() -> String {
    [
        r#"data: {"id":"r1","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-9","type":"function","function":{"name":"Bash","arguments":"{\"command\":"}}]},"finish_reason":null}]}"#,
        r#"data: {"id":"r1","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"touch approval-probe.txt\"}"}}]},"finish_reason":null}]}"#,
        r#"data: {"id":"r1","choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#,
        "data: [DONE]",
        "",
    ]
    .join("\n\n")
}

/// A long-running Bash call (sleep 30): the Esc-during-a-tool scenario.
fn openai_slow_bash_tool_calls() -> String {
    [
        r#"data: {"id":"r1","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-slow","type":"function","function":{"name":"Bash","arguments":"{\"command\":"}}]},"finish_reason":null}]}"#,
        r#"data: {"id":"r1","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"sleep 30 && echo done\"}"}}]},"finish_reason":null}]}"#,
        r#"data: {"id":"r1","choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#,
        "data: [DONE]",
        "",
    ]
    .join("\n\n")
}
fn anthropic_slow_bash_tool_calls() -> String {
    [
        r#"data: {"type":"message_start","usage":{"input_tokens":5,"output_tokens":0}}"#,
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu-slow","name":"Bash","input":{}}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"sleep 30 && echo done\"}"}}"#,
        r#"data: {"type":"content_block_stop","index":0}"#,
        r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3,"input_tokens":5}}"#,
        r#"data: {"type":"message_stop"}"#,
        "",
    ].join("\n\n")
}

fn anthropic_bash_tool_calls() -> String {
    [
        r#"data: {"type":"message_start","usage":{"input_tokens":5,"output_tokens":0}}"#,
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu-9","name":"Bash","input":{}}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"touch approval-probe.txt\"}"}}"#,
        r#"data: {"type":"content_block_stop","index":0}"#,
        r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3,"input_tokens":5}}"#,
        r#"data: {"type":"message_stop"}"#,
        "",
    ].join("\n\n")
}

fn anthropic_tool_calls() -> String {
    [
        r#"data: {"type":"message_start","usage":{"input_tokens":5,"output_tokens":0}}"#,
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu-1","name":"calculator","input":{}}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"expression\":"}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"2*(3+4)\"}"}}"#,
        r#"data: {"type":"content_block_stop","index":0}"#,
        r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3,"input_tokens":5,"cache_read_input_tokens":120,"cache_creation_input_tokens":8}}"#,
        r#"data: {"type":"message_stop"}"#,
        "",
    ].join("\n\n")
}
/// A fat response: ~50k tokens of text, so a few rounds push the
/// transcript past 90% of any small test window (gate 4).
fn anthropic_fat() -> String {
    let para = "The quick brown fox jumps over the lazy dog. ".repeat(40); // ~2k chars
    let body = para.repeat(25); // ~50k chars ≈ 12k+ tokens
    [
        r#"{"type":"message_start","usage":{"input_tokens":3,"output_tokens":0}}"#,
        &format!(
            r#"{{"type":"content_block_delta","delta":{{"type":"text_delta","text":"{body}"}}}}"#
        ),
        r#"{"type":"message_stop","usage":{"input_tokens":3,"output_tokens":12000}}"#,
        "",
    ]
    .join("\n\n")
}

fn anthropic_success() -> String {
    [
        r#"data: {"type":"message_start","usage":{"input_tokens":3,"output_tokens":0}}"#,
        r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello world"}}"#,
        r#"data: {"type":"message_stop","usage":{"input_tokens":3,"output_tokens":2}}"#,
        "",
    ].join("\n\n")
}
fn ollama_success() -> String {
    [
        r#"{"message":{"role":"assistant","content":"hello "},"done":false}"#,
        r#"{"message":{"role":"assistant","content":"world"},"done":false}"#,
        r#"{"message":{"role":"assistant","content":""},"done":true,"prompt_eval_count":3,"eval_count":2}"#,
        "",
    ].join("\n")
}

/// Spawn on `127.0.0.1:0` and return the assigned address + shutdown handle.
pub async fn spawn(
) -> Result<(SocketAddr, ServerState, tokio::task::JoinHandle<()>), std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let state = ServerState::default();
    let app = router(state.clone());
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, state, handle))
}

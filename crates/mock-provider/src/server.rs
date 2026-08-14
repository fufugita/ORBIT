//! Mock provider HTTP server — OpenAI / Anthropic / Ollama wire formats.
//!
//! Scriptable via `x-orbit-behavior`: `success` (default), `partial`, `rate-limit`,
//! `server-error`, `malformed`, `slow`, `tool-calls`. The same binary can run in
//! the homelab or in-process for the conformance tests.

use axum::{
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
    Json(_body): Json<Value>,
) -> Response {
    state
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    match behavior(&headers) {
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
        "slow" => {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            (
                StatusCode::OK,
                [("content-type", "text/event-stream")],
                openai_success(),
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
    Json(_body): Json<Value>,
) -> Response {
    state
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    match behavior(&headers) {
        "rate-limit" => (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            "rate limited",
        )
            .into_response(),
        "server-error" => (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response(),
        _ => (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            anthropic_success(),
        )
            .into_response(),
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
    openai_success()
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
pub async fn spawn() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = router(ServerState::default());
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, handle))
}

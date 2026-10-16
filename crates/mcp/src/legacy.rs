//! The legacy MCP GET event stream and advertised POST endpoint transport.

use crate::encode_frame;
use crate::http::{
    EventStream, HttpState, Message, bounded_body, classify_message, fatal, media_type,
    parse_message, run_owned, status_error, validated_endpoint,
};
use crate::{MAX_FRAME_BYTES, McpCallOptions};
use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::header::ACCEPT;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use url::Url;

const CANCEL_CLEANUP_BUDGET: Duration = Duration::from_millis(75);
const MAX_PENDING_POSTS: usize = 32;
const MAX_PENDING_POST_BYTES: usize = 2 * MAX_FRAME_BYTES;
type RpcResult<T> = Result<T, (String, bool)>;

struct Connection {
    post: HttpState,
    events: EventStream,
}

pub(crate) struct LegacyTransport {
    configured: HttpState,
    connection: Option<Connection>,
    alive: bool,
}

impl LegacyTransport {
    pub(crate) fn new(url: &str, headers: &BTreeMap<String, String>) -> Result<Self, String> {
        Ok(Self {
            configured: HttpState::new(url, headers)?,
            connection: None,
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
            let body = encode_frame(&json!({
                "jsonrpc":"2.0","id":id,"method":method,"params":params
            }))
            .map_err(fatal)?;
            self.ensure_connection(options).map_err(fatal)?;
            let mut connection = self
                .connection
                .take()
                .ok_or_else(|| fatal("mcp legacy SSE connection vanished"))?;
            connection.events.reset_budget();
            let cancel_target = connection.post.clone();
            let task_options = options.clone();
            let sent = Arc::new(AtomicBool::new(false));
            let task_sent = sent.clone();
            let response = run_owned(options, async move {
                duplex(connection, body, Some(id), task_options, task_sent).await
            });
            attempted = sent.load(Ordering::Acquire);
            let cancelled = match &response {
                Err(error) | Ok(Err((error, _))) => {
                    error == "mcp request cancelled" || error == "mcp request timed out"
                }
                _ => false,
            };
            if cancelled && method != "initialize" && attempted {
                cancel_attempted_request(cancel_target, id);
            }
            let (mut connection, result) = response.map_err(fatal)??;
            if method == "initialize"
                && let Ok(result) = &result
            {
                let version = result
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fatal("mcp initialize result has no protocol version"))?;
                connection
                    .post
                    .set_protocol_version(version)
                    .map_err(fatal)?;
            }
            self.connection = Some(connection);
            result
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
        let result = (|| {
            options.check()?;
            let body = encode_frame(&json!({"jsonrpc":"2.0","method":method,"params":params}))?;
            self.ensure_connection(options)?;
            let mut connection = self
                .connection
                .take()
                .ok_or("mcp legacy SSE connection vanished")?;
            connection.events.reset_budget();
            let task_options = options.clone();
            let (connection, result) = run_owned(options, async move {
                duplex(
                    connection,
                    body,
                    None,
                    task_options,
                    Arc::new(AtomicBool::new(false)),
                )
                .await
            })?
            .map_err(|(error, _)| error)?;
            self.connection = Some(connection);
            result.map(|_| ()).map_err(|(error, _)| error)
        })();
        if result.is_err() {
            self.retire();
        }
        result
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive
    }

    pub(crate) fn close(&mut self, options: &McpCallOptions) -> Result<(), String> {
        let result = options.check();
        self.retire();
        result
    }

    pub(crate) fn retire(&mut self) {
        self.alive = false;
        self.connection.take();
    }

    fn ensure_connection(&mut self, options: &McpCallOptions) -> Result<(), String> {
        if !self.alive {
            return Err("mcp transport is retired".into());
        }
        options.check()?;
        if self.connection.is_some() {
            return Ok(());
        }
        let state = self.configured.clone();
        let task_options = options.clone();
        self.connection = Some(run_owned(options, async move {
            connect(state, &task_options).await
        })??);
        Ok(())
    }
}

async fn connect(mut state: HttpState, options: &McpCallOptions) -> Result<Connection, String> {
    options.check()?;
    let response = state
        .request(reqwest::Method::GET, state.endpoint.clone())
        .header(ACCEPT, "text/event-stream")
        .send()
        .await
        .map_err(|_| "mcp legacy SSE connection failed".to_string())?;
    options.check()?;
    if !response.status().is_success() {
        return Err(status_error(response.status()));
    }
    if !media_type(&response)
        .map_err(|(error, _)| error)?
        .eq_ignore_ascii_case("text/event-stream")
    {
        return Err("mcp legacy SSE response has an unsupported content type".into());
    }
    let mut events = EventStream::new(response);
    let endpoint = events
        .next(options)
        .await?
        .ok_or("mcp legacy SSE stream ended before its endpoint advertisement")?;
    if endpoint.kind != "endpoint" {
        return Err("mcp legacy SSE stream did not advertise its POST endpoint first".into());
    }
    let advertised = std::str::from_utf8(&endpoint.data)
        .map_err(|_| "mcp legacy SSE endpoint is not UTF-8".to_string())?;
    state.endpoint = advertised_endpoint(&state.endpoint, advertised)?;
    Ok(Connection {
        post: state,
        events,
    })
}

type PostFuture = BoxFuture<'static, (bool, usize, Result<(), String>)>;

struct Outgoing {
    pending: FuturesUnordered<PostFuture>,
    bytes: usize,
    replies: usize,
    state: HttpState,
    options: McpCallOptions,
    attempted: Arc<AtomicBool>,
}

impl Outgoing {
    fn push(&mut self, body: Vec<u8>, original: bool) -> RpcResult<()> {
        let bytes = body.len();
        if self.pending.len() >= MAX_PENDING_POSTS
            || bytes > MAX_PENDING_POST_BYTES.saturating_sub(self.bytes)
        {
            return Err(fatal("mcp legacy SSE pending POSTs exceed their limit"));
        }
        self.bytes += bytes;
        if !original {
            self.replies += 1;
        }
        let state = self.state.clone();
        let options = self.options.clone();
        let attempted = if original {
            self.attempted.clone()
        } else {
            Arc::new(AtomicBool::new(false))
        };
        self.pending.push(Box::pin(async move {
            let result = send_legacy(&state, body, &options, &attempted).await;
            (original, bytes, result)
        }));
        Ok(())
    }

    fn acknowledge(
        &mut self,
        (original, bytes, result): (bool, usize, Result<(), String>),
    ) -> RpcResult<bool> {
        self.bytes -= bytes;
        if !original {
            self.replies -= 1;
        }
        result.map_err(fatal)?;
        Ok(original)
    }
}

async fn duplex(
    mut connection: Connection,
    body: Vec<u8>,
    expected_id: Option<u64>,
    options: McpCallOptions,
    attempted: Arc<AtomicBool>,
) -> RpcResult<(Connection, RpcResult<Value>)> {
    let mut result = None;
    let mut outgoing = Outgoing {
        pending: FuturesUnordered::new(),
        bytes: 0,
        replies: 0,
        state: connection.post.clone(),
        options: options.clone(),
        attempted,
    };
    outgoing.push(body, true)?;
    let mut original_accepted = false;
    loop {
        options.check().map_err(fatal)?;
        if expected_id.is_some()
            && result.is_some()
            && outgoing.replies == 0
            && outgoing.attempted.load(Ordering::Acquire)
        {
            return Ok((
                connection,
                result
                    .take()
                    .ok_or_else(|| fatal("mcp legacy SSE response vanished"))?,
            ));
        }
        if expected_id.is_none() && original_accepted && outgoing.pending.is_empty() {
            return Ok((connection, Ok(Value::Null)));
        }
        // Every POST, including replies to server requests, stays owned by this
        // loop. Waiting for one acknowledgement never stops GET processing.
        let event = tokio::select! {
            biased;
            completion = outgoing.pending.next(), if !outgoing.pending.is_empty() => {
                let completion = completion.ok_or_else(|| fatal("mcp legacy SSE pending POST vanished"))?;
                original_accepted |= outgoing.acknowledge(completion)?;
                continue;
            }
            event = connection.events.next(&options) => event.map_err(fatal)?,
        }.ok_or_else(|| fatal("mcp legacy SSE stream ended before completion"))?;
        if !event.kind.is_empty() && event.kind != "message" {
            return Err(fatal("mcp legacy SSE stream has an unexpected event type"));
        }
        let value = parse_message(&event.data)?;
        let is_response = value.get("method").is_none();
        let matches =
            expected_id.is_some_and(|id| value.get("id").and_then(Value::as_u64) == Some(id));
        match classify_message(value, expected_id.unwrap_or(0))? {
            Message::Response(response) if matches && result.is_none() => result = Some(response),
            Message::Response(_) | Message::Ignore if is_response => {
                return Err(fatal(
                    "mcp legacy SSE response has no outstanding matching request",
                ));
            }
            Message::Reply(reply) => outgoing.push(encode_frame(&reply).map_err(fatal)?, false)?,
            Message::Ignore => {}
            Message::Response(_) => {
                return Err(fatal("mcp legacy SSE response has invalid ownership"));
            }
        }
    }
}

fn advertised_endpoint(configured: &Url, advertised: &str) -> Result<Url, String> {
    if advertised.is_empty()
        || advertised.len() > 8192
        || advertised.trim() != advertised
        || advertised.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("mcp legacy SSE advertised endpoint is invalid".into());
    }
    let resolved = configured
        .join(advertised)
        .map_err(|_| "mcp legacy SSE advertised endpoint is invalid".to_string())?;
    let resolved = validated_endpoint(resolved.as_str())?;
    if configured.origin() != resolved.origin() {
        return Err("mcp legacy SSE advertised endpoint must have the configured origin".into());
    }
    Ok(resolved)
}

async fn send_legacy(
    state: &HttpState,
    body: Vec<u8>,
    options: &McpCallOptions,
    attempted: &AtomicBool,
) -> Result<(), String> {
    let response = state.post(body, options, attempted).await?;
    if !response.status().is_success() {
        return Err(status_error(response.status()));
    }
    // Legacy servers may acknowledge with a small text body (for example,
    // status 202 and "Accepted"). The RPC result belongs to the GET stream.
    bounded_body(response, options).await?;
    Ok(())
}

fn cancel_attempted_request(state: HttpState, id: u64) {
    let Ok(body) = encode_frame(&json!({
        "jsonrpc":"2.0","method":"notifications/cancelled",
        "params":{"requestId":id,"reason":"caller cancelled or deadline elapsed"}
    })) else {
        return;
    };
    let options = McpCallOptions::new(CANCEL_CLEANUP_BUDGET);
    let task_options = options.clone();
    let _ = run_owned(&options, async move {
        send_legacy(&state, body, &task_options, &AtomicBool::new(false)).await
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_post_endpoint_is_bound_to_exact_configured_origin() {
        let configured = Url::parse("https://example.invalid/path/events").unwrap();
        assert_eq!(
            advertised_endpoint(&configured, "../messages?session=fixture")
                .unwrap()
                .as_str(),
            "https://example.invalid/messages?session=fixture"
        );
        for value in [
            "https://other.invalid/messages",
            "http://example.invalid/messages",
            "https://example.invalid:444/messages",
            "//other.invalid/messages",
            "https://secret@example.invalid/messages",
            "/messages#secret",
            " /messages",
            "",
        ] {
            let error = advertised_endpoint(&configured, value).unwrap_err();
            assert!(!error.contains("secret"));
        }
    }
}

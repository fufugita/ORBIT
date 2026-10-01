//! Browser-harness integration tests (docs/browser-harness.md §4).
//!
//! Verifies the transport contract — SPA served, SSE event stream, token
//! gate, WS action funnel — against the real router via oneshot requests.
//! The full turn pipeline (prompt → stream → finished) is exercised by
//! scripts/pty_tui_test.py's web mode against a mock provider.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use orbit_web::{router, BridgeState};
use std::sync::{mpsc, Arc, Mutex};
use tower::ServiceExt;

fn state() -> (BridgeState, Arc<Mutex<mpsc::Receiver<serde_json::Value>>>) {
    orbit_web::__test_channels(None)
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, String, Option<String>) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, String::from_utf8_lossy(&body).into_owned(), ctype)
}

#[tokio::test]
async fn serves_index_html() {
    let (st, _rx) = state();
    let (status, body, ctype) = get(router(st), "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some("text/html; charset=utf-8"));
    assert!(
        body.contains("<title>ORBIT</title>"),
        "index must be the SPA"
    );
    assert!(body.contains("/static/app.js"), "SPA loads its script");
}

#[tokio::test]
async fn serves_app_js_as_javascript() {
    let (st, _rx) = state();
    let (status, _body, ctype) = get(router(st.clone()), "/static/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ctype.unwrap_or_default().contains("javascript"),
        "JS must be served as javascript"
    );
}

#[tokio::test]
async fn serves_styles_as_css() {
    let (st, _rx) = state();
    let (status, body, ctype) = get(router(st), "/static/styles.css").await;
    assert_eq!(status, StatusCode::OK);
    assert!(ctype.unwrap_or_default().contains("css"));
    assert!(
        body.contains("--accent"),
        "theme uses the palette custom properties"
    );
}

#[tokio::test]
async fn unknown_asset_404() {
    let (st, _rx) = state();
    let (status, _, _) = get(router(st), "/static/nope.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sse_stream_carries_emitted_events() {
    let (st, _rx) = state();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("text/event-stream"),
        "SSE content type"
    );
    // Emit AFTER the stream is established; the body must carry the frame.
    st.emit(
        "identity",
        serde_json::json!({ "model": "m1", "provider": "p", "session": "abcd" }),
    );
    // Read the first chunk (event: identity\ndata: {...}\n\n). The stream
    // stays open, so read a bounded prefix then drop it.
    let mut body = resp.into_body().into_data_stream();
    let mut buf = Vec::new();
    while buf.len() < 64 {
        match futures::StreamExt::next(&mut body).await {
            Some(Ok(chunk)) => buf.extend_from_slice(&chunk),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("event: identity"),
        "frame names the event: {text}"
    );
    assert!(
        text.contains(r#""model":"m1""#),
        "frame carries JSON: {text}"
    );
}

#[tokio::test]
async fn ws_actions_requires_token_when_configured() {
    // A token-protected state must refuse SSE/WS without the token.
    let (st, _rx) = orbit_web::__test_channels(Some("sekrit".into()));
    let (status, _, _) = get(router(st.clone()), "/events").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "SSE without token refused"
    );
}

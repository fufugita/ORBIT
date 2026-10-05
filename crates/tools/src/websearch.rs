//! WebSearch (Wave 2): search the web.
//!
//! Roadmap contract: "The provider's server-side search on Anthropic,
//! otherwise a configured search API; off until configured." The
//! search backend is a hook (the CLI installs one when the operator
//! configures a search API); without one the tool answers honestly
//! that search is not configured — it never fabricates results.

use crate::{Tool, ToolContext, ToolResult};
use std::sync::{Arc, Mutex, OnceLock};

/// One search result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// The search backend: query in, hits out. Installed by the CLI when
/// `ORBIT_SEARCH_API` (url) + `ORBIT_SEARCH_KEY` are configured.
pub type SearchBackend = Arc<dyn Fn(&str) -> Result<Vec<SearchHit>, String> + Send + Sync>;

fn backend() -> &'static Mutex<Option<SearchBackend>> {
    static B: OnceLock<Mutex<Option<SearchBackend>>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(None))
}

/// Install (or clear) the search backend.
pub fn set_search_backend(b: Option<SearchBackend>) {
    if let Ok(mut g) = backend().lock() {
        *g = b;
    }
}

/// Is search configured? (The TUI status line and the system prompt
/// both ask before advertising the tool.)
pub fn search_configured() -> bool {
    backend().lock().map(|g| g.is_some()).unwrap_or(false)
}

/// A Tavily-style search backend: POST {api} with the key, read
/// `results[].{title,url,content}`. Kept wire-generic (any API that
/// speaks this shape works); the default ORBIT_SEARCH_API value is
/// `https://api.tavily.com/search`. Runs on a short-lived thread with
/// its own mini runtime (the tool executor is sync — the same pattern
/// as WebFetch).
pub fn tavily_backend(api: &str, key: &str) -> SearchBackend {
    let api = api.to_string();
    let key = key.to_string();
    Arc::new(move |query: &str| {
        let api = api.clone();
        let key = key.clone();
        let query = query.to_string();
        let joined = std::thread::spawn(move || -> Result<Vec<SearchHit>, String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async {
                let mut roots = rustls::RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(cert);
                }
                let cfg = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let client = reqwest::Client::builder()
                    .use_preconfigured_tls(cfg)
                    .timeout(std::time::Duration::from_secs(20))
                    .build()
                    .map_err(|e| e.to_string())?;
                let body = serde_json::json!({
                    "api_key": key,
                    "query": query,
                    "max_results": 10,
                });
                let resp = client
                    .post(&api)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("search API status {}", resp.status()));
                }
                let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
                Ok(v.get("results")
                    .and_then(|r| r.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|h| {
                                Some(SearchHit {
                                    title: h.get("title")?.as_str()?.to_string(),
                                    url: h.get("url")?.as_str()?.to_string(),
                                    snippet: h
                                        .get("content")
                                        .or_else(|| h.get("snippet"))
                                        .and_then(|c| c.as_str())
                                        .unwrap_or_default()
                                        .to_string(),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default())
            })
        });
        joined
            .join()
            .map_err(|_| "search thread panicked".to_string())?
    })
}

pub struct WebSearchTool;

impl Tool for WebSearchTool {
    fn name(&self) -> &'static str {
        "WebSearch"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "description": "Max results (default 10)"}
            },
            "required": ["query"]
        })
    }
    fn read_only(&self) -> bool {
        true
    }
    fn permission_key(&self, _input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "WebSearch".into(),
            pattern: String::new(),
        }
    }
    fn run(&self, args: &serde_json::Value, _cx: &ToolContext) -> ToolResult {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        if query.is_empty() {
            return ToolResult::err("WebSearch requires a query");
        }
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10)
            .clamp(1, 25) as usize;
        let guard = backend().lock();
        match guard {
            Ok(g) => match g.as_ref() {
                Some(b) => match b(query) {
                    Ok(hits) => {
                        let hits: Vec<SearchHit> = hits.into_iter().take(limit).collect();
                        ToolResult::ok(serde_json::json!({ "results": hits }))
                    }
                    Err(e) => ToolResult::err(&format!("search failed: {e}")),
                },
                None => ToolResult::err(
                    "web search is not configured (set ORBIT_SEARCH_API and ORBIT_SEARCH_KEY)",
                ),
            },
            Err(_) => ToolResult::err("search backend lock poisoned"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend slot is process-global; tests that swap it must not
    /// interleave (parallel cargo tests share one process).
    static BACKEND_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn honest_when_unconfigured() {
        let _g = BACKEND_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_search_backend(None);
        let cx = ToolContext::new(
            std::env::temp_dir().join("websearch-test"),
            "s".into(),
            std::env::temp_dir(),
        );
        let r = WebSearchTool.run(&serde_json::json!({"query": "rust"}), &cx);
        assert!(r.is_error);
        assert!(r.payload.contains("not configured"));
    }

    #[test]
    fn runs_the_installed_backend() {
        let _g = BACKEND_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_search_backend(Some(Arc::new(|_q: &str| {
            Ok(vec![SearchHit {
                title: "t".into(),
                url: "https://example.com".into(),
                snippet: "s".into(),
            }])
        })));
        let cx = ToolContext::new(
            std::env::temp_dir().join("websearch-test"),
            "s".into(),
            std::env::temp_dir(),
        );
        let r = WebSearchTool.run(&serde_json::json!({"query": "x"}), &cx);
        set_search_backend(None);
        assert!(!r.is_error);
        assert!(r.payload.contains("example.com"));
    }
}

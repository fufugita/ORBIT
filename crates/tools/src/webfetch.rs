//! WebFetch (Wave 2): fetch a URL, convert to Markdown, answer a
//! prompt about it.
//!
//! Rules (roadmap §Wave 2): HTTPS only; refuses localhost; 15-minute
//! cache; cross-host redirects are RETURNED, not followed; each new
//! domain is an egress grant recorded in the ledger. The tool runs
//! sync in the tool executor, so the fetch is a blocking reqwest call
//! on a dedicated client (no async plumbing through the executor).

use crate::{Tool, ToolContext, ToolResult};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Cache entry: (fetched_at, final_url, markdown).
struct Cached {
    at: Instant,
    final_url: String,
    md: String,
}

static CACHE: std::sync::Mutex<Option<HashMap<String, Cached>>> = std::sync::Mutex::new(None);
const TTL: Duration = Duration::from_secs(15 * 60);
const MAX_BYTES: usize = 2 * 1024 * 1024;

pub struct WebFetchTool;

impl Tool for WebFetchTool {
    fn name(&self) -> &'static str {
        "WebFetch"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch (https:// only)"},
                "prompt": {"type": "string", "description": "What to answer about the page (returned with the content)"}
            },
            "required": ["url"]
        })
    }
    fn read_only(&self) -> bool {
        true // reads the web; the egress grant is the ask
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        let domain = input
            .get("url")
            .and_then(|v| v.as_str())
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        crate::PermissionKey {
            tool: "WebFetch".into(),
            pattern: domain,
        }
    }
    fn run(&self, args: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let raw = args
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        let prompt = args
            .get("prompt")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let Ok(url) = url::Url::parse(raw) else {
            return ToolResult::err("invalid URL");
        };

        // Rules: https only, no localhost/private hosts.
        if url.scheme() != "https" {
            return ToolResult::err("WebFetch is HTTPS only");
        }
        if let Some(host) = url.host_str() {
            let h = host.trim_matches(['[', ']']);
            if h == "localhost"
                || h.starts_with("127.")
                || h == "::1"
                || h.starts_with("10.")
                || h.starts_with("192.168.")
                || h.strip_prefix("172.")
                    .and_then(|r| r.split('.').next())
                    .and_then(|n| n.parse::<u8>().ok())
                    .is_some_and(|n| (16..=31).contains(&n))
            {
                return ToolResult::err("WebFetch refuses localhost and private addresses");
            }
        } else {
            return ToolResult::err("URL has no host");
        }

        // Egress grant: a record per new domain, in the session dir
        // (the ledger writer lives in the front-ends; the tool drops a
        // grant file the writer picks up).
        let domain = url.host_str().unwrap_or_default().to_string();
        record_egress_grant(cx, &domain, raw);

        // Cache.
        let cache_key = raw.to_string();
        {
            let g = CACHE.lock().unwrap();
            if let Some(map) = g.as_ref() {
                if let Some(c) = map.get(&cache_key) {
                    if c.at.elapsed() < TTL {
                        return ToolResult::ok(serde_json::json!({
                            "url": c.final_url,
                            "content": c.md,
                            "prompt": prompt,
                            "cached": true
                        }));
                    }
                }
            }
        }

        // Fetch. A blocking client on a short-lived runtime (the tool
        // executor is sync; a tiny runtime per call is fine at this
        // call rate).
        let fetch_url = url.clone();
        let joined = std::thread::spawn(move || -> Result<(String, String, bool), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async {
                // Manual-roots rustls (the workspace pins
                // rustls-tls-manual-roots-no-provider): load the
                // system store, ring provider, webpki verification.
                let mut roots = rustls::RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(cert);
                }
                let cfg = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let client = reqwest::Client::builder()
                    .use_preconfigured_tls(cfg)
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|e| e.to_string())?;
                let resp = client
                    .get(fetch_url.clone())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                let status = resp.status();
                // Cross-host redirect: return it, do not follow.
                if status.is_redirection() {
                    if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok())
                    {
                        let next = fetch_url.join(loc).map_err(|e| e.to_string())?;
                        if next.host_str() != fetch_url.host_str() {
                            return Ok((format!("{next}"), String::new(), true));
                        }
                        // same-host redirect: one follow is enough
                        let resp2 = client
                            .get(next.clone())
                            .send()
                            .await
                            .map_err(|e| e.to_string())?;
                        if !resp2.status().is_success() {
                            return Err(format!("HTTP {}", resp2.status()));
                        }
                        let bytes = cap(resp2.bytes().await.map_err(|e| e.to_string())?.to_vec());
                        return Ok((next.to_string(), html_to_markdown(&bytes), false));
                    }
                }
                if !status.is_success() {
                    return Err(format!("HTTP {status}"));
                }
                let final_url = resp.url().clone();
                let bytes = cap(resp.bytes().await.map_err(|e| e.to_string())?.to_vec());
                Ok((final_url.to_string(), html_to_markdown(&bytes), false))
            })
        })
        .join()
        .map_err(|_| "fetch thread panicked".to_string());
        let fetched = match joined {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return ToolResult::err(&format!("WebFetch: {e}")),
            Err(_) => return ToolResult::err("WebFetch: fetch thread failed"),
        };

        let (final_url, md, was_redirect) = fetched;
        if was_redirect {
            // A cross-host redirect is surfaced, never followed.
            return ToolResult::ok(serde_json::json!({
                "url": raw,
                "redirects_to": final_url,
                "note": "cross-host redirect returned, not followed; fetch it explicitly if you trust it"
            }));
        }

        // Store in cache.
        {
            let mut g = CACHE.lock().unwrap();
            let map = g.get_or_insert_with(HashMap::new);
            map.insert(
                cache_key,
                Cached {
                    at: Instant::now(),
                    final_url: final_url.clone(),
                    md: md.clone(),
                },
            );
        }

        ToolResult::ok(serde_json::json!({
            "url": final_url,
            "content": md,
            "prompt": prompt
        }))
    }
}

fn cap(b: impl IntoIterator<Item = u8>) -> Vec<u8> {
    b.into_iter().take(MAX_BYTES).collect()
}

/// Record an egress grant under the session dir: one file per domain,
/// idempotent. The ledger writer appends it as a record.
fn record_egress_grant(cx: &ToolContext, domain: &str, first_url: &str) {
    let dir = cx.home.join("sessions").join(&cx.session_id).join("egress");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let safe: String = domain
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = std::fs::write(
        dir.join(format!("{safe}.json")),
        serde_json::json!({
            "domain": domain,
            "first_url": first_url,
            "granted_at": stamp,
            "tool": "WebFetch"
        })
        .to_string(),
    );
}

/// A pragmatic HTML→Markdown: strip scripts/styles/tags, keep links
/// and code blocks. Not a full converter — good enough for a model to
/// answer a prompt over the page.
pub fn html_to_markdown(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len() / 2);
    let mut in_code = false;
    let mut skip = false;
    let mut tag_buf = String::new();
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => {
                in_tag = true;
                tag_buf.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                let t = tag_buf.trim().to_lowercase();
                if t.starts_with("script") || t.starts_with("style") {
                    skip = true;
                } else if t.starts_with("/script") || t.starts_with("/style") {
                    skip = false;
                } else if t.starts_with("pre") || t.starts_with("code") {
                    in_code = true;
                    out.push('\n');
                } else if t.starts_with("/pre") || t.starts_with("/code") {
                    in_code = false;
                    out.push('\n');
                } else if t.starts_with("/p")
                    || t.starts_with("/div")
                    || t.starts_with("/h")
                    || t.starts_with("/li")
                    || t.starts_with("br")
                {
                    out.push('\n');
                } else if t.starts_with("li") {
                    out.push_str("- ");
                } else if t.len() > 2 && t.starts_with('h') && t.as_bytes()[1].is_ascii_digit() {
                    out.push_str("\n## ");
                }
            }
            _ if in_tag => tag_buf.push(c),
            _ if skip => {}
            '\n' if in_code => out.push(c),
            _ => out.push(c),
        }
    }
    // Collapse blank runs.
    let mut collapsed = String::with_capacity(out.len());
    let mut blank = 0;
    for line in out.lines() {
        if line.trim().is_empty() {
            blank += 1;
            if blank <= 1 {
                collapsed.push('\n');
            }
        } else {
            blank = 0;
            collapsed.push_str(line.trim_end());
            collapsed.push('\n');
        }
    }
    collapsed.trim().to_string()
}

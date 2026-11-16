//! OAuth sign-in for remote MCP servers (authorization code + PKCE, with
//! discovery and dynamic client registration, per the MCP authorization
//! specification).
//!
//! `login` discovers the server's authorization server, registers a public
//! client when the server allows it, opens the consent page, receives the
//! code on a loopback listener, exchanges it, and stores the tokens in
//! `$ORBIT_HOME/mcp-oauth/` (mode 0600). A remote server whose configuration
//! carries no `Authorization` header then connects with the stored bearer
//! token, refreshed when it is about to expire.
//!
//! Tokens never enter the configuration, the ledger or any message. Every
//! endpoint must be HTTPS (or loopback HTTP), redirects are refused, and the
//! token is only ever sent to the exact server URL it was issued for.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::{McpCallOptions, McpServerConfig, McpTransport, http};

mod storage;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Refresh this long before the access token expires.
const EXPIRY_MARGIN_SECS: u64 = 60;

static HOME: OnceLock<PathBuf> = OnceLock::new();

/// The home whose stored sign-ins this process uses. First call wins.
pub fn remember_home(home: &Path) {
    let _ = HOME.set(home.to_path_buf());
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Stored {
    server: String,
    /// The exact MCP server URL the token was issued for.
    resource: String,
    token_endpoint: String,
    client_id: String,
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    /// Unix seconds; `None` when the server gave no lifetime.
    #[serde(default)]
    expires_at: Option<u64>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
fn store_path(home: &Path, server: &str) -> PathBuf {
    home.join("mcp-oauth").join(store_name(server))
}

fn store_name(server: &str) -> String {
    let digest = hex::encode(Sha256::digest(server.as_bytes()));
    format!("{}.json", &digest[..24])
}

fn load(home: &Path, server: &str) -> Option<Stored> {
    let bytes = storage::read(home, &store_name(server), MAX_RESPONSE_BYTES).ok()?;
    let stored: Stored = serde_json::from_slice(&bytes).ok()?;
    (stored.server == server).then_some(stored)
}

fn save(home: &Path, stored: &Stored) -> Result<(), String> {
    let bytes = serde_json::to_vec(stored).map_err(|e| format!("mcp sign-in store: {e}"))?;
    storage::write(
        home,
        &store_name(&stored.server),
        &bytes,
        MAX_RESPONSE_BYTES,
    )
    .map_err(|e| format!("mcp sign-in store: {e}"))
}

/// Forget a server's stored sign-in. Returns whether there was one.
pub fn logout(home: &Path, server: &str) -> Result<bool, String> {
    match storage::remove(home, &store_name(server)) {
        Ok(removed) => Ok(removed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("mcp sign-out: {e}")),
    }
}

/// One line for `/mcp`: whether a sign-in is stored, never the token.
pub fn status(home: &Path, server: &str) -> Option<String> {
    let stored = load(home, server)?;
    Some(match stored.expires_at {
        Some(at) if at <= now_unix() && stored.refresh_token.is_none() => "sign-in expired".into(),
        Some(at) if at <= now_unix() => "signed in (refreshes on next use)".into(),
        Some(at) => format!("signed in (token valid {} min)", (at - now_unix()) / 60),
        None => "signed in".into(),
    })
}

/// The bearer token for a connection to `server` at `url`, refreshed when
/// due. `None` when there is no usable sign-in: the server then answers 401
/// and the operator is pointed at `/mcp login`.
pub(crate) fn bearer_for(server: &str, url: &str) -> Option<String> {
    bearer_in(HOME.get()?, server, url)
}

fn bearer_in(home: &Path, server: &str, url: &str) -> Option<String> {
    let stored = load(home, server)?;
    if stored.resource != url {
        return None;
    }
    let due = stored
        .expires_at
        .is_some_and(|at| at <= now_unix().saturating_add(EXPIRY_MARGIN_SECS));
    if !due {
        return Some(stored.access_token);
    }
    let refresh = stored.refresh_token.clone()?;
    let form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh.clone()),
        ("client_id", stored.client_id.clone()),
        ("resource", stored.resource.clone()),
    ];
    let answer = post_form(&stored.token_endpoint, form, None).ok()?;
    let mut next = token_from(&answer, &stored).ok()?;
    if next.refresh_token.is_none() {
        next.refresh_token = Some(refresh);
    }
    let _ = save(home, &next);
    Some(next.access_token)
}

fn token_from(answer: &Value, base: &Stored) -> Result<Stored, String> {
    let access = answer
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN_BYTES && header_safe(t))
        .ok_or("mcp sign-in: the token response has no usable access token")?;
    let kind = answer
        .get("token_type")
        .and_then(Value::as_str)
        .unwrap_or("Bearer");
    if !kind.eq_ignore_ascii_case("bearer") {
        return Err("mcp sign-in: the server issued a token type ORBIT cannot use".into());
    }
    let refresh = answer
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN_BYTES)
        .map(str::to_string);
    let expires_at = answer
        .get("expires_in")
        .and_then(Value::as_u64)
        .map(|secs| now_unix().saturating_add(secs));
    Ok(Stored {
        access_token: access.to_string(),
        refresh_token: refresh,
        expires_at,
        ..base.clone()
    })
}

fn header_safe(token: &str) -> bool {
    token.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

// ───────────────────────────── HTTP ─────────────────────────────

fn client() -> Result<reqwest::Client, String> {
    let tls = orbit_provider_http::tls::client_config(&orbit_adapter::types::TlsPinPolicy {
        webpki: true,
        spki_sha256: None,
    })
    .map_err(|_| "mcp sign-in: TLS configuration failed".to_string())?;
    let tls = Arc::try_unwrap(tls).unwrap_or_else(|tls| (*tls).clone());
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "mcp sign-in: HTTP client configuration failed".to_string())
}

type Cancel = Option<Arc<dyn Fn() -> bool + Send + Sync>>;

fn options(cancel: Cancel) -> McpCallOptions {
    let mut options = McpCallOptions::new(REQUEST_TIMEOUT);
    options.cancel = cancel;
    options
}

async fn bounded_json(response: reqwest::Response) -> Result<(u16, Value), String> {
    let status = response.status().as_u16();
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "mcp sign-in: the response was interrupted".to_string())?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err("mcp sign-in: the response is too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

/// GET a metadata document. `Ok(None)` when the server has none there.
fn get_json(url: &str, cancel: Cancel) -> Result<Option<Value>, String> {
    let url = http::validated_endpoint(url)?;
    let client = client()?;
    let (status, value) = http::run_owned(&options(cancel), async move {
        let response = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| "mcp sign-in: the server could not be reached".to_string())?;
        bounded_json(response).await
    })??;
    Ok((status == 200 && value.is_object()).then_some(value))
}

fn post_form(
    url: &str,
    form: Vec<(&'static str, String)>,
    cancel: Cancel,
) -> Result<Value, String> {
    let url = http::validated_endpoint(url)?;
    let client = client()?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().map(|(k, v)| (*k, v.as_str())))
        .finish();
    let (status, value) = http::run_owned(&options(cancel), async move {
        let response = client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(|_| "mcp sign-in: the token endpoint could not be reached".to_string())?;
        bounded_json(response).await
    })??;
    if status != 200 {
        return Err(oauth_error(
            "the token endpoint refused the request",
            status,
            &value,
        ));
    }
    Ok(value)
}

fn post_json(url: &str, payload: Value, cancel: Cancel) -> Result<Value, String> {
    let url = http::validated_endpoint(url)?;
    let client = client()?;
    let (status, value) = http::run_owned(&options(cancel), async move {
        let response = client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload.to_string())
            .send()
            .await
            .map_err(|_| "mcp sign-in: client registration could not be reached".to_string())?;
        bounded_json(response).await
    })??;
    if !(200..300).contains(&status) {
        return Err(oauth_error(
            "client registration was refused",
            status,
            &value,
        ));
    }
    Ok(value)
}

/// The server's own `error` code is safe to show; its description is not
/// (free text from a remote party), so it is reduced to plain characters.
fn oauth_error(what: &str, status: u16, value: &Value) -> String {
    let code: String = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect();
    if code.is_empty() {
        format!("mcp sign-in: {what} (status {status})")
    } else {
        format!("mcp sign-in: {what} ({code})")
    }
}

// ─────────────────────────── Discovery ───────────────────────────

/// `https://host/a/b` → `https://host/.well-known/<name>/a/b`, then the
/// bare `https://host/.well-known/<name>`.
fn well_known(base: &Url, name: &str) -> Vec<String> {
    let origin = base.origin().ascii_serialization();
    let path = base.path().trim_end_matches('/');
    let mut out = Vec::new();
    if !path.is_empty() {
        out.push(format!("{origin}/.well-known/{name}{path}"));
    }
    out.push(format!("{origin}/.well-known/{name}"));
    out
}

// Tenant issuers use their own discovery paths, including OIDC's appended
// form. A root document may describe a different issuer and is not a fallback.
fn authorization_metadata_urls(issuer: &Url) -> Vec<String> {
    let origin = issuer.origin().ascii_serialization();
    let path = issuer.path().trim_end_matches('/');
    let mut urls = vec![
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!("{origin}/.well-known/openid-configuration{path}"),
    ];
    if !path.is_empty() {
        urls.push(format!("{origin}{path}/.well-known/openid-configuration"));
    }
    urls
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoints {
    authorization: String,
    token: String,
    registration: Option<String>,
    scopes: Vec<String>,
}

fn string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 2048)
        .map(str::to_string)
}

fn endpoints_from(
    issuer: &str,
    metadata: &Value,
    scopes: Vec<String>,
) -> Result<Endpoints, String> {
    // RFC 8414 §3.3: the document must name the issuer it was fetched for.
    let named = string(metadata, "issuer")
        .ok_or("mcp sign-in: the authorization server metadata has no issuer")?;
    if named != issuer {
        return Err("mcp sign-in: the authorization server metadata names another issuer".into());
    }
    if let Some(methods) = metadata
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
        && !methods.iter().any(|m| m.as_str() == Some("S256"))
    {
        return Err("mcp sign-in: the authorization server does not support PKCE S256".into());
    }
    let authorization = string(metadata, "authorization_endpoint")
        .ok_or("mcp sign-in: no authorization endpoint in the server metadata")?;
    let token = string(metadata, "token_endpoint")
        .ok_or("mcp sign-in: no token endpoint in the server metadata")?;
    let registration = string(metadata, "registration_endpoint");
    for endpoint in [Some(&authorization), Some(&token), registration.as_ref()]
        .into_iter()
        .flatten()
    {
        http::validated_endpoint(endpoint)
            .map_err(|_| "mcp sign-in: the server metadata names an unusable endpoint")?;
    }
    Ok(Endpoints {
        authorization,
        token,
        registration,
        scopes,
    })
}

fn discover(resource: &str, cancel: &Cancel) -> Result<Endpoints, String> {
    discover_with(resource, |candidate| get_json(candidate, cancel.clone()))
}

fn discover_with(
    resource: &str,
    mut fetch: impl FnMut(&str) -> Result<Option<Value>, String>,
) -> Result<Endpoints, String> {
    let resource_url = http::validated_endpoint(resource)?;
    // 1. The protected resource names its authorization server (RFC 9728).
    let mut issuer = None;
    let mut scopes = Vec::new();
    for candidate in well_known(&resource_url, "oauth-protected-resource") {
        if let Some(doc) = fetch(&candidate)? {
            // RFC 9728 §§3.3, 6: bind metadata to the exact requested
            // resource before following any authorization-server URL.
            if doc.get("resource").and_then(Value::as_str) != Some(resource) {
                return Err(
                    "mcp sign-in: the resource metadata does not identify this server".into(),
                );
            }
            issuer = Some(
                doc.get("authorization_servers")
                    .and_then(Value::as_array)
                    .and_then(|list| list.first())
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or("mcp sign-in: the resource metadata names no authorization server")?
                    .to_string(),
            );
            scopes = doc
                .get("scopes_supported")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .filter(|s| !s.is_empty() && s.len() <= 128 && header_safe(s))
                        .take(32)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            break;
        }
    }
    // 2. Older servers are their own authorization server.
    let issuer = issuer.unwrap_or_else(|| resource_url.origin().ascii_serialization());
    let issuer_url = http::validated_endpoint(&issuer)
        .map_err(|_| "mcp sign-in: the server names an unusable authorization server")?;
    for candidate in authorization_metadata_urls(&issuer_url) {
        if let Some(doc) = fetch(&candidate)? {
            return endpoints_from(&issuer, &doc, scopes);
        }
    }
    Err("mcp sign-in: this server publishes no OAuth metadata (it may want a static header instead)".into())
}

// ───────────────────────────── PKCE ─────────────────────────────

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        out.push(ALPHABET[(b[0] >> 2) as usize] as char);
        out.push(ALPHABET[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b[2] & 0x3f) as usize] as char);
        }
    }
    out
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| "mcp sign-in: no secure random source".to_string())?;
    Ok(base64url(&bytes))
}

fn challenge(verifier: &str) -> String {
    base64url(&Sha256::digest(verifier.as_bytes()))
}

fn authorization_url(
    endpoints: &Endpoints,
    client_id: &str,
    redirect: &str,
    verifier: &str,
    state: &str,
    resource: &str,
) -> Result<String, String> {
    let mut url = http::validated_endpoint(&endpoints.authorization)?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect)
            .append_pair("code_challenge", &challenge(verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state)
            .append_pair("resource", resource);
        if !endpoints.scopes.is_empty() {
            query.append_pair("scope", &endpoints.scopes.join(" "));
        }
    }
    Ok(url.into())
}

// ─────────────────────────── Callback ───────────────────────────

/// The `code` from one callback request line, once `state` matches.
/// `Ok(None)`: not the callback (a favicon request) — keep waiting.
fn parse_callback(request_line: &str, state: &str) -> Result<Option<String>, String> {
    let mut parts = request_line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(None);
    };
    let Some(query) = target.strip_prefix("/callback?") else {
        return Ok(None);
    };
    let mut code = None;
    let mut seen_state = None;
    let mut error = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => seen_state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    if seen_state.as_deref() != Some(state) {
        return Err("mcp sign-in: the callback did not carry this sign-in's state".into());
    }
    if let Some(error) = error {
        let error: String = error
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(64)
            .collect();
        return Err(format!("mcp sign-in: the server refused ({error})"));
    }
    match code {
        Some(code) if !code.is_empty() && code.len() <= 4096 => Ok(Some(code)),
        _ => Err("mcp sign-in: the callback carried no code".into()),
    }
}

fn wait_for_code(
    listener: &std::net::TcpListener,
    state: &str,
    deadline: Instant,
    cancel: &Cancel,
) -> Result<String, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("mcp sign-in: {e}"))?;
    loop {
        if cancel.as_ref().is_some_and(|check| check()) {
            return Err("mcp sign-in cancelled".into());
        }
        if Instant::now() >= deadline {
            return Err("mcp sign-in timed out waiting for the browser".into());
        }
        let (mut stream, peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(format!("mcp sign-in: {e}")),
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let mut buffer = [0_u8; 8192];
        let mut filled = 0;
        while filled < buffer.len() {
            match stream.read(&mut buffer[filled..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    filled += n;
                    if buffer[..filled].contains(&b'\n') {
                        break;
                    }
                }
            }
        }
        let text = String::from_utf8_lossy(&buffer[..filled]);
        let outcome = parse_callback(text.lines().next().unwrap_or(""), state);
        let (status, message) = match &outcome {
            Ok(Some(_)) => (
                "200 OK",
                "Signed in. You can close this tab and return to ORBIT.",
            ),
            Ok(None) => ("404 Not Found", "Not the sign-in callback."),
            Err(_) => (
                "400 Bad Request",
                "Sign-in failed. Return to ORBIT for the reason.",
            ),
        };
        let body =
            format!("<!doctype html><meta charset=utf-8><title>ORBIT</title><p>{message}</p>");
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.flush();
        match outcome {
            Ok(Some(code)) => return Ok(code),
            Ok(None) => continue,
            Err(error) => return Err(error),
        }
    }
}

fn open_browser(url: &str) {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(program)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

// ───────────────────────────── Login ─────────────────────────────

/// Sign in to one configured remote server. `announce` receives the consent
/// URL before the wait starts (the browser may not open by itself).
/// `client_id` skips dynamic registration for servers that do not offer it.
pub fn login(
    home: &Path,
    server: &str,
    config: &McpServerConfig,
    client_id: Option<&str>,
    announce: &mut dyn FnMut(&str),
    timeout: Duration,
    cancel: Cancel,
) -> Result<String, String> {
    login_with(
        home,
        server,
        config,
        client_id,
        announce,
        timeout,
        cancel,
        open_browser,
    )
}

#[allow(clippy::too_many_arguments)]
fn login_with(
    home: &Path,
    server: &str,
    config: &McpServerConfig,
    client_id: Option<&str>,
    announce: &mut dyn FnMut(&str),
    timeout: Duration,
    cancel: Cancel,
    open: fn(&str),
) -> Result<String, String> {
    if config.transport == McpTransport::Stdio {
        return Err(format!("{server} is a stdio server: it has no sign-in"));
    }
    let resource = config
        .url
        .as_deref()
        .ok_or("mcp remote configuration requires a URL")?;
    let deadline = Instant::now() + timeout;
    let endpoints = discover(resource, &cancel)?;

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("mcp sign-in: no loopback port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("mcp sign-in: {e}"))?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let client_id = match client_id {
        Some(id) if !id.is_empty() && id.len() <= 512 && header_safe(id) => id.to_string(),
        Some(_) => return Err("mcp sign-in: unusable client id".into()),
        None => {
            let registration = endpoints.registration.as_deref().ok_or(
                "mcp sign-in: this server does not register clients; pass a client id: /mcp login <server> <client-id>",
            )?;
            let answer = post_json(
                registration,
                serde_json::json!({
                    "client_name": "ORBIT",
                    "redirect_uris": [redirect],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                }),
                cancel.clone(),
            )?;
            string(&answer, "client_id")
                .filter(|id| header_safe(id))
                .ok_or("mcp sign-in: registration returned no client id")?
        }
    };

    let verifier = random_token()?;
    let state = random_token()?;
    let url = authorization_url(
        &endpoints, &client_id, &redirect, &verifier, &state, resource,
    )?;
    announce(&url);
    open(&url);
    let code = wait_for_code(&listener, &state, deadline, &cancel)?;
    drop(listener);

    let answer = post_form(
        &endpoints.token,
        vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("redirect_uri", redirect),
            ("client_id", client_id.clone()),
            ("code_verifier", verifier),
            ("resource", resource.to_string()),
        ],
        cancel,
    )?;
    let stored = token_from(
        &answer,
        &Stored {
            server: server.to_string(),
            resource: resource.to_string(),
            token_endpoint: endpoints.token,
            client_id,
            access_token: String::new(),
            refresh_token: None,
            expires_at: None,
        },
    )?;
    save(home, &stored)?;
    Ok(format!("signed in to {server}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_the_rfc_7636_example() {
        // RFC 7636 appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }

    #[test]
    fn well_known_urls_put_the_path_after_the_suffix() {
        let url = Url::parse("https://mcp.example.com/v1/mcp").unwrap();
        assert_eq!(
            well_known(&url, "oauth-protected-resource"),
            [
                "https://mcp.example.com/.well-known/oauth-protected-resource/v1/mcp",
                "https://mcp.example.com/.well-known/oauth-protected-resource",
            ]
        );
        let bare = Url::parse("https://auth.example.com").unwrap();
        assert_eq!(
            well_known(&bare, "oauth-authorization-server"),
            ["https://auth.example.com/.well-known/oauth-authorization-server"]
        );
    }

    #[test]
    fn metadata_must_name_its_issuer_support_s256_and_use_https() {
        let good = serde_json::json!({
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "registration_endpoint": "https://auth.example.com/register",
            "code_challenge_methods_supported": ["plain", "S256"],
        });
        let endpoints = endpoints_from("https://auth.example.com", &good, vec![]).unwrap();
        assert_eq!(endpoints.token, "https://auth.example.com/token");
        assert!(endpoints.registration.is_some());

        let mut other = good.clone();
        other["issuer"] = "https://evil.example.com".into();
        assert!(endpoints_from("https://auth.example.com", &other, vec![]).is_err());
        let mut plain = good.clone();
        plain["code_challenge_methods_supported"] = serde_json::json!(["plain"]);
        assert!(endpoints_from("https://auth.example.com", &plain, vec![]).is_err());
        let mut http = good.clone();
        http["token_endpoint"] = "http://auth.example.com/token".into();
        assert!(endpoints_from("https://auth.example.com", &http, vec![]).is_err());
        let mut missing = good;
        missing
            .as_object_mut()
            .unwrap()
            .remove("authorization_endpoint");
        assert!(endpoints_from("https://auth.example.com", &missing, vec![]).is_err());
    }

    #[test]
    fn metadata_requires_an_exact_issuer_without_normalization() {
        let issuer = "https://auth.example.com/tenant";
        let good = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "code_challenge_methods_supported": ["S256"],
        });
        assert!(endpoints_from(issuer, &good, vec![]).is_ok());
        for named in [
            Value::Null,
            Value::Bool(false),
            Value::String(String::new()),
            Value::String(format!("{issuer}/")),
            Value::String("https://AUTH.example.com/tenant".into()),
        ] {
            let mut metadata = good.clone();
            metadata["issuer"] = named;
            assert!(
                endpoints_from(issuer, &metadata, vec![]).is_err(),
                "{metadata}"
            );
        }
        let mut missing = good;
        missing.as_object_mut().unwrap().remove("issuer");
        assert!(endpoints_from(issuer, &missing, vec![]).is_err());
    }

    fn discovery_metadata(issuer: &str) -> Value {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "code_challenge_methods_supported": ["S256"],
        })
    }

    #[test]
    fn discovery_rejects_missing_or_mismatched_resource_before_contacting_an_issuer() {
        let resource = "https://mcp.example.com/tenant/mcp";
        for named in [
            None,
            Some(Value::Null),
            Some(Value::Bool(true)),
            Some(Value::String(String::new())),
            Some(Value::String(format!("{resource}/"))),
            Some(Value::String("https://mcp.example.com/other/mcp".into())),
            Some(Value::String("https://mcp.example.com/tenant/%6dcp".into())),
            Some(Value::String("https://MCP.example.com/tenant/mcp".into())),
        ] {
            let mut document = serde_json::json!({
                "authorization_servers": ["https://auth.example.com"],
            });
            if let Some(named) = named {
                document["resource"] = named;
            }
            let mut requests = Vec::new();
            let result = discover_with(resource, |url| {
                requests.push(url.to_string());
                if requests.len() == 1 {
                    Ok(Some(document.clone()))
                } else {
                    Ok(Some(discovery_metadata("https://auth.example.com")))
                }
            });
            assert!(result.is_err(), "unbound metadata accepted: {document}");
            assert_eq!(requests.len(), 1, "invalid metadata must stop discovery");
        }
    }

    #[test]
    fn discovery_requires_an_authorization_server_in_present_resource_metadata() {
        let resource = "https://mcp.example.com/mcp";
        for servers in [
            None,
            Some(Value::Null),
            Some(serde_json::json!([])),
            Some(serde_json::json!([null])),
            Some(serde_json::json!([""])),
            Some(serde_json::json!("https://auth.example.com")),
        ] {
            let mut document = serde_json::json!({"resource": resource});
            if let Some(servers) = servers {
                document["authorization_servers"] = servers;
            }
            let mut requests = 0;
            let result = discover_with(resource, |_| {
                requests += 1;
                if requests == 1 {
                    Ok(Some(document.clone()))
                } else {
                    Ok(Some(discovery_metadata("https://mcp.example.com")))
                }
            });
            assert!(result.is_err(), "malformed metadata accepted: {document}");
            assert_eq!(
                requests, 1,
                "malformed metadata must not trigger legacy fallback"
            );
        }
    }

    #[test]
    fn discovery_uses_root_resource_metadata_only_when_bound_to_the_requested_resource() {
        let resource = "https://mcp.example.com/tenant/mcp";
        let issuer = "https://auth.example.com";
        let mut requests = Vec::new();
        let endpoints = discover_with(resource, |url| {
            requests.push(url.to_string());
            match url {
                "https://mcp.example.com/.well-known/oauth-protected-resource/tenant/mcp" => {
                    Ok(None)
                }
                "https://mcp.example.com/.well-known/oauth-protected-resource" => {
                    Ok(Some(serde_json::json!({
                        "resource": resource,
                        "authorization_servers": [issuer],
                        "scopes_supported": ["read"],
                    })))
                }
                "https://auth.example.com/.well-known/oauth-authorization-server" => {
                    Ok(Some(discovery_metadata(issuer)))
                }
                _ => panic!("unexpected discovery request: {url}"),
            }
        })
        .unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(endpoints.token, "https://auth.example.com/token");
        assert_eq!(endpoints.scopes, ["read"]);
    }

    #[test]
    fn discovery_reaches_path_appended_openid_metadata_without_querying_another_tenant() {
        let resource = "https://mcp.example.com/mcp";
        let issuer = "https://auth.example.com/tenant";
        let mut requests = Vec::new();
        let result = discover_with(resource, |url| {
            requests.push(url.to_string());
            if url == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" {
                Ok(Some(serde_json::json!({
                    "resource": resource,
                    "authorization_servers": [issuer],
                })))
            } else if url == "https://auth.example.com/tenant/.well-known/openid-configuration" {
                Ok(Some(discovery_metadata(issuer)))
            } else {
                Ok(None)
            }
        });
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            requests,
            [
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                "https://auth.example.com/.well-known/oauth-authorization-server/tenant",
                "https://auth.example.com/.well-known/openid-configuration/tenant",
                "https://auth.example.com/tenant/.well-known/openid-configuration",
            ]
        );
    }

    #[test]
    fn discovery_keeps_legacy_origin_fallback_when_resource_metadata_is_absent() {
        let mut requests = Vec::new();
        let endpoints = discover_with("https://mcp.example.com/mcp", |url| {
            requests.push(url.to_string());
            if url == "https://mcp.example.com/.well-known/openid-configuration" {
                Ok(Some(discovery_metadata("https://mcp.example.com")))
            } else {
                Ok(None)
            }
        })
        .unwrap();
        assert_eq!(endpoints.token, "https://mcp.example.com/token");
        assert_eq!(
            requests,
            [
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                "https://mcp.example.com/.well-known/oauth-protected-resource",
                "https://mcp.example.com/.well-known/oauth-authorization-server",
                "https://mcp.example.com/.well-known/openid-configuration",
            ]
        );
    }

    #[cfg(unix)]
    fn storage_fixture() -> (PathBuf, Stored) {
        use std::os::unix::fs::DirBuilderExt;
        let home = std::env::temp_dir().join(format!("orbit-oauth-store-{}", ulid::Ulid::new()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&home)
            .unwrap();
        let stored = Stored {
            server: "docs".into(),
            resource: "https://mcp.example.com/mcp".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            client_id: "client".into(),
            access_token: "fixture-token".into(),
            refresh_token: None,
            expires_at: None,
        };
        (home, stored)
    }

    #[cfg(unix)]
    #[test]
    fn storage_refuses_a_symlinked_directory_without_changing_its_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (home, stored) = storage_fixture();
        let outside = home.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside, home.join("mcp-oauth")).unwrap();
        let result = save(&home, &stored);
        let unchanged = std::fs::read_dir(&outside).unwrap().count() == 0
            && std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777 == 0o755;
        std::fs::remove_dir_all(&home).unwrap();
        assert!(result.is_err(), "symlinked storage must be refused");
        assert!(
            unchanged,
            "the symlink target must not be written or chmodded"
        );
    }

    #[cfg(unix)]
    #[test]
    fn storage_does_not_follow_a_preexisting_temporary_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (home, stored) = storage_fixture();
        std::fs::create_dir(home.join("mcp-oauth")).unwrap();
        std::fs::set_permissions(
            home.join("mcp-oauth"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let target = home.join("keep-me");
        std::fs::write(&target, b"original bytes").unwrap();
        let old_temp =
            store_path(&home, &stored.server).with_extension(format!("tmp-{}", std::process::id()));
        symlink(&target, old_temp).unwrap();
        let result = save(&home, &stored);
        let unchanged = std::fs::read(&target).unwrap() == b"original bytes";
        let saved = load(&home, &stored.server);
        std::fs::remove_dir_all(&home).unwrap();
        assert!(result.is_ok());
        assert!(
            unchanged,
            "the preexisting symlink target must not be truncated"
        );
        assert_eq!(saved, Some(stored));
    }

    #[cfg(unix)]
    #[test]
    fn storage_refuses_exposed_and_hardlinked_records_without_repair() {
        use std::os::unix::fs::PermissionsExt;
        let (home, stored) = storage_fixture();
        save(&home, &stored).unwrap();
        let path = store_path(&home, &stored.server);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&home, &stored.server).is_none());
        assert!(save(&home, &stored).is_err());
        assert!(logout(&home, &stored.server).is_err());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = home.join("linked-record");
        std::fs::hard_link(&path, &alias).unwrap();
        let before = std::fs::read(&alias).unwrap();
        assert!(load(&home, &stored.server).is_none());
        assert!(save(&home, &stored).is_err());
        assert!(logout(&home, &stored.server).is_err());
        assert_eq!(std::fs::read(&alias).unwrap(), before);
        std::fs::remove_file(alias).unwrap();
        assert_eq!(load(&home, &stored.server), Some(stored));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn storage_concurrent_saves_publish_complete_records_without_temp_collisions() {
        let (home, stored) = storage_fixture();
        std::thread::scope(|scope| {
            for index in 0..8 {
                let home = &home;
                let mut stored = stored.clone();
                stored.access_token = format!("token-{index}");
                scope.spawn(move || save(home, &stored).unwrap());
            }
        });
        let saved = load(&home, &stored.server).unwrap();
        assert!(saved.access_token.starts_with("token-"));
        assert_eq!(
            std::fs::read_dir(home.join("mcp-oauth")).unwrap().count(),
            1
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn storage_bounds_records_before_creating_files() {
        let (home, mut stored) = storage_fixture();
        stored.access_token = "x".repeat(MAX_RESPONSE_BYTES);
        assert!(save(&home, &stored).is_err());
        assert!(!home.join("mcp-oauth").exists());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn the_authorization_url_carries_pkce_state_resource_and_scope() {
        let endpoints = Endpoints {
            authorization: "https://auth.example.com/authorize?tenant=a".into(),
            token: "https://auth.example.com/token".into(),
            registration: None,
            scopes: vec!["read".into(), "write".into()],
        };
        let url = authorization_url(
            &endpoints,
            "client 1",
            "http://127.0.0.1:4000/callback",
            "verifier",
            "st&te",
            "https://mcp.example.com/mcp",
        )
        .unwrap();
        let parsed = Url::parse(&url).unwrap();
        let get = |key: &str| {
            parsed
                .query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        };
        assert_eq!(get("tenant").as_deref(), Some("a"));
        assert_eq!(get("response_type").as_deref(), Some("code"));
        assert_eq!(get("client_id").as_deref(), Some("client 1"));
        assert_eq!(get("state").as_deref(), Some("st&te"));
        assert_eq!(get("code_challenge_method").as_deref(), Some("S256"));
        assert_eq!(get("code_challenge"), Some(challenge("verifier")));
        assert_eq!(
            get("resource").as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        assert_eq!(get("scope").as_deref(), Some("read write"));
        assert!(
            !url.contains("verifier"),
            "the verifier never leaves the process"
        );
    }

    #[test]
    fn the_callback_needs_the_right_state_and_a_code() {
        assert_eq!(
            parse_callback("GET /callback?code=abc&state=s1 HTTP/1.1", "s1"),
            Ok(Some("abc".into()))
        );
        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1", "s1"), Ok(None));
        assert_eq!(
            parse_callback("POST /callback?code=abc&state=s1 HTTP/1.1", "s1"),
            Ok(None)
        );
        assert!(parse_callback("GET /callback?code=abc&state=other HTTP/1.1", "s1").is_err());
        assert!(parse_callback("GET /callback?code=abc HTTP/1.1", "s1").is_err());
        assert!(parse_callback("GET /callback?state=s1 HTTP/1.1", "s1").is_err());
        let refused = parse_callback(
            "GET /callback?error=access_denied%3Cb%3E&state=s1 HTTP/1.1",
            "s1",
        )
        .unwrap_err();
        assert!(refused.ends_with("(access_deniedb)"), "{refused}");
    }

    #[test]
    fn the_listener_hands_back_the_code_and_answers_the_browser() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let browser = std::thread::spawn(move || {
            let mut replies = Vec::new();
            for target in ["/favicon.ico", "/callback?code=the-code&state=st"] {
                let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                write!(stream, "GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                let mut reply = String::new();
                let _ = stream.read_to_string(&mut reply);
                replies.push(reply);
            }
            replies
        });
        let code = wait_for_code(
            &listener,
            "st",
            Instant::now() + Duration::from_secs(10),
            &None,
        )
        .unwrap();
        assert_eq!(code, "the-code");
        let replies = browser.join().unwrap();
        assert!(replies[0].starts_with("HTTP/1.1 404"));
        assert!(replies[1].starts_with("HTTP/1.1 200"));
        assert!(!replies[1].contains("the-code"));
    }

    #[test]
    fn waiting_stops_on_cancel_and_on_the_deadline() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let cancelled: Cancel = Some(Arc::new(|| true));
        assert_eq!(
            wait_for_code(
                &listener,
                "s",
                Instant::now() + Duration::from_secs(5),
                &cancelled
            ),
            Err("mcp sign-in cancelled".into())
        );
        assert!(
            wait_for_code(&listener, "s", Instant::now(), &None)
                .unwrap_err()
                .contains("timed out")
        );
    }

    #[test]
    #[cfg(unix)]
    fn tokens_round_trip_privately_and_only_for_their_own_server() {
        let home = std::env::temp_dir().join(format!("orbit-mcp-oauth-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let base = Stored {
            server: "docs".into(),
            resource: "https://mcp.example.com/mcp".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            client_id: "c1".into(),
            access_token: String::new(),
            refresh_token: None,
            expires_at: None,
        };
        let stored = token_from(
            &serde_json::json!({
                "access_token": "tok-123", "token_type": "bearer",
                "expires_in": 3600, "refresh_token": "ref-9"
            }),
            &base,
        )
        .unwrap();
        assert_eq!(stored.access_token, "tok-123");
        assert!(stored.expires_at.unwrap() > now_unix() + 3000);
        save(&home, &stored).unwrap();
        assert_eq!(load(&home, "docs"), Some(stored.clone()));
        assert_eq!(load(&home, "other"), None);
        assert_eq!(
            bearer_in(&home, "docs", &stored.resource),
            Some("tok-123".into())
        );
        assert!(bearer_in(&home, "docs", "https://other.example.com/mcp").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store_path(&home, "docs"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let line = status(&home, "docs").unwrap();
        assert!(line.starts_with("signed in"), "{line}");
        assert!(!line.contains("tok-123"));
        assert_eq!(logout(&home, "docs"), Ok(true));
        assert_eq!(logout(&home, "docs"), Ok(false));
        assert_eq!(status(&home, "docs"), None);

        // Unusable token responses are refused.
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"access_token": ""}),
            serde_json::json!({"access_token": "a b"}),
            serde_json::json!({"access_token": "t", "token_type": "mac"}),
        ] {
            assert!(token_from(&bad, &base).is_err(), "{bad}");
        }
    }

    #[test]
    fn stdio_servers_have_no_sign_in() {
        let config: McpServerConfig =
            serde_json::from_value(serde_json::json!({"command": "server"})).unwrap();
        let error = login(
            Path::new("/nonexistent"),
            "local",
            &config,
            None,
            &mut |_| {},
            Duration::from_secs(1),
            None,
        )
        .unwrap_err();
        assert!(error.contains("stdio"), "{error}");
    }

    /// A loopback stand-in for an MCP server that is its own authorization
    /// server: metadata, registration and a token endpoint.
    fn fake_server() -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let (seen, requests) = std::sync::mpsc::channel();
        let origin = base.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut raw = Vec::new();
                let mut chunk = [0_u8; 4096];
                let (head_end, length) = loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (raw.len(), 0);
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..at]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (at + 4, length);
                    }
                };
                while raw.len() < head_end + length {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                }
                let text = String::from_utf8_lossy(&raw).into_owned();
                let line = text.lines().next().unwrap_or("").to_string();
                let body = text[head_end.min(text.len())..].to_string();
                let _ = seen.send(format!("{line} {body}"));
                let (status, json) =
                    if line.starts_with("GET /.well-known/oauth-authorization-server") {
                        (
                            "200 OK",
                            serde_json::json!({
                                "issuer": origin,
                                "authorization_endpoint": format!("{origin}/authorize"),
                                "token_endpoint": format!("{origin}/token"),
                                "registration_endpoint": format!("{origin}/register"),
                                "code_challenge_methods_supported": ["S256"],
                            }),
                        )
                    } else if line.starts_with("POST /register") {
                        (
                            "201 Created",
                            serde_json::json!({"client_id": "dyn-client"}),
                        )
                    } else if line.starts_with("POST /token")
                        && body.contains("grant_type=authorization_code")
                    {
                        (
                            "200 OK",
                            serde_json::json!({
                                "access_token": "first-token", "token_type": "Bearer",
                                "expires_in": 1, "refresh_token": "refresh-1"
                            }),
                        )
                    } else if line.starts_with("POST /token") {
                        (
                            "200 OK",
                            serde_json::json!({
                                "access_token": "second-token", "token_type": "Bearer",
                                "expires_in": 3600
                            }),
                        )
                    } else {
                        ("404 Not Found", serde_json::json!({"error": "not_found"}))
                    };
                let payload = json.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
            }
        });
        (base, requests)
    }

    #[test]
    #[cfg(unix)]
    fn a_whole_sign_in_registers_exchanges_stores_and_refreshes() {
        use std::os::unix::fs::DirBuilderExt;
        let home = std::env::temp_dir().join(format!("orbit-mcp-login-{}", ulid::Ulid::new()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&home)
            .unwrap();
        let (base, requests) = fake_server();
        let resource = format!("{base}/mcp");
        let config: McpServerConfig = serde_json::from_value(serde_json::json!({
            "transport": "streamable-http", "url": resource
        }))
        .unwrap();

        // The "browser": follow the consent URL's redirect_uri with a code.
        let (url_out, url_in) = std::sync::mpsc::channel::<String>();
        let browser = std::thread::spawn(move || {
            let consent = Url::parse(&url_in.recv().unwrap()).unwrap();
            let get = |key: &str| {
                consent
                    .query_pairs()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.into_owned())
                    .unwrap()
            };
            let redirect = Url::parse(&get("redirect_uri")).unwrap();
            let mut stream =
                std::net::TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
            write!(
                stream,
                "GET /callback?code=auth-code&state={} HTTP/1.1\r\nHost: x\r\n\r\n",
                get("state")
            )
            .unwrap();
            let mut reply = String::new();
            let _ = stream.read_to_string(&mut reply);
            (get("client_id"), get("resource"), get("code_challenge"))
        });
        let message = login_with(
            &home,
            "docs",
            &config,
            None,
            &mut |url| url_out.send(url.to_string()).unwrap(),
            Duration::from_secs(20),
            None,
            |_| {},
        )
        .unwrap();
        assert_eq!(message, "signed in to docs");
        let (client_id, asked_resource, code_challenge) = browser.join().unwrap();
        assert_eq!(client_id, "dyn-client");
        assert_eq!(asked_resource, resource);

        let stored = load(&home, "docs").unwrap();
        assert_eq!(stored.access_token, "first-token");
        assert_eq!(stored.resource, resource);

        // The exchange proved possession of the verifier behind the challenge.
        let seen: Vec<String> = requests.try_iter().collect();
        let exchange = seen
            .iter()
            .find(|r| r.contains("grant_type=authorization_code"))
            .unwrap();
        let verifier =
            url::form_urlencoded::parse(exchange.split(' ').next_back().unwrap().as_bytes())
                .find(|(k, _)| k == "code_verifier")
                .map(|(_, v)| v.into_owned())
                .unwrap();
        assert_eq!(challenge(&verifier), code_challenge);
        assert!(exchange.contains("code=auth-code"));

        // The token is for that URL only, and refreshes once it is due.
        assert_eq!(
            bearer_in(&home, "docs", "https://elsewhere.example/mcp"),
            None
        );
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(
            bearer_in(&home, "docs", &resource).as_deref(),
            Some("second-token")
        );
        let refreshed = load(&home, "docs").unwrap();
        assert_eq!(
            refreshed.refresh_token.as_deref(),
            Some("refresh-1"),
            "kept when not rotated"
        );
        let seen: Vec<String> = requests.try_iter().collect();
        assert!(seen.iter().any(|r| r.contains("grant_type=refresh_token")));
        assert_eq!(
            bearer_in(&home, "docs", &resource).as_deref(),
            Some("second-token")
        );
    }
}

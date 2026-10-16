//! Explicit, bounded provider catalog discovery with exact credential binding.
//!
//! Constructing a session resolves local credentials but sends no request. Its
//! catalog and detail calls share one deadline and byte allowance. HTTP errors
//! carry neither response bodies nor request URLs/headers. Sidecar publication
//! and configuration changes belong to the caller's complete setup candidate.

use crate::config::{ModelEntry, ProviderConfig, validate_provider_endpoint};
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ProviderAuthIdentity, ProviderCredentialError, ProviderCredentialSource,
    ProviderCredentialStore,
};
use orbit_provider_http::CancelToken;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::{Future, poll_fn};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio::time::Instant;
use url::Url;
use zeroize::Zeroizing;

pub const MAX_CATALOG_MODELS: usize = 8192;
pub const MAX_CATALOG_PAGES: usize = 32;
pub const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SESSION_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SELECTED_MODELS: usize = 128;
pub const MAX_DETAIL_CONCURRENCY: usize = 4;
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(45);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const PROVENANCE_VERSION: u32 = 1;
const MAX_MODEL_ID_BYTES: usize = 256;
const MAX_LABEL_BYTES: usize = 256;
const MAX_UNKNOWN_FIELDS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProfile {
    GenericOpenAi,
    OpenRouter,
    Anthropic,
    Ollama,
}

impl DiscoveryProfile {
    fn kind(self) -> &'static str {
        match self {
            Self::GenericOpenAi | Self::OpenRouter => "openai-compatible",
            Self::Anthropic => "anthropic",
            Self::Ollama => "ollama",
        }
    }
}

/// Names only the established schema, never inferred runtime capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataSource {
    GenericOpenAiModels,
    OpenRouterModels,
    AnthropicModels,
    AnthropicModelDetail,
    OllamaTags,
}

impl MetadataSource {
    fn profile(self) -> DiscoveryProfile {
        match self {
            Self::GenericOpenAiModels => DiscoveryProfile::GenericOpenAi,
            Self::OpenRouterModels => DiscoveryProfile::OpenRouter,
            Self::AnthropicModels | Self::AnthropicModelDetail => DiscoveryProfile::Anthropic,
            Self::OllamaTags => DiscoveryProfile::Ollama,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredModel {
    /// Exact provider identity; display escaping must never change selection.
    pub id: String,
    pub label: Option<String>,
    pub context_window: Option<u64>,
    pub max_output_tokens: Option<u32>,
    pub source: MetadataSource,
    /// False when a documented numeric field was malformed. Never merge it.
    pub metadata_valid: bool,
    /// Unknown values are deliberately not retained or made authoritative.
    pub unrecognized_fields: Vec<String>,
}

impl DiscoveredModel {
    pub fn needs_detail(&self) -> bool {
        !self.metadata_valid || self.context_window.is_none() || self.max_output_tokens.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryCompleteness {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryIssueKind {
    Cancelled,
    DeadlineExceeded,
    RequestTimeout,
    Transport,
    HttpStatus(u16),
    PageByteLimit,
    AggregateByteLimit,
    CatalogEntryLimit,
    CatalogPageLimit,
    SelectionLimit,
    InvalidJson,
    InvalidSchema,
    InvalidModelId,
    InvalidMetadata,
    ConflictingDuplicate,
    UnsupportedPagination,
    InvalidPagination,
    PaginationCycle,
    UnsupportedDetailSchema,
    DetailNotAttempted,
    DetailIdentityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryIssue {
    pub kind: DiscoveryIssueKind,
    pub model_id: Option<String>,
    pub page: Option<usize>,
}

impl DiscoveryIssue {
    fn new(kind: DiscoveryIssueKind) -> Self {
        Self {
            kind,
            model_id: None,
            page: None,
        }
    }

    fn model(kind: DiscoveryIssueKind, id: &str) -> Self {
        Self {
            kind,
            model_id: Some(id.to_owned()),
            page: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCatalog {
    pub models: Vec<DiscoveredModel>,
    pub completeness: DiscoveryCompleteness,
    pub issues: Vec<DiscoveryIssue>,
    pub pages_fetched: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDetails {
    /// Same order and IDs as the selected input, including unsuccessful details.
    pub models: Vec<DiscoveredModel>,
    pub completeness: DiscoveryCompleteness,
    pub issues: Vec<DiscoveryIssue>,
    pub considered: usize,
    pub attempted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    #[error("Provider discovery identity or endpoint is invalid")]
    InvalidProvider,
    #[error("Discovery schema does not match the selected adapter kind")]
    ProfileMismatch,
    #[error("Provider authentication could not be resolved: {0}")]
    Credential(ProviderCredentialError),
    #[error("Provider discovery HTTP initialization failed")]
    HttpInitialization,
}

/// Intentionally not cloneable. Request futures borrow the scoped secret and
/// are dropped on cancellation; no detached task can retain the credential.
pub struct DiscoverySession {
    endpoint: Url,
    identity: ProviderAuthIdentity,
    profile: DiscoveryProfile,
    credential: Option<SecretBytes>,
    credential_source: ProviderCredentialSource,
    client: reqwest::Client,
    cancel: CancelToken,
    deadline: Instant,
    consumed_bytes: AtomicUsize,
    detail_requests: AtomicUsize,
    detail_slots: tokio::sync::Semaphore,
}

impl std::fmt::Debug for DiscoverySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoverySession")
            .field("identity", &self.identity)
            .field("profile", &self.profile)
            .field("credential_source", &self.credential_source)
            .field("consumed_bytes", &self.consumed_bytes())
            .finish_non_exhaustive()
    }
}

impl DiscoverySession {
    pub fn new(
        home: &Path,
        provider: &ProviderConfig,
        profile: DiscoveryProfile,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
        cancel: CancelToken,
    ) -> Result<Self, DiscoveryError> {
        Self::new_with_lookup(home, provider, profile, draft, cancel, |name| {
            Ok(std::env::var_os(name).map(|value| SecretBytes::new(value.into_encoded_bytes())))
        })
    }

    /// Lookup injection exercises ENV precedence without process ENV mutation.
    /// Construction never opens a socket or creates a private-store directory.
    pub fn new_with_lookup<F>(
        home: &Path,
        provider: &ProviderConfig,
        profile: DiscoveryProfile,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
        cancel: CancelToken,
        lookup: F,
    ) -> Result<Self, DiscoveryError>
    where
        F: FnMut(&str) -> Result<Option<SecretBytes>, ProviderCredentialError>,
    {
        let deadline = Instant::now() + SESSION_TIMEOUT;
        if provider.kind != profile.kind() {
            return Err(DiscoveryError::ProfileMismatch);
        }
        let endpoint = validate_provider_endpoint(&provider.url)
            .map_err(|_| DiscoveryError::InvalidProvider)?;
        // These are protocol-owned cursor parameters, not a second base scope.
        if profile == DiscoveryProfile::Anthropic
            && endpoint
                .query_pairs()
                .any(|(key, _)| matches!(key.as_ref(), "after_id" | "before_id"))
        {
            return Err(DiscoveryError::InvalidProvider);
        }
        let identity = ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            endpoint.as_str(),
            provider.env.as_deref(),
        )
        .map_err(DiscoveryError::Credential)?;
        // Lexical absolute conversion preserves the store's descriptor-relative
        // no-follow validation; canonicalize would follow substituted symlinks.
        let home = std::path::absolute(home)
            .map_err(|_| DiscoveryError::Credential(ProviderCredentialError::UnsafeDirectory))?;
        let store = ProviderCredentialStore::new(&home).map_err(DiscoveryError::Credential)?;
        let resolved = store
            .resolve_with_draft(&identity, draft, lookup)
            .map_err(DiscoveryError::Credential)?;
        let credential_source = resolved.source();
        let credential = resolved.into_secret();
        let tls = orbit_provider_http::tls::client_config(&orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: None,
        })
        .map_err(|_| DiscoveryError::HttpInitialization)?;
        let tls = std::sync::Arc::try_unwrap(tls).unwrap_or_else(|tls| (*tls).clone());
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| DiscoveryError::HttpInitialization)?;
        Ok(Self {
            endpoint,
            identity,
            profile,
            credential,
            credential_source,
            client,
            cancel,
            deadline,
            consumed_bytes: AtomicUsize::new(0),
            detail_requests: AtomicUsize::new(0),
            detail_slots: tokio::sync::Semaphore::new(MAX_DETAIL_CONCURRENCY),
        })
    }

    pub fn identity(&self) -> &ProviderAuthIdentity {
        &self.identity
    }

    pub fn credential_source(&self) -> ProviderCredentialSource {
        self.credential_source
    }

    pub fn consumed_bytes(&self) -> usize {
        self.consumed_bytes.load(Ordering::SeqCst)
    }

    fn ready(&self) -> Result<(), DiscoveryIssueKind> {
        if self.cancel.is_cancelled() {
            Err(DiscoveryIssueKind::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(DiscoveryIssueKind::DeadlineExceeded)
        } else if self.consumed_bytes() >= MAX_SESSION_BYTES {
            Err(DiscoveryIssueKind::AggregateByteLimit)
        } else {
            Ok(())
        }
    }

    fn models_endpoint(&self, model: Option<&str>) -> Result<Url, DiscoveryIssueKind> {
        let mut endpoint = self.endpoint.clone();
        let base = endpoint.path().trim_end_matches('/');
        let path = if self.profile == DiscoveryProfile::Ollama {
            if base.ends_with("/api") {
                format!("{base}/tags")
            } else {
                format!("{base}/api/tags")
            }
        } else {
            format!("{}/models", if base.is_empty() { "/v1" } else { base })
        };
        endpoint.set_path(&path);
        if let Some(model) = model {
            if !valid_model_id(model) {
                return Err(DiscoveryIssueKind::InvalidModelId);
            }
            endpoint
                .path_segments_mut()
                .map_err(|_| DiscoveryIssueKind::InvalidSchema)?
                .push(model);
        }
        Ok(endpoint)
    }

    async fn fetch(&self, endpoint: Url) -> Result<Value, DiscoveryIssueKind> {
        self.ready()?;
        let request_deadline = self.deadline.min(Instant::now() + REQUEST_TIMEOUT);
        let operation = async {
            let mut request = self.client.get(endpoint);
            if self.profile == DiscoveryProfile::Anthropic {
                request = request.header("anthropic-version", "2023-06-01");
            }
            if let Some(secret) = &self.credential {
                let mut header = if self.profile == DiscoveryProfile::Anthropic {
                    HeaderValue::from_bytes(secret.expose())
                } else {
                    let mut bearer = Zeroizing::new(Vec::with_capacity(7 + secret.len()));
                    bearer.extend_from_slice(b"Bearer ");
                    bearer.extend_from_slice(secret.expose());
                    HeaderValue::from_bytes(&bearer)
                }
                .map_err(|_| DiscoveryIssueKind::Transport)?;
                header.set_sensitive(true);
                request = if self.profile == DiscoveryProfile::Anthropic {
                    request.header("x-api-key", header)
                } else {
                    request.header(AUTHORIZATION, header)
                };
            }
            let mut response = request.send().await.map_err(|error| {
                if error.is_timeout() {
                    DiscoveryIssueKind::RequestTimeout
                } else {
                    DiscoveryIssueKind::Transport
                }
            })?;
            if !response.status().is_success() {
                return Err(DiscoveryIssueKind::HttpStatus(response.status().as_u16()));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_PAGE_BYTES as u64)
            {
                return Err(DiscoveryIssueKind::PageByteLimit);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|error| {
                if error.is_timeout() {
                    DiscoveryIssueKind::RequestTimeout
                } else {
                    DiscoveryIssueKind::Transport
                }
            })? {
                let previous = self
                    .consumed_bytes
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                        Some(used.saturating_add(chunk.len()).min(MAX_SESSION_BYTES))
                    })
                    .expect("byte allowance update always has a value");
                if chunk.len() > MAX_SESSION_BYTES.saturating_sub(previous) {
                    return Err(DiscoveryIssueKind::AggregateByteLimit);
                }
                if chunk.len() > MAX_PAGE_BYTES.saturating_sub(bytes.len()) {
                    return Err(DiscoveryIssueKind::PageByteLimit);
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes).map_err(|_| DiscoveryIssueKind::InvalidJson)
        };
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(DiscoveryIssueKind::Cancelled),
            result = tokio::time::timeout_at(request_deadline, operation) => match result {
                Ok(result) => result,
                Err(_) if Instant::now() >= self.deadline => Err(DiscoveryIssueKind::DeadlineExceeded),
                Err(_) => Err(DiscoveryIssueKind::RequestTimeout),
            },
        }
    }

    pub async fn catalog(&self) -> DiscoveredCatalog {
        let mut result = DiscoveredCatalog {
            models: Vec::new(),
            completeness: DiscoveryCompleteness::Complete,
            issues: Vec::new(),
            pages_fetched: 0,
        };
        let mut positions = HashMap::<String, usize>::new();
        let mut cursors = HashSet::new();
        let mut cursor: Option<String> = None;
        let mut entries_seen = 0_usize;
        loop {
            if result.pages_fetched >= MAX_CATALOG_PAGES {
                result
                    .issues
                    .push(DiscoveryIssue::new(DiscoveryIssueKind::CatalogPageLimit));
                break;
            }
            let mut endpoint = match self.models_endpoint(None) {
                Ok(endpoint) => endpoint,
                Err(kind) => {
                    result.issues.push(DiscoveryIssue::new(kind));
                    break;
                }
            };
            // The only continuation input is a validated documented model ID.
            // An upstream URL can never replace the exact origin/path/base query.
            if let Some(cursor) = &cursor {
                endpoint.query_pairs_mut().append_pair("after_id", cursor);
            }
            let page = match self.fetch(endpoint).await {
                Ok(page) => {
                    result.pages_fetched += 1;
                    page
                }
                Err(kind) => {
                    result.issues.push(DiscoveryIssue {
                        kind,
                        model_id: None,
                        page: Some(result.pages_fetched + 1),
                    });
                    break;
                }
            };
            let parsed = match parse_page(&page, self.profile) {
                Ok(parsed) => parsed,
                Err(kind) => {
                    result.issues.push(DiscoveryIssue {
                        kind,
                        model_id: None,
                        page: Some(result.pages_fetched),
                    });
                    break;
                }
            };
            if parsed.entry_count > MAX_CATALOG_MODELS.saturating_sub(entries_seen) {
                result
                    .issues
                    .push(DiscoveryIssue::new(DiscoveryIssueKind::CatalogEntryLimit));
                break;
            }
            entries_seen += parsed.entry_count;
            result.issues.extend(parsed.issues);
            let mut conflict = false;
            for model in parsed.models {
                if let Some(index) = positions.get(&model.id).copied() {
                    if !same_observation(&result.models[index], &model) {
                        result.issues.push(DiscoveryIssue::model(
                            DiscoveryIssueKind::ConflictingDuplicate,
                            &model.id,
                        ));
                        conflict = true;
                        break;
                    }
                    continue;
                }
                if result.models.len() >= MAX_CATALOG_MODELS {
                    result
                        .issues
                        .push(DiscoveryIssue::new(DiscoveryIssueKind::CatalogEntryLimit));
                    conflict = true;
                    break;
                }
                positions.insert(model.id.clone(), result.models.len());
                result.models.push(model);
            }
            if conflict {
                break;
            }
            match parsed.next {
                Ok(Some(next)) => {
                    if entries_seen >= MAX_CATALOG_MODELS {
                        result
                            .issues
                            .push(DiscoveryIssue::new(DiscoveryIssueKind::CatalogEntryLimit));
                        break;
                    }
                    if !cursors.insert(next.clone()) {
                        result
                            .issues
                            .push(DiscoveryIssue::new(DiscoveryIssueKind::PaginationCycle));
                        break;
                    }
                    cursor = Some(next);
                }
                Ok(None) => break,
                Err(kind) => {
                    result.issues.push(DiscoveryIssue::new(kind));
                    break;
                }
            }
        }
        if !result.issues.is_empty() {
            result.completeness = DiscoveryCompleteness::Incomplete;
        }
        result
    }

    /// At most four borrowed HTTP futures exist. Every selected unknown entry
    /// is considered, and refresh requests all selected Anthropic entries.
    pub async fn details(&self, selected: &[DiscoveredModel], refresh: bool) -> DiscoveredDetails {
        let mut result = DiscoveredDetails {
            models: Vec::new(),
            completeness: DiscoveryCompleteness::Complete,
            issues: Vec::new(),
            considered: 0,
            attempted: 0,
        };
        if selected.len() > MAX_SELECTED_MODELS {
            result.completeness = DiscoveryCompleteness::Incomplete;
            result
                .issues
                .push(DiscoveryIssue::new(DiscoveryIssueKind::SelectionLimit));
            return result;
        }
        result.models = selected.to_vec();
        result.considered = selected.len();
        let mut ids = HashSet::new();
        for model in selected {
            if !valid_model_id(&model.id) || !ids.insert(model.id.as_str()) {
                result.completeness = DiscoveryCompleteness::Incomplete;
                result
                    .issues
                    .push(DiscoveryIssue::new(DiscoveryIssueKind::InvalidModelId));
                return result;
            }
            if model.source.profile() != self.profile {
                result.completeness = DiscoveryCompleteness::Incomplete;
                result.issues.push(DiscoveryIssue::model(
                    DiscoveryIssueKind::DetailIdentityMismatch,
                    &model.id,
                ));
                return result;
            }
        }
        let mut queue: VecDeque<usize> = selected
            .iter()
            .enumerate()
            .filter_map(|(index, model)| (refresh || model.needs_detail()).then_some(index))
            .collect();
        if !queue.is_empty()
            && let Err(kind) = self.ready()
        {
            result.completeness = DiscoveryCompleteness::Incomplete;
            if let Some(index) = queue.pop_front() {
                result
                    .issues
                    .push(DiscoveryIssue::model(kind, &selected[index].id));
            }
            for index in queue {
                result.issues.push(DiscoveryIssue::model(
                    DiscoveryIssueKind::DetailNotAttempted,
                    &selected[index].id,
                ));
            }
            return result;
        }
        if self.profile != DiscoveryProfile::Anthropic {
            if !queue.is_empty() {
                result.completeness = DiscoveryCompleteness::Incomplete;
                result.issues.push(DiscoveryIssue::new(
                    DiscoveryIssueKind::UnsupportedDetailSchema,
                ));
            }
            return result;
        }
        type DetailFuture<'a> =
            Pin<Box<dyn Future<Output = Result<DiscoveredModel, DiscoveryIssueKind>> + Send + 'a>>;
        let mut pending: Vec<(usize, DetailFuture<'_>)> = Vec::new();
        loop {
            while pending.len() < MAX_DETAIL_CONCURRENCY {
                let Some(index) = queue.pop_front() else {
                    break;
                };
                if let Err(kind) = self.ready() {
                    result
                        .issues
                        .push(DiscoveryIssue::model(kind, &selected[index].id));
                    for index in queue.drain(..) {
                        result.issues.push(DiscoveryIssue::model(
                            DiscoveryIssueKind::DetailNotAttempted,
                            &selected[index].id,
                        ));
                    }
                    break;
                }
                if self
                    .detail_requests
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                        (used < MAX_SELECTED_MODELS).then_some(used + 1)
                    })
                    .is_err()
                {
                    result.issues.push(DiscoveryIssue::model(
                        DiscoveryIssueKind::SelectionLimit,
                        &selected[index].id,
                    ));
                    for index in queue.drain(..) {
                        result.issues.push(DiscoveryIssue::model(
                            DiscoveryIssueKind::DetailNotAttempted,
                            &selected[index].id,
                        ));
                    }
                    break;
                }
                result.attempted += 1;
                pending.push((index, Box::pin(self.detail(&selected[index].id))));
            }
            if pending.is_empty() {
                break;
            }
            let (ready_index, detail) = poll_fn(|cx| {
                for (index, (_, future)) in pending.iter_mut().enumerate() {
                    if let Poll::Ready(value) = future.as_mut().poll(cx) {
                        return Poll::Ready((index, value));
                    }
                }
                Poll::Pending
            })
            .await;
            let (index, finished) = pending.swap_remove(ready_index);
            drop(finished);
            match detail {
                Ok(model) => {
                    if !model.metadata_valid {
                        result.issues.push(DiscoveryIssue::model(
                            DiscoveryIssueKind::InvalidMetadata,
                            &model.id,
                        ));
                    }
                    result.models[index] = model;
                }
                Err(kind) => result
                    .issues
                    .push(DiscoveryIssue::model(kind, &selected[index].id)),
            }
        }
        if !result.issues.is_empty() {
            result.completeness = DiscoveryCompleteness::Incomplete;
        }
        result
    }

    async fn detail(&self, id: &str) -> Result<DiscoveredModel, DiscoveryIssueKind> {
        self.ready()?;
        // Public session calls may themselves overlap; the session-wide permit
        // keeps their combined in-flight detail count within the same ceiling.
        let _permit = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Err(DiscoveryIssueKind::Cancelled),
            result = tokio::time::timeout_at(self.deadline, self.detail_slots.acquire()) => {
                match result {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(DiscoveryIssueKind::Transport),
                    Err(_) => return Err(DiscoveryIssueKind::DeadlineExceeded),
                }
            }
        };
        let value = self.fetch(self.models_endpoint(Some(id))?).await?;
        let model = parse_model(&value, MetadataSource::AnthropicModelDetail)?;
        if model.id != id {
            return Err(DiscoveryIssueKind::DetailIdentityMismatch);
        }
        Ok(model)
    }
}

struct ParsedPage {
    models: Vec<DiscoveredModel>,
    entry_count: usize,
    issues: Vec<DiscoveryIssue>,
    next: Result<Option<String>, DiscoveryIssueKind>,
}

fn parse_page(value: &Value, profile: DiscoveryProfile) -> Result<ParsedPage, DiscoveryIssueKind> {
    let field = if profile == DiscoveryProfile::Ollama {
        "models"
    } else {
        "data"
    };
    let entries = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or(DiscoveryIssueKind::InvalidSchema)?;
    // Refuse an oversized page rather than allocate/truncate a complete catalog.
    if entries.len() > MAX_CATALOG_MODELS {
        return Err(DiscoveryIssueKind::CatalogEntryLimit);
    }
    let source = match profile {
        DiscoveryProfile::GenericOpenAi => MetadataSource::GenericOpenAiModels,
        DiscoveryProfile::OpenRouter => MetadataSource::OpenRouterModels,
        DiscoveryProfile::Anthropic => MetadataSource::AnthropicModels,
        DiscoveryProfile::Ollama => MetadataSource::OllamaTags,
    };
    let mut models = Vec::with_capacity(entries.len());
    let mut issues = Vec::new();
    for entry in entries {
        match parse_model(entry, source) {
            Ok(model) => {
                if !model.metadata_valid {
                    issues.push(DiscoveryIssue::model(
                        DiscoveryIssueKind::InvalidMetadata,
                        &model.id,
                    ));
                }
                models.push(model);
            }
            Err(kind) => issues.push(DiscoveryIssue::new(kind)),
        }
    }
    let next = if unknown_pagination(value) {
        Err(DiscoveryIssueKind::UnsupportedPagination)
    } else if profile == DiscoveryProfile::Anthropic {
        match value.get("has_more").and_then(Value::as_bool) {
            Some(false) => Ok(None),
            Some(true) => {
                let cursor = value
                    .get("last_id")
                    .and_then(Value::as_str)
                    .filter(|id| valid_model_id(id));
                match cursor {
                    Some(cursor)
                        if entries
                            .last()
                            .and_then(|entry| entry.get("id"))
                            .and_then(Value::as_str)
                            == Some(cursor) =>
                    {
                        Ok(Some(cursor.to_owned()))
                    }
                    _ => Err(DiscoveryIssueKind::InvalidPagination),
                }
            }
            None => Err(DiscoveryIssueKind::InvalidPagination),
        }
    } else if value
        .get("has_more")
        .is_some_and(|value| value != &Value::Bool(false) && !value.is_null())
    {
        Err(DiscoveryIssueKind::UnsupportedPagination)
    } else {
        Ok(None)
    };
    Ok(ParsedPage {
        models,
        entry_count: entries.len(),
        issues,
        next,
    })
}

fn unknown_pagination(value: &Value) -> bool {
    fn active(value: &Value) -> bool {
        !value.is_null() && value != &Value::Bool(false) && value.as_str() != Some("")
    }
    [
        "next",
        "next_page",
        "next_page_url",
        "next_cursor",
        "continuation_token",
    ]
    .iter()
    .any(|field| value.get(field).is_some_and(active))
        || value.pointer("/links/next").is_some_and(active)
}

fn parse_model(
    value: &Value,
    source: MetadataSource,
) -> Result<DiscoveredModel, DiscoveryIssueKind> {
    let object = value.as_object().ok_or(DiscoveryIssueKind::InvalidSchema)?;
    let id_field = if source == MetadataSource::OllamaTags {
        "name"
    } else {
        "id"
    };
    let id = object
        .get(id_field)
        .and_then(Value::as_str)
        .filter(|id| valid_model_id(id))
        .ok_or(DiscoveryIssueKind::InvalidModelId)?;
    let mut valid = true;
    let (context_window, max_output_tokens, label_field, known): (
        Option<u64>,
        Option<u32>,
        Option<&str>,
        &[&str],
    ) = match source {
        MetadataSource::GenericOpenAiModels => {
            (None, None, None, &["id", "object", "created", "owned_by"])
        }
        MetadataSource::OpenRouterModels => {
            let context = positive_u64(object.get("context_length"), &mut valid);
            let output = match object.get("top_provider") {
                None | Some(Value::Null) => None,
                Some(Value::Object(provider)) => {
                    positive_u32(provider.get("max_completion_tokens"), &mut valid)
                }
                Some(_) => {
                    valid = false;
                    None
                }
            };
            (
                context,
                output,
                Some("name"),
                &["id", "name", "context_length", "top_provider"],
            )
        }
        MetadataSource::AnthropicModels | MetadataSource::AnthropicModelDetail => (
            positive_u64(object.get("max_input_tokens"), &mut valid),
            positive_u32(object.get("max_tokens"), &mut valid),
            Some("display_name"),
            &[
                "id",
                "type",
                "display_name",
                "created_at",
                "max_input_tokens",
                "max_tokens",
            ],
        ),
        // Tags advertise identity/architecture, not an active num_ctx. No show
        // parser is enabled until its primary schema is established.
        MetadataSource::OllamaTags => (
            None,
            None,
            None,
            &["name", "model", "modified_at", "size", "digest", "details"],
        ),
    };
    let label = label_field
        .and_then(|field| object.get(field))
        .and_then(Value::as_str)
        .map(display_safe)
        .filter(|label| !label.is_empty());
    let mut unrecognized_fields: Vec<_> = object
        .keys()
        .filter(|field| !known.contains(&field.as_str()))
        .map(|field| display_safe(field))
        .filter(|field| !field.is_empty())
        .take(MAX_UNKNOWN_FIELDS)
        .collect();
    unrecognized_fields.sort();
    Ok(DiscoveredModel {
        id: id.into(),
        label,
        context_window,
        max_output_tokens,
        source,
        metadata_valid: valid,
        unrecognized_fields,
    })
}

fn positive_u64(value: Option<&Value>, valid: &mut bool) -> Option<u64> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_u64().filter(|value| *value > 0) {
            Some(value) => Some(value),
            None => {
                *valid = false;
                None
            }
        },
    }
}

fn positive_u32(value: Option<&Value>, valid: &mut bool) -> Option<u32> {
    positive_u64(value, valid).and_then(|value| match u32::try_from(value) {
        Ok(value) => Some(value),
        Err(_) => {
            *valid = false;
            None
        }
    })
}

fn valid_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MODEL_ID_BYTES
        && value.trim() == value
        && !matches!(value, "." | "..")
        && !value
            .chars()
            .any(|character| character.is_control() || bidi_control(character))
}

fn bidi_control(character: char) -> bool {
    matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn display_safe(value: &str) -> String {
    let mut result = String::new();
    for character in value
        .chars()
        .filter(|character| !character.is_control() && !bidi_control(*character))
    {
        if result.len() + character.len_utf8() > MAX_LABEL_BYTES {
            break;
        }
        result.push(character);
    }
    result
}

fn same_observation(left: &DiscoveredModel, right: &DiscoveredModel) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.context_window == right.context_window
        && left.max_output_tokens == right.max_output_tokens
        && left.metadata_valid == right.metadata_valid
        && left.source == right.source
}

/// Non-secret sidecar record. The caller bounds/deserializes and publishes it.
/// Authentication-reference changes deliberately invalidate this provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProvenance {
    pub schema_version: u32,
    pub provider_binding: String,
    pub model_id: String,
    pub observed: DiscoveredModel,
    pub last_applied_context_window: Option<u64>,
    pub last_applied_max_output_tokens: Option<u32>,
    pub last_applied_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MergedDiscoveredModel {
    pub model: ModelEntry,
    /// None means identity/metadata refusal; never replace a good sidecar with it.
    pub provenance: Option<ModelProvenance>,
}

/// Update only fields still equal to the last auto-applied observation. Missing
/// or stale provenance preserves any existing value conservatively. Efforts,
/// pricing, sampling and raw IDs always remain exactly as explicitly declared.
pub fn merge_discovered_model(
    current: &ModelEntry,
    observed: &DiscoveredModel,
    previous: Option<&ModelProvenance>,
    exact_provider_identity: &ProviderAuthIdentity,
) -> MergedDiscoveredModel {
    let mut model = current.clone();
    if current.id != observed.id
        || !valid_model_id(&observed.id)
        || !observed.metadata_valid
        || observed.context_window == Some(0)
        || observed.max_output_tokens == Some(0)
        || observed
            .label
            .as_ref()
            .is_some_and(|label| display_safe(label) != *label)
    {
        return MergedDiscoveredModel {
            model,
            provenance: None,
        };
    }
    let binding = exact_provider_identity.binding_id();
    let previous = previous.filter(|previous| {
        previous.schema_version == PROVENANCE_VERSION
            && previous.provider_binding == binding
            && previous.model_id == observed.id
            && previous.observed.id == observed.id
            && previous.observed.metadata_valid
            && previous.observed.source.profile() == observed.source.profile()
            && previous.last_applied_context_window != Some(0)
            && previous.last_applied_max_output_tokens != Some(0)
            && previous
                .last_applied_context_window
                .is_none_or(|value| previous.observed.context_window == Some(value))
            && previous
                .last_applied_max_output_tokens
                .is_none_or(|value| previous.observed.max_output_tokens == Some(value))
            && previous
                .last_applied_label
                .as_ref()
                .is_none_or(|value| previous.observed.label.as_ref() == Some(value))
    });
    let managed_context = model.context_window.is_none()
        || previous.is_some_and(|previous| {
            previous.last_applied_context_window.is_some()
                && previous.last_applied_context_window == model.context_window
        });
    let managed_output = model.max_output_tokens.is_none()
        || previous.is_some_and(|previous| {
            previous.last_applied_max_output_tokens.is_some()
                && previous.last_applied_max_output_tokens == model.max_output_tokens
        });
    let managed_label = model.label.is_none()
        || previous.is_some_and(|previous| {
            previous.last_applied_label.is_some() && previous.last_applied_label == model.label
        });
    if managed_context {
        model.context_window = observed.context_window;
    }
    if managed_output {
        model.max_output_tokens = observed.max_output_tokens;
    }
    if managed_label {
        model.label = observed.label.clone();
    }
    let provenance = ModelProvenance {
        schema_version: PROVENANCE_VERSION,
        provider_binding: binding,
        model_id: observed.id.clone(),
        observed: observed.clone(),
        last_applied_context_window: managed_context.then_some(model.context_window).flatten(),
        last_applied_max_output_tokens: managed_output.then_some(model.max_output_tokens).flatten(),
        last_applied_label: if managed_label {
            model.label.clone()
        } else {
            None
        },
    };
    MergedDiscoveredModel {
        model,
        provenance: Some(provenance),
    }
}

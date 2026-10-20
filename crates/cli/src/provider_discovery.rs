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
use std::sync::Arc;
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
pub const PROVENANCE_VERSION: u32 = 2;
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

/// Bounded evidence about fields actually returned by a validated fetch.
/// Its age is independent of local saves and last-applied field ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_limit: Option<LimitObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_limit: Option<LimitObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitObservation {
    pub value: u64,
    pub observed_at_unix: u64,
    pub source: MetadataSource,
    pub schema: ObservationSchema,
    pub semantics: LimitSemantics,
    pub confidence: ObservationConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationSchema {
    #[serde(rename = "anthropic_models_2023_06_01")]
    AnthropicModels20230601,
    #[serde(rename = "open_router_models_fields_v1")]
    OpenRouterModelsFieldsV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitSemantics {
    InputTokens,
    CombinedTokens,
    OutputTokens,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationConfidence {
    DocumentedLimit,
    AdvertisedUnspecified,
}

/// Wall-clock evidence only. Monotonic request deadlines use their own clock.
pub trait ObservationClock: Send + Sync {
    fn unix_seconds(&self) -> Option<u64>;
}

struct SystemObservationClock;

impl ObservationClock for SystemObservationClock {
    fn unix_seconds(&self) -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ObservationEvidence>,
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
    ObservationTimeUnavailable,
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
    observation_clock: Arc<dyn ObservationClock>,
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
            observation_clock: Arc::new(SystemObservationClock),
        })
    }

    /// Construction and pure metadata operations never sample this clock.
    pub fn with_observation_clock(mut self, clock: Arc<dyn ObservationClock>) -> Self {
        self.observation_clock = clock;
        self
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

    fn stamp_fetched(&self, models: &mut [DiscoveredModel]) -> Result<(), DiscoveryIssueKind> {
        if !models.iter().any(has_numeric_observation) {
            return Ok(());
        }
        if self.cancel.is_cancelled() {
            return Err(DiscoveryIssueKind::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(DiscoveryIssueKind::DeadlineExceeded);
        }
        let time = self
            .observation_clock
            .unix_seconds()
            .ok_or(DiscoveryIssueKind::ObservationTimeUnavailable)?;
        for model in models
            .iter_mut()
            .filter(|model| has_numeric_observation(model))
        {
            model.evidence = Some(ObservationEvidence {
                context_limit: model
                    .context_window
                    .and_then(|value| limit_observation(model.source, value, time, false)),
                output_limit: model.max_output_tokens.and_then(|value| {
                    limit_observation(model.source, u64::from(value), time, true)
                }),
            });
        }
        Ok(())
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
            let mut parsed = match parse_page(&page, self.profile) {
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
            if let Err(kind) = self.stamp_fetched(&mut parsed.models) {
                result.issues.push(DiscoveryIssue {
                    kind,
                    model_id: None,
                    page: Some(result.pages_fetched),
                });
            }
            let mut conflict = false;
            for model in parsed.models {
                if let Some(index) = positions.get(&model.id).copied() {
                    if !same_observation(&result.models[index], &model) {
                        // Contradictory values cannot leave a freshly stamped
                        // fact on the disputed model.
                        result.models[index].evidence = None;
                        result.issues.push(DiscoveryIssue::model(
                            DiscoveryIssueKind::ConflictingDuplicate,
                            &model.id,
                        ));
                        conflict = true;
                        break;
                    }
                    if model.evidence.is_some() {
                        result.models[index].evidence = model.evidence;
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
        let mut model = parse_model(&value, MetadataSource::AnthropicModelDetail)?;
        if model.id != id {
            return Err(DiscoveryIssueKind::DetailIdentityMismatch);
        }
        self.stamp_fetched(std::slice::from_mut(&mut model))?;
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
        evidence: None,
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

fn evidence_shape(
    source: MetadataSource,
    output: bool,
) -> Option<(ObservationSchema, LimitSemantics, ObservationConfidence)> {
    match source {
        MetadataSource::AnthropicModels | MetadataSource::AnthropicModelDetail => Some((
            ObservationSchema::AnthropicModels20230601,
            if output {
                LimitSemantics::OutputTokens
            } else {
                LimitSemantics::InputTokens
            },
            ObservationConfidence::DocumentedLimit,
        )),
        MetadataSource::OpenRouterModels => Some((
            ObservationSchema::OpenRouterModelsFieldsV1,
            LimitSemantics::Unspecified,
            ObservationConfidence::AdvertisedUnspecified,
        )),
        MetadataSource::GenericOpenAiModels | MetadataSource::OllamaTags => None,
    }
}

fn has_numeric_observation(model: &DiscoveredModel) -> bool {
    model.metadata_valid
        && evidence_shape(model.source, false).is_some()
        && (model.context_window.is_some() || model.max_output_tokens.is_some())
}

fn limit_observation(
    source: MetadataSource,
    value: u64,
    observed_at_unix: u64,
    output: bool,
) -> Option<LimitObservation> {
    let (schema, semantics, confidence) = evidence_shape(source, output)?;
    Some(LimitObservation {
        value,
        observed_at_unix,
        source,
        schema,
        semantics,
        confidence,
    })
}

fn valid_evidence(model: &DiscoveredModel) -> bool {
    let Some(evidence) = &model.evidence else {
        return true;
    };
    if !model.metadata_valid
        || (evidence.context_limit.is_none() && evidence.output_limit.is_none())
    {
        return false;
    }
    [
        (&evidence.context_limit, model.context_window, false),
        (
            &evidence.output_limit,
            model.max_output_tokens.map(u64::from),
            true,
        ),
    ]
    .into_iter()
    .all(|(component, value, output)| {
        component.as_ref().is_none_or(|component| {
            value == Some(component.value)
                && component.value > 0
                && component.source.profile() == model.source.profile()
                && evidence_shape(component.source, output)
                    == Some((component.schema, component.semantics, component.confidence))
        })
    })
}

/// Preserve a retained component's age without treating an equal value as a
/// new fetch. A new explicit observation always wins, even with an older clock.
fn merged_evidence(
    observed: &DiscoveredModel,
    previous: Option<&ModelProvenance>,
) -> Option<ObservationEvidence> {
    let incoming = observed.evidence.as_ref();
    let old = previous.and_then(|previous| previous.observed.evidence.as_ref());
    let context_limit = incoming
        .and_then(|evidence| evidence.context_limit.clone())
        .or_else(|| {
            old.and_then(|evidence| evidence.context_limit.as_ref())
                .filter(|component| Some(component.value) == observed.context_window)
                .cloned()
        });
    let output_limit = incoming
        .and_then(|evidence| evidence.output_limit.clone())
        .or_else(|| {
            old.and_then(|evidence| evidence.output_limit.as_ref())
                .filter(|component| {
                    Some(component.value) == observed.max_output_tokens.map(u64::from)
                })
                .cloned()
        });
    (context_limit.is_some() || output_limit.is_some()).then_some(ObservationEvidence {
        context_limit,
        output_limit,
    })
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
    /// Local input policy established by an identifiable edit, never a
    /// provider capacity fact. Usable only while the current value matches.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_input_tokens"
    )]
    pub manual_input_tokens: Option<u64>,
    pub last_applied_max_output_tokens: Option<u32>,
    pub last_applied_label: Option<String>,
}

fn deserialize_manual_input_tokens<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<u64>::deserialize(deserializer)?;
    if value == Some(0) {
        return Err(serde::de::Error::custom(
            "manual input policy must be positive",
        ));
    }
    Ok(value)
}

fn valid_manual_ownership(record: &ModelProvenance) -> bool {
    record.manual_input_tokens.is_none_or(|value| {
        value > 0
            && record.schema_version == PROVENANCE_VERSION
            && record.last_applied_context_window.is_none()
    })
}

// Apply the existing strict stored-observation shape to programmatic receipts
// before they can establish local policy. Current-value matching is separate:
// an independently edited model must not invalidate historical fetched facts.
fn valid_prior_observation(observed: &DiscoveredModel) -> bool {
    if !observed.metadata_valid
        || !valid_evidence(observed)
        || observed.context_window == Some(0)
        || observed.max_output_tokens == Some(0)
        || observed
            .label
            .as_ref()
            .is_some_and(|label| display_safe(label) != *label)
        || observed.unrecognized_fields.len() > MAX_UNKNOWN_FIELDS
        || (matches!(
            observed.source,
            MetadataSource::GenericOpenAiModels | MetadataSource::OllamaTags
        ) && (observed.context_window.is_some() || observed.max_output_tokens.is_some()))
    {
        return false;
    }
    let mut fields = HashSet::new();
    observed.unrecognized_fields.iter().all(|field| {
        !field.is_empty() && display_safe(field) == *field && fields.insert(field.as_str())
    })
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
        || !valid_evidence(observed)
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
    let policy_previous = previous.filter(|previous| {
        matches!(previous.schema_version, 1 | PROVENANCE_VERSION)
            && (previous.schema_version != 1 || previous.observed.evidence.is_none())
            && valid_manual_ownership(previous)
            && previous.provider_binding == binding
            && previous.model_id == observed.id
            && previous.observed.id == observed.id
            && valid_prior_observation(&previous.observed)
            && previous.observed.source.profile().kind() == observed.source.profile().kind()
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
    let manual_input_tokens = policy_previous.and_then(|previous| {
        let current = model.context_window.filter(|value| *value > 0)?;
        (previous.manual_input_tokens == Some(current)
            || previous
                .last_applied_context_window
                .is_some_and(|applied| applied != current))
        .then_some(current)
    });
    // Local policy survives a same-kind discovery-profile switch. Fetched
    // numbers, evidence and their timestamps retain the stricter profile gate.
    let previous = policy_previous
        .filter(|previous| previous.observed.source.profile() == observed.source.profile());
    let managed_context = manual_input_tokens.is_none()
        && (model.context_window.is_none()
            || previous.is_some_and(|previous| {
                previous.last_applied_context_window.is_some()
                    && previous.last_applied_context_window == model.context_window
            }));
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
    let mut provenance_observed = observed.clone();
    provenance_observed.evidence = merged_evidence(observed, previous);
    let provenance = ModelProvenance {
        schema_version: PROVENANCE_VERSION,
        provider_binding: binding,
        model_id: observed.id.clone(),
        observed: provenance_observed,
        last_applied_context_window: managed_context.then_some(model.context_window).flatten(),
        manual_input_tokens,
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

pub use metadata_storage::{MetadataError, load_model_provenance, save_model_provenance};

mod metadata_storage {
    use super::{
        DiscoveredModel, MetadataSource, ModelProvenance, ObservationEvidence, PROVENANCE_VERSION,
        deserialize_manual_input_tokens, display_safe, valid_evidence, valid_manual_ownership,
        valid_model_id,
    };
    use crate::config::{ProviderConfig, ProvidersConfig, validate_provider_endpoint};
    use crate::customization::{Directory, Error as StorageError, Lock, publish, read_regular};
    use orbit_adapter::provider_credentials::ProviderAuthIdentity;
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
    use std::fs::Metadata;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Component, Path, PathBuf};

    const MAX_METADATA_BYTES: usize = 128 * 1024;
    const MAX_METADATA_MODELS: usize = 128;
    const MAX_METADATA_BINDINGS: usize = 128;
    const MAX_METADATA_STAGES: usize = 1;
    const MAX_CONFIG_BYTES: usize = 128 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    pub enum MetadataError {
        #[error("Provider metadata identity is invalid")]
        InvalidProvider,
        #[error("Provider metadata document is malformed")]
        InvalidDocument,
        #[error("Provider metadata does not match its exact binding")]
        IdentityMismatch,
        #[error("Provider metadata path is unsafe")]
        UnsafePath,
        #[error("Provider metadata exceeds its bounded size or count")]
        LimitExceeded,
        #[error("Published provider configuration is malformed")]
        InvalidConfig,
        #[error("Provider configuration changed or has not been published")]
        StaleConfig,
        #[error("Provider metadata is busy; retry after the current operation")]
        Busy,
        #[error("Provider metadata storage I/O failed")]
        Io,
        #[error("Provider metadata publication may have committed; inspect before retrying")]
        PublicationUncertain,
    }

    #[derive(Deserialize)]
    struct VersionHeader {
        #[serde(default)]
        schema_version: Option<u32>,
    }

    // Separate strict wire types keep unknown fields and duplicate JSON keys
    // out without changing the public provenance/config constructors.
    // The v1 observation intentionally has no evidence member. A document
    // cannot manufacture fresh authority by adding v2 fields to that shape.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetadataDocumentV1 {
        schema_version: u32,
        provider_binding: String,
        models: Vec<MetadataRecordV1>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetadataRecordV1 {
        schema_version: u32,
        provider_binding: String,
        model_id: String,
        observed: MetadataObservationV1,
        last_applied_context_window: Option<u64>,
        last_applied_max_output_tokens: Option<u32>,
        last_applied_label: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetadataObservationV1 {
        id: String,
        label: Option<String>,
        context_window: Option<u64>,
        max_output_tokens: Option<u32>,
        source: MetadataSource,
        metadata_valid: bool,
        unrecognized_fields: Vec<String>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetadataDocument {
        schema_version: u32,
        provider_binding: String,
        models: Vec<MetadataRecord>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetadataRecord {
        schema_version: u32,
        provider_binding: String,
        model_id: String,
        observed: MetadataObservation,
        last_applied_context_window: Option<u64>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_manual_input_tokens"
        )]
        manual_input_tokens: Option<u64>,
        last_applied_max_output_tokens: Option<u32>,
        last_applied_label: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetadataObservation {
        id: String,
        label: Option<String>,
        context_window: Option<u64>,
        max_output_tokens: Option<u32>,
        source: MetadataSource,
        metadata_valid: bool,
        unrecognized_fields: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<ObservationEvidence>,
    }

    impl From<&ModelProvenance> for MetadataRecord {
        fn from(record: &ModelProvenance) -> Self {
            let observed = &record.observed;
            Self {
                schema_version: PROVENANCE_VERSION,
                provider_binding: record.provider_binding.clone(),
                model_id: record.model_id.clone(),
                observed: MetadataObservation {
                    id: observed.id.clone(),
                    label: observed.label.clone(),
                    context_window: observed.context_window,
                    max_output_tokens: observed.max_output_tokens,
                    source: observed.source,
                    metadata_valid: observed.metadata_valid,
                    unrecognized_fields: observed.unrecognized_fields.clone(),
                    evidence: observed.evidence.clone(),
                },
                last_applied_context_window: record.last_applied_context_window,
                manual_input_tokens: record.manual_input_tokens,
                last_applied_max_output_tokens: record.last_applied_max_output_tokens,
                last_applied_label: record.last_applied_label.clone(),
            }
        }
    }

    impl From<MetadataRecord> for ModelProvenance {
        fn from(record: MetadataRecord) -> Self {
            let observed = record.observed;
            Self {
                schema_version: record.schema_version,
                provider_binding: record.provider_binding,
                model_id: record.model_id,
                observed: DiscoveredModel {
                    id: observed.id,
                    label: observed.label,
                    context_window: observed.context_window,
                    max_output_tokens: observed.max_output_tokens,
                    source: observed.source,
                    metadata_valid: observed.metadata_valid,
                    unrecognized_fields: observed.unrecognized_fields,
                    evidence: observed.evidence,
                },
                last_applied_context_window: record.last_applied_context_window,
                manual_input_tokens: record.manual_input_tokens,
                last_applied_max_output_tokens: record.last_applied_max_output_tokens,
                last_applied_label: record.last_applied_label,
            }
        }
    }

    impl From<MetadataRecordV1> for ModelProvenance {
        fn from(record: MetadataRecordV1) -> Self {
            let observed = record.observed;
            MetadataRecord {
                schema_version: record.schema_version,
                provider_binding: record.provider_binding,
                model_id: record.model_id,
                observed: MetadataObservation {
                    id: observed.id,
                    label: observed.label,
                    context_window: observed.context_window,
                    max_output_tokens: observed.max_output_tokens,
                    source: observed.source,
                    metadata_valid: observed.metadata_valid,
                    unrecognized_fields: observed.unrecognized_fields,
                    evidence: None,
                },
                last_applied_context_window: record.last_applied_context_window,
                manual_input_tokens: None,
                last_applied_max_output_tokens: record.last_applied_max_output_tokens,
                last_applied_label: record.last_applied_label,
            }
            .into()
        }
    }

    fn storage_error(error: StorageError) -> MetadataError {
        match error {
            StorageError::Busy => MetadataError::Busy,
            StorageError::PublicationUncertain(_) => MetadataError::PublicationUncertain,
            StorageError::UnsafePath(_) | StorageError::Invalid(_) => MetadataError::UnsafePath,
            StorageError::Io(_) => MetadataError::Io,
        }
    }

    fn home_path(home: &Path) -> Result<PathBuf, MetadataError> {
        let path = std::path::absolute(home).map_err(|_| MetadataError::Io)?;
        if path == Path::new("/")
            || path.as_os_str().as_encoded_bytes().len() > 4096
            || path.components().count() > 256
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(MetadataError::UnsafePath);
        }
        Ok(path)
    }

    fn binding(provider: &ProviderConfig) -> Result<String, MetadataError> {
        if !matches!(
            provider.kind.as_str(),
            "openai-compatible" | "anthropic" | "ollama"
        ) || provider.models.len() > MAX_METADATA_MODELS
        {
            return Err(MetadataError::InvalidProvider);
        }
        let mut ids = HashSet::new();
        if provider.models.iter().any(|model| {
            model.id.is_empty()
                || model.id.len() > 256
                || model.id.chars().any(char::is_control)
                || !ids.insert(model.id.as_str())
        }) {
            return Err(MetadataError::InvalidProvider);
        }
        identity_binding(provider)
    }

    fn read_binding(provider: &ProviderConfig) -> Result<String, MetadataError> {
        // Configured membership is broader than the stored receipt selection.
        // Bound the copied identity list before reusing the existing pure
        // configured-provider validator; keep decode's full provider context.
        if provider.models.len() > 1024 || provider.models.iter().any(|model| model.id.len() > 512)
        {
            return Err(MetadataError::InvalidProvider);
        }
        let config = ProvidersConfig {
            provider: vec![provider.clone()],
            ..Default::default()
        };
        crate::phase_routing::validate_providers(&config)
            .map_err(|_| MetadataError::InvalidProvider)?;
        identity_binding(provider)
    }

    fn identity_binding(provider: &ProviderConfig) -> Result<String, MetadataError> {
        let endpoint = validate_provider_endpoint(&provider.url)
            .map_err(|_| MetadataError::InvalidProvider)?;
        ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            endpoint.as_str(),
            provider.env.as_deref(),
        )
        .map(|identity| identity.binding_id())
        .map_err(|_| MetadataError::InvalidProvider)
    }

    fn check_directory(directory: &Directory) -> Result<(), MetadataError> {
        directory.check().map_err(storage_error)?;
        // check() protects the held inode. Reopening also rechecks current
        // ownership, private mode and every named ancestor after each operation.
        Directory::open(directory.path(), true).map_err(storage_error)?;
        Ok(())
    }

    fn existing_home(path: &Path) -> Result<Option<Directory>, MetadataError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Directory::open(path, true).map(Some).map_err(storage_error),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Missing storage is normal; still reject an existing symlink
                // ancestor rather than treating its missing destination as empty.
                let mut ancestor = path.parent().ok_or(MetadataError::UnsafePath)?;
                loop {
                    match std::fs::symlink_metadata(ancestor) {
                        Ok(_) => {
                            Directory::open(ancestor, false).map_err(storage_error)?;
                            return Ok(None);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            ancestor = ancestor.parent().ok_or(MetadataError::UnsafePath)?;
                        }
                        Err(_) => return Err(MetadataError::Io),
                    }
                }
            }
            Err(_) => Err(MetadataError::Io),
        }
    }

    fn optional_child(parent: &Directory, name: &str) -> Result<Option<Directory>, MetadataError> {
        check_directory(parent)?;
        let path = parent.io().map_err(storage_error)?.join(name);
        let result = match std::fs::symlink_metadata(path) {
            Ok(_) => parent.child(name, false).map(Some).map_err(storage_error),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(MetadataError::Io),
        }?;
        check_directory(parent)?;
        Ok(result)
    }

    fn file_metadata(
        directory: &Directory,
        path: &Path,
        maximum: usize,
    ) -> Result<Metadata, MetadataError> {
        check_directory(directory)?;
        let owner = std::fs::metadata(directory.io().map_err(storage_error)?)
            .map_err(|_| MetadataError::Io)?
            .uid();
        let metadata = std::fs::symlink_metadata(path).map_err(|_| MetadataError::Io)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != owner
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(MetadataError::UnsafePath);
        }
        if metadata.len() > maximum as u64 {
            return Err(MetadataError::LimitExceeded);
        }
        Ok(metadata)
    }

    fn same_file(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.uid() == right.uid()
            && left.nlink() == right.nlink()
            && left.mode() == right.mode()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }

    fn read_optional(
        directory: &Directory,
        name: &str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, MetadataError> {
        let path = directory.io().map_err(storage_error)?.join(name);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                check_directory(directory)?;
                return Ok(None);
            }
            Err(_) => return Err(MetadataError::Io),
            Ok(_) => {}
        }
        let before = file_metadata(directory, &path, maximum)?;
        let bytes = read_regular(&path, maximum, true).map_err(storage_error)?;
        let after = file_metadata(directory, &path, maximum)?;
        if !same_file(&before, &after) || bytes.len() as u64 != after.len() {
            return Err(MetadataError::UnsafePath);
        }
        check_directory(directory)?;
        Ok(Some(bytes))
    }

    /// Count all directory entries, including at most one atomic-publication
    /// stage. Every entry is bounded, owned, private, regular and single-link.
    fn directory_count(directory: &Directory) -> Result<usize, MetadataError> {
        check_directory(directory)?;
        let mut bindings = 0_usize;
        let mut stages = 0_usize;
        let entries = std::fs::read_dir(directory.io().map_err(storage_error)?)
            .map_err(|_| MetadataError::Io)?;
        for entry in entries {
            let entry = entry.map_err(|_| MetadataError::Io)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(MetadataError::UnsafePath)?;
            if name.len() == 69
                && name.ends_with(".json")
                && name.as_bytes()[..64]
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                bindings += 1;
            } else if let Some(stage) = name.strip_prefix(".stage-") {
                if ulid::Ulid::from_string(stage).is_err() {
                    return Err(MetadataError::UnsafePath);
                }
                stages += 1;
            } else {
                return Err(MetadataError::UnsafePath);
            }
            if bindings > MAX_METADATA_BINDINGS || stages > MAX_METADATA_STAGES {
                return Err(MetadataError::LimitExceeded);
            }
            file_metadata(directory, &entry.path(), MAX_METADATA_BYTES)?;
        }
        check_directory(directory)?;
        Ok(bindings)
    }

    fn validate_record(
        record: &ModelProvenance,
        expected: &str,
        provider: &ProviderConfig,
    ) -> Result<(), MetadataError> {
        let observed = &record.observed;
        if record.provider_binding != expected {
            return Err(MetadataError::IdentityMismatch);
        }
        if !matches!(record.schema_version, 1 | PROVENANCE_VERSION)
            || (record.schema_version == 1 && observed.evidence.is_some())
            || !valid_manual_ownership(record)
            || !valid_model_id(&record.model_id)
            || record.model_id != observed.id
            || !observed.metadata_valid
            || !valid_evidence(observed)
            || observed.source.profile().kind() != provider.kind
            || observed.context_window == Some(0)
            || observed.max_output_tokens == Some(0)
            || observed
                .label
                .as_ref()
                .is_some_and(|label| display_safe(label) != *label)
            || observed.unrecognized_fields.len() > 32
            || observed
                .unrecognized_fields
                .iter()
                .any(|field| field.is_empty() || display_safe(field) != *field)
            || record
                .last_applied_context_window
                .is_some_and(|value| observed.context_window != Some(value))
            || record
                .last_applied_max_output_tokens
                .is_some_and(|value| observed.max_output_tokens != Some(value))
            || record
                .last_applied_label
                .as_ref()
                .is_some_and(|value| observed.label.as_ref() != Some(value))
        {
            return Err(MetadataError::InvalidDocument);
        }
        if matches!(
            observed.source,
            MetadataSource::GenericOpenAiModels | MetadataSource::OllamaTags
        ) && (observed.context_window.is_some() || observed.max_output_tokens.is_some())
        {
            return Err(MetadataError::InvalidDocument);
        }
        let mut fields = HashSet::new();
        if observed
            .unrecognized_fields
            .iter()
            .any(|field| !fields.insert(field.as_str()))
        {
            return Err(MetadataError::InvalidDocument);
        }
        Ok(())
    }

    fn decode(
        bytes: &[u8],
        expected: &str,
        provider: &ProviderConfig,
    ) -> Result<Vec<ModelProvenance>, MetadataError> {
        let header: VersionHeader =
            serde_json::from_slice(bytes).map_err(|_| MetadataError::InvalidDocument)?;
        if !matches!(header.schema_version, Some(1 | PROVENANCE_VERSION)) {
            return Ok(Vec::new());
        }
        let (version, provider_binding, records): (_, _, Vec<ModelProvenance>) =
            if header.schema_version == Some(1) {
                let document: MetadataDocumentV1 =
                    serde_json::from_slice(bytes).map_err(|_| MetadataError::InvalidDocument)?;
                (
                    document.schema_version,
                    document.provider_binding,
                    document
                        .models
                        .into_iter()
                        .map(ModelProvenance::from)
                        .collect(),
                )
            } else {
                let document: MetadataDocument =
                    serde_json::from_slice(bytes).map_err(|_| MetadataError::InvalidDocument)?;
                (
                    document.schema_version,
                    document.provider_binding,
                    document
                        .models
                        .into_iter()
                        .map(ModelProvenance::from)
                        .collect(),
                )
            };
        if provider_binding != expected {
            return Err(MetadataError::IdentityMismatch);
        }
        if records.len() > MAX_METADATA_MODELS {
            return Err(MetadataError::LimitExceeded);
        }
        if records
            .iter()
            .any(|record| !matches!(record.schema_version, 1 | PROVENANCE_VERSION))
        {
            return Ok(Vec::new());
        }
        let mut ids = HashSet::new();
        let mut output = Vec::new();
        for record in records {
            if record.schema_version != version {
                return Err(MetadataError::InvalidDocument);
            }
            validate_record(&record, expected, provider)?;
            if !ids.insert(record.model_id.clone()) {
                return Err(MetadataError::InvalidDocument);
            }
            // Removed models have no consumer. Existing models retain their
            // provenance despite manual changes to other fields or models.
            if provider
                .models
                .iter()
                .any(|model| model.id == record.model_id)
            {
                output.push(record);
            }
        }
        Ok(output)
    }

    fn published_provider(
        home: &Directory,
        expected: &ProviderConfig,
    ) -> Result<(), MetadataError> {
        let bytes = read_optional(home, "providers.toml", MAX_CONFIG_BYTES)?
            .ok_or(MetadataError::StaleConfig)?;
        let raw = std::str::from_utf8(&bytes).map_err(|_| MetadataError::InvalidConfig)?;
        let config =
            ProvidersConfig::load_from_str(raw).map_err(|_| MetadataError::InvalidConfig)?;
        let mut matching = config
            .provider
            .iter()
            .filter(|provider| provider.name == expected.name);
        if matching.next() != Some(expected) || matching.next().is_some() {
            return Err(MetadataError::StaleConfig);
        }
        check_directory(home)
    }

    /// Load exact-binding provenance without comparing a provider-wide config
    /// fingerprint. The existing merge decides field ownership individually.
    pub fn load_model_provenance(
        home: &Path,
        provider: &ProviderConfig,
    ) -> Result<Vec<ModelProvenance>, MetadataError> {
        let expected = read_binding(provider)?;
        let home = home_path(home)?;
        let Some(root) = existing_home(&home)? else {
            return Ok(Vec::new());
        };
        let Some(metadata) = optional_child(&root, "metadata")? else {
            return Ok(Vec::new());
        };
        let Some(providers) = optional_child(&metadata, "providers")? else {
            return Ok(Vec::new());
        };
        directory_count(&providers)?;
        let bytes = read_optional(&providers, &format!("{expected}.json"), MAX_METADATA_BYTES)?;
        let records = match bytes {
            Some(bytes) => decode(&bytes, &expected, provider)?,
            None => Vec::new(),
        };
        check_directory(&providers)?;
        check_directory(&metadata)?;
        check_directory(&root)?;
        Ok(records)
    }

    /// Publish optional provenance only after this exact typed provider is
    /// present in providers.toml, with the setup-then-config lock order.
    /// Definite pre-publication failures retain the prior sidecar; uncertainty
    /// after the atomic rename remains an explicit typed result.
    pub fn save_model_provenance(
        home: &Path,
        provider: &ProviderConfig,
        records: &[ModelProvenance],
    ) -> Result<(), MetadataError> {
        let expected = binding(provider)?;
        if records.len() > MAX_METADATA_MODELS {
            return Err(MetadataError::LimitExceeded);
        }
        let mut ids = HashSet::new();
        for record in records {
            validate_record(record, &expected, provider)?;
            if !ids.insert(record.model_id.as_str())
                || !provider
                    .models
                    .iter()
                    .any(|model| model.id == record.model_id)
            {
                return Err(MetadataError::InvalidDocument);
            }
        }
        let document = MetadataDocument {
            schema_version: PROVENANCE_VERSION,
            provider_binding: expected.clone(),
            models: records.iter().map(MetadataRecord::from).collect(),
        };
        let bytes = serde_json::to_vec(&document).map_err(|_| MetadataError::InvalidDocument)?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(MetadataError::LimitExceeded);
        }
        let home = home_path(home)?;
        let root = existing_home(&home)?.ok_or(MetadataError::StaleConfig)?;
        published_provider(&root, provider)?;
        let _setup_lock = Lock::acquire(&root, ".setup.lock").map_err(storage_error)?;
        let _config_lock = Lock::acquire(&root, ".config.lock").map_err(storage_error)?;
        published_provider(&root, provider)?;
        let metadata = root.child("metadata", true).map_err(storage_error)?;
        let providers = metadata.child("providers", true).map_err(storage_error)?;
        let count = directory_count(&providers)?;
        let name = format!("{expected}.json");
        let previous = read_optional(&providers, &name, MAX_METADATA_BYTES)?;
        if let Some(previous) = &previous {
            let _ = decode(previous, &expected, provider)?;
        }
        if previous.is_none() && count >= MAX_METADATA_BINDINGS {
            return Err(MetadataError::LimitExceeded);
        }
        published_provider(&root, provider)?;
        check_directory(&metadata)?;
        check_directory(&providers)?;
        publish(&providers, &name, &bytes, false).map_err(storage_error)?;
        // A later verification error cannot be called a definite failure: the
        // sidecar rename has already taken place and its old inode is gone.
        (|| {
            let _ = read_optional(&providers, &name, MAX_METADATA_BYTES)?
                .ok_or(MetadataError::UnsafePath)?;
            check_directory(&providers)?;
            check_directory(&metadata)?;
            published_provider(&root, provider)
        })()
        .map_err(|_| MetadataError::PublicationUncertain)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod metadata_persistence_tests {
    use super::*;
    use crate::config::ProvidersConfig;
    use crate::customization::{
        Directory, Error as StorageError, Lock, PublicationPoint, with_test_hook,
    };
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    struct Tree(PathBuf);

    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("orbit-metadata-{}", ulid::Ulid::new()));
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn provider() -> ProviderConfig {
        ProviderConfig {
            name: "fixture".into(),
            kind: "openai-compatible".into(),
            url: "http://127.0.0.1:1/tenant/v1?scope=synthetic".into(),
            env: Some("ORBIT_AUTH_SYNTHETIC".into()),
            models: vec![ModelEntry {
                context_limits: None,
                id: "vendor/raw:free".into(),
                label: None,
                pricing: Default::default(),
                context_window: None,
                max_output_tokens: None,
                sampling: None,
                supported_efforts: None,
                default_effort: None,
                first_byte_timeout_ms: None,
                idle_timeout_ms: None,
            }],
        }
    }

    fn identity(provider: &ProviderConfig) -> ProviderAuthIdentity {
        let url = crate::config::validate_provider_endpoint(&provider.url).unwrap();
        ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            url.as_str(),
            provider.env.as_deref(),
        )
        .unwrap()
    }

    fn observation(id: &str, context: u64, output: u32) -> DiscoveredModel {
        DiscoveredModel {
            id: id.into(),
            label: Some("Visible model".into()),
            context_window: Some(context),
            max_output_tokens: Some(output),
            source: MetadataSource::OpenRouterModels,
            metadata_valid: true,
            unrecognized_fields: vec![],
            evidence: None,
        }
    }

    fn evidenced(
        mut model: DiscoveredModel,
        context_time: u64,
        output_time: u64,
    ) -> DiscoveredModel {
        model.evidence = Some(ObservationEvidence {
            context_limit: model
                .context_window
                .and_then(|value| limit_observation(model.source, value, context_time, false)),
            output_limit: model.max_output_tokens.and_then(|value| {
                limit_observation(model.source, u64::from(value), output_time, true)
            }),
        });
        model
    }

    #[test]
    fn evidence_pure_parsers_do_not_invent_fetch_times() {
        for (source, value) in [
            (
                MetadataSource::AnthropicModels,
                serde_json::json!({"id":"raw", "max_input_tokens":1000,"max_tokens":100}),
            ),
            (
                MetadataSource::OpenRouterModels,
                serde_json::json!({"id":"raw", "context_length":1000,"top_provider":{"max_completion_tokens":100}}),
            ),
        ] {
            let parsed = parse_model(&value, source).unwrap();
            assert_eq!(parsed.context_window, Some(1000));
            assert_eq!(parsed.max_output_tokens, Some(100));
            assert!(parsed.evidence.is_none());
        }
    }

    #[test]
    fn evidence_closed_matrix_does_not_promote_advertised_or_architectural_values() {
        let router = evidenced(observation("raw", 1000, 100), 10, 20);
        assert!(valid_evidence(&router));
        for component in [
            &router.evidence.as_ref().unwrap().context_limit,
            &router.evidence.as_ref().unwrap().output_limit,
        ] {
            let component = component.as_ref().unwrap();
            assert_eq!(component.semantics, LimitSemantics::Unspecified);
            assert_eq!(
                component.confidence,
                ObservationConfidence::AdvertisedUnspecified
            );
        }
        for variant in 0..6 {
            let mut invalid = router.clone();
            let component = invalid
                .evidence
                .as_mut()
                .unwrap()
                .context_limit
                .as_mut()
                .unwrap();
            match variant {
                0 => component.value += 1,
                1 => component.source = MetadataSource::AnthropicModels,
                2 => component.schema = ObservationSchema::AnthropicModels20230601,
                3 => component.semantics = LimitSemantics::CombinedTokens,
                4 => component.confidence = ObservationConfidence::DocumentedLimit,
                _ => invalid.context_window = None,
            }
            assert!(!valid_evidence(&invalid));
        }
        for source in [
            MetadataSource::GenericOpenAiModels,
            MetadataSource::OllamaTags,
        ] {
            assert!(evidence_shape(source, false).is_none());
            assert!(evidence_shape(source, true).is_none());
        }
    }

    #[test]
    fn evidence_pure_merge_carries_each_component_and_accepts_real_backwards_clock() {
        let provider = provider();
        let first = evidenced(observation(&provider.models[0].id, 1000, 100), 100, 200);
        let applied =
            merge_discovered_model(&provider.models[0], &first, None, &identity(&provider));
        let mut incoming = first.clone();
        incoming
            .evidence
            .as_mut()
            .unwrap()
            .context_limit
            .as_mut()
            .unwrap()
            .observed_at_unix = 50;
        incoming.evidence.as_mut().unwrap().output_limit = None;
        let merged = merge_discovered_model(
            &applied.model,
            &incoming,
            applied.provenance.as_ref(),
            &identity(&provider),
        );
        let evidence = merged.provenance.unwrap().observed.evidence.unwrap();
        assert_eq!(evidence.context_limit.unwrap().observed_at_unix, 50);
        assert_eq!(evidence.output_limit.unwrap().observed_at_unix, 200);
        incoming.max_output_tokens = Some(101);
        let changed = merge_discovered_model(
            &applied.model,
            &incoming,
            applied.provenance.as_ref(),
            &identity(&provider),
        );
        assert_eq!(changed.model.max_output_tokens, Some(101));
        assert!(
            changed
                .provenance
                .unwrap()
                .observed
                .evidence
                .unwrap()
                .output_limit
                .is_none()
        );
    }

    #[test]
    fn evidence_v1_ownership_updates_without_becoming_fresh() {
        let (provider, mut previous) = applied();
        previous.schema_version = 1;
        let next = observation(&previous.model_id, 2000, 200);
        let merged = merge_discovered_model(
            &provider.models[0],
            &next,
            Some(&previous),
            &identity(&provider),
        );
        assert_eq!(merged.model.context_window, Some(2000));
        assert_eq!(merged.model.max_output_tokens, Some(200));
        let record = merged.provenance.unwrap();
        assert_eq!(record.schema_version, 2);
        assert!(record.observed.evidence.is_none());
        previous.observed = evidenced(previous.observed, 100, 200);
        let refused_previous = merge_discovered_model(
            &provider.models[0],
            &next,
            Some(&previous),
            &identity(&provider),
        );
        assert_eq!(refused_previous.model, provider.models[0]);
        assert!(
            refused_previous
                .provenance
                .unwrap()
                .observed
                .evidence
                .is_none()
        );
    }

    #[test]
    fn evidence_explicit_limits_and_intervening_manual_values_survive_equal_refetch() {
        let (provider, previous) = applied();
        let mut current = provider.models[0].clone();
        current.context_window = Some(2000);
        current.context_limits = Some(
            serde_json::from_value(serde_json::json!({
                "input_tokens":2000, "combined_tokens":3000, "unknown_policy":"require-limit",
                "media_policy":"refuse", "max_age_seconds":60
            }))
            .unwrap(),
        );
        let observed = evidenced(observation(&current.id, 2000, 200), 123, 456);
        let merged =
            merge_discovered_model(&current, &observed, Some(&previous), &identity(&provider));
        assert_eq!(merged.model.context_limits, current.context_limits);
        assert_eq!(merged.model.context_window, Some(2000));
        assert_eq!(merged.model.max_output_tokens, Some(200));
        let record = merged.provenance.unwrap();
        assert_eq!(record.last_applied_context_window, None);
        assert_eq!(record.last_applied_max_output_tokens, Some(200));
        assert_eq!(record.observed.evidence, observed.evidence);
    }

    fn applied() -> (ProviderConfig, ModelProvenance) {
        let mut provider = provider();
        let observed = observation(&provider.models[0].id, 1000, 100);
        let merged =
            merge_discovered_model(&provider.models[0], &observed, None, &identity(&provider));
        provider.models[0] = merged.model;
        (provider, merged.provenance.unwrap())
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn publish_config(tree: &Tree, provider: &ProviderConfig) {
        let config = ProvidersConfig {
            provider: vec![provider.clone()],
            ..Default::default()
        };
        write_private(
            &tree.path().join("providers.toml"),
            toml::to_string(&config).unwrap().as_bytes(),
        );
    }

    fn sidecar(tree: &Tree, provider: &ProviderConfig) -> PathBuf {
        tree.path()
            .join("metadata/providers")
            .join(format!("{}.json", identity(provider).binding_id()))
    }

    fn seeded() -> (Tree, ProviderConfig, ModelProvenance) {
        let tree = Tree::new();
        let (provider, record) = applied();
        publish_config(&tree, &provider);
        save_model_provenance(tree.path(), &provider, std::slice::from_ref(&record)).unwrap();
        (tree, provider, record)
    }

    fn seeded_evidence() -> (Tree, ProviderConfig, ModelProvenance) {
        let (tree, provider, mut record) = seeded();
        record.observed = evidenced(record.observed, 10, 20);
        save_model_provenance(tree.path(), &provider, std::slice::from_ref(&record)).unwrap();
        (tree, provider, record)
    }

    #[test]
    fn evidence_v1_decode_and_save_upgrade_ownership_without_a_stamp() {
        let (tree, provider, _) = seeded();
        mutate_document(&tree, &provider, |document| {
            document["schema_version"] = 1.into();
            document["models"][0]["schema_version"] = 1.into();
        });
        let records = load_model_provenance(tree.path(), &provider).unwrap();
        assert_eq!(records[0].schema_version, 1);
        assert!(records[0].observed.evidence.is_none());
        save_model_provenance(tree.path(), &provider, &records).unwrap();
        assert_eq!(
            records[0].schema_version, 1,
            "saving cannot mutate the caller's ownership record"
        );
        let records = load_model_provenance(tree.path(), &provider).unwrap();
        assert_eq!(records[0].schema_version, 2);
        assert!(records[0].observed.evidence.is_none());
        assert_eq!(records[0].last_applied_context_window, Some(1000));
        assert_eq!(records[0].last_applied_max_output_tokens, Some(100));
    }

    #[test]
    fn evidence_v1_cannot_claim_v2_evidence_even_when_well_formed() {
        let (tree, provider, mut record) = seeded_evidence();
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        record.schema_version = 1;
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record]),
            Err(MetadataError::InvalidDocument)
        );
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
        mutate_document(&tree, &provider, |document| {
            document["schema_version"] = 1.into();
            document["models"][0]["schema_version"] = 1.into();
        });
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::InvalidDocument)
        );
    }

    #[test]
    fn evidence_v2_rejects_mixed_known_document_and_record_versions() {
        let (tree, provider, _) = seeded();
        mutate_document(&tree, &provider, |document| {
            document["models"][0]["schema_version"] = 1.into()
        });
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::InvalidDocument)
        );
    }

    #[test]
    fn evidence_v2_closed_components_reject_value_source_schema_and_semantic_swaps() {
        for (field, value) in [
            ("value", serde_json::json!(999)),
            ("source", serde_json::json!("anthropic_models")),
            ("schema", serde_json::json!("anthropic_models_2023_06_01")),
            ("semantics", serde_json::json!("input_tokens")),
            ("confidence", serde_json::json!("documented_limit")),
            ("observed_at_unix", serde_json::json!(-1)),
            ("observed_at_unix", serde_json::json!(1.5)),
            ("observed_at_unix", serde_json::json!("10")),
        ] {
            let (tree, provider, _) = seeded_evidence();
            mutate_document(&tree, &provider, |document| {
                document["models"][0]["observed"]["evidence"]["context_limit"][field] = value;
            });
            assert_eq!(
                load_model_provenance(tree.path(), &provider),
                Err(MetadataError::InvalidDocument),
                "invalid evidence member {field}"
            );
        }
    }

    #[test]
    fn evidence_v2_unknown_and_duplicate_nested_keys_are_refused() {
        for path in [0, 1, 2] {
            let (tree, provider, _) = seeded_evidence();
            mutate_document(&tree, &provider, |document| {
                let observed = &mut document["models"][0]["observed"];
                let target = match path {
                    0 => observed,
                    1 => &mut observed["evidence"],
                    _ => &mut observed["evidence"]["context_limit"],
                };
                target["unexpected"] = "synthetic-private-value".into();
            });
            let error = load_model_provenance(tree.path(), &provider).unwrap_err();
            assert_eq!(error, MetadataError::InvalidDocument);
            assert!(!format!("{error:?} {error}").contains("synthetic-private-value"));
        }
        for (needle, replacement) in [
            (
                "\"context_limit\":",
                "\"context_limit\":null,\"context_limit\":",
            ),
            (
                "\"observed_at_unix\":10",
                "\"observed_at_unix\":10,\"observed_at_unix\":10",
            ),
        ] {
            let (tree, provider, _) = seeded_evidence();
            let path = sidecar(&tree, &provider);
            let original = String::from_utf8(fs::read(&path).unwrap()).unwrap();
            let invalid = original.replacen(needle, replacement, 1);
            assert_ne!(invalid, original);
            write_private(&path, invalid.as_bytes());
            assert_eq!(
                load_model_provenance(tree.path(), &provider),
                Err(MetadataError::InvalidDocument)
            );
        }
    }

    #[test]
    fn evidence_pure_save_preserves_old_and_extreme_component_times_byte_for_byte() {
        let (tree, provider, mut record) = seeded_evidence();
        record
            .observed
            .evidence
            .as_mut()
            .unwrap()
            .output_limit
            .as_mut()
            .unwrap()
            .observed_at_unix = u64::MAX;
        save_model_provenance(tree.path(), &provider, std::slice::from_ref(&record)).unwrap();
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        let loaded = load_model_provenance(tree.path(), &provider).unwrap();
        assert_eq!(loaded, [record]);
        save_model_provenance(tree.path(), &provider, &loaded).unwrap();
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
        let evidence = loaded[0].observed.evidence.as_ref().unwrap();
        assert_eq!(
            evidence.context_limit.as_ref().unwrap().observed_at_unix,
            10
        );
        assert_eq!(
            evidence.output_limit.as_ref().unwrap().observed_at_unix,
            u64::MAX
        );
    }

    fn mutate_document(
        tree: &Tree,
        provider: &ProviderConfig,
        change: impl FnOnce(&mut serde_json::Value),
    ) {
        let path = sidecar(tree, provider);
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        change(&mut document);
        write_private(&path, &serde_json::to_vec(&document).unwrap());
    }

    #[test]
    fn metadata_reader_accepts_1024_configured_models_but_rejects_1025_before_storage() {
        let tree = Tree::new();
        let missing = tree.path().join("missing");
        let mut provider = provider();
        let template = provider.models[0].clone();
        provider.models = (0..1024)
            .map(|index| {
                let mut model = template.clone();
                model.id = format!("configured-{index:04}");
                model
            })
            .collect();
        assert_eq!(load_model_provenance(&missing, &provider), Ok(Vec::new()));
        let mut extra = template;
        extra.id = "configured-1024".into();
        provider.models.push(extra);
        assert_eq!(
            load_model_provenance(&missing, &provider),
            Err(MetadataError::InvalidProvider)
        );
        assert!(!missing.exists());
    }

    #[test]
    fn metadata_reader_checks_configured_ids_duplicates_and_provider_identity_before_storage() {
        let tree = Tree::new();
        let missing = tree.path().join("missing");
        let mut longest = provider();
        longest.models[0].id = "x".repeat(512);
        assert_eq!(load_model_provenance(&missing, &longest), Ok(Vec::new()));
        for variant in 0..10 {
            let mut invalid = provider();
            match variant {
                0 => invalid.models[0].id = "x".repeat(513),
                1 => invalid.models[0].id.clear(),
                2 => invalid.models[0].id = " leading".into(),
                3 => invalid.models[0].id = "trailing ".into(),
                4 => invalid.models[0].id = "control\ncharacter".into(),
                5 => invalid.models.push(invalid.models[0].clone()),
                6 => invalid.name = "invalid/provider".into(),
                7 => invalid.kind = "unsupported".into(),
                8 => invalid.env = Some("INVALID-REFERENCE".into()),
                _ => invalid.url = "http://user@127.0.0.1:1/v1".into(),
            }
            assert_eq!(
                load_model_provenance(&missing, &invalid),
                Err(MetadataError::InvalidProvider)
            );
        }
        assert!(!missing.exists());
    }

    #[test]
    fn metadata_writer_keeps_128_model_and_256_byte_id_selection_bounds() {
        let (tree, original, _) = seeded();
        let before = fs::read(sidecar(&tree, &original)).unwrap();
        let before_config = fs::read(tree.path().join("providers.toml")).unwrap();
        for long_id in [false, true] {
            let mut provider = original.clone();
            if long_id {
                provider.models[0].id = "x".repeat(257);
            } else {
                let template = provider.models[0].clone();
                provider.models = (0..129)
                    .map(|index| {
                        let mut model = template.clone();
                        model.id = format!("configured-{index:03}");
                        model
                    })
                    .collect();
            }
            assert_eq!(
                save_model_provenance(tree.path(), &provider, &[]),
                Err(MetadataError::InvalidProvider)
            );
            assert_eq!(fs::read(sidecar(&tree, &original)).unwrap(), before);
            assert_eq!(
                fs::read(tree.path().join("providers.toml")).unwrap(),
                before_config
            );
        }
    }

    #[test]
    fn metadata_missing_home_is_empty_and_does_not_create_it() {
        let tree = Tree::new();
        let missing = tree.path().join("missing/home");
        assert!(
            load_model_provenance(&missing, &provider())
                .unwrap()
                .is_empty()
        );
        assert!(!tree.path().join("missing").exists());
    }

    #[test]
    fn metadata_missing_file_is_empty_and_load_never_creates_directories() {
        let tree = Tree::new();
        let provider = provider();
        publish_config(&tree, &provider);
        let before = fs::read(tree.path().join("providers.toml")).unwrap();
        assert!(
            load_model_provenance(tree.path(), &provider)
                .unwrap()
                .is_empty()
        );
        assert!(!tree.path().join("metadata").exists());
        assert!(!tree.path().join(".setup.lock").exists());
        assert_eq!(
            before,
            fs::read(tree.path().join("providers.toml")).unwrap()
        );
    }

    #[test]
    fn metadata_roundtrip_uses_private_bounded_hash_filename_without_raw_endpoint() {
        let (tree, provider, record) = seeded();
        assert_eq!(
            load_model_provenance(tree.path(), &provider).unwrap(),
            vec![record]
        );
        let path = sidecar(&tree, &provider);
        let bytes = fs::read(&path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(bytes.len() < 128 * 1024);
        assert!(!text.contains(&provider.url));
        assert!(!text.contains("127.0.0.1"));
        assert!(!text.contains("ORBIT_AUTH_SYNTHETIC"));
        assert_eq!(path.file_name().unwrap().to_str().unwrap().len(), 69);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for path in [
            tree.path().join("metadata"),
            tree.path().join("metadata/providers"),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn metadata_load_keeps_provenance_after_manual_diff_and_merge_updates_only_auto_field() {
        let (tree, mut provider, record) = seeded();
        provider.models[0].max_output_tokens = Some(77);
        provider.models[0].label = Some("Hand edited".into());
        publish_config(&tree, &provider);
        let loaded = load_model_provenance(tree.path(), &provider).unwrap();
        assert_eq!(loaded, vec![record]);
        let fresh = observation(&provider.models[0].id, 2000, 200);
        let merged = merge_discovered_model(
            &provider.models[0],
            &fresh,
            loaded.first(),
            &identity(&provider),
        );
        assert_eq!(merged.model.context_window, Some(2000));
        assert_eq!(merged.model.max_output_tokens, Some(77));
        assert_eq!(merged.model.label.as_deref(), Some("Hand edited"));
    }

    #[test]
    fn metadata_load_filters_removed_models_without_requiring_whole_provider_equality() {
        let (tree, mut provider, record) = seeded();
        let mut added = provider.models[0].clone();
        added.id = "new/raw".into();
        provider.models.push(added);
        assert_eq!(
            load_model_provenance(tree.path(), &provider).unwrap(),
            vec![record]
        );
        provider.models.remove(0);
        assert!(
            load_model_provenance(tree.path(), &provider)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn metadata_endpoint_kind_provider_or_env_change_cannot_load_old_binding() {
        let (tree, provider, _) = seeded();
        for variant in 0..4 {
            let mut changed = provider.clone();
            match variant {
                0 => changed.url.push_str("&other=scope"),
                1 => changed.kind = "anthropic".into(),
                2 => changed.name = "other".into(),
                _ => changed.env = Some("ORBIT_AUTH_FRESH_SYNTHETIC".into()),
            }
            assert!(
                load_model_provenance(tree.path(), &changed)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn metadata_unpublished_provider_is_refused_before_any_storage_creation() {
        let tree = Tree::new();
        let (provider, record) = applied();
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record]),
            Err(MetadataError::StaleConfig)
        );
        for name in ["metadata", ".setup.lock", ".config.lock"] {
            assert!(!tree.path().join(name).exists());
        }
    }

    #[test]
    fn metadata_config_last_failure_preserves_previous_sidecar_and_configuration() {
        let (tree, published, record) = seeded();
        let old_config = fs::read(tree.path().join("providers.toml")).unwrap();
        let old_sidecar = fs::read(sidecar(&tree, &published)).unwrap();
        let observed = observation(&published.models[0].id, 2000, 200);
        let merged = merge_discovered_model(
            &published.models[0],
            &observed,
            Some(&record),
            &identity(&published),
        );
        let mut candidate = published.clone();
        candidate.models[0] = merged.model;
        assert_eq!(
            save_model_provenance(tree.path(), &candidate, &[merged.provenance.unwrap()]),
            Err(MetadataError::StaleConfig)
        );
        assert_eq!(fs::read(sidecar(&tree, &published)).unwrap(), old_sidecar);
        assert_eq!(
            fs::read(tree.path().join("providers.toml")).unwrap(),
            old_config
        );
    }

    #[test]
    fn metadata_failed_optional_save_keeps_old_provenance_conservative_after_config_update() {
        let (tree, mut provider, old_record) = seeded();
        provider.models[0].context_window = Some(2000);
        publish_config(&tree, &provider);
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        let mut invalid = old_record.clone();
        invalid.observed.metadata_valid = false;
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[invalid]),
            Err(MetadataError::InvalidDocument)
        );
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
        let loaded = load_model_provenance(tree.path(), &provider).unwrap();
        let fresh = observation(&provider.models[0].id, 3000, 200);
        let merged = merge_discovered_model(
            &provider.models[0],
            &fresh,
            loaded.first(),
            &identity(&provider),
        );
        assert_eq!(merged.model.context_window, Some(2000));
        assert_eq!(merged.model.max_output_tokens, Some(200));
    }

    #[test]
    fn metadata_setup_lock_busy_does_not_try_to_create_config_lock_or_sidecar() {
        let tree = Tree::new();
        let (provider, record) = applied();
        publish_config(&tree, &provider);
        let root = Directory::open(tree.path(), true).unwrap();
        let _held = Lock::acquire(&root, ".setup.lock").unwrap();
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record]),
            Err(MetadataError::Busy)
        );
        assert!(!tree.path().join(".config.lock").exists());
        assert!(!tree.path().join("metadata").exists());
    }

    #[test]
    fn metadata_config_lock_busy_releases_setup_lock_without_publication() {
        let tree = Tree::new();
        let (provider, record) = applied();
        publish_config(&tree, &provider);
        let root = Directory::open(tree.path(), true).unwrap();
        let _held = Lock::acquire(&root, ".config.lock").unwrap();
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record]),
            Err(MetadataError::Busy)
        );
        let _setup_released = Lock::acquire(&root, ".setup.lock").unwrap();
        assert!(!tree.path().join("metadata").exists());
    }

    #[test]
    fn metadata_publication_holds_both_setup_and_config_locks() {
        let tree = Tree::new();
        let (provider, record) = applied();
        publish_config(&tree, &provider);
        let home = tree.path().to_path_buf();
        with_test_hook(
            move |point, _| {
                if point == PublicationPoint::Staged {
                    let root = Directory::open(&home, true).unwrap();
                    assert!(matches!(
                        Lock::acquire(&root, ".setup.lock"),
                        Err(StorageError::Busy)
                    ));
                    assert!(matches!(
                        Lock::acquire(&root, ".config.lock"),
                        Err(StorageError::Busy)
                    ));
                }
            },
            || save_model_provenance(tree.path(), &provider, &[record]),
        )
        .unwrap();
    }

    #[test]
    fn metadata_staged_directory_substitution_preserves_previous_sidecar_bytes() {
        let (tree, provider, record) = seeded();
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        let original = tree.path().join("metadata/providers");
        let moved = tree.path().join("moved-providers");
        let original_hook = original.clone();
        let moved_hook = moved.clone();
        let result = with_test_hook(
            move |point, _| {
                if point == PublicationPoint::Staged {
                    fs::rename(&original_hook, &moved_hook).unwrap();
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&original_hook)
                        .unwrap();
                }
            },
            || save_model_provenance(tree.path(), &provider, &[record]),
        );
        assert!(matches!(
            result,
            Err(MetadataError::UnsafePath | MetadataError::Io)
        ));
        fs::remove_dir(&original).unwrap();
        fs::rename(&moved, &original).unwrap();
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
    }

    #[test]
    fn metadata_after_rename_failure_is_explicitly_uncertain() {
        let (tree, provider, record) = seeded();
        let original = tree.path().join("metadata/providers");
        let moved = tree.path().join("moved-providers");
        let original_hook = original.clone();
        let moved_hook = moved.clone();
        let result = with_test_hook(
            move |point, _| {
                if point == PublicationPoint::Published {
                    fs::rename(&original_hook, &moved_hook).unwrap();
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&original_hook)
                        .unwrap();
                }
            },
            || save_model_provenance(tree.path(), &provider, &[record]),
        );
        assert_eq!(result, Err(MetadataError::PublicationUncertain));
        fs::remove_dir(&original).unwrap();
        fs::rename(&moved, &original).unwrap();
        assert_eq!(
            load_model_provenance(tree.path(), &provider).unwrap().len(),
            1
        );
    }

    #[test]
    fn metadata_missing_or_stale_document_version_returns_empty() {
        for document in [
            br#"{"models":"old-shape"}"#.as_slice(),
            br#"{"schema_version":3,"models":"future-shape"}"#.as_slice(),
        ] {
            let (tree, provider, _) = seeded();
            write_private(&sidecar(&tree, &provider), document);
            assert!(
                load_model_provenance(tree.path(), &provider)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn metadata_stale_record_version_returns_empty_conservatively() {
        let (tree, provider, _) = seeded();
        mutate_document(&tree, &provider, |document| {
            document["models"][0]["schema_version"] = 3.into()
        });
        assert!(
            load_model_provenance(tree.path(), &provider)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn metadata_malformed_json_and_unknown_fields_are_safe_typed_errors() {
        let (tree, provider, _) = seeded();
        write_private(&sidecar(&tree, &provider), b"synthetic-secret-not-json");
        let error = load_model_provenance(tree.path(), &provider).unwrap_err();
        assert_eq!(error, MetadataError::InvalidDocument);
        assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
        let (tree, provider, _) = seeded();
        mutate_document(&tree, &provider, |document| {
            document["models"][0]["observed"]["credential"] = "synthetic-secret".into()
        });
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::InvalidDocument)
        );
    }

    #[test]
    fn metadata_duplicate_json_fields_are_refused() {
        let (tree, provider, _) = seeded();
        let path = sidecar(&tree, &provider);
        let raw = String::from_utf8(fs::read(&path).unwrap()).unwrap();
        let duplicate = raw.replacen(
            "\"schema_version\":2",
            "\"schema_version\":2,\"schema_version\":2",
            1,
        );
        write_private(&path, duplicate.as_bytes());
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::InvalidDocument)
        );
    }

    #[test]
    fn metadata_duplicate_model_ids_are_refused_without_changing_old_sidecar() {
        let (tree, provider, record) = seeded();
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record.clone(), record]),
            Err(MetadataError::InvalidDocument)
        );
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
        mutate_document(&tree, &provider, |document| {
            let record = document["models"][0].clone();
            document["models"].as_array_mut().unwrap().push(record);
        });
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::InvalidDocument)
        );
    }

    #[test]
    fn metadata_wrong_document_or_record_binding_is_refused() {
        for document_binding in [true, false] {
            let (tree, provider, _) = seeded();
            mutate_document(&tree, &provider, |document| {
                if document_binding {
                    document["provider_binding"] = "wrong".into();
                } else {
                    document["models"][0]["provider_binding"] = "wrong".into();
                }
            });
            assert_eq!(
                load_model_provenance(tree.path(), &provider),
                Err(MetadataError::IdentityMismatch)
            );
        }
    }

    #[test]
    fn metadata_wrong_raw_identity_zero_numeric_or_inconsistent_last_applied_is_refused() {
        for variant in 0..4 {
            let (tree, provider, _) = seeded();
            mutate_document(&tree, &provider, |document| match variant {
                0 => document["models"][0]["observed"]["id"] = "different/raw".into(),
                1 => document["models"][0]["observed"]["context_window"] = 0.into(),
                2 => document["models"][0]["last_applied_context_window"] = 999.into(),
                _ => document["models"][0]["observed"]["source"] = "anthropic_models".into(),
            });
            assert_eq!(
                load_model_provenance(tree.path(), &provider),
                Err(MetadataError::InvalidDocument)
            );
        }
    }

    #[test]
    fn metadata_invalid_observation_strings_counts_and_numeric_types_are_refused() {
        for variant in 0..5 {
            let (tree, provider, _) = seeded();
            mutate_document(&tree, &provider, |document| match variant {
                0 => document["models"][0]["observed"]["label"] = "unsafe\u{001b}label".into(),
                1 => {
                    document["models"][0]["observed"]["unrecognized_fields"] =
                        serde_json::json!(["same", "same"])
                }
                2 => document["models"][0]["observed"]["max_output_tokens"] = 4294967296_u64.into(),
                3 => document["models"][0]["observed"]["context_window"] = "1000".into(),
                _ => {
                    document["models"][0]["observed"]["unrecognized_fields"] =
                        serde_json::json!(vec!["field"; 33])
                }
            });
            assert_eq!(
                load_model_provenance(tree.path(), &provider),
                Err(MetadataError::InvalidDocument)
            );
        }
    }

    #[test]
    fn metadata_more_than_128_records_is_refused_before_publication() {
        let (tree, provider, record) = seeded();
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &vec![record; 129]),
            Err(MetadataError::LimitExceeded)
        );
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
    }

    #[test]
    fn metadata_oversized_existing_file_is_refused_without_echo_or_overwrite() {
        let (tree, provider, record) = seeded();
        let path = sidecar(&tree, &provider);
        let oversized = vec![b'x'; 128 * 1024 + 1];
        write_private(&path, &oversized);
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::LimitExceeded)
        );
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record]),
            Err(MetadataError::LimitExceeded)
        );
        assert_eq!(fs::read(path).unwrap(), oversized);
    }

    #[test]
    fn metadata_serialized_document_limit_preserves_old_sidecar() {
        let (tree, mut provider, record) = seeded();
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        let mut records = Vec::new();
        for index in 0..128 {
            let mut item = record.clone();
            item.model_id = format!("raw-{index}");
            item.observed.id = item.model_id.clone();
            item.observed.unrecognized_fields = (0..32)
                .map(|field| format!("f{field:02}{}", "x".repeat(253)))
                .collect();
            let mut model = provider.models[0].clone();
            model.id = item.model_id.clone();
            if index == 0 {
                provider.models.clear();
            }
            provider.models.push(model);
            records.push(item);
        }
        publish_config(&tree, &provider);
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &records),
            Err(MetadataError::LimitExceeded)
        );
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
    }

    #[test]
    fn metadata_binding_directory_count_is_bounded() {
        let tree = Tree::new();
        let (provider, record) = applied();
        publish_config(&tree, &provider);
        let root = Directory::open(tree.path(), true).unwrap();
        let metadata = root.child("metadata", true).unwrap();
        let providers = metadata.child("providers", true).unwrap();
        for index in 0..128 {
            write_private(&providers.path().join(format!("{index:064x}.json")), b"{}");
        }
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record]),
            Err(MetadataError::LimitExceeded)
        );
        assert!(!sidecar(&tree, &provider).exists());
    }

    #[test]
    fn metadata_symlink_and_dangling_symlink_files_are_refused() {
        for dangling in [false, true] {
            let (tree, provider, record) = seeded();
            let target = sidecar(&tree, &provider);
            let outside = tree.path().join("outside.json");
            if !dangling {
                fs::rename(&target, &outside).unwrap();
            } else {
                fs::remove_file(&target).unwrap();
            }
            symlink(&outside, &target).unwrap();
            assert_eq!(
                load_model_provenance(tree.path(), &provider),
                Err(MetadataError::UnsafePath)
            );
            assert_eq!(
                save_model_provenance(tree.path(), &provider, &[record]),
                Err(MetadataError::UnsafePath)
            );
            assert_eq!(outside.exists(), !dangling);
        }
    }

    #[test]
    fn metadata_hardlink_and_public_file_mode_are_refused() {
        let (tree, provider, record) = seeded();
        fs::hard_link(
            sidecar(&tree, &provider),
            tree.path().join("outside-hardlink.json"),
        )
        .unwrap();
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::UnsafePath)
        );
        assert_eq!(
            save_model_provenance(tree.path(), &provider, &[record]),
            Err(MetadataError::UnsafePath)
        );
        let (tree, provider, _) = seeded();
        fs::set_permissions(sidecar(&tree, &provider), fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_model_provenance(tree.path(), &provider),
            Err(MetadataError::UnsafePath)
        );
    }

    #[test]
    fn metadata_symlink_or_public_directory_is_refused() {
        for symlink_case in [false, true] {
            let (tree, provider, _) = seeded();
            let directory = tree.path().join("metadata");
            if symlink_case {
                let moved = tree.path().join("elsewhere");
                fs::rename(&directory, &moved).unwrap();
                symlink(&moved, &directory).unwrap();
            } else {
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
            }
            assert_eq!(
                load_model_provenance(tree.path(), &provider),
                Err(MetadataError::UnsafePath)
            );
        }
    }

    #[test]
    fn metadata_symlink_ancestor_and_parent_components_are_refused() {
        let tree = Tree::new();
        let alias = tree.path().join("alias");
        symlink(tree.path(), &alias).unwrap();
        assert_eq!(
            load_model_provenance(&alias.join("missing"), &provider()),
            Err(MetadataError::UnsafePath)
        );
        assert_eq!(
            load_model_provenance(&tree.path().join("../unexpected"), &provider()),
            Err(MetadataError::UnsafePath)
        );
    }

    #[test]
    fn metadata_malformed_published_config_is_typed_and_preserves_sidecar() {
        let (tree, provider, record) = seeded();
        let before = fs::read(sidecar(&tree, &provider)).unwrap();
        write_private(
            &tree.path().join("providers.toml"),
            b"synthetic-sensitive-config-is-not-toml",
        );
        let error = save_model_provenance(tree.path(), &provider, &[record]).unwrap_err();
        assert_eq!(error, MetadataError::InvalidConfig);
        assert!(!format!("{error:?} {error}").contains("synthetic-sensitive"));
        assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
    }

    #[test]
    fn metadata_save_refuses_symlink_hardlink_or_public_published_config() {
        for variant in 0..3 {
            let (tree, provider, record) = seeded();
            let before = fs::read(sidecar(&tree, &provider)).unwrap();
            let path = tree.path().join("providers.toml");
            let outside = tree.path().join("outside.toml");
            match variant {
                0 => {
                    fs::rename(&path, &outside).unwrap();
                    symlink(&outside, &path).unwrap();
                }
                1 => fs::hard_link(&path, &outside).unwrap(),
                _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            }
            assert_eq!(
                save_model_provenance(tree.path(), &provider, &[record]),
                Err(MetadataError::UnsafePath)
            );
            assert_eq!(fs::read(sidecar(&tree, &provider)).unwrap(), before);
        }
    }

    #[test]
    fn metadata_save_accepts_unrelated_config_changes_and_does_not_rewrite_config() {
        let (tree, provider, record) = seeded();
        let mut unrelated = provider.clone();
        unrelated.name = "unrelated".into();
        unrelated.models[0].id = "other/raw".into();
        let config = ProvidersConfig {
            provider: vec![provider.clone(), unrelated],
            ..Default::default()
        };
        let bytes = toml::to_string(&config).unwrap().into_bytes();
        write_private(&tree.path().join("providers.toml"), &bytes);
        save_model_provenance(tree.path(), &provider, &[record]).unwrap();
        assert_eq!(fs::read(tree.path().join("providers.toml")).unwrap(), bytes);
    }
}

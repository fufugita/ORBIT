//! One terminal provider draft, validated before private/config publication.
#[path = "provider_login.rs"]
pub mod provider_login;

use crate::config::{ModelEntry, ProviderConfig, ProvidersConfig};
use crate::customization::{Directory, Error as SetupError, Lock};
use crate::provider_discovery::{
    DiscoveredCatalog, DiscoveredDetails, DiscoveredModel, DiscoveryCompleteness,
    DiscoveryIssueKind, DiscoveryProfile, DiscoverySession, MetadataSource, ModelProvenance,
    load_model_provenance, merge_discovered_model, save_model_provenance,
};
use crate::setup::{self, SetupPlan, SetupReceipt, SetupRequest};
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ExpectedRevision, MAX_PROVIDER_KEY_BYTES, ProviderAuthIdentity, ProviderCredentialError,
    ProviderCredentialRevision, ProviderCredentialSource, ProviderCredentialStatus,
    ProviderCredentialStore,
};
use orbit_provider_http::CancelToken;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum OnboardingError {
    #[error("Setup canceled; no provider configuration was saved")]
    Canceled,
    #[error(
        "Interactive setup requires terminal input and output; use explicit manual flags for automation"
    )]
    TerminalRequired,
    #[error("Terminal input or output failed")]
    TerminalIo,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("Configuration changed during setup; restart to review the current settings")]
    Stale,
    #[error(transparent)]
    Setup(#[from] SetupError),
    #[error(transparent)]
    Credential(#[from] ProviderCredentialError),
    #[error(
        "Publication may have committed; private recovery state was retained. Inspect setup status before retrying"
    )]
    PublicationUncertain,
    #[error(
        "Setup did not complete; a new private credential remains referenced or cleanup could not be verified, so it was retained. Inspect provider configuration before retrying"
    )]
    CredentialCleanupPending,
    #[error(transparent)]
    Login(#[from] provider_login::LoginError),
}

impl OnboardingError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Canceled => "ORBIT-E1104",
            Self::Stale => "ORBIT-E1103",
            Self::CredentialCleanupPending => "ORBIT-E1106",
            Self::PublicationUncertain
            | Self::Credential(ProviderCredentialError::PublicationUncertain)
            | Self::Setup(SetupError::PublicationUncertain(_)) => "ORBIT-E1105",
            _ => "ORBIT-E1101",
        }
    }
}

/// A display label is never used as an execution identity.
#[derive(Clone, Copy)]
pub struct SetupChoice<'a> {
    pub id: &'a str,
    pub label: &'a str,
    pub detail: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupSelection {
    Chosen(String),
    Back,
    Canceled,
}

fn validate_choices(
    choices: &[SetupChoice<'_>],
    current: Option<&str>,
) -> Result<(), OnboardingError> {
    let mut ids = BTreeSet::new();
    let mut bytes = 0usize;
    if choices.is_empty() || choices.len() > crate::setup_terminal_ui::MAX_CHOICES {
        return Err(OnboardingError::Invalid(
            "Choose from a bounded, nonempty menu",
        ));
    }
    for choice in choices {
        bytes = bytes
            .saturating_add(choice.id.len())
            .saturating_add(choice.label.len())
            .saturating_add(choice.detail.map_or(0, str::len));
        if choice.id.is_empty()
            || choice.id.len() > crate::setup_terminal_ui::MAX_TYPED_BYTES
            || choice.id.chars().any(char::is_control)
            || !ids.insert(choice.id)
            || choice.label.len() > 32 * 1024
            || choice.detail.is_some_and(|d| d.len() > 32 * 1024)
            || bytes > crate::setup_terminal_ui::MAX_MENU_TEXT_BYTES
        {
            return Err(OnboardingError::Invalid(
                "Menu identities or labels exceed their bounds",
            ));
        }
    }
    if current.is_some_and(|id| !ids.contains(id)) {
        return Err(OnboardingError::Invalid("Current choice is not offered"));
    }
    Ok(())
}

fn selected_answer(
    value: &str,
    choices: &[SetupChoice<'_>],
    current: Option<&str>,
    allow_back: bool,
) -> Option<SetupSelection> {
    // Exact identities win over numeric aliases and displayed navigation words.
    if let Some(choice) = choices.iter().find(|choice| choice.id == value) {
        return Some(SetupSelection::Chosen(choice.id.to_owned()));
    }
    if value.is_empty() {
        return current.map(|id| SetupSelection::Chosen(id.to_owned()));
    }
    if let Some(choice) = value
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| choices.get(n))
    {
        return Some(SetupSelection::Chosen(choice.id.to_owned()));
    }
    match value {
        "back" if allow_back => Some(SetupSelection::Back),
        "cancel" => Some(SetupSelection::Canceled),
        _ => None,
    }
}

fn plain_select<T: SetupTerminal + ?Sized>(
    terminal: &mut T,
    prompt: &str,
    choices: &[SetupChoice<'_>],
    current: Option<&str>,
    allow_back: bool,
) -> Result<SetupSelection, OnboardingError> {
    validate_choices(choices, current)?;
    for (index, choice) in choices.iter().enumerate() {
        terminal.message(&format!(
            "  {}. {}{}{}",
            index + 1,
            crate::setup_terminal_ui::safe(choice.label),
            if current == Some(choice.id) {
                " [current]"
            } else {
                ""
            },
            choice
                .detail
                .map(|detail| format!(" — {}", crate::setup_terminal_ui::safe(detail)))
                .unwrap_or_default()
        ))?;
    }
    terminal.message(if allow_back { "Enter a number or exact choice; back goes to the previous step, cancel discards this draft." } else { "Enter a number or exact choice; cancel discards this draft." })?;
    loop {
        let value = terminal.line(
            &format!("{prompt}: "),
            crate::setup_terminal_ui::MAX_TYPED_BYTES,
        )?;
        if let Some(selection) = selected_answer(&value, choices, current, allow_back) {
            return Ok(selection);
        }
        terminal.message("Choose an offered number or exact identity. Nothing was changed.")?;
    }
}

/// Implementations must return Canceled on EOF, and must never echo hidden input.
pub trait SetupTerminal {
    fn message(&mut self, message: &str) -> Result<(), OnboardingError>;
    fn line(&mut self, prompt: &str, max_bytes: usize) -> Result<String, OnboardingError>;
    fn hidden(&mut self, prompt: &str, max_bytes: usize) -> Result<SecretBytes, OnboardingError>;
    fn rich_choices_available(&self) -> bool {
        false
    }
    fn select(
        &mut self,
        prompt: &str,
        choices: &[SetupChoice<'_>],
        current: Option<&str>,
        allow_back: bool,
    ) -> Result<SetupSelection, OnboardingError> {
        plain_select(self, prompt, choices, current, allow_back)
    }
    fn hidden_until(
        &mut self,
        _prompt: &str,
        _max_bytes: usize,
        _deadline: std::time::Instant,
    ) -> Result<SecretBytes, OnboardingError> {
        Err(OnboardingError::Invalid(
            "This terminal cannot enforce bounded hidden input",
        ))
    }
}

/// The draft has no serialization or Debug implementation, and owns any unpublished key.
pub struct OnboardingDraft {
    provider: ProviderConfig,
    main: Option<String>,
    home: PathBuf,
    plan: SetupPlan,
    expected_provider: Option<ProviderConfig>,
    expected_credential_revision: Option<ProviderCredentialRevision>,
    expected_main: String,
    private_key: Option<SecretBytes>,
    confirmed: bool,
    catalog_status: &'static str,
    provenance: Option<Vec<ModelProvenance>>,
    metadata_warning: bool,
    authentication_online: bool,
}

#[derive(Debug, Serialize)]
pub struct OnboardingReceipt {
    #[serde(flatten)]
    pub setup: SetupReceipt,
    pub provider: String,
    pub models_configured: usize,
    pub main: Option<String>,
    pub credential_source: &'static str,
    pub credential_ready: bool,
    pub connectivity: &'static str,
    pub catalog_status: &'static str,
    pub metadata_saved: Option<bool>,
    pub warnings: Vec<&'static str>,
    pub authentication_online: bool,
}

fn config_snapshot(home: &Path) -> Result<ProvidersConfig, OnboardingError> {
    let bytes = setup::optional_file(home, "providers.toml", 128 * 1024)?.unwrap_or_default();
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| OnboardingError::Invalid("Provider configuration is not UTF-8"))?;
    ProvidersConfig::load_from_str(text)
        .map_err(|_| OnboardingError::Invalid("Provider configuration is invalid"))
}

fn answer<T: SetupTerminal>(
    terminal: &mut T,
    prompt: &str,
    default: Option<&str>,
    max: usize,
) -> Result<String, OnboardingError> {
    let prompt = match default.filter(|s| !s.is_empty()) {
        Some(value) => format!("{prompt} [{value}]: "),
        None => format!("{prompt}: "),
    };
    let value = terminal.line(&prompt, max)?;
    if value.is_empty() {
        Ok(default.unwrap_or_default().to_owned())
    } else if value.chars().any(char::is_control) || value.trim() != value {
        Err(OnboardingError::Invalid(
            "Enter bounded text without control characters or surrounding whitespace",
        ))
    } else {
        Ok(value)
    }
}

fn yes<T: SetupTerminal>(terminal: &mut T, prompt: &str) -> Result<bool, OnboardingError> {
    match answer(terminal, prompt, None, 16)?
        .to_ascii_lowercase()
        .as_str()
    {
        "yes" => Ok(true),
        "" | "no" => Ok(false),
        _ => Err(OnboardingError::Invalid("Enter yes or no")),
    }
}

/// Raw wire IDs are never split at slashes or rewritten into display names.
pub fn parse_manual_models(value: &str) -> Result<Vec<ModelEntry>, OnboardingError> {
    if value.len() > 33 * 1024 {
        return Err(OnboardingError::Invalid("Model selection is too large"));
    }
    let mut seen = BTreeSet::new();
    let mut models = Vec::new();
    for id in value.split(',').map(str::trim) {
        if id.is_empty()
            || id.len() > 256
            || id.chars().any(char::is_whitespace)
            || id.chars().any(char::is_control)
            || !seen.insert(id)
        {
            return Err(OnboardingError::Invalid(
                "Enter 1..128 distinct raw model IDs, each at most 256 bytes, separated by commas",
            ));
        }
        models.push(ModelEntry {
            context_limits: None,
            id: id.to_owned(),
            label: None,
            pricing: None,
            billing: None,
            max_output_tokens: None,
            context_window: None,
            sampling: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
            default_effort: None,
        });
        if models.len() > 128 {
            return Err(OnboardingError::Invalid("Select at most 128 models"));
        }
    }
    Ok(models)
}

fn identity(provider: &ProviderConfig) -> Result<ProviderAuthIdentity, OnboardingError> {
    let endpoint = crate::config::validate_provider_endpoint(&provider.url)
        .map_err(|_| OnboardingError::Invalid("Provider URL is invalid"))?;
    Ok(ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        endpoint.as_str(),
        provider.env.as_deref(),
    )?)
}

fn lookup_env(name: &str) -> Result<Option<SecretBytes>, ProviderCredentialError> {
    Ok(std::env::var_os(name).map(|value| SecretBytes::new(value.into_encoded_bytes())))
}

impl OnboardingDraft {
    pub fn provider(&self) -> &ProviderConfig {
        &self.provider
    }
    pub fn main(&self) -> Option<&str> {
        self.main.as_deref()
    }

    /// Discovery and login extensions use this exact fixed candidate identity.
    pub fn auth_identity(&self) -> Result<ProviderAuthIdentity, OnboardingError> {
        identity(&self.provider)
    }

    /// Shared precedence for a later online catalog step; it performs no request.
    pub fn resolve_credential(
        &self,
    ) -> Result<orbit_adapter::provider_credentials::ResolvedProviderCredential, OnboardingError>
    {
        let id = self.auth_identity()?;
        Ok(
            ProviderCredentialStore::new(&self.home)?.resolve_with_draft(
                &id,
                self.private_key.as_ref().map(|key| (&id, key)),
                lookup_env,
            )?,
        )
    }
}

/// Manual collection makes no request. The named discover action explicitly
/// authorizes catalog/detail requests; declining still performs no publication.
pub fn collect_onboarding<T: SetupTerminal>(
    home: &Path,
    preset_id: Option<&str>,
    terminal: &mut T,
) -> Result<OnboardingDraft, OnboardingError> {
    collect_onboarding_with_discovery(home, preset_id, terminal, &mut ProviderDiscoveryFactory)
}

/// Explicit typed injection for integrations and controlled protocol fixtures.
/// Production command paths use collect_onboarding's fixed provider factory.
pub fn collect_onboarding_with_discovery<T: SetupTerminal>(
    home: &Path,
    preset_id: Option<&str>,
    terminal: &mut T,
    discovery: &mut impl ModelDiscoveryFactory,
) -> Result<OnboardingDraft, OnboardingError> {
    collect_onboarding_with_services(
        home,
        preset_id,
        terminal,
        discovery,
        &mut ProviderLoginServiceFactory::default(),
    )
}

#[derive(Clone, Copy)]
enum SetupStage {
    Provider,
    Identity,
    Authentication,
    Models,
    Default,
    Review,
}
struct IdentityDraft {
    provider: ProviderConfig,
    previous: Option<ProviderConfig>,
    previous_credential_revision: Option<ProviderCredentialRevision>,
}
struct AuthenticationDraft {
    env: Option<String>,
    key: Option<SecretBytes>,
    online: bool,
}
enum StepValue<T> {
    Complete(T),
    Back,
}

fn stage<T: SetupTerminal>(
    terminal: &mut T,
    number: usize,
    title: &str,
    detail: &str,
) -> Result<(), OnboardingError> {
    terminal.message(&format!("\nORBIT SETUP  {number}/6  {title}"))?;
    terminal.message(detail)
}

enum FieldRecovery {
    Retry,
    Back,
}

fn recover_field<T: SetupTerminal>(
    terminal: &mut T,
    message: &'static str,
) -> Result<FieldRecovery, OnboardingError> {
    terminal.message(message)?;
    match terminal.select(
        "Correct this field",
        &[SetupChoice {
            id: "retry",
            label: "Try this field again",
            detail: Some("Repeat only this local input; nothing has been saved"),
        }],
        Some("retry"),
        true,
    )? {
        SetupSelection::Chosen(id) if id == "retry" => Ok(FieldRecovery::Retry),
        SetupSelection::Back => Ok(FieldRecovery::Back),
        SetupSelection::Canceled => Err(OnboardingError::Canceled),
        _ => Err(OnboardingError::Invalid(
            "Choose an offered correction action",
        )),
    }
}

fn retry_field<T: SetupTerminal, V>(
    terminal: &mut T,
    mut field: impl FnMut(&mut T) -> Result<V, OnboardingError>,
) -> Result<StepValue<V>, OnboardingError> {
    loop {
        match field(terminal) {
            Err(OnboardingError::Invalid(message)) => match recover_field(terminal, message)? {
                FieldRecovery::Retry => {}
                FieldRecovery::Back => return Ok(StepValue::Back),
            },
            Ok(value) => return Ok(StepValue::Complete(value)),
            Err(error) => return Err(error),
        }
    }
}

// This propagates a typed local navigation result, never a public failure or data sentinel.
macro_rules! setup_field {
    ($terminal:expr, $field:expr) => {
        match retry_field($terminal, $field)? {
            StepValue::Complete(value) => value,
            StepValue::Back => return Ok(StepValue::Back),
        }
    };
}

fn cached_action<T: SetupTerminal>(
    terminal: &mut T,
    title: &str,
    allow_back: bool,
) -> Result<SetupSelection, OnboardingError> {
    terminal.select(
        title,
        &[
            SetupChoice {
                id: "keep",
                label: "Keep this draft",
                detail: Some("Continue without repeating a login, discovery request, or write"),
            },
            SetupChoice {
                id: "edit",
                label: "Edit this step",
                detail: Some("Dependent unpublished choices will be collected again"),
            },
        ],
        Some("keep"),
        allow_back,
    )
}

fn collect_identity<T: SetupTerminal>(
    home: &Path,
    terminal: &mut T,
    preset: &crate::presets::ProviderPreset,
    existing: &ProvidersConfig,
) -> Result<StepValue<IdentityDraft>, OnboardingError> {
    let custom = preset.id == "custom";
    let name = setup_field!(terminal, |terminal| {
        let name = answer(
            terminal,
            "Provider name",
            (!custom).then_some(preset.id),
            128,
        )?;
        // Validate the name before asking about replacement or collecting a key.
        ProviderAuthIdentity::new(
            &name,
            "openai-compatible",
            "https://provider.example/",
            None,
        )
        .map_err(|_| OnboardingError::Invalid("Use a valid bounded provider name"))?;
        Ok(name)
    });
    let previous = existing
        .provider
        .iter()
        .find(|provider| provider.name == name)
        .cloned();
    let previous_credential_revision = previous
        .as_ref()
        .map(|provider| saved_revision(home, provider))
        .transpose()?
        .flatten();
    if previous.is_some()
        && !setup_field!(terminal, |terminal| yes(
            terminal,
            "Replace this existing provider? Type yes to continue"
        ))
    {
        return Err(OnboardingError::Canceled);
    }
    let kind = if custom {
        setup_field!(terminal, |terminal| {
            let kind = answer(
                terminal,
                "Adapter kind (openai-compatible/anthropic/ollama)",
                Some("openai-compatible"),
                64,
            )?;
            if !["openai-compatible", "anthropic", "ollama"].contains(&kind.as_str()) {
                return Err(OnboardingError::Invalid(
                    "Choose openai-compatible, anthropic or ollama",
                ));
            }
            Ok(kind)
        })
    } else {
        preset.kind.to_owned()
    };
    let url = setup_field!(terminal, |terminal| {
        let url = answer(terminal, "Base URL", (!custom).then_some(preset.url), 2048)?;
        crate::config::validate_provider_endpoint(&url)
            .map(|url| url.to_string())
            .map_err(|_| {
                OnboardingError::Invalid(
                    "Use an absolute HTTP(S) provider URL without credentials or a fragment",
                )
            })
    });
    ProviderAuthIdentity::new(&name, &kind, &url, None)?;
    Ok(StepValue::Complete(IdentityDraft {
        provider: ProviderConfig {
            name,
            kind,
            url,
            env: None,
            models: Vec::new(),
        },
        previous,
        previous_credential_revision,
    }))
}

fn collect_authentication<T: SetupTerminal>(
    terminal: &mut T,
    base: &ProviderConfig,
    preset: &crate::presets::ProviderPreset,
    previous_saved_identity: Option<&ProviderAuthIdentity>,
    login: &mut impl LoginServiceFactory,
) -> Result<StepValue<AuthenticationDraft>, OnboardingError> {
    loop {
        let browser_supported = provider_login::supports_browser_login(base);
        let mut choices = vec![
            SetupChoice {
                id: "env",
                label: "Environment variable",
                detail: Some("Read the key from an ENV variable at request time"),
            },
            SetupChoice {
                id: "key",
                label: "API key",
                detail: Some("Hidden entry; saved privately only after confirmation"),
            },
            SetupChoice {
                id: "key-env",
                label: "API key with ENV override",
                detail: Some("A nonempty declared ENV value takes precedence"),
            },
        ];
        if browser_supported {
            choices.push(SetupChoice {
                id: "browser",
                label: "Browser sign-in",
                detail: Some("Supported official OpenRouter authorization flow"),
            });
        }
        let no_auth_supported = preset.id == "custom" || base.kind == "ollama";
        if no_auth_supported {
            choices.push(SetupChoice {
                id: "none",
                label: "No authentication",
                detail: Some("For custom or local providers only"),
            });
        }
        let auth = match terminal.select("Authentication method", &choices, None, true)? {
            SetupSelection::Chosen(auth) => auth,
            SetupSelection::Back => return Ok(StepValue::Back),
            SetupSelection::Canceled => return Err(OnboardingError::Canceled),
        };
        let (env, key) = match auth.as_str() {
            "env" => {
                let name = setup_field!(terminal, |terminal| {
                    let name = answer(
                        terminal,
                        "Credential ENV name",
                        (!preset.env.is_empty()).then_some(preset.env),
                        128,
                    )?;
                    ProviderAuthIdentity::new(&base.name, &base.kind, &base.url, Some(&name))
                        .map_err(|_| {
                            OnboardingError::Invalid("Use a valid credential ENV variable name")
                        })?;
                    Ok(name)
                });
                (Some(name), None)
            }
            "key" | "key-env" => {
                let reference = if auth == "key-env" {
                    let name = setup_field!(terminal, |terminal| {
                        let name = answer(terminal, "Credential ENV name", None, 128)?;
                        let candidate = ProviderAuthIdentity::new(
                            &base.name,
                            &base.kind,
                            &base.url,
                            Some(&name),
                        )
                        .map_err(|_| {
                            OnboardingError::Invalid("Use a valid credential ENV variable name")
                        })?;
                        if previous_saved_identity.is_some_and(|previous| previous == &candidate) {
                            return Err(OnboardingError::Invalid(
                                "Choose a new private credential ENV name to rotate a saved key",
                            ));
                        }
                        Ok(name)
                    });
                    terminal.message("A nonempty value in this ENV takes precedence over the private key, including during model discovery.")?;
                    name
                } else {
                    format!("ORBIT_AUTH_{}", ulid::Ulid::new())
                };
                terminal.message(
                    "The key is hidden and will be saved privately only after confirmation.",
                )?;
                let key = setup_field!(terminal, |terminal| {
                    let key = terminal.hidden("API key (hidden): ", MAX_PROVIDER_KEY_BYTES)?;
                    if key.is_empty() || key.len() > MAX_PROVIDER_KEY_BYTES {
                        return Err(OnboardingError::Invalid(
                            "API key must be nonempty and bounded",
                        ));
                    }
                    let text = std::str::from_utf8(key.expose())
                        .map_err(|_| OnboardingError::Invalid("API key must be UTF-8"))?;
                    if text.trim().is_empty() || text.chars().any(char::is_control) {
                        return Err(OnboardingError::Invalid(
                            "API key contains invalid characters",
                        ));
                    }
                    Ok(key)
                });
                (Some(reference), Some(key))
            }
            "browser" if browser_supported => {
                let mode = setup_field!(terminal, |terminal| match answer(
                    terminal,
                    "Browser mode (loopback/headless)",
                    Some("loopback"),
                    16
                )?
                .as_str()
                {
                    "loopback" => Ok(provider_login::LoginMode::Loopback),
                    "headless" => Ok(provider_login::LoginMode::Headless),
                    _ => Err(OnboardingError::Invalid("Choose loopback or headless")),
                });
                let reference = format!("ORBIT_AUTH_{}", ulid::Ulid::new());
                let mut provider = base.clone();
                provider.env = Some(reference.clone());
                // This effect runs only after an explicit authentication choice; Back/Keep never calls it.
                let key = browser_key(
                    &provider,
                    &ProviderLoginRequest {
                        method: Some(ProviderLoginMethod::Browser),
                        mode,
                        open_browser: mode == provider_login::LoginMode::Loopback,
                    },
                    terminal,
                    login,
                )?;
                (Some(reference), Some(key))
            }
            "none" if no_auth_supported => (None, None),
            "none" => match recover_field(
                terminal,
                "No-auth is available for custom or local providers",
            )? {
                FieldRecovery::Retry => continue,
                FieldRecovery::Back => return Ok(StepValue::Back),
            },
            _ => {
                return Err(OnboardingError::Invalid(
                    "Choose an offered authentication method",
                ));
            }
        };
        return Ok(StepValue::Complete(AuthenticationDraft {
            env,
            key,
            online: auth == "browser",
        }));
    }
}

fn selected_provider(
    identity: &IdentityDraft,
    auth: &AuthenticationDraft,
    selection: &ModelSelection,
) -> Result<ProviderConfig, OnboardingError> {
    let mut provider = identity.provider.clone();
    provider.env = auth.env.clone();
    provider.models = identity
        .previous
        .as_ref()
        .map(|provider| provider.models.clone())
        .unwrap_or_default();
    for model in &selection.models {
        if let Some(old) = provider.models.iter_mut().find(|old| old.id == model.id) {
            if selection.provenance.is_some() {
                *old = model.clone();
            }
        } else {
            provider.models.push(model.clone());
        }
    }
    setup::validate_provider(&provider)?;
    Ok(provider)
}

enum DefaultIntent {
    Select,
    Unchanged,
    Back,
}
enum ReviewIntent {
    Save,
    Back,
}

fn collect_default<T: SetupTerminal>(
    terminal: &mut T,
    provider: &ProviderConfig,
    existing_main: &str,
) -> Result<StepValue<Option<String>>, OnboardingError> {
    let intent = setup_field!(terminal, |terminal| match answer(
        terminal,
        "Set main default? (yes/no)",
        None,
        16
    )?
    .to_ascii_lowercase()
    .as_str()
    {
        "yes" => Ok(DefaultIntent::Select),
        "" | "no" => Ok(DefaultIntent::Unchanged),
        "back" => Ok(DefaultIntent::Back),
        "cancel" => Err(OnboardingError::Canceled),
        _ => Err(OnboardingError::Invalid(
            "Enter yes, no, back or cancel. Nothing was saved."
        )),
    });
    match intent {
        DefaultIntent::Unchanged => return Ok(StepValue::Complete(None)),
        DefaultIntent::Back => return Ok(StepValue::Back),
        DefaultIntent::Select => {}
    }
    let choices: Vec<_> = provider
        .models
        .iter()
        .map(|model| SetupChoice {
            id: &model.id,
            label: &model.id,
            detail: model.label.as_deref(),
        })
        .collect();
    let prefix = format!("{}/", provider.name);
    let current = existing_main
        .strip_prefix(&prefix)
        .filter(|id| provider.models.iter().any(|model| model.id == *id));
    let id = match terminal.select("Main model ID", &choices, current, true)? {
        SetupSelection::Chosen(id) => id,
        SetupSelection::Back => return Ok(StepValue::Back),
        SetupSelection::Canceled => return Err(OnboardingError::Canceled),
    };
    let qualified = format!("{}/{}", provider.name, id);
    if !existing_main.is_empty()
        && existing_main != qualified
        && !setup_field!(terminal, |terminal| yes(
            terminal,
            "Replace main default? Type yes to continue"
        ))
    {
        return Err(OnboardingError::Canceled);
    }
    Ok(StepValue::Complete(Some(qualified)))
}

pub fn collect_onboarding_with_services<T: SetupTerminal>(
    home: &Path,
    preset_id: Option<&str>,
    terminal: &mut T,
    discovery: &mut impl ModelDiscoveryFactory,
    login: &mut impl LoginServiceFactory,
) -> Result<OnboardingDraft, OnboardingError> {
    let absolute_home = std::path::absolute(home).map_err(crate::customization::io_error)?;
    let home = absolute_home.as_path();
    let _ = ProviderCredentialStore::new(home)?;
    let baseline = setup::plan_setup(home, &SetupRequest::default())?;
    let existing = config_snapshot(home)?;
    terminal.message("ORBIT\nProvider setup. Type Ctrl-C to cancel. Manual model entry makes no provider request.")?;
    let offered = crate::presets::presets();
    let mut preset = preset_id
        .map(|id| {
            crate::presets::preset_by_id(id).ok_or(OnboardingError::Invalid(
                "Choose an offered provider name or number",
            ))
        })
        .transpose()?;
    let mut state = if preset.is_some() {
        SetupStage::Identity
    } else {
        SetupStage::Provider
    };
    let mut identity_draft: Option<IdentityDraft> = None;
    let mut authentication: Option<AuthenticationDraft> = None;
    let mut models: Option<ModelSelection> = None;
    let mut main: Option<Option<String>> = None;
    let mut revisiting = false;
    loop {
        match state {
            SetupStage::Provider => {
                stage(
                    terminal,
                    1,
                    "Provider",
                    "Choose a preset or a custom compatible endpoint.",
                )?;
                let choices: Vec<_> = offered
                    .iter()
                    .map(|preset| SetupChoice {
                        id: preset.id,
                        label: preset.id,
                        detail: Some(preset.blurb),
                    })
                    .collect();
                let selected = match terminal.select(
                    "Provider (name or number)",
                    &choices,
                    preset.as_ref().map(|preset| preset.id),
                    false,
                )? {
                    SetupSelection::Chosen(id) => id,
                    SetupSelection::Back | SetupSelection::Canceled => {
                        return Err(OnboardingError::Canceled);
                    }
                };
                let next = crate::presets::preset_by_id(&selected).ok_or(
                    OnboardingError::Invalid("Choose an offered provider name or number"),
                )?;
                if preset.as_ref().is_none_or(|old| old.id != next.id) {
                    identity_draft = None;
                    authentication = None;
                    models = None;
                    main = None;
                    revisiting = false;
                }
                preset = Some(next);
                state = SetupStage::Identity;
            }
            SetupStage::Identity => {
                stage(
                    terminal,
                    2,
                    "Identity",
                    "Name and endpoint bind the unpublished credential to this provider.",
                )?;
                let selected_preset = preset
                    .as_ref()
                    .ok_or(OnboardingError::Invalid("Provider selection is missing"))?;
                if revisiting && identity_draft.is_some() {
                    match cached_action(terminal, "Provider identity draft", true)? {
                        SetupSelection::Chosen(action) if action == "keep" => {
                            state = SetupStage::Authentication;
                            continue;
                        }
                        SetupSelection::Chosen(_) => {}
                        SetupSelection::Back => {
                            state = SetupStage::Provider;
                            continue;
                        }
                        SetupSelection::Canceled => return Err(OnboardingError::Canceled),
                    }
                }
                let next = match collect_identity(home, terminal, selected_preset, &existing)? {
                    StepValue::Complete(next) => next,
                    StepValue::Back => {
                        revisiting = true;
                        state = SetupStage::Provider;
                        continue;
                    }
                };
                if identity_draft
                    .as_ref()
                    .is_none_or(|old| old.provider != next.provider)
                {
                    authentication = None;
                    models = None;
                    main = None;
                }
                identity_draft = Some(next);
                revisiting = authentication.is_some();
                state = SetupStage::Authentication;
            }
            SetupStage::Authentication => {
                stage(
                    terminal,
                    3,
                    "Authentication",
                    "Keys stay hidden and unpublished until the final confirmation.",
                )?;
                if revisiting && authentication.is_some() {
                    match cached_action(terminal, "Authentication draft", true)? {
                        SetupSelection::Chosen(action) if action == "keep" => {
                            state = SetupStage::Models;
                            continue;
                        }
                        SetupSelection::Chosen(_) => {
                            authentication = None;
                            models = None;
                            main = None;
                        }
                        SetupSelection::Back => {
                            state = SetupStage::Identity;
                            continue;
                        }
                        SetupSelection::Canceled => return Err(OnboardingError::Canceled),
                    }
                }
                let identity_draft = identity_draft
                    .as_ref()
                    .ok_or(OnboardingError::Invalid("Provider identity is missing"))?;
                let previous_saved_identity =
                    if identity_draft.previous_credential_revision.is_some() {
                        identity_draft.previous.as_ref().map(identity).transpose()?
                    } else {
                        None
                    };
                let base = &identity_draft.provider;
                match collect_authentication(
                    terminal,
                    base,
                    preset
                        .as_ref()
                        .ok_or(OnboardingError::Invalid("Provider selection is missing"))?,
                    previous_saved_identity.as_ref(),
                    login,
                ) {
                    Ok(StepValue::Back) => {
                        revisiting = true;
                        state = SetupStage::Identity;
                    }
                    Ok(StepValue::Complete(auth)) => {
                        authentication = Some(auth);
                        revisiting = false;
                        state = SetupStage::Models;
                    }
                    Err(error) => return Err(error),
                }
            }
            SetupStage::Models => {
                stage(
                    terminal,
                    4,
                    "Models",
                    "Enter raw IDs offline, or explicitly request the provider catalog.",
                )?;
                if revisiting && models.is_some() {
                    match cached_action(terminal, "Model selection draft", true)? {
                        SetupSelection::Chosen(action) if action == "keep" => {
                            state = SetupStage::Default;
                            continue;
                        }
                        SetupSelection::Chosen(_) => {
                            models = None;
                            main = None;
                        }
                        SetupSelection::Back => {
                            state = SetupStage::Authentication;
                            continue;
                        }
                        SetupSelection::Canceled => return Err(OnboardingError::Canceled),
                    }
                }
                let source = match terminal.select(
                    "Model source (manual/discover) [manual]",
                    &[
                        SetupChoice {
                            id: "manual",
                            label: "Enter model IDs",
                            detail: Some("Offline; no provider request"),
                        },
                        SetupChoice {
                            id: "discover",
                            label: "Discover models",
                            detail: Some("Explicitly fetch this provider's catalog"),
                        },
                    ],
                    Some("manual"),
                    true,
                )? {
                    SetupSelection::Chosen(source) => source,
                    SetupSelection::Back => {
                        revisiting = true;
                        state = SetupStage::Authentication;
                        continue;
                    }
                    SetupSelection::Canceled => return Err(OnboardingError::Canceled),
                };
                let draft = identity_draft
                    .as_ref()
                    .ok_or(OnboardingError::Invalid("Provider identity is missing"))?;
                let auth = authentication
                    .as_ref()
                    .ok_or(OnboardingError::Invalid("Authentication is missing"))?;
                let mut provider = draft.provider.clone();
                provider.env = auth.env.clone();
                provider.models = draft
                    .previous
                    .as_ref()
                    .map(|provider| provider.models.clone())
                    .unwrap_or_default();
                match collect_models(
                    home,
                    &provider,
                    auth.key.as_ref(),
                    preset
                        .as_ref()
                        .ok_or(OnboardingError::Invalid("Provider selection is missing"))?,
                    terminal,
                    discovery,
                    &source,
                )? {
                    StepValue::Complete(selection) => {
                        models = Some(selection);
                        main = None;
                        revisiting = false;
                        state = SetupStage::Default;
                    }
                    StepValue::Back => {
                        revisiting = true;
                        state = SetupStage::Authentication;
                    }
                }
            }
            SetupStage::Default => {
                stage(
                    terminal,
                    5,
                    "Default model",
                    "Choose the model a new plain orbit session will use. Type back to revisit models.",
                )?;
                if revisiting && main.is_some() {
                    match cached_action(terminal, "Default model draft", true)? {
                        SetupSelection::Chosen(action) if action == "keep" => {
                            state = SetupStage::Review;
                            continue;
                        }
                        SetupSelection::Chosen(_) => {
                            main = None;
                        }
                        SetupSelection::Back => {
                            state = SetupStage::Models;
                            continue;
                        }
                        SetupSelection::Canceled => return Err(OnboardingError::Canceled),
                    }
                }
                let provider = selected_provider(
                    identity_draft
                        .as_ref()
                        .ok_or(OnboardingError::Invalid("Provider identity is missing"))?,
                    authentication
                        .as_ref()
                        .ok_or(OnboardingError::Invalid("Authentication is missing"))?,
                    models
                        .as_ref()
                        .ok_or(OnboardingError::Invalid("Model selection is missing"))?,
                )?;
                match collect_default(terminal, &provider, &existing.roles.main)? {
                    StepValue::Back => {
                        revisiting = true;
                        state = SetupStage::Models;
                    }
                    StepValue::Complete(selected) => {
                        main = Some(selected);
                        revisiting = false;
                        state = SetupStage::Review;
                    }
                }
            }
            SetupStage::Review => {
                stage(
                    terminal,
                    6,
                    "Review and save",
                    "Type yes to publish this draft once, back to revisit it, or no/cancel to discard.",
                )?;
                let identity_draft = identity_draft
                    .as_ref()
                    .ok_or(OnboardingError::Invalid("Provider identity is missing"))?;
                let auth = authentication
                    .as_mut()
                    .ok_or(OnboardingError::Invalid("Authentication is missing"))?;
                let selection = models
                    .as_ref()
                    .ok_or(OnboardingError::Invalid("Model selection is missing"))?;
                let provider = selected_provider(identity_draft, auth, selection)?;
                let selected_main = main
                    .as_ref()
                    .ok_or(OnboardingError::Invalid("Default choice is missing"))?
                    .clone();
                let request = SetupRequest {
                    provider: Some(provider.clone()),
                    ..Default::default()
                };
                let plan = setup::plan_setup_with_main(home, &request, selected_main.as_deref())?;
                if plan.revision != baseline.revision {
                    return Err(OnboardingError::Stale);
                }
                let mut draft = OnboardingDraft {
                    provider,
                    main: selected_main,
                    home: home.to_path_buf(),
                    plan,
                    expected_provider: identity_draft.previous.clone(),
                    expected_credential_revision: identity_draft.previous_credential_revision,
                    expected_main: existing.roles.main.clone(),
                    private_key: auth.key.take(),
                    confirmed: false,
                    catalog_status: selection.catalog_status,
                    provenance: selection.provenance.clone(),
                    metadata_warning: selection.metadata_warning,
                    authentication_online: auth.online,
                };
                let (source, ready) = credential_status(&draft)?;
                let model_ids = draft
                    .provider
                    .models
                    .iter()
                    .map(|model| format!("  - {}", safe_display(&model.id)))
                    .collect::<Vec<_>>()
                    .join("\n");
                let model_ids = if model_ids.is_empty() {
                    "  (none)".to_owned()
                } else {
                    model_ids
                };
                let credential_env = draft
                    .provider
                    .env
                    .as_deref()
                    .map(safe_display)
                    .unwrap_or_else(|| "(none)".to_owned());
                let main_default = match draft.main.as_deref() {
                    Some(main) => main,
                    None if draft.expected_main.is_empty() => "not set",
                    None => &draft.expected_main,
                };
                terminal.message(&format!(
                    "Provider: {} ({})\nEndpoint: {}\nModels ({}):\n{}\nMain default: {}\nCredential: {}{}\nCredential ENV name: {}\nCatalog: {}\nCompletion connectivity: not tested",
                    safe_display(&draft.provider.name),
                    draft.provider.kind,
                    safe_display(&draft.provider.url),
                    draft.provider.models.len(),
                    model_ids,
                    safe_display(main_default),
                    source,
                    if ready { "" } else { " (missing; set the declared ENV before running)" },
                    credential_env,
                    draft.catalog_status
                ))?;
                let action = retry_field(terminal, |terminal| {
                    match answer(
                        terminal,
                        "Save provider configuration? Type yes to confirm",
                        None,
                        16,
                    )?
                    .to_ascii_lowercase()
                    .as_str()
                    {
                        "yes" => Ok(ReviewIntent::Save),
                        "back" => Ok(ReviewIntent::Back),
                        "" | "no" | "cancel" => Err(OnboardingError::Canceled),
                        _ => Err(OnboardingError::Invalid(
                            "Enter yes to save, back to edit, or no/cancel to discard. Nothing was saved.",
                        )),
                    }
                })?;
                match action {
                    StepValue::Complete(ReviewIntent::Save) => {
                        draft.confirmed = true;
                        return Ok(draft);
                    }
                    StepValue::Back | StepValue::Complete(ReviewIntent::Back) => {
                        auth.key = draft.private_key.take();
                        revisiting = true;
                        state = SetupStage::Default;
                    }
                }
            }
        }
    }
}

fn credential_status(draft: &OnboardingDraft) -> Result<(&'static str, bool), OnboardingError> {
    if draft.private_key.is_none() {
        // A review must not repair a malformed store before confirmation. The
        // read-only status path still applies the exact declared ENV precedence.
        return match ProviderCredentialStore::new(&draft.home)?
            .status_read_only_with(&identity(&draft.provider)?, lookup_env)
        {
            ProviderCredentialStatus::NoAuth => Ok(("no authentication", true)),
            ProviderCredentialStatus::Available { source, .. } => Ok((
                match source {
                    ProviderCredentialSource::None => "no authentication",
                    ProviderCredentialSource::Environment => "environment override",
                    ProviderCredentialSource::Draft => "private key",
                    ProviderCredentialSource::Saved => "saved private key",
                },
                true,
            )),
            ProviderCredentialStatus::Missing => Ok(("environment reference", false)),
            ProviderCredentialStatus::Invalid(error) => Err(error.into()),
        };
    }
    // A validated inline draft resolves without accessing the saved store;
    // use the same broker as discovery/dispatch so a nonempty exact ENV wins.
    match draft.resolve_credential() {
        Ok(resolved) => Ok((
            match resolved.source() {
                ProviderCredentialSource::None => "no authentication",
                ProviderCredentialSource::Environment => "environment override",
                ProviderCredentialSource::Draft => "private key",
                ProviderCredentialSource::Saved => "saved private key",
            },
            true,
        )),
        Err(OnboardingError::Credential(ProviderCredentialError::Missing)) => {
            Ok(("environment reference", false))
        }
        Err(error) => Err(error),
    }
}

pub fn commit_onboarding(mut draft: OnboardingDraft) -> Result<OnboardingReceipt, OnboardingError> {
    if !draft.confirmed {
        return Err(OnboardingError::Canceled);
    }
    let existing = config_snapshot(&draft.home)?;
    if existing
        .provider
        .iter()
        .find(|p| p.name == draft.provider.name)
        != draft.expected_provider.as_ref()
        || existing.roles.main != draft.expected_main
    {
        return Err(OnboardingError::Stale);
    }
    let old_credential = draft
        .expected_provider
        .as_ref()
        .map(|provider| identity(provider).map(|id| (id, draft.expected_credential_revision)))
        .transpose()?;
    if let Some(previous) = &draft.expected_provider
        && saved_revision(&draft.home, previous)? != draft.expected_credential_revision
    {
        return Err(OnboardingError::Stale);
    }
    let request = SetupRequest {
        provider: Some(draft.provider.clone()),
        ..Default::default()
    };
    let current = setup::plan_setup_with_main(&draft.home, &request, draft.main.as_deref())?;
    if current.revision != draft.plan.revision {
        return Err(OnboardingError::Stale);
    }
    let (source, ready) = credential_status(&draft)?;
    let id = draft.auth_identity()?;
    if draft.private_key.is_some()
        && old_credential
            .as_ref()
            .is_some_and(|(old_id, revision)| old_id == &id && revision.is_some())
    {
        return Err(OnboardingError::Invalid(
            "Choose a new private credential ENV name to rotate a saved key",
        ));
    }
    let store = ProviderCredentialStore::new(&draft.home)?;
    let saved = if let Some(secret) = draft.private_key.take() {
        // Publication begins only after all choices and the complete config validate.
        let _home = Directory::create(&draft.home)?;
        Some(store.save(&id, secret, ExpectedRevision::Absent)?)
    } else {
        None
    };
    let receipt = match setup::apply_setup(&draft.plan) {
        Ok(receipt) => receipt,
        Err(SetupError::PublicationUncertain(_)) => {
            // Config may already reference the new identity. Preserve both records.
            return Err(OnboardingError::PublicationUncertain);
        }
        Err(error) => {
            // A definite pre-publication failure permits cleanup only if a fresh,
            // locked config read proves the newly saved identity is unreferenced.
            if let Some(saved) = saved {
                match remove_credential_if_unreferenced(&draft.home, &id, saved.revision) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => return Err(OnboardingError::CredentialCleanupPending),
                }
            }
            return Err(error.into());
        }
    };

    let mut warnings = Vec::new();
    if let Some((old_id, Some(old_revision))) = old_credential
        && old_id != id
        && remove_credential_if_unreferenced(&draft.home, &old_id, old_revision).is_err()
    {
        warnings.push("Provider configuration was saved, but the previous private credential could not be safely retired. Review the credential store before rotating again.");
    }
    // The authoritative provider config is published and its locks released.
    // Optional metadata failure must never roll back this successful setup.
    let (metadata_saved, metadata_warnings) = publish_optional_metadata(
        &draft.home,
        &draft.provider,
        draft.provenance.as_deref(),
        draft.metadata_warning,
    );
    warnings.extend(metadata_warnings);
    let main = draft
        .main
        .or_else(|| (!draft.expected_main.is_empty()).then_some(draft.expected_main));
    Ok(OnboardingReceipt {
        setup: receipt,
        provider: draft.provider.name,
        models_configured: draft.provider.models.len(),
        main,
        credential_source: source,
        credential_ready: ready,
        connectivity: "not_tested",
        catalog_status: draft.catalog_status,
        metadata_saved,
        warnings,
        authentication_online: draft.authentication_online,
    })
}

pub fn run_onboarding<T: SetupTerminal>(
    home: &Path,
    preset: Option<&str>,
    terminal: &mut T,
) -> Result<OnboardingReceipt, OnboardingError> {
    let receipt = commit_onboarding(collect_onboarding(home, preset, terminal)?)?;
    for warning in &receipt.warnings {
        // Publication already succeeded. A closed output stream cannot undo it
        // or turn the result into a misleading definite setup failure.
        let _ = terminal.message(warning);
    }
    Ok(receipt)
}

/// Model transport stays independent of terminal input and publication.
pub trait ModelDiscovery {
    fn credential_source(&self) -> ProviderCredentialSource;
    fn catalog(&mut self) -> Result<DiscoveredCatalog, OnboardingError>;
    fn details(
        &mut self,
        selected: &[DiscoveredModel],
        refresh: bool,
    ) -> Result<DiscoveredDetails, OnboardingError>;
}

pub trait ModelDiscoveryFactory {
    fn open(
        &mut self,
        home: &Path,
        provider: &ProviderConfig,
        profile: DiscoveryProfile,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
    ) -> Result<Box<dyn ModelDiscovery>, OnboardingError>;
}

pub struct ProviderDiscoveryFactory;
struct ScopedModelDiscovery {
    runtime: Option<tokio::runtime::Runtime>,
    session: Option<DiscoverySession>,
    cancel: CancelToken,
}

impl ModelDiscoveryFactory for ProviderDiscoveryFactory {
    fn open(
        &mut self,
        home: &Path,
        provider: &ProviderConfig,
        profile: DiscoveryProfile,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
    ) -> Result<Box<dyn ModelDiscovery>, OnboardingError> {
        // Both runtime creation and eventual destruction happen outside any
        // caller runtime. The thread is scoped and joined; no terminal callback
        // or borrowed secret can outlive this call.
        let owned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| {
                            OnboardingError::Invalid("Discovery runtime is unavailable")
                        })?;
                    let cancel = CancelToken::new();
                    let session = {
                        let _entered = runtime.enter();
                        DiscoverySession::new(home, provider, profile, draft, cancel.clone())
                            .map_err(|error| match error {
                                crate::provider_discovery::DiscoveryError::Credential(error) => {
                                    OnboardingError::Credential(error)
                                }
                                _ => OnboardingError::Invalid("Provider discovery is unavailable"),
                            })?
                    };
                    Ok::<_, OnboardingError>(ScopedModelDiscovery {
                        runtime: Some(runtime),
                        session: Some(session),
                        cancel,
                    })
                })
                .join()
                .map_err(|_| OnboardingError::Invalid("Discovery worker failed"))?
        })?;
        Ok(Box::new(owned))
    }
}

impl ScopedModelDiscovery {
    fn run<R: Send>(
        &self,
        future: impl std::future::Future<Output = R> + Send,
    ) -> Result<R, OnboardingError> {
        let _serial = TERMINAL_LOCK
            .lock()
            .map_err(|_| OnboardingError::TerminalIo)?;
        // A network wait has its own signal scope, independently of every input
        // prompt, so Ctrl-C while fetching cancels the same bounded HTTP work.
        let signals = SignalGuard::new()?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(OnboardingError::Invalid("Discovery runtime is closed"))?;
        let result = std::thread::scope(|scope| {
            let worker = scope.spawn(|| runtime.block_on(future));
            while !worker.is_finished() {
                if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
                    self.cancel.cancel();
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            worker
                .join()
                .map_err(|_| OnboardingError::Invalid("Discovery worker failed"))
        });
        let restored = signals.restore();
        restored?;
        if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
            self.cancel.cancel();
            return Err(OnboardingError::Canceled);
        }
        result
    }
}

impl ModelDiscovery for ScopedModelDiscovery {
    fn credential_source(&self) -> ProviderCredentialSource {
        self.session
            .as_ref()
            .map(DiscoverySession::credential_source)
            .unwrap_or(ProviderCredentialSource::None)
    }
    fn catalog(&mut self) -> Result<DiscoveredCatalog, OnboardingError> {
        let session = self
            .session
            .as_ref()
            .ok_or(OnboardingError::Invalid("Discovery session is closed"))?;
        let catalog = self.run(session.catalog())?;
        if catalog
            .issues
            .iter()
            .any(|issue| issue.kind == DiscoveryIssueKind::Cancelled)
        {
            return Err(OnboardingError::Canceled);
        }
        Ok(catalog)
    }
    fn details(
        &mut self,
        selected: &[DiscoveredModel],
        refresh: bool,
    ) -> Result<DiscoveredDetails, OnboardingError> {
        let session = self
            .session
            .as_ref()
            .ok_or(OnboardingError::Invalid("Discovery session is closed"))?;
        let details = self.run(session.details(selected, refresh))?;
        if details
            .issues
            .iter()
            .any(|issue| issue.kind == DiscoveryIssueKind::Cancelled)
        {
            return Err(OnboardingError::Canceled);
        }
        Ok(details)
    }
}

impl Drop for ScopedModelDiscovery {
    fn drop(&mut self) {
        self.cancel.cancel();
        let session = self.session.take();
        let runtime = self.runtime.take();
        // Tokio forbids dropping an owned runtime inside another runtime's
        // asynchronous context. Join its teardown on a scoped ordinary thread.
        let _ = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    drop(session);
                    if let Some(runtime) = runtime {
                        // Blocking DNS lookups cannot be aborted after they start.
                        // Close async work without waiting for the OS resolver; its
                        // hostname-only lookup may finish after this scoped teardown.
                        runtime.shutdown_background();
                    }
                })
                .join()
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLoginMethod {
    Browser,
    Key,
    Env,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderLoginRequest {
    pub method: Option<ProviderLoginMethod>,
    pub mode: provider_login::LoginMode,
    pub open_browser: bool,
}
impl Default for ProviderLoginRequest {
    fn default() -> Self {
        Self {
            method: None,
            mode: provider_login::LoginMode::Loopback,
            open_browser: true,
        }
    }
}

/// User-interface service boundary; implementations retain all secret state.
pub trait LoginService {
    fn authorization_url(&self) -> &url::Url;
    fn deadline(&self) -> std::time::Instant;
    fn open_browser(&mut self) -> Result<provider_login::BrowserOpenOutcome, OnboardingError>;
    fn finish_callback(&mut self) -> Result<SecretBytes, OnboardingError>;
    fn finish_headless(&mut self, code: SecretBytes) -> Result<SecretBytes, OnboardingError>;
}
pub trait LoginServiceFactory {
    fn open(
        &mut self,
        provider: &ProviderConfig,
        mode: provider_login::LoginMode,
    ) -> Result<Box<dyn LoginService>, OnboardingError>;
}
pub trait AuthorizationOpener {
    fn open(
        &mut self,
        authorization: &url::Url,
    ) -> Result<provider_login::BrowserOpenOutcome, OnboardingError>;
}

#[derive(Default)]
pub struct ProviderLoginServiceFactory {
    test_transport: Option<provider_login::LoopbackTestTransport>,
    test_opener: Option<Box<dyn AuthorizationOpener>>,
    test_only: bool,
}
impl ProviderLoginServiceFactory {
    /// Explicit owned-loopback test capability. No command, ENV or config field
    /// can construct this alternative transport or substitute an opener.
    pub fn with_loopback_test_transport(
        transport: provider_login::LoopbackTestTransport,
        opener: Box<dyn AuthorizationOpener>,
    ) -> Self {
        Self {
            test_transport: Some(transport),
            test_opener: Some(opener),
            test_only: true,
        }
    }
}
struct ScopedLoginService {
    runtime: Option<tokio::runtime::Runtime>,
    login: Option<provider_login::ProviderLogin>,
    opener: Option<Box<dyn AuthorizationOpener>>,
    cancel: CancelToken,
}
impl LoginServiceFactory for ProviderLoginServiceFactory {
    fn open(
        &mut self,
        provider: &ProviderConfig,
        mode: provider_login::LoginMode,
    ) -> Result<Box<dyn LoginService>, OnboardingError> {
        if self.test_only && self.test_transport.is_none() {
            return Err(OnboardingError::Invalid(
                "The local login test transport is already used",
            ));
        }
        let transport = self.test_transport.take();
        let opener = self.test_opener.take();
        let (runtime, login, cancel) = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| OnboardingError::Invalid("Login runtime is unavailable"))?;
                    let cancel = CancelToken::new();
                    let result = runtime.block_on(async {
                        if let Some(transport) = transport {
                            provider_login::ProviderLogin::start_with_loopback_test_transport(
                                provider,
                                mode,
                                "ORBIT",
                                cancel.clone(),
                                transport,
                            )
                            .await
                        } else {
                            provider_login::ProviderLogin::start(
                                provider,
                                mode,
                                "ORBIT",
                                cancel.clone(),
                            )
                            .await
                        }
                    });
                    match result {
                        Ok(login) => Ok((runtime, login, cancel)),
                        Err(error) => {
                            runtime.shutdown_background();
                            Err(map_login_error(error))
                        }
                    }
                })
                .join()
                .map_err(|_| OnboardingError::Invalid("Login worker failed"))?
        })?;
        Ok(Box::new(ScopedLoginService {
            runtime: Some(runtime),
            login: Some(login),
            opener,
            cancel,
        }))
    }
}

fn map_login_error(error: provider_login::LoginError) -> OnboardingError {
    if error == provider_login::LoginError::Canceled {
        OnboardingError::Canceled
    } else {
        OnboardingError::Login(error)
    }
}
fn run_login_future<R: Send>(
    runtime: &tokio::runtime::Runtime,
    cancel: &CancelToken,
    future: impl std::future::Future<Output = Result<R, provider_login::LoginError>> + Send,
) -> Result<R, OnboardingError> {
    let _serial = TERMINAL_LOCK
        .lock()
        .map_err(|_| OnboardingError::TerminalIo)?;
    let signals = SignalGuard::new()?;
    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| runtime.block_on(future));
        while !worker.is_finished() {
            if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
                cancel.cancel();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        worker
            .join()
            .map_err(|_| OnboardingError::Invalid("Login worker failed"))
    });
    signals.restore()?;
    if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
        cancel.cancel();
        return Err(OnboardingError::Canceled);
    }
    result?.map_err(map_login_error)
}
impl LoginService for ScopedLoginService {
    fn authorization_url(&self) -> &url::Url {
        // The service exists only while its initialized session is held.
        self.login
            .as_ref()
            .expect("initialized login service")
            .authorization_url()
    }
    fn deadline(&self) -> std::time::Instant {
        self.login
            .as_ref()
            .expect("initialized login service")
            .deadline()
    }
    fn open_browser(&mut self) -> Result<provider_login::BrowserOpenOutcome, OnboardingError> {
        let login = self
            .login
            .as_ref()
            .ok_or(OnboardingError::Invalid("Login session is closed"))?;
        if let Some(opener) = &mut self.opener {
            return opener.open(login.authorization_url());
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(OnboardingError::Invalid("Login runtime is closed"))?;
        run_login_future(runtime, &self.cancel, login.open_browser())
    }
    fn finish_callback(&mut self) -> Result<SecretBytes, OnboardingError> {
        let login = self
            .login
            .as_mut()
            .ok_or(OnboardingError::Invalid("Login session is closed"))?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(OnboardingError::Invalid("Login runtime is closed"))?;
        run_login_future(runtime, &self.cancel, async {
            let code = login.wait_for_callback().await?;
            login.exchange(code).await
        })
    }
    fn finish_headless(&mut self, bytes: SecretBytes) -> Result<SecretBytes, OnboardingError> {
        let login = self
            .login
            .as_mut()
            .ok_or(OnboardingError::Invalid("Login session is closed"))?;
        let code = login.accept_headless_code(bytes).map_err(map_login_error)?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(OnboardingError::Invalid("Login runtime is closed"))?;
        run_login_future(runtime, &self.cancel, login.exchange(code))
    }
}
impl Drop for ScopedLoginService {
    fn drop(&mut self) {
        self.cancel.cancel();
        let login = self.login.take();
        let runtime = self.runtime.take();
        let _ = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    drop(login);
                    if let Some(runtime) = runtime {
                        runtime.shutdown_background();
                    }
                })
                .join()
        });
    }
}

fn browser_key(
    provider: &ProviderConfig,
    request: &ProviderLoginRequest,
    terminal: &mut impl SetupTerminal,
    factory: &mut impl LoginServiceFactory,
) -> Result<SecretBytes, OnboardingError> {
    if !provider_login::supports_browser_login(provider) {
        return Err(provider_login::LoginError::UnsupportedProvider.into());
    }
    let mut login = factory.open(provider, request.mode)?;
    terminal.message(&format!(
        "Authorize with the provider: {}",
        login.authorization_url()
    ))?;
    terminal.message(
        "Authorization returns an API key. It is kept private until you confirm saving.",
    )?;
    if request.open_browser
        && request.mode == provider_login::LoginMode::Loopback
        && login.open_browser()? == provider_login::BrowserOpenOutcome::ManualOpenRequired
    {
        terminal.message("The browser could not be opened automatically. Open the same authorization URL manually.")?;
    }
    if request.mode == provider_login::LoginMode::Headless {
        terminal.message("Open the authorization URL on your browser, then paste the displayed code privately here.")?;
        let code = terminal.hidden_until(
            "Authorization code (hidden): ",
            provider_login::MAX_AUTHORIZATION_CODE_BYTES,
            login.deadline(),
        )?;
        login.finish_headless(code)
    } else {
        terminal.message("Waiting for the local authorization callback. Ctrl-C cancels.")?;
        login.finish_callback()
    }
}

fn validate_private_key(key: SecretBytes) -> Result<SecretBytes, OnboardingError> {
    if key.is_empty() || key.len() > MAX_PROVIDER_KEY_BYTES {
        return Err(OnboardingError::Invalid(
            "API key must be nonempty and bounded",
        ));
    }
    let text = std::str::from_utf8(key.expose())
        .map_err(|_| OnboardingError::Invalid("API key must be UTF-8"))?;
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err(OnboardingError::Invalid(
            "API key contains invalid characters",
        ));
    }
    Ok(key)
}

pub fn collect_provider_login(
    home: &Path,
    name: &str,
    request: &ProviderLoginRequest,
    terminal: &mut impl SetupTerminal,
) -> Result<OnboardingDraft, OnboardingError> {
    collect_provider_login_with_services(
        home,
        name,
        request,
        terminal,
        &mut ProviderLoginServiceFactory::default(),
    )
}
pub fn collect_provider_login_with_services(
    home: &Path,
    name: &str,
    request: &ProviderLoginRequest,
    terminal: &mut impl SetupTerminal,
    login: &mut impl LoginServiceFactory,
) -> Result<OnboardingDraft, OnboardingError> {
    let home = std::path::absolute(home).map_err(crate::customization::io_error)?;
    let baseline = setup::plan_setup(&home, &SetupRequest::default())?;
    if baseline.initialize {
        return Err(OnboardingError::Invalid(
            "Initialize this private home with setup before provider login",
        ));
    }
    let existing = config_snapshot(&home)?;
    let expected = existing
        .provider
        .iter()
        .find(|provider| provider.name == name)
        .cloned()
        .ok_or(OnboardingError::Invalid("Unknown configured provider"))?;
    // Pin the old saved record before login input or browser flow begins.
    let expected_credential_revision = saved_revision(&home, &expected)?;
    let method = match request.method {
        Some(method) => method,
        None => {
            let choice = answer(
                terminal,
                if provider_login::supports_browser_login(&expected) {
                    "Login method (browser/key/env)"
                } else {
                    "Login method (key/env)"
                },
                None,
                16,
            )?;
            match choice.as_str() {
                "browser" => ProviderLoginMethod::Browser,
                "key" => ProviderLoginMethod::Key,
                "env" => ProviderLoginMethod::Env,
                _ => return Err(OnboardingError::Invalid("Choose an offered login method")),
            }
        }
    };
    if method != ProviderLoginMethod::Browser && request.mode == provider_login::LoginMode::Headless
    {
        return Err(OnboardingError::Invalid(
            "Headless mode requires browser login",
        ));
    }
    let mut provider = expected.clone();
    let private_key = match method {
        ProviderLoginMethod::Env => {
            let reference = answer(
                terminal,
                "Credential ENV name",
                expected.env.as_deref(),
                128,
            )?;
            provider.env = Some(reference);
            let _ = identity(&provider)?;
            None
        }
        ProviderLoginMethod::Key | ProviderLoginMethod::Browser => {
            provider.env = Some(format!("ORBIT_AUTH_{}", ulid::Ulid::new()));
            let _ = identity(&provider)?;
            Some(if method == ProviderLoginMethod::Browser {
                browser_key(&provider, request, terminal, login)?
            } else {
                validate_private_key(
                    terminal.hidden("API key (hidden): ", MAX_PROVIDER_KEY_BYTES)?,
                )?
            })
        }
    };
    let plan = setup::plan_setup_with_main(
        &home,
        &SetupRequest {
            provider: Some(provider.clone()),
            ..Default::default()
        },
        None,
    )?;
    if plan.revision != baseline.revision {
        return Err(OnboardingError::Stale);
    }
    let mut draft = OnboardingDraft {
        provider,
        main: None,
        home,
        plan,
        expected_provider: Some(expected),
        expected_credential_revision,
        expected_main: existing.roles.main,
        private_key,
        confirmed: false,
        catalog_status: "not_requested",
        provenance: None,
        metadata_warning: false,
        authentication_online: method == ProviderLoginMethod::Browser,
    };
    let (source, ready) = credential_status(&draft)?;
    let credential_reference = draft.provider.env.as_deref().unwrap_or("none");
    terminal.message(&format!("Provider: {}\nEndpoint: {}\nCredential reference: {}\nCredential: {}{}\nModels and defaults are preserved. Completion connectivity: not tested.",
        safe_display(&draft.provider.name), safe_display(&draft.provider.url), safe_display(credential_reference),
        source, if ready { "" } else { " (missing)" }))?;
    if draft.provider.env
        != draft
            .expected_provider
            .as_ref()
            .and_then(|provider| provider.env.clone())
    {
        terminal.message("The credential reference changes; the previous ENV reference no longer serves this provider.")?;
    }
    if !yes(terminal, "Save provider login? Type yes to confirm")? {
        return Err(OnboardingError::Canceled);
    }
    draft.confirmed = true;
    Ok(draft)
}

pub struct ProviderLogoutPlan {
    home: PathBuf,
    provider: ProviderConfig,
    revision: String,
    credential: Option<orbit_adapter::provider_credentials::ProviderCredentialRevision>,
}
#[derive(Debug, Serialize)]
pub struct ProviderLogoutReceipt {
    pub provider: String,
    pub removed: bool,
    pub env_override_active: bool,
    pub scope: &'static str,
}
fn saved_revision(
    home: &Path,
    provider: &ProviderConfig,
) -> Result<Option<orbit_adapter::provider_credentials::ProviderCredentialRevision>, OnboardingError>
{
    match ProviderCredentialStore::new(home)?
        .status_read_only_with(&identity(provider)?, |_| Ok(None))
    {
        ProviderCredentialStatus::Available { revision, .. } => Ok(revision),
        ProviderCredentialStatus::NoAuth | ProviderCredentialStatus::Missing => Ok(None),
        ProviderCredentialStatus::Invalid(error) => Err(error.into()),
    }
}

/// Remove a saved credential only while holding the config publication locks and
/// only when a fresh read confirms no provider still references its exact identity.
fn remove_credential_if_unreferenced(
    home: &Path,
    credential_identity: &ProviderAuthIdentity,
    revision: ProviderCredentialRevision,
) -> Result<bool, OnboardingError> {
    let directory = Directory::open(home, true)?;
    let _setup = Lock::acquire(&directory, ".setup.lock")?;
    let _config = Lock::acquire(&directory, ".config.lock")?;
    let config = config_snapshot(home)?;
    for provider in &config.provider {
        if &identity(provider)? == credential_identity {
            return Ok(false);
        }
    }
    ProviderCredentialStore::new(home)?
        .remove(credential_identity, ExpectedRevision::Exact(revision))?;
    Ok(true)
}
pub fn plan_provider_logout(
    home: &Path,
    name: &str,
) -> Result<ProviderLogoutPlan, OnboardingError> {
    let home = std::path::absolute(home).map_err(crate::customization::io_error)?;
    let baseline = setup::plan_setup(&home, &SetupRequest::default())?;
    if baseline.initialize {
        return Err(OnboardingError::Invalid(
            "Initialize this private home with setup before provider logout",
        ));
    }
    let existing = config_snapshot(&home)?;
    let provider = existing
        .provider
        .into_iter()
        .find(|provider| provider.name == name)
        .ok_or(OnboardingError::Invalid("Unknown configured provider"))?;
    let credential = saved_revision(&home, &provider)?;
    Ok(ProviderLogoutPlan {
        home,
        provider,
        revision: baseline.revision,
        credential,
    })
}
pub fn commit_provider_logout(
    plan: ProviderLogoutPlan,
) -> Result<ProviderLogoutReceipt, OnboardingError> {
    let home = Directory::open(&plan.home, true)?;
    let _setup = Lock::acquire(&home, ".setup.lock")?;
    let _config = Lock::acquire(&home, ".config.lock")?;
    let current = setup::plan_setup(&plan.home, &SetupRequest::default())?;
    if current.revision != plan.revision
        || config_snapshot(&plan.home)?
            .provider
            .iter()
            .find(|provider| provider.name == plan.provider.name)
            != Some(&plan.provider)
        || saved_revision(&plan.home, &plan.provider)? != plan.credential
    {
        return Err(OnboardingError::Stale);
    }
    let removed = if let Some(revision) = plan.credential {
        ProviderCredentialStore::new(&plan.home)?.remove(
            &identity(&plan.provider)?,
            ExpectedRevision::Exact(revision),
        )?;
        true
    } else {
        false
    };
    let verified = home.check().and_then(|()| {
        setup::plan_setup(&plan.home, &SetupRequest::default()).and_then(|current| {
            if current.revision == plan.revision {
                Ok(())
            } else {
                Err(SetupError::Busy)
            }
        })
    });
    if let Err(error) = verified {
        return Err(if removed {
            OnboardingError::PublicationUncertain
        } else {
            error.into()
        });
    }
    let env_override_active = match plan.provider.env.as_deref().map(lookup_env).transpose() {
        Ok(value) => value.flatten().is_some_and(|value| !value.is_empty()),
        Err(error) => {
            return Err(if removed {
                OnboardingError::PublicationUncertain
            } else {
                error.into()
            });
        }
    };
    Ok(ProviderLogoutReceipt {
        provider: plan.provider.name,
        removed,
        env_override_active,
        scope: "current_local_binding",
    })
}

pub fn confirm_provider_logout(
    plan: ProviderLogoutPlan,
    terminal: &mut impl SetupTerminal,
) -> Result<ProviderLogoutReceipt, OnboardingError> {
    terminal.message(&format!("Remove the current saved local key for {}? Provider configuration, models, defaults and ENV values are preserved. This does not revoke a key at the provider.", safe_display(&plan.provider.name)))?;
    if !yes(terminal, "Log out locally? Type yes to confirm")? {
        return Err(OnboardingError::Canceled);
    }
    commit_provider_logout(plan)
}

struct ModelSelection {
    models: Vec<ModelEntry>,
    provenance: Option<Vec<ModelProvenance>>,
    catalog_status: &'static str,
    metadata_warning: bool,
}

fn manual_selection<T: SetupTerminal>(
    terminal: &mut T,
    status: &'static str,
) -> Result<StepValue<ModelSelection>, OnboardingError> {
    let models = setup_field!(terminal, |terminal| parse_manual_models(&answer(
        terminal,
        "Raw model IDs (comma-separated)",
        None,
        33 * 1024,
    )?));
    Ok(StepValue::Complete(ModelSelection {
        models,
        provenance: None,
        catalog_status: status,
        metadata_warning: false,
    }))
}

fn profile_for(
    kind: &str,
    custom: bool,
    preset: &str,
    terminal: &mut impl SetupTerminal,
) -> Result<DiscoveryProfile, OnboardingError> {
    match kind {
        "anthropic" => Ok(DiscoveryProfile::Anthropic),
        "ollama" => Ok(DiscoveryProfile::Ollama),
        "openai-compatible" if custom => match answer(
            terminal,
            "Discovery schema (generic/openrouter)",
            Some("generic"),
            16,
        )?
        .as_str()
        {
            "generic" => Ok(DiscoveryProfile::GenericOpenAi),
            "openrouter" => Ok(DiscoveryProfile::OpenRouter),
            _ => Err(OnboardingError::Invalid(
                "Choose generic or openrouter discovery schema",
            )),
        },
        "openai-compatible" if preset == "openrouter" => Ok(DiscoveryProfile::OpenRouter),
        "openai-compatible" => Ok(DiscoveryProfile::GenericOpenAi),
        _ => Err(OnboardingError::Invalid("Unsupported discovery adapter")),
    }
}

fn safe_display(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn choose_catalog_rich<T: SetupTerminal>(
    terminal: &mut T,
    catalog: &[DiscoveredModel],
) -> Result<StepValue<Option<Vec<DiscoveredModel>>>, OnboardingError> {
    const PAGE_SIZE: usize = 20;
    const FILTER: &str = "catalog:filter";
    const MANUAL: &str = "catalog:manual";
    const PREVIOUS: &str = "catalog:previous";
    const NEXT: &str = "catalog:next";
    const FINISH: &str = "catalog:finish";

    let mut filter = String::new();
    let mut page = 0usize;
    let mut selected = Vec::<usize>::new();
    let mut focus = None::<String>;
    loop {
        let filtered: Vec<usize> = catalog
            .iter()
            .enumerate()
            .filter(|(_, model)| {
                filter.is_empty()
                    || model.id.to_lowercase().contains(&filter)
                    || model
                        .label
                        .as_ref()
                        .is_some_and(|label| label.to_lowercase().contains(&filter))
            })
            .map(|(index, _)| index)
            .collect();
        let pages = filtered.len().div_ceil(PAGE_SIZE).max(1);
        page = page.min(pages - 1);
        let start = page * PAGE_SIZE;
        let mut owned = Vec::<(String, String, Option<String>)>::new();
        for index in filtered.iter().copied().skip(start).take(PAGE_SIZE) {
            let model = &catalog[index];
            let marker = if selected.contains(&index) {
                "[x]"
            } else {
                "[ ]"
            };
            let label = format!(
                "{} {}{}",
                marker,
                safe_display(&model.id),
                model
                    .label
                    .as_ref()
                    .map(|label| format!(" - {}", safe_display(label)))
                    .unwrap_or_default()
            );
            let context = model
                .context_window
                .filter(|_| model.metadata_valid)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into());
            let output = model
                .max_output_tokens
                .filter(|_| model.metadata_valid)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into());
            owned.push((
                format!("catalog:model:{index}"),
                label,
                Some(format!("Context: {context}; max output: {output}")),
            ));
        }
        owned.push((
            FILTER.to_owned(),
            "Filter by model ID or label".to_owned(),
            None,
        ));
        if page > 0 {
            owned.push((PREVIOUS.to_owned(), "Previous page".to_owned(), None));
        }
        if page + 1 < pages {
            owned.push((NEXT.to_owned(), "Next page".to_owned(), None));
        }
        owned.push((
            MANUAL.to_owned(),
            "Use manual entry instead".to_owned(),
            None,
        ));
        owned.push((
            FINISH.to_owned(),
            format!("Finish selection ({} selected)", selected.len()),
            None,
        ));
        let choices: Vec<_> = owned
            .iter()
            .map(|(id, label, detail)| SetupChoice {
                id,
                label,
                detail: detail.as_deref(),
            })
            .collect();
        let title = format!(
            "Discovered models (page {}/{}, {} selected; Enter toggles, Finish continues)",
            page + 1,
            pages,
            selected.len()
        );
        let choice = match terminal.select(&title, &choices, focus.as_deref(), true)? {
            SetupSelection::Chosen(id) => id,
            SetupSelection::Back => return Ok(StepValue::Back),
            SetupSelection::Canceled => return Err(OnboardingError::Canceled),
        };
        if let Some(index) = choice
            .strip_prefix("catalog:model:")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|index| {
                filtered
                    .iter()
                    .copied()
                    .skip(start)
                    .take(PAGE_SIZE)
                    .any(|visible| visible == *index)
            })
        {
            if let Some(position) = selected.iter().position(|selected| *selected == index) {
                selected.remove(position);
            } else if selected.len() < 128 {
                selected.push(index);
            } else {
                terminal.message(
                    "You can select at most 128 models. Remove one before adding another.",
                )?;
            }
            focus = Some(choice);
            continue;
        }
        match choice.as_str() {
            FILTER => {
                let query = terminal.line("Filter models (blank shows all)", 128)?;
                filter = query.trim().to_lowercase();
                page = 0;
                focus = filtered
                    .iter()
                    .copied()
                    .find(|index| catalog[*index].id.to_lowercase().contains(&filter))
                    .map(|index| format!("catalog:model:{index}"));
            }
            PREVIOUS => {
                page = page.saturating_sub(1);
                focus = filtered
                    .iter()
                    .copied()
                    .skip(page * PAGE_SIZE)
                    .take(PAGE_SIZE)
                    .next()
                    .map(|index| format!("catalog:model:{index}"));
            }
            NEXT => {
                page = (page + 1).min(pages - 1);
                focus = filtered
                    .iter()
                    .copied()
                    .skip(page * PAGE_SIZE)
                    .take(PAGE_SIZE)
                    .next()
                    .map(|index| format!("catalog:model:{index}"));
            }
            MANUAL => {
                if selected.is_empty()
                    || yes(
                        terminal,
                        "Discard selected catalog models and enter them manually?",
                    )?
                {
                    return Ok(StepValue::Complete(None));
                }
            }
            FINISH => {
                if selected.is_empty() {
                    terminal.message("Select at least one model, or choose manual entry.")?;
                    continue;
                }
                return Ok(StepValue::Complete(Some(
                    selected
                        .iter()
                        .map(|index| catalog[*index].clone())
                        .collect(),
                )));
            }
            _ => {
                terminal.message("Choose a visible model or catalog action.")?;
            }
        }
    }
}

fn choose_catalog<T: SetupTerminal>(
    terminal: &mut T,
    catalog: &[DiscoveredModel],
) -> Result<StepValue<Option<Vec<DiscoveredModel>>>, OnboardingError> {
    if terminal.rich_choices_available() {
        return choose_catalog_rich(terminal, catalog);
    }
    const PAGE_SIZE: usize = 20;
    let mut filter = String::new();
    let mut page: usize = 0;
    loop {
        let filtered: Vec<_> = catalog
            .iter()
            .filter(|model| {
                filter.is_empty()
                    || model.id.to_lowercase().contains(&filter)
                    || model
                        .label
                        .as_ref()
                        .is_some_and(|label| label.to_lowercase().contains(&filter))
            })
            .collect();
        let pages = filtered.len().div_ceil(PAGE_SIZE).max(1);
        page = page.min(pages - 1);
        terminal.message(&format!(
            "Catalog page {}/{} ({} matching models)",
            page + 1,
            pages,
            filtered.len()
        ))?;
        for (index, model) in filtered
            .iter()
            .enumerate()
            .skip(page * PAGE_SIZE)
            .take(PAGE_SIZE)
        {
            terminal.message(&format!(
                "  {}. {}{}; context {}; output {}",
                index + 1,
                safe_display(&model.id),
                model
                    .label
                    .as_ref()
                    .map(|label| format!(" - {}", safe_display(label)))
                    .unwrap_or_default(),
                model
                    .context_window
                    .filter(|_| model.metadata_valid)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                model
                    .max_output_tokens
                    .filter(|_| model.metadata_valid)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ))?;
        }
        let choice = setup_field!(terminal, |terminal| answer(
            terminal,
            "Select model numbers (comma-separated), next, prev, filter TEXT, manual, or cancel",
            None,
            2048,
        ));
        match choice.as_str() {
            "next" => {
                page = (page + 1).min(pages - 1);
                continue;
            }
            "prev" => {
                page = page.saturating_sub(1);
                continue;
            }
            "filter" => {
                filter.clear();
                page = 0;
                continue;
            }
            "manual" => return Ok(StepValue::Complete(None)),
            "cancel" => return Err(OnboardingError::Canceled),
            _ => {}
        }
        if let Some(text) = choice.strip_prefix("filter ") {
            filter = text.to_lowercase();
            page = 0;
            continue;
        }
        let parsed = (|| {
            let mut seen = BTreeSet::new();
            let mut selected = Vec::new();
            for part in choice.split(',').map(str::trim) {
                let index = part
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| index.checked_sub(1))
                    .filter(|index| *index < filtered.len())
                    .ok_or(OnboardingError::Invalid("Select valid catalog numbers"))?;
                if !seen.insert(index) || selected.len() >= 128 {
                    return Err(OnboardingError::Invalid(
                        "Select 1..128 distinct catalog numbers",
                    ));
                }
                selected.push((*filtered[index]).clone());
            }
            Ok(selected)
        })();
        match parsed {
            Ok(selected) => return Ok(StepValue::Complete(Some(selected))),
            Err(OnboardingError::Invalid(message)) => match recover_field(terminal, message)? {
                FieldRecovery::Retry => {}
                FieldRecovery::Back => return Ok(StepValue::Back),
            },
            Err(error) => return Err(error),
        }
    }
}

fn fallback_after_error<T: SetupTerminal>(
    terminal: &mut T,
    error: OnboardingError,
) -> Result<StepValue<ModelSelection>, OnboardingError> {
    match error {
        OnboardingError::Canceled
        | OnboardingError::TerminalIo
        | OnboardingError::Stale
        | OnboardingError::PublicationUncertain
        | OnboardingError::Setup(_) => Err(error),
        OnboardingError::Credential(error) if error != ProviderCredentialError::Missing => {
            Err(OnboardingError::Credential(error))
        }
        _ => {
            terminal.message("Discovery unavailable. Enter raw model IDs manually; no provider configuration was saved.")?;
            manual_selection(terminal, "manual_fallback")
        }
    }
}

fn collect_models<T: SetupTerminal>(
    home: &Path,
    provider: &ProviderConfig,
    private_key: Option<&SecretBytes>,
    preset: &crate::presets::ProviderPreset,
    terminal: &mut T,
    discovery: &mut impl ModelDiscoveryFactory,
    source: &str,
) -> Result<StepValue<ModelSelection>, OnboardingError> {
    match source {
        "manual" => return manual_selection(terminal, "not_requested"),
        "discover" => {}
        _ => return Err(OnboardingError::Invalid("Choose manual or discover")),
    }
    let profile = setup_field!(terminal, |terminal| profile_for(
        &provider.kind,
        preset.id == "custom",
        preset.id,
        terminal
    ));
    let id = identity(provider)?;
    let mut session =
        match discovery.open(home, provider, profile, private_key.map(|key| (&id, key))) {
            Ok(session) => session,
            Err(error) => return fallback_after_error(terminal, error),
        };
    terminal.message(&format!("Fetching provider catalog using {:?} credentials. Completion connectivity remains untested.", session.credential_source()))?;
    let catalog = match session.catalog() {
        Ok(catalog) => catalog,
        Err(error) => return fallback_after_error(terminal, error),
    };
    let mut status = if catalog.completeness == DiscoveryCompleteness::Complete {
        "complete"
    } else {
        "incomplete"
    };
    terminal.message(&format!(
        "Catalog fetch: {status}; {} models; {} reported limitations.",
        catalog.models.len(),
        catalog.issues.len()
    ))?;
    if catalog.models.is_empty() {
        terminal.message("No selectable catalog entries. Use manual model IDs or cancel.")?;
        return manual_selection(terminal, "manual_fallback");
    }
    if catalog.completeness == DiscoveryCompleteness::Incomplete
        && !setup_field!(terminal, |terminal| yes(
            terminal,
            "Catalog is incomplete. Use partial results? (yes/no)",
        ))
    {
        return manual_selection(terminal, "manual_fallback");
    }
    let selected = match choose_catalog(terminal, &catalog.models)? {
        StepValue::Complete(Some(selected)) => selected,
        StepValue::Complete(None) => return manual_selection(terminal, "manual_fallback"),
        StepValue::Back => return Ok(StepValue::Back),
    };
    // The same session/deadline/credential serves every selected detail. This
    // includes all unknown Anthropic selections, not just the first one.
    let details = match session.details(&selected, false) {
        Ok(details) => details,
        Err(error) => return fallback_after_error(terminal, error),
    };
    if details.completeness == DiscoveryCompleteness::Incomplete {
        status = "incomplete";
        terminal.message("Selected metadata is incomplete. Unknown limits stay unknown; explicit existing limits are preserved.")?;
    }
    let (mut provenance, metadata_warning) = match load_model_provenance(home, provider) {
        Ok(records) => (records, false),
        Err(_) => {
            terminal.message(
                "Metadata history unavailable. Existing explicit limits will be preserved.",
            )?;
            (Vec::new(), true)
        }
    };
    let mut models = Vec::new();
    for observed in details.models {
        let current = provider
            .models
            .iter()
            .find(|model| model.id == observed.id)
            .cloned()
            .unwrap_or(ModelEntry {
                context_limits: None,
                id: observed.id.clone(),
                label: None,
                pricing: None,
                billing: None,
                max_output_tokens: None,
                context_window: None,
                sampling: None,
                supported_efforts: None,
                first_byte_timeout_ms: None,
                idle_timeout_ms: None,
                default_effort: None,
            });
        let previous = provenance
            .iter()
            .find(|record| record.model_id == observed.id);
        let merged = merge_discovered_model(&current, &observed, previous, &id);
        if let Some(record) = merged.provenance {
            provenance.retain(|old| old.model_id != record.model_id);
            provenance.push(record);
        }
        models.push(merged.model);
    }
    Ok(StepValue::Complete(ModelSelection {
        models,
        provenance: Some(provenance),
        catalog_status: status,
        metadata_warning,
    }))
}

const METADATA_WARNING: &str = "Provider saved. Optional metadata history is unavailable or uncertain; review model limits before refresh.";
fn publish_optional_metadata(
    home: &Path,
    provider: &ProviderConfig,
    provenance: Option<&[ModelProvenance]>,
    previous_warning: bool,
) -> (Option<bool>, Vec<&'static str>) {
    let saved = provenance.map(|records| save_model_provenance(home, provider, records).is_ok());
    let mut warnings = Vec::new();
    if previous_warning {
        warnings.push(
            "Previous metadata history unavailable; existing explicit limits were preserved.",
        );
    }
    if saved == Some(false) {
        warnings.push(METADATA_WARNING);
    }
    (saved, warnings)
}

/// An unpublished refresh candidate. Fetching never changes config, credentials,
/// routing, defaults or sidecar files; commit revalidates the whole revision.
pub struct ProviderRefreshDraft {
    home: PathBuf,
    provider: ProviderConfig,
    expected_provider: ProviderConfig,
    plan: SetupPlan,
    provenance: Vec<ModelProvenance>,
    catalog_status: &'static str,
    metadata_warning: bool,
    credential_source: ProviderCredentialSource,
    main: String,
}
impl ProviderRefreshDraft {
    pub fn provider(&self) -> &ProviderConfig {
        &self.provider
    }
    pub fn catalog_status(&self) -> &'static str {
        self.catalog_status
    }
}

/// Choose the declared adapter schema or retain an exact-bound previously
/// observed OpenRouter schema. Custom OpenAI catalogs otherwise remain generic.
pub fn prepare_provider_refresh_auto(
    home: &Path,
    provider_name: &str,
    schema: Option<DiscoveryProfile>,
) -> Result<ProviderRefreshDraft, OnboardingError> {
    let existing = config_snapshot(home)?;
    let provider = existing
        .provider
        .iter()
        .find(|provider| provider.name == provider_name)
        .ok_or(OnboardingError::Invalid("Unknown configured provider"))?;
    let profile = schema.unwrap_or_else(|| match provider.kind.as_str() {
        "anthropic" => DiscoveryProfile::Anthropic,
        "ollama" => DiscoveryProfile::Ollama,
        _ => {
            let official = provider.url.trim_end_matches('/') == "https://openrouter.ai/api/v1";
            let previous = load_model_provenance(home, provider).unwrap_or_default();
            if official
                || (!previous.is_empty()
                    && previous
                        .iter()
                        .all(|record| record.observed.source == MetadataSource::OpenRouterModels))
            {
                DiscoveryProfile::OpenRouter
            } else {
                DiscoveryProfile::GenericOpenAi
            }
        }
    });
    prepare_provider_refresh(home, provider_name, profile)
}

pub fn prepare_provider_refresh(
    home: &Path,
    provider_name: &str,
    profile: DiscoveryProfile,
) -> Result<ProviderRefreshDraft, OnboardingError> {
    prepare_provider_refresh_with_discovery(
        home,
        provider_name,
        profile,
        &mut ProviderDiscoveryFactory,
    )
}

pub fn prepare_provider_refresh_with_discovery(
    home: &Path,
    provider_name: &str,
    profile: DiscoveryProfile,
    discovery: &mut impl ModelDiscoveryFactory,
) -> Result<ProviderRefreshDraft, OnboardingError> {
    let home = std::path::absolute(home).map_err(crate::customization::io_error)?;
    let baseline = setup::plan_setup(&home, &SetupRequest::default())?;
    let existing = config_snapshot(&home)?;
    let mut provider = existing
        .provider
        .iter()
        .find(|provider| provider.name == provider_name)
        .cloned()
        .ok_or(OnboardingError::Invalid("Unknown configured provider"))?;
    let expected_provider = provider.clone();
    let id = identity(&provider)?;
    let mut session = discovery.open(&home, &provider, profile, None)?;
    let source = session.credential_source();
    let catalog = session.catalog()?;
    let source_kind = match profile {
        DiscoveryProfile::GenericOpenAi => MetadataSource::GenericOpenAiModels,
        DiscoveryProfile::OpenRouter => MetadataSource::OpenRouterModels,
        DiscoveryProfile::Anthropic => MetadataSource::AnthropicModels,
        DiscoveryProfile::Ollama => MetadataSource::OllamaTags,
    };
    let selected: Vec<_> = provider
        .models
        .iter()
        .map(|model| {
            catalog
                .models
                .iter()
                .find(|observed| observed.id == model.id)
                .cloned()
                .unwrap_or(DiscoveredModel {
                    id: model.id.clone(),
                    label: None,
                    context_window: None,
                    max_output_tokens: None,
                    source: source_kind,
                    metadata_valid: false,
                    unrecognized_fields: Vec::new(),
                    evidence: None,
                })
        })
        .collect();
    let details = session.details(&selected, true)?;
    let catalog_status = if catalog.completeness == DiscoveryCompleteness::Complete
        && details.completeness == DiscoveryCompleteness::Complete
    {
        "complete"
    } else {
        "incomplete"
    };
    let (mut provenance, metadata_warning) = match load_model_provenance(&home, &provider) {
        Ok(records) => (records, false),
        Err(_) => (Vec::new(), true),
    };
    for observed in details.models {
        let Some(current) = provider
            .models
            .iter_mut()
            .find(|model| model.id == observed.id)
        else {
            continue;
        };
        let merged = merge_discovered_model(
            current,
            &observed,
            provenance
                .iter()
                .find(|record| record.model_id == observed.id),
            &id,
        );
        *current = merged.model;
        if let Some(record) = merged.provenance {
            provenance.retain(|old| old.model_id != record.model_id);
            provenance.push(record);
        }
    }
    let request = SetupRequest {
        provider: Some(provider.clone()),
        ..Default::default()
    };
    let plan = setup::plan_setup(&home, &request)?;
    if baseline.revision != plan.revision {
        return Err(OnboardingError::Stale);
    }
    Ok(ProviderRefreshDraft {
        home,
        provider,
        expected_provider,
        plan,
        provenance,
        catalog_status,
        metadata_warning,
        credential_source: source,
        main: existing.roles.main,
    })
}

pub fn commit_provider_refresh(
    draft: ProviderRefreshDraft,
) -> Result<OnboardingReceipt, OnboardingError> {
    let existing = config_snapshot(&draft.home)?;
    if existing
        .provider
        .iter()
        .find(|provider| provider.name == draft.provider.name)
        != Some(&draft.expected_provider)
    {
        return Err(OnboardingError::Stale);
    }
    let current = setup::plan_setup(
        &draft.home,
        &SetupRequest {
            provider: Some(draft.provider.clone()),
            ..Default::default()
        },
    )?;
    if current.revision != draft.plan.revision {
        return Err(OnboardingError::Stale);
    }
    let setup = setup::apply_setup(&draft.plan)?;
    let (metadata_saved, warnings) = publish_optional_metadata(
        &draft.home,
        &draft.provider,
        Some(&draft.provenance),
        draft.metadata_warning,
    );
    Ok(OnboardingReceipt {
        setup,
        provider: draft.provider.name,
        models_configured: draft.provider.models.len(),
        main: (!draft.main.is_empty()).then_some(draft.main),
        credential_source: match draft.credential_source {
            ProviderCredentialSource::None => "no authentication",
            ProviderCredentialSource::Environment => "environment override",
            ProviderCredentialSource::Draft => "private key",
            ProviderCredentialSource::Saved => "saved private key",
        },
        credential_ready: true,
        connectivity: "not_tested",
        catalog_status: draft.catalog_status,
        metadata_saved,
        warnings,
        authentication_online: false,
    })
}

/// Production input is byte-bounded and temporarily noncanonical. Ctrl-C/EOF are
/// cancellation bytes, so normal cancellation runs destructors and restores echo.
pub struct StdSetupTerminal;

fn input_buffer(max: usize) -> Result<Zeroizing<Vec<u8>>, OnboardingError> {
    if max == 0 || max > 64 * 1024 {
        return Err(OnboardingError::Invalid("Input bound is invalid"));
    }
    // Vec growth frees its previous allocation without wiping it. Reserve the
    // complete accepted bound before collecting even the first secret byte.
    Ok(Zeroizing::new(Vec::with_capacity(max)))
}

fn erase_input_tail(bytes: &mut [u8], start: usize) {
    // Truncation alone leaves deleted secret bytes in the allocation.
    bytes[start..].zeroize();
}

impl StdSetupTerminal {
    pub fn new() -> Result<Self, OnboardingError> {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err(OnboardingError::TerminalRequired);
        }
        Ok(Self)
    }

    #[allow(unsafe_code)] // Choice input borrows stdin using the existing terminal guards.
    fn read_choice(
        &mut self,
        prompt: &str,
        choices: &[SetupChoice<'_>],
        current: Option<&str>,
        allow_back: bool,
    ) -> Result<Option<SetupSelection>, OnboardingError> {
        use crate::setup_terminal_ui::{self as ui, Key};
        validate_choices(choices, current)?;
        let dimensions = terminal_dimensions()?;
        if dimensions.0 < 24 || dimensions.1 < 8 {
            return Ok(None);
        }
        let _serial = TERMINAL_LOCK
            .lock()
            .map_err(|_| OnboardingError::TerminalIo)?;
        let signals = SignalGuard::new()?;
        let guard = EchoGuard::new(libc::STDIN_FILENO)?;
        let mut out = std::io::stdout().lock();
        let mut screen = ChoiceScreen::new(&mut out)?;
        let mut menu = ui::Menu::new(
            choices.len(),
            current.and_then(|id| choices.iter().position(|choice| choice.id == id)),
        );
        let mut typed = Vec::new();
        let mut escaped = Vec::new();
        let mut escape_started = None;
        let mut error = "";
        let mut redraw = true;
        let mut last_dimensions = None;
        let result = (|| {
            loop {
                if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(OnboardingError::Canceled);
                }
                let (columns, rows) = terminal_dimensions()?;
                if columns < 24 || rows < 8 {
                    return Ok(None);
                }
                let mut frame =
                    ui::frame(prompt, choices, &menu, &typed, columns, rows, allow_back);
                frame.lines[2] = ui::clip(error, columns.saturating_sub(1));
                if redraw || last_dimensions != Some((columns, rows)) {
                    out.write_all(b"\x1b[H\x1b[2J")
                        .map_err(|_| OnboardingError::TerminalIo)?;
                    for (index, line) in frame.lines.iter().enumerate() {
                        if index > 0 {
                            out.write_all(b"\r\n")
                                .map_err(|_| OnboardingError::TerminalIo)?;
                        }
                        let style: &[u8] = if index == 0 {
                            b"\x1b[1;35m"
                        } else if index == frame.selected_line {
                            b"\x1b[1;36m"
                        } else if index == 2 && !error.is_empty() {
                            b"\x1b[33m"
                        } else {
                            b"\x1b[0m"
                        };
                        out.write_all(style)
                            .and_then(|()| out.write_all(line.as_bytes()))
                            .and_then(|()| out.write_all(b"\x1b[0m"))
                            .map_err(|_| OnboardingError::TerminalIo)?;
                    }
                    out.flush().map_err(|_| OnboardingError::TerminalIo)?;
                    redraw = false;
                    last_dimensions = Some((columns, rows));
                }
                let mut ready = libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: ready is one initialized writable pollfd borrowed for this call.
                let polled =
                    unsafe { libc::poll(&mut ready, 1, if escaped.is_empty() { 100 } else { 30 }) };
                let event = if polled == 0 {
                    if escape_started.is_some_and(|at: std::time::Instant| {
                        at.elapsed() >= std::time::Duration::from_millis(90)
                    }) {
                        escaped.clear();
                        escape_started = None;
                        Key::Back
                    } else {
                        continue;
                    }
                } else {
                    if polled < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        return Err(OnboardingError::TerminalIo);
                    }
                    if ready.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                        return Err(OnboardingError::TerminalIo);
                    }
                    if ready.revents & libc::POLLIN == 0 {
                        if ready.revents & libc::POLLHUP != 0 {
                            return Err(OnboardingError::Canceled);
                        }
                        continue;
                    }
                    let mut byte = [0u8; 1];
                    // SAFETY: byte is an initialized, live writable one-byte buffer; stdin is borrowed.
                    let count =
                        unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
                    if count == 0 {
                        return Err(OnboardingError::Canceled);
                    }
                    if count < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        return Err(OnboardingError::TerminalIo);
                    }
                    if byte[0] == 27 && escaped.is_empty() {
                        escaped.push(27);
                        escape_started = Some(std::time::Instant::now());
                        continue;
                    }
                    if escaped.is_empty() {
                        ui::key(&byte).unwrap_or(Key::Ignore)
                    } else {
                        escaped.push(byte[0]);
                        match ui::key(&escaped) {
                            Some(event) => {
                                escaped.clear();
                                escape_started = None;
                                event
                            }
                            None => continue,
                        }
                    }
                };
                redraw = true;
                match event {
                    Key::Cancel => return Err(OnboardingError::Canceled),
                    Key::Back => {
                        return Ok(Some(if allow_back {
                            SetupSelection::Back
                        } else {
                            SetupSelection::Canceled
                        }));
                    }
                    Key::Up | Key::Down | Key::Home | Key::End | Key::PageUp | Key::PageDown => {
                        typed.clear();
                        error = "";
                        menu.navigate(event, frame.page);
                    }
                    Key::Erase => {
                        if !typed.is_empty() {
                            let mut start = typed.len() - 1;
                            while start > 0 && typed[start] & 0xc0 == 0x80 {
                                start -= 1;
                            }
                            typed.truncate(start);
                        }
                        error = "";
                    }
                    Key::Text(byte) => {
                        if typed.len() < ui::MAX_TYPED_BYTES {
                            typed.push(byte);
                            error = "";
                        } else {
                            error = "Choice exceeds its byte limit; erase or choose a row.";
                        }
                    }
                    Key::Enter => {
                        let selected = if typed.is_empty() && menu.armed {
                            Some(SetupSelection::Chosen(choices[menu.selected].id.to_owned()))
                        } else {
                            std::str::from_utf8(&typed).ok().and_then(|value| {
                                selected_answer(value, choices, current, allow_back)
                            })
                        };
                        if let Some(selected) = selected {
                            return Ok(Some(selected));
                        }
                        typed.clear();
                        error = "Choose an offered number, identity, or arrow-selected row.";
                    }
                    Key::Ignore => {}
                }
            }
        })();
        if result.is_err()
            || matches!(
                &result,
                Ok(Some(SetupSelection::Back | SetupSelection::Canceled))
            )
        {
            // SAFETY: tcflush operates only on the borrowed terminal fd and retains no pointer.
            unsafe {
                libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
            }
        }
        let screen_restored = screen.restore(&mut out);
        let restored = guard.restore();
        let signals_restored = signals.restore();
        restored?;
        signals_restored?;
        screen_restored?;
        if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(OnboardingError::Canceled);
        }
        result
    }

    fn read(
        &mut self,
        prompt: &str,
        max: usize,
        hidden: bool,
    ) -> Result<Zeroizing<Vec<u8>>, OnboardingError> {
        self.read_until(prompt, max, hidden, None)
    }

    // Only this terminal boundary and its restoration guards use Unix FFI.
    #[allow(unsafe_code)]
    fn read_until(
        &mut self,
        prompt: &str,
        max: usize,
        hidden: bool,
        deadline: Option<std::time::Instant>,
    ) -> Result<Zeroizing<Vec<u8>>, OnboardingError> {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(provider_login::LoginError::DeadlineExceeded.into());
        }
        let mut bytes = input_buffer(max)?;
        let _serial = TERMINAL_LOCK
            .lock()
            .map_err(|_| OnboardingError::TerminalIo)?;
        let signals = SignalGuard::new()?;
        let guard = EchoGuard::new(libc::STDIN_FILENO)?;
        // Enter hidden mode before publishing the prompt: a fast paste must not
        // race terminal echo while the caller is waiting for the key prompt.
        let mut out = std::io::stdout().lock();
        out.write_all(prompt.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|_| OnboardingError::TerminalIo)?;
        let result = loop {
            if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
                break Err(OnboardingError::Canceled);
            }
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                break Err(provider_login::LoginError::DeadlineExceeded.into());
            }
            // A short poll also observes a signal delivered just before read.
            let mut ready = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = deadline
                .map(|deadline| {
                    deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .as_millis()
                        .saturating_add(1)
                        .min(100) as libc::c_int
                })
                .unwrap_or(100);
            // SAFETY: ready is one live, writable pollfd for the whole call;
            // its descriptor is borrowed from process stdin, never closed here.
            let polled = unsafe { libc::poll(&mut ready, 1, timeout) };
            if polled == 0 {
                continue;
            }
            if polled < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break Err(OnboardingError::TerminalIo);
            }
            if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
                break Err(OnboardingError::Canceled);
            }
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                break Err(provider_login::LoginError::DeadlineExceeded.into());
            }
            if ready.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                break Err(OnboardingError::TerminalIo);
            }
            if ready.revents & libc::POLLIN == 0 {
                if ready.revents & libc::POLLHUP != 0 {
                    break Err(OnboardingError::Canceled);
                }
                continue;
            }
            let mut byte = Zeroizing::new([0u8; 1]);
            // SAFETY: the destination is a live writable one-byte array, its
            // exact size is passed, and read retains no pointer after returning.
            let count = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
            if count == 0 {
                break Err(OnboardingError::Canceled);
            }
            if count < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break Err(OnboardingError::TerminalIo);
            }
            match byte[0] {
                3 | 4 | 26 | 28 => break Err(OnboardingError::Canceled),
                b'\n' | b'\r' => break Ok(bytes),
                8 | 127 => {
                    if !bytes.is_empty() {
                        let mut start = bytes.len() - 1;
                        while start > 0 && bytes[start] & 0xc0 == 0x80 {
                            start -= 1;
                        }
                        erase_input_tail(&mut bytes, start);
                        bytes.truncate(start);
                        if !hidden && out.write_all(b"\x08 \x08").is_err() {
                            break Err(OnboardingError::TerminalIo);
                        }
                    }
                }
                0..=31 => {
                    break Err(OnboardingError::Invalid(
                        "Input contains a control character",
                    ));
                }
                _ => {
                    if bytes.len() >= max {
                        break Err(OnboardingError::Invalid("Input exceeds its byte limit"));
                    }
                    bytes.push(byte[0]);
                    if !hidden && out.write_all(&*byte).and_then(|()| out.flush()).is_err() {
                        break Err(OnboardingError::TerminalIo);
                    }
                }
            }
        };
        if result.is_err() {
            // SAFETY: tcflush only operates on the borrowed stdin descriptor;
            // it receives no memory pointers and cannot outlive this call.
            unsafe {
                libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
            }
        }
        // Explicit restoration lets a failed tcsetattr become an error as well.
        let restored = guard.restore();
        let signals_restored = signals.restore();
        out.write_all(b"\n")
            .and_then(|()| out.flush())
            .map_err(|_| OnboardingError::TerminalIo)?;
        restored?;
        signals_restored?;
        if CANCELED.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(OnboardingError::Canceled);
        }
        result
    }
}

impl SetupTerminal for StdSetupTerminal {
    fn rich_choices_available(&self) -> bool {
        std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").is_ok_and(|term| !term.is_empty() && term != "dumb")
    }

    fn select(
        &mut self,
        prompt: &str,
        choices: &[SetupChoice<'_>],
        current: Option<&str>,
        allow_back: bool,
    ) -> Result<SetupSelection, OnboardingError> {
        if self.rich_choices_available()
            && let Some(selected) = self.read_choice(prompt, choices, current, allow_back)?
        {
            return Ok(selected);
        }
        plain_select(self, prompt, choices, current, allow_back)
    }
    fn message(&mut self, message: &str) -> Result<(), OnboardingError> {
        let mut out = std::io::stdout().lock();
        out.write_all(message.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|_| OnboardingError::TerminalIo)
    }
    fn line(&mut self, prompt: &str, max: usize) -> Result<String, OnboardingError> {
        let bytes = self.read(prompt, max, false)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| OnboardingError::Invalid("Input must be UTF-8"))
    }
    fn hidden(&mut self, prompt: &str, max: usize) -> Result<SecretBytes, OnboardingError> {
        let mut bytes = self.read(prompt, max, true)?;
        std::str::from_utf8(&bytes)
            .map_err(|_| OnboardingError::Invalid("API key must be UTF-8"))?;
        Ok(SecretBytes::new(std::mem::take(&mut *bytes)))
    }
    fn hidden_until(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: std::time::Instant,
    ) -> Result<SecretBytes, OnboardingError> {
        let mut bytes = self.read_until(prompt, max, true, Some(deadline))?;
        std::str::from_utf8(&bytes)
            .map_err(|_| OnboardingError::Invalid("Hidden input must be UTF-8"))?;
        Ok(SecretBytes::new(std::mem::take(&mut *bytes)))
    }
}

struct ChoiceScreen {
    restored: bool,
}
impl ChoiceScreen {
    fn new(out: &mut impl Write) -> Result<Self, OnboardingError> {
        let screen = Self { restored: false };
        out.write_all(b"\x1b[?1049h\x1b[?25l")
            .and_then(|()| out.flush())
            .map_err(|_| OnboardingError::TerminalIo)?;
        Ok(screen)
    }
    fn restore(&mut self, out: &mut impl Write) -> Result<(), OnboardingError> {
        out.write_all(b"\x1b[?25h\x1b[0m\x1b[?1049l")
            .and_then(|()| out.flush())
            .map_err(|_| OnboardingError::TerminalIo)?;
        self.restored = true;
        Ok(())
    }
}
impl Drop for ChoiceScreen {
    fn drop(&mut self) {
        if !self.restored {
            let _ = std::io::stdout().write_all(b"\x1b[?25h\x1b[0m\x1b[?1049l");
        }
    }
}

#[allow(unsafe_code)] // A read-only terminal-size ioctl on borrowed stdout.
fn terminal_dimensions() -> Result<(usize, usize), OnboardingError> {
    // SAFETY: winsize is a zero-valid C aggregate used as an initialized writable output.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: size is live and correctly aligned for TIOCGWINSZ; the fd is borrowed.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } != 0 {
        return Err(OnboardingError::TerminalIo);
    }
    Ok((usize::from(size.ws_col), usize::from(size.ws_row)))
}

static TERMINAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static CANCELED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn cancel_signal(_signal: libc::c_int) {
    CANCELED.store(true, std::sync::atomic::Ordering::SeqCst);
}

struct SignalGuard {
    old: Vec<(libc::c_int, libc::sigaction)>,
}
#[allow(unsafe_code)] // Audited process-signal installation/restoration boundary.
impl SignalGuard {
    fn new() -> Result<Self, OnboardingError> {
        CANCELED.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut guard = Self { old: Vec::new() };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            // SAFETY: libc's sigaction is a C aggregate of zero-valid scalar,
            // pointer and signal-mask fields; sigemptyset initializes its mask.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: the initialized aggregate is writable for sigaction's
            // output, and is only retained after that call succeeds.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = cancel_signal as *const () as usize;
            // SAFETY: action.sa_mask is a live, correctly aligned sigset_t.
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
                return Err(OnboardingError::TerminalIo);
            }
            // SAFETY: both action pointers remain valid for this call. The
            // static C handler only sets a lock-free AtomicBool and never panics.
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                return Err(OnboardingError::TerminalIo);
            }
            guard.old.push((signal, old));
        }
        Ok(guard)
    }

    fn restore(mut self) -> Result<(), OnboardingError> {
        let mut failed = false;
        for index in (0..self.old.len()).rev() {
            let (signal, old) = &self.old[index];
            // SAFETY: old is the exact initialized action captured from this
            // signal; sigaction reads it only for this call, with no output.
            if unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()) } == 0 {
                self.old.remove(index);
            } else {
                failed = true;
            }
        }
        if failed {
            // Drop retries only the actions whose restoration failed.
            Err(OnboardingError::TerminalIo)
        } else {
            Ok(())
        }
    }
}
#[allow(unsafe_code)] // Last-resort restoration on every early-return path.
impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, old) in self.old.iter().rev() {
            // SAFETY: each initialized saved action belongs to its signal and
            // remains borrowed for the duration of this non-retaining call.
            unsafe {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
        }
    }
}

struct EchoGuard {
    fd: libc::c_int,
    original: libc::termios,
    restored: bool,
}
#[allow(unsafe_code)] // Audited terminal attribute installation/restoration.
impl EchoGuard {
    fn new(fd: libc::c_int) -> Result<Self, OnboardingError> {
        // SAFETY: termios is a zero-valid C aggregate used as a writable output
        // buffer; it is not inspected unless tcgetattr successfully fills it.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: original is a live, writable, aligned termios, fd is borrowed.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(OnboardingError::TerminalIo);
        }
        let mut edited = original;
        edited.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        edited.c_iflag &= !(libc::IXON | libc::IXOFF);
        edited.c_cc[libc::VMIN] = 1;
        edited.c_cc[libc::VTIME] = 0;
        let guard = Self {
            fd,
            original,
            restored: false,
        };
        // Even a failed installation gets a restoration attempt from Drop.
        apply_terminal_attributes(fd, &edited)?;
        Ok(guard)
    }
    fn restore(mut self) -> Result<(), OnboardingError> {
        apply_terminal_attributes(self.fd, &self.original)?;
        self.restored = true;
        Ok(())
    }
}
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if !self.restored {
            let _ = apply_terminal_attributes(self.fd, &self.original);
        }
    }
}

#[allow(unsafe_code)] // One borrowed terminal attribute syscall, retried on EINTR.
fn apply_terminal_attributes(
    fd: libc::c_int,
    attributes: &libc::termios,
) -> Result<(), OnboardingError> {
    loop {
        // SAFETY: attributes is an initialized termios with a live immutable
        // borrow for the entire call. tcsetattr retains no pointer or fd owner.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, attributes) } == 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(OnboardingError::TerminalIo);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erased_secret_tail_is_wiped_before_truncation() {
        let mut bytes = b"keep-erased-secret".to_vec();
        erase_input_tail(&mut bytes, 4);
        assert_eq!(&bytes[..4], b"keep");
        assert!(bytes[4..].iter().all(|byte| *byte == 0));
        bytes.truncate(4);
        assert_eq!(bytes, b"keep");
    }

    #[test]
    fn discovery_runtime_teardown_is_bounded_with_inflight_blocking_lookup() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        runtime.spawn_blocking(move || {
            started_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(2));
            let _ = done_tx.send(());
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let discovery = ScopedModelDiscovery {
            runtime: Some(runtime),
            session: None,
            cancel: CancelToken::new(),
        };
        let started = std::time::Instant::now();
        drop(discovery);
        let elapsed = started.elapsed();
        let _ = release_tx.send(());
        done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "discovery teardown waited for an unabortable blocking lookup: {elapsed:?}"
        );
    }

    #[test]
    fn hidden_input_buffer_keeps_one_allocation_through_full_validated_bound() {
        for max in [MAX_PROVIDER_KEY_BYTES, 33 * 1024] {
            let mut bytes = input_buffer(max).unwrap();
            let allocation = bytes.as_ptr();
            let capacity = bytes.capacity();
            assert!(capacity >= max);
            for _ in 0..max {
                bytes.push(b'x');
                assert_eq!(bytes.as_ptr(), allocation);
                assert_eq!(bytes.capacity(), capacity);
            }
        }
        assert!(input_buffer(0).is_err());
        assert!(input_buffer(64 * 1024 + 1).is_err());
    }

    #[test]
    fn safe_display_escapes_bidi_formatting_without_changing_stored_identity() {
        let raw = "provider\u{202e}model";
        let rendered = safe_display(raw);
        assert_eq!(rendered, "provider\\u{202e}model");
        assert!(!rendered.contains('\u{202e}'));
    }

    #[test]
    fn back_from_default_model_selector_returns_to_models_stage() {
        struct ScriptedTerminal {
            answers: std::collections::VecDeque<&'static str>,
        }

        impl SetupTerminal for ScriptedTerminal {
            fn message(&mut self, _message: &str) -> Result<(), OnboardingError> {
                Ok(())
            }

            fn line(
                &mut self,
                _prompt: &str,
                _max_bytes: usize,
            ) -> Result<String, OnboardingError> {
                self.answers
                    .pop_front()
                    .map(str::to_owned)
                    .ok_or(OnboardingError::Canceled)
            }

            fn hidden(
                &mut self,
                _prompt: &str,
                _max_bytes: usize,
            ) -> Result<SecretBytes, OnboardingError> {
                Ok(SecretBytes::new(Vec::new()))
            }
        }

        let provider: ProviderConfig = toml::from_str(
            r#"
name = "fixture"
url = "http://127.0.0.1:9/v1"
[[models]]
id = "family/raw"
"#,
        )
        .unwrap();
        let mut terminal = ScriptedTerminal {
            answers: std::collections::VecDeque::from(["yes", "back", "cancel"]),
        };

        let result = collect_default(&mut terminal, &provider, "").unwrap();

        assert!(matches!(result, StepValue::Back));
        assert_eq!(terminal.answers.front(), Some(&"cancel"));
    }
}

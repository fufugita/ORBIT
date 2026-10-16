//! One terminal provider draft, validated before private/config publication.
use crate::config::{ModelEntry, Pricing, ProviderConfig, ProvidersConfig};
use crate::customization::{Directory, Error as SetupError};
use crate::setup::{self, SetupPlan, SetupReceipt, SetupRequest};
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ExpectedRevision, MAX_PROVIDER_KEY_BYTES, ProviderAuthIdentity, ProviderCredentialError,
    ProviderCredentialSource, ProviderCredentialStore,
};
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
}

impl OnboardingError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Canceled => "ORBIT-E1104",
            Self::Stale => "ORBIT-E1103",
            Self::PublicationUncertain
            | Self::Credential(ProviderCredentialError::PublicationUncertain)
            | Self::Setup(SetupError::PublicationUncertain(_)) => "ORBIT-E1105",
            _ => "ORBIT-E1101",
        }
    }
}

/// Implementations must return Canceled on EOF, and must never echo hidden input.
pub trait SetupTerminal {
    fn message(&mut self, message: &str) -> Result<(), OnboardingError>;
    fn line(&mut self, prompt: &str, max_bytes: usize) -> Result<String, OnboardingError>;
    fn hidden(&mut self, prompt: &str, max_bytes: usize) -> Result<SecretBytes, OnboardingError>;
}

/// The draft has no serialization or Debug implementation, and owns any unpublished key.
pub struct OnboardingDraft {
    provider: ProviderConfig,
    main: Option<String>,
    home: PathBuf,
    plan: SetupPlan,
    expected_provider: Option<ProviderConfig>,
    expected_main: String,
    private_key: Option<SecretBytes>,
    confirmed: bool,
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
            id: id.to_owned(),
            label: None,
            pricing: Pricing::default(),
            max_output_tokens: None,
            context_window: None,
            sampling: None,
            supported_efforts: None,
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

/// Collecting or declining a draft does not create a home or contact a provider.
/// The manual model step is the extension boundary for catalog discovery.
pub fn collect_onboarding<T: SetupTerminal>(
    home: &Path,
    preset_id: Option<&str>,
    terminal: &mut T,
) -> Result<OnboardingDraft, OnboardingError> {
    // Lexical absolutization keeps supported relative --home paths without
    // canonicalizing or following a symlink. Store validation still rejects '..'.
    let absolute_home = std::path::absolute(home).map_err(crate::customization::io_error)?;
    let home = absolute_home.as_path();
    // Construction only validates the path; it does not create or read storage.
    let _ = ProviderCredentialStore::new(home)?;
    let baseline = setup::plan_setup(home, &SetupRequest::default())?;
    let existing = config_snapshot(home)?;
    terminal.message(
        "Provider setup. Type Ctrl-C to cancel. Manual model entry makes no provider request.",
    )?;
    let offered = crate::presets::presets();
    let selection = match preset_id {
        Some(id) => id.to_owned(),
        None => {
            for (index, preset) in offered.iter().enumerate() {
                terminal.message(&format!(
                    "  {}. {} - {}",
                    index + 1,
                    preset.id,
                    preset.blurb
                ))?;
            }
            answer(terminal, "Provider (name or number)", None, 128)?
        }
    };
    let preset = if let Ok(index) = selection.parse::<usize>() {
        index.checked_sub(1).and_then(|n| offered.get(n)).cloned()
    } else {
        crate::presets::preset_by_id(&selection)
    }
    .ok_or(OnboardingError::Invalid(
        "Choose an offered provider name or number",
    ))?;
    let custom = preset.id == "custom";
    let name = answer(
        terminal,
        "Provider name",
        (!custom).then_some(preset.id),
        128,
    )?;
    let expected_provider = existing.provider.iter().find(|p| p.name == name).cloned();
    if expected_provider.is_some()
        && !yes(
            terminal,
            "Replace this existing provider? Type yes to continue",
        )?
    {
        return Err(OnboardingError::Canceled);
    }
    let kind = if custom {
        answer(
            terminal,
            "Adapter kind (openai-compatible/anthropic/ollama)",
            Some("openai-compatible"),
            64,
        )?
    } else {
        preset.kind.to_owned()
    };
    let url = answer(terminal, "Base URL", (!custom).then_some(preset.url), 2048)?;
    let endpoint = crate::config::validate_provider_endpoint(&url).map_err(|_| {
        OnboardingError::Invalid(
            "Use an absolute HTTP(S) provider URL without credentials or a fragment",
        )
    })?;
    // Validate identity before reading any credential, including custom names/kinds.
    let _ = ProviderAuthIdentity::new(&name, &kind, endpoint.as_str(), None)?;
    if !["openai-compatible", "anthropic", "ollama"].contains(&kind.as_str()) {
        return Err(OnboardingError::Invalid(
            "Choose openai-compatible, anthropic or ollama",
        ));
    }
    let auth = answer(terminal, "Authentication (env/key/none)", None, 16)?;
    let (env, private_key) = match auth.as_str() {
        "env" => {
            let env_name = answer(
                terminal,
                "Credential ENV name",
                (!preset.env.is_empty()).then_some(preset.env),
                128,
            )?;
            let _ = ProviderAuthIdentity::new(&name, &kind, endpoint.as_str(), Some(&env_name))?;
            (Some(env_name), None)
        }
        "key" => {
            let reference = format!("ORBIT_AUTH_{}", ulid::Ulid::new());
            terminal.message(
                "The key is hidden and will be saved privately only after confirmation.",
            )?;
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
            (Some(reference), Some(key))
        }
        "none" if custom || kind == "ollama" => (None, None),
        "none" => {
            return Err(OnboardingError::Invalid(
                "No-auth is available for custom or local providers",
            ));
        }
        _ => return Err(OnboardingError::Invalid("Choose env, key or none")),
    };
    let mut provider = ProviderConfig {
        name,
        kind,
        url: endpoint.to_string(),
        env,
        models: Vec::new(),
    };
    let _ = identity(&provider)?;
    let source = answer(terminal, "Model source (manual)", Some("manual"), 16)?;
    if source != "manual" {
        return Err(OnboardingError::Invalid("Choose manual model entry"));
    }
    let selected = parse_manual_models(&answer(
        terminal,
        "Raw model IDs (comma-separated)",
        None,
        33 * 1024,
    )?)?;
    provider.models = expected_provider
        .as_ref()
        .map(|p| p.models.clone())
        .unwrap_or_default();
    for model in selected {
        if !provider.models.iter().any(|old| old.id == model.id) {
            provider.models.push(model);
        }
    }
    setup::validate_provider(&provider)?;
    let main = if yes(terminal, "Set main default? (yes/no)")? {
        let id = answer(terminal, "Main model ID", None, 256)?;
        if !provider.models.iter().any(|model| model.id == id) {
            return Err(OnboardingError::Invalid(
                "Main model must be among this provider's configured raw IDs",
            ));
        }
        let qualified = format!("{}/{}", provider.name, id);
        if !existing.roles.main.is_empty()
            && existing.roles.main != qualified
            && !yes(terminal, "Replace main default? Type yes to continue")?
        {
            return Err(OnboardingError::Canceled);
        }
        Some(qualified)
    } else {
        None
    };
    let request = SetupRequest {
        provider: Some(provider.clone()),
        ..Default::default()
    };
    let plan = setup::plan_setup_with_main(home, &request, main.as_deref())?;
    if plan.revision != baseline.revision {
        return Err(OnboardingError::Stale);
    }
    let mut draft = OnboardingDraft {
        provider,
        main,
        home: home.to_path_buf(),
        plan,
        expected_provider,
        expected_main: existing.roles.main,
        private_key,
        confirmed: false,
    };
    let (source, ready) = credential_status(&draft)?;
    terminal.message(&format!("Provider: {} ({})\nEndpoint: {}\nModels: {}\nMain default: {}\nCredential: {}{}\nConnectivity: not tested",
        draft.provider.name, draft.provider.kind, draft.provider.url, draft.provider.models.len(),
        draft.main.as_deref().unwrap_or(if draft.expected_main.is_empty() { "not set" } else { &draft.expected_main }),
        source, if ready { "" } else { " (missing; set the declared ENV before running)" },
    ))?;
    if !yes(terminal, "Save provider configuration? Type yes to confirm")? {
        return Err(OnboardingError::Canceled);
    }
    draft.confirmed = true;
    Ok(draft)
}

fn credential_status(draft: &OnboardingDraft) -> Result<(&'static str, bool), OnboardingError> {
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
            return Err(OnboardingError::PublicationUncertain);
        }
        Err(error) => {
            // apply_setup's publication contract classifies every error after
            // identity/config publication as PublicationUncertain. Only its
            // definite pre-publication errors authorize this exact-new-key cleanup.
            if let Some(saved) = saved
                && store
                    .remove(&id, ExpectedRevision::Exact(saved.revision))
                    .is_err()
            {
                return Err(OnboardingError::PublicationUncertain);
            }
            return Err(error.into());
        }
    };
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
    })
}

pub fn run_onboarding<T: SetupTerminal>(
    home: &Path,
    preset: Option<&str>,
    terminal: &mut T,
) -> Result<OnboardingReceipt, OnboardingError> {
    commit_onboarding(collect_onboarding(home, preset, terminal)?)
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

    // Only this terminal boundary and its restoration guards use Unix FFI.
    #[allow(unsafe_code)]
    fn read(
        &mut self,
        prompt: &str,
        max: usize,
        hidden: bool,
    ) -> Result<Zeroizing<Vec<u8>>, OnboardingError> {
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
            // A short poll also observes a signal delivered just before read.
            let mut ready = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: ready is one live, writable pollfd for the whole call;
            // its descriptor is borrowed from process stdin, never closed here.
            let polled = unsafe { libc::poll(&mut ready, 1, 100) };
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
}

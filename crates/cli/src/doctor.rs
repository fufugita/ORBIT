//! Bounded offline readiness. No check launches a program or contacts a provider.
use crate::customization::{Directory, Error, read_regular};
use crate::setup::{optional_file, validate_provider, verify_bounded_ledger, verify_identity};
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ProviderAuthIdentity, ProviderCredentialError, ProviderCredentialSource,
    ProviderCredentialStatus, ProviderCredentialStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ready,
    Missing,
    Invalid,
    Configured,
    Unavailable,
    NotTested,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub detail: String,
    pub required: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub ready: bool,
    pub checks: Vec<DoctorCheck>,
}
impl DoctorReport {
    fn new() -> Self {
        Self {
            schema_version: 1,
            ready: true,
            checks: Vec::new(),
        }
    }
    fn add(&mut self, id: &str, status: CheckStatus, detail: &str, required: bool) {
        if self.checks.len() >= 127 {
            if self.checks.len() == 127 {
                self.checks.push(DoctorCheck {
                    id: "limits".into(),
                    status: CheckStatus::Invalid,
                    detail: "Readiness checks truncated at 128".into(),
                    required: true,
                });
            }
            self.ready = false;
            return;
        }
        let mut detail =
            orbit_hud::display_safe(detail).unwrap_or_else(|_| "Diagnostic withheld".into());
        let mut end = detail.len().min(256);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
        if required && !matches!(status, CheckStatus::Ready | CheckStatus::Configured) {
            self.ready = false;
        }
        self.checks.push(DoctorCheck {
            id: id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .take(96)
                .collect(),
            status,
            detail,
            required,
        });
    }
}
/// PATH inspection accepts regular executable files only, without spawning them.
pub fn find_executable(command: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if command.is_empty() || command.len() > 256 || command.chars().any(char::is_control) {
        return None;
    }
    let check = |p: PathBuf| {
        let m = std::fs::symlink_metadata(&p).ok()?;
        if m.is_file() && !m.file_type().is_symlink() && m.permissions().mode() & 0o111 != 0 {
            Some(p)
        } else {
            None
        }
    };
    if command.contains('/') {
        return Path::new(command)
            .is_absolute()
            .then(|| PathBuf::from(command))
            .and_then(check);
    }
    std::env::split_paths(path?)
        .take(128)
        .filter(|p| p.is_absolute() && p.as_os_str().len() <= 256)
        .find_map(|p| check(p.join(command)))
}
fn inspect_integration(home: &Path, filename: &str, report: &mut DoctorReport) {
    let label = if filename == "mcp.json" { "mcp" } else { "lsp" };
    let bytes = match optional_file(home, filename, 128 * 1024) {
        Ok(Some(b)) => b,
        Ok(None) => {
            report.add(
                label,
                CheckStatus::Missing,
                "Optional configuration is absent",
                false,
            );
            return;
        }
        Err(_) => {
            report.add(
                label,
                CheckStatus::Invalid,
                "Configuration must be a bounded checked regular file",
                false,
            );
            return;
        }
    };
    inspect_integration_bytes(&bytes, label, report);
}
fn inspect_integration_bytes(bytes: &[u8], label: &str, report: &mut DoctorReport) {
    let path_env = std::env::var_os("PATH");
    if label == "mcp" {
        let config: orbit_mcp::McpConfig = match serde_json::from_slice(bytes) {
            Ok(c) => c,
            Err(_) => {
                report.add(label, CheckStatus::Invalid, "MCP JSON is invalid", false);
                return;
            }
        };
        if config.servers.len() > 64 {
            report.add(
                label,
                CheckStatus::Invalid,
                "MCP configuration exceeds 64 servers",
                false,
            );
            return;
        }
        for (index, server) in config.servers.values().enumerate() {
            let id = format!("mcp.{index}");
            if server.validate().is_err() {
                report.add(
                    &id,
                    CheckStatus::Invalid,
                    "MCP server declaration is invalid",
                    false,
                );
            } else if !server.enabled {
                report.add(
                    &id,
                    CheckStatus::Configured,
                    "Server is disabled; not launched",
                    false,
                );
            } else if server.transport != orbit_mcp::McpTransport::Stdio {
                report.add(
                    &id,
                    CheckStatus::Configured,
                    "Remote MCP endpoint is configured; connectivity not tested and no request sent",
                    false,
                );
            } else if find_executable(&server.command, path_env.as_deref()).is_none() {
                report.add(
                    &id,
                    CheckStatus::Unavailable,
                    "Configured executable is absent or not a regular executable; not launched",
                    false,
                );
            } else {
                report.add(
                    &id,
                    CheckStatus::NotTested,
                    "Configured executable exists; server handshake has not been tested",
                    false,
                );
            }
        }
        report.add(
            "mcp.configuration",
            CheckStatus::Configured,
            "Configuration inspected without server launch or handshake",
            false,
        );
        report.add(
            "mcp.connectivity",
            CheckStatus::NotTested,
            "No MCP server was contacted; connectivity and handshake were not tested",
            false,
        );
    } else {
        if bytes.len() > 64 * 1024 {
            report.add(
                label,
                CheckStatus::Invalid,
                "LSP configuration exceeds the runtime's 64 KiB limit",
                false,
            );
            return;
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            #[serde(default)]
            enabled: bool,
            #[serde(default)]
            servers: Vec<Server>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Server {
            name: String,
            command: String,
            #[serde(default)]
            args: Vec<String>,
            language_id: String,
            extensions: Vec<String>,
            workspace_root: PathBuf,
            #[serde(default = "timeout")]
            timeout_ms: u64,
        }
        fn timeout() -> u64 {
            5000
        }
        let config: Config = match std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| toml::from_str(s).ok())
        {
            Some(c) => c,
            None => {
                report.add(label, CheckStatus::Invalid, "LSP TOML is invalid", false);
                return;
            }
        };
        if config.servers.len() > 16 {
            report.add(
                label,
                CheckStatus::Invalid,
                "LSP configuration exceeds the runtime's 16-server limit",
                false,
            );
            return;
        }
        let identifier = |value: &str| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'+'))
        };
        let mut names = std::collections::BTreeSet::new();
        for (index, server) in config.servers.iter().enumerate() {
            let id = format!("lsp.{index}");
            let valid = identifier(&server.name)
                && identifier(&server.language_id)
                && names.insert(&server.name)
                && !server.extensions.is_empty()
                && server.extensions.len() <= 32
                && server
                    .extensions
                    .iter()
                    .all(|e| identifier(e) && !e.contains('.'))
                && server.args.len() <= 64
                && server.args.iter().map(String::len).sum::<usize>() <= 16 * 1024
                && server.args.iter().all(|s| !s.contains('\0'))
                && (100..=30000).contains(&server.timeout_ms)
                && server.workspace_root.as_os_str().len() <= 256;
            if !valid {
                report.add(
                    &id,
                    CheckStatus::Invalid,
                    "LSP server declaration is invalid",
                    false,
                );
            } else if !config.enabled {
                report.add(
                    &id,
                    CheckStatus::Configured,
                    "Diagnostics are disabled; not launched",
                    false,
                );
            } else if find_executable(&server.command, path_env.as_deref()).is_none() {
                report.add(
                    &id,
                    CheckStatus::Unavailable,
                    "Configured executable is absent or not a regular executable; not launched",
                    false,
                );
            } else {
                report.add(
                    &id,
                    CheckStatus::NotTested,
                    "Configured executable exists; diagnostics have not been requested",
                    false,
                );
            }
        }
        report.add(
            "lsp.configuration",
            CheckStatus::Configured,
            "Configuration inspected without language-server launch",
            false,
        );
    }
}
fn inspect_project(home: &Path, workspace: &Path, report: &mut DoctorReport) {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(workspace);
    report.add(
        "project.trust",
        CheckStatus::Configured,
        if trusted {
            "Folder trust already exists; unchanged"
        } else {
            "Folder is untrusted; project integrations are not activated or launched"
        },
        false,
    );
    if !trusted {
        return;
    }
    let root = match Directory::open(workspace, false) {
        Ok(r) => r,
        Err(_) => {
            report.add(
                "project",
                CheckStatus::Invalid,
                "Workspace path is unsafe",
                false,
            );
            return;
        }
    };
    let path = workspace.join(".orbit");
    if !path.exists() {
        return;
    }
    let project = match Directory::open(&path, false) {
        Ok(p) => p,
        Err(_) => {
            report.add(
                "project",
                CheckStatus::Invalid,
                "Project configuration directory is unsafe",
                false,
            );
            return;
        }
    };
    for (file, label) in [("mcp.json", "mcp"), ("lsp.toml", "lsp")] {
        let Ok(base) = project.io() else {
            report.add(
                "project",
                CheckStatus::Invalid,
                "Project configuration identity changed",
                false,
            );
            return;
        };
        let path = base.join(file);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                report.add(
                    &format!("project.{label}"),
                    CheckStatus::Invalid,
                    "Project configuration is unreadable",
                    false,
                );
                continue;
            }
            Ok(_) => {}
        }
        let bytes = match read_regular(&path, 128 * 1024, false) {
            Ok(b) => b,
            Err(_) => {
                report.add(
                    &format!("project.{label}"),
                    CheckStatus::Invalid,
                    "Project configuration is unsafe or exceeds its bound",
                    false,
                );
                continue;
            }
        };
        if label == "lsp" {
            let enabled = optional_file(home, "lsp.toml", 128 * 1024)
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|s| toml::from_str::<toml::Value>(&s).ok())
                .and_then(|v| v.get("enabled").and_then(toml::Value::as_bool))
                .unwrap_or(false);
            if !enabled {
                report.add("project.lsp",CheckStatus::Configured,"Project diagnostics configuration exists; user-level diagnostics are disabled or absent",false);
                continue;
            }
        }
        let mut temporary = DoctorReport::new();
        inspect_integration_bytes(&bytes, label, &mut temporary);
        for check in temporary.checks {
            report.add(
                &format!("project.{}", check.id),
                check.status,
                &check.detail,
                false,
            );
        }
    }
    if root.check().is_err() || project.check().is_err() {
        report.add(
            "project",
            CheckStatus::Invalid,
            "Project configuration identity changed",
            false,
        );
    }
}
fn inspect_mods(home: &Path, report: &mut DoctorReport) {
    match crate::mods::validation_status(home) {
        Ok(status) => report.add(
            "mods",
            if status.bundles == 0 { CheckStatus::Missing } else { CheckStatus::Configured },
            if status.bundles == 0 { "Optional instruction bundles are absent" } else { "Instruction bundles and enabled metadata are valid local data; no extension code was executed" },
            false,
        ),
        Err(_) => report.add(
            "mods", CheckStatus::Invalid,
            "Instruction bundle or enabled metadata is malformed or unsafe; existing bytes were preserved",
            false,
        ),
    }
}
/// Inspect a managed bundle manifest next to both binaries. No binary is executed.
pub fn browser_check(binary: &Path) -> DoctorCheck {
    let result = (|| -> Result<CheckStatus, Error> {
        let parent = binary
            .parent()
            .ok_or_else(|| Error::UnsafePath("browser parent missing".into()))?;
        let sibling = parent.join("orbit-web");
        if !sibling.exists() {
            return Ok(CheckStatus::Unavailable);
        }
        if find_executable(&sibling.to_string_lossy(), None).is_none() {
            return Ok(CheckStatus::Invalid);
        }
        let manifest = parent.join("manifest.json");
        if !manifest.exists() {
            return Ok(CheckStatus::NotTested);
        }
        let bytes = read_regular(&manifest, 128 * 1024, false)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Invalid("bundle manifest is invalid".into()))?;
        if value.get("schema_version").and_then(|v| v.as_u64()) != Some(1)
            || value.get("version").and_then(|v| v.as_str()) != Some(env!("CARGO_PKG_VERSION"))
            || value.get("target").and_then(|v| v.as_str()) != Some(native_target())
            || value.get("signature").and_then(|v| v.as_str()) != Some("absent")
        {
            return Ok(CheckStatus::Invalid);
        }
        // The distribution lane supplies the canonical components object.
        let Some(components) = value.get("components").and_then(|v| v.as_object()) else {
            return Ok(CheckStatus::NotTested);
        };
        for name in ["orbit", "orbit-web"] {
            let Some(component) = components.get(name) else {
                return Ok(CheckStatus::Invalid);
            };
            let bytes = read_regular(&parent.join(name), 256 * 1024 * 1024, false)?;
            if component.get("size").and_then(|v| v.as_u64()) != Some(bytes.len() as u64)
                || component.get("sha256").and_then(|v| v.as_str())
                    != Some(hex::encode(Sha256::digest(&bytes)).as_str())
            {
                return Ok(CheckStatus::Invalid);
            }
        }
        Ok(CheckStatus::Ready)
    })();
    let status = result.unwrap_or(CheckStatus::Invalid);
    DoctorCheck {
        id: "browser".into(),
        status,
        detail: match status {
            CheckStatus::Ready => "Managed CLI/browser bundle version and component hashes match",
            CheckStatus::Unavailable => "Browser sibling is absent",
            CheckStatus::NotTested => {
                "Browser sibling exists; matching managed bundle metadata is absent"
            }
            _ => "Browser bundle metadata or component identity is invalid",
        }
        .into(),
        required: false,
    }
}
pub fn native_target() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu"
    } else {
        "unverified-platform"
    }
}
fn provider_credential_status(
    home: &Path,
    provider: &crate::config::ProviderConfig,
) -> (CheckStatus, &'static str) {
    let selected = (|| {
        let endpoint = crate::config::validate_provider_endpoint(&provider.url)
            .map_err(|_| ProviderCredentialError::InvalidIdentity)?;
        let identity = ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            endpoint.as_str(),
            provider.env.as_deref(),
        )?;
        let home =
            std::path::absolute(home).map_err(|_| ProviderCredentialError::UnsafeDirectory)?;
        let store = ProviderCredentialStore::new(&home)?;
        Ok(store.status_read_only_with(&identity, |name| {
            Ok(std::env::var_os(name).map(|value| SecretBytes::new(value.into_encoded_bytes())))
        }))
    })();
    let status = selected.unwrap_or_else(ProviderCredentialStatus::Invalid);
    match status {
        ProviderCredentialStatus::NoAuth => (
            CheckStatus::Configured,
            "Credential source: no authentication; no credential lookup or provider request",
        ),
        ProviderCredentialStatus::Available {
            source: ProviderCredentialSource::Environment,
            ..
        } => (
            CheckStatus::Ready,
            "Credential source: environment override; key format valid, connectivity not tested",
        ),
        ProviderCredentialStatus::Available {
            source: ProviderCredentialSource::Saved,
            ..
        } => (
            CheckStatus::Ready,
            "Credential source: saved private key; exact binding verified, connectivity not tested",
        ),
        ProviderCredentialStatus::Missing => (
            CheckStatus::Missing,
            "Credential source missing; set the declared ENV or save a matching private key",
        ),
        ProviderCredentialStatus::Invalid(ProviderCredentialError::InvalidKey) => (
            CheckStatus::Invalid,
            "Credential value is invalid; check the declared ENV or saved key without displaying it",
        ),
        ProviderCredentialStatus::Invalid(ProviderCredentialError::EnvironmentUnavailable) => (
            CheckStatus::Invalid,
            "Credential environment is unavailable; no saved fallback or provider request was attempted",
        ),
        ProviderCredentialStatus::Invalid(ProviderCredentialError::Busy) => (
            CheckStatus::Unavailable,
            "Credential storage is busy; retry after the current operation, connectivity not tested",
        ),
        ProviderCredentialStatus::Invalid(_) => (
            CheckStatus::Invalid,
            "Credential storage or binding is invalid or unsafe; no files changed or provider request sent",
        ),
        ProviderCredentialStatus::Available { .. } => (
            CheckStatus::Invalid,
            "Credential source could not be verified; no provider request sent",
        ),
    }
}

pub fn doctor(home: &Path, workspace: &Path) -> DoctorReport {
    let mut report = DoctorReport::new();
    if !home.exists() {
        report.add(
            "home",
            CheckStatus::Missing,
            "Initialize a private ORBIT home with setup",
            true,
        );
        return report;
    }
    if Directory::open(home, true).is_err() {
        report.add(
            "home",
            CheckStatus::Invalid,
            "Home must be an owned private directory without symlinks",
            true,
        );
        return report;
    }
    report.add(
        "home",
        CheckStatus::Ready,
        "Private local home is readable",
        true,
    );
    let adapter_identity = orbit_engine::retry::adapter_identity_digest(
        &orbit_provider_http::openai::openai_identity(),
    );
    report.add(
        "retry.openai_adapter_identity",
        CheckStatus::Configured,
        &format!(
            "Current OpenAI-compatible adapter identity SHA256: {adapter_identity}; offline implementation digest"
        ),
        false,
    );
    match verify_identity(home) {
        Ok(_) => report.add(
            "identity",
            CheckStatus::Ready,
            "Signing key, signed trust manifest and PIB identity match",
            true,
        ),
        Err(_) => report.add(
            "identity",
            CheckStatus::Invalid,
            "Identity is missing, partial or cryptographically invalid; use setup repair --dry-run",
            true,
        ),
    }
    match verify_bounded_ledger(home) {
        Ok((n, _)) => report.add(
            "ledger",
            CheckStatus::Ready,
            &format!("Verified {n} bounded hash-chain records"),
            true,
        ),
        Err(_) => report.add(
            "ledger",
            CheckStatus::Invalid,
            "Ledger chain is missing, unsafe, truncated or invalid",
            true,
        ),
    }
    match optional_file(home, "providers.toml", 128 * 1024) {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| crate::config::ProvidersConfig::load_from_str(s).ok())
        {
            Some(config) => {
                report.add(
                    "providers",
                    if config.provider.is_empty() {
                        CheckStatus::Missing
                    } else {
                        CheckStatus::Configured
                    },
                    "Offline provider declarations; connectivity is not tested",
                    true,
                );
                let routing_valid = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|raw| crate::phase_routing::parse_settings(raw).ok())
                    .is_some_and(|settings| {
                        crate::phase_routing::validate_settings(&config, &settings).is_ok()
                    });
                let default_spec = if config.roles.main.is_empty() {
                    config.provider.iter().find_map(|provider| {
                        provider
                            .models
                            .first()
                            .map(|model| format!("{}/{}", provider.name, model.id))
                    })
                } else {
                    Some(config.roles.main.clone())
                };
                let default_config = default_spec
                    .as_deref()
                    .and_then(|spec| crate::phase_routing::resolve_model(&config, spec, None).ok())
                    .and_then(|model| model.turn_config(None).ok());
                match default_config {
                    Some(selected) => match crate::provider_policies::load_for_config(home, &selected) {
                        Ok(Some(binding)) => report.add(
                            "retry.policy",
                            CheckStatus::Configured,
                            &format!(
                                "Configured main/default only: total max_attempts={}; requires managed uncapped ordinary admission; smaller caller ceilings apply; final generation-refusal assumption; provider usage/billing unknown; connectivity untested",
                                binding.max_attempts()
                            ),
                            false,
                        ),
                        Ok(None) => report.add(
                            "retry.policy",
                            CheckStatus::NotTested,
                            "No usable optional retry declaration matches the configured main/default model; ordinary retries remain conservative; connectivity not tested",
                            false,
                        ),
                        Err(_) => report.add(
                            "retry.policy",
                            CheckStatus::Invalid,
                            "Provider retry policy is invalid or unsafe; no policy details shown or provider request sent",
                            true,
                        ),
                    },
                    None => report.add(
                        "retry.policy",
                        CheckStatus::Unavailable,
                        "Configured main/default model could not be resolved; optional retry policy was not checked",
                        false,
                    ),
                }
                for (index, provider) in config.provider.iter().enumerate().take(64) {
                    let id = format!("provider.{index}");
                    if validate_provider(provider).is_err() {
                        report.add(
                            &id,
                            CheckStatus::Invalid,
                            "Provider URL/model/ENV declaration is invalid",
                            true,
                        );
                        continue;
                    }
                    report.add(
                        &id,
                        CheckStatus::Configured,
                        "Explicit provider models and adapter are configured; no request sent",
                        true,
                    );
                    let (status, detail) = provider_credential_status(home, provider);
                    report.add(&format!("credential.{index}"), status, detail, true);
                }
                report.add("routing",if routing_valid{CheckStatus::Configured}else{CheckStatus::Invalid},"Exact roles, phase/difficulty targets and keyword bounds checked without dispatch",true);
            }
            None => report.add(
                "providers",
                CheckStatus::Invalid,
                "Provider configuration is malformed",
                true,
            ),
        },
        Ok(None) => report.add(
            "providers",
            CheckStatus::Missing,
            "No providers are configured; setup accepts manual models offline",
            true,
        ),
        Err(_) => report.add(
            "providers",
            CheckStatus::Invalid,
            "Provider configuration is unsafe or exceeds 128 KiB",
            true,
        ),
    }
    match crate::customization::load(home, workspace) {
        Ok(_) => report.add(
            "customization",
            CheckStatus::Ready,
            "Portable profile and legacy configuration validate",
            true,
        ),
        Err(_) => report.add(
            "customization",
            CheckStatus::Invalid,
            "Customization is invalid; no automatic reset or rewrite was performed",
            true,
        ),
    }
    inspect_integration(home, "mcp.json", &mut report);
    inspect_integration(home, "lsp.toml", &mut report);
    inspect_project(home, workspace, &mut report);
    let context =
        orbit_tools::ToolContext::new(home.to_path_buf(), "doctor".into(), workspace.to_path_buf());
    match crate::lsp::availability(home, &context) {
        Ok(Some(_)) => report.add(
            "lsp.activation",
            CheckStatus::Configured,
            "Effective trusted diagnostics configuration validates; no server was launched",
            false,
        ),
        Ok(None) => report.add(
            "lsp.activation",
            CheckStatus::NotTested,
            "Diagnostics are disabled or have no effective trusted server; no launch attempted",
            false,
        ),
        Err(_) => report.add(
            "lsp.activation",
            CheckStatus::Invalid,
            "Effective diagnostics configuration does not pass runtime validation",
            false,
        ),
    }
    inspect_mods(home, &mut report);
    use std::io::IsTerminal;
    report.add(
        "terminal",
        CheckStatus::Configured,
        if std::io::stdout().is_terminal() {
            "Terminal output is attached; fonts are controlled by the terminal host"
        } else {
            "Output is not a terminal; fonts are controlled by the terminal host"
        },
        false,
    );
    report.add(
        "color",
        CheckStatus::Configured,
        if std::env::var_os("NO_COLOR").is_some() {
            "NO_COLOR is present; color output is disabled"
        } else {
            "Terminal color capability is evaluated by the frontend"
        },
        false,
    );
    if let Ok(binary) = std::env::current_exe() {
        let browser = browser_check(&binary);
        report.add(
            &browser.id,
            browser.status,
            &browser.detail,
            browser.required,
        );
    }
    report.add(
        "provider.connectivity",
        CheckStatus::NotTested,
        "No provider request was sent; run the real-provider checklist explicitly",
        false,
    );
    report
}

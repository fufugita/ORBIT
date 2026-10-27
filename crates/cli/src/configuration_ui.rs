//! Terminal configuration over the checked provider and profile stores.
use crate::config::ProvidersConfig;
use crate::onboarding::{self, OnboardingError, SetupChoice, SetupSelection, SetupTerminal};
use crate::phase_routing::{self, RouteMutation};
use crate::tool_runtime::PermissionScope;
use orbit_engine::routing::Difficulty;
use orbit_frontend_protocol::customization::{CustomizationError, Profile, ProfileCommand};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error(transparent)]
    Terminal(OnboardingError),
    #[error("Configuration canceled. Previously confirmed changes are retained")]
    Canceled,
    #[error("Provider configuration could not be read or saved; inspect it before retrying")]
    Providers,
    #[error("Configuration changed during review; reload before choosing again")]
    Stale,
    #[error("Configuration is busy; leave the current edit and try again later")]
    Busy,
    #[error("Publication may have committed; inspect the saved configuration before retrying")]
    PublicationUncertain,
    #[error(transparent)]
    Appearance(#[from] CustomizationError),
    #[error("The terminal returned a choice that was not offered")]
    InvalidChoice,
}

impl ConfigurationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Terminal(error) => error.code(),
            Self::Canceled => "ORBIT-E1104",
            Self::Stale | Self::Busy | Self::Appearance(CustomizationError::Busy) => "ORBIT-E1103",
            Self::PublicationUncertain
            | Self::Appearance(CustomizationError::PublicationUncertain(_)) => "ORBIT-E1105",
            _ => "ORBIT-E1106",
        }
    }
}

impl From<OnboardingError> for ConfigurationError {
    fn from(error: OnboardingError) -> Self {
        match error {
            OnboardingError::Canceled => Self::Canceled,
            other => Self::Terminal(other),
        }
    }
}

struct ProviderSnapshot {
    raw: Option<String>,
    config: ProvidersConfig,
}

fn snapshot(home: &Path) -> Result<ProviderSnapshot, ConfigurationError> {
    let bytes = crate::setup::optional_file(home, "providers.toml", 128 * 1024)
        .map_err(ConfigurationError::Appearance)?;
    let raw = bytes
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| ConfigurationError::Providers)?;
    let config = ProvidersConfig::load_from_str(raw.as_deref().unwrap_or_default())
        .map_err(|_| ConfigurationError::Providers)?;
    phase_routing::validate_settings(&config, &config.phase_settings())
        .map_err(|_| ConfigurationError::Providers)?;
    Ok(ProviderSnapshot { raw, config })
}

fn safe(value: &str) -> String {
    let scanned = crate::daemon::scan_display(value);
    crate::setup_terminal_ui::safe(&scanned)
}

fn automatic(value: &str) -> String {
    if value.is_empty() {
        "Automatic / inherited".into()
    } else {
        safe(value)
    }
}

fn appearance_values(profile: &Profile) -> Value {
    json!({
        "theme": profile.theme,
        "layout": profile.layout.preset,
        "density": profile.density,
        "glyphs": profile.glyphs,
        "color_mode": profile.color_mode,
        "reduced_motion": profile.reduced_motion,
        "browser_font_family": if profile.browser.font_family == "monospace" {
            "Default (value hidden)"
        } else {
            "Custom (value hidden)"
        },
        "browser_font_size_px": profile.browser.font_size_px,
        "terminal_font": "Controlled by your terminal application"
    })
}

/// Read only nonsecret settings. This does not discover models or start integrations.
pub fn show(home: &Path, workspace: &Path) -> Result<Value, ConfigurationError> {
    let saved = snapshot(home)?;
    let profile =
        crate::customization_host::host(home, workspace, PermissionScope::default(), false)
            .load()?;
    let providers: Vec<Value> = saved.config.provider.iter().map(|provider| json!({
        "name": provider.name,
        "kind": provider.kind,
        "models": provider.models.iter().map(|model| model.id.clone()).collect::<Vec<_>>(),
        "authentication": if provider.env.is_some() { "credential reference configured" } else { "no credential reference" }
    })).collect();
    Ok(crate::display_safe_json(json!({
        "schema": "orbit.cli/v1",
        "command": "config",
        "status": "ok",
        "interactive": false,
        "providers": providers,
        "models_configured": !saved.config.all_models().is_empty(),
        "roles": saved.config.roles,
        "routing": {
            "easy": saved.config.routing.easy,
            "hard": saved.config.routing.hard,
            "phase_overrides": saved.config.routing.phases.len(),
            "scope": "Fallback targets; phase-specific settings take precedence"
        },
        "appearance": appearance_values(&profile.profile),
        "connectivity": "not_tested"
    })))
}

pub fn human_report(value: &Value) -> String {
    let mut out = String::from("ORBIT configuration\n\n");
    let models = value
        .get("models_configured")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    out.push_str(if models {
        "Providers and models are configured. Connectivity is not tested.\n"
    } else {
        "Add a provider to choose models and enable phase routing.\n"
    });
    for (key, title) in [
        ("main", "Main model"),
        ("subagent", "Subagents"),
        ("explore", "Explore"),
        ("compaction", "Compaction"),
    ] {
        let current = value
            .get("roles")
            .and_then(|v| v.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default();
        out.push_str(&format!("  {title}: {}\n", automatic(current)));
    }
    for key in ["easy", "hard"] {
        let current = value
            .get("routing")
            .and_then(|v| v.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default();
        out.push_str(&format!("  {key} fallback: {}\n", automatic(current)));
    }
    out.push_str("  Phase-specific routes and explicit session models take precedence.\n");
    for (key, title) in [
        ("theme", "Theme"),
        ("layout", "Layout"),
        ("density", "Density"),
        ("glyphs", "Glyphs"),
        ("color_mode", "Colors"),
        ("browser_font_family", "Browser font"),
        ("browser_font_size_px", "Browser font size (px)"),
    ] {
        let appearance = value.get("appearance").and_then(|v| v.get(key));
        let current = appearance
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| appearance.filter(|v| v.is_number()).map(Value::to_string))
            .unwrap_or_else(|| "unknown".into());
        out.push_str(&format!("  {title}: {}\n", safe(&current)));
    }
    out.push_str(
        "\nRun orbit config in a terminal to edit. Each confirmed edit is saved separately.\n",
    );
    out
}

fn selected<T: SetupTerminal>(
    terminal: &mut T,
    prompt: &str,
    choices: &[SetupChoice<'_>],
    current: Option<&str>,
) -> Result<Option<String>, ConfigurationError> {
    match selection(terminal, prompt, choices, current)? {
        SetupSelection::Chosen(id) => Ok(Some(id)),
        SetupSelection::Back | SetupSelection::Canceled => Ok(None),
    }
}

fn selection<T: SetupTerminal>(
    terminal: &mut T,
    prompt: &str,
    choices: &[SetupChoice<'_>],
    current: Option<&str>,
) -> Result<SetupSelection, ConfigurationError> {
    let selected = terminal.select(prompt, choices, current, true)?;
    if matches!(&selected, SetupSelection::Chosen(id) if !choices.iter().any(|choice| choice.id == id.as_str()))
    {
        return Err(ConfigurationError::InvalidChoice);
    }
    Ok(selected)
}

fn confirm<T: SetupTerminal>(terminal: &mut T, review: &str) -> Result<bool, ConfigurationError> {
    terminal.message(review)?;
    let value = terminal.line("Save this change? Type yes to confirm: ", 16)?;
    Ok(value == "yes")
}

fn correction_action<T: SetupTerminal>(
    terminal: &mut T,
    message: &str,
) -> Result<SetupSelection, ConfigurationError> {
    terminal.message(message)?;
    let choices = [
        SetupChoice {
            id: "retry",
            label: "Try again",
            detail: None,
        },
        SetupChoice {
            id: "back",
            label: "Back to appearance settings",
            detail: None,
        },
    ];
    selection(
        terminal,
        "Invalid appearance value",
        &choices,
        Some("retry"),
    )
}

fn handle_edit<T: SetupTerminal>(
    terminal: &mut T,
    error: ConfigurationError,
) -> Result<(), ConfigurationError> {
    if matches!(
        error,
        ConfigurationError::Stale
            | ConfigurationError::Busy
            | ConfigurationError::Appearance(CustomizationError::Busy)
    ) {
        terminal.message("Settings changed or are busy. This edit was not retried. Choose again to review current settings.")?;
        Ok(())
    } else {
        Err(error)
    }
}

/// Open the local hub. Leaving it preserves every previously confirmed edit.
pub fn run<T: SetupTerminal>(
    home: &Path,
    workspace: &Path,
    terminal: &mut T,
) -> Result<Value, ConfigurationError> {
    terminal.message("ORBIT / Configuration\nChanges apply to new sessions. Each edit is saved only after confirmation.")?;
    let mut changes = 0usize;
    loop {
        let view = show(home, workspace)?;
        let models = view["models_configured"].as_bool().unwrap_or(false);
        let defaults = format!(
            "Main: {}",
            automatic(view["roles"]["main"].as_str().unwrap_or_default())
        );
        let appearance = format!(
            "{} / {}",
            view["appearance"]["theme"].as_str().unwrap_or("unknown"),
            view["appearance"]["layout"].as_str().unwrap_or("unknown")
        );
        let choices = [
            SetupChoice {
                id: "defaults",
                label: "Models and roles",
                detail: Some(&defaults),
            },
            SetupChoice {
                id: "routing",
                label: "Phase routing",
                detail: Some("Easy and hard fallbacks; phase overrides are preserved"),
            },
            SetupChoice {
                id: "appearance",
                label: "Appearance and layout",
                detail: Some(&appearance),
            },
            SetupChoice {
                id: "provider",
                label: "Add or replace a provider",
                detail: Some("API key, ENV, custom endpoint or supported browser sign-in"),
            },
            SetupChoice {
                id: "done",
                label: "Done",
                detail: Some("Keep confirmed changes and return to your terminal"),
            },
        ];
        let action = selected(terminal, "Configuration", &choices, Some("defaults"))?;
        let result = match action.as_deref() {
            None | Some("done") => break,
            Some("defaults" | "routing") if !models => {
                terminal.message("No models are configured. Choose Add or replace a provider first; no settings were changed.")?;
                continue;
            }
            Some("defaults") => edit_defaults(home, terminal),
            Some("routing") => edit_routing(home, terminal),
            Some("appearance") => edit_appearance(home, workspace, terminal),
            Some("provider") => match onboarding::run_onboarding(home, None, terminal) {
                Ok(_) => Ok(true),
                Err(OnboardingError::Canceled) => {
                    terminal.message(
                        "Provider setup canceled. Previously confirmed changes are retained.",
                    )?;
                    Ok(false)
                }
                Err(error) => Err(error.into()),
            },
            _ => return Err(ConfigurationError::InvalidChoice),
        };
        match result {
            Ok(true) => {
                changes += 1;
                terminal.message("Saved. New sessions will use this setting; existing explicit model selections are preserved.")?;
            }
            Ok(false) => {}
            Err(error) => handle_edit(terminal, error)?,
        }
    }
    let mut view = show(home, workspace)?;
    view["interactive"] = json!(true);
    view["changes_saved"] = json!(changes);
    Ok(view)
}

fn choose_model<T: SetupTerminal>(
    terminal: &mut T,
    saved: &ProviderSnapshot,
    current: &str,
    automatic_label: &str,
) -> Result<SetupSelection, ConfigurationError> {
    let identities: Vec<String> = saved
        .config
        .all_models()
        .into_iter()
        .map(|(provider, model)| format!("{provider}/{model}"))
        .collect();
    let resolved = if current.is_empty() {
        None
    } else {
        Some(
            phase_routing::resolve_model(&saved.config, current, None)
                .map_err(|_| ConfigurationError::Providers)?,
        )
    };
    let current = resolved
        .as_ref()
        .map_or_else(|| "inherit".into(), |model| model.qualified());
    let labels: Vec<String> = identities.iter().map(|id| safe(id)).collect();
    let flat_choices = identity_choices(&identities, &labels, automatic_label);
    let text_bytes = flat_choices.iter().fold(0usize, |used, choice| {
        used.saturating_add(choice.id.len())
            .saturating_add(choice.label.len())
            .saturating_add(choice.detail.map_or(0, str::len))
    });
    if flat_choices.len() <= crate::setup_terminal_ui::MAX_CHOICES
        && text_bytes <= crate::setup_terminal_ui::MAX_MENU_TEXT_BYTES
    {
        return choose_identity(terminal, &flat_choices, &current);
    }
    // A valid bounded document can exceed one menu's count or text budget.
    // Group those declarations without truncating any provider or raw model ID.
    let providers: Vec<_> = saved
        .config
        .provider
        .iter()
        .filter(|provider| !provider.models.is_empty())
        .collect();
    let provider_ids: Vec<String> = providers
        .iter()
        .map(|provider| format!("provider:{}", provider.name))
        .collect();
    let labels: Vec<String> = providers
        .iter()
        .map(|provider| safe(&provider.name))
        .collect();
    let mut choices = vec![SetupChoice {
        id: "inherit",
        label: automatic_label,
        detail: None,
    }];
    choices.extend(
        provider_ids
            .iter()
            .zip(&labels)
            .map(|(id, label)| SetupChoice {
                id,
                label,
                detail: None,
            }),
    );
    let highlighted = resolved.as_ref().map_or_else(
        || "inherit".into(),
        |model| format!("provider:{}", model.provider_id),
    );
    loop {
        let group = match selection(terminal, "Choose a provider", &choices, Some(&highlighted))? {
            SetupSelection::Chosen(id) if id == "inherit" => {
                return Ok(SetupSelection::Chosen(String::new()));
            }
            SetupSelection::Chosen(id) => id,
            other => return Ok(other),
        };
        let index = provider_ids
            .iter()
            .position(|id| *id == group)
            .ok_or(ConfigurationError::InvalidChoice)?;
        let provider = providers[index];
        let identities = provider
            .models
            .iter()
            .map(|model| format!("{}/{}", provider.name, model.id))
            .collect::<Vec<_>>();
        let labels = identities.iter().map(|id| safe(id)).collect::<Vec<_>>();
        let choices = identity_choices(&identities, &labels, automatic_label);
        match choose_identity(terminal, &choices, &current)? {
            SetupSelection::Back => continue,
            other => return Ok(other),
        }
    }
}

fn identity_choices<'a>(
    identities: &'a [String],
    labels: &'a [String],
    automatic_label: &'a str,
) -> Vec<SetupChoice<'a>> {
    let mut choices = vec![SetupChoice {
        id: "inherit",
        label: automatic_label,
        detail: None,
    }];
    choices.extend(
        identities
            .iter()
            .zip(labels)
            .map(|(id, label)| SetupChoice {
                id,
                label,
                detail: None,
            }),
    );
    choices
}

fn choose_identity<T: SetupTerminal>(
    terminal: &mut T,
    choices: &[SetupChoice<'_>],
    current: &str,
) -> Result<SetupSelection, ConfigurationError> {
    let highlight = choices
        .iter()
        .any(|choice| choice.id == current)
        .then_some(current);
    selection(terminal, "Choose a model", choices, highlight).map(|result| match result {
        SetupSelection::Chosen(id) if id == "inherit" => SetupSelection::Chosen(String::new()),
        other => other,
    })
}

fn writable_snapshot(home: &Path) -> Result<ProviderSnapshot, ConfigurationError> {
    let saved = snapshot(home)?;
    if saved.raw.as_ref().is_none_or(String::is_empty) || saved.config.all_models().is_empty() {
        return Err(ConfigurationError::Stale);
    }
    Ok(saved)
}

fn same_selection(
    saved: &ProviderSnapshot,
    old: &str,
    chosen: &str,
) -> Result<bool, ConfigurationError> {
    if old.is_empty() {
        return Ok(chosen.is_empty());
    }
    Ok(phase_routing::resolve_model(&saved.config, old, None)
        .map_err(|_| ConfigurationError::Providers)?
        .qualified()
        == chosen)
}

fn commit_provider_edit(
    saved: &ProviderSnapshot,
    home: &Path,
    candidate: impl FnOnce(&str, &ProvidersConfig) -> Result<String, String>,
) -> Result<(), ConfigurationError> {
    let expected = saved
        .raw
        .as_deref()
        .filter(|raw| !raw.is_empty())
        .ok_or(ConfigurationError::Stale)?;
    let mut stale = false;
    let result = ProvidersConfig::update_atomic(home, |raw| {
        if raw != expected {
            stale = true;
            return Err("configuration review is stale".into());
        }
        let current = ProvidersConfig::load_from_str(raw)?;
        candidate(raw, &current)
    });
    match result {
        Ok(_) => Ok(()),
        Err(_) if stale => Err(ConfigurationError::Stale),
        Err(error) if error.contains("publication uncertain") => {
            Err(ConfigurationError::PublicationUncertain)
        }
        Err(error) if error.contains("busy") => Err(ConfigurationError::Busy),
        Err(_) => Err(ConfigurationError::Providers),
    }
}

fn edit_defaults<T: SetupTerminal>(
    home: &Path,
    terminal: &mut T,
) -> Result<bool, ConfigurationError> {
    let saved = writable_snapshot(home)?;
    loop {
        let labels: Vec<String> = ["main", "subagent", "explore", "compaction"]
            .iter()
            .map(|role| {
                format!(
                    "{role}: {}",
                    automatic(saved.config.roles.get(role).unwrap_or_default())
                )
            })
            .collect();
        let roles = ["main", "subagent", "explore", "compaction"];
        let choices: Vec<SetupChoice<'_>> = roles
            .iter()
            .zip(&labels)
            .map(|(id, label)| SetupChoice {
                id,
                label,
                detail: None,
            })
            .collect();
        let Some(role) = selected(terminal, "Models and roles", &choices, Some("main"))? else {
            return Ok(false);
        };
        let old = saved.config.roles.get(&role).unwrap_or_default();
        let inherit = if role == "main" {
            "Automatic: use the first configured model"
        } else {
            "Inherit the selected session model"
        };
        let model = match choose_model(terminal, &saved, old, inherit)? {
            SetupSelection::Chosen(model) => model,
            SetupSelection::Back => continue,
            SetupSelection::Canceled => return Ok(false),
        };
        if same_selection(&saved, old, &model)? {
            terminal.message("This setting is already selected; nothing changed.")?;
            return Ok(false);
        }
        if !confirm(
            terminal,
            &format!(
                "{}: {}\nApplies to new work; explicit session models stay pinned.",
                safe(&role),
                automatic(&model)
            ),
        )? {
            return Ok(false);
        }
        commit_provider_edit(&saved, home, |raw, current| {
            if !model.is_empty() {
                phase_routing::resolve_model(current, &model, None)?;
            }
            let mut document: toml::Value =
                toml::from_str(raw).map_err(|_| "invalid provider configuration")?;
            let table = document
                .as_table_mut()
                .ok_or("provider configuration must be a table")?
                .entry("roles")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .ok_or("roles must be a table")?;
            table.insert(role, toml::Value::String(model));
            phase_routing::encode_candidate_section(raw, &document, "roles")
        })?;
        return Ok(true);
    }
}

fn edit_routing<T: SetupTerminal>(
    home: &Path,
    terminal: &mut T,
) -> Result<bool, ConfigurationError> {
    let saved = writable_snapshot(home)?;
    loop {
        let easy = automatic(&saved.config.routing.easy);
        let hard = automatic(&saved.config.routing.hard);
        let choices = [
            SetupChoice {
                id: "easy",
                label: "Easy fallback",
                detail: Some(&easy),
            },
            SetupChoice {
                id: "hard",
                label: "Hard fallback",
                detail: Some(&hard),
            },
        ];
        terminal.message("Fallbacks apply only when a phase-specific target does not override them. Existing custom phase routes are preserved.")?;
        let Some(tier) = selected(terminal, "Phase routing", &choices, Some("easy"))? else {
            return Ok(false);
        };
        let old = if tier == "easy" {
            &saved.config.routing.easy
        } else {
            &saved.config.routing.hard
        };
        let model = match choose_model(
            terminal,
            &saved,
            old,
            "Keep the session model when no phase override applies",
        )? {
            SetupSelection::Chosen(model) => model,
            SetupSelection::Back => continue,
            SetupSelection::Canceled => return Ok(false),
        };
        if same_selection(&saved, old, &model)? {
            terminal.message("This fallback is already selected; nothing changed.")?;
            return Ok(false);
        }
        if !confirm(
            terminal,
            &format!(
                "{} fallback: {}\nPhase overrides and explicit session models are preserved.",
                safe(&tier),
                automatic(&model)
            ),
        )? {
            return Ok(false);
        }
        commit_provider_edit(&saved, home, |raw, current| {
            if !model.is_empty() {
                phase_routing::resolve_model(current, &model, None)?;
            }
            phase_routing::config_candidate(
                raw,
                RouteMutation::LegacyTarget {
                    difficulty: if tier == "easy" {
                        Difficulty::Easy
                    } else {
                        Difficulty::Hard
                    },
                    model,
                },
            )
        })?;
        return Ok(true);
    }
}

fn profile_value(profile: &Profile, key: &str) -> String {
    match key {
        "browser.font_family" => return profile.browser.font_family.clone(),
        "browser.font_size_px" => return profile.browser.font_size_px.to_string(),
        _ => {}
    }
    let values = appearance_values(profile);
    values
        .get(if key == "layout.preset" {
            "layout"
        } else {
            key
        })
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string())
        })
        .unwrap_or_default()
}

fn edit_appearance<T: SetupTerminal>(
    home: &Path,
    workspace: &Path,
    terminal: &mut T,
) -> Result<bool, ConfigurationError> {
    let host = crate::customization_host::host(home, workspace, PermissionScope::default(), false);
    let reviewed = host.load()?;
    'appearance: loop {
        let fields = [
            ("theme", "Theme"),
            ("layout.preset", "Layout"),
            ("density", "Density"),
            ("glyphs", "Glyphs"),
            ("color_mode", "Color mode"),
            ("reduced_motion", "Reduced motion"),
            ("browser.font_family", "Browser font family"),
            ("browser.font_size_px", "Browser font size (px)"),
        ];
        let details: Vec<String> = fields
            .iter()
            .map(|(key, _)| safe(&profile_value(&reviewed.profile, key)))
            .collect();
        let choices: Vec<SetupChoice<'_>> = fields
            .iter()
            .zip(&details)
            .map(|((id, label), detail)| SetupChoice {
                id,
                label,
                detail: Some(detail),
            })
            .collect();
        let Some(key) = selected(terminal, "Appearance and layout", &choices, Some("theme"))?
        else {
            return Ok(false);
        };
        let current = profile_value(&reviewed.profile, &key);
        let value = match key.as_str() {
            "browser.font_family" => {
                let options = ["monospace", "system-ui", "sans-serif", "serif", "custom"];
                let choices: Vec<SetupChoice<'_>> = options
                    .iter()
                    .map(|id| SetupChoice {
                        id,
                        label: id,
                        detail: None,
                    })
                    .collect();
                let highlight = options
                    .contains(&current.as_str())
                    .then_some(current.as_str());
                match selection(terminal, "Choose browser font family", &choices, highlight)? {
                    SetupSelection::Chosen(value) if value == "custom" => loop {
                        let value = match terminal.line(
                            "Font families (comma-separated; letters, numbers, spaces, _ or -): ",
                            128,
                        ) {
                            Ok(value) => value.trim().to_owned(),
                            Err(OnboardingError::Invalid("Input exceeds its byte limit")) => {
                                match correction_action(
                                    terminal,
                                    "Font family is too long. Use up to 128 bytes, or return to appearance settings.",
                                )? {
                                    SetupSelection::Chosen(action) if action == "retry" => continue,
                                    SetupSelection::Chosen(_) | SetupSelection::Back => {
                                        continue 'appearance;
                                    }
                                    SetupSelection::Canceled => return Ok(false),
                                }
                            }
                            Err(error) => return Err(error.into()),
                        };
                        let mut candidate = reviewed.profile.clone();
                        candidate.browser.font_family = value.clone();
                        if candidate.validate().is_ok() {
                            break value;
                        }
                        match correction_action(
                            terminal,
                            "Use 1–8 comma-separated font names with letters, numbers, spaces, _ or -, up to 128 bytes.",
                        )? {
                            SetupSelection::Chosen(action) if action == "retry" => continue,
                            SetupSelection::Chosen(_) | SetupSelection::Back => {
                                continue 'appearance;
                            }
                            SetupSelection::Canceled => return Ok(false),
                        }
                    },
                    SetupSelection::Chosen(value) => value,
                    SetupSelection::Back => continue,
                    SetupSelection::Canceled => return Ok(false),
                }
            }
            "browser.font_size_px" => loop {
                let input = match terminal.line("Browser font size in pixels (10-24): ", 16) {
                    Ok(value) => value.trim().to_owned(),
                    Err(OnboardingError::Invalid("Input exceeds its byte limit")) => {
                        match correction_action(
                            terminal,
                            "Font size entry is too long. Use at most 16 bytes, or return to appearance settings.",
                        )? {
                            SetupSelection::Chosen(action) if action == "retry" => continue,
                            SetupSelection::Chosen(_) | SetupSelection::Back => {
                                continue 'appearance;
                            }
                            SetupSelection::Canceled => return Ok(false),
                        }
                    }
                    Err(error) => return Err(error.into()),
                };
                let Ok(size) = input.parse::<f32>() else {
                    match correction_action(
                        terminal,
                        "Enter a browser font size from 10 through 24 pixels.",
                    )? {
                        SetupSelection::Chosen(action) if action == "retry" => continue,
                        SetupSelection::Chosen(_) | SetupSelection::Back => continue 'appearance,
                        SetupSelection::Canceled => return Ok(false),
                    }
                };
                let mut candidate = reviewed.profile.clone();
                candidate.browser.font_size_px = size;
                if candidate.validate().is_ok() {
                    break size.to_string();
                }
                match correction_action(
                    terminal,
                    "Enter a browser font size from 10 through 24 pixels.",
                )? {
                    SetupSelection::Chosen(action) if action == "retry" => continue,
                    SetupSelection::Chosen(_) | SetupSelection::Back => continue 'appearance,
                    SetupSelection::Canceled => return Ok(false),
                }
            },
            _ => {
                let options: &[&str] = match key.as_str() {
                    "theme" => &["orbit", "midnight", "paper"],
                    "layout.preset" => &["default", "columns", "build", "agents", "review"],
                    "density" => &["comfortable", "compact"],
                    "glyphs" => &["auto", "unicode", "ascii"],
                    "color_mode" => &["auto", "truecolor", "256", "16", "mono"],
                    "reduced_motion" => &["false", "true"],
                    _ => return Err(ConfigurationError::InvalidChoice),
                };
                let choices: Vec<SetupChoice<'_>> = options
                    .iter()
                    .map(|id| SetupChoice {
                        id,
                        label: id,
                        detail: None,
                    })
                    .collect();
                let highlight = options
                    .contains(&current.as_str())
                    .then_some(current.as_str());
                match selection(terminal, "Choose appearance", &choices, highlight)? {
                    SetupSelection::Chosen(value) => value,
                    SetupSelection::Back => continue,
                    SetupSelection::Canceled => return Ok(false),
                }
            }
        };
        if current == value {
            terminal.message("This appearance setting is already selected; nothing changed.")?;
            return Ok(false);
        }
        let scope = if key == "layout.preset" {
            "Replaces the current layout tree with the selected preset."
        } else {
            "Updates this setting in the shared terminal and browser profile."
        };
        if !confirm(
            terminal,
            &format!(
                "{}: {} -> {}\n{scope}\nTerminal fonts remain controlled by your terminal application.",
                safe(&key),
                safe(&current),
                safe(&value)
            ),
        )? {
            return Ok(false);
        }
        host.command_checked(ProfileCommand::Set { key, value }, &reviewed.revision)?;
        return Ok(true);
    }
}

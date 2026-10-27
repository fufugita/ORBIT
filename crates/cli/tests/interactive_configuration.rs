#![cfg(target_os = "linux")]

use orbit_adapter::SecretBytes;
use orbit_cli::config::ProvidersConfig;
use orbit_cli::configuration_ui::{self, ConfigurationError};
use orbit_cli::onboarding::{OnboardingError, SetupChoice, SetupSelection, SetupTerminal};
use orbit_cli::phase_routing::{self, SelectionOrigin};
use orbit_engine::routing::{Difficulty, TaskPhase};
use orbit_frontend_protocol::customization::{Profile, ProfileCommand};
use std::collections::VecDeque;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::PathBuf;

const DOCUMENT: &str = r#"
[[provider]]
name='first'
url='https://first.example/v1?access=fixture_hidden_query'
env='FIXTURE_REFERENCE'
[[provider.models]]
id='shared'
context_window=1024
[[provider.models]]
id='vendor/model-a'
context_window=8192
[[provider]]
name='second'
url='https://second.example/v1'
[[provider.models]]
id='shared'
context_window=4096
[roles]
main='first/shared'
subagent='first/shared'
explore='first/shared'
compaction='first/shared'
[routing]
easy='first/shared'
hard='first/vendor/model-a'
[routing.keywords]
clear=true
easy=['light']
hard=['deep']
[routing.phases.coding]
hard='first/vendor/model-a'
[unrelated]
keep='fixture_hidden_value'
"#;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn absent() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-config-ui-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        Self {
            home: root.join("home"),
            workspace,
            root,
        }
    }
    fn configured() -> Self {
        let fixture = Self::absent();
        fixture.write(DOCUMENT);
        fixture
    }
    fn write(&self, raw: &str) {
        if !self.home.exists() {
            std::fs::create_dir(&self.home).unwrap();
            std::fs::set_permissions(&self.home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(self.home.join("providers.toml"), raw).unwrap();
        std::fs::set_permissions(
            self.home.join("providers.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.home.join("providers.toml")).unwrap()
    }
    fn run(&self, replies: &[Reply]) -> serde_json::Value {
        let mut terminal = Terminal::new(replies);
        let receipt = configuration_ui::run(&self.home, &self.workspace, &mut terminal).unwrap();
        assert!(terminal.replies.is_empty(), "unconsumed terminal replies");
        receipt
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
enum Reply {
    Choose(&'static str),
    Confirm(&'static str),
    Type(&'static str),
    TooLong,
    Back,
    Cancel,
}

struct Terminal {
    replies: VecDeque<Reply>,
    messages: Vec<String>,
    before_confirmation: Option<Box<dyn FnOnce()>>,
}

impl Terminal {
    fn new(replies: &[Reply]) -> Self {
        Self {
            replies: replies.iter().cloned().collect(),
            messages: Vec::new(),
            before_confirmation: None,
        }
    }
}

impl SetupTerminal for Terminal {
    fn message(&mut self, message: &str) -> Result<(), OnboardingError> {
        self.messages.push(message.to_owned());
        Ok(())
    }
    fn line(&mut self, _: &str, _: usize) -> Result<String, OnboardingError> {
        match self.replies.pop_front().expect("missing confirmation") {
            Reply::Confirm(value) => {
                if let Some(change) = self.before_confirmation.take() {
                    change();
                }
                Ok(value.into())
            }
            Reply::Type(value) => Ok(value.into()),
            Reply::TooLong => Err(OnboardingError::Invalid("Input exceeds its byte limit")),
            Reply::Cancel => Err(OnboardingError::Canceled),
            _ => panic!("expected explicit confirmation"),
        }
    }
    fn hidden(&mut self, _: &str, _: usize) -> Result<SecretBytes, OnboardingError> {
        panic!("configuration edits must not request a credential")
    }
    fn select(
        &mut self,
        prompt: &str,
        choices: &[SetupChoice<'_>],
        current: Option<&str>,
        allow_back: bool,
    ) -> Result<SetupSelection, OnboardingError> {
        assert!(
            choices.len() <= 4096,
            "valid configurations must fit the shared menu bounds"
        );
        let text_bytes = choices.iter().fold(0usize, |used, choice| {
            used.saturating_add(choice.id.len())
                .saturating_add(choice.label.len())
                .saturating_add(choice.detail.map_or(0, str::len))
        });
        assert!(
            text_bytes <= 1024 * 1024,
            "valid configurations must fit the shared menu text budget"
        );
        assert!(current.is_none_or(|id| choices.iter().any(|choice| choice.id == id)));
        if prompt == "Configuration" {
            assert_eq!(current, Some("defaults"), "hub opens on a useful action");
        }
        match self.replies.pop_front().expect("missing menu selection") {
            Reply::Choose(id) => {
                assert!(
                    choices.iter().any(|choice| choice.id == id),
                    "choice was not offered: {id}"
                );
                Ok(SetupSelection::Chosen(id.into()))
            }
            Reply::Back => {
                assert!(allow_back);
                Ok(SetupSelection::Back)
            }
            Reply::Cancel => Ok(SetupSelection::Canceled),
            Reply::Confirm(_) => panic!("expected menu selection"),
            Reply::Type(_) => panic!("expected menu selection, received line input"),
            Reply::TooLong => panic!("expected line input"),
        }
    }
}

#[test]
fn missing_home_show_and_hub_cancel_are_read_only() {
    let fixture = Fixture::absent();
    let view = configuration_ui::show(&fixture.home, &fixture.workspace).unwrap();
    assert_eq!(view["models_configured"], false);
    assert_eq!(view["connectivity"], "not_tested");
    assert!(!fixture.home.exists());
    let result = fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("routing"),
        Reply::Back,
    ]);
    assert_eq!(result["changes_saved"], 0);
    assert!(!fixture.home.exists());
}

#[test]
fn empty_document_and_empty_provider_cancel_preserve_exact_bytes() {
    for raw in [
        "",
        "[[provider]]\nname='pending'\nurl='https://example.invalid/v1'\n",
    ] {
        let fixture = Fixture::absent();
        fixture.write(raw);
        fixture.run(&[Reply::Choose("defaults"), Reply::Choose("done")]);
        assert_eq!(fixture.bytes(), raw.as_bytes());
        assert!(!fixture.home.join("customization.json").exists());
    }
}

#[test]
fn show_excludes_endpoints_references_unknown_values_and_profile_secrets() {
    let fixture = Fixture::configured();
    let mut profile = Profile::default();
    profile.browser.font_family = "fixture_private_font".into();
    orbit_cli::customization::replace(&fixture.home, &fixture.workspace, &profile).unwrap();
    let view = configuration_ui::show(&fixture.home, &fixture.workspace).unwrap();
    let encoded = serde_json::to_string(&view).unwrap();
    let human = configuration_ui::human_report(&view);
    for hidden in [
        "fixture_hidden_query",
        "FIXTURE_REFERENCE",
        "fixture_hidden_value",
        "fixture_private_font",
        "https://first.example",
    ] {
        assert!(!encoded.contains(hidden));
        assert!(!human.contains(hidden));
    }
    assert_eq!(view["providers"][0]["models"][1], "vendor/model-a");
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn human_configuration_report_makes_invisible_model_code_points_visible() {
    let fixture = Fixture::configured();
    let mut view = configuration_ui::show(&fixture.home, &fixture.workspace).unwrap();
    view["roles"]["main"] = serde_json::Value::String("vendor\u{202e}/model\u{200b}-fast".into());
    let human = configuration_ui::human_report(&view);
    assert!(human.contains("vendor⟦U+202E⟧/model⟦U+200B⟧-fast"));
    assert!(!human.contains('\u{200b}'));
    assert_eq!(view["roles"]["main"], "vendor\u{202e}/model\u{200b}-fast");
}

#[test]
fn confirmed_main_selection_is_used_by_a_fresh_checked_consumer() {
    let fixture = Fixture::configured();
    let receipt = fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("second/shared"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 1);
    let config = ProvidersConfig::load(&fixture.home).unwrap();
    assert_eq!(config.roles.main, "second/shared");
    let turn = orbit_cli::checked_model_turn(&fixture.home, &config.roles.main, None, None, false)
        .unwrap();
    assert_eq!(
        (turn.provider_id.as_str(), turn.model.as_str()),
        ("second", "shared")
    );
    assert_eq!(
        orbit_cli::context_window_for_turn(&fixture.home, &turn),
        Some(4096)
    );
    let saved: toml::Value =
        toml::from_str(std::str::from_utf8(&fixture.bytes()).unwrap()).unwrap();
    assert_eq!(
        saved["unrelated"]["keep"].as_str(),
        Some("fixture_hidden_value")
    );
    assert_eq!(config.roles.explore, "first/shared");
}

#[test]
fn auxiliary_role_uses_exact_raw_slash_identity_and_automatic_restores_inheritance() {
    let fixture = Fixture::configured();
    fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("compaction"),
        Reply::Choose("first/vendor/model-a"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    let base =
        orbit_cli::checked_model_turn(&fixture.home, "second/shared", None, None, false).unwrap();
    let selected = orbit_cli::try_role_turn_config(&fixture.home, &base, "compaction").unwrap();
    assert_eq!(
        (selected.provider_id.as_str(), selected.model.as_str()),
        ("first", "vendor/model-a")
    );
    assert_eq!(
        orbit_cli::context_window_for_turn(&fixture.home, &selected),
        Some(8192)
    );
    fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("compaction"),
        Reply::Choose("inherit"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    let inherited = orbit_cli::try_role_turn_config(&fixture.home, &base, "compaction").unwrap();
    assert_eq!(
        (inherited.provider_id.as_str(), inherited.model.as_str()),
        ("second", "shared")
    );
}

#[test]
fn unchanged_or_declined_selection_keeps_the_original_document_byte_for_byte() {
    let fixture = Fixture::configured();
    for answer in ["", "no", "y", "YES"] {
        let result = fixture.run(&[
            Reply::Choose("defaults"),
            Reply::Choose("main"),
            Reply::Choose("second/shared"),
            Reply::Confirm(answer),
            Reply::Choose("done"),
        ]);
        assert_eq!(result["changes_saved"], 0);
        assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
    }
    let result = fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("first/shared"),
        Reply::Choose("done"),
    ]);
    assert_eq!(result["changes_saved"], 0);
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn shorthand_current_identity_is_a_noop_when_its_exact_model_is_kept() {
    let fixture = Fixture::configured();
    let raw = DOCUMENT.replace("main='first/shared'", "main='first/vendor/model-a'");
    fixture.write(&raw);
    // This raw slash ID is unambiguous without its optional provider prefix.
    let raw = raw.replace("main='first/vendor/model-a'", "main='vendor/model-a'");
    fixture.write(&raw);
    let receipt = fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("first/vendor/model-a"),
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 0);
    assert_eq!(fixture.bytes(), raw.as_bytes());
}

#[test]
fn fallback_edits_reach_fresh_preview_without_overwriting_phase_or_explicit_pins() {
    let fixture = Fixture::configured();
    let receipt = fixture.run(&[
        Reply::Choose("routing"),
        Reply::Choose("easy"),
        Reply::Choose("second/shared"),
        Reply::Confirm("yes"),
        Reply::Choose("routing"),
        Reply::Choose("hard"),
        Reply::Choose("second/shared"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 2);
    let config = ProvidersConfig::load(&fixture.home).unwrap();
    assert_eq!(config.routing.easy, "second/shared");
    assert_eq!(config.routing.hard, "second/shared");
    let settings = config.phase_settings();
    let base = phase_routing::resolve_model(&config, "first/shared", None).unwrap();
    for (prompt, difficulty) in [("light", Difficulty::Easy), ("deep", Difficulty::Hard)] {
        let routed = phase_routing::preview(
            &config,
            &settings,
            &base,
            SelectionOrigin::Default,
            prompt,
            Some(TaskPhase::General),
        )
        .unwrap();
        assert_eq!(routed.difficulty, difficulty);
        assert_eq!(
            (routed.provider_id.as_str(), routed.raw_model.as_str()),
            ("second", "shared")
        );
    }
    let custom = phase_routing::preview(
        &config,
        &settings,
        &base,
        SelectionOrigin::Default,
        "deep",
        Some(TaskPhase::Coding),
    )
    .unwrap();
    assert_eq!(custom.raw_model, "vendor/model-a");
    let pinned = phase_routing::preview(
        &config,
        &settings,
        &base,
        SelectionOrigin::Interactive,
        "deep",
        Some(TaskPhase::General),
    )
    .unwrap();
    assert_eq!(
        (pinned.provider_id.as_str(), pinned.raw_model.as_str()),
        ("first", "shared")
    );
}

#[test]
fn role_review_detects_concurrent_changes_inside_the_atomic_write() {
    let fixture = Fixture::configured();
    let changed = format!("{DOCUMENT}\n# concurrent edit\n");
    let path = fixture.home.join("providers.toml");
    let expected = changed.clone();
    let mut terminal = Terminal::new(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("second/shared"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    terminal.before_confirmation = Some(Box::new(move || std::fs::write(path, changed).unwrap()));
    let result = configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
    assert_eq!(result["changes_saved"], 0);
    assert_eq!(fixture.bytes(), expected.as_bytes());
    assert_eq!(
        ProvidersConfig::load(&fixture.home).unwrap().roles.main,
        "first/shared"
    );
    assert!(
        terminal
            .messages
            .iter()
            .any(|message| message.contains("not retried"))
    );
}

#[test]
fn confirmed_edit_does_not_recreate_a_removed_or_emptied_provider_document() {
    for remove in [false, true] {
        let fixture = Fixture::configured();
        let path = fixture.home.join("providers.toml");
        let mut terminal = Terminal::new(&[
            Reply::Choose("defaults"),
            Reply::Choose("main"),
            Reply::Choose("second/shared"),
            Reply::Confirm("yes"),
            Reply::Choose("done"),
        ]);
        terminal.before_confirmation = Some(Box::new(move || {
            if remove {
                std::fs::remove_file(path).unwrap();
            } else {
                std::fs::write(path, b"").unwrap();
            }
        }));
        let result =
            configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
        assert_eq!(result["changes_saved"], 0);
        assert_eq!(fixture.home.join("providers.toml").exists(), !remove);
        if !remove {
            assert!(fixture.bytes().is_empty());
        }
    }
}

#[test]
fn appearance_changes_are_consumed_by_a_fresh_shared_profile_host() {
    let fixture = Fixture::configured();
    let receipt = fixture.run(&[
        Reply::Choose("appearance"),
        Reply::Choose("theme"),
        Reply::Choose("midnight"),
        Reply::Confirm("yes"),
        Reply::Choose("appearance"),
        Reply::Choose("layout.preset"),
        Reply::Choose("agents"),
        Reply::Confirm("yes"),
        Reply::Choose("appearance"),
        Reply::Choose("density"),
        Reply::Choose("compact"),
        Reply::Confirm("yes"),
        Reply::Choose("appearance"),
        Reply::Choose("glyphs"),
        Reply::Choose("ascii"),
        Reply::Confirm("yes"),
        Reply::Choose("appearance"),
        Reply::Choose("color_mode"),
        Reply::Choose("mono"),
        Reply::Confirm("yes"),
        Reply::Choose("appearance"),
        Reply::Choose("reduced_motion"),
        Reply::Choose("true"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 6);
    let host = orbit_cli::customization_host::host(
        &fixture.home,
        &fixture.workspace,
        orbit_cli::tool_runtime::PermissionScope::default(),
        false,
    );
    let current = host.load().unwrap();
    assert_eq!(current.profile.theme, "midnight");
    assert_eq!(current.profile.layout.preset, "agents");
    assert_eq!(
        current.profile.density,
        orbit_frontend_protocol::customization::Density::Compact
    );
    assert_eq!(
        current.profile.glyphs,
        orbit_frontend_protocol::customization::Glyphs::Ascii
    );
    assert_eq!(
        current.profile.color_mode,
        orbit_frontend_protocol::customization::ColorMode::Mono
    );
    assert!(current.profile.reduced_motion);
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn browser_fonts_are_editable_and_persist_to_a_fresh_profile_consumer() {
    let fixture = Fixture::configured();
    let receipt = fixture.run(&[
        Reply::Choose("appearance"),
        Reply::Choose("browser.font_family"),
        Reply::Choose("custom"),
        Reply::Type("IBM Plex Mono, monospace"),
        Reply::Confirm("yes"),
        Reply::Choose("appearance"),
        Reply::Choose("browser.font_size_px"),
        Reply::Type("16.5"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 2);

    let view = configuration_ui::show(&fixture.home, &fixture.workspace).unwrap();
    let encoded = serde_json::to_string(&view).unwrap();
    let human = configuration_ui::human_report(&view);
    assert!(!encoded.contains("IBM Plex Mono"));
    assert!(!human.contains("IBM Plex Mono"));
    assert_eq!(
        view["appearance"]["browser_font_family"],
        "Custom (value hidden)"
    );
    assert_eq!(view["appearance"]["browser_font_size_px"], 16.5);
    assert!(human.contains("Browser font: Custom (value hidden)"));
    assert!(human.contains("Browser font size (px): 16.5"));

    let host = orbit_cli::customization_host::host(
        &fixture.home,
        &fixture.workspace,
        orbit_cli::tool_runtime::PermissionScope::default(),
        false,
    );
    let current = host.load().unwrap();
    assert_eq!(
        current.profile.browser.font_family,
        "IBM Plex Mono, monospace"
    );
    assert_eq!(current.profile.browser.font_size_px, 16.5);
    let browser_profile = serde_json::to_value(&current.profile).unwrap();
    assert_eq!(
        browser_profile["browser"]["font_family"],
        "IBM Plex Mono, monospace"
    );
    assert_eq!(browser_profile["browser"]["font_size_px"], 16.5);
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn invalid_browser_font_family_can_be_corrected_before_publication() {
    let fixture = Fixture::configured();
    let mut terminal = Terminal::new(&[
        Reply::Choose("appearance"),
        Reply::Choose("browser.font_family"),
        Reply::Choose("custom"),
        Reply::Type("Invalid;Family"),
        Reply::Choose("retry"),
        Reply::Type("IBM Plex Mono, monospace"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    let result = configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
    assert_eq!(result["changes_saved"], 1);
    assert!(terminal.replies.is_empty());
    assert!(
        terminal
            .messages
            .iter()
            .any(|message| message.contains("Use 1–8"))
    );
    let host = orbit_cli::customization_host::host(
        &fixture.home,
        &fixture.workspace,
        orbit_cli::tool_runtime::PermissionScope::default(),
        false,
    );
    assert_eq!(
        host.load().unwrap().profile.browser.font_family,
        "IBM Plex Mono, monospace"
    );
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn invalid_browser_font_size_can_be_corrected_before_publication() {
    let fixture = Fixture::configured();
    let mut terminal = Terminal::new(&[
        Reply::Choose("appearance"),
        Reply::Choose("browser.font_size_px"),
        Reply::Type("24.1"),
        Reply::Choose("retry"),
        Reply::Type("16"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    let result = configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
    assert_eq!(result["changes_saved"], 1);
    assert!(terminal.replies.is_empty());
    assert!(
        terminal
            .messages
            .iter()
            .any(|message| message.contains("from 10 through 24"))
    );
    let host = orbit_cli::customization_host::host(
        &fixture.home,
        &fixture.workspace,
        orbit_cli::tool_runtime::PermissionScope::default(),
        false,
    );
    assert_eq!(host.load().unwrap().profile.browser.font_size_px, 16.0);
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn backing_out_after_invalid_browser_font_input_preserves_the_profile() {
    for (field, custom, invalid) in [
        ("browser.font_family", true, "Invalid;Family"),
        ("browser.font_size_px", false, "not-a-size"),
    ] {
        let fixture = Fixture::configured();
        let before = fixture.bytes();
        let mut replies = vec![Reply::Choose("appearance"), Reply::Choose(field)];
        if custom {
            replies.push(Reply::Choose("custom"));
        }
        replies.extend([
            Reply::Type(invalid),
            Reply::Back,
            Reply::Back,
            Reply::Choose("done"),
        ]);
        let mut terminal = Terminal::new(&replies);
        let result =
            configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
        assert_eq!(result["changes_saved"], 0);
        assert!(terminal.replies.is_empty());
        assert_eq!(fixture.bytes(), before);
        assert!(!fixture.home.join("customization.json").exists());
    }
}

#[test]
fn over_limit_browser_font_entry_can_be_retried_or_backed_out_safely() {
    for (field, custom, retry) in [
        ("browser.font_family", true, true),
        ("browser.font_family", true, false),
        ("browser.font_size_px", false, true),
        ("browser.font_size_px", false, false),
    ] {
        let fixture = Fixture::configured();
        let before = fixture.bytes();
        let mut replies = vec![Reply::Choose("appearance"), Reply::Choose(field)];
        if custom {
            replies.push(Reply::Choose("custom"));
        }
        replies.push(Reply::TooLong);
        if retry {
            replies.extend([
                Reply::Choose("retry"),
                Reply::Type(if custom { "IBM Plex Mono" } else { "16" }),
                Reply::Confirm("yes"),
                Reply::Choose("done"),
            ]);
        } else {
            replies.extend([Reply::Back, Reply::Back, Reply::Choose("done")]);
        }
        let mut terminal = Terminal::new(&replies);
        let result =
            configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
        assert!(terminal.replies.is_empty());
        assert_eq!(fixture.bytes(), before);
        if retry {
            assert_eq!(result["changes_saved"], 1);
            assert!(
                terminal
                    .messages
                    .iter()
                    .any(|message| message.contains("too long"))
            );
        } else {
            assert_eq!(result["changes_saved"], 0);
            assert!(!fixture.home.join("customization.json").exists());
        }
    }
}

#[test]
fn stale_appearance_review_preserves_the_intervening_profile() {
    let fixture = Fixture::configured();
    let home = fixture.home.clone();
    let workspace = fixture.workspace.clone();
    let mut terminal = Terminal::new(&[
        Reply::Choose("appearance"),
        Reply::Choose("theme"),
        Reply::Choose("midnight"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    terminal.before_confirmation = Some(Box::new(move || {
        let host = orbit_cli::customization_host::host(
            &home,
            &workspace,
            orbit_cli::tool_runtime::PermissionScope::default(),
            false,
        );
        let current = host.load().unwrap();
        host.command_checked(
            ProfileCommand::Set {
                key: "theme".into(),
                value: "paper".into(),
            },
            &current.revision,
        )
        .unwrap();
    }));
    let receipt = configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
    assert_eq!(receipt["changes_saved"], 0);
    assert_eq!(
        orbit_cli::customization::load(&fixture.home, &fixture.workspace)
            .unwrap()
            .profile
            .theme,
        "paper"
    );
}

#[test]
fn busy_provider_writer_keeps_the_reviewed_document_without_retrying() {
    let fixture = Fixture::configured();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(fixture.home.join(".config.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let receipt = fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("second/shared"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 0);
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn busy_profile_writer_keeps_the_previous_profile() {
    let fixture = Fixture::configured();
    let before =
        orbit_cli::customization::replace(&fixture.home, &fixture.workspace, &Profile::default())
            .unwrap();
    let bytes = std::fs::read(fixture.home.join("customization.json")).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(fixture.home.join(".customization.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let receipt = fixture.run(&[
        Reply::Choose("appearance"),
        Reply::Choose("theme"),
        Reply::Choose("paper"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 0);
    assert_eq!(
        std::fs::read(fixture.home.join("customization.json")).unwrap(),
        bytes
    );
    assert_eq!(
        orbit_cli::customization::load(&fixture.home, &fixture.workspace)
            .unwrap()
            .revision,
        before.revision
    );
}

#[test]
fn appearance_cancel_does_not_create_a_missing_home_or_profile() {
    let fixture = Fixture::absent();
    fixture.run(&[
        Reply::Choose("appearance"),
        Reply::Choose("theme"),
        Reply::Choose("paper"),
        Reply::Confirm("no"),
        Reply::Choose("done"),
    ]);
    assert!(!fixture.home.exists());
}

#[test]
fn custom_layout_can_be_explicitly_replaced_by_a_builtin_preset() {
    let fixture = Fixture::configured();
    let mut profile = Profile::default();
    profile.layout.preset = "custom".into();
    orbit_cli::customization::replace(&fixture.home, &fixture.workspace, &profile).unwrap();
    fixture.run(&[
        Reply::Choose("appearance"),
        Reply::Choose("layout.preset"),
        Reply::Choose("review"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    assert_eq!(
        orbit_cli::customization::load(&fixture.home, &fixture.workspace)
            .unwrap()
            .profile
            .layout
            .preset,
        "review"
    );
}

#[test]
fn unsafe_provider_entries_are_refused_without_following_or_rewriting_them() {
    for hardlink in [false, true] {
        let fixture = Fixture::configured();
        let source = fixture.root.join("owned-original.toml");
        std::fs::rename(fixture.home.join("providers.toml"), &source).unwrap();
        if hardlink {
            std::fs::hard_link(&source, fixture.home.join("providers.toml")).unwrap();
        } else {
            symlink(&source, fixture.home.join("providers.toml")).unwrap();
        }
        assert!(configuration_ui::show(&fixture.home, &fixture.workspace).is_err());
        assert_eq!(std::fs::read(source).unwrap(), DOCUMENT.as_bytes());
    }
}

#[test]
fn terminal_cannot_inject_an_unoffered_mutation_identity() {
    struct Unoffered;
    impl SetupTerminal for Unoffered {
        fn message(&mut self, _: &str) -> Result<(), OnboardingError> {
            Ok(())
        }
        fn line(&mut self, _: &str, _: usize) -> Result<String, OnboardingError> {
            panic!("no confirmation is valid")
        }
        fn hidden(&mut self, _: &str, _: usize) -> Result<SecretBytes, OnboardingError> {
            panic!("no credentials")
        }
        fn select(
            &mut self,
            _: &str,
            _: &[SetupChoice<'_>],
            _: Option<&str>,
            _: bool,
        ) -> Result<SetupSelection, OnboardingError> {
            Ok(SetupSelection::Chosen("unoffered".into()))
        }
    }
    let fixture = Fixture::configured();
    assert!(matches!(
        configuration_ui::run(&fixture.home, &fixture.workspace, &mut Unoffered),
        Err(ConfigurationError::InvalidChoice)
    ));
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
}

#[test]
fn leaving_after_saved_change_does_not_undo_it() {
    let fixture = Fixture::configured();
    let receipt = fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("second/shared"),
        Reply::Confirm("yes"),
        Reply::Cancel,
    ]);
    assert_eq!(receipt["changes_saved"], 1);
    assert_eq!(
        ProvidersConfig::load(&fixture.home).unwrap().roles.main,
        "second/shared"
    );
}

#[test]
fn eof_during_a_later_confirmation_truthfully_retains_an_earlier_save() {
    let fixture = Fixture::configured();
    let mut terminal = Terminal::new(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("second/shared"),
        Reply::Confirm("yes"),
        Reply::Choose("defaults"),
        Reply::Choose("subagent"),
        Reply::Choose("second/shared"),
        Reply::Cancel,
    ]);
    let error =
        configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap_err();
    assert!(matches!(error, ConfigurationError::Canceled));
    assert!(
        error
            .to_string()
            .contains("Previously confirmed changes are retained")
    );
    let config = ProvidersConfig::load(&fixture.home).unwrap();
    assert_eq!(config.roles.main, "second/shared");
    assert_eq!(config.roles.subagent, "first/shared");
}

#[test]
fn back_from_model_or_preset_returns_to_the_parent_menu_without_a_write() {
    let fixture = Fixture::configured();
    let receipt = fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Back,
        Reply::Choose("subagent"),
        Reply::Cancel,
        Reply::Choose("routing"),
        Reply::Choose("easy"),
        Reply::Back,
        Reply::Choose("hard"),
        Reply::Cancel,
        Reply::Choose("appearance"),
        Reply::Choose("theme"),
        Reply::Back,
        Reply::Choose("density"),
        Reply::Cancel,
        Reply::Choose("done"),
    ]);
    assert_eq!(receipt["changes_saved"], 0);
    assert_eq!(fixture.bytes(), DOCUMENT.as_bytes());
    assert!(!fixture.home.join("customization.json").exists());
}

#[test]
fn large_valid_catalogs_group_providers_without_truncating_model_choices() {
    let fixture = Fixture::absent();
    let mut raw = String::new();
    for provider in 0..5 {
        raw.push_str(&format!(
            "[[provider]]\nname='p{provider}'\nurl='https://example.invalid/v1'\nmodels=["
        ));
        for model in 0..1000 {
            raw.push_str(&format!("{{id='m{model}'}},"));
        }
        raw.push_str("]\n");
    }
    raw.push_str("[roles]\nmain='p0/m0'\n");
    assert!(raw.len() < 128 * 1024);
    fixture.write(&raw);
    fixture.run(&[
        Reply::Choose("defaults"),
        Reply::Choose("main"),
        Reply::Choose("provider:p4"),
        Reply::Choose("p4/m999"),
        Reply::Confirm("yes"),
        Reply::Choose("done"),
    ]);
    let saved = ProvidersConfig::load(&fixture.home).unwrap();
    assert_eq!(saved.roles.main, "p4/m999");
    assert_eq!(saved.all_models().len(), 5000);
    let turn =
        orbit_cli::checked_model_turn(&fixture.home, &saved.roles.main, None, None, false).unwrap();
    assert_eq!(
        (turn.provider_id.as_str(), turn.model.as_str()),
        ("p4", "m999")
    );
}

#[test]
fn long_provider_names_group_when_catalog_text_exceeds_the_shared_budget() {
    let fixture = Fixture::absent();
    let providers: Vec<String> = (0..4)
        .map(|index| format!("provider{}{index}", "a".repeat(119)))
        .collect();
    let mut raw = String::new();
    for provider in &providers {
        assert_eq!(provider.len(), 128);
        raw.push_str(&format!(
            "[[provider]]\nname='{provider}'\nurl='https://example.invalid/v1'\nmodels=["
        ));
        for model in 0..1000 {
            raw.push_str(&format!("{{id='m{model}'}},"));
        }
        raw.push_str("]\n");
    }
    raw.push_str(&format!("[roles]\nmain='{}/m0'\n", providers[0]));
    assert!(raw.len() < 128 * 1024);
    fixture.write(&raw);
    let config = ProvidersConfig::load(&fixture.home).unwrap();
    phase_routing::validate_settings(&config, &config.phase_settings()).unwrap();
    let model_count = config.all_models().len();
    assert_eq!(model_count, 4000);
    let flat_text_bytes = config.all_models().into_iter().fold(
        "inherit".len() + "Automatic: use the first configured model".len(),
        |used, (provider, model)| {
            let id = format!("{provider}/{model}");
            // These fixture identities are plain ASCII and contain no display-redacted material.
            used + 2 * id.len()
        },
    );
    assert!(model_count < 4096);
    assert!(flat_text_bytes > 1024 * 1024);
    let group = format!("provider:{}", providers[3]);
    let selected = format!("{}/m999", providers[3]);
    let mut terminal = OwnedSelectionTerminal {
        choices: [
            "defaults".to_owned(),
            "main".to_owned(),
            group,
            selected.clone(),
            "done".to_owned(),
        ]
        .into(),
        confirmations: 0,
    };
    let receipt = configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
    assert_eq!(receipt["changes_saved"], 1);
    assert_eq!(terminal.confirmations, 1);
    assert!(terminal.choices.is_empty());
    let reopened = ProvidersConfig::load(&fixture.home).unwrap();
    assert_eq!(reopened.roles.main, selected);
    assert_eq!(reopened.all_models().len(), 4000);
    let turn =
        orbit_cli::checked_model_turn(&fixture.home, &reopened.roles.main, None, None, false)
            .unwrap();
    assert_eq!(turn.provider_id, providers[3]);
    assert_eq!(turn.model, "m999");
}

struct OwnedSelectionTerminal {
    choices: VecDeque<String>,
    confirmations: usize,
}

impl SetupTerminal for OwnedSelectionTerminal {
    fn message(&mut self, _: &str) -> Result<(), OnboardingError> {
        Ok(())
    }
    fn line(&mut self, _: &str, _: usize) -> Result<String, OnboardingError> {
        self.confirmations += 1;
        Ok("yes".into())
    }
    fn hidden(&mut self, _: &str, _: usize) -> Result<SecretBytes, OnboardingError> {
        panic!("no credentials")
    }
    fn select(
        &mut self,
        _: &str,
        choices: &[SetupChoice<'_>],
        current: Option<&str>,
        _: bool,
    ) -> Result<SetupSelection, OnboardingError> {
        assert!(choices.len() <= 4096);
        let text_bytes = choices.iter().fold(0usize, |used, choice| {
            used.saturating_add(choice.id.len())
                .saturating_add(choice.label.len())
                .saturating_add(choice.detail.map_or(0, str::len))
        });
        assert!(
            text_bytes <= 1024 * 1024,
            "the long-name fixture must exercise grouping before selection"
        );
        assert!(current.is_none_or(|id| choices.iter().any(|choice| choice.id == id)));
        let id = self.choices.pop_front().expect("missing menu selection");
        assert!(choices.iter().any(|choice| choice.id == id));
        Ok(SetupSelection::Chosen(id))
    }
}

#[test]
fn compact_large_catalog_fallback_saves_preserve_models_and_reach_fresh_routing() {
    for provider_count in [4, 5] {
        let fixture = Fixture::absent();
        let mut raw = String::new();
        for provider in 0..provider_count {
            raw.push_str(&format!(
                "[[provider]]\nname='p{provider}'\nurl='https://example.invalid/v1'\nmodels=["
            ));
            for model in 0..1000 {
                raw.push_str(&format!("{{id='m{model}'}},"));
            }
            raw.push_str("]\n");
        }
        raw.push_str("[roles]\nmain='p0/m0'\n");
        assert!(raw.len() < phase_routing::MAX_CONFIG_BYTES);
        fixture.write(&raw);
        let previous = ProvidersConfig::load(&fixture.home).unwrap();
        let last = provider_count - 1;
        let selected = format!("p{last}/m999");
        let mut choices = vec!["routing".to_owned(), "hard".to_owned()];
        if provider_count == 5 {
            choices.push(format!("provider:p{last}"));
        }
        choices.extend([selected.clone(), "done".to_owned()]);
        let mut terminal = OwnedSelectionTerminal {
            choices: choices.into(),
            confirmations: 0,
        };
        let receipt =
            configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap();
        assert_eq!(receipt["changes_saved"], 1);
        assert_eq!(terminal.confirmations, 1);
        assert!(terminal.choices.is_empty());
        let reopened = ProvidersConfig::load(&fixture.home).unwrap();
        assert_eq!(reopened.provider, previous.provider);
        assert_eq!(reopened.all_models().len(), provider_count * 1000);
        assert_eq!(reopened.routing.hard, selected);
        let base = phase_routing::resolve_model(&reopened, &reopened.roles.main, None).unwrap();
        let routed = phase_routing::preview(
            &reopened,
            &reopened.phase_settings(),
            &base,
            SelectionOrigin::Default,
            "debug",
            Some(TaskPhase::General),
        )
        .unwrap();
        assert_eq!(
            (routed.provider_id.as_str(), routed.raw_model.as_str()),
            (format!("p{last}").as_str(), "m999")
        );
        let turn =
            orbit_cli::checked_model_turn(&fixture.home, &reopened.routing.hard, None, None, false)
                .unwrap();
        assert_eq!(turn.model, "m999");
        let saved = String::from_utf8(fixture.bytes()).unwrap();
        assert!(saved.contains("models=[{id='m0'},"));
        assert!(!saved.contains("[[provider.models]]"));
        assert!(saved.len() <= phase_routing::MAX_CONFIG_BYTES);
    }
}

#[test]
fn section_encoding_preserves_unknown_comments_float_values_and_compact_models() {
    let prefix = "# retained document marker\nuntouched={nested={label='keep'},values=[nan,-nan,inf,-inf,-0.0,0.0]}\nother.nested='keep dotted'\n";
    let provider = "[[provider]]\nname='p'\nurl='https://example.invalid/v1'\nmodels=[{id='m'},{id='n'}] # compact retained\n";
    for roles in [
        "",
        "roles={main='p/m',future={style='keep'}}\n",
        "roles.main='p/m'\nroles.future.style='keep'\n",
    ] {
        for routing in [
            "",
            "routing={easy='p/m',future={style='keep'}}\n",
            "routing.easy='p/m'\nrouting.future.style='keep'\n",
        ] {
            let fixture = Fixture::absent();
            let raw = format!("{prefix}{roles}{routing}{provider}");
            fixture.write(&raw);
            let mut intended: toml::Value = toml::from_str(&raw).unwrap();
            intended
                .as_table_mut()
                .unwrap()
                .entry("roles")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .unwrap()
                .insert("main".into(), "p/n".into());
            let saved = ProvidersConfig::update_atomic(&fixture.home, |current| {
                assert_eq!(current, raw);
                phase_routing::encode_candidate_section(current, &intended, "roles")
            })
            .unwrap();
            assert_eq!(saved.roles.main, "p/n");
            let candidate = String::from_utf8(fixture.bytes()).unwrap();
            assert!(candidate.contains(prefix));
            assert!(candidate.contains(provider));
            assert_eq!(
                toml::to_string(&toml::from_str::<toml::Value>(&candidate).unwrap()).unwrap(),
                toml::to_string(&intended).unwrap()
            );
            let routed = phase_routing::config_candidate(
                &candidate,
                phase_routing::RouteMutation::LegacyTarget {
                    difficulty: Difficulty::Hard,
                    model: "p/n".into(),
                },
            )
            .unwrap();
            assert!(routed.contains(prefix));
            assert!(routed.contains(provider));
            let routed_value: toml::Value = toml::from_str(&routed).unwrap();
            intended
                .as_table_mut()
                .unwrap()
                .entry("routing")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .unwrap()
                .insert("hard".into(), "p/n".into());
            assert_eq!(
                toml::to_string(&routed_value).unwrap(),
                toml::to_string(&intended).unwrap()
            );
        }
    }
}

#[test]
fn section_encoding_handles_empty_and_removed_sections_and_refuses_unrelated_changes() {
    let raw = "# retained\nkeep.value='original'\n[[provider]]\nname='p'\nurl='https://example.invalid/v1'\nmodels=[{id='m'}]\n";
    for section in ["roles", "routing"] {
        let mut intended: toml::Value = toml::from_str(raw).unwrap();
        intended
            .as_table_mut()
            .unwrap()
            .insert(section.into(), toml::Value::Table(Default::default()));
        let empty = phase_routing::encode_candidate_section(raw, &intended, section).unwrap();
        assert!(
            toml::from_str::<toml::Value>(&empty).unwrap()[section]
                .as_table()
                .unwrap()
                .is_empty()
        );
        intended.as_table_mut().unwrap().remove(section);
        let removed = phase_routing::encode_candidate_section(&empty, &intended, section).unwrap();
        assert!(
            toml::from_str::<toml::Value>(&removed)
                .unwrap()
                .get(section)
                .is_none()
        );
        assert!(removed.contains("# retained"));
        assert!(removed.contains("models=[{id='m'}]"));
        intended["keep"]["value"] = "unexpected edit".into();
        let error = phase_routing::encode_candidate_section(raw, &intended, section).unwrap_err();
        assert_eq!(
            error,
            "providers candidate did not preserve intended values"
        );
        assert!(!error.contains("original"));
        assert!(phase_routing::encode_candidate_section(raw, &intended, "provider").is_err());
    }
}

#[test]
fn confirmed_role_and_fallback_overflow_refuse_without_replacing_original_bytes() {
    for section in ["defaults", "routing"] {
        let fixture = Fixture::absent();
        let mut raw = DOCUMENT.to_owned();
        let padding = phase_routing::MAX_CONFIG_BYTES - 1 - raw.len() - 2;
        raw.push('#');
        raw.push_str(&"x".repeat(padding));
        raw.push('\n');
        assert_eq!(raw.len(), phase_routing::MAX_CONFIG_BYTES - 1);
        fixture.write(&raw);
        ProvidersConfig::load(&fixture.home).unwrap();
        let slot = if section == "defaults" {
            "main"
        } else {
            "easy"
        };
        let mut terminal = Terminal::new(&[
            Reply::Choose(section),
            Reply::Choose(slot),
            Reply::Choose("first/vendor/model-a"),
            Reply::Confirm("yes"),
        ]);
        let error =
            configuration_ui::run(&fixture.home, &fixture.workspace, &mut terminal).unwrap_err();
        assert!(matches!(error, ConfigurationError::Providers));
        assert!(terminal.replies.is_empty());
        assert_eq!(fixture.bytes(), raw.as_bytes());
        assert!(!fixture.home.join("customization.json").exists());
    }
}

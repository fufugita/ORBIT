use orbit_adapter::types::EffortValue;
use orbit_cli::{checked_model_turn, context_window_for_turn, try_role_turn_config};
use std::path::PathBuf;
struct Home(PathBuf);
impl Home {
    fn new(role: &str) -> Self {
        let path = std::env::temp_dir().join(format!("orbit-role-pair-{}", ulid::Ulid::new()));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("providers.toml"),
            format!(
                r#"
[[provider]]
name='first'
url='https://first.example/v1'
[[provider.models]]
id='shared'
supported_efforts=['low','high']
default_effort='low'
context_window=1024
[[provider.models]]
id='first/shared'
supported_efforts=['medium']
default_effort='medium'
context_window=8192
[[provider]]
name='second'
url='https://second.example/v1'
[[provider.models]]
id='shared'
supported_efforts=['medium']
default_effort='medium'
context_window=4096
[roles]
compaction={role:?}
"#
            ),
        )
        .unwrap();
        Self(path)
    }
    fn base(&self) -> orbit_engine::TurnConfig {
        // This selection is validated before the test mutates the role config.
        let config = orbit_cli::config::ProvidersConfig::load(&self.0).unwrap();
        orbit_cli::phase_routing::resolve_model(&config, "shared", Some("second"))
            .unwrap()
            .turn_config(None)
            .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn role_qualified_prefix_does_not_become_a_colliding_raw_id() {
    let home = Home::new("first/shared");
    let turn = try_role_turn_config(&home.0, &home.base(), "compaction").unwrap();
    assert_eq!(
        (turn.provider_id.as_str(), turn.model.as_str()),
        ("first", "shared")
    );
    assert_eq!(turn.gate, "https://first.example/v1");
    assert_eq!(turn.effort, Some(EffortValue::Level("low".into())));
}
#[test]
fn role_explicit_raw_slash_model_uses_its_own_capabilities() {
    let home = Home::new("first/first/shared");
    let turn = try_role_turn_config(&home.0, &home.base(), "compaction").unwrap();
    assert_eq!(turn.model, "first/shared");
    assert_eq!(context_window_for_turn(&home.0, &turn), Some(8192));
    assert_eq!(turn.effort, Some(EffortValue::Level("medium".into())));
}
#[test]
fn ambiguous_or_unknown_role_refuses_instead_of_using_base() {
    for role in ["shared", "missing/model"] {
        let home = Home::new(role);
        assert!(try_role_turn_config(&home.0, &home.base(), "compaction").is_err());
    }
}
#[test]
fn same_pair_role_retains_effort_and_exact_context_window() {
    let home = Home::new("second/shared");
    let mut base = checked_model_turn(&home.0, "second/shared", None, None, false).unwrap();
    base.effort = Some(EffortValue::Level("medium".into()));
    let turn = try_role_turn_config(&home.0, &base, "compaction").unwrap();
    assert_eq!(turn.effort, base.effort);
    assert_eq!(context_window_for_turn(&home.0, &turn), Some(4096));
}

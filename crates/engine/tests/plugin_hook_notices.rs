//! A plugin the operator named in `plugin_hooks` that cannot run is said once, when hooks load: the
//! plugin's hooks are the operator's choice, and a name that does nothing must not do it silently.
//! Listing the hooks (`/hooks`, `orbit doctor`) is its own report and announces nothing.

#![deny(unsafe_code)]

use orbit_engine::hooks::{Hooks, take_hook_problems};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

/// Hook trouble is reported process-wide and each text is announced once per process, so the tests
/// take turns, and each uses names of its own.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn home_with(name: &str, settings: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "orbit-plugin-hook-notices-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("mkdir home");
    // The plugin store only works in a private home.
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).expect("chmod home");
    std::fs::write(home.join("settings.toml"), settings).expect("write settings");
    home
}

#[test]
fn a_named_plugin_that_cannot_run_is_announced_once_when_hooks_load_and_not_when_listed() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let home = home_with("missing", "plugin_hooks = [\"zz-never-imported\"]\n");
    let listed = Hooks::inspect(&home, None);
    assert!(listed.hooks.is_empty());
    assert!(
        take_hook_problems().is_empty(),
        "listing announces nothing: its own report does that"
    );
    let loaded = Hooks::load(&home, false);
    assert!(loaded.hooks.is_empty());
    let problems = take_hook_problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    for part in ["zz-never-imported", "do not run", "not imported"] {
        assert!(problems[0].contains(part), "{part:?} in {:?}", problems[0]);
    }
    // Every tool call loads the hooks again: the operator is told once.
    let _ = Hooks::load(&home, false);
    let _ = Hooks::load(&home, false);
    assert!(take_hook_problems().is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_setting_that_is_not_a_list_is_announced_with_what_it_should_be() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let home = home_with("scalar", "plugin_hooks = \"zz-scalar\"\n");
    let _ = Hooks::load(&home, false);
    let problems = take_hook_problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("list of plugin names"),
        "{:?}",
        problems[0]
    );
    let _ = std::fs::remove_dir_all(&home);
}

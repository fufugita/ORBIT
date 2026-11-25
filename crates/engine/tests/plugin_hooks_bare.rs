//! `--bare` runs no plugin hooks, even for a plugin the operator named. Bare mode lasts for the life
//! of a process, so this is the only test in its binary.

#![deny(unsafe_code)]

use orbit_engine::hooks::Hooks;
use orbit_engine::plugin_hooks::resolve;
use orbit_plugin_compat::{InspectOptions, PluginFormat, PluginStore, StoreScope};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn open_tree(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.is_dir()
    {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
            open_tree(&entry.path());
        }
    }
}

#[test]
fn bare_mode_runs_no_plugin_hooks_even_for_a_plugin_that_is_named() {
    let root = std::env::temp_dir().join(format!("orbit-plugin-hooks-bare-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (home, project, source) = (root.join("home"), root.join("project"), root.join("source"));
    for dir in [
        &home,
        &project,
        &source.join(".claude-plugin"),
        &source.join("hooks"),
    ] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        source.join(".claude-plugin/plugin.json"),
        r#"{"name":"barely","description":"d"}"#,
    )
    .unwrap();
    std::fs::write(
        source.join("hooks/hooks.json"),
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
    )
    .unwrap();
    PluginStore::open(&home, &project, false)
        .unwrap()
        .import(
            &source,
            &InspectOptions {
                format: Some(PluginFormat::Claude),
                ..InspectOptions::default()
            },
            StoreScope::User,
            true,
        )
        .unwrap();
    std::fs::write(home.join("settings.toml"), "plugin_hooks = [\"barely\"]\n").unwrap();

    // The control: named, and it runs.
    assert_eq!(resolve(&home).hooks.len(), 1);
    assert_eq!(Hooks::inspect(&home, None).hooks.len(), 1);

    orbit_engine::enable_bare_mode();
    assert!(resolve(&home).hooks.is_empty(), "bare: nothing resolves");
    assert!(
        resolve(&home).report.is_empty() && resolve(&home).problems.is_empty(),
        "and nothing is said about it"
    );
    assert!(Hooks::inspect(&home, None).hooks.is_empty());

    open_tree(&root);
    let _ = std::fs::remove_dir_all(&root);
}

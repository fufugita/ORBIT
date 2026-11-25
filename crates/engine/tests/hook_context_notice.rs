//! When the limit takes some of the text hooks add to the model's context, the operator is
//! told once, with each hook's size and the setting that raises it. One test, in order: the
//! notice is process-wide and told once, so tests in this file could not take turns.

#![deny(unsafe_code)]

use orbit_engine::hooks::{HookEvent, Hooks, take_hook_problems};

/// A home whose SessionStart hooks print `sizes` bytes of plain text each.
fn home_with_hooks(name: &str, top: &str, sizes: &[usize]) -> std::path::PathBuf {
    let home =
        std::env::temp_dir().join(format!("orbit-hook-context-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("mkdir");
    let mut text = format!("{top}\n");
    for (at, size) in sizes.iter().enumerate() {
        let letter = (b'A' + at as u8) as char;
        text.push_str(&format!(
            "[[hooks]]\nevent = \"SessionStart\"\ncommand = \"head -c {size} /dev/zero | tr '\\\\0' {letter}\"\n"
        ));
    }
    std::fs::write(home.join("settings.toml"), text).expect("settings");
    home
}

fn session_start_context(hooks: &Hooks) -> String {
    let outcomes = hooks.fire(
        HookEvent::SessionStart,
        &serde_json::json!({"source": "startup"}),
    );
    hooks.prompt_context(&outcomes).unwrap_or_default()
}

#[test]
fn the_operator_is_told_once_when_hook_context_is_cut() {
    let _ = take_hook_problems();
    // Three hooks that together want 11 KB, and the default 8 KiB.
    let home = home_with_hooks("default", "", &[6000, 5000, 400]);
    let hooks = Hooks::load(&home, false);
    let _ = take_hook_problems();
    let text = session_start_context(&hooks);
    assert!(text.len() <= 8 * 1024, "{} bytes", text.len());
    assert!(
        text.ends_with("(hook context cut at 8192 bytes)"),
        "{}",
        &text[text.len() - 60..]
    );
    assert!(
        text.contains(&"A".repeat(6000)) && !text.contains('C'),
        "the third hook did not fit"
    );
    let problems = take_hook_problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    let told = &problems[0];
    assert!(
        told.contains("6000") && told.contains("5000") && told.contains("400"),
        "each hook's size: {told}"
    );
    assert!(
        told.contains("8192") && told.contains("hook_context_max_bytes"),
        "{told}"
    );
    // The next prompt is cut the same way, and the operator is not told again.
    let _ = session_start_context(&hooks);
    assert!(take_hook_problems().is_empty(), "told once");

    // The same hooks under the operator's own, larger limit: nothing is cut, nothing said.
    let home = home_with_hooks(
        "raised",
        "hook_context_max_bytes = 65536",
        &[6000, 5000, 400],
    );
    let hooks = Hooks::load(&home, false);
    assert_eq!(hooks.context_limit(), 65_536);
    let _ = take_hook_problems();
    let text = session_start_context(&hooks);
    assert_eq!(
        text.len(),
        6000 + 1 + 5000 + 1 + 400,
        "everything the hooks printed"
    );
    assert!(!text.contains("cut at"));
    assert!(take_hook_problems().is_empty());

    // A value that cannot be used is reported with the rest of the hook trouble.
    let home = home_with_hooks("typo", "hook_context_max_bytes = \"lots\"", &[100]);
    let hooks = Hooks::load(&home, false);
    assert_eq!(hooks.context_limit(), 8 * 1024);
    let problems = take_hook_problems();
    assert!(
        problems
            .iter()
            .any(|p| p.contains("hook_context_max_bytes") && p.contains("whole number")),
        "{problems:?}"
    );
}

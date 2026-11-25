//! A matcher written as a regular expression that is not one used to match nothing, without a
//! word, so the hook it guarded never ran. Loading the hooks now says so, once per hook, with the
//! reason and the hook's command; a pattern that works is not mentioned.

#![deny(unsafe_code)]

use orbit_engine::hooks::{HookEvent, Hooks, take_hook_problems};
use std::path::PathBuf;
use std::sync::Mutex;

/// Hook trouble is reported process-wide and a pattern is announced once per process, so the
/// tests take turns, and each uses patterns of its own.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn home_with(name: &str, settings: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "orbit-matcher-report-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("mkdir home");
    std::fs::write(home.join("settings.toml"), settings).expect("write settings");
    home
}

fn hook(event: &str, matcher: &str, command: &str) -> String {
    format!("[[hooks]]\nevent = \"{event}\"\nmatcher = '{matcher}'\ncommand = \"{command}\"\n")
}

#[test]
fn a_broken_regular_expression_is_announced_once_with_its_reason_and_its_hook() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let home = home_with(
        "broken",
        &hook(
            "PreToolUse",
            "mcp__.*(zzbroken",
            "/opt/guards/egress-guard.sh",
        ),
    );
    let hooks = Hooks::load(&home, false);
    assert_eq!(hooks.hooks.len(), 1, "the hook itself still loads");
    let problems = take_hook_problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    let problem = &problems[0];
    for part in [
        "PreToolUse",
        "mcp__.*(zzbroken",
        "not a valid regular expression",
        "unclosed group",
        "/opt/guards/egress-guard.sh",
    ] {
        assert!(problem.contains(part), "{part:?} missing from {problem:?}");
    }
    // Every tool call loads the hooks again: the operator is not told again.
    let _ = Hooks::load(&home, false);
    let _ = Hooks::load(&home, false);
    assert!(take_hook_problems().is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn two_hooks_with_the_same_broken_pattern_are_each_announced() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let settings = format!(
        "{}{}",
        hook("PreToolUse", "^(zzpair", "/opt/guards/one.sh"),
        hook("PostToolUse", "^(zzpair", "/opt/guards/two.sh"),
    );
    let home = home_with("pair", &settings);
    let _ = Hooks::load(&home, false);
    let problems = take_hook_problems();
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(problems.iter().any(|p| p.contains("one.sh")));
    assert!(problems.iter().any(|p| p.contains("two.sh")));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn inspecting_announces_nothing_and_leaves_the_announcement_for_the_real_load() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let home = home_with(
        "quiet",
        &hook("PreToolUse", "mcp__.*(zzquiet", "/opt/guards/quiet.sh"),
    );
    let quiet = Hooks::inspect(&home, None);
    assert_eq!(quiet.hooks.len(), 1);
    assert!(
        take_hook_problems().is_empty(),
        "a diagnostic prints its own findings"
    );
    let _ = Hooks::load(&home, false);
    assert_eq!(take_hook_problems().len(), 1);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn inspecting_reads_the_named_projects_hooks_and_only_when_it_is_given_one() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let home = home_with("project", &hook("PreToolUse", "Write", "user-hook"));
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".orbit")).unwrap();
    std::fs::write(
        project.join(".orbit/settings.toml"),
        hook("PreToolUse", "^(zzproject)$", "project-hook"),
    )
    .unwrap();
    let untrusted = Hooks::inspect(&home, None);
    assert_eq!(untrusted.hooks.len(), 1, "only the operator's own");
    assert!(!untrusted.project_trusted);
    let trusted = Hooks::inspect(&home, Some(&project));
    let commands: Vec<_> = trusted.hooks.iter().map(|h| h.command.as_str()).collect();
    assert_eq!(commands, ["user-hook", "project-hook"]);
    assert!(trusted.project_trusted);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_working_pattern_and_plain_lists_are_not_mentioned() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let settings = [
        hook("PreToolUse", "^(zzgood|zzfine)$", "a"),
        hook("PreToolUse", "WebSearch|WebFetch|mcp__.*(exa|tavily)", "b"),
        hook("PreToolUse", "Write|Edit", "c"),
        hook("PreToolUse", "mcp__*zztavily*", "d"),
        hook("SessionStart", "[id].tsx", "e"),
        hook("PreToolUse", "*", "f"),
    ]
    .concat();
    let home = home_with("good", &settings);
    let hooks = Hooks::load(&home, false);
    assert_eq!(hooks.hooks.len(), 6);
    assert!(take_hook_problems().is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn an_announcement_carries_no_terminal_control_characters() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let home = home_with(
        "control",
        "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"\\u001b[31m(zzcontrol\"\ncommand = \"echo \\u001b[2J\"\n",
    );
    let _ = Hooks::load(&home, false);
    let problems = take_hook_problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        !problems[0].chars().any(char::is_control),
        "{:?}",
        problems[0]
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_regular_expression_hook_runs_its_command_for_the_names_it_matches() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = take_hook_problems();
    let home = home_with("runs", "");
    let ran = home.join("ran");
    std::fs::write(
        home.join("settings.toml"),
        hook(
            "PreToolUse",
            "^(zzalpha|zzbeta)$",
            &format!("echo ran >> '{}'", ran.display()),
        ),
    )
    .unwrap();
    let hooks = Hooks::load(&home, false);
    let count = || std::fs::read_to_string(&ran).map_or(0, |text| text.lines().count());
    let fire = |tool: &str| {
        hooks.fire(
            HookEvent::PreToolUse,
            &serde_json::json!({"tool": tool, "arguments": {}}),
        )
    };
    fire("zzalpha");
    assert_eq!(count(), 1);
    fire("zzbeta");
    assert_eq!(count(), 2);
    fire("zzgamma");
    fire("zzalphax");
    assert_eq!(count(), 2, "the pattern is pinned with ^…$");
    assert!(take_hook_problems().is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

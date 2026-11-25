//! Plugins as they are found in the wild. What the importer recognises because Claude Code does, always; what it leaves
//! out only when the operator asked for `lenient`; and what stays a refusal either way.

use orbit_plugin_compat::{
    Compatibility, ComponentKind, DiagnosticSeverity, InspectOptions, Inspection, inspect,
};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, bytes).unwrap();
}

fn claude(root: &Path) {
    write(
        root,
        ".claude-plugin/plugin.json",
        serde_json::to_vec(
            &json!({"name": "sample", "description": "A package", "license": "MIT"}),
        )
        .unwrap(),
    );
}

fn lenient() -> InspectOptions {
    InspectOptions {
        lenient: true,
        ..InspectOptions::default()
    }
}

fn code(root: &Path, options: &InspectOptions) -> String {
    inspect(root, options).unwrap_err().code
}

fn ids(inspection: &Inspection) -> Vec<String> {
    inspection.components.iter().map(|c| c.id.clone()).collect()
}

/// An error that names no component taints every component of the plugin when it is used.
fn package_wide_errors(inspection: &Inspection) -> Vec<String> {
    inspection
        .diagnostics
        .iter()
        .filter(|d| d.severity == DiagnosticSeverity::Error && d.component_id.is_none())
        .map(|d| d.code.clone())
        .collect()
}

fn warnings(inspection: &Inspection, code: &str) -> Vec<(Option<String>, String)> {
    inspection
        .diagnostics
        .iter()
        .filter(|d| d.severity == DiagnosticSeverity::Warning && d.code == code)
        .map(|d| {
            (
                d.source_path.clone(),
                format!("{} {}", d.message, d.action.clone().unwrap_or_default()),
            )
        })
        .collect()
}

fn mcp_servers(inspection: &Inspection) -> Vec<String> {
    inspection
        .components
        .iter()
        .filter_map(|c| match &c.kind {
            ComponentKind::Mcp(server) => Some(server.server_id.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------- recognised always

#[test]
fn a_flat_mcp_json_is_read_like_the_wrapped_one() {
    let flat = r#"{"linear":{"type":"http","url":"https://mcp.example.test/mcp"}}"#;
    let wrapped =
        r#"{"mcpServers":{"linear":{"type":"http","url":"https://mcp.example.test/mcp"}}}"#;
    let mut seen = Vec::new();
    for text in [flat, wrapped] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path());
        write(temp.path(), ".mcp.json", text);
        let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
        assert_eq!(mcp_servers(&inspected), ["linear"], "{text}");
        seen.push(ids(&inspected));
    }
    assert_eq!(seen[0], seen[1], "the same component either way");

    // Several servers, a command one and a remote one, as the official plugins write them.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        ".mcp.json",
        r#"{"terraform":{"command":"docker","args":["run","-i","--rm","img"]},"linear":{"type":"http","url":"https://mcp.example.test/mcp"}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let mut servers = mcp_servers(&inspected);
    servers.sort();
    assert_eq!(servers, ["linear", "terraform"]);

    // A plugin that ships an empty file has no servers, and is not refused for it.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(temp.path(), ".mcp.json", "{}");
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(mcp_servers(&inspected).is_empty());
}

#[test]
fn a_flat_mcp_json_that_is_not_a_map_of_servers_is_still_refused() {
    for text in [
        r#"{"linear":"not an object"}"#,
        r#"{"linear":{"url":"x"},"note":3}"#,
        r#"[]"#,
        r#"{"mcpServers":[]}"#,
        r#"{"mcpServers":{"a":{"command":"x"}},"other":{"command":"y"}}"#,
        r#"{"bad name":{"command":"x"}}"#,
    ] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path());
        write(temp.path(), ".mcp.json", text);
        assert_eq!(
            code(temp.path(), &InspectOptions::default()),
            "mcp_field_invalid",
            "{text}"
        );
    }
}

#[test]
fn hook_modules_are_noted_and_the_command_hooks_beside_them_are_read() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(temp.path(), "hooks/mod/register.ts", "export default {}\n");
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"description":"d","modules":["./mod/register.ts"],"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}]}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let hooks = inspected
        .components
        .iter()
        .filter(|c| matches!(c.kind, ComponentKind::Hook(_)))
        .count();
    assert_eq!(hooks, 1, "the command hook is still read");
    let noted = warnings(&inspected, "hook_modules_unsupported");
    assert_eq!(noted.len(), 1, "{:?}", inspected.diagnostics);
    assert_eq!(noted[0].0.as_deref(), Some("hooks/hooks.json"));
    assert!(
        package_wide_errors(&inspected).is_empty(),
        "a module must not make every skill of the plugin unavailable: {:?}",
        inspected.diagnostics
    );

    // A file that is only modules (a plugin made of nothing else) has no hooks and is not refused.
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"modules":["./mod/register.ts"]}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        !inspected
            .components
            .iter()
            .any(|c| matches!(c.kind, ComponentKind::Hook(_)))
    );
    assert_eq!(warnings(&inspected, "hook_modules_unsupported").len(), 1);
}

#[test]
fn hook_modules_that_are_not_a_list_of_package_files_are_still_refused() {
    for text in [
        r#"{"modules":"./a.ts","hooks":{}}"#,
        r#"{"modules":[1],"hooks":{}}"#,
        r#"{"modules":["a.ts"],"hooks":{}}"#,
        r#"{"modules":["../a.ts"],"hooks":{}}"#,
        r#"{"modules":["./missing.ts"],"hooks":{}}"#,
        // Named relative to the hooks file's folder: a file only at the package root is not found.
        r#"{"modules":["./only-at-root.ts"],"hooks":{}}"#,
        r#"{"hooks":{},"surprise":true}"#,
    ] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path());
        write(temp.path(), "hooks/a.ts", "x\n");
        write(temp.path(), "a.ts", "x\n");
        write(temp.path(), "only-at-root.ts", "x\n");
        write(temp.path(), "hooks/hooks.json", text);
        assert!(
            inspect(temp.path(), &InspectOptions::default()).is_err(),
            "{text}"
        );
    }
}

#[test]
fn an_argument_hint_may_be_a_list_of_words() {
    for (hint, shown) in [
        ("[setup|restore|status]", "[setup|restore|status]"),
        ("[a, b]", "[a, b]"),
        ("[--strict]", "[--strict]"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path());
        write(
            temp.path(),
            "commands/run.md",
            format!("---\ndescription: d\nargument-hint: {hint}\n---\nbody\n"),
        );
        write(
            temp.path(),
            "skills/run/SKILL.md",
            format!("---\nname: run\ndescription: d\nargument-hint: {hint}\n---\nbody\n"),
        );
        let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
        let command = inspected
            .components
            .iter()
            .find_map(|c| match &c.kind {
                ComponentKind::Command(spec) => Some(spec.clone()),
                _ => None,
            })
            .expect("a command");
        assert_eq!(command.argument_hint.as_deref(), Some(shown), "{hint}");
    }
    // A hint that is neither text nor a short list of text stays an error.
    let too_long = format!(
        "[{}]",
        (0..40)
            .map(|n| format!("w{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for hint in ["{a: b}", "[1, 2]", "[[a]]", "true", too_long.as_str()] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path());
        write(
            temp.path(),
            "commands/run.md",
            format!("---\ndescription: d\nargument-hint: {hint}\n---\nbody\n"),
        );
        assert_eq!(
            code(temp.path(), &InspectOptions::default()),
            "component_field_invalid",
            "{hint}"
        );
    }
}

#[test]
fn hook_handler_fields_that_have_a_meaning_are_not_reported_as_unmapped() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"x","if":"Bash(git *)","shell":"bash","powershell":"& y","commandWindows":"& z","timeout":5,"async":true,"statusMessage":"s"}]}]}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        !inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "component_field_unmapped"),
        "{:?}",
        inspected.diagnostics
    );
    // What has no meaning here is still named, so nothing runs that was never understood.
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x","rewakeMessage":"m"}]}]}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "component_field_unmapped")
    );
}

// ---------------------------------------------------------------------------------------------- lenient: front matter

#[test]
fn front_matter_that_claude_code_accepts_needs_lenient_to_import() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        "commands/doctor.md",
        "---\ndescription: Run it. Input: a category\nargument-hint: [--strict] [--json]\nallowed-tools:\n  - Read\n---\nbody\n",
    );
    assert_eq!(
        code(temp.path(), &InspectOptions::default()),
        "yaml_invalid"
    );
    let inspected = inspect(temp.path(), &lenient()).unwrap();
    let command = inspected
        .components
        .iter()
        .find_map(|c| match &c.kind {
            ComponentKind::Command(spec) => Some(spec.clone()),
            _ => None,
        })
        .expect("the command was read");
    assert_eq!(command.description, "Run it. Input: a category");
    assert_eq!(
        command.argument_hint.as_deref(),
        Some("[--strict] [--json]")
    );
    assert_eq!(
        command.allowed_tools.as_deref().map(<[String]>::len),
        Some(1)
    );
    assert!(
        warnings(&inspected, "component_skipped").is_empty(),
        "nothing was left out"
    );

    // The same for a skill and an agent.
    write(
        temp.path(),
        "skills/fetch/SKILL.md",
        "---\nname: fetch\ndescription: Fetch things. Use when: asked\n---\nbody\n",
    );
    write(
        temp.path(),
        "agents/fetcher.md",
        "---\nname: fetcher\ndescription: On-demand fetcher. Input: a name\ntools: [WebFetch]\n---\nbody\n",
    );
    let inspected = inspect(temp.path(), &lenient()).unwrap();
    assert_eq!(
        ids(&inspected),
        [
            "sample:agent:fetcher",
            "sample:command:doctor",
            "sample:skill:fetch"
        ]
    );
}

// ---------------------------------------------------------------------------------------------- lenient: components

#[test]
fn lenient_still_refuses_what_guards_the_package_as_a_whole() {
    // Two skills that claim one identity are not one bad file: leaving the second out would decide
    // silently which of them the plugin means.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    for directory in ["one", "two"] {
        write(
            temp.path(),
            &format!("skills/{directory}/SKILL.md"),
            "---\nname: same-review\ndescription: d\n---\nbody\n",
        );
    }
    assert_eq!(
        code(temp.path(), &InspectOptions::default()),
        "component_id_collision"
    );
    assert_eq!(code(temp.path(), &lenient()), "component_id_collision");
}

#[test]
fn a_component_left_out_leaves_nothing_of_itself_behind() {
    // The agent's model is mapped, which records a requirement, before a later field is refused.
    // Leaving the agent out must take that requirement with it, or the plugin is held to a
    // prerequisite of a component it does not have.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        "agents/ok.md",
        "---\nname: ok\ndescription: d\n---\nbody\n",
    );
    write(
        temp.path(),
        "agents/bad.md",
        "---\nname: bad\ndescription: d\nmodel: sonnet\ntools: {a: b}\n---\nbody\n",
    );
    let inspected = inspect(temp.path(), &lenient()).unwrap();
    assert_eq!(ids(&inspected), ["sample:agent:ok"]);
    assert_eq!(warnings(&inspected, "component_skipped").len(), 1);
    assert!(
        inspected
            .requirements
            .iter()
            .all(|r| r.component_id.as_deref() != Some("sample:agent:bad")),
        "{:?}",
        inspected.requirements
    );
}

#[test]
fn lenient_leaves_out_one_bad_component_and_keeps_the_rest() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        "skills/good/SKILL.md",
        "---\nname: good\ndescription: d\n---\nbody\n",
    );
    write(
        temp.path(),
        "skills/spaced/SKILL.md",
        "---\nname: Agent Cost Report\ndescription: d\n---\nbody\n",
    );
    write(
        temp.path(),
        "skills/broken/SKILL.md",
        "---\nname: broken\ndescription: \"never closed\n---\nbody\n",
    );
    write(
        temp.path(),
        "commands/fine.md",
        "---\ndescription: d\n---\nbody\n",
    );
    write(
        temp.path(),
        "commands/weird.md",
        "---\ndescription: d\nargument-hint: {a: b}\n---\nbody\n",
    );
    write(
        temp.path(),
        "agents/ok.md",
        "---\nname: ok\ndescription: d\n---\nbody\n",
    );
    write(
        temp.path(),
        "agents/spaced.md",
        "---\nname: Pentester Executor\ndescription: d\n---\nbody\n",
    );

    // Strict is unchanged: the first bad file refuses the package.
    assert!(inspect(temp.path(), &InspectOptions::default()).is_err());

    let inspected = inspect(temp.path(), &lenient()).unwrap();
    assert_eq!(
        ids(&inspected),
        [
            "sample:agent:ok",
            "sample:command:fine",
            "sample:skill:good"
        ]
    );
    let left_out = warnings(&inspected, "component_skipped");
    let mut paths: Vec<_> = left_out.iter().filter_map(|(p, _)| p.clone()).collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            "agents/spaced.md",
            "commands/weird.md",
            "skills/broken/SKILL.md",
            "skills/spaced/SKILL.md"
        ]
    );
    for (path, text) in &left_out {
        assert!(
            text.contains("component_id_invalid")
                || text.contains("component_field_invalid")
                || text.contains("yaml_invalid"),
            "{path:?} names its code: {text}"
        );
    }
    assert!(
        package_wide_errors(&inspected).is_empty(),
        "{:?}",
        inspected.diagnostics
    );
    assert!(
        inspected.requirements.iter().all(|r| r
            .component_id
            .as_ref()
            .is_none_or(|id| ids(&inspected).contains(id))),
        "nothing is left behind by a component that was dropped"
    );
}

#[test]
fn lenient_keeps_every_refusal_that_guards_the_package() {
    // Two components with one identity.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    for directory in ["one", "two"] {
        write(
            temp.path(),
            &format!("skills/{directory}/SKILL.md"),
            "---\nname: same\ndescription: d\n---\nbody\n",
        );
    }
    assert_eq!(code(temp.path(), &lenient()), "component_id_collision");

    // A path out of the package.
    let temp = tempfile::tempdir().unwrap();
    write(
        temp.path(),
        ".claude-plugin/plugin.json",
        r#"{"name":"sample","commands":"../elsewhere"}"#,
    );
    assert_eq!(code(temp.path(), &lenient()), "component_path_invalid");

    // A plugin identity that is not allowed.
    let temp = tempfile::tempdir().unwrap();
    write(
        temp.path(),
        ".claude-plugin/plugin.json",
        r#"{"name":"orbit"}"#,
    );
    assert_eq!(code(temp.path(), &lenient()), "plugin_id_invalid");

    // Malformed hook and MCP declarations.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(temp.path(), "hooks/hooks.json", "{not json");
    assert!(inspect(temp.path(), &lenient()).is_err());
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(temp.path(), ".mcp.json", r#"{"a":"nope"}"#);
    assert_eq!(code(temp.path(), &lenient()), "mcp_field_invalid");
}

#[test]
fn lenient_never_relaxes_what_the_front_matter_reader_refuses_for_safety() {
    for (text, expected) in [
        ("---\na: &x 1\nb: *x\n---\nbody\n", "yaml_alias_unsupported"),
        (
            "---\nname: ok\nname: again\n---\nbody\n",
            "yaml_duplicate_key",
        ),
        (
            "---\nname: !!python/object x\n---\nbody\n",
            "yaml_tag_unsupported",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path());
        write(temp.path(), "agents/bad.md", text);
        write(
            temp.path(),
            "agents/fine.md",
            "---\nname: fine\ndescription: d\n---\nbody\n",
        );
        let inspected = inspect(temp.path(), &lenient()).unwrap();
        assert_eq!(ids(&inspected), ["sample:agent:fine"], "{expected}");
        let left_out = warnings(&inspected, "component_skipped");
        assert_eq!(left_out.len(), 1, "{expected}");
        assert!(
            left_out[0].1.contains(expected),
            "{expected}: {}",
            left_out[0].1
        );
    }
}

// ---------------------------------------------------------------------------------------------- lenient: the source tree

#[test]
fn lenient_skips_symbolic_links_and_never_follows_them() {
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "secret.txt", "outside");
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        "skills/ok/SKILL.md",
        "---\nname: ok\ndescription: d\n---\nbody\n",
    );
    symlink(
        outside.path().join("secret.txt"),
        temp.path().join("escape"),
    )
    .unwrap();
    symlink(outside.path(), temp.path().join("folder")).unwrap();
    assert_eq!(
        code(temp.path(), &InspectOptions::default()),
        "source_entry_type"
    );
    let inspected = inspect(temp.path(), &lenient()).unwrap();
    assert!(
        inspected
            .source
            .files
            .iter()
            .all(|f| f.path != "escape" && !f.path.starts_with("folder"))
    );
    assert!(
        inspected
            .source
            .files
            .iter()
            .all(|f| !f.path.contains("secret"))
    );
    let skipped = warnings(&inspected, "source_entry_skipped");
    let mut paths: Vec<_> = skipped.iter().filter_map(|(p, _)| p.clone()).collect();
    paths.sort();
    assert_eq!(paths, ["escape", "folder"]);
    assert!(package_wide_errors(&inspected).is_empty());
    assert_eq!(ids(&inspected), ["sample:skill:ok"]);
}

#[test]
fn lenient_keeps_refusing_special_files_hard_links_and_case_collisions() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    let made = std::process::Command::new("mkfifo")
        .arg(temp.path().join("pipe"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    assert!(made, "mkfifo is needed for this test");
    assert_eq!(code(temp.path(), &lenient()), "source_entry_type");

    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "outside.txt", "outside");
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    fs::hard_link(
        outside.path().join("outside.txt"),
        temp.path().join("linked.txt"),
    )
    .unwrap();
    assert_eq!(code(temp.path(), &lenient()), "source_hardlink");

    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(temp.path(), "File.txt", "one");
    write(temp.path(), "file.txt", "two");
    assert_eq!(code(temp.path(), &lenient()), "source_case_collision");
}

#[test]
fn lenient_leaves_dependency_folders_out_of_the_package() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        "skills/ok/SKILL.md",
        "---\nname: ok\ndescription: d\n---\nbody\n",
    );
    write(
        temp.path(),
        "node_modules/dep/index.js",
        "module.exports = 1\n",
    );
    symlink("../dep/bin.js", {
        fs::create_dir_all(temp.path().join("node_modules/.bin")).unwrap();
        temp.path().join("node_modules/.bin/tool")
    })
    .unwrap();
    write(temp.path(), "mcp-server/.venv/lib/site.py", "x = 1\n");
    write(temp.path(), "scripts/venv/pyvenv.cfg", "home = /usr\n");
    write(temp.path(), "scripts/__pycache__/x.pyc", "bytecode");
    write(temp.path(), "scripts/run.sh", "echo hi\n");
    // A file that merely has the name of such a folder is an ordinary file.
    write(temp.path(), "docs/venv", "not a folder\n");

    // Strict reads all of it, and the link inside the folder refuses the package.
    assert_eq!(
        code(temp.path(), &InspectOptions::default()),
        "source_entry_type"
    );

    let inspected = inspect(temp.path(), &lenient()).unwrap();
    let mut files: Vec<_> = inspected
        .source
        .files
        .iter()
        .map(|f| f.path.clone())
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            ".claude-plugin/plugin.json",
            "docs/venv",
            "scripts/run.sh",
            "skills/ok/SKILL.md"
        ]
    );
    let mut skipped: Vec<_> = warnings(&inspected, "source_dependencies_skipped")
        .into_iter()
        .filter_map(|(p, _)| p)
        .collect();
    skipped.sort();
    assert_eq!(
        skipped,
        [
            "mcp-server/.venv",
            "node_modules",
            "scripts/__pycache__",
            "scripts/venv"
        ]
    );
    assert!(package_wide_errors(&inspected).is_empty());
}

// ---------------------------------------------------------------------------------------------- limits

#[test]
fn files_up_to_sixteen_mebibytes_and_packages_up_to_sixty_four_are_read() {
    let mib = |n: usize| vec![b'x'; n * 1024 * 1024];
    // Was refused at 8 MiB: a bundled script a plugin ships.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(temp.path(), "scripts/bundle.mjs", mib(10));
    assert!(inspect(temp.path(), &InspectOptions::default()).is_ok());
    // One byte over the limit.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    let mut over = mib(16);
    over.push(b'x');
    write(temp.path(), "scripts/bundle.mjs", over);
    assert_eq!(
        code(temp.path(), &InspectOptions::default()),
        "source_file_limit"
    );
    assert_eq!(code(temp.path(), &lenient()), "source_file_limit");
    // Several files that add up to more than the old 32 MiB package limit.
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    for n in 0..4 {
        write(temp.path(), &format!("assets/{n}.bin"), mib(14));
    }
    assert!(
        inspect(temp.path(), &InspectOptions::default()).is_ok(),
        "56 MiB"
    );
    // And more than the new one.
    write(temp.path(), "assets/4.bin", mib(14));
    assert_eq!(
        code(temp.path(), &InspectOptions::default()),
        "source_size_limit"
    );
}

// ---------------------------------------------------------------------------------------------- what a skipped hook declares

#[test]
fn hooks_are_still_marked_as_needing_activation_whatever_the_mode() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path());
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x"}]}]}}"#,
    );
    for options in [InspectOptions::default(), lenient()] {
        let inspected = inspect(temp.path(), &options).unwrap();
        let hook = inspected
            .components
            .iter()
            .find(|c| matches!(c.kind, ComponentKind::Hook(_)))
            .expect("a hook");
        assert_eq!(hook.compatibility, Compatibility::RequiresMigration);
        let _: &Value = &hook.metadata;
    }
}

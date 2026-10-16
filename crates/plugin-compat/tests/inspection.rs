use orbit_plugin_compat::{ComponentKind, InspectOptions, PluginFormat, inspect};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, bytes).unwrap();
}

fn portable(root: &Path) {
    write(
        root,
        "plugin.json",
        serde_json::to_vec(&json!({
            "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name": "sample", "version": "1.2.3", "license": "MIT",
            "description": "A portable package"
        }))
        .unwrap(),
    );
}

fn error(root: &Path) -> String {
    inspect(root, &InspectOptions::default()).unwrap_err().code
}

#[test]
fn inventories_portable_skills_mcp_and_support_files_without_execution() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    let skill = "---\nname: review\ndescription: >-\n  Review carefully\n  and explain findings.\nallowed-tools:\n  - Read\ndisable-model-invocation: true\nuser-invocable: false\nmetadata: {reference: guide.txt}\n---\n\nRead references/guide.txt.\n\nKeep --- inside the body.\n";
    write(temp.path(), "skills/review/SKILL.md", skill);
    write(
        temp.path(),
        "skills/review/references/guide.txt",
        "Reference bytes\n",
    );
    write(
        temp.path(),
        "scripts/probe.py",
        "from pathlib import Path\nPath('execution-marker').touch()\n",
    );
    fs::set_permissions(
        temp.path().join("scripts/probe.py"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    write(temp.path(), "mcp.json", serde_json::to_vec(&json!({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"sample": {"type": "stdio", "command": "example-server", "args": ["--stdio"], "env": {"TOKEN": "${SAMPLE_TOKEN}"}}}
    })).unwrap());
    let before = fs::read(temp.path().join("skills/review/SKILL.md")).unwrap();
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.schema_version, 1);
    assert_eq!(inspected.source.format, PluginFormat::Portable);
    assert_eq!(inspected.manifest.id, "sample");
    assert_eq!(inspected.source.files.len(), 5);
    assert_eq!(inspected.components.len(), 2);
    let component = inspected
        .components
        .iter()
        .find(|c| matches!(c.kind, ComponentKind::Skill(_)))
        .unwrap();
    let ComponentKind::Skill(skill) = &component.kind else {
        unreachable!()
    };
    assert_eq!(component.id, "sample:skill:review");
    assert_eq!(skill.name, "sample:review");
    assert_eq!(skill.description, "Review carefully and explain findings.");
    assert_eq!(
        skill.allowed_tools.as_deref(),
        Some(["Read".to_owned()].as_slice())
    );
    assert!(skill.disable_model_invocation);
    assert!(!skill.user_invocable);
    assert_eq!(
        skill.body,
        "Read references/guide.txt.\n\nKeep --- inside the body."
    );
    let component = inspected
        .components
        .iter()
        .find(|c| matches!(c.kind, ComponentKind::Mcp(_)))
        .unwrap();
    let ComponentKind::Mcp(mcp) = &component.kind else {
        unreachable!()
    };
    assert_eq!(mcp.command.as_deref(), Some("example-server"));
    assert_eq!(mcp.env["TOKEN"], "${SAMPLE_TOKEN}");
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "executable" && !r.satisfied)
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "inspection_only")
    );
    assert_eq!(
        fs::read(temp.path().join("skills/review/SKILL.md")).unwrap(),
        before
    );
    assert!(!temp.path().join("execution-marker").exists());
    assert!(!temp.path().join("plugins").exists());
    let script = inspected
        .source
        .files
        .iter()
        .find(|f| f.path == "scripts/probe.py")
        .unwrap();
    assert!(script.executable);
    assert_eq!(
        inspected,
        inspect(temp.path(), &InspectOptions::default()).unwrap()
    );
}

#[test]
fn skill_version_is_descriptive_in_portable_and_claude_packages() {
    for format in [PluginFormat::Portable, PluginFormat::Claude] {
        let temp = tempfile::tempdir().unwrap();
        match format {
            PluginFormat::Portable => portable(temp.path()),
            PluginFormat::Claude => claude(temp.path(), json!({})),
            _ => unreachable!(),
        }
        let path = "skills/review/SKILL.md";
        for version in ["0.1.0".to_owned(), "v".repeat(256)] {
            let source = format!(
                "---\nname: review\ndescription: Review changes\nversion: {version}\nallowed-tools: [Read]\nuser-invocable: false\nmetadata: {{revision: 7, archived: false}}\n---\nReview the changes.\n\nKeep --- inside the body.\n"
            );
            write(temp.path(), path, &source);
            let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
            let component = &inspected.components[0];
            let ComponentKind::Skill(skill) = &component.kind else {
                panic!("skill component missing")
            };
            assert_eq!(
                component.compatibility,
                orbit_plugin_compat::Compatibility::Adapted
            );
            assert_eq!(component.metadata["version"], version);
            assert_eq!(
                component.metadata["metadata"],
                json!({"revision": 7, "archived": false})
            );
            assert_eq!(skill.allowed_tools, Some(vec!["Read".to_owned()]));
            assert!(!skill.user_invocable);
            assert_eq!(
                skill.body,
                "Review the changes.\n\nKeep --- inside the body."
            );
            assert!(
                !inspected
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "component_field_unmapped")
            );
            assert!(
                inspected
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "inspection_only")
            );
            assert_eq!(fs::read(temp.path().join(path)).unwrap(), source.as_bytes());

            write(
                temp.path(),
                path,
                source.replacen("version:", "autoApprove: true\nversion:", 1),
            );
            let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
            assert_eq!(
                inspected.components[0].compatibility,
                orbit_plugin_compat::Compatibility::RequiresMigration
            );
            assert!(
                inspected
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "component_field_unmapped")
            );
        }
    }
}

#[test]
fn claude_skill_declared_identity_and_directory_default_preserve_source_path() {
    for declared in [Some("writing-hookify-rules"), None] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path(), json!({}));
        let name = declared
            .map(|name| format!("name: {name}\n"))
            .unwrap_or_default();
        let source = format!(
            "---\n{name}description: Write evidence-based rules\nversion: 0.1.0\nmodel: inherit\neffort: false\nallowed-tools: [Read]\ndisable-model-invocation: true\nuser-invocable: false\n---\nReview the rules and their original relative references.\n"
        );
        let path = "skills/writing-rules/SKILL.md";
        write(temp.path(), path, &source);
        let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
        let expected = declared.unwrap_or("writing-rules");
        let component = inspected
            .components
            .iter()
            .find(|component| matches!(component.kind, ComponentKind::Skill(_)))
            .unwrap();
        assert_eq!(component.id, format!("sample:skill:{expected}"));
        assert_eq!(component.source_path.as_deref(), Some(path));
        let ComponentKind::Skill(skill) = &component.kind else {
            unreachable!()
        };
        assert_eq!(skill.name, format!("sample:{expected}"));
        assert_eq!(skill.entry, path);
        assert_eq!(
            skill.body,
            "Review the rules and their original relative references."
        );
        assert_eq!(skill.model, None);
        assert_eq!(skill.effort, Some(json!(false)));
        assert_eq!(skill.allowed_tools, Some(vec!["Read".into()]));
        assert!(skill.disable_model_invocation);
        assert!(!skill.user_invocable);
        assert_eq!(
            component.metadata.get("name").and_then(Value::as_str),
            declared
        );
        assert_eq!(fs::read(temp.path().join(path)).unwrap(), source.as_bytes());
    }
}

#[test]
fn claude_skill_identity_adaptation_keeps_invalid_names_and_portable_mismatch_rejected() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    write(
        temp.path(),
        "skills/directory-name/SKILL.md",
        "---\nname: declared-name\ndescription: Keep portable directory identity strict\n---\nReview evidence.\n",
    );
    assert_eq!(error(temp.path()), "component_id_invalid");
    let oversized = "x".repeat(65);
    for invalid in [
        "",
        "../escape",
        "with/slash",
        "two words",
        "bad:name",
        "-leading",
        "trailing-",
        oversized.as_str(),
    ] {
        let temp = tempfile::tempdir().unwrap();
        claude(temp.path(), json!({}));
        let source = format!(
            "---\nname: {}\ndescription: Reject unsafe identity\n---\nReview evidence.\n",
            serde_json::to_string(invalid).unwrap()
        );
        write(temp.path(), "skills/directory-name/SKILL.md", source);
        assert_eq!(
            error(temp.path()),
            "component_id_invalid",
            "invalid declared identity: {invalid:?}"
        );
    }
}

#[test]
fn claude_skills_in_distinct_directories_cannot_share_declared_identity() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path(), json!({}));
    for directory in ["one", "two"] {
        write(
            temp.path(),
            &format!("skills/{directory}/SKILL.md"),
            "---\nname: same-review\ndescription: Review evidence\n---\nReview evidence.\n",
        );
    }
    assert_eq!(error(temp.path()), "component_id_collision");
}

#[test]
fn claude_nonadjacent_case_folded_component_names_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path(), json!({}));
    for (directory, name) in [
        ("one", "A-review"),
        ("two", "B-review"),
        ("three", "a-review"),
    ] {
        write(
            temp.path(),
            &format!("skills/{directory}/SKILL.md"),
            format!("---\nname: {name}\ndescription: Review evidence\n---\nReview evidence.\n"),
        );
    }
    assert_eq!(error(temp.path()), "component_id_collision");
}

#[test]
fn skill_version_rejects_invalid_descriptive_values() {
    for format in [PluginFormat::Portable, PluginFormat::Claude] {
        let temp = tempfile::tempdir().unwrap();
        match format {
            PluginFormat::Portable => portable(temp.path()),
            PluginFormat::Claude => claude(temp.path(), json!({})),
            _ => unreachable!(),
        }
        for version in [
            Value::Null,
            json!(false),
            json!(1),
            json!(["0.1.0"]),
            json!({"label": "0.1.0"}),
            json!(""),
            json!("   "),
            json!("v".repeat(257)),
            json!("0.1\n.0"),
        ] {
            write(
                temp.path(),
                "skills/review/SKILL.md",
                format!(
                    "---\nname: review\ndescription: Review changes\nversion: {version}\n---\nReview the changes.\n"
                ),
            );
            assert_eq!(
                error(temp.path()),
                "component_field_invalid",
                "{format:?}: {version}"
            );
        }
    }
}

#[test]
fn original_deja_portable_manifests_inspect_offline() {
    // Original manifest/MCP bytes: vshulcz/deja-vu, commit
    // c489a992d5eceb3b7b0479f8701746a245552135, MIT.
    // https://github.com/vshulcz/deja-vu/tree/c489a992d5eceb3b7b0479f8701746a245552135
    // Copyright (c) 2026 Vladislav Shulcz
    //
    // Permission is hereby granted, free of charge, to any person obtaining a copy
    // of this software and associated documentation files (the "Software"), to deal
    // in the Software without restriction, including without limitation the rights
    // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    // copies of the Software, and to permit persons to whom the Software is
    // furnished to do so, subject to the following conditions:
    //
    // The above copyright notice and this permission notice shall be included in all
    // copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    // SOFTWARE.
    let manifest = r#"{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  "name": "deja-vu",
  "version": "0.21.7",
  "description": "deja-vu: memory for coding agents from the sessions already on your disk — Claude Code, Codex, Cursor, opencode and thirty-four more — including work from before it was installed.",
  "author": {
    "name": "vshulcz",
    "url": "https://github.com/vshulcz"
  },
  "homepage": "https://vshulcz.github.io/deja-vu/",
  "repository": "https://github.com/vshulcz/deja-vu",
  "license": "MIT",
  "keywords": [
    "memory",
    "recall",
    "sessions",
    "search",
    "history"
  ]
}
"#;
    let mcp = r#"{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
  "mcpServers": {
    "deja": {
      "type": "stdio",
      "command": "deja",
      "args": ["mcp"]
    }
  }
}
"#;
    let temp = tempfile::tempdir().unwrap();
    write(temp.path(), "plugin.json", manifest);
    write(temp.path(), "mcp.json", mcp);
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.manifest.id, "deja-vu");
    assert_eq!(inspected.manifest.version.as_deref(), Some("0.21.7"));
    assert_eq!(inspected.manifest.license.as_deref(), Some("MIT"));
    assert_eq!(
        inspected.manifest.source_metadata,
        serde_json::from_str::<Value>(manifest).unwrap()
    );
    let ComponentKind::Mcp(server) = &inspected.components[0].kind else {
        panic!("MCP component missing")
    };
    assert_eq!(server.server_id, "deja");
    assert_eq!(server.command.as_deref(), Some("deja"));
    assert_eq!(server.args, ["mcp"]);
    assert_eq!(
        fs::read(temp.path().join("mcp.json")).unwrap(),
        mcp.as_bytes()
    );
}

#[test]
fn source_digest_covers_content_paths_and_executable_mode() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    write(temp.path(), "asset.txt", "first");
    let first = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let asset = first
        .source
        .files
        .iter()
        .find(|f| f.path == "asset.txt")
        .unwrap();
    assert_eq!(asset.sha256, hex::encode(Sha256::digest(b"first")));
    write(temp.path(), "asset.txt", "other");
    let second = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_ne!(first.source.source_digest, second.source.source_digest);
    fs::rename(
        temp.path().join("asset.txt"),
        temp.path().join("renamed.txt"),
    )
    .unwrap();
    let third = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_ne!(second.source.source_digest, third.source.source_digest);
    fs::set_permissions(
        temp.path().join("renamed.txt"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let fourth = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_ne!(third.source.source_digest, fourth.source.source_digest);
}

#[test]
fn rejects_symbolic_links_hardlinks_and_case_collisions() {
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "outside.txt", "outside");
    for directory in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        portable(temp.path());
        symlink(
            if directory {
                outside.path().to_path_buf()
            } else {
                outside.path().join("outside.txt")
            },
            temp.path().join("escape"),
        )
        .unwrap();
        assert_eq!(error(temp.path()), "source_entry_type");
    }
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    fs::hard_link(
        outside.path().join("outside.txt"),
        temp.path().join("linked.txt"),
    )
    .unwrap();
    assert_eq!(error(temp.path()), "source_hardlink");
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    write(temp.path(), "File.txt", "one");
    write(temp.path(), "file.txt", "two");
    assert_eq!(error(temp.path()), "source_case_collision");
}

#[test]
fn ignores_only_git_control_metadata_with_an_explicit_diagnostic() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    write(temp.path(), ".git/config", "SCM metadata");
    write(temp.path(), ".gitignore", "kept asset");
    write(temp.path(), "node_modules/example/file.txt", "kept asset");
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        inspected
            .source
            .files
            .iter()
            .all(|f| !f.path.starts_with(".git/"))
    );
    assert!(
        inspected
            .source
            .files
            .iter()
            .any(|f| f.path == ".gitignore")
    );
    assert!(
        inspected
            .source
            .files
            .iter()
            .any(|f| f.path == "node_modules/example/file.txt")
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "source_scm_excluded")
    );
}

#[test]
fn rejects_duplicate_json_keys_unknown_authority_and_unsafe_ids() {
    let temp = tempfile::tempdir().unwrap();
    write(
        temp.path(),
        "plugin.json",
        r#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"sample","name":"other"}"#,
    );
    assert_eq!(error(temp.path()), "manifest_json_invalid");
    for name in [
        "../escape",
        "Uppercase",
        "two--parts",
        "two..parts",
        "-start",
        "end-",
        "orbit",
        "mcp__reserved",
    ] {
        write(temp.path(), "plugin.json", serde_json::to_vec(&json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name":name})).unwrap());
        assert_eq!(error(temp.path()), "plugin_id_invalid", "name: {name}");
    }
    portable(temp.path());
    write(
        temp.path(),
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: sample\nallow-everything: true\n---\nbody",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "component_field_unmapped")
    );
}

#[test]
fn preserves_restriction_types_and_rejects_mixed_mcp_transport_fields() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    write(
        temp.path(),
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: sample\nuser-invocable: 'false'\n---\nbody",
    );
    assert_eq!(error(temp.path()), "component_field_invalid");
    fs::remove_dir_all(temp.path().join("skills")).unwrap();
    write(temp.path(), "mcp.json", serde_json::to_vec(&json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers":{"bad":{"type":"stdio","command":"server", "url":"https://example.test/mcp"}}})).unwrap());
    assert_eq!(error(temp.path()), "mcp_field_invalid");
}

fn claude(root: &Path, extra: Value) {
    let mut manifest = json!({"name":"sample", "description":"A Claude package", "license":"MIT"});
    manifest
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    write(
        root,
        ".claude-plugin/plugin.json",
        serde_json::to_vec(&manifest).unwrap(),
    );
}

#[test]
fn claude_default_layout_preserves_agents_commands_hooks_and_assets() {
    let temp = tempfile::tempdir().unwrap();
    claude(temp.path(), json!({}));
    write(
        temp.path(),
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: careful review\nallowed-tools: Bash(python *) Bash(python3 *) Read\n---\nRead references/guide.txt.",
    );
    write(
        temp.path(),
        "skills/review/references/guide.txt",
        "unchanged reference",
    );
    write(
        temp.path(),
        "agents/analyzer.md",
        "---\nname: analyzer\ndescription: >-\n  Analyze the\n  conversation.\nmodel: inherit\ncolor: yellow\ntools: [Read, Grep]\nmaxTurns: 7\neffort: 'false'\n---\n\nFull instructions.\n\nKeep --- markers.\n",
    );
    write(
        temp.path(),
        "commands/help.md",
        "---\ndescription: Help the user\nallowed-tools: [Read]\nargument-hint: '[topic]'\n---\nExplain $ARGUMENTS.",
    );
    write(temp.path(), "hooks/hooks.json", serde_json::to_vec(&json!({"description":"hooks", "hooks":{"PreToolUse":[{"matcher":"Bash|Edit", "hooks":[{"type":"command", "command":"python3 \"${CLAUDE_PLUGIN_ROOT}/hooks/check.py\"", "timeout":10}]}]}})).unwrap());
    write(
        temp.path(),
        "hooks/check.py",
        "raise SystemExit('inspection must not execute this')\n",
    );
    write(temp.path(), ".mcp.json", serde_json::to_vec(&json!({"mcpServers":{"memory":{"command":"node", "args":["${CLAUDE_PLUGIN_ROOT}/server.js"]}}})).unwrap());
    write(
        temp.path(),
        "server.js",
        "throw new Error('inspection must not execute this');\n",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.source.format, PluginFormat::Claude);
    assert_eq!(
        inspected.source.manifest_path.as_deref(),
        Some(".claude-plugin/plugin.json")
    );
    assert_eq!(inspected.components.len(), 5);
    let agent = inspected
        .components
        .iter()
        .find_map(|c| {
            if let ComponentKind::Agent(value) = &c.kind {
                Some(value)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(agent.name, "sample:analyzer");
    assert_eq!(
        agent.instructions,
        "Full instructions.\n\nKeep --- markers."
    );
    assert_eq!(agent.model, None);
    assert_eq!(agent.max_turns, Some(7));
    assert_eq!(agent.effort, Some(json!("false")));
    let skill = inspected
        .components
        .iter()
        .find_map(|c| {
            if let ComponentKind::Skill(value) = &c.kind {
                Some(value)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(
        skill.allowed_tools,
        Some(vec![
            "Bash(python *)".to_owned(),
            "Bash(python3 *)".to_owned(),
            "Read".to_owned()
        ])
    );
    let command = inspected
        .components
        .iter()
        .find_map(|c| {
            if let ComponentKind::Command(value) = &c.kind {
                Some(value)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(command.prompt.as_deref(), Some("Explain $ARGUMENTS."));
    assert_eq!(command.argument_hint.as_deref(), Some("[topic]"));
    let hook = inspected
        .components
        .iter()
        .find_map(|c| {
            if let ComponentKind::Hook(value) = &c.kind {
                Some(value)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(hook.event, "PreToolUse");
    assert_eq!(hook.matcher.as_deref(), Some("Bash|Edit"));
    assert_eq!(hook.timeout_secs, Some(10));
    assert!(
        inspected
            .source
            .files
            .iter()
            .any(|f| f.path == "skills/review/references/guide.txt")
    );
    assert!(
        !inspected
            .diagnostics
            .iter()
            .any(|d| d.severity == orbit_plugin_compat::DiagnosticSeverity::Error)
    );
}

#[test]
fn claude_declared_paths_follow_additive_and_replacement_rules() {
    let temp = tempfile::tempdir().unwrap();
    claude(
        temp.path(),
        json!({"skills":["./extra-skills/"], "commands":"./custom-commands/", "agents":["./custom-agents/worker.md"], "hooks":["./config/hooks.json", {"SessionEnd":[{"hooks":[{"type":"command","command":"printf end"}]}]}]}),
    );
    for path in ["skills/default/SKILL.md", "extra-skills/extra/SKILL.md"] {
        let name = path.split('/').nth(1).unwrap();
        write(
            temp.path(),
            path,
            format!("---\nname: {name}\ndescription: sample\n---\nbody"),
        );
    }
    write(
        temp.path(),
        "commands/ignored.md",
        "This default command is replaced.",
    );
    write(
        temp.path(),
        "custom-commands/selected.md",
        "Selected command.",
    );
    write(
        temp.path(),
        "agents/ignored.md",
        "---\nname: ignored\ndescription: ignored\n---\nignored",
    );
    write(
        temp.path(),
        "custom-agents/worker.md",
        "---\nname: worker\ndescription: selected\n---\nselected instructions",
    );
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf stop"}]}]}}"#,
    );
    write(
        temp.path(),
        "config/hooks.json",
        r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf start"}]}]}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let ids: Vec<_> = inspected.components.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"sample:skill:default"));
    assert!(ids.contains(&"sample:skill:extra"));
    assert!(ids.contains(&"sample:command:selected"));
    assert!(ids.contains(&"sample:agent:worker"));
    assert!(ids.iter().all(|id| !id.contains("ignored")));
    assert_eq!(
        inspected
            .components
            .iter()
            .filter(|c| matches!(c.kind, ComponentKind::Hook(_)))
            .count(),
        3
    );
}

#[test]
fn claude_inline_command_maps_preserve_overrides_and_prompt_bytes() {
    let temp = tempfile::tempdir().unwrap();
    claude(
        temp.path(),
        json!({"commands":{
            "about":{"content":"Describe $ARGUMENTS; never execute it here.", "description":"About", "argumentHint":"[topic]", "model":"source-alias", "allowedTools":["Read"]},
            "renamed":{"source":"./custom/original.md", "description":"Override description"}
        }}),
    );
    write(
        temp.path(),
        "custom/original.md",
        "---\nname: original\ndescription: Original description\n---\nOriginal body.",
    );
    let mut options = InspectOptions::default();
    options
        .model_map
        .insert("source-alias".into(), "provider/model".into());
    let inspected = inspect(temp.path(), &options).unwrap();
    let commands: Vec<_> = inspected
        .components
        .iter()
        .filter_map(|c| {
            if let ComponentKind::Command(value) = &c.kind {
                Some(value)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].name, "sample:about");
    assert_eq!(commands[0].model.as_deref(), Some("provider/model"));
    assert_eq!(
        commands[0].prompt.as_deref(),
        Some("Describe $ARGUMENTS; never execute it here.")
    );
    assert_eq!(commands[1].name, "sample:renamed");
    assert_eq!(commands[1].description, "Override description");
    assert_eq!(commands[1].prompt.as_deref(), Some("Original body."));
}

#[test]
fn claude_unmapped_authority_and_deep_host_features_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    claude(
        temp.path(),
        json!({"unknownAuthority":{"allow":true}, "lspServers":{"example":{"command":"example-lsp"}}, "workflows":"./workflows/"}),
    );
    write(
        temp.path(),
        "workflows/example.js",
        "export default function () {}\n",
    );
    write(
        temp.path(),
        "agents/worker.md",
        "---\nname: worker\ndescription: sample\nmodel: foreign-alias\npermissionMode: bypassPermissions\n---\nbody",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "manifest_field_unmapped")
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "component_field_unmapped")
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "host_adapter_required")
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "model_mapping" && r.name == "foreign-alias" && !r.satisfied)
    );
    assert!(
        inspected
            .manifest
            .source_metadata
            .get("unknownAuthority")
            .is_some()
    );
    assert!(
        inspected
            .source
            .files
            .iter()
            .any(|f| f.path == "workflows/example.js")
    );
    assert!(inspected.migration.files.is_empty());
}

#[test]
fn claude_manifest_paths_cannot_escape_or_point_at_git_metadata() {
    let temp = tempfile::tempdir().unwrap();
    for path in [
        "../outside.md",
        "./../outside.md",
        "/absolute.md",
        "./.git/config",
        "./sub/../../outside.md",
        "commands/no-prefix.md",
    ] {
        claude(temp.path(), json!({"commands":path}));
        assert_eq!(
            error(temp.path()),
            "component_path_invalid",
            "path case: {path}"
        );
    }
    claude(temp.path(), json!({"agents":"./missing.md"}));
    assert_eq!(error(temp.path()), "source_component_missing");
    claude(temp.path(), json!({"agents":"./agents/"}));
    write(
        temp.path(),
        "agents/worker.md",
        "---\nname: worker\ndescription: sample\n---\nbody",
    );
    assert_eq!(error(temp.path()), "component_path_invalid");
}

#[test]
fn explicit_claude_selection_resolves_competing_roots_without_merging_them() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    claude(temp.path(), json!({"name":"claude-package"}));
    assert_eq!(error(temp.path()), "plugin_format_ambiguous");
    let options = InspectOptions {
        format: Some(PluginFormat::Claude),
        ..Default::default()
    };
    let inspected = inspect(temp.path(), &options).unwrap();
    assert_eq!(inspected.manifest.id, "claude-package");
    assert_eq!(inspected.source.format, PluginFormat::Claude);
}

#[test]
fn original_hookify_manifest_and_hook_contract_are_normalized_offline() {
    // Original manifest: anthropics/claude-plugins-official,
    // 054417d0fc687dd7d639331f21522d0e06c09cf9, plugins/hookify,
    // Apache-2.0. The synthetic hook command below is an envelope fixture.
    let temp = tempfile::tempdir().unwrap();
    write(
        temp.path(),
        ".claude-plugin/plugin.json",
        "{\n  \"name\": \"hookify\",\n  \"description\": \"Easily create hooks to prevent unwanted behaviors by analyzing conversation patterns\",\n  \"author\": {\n    \"name\": \"Anthropic\",\n    \"email\": \"support@anthropic.com\"\n  }\n}\n",
    );
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"python3 \"${CLAUDE_PLUGIN_ROOT}/hooks/pretooluse.py\"","timeout":10}]}]}}"#,
    );
    write(
        temp.path(),
        "hooks/pretooluse.py",
        "raise SystemExit('not during inspection')\n",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.manifest.id, "hookify");
    assert_eq!(inspected.components.len(), 1);
    let component = &inspected.components[0];
    let ComponentKind::Hook(hook) = &component.kind else {
        panic!("hook missing")
    };
    assert_eq!(hook.source_contract, "claude");
    assert_eq!(hook.timeout_secs, Some(10));
    assert_eq!(
        component.compatibility,
        orbit_plugin_compat::Compatibility::RequiresMigration
    );
}

#[test]
fn manifestless_claude_uses_validated_directory_identity() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("manifestless");
    write(
        &package,
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: sample\n---\nbody",
    );
    let inspected = inspect(&package, &InspectOptions::default()).unwrap();
    assert_eq!(inspected.source.format, PluginFormat::Claude);
    assert_eq!(inspected.source.manifest_path, None);
    assert_eq!(
        inspected.source.inferred_name.as_deref(),
        Some("manifestless")
    );
    assert_eq!(inspected.manifest.id, "manifestless");
    assert_eq!(inspected.manifest.source_metadata, Value::Null);
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "manifest_inferred")
    );
    let invalid = temp.path().join("invalid:name");
    fs::rename(&package, &invalid).unwrap();
    assert_eq!(error(&invalid), "plugin_id_invalid");
}

#[test]
fn claude_mcp_default_to_explicit_override_retains_source_provenance() {
    let temp = tempfile::tempdir().unwrap();
    claude(
        temp.path(),
        json!({"mcpServers":{"sample":{"command":"explicit-server","args":["--stdio"]}}}),
    );
    write(
        temp.path(),
        ".mcp.json",
        r#"{"mcpServers":{"sample":{"command":"default-server"}}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.components.len(), 1);
    let component = &inspected.components[0];
    let ComponentKind::Mcp(server) = &component.kind else {
        panic!("MCP server missing")
    };
    assert_eq!(server.command.as_deref(), Some("explicit-server"));
    assert_eq!(
        component.metadata["overridden"][0]["source_path"],
        ".mcp.json"
    );
    assert_eq!(
        component.metadata["overridden"][0]["definition"]["command"],
        "default-server"
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "mcp_source_override")
    );
    claude(
        temp.path(),
        json!({"mcpServers":[{"sample":{"command":"one"}},{"sample":{"command":"two"}}]}),
    );
    assert_eq!(error(temp.path()), "component_id_collision");
}

fn codex(root: &Path, extra: Value) {
    let mut manifest = json!({"name":"sample", "version":"1.0.0", "description":"A Codex package", "author":{"name":"Example"}, "interface":{"displayName":"Sample", "capabilities":[]}});
    manifest
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    write(
        root,
        ".codex-plugin/plugin.json",
        serde_json::to_vec(&manifest).unwrap(),
    );
}

#[test]
fn original_deja_codex_manifest_preserves_legacy_components_and_interface_assets() {
    // Original vshulcz/deja-vu manifest at c489a992d5eceb3b7b0479f8701746a245552135.
    // The MIT notice accompanying the original Deja fixture above also applies
    // here. The skill, hook and SVG contents below are controlled envelope fixtures.
    let manifest = r##"{
  "name": "deja-vu",
  "version": "0.21.7",
  "description": "deja-vu memory for Codex: your own past sessions, from every coding agent on the machine, recalled before you ask.",
  "author": {
    "name": "vshulcz",
    "url": "https://github.com/vshulcz"
  },
  "homepage": "https://vshulcz.github.io/deja-vu/guide/memory-for-codex.html",
  "repository": "https://github.com/vshulcz/deja-vu",
  "license": "MIT",
  "keywords": [
    "memory",
    "recall",
    "sessions",
    "search"
  ],
  "skills": "./skills/",
  "mcpServers": "./.mcp.json",
  "hooks": "./hooks/hooks.json",
  "interface": {
    "displayName": "deja-vu",
    "shortDescription": "Search and recall your own past AI coding sessions.",
    "longDescription": "deja indexes the sessions you already have on this machine — Claude Code, Codex, Cursor, opencode and thirty-four more agents — and gives Codex tools to search them. Ask what you fixed before instead of debugging it twice.",
    "developerName": "vshulcz",
    "category": "Productivity",
    "capabilities": [],
    "websiteURL": "https://github.com/vshulcz/deja-vu",
    "defaultPrompt": [
      "What did we decide about this last time?",
      "Have I hit this error before?"
    ],
    "privacyPolicyURL": "https://vshulcz.github.io/deja-vu/guide/privacy.html",
    "termsOfServiceURL": "https://github.com/vshulcz/deja-vu/blob/main/LICENSE",
    "composerIcon": "./assets/icon.svg",
    "logo": "./assets/logo.svg",
    "logoDark": "./assets/logo-dark.svg",
    "brandColor": "#1f6feb"
  }
}
"##;
    assert_eq!(
        hex::encode(Sha256::digest(manifest.as_bytes())),
        "bd36ea42d0b71e7e6e59a32213c6e0d35dfafd5a655d70b3fe8930cb7c90320a"
    );
    let temp = tempfile::tempdir().unwrap();
    write(temp.path(), ".codex-plugin/plugin.json", manifest);
    write(
        temp.path(),
        ".mcp.json",
        "{\n  \"mcpServers\": {\n    \"deja\": {\n      \"command\": \"deja\",\n      \"args\": [\"mcp\"]\n    }\n  }\n}\n",
    );
    write(
        temp.path(),
        "skills/deja-history/SKILL.md",
        "---\nname: deja-history\ndescription: Search prior sessions\n---\nUse the packaged memory tool.",
    );
    for asset in ["icon.svg", "logo.svg", "logo-dark.svg"] {
        write(
            temp.path(),
            &format!("assets/{asset}"),
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n",
        );
    }
    write(temp.path(), "hooks/hooks.json", serde_json::to_vec(&json!({"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"${PLUGIN_ROOT}/hooks/deja.sh hook-context","timeout":10,"statusMessage":"Recalling past sessions…"}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":"${PLUGIN_ROOT}/hooks/deja.sh hook-prompt","timeout":10}]}],"PreToolUse":[{"matcher":"Bash|apply_patch","hooks":[{"type":"command","command":"${PLUGIN_ROOT}/hooks/deja.sh hook-tool","timeout":10}]}],"PreCompact":[{"matcher":"manual|auto","hooks":[{"type":"command","command":"${PLUGIN_ROOT}/hooks/deja.sh hook-precompact","timeout":30}]}],"SessionEnd":[{"hooks":[{"type":"command","command":"${PLUGIN_ROOT}/hooks/deja.sh hook-session-end","timeout":10}]}]}})).unwrap());
    write(temp.path(), "hooks/deja.sh", "exit 99\n");
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.source.format, PluginFormat::Codex);
    assert_eq!(
        inspected.source.manifest_path.as_deref(),
        Some(".codex-plugin/plugin.json")
    );
    assert_eq!(inspected.manifest.id, "deja-vu");
    assert_eq!(inspected.components.len(), 7);
    assert_eq!(
        inspected
            .components
            .iter()
            .filter(|c| matches!(c.kind, ComponentKind::Hook(_)))
            .count(),
        5
    );
    assert!(
        inspected
            .components
            .iter()
            .filter_map(|c| if let ComponentKind::Hook(hook) = &c.kind {
                Some(hook)
            } else {
                None
            })
            .all(|hook| hook.source_contract == "codex")
    );
    let server = inspected
        .components
        .iter()
        .find_map(|c| {
            if let ComponentKind::Mcp(server) = &c.kind {
                Some(server)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(server.command.as_deref(), Some("deja"));
    assert_eq!(server.args, ["mcp"]);
    assert!(
        inspected
            .source
            .files
            .iter()
            .any(|f| f.path == "assets/logo-dark.svg")
    );
    assert!(
        !inspected
            .diagnostics
            .iter()
            .any(|d| d.severity == orbit_plugin_compat::DiagnosticSeverity::Error)
    );
}

#[test]
fn codex_inline_overlay_replaces_legacy_without_parsing_ignored_settings() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    let root = json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name":"canonical", "version":"2.0.0", "extensions":{"com.openai":{"interface":{"displayName":"Inline presentation"}, "hooks":"./hooks/selected.json"}}});
    write(
        temp.path(),
        "plugin.json",
        serde_json::to_vec(&root).unwrap(),
    );
    write(
        temp.path(),
        ".codex-plugin/plugin.json",
        "{ malformed and ignored legacy settings",
    );
    write(
        temp.path(),
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: sample\n---\ncanonical body",
    );
    write(temp.path(), "mcp.json", serde_json::to_vec(&json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers":{"canonical":{"type":"stdio","command":"canonical-server"}}})).unwrap());
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"ignored-default"}]}]}}"#,
    );
    write(
        temp.path(),
        "hooks/selected.json",
        r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"selected-hook"}]}]}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.manifest.id, "canonical");
    assert_eq!(inspected.manifest.version.as_deref(), Some("2.0.0"));
    assert_eq!(
        inspected.source.manifest_path.as_deref(),
        Some("plugin.json")
    );
    assert_eq!(inspected.components.len(), 3);
    let hook = inspected
        .components
        .iter()
        .find_map(|c| {
            if let ComponentKind::Hook(hook) = &c.kind {
                Some(hook)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(hook.command.as_deref(), Some("selected-hook"));
    assert_eq!(hook.source_contract, "codex");
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "openai_overlay_selected")
    );
}

#[test]
fn codex_fallback_overlay_cannot_replace_or_add_portable_components() {
    let temp = tempfile::tempdir().unwrap();
    portable(temp.path());
    codex(
        temp.path(),
        json!({"name":"ignored-legacy-name", "version":"9.9.9", "skills":"./missing-skills/", "mcpServers":"./missing-mcp.json", "hooks":[]}),
    );
    write(
        temp.path(),
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: sample\n---\ncanonical body",
    );
    write(temp.path(), "mcp.json", serde_json::to_vec(&json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers":{"canonical":{"type":"stdio","command":"canonical-server"}}})).unwrap());
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(inspected.manifest.id, "sample");
    assert_eq!(inspected.manifest.version.as_deref(), Some("1.2.3"));
    assert_eq!(inspected.components.len(), 2);
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "portable_component_precedence")
    );
    assert_eq!(
        inspected.manifest.source_metadata["openai_overlay"]["name"],
        "ignored-legacy-name"
    );
}

#[test]
fn codex_url_only_legacy_server_uses_documented_http_transport() {
    let temp = tempfile::tempdir().unwrap();
    codex(temp.path(), json!({"mcpServers":"./.mcp.json"}));
    write(
        temp.path(),
        ".mcp.json",
        r#"{"mcpServers":{"remote":{"url":"https://example.test/mcp","headers":{"Authorization":"Bearer ${EXAMPLE_TOKEN}"}}}}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let ComponentKind::Mcp(server) = &inspected.components[0].kind else {
        panic!("server missing")
    };
    assert_eq!(
        server.transport,
        orbit_plugin_compat::McpTransport::StreamableHttp
    );
    assert_eq!(server.url.as_deref(), Some("https://example.test/mcp"));
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "credential_env" && r.name == "EXAMPLE_TOKEN" && !r.satisfied)
    );
}

#[test]
fn codex_preserves_server_auth_extensions_and_requires_real_setup() {
    let temp = tempfile::tempdir().unwrap();
    write(temp.path(), "plugin.json", serde_json::to_vec(&json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name":"sample", "extensions":{"com.openai":{}}})).unwrap());
    let auth = json!({"type":"oauth", "client":{"mode":"provided", "clientId":"public-client", "tokenEndpointAuthMethod":"none"}, "authorizationUrl":"https://example.test/authorize", "tokenUrl":"https://example.test/token", "authorizationServerBase":"http://example.test/auth", "baseScopes":["read:notes"], "defaultScopes":[], "oidcEnabled":false, "oidcConfigurationUrl":"https://example.test/.well-known/openid-configuration", "oidcUserinfoEndpoint":"https://example.test/userinfo", "oidcScopesSupported":["openid"]});
    let mut mcp = json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers":{"remote":{"type":"streamable-http", "url":"https://example.test/mcp", "extensions":{"com.openai":{"auth":auth}}}}});
    write(temp.path(), "mcp.json", serde_json::to_vec(&mcp).unwrap());
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let ComponentKind::Mcp(server) = &inspected.components[0].kind else {
        panic!("server missing")
    };
    assert_eq!(server.auth.as_ref(), Some(&auth));
    assert_eq!(
        inspected.components[0].compatibility,
        orbit_plugin_compat::Compatibility::RequiresMigration
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "mcp_auth_setup" && !r.satisfied)
    );
    mcp["mcpServers"]["remote"]["extensions"]["com.openai"]["auth"]["clientSecret"] =
        json!("source-literal");
    write(temp.path(), "mcp.json", serde_json::to_vec(&mcp).unwrap());
    assert_eq!(error(temp.path()), "mcp_auth_invalid");
}

#[test]
fn codex_no_auth_preserves_transport_readiness_without_auth_setup() {
    let temp = tempfile::tempdir().unwrap();
    write(temp.path(), "plugin.json", serde_json::to_vec(&json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name":"sample", "extensions":{"com.openai":{}}})).unwrap());
    let mut mcp = json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers":{"remote":{"type":"streamable-http", "url":"https://example.test/mcp"}}});
    write(temp.path(), "mcp.json", serde_json::to_vec(&mcp).unwrap());
    let baseline = inspect(temp.path(), &InspectOptions::default()).unwrap();
    mcp["mcpServers"]["remote"]["extensions"] = json!({"com.openai":{"auth":{"type":"none"}}});
    write(temp.path(), "mcp.json", serde_json::to_vec(&mcp).unwrap());
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let component = &inspected.components[0];
    let ComponentKind::Mcp(server) = &component.kind else {
        panic!("server missing")
    };
    assert_eq!(server.auth, Some(json!({"type":"none"})));
    assert_eq!(component.metadata, mcp["mcpServers"]["remote"]);
    assert_eq!(
        component.compatibility,
        baseline.components[0].compatibility
    );
    assert_eq!(
        serde_json::to_value(&inspected.requirements).unwrap(),
        serde_json::to_value(&baseline.requirements).unwrap()
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "remote_mcp" && !r.satisfied)
    );
    assert!(
        !inspected
            .requirements
            .iter()
            .any(|r| r.kind == "mcp_auth_setup")
    );
    mcp["mcpServers"]["remote"]["extensions"]["com.openai"]["auth"] =
        json!({"type":"api_key", "headerScheme":"bearer"});
    write(temp.path(), "mcp.json", serde_json::to_vec(&mcp).unwrap());
    let api_key = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(
        api_key.components[0].compatibility,
        orbit_plugin_compat::Compatibility::RequiresMigration
    );
    assert!(
        api_key
            .requirements
            .iter()
            .any(|r| r.kind == "mcp_auth_setup" && !r.satisfied)
    );
}

#[test]
fn codex_onboarding_assets_and_unknown_authority_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let root = json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name":"sample", "extensions":{"com.openai":{"onboardingSkill":"./skills/setup/SKILL.md", "apps":"./.app.json", "autoApprove":true, "interface":{"logo":"./assets/logo.svg", "unknownAuthority":true}}}});
    write(
        temp.path(),
        "plugin.json",
        serde_json::to_vec(&root).unwrap(),
    );
    write(
        temp.path(),
        "skills/setup/SKILL.md",
        "---\nname: setup\ndescription: Configure the package\n---\nAsk for explicit preferences.",
    );
    write(temp.path(), "assets/logo.svg", "<svg/>");
    write(
        temp.path(),
        ".app.json",
        r#"{"apps":[{"id":"registered-example"}]}"#,
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "openai_overlay_field_unmapped")
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "onboarding_skill" && !r.satisfied)
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "registered_mcp_mapping" && !r.satisfied)
    );
    let skill = inspected
        .components
        .iter()
        .find(|c| matches!(c.kind, ComponentKind::Skill(_)))
        .unwrap();
    assert_eq!(skill.metadata["onboarding"], true);
    fs::remove_file(temp.path().join("assets/logo.svg")).unwrap();
    assert_eq!(error(temp.path()), "source_component_missing");
}

#[test]
fn codex_hook_override_and_overlay_types_never_fall_back_silently() {
    let temp = tempfile::tempdir().unwrap();
    codex(temp.path(), json!({"hooks":[]}));
    write(
        temp.path(),
        "hooks/hooks.json",
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"default-hook"}]}]}}"#,
    );
    assert!(
        inspect(temp.path(), &InspectOptions::default())
            .unwrap()
            .components
            .is_empty()
    );
    codex(temp.path(), json!({"hooks":null}));
    assert_eq!(error(temp.path()), "hook_field_invalid");
    write(temp.path(), "plugin.json", serde_json::to_vec(&json!({"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name":"sample", "extensions":{"com.openai":"invalid"}})).unwrap());
    assert_eq!(error(temp.path()), "manifest_field_invalid");
}

fn hermes(root: &Path, manifest: &str) {
    write(root, "plugin.yaml", manifest);
    write(
        root,
        "__init__.py",
        "raise RuntimeError('inspection must not import this package')\n",
    );
}

#[test]
fn original_hermes_manifests_preserve_declarations_without_inventing_callbacks() {
    // Original manifests from vshulcz/deja-vu c489a992d5eceb3b7b0479f8701746a245552135
    // (MIT, notice above), headroomlabs-ai/headroom 1ad92f0cbc3dea27676e253588100f64a2af6994
    // (Apache-2.0), and NousResearch/hermes-agent 25a71a744cb9ef06950a91638e6229b4f808d461
    // Their manifest glue is MIT, Copyright (c) 2025 Nous Research; the MIT
    // permission and warranty notice above applies to these manifest copies too.
    // Security-guidance's separate pattern implementation is Apache-2.0 and is
    // not included here.
    // The Python entry contents supplied by hermes() are controlled test envelopes.
    let sources = [
        (
            "deja-memory",
            "c666bb43ce0e5b80b25a99a7b79f9007a3c404198acb71921398ab81b0b640f1",
            r#"name: deja-memory
version: 0.1.0
description: "deja — memory from the coding sessions every agent on this machine already wrote to disk. No model, no key, no server."
external_dependencies:
  - name: deja
    install: "brew install deja-vu"
    check: "deja --version"
"#,
        ),
        (
            "headroom_retrieve",
            "14f1d1b956156007a02afba6443149fb95da2849015c814c24149fb32c39150a",
            r#"name: headroom_retrieve
version: 1.0.0
description: "Retrieve original content compressed by the headroom proxy (CCR markers)"
author: akb4q
provides_tools:
  - headroom_retrieve
"#,
        ),
        (
            "disk-cleanup",
            "82e30bc141d776c665a3772c824486e2f39d19782bb93d23df92d769b6f19597",
            r#"name: disk-cleanup
version: 2.0.0
description: "Auto-track and clean up ephemeral files (test scripts, temp outputs, cron logs) created during Hermes sessions. Runs via plugin hooks — no agent action required."
author: "@LVT382009 (original), NousResearch (plugin port)"
provides_hooks:
  - pre_tool_call
  - post_tool_call
  - on_session_end
"#,
        ),
        (
            "security-guidance",
            "8e4ad9fdd3cff41abdc71a6b5ae04b09328152460f0369e9e8ed0d8e64b2ad81",
            r#"name: security-guidance
version: "0.1.0"
description: "Append security warnings to file-write tool results when the new content contains known-dangerous patterns (pickle.load, yaml.load, eval(, os.system, dangerouslySetInnerHTML, verify=False, ECB, XXE, GitHub Actions injection, ...). 25 regex/substring rules forked from Anthropic's claude-plugins-official under Apache-2.0. Non-blocking — the file is written and the warning rides back to the model in the next turn so it can self-correct."
author: "Anthropic (patterns, Apache-2.0) / NousResearch (Hermes plugin port)"
provides_hooks:
  - transform_tool_result
  - pre_tool_call
"#,
        ),
    ];
    for (name, digest, manifest) in sources {
        assert_eq!(
            hex::encode(Sha256::digest(manifest.as_bytes())),
            digest,
            "{name}"
        );
        let temp = tempfile::tempdir().unwrap();
        hermes(temp.path(), manifest);
        let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
        assert_eq!(inspected.source.format, PluginFormat::Hermes);
        assert_eq!(
            inspected.source.manifest_path.as_deref(),
            Some("plugin.yaml")
        );
        assert_eq!(inspected.manifest.id, name);
        assert_eq!(inspected.components.len(), 1);
        let component = &inspected.components[0];
        let ComponentKind::PythonRuntime(runtime) = &component.kind else {
            panic!("native runtime missing")
        };
        assert_eq!(runtime.entry, "__init__.py");
        assert_eq!(component.id, format!("{name}:python_runtime:register"));
        assert_eq!(
            component.compatibility,
            orbit_plugin_compat::Compatibility::RequiresMigration
        );
        assert_eq!(
            component.metadata["source_manifest"],
            inspected.manifest.source_metadata
        );
        assert_eq!(component.metadata["registration"]["discovered"], false);
        assert!(
            inspected
                .requirements
                .iter()
                .any(|r| r.kind == "python_runtime" && !r.satisfied)
        );
        let declarations = inspected
            .manifest
            .source_metadata
            .get("provides_tools")
            .or_else(|| inspected.manifest.source_metadata.get("provides_hooks"));
        if let Some(declarations) = declarations {
            for declaration in declarations.as_array().unwrap() {
                assert!(
                    inspected
                        .requirements
                        .iter()
                        .any(|r| r.name == declaration.as_str().unwrap() && !r.satisfied)
                );
            }
        }
        if name == "deja-memory" {
            assert!(
                inspected
                    .requirements
                    .iter()
                    .any(|r| r.kind == "external_dependency" && r.name == "deja" && !r.satisfied)
            );
            assert!(
                !inspected
                    .components
                    .iter()
                    .any(|c| matches!(c.kind, ComponentKind::MemoryProvider(_)))
            );
        }
        assert_eq!(
            fs::read(temp.path().join("plugin.yaml")).unwrap(),
            manifest.as_bytes()
        );
    }
}

#[test]
fn hermes_inspection_does_not_import_or_run_dependency_commands() {
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("execution-marker");
    hermes(
        temp.path(),
        "name: sample\npython_dependencies: ['example>=1,<2', 'other; python_version >= \"3.11\"']\nexternal_dependencies:\n  - name: example\n    check: 'touch execution-marker'\n    install: 'touch execution-marker'\n",
    );
    let entry = format!(
        "from pathlib import Path\nPath({:?}).touch()\ndef register(ctx):\n    raise RuntimeError('must not register')\n",
        marker.to_string_lossy()
    );
    write(temp.path(), "__init__.py", &entry);
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(!marker.exists());
    assert_eq!(
        fs::read_to_string(temp.path().join("__init__.py")).unwrap(),
        entry
    );
    let ComponentKind::PythonRuntime(runtime) = &inspected.components[0].kind else {
        panic!("runtime missing")
    };
    assert_eq!(
        runtime.dependencies,
        ["example>=1,<2", "other; python_version >= \"3.11\""]
    );
    assert_eq!(
        inspected
            .requirements
            .iter()
            .filter(|r| r.kind == "python_dependency" && !r.satisfied)
            .count(),
        2
    );
    assert!(inspected.migration.files.is_empty());
}

#[test]
fn hermes_python_project_precedence_preserves_requirements_and_constraints() {
    let temp = tempfile::tempdir().unwrap();
    hermes(
        temp.path(),
        "name: sample\npython_dependencies: false\npip_dependencies: [ignored]\napi_version: 1\n",
    );
    let requirement = "example>=1,<2; python_version >= '3.11'";
    write(
        temp.path(),
        "pyproject.toml",
        "[project]\nname = 'sample'\ndependencies = [\"example>=1,<2; python_version >= '3.11'\"]\nrequires-python = '>=3.11,<4'\n[build-system]\nrequires = ['setuptools>=70,<80']\nbuild-backend = 'setuptools.build_meta'\n",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let component = &inspected.components[0];
    let ComponentKind::PythonRuntime(runtime) = &component.kind else {
        panic!("runtime missing")
    };
    assert_eq!(runtime.dependencies, [requirement]);
    assert_eq!(runtime.python.as_deref(), Some(">=3.11,<4"));
    assert_eq!(runtime.api_version.as_deref(), Some("1"));
    assert_eq!(component.metadata["dependency_source"], "pyproject.toml");
    assert_eq!(
        component.metadata["pyproject"]["build-system"]["build-backend"],
        "setuptools.build_meta"
    );
    assert_eq!(
        inspected.manifest.source_metadata["python_dependencies"],
        false
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "hermes_dependency_precedence")
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "python_constraint" && !r.satisfied)
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "python_project" && !r.satisfied)
    );
}

#[test]
fn hermes_legacy_dependency_aliases_and_external_runtime_remain_explicit() {
    let temp = tempfile::tempdir().unwrap();
    hermes(
        temp.path(),
        "name: sample\npip_dependencies: ['first>=1,<2', shared]\npython_dependencies: [shared, second]\npython_runtime: external\nmanifest_version: 2\n",
    );
    write(
        temp.path(),
        "pyproject.toml",
        "# GENERATED by pm\nlegacy ignored text\n",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    let ComponentKind::PythonRuntime(runtime) = &inspected.components[0].kind else {
        panic!("runtime missing")
    };
    assert_eq!(runtime.dependencies, ["first>=1,<2", "shared", "second"]);
    assert_eq!(runtime.python, None);
    assert_eq!(
        inspected.components[0].metadata["dependency_source"],
        "plugin.yaml"
    );
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "hermes_host_mapping" && r.name == "python_runtime" && !r.satisfied)
    );
    assert!(
        !inspected
            .requirements
            .iter()
            .any(|r| r.kind == "python_project")
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "hermes_dependency_precedence")
    );
}

#[test]
fn hermes_host_authority_and_environment_declarations_are_not_silently_dropped() {
    let temp = tempfile::tempdir().unwrap();
    hermes(
        temp.path(),
        "name: sample\nrequires_env:\n  - PATH\n  - name: EXAMPLE_TOKEN\n    description: Service key\n    secret: true\noptional_env: [OPTIONAL_EXAMPLE_TOKEN]\ncapabilities: [tools.override]\nrequires_plugins: [other, {id: dependency, version_range: '>=1,<2'}]\nconfig_schema: {token: {type: secret}}\nprovides_commands: [example]\nprovides_memory_provider: memory\nprovides_ui: {panes: [overview]}\nprovides_middleware: [pre_llm]\nnotes: {reference: preserved}\n",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    for name in ["PATH", "EXAMPLE_TOKEN"] {
        assert!(
            inspected
                .requirements
                .iter()
                .any(|r| r.kind == "credential_env" && r.name == name && !r.satisfied)
        );
    }
    assert!(
        !inspected
            .requirements
            .iter()
            .any(|r| r.name == "OPTIONAL_EXAMPLE_TOKEN")
    );
    for field in [
        "config_schema",
        "provides_commands",
        "provides_memory_provider",
        "provides_ui",
        "provides_middleware",
    ] {
        assert!(
            inspected
                .requirements
                .iter()
                .any(|r| r.kind == "hermes_host_mapping" && r.name == field && !r.satisfied)
        );
    }
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "capability_consent" && r.name == "tools.override" && !r.satisfied)
    );
    assert_eq!(
        inspected
            .requirements
            .iter()
            .filter(|r| r.kind == "plugin_dependency" && !r.satisfied)
            .count(),
        2
    );
    assert_eq!(
        inspected.manifest.source_metadata["notes"]["reference"],
        "preserved"
    );
    assert_eq!(inspected.components.len(), 1);
}

#[test]
fn hermes_inferred_identity_and_competing_formats_require_exact_selection() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("native-package");
    hermes(&root, "description: Uses its original package directory\n");
    let inspected = inspect(&root, &InspectOptions::default()).unwrap();
    assert_eq!(inspected.manifest.id, "native-package");
    assert_eq!(
        inspected.source.inferred_name.as_deref(),
        Some("native-package")
    );
    assert_eq!(
        inspected.source.manifest_path.as_deref(),
        Some("plugin.yaml")
    );
    portable(&root);
    assert_eq!(error(&root), "plugin_format_ambiguous");
    let options = InspectOptions {
        format: Some(PluginFormat::Hermes),
        ..InspectOptions::default()
    };
    assert_eq!(
        inspect(&root, &options).unwrap().manifest.id,
        "native-package"
    );
    fs::remove_file(root.join("plugin.json")).unwrap();
    hermes(&root, "name: 'invalid:name'\n");
    assert_eq!(error(&root), "plugin_id_invalid");
    hermes(&root, "name: sample\nentry: ../../outside.py\n");
    let inspected = inspect(&root, &InspectOptions::default()).unwrap();
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.name == "entry" && !r.satisfied)
    );
    let ComponentKind::PythonRuntime(runtime) = &inspected.components[0].kind else {
        panic!("runtime missing")
    };
    assert_eq!(runtime.entry, "__init__.py");
    fs::remove_file(root.join("__init__.py")).unwrap();
    assert_eq!(error(&root), "source_component_missing");
}

#[test]
fn hermes_reuses_bounded_yaml_and_rejects_malformed_python_projects() {
    let temp = tempfile::tempdir().unwrap();
    for (manifest, expected) in [
        ("name: sample\nname: repeated\n", "yaml_duplicate_key"),
        (
            "name: &alias sample\nversion: *alias\n",
            "yaml_alias_unsupported",
        ),
        ("[sample]\n", "yaml_root_type"),
        (
            "name: sample\nprovides_tools: true\n",
            "manifest_field_invalid",
        ),
    ] {
        hermes(temp.path(), manifest);
        assert_eq!(error(temp.path()), expected, "{expected}");
    }
    hermes(temp.path(), "name: sample\n");
    for (project, expected) in [
        (
            "[project]\nname='sample'\nname='duplicate'\n",
            "manifest_toml_invalid",
        ),
        ("[project]\ndependencies=[42]\n", "manifest_field_invalid"),
        (
            "[project]\nrequires-python=false\n",
            "manifest_field_invalid",
        ),
    ] {
        write(temp.path(), "pyproject.toml", project);
        assert_eq!(error(temp.path()), expected, "{expected}");
    }
    write(
        temp.path(),
        "pyproject.toml",
        format!("#{}", "x".repeat(256 * 1024)),
    );
    assert_eq!(error(temp.path()), "manifest_size_limit");
}

#[test]
fn hermes_hook_alias_precedence_and_host_assets_preserve_remaining_contracts() {
    let temp = tempfile::tempdir().unwrap();
    hermes(
        temp.path(),
        "name: sample\nprovides_hooks: [pre_tool_call]\nhooks: invalid-ignored-alias\n",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(
        inspected
            .requirements
            .iter()
            .filter(|r| r.kind == "runtime_hook")
            .count(),
        1
    );
    assert!(
        inspected
            .diagnostics
            .iter()
            .any(|d| d.code == "hermes_hook_declaration_precedence")
    );
    assert!(
        !inspected
            .components
            .iter()
            .any(|c| matches!(c.kind, ComponentKind::Hook(_)))
    );
    hermes(temp.path(), "name: sample\nhooks: [on_session_end]\n");
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "runtime_hook" && r.name == "on_session_end" && !r.satisfied)
    );
    write(
        temp.path(),
        "desktop/plugin.js",
        "throw new Error('do not execute');\n",
    );
    fs::remove_file(temp.path().join("__init__.py")).unwrap();
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(inspected.components.is_empty());
    assert!(
        inspected
            .requirements
            .iter()
            .any(|r| r.kind == "host_adapter" && r.name == "desktop/plugin.js" && !r.satisfied)
    );
}

#[test]
fn hermes_yml_alias_preserves_inferred_identity_and_actual_source_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("alias-package");
    let manifest = "description: Uses the short YAML extension\npython_dependencies: [example]\nprovides_hooks: [pre_tool_call]\nhooks: ignored\noptional_env: [OPTIONAL_EXAMPLE_TOKEN]\nprovides_commands: [example]\n";
    hermes(&root, manifest);
    fs::rename(root.join("plugin.yaml"), root.join("plugin.yml")).unwrap();
    let inspected = inspect(&root, &InspectOptions::default()).unwrap();
    assert_eq!(inspected.source.format, PluginFormat::Hermes);
    assert_eq!(
        inspected.source.manifest_path.as_deref(),
        Some("plugin.yml")
    );
    assert_eq!(
        inspected.source.inferred_name.as_deref(),
        Some("alias-package")
    );
    assert_eq!(inspected.manifest.id, "alias-package");
    assert_eq!(
        inspected.manifest.source_metadata["description"],
        "Uses the short YAML extension"
    );
    assert_eq!(
        inspected.components[0].metadata["source_manifest"],
        inspected.manifest.source_metadata
    );
    assert_eq!(
        inspected.components[0].metadata["dependency_source"],
        "plugin.yml"
    );
    for code in [
        "manifest_inferred",
        "hermes_hook_declaration_precedence",
        "hermes_optional_environment",
        "hermes_field_unmapped",
    ] {
        assert!(
            inspected
                .diagnostics
                .iter()
                .any(|d| d.code == code && d.source_path.as_deref() == Some("plugin.yml")),
            "{code}"
        );
    }
    assert!(
        inspected
            .diagnostics
            .iter()
            .chain(&inspected.migration.diagnostics)
            .all(|d| d.source_path.as_deref() != Some("plugin.yaml"))
    );
    assert_eq!(
        fs::read(root.join("plugin.yml")).unwrap(),
        manifest.as_bytes()
    );
    write(&root, "plugin.yml", "name: sample\nprovides_tools: true\n");
    assert_eq!(error(&root), "manifest_field_invalid");
}

#[test]
fn hermes_yaml_precedes_yml_and_never_parses_or_falls_back_to_ignored_manifest() {
    let temp = tempfile::tempdir().unwrap();
    hermes(temp.path(), "name: preferred\nversion: 1.2.3\n");
    let ignored = "name: [malformed ignored YAML\n";
    write(temp.path(), "plugin.yml", ignored);
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(
        inspected.source.manifest_path.as_deref(),
        Some("plugin.yaml")
    );
    assert_eq!(inspected.manifest.id, "preferred");
    assert_eq!(inspected.manifest.source_metadata["version"], "1.2.3");
    assert_eq!(
        inspected.components[0].metadata["dependency_source"],
        "plugin.yaml"
    );
    assert!(
        inspected
            .source
            .files
            .iter()
            .any(|file| file.path == "plugin.yml"
                && file.sha256 == hex::encode(Sha256::digest(ignored.as_bytes())))
    );
    write(
        temp.path(),
        "plugin.yaml",
        "name: [malformed selected YAML\n",
    );
    write(temp.path(), "plugin.yml", "name: valid-ignored-fallback\n");
    assert_eq!(error(temp.path()), "yaml_invalid");
}

#[test]
fn hermes_python_project_depth_and_node_limits_reject_bounded_large_structures() {
    let temp = tempfile::tempdir().unwrap();
    hermes(temp.path(), "name: sample\n");
    let boundary_depth = vec!["level"; 31].join(".");
    write(
        temp.path(),
        "pyproject.toml",
        format!("[{boundary_depth}]\nvalue=0\n"),
    );
    assert!(inspect(temp.path(), &InspectOptions::default()).is_ok());
    let excessive_depth = vec!["level"; 33].join(".");
    write(
        temp.path(),
        "pyproject.toml",
        format!("[{excessive_depth}]\nvalue=0\n"),
    );
    assert_eq!(error(temp.path()), "manifest_structure_limit");
    // Root table, metadata table and array consume three of the 8192 nodes.
    write(
        temp.path(),
        "pyproject.toml",
        format!("[metadata]\nvalues=[{}]\n", vec!["0"; 8189].join(",")),
    );
    assert!(inspect(temp.path(), &InspectOptions::default()).is_ok());
    write(
        temp.path(),
        "pyproject.toml",
        format!("[metadata]\nvalues=[{}]\n", vec!["0"; 8190].join(",")),
    );
    assert_eq!(error(temp.path()), "manifest_structure_limit");
}

#[test]
fn hermes_quoted_positive_versions_preserve_authored_yaml_and_normalize_generations() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = "name: sample\nmanifest_version: ' +002 '\napi_version: '0001'\nprovides_commands: [example]\n";
    hermes(temp.path(), manifest);
    fs::rename(
        temp.path().join("plugin.yaml"),
        temp.path().join("plugin.yml"),
    )
    .unwrap();
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert_eq!(
        inspected.source.manifest_path.as_deref(),
        Some("plugin.yml")
    );
    assert_eq!(
        inspected.manifest.source_metadata["manifest_version"],
        " +002 "
    );
    assert_eq!(inspected.manifest.source_metadata["api_version"], "0001");
    let ComponentKind::PythonRuntime(runtime) = &inspected.components[0].kind else {
        panic!("runtime missing")
    };
    assert_eq!(runtime.api_version.as_deref(), Some("1"));
    assert!(
        !inspected
            .requirements
            .iter()
            .any(|r| r.kind == "hermes_host_mapping" && r.name == "manifest_version")
    );
    assert!(inspected.diagnostics.iter().any(
        |d| d.code == "hermes_field_unmapped" && d.source_path.as_deref() == Some("plugin.yml")
    ));
    assert_eq!(
        fs::read(temp.path().join("plugin.yml")).unwrap(),
        manifest.as_bytes()
    );
    write(
        temp.path(),
        "plugin.yml",
        "name: sample\nmanifest_version: '3'\napi_version: '18446744073709551615'\n",
    );
    let future = inspect(temp.path(), &InspectOptions::default()).unwrap();
    assert!(
        future
            .requirements
            .iter()
            .any(|r| r.name == "manifest_version" && !r.satisfied)
    );
    let ComponentKind::PythonRuntime(runtime) = &future.components[0].kind else {
        panic!("runtime missing")
    };
    assert_eq!(runtime.api_version.as_deref(), Some("18446744073709551615"));
}

#[test]
fn hermes_versions_reject_nonpositive_fraction_boolean_invalid_and_overflow_values() {
    let temp = tempfile::tempdir().unwrap();
    for field in ["api_version", "manifest_version"] {
        for invalid in [
            "0",
            "-1",
            "1.5",
            "true",
            "false",
            "null",
            "''",
            "'+'",
            "'-1'",
            "'1.5'",
            "'1e0'",
            "'invalid'",
            "'18446744073709551616'",
        ] {
            hermes(temp.path(), &format!("name: sample\n{field}: {invalid}\n"));
            assert_eq!(
                error(temp.path()),
                "manifest_field_invalid",
                "{field}: {invalid}"
            );
        }
    }
}

#[test]
fn hermes_qualified_dependency_references_are_preserved_without_becoming_local_ids() {
    let temp = tempfile::tempdir().unwrap();
    hermes(
        temp.path(),
        "name: sample\nrequires_plugins:\n  - community/example\n  - id: browser/provider.name\n    version_range: '>=1,<2'\n  - orbit\n",
    );
    let inspected = inspect(temp.path(), &InspectOptions::default()).unwrap();
    for reference in ["community/example", "browser/provider.name", "orbit"] {
        assert!(
            inspected
                .requirements
                .iter()
                .any(|r| r.kind == "plugin_dependency" && r.name == reference && !r.satisfied),
            "{reference}"
        );
    }
    assert_eq!(
        inspected.manifest.source_metadata["requires_plugins"][0],
        "community/example"
    );
    assert_eq!(
        inspected.manifest.source_metadata["requires_plugins"][1]["id"],
        "browser/provider.name"
    );
    assert_eq!(
        inspected.manifest.source_metadata["requires_plugins"][1]["version_range"],
        ">=1,<2"
    );
    assert_eq!(inspected.components.len(), 1);
    let oversized = "x".repeat(257);
    for reference in [
        "",
        "   ",
        "/absolute",
        "../escape",
        "community/../escape",
        "community//example",
        "community/example/",
        "community\\example",
        "community/ex\nample",
        "community/ex\u{7f}ample",
        oversized.as_str(),
    ] {
        let manifest = json!({"name":"sample", "requires_plugins":[reference]})
            .to_string()
            .replace('\u{7f}', "\\u007f");
        hermes(temp.path(), &manifest);
        assert_eq!(
            error(temp.path()),
            "manifest_field_invalid",
            "invalid reference must be rejected: {reference:?}"
        );
    }
    hermes(
        temp.path(),
        "name: orbit\nrequires_plugins: [community/example]\n",
    );
    assert_eq!(error(temp.path()), "plugin_id_invalid");
}

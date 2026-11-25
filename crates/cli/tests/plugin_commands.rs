#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    work: PathBuf,
    source: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-plugin-cli-{}", ulid::Ulid::new()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            home: root.join("home"),
            work: root.join("workspace"),
            source: root.join("source"),
            root,
        };
        for path in [&fixture.home, &fixture.work, &fixture.source] {
            fs::create_dir(path).unwrap();
        }
        fs::write(
            fixture.home.join("providers.toml"),
            "deliberately invalid provider configuration\n",
        )
        .unwrap();
        fs::write(fixture.home.join("operator-file"), "preserve these bytes\n").unwrap();
        fs::create_dir(fixture.work.join(".orbit")).unwrap();
        fs::write(
            fixture.work.join(".orbit/settings.toml"),
            "operator settings\n",
        )
        .unwrap();
        fixture.write("plugin.json", serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name":"portable-sample", "version":"1.2.3", "license":"MIT", "description":"Inspect the sample safely"
        })).unwrap());
        fixture.write("skills/review/SKILL.md", "---\nname: review\ndescription: Review a local change\nallowed-tools: [Read]\n---\nRead the change and summarize it.\n");
        fixture.write("mcp.json", serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers":{"sample":{"type":"stdio","command":"sh","args":["-c",format!("printf executed > '{}'",fixture.root.join("execution-marker").display())],"env":{"SAMPLE_TOKEN":"${SAMPLE_TOKEN}"}}}
        })).unwrap());
        fixture
    }

    fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        let target = self.source.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_in(&self.work, args)
    }

    fn run_in(&self, project: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_orbit"))
            .env_clear()
            .env("HOME", &self.home)
            .env("ORBIT_HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.root.join("xdg-config"))
            .env("XDG_CACHE_HOME", self.root.join("xdg-cache"))
            .env("XDG_DATA_HOME", self.root.join("xdg-data"))
            .env("CODEX_HOME", self.root.join("codex"))
            .env("CLAUDE_CONFIG_DIR", self.root.join("claude"))
            .env("HERMES_HOME", self.root.join("hermes"))
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("SAMPLE_TOKEN", "ambient-fixture-value-must-never-be-read")
            .current_dir(project)
            .args(args)
            .output()
            .unwrap()
    }

    fn source_arg(&self) -> &str {
        self.source.to_str().unwrap()
    }

    fn inventory(&self) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
        fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
            let metadata = fs::symlink_metadata(path).unwrap();
            let bytes = if metadata.is_file() {
                fs::read(path).unwrap()
            } else {
                Vec::new()
            };
            result.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                (metadata.permissions().mode(), bytes),
            );
            if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), result);
                }
            }
        }
        let mut result = BTreeMap::new();
        visit(&self.root, &self.root, &mut result);
        result
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inspect_json_and_human_use_actual_binary_without_initializing_or_executing() {
    let fixture = Fixture::new();
    let before = fixture.inventory();
    let output = fixture.run(&[
        "plugin",
        "inspect",
        fixture.source_arg(),
        "--format",
        "portable",
        "--json",
    ]);
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "orbit.cli/v1");
    assert_eq!(report["command"], "plugin inspect");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["inspection"]["source"]["format"], "portable");
    assert_eq!(report["inspection"]["manifest"]["name"], "portable-sample");
    assert_eq!(
        report["inspection"]["components"].as_array().unwrap().len(),
        2
    );
    assert!(stdout(&output).contains("${SAMPLE_TOKEN}"));
    assert!(!stdout(&output).contains("ambient-fixture-value-must-never-be-read"));
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg()]);
    success(&output);
    let human = stdout(&output);
    for expected in [
        "Plugin: portable-sample",
        "Format: portable",
        "Version: 1.2.3",
        "Components:",
        "Requirements:",
        "Diagnostics:",
        "inspection_only",
    ] {
        assert!(
            human.contains(expected),
            "missing human metadata: {expected}"
        );
    }
    assert!(!human.contains("Read the change and summarize it."));
    assert_eq!(fixture.inventory(), before);
    assert!(!fixture.root.join("execution-marker").exists());
    assert!(!fixture.home.join("identity").exists());
}

#[test]
fn inspect_accepts_json_before_plugin_and_explicit_mapping_flags() {
    let fixture = Fixture::new();
    let before = fixture.inventory();
    let output = fixture.run(&[
        "--json",
        "plugin",
        "inspect",
        fixture.source_arg(),
        "--model-map",
        "fast=primary/model",
        "--tool-map",
        "Read=Read",
        "--tool-map",
        "Write=Write",
    ]);
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["command"], "plugin inspect");
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_rejects_ambiguous_or_unknown_arguments_without_state_changes() {
    let fixture = Fixture::new();
    let before = fixture.inventory();
    let cases = [
        vec!["plugin", "inspect"],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            fixture.source_arg(),
        ],
        vec!["plugin", "inspect", fixture.source_arg(), "--unknown"],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "-p",
            "must not run",
        ],
        vec!["plugin", "inspect", fixture.source_arg(), "--format"],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "--format",
            "invalid",
        ],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "--format",
            "portable",
            "--format",
            "portable",
        ],
        vec!["plugin", "inspect", fixture.source_arg(), "--model-map"],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "--model-map",
            "source=",
        ],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "--model-map",
            "=target",
        ],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "--tool-map",
            "A=B=C",
        ],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "--tool-map",
            "Read=Read",
            "--tool-map",
            "Read=Write",
        ],
        vec![
            "plugin",
            "inspect",
            fixture.source_arg(),
            "--json",
            "--json",
        ],
        vec!["plugin", "enable"],
    ];
    for args in cases {
        let output = fixture.run(&args);
        assert_eq!(
            output.status.code(),
            Some(64),
            "arguments: {args:?}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "usage failure must not print a success record"
        );
    }
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_help_only_advertises_implemented_operations() {
    let fixture = Fixture::new();
    let before = fixture.inventory();
    for args in [
        vec!["plugin", "help"],
        vec!["plugin", "--help"],
        vec!["plugin", "-h"],
        vec!["plugin", "inspect", "--help"],
        vec!["plugin", "inspect", "-h"],
    ] {
        let output = fixture.run(&args);
        success(&output);
        let human = stdout(&output);
        assert!(human.contains("orbit plugin inspect PATH"));
        assert!(human.contains("plugin import|install PATH"));
        assert!(human.contains("plugin list"));
        assert!(human.contains("plugin status ID"));
        assert!(human.contains("plugin enable|disable|remove ID"));
        assert!(human.contains("plugin upgrade ID PATH"));
        assert!(!human.contains("plugin migrate"));
        assert!(!human.contains("plugin doctor"));
    }
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_errors_keep_parser_code_and_withhold_source_values() {
    let fixture = Fixture::new();
    fixture.write(
        "plugin.json",
        "{\"credential\":\"malformed-fixture-secret\"",
    );
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg(), "--json"]);
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("json_invalid"),
        "parser code was lost: {error}"
    );
    assert!(!error.contains("malformed-fixture-secret"));
    assert!(!error.contains(fixture.source_arg()));
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_redacts_literal_credentials_before_json_and_human_output() {
    let fixture = Fixture::new();
    let token = "ghp_0123456789abcdef0123456789abcdef012345";
    fixture.write("plugin.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name":"portable-sample", "version":"1.2.3",
        "description":format!("short sk-word then {token}; literal-fixture-value; https://example.test/path?unusual=private-query-value\u{202e}\u{001b}"),
        "extensions":{"dev.example":{"password":"tiny-fixture-password", "client_secret":"tiny-fixture-client-secret", "max_tokens":4096, "context_window":32768}}
    })).unwrap());
    fixture.write("mcp.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers":{
            "stdio":{"type":"stdio","command":"example-server","env":{"VISIBLE_NAME":"literal-fixture-value", "REFERENCED":"${SAMPLE_TOKEN}"}},
            "remote":{"type":"streamable-http","url":"https://example.test/mcp?custom=remote-query-secret", "headers":{"Authorization":"short-fixture-bearer", "X-Custom":"custom-header-literal", "X-Reference":"${SAMPLE_TOKEN}"}}
        }
    })).unwrap());
    let before = fixture.inventory();
    for suffix in [vec!["--json"], Vec::new()] {
        let json_output = !suffix.is_empty();
        let mut args = vec!["plugin", "inspect", fixture.source_arg()];
        args.extend(suffix);
        let output = fixture.run(&args);
        success(&output);
        let output = stdout(&output);
        for secret in [
            token,
            "literal-fixture-value",
            "tiny-fixture-password",
            "tiny-fixture-client-secret",
            "private-query-value",
            "remote-query-secret",
            "short-fixture-bearer",
            "custom-header-literal",
            "ambient-fixture-value-must-never-be-read",
        ] {
            assert!(
                !output.contains(secret),
                "a source credential escaped inspection output"
            );
        }
        assert!(!output.contains(['\u{202e}', '\u{001b}']));
        if json_output {
            let report: Value = serde_json::from_str(&output).unwrap();
            assert!(output.contains("${SAMPLE_TOKEN}"));
            assert!(output.contains("[configured literal]"));
            assert_eq!(
                report["inspection"]["manifest"]["source_metadata"]["extensions"]["dev.example"]["max_tokens"],
                4096
            );
            assert_eq!(
                report["inspection"]["manifest"]["source_metadata"]["extensions"]["dev.example"]["context_window"],
                32768
            );
        }
    }
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_bounds_hostile_descriptions_and_body_output() {
    let fixture = Fixture::new();
    fixture.write(
        "skills/review/SKILL.md",
        format!(
            "---\nname: review\ndescription: A bounded package\n---\n{}",
            "x".repeat(128 * 1024)
        ),
    );
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg(), "--json"]);
    success(&output);
    assert!(output.stdout.len() < 256 * 1024);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["display_truncated"], true);
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_preserves_typed_identifiers_and_computed_hashes_with_benign_literals() {
    let fixture = Fixture::new();
    fixture.write(
        "plugin.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name":"portable-sample", "version":"1.2.3",
            "extensions":{"dev.example":{"a\u{202e}b":"first value", "ab":"second value",
                "bytes":[1,2,3], "b\u{202e}ytes":[83,69,67]}}
        }))
        .unwrap(),
    );
    fixture.write(
        "mcp.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers":{"sample":{"type":"stdio","command":"example-server",
                "env":{"PYTHONUNBUFFERED":"1", "LABEL":"name", "PAYLOAD_LABEL":"bytes"}}}
        }))
        .unwrap(),
    );
    let expected = orbit_plugin_compat::inspect(&fixture.source, &Default::default()).unwrap();
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg(), "--json"]);
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let actual = &report["inspection"];
    assert_eq!(actual["manifest"]["name"], "portable-sample");
    assert_eq!(actual["manifest"]["version"], "1.2.3");
    assert_eq!(
        actual["source"]["source_digest"],
        expected.source.source_digest
    );
    assert_eq!(
        actual["source"]["files"],
        serde_json::to_value(&expected.source.files).unwrap()
    );
    assert_eq!(
        actual["manifest"]["source_metadata"]["name"],
        "portable-sample"
    );
    let extension = actual["manifest"]["source_metadata"]["extensions"]["dev.example"]
        .as_object()
        .unwrap();
    assert_eq!(
        extension.len(),
        4,
        "sanitized metadata keys must not collide"
    );
    assert!(extension.values().any(|value| value == "first value"));
    assert!(extension.values().any(|value| value == "second value"));
    assert_eq!(
        extension
            .values()
            .filter(|value| value.as_str() == Some("[file payload withheld]"))
            .count(),
        2
    );
    let mcp = actual["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["kind"]["type"] == "mcp")
        .unwrap();
    assert_eq!(
        mcp["kind"]["spec"]["env"]["PYTHONUNBUFFERED"],
        "[configured literal]"
    );
    let human = fixture.run(&["plugin", "inspect", fixture.source_arg()]);
    success(&human);
    assert!(stdout(&human).contains("Version: 1.2.3"));
    assert!(stdout(&human).contains("Plugin: portable-sample"));
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_matches_overlapping_credentials_once_without_rescanning_markers() {
    let fixture = Fixture::new();
    fixture.write("plugin.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name":"portable-sample", "version":"1.2.3", "description":"aba ab a Bearer tiny",
        "extensions":{"dev.example":{"password":"a", "token":"ab", "client_secret":"aba", "api_key":"Bearer tiny"}}
    })).unwrap());
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg(), "--json"]);
    success(&output);
    assert!(output.stdout.len() < 32 * 1024);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["inspection"]["manifest"]["description"],
        "[configured literal] [configured literal] [configured literal] [configured literal]"
    );
    assert!(
        report["inspection"]["manifest"]["name"]
            .as_str()
            .unwrap()
            .contains("[configured literal]")
    );
    assert_eq!(report["inspection"]["manifest"]["version"], "1.2.3");
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_bounds_alphabet_configuration_without_marker_expansion() {
    let fixture = Fixture::new();
    let env: serde_json::Map<String, Value> = (b'a'..=b'z')
        .map(|letter| {
            (
                format!("SETTING_{}", char::from(letter).to_ascii_uppercase()),
                Value::String(char::from(letter).to_string()),
            )
        })
        .collect();
    let description = "z".repeat(8192);
    fixture.write(
        "plugin.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name":"portable-sample", "version":"1.2.3", "description":description
        }))
        .unwrap(),
    );
    fixture.write(
        "mcp.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers":{"sample":{"type":"stdio","command":"example-server", "env":env}}
        }))
        .unwrap(),
    );
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg(), "--json"]);
    success(&output);
    assert!(output.stdout.len() < 64 * 1024);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["inspection"]["manifest"]["description"], description);
    assert_eq!(report["inspection"]["manifest"]["version"], "1.2.3");
    assert_eq!(fixture.inventory(), before);

    // The same bounded input with explicitly credential-shaped names also
    // terminates: matching short secrets cannot recursively expand markers.
    let credentials: serde_json::Map<String, Value> = (b'a'..=b'z')
        .map(|letter| {
            (
                format!("SETTING_{}_TOKEN", char::from(letter).to_ascii_uppercase()),
                Value::String(char::from(letter).to_string()),
            )
        })
        .collect();
    fixture.write(
        "mcp.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers":{"sample":{"type":"stdio","command":"example-server", "env":credentials}}
        }))
        .unwrap(),
    );
    let expected = orbit_plugin_compat::inspect(&fixture.source, &Default::default()).unwrap();
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg(), "--json"]);
    success(&output);
    assert!(output.stdout.len() < 64 * 1024);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["display_truncated"], true);
    assert!(
        report["inspection"]["manifest"]["description"]
            .as_str()
            .unwrap()
            .len()
            < 128
    );
    assert_eq!(report["inspection"]["manifest"]["version"], "1.2.3");
    assert_eq!(
        report["inspection"]["source"]["source_digest"],
        expected.source.source_digest
    );
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_normalizes_hidden_characters_before_url_and_credential_classification() {
    let fixture = Fixture::new();
    fixture.write("plugin.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name":"portable-sample", "version":"1.2.3",
        "description":"https:\u{202e}//example.test/mcp?unusual=fixture-private-query https:\u{001b}//user:tiny-userinfo@example.test/mcp?extra=fixture-control-query",
        "extensions":{"dev.example":{"pass\u{202e}word":"tiny-private-value", "client\u{001b}_secret":"tiny-client-value"}}
    })).unwrap());
    let before = fixture.inventory();
    for suffix in [vec!["--json"], Vec::new()] {
        let mut args = vec!["plugin", "inspect", fixture.source_arg()];
        args.extend(suffix);
        let output = fixture.run(&args);
        success(&output);
        let output = stdout(&output);
        for secret in [
            "fixture-private-query",
            "tiny-userinfo",
            "fixture-control-query",
            "tiny-private-value",
            "tiny-client-value",
        ] {
            assert!(
                !output.contains(secret),
                "canonicalized credential escaped display"
            );
        }
        assert!(!output.contains(['\u{202e}', '\u{001b}']));
    }
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_handles_quoted_unicode_secret_assignment_without_panicking() {
    let fixture = Fixture::new();
    let secret = "éAbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    fixture.write("plugin.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name":"portable-sample", "version":"1.2.3", "description":format!("secret note = \"{secret}\"")
    })).unwrap());
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "inspect", fixture.source_arg(), "--json"]);
    success(&output);
    assert!(!stdout(&output).contains(secret));
    assert!(stdout(&output).contains("redacted:secret"));
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn inspect_masks_known_credentials_in_source_names_versions_models_and_paths() {
    let fixture = Fixture::new();
    let secret = "tiny-fixture-password";
    fixture.write(
        "notes/tiny-fixture-password.txt",
        "ordinary reference bytes\n",
    );
    fixture.write("skills/review/SKILL.md", format!(
        "---\nname: review\ndescription: Review a local change\nmodel: {secret}\n---\nReview the source.\n"));
    for version in [secret.to_owned(), format!("v1-{secret}")] {
        fixture.write(
            "plugin.json",
            serde_json::to_vec(&json!({
                "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
                "name":secret, "version":version,
                "extensions":{"dev.example":{"password":secret}}
            }))
            .unwrap(),
        );
        let expected = orbit_plugin_compat::inspect(&fixture.source, &Default::default()).unwrap();
        let before = fixture.inventory();
        for json_mode in [true, false] {
            let mut args = vec!["plugin", "inspect", fixture.source_arg()];
            if json_mode {
                args.push("--json");
            }
            let output = fixture.run(&args);
            success(&output);
            assert!(
                !stdout(&output).contains(secret),
                "source-controlled public field leaked a known credential"
            );
            if json_mode {
                let report: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(
                    report["inspection"]["manifest"]["name"],
                    "[configured literal]"
                );
                assert!(
                    report["inspection"]["manifest"]["version"]
                        .as_str()
                        .unwrap()
                        .contains("[configured literal]")
                );
                assert_eq!(
                    report["inspection"]["source"]["source_digest"],
                    expected.source.source_digest
                );
                let files = report["inspection"]["source"]["files"].as_array().unwrap();
                assert_eq!(files.len(), expected.source.files.len());
                for (actual, expected) in files.iter().zip(&expected.source.files) {
                    assert_eq!(actual["sha256"], expected.sha256);
                }
            }
        }
        assert_eq!(fixture.inventory(), before);
    }
}

fn managed_fixture() -> Fixture {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        fixture.work.join(".orbit"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fixture.write("LICENSE", "Preserved sample license bytes\n");
    fixture
}

fn assert_only_managed_changes(
    before: &BTreeMap<PathBuf, (u32, Vec<u8>)>,
    after: &BTreeMap<PathBuf, (u32, Vec<u8>)>,
) {
    for (path, expected) in before {
        assert_eq!(
            after.get(path),
            Some(expected),
            "preexisting source/configuration changed: {path:?}"
        );
    }
    for path in after.keys().filter(|path| !before.contains_key(*path)) {
        assert!(
            path.starts_with("home/plugins") || path.starts_with("workspace/.orbit/plugins"),
            "operation created unrelated state: {path:?}"
        );
    }
}

#[test]
fn managed_import_install_and_fresh_queries_preserve_source_and_unrelated_state() {
    let fixture = managed_fixture();
    let expected = orbit_plugin_compat::inspect(&fixture.source, &Default::default()).unwrap();
    let before = fixture.inventory();
    let options = [
        "--scope",
        "user",
        "--no-enable",
        "--format",
        "portable",
        "--model-map",
        "alias=primary/model",
        "--tool-map",
        "Read=Read",
        "--json",
    ];
    let mut args = vec!["plugin", "import", fixture.source_arg()];
    args.extend(options);
    let output = fixture.run(&args);
    success(&output);
    let imported: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(imported["command"], "plugin import");
    assert_eq!(imported["package_code_executed"], false);
    assert_eq!(imported["runtime_readiness"], "unchecked");
    assert_eq!(imported["receipt"]["reused"], false);
    assert_eq!(imported["receipt"]["plugin"]["id"]["scope"], "user");
    assert_eq!(imported["receipt"]["plugin"]["enabled"], false);
    assert_eq!(
        imported["receipt"]["plugin"]["digest"],
        expected.source.source_digest
    );
    assert_eq!(
        imported["receipt"]["plugin"]["options"]["model_map"]["alias"],
        "primary/model"
    );
    assert_eq!(
        imported["receipt"]["snapshot"]["revision"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let after = fixture.inventory();
    assert_only_managed_changes(&before, &after);
    let package = fixture
        .home
        .join("plugins/portable/packages/portable-sample")
        .join(&expected.source.source_digest);
    for file in &expected.source.files {
        assert_eq!(
            fs::read(package.join(&file.path)).unwrap(),
            fs::read(fixture.source.join(&file.path)).unwrap()
        );
    }
    let mut args = vec!["plugin", "install", fixture.source_arg()];
    args.extend(options);
    let output = fixture.run(&args);
    success(&output);
    let repeated: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(repeated["command"], "plugin install");
    assert_eq!(repeated["receipt"]["reused"], true);
    assert_eq!(
        repeated["receipt"]["snapshot"],
        imported["receipt"]["snapshot"]
    );
    assert_eq!(
        fixture.inventory(),
        after,
        "identical install must not rewrite stored state"
    );
    let output = fixture.run(&["--json", "plugin", "list"]);
    success(&output);
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed["snapshot"], imported["receipt"]["snapshot"]);
    let output = fixture.run(&[
        "plugin",
        "status",
        "portable-sample",
        "--scope",
        "user",
        "--json",
    ]);
    success(&output);
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["plugin"], imported["receipt"]["plugin"]);
    for args in [
        vec!["plugin", "list"],
        vec!["plugin", "status", "portable-sample"],
    ] {
        let output = fixture.run(&args);
        success(&output);
        assert!(stdout(&output).contains("portable-sample"));
        assert!(stdout(&output).contains("Runtime readiness: unchecked"));
    }
    assert_eq!(
        fixture.inventory(),
        after,
        "fresh query processes must remain read-only"
    );
    assert!(!fixture.root.join("execution-marker").exists());
}

#[test]
fn managed_project_import_requires_actual_project_trust_and_explicit_scope() {
    let fixture = managed_fixture();
    let trust = orbit_tools::permissions::FolderTrust::new(fixture.home.clone());
    trust.trust(&fixture.source).unwrap();
    let before = fixture.inventory();
    let output = fixture.run(&[
        "plugin",
        "import",
        fixture.source_arg(),
        "--scope",
        "project",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(93));
    assert!(String::from_utf8_lossy(&output.stderr).contains("store_project_untrusted"));
    assert_eq!(fixture.inventory(), before);
    trust.trust(&fixture.work).unwrap();
    let before = fixture.inventory();
    let output = fixture.run(&[
        "plugin",
        "install",
        fixture.source_arg(),
        "--scope",
        "project",
        "--json",
    ]);
    success(&output);
    let imported: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(imported["receipt"]["plugin"]["id"]["scope"], "project");
    assert_eq!(imported["receipt"]["plugin"]["enabled"], true);
    assert_eq!(imported["runtime_readiness"], "unchecked");
    assert_only_managed_changes(&before, &fixture.inventory());
    let before = fixture.inventory();
    let output = fixture.run(&[
        "plugin",
        "status",
        "portable-sample",
        "--scope",
        "project",
        "--json",
    ]);
    success(&output);
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["plugin"], imported["receipt"]["plugin"]);
    let output = fixture.run(&["plugin", "status", "portable-sample", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(78),
        "status must not guess another scope"
    );
    assert_eq!(fixture.inventory(), before);
    let other = fixture.root.join("other-project");
    fs::create_dir(&other).unwrap();
    let before = fixture.inventory();
    let output = fixture.run_in(
        &other,
        &[
            "plugin",
            "status",
            "portable-sample",
            "--scope",
            "project",
            "--json",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(93),
        "trust in the original project must not authorize another cwd"
    );
    let output = fixture.run_in(&other, &["plugin", "list", "--json"]);
    success(&output);
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed["snapshot"]["entries"].as_array().unwrap().len(), 0);
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn managed_queries_and_invalid_operation_flags_never_initialize_state() {
    let fixture = managed_fixture();
    let before = fixture.inventory();
    let output = fixture.run(&["plugin", "list", "--json"]);
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["snapshot"]["entries"].as_array().unwrap().is_empty());
    let output = fixture.run(&["plugin", "status", "missing", "--json"]);
    assert_eq!(output.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&output.stderr).contains("store_plugin_not_found"));
    let cases = [
        vec!["import"],
        vec!["install", fixture.source_arg(), fixture.source_arg()],
        vec!["import", fixture.source_arg(), "--scope"],
        vec!["import", fixture.source_arg(), "--scope", "invalid"],
        vec![
            "import",
            fixture.source_arg(),
            "--scope",
            "user",
            "--scope",
            "project",
        ],
        vec![
            "install",
            fixture.source_arg(),
            "--no-enable",
            "--no-enable",
        ],
        vec!["import", fixture.source_arg(), "--unknown"],
        vec!["inspect", fixture.source_arg(), "--scope", "user"],
        vec!["inspect", fixture.source_arg(), "--no-enable"],
        vec!["list", "extra"],
        vec!["list", "--scope", "user"],
        vec!["status"],
        vec!["status", "one", "two"],
        vec!["status", "one", "--no-enable"],
        vec!["status", "one", "--format", "portable"],
        vec!["status", "one", "--scope", "user", "--scope", "user"],
        vec!["remove"],
        vec!["doctor", "one"],
    ];
    for tail in cases {
        let mut args = vec!["plugin"];
        args.extend(tail);
        let output = fixture.run(&args);
        assert_eq!(
            output.status.code(),
            Some(64),
            "invalid operation arguments: {args:?}"
        );
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn managed_reports_redact_credentials_and_dynamic_mapping_keys_without_forged_hash_exemptions() {
    let fixture = managed_fixture();
    let secret = "tiny-fixture-password";
    fixture.write("plugin.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name":"portable-sample", "version":"1.2.3",
        "extensions":{"dev.example":{"password":secret, "revision":secret, "digest":secret, "source_digest":secret}}
    })).unwrap());
    fixture.write("mcp.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers":{"sample":{"type":"stdio","command":"example-server", "env":{"API_KEY":secret,"PYTHONUNBUFFERED":"1","REFERENCE":"${SAMPLE_TOKEN}"}}}
    })).unwrap());
    let expected = orbit_plugin_compat::inspect(&fixture.source, &Default::default()).unwrap();
    let before = fixture.inventory();
    let output = fixture.run(&[
        "plugin",
        "import",
        fixture.source_arg(),
        "--model-map",
        &format!("revision={secret}"),
        "--model-map",
        &format!("digest={secret}"),
        "--tool-map",
        &format!("source_digest={secret}"),
        "--json",
    ]);
    success(&output);
    assert!(!stdout(&output).contains(secret));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let plugin = &report["receipt"]["plugin"];
    assert_eq!(plugin["digest"], expected.source.source_digest);
    assert_eq!(
        plugin["source"]["source_digest"],
        expected.source.source_digest
    );
    assert_eq!(
        report["receipt"]["snapshot"]["revision"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        plugin["options"]["model_map"]["revision"],
        "[configured literal]"
    );
    assert_eq!(
        plugin["options"]["model_map"]["digest"],
        "[configured literal]"
    );
    assert_eq!(
        plugin["options"]["tool_map"]["source_digest"],
        "[configured literal]"
    );
    for key in ["revision", "digest", "source_digest"] {
        assert_eq!(
            plugin["manifest"]["source_metadata"]["extensions"]["dev.example"][key],
            "[configured literal]"
        );
    }
    assert_only_managed_changes(&before, &fixture.inventory());
    let before = fixture.inventory();
    for args in [
        vec!["plugin", "list", "--json"],
        vec!["plugin", "status", "portable-sample", "--json"],
        vec!["plugin", "list"],
        vec!["plugin", "status", "portable-sample"],
    ] {
        let output = fixture.run(&args);
        success(&output);
        assert!(
            !stdout(&output).contains(secret),
            "{args:?} printed a configured literal:\n{}",
            stdout(&output)
        );
        // An environment reference is not a secret and stays readable where the component is shown:
        // in the whole record of one plugin, not in the list, which only counts what a plugin holds.
        if args.contains(&"--json") && args.contains(&"status") {
            assert!(stdout(&output).contains("${SAMPLE_TOKEN}"));
        }
        if args.contains(&"--json") && args.contains(&"list") {
            assert!(!stdout(&output).contains("${SAMPLE_TOKEN}"));
            assert!(stdout(&output).contains("component_counts"));
        }
    }
    assert_eq!(fixture.inventory(), before);
}

fn lifecycle_report(fixture: &Fixture, args: &[&str]) -> Value {
    let output = fixture.run(args);
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["package_code_executed"], false);
    assert_eq!(report["runtime_readiness"], "unchecked");
    assert!(!fixture.root.join("execution-marker").exists());
    report
}

#[test]
fn lifecycle_fresh_process_enable_disable_upgrade_remove_preserves_packages_and_data() {
    let fixture = managed_fixture();
    let original = fixture.inventory();
    let imported = lifecycle_report(
        &fixture,
        &[
            "plugin",
            "import",
            fixture.source_arg(),
            "--no-enable",
            "--json",
        ],
    );
    let first_digest = imported["receipt"]["plugin"]["digest"].as_str().unwrap();
    let first_package = fixture
        .home
        .join("plugins/portable/packages/portable-sample")
        .join(first_digest);
    let first_manifest = fs::read(first_package.join("plugin.json")).unwrap();
    let data_root = fixture.home.join("plugins/portable/data/portable-sample");
    fs::create_dir_all(&data_root).unwrap();
    fs::set_permissions(&data_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        data_root.join("settings.json"),
        "preserve user plugin settings\n",
    )
    .unwrap();

    let enabled = lifecycle_report(
        &fixture,
        &[
            "plugin",
            "enable",
            "portable-sample",
            "--revision",
            imported["receipt"]["snapshot"]["revision"]
                .as_str()
                .unwrap(),
            "--json",
        ],
    );
    assert_eq!(enabled["command"], "plugin enable");
    assert_eq!(enabled["snapshot"]["entries"][0]["enabled"], true);
    let queried = lifecycle_report(&fixture, &["plugin", "status", "portable-sample", "--json"]);
    assert_eq!(queried["plugin"]["enabled"], true);
    let disabled = lifecycle_report(
        &fixture,
        &["plugin", "disable", "portable-sample", "--json"],
    );
    assert_eq!(disabled["snapshot"]["entries"][0]["enabled"], false);

    fixture.write(
        "plugin.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name":"portable-sample", "version":"2.0.0", "license":"MIT"
        }))
        .unwrap(),
    );
    let before_upgrade = fixture.inventory();
    let prior_index = fs::read(fixture.home.join("plugins/portable/index.json")).unwrap();
    let upgraded = lifecycle_report(
        &fixture,
        &[
            "plugin",
            "upgrade",
            "portable-sample",
            fixture.source_arg(),
            "--format",
            "portable",
            "--model-map",
            "alias=primary/model",
            "--tool-map",
            "Read=Read",
            "--revision",
            disabled["snapshot"]["revision"].as_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(upgraded["command"], "plugin upgrade");
    assert_eq!(upgraded["receipt"]["plugin"]["enabled"], false);
    assert_eq!(
        upgraded["receipt"]["plugin"]["manifest"]["version"],
        "2.0.0"
    );
    assert_eq!(
        upgraded["receipt"]["plugin"]["options"]["model_map"]["alias"],
        "primary/model"
    );
    assert_ne!(upgraded["receipt"]["plugin"]["digest"], first_digest);
    let second_package = fixture
        .home
        .join("plugins/portable/packages/portable-sample")
        .join(upgraded["receipt"]["plugin"]["digest"].as_str().unwrap());
    assert_eq!(
        fs::read(second_package.join("plugin.json")).unwrap(),
        fs::read(fixture.source.join("plugin.json")).unwrap()
    );
    assert_eq!(
        fs::read(first_package.join("plugin.json")).unwrap(),
        first_manifest
    );
    assert_eq!(
        fs::read(fixture.home.join("plugins/portable/index.previous.json")).unwrap(),
        prior_index,
        "upgrade must preserve the actual previously accepted index as its recovery copy"
    );
    for (path, expected) in &before_upgrade {
        if path != Path::new("home/plugins/portable/index.json")
            && path != Path::new("home/plugins/portable/index.previous.json")
        {
            assert_eq!(
                fixture.inventory().get(path),
                Some(expected),
                "upgrade changed {path:?}"
            );
        }
    }
    lifecycle_report(&fixture, &["plugin", "enable", "portable-sample", "--json"]);
    let removed = lifecycle_report(&fixture, &["plugin", "remove", "portable-sample", "--json"]);
    assert_eq!(removed["command"], "plugin remove");
    assert!(
        removed["snapshot"]["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let listed = lifecycle_report(&fixture, &["plugin", "list", "--json"]);
    assert_eq!(listed["snapshot"], removed["snapshot"]);
    assert_eq!(
        fs::read(data_root.join("settings.json")).unwrap(),
        b"preserve user plugin settings\n"
    );
    assert_eq!(
        fs::read(first_package.join("plugin.json")).unwrap(),
        first_manifest
    );
    assert!(second_package.join("plugin.json").exists());
    for (path, expected) in original {
        if path != Path::new("source/plugin.json") {
            assert_eq!(
                fixture.inventory().get(&path),
                Some(&expected),
                "lifecycle changed {path:?}"
            );
        }
    }
}

#[test]
fn lifecycle_stale_revision_and_identity_mismatch_never_change_state() {
    let fixture = managed_fixture();
    let imported = lifecycle_report(
        &fixture,
        &[
            "plugin",
            "import",
            fixture.source_arg(),
            "--no-enable",
            "--json",
        ],
    );
    let stale = imported["receipt"]["snapshot"]["revision"]
        .as_str()
        .unwrap();
    lifecycle_report(&fixture, &["plugin", "enable", "portable-sample", "--json"]);
    let before = fixture.inventory();
    for operation in ["enable", "disable", "remove", "upgrade"] {
        let mut args = vec!["plugin", operation, "portable-sample"];
        if operation == "upgrade" {
            args.push(fixture.source_arg());
        }
        args.extend(["--revision", stale, "--json"]);
        let output = fixture.run(&args);
        assert_eq!(
            output.status.code(),
            Some(78),
            "{operation} must reject a stale revision"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("store_revision_changed"));
        assert!(output.stdout.is_empty());
        assert_eq!(fixture.inventory(), before);
    }
    fixture.write(
        "plugin.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name":"another-package", "version":"3.0.0"
        }))
        .unwrap(),
    );
    let before = fixture.inventory();
    let output = fixture.run(&[
        "plugin",
        "upgrade",
        "portable-sample",
        fixture.source_arg(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&output.stderr).contains("store_identity_mismatch"));
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn lifecycle_human_output_and_upgrade_keep_existing_mappings_and_enabled_state() {
    let fixture = managed_fixture();
    lifecycle_report(
        &fixture,
        &[
            "plugin",
            "import",
            fixture.source_arg(),
            "--no-enable",
            "--format",
            "portable",
            "--model-map",
            "alias=primary/model",
            "--tool-map",
            "Read=Read",
            "--json",
        ],
    );
    for (operation, heading) in [
        ("enable", "Plugin enabled in index."),
        ("disable", "Plugin disabled in index."),
        ("enable", "Plugin enabled in index."),
    ] {
        let output = fixture.run(&["plugin", operation, "portable-sample"]);
        success(&output);
        assert!(stdout(&output).starts_with(heading));
        assert!(stdout(&output).contains("portable-sample"));
        assert!(stdout(&output).contains("Runtime readiness: unchecked"));
        assert!(!stdout(&output).contains("unknown"));
    }
    fixture.write("notes/new-version.txt", "new immutable version\n");
    let output = fixture.run(&["plugin", "upgrade", "portable-sample", fixture.source_arg()]);
    success(&output);
    assert!(stdout(&output).starts_with("Immutable plugin snapshot upgraded."));
    let status = lifecycle_report(&fixture, &["plugin", "status", "portable-sample", "--json"]);
    assert_eq!(status["plugin"]["enabled"], true);
    assert_eq!(status["plugin"]["options"]["format"], "portable");
    assert_eq!(
        status["plugin"]["options"]["model_map"]["alias"],
        "primary/model"
    );
    assert_eq!(status["plugin"]["options"]["tool_map"]["Read"], "Read");
    let output = fixture.run(&["plugin", "remove", "portable-sample"]);
    success(&output);
    assert!(
        stdout(&output)
            .starts_with("Plugin removed from index; package versions and user data retained.")
    );
    assert!(stdout(&output).contains("No managed packages."));
    assert!(!stdout(&output).contains("unknown"));
    assert!(!fixture.root.join("execution-marker").exists());
    let output = fixture.run(&["plugin", "help"]);
    success(&output);
    assert!(stdout(&output).contains("enable|disable|remove ID"));
    assert!(stdout(&output).contains("upgrade ID PATH"));
    assert!(!stdout(&output).contains("plugin migrate"));
}

#[test]
fn lifecycle_project_mutations_require_current_project_trust_and_exact_scope() {
    let fixture = managed_fixture();
    let trust = orbit_tools::permissions::FolderTrust::new(fixture.home.clone());
    trust.trust(&fixture.work).unwrap();
    lifecycle_report(
        &fixture,
        &[
            "plugin",
            "import",
            fixture.source_arg(),
            "--scope",
            "project",
            "--no-enable",
            "--json",
        ],
    );
    let enabled = lifecycle_report(
        &fixture,
        &[
            "plugin",
            "enable",
            "portable-sample",
            "--scope",
            "project",
            "--json",
        ],
    );
    assert_eq!(enabled["snapshot"]["entries"][0]["id"]["scope"], "project");
    assert_eq!(enabled["snapshot"]["entries"][0]["enabled"], true);
    let before = fixture.inventory();
    let wrong_scope = fixture.run(&["plugin", "disable", "portable-sample", "--json"]);
    assert_eq!(wrong_scope.status.code(), Some(78));
    assert_eq!(fixture.inventory(), before);
    trust.untrust(&fixture.work).unwrap();
    let before = fixture.inventory();
    for operation in ["enable", "disable", "remove", "upgrade"] {
        let mut args = vec!["plugin", operation, "portable-sample"];
        if operation == "upgrade" {
            args.push(fixture.source_arg());
        }
        args.extend(["--scope", "project", "--json"]);
        let output = fixture.run(&args);
        assert_eq!(
            output.status.code(),
            Some(93),
            "{operation} must require actual cwd trust"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("store_project_untrusted"));
        assert_eq!(fixture.inventory(), before);
    }
}

#[test]
fn lifecycle_strict_grammar_rejects_invalid_flags_before_state_initialization() {
    let fixture = managed_fixture();
    let before = fixture.inventory();
    let first_revision = "a".repeat(64);
    let second_revision = "b".repeat(64);
    for operation in ["enable", "disable", "remove", "upgrade"] {
        let mut valid = vec!["plugin", operation, "portable-sample"];
        if operation == "upgrade" {
            valid.push(fixture.source_arg());
        }
        let mut cases = vec![vec!["plugin", operation], valid.clone()];
        cases[1].push("--unknown");
        for tail in [
            vec!["--revision"],
            vec!["--revision", ""],
            vec!["--revision", "short"],
            vec![
                "--revision",
                &first_revision,
                "--revision",
                &second_revision,
            ],
            vec!["--scope", "user", "--scope", "project"],
            vec!["--scope", "invalid"],
            vec!["--no-enable"],
            vec!["extra"],
            vec!["--json", "--json"],
        ] {
            let mut args = valid.clone();
            args.extend(tail);
            cases.push(args);
        }
        if operation != "upgrade" {
            for tail in [
                vec!["--format", "portable"],
                vec!["--model-map", "a=b"],
                vec!["--tool-map", "a=b"],
            ] {
                let mut args = valid.clone();
                args.extend(tail);
                cases.push(args);
            }
        } else {
            cases.extend([
                vec!["plugin", "upgrade", "portable-sample"],
                vec![
                    "plugin",
                    "upgrade",
                    "portable-sample",
                    fixture.source_arg(),
                    "--format",
                    "portable",
                    "--format",
                    "claude",
                ],
                vec![
                    "plugin",
                    "upgrade",
                    "portable-sample",
                    fixture.source_arg(),
                    "--tool-map",
                    "Read=Read",
                    "--tool-map",
                    "Read=Write",
                ],
            ]);
        }
        for args in cases {
            let output = fixture.run(&args);
            assert_eq!(
                output.status.code(),
                Some(64),
                "invalid lifecycle grammar: {args:?}"
            );
            assert!(output.stdout.is_empty());
            assert_eq!(fixture.inventory(), before);
        }
    }
}

/// A Claude Code plugin as one finds it in the wild: a good skill, a skill with a name the id rules
/// refuse, a command whose YAML Claude Code reads and a strict parser does not, and a link.
fn wild_plugin(fixture: &Fixture) -> PathBuf {
    let source = fixture.root.join("wild-source");
    for (path, bytes) in [
        (
            ".claude-plugin/plugin.json",
            r#"{"name":"wild","description":"d","license":"MIT"}"#,
        ),
        (
            "skills/good/SKILL.md",
            "---\nname: good\ndescription: d\n---\nbody\n",
        ),
        (
            "skills/spaced/SKILL.md",
            "---\nname: Agent Cost Report\ndescription: d\n---\nbody\n",
        ),
        (
            "commands/doctor.md",
            "---\ndescription: Run it. Input: a name\nargument-hint: [--strict] [--json]\n---\nbody\n",
        ),
    ] {
        let target = source.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    std::os::unix::fs::symlink("/etc/hostname", source.join("link")).unwrap();
    source
}

#[test]
fn lenient_import_keeps_the_good_content_says_what_it_left_out_and_remembers_the_choice() {
    let fixture = managed_fixture();
    let source = wild_plugin(&fixture);
    let source = source.to_str().unwrap();

    // As before: one link, one name and one line of YAML refuse the whole package.
    let strict = fixture.run(&["plugin", "import", source, "--format", "claude", "--json"]);
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("source_entry_type"));
    assert!(
        !fixture.home.join("plugins").exists(),
        "a refusal writes nothing"
    );

    let output = fixture.run(&[
        "plugin",
        "import",
        source,
        "--format",
        "claude",
        "--lenient",
        "--json",
    ]);
    success(&output);
    let imported: Value = serde_json::from_slice(&output.stdout).unwrap();
    let plugin = &imported["receipt"]["plugin"];
    assert_eq!(plugin["options"]["lenient"], true);
    let mut ids: Vec<_> = plugin["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    assert_eq!(ids, ["wild:command:doctor", "wild:skill:good"]);
    let codes: Vec<_> = plugin["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_str().unwrap().to_owned())
        .collect();
    for code in ["component_skipped", "source_entry_skipped"] {
        assert!(codes.iter().any(|c| c == code), "{code} in {codes:?}");
    }

    // A fresh process reads the stored copy the same way: the choice travelled with the plugin.
    let status = fixture.run(&["plugin", "status", "wild", "--json"]);
    success(&status);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["plugin"]["options"]["lenient"], true);
    assert_eq!(status["plugin"]["components"].as_array().unwrap().len(), 2);

    // An upgrade without the flag keeps what the plugin was imported with.
    let upgraded = fixture.run(&["plugin", "upgrade", "wild", source, "--json"]);
    success(&upgraded);
    let again = fixture.run(&["plugin", "status", "wild", "--json"]);
    let again: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again["plugin"]["options"]["lenient"], true);

    // Inspecting takes the flag too; a doubled flag is a usage error and a strict inspect is unchanged.
    success(&fixture.run(&[
        "plugin",
        "inspect",
        source,
        "--format",
        "claude",
        "--lenient",
        "--json",
    ]));
    assert!(
        !fixture
            .run(&["plugin", "inspect", source, "--format", "claude", "--json"])
            .status
            .success()
    );
    let twice = fixture.run(&["plugin", "inspect", source, "--lenient", "--lenient"]);
    assert!(!twice.status.success());
    assert!(String::from_utf8_lossy(&twice.stderr).contains("duplicate --lenient"));
}

// ---------------------------------------------------------------------------------------------
// `orbit plugin import --from-claude`: bring in what Claude Code has installed and enabled.
// ---------------------------------------------------------------------------------------------

/// A token Claude Code keeps next to its plugin registry. Importing plugins has no business reading
/// it, so it must never reach an output or ORBIT's own folder.
const CLAUDE_TOKEN: &str = "claude-code-credential-that-nothing-may-read";

impl Fixture {
    fn claude(&self) -> PathBuf {
        self.root.join("claude")
    }

    /// Install a plugin the way Claude Code lays it out in its cache and return its folder.
    fn claude_plugin(&self, key: &str, files: &[(&str, &str)]) -> PathBuf {
        let (name, market) = key.split_once('@').unwrap();
        let dir = self
            .claude()
            .join("plugins/cache")
            .join(market)
            .join(name)
            .join("1.0.0");
        self.claude_files(&dir, name, files);
        dir
    }

    fn claude_files(&self, dir: &Path, name: &str, files: &[(&str, &str)]) {
        let manifest = format!(r#"{{"name":"{name}","description":"d","version":"1.0.0"}}"#);
        let mut all = vec![(".claude-plugin/plugin.json", manifest.as_str())];
        all.extend_from_slice(files);
        for (path, text) in all {
            let target = dir.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, text).unwrap();
        }
    }

    /// Claude Code's records: the install registry and the user settings that say what is enabled.
    /// `installs` is `(key, install path, scope)`; `enabled` is `(key, value)`.
    fn claude_registry(&self, installs: &[(&str, &Path, &str)], enabled: &[(&str, Value)]) {
        let mut plugins = serde_json::Map::new();
        for (key, path, scope) in installs {
            plugins.insert(
                (*key).to_owned(),
                json!([{"scope": scope, "installPath": path, "version": "1.0.0"}]),
            );
        }
        let claude = self.claude();
        fs::create_dir_all(claude.join("plugins")).unwrap();
        fs::write(
            claude.join("plugins/installed_plugins.json"),
            serde_json::to_vec(&json!({"version": 2, "plugins": plugins})).unwrap(),
        )
        .unwrap();
        let enabled: serde_json::Map<String, Value> = enabled
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect();
        fs::write(
            claude.join("settings.json"),
            serde_json::to_vec(&json!({
                "enabledPlugins": enabled,
                "env": {"ANTHROPIC_AUTH_TOKEN": CLAUDE_TOKEN},
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            claude.join(".credentials.json"),
            format!(r#"{{"claudeAiOauth":{{"accessToken":"{CLAUDE_TOKEN}"}}}}"#),
        )
        .unwrap();
    }

    fn bulk(&self, args: &[&str]) -> Value {
        let mut all = vec!["plugin", "import", "--from-claude", "--json"];
        all.extend_from_slice(args);
        let output = self.run(&all);
        success(&output);
        let text = stdout(&output);
        assert!(
            !text.contains(CLAUDE_TOKEN),
            "a Claude Code credential was printed"
        );
        serde_json::from_str(&text).unwrap()
    }
}

fn entry<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["bulk"]["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|plugin| plugin["name"] == name)
        .unwrap_or_else(|| panic!("no entry {name} in {}", report["bulk"]["plugins"]))
}

const ALPHA_HOOKS: &str = r#"{"hooks":{
  "PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"echo one"}]}],
  "Stop":[{"hooks":[{"type":"command","command":"echo two"}]}]}}"#;

/// What the operator's Claude Code looks like in miniature: a plugin with everything, one that needs
/// a lenient read, one nothing can read, two of one name, and the ways an entry can be unusable.
fn claude_world(fixture: &Fixture) {
    let alpha = fixture.claude_plugin(
        "alpha@market-a",
        &[
            (
                "skills/review/SKILL.md",
                "---\nname: review\ndescription: Review a change\n---\nbody\n",
            ),
            (
                "commands/ship.md",
                "---\ndescription: Ship it\n---\nShip.\n",
            ),
            ("hooks/hooks.json", ALPHA_HOOKS),
            (
                ".mcp.json",
                r#"{"mcpServers":{"srv":{"command":"srv-bin"}}}"#,
            ),
        ],
    );
    let wild = fixture.claude_plugin(
        "wild@market-a",
        &[
            ("skills/good/SKILL.md", "---\nname: good\ndescription: d\n---\nbody\n"),
            ("skills/spaced/SKILL.md", "---\nname: Agent Cost Report\ndescription: d\n---\nbody\n"),
            ("commands/doctor.md", "---\ndescription: Run it. Input: a name\nargument-hint: [--strict] [--json]\n---\nbody\n"),
        ],
    );
    std::os::unix::fs::symlink("/etc/hostname", wild.join("link")).unwrap();
    let broken =
        fixture.claude_plugin("broken@market-a", &[("hooks/hooks.json", r#"{"hooks":5}"#)]);
    let twin_a = fixture.claude_plugin(
        "twin@market-a",
        &[(
            "skills/a/SKILL.md",
            "---\nname: a\ndescription: d\n---\nbody\n",
        )],
    );
    let twin_b = fixture.claude_plugin(
        "twin@market-b",
        &[(
            "skills/b/SKILL.md",
            "---\nname: b\ndescription: d\n---\nbody\n",
        )],
    );
    let quiet = fixture.claude_plugin("quiet@market-a", &[]);
    let elsewhere = fixture.claude_plugin("elsewhere@market-a", &[]);
    let outside = fixture.root.join("outside-the-claude-folder");
    fixture.claude_files(&outside, "outside", &[]);
    fixture.claude_registry(
        &[
            ("alpha@market-a", &alpha, "user"),
            ("wild@market-a", &wild, "user"),
            ("broken@market-a", &broken, "user"),
            ("twin@market-a", &twin_a, "user"),
            ("twin@market-b", &twin_b, "user"),
            ("quiet@market-a", &quiet, "user"),
            ("elsewhere@market-a", &elsewhere, "project"),
            ("outside@market-a", &outside, "user"),
        ],
        &[
            ("alpha@market-a", json!(true)),
            ("wild@market-a", json!(true)),
            ("broken@market-a", json!(true)),
            ("twin@market-a", json!(true)),
            ("twin@market-b", json!(true)),
            ("quiet@market-a", json!(false)),
            ("elsewhere@market-a", json!(true)),
            ("ghost@market-a", json!(true)),
            ("outside@market-a", json!(true)),
            ("odd@market-a", json!("yes")),
        ],
    );
}

#[test]
fn bulk_import_brings_in_what_claude_code_has_enabled_and_says_what_it_did_not() {
    let fixture = managed_fixture();
    claude_world(&fixture);
    let before = fixture.inventory();
    let report = fixture.bulk(&[]);
    assert_eq!(report["package_code_executed"], false);
    let bulk = &report["bulk"];
    assert_eq!(bulk["dry_run"], false);
    assert_eq!(bulk["lenient"], true);
    let summary = &bulk["summary"];
    for (key, expected) in [
        ("enabled", 8),
        ("imported", 3),
        ("already", 0),
        ("changed", 0),
        ("refused", 2),
        ("skipped", 4),
        ("not_enabled", 1),
    ] {
        assert_eq!(summary[key], expected, "{key} in {summary}");
    }

    // A plugin with everything: what it holds, and what stays off.
    let alpha = entry(&report, "alpha");
    assert_eq!(alpha["status"], "imported");
    assert_eq!(alpha["marketplace"], "market-a");
    assert_eq!(
        alpha["components"],
        json!({"skill": 1, "agent": 0, "command": 1, "hook": 2, "mcp": 1})
    );
    assert_eq!(alpha["withheld"]["hooks"], 2);
    assert_eq!(alpha["withheld"]["mcp_servers"], 1);
    assert!(alpha["digest"].as_str().unwrap().len() >= 8);

    // Read as Claude Code reads it: the good content comes in, and what was left out is said.
    let wild = entry(&report, "wild");
    assert_eq!(wild["status"], "imported");
    assert_eq!(wild["components"]["skill"], 1);
    assert_eq!(wild["components"]["command"], 1);
    assert_eq!(wild["withheld"]["left_out"], 1);
    let warnings: Vec<_> = wild["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect();
    assert!(warnings.contains(&"component_skipped"), "{warnings:?}");

    // A plugin nothing can read is refused with its code and costs the others nothing.
    let broken = entry(&report, "broken");
    assert_eq!(broken["status"], "refused");
    assert!(!broken["code"].as_str().unwrap().is_empty());

    // One store entry per name: the second marketplace's copy is named and left alone.
    assert_eq!(entry(&report, "twin")["status"], "imported");
    let twin_b = report["bulk"]["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "twin" && p["marketplace"] == "market-b")
        .unwrap();
    assert_eq!(twin_b["status"], "skipped");
    assert!(
        twin_b["reason"].as_str().unwrap().contains("market-a"),
        "{twin_b}"
    );

    // The ways an entry can be unusable.
    let reason = |name: &str| entry(&report, name)["reason"].as_str().unwrap().to_owned();
    assert!(
        reason("elsewhere").contains("project"),
        "{}",
        reason("elsewhere")
    );
    assert!(
        reason("ghost").contains("not installed"),
        "{}",
        reason("ghost")
    );
    assert!(
        reason("odd").contains("neither true nor false"),
        "an enabledPlugins value that is not a bool is said, not guessed: {}",
        reason("odd")
    );
    assert_eq!(entry(&report, "outside")["status"], "refused");
    assert!(
        reason("outside").contains("outside"),
        "{}",
        reason("outside")
    );
    assert!(
        report["bulk"]["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["name"] != "quiet")
    );

    // ORBIT now holds exactly the three, enabled; nothing else about Claude Code moved or was read.
    let listed = fixture.run(&["plugin", "list", "--json"]);
    success(&listed);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let mut names: Vec<_> = listed["snapshot"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["id"]["name"].as_str().unwrap().to_owned(),
                p["enabled"].as_bool().unwrap(),
                p["options"]["lenient"].as_bool().unwrap(),
            )
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            ("alpha".to_owned(), true, true),
            ("twin".to_owned(), true, true),
            ("wild".to_owned(), true, true)
        ]
    );
    let after = fixture.inventory();
    for (path, was) in &before {
        assert_eq!(after.get(path), Some(was), "{} changed", path.display());
    }
    for path in after.keys().filter(|path| !before.contains_key(*path)) {
        assert!(
            path.starts_with("home/plugins"),
            "wrote outside the plugin store: {}",
            path.display()
        );
    }
    for (path, (_, bytes)) in &after {
        if path.starts_with("home") {
            assert!(
                !String::from_utf8_lossy(bytes).contains(CLAUDE_TOKEN),
                "{} holds a Claude Code credential",
                path.display()
            );
        }
    }

    // The same run for people: one line per plugin, what stays off, and how to turn hooks on.
    let human = fixture.run(&["plugin", "import", "--from-claude"]);
    success(&human);
    let text = stdout(&human);
    assert!(!text.contains(CLAUDE_TOKEN));
    for part in [
        "alpha",
        "already",
        "wild",
        "broken",
        "refused",
        "twin",
        "market-b",
        "no package code was run",
        "plugin_hooks",
    ] {
        assert!(text.contains(part), "{part} in:\n{text}");
    }
    // The last line says how to turn the hooks of what was imported on, with the plugin that has some.
    assert!(
        text.contains("plugin_hooks = [\"alpha\""),
        "how to turn hooks on, naming the plugin that has them:\n{text}"
    );
}

#[test]
fn bulk_import_is_repeatable_previews_without_writing_and_never_overwrites() {
    let fixture = managed_fixture();
    claude_world(&fixture);
    let before = fixture.inventory();

    // A preview inspects everything and writes nothing at all.
    let preview = fixture.bulk(&["--dry-run"]);
    assert_eq!(preview["bulk"]["dry_run"], true);
    assert_eq!(entry(&preview, "alpha")["status"], "would_import");
    assert_eq!(entry(&preview, "broken")["status"], "refused");
    assert_eq!(preview["bulk"]["summary"]["imported"], 0);
    assert_eq!(fixture.inventory(), before);

    // `--only` takes one plugin; a name that matches nothing is said, not ignored.
    let one = fixture.bulk(&["--only", "alpha", "--only", "nonesuch"]);
    assert_eq!(entry(&one, "alpha")["status"], "imported");
    assert_eq!(one["bulk"]["plugins"].as_array().unwrap().len(), 2, "{one}");
    assert_eq!(entry(&one, "nonesuch")["status"], "skipped");
    let listed = fixture.run(&["plugin", "list", "--json"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["snapshot"]["entries"].as_array().unwrap().len(), 1);

    // The rest follows; what is already there is recognised by its content and left alone.
    let rest = fixture.bulk(&[]);
    assert_eq!(entry(&rest, "alpha")["status"], "already");
    assert_eq!(entry(&rest, "wild")["status"], "imported");
    let revision = |fixture: &Fixture| {
        let listed = fixture.run(&["plugin", "list", "--json"]);
        let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
        listed["snapshot"]["revision"].as_str().unwrap().to_owned()
    };
    let settled = revision(&fixture);
    let again = fixture.bulk(&[]);
    for name in ["alpha", "wild", "twin"] {
        assert_eq!(entry(&again, name)["status"], "already", "{name}");
    }
    assert_eq!(again["bulk"]["summary"]["imported"], 0);
    assert_eq!(revision(&fixture), settled, "a repeat changes nothing");

    // Claude Code updates a plugin: ORBIT's copy is kept, and the way to take the new one is named.
    let alpha_dir = fixture.claude().join("plugins/cache/market-a/alpha/1.0.0");
    fs::write(
        alpha_dir.join("skills/review/SKILL.md"),
        "---\nname: review\ndescription: Changed\n---\nnew body\n",
    )
    .unwrap();
    let moved = fixture.bulk(&[]);
    let alpha = entry(&moved, "alpha");
    assert_eq!(alpha["status"], "changed");
    assert!(
        alpha["hint"]
            .as_str()
            .unwrap()
            .contains("orbit plugin upgrade alpha"),
        "{alpha}"
    );
    assert_eq!(moved["bulk"]["summary"]["changed"], 1);
    let preview = fixture.bulk(&["--dry-run"]);
    let alpha = entry(&preview, "alpha");
    assert_eq!(
        alpha["status"], "changed",
        "a preview says what a run would"
    );
    assert!(
        alpha["hint"]
            .as_str()
            .unwrap()
            .contains("orbit plugin upgrade alpha"),
        "{alpha}"
    );
    assert_eq!(
        revision(&fixture),
        settled,
        "the stored copy was not touched"
    );

    // A plugin disabled in ORBIT is not switched back on behind the operator's back.
    success(&fixture.run(&["plugin", "disable", "wild"]));
    let off = revision(&fixture);
    let kept = fixture.bulk(&[]);
    assert_eq!(entry(&kept, "wild")["status"], "kept");
    assert_eq!(revision(&fixture), off);
}

#[test]
fn bulk_import_refuses_unreadable_registries_and_ambiguous_commands_without_writing() {
    let fixture = managed_fixture();
    let ours = |fixture: &Fixture| {
        fixture
            .inventory()
            .into_iter()
            .filter(|(path, _)| path.starts_with("home") || path.starts_with("workspace"))
            .collect::<BTreeMap<_, _>>()
    };
    let before = ours(&fixture);
    let fails = |args: &[&str], code: Option<i32>, needle: &str| {
        let mut all = vec!["plugin", "import", "--from-claude"];
        all.extend_from_slice(args);
        let output = fixture.run(&all);
        assert!(!output.status.success(), "{args:?}");
        if code.is_some() {
            assert_eq!(output.status.code(), code, "{args:?}");
        }
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(needle), "{needle} in {stderr}");
        assert!(!stderr.contains(CLAUDE_TOKEN));
    };

    // No registry at all, then a broken one, then one from a format this was never checked against.
    fails(&[], None, "installed_plugins.json");
    fixture.claude_registry(&[], &[]);
    let registry = fixture.claude().join("plugins/installed_plugins.json");
    fs::write(&registry, "{ not json").unwrap();
    fails(&[], None, "installed_plugins.json");
    fs::write(&registry, r#"{"version":3,"plugins":{}}"#).unwrap();
    fails(&[], None, "version 3");
    fs::write(&registry, r#"{"version":2,"plugins":{}}"#).unwrap();
    fs::write(fixture.claude().join("settings.json"), "[1, 2]").unwrap();
    fails(&[], None, "settings.json");
    fs::write(
        fixture.claude().join("settings.json"),
        r#"{"enabledPlugins": [1]}"#,
    )
    .unwrap();
    fails(&[], None, "enabledPlugins");

    // Ambiguous or unsupported commands are usage errors.
    fails(&["somewhere"], Some(64), "package path");
    fails(&["--scope", "project"], Some(64), "--scope");
    fails(&["--dry-run", "--dry-run"], Some(64), "duplicate --dry-run");
    fails(&["--only"], Some(64), "--only");
    fails(&["--from-claude"], Some(64), "duplicate --from-claude");
    fails(&["--format", "claude"], Some(64), "--format");
    for operation in ["inspect", "install", "upgrade"] {
        let output = fixture.run(&["plugin", operation, "--from-claude"]);
        assert_eq!(output.status.code(), Some(64), "{operation}");
    }
    let help = fixture.run(&["plugin", "--help"]);
    assert!(
        stdout(&help).contains("--from-claude"),
        "the usage line lists the new command"
    );
    assert_eq!(
        ours(&fixture),
        before,
        "a refusal writes nothing to ORBIT's home or the workspace"
    );
}

#[test]
fn a_store_of_many_plugins_still_lists_every_plugin_by_name() {
    // Seventy plugins is what importing everything Claude Code has enabled leaves. The list used to
    // carry every plugin's whole record and ran out of display budget before it reached the names.
    let fixture = managed_fixture();
    let names: Vec<String> = (0..8).map(|n| format!("plug{n}")).collect();
    for name in &names {
        let source = fixture.root.join(format!("many-{name}"));
        fs::create_dir_all(source.join(".claude-plugin")).unwrap();
        fs::write(
            source.join(".claude-plugin/plugin.json"),
            format!(r#"{{"name":"{name}","description":"d","version":"1.0.0"}}"#),
        )
        .unwrap();
        for skill in 0..30 {
            let dir = source.join(format!("skills/s{skill}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("SKILL.md"),
                format!("---\nname: s{skill}\ndescription: Skill number {skill} of {name}\n---\nBody of skill {skill}.\n"),
            )
            .unwrap();
        }
        fs::create_dir_all(source.join("hooks")).unwrap();
        fs::write(
            source.join("hooks/hooks.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo x"}]}]}}"#,
        )
        .unwrap();
        let imported = fixture.run(&[
            "plugin",
            "import",
            source.to_str().unwrap(),
            "--format",
            "claude",
            "--json",
        ]);
        success(&imported);
        // The receipt shows the plugin just taken in in full, and the store beside it compactly.
        let receipt: Value = serde_json::from_slice(&imported.stdout).unwrap();
        assert_eq!(
            receipt["receipt"]["plugin"]["components"]
                .as_array()
                .unwrap()
                .len(),
            31
        );
        for entry in receipt["receipt"]["snapshot"]["entries"]
            .as_array()
            .unwrap()
        {
            assert!(entry.get("components").is_none(), "{entry}");
            assert_eq!(entry["component_counts"]["skill"], 30);
        }
    }
    let output = fixture.run(&["plugin", "list", "--json"]);
    success(&output);
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        listed["display_truncated"], false,
        "the list fits its display"
    );
    let entries = listed["snapshot"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 8);
    let mut found: Vec<_> = entries
        .iter()
        .map(|e| e["id"]["name"].as_str().unwrap().to_owned())
        .collect();
    found.sort();
    assert_eq!(found, names, "every name is there, none withheld");
    for entry in entries {
        assert_eq!(entry["component_counts"]["skill"], 30, "{entry}");
        assert_eq!(entry["component_counts"]["hook"], 1);
        assert!(
            entry.get("components").is_none(),
            "the whole record is `plugin status`"
        );
        assert!(entry["manifest"]["version"] == "1.0.0");
        assert_eq!(entry["enabled"], true);
    }
    // For people: a line a plugin, with what it holds.
    let human = fixture.run(&["plugin", "list"]);
    success(&human);
    let text = stdout(&human);
    assert!(!text.contains("withheld"), "{text}");
    for name in &names {
        assert!(
            text.contains(&format!("{name} [user], version 1.0.0")),
            "{name} in:\n{text}"
        );
    }
    assert!(
        text.contains("30 skills") && text.contains("1 command hook"),
        "{text}"
    );
    // The whole record of one is a command away, and is the one the import receipt showed.
    let status = fixture.run(&["plugin", "status", "plug3", "--json"]);
    success(&status);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["plugin"]["components"].as_array().unwrap().len(), 31);
}

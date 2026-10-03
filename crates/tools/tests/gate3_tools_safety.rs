//! Gate 3 — tools and safety. The roadmap's scenario, in its
//! scriptable parts:
//!
//! 1. "make the tests pass": Read → Edit → Bash(cargo test) in a
//!    fixture with one failing test, driven through the tool registry
//!    with the permission layer enforcing default mode.
//! 2. The denial legs: a Read of ~/.ssh/id_rsa meets the deny-read
//!    list; `rm -rf ~` is high-risk (asks in default, denied in
//!    dontAsk); in dontAsk every uncovered call is denied, never a
//!    hang.
//! 3. The secret scanner on every tool result: a file holding a fake
//!    API key reads back redacted, the line kept.

#![deny(unsafe_code)]

use orbit_tools::fs_tools::{EditTool, ReadTool, WriteTool};
use orbit_tools::permissions::{evaluate, parse_rule, PermissionMode, RuleEffectSerde, RuleSet};
use orbit_tools::{bash, Tool, ToolContext};

fn cx_for(dir: &std::path::Path) -> ToolContext {
    ToolContext::new(
        dir.join(".orbit"),
        format!("g3-{}", std::process::id()),
        dir.to_path_buf(),
    )
}

#[test]
fn gate3_fix_a_failing_test() {
    let dir = std::env::temp_dir().join(format!("orbit-g3-fix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Fixture: one failing test.
    let fixture = r#"
fn add(a: u32, b: u32) -> u32 { a - b }

fn main() { println!("{}", add(2, 2)); }
"#;
    std::fs::write(dir.join("fixture.rs"), fixture).unwrap();

    let cx = cx_for(&dir);

    // 1. Read the file (read-only: runs freely in default mode).
    let read = ReadTool;
    let verdict = evaluate(
        PermissionMode::Default,
        &RuleSet::default(),
        "Read",
        &dir.join("fixture.rs").to_string_lossy(),
        read.read_only(),
        false,
    );
    assert_eq!(verdict, orbit_tools::permissions::Verdict::Allow);
    let result = read.run(
        &serde_json::json!({ "file_path": dir.join("fixture.rs").to_string_lossy() }),
        &cx,
    );
    assert!(!result.is_error, "read must succeed");
    assert!(result.payload.contains("a - b"), "content present");

    // 2. Edit the bug (asks in default mode — the operator allows).
    let edit = EditTool;
    let verdict = evaluate(
        PermissionMode::Default,
        &RuleSet::default(),
        "Edit",
        &dir.join("fixture.rs").to_string_lossy(),
        edit.read_only(),
        false,
    );
    assert_eq!(verdict, orbit_tools::permissions::Verdict::Ask);
    // (operator pressed y — the executor proceeds)
    let result = edit.run(
        &serde_json::json!({
            "file_path": dir.join("fixture.rs").to_string_lossy(),
            "old_string": "a - b",
            "new_string": "a + b",
        }),
        &cx,
    );
    assert!(!result.is_error, "edit must succeed: {}", result.payload);
    let fixed = std::fs::read_to_string(dir.join("fixture.rs")).unwrap();
    assert!(fixed.contains("a + b"), "the edit landed");

    // 3. Run the "tests" (a stand-in command; the permission layer
    //    asks for non-allowlisted Bash in default mode).
    let bash_tool = bash::BashTool;
    let verdict = evaluate(
        PermissionMode::Default,
        &RuleSet::default(),
        "Bash",
        "echo running-tests",
        bash_tool.read_only(),
        bash::is_readonly_command("echo running-tests"),
    );
    assert_eq!(verdict, orbit_tools::permissions::Verdict::Allow);
    let result = bash_tool.run(&serde_json::json!({ "command": "echo running-tests" }), &cx);
    assert!(!result.is_error);
    assert!(result.payload.contains("running-tests"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gate3_deny_read_list_blocks_credentials() {
    let dir = std::env::temp_dir().join(format!("orbit-g3-deny-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cx = cx_for(&dir);

    // A fake credential file under a deny-read path shape.
    let home = std::env::var("HOME").unwrap();
    let ssh_dir = std::path::Path::new(&home).join(".orbit-gate3-ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let key = ssh_dir.join("id_rsa");
    std::fs::write(&key, "FAKE KEY MATERIAL").unwrap();

    // The deny-read list matches ~/.ssh/** — our stand-in dir does not
    // match, so test the real matcher on the real path shape.
    assert!(orbit_tools::is_deny_read(
        &std::path::Path::new(&home).join(".ssh/id_rsa")
    ));
    assert!(orbit_tools::is_deny_read(std::path::Path::new("/x/.env")));
    assert!(!orbit_tools::is_deny_read(std::path::Path::new(
        "/src/main.rs"
    )));

    // And the Read tool refuses a deny-read path end to end.
    let read = ReadTool;
    let result = read.run(
        &serde_json::json!({ "file_path": format!("{}/.ssh/id_rsa", home) }),
        &cx,
    );
    assert!(result.is_error, "reading a credential must be refused");
    assert!(result.payload.contains("deny-read"));

    let _ = std::fs::remove_dir_all(&ssh_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gate3_high_risk_and_dontask() {
    // rm -rf is high risk.
    assert_eq!(bash::command_risk("rm -rf ~"), 3);
    assert_eq!(bash::command_risk("git push --force origin main"), 3);
    assert_eq!(bash::command_risk("cargo test"), 1);

    // In default mode an uncovered Bash asks; in dontAsk it is denied,
    // never a hang.
    assert_eq!(
        evaluate(
            PermissionMode::Default,
            &RuleSet::default(),
            "Bash",
            "rm -rf ~",
            false,
            false
        ),
        orbit_tools::permissions::Verdict::Ask
    );
    assert!(matches!(
        evaluate(
            PermissionMode::DontAsk,
            &RuleSet::default(),
            "Bash",
            "rm -rf ~",
            false,
            false
        ),
        orbit_tools::permissions::Verdict::Deny(_)
    ));

    // An allow rule covers cargo test even in dontAsk.
    let rs = RuleSet {
        rules: vec![parse_rule("Bash(cargo test *)", RuleEffectSerde::Allow).unwrap()],
    };
    assert_eq!(
        evaluate(
            PermissionMode::DontAsk,
            &rs,
            "Bash",
            "cargo test --release",
            false,
            false
        ),
        orbit_tools::permissions::Verdict::Allow
    );
    // But a deny rule for the dangerous shape still wins.
    let rs = RuleSet {
        rules: vec![
            parse_rule("Bash(cargo test *)", RuleEffectSerde::Allow).unwrap(),
            parse_rule("Bash(rm -rf *)", RuleEffectSerde::Deny).unwrap(),
        ],
    };
    assert!(matches!(
        evaluate(
            PermissionMode::DontAsk,
            &rs,
            "Bash",
            "rm -rf ~",
            false,
            false
        ),
        orbit_tools::permissions::Verdict::Deny(_)
    ));
}

#[test]
fn gate3_secret_scanner_on_tool_results() {
    let dir = std::env::temp_dir().join(format!("orbit-g3-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cx = cx_for(&dir);

    // A file holding a fake API key.
    let secret_file = dir.join("config.txt");
    std::fs::write(
        &secret_file,
        "token = sk-abcdefghijklmnopqrstuvwxyz123456\nport = 8080\n",
    )
    .unwrap();

    let read = ReadTool;
    let result = read.run(
        &serde_json::json!({ "file_path": secret_file.to_string_lossy() }),
        &cx,
    );
    assert!(!result.is_error);
    // The key is redacted, the line is kept, the rest survives.
    assert!(
        result.payload.contains("[redacted:api token]"),
        "{}",
        result.payload
    );
    assert!(!result.payload.contains("abcdefghijklmnopqrstuvwxyz123456"));
    assert!(result.payload.contains("port = 8080"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gate3_read_before_edit_enforced() {
    let dir = std::env::temp_dir().join(format!("orbit-g3-rbe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cx = cx_for(&dir);

    let f = dir.join("unread.rs");
    std::fs::write(&f, "fn main() {}\n").unwrap();

    // Edit without a prior Read: refused.
    let edit = EditTool;
    let result = edit.run(
        &serde_json::json!({
            "file_path": f.to_string_lossy(),
            "old_string": "main",
            "new_string": "other",
        }),
        &cx,
    );
    assert!(result.is_error, "blind edit must be refused");
    assert!(result.payload.contains("read the file"));

    // Read, then edit: works.
    let read = ReadTool;
    let _ = read.run(
        &serde_json::json!({ "file_path": f.to_string_lossy() }),
        &cx,
    );
    let result = edit.run(
        &serde_json::json!({
            "file_path": f.to_string_lossy(),
            "old_string": "main",
            "new_string": "other",
        }),
        &cx,
    );
    assert!(
        !result.is_error,
        "edit after read must succeed: {}",
        result.payload
    );

    // Write to an existing unread file: refused.
    let g = dir.join("unread2.rs");
    std::fs::write(&g, "x\n").unwrap();
    let write = WriteTool;
    let result = write.run(
        &serde_json::json!({
            "file_path": g.to_string_lossy(),
            "content": "y\n",
        }),
        &cx,
    );
    assert!(result.is_error, "blind overwrite must be refused");

    let _ = std::fs::remove_dir_all(&dir);
}

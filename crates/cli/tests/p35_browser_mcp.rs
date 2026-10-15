#![cfg(unix)]

use orbit_cli::tool_runtime::{
    ApprovalChannel, ApprovalRequest, ApprovalVerdict, AutoGrants, PermissionScope, execute_call,
    permission_command,
};
use serde_json::{Value, json};
use std::path::PathBuf;

const TOOLS: [&str; 4] = [
    "browser_navigate",
    "browser_snapshot",
    "browser_click",
    "browser_close",
];

struct Fixture {
    home: PathBuf,
    work: PathBuf,
    page: PathBuf,
    server: String,
    cx: orbit_tools::ToolContext,
}

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let server = format!("browser{}", ulid::Ulid::new());
        let home = std::env::temp_dir().join(format!("orbit-browser-mcp-{server}"));
        let work = home.join("work");
        std::fs::create_dir_all(&work).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let page = home.join("page.html");
        std::fs::copy(root.join("scripts/fixtures/p35_browser.html"), &page).unwrap();
        let cx = orbit_tools::ToolContext::new(home.clone(), "browser-owner".into(), work.clone());
        let fixture = Self {
            home,
            work,
            page,
            server,
            cx,
        };
        fixture.configure();
        fixture
    }
    fn server_config(&self) -> Value {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        json!({"command":"python3", "args":[
            root.join("scripts/fixtures/p35_browser_mcp.py"), "--log", self.home.join("calls.jsonl"),
            "--state", self.home.join("state.json"), "--page", self.page
        ], "tools":TOOLS, "timeout_ms":1500, "initialize_timeout_ms":1500})
    }
    fn configure(&self) {
        std::fs::write(
            self.home.join("mcp.json"),
            json!({"servers":{(&self.server):self.server_config()}}).to_string(),
        )
        .unwrap();
    }
    fn wire(&self, tool: &str) -> String {
        orbit_mcp::wire_name(&self.server, tool)
    }
    fn selector(&self) -> String {
        format!("mcp__{}__*", self.server)
    }
    fn url(&self) -> String {
        url::Url::from_file_path(&self.page).unwrap().into()
    }
    fn policy(&self, verb: &str) {
        permission_command(
            &self.home,
            &PermissionScope::default(),
            &self.work,
            &format!("{verb} {}", self.selector()),
        )
        .unwrap();
    }
    fn call(
        &self,
        tool: &str,
        args: Value,
        channel: &mut dyn ApprovalChannel,
        auto: bool,
    ) -> Value {
        let call = orbit_cli::PendingToolCall {
            index: 0,
            id: ulid::Ulid::new().to_string(),
            name: self.wire(tool),
            arguments: serde_json::to_vec(&args).unwrap(),
        };
        let (output, _) = execute_call(
            &self.home,
            "browser-owner",
            "decision",
            &call,
            auto,
            true,
            channel,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
            &self.cx,
        )
        .unwrap();
        assert!(output.len() <= 64 * 1024);
        serde_json::from_str(&output).unwrap()
    }
    fn requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.home.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["method"] == "tools/call")
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}
struct Answer {
    answer: ApprovalVerdict,
    asked: usize,
}
impl Answer {
    fn new(answer: ApprovalVerdict) -> Self {
        Self { answer, asked: 0 }
    }
}
impl ApprovalChannel for Answer {
    fn ask(&mut self, _: &ApprovalRequest, auto: bool) -> ApprovalVerdict {
        assert!(
            !auto,
            "explicit confirmation must not receive convenience consent"
        );
        self.asked += 1;
        self.answer
    }
}

#[test]
fn navigation_policy_allowed_navigation_and_snapshot_are_real_scanned_calls() {
    let f = Fixture::new();
    f.policy("allow");
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let navigate = f.call(
        "browser_navigate",
        json!({"url":f.url()}),
        &mut answer,
        false,
    );
    assert_eq!(navigate["ok"], true, "{navigate}");
    let snapshot = f.call("browser_snapshot", json!({}), &mut answer, false);
    assert_eq!(snapshot["ok"], true, "{snapshot}");
    assert!(snapshot["result"].as_str().unwrap().contains("Count: 0"));
    assert!(
        snapshot["result"]
            .as_str()
            .unwrap()
            .contains("Untrusted page text")
    );
    assert!(!snapshot.to_string().contains("abcdefghijklmnopqrstuvwxyz"));
    assert!(snapshot["redactions"].as_u64().unwrap() >= 2);
    let requests = f.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["params"]["name"], "browser_navigate");
    assert_eq!(requests[0]["params"]["arguments"]["url"], f.url());
    assert_eq!(requests[1]["params"]["name"], "browser_snapshot");
    assert_eq!(answer.asked, 0);
}
#[test]
fn navigation_policy_catalog_exposes_only_exact_browser_identities() {
    let f = Fixture::new();
    let defs = orbit_cli::tools::session_tool_definitions_with_context(&f.home, &f.cx, None);
    let names: Vec<_> = defs
        .iter()
        .filter(|definition| definition.name.starts_with("mcp__"))
        .map(|definition| definition.name.as_str())
        .collect();
    assert_eq!(names.len(), 4);
    for tool in TOOLS {
        assert!(names.contains(&f.wire(tool).as_str()));
    }
    assert!(!names.contains(&f.wire("browser_evaluate").as_str()));
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let result = f.call("browser_evaluate", json!({}), &mut answer, true);
    assert_eq!(result["ok"], false, "{result}");
    assert!(f.requests().is_empty());
    assert_eq!(answer.asked, 0);
}
#[test]
fn navigation_policy_deny_prevents_outgoing_calls_and_spawn() {
    let f = Fixture::new();
    f.policy("deny");
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let result = f.call(
        "browser_navigate",
        json!({"url":f.url()}),
        &mut answer,
        true,
    );
    assert_eq!(result["ok"], false, "{result}");
    assert!(f.requests().is_empty());
    assert_eq!(answer.asked, 0);
    assert!(!f.home.join("calls.jsonl").exists());
}
#[test]
fn navigation_policy_declined_explicit_ask_prevents_outgoing_calls_and_spawn() {
    let f = Fixture::new();
    f.policy("ask");
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let result = f.call(
        "browser_navigate",
        json!({"url":f.url()}),
        &mut answer,
        true,
    );
    assert_eq!(result["ok"], false, "{result}");
    assert!(f.requests().is_empty());
    assert_eq!(answer.asked, 1);
    assert!(!f.home.join("calls.jsonl").exists());
}
#[test]
fn navigation_policy_separator_server_does_not_inherit_neighbor_deny() {
    let mut f = Fixture::new();
    let base = f.server.clone();
    f.server = format!("{base}__local");
    f.configure();
    let mut cfg: Value =
        serde_json::from_slice(&std::fs::read(f.home.join("mcp.json")).unwrap()).unwrap();
    cfg["servers"][&base] = f.server_config();
    std::fs::write(f.home.join("mcp.json"), cfg.to_string()).unwrap();
    std::fs::write(
        f.home.join("settings.toml"),
        format!("[permissions]\ndeny=[\"mcp__{base}__*\"]\n"),
    )
    .unwrap();
    f.policy("allow");
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let result = f.call(
        "browser_navigate",
        json!({"url":f.url()}),
        &mut answer,
        false,
    );
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(f.requests().len(), 1);
    assert_eq!(answer.asked, 0);
    assert_eq!(f.requests()[0]["params"]["name"], "browser_navigate");
}

#[test]
fn browser_action_changes_actual_fixture_state_and_next_snapshot() {
    let f = Fixture::new();
    f.policy("allow");
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    assert_eq!(
        f.call(
            "browser_navigate",
            json!({"url":f.url()}),
            &mut answer,
            false
        )["ok"],
        true
    );
    let clicked = f.call(
        "browser_click",
        json!({"ref":"increment"}),
        &mut answer,
        false,
    );
    assert_eq!(clicked["ok"], true, "{clicked}");
    let snapshot = f.call("browser_snapshot", json!({}), &mut answer, false);
    assert_eq!(snapshot["ok"], true, "{snapshot}");
    assert!(snapshot["result"].as_str().unwrap().contains("Count: 1"));
    let state: Value =
        serde_json::from_slice(&std::fs::read(f.home.join("state.json")).unwrap()).unwrap();
    assert_eq!(state["counter"], 1);
    let requests = f.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1]["params"]["name"], "browser_click");
    assert_eq!(
        requests[1]["params"]["arguments"],
        json!({"ref":"increment"})
    );
    assert_eq!(answer.asked, 0);
}

#[test]
fn browser_close_releases_page_and_later_snapshot_reports_real_error() {
    let f = Fixture::new();
    f.policy("allow");
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    assert_eq!(
        f.call(
            "browser_navigate",
            json!({"url":f.url()}),
            &mut answer,
            false
        )["ok"],
        true
    );
    let closed = f.call("browser_close", json!({}), &mut answer, false);
    assert_eq!(closed["ok"], true, "{closed}");
    let snapshot = f.call("browser_snapshot", json!({}), &mut answer, false);
    assert_eq!(snapshot["ok"], false, "{snapshot}");
    assert_eq!(snapshot["result_error"], true);
    assert!(
        snapshot["result"]
            .as_str()
            .unwrap()
            .contains("no open page")
    );
    let state: Value =
        serde_json::from_slice(&std::fs::read(f.home.join("state.json")).unwrap()).unwrap();
    assert_eq!(state["closed"], true);
    assert_eq!(state["url"], Value::Null);
    assert_eq!(f.requests().len(), 3);
    assert_eq!(f.requests()[1]["params"]["name"], "browser_close");
    assert_eq!(answer.asked, 0);
}

#[test]
fn browser_explicit_ask_approval_reaches_one_exact_stdio_call() {
    let f = Fixture::new();
    f.policy("ask");
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let result = f.call(
        "browser_navigate",
        json!({"url":f.url()}),
        &mut answer,
        true,
    );
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(answer.asked, 1);
    let requests = f.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["params"]["name"], "browser_navigate");
    assert_eq!(requests[0]["params"]["arguments"]["url"], f.url());
}

#[test]
fn browser_exact_deny_survives_server_allow_without_launching_fixture() {
    let f = Fixture::new();
    f.policy("allow");
    let report = permission_command(
        &f.home,
        &PermissionScope::default(),
        &f.work,
        &format!("deny {}", f.wire("browser_click")),
    )
    .unwrap();
    assert!(report.to_ascii_lowercase().contains("deny"), "{report}");
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let result = f.call(
        "browser_click",
        json!({"ref":"increment"}),
        &mut answer,
        true,
    );
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(answer.asked, 0);
    assert!(f.requests().is_empty());
    assert!(!f.home.join("calls.jsonl").exists());
}

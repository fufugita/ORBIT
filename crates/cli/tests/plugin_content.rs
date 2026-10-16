#![cfg(target_os = "linux")]

use orbit_adapter::types::ChatRole;
use orbit_cli::tool_runtime::{
    self, ApprovalChannel, ApprovalRequest, ApprovalVerdict, AutoGrants, PermissionScope,
};
use orbit_plugin_compat::{InspectOptions, PluginFormat, PluginStore, StoreScope};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

const AGENT: &str = include_str!("../../engine/tests/fixtures/hookify-agent.txt");
const SKILL_BODY: &str = "Review the selected change against its evidence.\nKeep the relative reference at ${CLAUDE_PLUGIN_ROOT}/references/review.txt.\n";

struct Mock {
    url: String,
    state: orbit_mock_provider::server::ServerState,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Mock {
    fn new() -> Self {
        let (ready, receive) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (address, state, handle) = orbit_mock_provider::server::spawn().await.unwrap();
                ready.send((address, state)).unwrap();
                let _ = stopped.await;
                handle.abort();
                let _ = handle.await;
            });
        });
        let (address, state) = receive.recv().unwrap();
        Self {
            url: format!("http://{address}"),
            state,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn calls(&self) -> u64 {
        self.state.requests.load(Ordering::SeqCst)
    }

    fn body(&self) -> Value {
        self.state.last_body.lock().unwrap().clone().unwrap()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

struct Approve;

impl ApprovalChannel for Approve {
    fn ask(&mut self, _: &ApprovalRequest, _: bool) -> ApprovalVerdict {
        ApprovalVerdict::AllowOnce
    }
}

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    work: PathBuf,
    source: PathBuf,
    cx: orbit_tools::ToolContext,
    mock: Mock,
}

impl Fixture {
    fn new(model: &str) -> Self {
        let root = std::env::temp_dir().join(format!("orbit-plugin-content-{}", ulid::Ulid::new()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.join("home");
        let work = root.join("workspace");
        let source = root.join("source");
        for path in [&home, &work, &source] {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let mock = Mock::new();
        let cx = orbit_tools::ToolContext::new(home.clone(), "owner".into(), work.clone());
        let fixture = Self {
            root,
            home,
            work,
            source,
            cx,
            mock,
        };
        write(
            &fixture.home,
            "providers.toml",
            format!(
                "[[provider]]\nname='fixture'\nurl='{}'\n[[provider.models]]\nid='{model}'\n",
                fixture.mock.url
            ),
        );
        let config = orbit_cli::phase_routing::resolve_model(
            &orbit_cli::config::ProvidersConfig::load(&fixture.home).unwrap(),
            &format!("fixture/{model}"),
            None,
        )
        .unwrap()
        .turn_config(None)
        .unwrap();
        tool_runtime::remember_turn_config(&fixture.cx, &config);
        write(
            &fixture.source,
            ".claude-plugin/plugin.json",
            r#"{"name":"hookify","version":"1.0.0","description":"Review changes"}"#,
        );
        write(&fixture.source, "agents/conversation-analyzer.md", AGENT);
        write(
            &fixture.source,
            "skills/review/SKILL.md",
            format!(
                "---\nname: review\ndescription: Review the selected change\n---\n{SKILL_BODY}"
            ),
        );
        write(
            &fixture.source,
            "references/review.txt",
            "Original reference bytes: λ → evidence.\n",
        );
        fixture
    }

    fn import(&self, scope: StoreScope, enabled: bool) {
        let receipt = PluginStore::open(&self.home, &self.work, true)
            .unwrap()
            .import(
                &self.source,
                &InspectOptions {
                    format: Some(PluginFormat::Claude),
                    ..Default::default()
                },
                scope,
                enabled,
            )
            .unwrap();
        assert_eq!(receipt.plugin.enabled, enabled);
    }

    fn call(&self, name: &str, arguments: Value) -> Value {
        let call = orbit_cli::PendingToolCall {
            index: 0,
            id: ulid::Ulid::new().to_string(),
            name: name.into(),
            arguments: serde_json::to_vec(&arguments).unwrap(),
        };
        let (output, _) = tool_runtime::execute_call(
            &self.home,
            "owner",
            "decision",
            &call,
            true,
            false,
            &mut Approve,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
            &self.cx,
        )
        .unwrap();
        serde_json::from_str(&output).unwrap()
    }

    fn system(&self) -> String {
        orbit_engine::context::build_system_prompt(
            &self.home,
            &self.work,
            "fixture-notools",
            &["Skill", "Task"],
            "",
        )
        .text
    }

    fn agents(&self) -> orbit_engine::agent_store::AgentStore {
        orbit_engine::agent_store::AgentStore::new(&self.home, "owner").unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write(root: &Path, relative: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn enabled_content_namespaced_skill_is_discovered_and_loaded() {
    let fixture = Fixture::new("fixture-notools");
    fixture.import(StoreScope::User, true);
    let result = fixture.call("Skill", json!({"name":"hookify:review"}));
    assert_eq!(
        result["ok"], true,
        "installed skill is not executable: {result}"
    );
    let root = result["result"]["source_root"]
        .as_str()
        .expect("missing bound asset root");
    assert_eq!(
        result["result"]["body"],
        SKILL_BODY.trim().replace("${CLAUDE_PLUGIN_ROOT}", root)
    );
    let system = fixture.system();
    assert!(
        system.contains("hookify:review: Review the selected change"),
        "missing namespaced skill description"
    );
    assert!(
        !system.contains(SKILL_BODY.trim()),
        "discovery eagerly inserted the skill body"
    );
    assert_eq!(
        fixture.mock.calls(),
        0,
        "loading a skill invoked a provider"
    );
}

#[test]
fn enabled_content_real_agent_instructions_reach_new_and_resumed_requests_once() {
    let fixture = Fixture::new("fixture-notools");
    fixture.import(StoreScope::User, true);
    let original_body = orbit_plugin_compat::parse_frontmatter(AGENT)
        .unwrap()
        .body
        .trim()
        .to_owned();
    let first = fixture.call(
        "Task",
        json!({"agent":"hookify:conversation-analyzer","prompt":"Review the change"}),
    );
    assert_eq!(
        first["ok"], true,
        "installed agent is not executable: {first}"
    );
    let id = first["result"]["agent_id"].as_str().unwrap();
    let first_body = fixture.mock.body();
    let saved = fixture.agents().load(id).unwrap();
    assert!(saved.transcript.iter().all(
        |message| message.role != ChatRole::System && !message.content.contains(&original_body)
    ));
    let resumed = fixture.call("Task", json!({"agent":"hookify:conversation-analyzer","resume":id,"prompt":"Review the next change"}));
    assert_eq!(
        resumed["ok"], true,
        "resumed installed agent failed: {resumed}"
    );
    assert_eq!(resumed["result"]["agent_id"], id);
    assert_eq!(fixture.mock.calls(), 2);
    for request in [first_body, fixture.mock.body()] {
        let system = request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] == "system")
            .map(|message| message["content"].as_str().unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            system.matches(&original_body).count(),
            1,
            "original body lost or inserted twice"
        );
        let names = request["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["function"]["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Read", "Grep"]);
    }
}

#[test]
fn enabled_content_project_discovery_uses_actual_context_not_process_directory() {
    let fixture = Fixture::new("fixture-notools");
    assert_ne!(std::env::current_dir().unwrap(), fixture.work);
    fixture.import(StoreScope::Project, true);
    assert!(
        !fixture.system().contains("hookify:review"),
        "untrusted project content exposed"
    );
    orbit_tools::permissions::FolderTrust::new(fixture.home.clone())
        .trust(&fixture.work)
        .unwrap();
    let result = fixture.call("Skill", json!({"name":"hookify:review"}));
    assert_eq!(
        result["ok"], true,
        "trusted actual project skill was not resolved: {result}"
    );
    assert!(fixture.system().contains("hookify:review"));
}

#[test]
fn invocation_controls_agent_ceiling_denies_actual_unadvertised_tool_before_grants() {
    let fixture = Fixture::new("fixture-bash");
    write(
        &fixture.home,
        "agents/restricted.md",
        "---\nname: restricted\ndescription: Read evidence\ntools: [Read]\nmaxTurns: 3\n---\nUse only the permitted Read tool.\n",
    );
    write(
        &fixture.home,
        "permissions.toml",
        "[allow]\ntools=['Bash']\n",
    );
    let result = fixture.call(
        "Task",
        json!({"agent":"restricted","prompt":"Review evidence"}),
    );
    assert_eq!(
        result["ok"], true,
        "fixture turn did not complete: {result}"
    );
    assert!(
        !fixture.work.join("approval-probe.txt").exists(),
        "unadvertised Bash escaped the child tool ceiling"
    );
    let saved = fixture
        .agents()
        .load(result["result"]["agent_id"].as_str().unwrap())
        .unwrap();
    let tool = saved
        .transcript
        .iter()
        .find(|message| message.role == ChatRole::Tool)
        .expect("no actual tool result");
    assert!(
        orbit_tools::result_is_denial(&tool.content),
        "actual tool call was not refused: {}",
        tool.content
    );
    assert_eq!(fixture.mock.calls(), 2);
}

#[test]
fn invocation_controls_policy_skill_uses_real_child_without_mutating_parent() {
    let fixture = Fixture::new("fixture-bash");
    write(
        &fixture.source,
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: Read evidence\nallowed-tools: [Read]\ncontext: fork\n---\nReview the selected evidence.\n",
    );
    fixture.import(StoreScope::User, true);
    write(
        &fixture.home,
        "permissions.toml",
        "[allow]\ntools=['Bash']\n",
    );
    let result = fixture.call("Skill", json!({"name":"hookify:review"}));
    assert_eq!(
        result["ok"], true,
        "restricted skill did not finish: {result}"
    );
    assert_eq!(result["result"]["mode"], "restricted_child");
    assert!(
        result["result"].get("body").is_none(),
        "restricted instructions escaped into the parent"
    );
    assert_eq!(
        fixture.mock.calls(),
        2,
        "skill did not execute a real child turn"
    );
    assert!(!fixture.work.join("approval-probe.txt").exists());
    assert!(
        fixture
            .cx
            .ext::<orbit_cli::plugin_content::InvocationToolCeiling>()
            .is_none(),
        "skill changed the parent's tool ceiling"
    );
    let parent = fixture.call("Bash", json!({"command":"touch approval-probe.txt"}));
    assert_eq!(
        parent["ok"], true,
        "parent authority changed after skill: {parent}"
    );
    assert!(fixture.work.join("approval-probe.txt").exists());
}

#[test]
fn invocation_controls_empty_and_inherited_ceilings_deny_actual_calls() {
    for tools in ["[]", "[Read, Bash]"] {
        let fixture = Fixture::new("fixture-bash");
        write(
            &fixture.source,
            "agents/conversation-analyzer.md",
            format!(
                "---\nname: conversation-analyzer\ndescription: Review evidence\ntools: {tools}\n---\nReview the evidence.\n"
            ),
        );
        fixture.import(StoreScope::User, true);
        if tools != "[]" {
            orbit_cli::plugin_content::restrict_context(
                &fixture.cx,
                Some(&["Read".into(), "Task".into()]),
            )
            .unwrap();
        }
        write(
            &fixture.home,
            "permissions.toml",
            "[allow]\ntools=['Bash']\n",
        );
        let result = fixture.call(
            "Task",
            json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
        );
        assert_eq!(result["ok"], true, "turn failed: {result}");
        assert_eq!(
            fixture.mock.calls(),
            2,
            "no actual unadvertised call was received"
        );
        assert!(
            !fixture.work.join("approval-probe.txt").exists(),
            "child widened {tools} ceiling"
        );
        let saved = fixture
            .agents()
            .load(result["result"]["agent_id"].as_str().unwrap())
            .unwrap();
        let tool = saved
            .transcript
            .iter()
            .find(|message| message.role == ChatRole::Tool)
            .unwrap();
        assert!(
            orbit_tools::result_is_denial(&tool.content),
            "actual result was not denied: {}",
            tool.content
        );
    }
}

#[test]
fn enabled_content_disabled_packages_are_not_discovered_or_executed() {
    let fixture = Fixture::new("fixture-notools");
    fixture.import(StoreScope::User, false);
    assert!(!fixture.system().contains("hookify:review"));
    let skill = fixture.call("Skill", json!({"name":"hookify:review"}));
    let agent = fixture.call(
        "Task",
        json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
    );
    assert_eq!(skill["ok"], false);
    assert_eq!(agent["ok"], false);
    assert_eq!(fixture.mock.calls(), 0);
}

#[test]
fn invocation_controls_origin_and_arguments_are_literal() {
    use orbit_cli::plugin_content::{InvocationOrigin, expand_prompt, invoke_skill};
    let fixture = Fixture::new("fixture-notools");
    write(
        &fixture.source,
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: Explicit review\ndisable-model-invocation: true\n---\nReview $ARGUMENTS, then $1.\n",
    );
    fixture.import(StoreScope::User, true);
    assert!(!fixture.system().contains("hookify:review"));
    let forged = fixture.call(
        "Skill",
        json!({"name":"hookify:review","user_invocation":true}),
    );
    assert_eq!(forged["ok"], false, "model JSON forged user authority");
    let text = "$(touch should-not-exist) $ARGUMENTS `touch should-not-exist`";
    let explicit = invoke_skill(
        &fixture.cx,
        "owner",
        "hookify:review",
        &json!({"arguments":[text]}),
        InvocationOrigin::User,
        &PermissionScope::default(),
        &mut Approve,
    )
    .unwrap();
    assert_eq!(explicit["body"], format!("Review {text}, then {text}."));
    assert_eq!(
        expand_prompt("$1 $ARGUMENTS", &[text.into()], None).unwrap(),
        format!("{text} {text}")
    );
    assert!(!fixture.work.join("should-not-exist").exists());
    assert_eq!(fixture.mock.calls(), 0);
}

#[test]
fn review_skill_builtin_and_local_agent_resolution_is_explicit() {
    for agent in ["Explore", "conversation-analyzer"] {
        let fixture = Fixture::new("fixture-notools");
        write(
            &fixture.source,
            "skills/review/SKILL.md",
            format!(
                "---\nname: review\ndescription: Review evidence\ncontext: fork\nagent: {agent}\n---\nReview this evidence.\n"
            ),
        );
        fixture.import(StoreScope::User, true);
        let result = fixture.call("Skill", json!({"name":"hookify:review"}));
        assert_eq!(
            result["ok"], true,
            "valid agent reference {agent} failed: {result}"
        );
        assert_eq!(fixture.mock.calls(), 1);
        assert_eq!(result["result"]["mode"], "restricted_child");
    }
    let fixture = Fixture::new("fixture-notools");
    write(
        &fixture.home,
        "agents/conversation-analyzer.md",
        "---\nname: conversation-analyzer\ndescription: Native review\n---\nNative review instructions.\n",
    );
    write(
        &fixture.source,
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: Review evidence\ncontext: fork\nagent: conversation-analyzer\n---\nReview evidence.\n",
    );
    fixture.import(StoreScope::User, true);
    let ambiguous = fixture.call("Skill", json!({"name":"hookify:review"}));
    assert_eq!(
        ambiguous["ok"], false,
        "ambiguous exact/local name silently won: {ambiguous}"
    );
    assert_eq!(fixture.mock.calls(), 0);
}

#[test]
fn review_skill_result_scanning_and_encoded_bounds_cover_actual_tool_output() {
    use sha2::Digest;
    for body in [
        "Credential fixture: ghp_abcdefghijklmnopqrstuvwxyz123456".to_string(),
        "\"\\".repeat(27_000),
    ] {
        let fixture = Fixture::new("fixture-notools");
        write(
            &fixture.source,
            "skills/review/SKILL.md",
            format!("---\nname: review\ndescription: Review evidence\n---\n{body}\n"),
        );
        fixture.import(StoreScope::User, true);
        let result = fixture.call("Skill", json!({"name":"hookify:review"}));
        let encoded = serde_json::to_vec(&result).unwrap();
        assert!(
            encoded.len() <= 64 * 1024,
            "encoded Skill result escaped its bound: {}",
            encoded.len()
        );
        assert!(
            !String::from_utf8(encoded)
                .unwrap()
                .contains("ghp_abcdefghijklmnopqrstuvwxyz123456"),
            "source credential reached the outgoing tool result"
        );
        let returned = result.to_string();
        let (records, _) = orbit_ledger::verify_ledger(&fixture.home.join("ledger")).unwrap();
        let recorded = records
            .iter()
            .rev()
            .find_map(|record| match &record.record.event {
                orbit_ledger::event::LedgerEvent::ToolResult(result)
                    if result.tool_name == "Skill" =>
                {
                    Some(result)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(recorded.output_bytes, returned.len() as u64);
        assert_eq!(
            recorded.output_sha256,
            hex::encode(sha2::Sha256::digest(returned.as_bytes()))
        );
        assert_eq!(
            recorded.status,
            if result["ok"] == true { "ok" } else { "error" }
        );
        assert_eq!(fixture.mock.calls(), 0);
    }
}

struct CountDeny(usize);
impl ApprovalChannel for CountDeny {
    fn ask(&mut self, _: &ApprovalRequest, _: bool) -> ApprovalVerdict {
        self.0 += 1;
        ApprovalVerdict::Deny
    }
}

#[test]
fn review_asset_uri_and_resolved_project_policies_intersect_before_grants() {
    for effect in ["deny", "ask"] {
        for use_uri in [true, false] {
            for grant in ["auto", "persistent", "session"] {
                let fixture = Fixture::new("fixture-notools");
                fixture.import(StoreScope::User, true);
                orbit_tools::permissions::FolderTrust::new(fixture.home.clone())
                    .trust(&fixture.work)
                    .unwrap();
                let loaded = fixture.call("Skill", json!({"name":"hookify:review"}));
                let uri = format!(
                    "{}/references/review.txt",
                    loaded["result"]["source_root"].as_str().unwrap()
                );
                let catalog =
                    orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true).unwrap();
                let binding = catalog
                    .skills
                    .iter()
                    .find(|entry| entry.skill.name == "hookify:review")
                    .unwrap()
                    .binding
                    .as_ref()
                    .unwrap();
                let actual = binding.root.join("references/review.txt");
                let selector = format!(
                    "Read({})",
                    if use_uri {
                        uri.clone()
                    } else {
                        actual.to_string_lossy().into_owned()
                    }
                );
                fs::create_dir_all(fixture.work.join(".orbit")).unwrap();
                fs::set_permissions(
                    fixture.work.join(".orbit"),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
                write(
                    &fixture.work,
                    ".orbit/settings.toml",
                    format!(
                        "[permissions]\n{effect} = [{}]\n",
                        serde_json::to_string(&selector).unwrap()
                    ),
                );
                let available =
                    orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true).unwrap();
                assert!(
                    available
                        .skills
                        .iter()
                        .any(|entry| entry.skill.name == "hookify:review"),
                    "permission fixture became unavailable before Read policy evaluation"
                );
                let call = orbit_cli::PendingToolCall {
                    index: 0,
                    id: ulid::Ulid::new().to_string(),
                    name: "Read".into(),
                    arguments: serde_json::to_vec(&json!({"file_path":uri})).unwrap(),
                };
                let mut approval = CountDeny(0);
                let mut grants = AutoGrants::new();
                if grant == "persistent" {
                    write(
                        &fixture.home,
                        "permissions.toml",
                        "[allow]\ntools=['Read']\n",
                    );
                }
                if grant == "session" {
                    grants.grant("Read");
                }
                let (output, _) = tool_runtime::execute_call(
                    &fixture.home,
                    "owner",
                    "decision",
                    &call,
                    grant == "auto",
                    true,
                    &mut approval,
                    &mut grants,
                    &PermissionScope::default(),
                    &fixture.cx,
                )
                .unwrap();
                assert!(
                    orbit_tools::result_is_denial(&output),
                    "{effect} policy on URI={use_uri} was bypassed: {output}"
                );
                assert_eq!(
                    approval.0,
                    usize::from(effect == "ask"),
                    "explicit ask must survive convenience grants: effect={effect}, uri={use_uri}, grant={grant}, output={output}"
                );
                assert!(!output.contains("Original reference bytes"));
            }
        }
    }
}

struct ScriptedProvider {
    child: std::process::Child,
    requests: PathBuf,
}

impl ScriptedProvider {
    fn new(fixture: &Fixture, alpha: &str, beta: &str) -> Self {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        write(
            &fixture.root,
            "provider.py",
            r#"import http.server, json, sys
class Handler(http.server.BaseHTTPRequestHandler):
    timeout = 3
    def log_message(self, *args):
        pass
    def do_POST(self):
        size = int(self.headers.get('content-length', '0'))
        if size <= 0 or size > 262144:
            self.send_error(413)
            return
        body = json.loads(self.rfile.read(size))
        with open(sys.argv[1], 'a') as output:
            output.write(json.dumps(body) + '\n')
        messages = body.get('messages', [])
        if messages and messages[-1].get('role') == 'tool':
            delta = {'content':'child MCP invocation complete'}
            finish = 'stop'
        else:
            beta = any(message.get('role') == 'user' and 'attempt-beta' in message.get('content', '') for message in messages)
            delta = {'tool_calls':[{'index':0,'id':'child-mcp-call','type':'function','function':{'name':sys.argv[3] if beta else sys.argv[2],'arguments':'{}'}}]}
            finish = 'tool_calls'
        chunks = [{'id':'fixture','choices':[{'delta':delta,'finish_reason':None}]}, {'id':'fixture','choices':[{'delta':{},'finish_reason':finish}]}]
        reply = ''.join('data: ' + json.dumps(chunk) + '\n\n' for chunk in chunks) + 'data: [DONE]\n\n'
        encoded = reply.encode()
        self.send_response(200)
        self.send_header('content-type', 'text/event-stream')
        self.send_header('content-length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
print('http://127.0.0.1:' + str(server.server_port), flush=True)
server.serve_forever(poll_interval=0.1)
"#,
        );
        let requests = fixture.root.join("provider-requests.jsonl");
        let mut child = Command::new("python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &fixture.home)
            .env("CODEX_HOME", fixture.root.join("codex"))
            .env("CLAUDE_CONFIG_DIR", fixture.root.join("claude"))
            .env("HERMES_HOME", fixture.root.join("hermes"))
            .env("XDG_CONFIG_HOME", fixture.root.join("xdg"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .current_dir(&fixture.work)
            .arg(fixture.root.join("provider.py"))
            .arg(&requests)
            .arg(alpha)
            .arg(beta)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (ready, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let result = std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .map(|_| line);
            let _ = ready.send(result);
        });
        let url = match receive.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(Ok(url)) if !url.trim().is_empty() => url,
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                reader.join().unwrap();
                panic!("owned provider did not start");
            }
        };
        reader.join().unwrap();
        write(
            &fixture.home,
            "providers.toml",
            format!(
                "[[provider]]\nname='fixture'\nurl='{}'\n[[provider.models]]\nid='fixture-mcp'\n",
                url.trim()
            ),
        );
        let config = orbit_cli::phase_routing::resolve_model(
            &orbit_cli::config::ProvidersConfig::load(&fixture.home).unwrap(),
            "fixture/fixture-mcp",
            None,
        )
        .unwrap()
        .turn_config(None)
        .unwrap();
        tool_runtime::remember_turn_config(&fixture.cx, &config);
        Self { child, requests }
    }

    fn requests(&self) -> Vec<Value> {
        fs::read_to_string(&self.requests)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl Drop for ScriptedProvider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn review_bad_effort_does_not_disable_healthy_native_and_plugin_content() {
    let fixture = Fixture::new("fixture-notools");
    write(
        &fixture.source,
        "agents/conversation-analyzer.md",
        "---\nname: conversation-analyzer\ndescription: Bad effort\neffort: ' low '\n---\nReview evidence.\n",
    );
    fixture.import(StoreScope::User, true);
    let skill = fixture.call("Skill", json!({"name":"hookify:review"}));
    assert_eq!(
        skill["ok"], true,
        "unrelated malformed effort disabled a healthy skill: {skill}"
    );
    let native = fixture.call(
        "Task",
        json!({"agent":"Explore","prompt":"Review evidence"}),
    );
    assert_eq!(
        native["ok"], true,
        "malformed plugin effort disabled a built-in: {native}"
    );
    let bad = fixture.call(
        "Task",
        json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
    );
    assert_eq!(bad["ok"], false);
    assert_eq!(fixture.mock.calls(), 1);
}

#[test]
fn review_mcp_selector_is_advertised_and_executes_with_parent_intersection() {
    let fixture = Fixture::new("fixture-notools");
    let server = format!(
        "fixture{}",
        ulid::Ulid::new().to_string().to_ascii_lowercase()
    );
    write(
        &fixture.root,
        "server.py",
        r#"import json, sys
for line in sys.stdin:
    req = json.loads(line)
    if 'id' not in req:
        continue
    method = req.get('method')
    if method == 'initialize':
        result = {'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'fixture','version':'1'}}
    elif method == 'tools/list':
        result = {'tools':[{'name':name,'description':'Read a fixture','inputSchema':{'type':'object'}} for name in ['alpha','beta']]}
    elif method == 'tools/call':
        with open(sys.argv[1], 'a') as output:
            output.write(req['params']['name'] + '\n')
        result = {'content':[{'type':'text','text':req['params']['name']}]}
    else:
        result = {}
    print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result}), flush=True)
"#,
    );
    let calls = fixture.root.join("mcp-calls.txt");
    write(&fixture.home, "mcp.json", serde_json::to_vec(&json!({"servers":{(server.clone()):{"command":"python3","args":[fixture.root.join("server.py"),&calls],"timeout_ms":1000,"initialize_timeout_ms":1000}}})).unwrap());
    let wildcard = format!("mcp__{server}__*");
    let alpha = orbit_mcp::wire_name(&server, "alpha");
    let beta = orbit_mcp::wire_name(&server, "beta");
    let provider = ScriptedProvider::new(&fixture, &alpha, &beta);
    write(
        &fixture.source,
        "agents/conversation-analyzer.md",
        format!(
            "---\nname: conversation-analyzer\ndescription: Read fixture\ntools: [{wildcard}]\n---\nRead the fixture.\n"
        ),
    );
    fixture.import(StoreScope::User, true);
    let result = fixture.call(
        "Task",
        json!({"agent":"hookify:conversation-analyzer","prompt":"Read fixture"}),
    );
    assert_eq!(result["ok"], true, "wildcard agent failed: {result}");
    let requests = provider.requests();
    assert_eq!(
        requests.len(),
        2,
        "child did not return its MCP result to the provider"
    );
    let request = &requests[0];
    let names: Vec<_> = request["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![alpha.as_str(), beta.as_str()],
        "accepted MCP selector lost advertised tools"
    );
    let first = fixture
        .agents()
        .load(result["result"]["agent_id"].as_str().unwrap())
        .unwrap();
    let tool = first
        .transcript
        .iter()
        .find(|message| message.role == ChatRole::Tool)
        .unwrap();
    assert!(
        !orbit_tools::result_is_error(&tool.content),
        "actual child MCP dispatch failed: {}",
        tool.content
    );
    assert!(tool.content.contains("alpha"));
    assert_eq!(
        requests[1]["messages"].as_array().unwrap().last().unwrap()["role"],
        "tool"
    );
    assert_eq!(fs::read_to_string(&calls).unwrap(), "alpha\n");
    orbit_cli::plugin_content::restrict_context(&fixture.cx, Some(&["Task".into(), alpha.clone()]))
        .unwrap();
    let narrower = fixture.call("Task", json!({"agent":"hookify:conversation-analyzer","prompt":"attempt-beta under the narrower selection"}));
    assert_eq!(
        narrower["ok"], true,
        "inherited exact MCP child selection failed: {narrower}"
    );
    let requests = provider.requests();
    assert_eq!(requests.len(), 4);
    let request = &requests[2];
    let names: Vec<_> = request["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![alpha.as_str()],
        "child selector widened inherited MCP selection"
    );
    let second = fixture
        .agents()
        .load(narrower["result"]["agent_id"].as_str().unwrap())
        .unwrap();
    let tool = second
        .transcript
        .iter()
        .find(|message| message.role == ChatRole::Tool)
        .unwrap();
    assert!(
        orbit_tools::result_is_denial(&tool.content),
        "unadvertised child beta was not denied: {}",
        tool.content
    );
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "alpha\n",
        "denied child tool had a side effect"
    );
    let denied = fixture.call(&beta, json!({}));
    assert_eq!(
        denied["denied"], true,
        "parent narrower selection was widened"
    );
    let called = fixture.call(&alpha, json!({}));
    assert_eq!(
        called["ok"], true,
        "selected MCP tool did not execute: {called}"
    );
    assert!(called.to_string().contains("alpha"));
    let invalid = orbit_cli::plugin_content::restrict_context(
        &fixture.cx,
        Some(&[format!("{alpha}(argument)")]),
    );
    assert!(
        invalid.is_err(),
        "unsupported MCP argument selector was accepted"
    );
}

#[test]
fn enabled_content_assets_survive_source_removal_with_exact_inventory_bytes() {
    use sha2::Digest;
    let fixture = Fixture::new("fixture-notools");
    let mut skill = "hookify:review";
    let mut asset = "references/review.txt";
    let expected = if let Some(corpus) = std::env::var_os("ORBIT_PLUGIN_TEST_CORPUS") {
        let corpus = PathBuf::from(corpus).join("hookify");
        write(
            &fixture.source,
            ".claude-plugin/plugin.json",
            fs::read(corpus.join(".claude-plugin/plugin.json")).unwrap(),
        );
        let original_skill = fs::read(corpus.join("skills/writing-rules/SKILL.md")).unwrap();
        let original_asset = fs::read(corpus.join("examples/dangerous-rm.local.md")).unwrap();
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&original_skill)),
            "2994b5d3152243b1a1cbf8358e9d7c18f290f31a23920647f31053c3efdf990d"
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&original_asset)),
            "fad5e3e0d5dc1f60901d2d4d948a609eeeb69d0e91f49fcb02d81e4e01489acf"
        );
        write(
            &fixture.source,
            "skills/writing-rules/SKILL.md",
            original_skill,
        );
        write(
            &fixture.source,
            "examples/dangerous-rm.local.md",
            &original_asset,
        );
        skill = "hookify:writing-hookify-rules";
        asset = "examples/dangerous-rm.local.md";
        eprintln!("verified original Hookify skill and asset corpus exercised");
        original_asset
    } else {
        fs::read(fixture.source.join(asset)).unwrap()
    };
    fixture.import(StoreScope::User, true);
    let loaded = fixture.call("Skill", json!({"name":skill}));
    assert_eq!(
        loaded["ok"], true,
        "installed source skill failed: {loaded}"
    );
    let root = loaded["result"]["source_root"].as_str().unwrap();
    let uri = format!("{root}/{asset}");
    let catalog = orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true).unwrap();
    let binding = catalog
        .skills
        .iter()
        .find(|entry| entry.skill.name == skill)
        .unwrap()
        .binding
        .as_ref()
        .unwrap();
    fs::remove_dir_all(&fixture.source).unwrap();
    let store = PluginStore::open(&fixture.home, &fixture.work, false).unwrap();
    assert_eq!(
        store
            .read_asset(&binding.plugin, &binding.digest, asset, 64 * 1024)
            .unwrap(),
        expected
    );
    orbit_cli::plugin_content::restrict_context(&fixture.cx, Some(&[format!("Read({uri})")]))
        .unwrap();
    let read = fixture.call("Read", json!({"file_path":uri}));
    assert_eq!(
        read["ok"], true,
        "bound asset did not use URI ceiling: {read}"
    );
    let expected_numbered = String::from_utf8(expected)
        .unwrap()
        .lines()
        .enumerate()
        .map(|(index, line)| format!("{}\t{line}", index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        read["content"],
        orbit_tools::scan::scan_result(&expected_numbered).text
    );
    assert_eq!(fixture.mock.calls(), 0);
}

#[test]
fn enabled_content_assets_reject_stale_traversal_tamper_links_and_read_denial() {
    for mode in [
        "stale",
        "traversal",
        "oversized",
        "tamper",
        "link",
        "disabled",
        "denied",
    ] {
        let fixture = Fixture::new("fixture-notools");
        fixture.import(StoreScope::User, true);
        let loaded = fixture.call("Skill", json!({"name":"hookify:review"}));
        let uri = format!(
            "{}/references/review.txt",
            loaded["result"]["source_root"].as_str().unwrap()
        );
        let catalog =
            orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true).unwrap();
        let binding = catalog
            .skills
            .iter()
            .find(|entry| entry.skill.name == "hookify:review")
            .unwrap()
            .binding
            .as_ref()
            .unwrap();
        let store = PluginStore::open(&fixture.home, &fixture.work, false).unwrap();
        let mut request = uri.clone();
        match mode {
            "stale" => {
                assert!(
                    store
                        .read_asset(
                            &binding.plugin,
                            &"0".repeat(64),
                            "references/review.txt",
                            64 * 1024
                        )
                        .is_err()
                );
                continue;
            }
            "oversized" => {
                assert!(
                    store
                        .read_asset(&binding.plugin, &binding.digest, "references/review.txt", 1)
                        .is_err()
                );
                continue;
            }
            "traversal" => {
                request = format!(
                    "{}/../outside.txt",
                    loaded["result"]["source_root"].as_str().unwrap()
                )
            }
            "disabled" => {
                store
                    .disable(&binding.plugin, &store.list().unwrap().revision)
                    .unwrap();
            }
            "denied" => {
                write(
                    &fixture.home,
                    "permissions.toml",
                    "[deny]\ntools=['Read']\n",
                );
            }
            "tamper" | "link" => {
                let path = binding.root.join("references/review.txt");
                fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700))
                    .unwrap();
                if mode == "tamper" {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&path, "outside-read-marker").unwrap();
                } else {
                    write(&fixture.root, "outside.txt", "outside-read-marker");
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink(fixture.root.join("outside.txt"), &path).unwrap();
                }
            }
            _ => unreachable!(),
        }
        let read = fixture.call("Read", json!({"file_path":request}));
        assert_eq!(read["ok"], false, "{mode} asset was admitted: {read}");
        assert!(
            !read.to_string().contains("outside-read-marker"),
            "outside bytes were exposed"
        );
        assert_eq!(fixture.mock.calls(), 0);
    }
}

#[test]
fn invocation_controls_mapped_model_and_effort_reach_fresh_and_resumed_child_wire() {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    let fixture = Fixture::new("fixture-notools");
    let target = Mock::new();
    write(
        &fixture.home,
        "providers.toml",
        format!(
            "[[provider]]\nname='fixture'\nurl='{}'\n[[provider.models]]\nid='parent-notools'\nsupported_efforts=['low','high']\ndefault_effort='low'\n[[provider]]\nname='mapped'\nurl='{}'\n[[provider.models]]\nid='family/exact-notools'\nsupported_efforts=['low','high']\ndefault_effort='high'\n",
            fixture.mock.url, target.url
        ),
    );
    let mut parent = orbit_cli::phase_routing::resolve_model(
        &orbit_cli::config::ProvidersConfig::load(&fixture.home).unwrap(),
        "fixture/parent-notools",
        None,
    )
    .unwrap()
    .turn_config(None)
    .unwrap();
    let parent_setting = EffortSetting::Value(EffortValue::Level("high".into()));
    orbit_cli::apply_effort_setting(&fixture.home, &mut parent, &parent_setting).unwrap();
    tool_runtime::remember_turn_config(&fixture.cx, &parent);
    tool_runtime::remember_effort_setting(&fixture.cx, &Some(parent_setting.clone()));
    let parent_before = format!("{parent:?}");
    write(
        &fixture.source,
        "agents/conversation-analyzer.md",
        "---\nname: conversation-analyzer\ndescription: Exact mapped model\nmodel: source-profile\neffort: low\ntools: []\n---\nReview the evidence.\n",
    );
    let mut options = InspectOptions {
        format: Some(PluginFormat::Claude),
        ..Default::default()
    };
    options.model_map.insert(
        "source-profile".into(),
        "mapped/family/exact-notools".into(),
    );
    PluginStore::open(&fixture.home, &fixture.work, true)
        .unwrap()
        .import(&fixture.source, &options, StoreScope::User, true)
        .unwrap();
    let first = fixture.call(
        "Task",
        json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
    );
    assert_eq!(first["ok"], true, "mapped fresh Task failed: {first}");
    let id = first["result"]["agent_id"].as_str().unwrap();
    let fresh_wire = target.body();
    let saved = fixture.agents().load(id).unwrap();
    assert_eq!(saved.model, "mapped/family/exact-notools");
    assert_eq!(
        saved.effort,
        Some(EffortSetting::Value(EffortValue::Level("low".into())))
    );
    let resumed = fixture.call("Task", json!({"agent":"hookify:conversation-analyzer","resume":id,"prompt":"Review the next evidence"}));
    assert_eq!(resumed["ok"], true, "mapped resumed Task failed: {resumed}");
    assert_eq!(resumed["result"]["agent_id"], id);
    let final_saved = fixture.agents().load(id).unwrap();
    assert_eq!(final_saved.turns, 2);
    assert_eq!(final_saved.model, saved.model);
    assert_eq!(final_saved.effort, saved.effort);
    assert!(final_saved.transcript.starts_with(&saved.transcript));
    for request in [fresh_wire, target.body()] {
        assert_eq!(
            request["model"], "family/exact-notools",
            "raw configured model identity changed"
        );
        assert_eq!(
            request["reasoning_effort"], "low",
            "profile effort was replaced by model default or parent"
        );
    }
    assert_eq!(target.calls(), 2);
    assert_eq!(
        fixture.mock.calls(),
        0,
        "mapped child leaked onto parent provider"
    );
    assert_eq!(
        format!(
            "{:?}",
            fixture
                .cx
                .ext::<tool_runtime::SessionTurnConfig>()
                .unwrap()
                .0
        ),
        parent_before
    );
    assert_eq!(
        fixture
            .cx
            .ext::<tool_runtime::SessionEffortSetting>()
            .unwrap()
            .0,
        Some(parent_setting)
    );
}

#[test]
fn invocation_controls_unmapped_model_and_unsupported_effort_refuse_before_dispatch() {
    for (model, effort, capabilities) in [
        (
            "model: unconfigured-source-alias\n",
            "",
            "supported_efforts=['low']\n",
        ),
        ("", "effort: true\n", "supported_efforts=['low']\n"),
        ("", "effort: high\n", "supported_efforts=[]\n"),
        ("", "effort: high\n", ""),
    ] {
        let fixture = Fixture::new("fixture-notools");
        write(
            &fixture.home,
            "providers.toml",
            format!(
                "[[provider]]\nname='fixture'\nurl='{}'\n[[provider.models]]\nid='fixture-notools'\n{capabilities}",
                fixture.mock.url
            ),
        );
        let parent = orbit_cli::phase_routing::resolve_model(
            &orbit_cli::config::ProvidersConfig::load(&fixture.home).unwrap(),
            "fixture/fixture-notools",
            None,
        )
        .unwrap()
        .turn_config(None)
        .unwrap();
        tool_runtime::remember_turn_config(&fixture.cx, &parent);
        let before = format!("{parent:?}");
        write(
            &fixture.source,
            "agents/conversation-analyzer.md",
            format!(
                "---\nname: conversation-analyzer\ndescription: Explicit capability requirement\n{model}{effort}tools: []\n---\nReview the evidence.\n"
            ),
        );
        fixture.import(StoreScope::User, true);
        let result = fixture.call(
            "Task",
            json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
        );
        assert_eq!(
            result["ok"], false,
            "unsupported declaration was silently adapted: {result}"
        );
        assert_eq!(
            fixture.mock.calls(),
            0,
            "unsupported declaration reached a provider"
        );
        assert!(
            fixture.agents().list().unwrap().is_empty(),
            "a refused profile created a durable agent"
        );
        assert_eq!(
            format!(
                "{:?}",
                fixture
                    .cx
                    .ext::<tool_runtime::SessionTurnConfig>()
                    .unwrap()
                    .0
            ),
            before
        );
        if !model.is_empty() {
            assert!(result["error"].as_str().unwrap().contains("--model-map"));
        }
    }
}

#[test]
fn invocation_controls_effort_absent_default_and_values_preserve_provider_types() {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    for kind in ["openai-compatible", "anthropic", "ollama"] {
        let cases = if kind == "ollama" {
            vec!["absent", "default", "boolean", "string"]
        } else {
            vec!["absent", "default", "value"]
        };
        for case in cases {
            let fixture = Fixture::new("fixture-notools");
            let capabilities = if kind == "ollama" {
                "supported_efforts=[true,false,'false']\ndefault_effort=true\n"
            } else {
                "supported_efforts=['low','high']\ndefault_effort='low'\n"
            };
            write(
                &fixture.home,
                "providers.toml",
                format!(
                    "[[provider]]\nname='fixture'\nkind='{kind}'\nurl='{}'\n[[provider.models]]\nid='fixture-notools'\n{capabilities}",
                    fixture.mock.url
                ),
            );
            let mut parent = orbit_cli::phase_routing::resolve_model(
                &orbit_cli::config::ProvidersConfig::load(&fixture.home).unwrap(),
                "fixture/fixture-notools",
                None,
            )
            .unwrap()
            .turn_config(None)
            .unwrap();
            let parent_value = if kind == "ollama" {
                EffortValue::Bool(false)
            } else {
                EffortValue::Level("high".into())
            };
            let parent_setting = EffortSetting::Value(parent_value.clone());
            orbit_cli::apply_effort_setting(&fixture.home, &mut parent, &parent_setting).unwrap();
            tool_runtime::remember_turn_config(&fixture.cx, &parent);
            tool_runtime::remember_effort_setting(&fixture.cx, &Some(parent_setting.clone()));
            let before = format!("{parent:?}");
            let (declaration, selection, expected) = match case {
                "absent" => (
                    "",
                    parent_setting.clone(),
                    serde_json::to_value(&parent_value).unwrap(),
                ),
                "default" => (
                    "effort: default\n",
                    EffortSetting::Default,
                    if kind == "ollama" {
                        json!(true)
                    } else {
                        json!("low")
                    },
                ),
                "boolean" => (
                    "effort: false\n",
                    EffortSetting::Value(EffortValue::Bool(false)),
                    json!(false),
                ),
                "string" => (
                    "effort: 'false'\n",
                    EffortSetting::Value(EffortValue::Level("false".into())),
                    json!("false"),
                ),
                "value" => (
                    "effort: low\n",
                    EffortSetting::Value(EffortValue::Level("low".into())),
                    json!("low"),
                ),
                _ => unreachable!(),
            };
            write(
                &fixture.source,
                "agents/conversation-analyzer.md",
                format!(
                    "---\nname: conversation-analyzer\ndescription: Exact typed effort\n{declaration}tools: []\n---\nReview evidence.\n"
                ),
            );
            fixture.import(StoreScope::User, true);
            let first = fixture.call(
                "Task",
                json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
            );
            assert_eq!(first["ok"], true, "{kind}/{case}: {first}");
            let first_wire = fixture.mock.body();
            let id = first["result"]["agent_id"].as_str().unwrap();
            assert_eq!(
                fixture.agents().load(id).unwrap().effort,
                Some(selection.clone()),
                "{kind}/{case}: typed selection was lost"
            );
            let resumed = fixture.call("Task", json!({"agent":"hookify:conversation-analyzer","resume":id,"prompt":"Review the next evidence"}));
            assert_eq!(resumed["ok"], true, "{kind}/{case}: {resumed}");
            assert_eq!(fixture.agents().load(id).unwrap().effort, Some(selection));
            for wire in [first_wire, fixture.mock.body()] {
                let actual = match kind {
                    "ollama" => &wire["think"],
                    "anthropic" => &wire["output_config"]["effort"],
                    _ => &wire["reasoning_effort"],
                };
                assert_eq!(
                    actual, &expected,
                    "{kind}/{case}: effort was translated or inherited incorrectly"
                );
            }
            assert_eq!(fixture.mock.calls(), 2);
            assert_eq!(
                format!(
                    "{:?}",
                    fixture
                        .cx
                        .ext::<tool_runtime::SessionTurnConfig>()
                        .unwrap()
                        .0
                ),
                before
            );
            assert_eq!(
                fixture
                    .cx
                    .ext::<tool_runtime::SessionEffortSetting>()
                    .unwrap()
                    .0,
                Some(parent_setting)
            );
        }
    }
}

#[test]
fn invocation_controls_user_invocable_is_enforced_by_host_origin() {
    use orbit_cli::plugin_content::{InvocationOrigin, invoke_skill};
    let fixture = Fixture::new("fixture-notools");
    write(
        &fixture.source,
        "skills/model-only/SKILL.md",
        "---\nname: model-only\ndescription: Model-selected review\nuser-invocable: false\n---\nReview the evidence without running tools.\n",
    );
    fixture.import(StoreScope::User, true);
    let denied = invoke_skill(
        &fixture.cx,
        "owner",
        "hookify:model-only",
        &json!({"origin":"model"}),
        InvocationOrigin::User,
        &PermissionScope::default(),
        &mut Approve,
    );
    assert!(denied.is_err(), "model JSON overrode trusted user origin");
    let allowed = fixture.call(
        "Skill",
        json!({"name":"hookify:model-only","user_invocation":true,"origin":"user"}),
    );
    assert_eq!(
        allowed["ok"], true,
        "user-invocable restriction incorrectly disabled model loading: {allowed}"
    );
    assert_eq!(allowed["result"]["mode"], "load");
    assert_eq!(fixture.mock.calls(), 0);
}

#[test]
fn enabled_content_unavailable_managed_store_preserves_native_runtime_and_reports_quarantine() {
    let fixture = Fixture::new("fixture-notools");
    fixture.import(StoreScope::User, true);
    write(
        &fixture.home,
        "skills/native-review/SKILL.md",
        "---\nname: native-review\ndescription: Native evidence review\n---\nKeep native review instructions.\n",
    );
    write(
        &fixture.home,
        "agents/native-reviewer.md",
        "---\nname: native-reviewer\ndescription: Native evidence review\ntools: [Read]\n---\nFollow the retained native review instructions.\n",
    );
    write(
        &fixture.home,
        "skills/shadow/SKILL.md",
        "---\nname: hookify:review\ndescription: Shadowed plugin identity\n---\nThis native shadow must never replace a quarantined plugin.\n",
    );
    write(
        &fixture.home,
        "agents/shadow.md",
        "---\nname: hookify:conversation-analyzer\ndescription: Shadowed plugin identity\ntools: [Read]\n---\nThis native shadow must never replace a quarantined plugin.\n",
    );
    assert_eq!(
        orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true)
            .unwrap_err()
            .code,
        "content_identity_collision",
        "healthy managed/native identity collisions stopped failing visibly"
    );
    let managed_root = fixture.home.join("plugins/portable");
    fs::set_permissions(&managed_root, fs::Permissions::from_mode(0o755)).unwrap();
    let unavailable = PluginStore::open(&fixture.home, &fixture.work, false)
        .and_then(|store| store.active())
        .expect_err("managed store privacy fixture remained available");
    assert_eq!(unavailable.code, "store_file_unsafe");
    let catalog = orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true).unwrap();
    assert!(
        catalog
            .skills
            .iter()
            .any(|entry| entry.skill.name == "native-review")
    );
    assert!(
        catalog
            .agents
            .iter()
            .any(|entry| entry.agent.name == "native-reviewer")
    );
    assert!(catalog.skills.iter().all(|entry| entry.binding.is_none()));
    assert!(catalog.agents.iter().all(|entry| entry.binding.is_none()));
    assert!(
        catalog
            .skills
            .iter()
            .all(|entry| !entry.skill.name.contains(':'))
    );
    assert!(
        catalog
            .agents
            .iter()
            .all(|entry| !entry.agent.name.contains(':'))
    );
    assert!(
        catalog
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("Namespaced native definitions are withheld"))
    );
    assert!(catalog.diagnostics.iter().any(|diagnostic| {
        diagnostic.contains("Managed plugin content is unavailable")
            && diagnostic.contains("store_file_unsafe")
    }));
    assert!(
        fixture.system().contains("store_file_unsafe"),
        "managed readiness diagnostic was hidden"
    );
    let native_skill = fixture.call("Skill", json!({"name":"native-review"}));
    assert_eq!(
        native_skill["ok"], true,
        "unavailable managed store disabled native skill: {native_skill}"
    );
    let native = fixture.call(
        "Task",
        json!({"agent":"native-reviewer","prompt":"Review evidence"}),
    );
    assert_eq!(
        native["ok"], true,
        "unavailable managed store disabled native Task: {native}"
    );
    assert!(
        fixture.mock.body()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["role"] == "system"
                && message["content"].as_str().is_some_and(
                    |body| body.contains("Follow the retained native review instructions.")
                ))
    );
    assert_eq!(fixture.mock.calls(), 1);
    let managed_skill = fixture.call("Skill", json!({"name":"hookify:review"}));
    let managed_agent = fixture.call(
        "Task",
        json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
    );
    assert_eq!(
        managed_skill["ok"], false,
        "quarantined managed skill executed: {managed_skill}"
    );
    assert_eq!(
        managed_agent["ok"], false,
        "quarantined managed agent executed: {managed_agent}"
    );
    assert_eq!(
        fixture.mock.calls(),
        1,
        "quarantined managed ID reached provider"
    );
    assert_eq!(
        fs::metadata(&managed_root).unwrap().permissions().mode() & 0o777,
        0o755,
        "catalog rewrote operator privacy state"
    );
    assert_eq!(
        fs::metadata(&fixture.home).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn enabled_content_failed_package_namespace_cannot_fall_back_to_native_shadows() {
    for failure in ["missing", "tampered"] {
        let fixture = Fixture::new("fixture-notools");
        fixture.import(StoreScope::User, true);
        let store = PluginStore::open(&fixture.home, &fixture.work, false).unwrap();
        let original = store.active().unwrap();
        let root = original
            .plugins
            .iter()
            .find(|entry| entry.plugin.id.name == "hookify")
            .unwrap()
            .root
            .clone();
        let healthy_source = fixture.root.join("healthy-source");
        write(
            &healthy_source,
            ".claude-plugin/plugin.json",
            r#"{"name":"healthy","description":"Healthy independent plugin"}"#,
        );
        write(
            &healthy_source,
            "skills/review/SKILL.md",
            "---\nname: review\ndescription: Healthy managed review\n---\nHealthy managed review instructions.\n",
        );
        store
            .import(
                &healthy_source,
                &InspectOptions {
                    format: Some(PluginFormat::Claude),
                    ..Default::default()
                },
                StoreScope::User,
                true,
            )
            .unwrap();
        write(
            &fixture.home,
            "skills/shadow/SKILL.md",
            "---\nname: hookify:review\ndescription: Native shadow\n---\nForbidden managed identity fallback.\n",
        );
        write(
            &fixture.home,
            "agents/shadow.md",
            "---\nname: hookify:conversation-analyzer\ndescription: Native shadow\ntools: [Read]\n---\nForbidden managed identity fallback.\n",
        );
        write(
            &fixture.home,
            "agents/native-reviewer.md",
            "---\nname: native-reviewer\ndescription: Ordinary native reviewer\ntools: [Read]\n---\nKeep ordinary native review available.\n",
        );
        if failure == "missing" {
            fs::set_permissions(root.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
            fs::rename(&root, fixture.root.join("quarantined-package")).unwrap();
        } else {
            let entry = root.join("skills/review/SKILL.md");
            fs::set_permissions(&entry, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&entry, "tampered managed package bytes").unwrap();
        }
        let active = store.active().unwrap();
        assert!(
            active
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity
                    == orbit_plugin_compat::DiagnosticSeverity::Error
                    && diagnostic.component_id.as_deref() == Some("hookify")),
            "fixture did not quarantine the failed package"
        );
        assert_eq!(active.plugins.len(), 1);
        assert_eq!(active.plugins[0].plugin.id.name, "healthy");
        let catalog =
            orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true).unwrap();
        assert!(
            catalog
                .skills
                .iter()
                .all(|entry| !entry.skill.name.starts_with("hookify:")),
            "failed skill namespace fell back to native content"
        );
        assert!(
            catalog
                .agents
                .iter()
                .all(|entry| !entry.agent.name.starts_with("hookify:")),
            "failed agent namespace fell back to native content"
        );
        assert!(
            catalog
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("namespaces remain reserved"))
        );
        let denied_skill = fixture.call("Skill", json!({"name":"hookify:review"}));
        let denied_agent = fixture.call(
            "Task",
            json!({"agent":"hookify:conversation-analyzer","prompt":"Review evidence"}),
        );
        assert_eq!(
            denied_skill["ok"], false,
            "quarantined Skill fell back: {denied_skill}"
        );
        assert_eq!(
            denied_agent["ok"], false,
            "quarantined Task fell back: {denied_agent}"
        );
        assert_eq!(fixture.mock.calls(), 0);
        let healthy = fixture.call("Skill", json!({"name":"healthy:review"}));
        assert_eq!(
            healthy["ok"], true,
            "unrelated managed plugin was quarantined: {healthy}"
        );
        assert_eq!(
            healthy["result"]["body"],
            "Healthy managed review instructions."
        );
        let native = fixture.call(
            "Task",
            json!({"agent":"native-reviewer","prompt":"Review evidence"}),
        );
        assert_eq!(
            native["ok"], true,
            "ordinary native Task was disabled: {native}"
        );
        assert_eq!(fixture.mock.calls(), 1);
        write(
            &fixture.home,
            "skills/healthy-shadow/SKILL.md",
            "---\nname: healthy:review\ndescription: Healthy identity collision\n---\nDo not silently resolve a healthy collision.\n",
        );
        assert_eq!(
            orbit_engine::skills::load_catalog(&fixture.home, &fixture.work, true)
                .unwrap_err()
                .code,
            "content_identity_collision",
            "healthy namespace collision was hidden by unrelated quarantine"
        );
    }
}

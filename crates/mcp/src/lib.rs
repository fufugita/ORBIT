//! orbit-mcp — the MCP client (roadmap phase 5, §Extensibility).
//!
//! stdio transport: servers from `.orbit/mcp.json` (project scope,
//! needs folder trust) and the user scope (`$ORBIT_HOME/mcp.json`).
//! Tools appear as `mcp__<server>__<tool>`; every result passes the
//! secret scanner before it enters the transcript. Declared at session
//! start so the tool list never changes mid-conversation.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// One configured server entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
}

/// The merged server map from both scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(default)]
    pub servers: std::collections::BTreeMap<String, McpServerConfig>,
}

impl McpConfig {
    /// Load user scope + project scope (project needs folder trust —
    /// the caller checks; cloning a repo cannot grant itself servers).
    pub fn load(home: &Path, project_trusted: bool) -> Self {
        let mut cfg = McpConfig::default();
        for (path, is_project) in [
            (home.join("mcp.json"), false),
            (Path::new(".orbit/mcp.json").to_path_buf(), true),
        ] {
            if is_project && !project_trusted {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(c) = serde_json::from_str::<McpConfig>(&text) {
                    for (name, server) in c.servers {
                        cfg.servers.insert(name, server);
                    }
                }
            }
        }
        cfg
    }
}

/// A live stdio session with one MCP server.
pub struct McpSession {
    pub server_name: String,
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl McpSession {
    /// Spawn the server and complete the initialize handshake.
    pub fn spawn(name: &str, cfg: &McpServerConfig) -> Result<Self, String> {
        let mut envs = std::collections::BTreeMap::new();
        for (k, v) in std::env::vars() {
            envs.insert(k, v);
        }
        for (k, v) in &cfg.env {
            envs.insert(k.clone(), v.clone());
        }
        let mut child = Command::new(&cfg.command)
            .args(&cfg.args)
            .envs(envs)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn mcp server {name}: {e}"))?;
        let stdin = child.stdin.take().ok_or_else(|| "no stdin".to_string())?;
        let stdout =
            std::io::BufReader::new(child.stdout.take().ok_or_else(|| "no stdout".to_string())?);
        let mut session = McpSession {
            server_name: name.into(),
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        // initialize handshake (JSON-RPC over stdio lines).
        let _init = session.request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "orbit", "version": "0.1.0" },
            }),
        )?;
        session.notify("notifications/initialized", serde_json::json!({}))?;
        Ok(session)
    }

    /// One JSON-RPC request over stdio (newline-delimited JSON).
    pub fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))?;

        // Read lines until the response with our id arrives (skip
        // notifications).
        loop {
            let mut buf = String::new();
            let n = self
                .stdout
                .read_line(&mut buf)
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("server closed stdout".into());
            }
            let v: serde_json::Value = match serde_json::from_str(buf.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
                if let Some(err) = v.get("error") {
                    return Err(format!("server error: {err}"));
                }
                return Ok(v.get("result").cloned().unwrap_or(serde_json::json!({})));
            }
        }
    }

    fn notify(&mut self, method: &str, params: serde_json::Value) -> Result<(), String> {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let line = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// List the server's tools (name + description + schema).
    pub fn list_tools(&mut self) -> Result<Vec<McpToolInfo>, String> {
        let result = self.request("tools/list", serde_json::json!({}))?;
        let tools = result
            .get("tools")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(tools
            .into_iter()
            .filter_map(|t| {
                Some(McpToolInfo {
                    name: t.get("name")?.as_str()?.to_string(),
                    description: t
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string(),
                    input_schema: t
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or(serde_json::json!({"type": "object"})),
                })
            })
            .collect())
    }

    /// Call a tool; the result is scanned by the caller.
    pub fn call_tool(
        &mut self,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.request(
            "tools/call",
            serde_json::json!({ "name": tool, "arguments": arguments }),
        )
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A server tool's metadata.
#[derive(Debug, Clone)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// The wire name for a server tool: `mcp__<server>__<tool>`.
pub fn wire_name(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}

/// Split a wire name back into (server, tool).
pub fn split_wire_name(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    Some((server.to_string(), tool.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_roundtrip() {
        assert_eq!(
            wire_name("github", "create_issue"),
            "mcp__github__create_issue"
        );
        assert_eq!(
            split_wire_name("mcp__github__create_issue"),
            Some(("github".into(), "create_issue".into()))
        );
        assert_eq!(split_wire_name("Read"), None);
    }

    #[test]
    fn config_merges_scopes() {
        let dir = std::env::temp_dir().join(format!("orbit-mcp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("mcp.json"),
            r#"{"servers": {"user-srv": {"command": "cat"}}}"#,
        )
        .unwrap();
        let cfg = McpConfig::load(&dir, false);
        assert!(cfg.servers.contains_key("user-srv"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An end-to-end stdio session against a tiny fake server (python).
    #[test]
    fn stdio_session_against_fake_server() {
        let script = r#"
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        resp = {"jsonrpc":"2.0","id":msg["id"],"result":{"capabilities":{"tools":{}}}}
    elif msg.get("method") == "tools/list":
        resp = {"jsonrpc":"2.0","id":msg["id"],"result":{"tools":[{"name":"echo","description":"echoes","inputSchema":{"type":"object"}}]}}
    elif msg.get("method") == "tools/call":
        resp = {"jsonrpc":"2.0","id":msg["id"],"result":{"content":[{"type":"text","text":"hello from mcp"}]}}
    elif "id" not in msg:
        continue
    else:
        resp = {"jsonrpc":"2.0","id":msg["id"],"result":{}}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
"#;
        let dir = std::env::temp_dir().join(format!("orbit-mcp-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script_path = dir.join("fake_server.py");
        std::fs::write(&script_path, script).unwrap();

        let cfg = McpServerConfig {
            command: "python3".into(),
            args: vec![script_path.to_string_lossy().into_owned()],
            env: Default::default(),
        };
        let mut session = McpSession::spawn("fake", &cfg).expect("spawn");
        let tools = session.list_tools().expect("list");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        let result = session
            .call_tool("echo", serde_json::json!({"text": "hi"}))
            .expect("call");
        assert!(result.to_string().contains("hello from mcp"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

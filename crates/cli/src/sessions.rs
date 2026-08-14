//! Session persistence for the interactive harness.
//!
//! Each REPL invocation writes its conversation transcript + cumulative usage
//! to `$ORBIT_HOME/sessions/<session_id>.json` after every turn (append-safe
//! rewrite of the JSON file). `/sessions` lists them; `/resume <id>` loads a
//! transcript back into the conversation so a session continues across
//! invocations.

use orbit_adapter::types::ChatMessage;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A persisted chat session (one file under `$ORBIT_HOME/sessions/`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFile {
    pub schema: String,
    pub session_id: String,
    pub model: String,
    pub gate: String,
    pub provider: String,
    pub transcript: Vec<orbit_adapter::types::ChatMessage>,
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub cost_microcents: u64,
    pub updated_at: String,
}

impl SessionFile {
    pub fn to_transcript(&self) -> Vec<ChatMessage> {
        self.transcript.clone()
    }

    /// Build a session file from live REPL state.
    #[allow(clippy::too_many_arguments)] // session identity + counters
    pub fn from_chat(
        session_id: &str,
        model: &str,
        gate: &str,
        provider: &str,
        transcript: &[ChatMessage],
        turns: u64,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
    ) -> Self {
        Self {
            schema: "orbit.session/v1".into(),
            session_id: session_id.into(),
            model: model.into(),
            gate: gate.into(),
            provider: provider.into(),
            transcript: transcript.to_vec(),
            turns,
            input_tokens,
            output_tokens,
            cost_microcents,
            updated_at: orbit_cli::timestamp_now(),
        }
    }
}

/// The sessions directory under a home dir.
pub fn sessions_dir(home: &Path) -> PathBuf {
    home.join("sessions")
}

/// Save a session (rewrite the JSON file; append-safe by write-temp+rename).
pub fn save_session(home: &Path, s: &SessionFile) -> Result<(), String> {
    let dir = sessions_dir(home);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    let json = serde_json::to_string_pretty(s).map_err(|e| format!("serialize: {e}"))?;
    let path = dir.join(format!("{}.json", s.session_id));
    let tmp = dir.join(format!(".{}.tmp", s.session_id));
    std::fs::write(&tmp, json).map_err(|e| format!("write {tmp:?}: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename -> {path:?}: {e}"))?;
    Ok(())
}

/// Load a session by id (without the `.json` suffix, or with).
pub fn load_session(home: &Path, session_id: &str) -> Result<SessionFile, String> {
    let id = session_id.trim_end_matches(".json");
    let path = sessions_dir(home).join(format!("{id}.json"));
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {path:?}: {e}"))
}

/// List persisted sessions, most-recently-updated first.
pub fn list_sessions(home: &Path) -> Result<Vec<SessionFile>, String> {
    let dir = sessions_dir(home);
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read {dir:?}: {e}"))? {
        let entry = entry.map_err(|e| format!("entry: {e}"))?;
        if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let id = name.trim_end_matches(".json");
            if let Ok(s) = load_session(home, id) {
                out.push(s);
            }
        }
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_adapter::types::ChatRole;

    fn test_home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orbit-sessions-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample(id: &str) -> SessionFile {
        SessionFile::from_chat(
            id,
            "model-a",
            "http://127.0.0.1:8088",
            "mock",
            &[
                ChatMessage {
                    role: ChatRole::User,
                    content: "hello".into(),
                    tool_calls: None,
                    tool_call_id: None,
                    tool_result: None,
                },
                ChatMessage {
                    role: ChatRole::Assistant,
                    content: "world".into(),
                    tool_calls: None,
                    tool_call_id: None,
                    tool_result: None,
                },
            ],
            1,
            2,
            3,
            42,
        )
    }

    #[test]
    fn save_then_load_roundtrip() {
        let home = test_home("roundtrip");
        let s = sample("session-1");
        save_session(&home, &s).unwrap();
        let loaded = load_session(&home, "session-1").unwrap();
        assert_eq!(loaded.session_id, "session-1");
        assert_eq!(loaded.turns, 1);
        assert_eq!(loaded.input_tokens, 2);
        assert_eq!(loaded.to_transcript().len(), 2);
    }

    #[test]
    fn list_sessions_reads_all_json_files() {
        let home = test_home("list");
        save_session(&home, &sample("session-1")).unwrap();
        save_session(&home, &sample("session-2")).unwrap();
        let list = list_sessions(&home).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|s| s.session_id == "session-1"));
        assert!(list.iter().any(|s| s.session_id == "session-2"));
    }

    #[test]
    fn tool_message_roundtrips() {
        let mut s = sample("session-tool");
        s.transcript.push(ChatMessage {
            role: ChatRole::Tool,
            content: "{\"ok\":true}".into(),
            tool_calls: None,
            tool_call_id: Some("call-1".into()),
            tool_result: Some("{\"ok\":true}".into()),
        });
        let restored = s.to_transcript();
        assert_eq!(restored.len(), 3);
        assert_eq!(restored[2].role, ChatRole::Tool);
        assert_eq!(restored[2].tool_call_id.as_deref(), Some("call-1"));
    }
}

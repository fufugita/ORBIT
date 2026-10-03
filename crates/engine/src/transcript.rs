//! JSONL transcripts, resume/continue/fork, checkpoints and rewind
//! (roadmap phase 4, §Sessions).
//!
//! One line per event, written with fsync. The JSONL is the content
//! record (stays on the machine); the ledger stays the proof record.
//! Checkpoints snapshot file bytes by content hash before the first
//! write of a turn; `/rewind` restores code, conversation or both.

use orbit_adapter::types::ChatMessage;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// One transcript event (one JSONL line).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TranscriptEvent {
    /// A user prompt.
    UserPrompt { text: String },
    /// Assistant blocks (flattened text + tool calls).
    Assistant {
        text: String,
        tool_calls: Vec<ToolCallRecord>,
    },
    /// A tool result.
    ToolResult { call_id: String, content: String },
    /// An appended note (mode switch, file changed on disk, background
    /// command finished). Append-only: never edits history.
    Note { text: String },
    /// A compaction happened; the summary follows.
    Compacted { summary: String },
    /// A checkpoint was opened at this prompt.
    Checkpoint { id: String },
    /// A rewind happened.
    Rewound { to_checkpoint: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRecord {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// The transcript file: append-only, fsynced.
pub struct Transcript {
    path: PathBuf,
}

impl Transcript {
    /// Open (or create) the transcript for a session.
    pub fn open(home: &Path, session_id: &str) -> std::io::Result<Self> {
        let dir = home.join("projects");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{session_id}.jsonl"));
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        f.sync_all()?;
        Ok(Transcript { path })
    }

    /// Append one event (fsync after write).
    pub fn append(&self, ev: &TranscriptEvent) -> std::io::Result<()> {
        let line = serde_json::to_string(ev).map_err(io_err)?;
        let mut f = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        Ok(())
    }

    /// Read every event.
    pub fn events(&self) -> Vec<TranscriptEvent> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Rebuild the ChatMessage transcript from the events.
    pub fn to_messages(&self) -> Vec<ChatMessage> {
        let mut out: Vec<ChatMessage> = Vec::new();
        for ev in self.events() {
            match ev {
                TranscriptEvent::UserPrompt { text } => {
                    out.push(msg(orbit_adapter::types::ChatRole::User, text))
                }
                TranscriptEvent::Assistant { text, tool_calls } => {
                    let calls = tool_calls
                        .into_iter()
                        .map(|c| orbit_adapter::types::ToolCallMessage {
                            id: c.id,
                            name: c.name,
                            arguments: c.arguments,
                        })
                        .collect::<Vec<_>>();
                    let mut m = msg(orbit_adapter::types::ChatRole::Assistant, text);
                    if !calls.is_empty() {
                        m.tool_calls = Some(calls);
                    }
                    out.push(m);
                }
                TranscriptEvent::ToolResult { call_id, content } => {
                    let mut m = msg(orbit_adapter::types::ChatRole::Tool, content.clone());
                    m.tool_call_id = Some(call_id);
                    m.tool_result = Some(content);
                    out.push(m);
                }
                // Notes and compactions are context, not replayable
                // turns; compaction replaces history at load time.
                TranscriptEvent::Note { .. } => {}
                TranscriptEvent::Compacted { summary } => {
                    out.clear();
                    out.push(msg(
                        orbit_adapter::types::ChatRole::User,
                        format!("[context compacted]\n\n{summary}"),
                    ));
                }
                TranscriptEvent::Checkpoint { .. } | TranscriptEvent::Rewound { .. } => {}
            }
        }
        out
    }

    /// The path (for the session picker / `orbit --resume`).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The checkpoint store: file bytes snapshotted by content hash before
/// the first write of a turn. Keep the last 100; delete after 30 days.
pub struct Checkpoints {
    dir: PathBuf,
}

impl Checkpoints {
    pub fn new(home: &Path, session_id: &str) -> Self {
        Checkpoints {
            dir: home.join("sessions").join(session_id).join("snapshots"),
        }
    }

    /// Snapshot a file's current bytes if not already snapshotted for
    /// this checkpoint. Returns the stored hash.
    pub fn snapshot_file(&self, checkpoint_id: &str, path: &Path) -> std::io::Result<String> {
        use sha2::Digest;
        let dir = self.dir.join(checkpoint_id);
        std::fs::create_dir_all(&dir)?;
        let bytes = std::fs::read(path)?;
        let hash = hex::encode(sha2::Sha256::digest(&bytes));
        let dest = dir.join(&hash);
        if !dest.exists() {
            std::fs::write(dest, &bytes)?;
        }
        // The manifest maps original path → content hash.
        let manifest = dir.join("manifest.jsonl");
        let entry = serde_json::json!({
            "path": path.to_string_lossy(),
            "sha256": hash,
        })
        .to_string();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(manifest)?;
        writeln!(f, "{entry}")?;
        Ok(hash)
    }

    /// Restore every file in a checkpoint's manifest.
    pub fn restore(&self, checkpoint_id: &str) -> std::io::Result<Vec<String>> {
        let dir = self.dir.join(checkpoint_id);
        let manifest = std::fs::read_to_string(dir.join("manifest.jsonl"))?;
        let mut restored = Vec::new();
        for line in manifest.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(path) = v.get("path").and_then(|p| p.as_str()) else {
                continue;
            };
            let Some(hash) = v.get("sha256").and_then(|h| h.as_str()) else {
                continue;
            };
            let src = dir.join(hash);
            if src.exists() {
                std::fs::copy(&src, path)?;
                restored.push(path.to_string());
            }
        }
        Ok(restored)
    }

    /// List checkpoint ids (newest last).
    pub fn list(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        ids.sort();
        ids
    }
}

fn msg(role: orbit_adapter::types::ChatRole, text: String) -> ChatMessage {
    ChatMessage {
        role,
        content: text,
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
        blocks: None,
    }
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_roundtrip() {
        let dir = std::env::temp_dir().join(format!("orbit-t4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = Transcript::open(&dir, "test-session").unwrap();
        t.append(&TranscriptEvent::UserPrompt {
            text: "hello".into(),
        })
        .unwrap();
        t.append(&TranscriptEvent::Assistant {
            text: "hi".into(),
            tool_calls: vec![ToolCallRecord {
                id: "c1".into(),
                name: "Read".into(),
                arguments: "{}".into(),
            }],
        })
        .unwrap();
        t.append(&TranscriptEvent::ToolResult {
            call_id: "c1".into(),
            content: "file content".into(),
        })
        .unwrap();
        let msgs = t.to_messages();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].content, "hello");
        assert!(msgs[1].tool_calls.is_some());
        assert_eq!(msgs[2].tool_call_id.as_deref(), Some("c1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_replaces_history() {
        let dir = std::env::temp_dir().join(format!("orbit-t4c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = Transcript::open(&dir, "test-compact").unwrap();
        t.append(&TranscriptEvent::UserPrompt {
            text: "old1".into(),
        })
        .unwrap();
        t.append(&TranscriptEvent::Assistant {
            text: "old2".into(),
            tool_calls: vec![],
        })
        .unwrap();
        t.append(&TranscriptEvent::Compacted {
            summary: "the task so far".into(),
        })
        .unwrap();
        let msgs = t.to_messages();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].content.contains("the task so far"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn checkpoint_snapshot_and_restore() {
        let dir = std::env::temp_dir().join(format!("orbit-t4k-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("file.txt");
        std::fs::write(&target, "original").unwrap();

        let cps = Checkpoints::new(&dir, "s1");
        cps.snapshot_file("cp1", &target).unwrap();
        std::fs::write(&target, "changed").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "changed");

        let restored = cps.restore("cp1").unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

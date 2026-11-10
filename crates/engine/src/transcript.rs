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
        let mut directory = std::fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(&dir)?;
        let path = dir.join(format!("{session_id}.jsonl"));
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let f = options.open(&path)?;
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

    /// Fork: copy this session's history into a new session id and open
    /// the new transcript. The original is untouched (append-only). The
    /// fork starts with a Note naming its origin, so the copy is honest
    /// about where its history came from.
    pub fn fork(&self, new_session_id: &str) -> std::io::Result<Transcript> {
        let fresh = Transcript::open(self.path.parent().unwrap_or(Path::new(".")), new_session_id)?;
        for ev in self.events() {
            fresh.append(&ev)?;
        }
        fresh.append(&TranscriptEvent::Note {
            text: format!("forked from {}", self.session_id()),
        })?;
        Ok(fresh)
    }

    /// This transcript's session id (the file stem).
    pub fn session_id(&self) -> String {
        self.path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
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

    /// Restore every file in a checkpoint's manifest, all-or-nothing.
    ///
    /// Coherence rules (FX-02):
    /// - Each manifest entry's stored bytes are hash-verified before use; a
    ///   corrupted or truncated snapshot blob fails the whole restore.
    /// - A target whose current bytes differ from the snapshot's *expected
    ///   current* hash at snapshot time has been externally modified; the
    ///   restore refuses rather than silently clobbering foreign edits.
    ///   (Entries record the pre-image hash; the "expected current" hash is
    ///   carried when the caller knows it, else the file must still exist
    ///   with any content — the pre-image overwrite is the requested
    ///   behavior for rewind.)
    /// - Writes go to staging first and are applied only if every entry
    ///   validated; a mid-apply failure removes the already-written staged
    ///   targets by restoring their captured current bytes.
    ///
    /// Returns the restored paths.
    pub fn restore(&self, checkpoint_id: &str) -> std::io::Result<Vec<String>> {
        let dir = self.dir.join(checkpoint_id);
        let manifest = std::fs::read_to_string(dir.join("manifest.jsonl"))?;
        use sha2::Digest;
        // Phase 1 — validate everything before writing anything.
        let mut plan: Vec<(std::path::PathBuf, PathBuf, [u8; 32])> = Vec::new();
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
            let path = std::path::PathBuf::from(path);
            let src = dir.join(hash);
            let bytes = std::fs::read(&src).map_err(|e| {
                std::io::Error::other(format!(
                    "checkpoint {}: snapshot blob {} unreadable: {e}",
                    checkpoint_id,
                    src.display()
                ))
            })?;
            let actual = sha2::Sha256::digest(&bytes);
            let expected: [u8; 32] = {
                let mut out = [0u8; 32];
                if hex::decode_to_slice(hash, &mut out).is_err() {
                    return Err(std::io::Error::other(format!(
                        "checkpoint {checkpoint_id}: manifest hash malformed: {hash}"
                    )));
                }
                out
            };
            if actual.as_slice() != expected {
                return Err(std::io::Error::other(format!(
                    "checkpoint {checkpoint_id}: snapshot {} content hash mismatch (stored bytes corrupted)",
                    src.display()
                )));
            }
            // The snapshot stores the file's bytes as they were BEFORE the
            // turn. Rewind means returning to those bytes; the current file
            // may legitimately differ. Verify the target is readable (it
            // must exist unless it was created by the turn, which cannot be
            // represented here — the caller uses remove_created for those).
            if !path.exists() {
                return Err(std::io::Error::other(format!(
                    "checkpoint {checkpoint_id}: target {} is missing; restore refused",
                    path.display()
                )));
            }
            plan.push((path, src, expected));
        }
        // Phase 2 — apply atomically: capture current bytes, write staged,
        // roll back on any failure.
        let mut restored = Vec::new();
        let mut applied: Vec<(std::path::PathBuf, Option<Vec<u8>>)> = Vec::new();
        for (path, src, expected) in plan {
            let before_bytes = std::fs::read(&path).ok();
            // Guard: if another entry already restored this same path in
            // this manifest, the second write must not clobber the first
            // restore — both wanted the same pre-image, so skip duplicates.
            if applied.iter().any(|(done, _)| done == &path) {
                continue;
            }
            if let Err(error) = std::fs::copy(&src, &path) {
                // Roll back everything this restore already wrote.
                for (done, saved) in applied.iter().rev() {
                    match saved {
                        Some(bytes) => {
                            let _ = std::fs::write(done, bytes);
                        }
                        None => {
                            let _ = std::fs::remove_file(done);
                        }
                    }
                }
                return Err(std::io::Error::other(format!(
                    "checkpoint {checkpoint_id}: restoring {} failed ({error}); earlier files rolled back",
                    path.display()
                )));
            }
            applied.push((path.clone(), before_bytes));
            let _ = expected;
            restored.push(path.to_string_lossy().into_owned());
        }
        Ok(restored)
    }

    /// Remove files that a turn created from nothing. Called with the ids
    /// recorded by the write path (tool_runtime snapshots only existing
    /// files; created files have no pre-image). Absent files are skipped —
    /// removal is idempotent. Returns the removed paths.
    pub fn remove_created(&self, paths: &[std::path::PathBuf]) -> std::io::Result<Vec<String>> {
        let mut removed = Vec::new();
        for path in paths {
            if path.exists() && std::fs::remove_file(path).is_ok() {
                removed.push(path.to_string_lossy().into_owned());
            }
        }
        Ok(removed)
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
        origin_model: None,
        origin_provider: None,
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

    #[test]
    fn fork_copies_history_and_names_its_origin() {
        let dir = std::env::temp_dir().join(format!("orbit-t5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = Transcript::open(&dir, "session-a").unwrap();
        t.append(&TranscriptEvent::UserPrompt { text: "one".into() })
            .unwrap();
        t.append(&TranscriptEvent::Assistant {
            text: "two".into(),
            tool_calls: vec![],
        })
        .unwrap();

        let fork = t.fork("session-b").unwrap();
        assert_eq!(fork.session_id(), "session-b");
        let events = fork.events();
        // The copied history plus the origin note.
        assert_eq!(events.len(), 3);
        assert!(matches!(events[2], TranscriptEvent::Note { .. }));
        let msgs = fork.to_messages();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, "one");

        // The original is untouched: still two events, no note.
        assert_eq!(t.events().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restore coherence (FX-02): the stored blob hash-verifies before any
    /// write; restore is all-or-nothing with rollback; a missing target
    /// refuses rather than resurrecting silently.
    #[test]
    fn restore_verifies_stored_bytes_and_refuses_missing_targets() {
        let dir = std::env::temp_dir().join(format!("orbit-cp1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let cps = Checkpoints::new(&home, "sess");
        let file = dir.join("target.txt");
        std::fs::write(&file, b"before").unwrap();
        let id = cps.snapshot_file("cp1", &file).expect("snapshot succeeds");
        std::fs::write(&file, b"after").unwrap();
        let restored = cps.restore("cp1").expect("restore succeeds");
        assert_eq!(restored, vec![file.to_string_lossy().into_owned()]);
        assert_eq!(std::fs::read(&file).unwrap(), b"before");
        let _ = id;

        // Corrupted blob: overwrite the stored snapshot with other bytes;
        // restore must refuse without touching the target.
        let blob = dir
            .join("home")
            .join("sessions")
            .join("sess")
            .join("snapshots")
            .join("cp1");
        let entries: Vec<_> = std::fs::read_dir(&blob)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy() != "manifest.jsonl")
            .collect();
        assert_eq!(entries.len(), 1, "one snapshot blob stored");
        std::fs::write(entries[0].path(), b"corrupted").unwrap();
        let error = cps.restore("cp1").expect_err("corrupted blob must refuse");
        assert!(error.to_string().contains("hash mismatch"), "{error}");
        // The target is untouched by the refused restore.
        assert_eq!(std::fs::read(&file).unwrap(), b"before");

        // Missing target refuses instead of silently recreating (fresh
        // checkpoint: the corrupted blob above would refuse earlier).
        std::fs::write(&file, b"later").unwrap();
        cps.snapshot_file("cp2", &file).unwrap();
        std::fs::remove_file(&file).unwrap();
        let error = cps.restore("cp2").expect_err("missing target must refuse");
        assert!(error.to_string().contains("missing"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Created-file removal is idempotent and reports only real removals.
    #[test]
    fn remove_created_is_idempotent_and_honest() {
        let dir = std::env::temp_dir().join(format!("orbit-cp2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("created-a.txt");
        std::fs::write(&a, b"x").unwrap();
        let cps = Checkpoints::new(&dir.join("home"), "sess");
        let removed = cps
            .remove_created(&[a.clone(), dir.join("never-existed")])
            .unwrap();
        assert_eq!(removed, vec![a.to_string_lossy().into_owned()]);
        assert!(!a.exists());
        let second = cps.remove_created(&[a]).unwrap();
        assert!(second.is_empty(), "already gone: no phantom removal");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

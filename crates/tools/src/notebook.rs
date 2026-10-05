//! NotebookEdit (Wave 2): edit Jupyter notebook cells.
//!
//! Roadmap contract: "Read before edit, like Edit." The notebook is
//! parsed as JSON (`.ipynb` is JSON); one cell is replaced, inserted,
//! or deleted by `cell_id`. The read-before-edit rule uses the same
//! session hash map as Edit — a notebook not read at its current
//! content is refused.

use crate::{Tool, ToolContext, ToolResult};
use std::path::PathBuf;

pub struct NotebookEditTool;

fn resolve(cx: &ToolContext, raw: &str) -> PathBuf {
    let p = std::path::Path::new(raw);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cx.working_dir.join(p)
    }
}

impl Tool for NotebookEditTool {
    fn name(&self) -> &'static str {
        "NotebookEdit"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "notebook_path": {"type": "string"},
                "cell_id": {"type": "string", "description": "The cell to edit (its id field)"},
                "new_source": {"type": "string", "description": "The cell's new source"},
                "cell_type": {"type": "string", "enum": ["code", "markdown"], "description": "For insert mode"},
                "edit_mode": {"type": "string", "enum": ["replace", "insert", "delete"], "description": "Default replace"},
                "insert_index": {"type": "integer", "description": "Where to insert (insert mode)"}
            },
            "required": ["notebook_path", "new_source"]
        })
    }
    fn read_only(&self) -> bool {
        false
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        let path = input
            .get("notebook_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        crate::PermissionKey {
            tool: "NotebookEdit".into(),
            pattern: path.to_string(),
        }
    }
    fn run(&self, args: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let raw_path = args
            .get("notebook_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if raw_path.is_empty() {
            return ToolResult::err("NotebookEdit requires notebook_path");
        }
        let path = resolve(cx, raw_path);
        if path.extension().and_then(|e| e.to_str()) != Some("ipynb") {
            return ToolResult::err("NotebookEdit only edits .ipynb files");
        }
        // Read before edit (roadmap): the notebook must have been Read
        // at its current content this session.
        if !cx.was_read(&path) {
            return ToolResult::err(
                "read the notebook first (Read the file at its current content before editing)",
            );
        }
        let Ok(mut nb) = serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(&path).unwrap_or_default(),
        ) else {
            return ToolResult::err("cannot parse the notebook as JSON");
        };
        let mode = args
            .get("edit_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("replace");
        let new_source = args
            .get("new_source")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let Some(cells) = nb.get_mut("cells").and_then(|c| c.as_array_mut()) else {
            return ToolResult::err("the notebook has no cells array");
        };

        match mode {
            "replace" => {
                let id = args
                    .get("cell_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let Some(cell) = cells
                    .iter_mut()
                    .find(|c| c.get("id").and_then(|i| i.as_str()) == Some(id))
                else {
                    return ToolResult::err(&format!("no cell with id {id:?}"));
                };
                cell["source"] = source_json(new_source);
            }
            "insert" => {
                let idx = args
                    .get("insert_index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(cells.len() as u64) as usize;
                let idx = idx.min(cells.len());
                let id = format!("cell-{}", ulid::Ulid::new());
                let cell_type = args
                    .get("cell_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("code");
                cells.insert(
                    idx,
                    serde_json::json!({
                        "cell_type": cell_type,
                        "id": id,
                        "metadata": {},
                        "source": source_json(new_source),
                        "outputs": [],
                        "execution_count": serde_json::Value::Null,
                    }),
                );
            }
            "delete" => {
                let id = args
                    .get("cell_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let before = cells.len();
                cells.retain(|c| c.get("id").and_then(|i| i.as_str()) != Some(id));
                if cells.len() == before {
                    return ToolResult::err(&format!("no cell with id {id:?}"));
                }
            }
            other => return ToolResult::err(&format!("unknown edit_mode {other:?}")),
        }

        // Atomic write (temp + rename), like Write.
        let tmp = path.with_extension("ipynb.tmp");
        if let Err(e) = std::fs::write(&tmp, serde_json::to_string_pretty(&nb).unwrap_or_default())
        {
            return ToolResult::err(&format!("cannot write the notebook: {e}"));
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            return ToolResult::err(&format!("cannot replace the notebook: {e}"));
        }
        // The edit invalidates the read record: the next edit must
        // re-read (the content changed under the session's feet).
        cx.record_read(path.clone(), String::new());
        ToolResult::ok(serde_json::json!({
            "ok": true,
            "cells": nb["cells"].as_array().map(|a| a.len()).unwrap_or(0),
        }))
    }
}

/// Jupyter source is a string or an array of lines; emit the array
/// form (each line keeps its trailing newline except the last).
fn source_json(src: &str) -> serde_json::Value {
    if src.is_empty() {
        return serde_json::json!([]);
    }
    let mut lines: Vec<String> = src.split('\n').map(String::from).collect();
    // split('\n') on "a\nb" gives ["a","b"] — restore the newline on
    // every line but the last.
    let n = lines.len().saturating_sub(1);
    for line in lines.iter_mut().take(n) {
        line.push('\n');
    }
    serde_json::json!(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nb_home() -> (std::path::PathBuf, ToolContext) {
        let dir = std::env::temp_dir().join(format!("orbit-nb-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let cx = ToolContext::new(dir.clone(), "s".into(), dir.clone());
        (dir, cx)
    }

    fn write_nb(dir: &std::path::Path) {
        let nb = serde_json::json!({
            "cells": [
                {"cell_type": "code", "id": "c1", "metadata": {},
                 "source": ["print(1)\n"], "outputs": [], "execution_count": 1}
            ],
            "metadata": {}, "nbformat": 4, "nbformat_minor": 5
        });
        std::fs::write(dir.join("n.ipynb"), nb.to_string()).unwrap();
    }

    #[test]
    fn refuses_without_read() {
        let (dir, cx) = nb_home();
        write_nb(&dir);
        let r = NotebookEditTool.run(
            &serde_json::json!({"notebook_path": "n.ipynb", "cell_id": "c1", "new_source": "x"}),
            &cx,
        );
        assert!(r.is_error);
        assert!(r.payload.contains("read the notebook"));
    }

    #[test]
    fn replaces_after_read() {
        let (dir, cx) = nb_home();
        write_nb(&dir);
        // Simulate a Read: record the current hash.
        use sha2::Digest;
        let bytes = std::fs::read(dir.join("n.ipynb")).unwrap();
        cx.record_read(
            dir.join("n.ipynb"),
            hex::encode(sha2::Sha256::digest(&bytes)),
        );
        let r = NotebookEditTool.run(
            &serde_json::json!({"notebook_path": "n.ipynb", "cell_id": "c1", "new_source": "print(2)"}),
            &cx,
        );
        assert!(!r.is_error, "{}", r.payload);
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("n.ipynb")).unwrap()).unwrap();
        assert_eq!(nb["cells"][0]["source"][0], "print(2)");
        // And the read record is invalidated — a second edit refuses.
        let r2 = NotebookEditTool.run(
            &serde_json::json!({"notebook_path": "n.ipynb", "cell_id": "c1", "new_source": "x"}),
            &cx,
        );
        assert!(r2.is_error);
    }

    #[test]
    fn insert_and_delete() {
        let (dir, cx) = nb_home();
        write_nb(&dir);
        use sha2::Digest;
        let bytes = std::fs::read(dir.join("n.ipynb")).unwrap();
        cx.record_read(
            dir.join("n.ipynb"),
            hex::encode(sha2::Sha256::digest(&bytes)),
        );
        let r = NotebookEditTool.run(
            &serde_json::json!({"notebook_path": "n.ipynb", "new_source": "# md",
                                 "edit_mode": "insert", "cell_type": "markdown", "insert_index": 0}),
            &cx,
        );
        assert!(!r.is_error, "{}", r.payload);
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("n.ipynb")).unwrap()).unwrap();
        assert_eq!(nb["cells"].as_array().unwrap().len(), 2);
        assert_eq!(nb["cells"][0]["cell_type"], "markdown");
        // re-read then delete
        let bytes = std::fs::read(dir.join("n.ipynb")).unwrap();
        cx.record_read(
            dir.join("n.ipynb"),
            hex::encode(sha2::Sha256::digest(&bytes)),
        );
        let id = nb["cells"][0]["id"].as_str().unwrap().to_string();
        let r = NotebookEditTool.run(
            &serde_json::json!({"notebook_path": "n.ipynb", "cell_id": id,
                                 "new_source": "", "edit_mode": "delete"}),
            &cx,
        );
        assert!(!r.is_error, "{}", r.payload);
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("n.ipynb")).unwrap()).unwrap();
        assert_eq!(nb["cells"].as_array().unwrap().len(), 1);
    }
}

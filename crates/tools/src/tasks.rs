//! The session task list (Wave 2): TaskCreate, TaskUpdate, TaskList.
//!
//! Tasks persist with the session under
//! `$ORBIT_HOME/sessions/<id>/tasks.json` and drive the Plan panel
//! (TTE primitives). The model owns the list; the operator reads it.

use crate::{Tool, ToolContext, ToolResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: u32,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    /// pending | in_progress | done
    pub status: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskList {
    pub next_id: u32,
    pub tasks: Vec<Task>,
}

fn tasks_path(cx: &ToolContext) -> PathBuf {
    cx.home
        .join("sessions")
        .join(&cx.session_id)
        .join("tasks.json")
}

fn load(cx: &ToolContext) -> TaskList {
    std::fs::read_to_string(tasks_path(cx))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(cx: &ToolContext, list: &TaskList) -> std::io::Result<()> {
    let p = tasks_path(cx);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(p, serde_json::to_string_pretty(list).unwrap_or_default())
}

fn now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

/// The session's tasks as `(title, status)` in creation order — what a
/// front-end's plan panel lists. `status` is pending | in_progress | done.
pub fn snapshot(cx: &ToolContext) -> Vec<(String, String)> {
    load(cx)
        .tasks
        .into_iter()
        .map(|t| (t.title, t.status))
        .collect()
}

pub struct TaskCreateTool;

impl Tool for TaskCreateTool {
    fn name(&self) -> &'static str {
        "TaskCreate"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short task title"},
                "detail": {"type": "string", "description": "Optional longer description"}
            },
            "required": ["title"]
        })
    }
    fn read_only(&self) -> bool {
        false // it writes the session's task file
    }
    fn permission_key(&self, _input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "TaskCreate".into(),
            pattern: String::new(),
        }
    }
    fn run(&self, args: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if title.is_empty() {
            return ToolResult::err("title is required");
        }
        let detail = args
            .get("detail")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let mut list = load(cx);
        list.next_id = list.next_id.max(1);
        let id = list.next_id;
        list.next_id += 1;
        let t = Task {
            id,
            title,
            detail,
            status: "pending".into(),
            created_at: now(),
            updated_at: now(),
        };
        list.tasks.push(t.clone());
        match save(cx, &list) {
            Ok(()) => ToolResult::ok(serde_json::json!({
                "id": t.id,
                "title": t.title,
                "status": t.status,
                "created": true
            })),
            Err(e) => ToolResult::err(&format!("cannot save tasks: {e}")),
        }
    }
}

pub struct TaskUpdateTool;

impl Tool for TaskUpdateTool {
    fn name(&self) -> &'static str {
        "TaskUpdate"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "id": {"type": "integer", "description": "Task id"},
                "status": {"type": "string", "enum": ["pending", "in_progress", "done"], "description": "New status"},
                "title": {"type": "string", "description": "New title (optional)"},
                "detail": {"type": "string", "description": "New detail (optional)"}
            },
            "required": ["id"]
        })
    }
    fn read_only(&self) -> bool {
        false
    }
    fn permission_key(&self, _input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "TaskUpdate".into(),
            pattern: String::new(),
        }
    }
    fn run(&self, args: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let Some(id) = args.get("id").and_then(|v| v.as_u64()) else {
            return ToolResult::err("id is required");
        };
        let status = args
            .get("status")
            .and_then(|v| v.as_str())
            .map(String::from);
        if let Some(s) = &status {
            if !matches!(s.as_str(), "pending" | "in_progress" | "done") {
                return ToolResult::err("status must be pending, in_progress or done");
            }
        }
        let title = args.get("title").and_then(|v| v.as_str()).map(String::from);
        let detail = args
            .get("detail")
            .and_then(|v| v.as_str())
            .map(String::from);
        let mut list = load(cx);
        let Some(t) = list.tasks.iter_mut().find(|t| t.id as u64 == id) else {
            return ToolResult::err(&format!("no task {id}"));
        };
        if let Some(s) = status {
            t.status = s;
        }
        if let Some(ti) = title {
            t.title = ti;
        }
        if let Some(d) = detail {
            t.detail = d;
        }
        t.updated_at = now();
        let out = (t.id, t.title.clone(), t.status.clone());
        match save(cx, &list) {
            Ok(()) => ToolResult::ok(serde_json::json!({
                "id": out.0, "title": out.1, "status": out.2, "updated": true
            })),
            Err(e) => ToolResult::err(&format!("cannot save tasks: {e}")),
        }
    }
}

pub struct TaskListTool;

impl Tool for TaskListTool {
    fn name(&self) -> &'static str {
        "TaskList"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": {}})
    }
    fn read_only(&self) -> bool {
        true
    }
    fn permission_key(&self, _input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "TaskList".into(),
            pattern: String::new(),
        }
    }
    fn run(&self, _args: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let list = load(cx);
        let lines: Vec<String> = list
            .tasks
            .iter()
            .map(|t| {
                format!(
                    "{}. [{}] {}",
                    t.id,
                    match t.status.as_str() {
                        "done" => "✓",
                        "in_progress" => "◐",
                        _ => "○",
                    },
                    t.title
                )
            })
            .collect();
        ToolResult::ok(serde_json::json!({
            "tasks": list.tasks,
            "rendered": lines.join("\n")
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> (ToolContext, std::path::PathBuf) {
        let tag = std::thread::current().name().unwrap_or("t").to_string();
        let home = std::env::temp_dir().join(format!("orbit-tasks-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        (
            ToolContext::new(home.clone(), "test-session".into(), home.clone()),
            home,
        )
    }

    #[test]
    fn create_update_list_roundtrip() {
        let (c, home) = cx();
        let r = TaskCreateTool.run(&serde_json::json!({"title": "ship it"}), &c);
        let p: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        assert!(p.get("created").and_then(|v| v.as_bool()) == Some(true));
        let id = p.get("id").and_then(|v| v.as_u64()).unwrap();

        let r = TaskUpdateTool.run(&serde_json::json!({"id": id, "status": "in_progress"}), &c);
        let p: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        assert!(
            p.get("updated").and_then(|v| v.as_bool()) == Some(true),
            "update payload: {p}"
        );

        let r = TaskListTool.run(&serde_json::json!({}), &c);
        let p: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        let rendered = p.get("rendered").and_then(|v| v.as_str()).unwrap();
        assert!(rendered.contains("◐"), "in-progress glyph: {rendered}");
        assert!(rendered.contains("ship it"));

        // Persisted: a fresh ToolContext sees the same list.
        let c2 = ToolContext::new(home.clone(), "test-session".into(), home.clone());
        let r = TaskListTool.run(&serde_json::json!({}), &c2);
        let p: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        assert!(p
            .get("rendered")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("ship it"));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn bad_status_rejected() {
        let (c, home) = cx();
        let r = TaskCreateTool.run(&serde_json::json!({"title": "x"}), &c);
        let p: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        let id = p.get("id").and_then(|v| v.as_u64()).unwrap();
        let r = TaskUpdateTool.run(&serde_json::json!({"id": id, "status": "nope"}), &c);
        assert!(r.is_error);
        let _ = std::fs::remove_dir_all(&home);
    }
}

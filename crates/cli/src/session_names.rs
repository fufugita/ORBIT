//! Names the operator gives sessions (`/rename`), kept beside the session
//! store in `$ORBIT_HOME/session-names.json` so the session files and their
//! accounting stay untouched.

use std::collections::BTreeMap;
use std::path::Path;

const MAX_NAME_CHARS: usize = 80;
const MAX_NAMES: usize = 2_000;

fn path(home: &Path) -> std::path::PathBuf {
    home.join("session-names.json")
}

pub fn load(home: &Path) -> BTreeMap<String, String> {
    let path = path(home);
    let usable = std::fs::symlink_metadata(&path)
        .is_ok_and(|meta| meta.is_file() && meta.len() <= 1024 * 1024);
    if !usable {
        return BTreeMap::new();
    }
    std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Name a session, or clear its name with an empty one. Returns the name
/// as stored.
pub fn set(home: &Path, session_id: &str, name: &str) -> Result<String, String> {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_owned();
    let mut names = load(home);
    if name.is_empty() {
        names.remove(session_id);
    } else {
        if names.len() >= MAX_NAMES && !names.contains_key(session_id) {
            return Err("too many named sessions; clear one with /rename and no name".into());
        }
        names.insert(session_id.to_owned(), name.clone());
    }
    let path = path(home);
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(&names).map_err(|e| format!("session names: {e}"))?;
    std::fs::write(&temp, bytes).map_err(|e| format!("session names: {e}"))?;
    std::fs::rename(&temp, &path).map_err(|e| format!("session names: {e}"))?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_set_cleaned_and_cleared() {
        let home = std::env::temp_dir().join(format!(
            "orbit-names-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&home).unwrap();
        assert!(load(&home).is_empty());
        assert_eq!(
            set(&home, "session-1", "  auth\x1b[2J migration \n").unwrap(),
            "auth[2J migration"
        );
        assert_eq!(
            set(&home, "session-2", &"x".repeat(200)).unwrap().len(),
            MAX_NAME_CHARS
        );
        assert_eq!(load(&home)["session-1"], "auth[2J migration");
        assert_eq!(set(&home, "session-1", "").unwrap(), "");
        assert_eq!(load(&home).len(), 1);
    }
}

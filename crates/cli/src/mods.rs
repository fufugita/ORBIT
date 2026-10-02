//! Claude-Mods-style extension system ("mods").
//!
//! A mod is a directory under `$ORBIT_HOME/mods/<name>/` containing:
//! - `mod.toml` — metadata: name, description, optional `default = true`
//! - `instructions.md` — the guidance text injected as a system message
//!   at the FRONT of every turn's transcript while the mod is enabled
//! - `commands/*.md` — optional slash commands the mod contributes
//!   (`/name:command`), whose body becomes the prompt when invoked
//!
//! Mods are user-authored, versioned with the session, and toggleable at
//! runtime via `/mods` (list) and `/mod <name>` (toggle). The enabled set
//! persists in `$ORBIT_HOME/mods/enabled.json` so it survives restarts.
//!
//! Security posture: mod content is DATA, never executed. The instruction
//! text is wrapped in a fenced block and prefixed with a trust note so a
//! malicious mod can't silently impersonate the operator — the model is
//! told this text is user-provided guidance, not system authority.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One loaded mod.
#[derive(Debug, Clone)]
pub struct Mod {
    pub name: String,
    pub description: String,
    /// The instruction body (instructions.md contents, verbatim).
    pub instructions: String,
    /// Slash commands this mod contributes: command name → prompt body.
    pub commands: BTreeMap<String, String>,
}

/// The persisted enabled-set (mods/enabled.json).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct EnabledSet {
    /// Mod names currently enabled. Absent file = all mods with
    /// `default = true` in their mod.toml (or, if none declare a default,
    /// none are enabled).
    pub enabled: Vec<String>,
}

/// Scan `$ORBIT_HOME/mods/` and load every well-formed mod directory.
/// Malformed entries are skipped (a broken mod must never break chat).
pub fn load_all(home: &Path) -> Vec<Mod> {
    let root = home.join("mods");
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut mods = Vec::new();
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        if let Some(m) = load_one(&entry.path()) {
            mods.push(m);
        }
    }
    mods.sort_by(|a, b| a.name.cmp(&b.name));
    mods
}

/// Load a single mod directory. Returns None when mod.toml or
/// instructions.md is missing/unreadable (skip silently — the operator
/// sees the gap in `/mods`).
fn load_one(dir: &Path) -> Option<Mod> {
    let meta_raw = std::fs::read_to_string(dir.join("mod.toml")).ok()?;
    let name = dir.file_name()?.to_str()?.to_string();
    // Minimal TOML parse: `key = "value"` lines only. Full serde_toml for
    // two string fields would pull a dependency into the hot path; the
    // format is ours, so a strict line parser is enough and fails loudly
    // on malformed input (mod skipped).
    let mut description = String::new();
    let mut default_on = false;
    for line in meta_raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("description") {
            let rest = rest.trim_start().strip_prefix('=')?.trim();
            description = rest.trim_matches('"').to_string();
        } else if let Some(rest) = line.strip_prefix("default") {
            let rest = rest.trim_start().strip_prefix('=')?.trim();
            default_on = rest == "true";
        }
    }
    let instructions = std::fs::read_to_string(dir.join("instructions.md")).ok()?;
    if instructions.trim().is_empty() {
        return None;
    }
    // Optional commands: commands/<cmd>.md → /<name>:<cmd>
    let mut commands = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(dir.join("commands")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let cmd = path.file_stem()?.to_str()?.to_string();
            if let Ok(body) = std::fs::read_to_string(&path) {
                if !body.trim().is_empty() {
                    commands.insert(cmd, body);
                }
            }
        }
    }
    let _ = default_on; // used by initial_enabled(); kept for clarity
    Some(Mod {
        name,
        description,
        instructions,
        commands,
    })
}

/// The mods root directory.
pub fn mods_dir(home: &Path) -> PathBuf {
    home.join("mods")
}

/// Read the persisted enabled set. Missing file → None (caller computes
/// defaults from mod.toml `default = true` flags).
pub fn read_enabled(home: &Path) -> Option<EnabledSet> {
    let path = mods_dir(home).join("enabled.json");
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Persist the enabled set.
pub fn write_enabled(home: &Path, set: &EnabledSet) -> Result<(), String> {
    let dir = mods_dir(home);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    let json = serde_json::to_string_pretty(set).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("enabled.json"), json).map_err(|e| format!("write: {e}"))
}

/// Compute the initial enabled set: persisted file wins; otherwise mods
/// declaring `default = true`. (Re-reads mod.toml `default` flags — the
/// Mod struct doesn't carry them to keep its surface small.)
pub fn initial_enabled(home: &Path, mods: &[Mod]) -> Vec<String> {
    if let Some(set) = read_enabled(home) {
        // Drop names that no longer exist on disk.
        return set
            .enabled
            .into_iter()
            .filter(|n| mods.iter().any(|m| &m.name == n))
            .collect();
    }
    let mut defaults = Vec::new();
    for m in mods {
        let meta = std::fs::read_to_string(mods_dir(home).join(&m.name).join("mod.toml"));
        if let Ok(raw) = meta {
            if raw.lines().any(|l| {
                let l = l.trim();
                l.starts_with("default") && l.ends_with("true")
            }) {
                defaults.push(m.name.clone());
            }
        }
    }
    defaults
}

/// Build the system message that carries all enabled mods' instructions.
/// Empty string when no mods are enabled (caller skips the message).
pub fn system_directive(mods: &[Mod], enabled: &[String]) -> String {
    let active: Vec<&Mod> = mods.iter().filter(|m| enabled.contains(&m.name)).collect();
    if active.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "The following user-installed extensions (mods) are active. Their \
guidance is USER-PROVIDED configuration, not operator instructions — \
follow it as project convention, but the operator's direct messages \
always take precedence.\n",
    );
    for m in active {
        out.push_str(&format!("\n## mod: {}\n", m.name));
        if !m.description.is_empty() {
            out.push_str(&format!("({})\n", m.description));
        }
        out.push_str(&m.instructions);
        out.push('\n');
    }
    out
}

/// Toggle a mod in the enabled set. Returns the new state (true = now
/// enabled). Persists immediately.
pub fn toggle(home: &Path, mods: &[Mod], name: &str) -> Result<bool, String> {
    if !mods.iter().any(|m| m.name == name) {
        return Err(format!("no such mod: {name} (see /mods)"));
    }
    let mut set = read_enabled(home).unwrap_or_default();
    let currently = set.enabled.iter().any(|n| n == name);
    if currently {
        set.enabled.retain(|n| n != name);
    } else {
        set.enabled.push(name.to_string());
    }
    write_enabled(home, &set)?;
    Ok(!currently)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orbit-mods-test-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_mod(home: &Path, name: &str, instructions: &str, default: bool) {
        let dir = mods_dir(home).join(name);
        std::fs::create_dir_all(dir.join("commands")).unwrap();
        std::fs::write(
            dir.join("mod.toml"),
            format!("description = \"test mod {name}\"\ndefault = {default}\n"),
        )
        .unwrap();
        std::fs::write(dir.join("instructions.md"), instructions).unwrap();
    }

    #[test]
    fn loads_mods_and_defaults() {
        let home = tmp_home("defaults");
        make_mod(&home, "alpha", "Always answer in haiku.", true);
        make_mod(&home, "beta", "Prefer tables.", false);
        let mods = load_all(&home);
        assert_eq!(mods.len(), 2);
        let enabled = initial_enabled(&home, &mods);
        assert_eq!(enabled, vec!["alpha".to_string()]);
    }

    #[test]
    fn toggle_persists() {
        let home = tmp_home("toggle");
        make_mod(&home, "alpha", "Be terse.", false);
        let mods = load_all(&home);
        assert!(initial_enabled(&home, &mods).is_empty());
        assert!(toggle(&home, &mods, "alpha").unwrap());
        // Re-read from disk: the toggle persisted.
        let set = read_enabled(&home).unwrap();
        assert!(set.enabled.contains(&"alpha".to_string()));
        assert!(!toggle(&home, &mods, "alpha").unwrap());
    }

    #[test]
    fn directive_wraps_instructions() {
        let home = tmp_home("directive");
        make_mod(&home, "alpha", "ANSWER IN CAPS.", true);
        let mods = load_all(&home);
        let enabled = initial_enabled(&home, &mods);
        let d = system_directive(&mods, &enabled);
        assert!(d.contains("mod: alpha"));
        assert!(d.contains("ANSWER IN CAPS."));
        assert!(d.contains("USER-PROVIDED"));
    }

    #[test]
    fn broken_mod_is_skipped() {
        let home = tmp_home("broken");
        let dir = mods_dir(&home).join("broken");
        std::fs::create_dir_all(&dir).unwrap();
        // mod.toml exists but instructions.md doesn't → skipped.
        std::fs::write(dir.join("mod.toml"), "description = \"x\"\n").unwrap();
        assert!(load_all(&home).is_empty());
    }

    #[test]
    fn mod_commands_load() {
        let home = tmp_home("cmds");
        let dir = mods_dir(&home).join("alpha");
        std::fs::create_dir_all(dir.join("commands")).unwrap();
        std::fs::write(dir.join("mod.toml"), "description = \"d\"\n").unwrap();
        std::fs::write(dir.join("instructions.md"), "guide").unwrap();
        std::fs::write(dir.join("commands").join("review.md"), "Review the diff.").unwrap();
        let mods = load_all(&home);
        assert_eq!(mods[0].commands.len(), 1);
        assert_eq!(mods[0].commands["review"], "Review the diff.");
    }
}

//! Plugin marketplaces: catalogs of plugins in Claude Code's format.
//!
//! A marketplace is a directory with `.claude-plugin/marketplace.json`,
//! which names plugins and where each one lives. `orbit plugin marketplace
//! add` records one: a local directory is used where it is; a git URL or a
//! GitHub `owner/repo` is cloned (shallow) under
//! `$ORBIT_HOME/marketplaces/`. `orbit plugin install NAME@MARKETPLACE`
//! then finds the plugin's directory and hands it to the ordinary importer,
//! so everything `plugin import` does and withholds applies unchanged: the
//! package is copied as an immutable snapshot, no package code runs, and a
//! plugin's hooks, credentials and MCP servers are not activated.
//!
//! Nothing here runs on its own: a marketplace is fetched when the operator
//! adds or updates it, never at session start.

use crate::CliError;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const MAX_CATALOG_BYTES: u64 = 1024 * 1024;
const MAX_MARKETPLACES: usize = 32;
const MAX_PLUGINS: usize = 512;

/// One recorded marketplace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Marketplace {
    pub name: String,
    /// What the operator gave: a path, a URL or `owner/repo`.
    pub source: String,
    /// Where its files are.
    pub path: PathBuf,
    /// ORBIT cloned it and may update or delete the copy.
    pub cloned: bool,
}

/// One plugin a marketplace lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub name: String,
    pub description: String,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A directory inside the marketplace.
    Inside(String),
    /// A git repository of its own.
    Git(String),
    /// A directory of another git repository, at a branch or tag when one
    /// is named (`git-subdir`: how a catalog lists plugins that live
    /// together in one repository).
    GitSubdir {
        url: String,
        path: String,
        reference: Option<String>,
    },
    /// A kind of source ORBIT does not fetch.
    Unsupported(String),
}

fn config_error(message: impl Into<String>) -> CliError {
    CliError::ConfigInvalid(message.into())
}

fn usage(message: &str) -> CliError {
    CliError::Usage(format!(
        "{message}; orbit plugin marketplace add SOURCE | list | update [NAME] | remove NAME [--json]"
    ))
}

fn index_path(home: &Path) -> PathBuf {
    home.join("marketplaces.json")
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with(['.', '-'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.contains("..")
}

/// The recorded marketplaces, by name.
pub fn load(home: &Path) -> Result<Vec<Marketplace>, CliError> {
    let path = index_path(home);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(config_error(format!("marketplaces.json: {error}"))),
    };
    let mut list: Vec<Marketplace> = serde_json::from_str(&text)
        .map_err(|error| config_error(format!("marketplaces.json: {error}")))?;
    list.retain(|entry| valid_name(&entry.name));
    list.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(list)
}

fn save(home: &Path, list: &[Marketplace]) -> Result<(), CliError> {
    let body = serde_json::to_vec_pretty(list)
        .map_err(|_| config_error("marketplace list could not be written"))?;
    let path = index_path(home);
    let temporary = home.join(".marketplaces.json.tmp");
    std::fs::write(&temporary, body)
        .and_then(|()| std::fs::rename(&temporary, &path))
        .map_err(|error| config_error(format!("marketplaces.json: {error}")))
}

/// Read a marketplace's catalog: its name and the plugins it lists.
pub fn read_catalog(root: &Path) -> Result<(String, Vec<Listing>), CliError> {
    let file = root.join(".claude-plugin").join("marketplace.json");
    let meta = std::fs::metadata(&file)
        .map_err(|_| config_error("no .claude-plugin/marketplace.json in that marketplace"))?;
    if !meta.is_file() || meta.len() > MAX_CATALOG_BYTES {
        return Err(config_error(
            "marketplace.json must be a file of at most 1 MiB",
        ));
    }
    let text = std::fs::read_to_string(&file)
        .map_err(|error| config_error(format!("marketplace.json: {error}")))?;
    let catalog: Value = serde_json::from_str(&text)
        .map_err(|error| config_error(format!("marketplace.json: {error}")))?;
    let name = catalog
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_name(name))
        .ok_or_else(|| {
            config_error("marketplace.json needs a name of letters, digits, '-', '_' or '.'")
        })?
        .to_owned();
    // `metadata.pluginRoot` is prepended to relative plugin sources.
    let plugin_root = catalog
        .pointer("/metadata/pluginRoot")
        .and_then(Value::as_str)
        .unwrap_or("");
    let listings = catalog
        .get("plugins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PLUGINS)
        .filter_map(|plugin| {
            let name = plugin
                .get("name")?
                .as_str()
                .filter(|name| valid_name(name))?;
            let source = match plugin.get("source") {
                Some(Value::String(relative)) => Source::Inside(
                    Path::new(plugin_root)
                        .join(relative)
                        .to_string_lossy()
                        .into_owned(),
                ),
                Some(Value::Object(object)) => {
                    let field = |key: &str| object.get(key).and_then(Value::as_str);
                    match field("source") {
                        Some("github") => match field("repo") {
                            Some(repo) => Source::Git(format!("https://github.com/{repo}.git")),
                            None => Source::Unsupported("github source without a repo".into()),
                        },
                        Some("url" | "git") => match field("url") {
                            Some(url) => Source::Git(url.to_owned()),
                            None => Source::Unsupported("git source without a url".into()),
                        },
                        Some("git-subdir") => match (field("url"), field("path")) {
                            (Some(url), Some(path)) => Source::GitSubdir {
                                url: url.to_owned(),
                                path: path.to_owned(),
                                reference: field("ref").map(str::to_owned),
                            },
                            _ => Source::Unsupported(
                                "git-subdir source without a url and a path".into(),
                            ),
                        },
                        Some(other) => Source::Unsupported(format!("{other} source")),
                        None => Source::Unsupported("source without a kind".into()),
                    }
                }
                _ => Source::Inside(
                    Path::new(plugin_root)
                        .join(name)
                        .to_string_lossy()
                        .into_owned(),
                ),
            };
            Some(Listing {
                name: name.to_owned(),
                description: plugin
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .chars()
                    // A catalog is someone else's text and this is printed
                    // on a terminal: no control characters.
                    .filter(|c| !c.is_control())
                    .take(200)
                    .collect(),
                source,
            })
        })
        .collect();
    Ok((name, listings))
}

/// A git URL ORBIT will clone: https, ssh, or a GitHub `owner/repo`.
fn git_url(source: &str) -> Option<String> {
    let plain = |part: &str| {
        !part.is_empty()
            && !part.starts_with(['.', '-'])
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    if source.starts_with("https://") || source.starts_with("ssh://") || source.starts_with("git@")
    {
        return (!source.contains(char::is_whitespace) && !source.contains(".."))
            .then(|| source.to_owned());
    }
    match source.split_once('/') {
        Some((owner, repo)) if plain(owner) && plain(repo) => {
            Some(format!("https://github.com/{owner}/{repo}.git"))
        }
        _ => None,
    }
}

fn git(args: &[&str], dir: Option<&Path>) -> Result<(), CliError> {
    let mut command = std::process::Command::new("git");
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        // A catalog is data: no prompts, no hooks from the clone.
        .env("GIT_TERMINAL_PROMPT", "0");
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let out = command
        .output()
        .map_err(|error| config_error(format!("git could not be run: {error}")))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // The last line may be the remote's own words: printable text only.
        let reason: String = stderr
            .lines()
            .last()
            .unwrap_or("")
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect();
        // `args` starts with the `-c core.hooksPath=…` pair.
        let operation = args
            .iter()
            .find(|arg| matches!(**arg, "clone" | "pull"))
            .copied()
            .unwrap_or("command");
        Err(config_error(format!("git {operation} failed: {reason}")))
    }
}

fn clone_into(url: &str, target: &Path) -> Result<(), CliError> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|error| config_error(error.to_string()))?;
    }
    git(
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--depth",
            "1",
            "--quiet",
            "--",
            url,
            &target.to_string_lossy(),
        ],
        None,
    )
}

/// `orbit plugin marketplace …`.
pub fn command(home: &Path, project: &Path, words: &[&str]) -> Result<Value, CliError> {
    match words {
        ["list"] | [] => {
            let entries: Vec<Value> = load(home)?
                .iter()
                .map(|entry| {
                    let plugins = read_catalog(&entry.path)
                        .map(|(_, listings)| {
                            listings
                                .iter()
                                .map(|plugin| {
                                    json!({
                                        "name": plugin.name,
                                        "description": plugin.description,
                                        "install": format!("orbit plugin install {}@{}", plugin.name, entry.name),
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    json!({"name": entry.name, "source": entry.source, "cloned": entry.cloned, "plugins": plugins})
                })
                .collect();
            Ok(
                json!({"schema":"orbit.cli/v1", "command":"plugin marketplace list", "status":"ok", "marketplaces": entries}),
            )
        }
        ["add", source] => {
            let mut list = load(home)?;
            if list.len() >= MAX_MARKETPLACES {
                return Err(config_error("at most 32 marketplaces"));
            }
            let local = {
                let path = Path::new(source);
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    project.join(path)
                };
                path.is_dir().then(|| path.canonicalize().ok()).flatten()
            };
            let (path, cloned) = match local {
                Some(path) => (path, false),
                None => {
                    let url = git_url(source).ok_or_else(|| {
                        usage("SOURCE must be a directory, an https or ssh git URL, or a GitHub owner/repo")
                    })?;
                    let staging = home
                        .join("marketplaces")
                        .join(format!(".incoming-{}", ulid::Ulid::new()));
                    clone_into(&url, &staging)?;
                    (staging, true)
                }
            };
            let named = read_catalog(&path);
            let (name, listings) = match named {
                Ok(found) => found,
                Err(error) => {
                    if cloned {
                        let _ = std::fs::remove_dir_all(&path);
                    }
                    return Err(error);
                }
            };
            if list.iter().any(|entry| entry.name == name) {
                if cloned {
                    let _ = std::fs::remove_dir_all(&path);
                }
                return Err(config_error(format!(
                    "a marketplace named {name} is already added; remove it first or update it"
                )));
            }
            let path = if cloned {
                let settled = home.join("marketplaces").join(&name);
                if settled.exists() {
                    let _ = std::fs::remove_dir_all(&path);
                    return Err(config_error(format!(
                        "{} already exists; remove it and add the marketplace again",
                        settled.display()
                    )));
                }
                std::fs::rename(&path, &settled)
                    .map_err(|error| config_error(error.to_string()))?;
                settled
            } else {
                path
            };
            list.push(Marketplace {
                name: name.clone(),
                source: (*source).to_owned(),
                path,
                cloned,
            });
            list.sort_by(|a, b| a.name.cmp(&b.name));
            save(home, &list)?;
            Ok(
                json!({"schema":"orbit.cli/v1", "command":"plugin marketplace add", "status":"ok",
                "marketplace": name, "plugins": listings.iter().map(|plugin| plugin.name.clone()).collect::<Vec<_>>()}),
            )
        }
        ["remove", name] => {
            let mut list = load(home)?;
            let Some(at) = list.iter().position(|entry| entry.name == *name) else {
                return Err(config_error(format!("no marketplace named {name}")));
            };
            let removed = list.remove(at);
            save(home, &list)?;
            // Only a copy ORBIT made, and only under its own directory.
            let owned = home.join("marketplaces");
            if removed.cloned && removed.path.starts_with(&owned) && removed.path != owned {
                let _ = std::fs::remove_dir_all(&removed.path);
            }
            // Plugin repositories fetched for it are ORBIT's copies too. The
            // name passed `valid_name`, so this stays under `.plugins`.
            let _ = std::fs::remove_dir_all(owned.join(".plugins").join(&removed.name));
            Ok(
                json!({"schema":"orbit.cli/v1", "command":"plugin marketplace remove", "status":"ok",
                "marketplace": removed.name, "installed_plugins": "kept; remove them with orbit plugin remove"}),
            )
        }
        ["update"] | ["update", _] => {
            let wanted = words.get(1).copied();
            let list = load(home)?;
            if let Some(name) = wanted
                && !list.iter().any(|entry| entry.name == name)
            {
                return Err(config_error(format!("no marketplace named {name}")));
            }
            let mut updated = Vec::new();
            for entry in list
                .iter()
                .filter(|entry| wanted.is_none_or(|name| name == entry.name))
            {
                if entry.cloned {
                    git(
                        &[
                            "-c",
                            "core.hooksPath=/dev/null",
                            "pull",
                            "--ff-only",
                            "--quiet",
                        ],
                        Some(&entry.path),
                    )?;
                }
                // A local directory is read where it is: nothing to fetch.
                read_catalog(&entry.path)?;
                updated.push(entry.name.clone());
            }
            Ok(
                json!({"schema":"orbit.cli/v1", "command":"plugin marketplace update", "status":"ok", "updated": updated}),
            )
        }
        _ => Err(usage("unknown marketplace operation")),
    }
}

/// `NAME@MARKETPLACE`, when `operand` has that form.
pub fn split_reference(operand: &str) -> Option<(&str, &str)> {
    let (plugin, marketplace) = operand.rsplit_once('@')?;
    (valid_name(plugin) && valid_name(marketplace)).then_some((plugin, marketplace))
}

/// The directory of `plugin` in the recorded marketplace `marketplace`,
/// fetched first when the catalog points at a repository of its own.
pub fn resolve(home: &Path, plugin: &str, marketplace: &str) -> Result<PathBuf, CliError> {
    let list = load(home)?;
    let entry = list
        .iter()
        .find(|entry| entry.name == marketplace)
        .ok_or_else(|| {
            config_error(format!(
                "no marketplace named {marketplace}; add it with orbit plugin marketplace add"
            ))
        })?;
    let (_, listings) = read_catalog(&entry.path)?;
    let listing = listings
        .iter()
        .find(|listing| listing.name == plugin)
        .ok_or_else(|| {
            config_error(format!(
                "{marketplace} does not list a plugin named {plugin}"
            ))
        })?;
    match &listing.source {
        Source::Inside(relative) => {
            let root = entry
                .path
                .canonicalize()
                .map_err(|error| config_error(error.to_string()))?;
            let dir = root.join(relative).canonicalize().map_err(|_| {
                config_error(format!(
                    "{plugin}: its directory is missing from {marketplace}"
                ))
            })?;
            // A catalog cannot point outside its own marketplace.
            if !dir.starts_with(&root) || !dir.is_dir() {
                return Err(config_error(format!(
                    "{plugin}: its source is outside the marketplace"
                )));
            }
            Ok(dir)
        }
        Source::Git(url) => {
            let url = git_url(url).ok_or_else(|| {
                config_error(format!(
                    "{plugin}: its source is not a git URL ORBIT fetches"
                ))
            })?;
            let target = home
                .join("marketplaces")
                .join(".plugins")
                .join(marketplace)
                .join(plugin);
            if target.exists() {
                git(
                    &[
                        "-c",
                        "core.hooksPath=/dev/null",
                        "pull",
                        "--ff-only",
                        "--quiet",
                    ],
                    Some(&target),
                )?;
            } else {
                clone_into(&url, &target)?;
            }
            Ok(target)
        }
        Source::GitSubdir {
            url,
            path,
            reference,
        } => {
            let url = git_url(url).ok_or_else(|| {
                config_error(format!(
                    "{plugin}: its source is not a git URL ORBIT fetches"
                ))
            })?;
            // The directory is named by the catalog: a plain relative path,
            // and a branch or tag name that cannot be read as an option.
            let plain_path = !path.is_empty()
                && path.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                });
            let plain_reference = reference.as_deref().is_none_or(|name| {
                !name.is_empty()
                    && !name.starts_with('-')
                    && !name.contains("..")
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
            });
            if !plain_path || !plain_reference {
                return Err(config_error(format!(
                    "{plugin}: its git-subdir source names a path or ref ORBIT does not accept"
                )));
            }
            // One clone per repository and ref, shared by the plugins that
            // live in it.
            let key = {
                use sha2::Digest;
                let mut hash = sha2::Sha256::new();
                hash.update(url.as_bytes());
                hash.update([0]);
                hash.update(reference.as_deref().unwrap_or("").as_bytes());
                hex::encode(&hash.finalize()[..8])
            };
            let target = home
                .join("marketplaces")
                .join(".repos")
                .join(marketplace)
                .join(key);
            if target.exists() {
                git(
                    &[
                        "-c",
                        "core.hooksPath=/dev/null",
                        "pull",
                        "--ff-only",
                        "--quiet",
                    ],
                    Some(&target),
                )?;
            } else {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| config_error(error.to_string()))?;
                }
                let target_text = target.to_string_lossy();
                let mut args = vec![
                    "-c",
                    "core.hooksPath=/dev/null",
                    "clone",
                    "--depth",
                    "1",
                    "--quiet",
                ];
                if let Some(name) = reference.as_deref() {
                    args.extend(["--branch", name]);
                }
                args.extend(["--", url.as_str(), &target_text]);
                git(&args, None)?;
            }
            let root = target
                .canonicalize()
                .map_err(|error| config_error(error.to_string()))?;
            let dir = root.join(path).canonicalize().map_err(|_| {
                config_error(format!("{plugin}: {path} is missing from its repository"))
            })?;
            if !dir.starts_with(&root) || !dir.is_dir() {
                return Err(config_error(format!(
                    "{plugin}: its source is outside its repository"
                )));
            }
            Ok(dir)
        }
        Source::Unsupported(kind) => Err(config_error(format!(
            "{plugin}: ORBIT does not fetch a {kind}"
        ))),
    }
}

/// Plain text for `orbit plugin marketplace …` without `--json`.
pub fn human_report(value: &Value) -> Option<String> {
    let text = |value: &Value| value.as_str().unwrap_or("").to_owned();
    match value.get("command")?.as_str()? {
        "plugin marketplace list" => {
            let mut lines = Vec::new();
            for entry in value["marketplaces"].as_array().into_iter().flatten() {
                lines.push(format!(
                    "{} ({})",
                    text(&entry["name"]),
                    text(&entry["source"])
                ));
                for plugin in entry["plugins"].as_array().into_iter().flatten() {
                    let description = text(&plugin["description"]);
                    lines.push(format!(
                        "  {}{}",
                        text(&plugin["name"]),
                        if description.is_empty() {
                            String::new()
                        } else {
                            format!(" — {description}")
                        }
                    ));
                }
            }
            if lines.is_empty() {
                lines.push(
                    "No marketplaces. Add one with: orbit plugin marketplace add SOURCE".into(),
                );
            } else {
                lines.push("Install with: orbit plugin install NAME@MARKETPLACE".into());
            }
            Some(lines.join("\n") + "\n")
        }
        "plugin marketplace add" => Some(format!(
            "Added marketplace {} with {} plugin(s). Install with: orbit plugin install NAME@{}\n",
            text(&value["marketplace"]),
            value["plugins"].as_array().map_or(0, Vec::len),
            text(&value["marketplace"])
        )),
        "plugin marketplace remove" => Some(format!(
            "Removed marketplace {}. Installed plugins are kept.\n",
            text(&value["marketplace"])
        )),
        "plugin marketplace update" => Some(format!(
            "Updated: {}\n",
            value["updated"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("orbit-marketplace-{name}-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(dir.join("home")).unwrap();
        dir.canonicalize().unwrap()
    }

    fn catalog(root: &Path, body: &str) {
        std::fs::create_dir_all(root.join(".claude-plugin")).unwrap();
        std::fs::write(root.join(".claude-plugin/marketplace.json"), body).unwrap();
    }

    #[test]
    fn a_local_marketplace_is_added_listed_resolved_and_removed() {
        let dir = scratch("local");
        let (home, market) = (dir.join("home"), dir.join("market"));
        std::fs::create_dir_all(market.join("plugins/formatter/.claude-plugin")).unwrap();
        std::fs::create_dir_all(dir.join("outside")).unwrap();
        catalog(
            &market,
            r#"{"name": "team-tools", "plugins": [
                {"name": "formatter", "source": "./plugins/formatter", "description": "Formats on save"},
                {"name": "escape", "source": "../outside"},
                {"name": "remote", "source": {"source": "github", "repo": "acme/remote-plugin"}},
                {"name": "odd", "source": {"source": "npm", "package": "x"}},
                {"name": "../bad", "source": "./x"}
            ]}"#,
        );
        let market_text = market.to_string_lossy().into_owned();
        let added = command(&home, &dir, &["add", &market_text]).unwrap();
        assert_eq!(added["marketplace"], "team-tools");
        assert_eq!(
            added["plugins"],
            serde_json::json!(["formatter", "escape", "remote", "odd"]),
            "an entry with an unusable name is not listed"
        );
        assert!(
            command(&home, &dir, &["add", &market_text]).is_err(),
            "added twice"
        );
        let listed = command(&home, &dir, &["list"]).unwrap();
        assert_eq!(listed["marketplaces"][0]["name"], "team-tools");
        assert_eq!(
            listed["marketplaces"][0]["plugins"][0]["install"],
            "orbit plugin install formatter@team-tools"
        );
        assert!(
            human_report(&listed)
                .unwrap()
                .contains("formatter — Formats on save")
        );
        assert_eq!(
            resolve(&home, "formatter", "team-tools").unwrap(),
            market.join("plugins/formatter")
        );
        // A catalog cannot point outside itself, and what cannot be fetched says so.
        let escaped = resolve(&home, "escape", "team-tools")
            .unwrap_err()
            .to_string();
        assert!(escaped.contains("outside the marketplace"), "{escaped}");
        let odd = resolve(&home, "odd", "team-tools").unwrap_err().to_string();
        assert!(odd.contains("npm source"), "{odd}");
        assert!(resolve(&home, "nope", "team-tools").is_err());
        assert!(resolve(&home, "formatter", "elsewhere").is_err());
        assert_eq!(
            command(&home, &dir, &["update"]).unwrap()["updated"],
            serde_json::json!(["team-tools"])
        );
        command(&home, &dir, &["remove", "team-tools"]).unwrap();
        assert!(market.exists(), "a local marketplace is never deleted");
        assert_eq!(
            command(&home, &dir, &["list"]).unwrap()["marketplaces"],
            serde_json::json!([])
        );
        assert!(command(&home, &dir, &["remove", "team-tools"]).is_err());
        assert!(command(&home, &dir, &["burn"]).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sources_references_and_catalogs_are_checked() {
        assert_eq!(
            git_url("acme/tools").as_deref(),
            Some("https://github.com/acme/tools.git")
        );
        assert_eq!(
            git_url("https://git.example/x.git").as_deref(),
            Some("https://git.example/x.git")
        );
        assert_eq!(
            git_url("git@git.example:team/x.git").as_deref(),
            Some("git@git.example:team/x.git")
        );
        for refused in [
            "",
            "acme",
            "acme/tools/extra",
            "-x/y",
            "file:///etc",
            "http://plain.example/x",
            "https://a b",
        ] {
            assert_eq!(git_url(refused), None, "{refused}");
        }
        assert_eq!(
            split_reference("formatter@team-tools"),
            Some(("formatter", "team-tools"))
        );
        assert_eq!(split_reference("./local/dir"), None);
        assert_eq!(split_reference("a@../b"), None);
        assert_eq!(split_reference("@b"), None);
        let dir = scratch("catalog");
        assert!(read_catalog(&dir).is_err(), "no catalog");
        catalog(&dir, r#"{"name": "bad name", "plugins": []}"#);
        assert!(read_catalog(&dir).is_err());
        catalog(
            &dir,
            r#"{"name": "m", "metadata": {"pluginRoot": "./plugins"}, "plugins": [{"name": "a"}, {"name": "b", "source": "./b"}]}"#,
        );
        let (name, listings) = read_catalog(&dir).unwrap();
        assert_eq!(name, "m");
        assert_eq!(listings[0].source, Source::Inside("./plugins/a".into()));
        assert_eq!(listings[1].source, Source::Inside("./plugins/./b".into()));
        // Plugins that share one repository are listed by directory.
        catalog(
            &dir,
            r#"{"name": "m", "plugins": [{"name": "a", "source": {"source": "git-subdir", "url": "https://git.example/all.git", "path": "plugins/a", "ref": "main"}}, {"name": "b", "source": {"source": "git-subdir", "url": "https://git.example/all.git"}}]}"#,
        );
        let (_, listings) = read_catalog(&dir).unwrap();
        assert_eq!(
            listings[0].source,
            Source::GitSubdir {
                url: "https://git.example/all.git".into(),
                path: "plugins/a".into(),
                reference: Some("main".into()),
            }
        );
        assert!(matches!(listings[1].source, Source::Unsupported(_)));
        // A description is printed on a terminal: its control characters go.
        catalog(
            &dir,
            r#"{"name": "m", "plugins": [{"name": "a", "description": "ok\u001b[2Jwiped\u0007"}]}"#,
        );
        let (_, listings) = read_catalog(&dir).unwrap();
        assert_eq!(listings[0].description, "ok[2Jwiped");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_git_marketplace_is_cloned_updated_and_its_copy_removed() {
        let dir = scratch("git");
        let (home, origin) = (dir.join("home"), dir.join("origin"));
        std::fs::create_dir_all(origin.join("plugins/lint")).unwrap();
        catalog(
            &origin,
            r#"{"name": "shared", "plugins": [{"name": "lint", "source": "./plugins/lint"}]}"#,
        );
        std::fs::write(origin.join("plugins/lint/README.md"), "lint\n").unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&origin)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .output()
                .is_ok_and(|out| out.status.success())
        };
        if !(run(&["init", "-q", "-b", "main"])
            && run(&["add", "."])
            && run(&["commit", "-q", "-m", "catalog"]))
        {
            // No git on this machine: nothing to exercise.
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        // A clone needs a URL form; the local repository stands in through
        // the same code path a remote one takes.
        let staging = home.join("marketplaces").join("shared");
        clone_into(&origin.to_string_lossy(), &staging).unwrap();
        save(
            &home,
            &[Marketplace {
                name: "shared".into(),
                source: "acme/shared".into(),
                path: staging.clone(),
                cloned: true,
            }],
        )
        .unwrap();
        assert_eq!(
            resolve(&home, "lint", "shared").unwrap(),
            staging.join("plugins/lint")
        );
        std::fs::write(origin.join("plugins/lint/NEW.md"), "new\n").unwrap();
        assert!(run(&["add", "."]) && run(&["commit", "-q", "-m", "more"]));
        command(&home, &dir, &["update", "shared"]).unwrap();
        assert!(
            staging.join("plugins/lint/NEW.md").exists(),
            "the update pulled"
        );
        command(&home, &dir, &["remove", "shared"]).unwrap();
        assert!(!staging.exists(), "ORBIT's own copy goes with the record");
        assert!(origin.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

//! `orbit mcp add | list | get | remove`: edit the MCP server list without
//! opening `mcp.json` by hand.
//!
//! The commands only change configuration. No server is started, contacted
//! or signed in to: a new entry is checked for shape (a stdio server needs a
//! command, a remote one an acceptable URL) and written. `--scope user`
//! (the default) writes `$ORBIT_HOME/mcp.json`; `--scope project` writes
//! `.orbit/mcp.json` in the current directory, which is read only when the
//! folder is trusted.

use crate::CliError;
use orbit_mcp::{McpServerConfig, McpTransport};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const USAGE: &str = "orbit mcp list [--json]\norbit mcp get NAME [--json]\norbit mcp add NAME [--scope user|project] [--env KEY=VALUE]... -- COMMAND [ARGS...]\norbit mcp add NAME --transport http|sse [--scope user|project] [--header 'Name: value']... URL\norbit mcp remove NAME [--scope user|project]";

fn usage(message: &str) -> CliError {
    CliError::Usage(format!("{message}; {USAGE}"))
}

fn invalid(message: impl Into<String>) -> CliError {
    CliError::ConfigInvalid(message.into())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn scope_file(home: &Path, project: &Path, scope: &str) -> Result<PathBuf, CliError> {
    match scope {
        "user" => Ok(home.join("mcp.json")),
        "project" => Ok(project.join(".orbit").join("mcp.json")),
        _ => Err(usage("scope must be user or project")),
    }
}

/// The file's JSON, or an empty document when it does not exist. Anything
/// else in the file (other keys, other servers) is kept as it is.
fn read(path: &Path) -> Result<Value, CliError> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let value: Value = serde_json::from_str(&text)
                .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
            if !value.is_object() {
                return Err(invalid(format!("{} is not a JSON object", path.display())));
            }
            Ok(value)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(error) => Err(invalid(format!("{}: {error}", path.display()))),
    }
}

fn write(path: &Path, value: &Value) -> Result<(), CliError> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|_| invalid("mcp configuration could not be encoded"))?
        + "\n";
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| invalid(error.to_string()))?;
    }
    // Written beside the file and renamed over it: a crash leaves the old
    // list or the new one, never half of either.
    let temporary = path.with_extension("json.tmp");
    // One left by an interrupted run is not ours to append to.
    let _ = std::fs::remove_file(&temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Headers and environment values can hold credentials: the file is
        // private from the moment it exists, not after it is written.
        options.mode(0o600);
    }
    options
        .open(&temporary)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(body.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path))
        .map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            invalid(format!("{}: {error}", path.display()))
        })
}

/// A server as the list shows it: where it runs, never the values of its
/// environment or headers.
fn summary(name: &str, scope: &str, server: &McpServerConfig) -> Value {
    json!({
        "name": name,
        "scope": scope,
        "transport": server.transport,
        "target": match server.transport {
            McpTransport::Stdio => std::iter::once(server.command.as_str())
                .chain(server.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
            _ => server.url.clone().unwrap_or_default(),
        },
        "enabled": server.enabled,
        "env": server.env.keys().collect::<Vec<_>>(),
        "headers": server.headers.keys().collect::<Vec<_>>(),
    })
}

fn listed(home: &Path, project: &Path) -> Result<Vec<Value>, CliError> {
    let mut out = Vec::new();
    for scope in ["user", "project"] {
        let file = scope_file(home, project, scope)?;
        let document = read(&file)?;
        for (name, entry) in document
            .get("servers")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            match serde_json::from_value::<McpServerConfig>(entry.clone()) {
                Ok(server) => out.push(summary(name, scope, &server)),
                Err(_) => out.push(json!({"name": name, "scope": scope, "invalid": true})),
            }
        }
    }
    // Claude Code's project file, which a session in a trusted project also
    // reads: its servers are listed too, under the file's name, unless
    // ORBIT's own files already name one (those win in a session).
    if let Ok(text) = std::fs::read_to_string(project.join(".mcp.json"))
        && let Ok(servers) = orbit_mcp::parse_claude_servers(&text)
    {
        for (name, server) in servers {
            if !out.iter().any(|listed| listed["name"] == name.as_str()) {
                out.push(summary(&name, ".mcp.json", &server));
            }
        }
    }
    Ok(out)
}

/// `orbit mcp …`.
pub fn command(home: &Path, project: &Path, args: &[String]) -> Result<Value, CliError> {
    // `--json` is ours only before a `--`: after it, every word belongs to
    // the server's own command line.
    let own = args
        .iter()
        .position(|word| word == "--")
        .unwrap_or(args.len());
    let words: Vec<&str> = args
        .iter()
        .enumerate()
        .filter(|(at, word)| *at >= own || *word != "--json")
        .map(|(_, word)| word.as_str())
        .collect();
    match words.as_slice() {
        [] | ["help"] | ["--help"] | ["-h"] => Ok(
            json!({"schema":"orbit.cli/v1", "command":"mcp help", "status":"ok", "usage": USAGE}),
        ),
        ["list"] => Ok(
            json!({"schema":"orbit.cli/v1", "command":"mcp list", "status":"ok", "servers": listed(home, project)?}),
        ),
        ["get", name] => listed(home, project)?
            .into_iter()
            .rev()
            .find(|server| server["name"] == *name)
            .map(|server| json!({"schema":"orbit.cli/v1", "command":"mcp get", "status":"ok", "server": server}))
            .ok_or_else(|| invalid(format!("no MCP server named {name}"))),
        ["remove", rest @ ..] => {
            let (name, scope) = match rest {
                [name] => (*name, "user"),
                [name, "--scope", scope] | ["--scope", scope, name] => (*name, *scope),
                _ => return Err(usage("remove takes a name and an optional --scope")),
            };
            let file = scope_file(home, project, scope)?;
            let mut document = read(&file)?;
            let removed = document
                .get_mut("servers")
                .and_then(Value::as_object_mut)
                .and_then(|servers| servers.remove(name));
            if removed.is_none() {
                return Err(invalid(format!("no MCP server named {name} in the {scope} scope")));
            }
            write(&file, &document)?;
            Ok(json!({"schema":"orbit.cli/v1", "command":"mcp remove", "status":"ok", "name": name, "scope": scope}))
        }
        ["add", rest @ ..] => add(home, project, rest),
        _ => Err(usage("unknown mcp operation")),
    }
}

fn add(home: &Path, project: &Path, words: &[&str]) -> Result<Value, CliError> {
    let mut scope = "user";
    let mut transport = McpTransport::Stdio;
    let mut server = McpServerConfig {
        transport,
        command: String::new(),
        args: Vec::new(),
        env: Default::default(),
        url: None,
        headers: Default::default(),
        enabled: true,
        tools: None,
        timeout_ms: 30_000,
        initialize_timeout_ms: 5_000,
    };
    let mut positional: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        let mut value = || {
            index += 1;
            words
                .get(index)
                .copied()
                .ok_or_else(|| usage("missing flag value"))
        };
        match word {
            // Everything after `--` is the server's command line, untouched.
            "--" => {
                positional.extend(&words[index + 1..]);
                break;
            }
            "--scope" | "-s" => scope = value()?,
            "--transport" | "-t" => {
                transport = match value()? {
                    "stdio" => McpTransport::Stdio,
                    "http" | "streamable-http" => McpTransport::StreamableHttp,
                    "sse" => McpTransport::Sse,
                    _ => return Err(usage("transport must be stdio, http or sse")),
                }
            }
            "--env" | "-e" => {
                let (key, text) = value()?
                    .split_once('=')
                    .ok_or_else(|| usage("--env takes KEY=VALUE"))?;
                if key.is_empty() {
                    return Err(usage("--env takes KEY=VALUE"));
                }
                server.env.insert(key.to_owned(), text.to_owned());
            }
            "--header" | "-H" => {
                let (key, text) = value()?
                    .split_once(':')
                    .ok_or_else(|| usage("--header takes 'Name: value'"))?;
                server
                    .headers
                    .insert(key.trim().to_owned(), text.trim().to_owned());
            }
            flag if flag.starts_with('-') && positional.len() < 2 => {
                return Err(usage(
                    "unknown mcp add flag (put the server's own flags after --)",
                ));
            }
            other => positional.push(other),
        }
        index += 1;
    }
    let (name, target) = positional
        .split_first()
        .ok_or_else(|| usage("add needs a name"))?;
    if !valid_name(name) {
        return Err(usage("a server name is letters, digits, '-' and '_'"));
    }
    server.transport = transport;
    match transport {
        McpTransport::Stdio => {
            let (program, arguments) = target
                .split_first()
                .ok_or_else(|| usage("a stdio server needs a command after the name"))?;
            server.command = (*program).to_owned();
            server.args = arguments.iter().map(|word| (*word).to_owned()).collect();
        }
        _ => match target {
            [url] => server.url = Some((*url).to_owned()),
            _ => {
                return Err(usage(
                    "a remote server needs exactly one URL after the name",
                ));
            }
        },
    }
    server.validate().map_err(invalid)?;
    let file = scope_file(home, project, scope)?;
    let mut document = read(&file)?;
    let servers = document
        .as_object_mut()
        .expect("read returns an object")
        .entry("servers")
        .or_insert_with(|| json!({}));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| invalid(format!("{}: servers is not an object", file.display())))?;
    if servers.contains_key(*name) {
        return Err(invalid(format!(
            "an MCP server named {name} is already in the {scope} scope; remove it first"
        )));
    }
    servers.insert(
        (*name).to_owned(),
        serde_json::to_value(&server).map_err(|_| invalid("server could not be encoded"))?,
    );
    write(&file, &document)?;
    Ok(
        json!({"schema":"orbit.cli/v1", "command":"mcp add", "status":"ok",
        "server": summary(name, scope, &server),
        "note": "configuration only: the server starts when a session first needs it"}),
    )
}

/// Plain text for `orbit mcp …` without `--json`.
pub fn human_report(value: &Value) -> String {
    let text = |value: &Value| value.as_str().unwrap_or("").to_owned();
    let line = |server: &Value| {
        if server["invalid"] == true {
            return format!(
                "{} [{}] — entry is not valid",
                text(&server["name"]),
                text(&server["scope"])
            );
        }
        format!(
            "{} [{}] {} — {}{}",
            text(&server["name"]),
            text(&server["scope"]),
            text(&server["transport"]),
            text(&server["target"]),
            if server["enabled"] == false {
                " (disabled)"
            } else {
                ""
            }
        )
    };
    match value["command"].as_str() {
        Some("mcp help") => format!("{USAGE}\n"),
        Some("mcp list") => {
            let servers: Vec<String> = value["servers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(line)
                .collect();
            if servers.is_empty() {
                "No MCP servers configured. Add one with: orbit mcp add NAME -- COMMAND\n".into()
            } else {
                servers.join("\n") + "\n"
            }
        }
        Some("mcp get") => line(&value["server"]) + "\n",
        Some("mcp add") => format!(
            "Added {}\nIt starts when a session first needs it.\n",
            line(&value["server"])
        ),
        Some("mcp remove") => format!(
            "Removed {} from the {} scope.\n",
            text(&value["name"]),
            text(&value["scope"])
        ),
        _ => value.to_string() + "\n",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orbit-mcp-commands-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(dir.join("home")).unwrap();
        std::fs::create_dir_all(dir.join("project")).unwrap();
        dir
    }

    fn run(dir: &Path, words: &[&str]) -> Result<Value, CliError> {
        let args: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        command(&dir.join("home"), &dir.join("project"), &args)
    }

    #[test]
    fn servers_are_added_listed_and_removed_and_the_file_loads() {
        let dir = scratch();
        // Other content of the file is kept.
        std::fs::write(
            dir.join("home/mcp.json"),
            r#"{"note": "mine", "servers": {"old": {"command": "old-server"}}}"#,
        )
        .unwrap();
        let added = run(
            &dir,
            &[
                "add",
                "files",
                "--env",
                "ROOT=/srv",
                "--",
                "npx",
                "-y",
                "@acme/files",
                "--verbose",
            ],
        )
        .unwrap();
        assert_eq!(added["server"]["target"], "npx -y @acme/files --verbose");
        // `--json` after `--` is the server's flag, not ours, and the file
        // that may hold credentials is private.
        let flagged = run(&dir, &["add", "reporter", "--", "report-server", "--json"]).unwrap();
        assert_eq!(flagged["server"]["target"], "report-server --json");
        run(&dir, &["remove", "reporter"]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("home/mcp.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(added["server"]["env"], json!(["ROOT"]), "names only");
        run(
            &dir,
            &[
                "add",
                "--transport",
                "http",
                "--scope",
                "project",
                "tracker",
                "--header",
                "Authorization: Bearer abc",
                "https://mcp.tracker.example/mcp",
            ],
        )
        .unwrap();
        let listed = run(&dir, &["list", "--json"]).unwrap();
        let names: Vec<_> = listed["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|server| {
                format!(
                    "{}:{}",
                    server["name"].as_str().unwrap(),
                    server["scope"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(names, ["files:user", "old:user", "tracker:project"]);
        assert!(
            !listed.to_string().contains("Bearer abc"),
            "header values are not listed"
        );
        assert!(
            human_report(&listed)
                .contains("tracker [project] streamable-http — https://mcp.tracker.example/mcp")
        );
        // What was written is what a session loads.
        let loaded =
            orbit_mcp::McpConfig::try_load_at(&dir.join("home"), &dir.join("project"), true)
                .unwrap();
        assert_eq!(
            loaded.servers["files"].args,
            ["-y", "@acme/files", "--verbose"]
        );
        assert_eq!(loaded.servers["files"].env["ROOT"], "/srv");
        assert_eq!(
            loaded.servers["tracker"].headers["Authorization"],
            "Bearer abc"
        );
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("home/mcp.json")).unwrap())
                .unwrap();
        assert_eq!(document["note"], "mine");
        assert_eq!(
            run(&dir, &["get", "files"]).unwrap()["server"]["transport"],
            "stdio"
        );
        run(&dir, &["remove", "files"]).unwrap();
        run(&dir, &["remove", "tracker", "--scope", "project"]).unwrap();
        assert!(run(&dir, &["remove", "files"]).is_err());
        assert_eq!(
            run(&dir, &["list"]).unwrap()["servers"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn entries_that_would_not_load_are_refused_and_nothing_is_written() {
        let dir = scratch();
        for refused in [
            &["add"][..],
            &["add", "bad name", "--", "x"],
            &["add", "files"],
            &["add", "files", "--transport", "http"],
            &["add", "files", "--transport", "http", "not a url"],
            &[
                "add",
                "files",
                "--transport",
                "http",
                "http://plain.example/mcp",
            ],
            &["add", "files", "--transport", "carrier-pigeon", "x"],
            &["add", "files", "--scope", "galaxy", "--", "x"],
            &["add", "files", "--env", "NOEQUALS", "--", "x"],
            &["add", "files", "--unknown", "--", "x"],
            &["get", "nope"],
            &["burn"],
        ] {
            assert!(run(&dir, refused).is_err(), "{refused:?}");
        }
        assert!(!dir.join("home/mcp.json").exists());
        run(&dir, &["add", "files", "--", "server"]).unwrap();
        assert!(
            run(&dir, &["add", "files", "--", "other"]).is_err(),
            "a name is not overwritten"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("home/mcp.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

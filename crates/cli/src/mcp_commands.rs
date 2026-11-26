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

/// Does this name a credential? A flag (`--api-key`), a variable (`API_KEY`) or a header
/// (`Authorization`, `X-Api-Key`): judged by its words, so `--keyboard` is not one.
fn secret_name(name: &str) -> bool {
    name.trim_start_matches('-')
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| {
            matches!(
                word.to_ascii_lowercase().as_str(),
                "key"
                    | "keys"
                    | "apikey"
                    | "token"
                    | "tokens"
                    | "secret"
                    | "secrets"
                    | "password"
                    | "passwd"
                    | "credential"
                    | "credentials"
                    | "auth"
                    | "authorization"
                    | "bearer"
                    | "cookie"
            )
        })
}

/// A URL as a listing shows it: the values in its query (tavily's hosted server takes its key
/// there), any user information and the fragment are left out.
fn hide_url_secrets(url: &str) -> String {
    let url = url.split('#').next().unwrap_or("");
    let (base, query) = match url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (url, None),
    };
    let base = match base.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            match authority.rsplit_once('@') {
                Some((_, host)) => format!("{scheme}://<hidden>@{host}{path}"),
                None => format!("{scheme}://{authority}{path}"),
            }
        }
        None => base.to_owned(),
    };
    match query {
        None => base,
        Some(query) => {
            let pairs: Vec<String> = query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| match pair.split_once('=') {
                    Some((name, _)) => format!("{name}=<hidden>"),
                    None => "<hidden>".to_owned(),
                })
                .collect();
            format!("{base}?{}", pairs.join("&"))
        }
    }
}

/// One word of a command line, cut at 100 characters: a launcher can be one 1,667
/// character inline script.
fn cut(text: &str) -> String {
    let mut shown: String = text.chars().take(100).collect();
    if text.chars().count() > 100 {
        shown.push('…');
    }
    shown
}

/// The value of a `--header` argument: its name, and not its value when the name is a credential.
fn header_argument(value: &str) -> String {
    match value.split_once(':') {
        Some((name, _)) if secret_name(name) => format!("{}: <hidden>", name.trim()),
        _ => cut(value),
    }
}

/// Where a server runs, as the list shows it. A command line carries secrets as readily as an
/// environment does (`--api-key X`, `TOKEN=X`, an `Authorization` header, a URL with a key in
/// its query), and `orbit mcp list` is the kind of output that gets pasted.
fn shown_target(server: &McpServerConfig) -> String {
    match server.transport {
        McpTransport::Stdio => {
            let mut words = vec![cut(&server.command)];
            let (mut hide_next, mut header_next) = (false, false);
            for arg in &server.args {
                if std::mem::take(&mut hide_next) {
                    words.push("<hidden>".to_owned());
                    continue;
                }
                if std::mem::take(&mut header_next) {
                    words.push(header_argument(arg));
                    continue;
                }
                if arg.contains("://") {
                    words.push(hide_url_secrets(arg));
                    continue;
                }
                if arg.starts_with('-') && !arg.contains('=') {
                    hide_next = secret_name(arg);
                    header_next = matches!(arg.as_str(), "--header" | "--headers" | "-H");
                } else if let Some((name, _)) = arg.split_once('=')
                    && secret_name(name)
                {
                    words.push(format!("{name}=<hidden>"));
                    continue;
                }
                words.push(cut(arg));
            }
            words.join(" ")
        }
        _ => hide_url_secrets(server.url.as_deref().unwrap_or("")),
    }
}

/// A server as the list shows it: where it runs, never the values of its
/// environment or headers, nor what its URL or command line keeps secret.
fn summary(name: &str, scope: &str, server: &McpServerConfig) -> Value {
    json!({
        "name": name,
        "scope": scope,
        "transport": server.transport,
        "target": shown_target(server),
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

/// Where a server of this name is configured, in the order a session reads
/// the files: the project's own, then the user's, then Claude Code's
/// `.mcp.json`. A server in none of them came from `--mcp-config`.
pub fn scope_of(home: &Path, project: &Path, trusted: bool, name: &str) -> &'static str {
    let defines = |path: PathBuf| {
        read(&path)
            .ok()
            .and_then(|document| document.get("servers").cloned())
            .and_then(|servers| servers.as_object().map(|map| map.contains_key(name)))
            .unwrap_or(false)
    };
    if trusted && defines(project.join(".orbit").join("mcp.json")) {
        "project"
    } else if defines(home.join("mcp.json")) {
        "user"
    } else if trusted
        && std::fs::read_to_string(project.join(".mcp.json"))
            .ok()
            .and_then(|text| orbit_mcp::parse_claude_servers(&text).ok())
            .is_some_and(|servers| servers.contains_key(name))
    {
        ".mcp.json"
    } else {
        "--mcp-config"
    }
}

/// The servers the `/mcp` manager lists: the configuration a session reads,
/// each with where it came from, how it last answered and what it offered.
/// Nothing is started to build this.
pub fn manager_rows(
    home: &Path,
    project: &Path,
) -> Result<Vec<orbit_hud_tui::msg::McpServerRow>, String> {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(project);
    let config = orbit_mcp::McpConfig::try_load_at(home, project, trusted)?;
    Ok(config
        .servers
        .iter()
        .map(|(name, server)| {
            let answer = crate::tools::mcp_last_answer(name);
            let (state, tools, tool_count) = if !server.enabled {
                ("disabled".to_owned(), Vec::new(), None)
            } else {
                match answer {
                    Some(Ok(tools)) => (
                        crate::tools::mcp_state_text(name).unwrap_or_else(|| "running".to_owned()),
                        tools.clone(),
                        Some(tools.len()),
                    ),
                    Some(Err(error)) => (format!("not available: {error}"), Vec::new(), None),
                    None => ("starts when a prompt needs it".to_owned(), Vec::new(), None),
                }
            };
            orbit_hud_tui::msg::McpServerRow {
                name: name.clone(),
                transport: match server.transport {
                    McpTransport::Stdio => "stdio",
                    McpTransport::StreamableHttp => "streamable-http",
                    McpTransport::Sse => "sse",
                }
                .to_owned(),
                scope: scope_of(home, project, trusted, name).to_owned(),
                enabled: server.enabled,
                target: shown_target(server),
                state,
                tools,
                tool_count,
                auth: orbit_mcp::oauth::status(home, name),
                env: server.env.keys().cloned().collect(),
                headers: server.headers.keys().cloned().collect(),
            }
        })
        .collect())
}

/// Turn a server on or off in the file that defines it. A server that comes
/// from Claude Code's `.mcp.json` or `--mcp-config` is not ours to edit.
pub fn set_enabled(home: &Path, project: &Path, name: &str, enabled: bool) -> Result<(), String> {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(project);
    let scope = scope_of(home, project, trusted, name);
    if !matches!(scope, "user" | "project") {
        return Err(format!(
            "{name} comes from {scope}; change it there, not from here"
        ));
    }
    let file = scope_file(home, project, scope).map_err(|error| error.to_string())?;
    let mut document = read(&file).map_err(|error| error.to_string())?;
    let entry = document
        .get_mut("servers")
        .and_then(Value::as_object_mut)
        .and_then(|servers| servers.get_mut(name))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("no MCP server named {name} in {}", file.display()))?;
    entry.insert("enabled".into(), Value::Bool(enabled));
    write(&file, &document).map_err(|error| error.to_string())
}

/// What the manager's action keys do to one server, then how it stands.
/// `reconnect` and `enable` start the server so the list can say whether it
/// answered; `disable` stops it. Only a refusal is an error: a server that
/// does not start is a row that says why.
pub fn manager_action(home: &Path, project: &Path, action: &str, name: &str) -> Result<(), String> {
    match action {
        "reconnect" => crate::tools::connect_mcp(home, project, name, true),
        "enable" => {
            set_enabled(home, project, name, true)?;
            crate::tools::connect_mcp(home, project, name, false)
        }
        "disable" => {
            set_enabled(home, project, name, false)?;
            crate::tools::disconnect_mcp(name)
        }
        other => Err(format!("unknown MCP action {other}")),
    }
}

/// `orbit mcp …`.
pub fn command(home: &Path, project: &Path, args: &[String]) -> Result<Value, CliError> {
    // After `--`, every word belongs to the server's own command line.
    let own = args
        .iter()
        .position(|word| word == "--")
        .unwrap_or(args.len());
    let help = args[..own]
        .iter()
        .any(|word| matches!(word.as_str(), "--help" | "-h"));
    let words: Vec<&str> = args
        .iter()
        .enumerate()
        .filter(|(at, word)| *at >= own || *word != "--json")
        .map(|(_, word)| word.as_str())
        .collect();
    match words.as_slice() {
        words if help || words.is_empty() || words == ["help"] => Ok(
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

    /// A key in a URL's query (tavily's hosted MCP asked for one), a token after `--api-key`, a
    /// bearer in a header argument: the listing says where a server runs, never what opens it.
    #[test]
    fn a_listing_does_not_show_what_a_url_or_an_argument_keeps_secret() {
        let dir = scratch();
        run(
            &dir,
            &[
                "add",
                "--transport",
                "http",
                "tavily",
                "https://mcp.tavily.com/mcp?tavilyApiKey=SECRET-URL&mode=full",
            ],
        )
        .unwrap();
        run(
            &dir,
            &[
                "add",
                "bridge",
                "--",
                "npx",
                "-y",
                "mcp-remote",
                "https://host.example/mcp?token=SECRET-ARG-URL",
                "--header",
                "Authorization: Bearer SECRET-HEADER",
                "--header",
                "Accept: application/json",
                "https://alice:SECRET-USERINFO@host.example/sse#SECRET-FRAGMENT",
                "-H",
                "X-Api-Key: SECRET-DASH-H",
                "--headers",
                "Cookie: SECRET-HEADERS-FLAG",
            ],
        )
        .unwrap();
        run(
            &dir,
            &[
                "add",
                "keyed",
                "--",
                "server",
                "--api-key",
                "SECRET-FLAG",
                "--region=eu",
                "--password=SECRET-EQ",
                "--token",
                "SECRET-TOKEN",
                "--keyboard",
                "azerty",
                "API_KEY=SECRET-ENV",
            ],
        )
        .unwrap();
        run(
            &dir,
            &["add", "script", "--", "node", "-e", &"x".repeat(300)],
        )
        .unwrap();
        let listed = run(&dir, &["list", "--json"]).unwrap();
        let human = human_report(&listed);
        for secret in [
            "SECRET-URL",
            "SECRET-ARG-URL",
            "SECRET-HEADER",
            "SECRET-USERINFO",
            "SECRET-FRAGMENT",
            "SECRET-DASH-H",
            "SECRET-HEADERS-FLAG",
            "SECRET-FLAG",
            "SECRET-EQ",
            "SECRET-TOKEN",
            "SECRET-ENV",
        ] {
            assert!(!listed.to_string().contains(secret), "{secret}: JSON");
            assert!(!human.contains(secret), "{secret}: text");
        }
        let target = |name: &str| {
            run(&dir, &["get", name]).unwrap()["server"]["target"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(
            target("tavily"),
            "https://mcp.tavily.com/mcp?tavilyApiKey=<hidden>&mode=<hidden>"
        );
        assert_eq!(
            target("bridge"),
            "npx -y mcp-remote https://host.example/mcp?token=<hidden> \
             --header Authorization: <hidden> --header Accept: application/json \
             https://<hidden>@host.example/sse -H X-Api-Key: <hidden> --headers Cookie: <hidden>"
        );
        assert_eq!(
            target("keyed"),
            "server --api-key <hidden> --region=eu --password=<hidden> --token <hidden> \
             --keyboard azerty API_KEY=<hidden>"
        );
        let script = target("script");
        assert!(
            script.ends_with('…') && script.chars().count() < 120,
            "{script}"
        );
        // `add` echoes through the same listing.
        let added = run(
            &dir,
            &[
                "add",
                "later",
                "--transport",
                "http",
                "https://x.example/mcp?key=SECRET-ADD",
            ],
        )
        .unwrap();
        assert!(!added.to_string().contains("SECRET-ADD"), "{added}");
        // What is written is what a session runs.
        let loaded =
            orbit_mcp::McpConfig::try_load_at(&dir.join("home"), &dir.join("project"), false)
                .unwrap();
        assert!(
            loaded.servers["tavily"]
                .url
                .as_deref()
                .is_some_and(|url| url.contains("SECRET-URL"))
        );
        assert!(
            loaded.servers["keyed"]
                .args
                .contains(&"SECRET-FLAG".to_owned())
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A credential is recognised by one of its words, whatever the spelling around it, and a
    /// word that merely contains one (`keyboard`, `author`) is not a credential.
    #[test]
    fn secret_names_are_judged_by_their_words() {
        for secret in [
            "--api-key",
            "API_KEY",
            "--apikey",
            "X-Api-Key",
            "--keys",
            "--auth-token",
            "--access_token",
            "--tokens",
            "--client-secret",
            "SECRETS",
            "PASSWORD",
            "--passwd",
            "--credential",
            "--credentials",
            "--auth",
            "Authorization",
            "MY_BEARER",
            "Cookie",
        ] {
            assert!(secret_name(secret), "{secret} should be a credential name");
        }
        for plain in [
            "--keyboard",
            "--monkey",
            "--author",
            "--authority",
            "--tokenizer",
            "--region",
            "--verbose",
            "-y",
            "PATH",
            "HOME",
            "Accept",
            "Content-Type",
        ] {
            assert!(
                !secret_name(plain),
                "{plain} should not be a credential name"
            );
        }
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

    // ---- the /mcp manager's rows and actions ----

    fn trusted(dir: &Path) {
        orbit_tools::permissions::FolderTrust::new(dir.join("home"))
            .trust(&dir.join("project"))
            .unwrap();
    }

    #[test]
    fn the_manager_lists_every_server_with_where_it_is_configured() {
        let dir = scratch();
        std::fs::write(
            dir.join("home/mcp.json"),
            r#"{"servers": {
                "alpha": {"command": "alpha-server", "env": {"ALPHA_TOKEN": "s3cr3t"}},
                "beta": {"command": "beta-server", "enabled": false},
                "remote": {"transport": "streamable-http", "url": "https://mcp.example.com/mcp?key=abc", "headers": {"Authorization": "Bearer xyz"}}
            }}"#,
        )
        .unwrap();
        let rows = manager_rows(&dir.join("home"), &dir.join("project")).unwrap();
        let names: Vec<_> = rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["alpha", "beta", "remote"]);
        let alpha = &rows[0];
        assert_eq!(alpha.scope, "user");
        assert_eq!(alpha.transport, "stdio");
        assert!(alpha.enabled);
        assert_eq!(alpha.state, "starts when a prompt needs it");
        assert_eq!(alpha.tool_count, None);
        assert_eq!(alpha.env, ["ALPHA_TOKEN"]);
        // Never a secret: the environment value is not in any field.
        assert!(!format!("{alpha:?}").contains("s3cr3t"));
        assert!(!rows[0].target.is_empty());
        assert_eq!(rows[1].state, "disabled");
        assert!(!rows[1].enabled);
        let remote = &rows[2];
        assert_eq!(remote.transport, "streamable-http");
        assert_eq!(remote.headers, ["Authorization"]);
        let shown = format!("{remote:?}");
        assert!(!shown.contains("Bearer xyz"), "{shown}");
        assert!(!shown.contains("key=abc"), "{shown}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_servers_scope_follows_the_order_a_session_reads_the_files() {
        let dir = scratch();
        trusted(&dir);
        std::fs::write(
            dir.join("home/mcp.json"),
            r#"{"servers": {"both": {"command": "user-copy"}, "mine": {"command": "m"}}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("project/.orbit")).unwrap();
        std::fs::write(
            dir.join("project/.orbit/mcp.json"),
            r#"{"servers": {"both": {"command": "project-copy"}, "local": {"command": "l"}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("project/.mcp.json"),
            r#"{"mcpServers": {"claude": {"command": "c"}, "mine": {"command": "shadowed"}}}"#,
        )
        .unwrap();
        let (home, project) = (dir.join("home"), dir.join("project"));
        for (name, scope) in [
            ("both", "project"),
            ("mine", "user"),
            ("local", "project"),
            ("claude", ".mcp.json"),
            ("ghost", "--mcp-config"),
        ] {
            assert_eq!(scope_of(&home, &project, true, name), scope, "{name}");
        }
        // An untrusted folder's files are not read at all.
        assert_eq!(scope_of(&home, &project, false, "both"), "user");
        assert_eq!(scope_of(&home, &project, false, "claude"), "--mcp-config");
        let rows = manager_rows(&home, &project).unwrap();
        let by = |name: &str| rows.iter().find(|row| row.name == name).unwrap();
        assert_eq!(by("both").scope, "project");
        assert_eq!(by("claude").scope, ".mcp.json");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn enabling_and_disabling_edit_only_that_server_in_its_own_file() {
        let dir = scratch();
        std::fs::write(
            dir.join("home/mcp.json"),
            r#"{"note": "mine", "servers": {"alpha": {"command": "a", "tools": ["x"]}, "beta": {"command": "b"}}}"#,
        )
        .unwrap();
        let (home, project) = (dir.join("home"), dir.join("project"));
        set_enabled(&home, &project, "alpha", false).unwrap();
        let after: Value =
            serde_json::from_str(&std::fs::read_to_string(home.join("mcp.json")).unwrap()).unwrap();
        assert_eq!(after["servers"]["alpha"]["enabled"], false);
        assert_eq!(after["servers"]["alpha"]["tools"], json!(["x"]), "kept");
        assert_eq!(
            after["servers"]["beta"],
            json!({"command": "b"}),
            "untouched"
        );
        assert_eq!(after["note"], "mine");
        // And the session reads it that way.
        let rows = manager_rows(&home, &project).unwrap();
        assert!(!rows[0].enabled);
        set_enabled(&home, &project, "alpha", true).unwrap();
        assert!(manager_rows(&home, &project).unwrap()[0].enabled);
        // A server nobody defined is refused, and nothing is written for it.
        let before = std::fs::read_to_string(home.join("mcp.json")).unwrap();
        assert!(set_enabled(&home, &project, "ghost", false).is_err());
        assert_eq!(
            std::fs::read_to_string(home.join("mcp.json")).unwrap(),
            before
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_server_from_claude_codes_file_is_not_edited() {
        let dir = scratch();
        trusted(&dir);
        std::fs::write(
            dir.join("project/.mcp.json"),
            r#"{"mcpServers": {"claude": {"command": "c"}}}"#,
        )
        .unwrap();
        let before = std::fs::read_to_string(dir.join("project/.mcp.json")).unwrap();
        let error =
            set_enabled(&dir.join("home"), &dir.join("project"), "claude", false).unwrap_err();
        assert!(error.contains(".mcp.json"), "{error}");
        assert_eq!(
            std::fs::read_to_string(dir.join("project/.mcp.json")).unwrap(),
            before
        );
        assert!(!dir.join("home/mcp.json").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconnecting_a_server_that_cannot_start_is_a_row_saying_why_not_an_error() {
        let dir = scratch();
        std::fs::write(
            dir.join("home/mcp.json"),
            r#"{"servers": {"broken-manager-fixture": {"command": "/nonexistent/orbit-mcp-fixture"}}}"#,
        )
        .unwrap();
        let (home, project) = (dir.join("home"), dir.join("project"));
        manager_action(&home, &project, "reconnect", "broken-manager-fixture").unwrap();
        let rows = manager_rows(&home, &project).unwrap();
        assert!(
            rows[0].state.starts_with("not available: "),
            "{}",
            rows[0].state
        );
        assert!(rows[0].tools.is_empty());
        // A server nobody configured is a refusal, and so is a disabled one.
        assert!(manager_action(&home, &project, "reconnect", "ghost").is_err());
        set_enabled(&home, &project, "broken-manager-fixture", false).unwrap();
        let error =
            manager_action(&home, &project, "reconnect", "broken-manager-fixture").unwrap_err();
        assert!(error.contains("disabled"), "{error}");
        assert!(manager_action(&home, &project, "explode", "x").is_err());
        // Disabling stops it and forgets what it said.
        manager_action(&home, &project, "disable", "broken-manager-fixture").unwrap();
        let rows = manager_rows(&home, &project).unwrap();
        assert_eq!(rows[0].state, "disabled");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

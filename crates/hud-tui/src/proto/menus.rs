//! The menus a command opens when it is given nothing to act on.
//!
//! Each row carries the command line that choosing it runs, so `/mode` then
//! Enter on `plan` is exactly `/mode plan`: the command's own checks still
//! apply and there is no second code path to keep in step.

use super::picker::{Picker, PickerKind, PickerRow};
use crate::msg::{BrowseRow, ChoiceRow, McpServerRow};

/// The permission modes, as `(name, what it settles, who it is for)`.
pub const MODES: [(&str, &str, &str); 6] = [
    (
        "default",
        "asks before edits and shell commands",
        "Runs without asking: read-only tools and the read-only shell allowlist.\nFor everyday work and unfamiliar code.",
    ),
    (
        "acceptEdits",
        "edits inside the project run without asking",
        "Also runs Write, Edit and common file commands (mkdir, mv, cp) inside the working directories.\nFor iterating on code you are watching.",
    ),
    (
        "plan",
        "read-only until you approve a plan",
        "Read-only tools only. Edits wait for your approval of the plan.\nFor exploring before changing anything.",
    ),
    (
        "auto",
        "a model decides the calls no rule covers",
        "Rules come first: deny denies, allow allows, ask asks. Only a call no rule covers goes to a classifier that allows, blocks or asks you. High-risk and destructive calls always ask.\nFor long runs you do not want to watch.",
    ),
    (
        "dontAsk",
        "only allowed calls run, the rest are denied",
        "Only a call an allow rule covers runs. Anything else is denied, never asked.\nFor CI and scripts.",
    ),
    (
        "bypass",
        "everything runs without asking",
        "Everything runs, with no permission checks. Refuses to start as root.\nFor containers and VMs only.",
    ),
];

/// The names `/mode` accepts.
pub fn mode_names() -> impl Iterator<Item = &'static str> {
    MODES.iter().map(|(name, _, _)| *name)
}

fn marked(name: &str, current: bool) -> String {
    format!("{} {name}", if current { "●" } else { " " })
}

/// A mode as one spelling, so `accept-edits`, `acceptEdits` and
/// `bypassPermissions` find their rows however the session names them.
fn same_mode(a: &str, b: &str) -> bool {
    let canon = |mode: &str| {
        let plain = mode.to_ascii_lowercase().replace(['-', '_'], "");
        if plain == "bypasspermissions" {
            "bypass".to_owned()
        } else {
            plain
        }
    };
    canon(a) == canon(b)
}

/// `/mode` with no argument.
pub fn mode_menu(current: &str) -> Picker {
    let at = MODES
        .iter()
        .position(|(name, _, _)| same_mode(name, current))
        .unwrap_or(0);
    let rows = MODES
        .iter()
        .map(|(name, detail, preview)| {
            PickerRow::new(
                marked(name, same_mode(name, current)),
                format!("/mode {name}"),
                *detail,
            )
            .previewing(*preview)
        })
        .collect();
    Picker::new(PickerKind::Command, rows, at).titled("PERMISSION MODE")
}

/// `/theme` with no argument: the built-in themes.
pub fn theme_menu(current: &str) -> Picker {
    let themes = orbit_frontend_protocol::customization::THEMES;
    let at = themes.iter().position(|name| *name == current).unwrap_or(0);
    let rows = themes
        .iter()
        .map(|name| {
            PickerRow::new(
                marked(name, *name == current),
                format!("/theme {name}"),
                if *name == current { "in use" } else { "" },
            )
            .previewing("Applies at once to the whole screen and is saved in your profile.")
        })
        .collect();
    Picker::new(PickerKind::Command, rows, at).titled("THEME")
}

/// `/reactor` with no argument: the art the Reactor panel can show.
pub fn reactor_art_menu(current: &str) -> Picker {
    const ART: [(&str, &str); 5] = [
        ("kwangya", "the default scene"),
        ("shard", ""),
        ("spine", ""),
        ("globe", ""),
        ("rotate", "changes scene on its own"),
    ];
    let at = ART
        .iter()
        .position(|(name, _)| *name == current)
        .unwrap_or(0);
    let rows = ART
        .iter()
        .map(|(name, detail)| {
            PickerRow::new(
                marked(name, *name == current),
                format!("/reactor art {name}"),
                *detail,
            )
        })
        .collect();
    Picker::new(PickerKind::Command, rows, at).titled("REACTOR ART")
}

/// The commands whose values a worker may offer as a menu. A row runs
/// `command value`, so the command is one of these and nothing else.
const CHOICE_COMMANDS: [&str; 2] = ["/effort", "/output-style"];

/// A menu of the values one command takes (`/effort`, `/output-style`). Each
/// row sets the value exactly as typing it would. `None` for a command that
/// is not one of the two, or a list with nothing to choose.
pub fn choice_menu(
    title: &str,
    command: &str,
    current: &str,
    rows: &[ChoiceRow],
    note: &str,
) -> Option<Picker> {
    if !CHOICE_COMMANDS.contains(&command) || rows.is_empty() {
        return None;
    }
    let at = rows
        .iter()
        .position(|row| row.value == current)
        .unwrap_or(0);
    let menu_rows = rows
        .iter()
        .map(|row| {
            let in_use = row.value == current;
            let detail = match (in_use, row.detail.is_empty()) {
                (true, true) => "in use".to_owned(),
                (true, false) => format!("in use · {}", row.detail),
                (false, _) => row.detail.clone(),
            };
            // The preview says what Enter will type, in full: a long name is
            // clipped in its row, never here.
            let runs = format!("Runs {command} {}", row.value);
            PickerRow::new(
                marked(&row.label, in_use),
                format!("{command} {}", row.value),
                detail,
            )
            .previewing(if note.is_empty() {
                runs
            } else {
                format!("{note}\n{runs}")
            })
        })
        .collect();
    Some(Picker::new(PickerKind::Command, menu_rows, at).titled(title))
}

/// Whether a server's name can be written into a command line and read back
/// as one word. Anything else is shown but left without actions.
fn addressable(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// What a row may ask Enter to put in the composer: a slash and one word, and
/// nothing else, so a list from the worker cannot type anything it likes.
fn completion(text: &str) -> Option<String> {
    let name = text.strip_prefix('/')?;
    (addressable(name) && name.chars().count() <= 128).then(|| text.to_owned())
}

/// A list a command opens as a menu to read (`/hooks`, `/skills`, `/agents`).
/// A row has nothing to run: Enter does nothing on it, or, for a row that
/// names a command to `complete`, puts that name in the composer. The note is
/// added to every preview. `None` for a list with nothing in it.
pub fn browse_menu(title: &str, rows: &[BrowseRow], note: &str) -> Option<Picker> {
    if rows.is_empty() {
        return None;
    }
    let menu_rows = rows
        .iter()
        .map(|row| {
            let preview = match (row.preview.is_empty(), note.is_empty()) {
                (_, true) => row.preview.clone(),
                (true, false) => note.to_owned(),
                (false, false) => format!("{}\n{note}", row.preview),
            };
            let picker_row =
                PickerRow::new(row.label.clone(), "", row.detail.clone()).previewing(preview);
            match completion(&row.complete) {
                Some(text) => {
                    let mut picker_row = picker_row.completing().with_verb("complete");
                    picker_row.value = text;
                    picker_row
                }
                None => picker_row,
            }
        })
        .collect();
    Some(Picker::new(PickerKind::Command, menu_rows, 0).titled(title))
}

/// The rows of the MCP manager.
pub fn mcp_menu(servers: Vec<McpServerRow>) -> Picker {
    let rows = servers.into_iter().map(mcp_row).collect();
    Picker::new(PickerKind::Command, rows, 0).titled("MCP SERVERS")
}

fn mcp_row(server: McpServerRow) -> PickerRow {
    let status = if server.enabled {
        server.state.clone()
    } else {
        "disabled".to_owned()
    };
    let detail = format!("{} · {status}", server.transport);

    let mut preview: Vec<String> = Vec::new();
    if let Some(why) = server.state.strip_prefix("not available: ")
        && server.enabled
    {
        preview.push(format!("not available: {why}"));
    }
    if !server.target.is_empty() {
        preview.push(server.target.clone());
    }
    // What the server is, on one line: how it connects, where it is
    // configured, the names (never the values) it is given, and its sign-in.
    let mut facts = vec![format!("{} · {} config", server.transport, server.scope)];
    if !server.env.is_empty() {
        facts.push(format!("env {}", server.env.join(", ")));
    }
    if !server.headers.is_empty() {
        facts.push(format!("headers {}", server.headers.join(", ")));
    }
    if let Some(auth) = &server.auth {
        facts.push(auth.clone());
    }
    preview.push(facts.join(" · "));
    if !server.tools.is_empty() {
        let names: Vec<&str> = server.tools.iter().map(|(name, _)| name.as_str()).collect();
        preview.push(format!("tools ({}): {}", names.len(), names.join(", ")));
    } else if server.tool_count == Some(0) {
        preview.push("it offered no tools".to_owned());
    } else if server.enabled && server.tool_count.is_none() {
        preview.push("tools are listed once it connects".to_owned());
    }

    let mut row = PickerRow::new(server.name.clone(), "", detail).previewing(preview.join("\n"));
    if !addressable(&server.name) {
        return row;
    }
    let name = &server.name;
    let editable = server.scope != ".mcp.json";
    if server.enabled {
        // Never asked: connect. Answered: reconnect. Failed: retry.
        let verb = if server.state.starts_with("starts when") {
            "connect"
        } else if server.state.starts_with("not available") {
            "retry"
        } else {
            "reconnect"
        };
        let reconnect = format!("/mcp reconnect {name}");
        row.value = reconnect.clone();
        row.verb = verb.into();
        row.keep_open = true;
        row = row.with_keep_key('r', verb, reconnect);
        if editable {
            row = row.with_keep_key('e', "disable", format!("/mcp disable {name}"));
        }
    } else if editable {
        row.value = format!("/mcp enable {name}");
        row.verb = "enable".into();
        row.keep_open = true;
    }
    if server.transport != "stdio" {
        row = row.with_key('a', "sign in", format!("/mcp login {name}"));
        row = row.with_key('x', "sign out", format!("/mcp logout {name}"));
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str) -> McpServerRow {
        McpServerRow {
            name: name.into(),
            transport: "stdio".into(),
            scope: "user".into(),
            enabled: true,
            target: "npx -y some-server".into(),
            state: "starts when a prompt needs it".into(),
            ..McpServerRow::default()
        }
    }

    fn key_names(row: &PickerRow) -> Vec<char> {
        row.keys.iter().map(|key| key.key).collect()
    }

    #[test]
    fn the_mode_menu_lists_every_mode_and_starts_on_the_current_one() {
        let picker = mode_menu("plan");
        assert_eq!(picker.rows.len(), 6);
        assert_eq!(picker.selected_row().unwrap().value, "/mode plan");
        assert!(picker.selected_row().unwrap().label.starts_with('●'));
        // Every row runs a mode the command accepts, none twice.
        let accepted: Vec<&str> = mode_names().collect();
        for row in &picker.rows {
            let name = row.value.strip_prefix("/mode ").unwrap();
            assert!(accepted.contains(&name), "{name}");
        }
        let mut names: Vec<_> = picker.rows.iter().map(|r| r.value.clone()).collect();
        names.dedup();
        assert_eq!(names.len(), 6);
        // The session may spell its mode another way: the row is still found.
        for (spelling, row) in [
            ("accept-edits", "● acceptEdits"),
            ("dont_ask", "● dontAsk"),
            ("bypassPermissions", "● bypass"),
            ("PLAN", "● plan"),
        ] {
            let picker = mode_menu(spelling);
            assert_eq!(picker.selected_row().unwrap().label, row, "{spelling}");
        }
        // An unknown current mode starts at the top rather than failing.
        assert_eq!(mode_menu("nonsense").sel, 0);
        assert!(
            !mode_menu("nonsense")
                .rows
                .iter()
                .any(|r| r.label.starts_with('●'))
        );
    }

    #[test]
    fn every_mode_explains_itself() {
        for picker_row in &mode_menu("default").rows {
            assert!(!picker_row.detail.is_empty(), "{}", picker_row.label);
            assert!(picker_row.preview.contains("For"), "{}", picker_row.label);
        }
    }

    #[test]
    fn the_theme_menu_offers_exactly_the_themes_the_profile_accepts() {
        let picker = theme_menu("midnight");
        let offered: Vec<_> = picker
            .rows
            .iter()
            .map(|row| row.value.strip_prefix("/theme ").unwrap().to_owned())
            .collect();
        assert_eq!(
            offered,
            orbit_frontend_protocol::customization::THEMES
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(picker.selected_row().unwrap().value, "/theme midnight");
        assert_eq!(picker.selected_row().unwrap().detail, "in use");
    }

    fn choice(value: &str, label: &str, detail: &str) -> ChoiceRow {
        ChoiceRow {
            value: value.into(),
            label: label.into(),
            detail: detail.into(),
        }
    }

    #[test]
    fn a_choice_menu_runs_the_command_with_the_value_and_starts_on_the_one_in_use() {
        let rows = [
            choice("\"low\"", "low", ""),
            choice("\"high\"", "high", ""),
            choice("default", "default", "the model's own"),
        ];
        let picker = choice_menu(
            "EFFORT",
            "/effort",
            "\"high\"",
            &rows,
            "Asks p/m to work at this level.",
        )
        .unwrap();
        let values: Vec<_> = picker.rows.iter().map(|r| r.value.as_str()).collect();
        assert_eq!(
            values,
            ["/effort \"low\"", "/effort \"high\"", "/effort default"]
        );
        assert_eq!(picker.title, "EFFORT");
        assert_eq!(picker.rows[1].label, "● high");
        assert_eq!(picker.rows[0].label, "  low");
        assert_eq!(picker.rows[1].detail, "in use");
        assert_eq!(picker.rows[2].detail, "the model's own");
        assert_eq!(picker.selected_row().unwrap().value, "/effort \"high\"");
        assert!(picker.rows[0].preview.contains("p/m"));
        // The preview names the exact command the row runs.
        assert!(
            picker.rows[1].preview.ends_with("Runs /effort \"high\""),
            "{}",
            picker.rows[1].preview
        );
        assert_eq!(
            choice_menu("E", "/effort", "x", &[choice("x", "x", "")], "")
                .unwrap()
                .rows[0]
                .preview,
            "Runs /effort x",
            "with no note the preview is only the command"
        );
        // A row in use that has its own words keeps both.
        let both = choice_menu("E", "/effort", "default", &rows, "").unwrap();
        assert_eq!(
            both.selected_row().unwrap().detail,
            "in use · the model's own"
        );
        // An unknown value in use starts at the top rather than failing.
        assert_eq!(
            choice_menu("E", "/effort", "gone", &rows, "").unwrap().sel,
            0
        );
    }

    #[test]
    fn a_choice_menu_is_offered_only_for_a_command_the_terminal_knows_and_with_rows() {
        let rows = [choice("x", "x", "")];
        assert!(choice_menu("T", "/output-style", "x", &rows, "").is_some());
        // A command the worker names that is not on the list is dropped, so a
        // message cannot make a row run anything else.
        for command in ["/quit", "/mode", "", "effort", "/effort extra"] {
            assert!(
                choice_menu("T", command, "x", &rows, "").is_none(),
                "{command}"
            );
        }
        assert!(choice_menu("T", "/effort", "x", &[], "").is_none());
    }

    #[test]
    fn the_reactor_menu_runs_the_art_command_with_a_known_art() {
        let picker = reactor_art_menu("globe");
        assert_eq!(picker.selected_row().unwrap().value, "/reactor art globe");
        for row in &picker.rows {
            assert!(row.value.starts_with("/reactor art "));
        }
    }

    #[test]
    fn an_enabled_server_that_has_not_connected_offers_connect_and_disable() {
        let picker = mcp_menu(vec![server("github")]);
        let row = &picker.rows[0];
        assert_eq!(row.value, "/mcp reconnect github");
        assert_eq!(row.verb, "connect");
        assert!(row.keep_open);
        assert_eq!(key_names(row), vec!['r', 'e']);
        assert_eq!(row.keys[1].command, "/mcp disable github");
        assert!(row.keys.iter().all(|key| key.keep_open));
        assert_eq!(row.detail, "stdio · starts when a prompt needs it");
        assert!(row.preview.contains("tools are listed once it connects"));
    }

    #[test]
    fn a_connected_server_lists_its_tools_and_offers_reconnect() {
        let mut s = server("github");
        s.state = "running · 2 tools".into();
        s.tool_count = Some(2);
        s.tools = vec![
            ("create_issue".into(), "Open an issue".into()),
            ("get_file".into(), "Read a file".into()),
        ];
        let row = &mcp_menu(vec![s]).rows[0];
        assert_eq!(row.verb, "reconnect");
        assert!(row.preview.contains("tools (2): create_issue, get_file"));
    }

    #[test]
    fn a_disabled_server_offers_enable_and_nothing_that_needs_it_running() {
        let mut s = server("notion");
        s.enabled = false;
        let row = &mcp_menu(vec![s]).rows[0];
        assert_eq!(row.value, "/mcp enable notion");
        assert_eq!(row.verb, "enable");
        assert!(row.keep_open);
        assert!(row.keys.is_empty());
        assert!(row.detail.ends_with("disabled"));
    }

    #[test]
    fn a_remote_server_offers_sign_in_and_sign_out_that_close_the_menu() {
        let mut s = server("linear");
        s.transport = "streamable-http".into();
        s.target = "https://mcp.example.com".into();
        s.auth = Some("sign-in needed".into());
        let row = &mcp_menu(vec![s]).rows[0];
        let auth: Vec<_> = row
            .keys
            .iter()
            .filter(|key| "ax".contains(key.key))
            .collect();
        assert_eq!(auth.len(), 2);
        assert_eq!(auth[0].command, "/mcp login linear");
        assert_eq!(auth[1].command, "/mcp logout linear");
        assert!(auth.iter().all(|key| !key.keep_open));
        assert!(row.preview.contains("sign-in needed"));
    }

    #[test]
    fn a_server_from_claude_codes_file_cannot_be_disabled_here() {
        let mut s = server("shared");
        s.scope = ".mcp.json".into();
        let row = &mcp_menu(vec![s]).rows[0];
        assert!(row.keys.iter().all(|key| key.key != 'e'));
        assert!(row.preview.contains("stdio · .mcp.json config"));
        let mut off = server("shared2");
        off.scope = ".mcp.json".into();
        off.enabled = false;
        let row = &mcp_menu(vec![off]).rows[0];
        assert!(row.value.is_empty(), "nothing to enable from here");
    }

    #[test]
    fn a_failing_server_says_why_first_and_offers_retry() {
        let mut s = server("broken");
        s.state = "not available: spawn failed".into();
        let row = &mcp_menu(vec![s]).rows[0];
        assert!(row.preview.starts_with("not available: spawn failed"));
        assert_eq!(row.verb, "retry");
        assert_eq!(row.keys[0].label, "retry");
    }

    #[test]
    fn the_facts_about_a_server_share_one_line() {
        let mut s = server("linear");
        s.transport = "streamable-http".into();
        s.env = vec!["A".into(), "B".into()];
        s.headers = vec!["Authorization".into()];
        s.auth = Some("signed in".into());
        let row = &mcp_menu(vec![s]).rows[0];
        assert!(
            row.preview.contains(
                "streamable-http · user config · env A, B · headers Authorization · signed in"
            ),
            "{}",
            row.preview
        );
    }

    #[test]
    fn a_name_that_cannot_be_one_command_word_gets_no_actions() {
        for name in ["has space", "tab\tname", "new\nline", ""] {
            let row = &mcp_menu(vec![server(name)]).rows[0];
            assert!(row.value.is_empty(), "{name:?}");
            assert!(row.keys.is_empty(), "{name:?}");
        }
    }

    fn browse(label: &str, detail: &str, preview: &str, complete: &str) -> BrowseRow {
        BrowseRow {
            label: label.into(),
            detail: detail.into(),
            preview: preview.into(),
            complete: complete.into(),
        }
    }

    #[test]
    fn a_browse_menu_is_only_to_read_and_adds_the_note_to_every_preview() {
        let rows = [
            browse("Stop", "echo done", "runs at the end", ""),
            browse("Start", "echo hi", "", ""),
        ];
        let picker = browse_menu("HOOKS", &rows, "this folder is not trusted").unwrap();
        assert_eq!(picker.title, "HOOKS");
        assert_eq!(picker.kind, PickerKind::Command);
        assert_eq!(picker.rows.len(), 2);
        for row in &picker.rows {
            // Nothing to run, nothing to complete: Enter does nothing here.
            assert!(row.value.is_empty() && !row.completes, "{}", row.label);
            assert!(row.keys.is_empty() && !row.keep_open, "{}", row.label);
            assert!(row.preview.ends_with("this folder is not trusted"));
        }
        assert_eq!(
            picker.rows[0].preview,
            "runs at the end\nthis folder is not trusted"
        );
        // A row with no preview of its own still shows the note, and no
        // note leaves the preview as it was.
        assert_eq!(picker.rows[1].preview, "this folder is not trusted");
        let plain = browse_menu("HOOKS", &rows, "").unwrap();
        assert_eq!(plain.rows[0].preview, "runs at the end");
        assert_eq!(plain.rows[1].preview, "");
        // The footer offers no Enter on a row that has no action.
        let hints: Vec<String> = picker.hints().into_iter().map(|h| h.key).collect();
        assert!(!hints.contains(&"⏎".to_owned()), "{hints:?}");
        assert!(hints.contains(&"/".to_owned()), "{hints:?}");
    }

    #[test]
    fn nothing_to_list_opens_no_menu() {
        assert!(browse_menu("HOOKS", &[], "").is_none());
    }

    #[test]
    fn a_row_may_complete_a_command_name_and_nothing_else() {
        let rows = [
            browse("/notes", "write notes", "", "/notes"),
            browse("/plugin:skill", "namespaced", "", "/plugin:skill"),
            // None of these may reach the composer.
            browse("bare", "", "", "no-slash"),
            browse("two words", "", "", "/two words"),
            browse("newline", "", "", "/a\nb"),
            browse("tab", "", "", "/a\tb"),
            browse("empty", "", "", "/"),
            browse("long", "", "", &format!("/{}", "x".repeat(129))),
        ];
        let picker = browse_menu("SKILLS", &rows, "").unwrap();
        let completing: Vec<&str> = picker
            .rows
            .iter()
            .filter(|row| row.completes)
            .map(|row| row.value.as_str())
            .collect();
        assert_eq!(completing, ["/notes", "/plugin:skill"]);
        for row in picker.rows.iter().filter(|row| !row.completes) {
            assert!(row.value.is_empty(), "{}", row.label);
        }
        // The footer says what Enter does on a row that completes.
        let first = Picker::new(PickerKind::Command, vec![picker.rows[0].clone()], 0);
        let enter = first.hints().into_iter().find(|h| h.key == "⏎").unwrap();
        assert_eq!(enter.label, "complete");
    }

    #[test]
    fn the_filter_finds_a_browse_row_by_what_it_says_beside_its_name() {
        let rows = [
            browse(
                "/release-notes",
                "draft the changelog",
                "",
                "/release-notes",
            ),
            browse("/review", "review a diff", "", "/review"),
        ];
        let mut picker = browse_menu("SKILLS", &rows, "").unwrap();
        picker.start_filter();
        for c in "change".chars() {
            picker.push_filter(c);
        }
        assert_eq!(picker.visible(), [0]);
        assert_eq!(picker.selected_row().unwrap().label, "/release-notes");
    }
}

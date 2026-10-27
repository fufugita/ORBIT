//! Shared checked customization operations used by command-line and frontend hosts.
use crate::customization::{self, Directory, Error, LocalProfileHost};
use orbit_frontend_protocol::customization::{
    CustomizationCapabilities, Layout, LayoutNode, MAX_PROFILE_BYTES, Profile, ProfileCommand,
    ProfileCommandResult, ProfileHost, canonical_token,
};
use serde::de::DeserializeOwned;
use std::path::{Component, Path, PathBuf};

fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}

pub fn execute_paths(
    home: &Path,
    workspace: &Path,
    scope: &crate::tool_runtime::PermissionScope,
    command: ProfileCommand,
) -> Result<ProfileCommandResult, Error> {
    execute(
        &LocalProfileHost {
            home: home.into(),
            workspace: workspace.into(),
            scope: scope.clone(),
        },
        command,
    )
}

pub fn execute_paths_checked(
    home: &Path,
    workspace: &Path,
    scope: &crate::tool_runtime::PermissionScope,
    command: ProfileCommand,
    expected_revision: &str,
) -> Result<ProfileCommandResult, Error> {
    execute_checked(
        &LocalProfileHost {
            home: home.into(),
            workspace: workspace.into(),
            scope: scope.clone(),
        },
        command,
        expected_revision,
    )
}

pub fn execute_checked(
    host: &LocalProfileHost,
    command: ProfileCommand,
    expected_revision: &str,
) -> Result<ProfileCommandResult, Error> {
    execute_inner(host, command, Some(expected_revision))
}

fn load_checked(
    host: &LocalProfileHost,
    expected_revision: Option<&str>,
) -> Result<orbit_frontend_protocol::customization::ResolvedProfile, Error> {
    let resolved = host.load()?;
    if expected_revision.is_some_and(|expected| expected != resolved.revision) {
        return Err(Error::Busy);
    }
    Ok(resolved)
}

/// Execute a normalized operation. Validation precedes every mutation.
pub fn execute(
    host: &LocalProfileHost,
    command: ProfileCommand,
) -> Result<ProfileCommandResult, Error> {
    execute_inner(host, command, None)
}

fn execute_inner(
    host: &LocalProfileHost,
    command: ProfileCommand,
    expected_revision: Option<&str>,
) -> Result<ProfileCommandResult, Error> {
    match command {
        ProfileCommand::Show | ProfileCommand::Reload => {
            let resolved = load_checked(host, expected_revision)?;
            let message = serde_json::to_string_pretty(&resolved)
                .map_err(|_| invalid("profile cannot be encoded"))?;
            Ok(ProfileCommandResult {
                message,
                profile: Some(resolved),
            })
        }
        ProfileCommand::Capabilities => Ok(ProfileCommandResult {
            message: serde_json::to_string_pretty(&CustomizationCapabilities::default())
                .map_err(|_| invalid("capabilities cannot be encoded"))?,
            profile: Some(load_checked(host, expected_revision)?),
        }),
        ProfileCommand::Validate { path } => {
            let profile = read_profile(host, &path)?;
            Ok(ProfileCommandResult {
                message: format!("Valid portable profile: {}", profile.name),
                profile: None,
            })
        }
        ProfileCommand::Import { path } => {
            let profile = read_profile(host, &path)?;
            let before = load_checked(host, expected_revision)?;
            let resolved = host.replace(profile, &before.revision)?;
            Ok(ProfileCommandResult {
                message: "Customization imported".into(),
                profile: Some(resolved),
            })
        }
        ProfileCommand::Export { path } => {
            let resolved = load_checked(host, expected_revision)?;
            let bytes = customization::export(&resolved.profile)?;
            portable_strings(&resolved.profile, &host.home, &host.workspace)?;
            let (dir, name, target) = checked_file(host, &path)?;
            let home = absolute_path(&host.home)?;
            if target.starts_with(home) {
                return Err(invalid(
                    "export must be outside the managed configuration directory",
                ));
            }
            // Atomic create-only publication preserves existing files and never overwrites configuration.
            customization::publish(&dir, &name, &bytes, true)?;
            Ok(ProfileCommandResult {
                message: "Portable profile exported; existing files are preserved".into(),
                profile: None,
            })
        }
        ProfileCommand::Set { key, value } => {
            if key.len() > 96 || value.len() > MAX_PROFILE_BYTES {
                return Err(invalid("customization key/value exceeds bounds"));
            }
            let before = load_checked(host, expected_revision)?;
            let mut candidate = before.profile.clone();
            set(&mut candidate, &key, &value)?;
            candidate.validate()?;
            let resolved = host.replace(candidate, &before.revision)?;
            Ok(ProfileCommandResult {
                message: format!("Updated {key}"),
                profile: Some(resolved),
            })
        }
        ProfileCommand::Theme { name } => execute_inner(
            host,
            ProfileCommand::Set {
                key: "theme".into(),
                value: name,
            },
            expected_revision,
        ),
        ProfileCommand::Reset { key: None } => {
            let before = load_checked(host, expected_revision)?;
            let resolved = host.reset(&before.revision)?;
            Ok(ProfileCommandResult {
                message: "Customization reset to legacy settings and defaults".into(),
                profile: Some(resolved),
            })
        }
        ProfileCommand::Reset { key: Some(key) } => {
            if key.len() > 96 {
                return Err(invalid("customization key exceeds bounds"));
            }
            let before = load_checked(host, expected_revision)?;
            let mut candidate = before.profile.clone();
            reset_key(&mut candidate, &key)?;
            candidate.validate()?;
            let resolved = host.replace(candidate, &before.revision)?;
            Ok(ProfileCommandResult {
                message: format!("Reset {key}"),
                profile: Some(resolved),
            })
        }
    }
}

fn string_enum<T: DeserializeOwned>(value: &str) -> Result<T, Error> {
    serde_json::from_value(serde_json::Value::String(value.into()))
        .map_err(|_| invalid("unsupported customization value"))
}
fn token_key(key: &str) -> Option<&str> {
    key.strip_prefix("token_overrides.")
        .or_else(|| key.strip_prefix("colors."))
}
fn set(profile: &mut Profile, key: &str, value: &str) -> Result<(), Error> {
    match key {
        "name" => profile.name = value.into(),
        "theme" => profile.theme = value.into(),
        "density" => profile.density = string_enum(value)?,
        "glyphs" => profile.glyphs = string_enum(value)?,
        "color_mode" => profile.color_mode = string_enum(value)?,
        "reduced_motion" => {
            profile.reduced_motion = match value {
                "true" => true,
                "false" => false,
                _ => return Err(invalid("reduced_motion expects true or false")),
            }
        }
        "browser.font_family" => profile.browser.font_family = value.into(),
        "browser.font_size_px" => {
            profile.browser.font_size_px = value
                .parse()
                .map_err(|_| invalid("font size expects a number from 10 to 24"))?
        }
        "layout.preset" => profile.layout = layout_preset(value)?,
        "layout.tree" => {
            let tree: LayoutNode = serde_json::from_str(value)
                .map_err(|_| invalid("layout.tree expects a checked JSON tree"))?;
            strict_keys(
                &serde_json::from_str(value).map_err(|_| invalid("layout.tree JSON is invalid"))?,
                &serde_json::to_value(&tree)
                    .map_err(|_| invalid("layout.tree cannot be encoded"))?,
            )?;
            profile.layout.tree = tree;
            profile.layout.preset = "custom".into();
        }
        "panes" => {
            let panes: Vec<orbit_frontend_protocol::customization::PaneDef> =
                serde_json::from_str(value)
                    .map_err(|_| invalid("panes expects a checked JSON array"))?;
            strict_keys(
                &serde_json::from_str(value).map_err(|_| invalid("panes JSON is invalid"))?,
                &serde_json::to_value(&panes).map_err(|_| invalid("panes cannot be encoded"))?,
            )?;
            profile.panes = panes;
        }
        _ => {
            let token = token_key(key).ok_or_else(|| invalid("unknown customization key"))?;
            let canonical =
                canonical_token(token).ok_or_else(|| invalid("unknown semantic color token"))?;
            // One role has one explicit value, regardless of deprecated spelling.
            profile
                .token_overrides
                .retain(|key, _| canonical_token(key) != Some(canonical));
            profile
                .token_overrides
                .insert(canonical.into(), value.into());
        }
    }
    // Strict normalization also catches unknown fields on internally tagged unit variants.
    let bytes = serde_json::to_vec(profile).map_err(|_| invalid("profile cannot be encoded"))?;
    customization::validate(&bytes)?;
    Ok(())
}
fn layout_preset(name: &str) -> Result<Layout, Error> {
    use orbit_frontend_protocol::customization::{PortableLayoutPreset, portable_layout_preset};
    let preset = match name {
        "default" | "columns" => PortableLayoutPreset::Columns,
        "build" => PortableLayoutPreset::Build,
        "agents" => PortableLayoutPreset::Agents,
        "review" => PortableLayoutPreset::Review,
        _ => {
            return Err(invalid(
                "layout.preset expects default, columns, build, agents or review",
            ));
        }
    };
    Ok(Layout {
        preset: name.into(),
        tree: portable_layout_preset(preset),
    })
}
fn reset_key(profile: &mut Profile, key: &str) -> Result<(), Error> {
    let defaults = Profile::default();
    match key {
        "name" => profile.name = defaults.name,
        "theme" => profile.theme = defaults.theme,
        "density" => profile.density = defaults.density,
        "glyphs" => profile.glyphs = defaults.glyphs,
        "color_mode" => profile.color_mode = defaults.color_mode,
        "reduced_motion" => profile.reduced_motion = defaults.reduced_motion,
        "browser.font_family" => profile.browser.font_family = defaults.browser.font_family,
        "browser.font_size_px" => profile.browser.font_size_px = defaults.browser.font_size_px,
        "browser" => profile.browser = defaults.browser,
        "token_overrides" | "colors" => profile.token_overrides.clear(),
        "layout" | "layout.preset" | "layout.tree" => profile.layout = defaults.layout,
        "panes" => profile.panes.clear(),
        _ => {
            let canonical = canonical_token(
                token_key(key).ok_or_else(|| invalid("unknown customization key"))?,
            )
            .ok_or_else(|| invalid("unknown semantic color token"))?;
            profile
                .token_overrides
                .retain(|key, _| canonical_token(key) != Some(canonical));
        }
    }
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf, Error> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(customization::io_error)?
            .join(path)
    };
    if path
        .components()
        .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid("path contains non-normal components"));
    }
    Ok(path)
}
fn checked_file(
    host: &LocalProfileHost,
    input: &str,
) -> Result<(Directory, String, PathBuf), Error> {
    if input.is_empty() || input.len() > 256 || input.chars().any(char::is_control) {
        return Err(invalid("file path must contain 1..256 printable bytes"));
    }
    let path = Path::new(input);
    let target = absolute_path(&if path.is_absolute() {
        path.into()
    } else {
        host.workspace.join(path)
    })?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("file name is invalid"))?
        .to_string();
    let parent = target
        .parent()
        .ok_or_else(|| invalid("file parent is missing"))?;
    let directory = Directory::open(parent, false)?;
    Ok((directory, name, target))
}
fn read_profile(host: &LocalProfileHost, input: &str) -> Result<Profile, Error> {
    let (directory, name, _) = checked_file(host, input)?;
    let bytes = customization::read_regular(&directory.io()?.join(name), MAX_PROFILE_BYTES, false)?;
    directory.check()?;
    let profile = customization::validate(&bytes)?;
    let supplied: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid("profile JSON is invalid"))?;
    let normalized =
        serde_json::to_value(&profile).map_err(|_| invalid("profile cannot be encoded"))?;
    strict_keys(&supplied, &normalized)?;
    Ok(profile)
}
fn strict_keys(input: &serde_json::Value, normalized: &serde_json::Value) -> Result<(), Error> {
    match (input, normalized) {
        (serde_json::Value::Object(got), serde_json::Value::Object(expected)) => {
            for (key, value) in got {
                strict_keys(
                    value,
                    expected
                        .get(key)
                        .ok_or_else(|| invalid("profile contains an unsupported field"))?,
                )?;
            }
        }
        (serde_json::Value::Array(got), serde_json::Value::Array(expected)) => {
            if got.len() != expected.len() {
                return Err(invalid("profile normalization changed an array"));
            }
            for (a, b) in got.iter().zip(expected) {
                strict_keys(a, b)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn portable_strings(profile: &Profile, home: &Path, workspace: &Path) -> Result<(), Error> {
    let value = serde_json::to_value(profile).map_err(|_| invalid("profile cannot be encoded"))?;
    fn walk(value: &serde_json::Value, private: &[String]) -> Result<(), Error> {
        match value {
            serde_json::Value::String(text) => {
                if private
                    .iter()
                    .any(|path| path.len() > 1 && text.contains(path))
                    || contains_absolute_path(text)
                {
                    return Err(invalid(
                        "portable export contains an absolute or local private path",
                    ));
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    walk(value, private)?;
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values() {
                    walk(value, private)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(
        &value,
        &[
            absolute_path(home)?.to_string_lossy().into_owned(),
            absolute_path(workspace)?.to_string_lossy().into_owned(),
        ],
    )
}

fn path_field_before(text: &str, index: usize) -> bool {
    let prefix = text[..index]
        .trim_end_matches(['"', '\''])
        .trim_end()
        .trim_end_matches(['=', ':'])
        .trim_end()
        .trim_end_matches(['"', '\''])
        .trim_end();
    let key_start = prefix
        .char_indices()
        .rev()
        .find_map(|(offset, character)| {
            (character.is_whitespace()
                || matches!(
                    character,
                    '=' | ':'
                        | ','
                        | '"'
                        | '\''
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '`'
                        | '<'
                        | '>'
                ))
            .then_some(offset + character.len_utf8())
        })
        .unwrap_or(0);
    let key = prefix[key_start..]
        .trim_matches(['"', '\'', ' '])
        .to_ascii_lowercase();
    [
        "path",
        "file",
        "directory",
        "dir",
        "folder",
        "root",
        "location",
    ]
    .iter()
    .any(|field| key == *field || key.ends_with(&format!("_{field}")))
}

fn web_url_ranges(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii() {
            index += 1;
            continue;
        }
        let scheme_len = if bytes
            .get(index..index + 8)
            .is_some_and(|value| value.eq_ignore_ascii_case(b"https://"))
        {
            8
        } else if bytes
            .get(index..index + 7)
            .is_some_and(|value| value.eq_ignore_ascii_case(b"http://"))
        {
            7
        } else {
            index += 1;
            continue;
        };
        let boundary = text[..index].chars().next_back().is_none_or(|previous| {
            previous.is_whitespace()
                || matches!(
                    previous,
                    '=' | ':' | '"' | '\'' | '(' | '[' | '{' | '`' | '<'
                )
        });
        if !boundary {
            index += scheme_len;
            continue;
        }
        let mut end = index + scheme_len;
        while end < bytes.len()
            && !bytes[end].is_ascii_whitespace()
            && !matches!(bytes[end], b'"' | b'\'' | b'<' | b'>')
        {
            end += 1;
        }
        ranges.push((index, end));
        index = end;
    }
    ranges
}

fn contains_absolute_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    let is_boundary = |index: usize| {
        text[..index].chars().next_back().is_none_or(|previous| {
            previous.is_whitespace()
                || matches!(
                    previous,
                    '=' | ':' | ',' | '"' | '\'' | '(' | '[' | '{' | '\\' | '`' | '<'
                )
        })
    };

    for index in 0..bytes.len() {
        if !bytes[index].is_ascii() {
            continue;
        }
        let is_backslash = bytes[index] == b'\\';
        let drive_rooted = bytes[index].is_ascii_alphabetic()
            && bytes.get(index + 1) == Some(&b':')
            && bytes
                .get(index + 2)
                .is_some_and(|separator| matches!(*separator, b'/' | b'\\'));
        if !is_backslash && !drive_rooted {
            continue;
        }
        let unc_rooted = is_backslash && bytes.get(index + 1) == Some(&b'\\');
        let single_rooted = is_backslash && !unc_rooted;
        let comma_rooted = text[..index].ends_with(',');
        if !is_boundary(index) {
            continue;
        }
        if drive_rooted || unc_rooted {
            return true;
        }
        let path_shape = bytes[index + 1..]
            .iter()
            .take_while(|byte| {
                !byte.is_ascii_whitespace()
                    && !matches!(**byte, b'"' | b'\'' | b')' | b']' | b'}' | b',')
            })
            .any(|byte| matches!(*byte, b'/' | b'\\'));
        // Non-ASCII bytes were skipped above, so each candidate index is a
        // UTF-8 boundary even when the profile contains non-ASCII characters.
        if single_rooted && (comma_rooted || path_field_before(text, index) || path_shape) {
            return true;
        }
    }

    let url_ranges = web_url_ranges(text);
    let mut url_index = 0;
    for (index, character) in text.char_indices() {
        while url_ranges
            .get(url_index)
            .is_some_and(|(_, end)| *end <= index)
        {
            url_index += 1;
        }
        if url_ranges
            .get(url_index)
            .is_some_and(|(start, end)| *start <= index && index < *end)
        {
            continue;
        }
        if character != '/' {
            continue;
        }
        if !is_boundary(index) {
            continue;
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture {
        dir: PathBuf,
        host: LocalProfileHost,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "orbit-profile-command-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir(&dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let home = dir.join("home");
            Self {
                host: LocalProfileHost {
                    home,
                    workspace: dir.clone(),
                    scope: Default::default(),
                },
                dir,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    fn set(host: &LocalProfileHost, key: &str, value: &str) -> Result<ProfileCommandResult, Error> {
        execute(
            host,
            ProfileCommand::Set {
                key: key.into(),
                value: value.into(),
            },
        )
    }
    fn private_write(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn text_profile(f: &Fixture, text: &str) {
        let mut profile = f.host.load().unwrap();
        profile.profile.panes = vec![orbit_frontend_protocol::customization::PaneDef {
            id: "notes".into(),
            title: "Notes".into(),
            surfaces: vec![orbit_frontend_protocol::customization::Surface::Browser],
            source: orbit_frontend_protocol::customization::PaneSource::Text { text: text.into() },
            actions: vec![],
        }];
        f.host.replace(profile.profile, &profile.revision).unwrap();
    }
    #[test]
    fn profile_export_rejects_assignment_absolute_paths_and_preserves_existing_output() {
        let f = Fixture::new();
        for text in [
            "capture_path=/opt/client/private",
            "note,/opt/client/private",
            "capture `/opt/client/private`",
            "capture </opt/client/private>",
            "capture_path=C:\\Users\\alice\\private",
            "note,C:\\Users\\alice\\private",
            r"capture_path=\Users\alice\private",
            r"note,\Users\alice\private",
            r"note,\Users",
            r"note,\secret.txt",
            r"note,\alpha",
            r#"{"capture_path":"\Users"}"#,
            "capture_path=\\\\server\\share\\private",
            "référence C:\\Users\\alice\\private",
        ] {
            text_profile(&f, text);
            let before = std::fs::read(f.host.home.join("customization.json")).unwrap();
            private_write(&f.dir.join("existing.json"), b"preserve existing export");
            for path in ["new.json", "existing.json"] {
                assert!(
                    execute(&f.host, ProfileCommand::Export { path: path.into() }).is_err(),
                    "expected path rejection for {text:?}"
                );
            }
            assert!(!f.dir.join("new.json").exists());
            assert_eq!(
                std::fs::read(f.dir.join("existing.json")).unwrap(),
                b"preserve existing export"
            );
            assert_eq!(
                std::fs::read(f.host.home.join("customization.json")).unwrap(),
                before
            );
            std::fs::remove_file(f.dir.join("existing.json")).unwrap();
        }
    }
    #[test]
    fn profile_export_rejects_quoted_json_absolute_paths_but_keeps_web_urls_portable() {
        let f = Fixture::new();
        text_profile(&f, r#"{"capture_path":"/opt/client/private"}"#);
        let before = std::fs::read(f.host.home.join("customization.json")).unwrap();
        assert!(
            execute(
                &f.host,
                ProfileCommand::Export {
                    path: "quoted.json".into()
                }
            )
            .is_err()
        );
        assert!(!f.dir.join("quoted.json").exists());
        assert_eq!(
            std::fs::read(f.host.home.join("customization.json")).unwrap(),
            before
        );
        text_profile(&f, "HTTPS://example.invalid/public/path");
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "public.json".into(),
            },
        )
        .unwrap();
        assert!(
            std::fs::read_to_string(f.dir.join("public.json"))
                .unwrap()
                .contains("HTTPS://example.invalid/public/path")
        );

        let query_url = "https://example.invalid/?next=/docs";
        text_profile(&f, query_url);
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "query-url.json".into(),
            },
        )
        .unwrap();
        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.dir.join("query-url.json")).unwrap()).unwrap();
        assert_eq!(exported["panes"][0]["source"]["text"], query_url);

        let relative_path = r"reports\latest\brief.txt";
        text_profile(&f, relative_path);
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "relative-windows.json".into(),
            },
        )
        .unwrap();
        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.dir.join("relative-windows.json")).unwrap())
                .unwrap();
        assert_eq!(exported["panes"][0]["source"]["text"], relative_path);

        let tex = r"Use \alpha in math";
        text_profile(&f, tex);
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "tex-command.json".into(),
            },
        )
        .unwrap();
        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.dir.join("tex-command.json")).unwrap())
                .unwrap();
        assert_eq!(exported["panes"][0]["source"]["text"], tex);

        let formula = r"formula=\alpha";
        text_profile(&f, formula);
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "formula.json".into(),
            },
        )
        .unwrap();
        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.dir.join("formula.json")).unwrap()).unwrap();
        assert_eq!(exported["panes"][0]["source"]["text"], formula);

        let repeated_tex = r"(\a)".repeat(4096);
        text_profile(&f, &repeated_tex);
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "repeated-tex.json".into(),
            },
        )
        .unwrap();
        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.dir.join("repeated-tex.json")).unwrap())
                .unwrap();
        assert_eq!(exported["panes"][0]["source"]["text"], repeated_tex);

        let repeated_quoted_tex = r#"\a""#.repeat(4096);
        text_profile(&f, &repeated_quoted_tex);
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "repeated-quoted-tex.json".into(),
            },
        )
        .unwrap();
        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.dir.join("repeated-quoted-tex.json")).unwrap())
                .unwrap();
        assert_eq!(exported["panes"][0]["source"]["text"], repeated_quoted_tex);
    }
    #[test]
    fn checked_profile_command_rejects_stale_browser_revision_before_publication() {
        let f = Fixture::new();
        set(&f.host, "theme", "paper").unwrap();
        let stale = f.host.load().unwrap().revision;
        set(&f.host, "density", "compact").unwrap();
        let path = f.host.home.join("customization.json");
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            execute_checked(
                &f.host,
                ProfileCommand::Theme {
                    name: "midnight".into()
                },
                &stale
            ),
            Err(Error::Busy)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let current = f.host.load().unwrap().revision;
        let reply = execute_checked(
            &f.host,
            ProfileCommand::Theme {
                name: "midnight".into(),
            },
            &current,
        )
        .unwrap();
        let profile = reply.profile.unwrap().profile;
        assert_eq!(profile.theme, "midnight");
        assert_eq!(
            profile.density,
            orbit_frontend_protocol::customization::Density::Compact
        );
    }
    #[test]
    fn profile_commands_set_reload_and_reset_preserve_unrelated_values() {
        let f = Fixture::new();
        set(&f.host, "theme", "paper").unwrap();
        set(&f.host, "browser.font_size_px", "18").unwrap();
        let before = f.host.load().unwrap();
        assert_eq!(before.profile.theme, "paper");
        assert_eq!(before.profile.browser.font_size_px, 18.0);
        execute(
            &f.host,
            ProfileCommand::Reset {
                key: Some("theme".into()),
            },
        )
        .unwrap();
        let after = f.host.load().unwrap();
        assert_eq!(after.profile.theme, "orbit");
        assert_eq!(after.profile.browser.font_size_px, 18.0);
        assert!(
            execute(&f.host, ProfileCommand::Reload)
                .unwrap()
                .profile
                .is_some()
        );
    }
    #[test]
    fn profile_commands_invalid_changes_preserve_exact_existing_bytes() {
        let f = Fixture::new();
        set(&f.host, "theme", "midnight").unwrap();
        let path = f.host.home.join("customization.json");
        let before = std::fs::read(&path).unwrap();
        for (key, value) in [
            ("unknown", "x"),
            ("browser.font_size_px", "25"),
            ("theme", "unknown"),
            ("token_overrides.ink", "red"),
            ("browser.font_family", "url(http://invalid)"),
        ] {
            assert!(set(&f.host, key, value).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
    #[test]
    fn profile_commands_portable_export_roundtrips_without_overwriting() {
        let f = Fixture::new();
        set(&f.host, "theme", "paper").unwrap();
        execute(
            &f.host,
            ProfileCommand::Export {
                path: "export.json".into(),
            },
        )
        .unwrap();
        let bytes = std::fs::read(f.dir.join("export.json")).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(f.dir.to_string_lossy().as_ref()));
        execute(
            &f.host,
            ProfileCommand::Validate {
                path: "export.json".into(),
            },
        )
        .unwrap();
        execute(&f.host, ProfileCommand::Reset { key: None }).unwrap();
        execute(
            &f.host,
            ProfileCommand::Import {
                path: "export.json".into(),
            },
        )
        .unwrap();
        assert_eq!(f.host.load().unwrap().profile.theme, "paper");
        assert!(
            execute(
                &f.host,
                ProfileCommand::Export {
                    path: "export.json".into()
                }
            )
            .is_err()
        );
        assert_eq!(std::fs::read(f.dir.join("export.json")).unwrap(), bytes);
    }
    #[test]
    fn profile_commands_import_rejects_unknown_unit_action_fields() {
        let f = Fixture::new();
        let text=br#"{"panes":[{"id":"notes","title":"Notes","surfaces":["terminal"],"source":{"kind":"text","text":"safe"},"actions":[{"kind":"refresh","unexpected":"refuse"}]}]}"#;
        private_write(&f.dir.join("bad.json"), text);
        assert!(
            execute(
                &f.host,
                ProfileCommand::Import {
                    path: "bad.json".into()
                }
            )
            .is_err()
        );
        assert!(!f.host.home.exists());
        assert!(set(&f.host,"panes",r#"[{"id":"notes","title":"Notes","surfaces":["terminal"],"source":{"kind":"text","text":"safe"},"actions":[{"kind":"refresh","unexpected":"refuse"}]}]"#).is_err());
        assert!(!f.host.home.exists());
    }
    #[cfg(unix)]
    #[test]
    fn profile_commands_input_symlink_refuses_and_preserves_destination() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        private_write(&f.dir.join("real.json"), b"{}");
        symlink(f.dir.join("real.json"), f.dir.join("link.json")).unwrap();
        assert!(
            execute(
                &f.host,
                ProfileCommand::Import {
                    path: "link.json".into()
                }
            )
            .is_err()
        );
        assert!(!f.host.home.exists());
    }
    #[test]
    fn profile_commands_color_aliases_update_one_semantic_role() {
        let f = Fixture::new();
        set(&f.host, "colors.accent", "#123456").unwrap();
        set(&f.host, "token_overrides.magenta", "#654321").unwrap();
        let profile = f.host.load().unwrap().profile;
        assert_eq!(profile.token_overrides.len(), 1);
        assert_eq!(profile.token_overrides["magenta"], "#654321");
        execute(
            &f.host,
            ProfileCommand::Reset {
                key: Some("colors.accent".into()),
            },
        )
        .unwrap();
        assert!(f.host.load().unwrap().profile.token_overrides.is_empty());
    }
    #[test]
    fn profile_commands_export_cannot_create_an_active_managed_config() {
        let f = Fixture::new();
        set(&f.host, "theme", "paper").unwrap();
        let path = f.host.home.join("new-export.json");
        assert!(
            execute(
                &f.host,
                ProfileCommand::Export {
                    path: path.to_string_lossy().into_owned()
                }
            )
            .is_err()
        );
        assert!(!path.exists());
    }
    #[test]
    fn profile_commands_layout_presets_retain_exactly_one_conversation() {
        let f = Fixture::new();
        for preset in ["default", "columns", "build", "agents", "review"] {
            let profile = set(&f.host, "layout.preset", preset)
                .unwrap()
                .profile
                .unwrap()
                .profile;
            profile.validate().unwrap();
            assert_eq!(profile.layout.preset, preset);
        }
    }

    #[test]
    fn profile_preset_aliases_reopen_exact_portable_trees_through_the_checked_host() {
        use orbit_frontend_protocol::customization::{
            PortableLayoutPreset, portable_layout_preset,
        };
        let f = Fixture::new();
        set(&f.host, "theme", "paper").unwrap();
        for (name, preset) in [
            ("default", PortableLayoutPreset::Columns),
            ("columns", PortableLayoutPreset::Columns),
            ("build", PortableLayoutPreset::Build),
            ("agents", PortableLayoutPreset::Agents),
            ("review", PortableLayoutPreset::Review),
        ] {
            let before = f.host.load().unwrap();
            execute_checked(
                &f.host,
                ProfileCommand::Set {
                    key: "layout.preset".into(),
                    value: name.into(),
                },
                &before.revision,
            )
            .unwrap();
            let fresh = LocalProfileHost {
                home: f.host.home.clone(),
                workspace: f.host.workspace.clone(),
                scope: f.host.scope.clone(),
            };
            let reopened = fresh.load().unwrap();
            reopened.profile.validate().unwrap();
            assert_eq!(reopened.profile.layout.preset, name);
            assert_eq!(reopened.profile.layout.tree, portable_layout_preset(preset));
            assert_eq!(reopened.profile.theme, "paper");
        }
    }
}

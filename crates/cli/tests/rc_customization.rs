#![cfg(target_os = "linux")]
pub use orbit_cli::profile_commands;
#[path = "../src/customization.rs"]
#[allow(dead_code)]
mod customization;
use customization::*;
pub use orbit_cli::tool_runtime;
use orbit_frontend_protocol::customization::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use tool_runtime::PermissionScope;
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-profile-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.join("home");
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        Self {
            root,
            home,
            workspace,
        }
    }
    fn save(&self, p: &Profile) -> ResolvedProfile {
        replace(&self.home, &self.workspace, p).unwrap()
    }
    fn pane(&self, source: PaneSource) -> Profile {
        let mut p = Profile::default();
        p.panes.push(PaneDef {
            id: "notes".into(),
            title: "Notes".into(),
            surfaces: vec![Surface::Terminal, Surface::Browser],
            source,
            actions: vec![PaneAction::Refresh, PaneAction::OwnerCancel],
        });
        p
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn assert_actual_ask_rule(f: &Fixture, path: &str) {
    let rules = orbit_tools::executor::load_sourced_rules_in(&f.home, &f.workspace).unwrap();
    let rules = orbit_tools::permissions::RuleSet {
        rules: rules
            .into_iter()
            .filter(|rule| !rule.shadowed)
            .map(|rule| rule.rule)
            .collect(),
    };
    assert_eq!(
        rules.evaluate("Read", path),
        Some(orbit_tools::permissions::RuleEffect::Ask)
    );
}
fn invalid_unchanged(mutator: impl FnOnce(&mut Profile)) {
    let f = Fixture::new();
    f.save(&Profile::default());
    let before = std::fs::read(f.home.join("customization.json")).unwrap();
    let mut p = Profile::default();
    mutator(&mut p);
    assert!(replace(&f.home, &f.workspace, &p).is_err());
    assert_eq!(
        std::fs::read(f.home.join("customization.json")).unwrap(),
        before
    );
}
#[test]
fn profile_roundtrip_default_reopen_export() {
    let f = Fixture::new();
    let p = Profile::default();
    let saved = f.save(&p);
    assert_eq!(load(&f.home, &f.workspace).unwrap(), saved);
    assert_eq!(validate(&export(&p).unwrap()).unwrap(), p);
    assert_eq!(
        std::fs::metadata(f.home.join("customization.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&f.home).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
#[test]
fn profile_roundtrip_absent_is_read_only() {
    let f = Fixture::new();
    let r = load(&f.home, &f.workspace).unwrap();
    assert!(!f.home.exists());
    assert_eq!(r.profile, Profile::default());
    assert!(r.sources.values().all(|s| *s == EffectiveSource::Default));
}
#[test]
fn profile_roundtrip_legacy_merge_preserves_bytes() {
    let f = Fixture::new();
    std::fs::create_dir(&f.home).unwrap();
    std::fs::set_permissions(&f.home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bytes=b"[colors]\naccent='#112233'\n[color]\nglyphs='ascii'\nreduced=true\n[unrelated]\nkeep='original'\n";
    std::fs::write(f.home.join("tui.toml"), bytes).unwrap();
    let r = load(&f.home, &f.workspace).unwrap();
    assert_eq!(r.profile.glyphs, Glyphs::Ascii);
    assert_eq!(r.profile.resolved_tokens()["magenta"], "#112233");
    assert_eq!(r.sources["glyphs"], EffectiveSource::Legacy);
    f.save(&r.profile);
    reset(&f.home, &f.workspace).unwrap();
    assert_eq!(std::fs::read(f.home.join("tui.toml")).unwrap(), bytes);
}
#[test]
fn profile_roundtrip_invalid_version_before_home() {
    let f = Fixture::new();
    let p = Profile {
        schema_version: 2,
        ..Default::default()
    };
    assert!(replace(&f.home, &f.workspace, &p).is_err());
    assert!(!f.home.exists());
}
#[test]
fn profile_roundtrip_alias_canonical_wins() {
    let f = Fixture::new();
    let mut p = Profile::default();
    p.token_overrides.insert("accent".into(), "#112233".into());
    p.token_overrides.insert("magenta".into(), "#445566".into());
    assert_eq!(f.save(&p).profile.resolved_tokens()["magenta"], "#445566");
}
#[test]
fn profile_roundtrip_custom_identity_and_actions() {
    let f = Fixture::new();
    let mut p = f.pane(PaneSource::Text {
        text: "hello".into(),
    });
    p.layout.tree = LayoutNode::Split {
        direction: Direction::Right,
        shares: vec![60, 40],
        children: vec![
            LayoutNode::panel(View::Conversation),
            LayoutNode::Custom {
                pane_id: "notes".into(),
            },
        ],
    };
    let r = f.save(&p);
    assert_eq!(load(&f.home, &f.workspace).unwrap().profile, p);
    assert_eq!(r.sources["panes"], EffectiveSource::Profile);
}
#[test]
fn unknown_token_refuses_without_mutation() {
    invalid_unchanged(|p| {
        p.token_overrides.insert("css".into(), "#112233".into());
    });
}
#[test]
fn malformed_color_refuses_without_mutation() {
    invalid_unchanged(|p| {
        p.token_overrides.insert("bg".into(), "url(remote)".into());
    });
}
#[test]
fn css_font_refuses_without_mutation() {
    invalid_unchanged(|p| p.browser.font_family = "mono; background:url(remote)".into());
}
#[test]
fn oversized_font_refuses_without_mutation() {
    invalid_unchanged(|p| p.browser.font_size_px = 25.0);
}
#[test]
fn missing_conversation_refuses_without_mutation() {
    invalid_unchanged(|p| p.layout.tree = LayoutNode::panel(View::Changes));
}
#[test]
fn duplicate_conversation_refuses_without_mutation() {
    invalid_unchanged(|p| {
        p.layout.tree = LayoutNode::Split {
            direction: Direction::Right,
            shares: vec![1, 1],
            children: vec![LayoutNode::panel(View::Conversation); 2],
        }
    });
}
#[test]
fn invalid_geometry_refuses_without_mutation() {
    invalid_unchanged(|p| {
        p.layout.tree = LayoutNode::Split {
            direction: Direction::Right,
            shares: vec![0],
            children: vec![LayoutNode::panel(View::Conversation)],
        }
    });
}
#[test]
fn unresolved_custom_reference_refuses_without_mutation() {
    invalid_unchanged(|p| {
        p.layout.tree = LayoutNode::Custom {
            pane_id: "ghost".into(),
        }
    });
}
#[test]
fn strict_unknown_and_duplicate_json() {
    assert!(validate(br#"{"unknown":true}"#).is_err());
    assert!(validate(br#"{"name":"a","name":"b"}"#).is_err());
    assert!(validate(br##"{"token_overrides":{"bg":"#112233","bg":"#445566"}}"##).is_err());
    assert!(validate(&vec![b' '; MAX_PROFILE_BYTES + 1]).is_err());
}
#[test]
fn stale_revision_does_not_lose_edit() {
    let f = Fixture::new();
    let first = f.save(&Profile::default());
    let p = Profile {
        theme: "paper".into(),
        ..Default::default()
    };
    let second = replace_checked(&f.home, &f.workspace, &p, &first.revision).unwrap();
    assert_eq!(
        replace_checked(&f.home, &f.workspace, &Profile::default(), &first.revision),
        Err(Error::Busy)
    );
    assert_eq!(load(&f.home, &f.workspace).unwrap(), second);
}
#[test]
fn held_lock_refuses_second_writer() {
    let f = Fixture::new();
    f.save(&Profile::default());
    let d = Directory::open(&f.home, true).unwrap();
    let _lock = Lock::acquire(&d, ".customization.lock").unwrap();
    assert_eq!(
        replace(&f.home, &f.workspace, &Profile::default()),
        Err(Error::Busy)
    );
}
#[test]
fn symlink_profile_refuses_without_reading_target() {
    let f = Fixture::new();
    f.save(&Profile::default());
    std::fs::remove_file(f.home.join("customization.json")).unwrap();
    std::fs::write(f.root.join("outside"), b"outside secret").unwrap();
    symlink(f.root.join("outside"), f.home.join("customization.json")).unwrap();
    assert!(matches!(
        load(&f.home, &f.workspace),
        Err(Error::UnsafePath(_))
    ));
    assert_eq!(
        std::fs::read(f.root.join("outside")).unwrap(),
        b"outside secret"
    );
}
#[test]
fn hardlink_profile_refuses() {
    let f = Fixture::new();
    f.save(&Profile::default());
    std::fs::hard_link(f.home.join("customization.json"), f.root.join("alias")).unwrap();
    assert!(matches!(
        load(&f.home, &f.workspace),
        Err(Error::UnsafePath(_))
    ));
}
#[test]
fn malformed_legacy_is_visible_and_never_rewritten() {
    let f = Fixture::new();
    f.save(&Profile::default());
    std::fs::write(f.home.join("tui.toml"), b"[malformed").unwrap();
    assert!(matches!(
        load(&f.home, &f.workspace),
        Err(Error::Invalid(_))
    ));
    assert!(reset(&f.home, &f.workspace).is_err());
    assert_eq!(
        std::fs::read(f.home.join("tui.toml")).unwrap(),
        b"[malformed"
    );
    assert_eq!(
        safe_session_defaults().sources["theme"],
        EffectiveSource::Session
    );
}
#[test]
fn pane_markdown_scanned_inert_and_controller_filtered() {
    let f = Fixture::new();
    let p = f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    });
    f.save(&p);
    std::fs::write(
        f.workspace.join("notes.md"),
        "<script>inert</script>\x1b[31m\nAPI_KEY=abcdefghijklmnopqrstuvwxyz1234567890\n",
    )
    .unwrap();
    let out = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert!(!out.text.contains('\x1b'));
    assert!(!out.text.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
    assert!(!out.actions.contains(&PaneAction::OwnerCancel));
    assert_eq!(out.state, PaneState::Ready);
}
#[test]
fn pane_inherited_read_denial() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.workspace.join("notes.md"), b"secret").unwrap();
    let scope = PermissionScope::from_flags(None, None, Some("Read"));
    assert!(
        read_pane_scoped(
            &f.home,
            &f.workspace,
            "notes",
            &PaneContext::default(),
            &scope
        )
        .is_err()
    );
}
#[test]
fn pane_saved_path_rule_denial() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.workspace.join("notes.md"), b"secret").unwrap();
    std::fs::write(f.home.join("permissions.toml"), "[deny]\ntools=['Read']\n").unwrap();
    assert!(read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).is_err());
}
#[test]
fn pane_symlink_and_fifo_refuse_before_content() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.root.join("outside"), b"secret").unwrap();
    symlink(f.root.join("outside"), f.workspace.join("notes.md")).unwrap();
    assert!(read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).is_err());
    std::fs::remove_file(f.workspace.join("notes.md")).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(f.workspace.join("notes.md").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).is_err());
}
#[test]
fn pane_missing_and_bounded_real_counts() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::Snapshot {
        snapshot: SnapshotKind::Evidence,
    }));
    let missing = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert_eq!(missing.state, PaneState::Missing);
    std::fs::create_dir(f.workspace.join("evidence")).unwrap();
    for i in 0..3 {
        std::fs::write(f.workspace.join(format!("evidence/{i}.txt")), b"proof").unwrap();
    }
    let out = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert!(out.text.contains("Files: 3"));
    assert!(out.text.contains("not verified proof"));
}
#[test]
fn pane_line_bound_and_safe_context() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::Text {
        text: "line\n".repeat(600),
    }));
    let out = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert!(out.truncated);
    assert_eq!(out.text.lines().count(), 512);
    assert!(out.text.len() <= MAX_PANE_OUTPUT_BYTES);
}
#[test]
fn staged_parent_replacement_preserves_original() {
    let f = Fixture::new();
    f.save(&Profile::default());
    let old = f.home.join("customization.json");
    let before = std::fs::read(&old).unwrap();
    let moved = f.root.join("moved");
    let h = f.home.clone();
    let result = with_test_hook(
        move |point, _| {
            if point == PublicationPoint::Staged {
                std::fs::rename(&h, &moved).unwrap();
                std::fs::create_dir(&h).unwrap();
            }
        },
        || {
            replace(
                &f.home,
                &f.workspace,
                &Profile {
                    theme: "paper".into(),
                    ..Default::default()
                },
            )
        },
    );
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(f.root.join("moved/customization.json")).unwrap(),
        before
    );
    assert!(!f.home.join("customization.json").exists());
}
#[test]
fn published_parent_replacement_reports_uncertainty() {
    let f = Fixture::new();
    f.save(&Profile::default());
    let moved = f.root.join("moved");
    let h = f.home.clone();
    let result = with_test_hook(
        move |point, _| {
            if point == PublicationPoint::Published {
                std::fs::rename(&h, &moved).unwrap();
                std::fs::create_dir(&h).unwrap();
            }
        },
        || {
            replace(
                &f.home,
                &f.workspace,
                &Profile {
                    theme: "paper".into(),
                    ..Default::default()
                },
            )
        },
    );
    assert!(matches!(result, Err(Error::PublicationUncertain(_))));
    let saved = validate(&std::fs::read(f.root.join("moved/customization.json")).unwrap()).unwrap();
    assert_eq!(saved.theme, "paper");
}
#[test]
fn review_regression_relative_read_rule_protects_snapshot_counts() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::Snapshot {
        snapshot: SnapshotKind::Evidence,
    }));
    std::fs::create_dir(f.workspace.join("evidence")).unwrap();
    std::fs::write(f.workspace.join("evidence/private.txt"), b"private proof").unwrap();
    std::fs::write(
        f.home.join("permissions.toml"),
        "[deny]\ntools=['Read(evidence/private.txt)']\n",
    )
    .unwrap();
    assert!(matches!(
        read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()),
        Err(Error::UnsafePath(_))
    ));
    std::fs::remove_file(f.home.join("permissions.toml")).unwrap();
    let out = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert!(out.text.contains("Files: 1"));
}
#[test]
fn review_regression_prefixed_assignment_text_is_scanned_with_context() {
    let f = Fixture::new();
    let secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    f.save(&f.pane(PaneSource::Text {
        text: format!("status=ok API_KEY={secret} tail=kept"),
    }));
    let out = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert!(!out.text.contains(secret));
    assert!(out.text.contains("status=ok"));
    assert!(out.text.contains("tail=kept"));
}
#[test]
fn review_regression_prefixed_assignment_markdown_is_scanned_with_context() {
    let f = Fixture::new();
    let secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(
        f.workspace.join("notes.md"),
        format!("status=ok API_KEY={secret}\n"),
    )
    .unwrap();
    let out = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert!(!out.text.contains(secret));
    assert!(out.text.contains("status=ok"));
    assert!(out.text.contains("redacted"));
}
#[test]
fn review_regression_export_refuses_text_secret_without_changing_saved_profile() {
    let f = Fixture::new();
    let secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    let p = f.pane(PaneSource::Text {
        text: format!("status=ok API_KEY={secret}"),
    });
    f.save(&p);
    let before = std::fs::read(f.home.join("customization.json")).unwrap();
    let error = export(&p).unwrap_err();
    assert!(matches!(error, Error::Invalid(_)));
    assert!(error.to_string().contains("panes[0].source.text"));
    assert!(!error.to_string().contains(secret));
    assert_eq!(
        std::fs::read(f.home.join("customization.json")).unwrap(),
        before
    );
}
#[test]
fn review_regression_export_refuses_prompt_secret_without_partial_export() {
    let f = Fixture::new();
    let secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    let mut p = f.pane(PaneSource::Text {
        text: "ordinary data".into(),
    });
    p.panes[0].actions.push(PaneAction::InsertPrompt {
        text: format!("status=ok API_KEY={secret}"),
    });
    f.save(&p);
    let error = export(&p).unwrap_err();
    assert!(error.to_string().contains("actions[2].text"));
    assert!(!error.to_string().contains(secret));
    assert!(f.home.join("customization.json").is_file());
}

#[test]
fn review_regression_markdown_read_ask_requires_approval_and_preserves_scanning() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    let secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    let bytes = format!("LOCAL PRIVATE NOTE status=ok API_KEY={secret}\n");
    std::fs::write(f.workspace.join("notes.md"), &bytes).unwrap();
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\nask=['Read(notes.md)']\n",
    )
    .unwrap();
    assert_actual_ask_rule(&f, "notes.md");
    let result = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default());
    let error = result.unwrap_err();
    assert!(matches!(error, Error::UnsafePath(_)));
    assert!(error.to_string().contains("approval"));
    assert!(!error.to_string().contains("LOCAL PRIVATE NOTE"));
    assert!(!error.to_string().contains(secret));
    assert_eq!(
        std::fs::read_to_string(f.workspace.join("notes.md")).unwrap(),
        bytes
    );
    std::fs::remove_file(f.home.join("settings.toml")).unwrap();
    let output = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap();
    assert!(output.text.contains("LOCAL PRIVATE NOTE"));
    assert!(!output.text.contains(secret));
    assert!(output.text.contains("redacted"));
}

#[test]
fn review_regression_scope_snapshot_read_ask_does_not_read_scope_file() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::Snapshot {
        snapshot: SnapshotKind::Scope,
    }));
    std::fs::write(f.workspace.join("scope.toml"), "name='PRIVATE SCOPE'\n").unwrap();
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\nask=['Read(scope.toml)']\n",
    )
    .unwrap();
    assert_actual_ask_rule(&f, "scope.toml");
    let error = read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()).unwrap_err();
    assert!(error.to_string().contains("approval"));
    assert!(!error.to_string().contains("PRIVATE SCOPE"));
    std::fs::remove_file(f.home.join("settings.toml")).unwrap();
    assert!(
        read_pane(&f.home, &f.workspace, "notes", &PaneContext::default())
            .unwrap()
            .text
            .contains("PRIVATE SCOPE")
    );
}

#[test]
fn review_regression_dontask_pane_without_allow_rule_refuses_read() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.workspace.join("notes.md"), b"PRIVATE DEFAULT-DENIED NOTE").unwrap();
    let scope = PermissionScope::from_flags(Some("dontAsk"), None, None);
    let error = read_pane_scoped(
        &f.home,
        &f.workspace,
        "notes",
        &PaneContext::default(),
        &scope,
    )
    .unwrap_err();
    assert!(error.to_string().contains("allow rule"));
    assert!(!error.to_string().contains("PRIVATE DEFAULT-DENIED NOTE"));
}

#[test]
fn review_regression_dontask_inherited_bare_read_allows_and_keeps_denials() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.workspace.join("notes.md"), b"INHERITED BARE READ NOTE").unwrap();
    let mut scope = PermissionScope::from_flags(Some("dontAsk"), Some("Read"), None);
    assert!(
        read_pane_scoped(
            &f.home,
            &f.workspace,
            "notes",
            &PaneContext::default(),
            &scope
        )
        .unwrap()
        .text
        .contains("INHERITED BARE READ NOTE")
    );
    scope.disallowlist.push("Read(notes.md)".into());
    assert!(matches!(
        read_pane_scoped(
            &f.home,
            &f.workspace,
            "notes",
            &PaneContext::default(),
            &scope
        ),
        Err(Error::UnsafePath(_))
    ));
}

#[test]
fn review_regression_dontask_inherited_matching_read_selector_allows_but_ask_wins() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.workspace.join("notes.md"), b"MATCHED INHERITED READ NOTE").unwrap();
    let scope = PermissionScope::from_flags(Some("dontAsk"), Some("Read(notes.md)"), None);
    assert!(
        read_pane_scoped(
            &f.home,
            &f.workspace,
            "notes",
            &PaneContext::default(),
            &scope
        )
        .unwrap()
        .text
        .contains("MATCHED INHERITED READ NOTE")
    );
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\nask=['Read(notes.md)']\n",
    )
    .unwrap();
    assert_actual_ask_rule(&f, "notes.md");
    let error = read_pane_scoped(
        &f.home,
        &f.workspace,
        "notes",
        &PaneContext::default(),
        &scope,
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsafePath(_)));
    assert!(error.to_string().contains("approval"));
}

#[test]
fn review_regression_inherited_unmatched_read_selector_is_a_ceiling() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(
        f.workspace.join("notes.md"),
        b"OUTSIDE INHERITED READ SCOPE",
    )
    .unwrap();
    std::fs::write(f.home.join("permissions.toml"), "[allow]\ntools=['Read']\n").unwrap();
    for mode in ["default", "dontAsk", "bypass"] {
        let scope = PermissionScope::from_flags(Some(mode), Some("Read(other.md)"), None);
        let error = read_pane_scoped(
            &f.home,
            &f.workspace,
            "notes",
            &PaneContext::default(),
            &scope,
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsafePath(_)));
        assert!(error.to_string().contains("allowlist"));
        assert!(!error.to_string().contains("OUTSIDE INHERITED READ SCOPE"));
    }
}

#[test]
fn review_regression_dontask_pane_allow_rule_permits_read_but_cannot_override_ask() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.workspace.join("notes.md"), b"EXPLICITLY PERMITTED NOTE").unwrap();
    let scope = PermissionScope::from_flags(Some("dontAsk"), None, None);
    std::fs::write(
        f.home.join("permissions.toml"),
        "[allow]\ntools=['Read(notes.md)']\n",
    )
    .unwrap();
    assert!(
        read_pane_scoped(
            &f.home,
            &f.workspace,
            "notes",
            &PaneContext::default(),
            &scope
        )
        .unwrap()
        .text
        .contains("EXPLICITLY PERMITTED NOTE")
    );
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\nallow=['Read']\nask=['Read(notes.md)']\n",
    )
    .unwrap();
    assert_actual_ask_rule(&f, "notes.md");
    let error = read_pane_scoped(
        &f.home,
        &f.workspace,
        "notes",
        &PaneContext::default(),
        &scope,
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsafePath(_)));
    assert!(error.to_string().contains("approval"));
}

#[test]
fn review_regression_live_pane_mode_overrides_only_mode_and_keeps_inherited_denials() {
    use orbit_tools::permissions::PermissionMode;
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    std::fs::write(f.workspace.join("notes.md"), b"LOCAL LIVE MODE NOTE").unwrap();
    let stored = std::fs::read(f.home.join("customization.json")).unwrap();
    let mut host = LocalProfileHost {
        home: f.home.clone(),
        workspace: f.workspace.clone(),
        scope: PermissionScope::default(),
    };
    let mut context = PaneContext::default();
    assert!(
        host.read_pane("notes", &context)
            .unwrap()
            .text
            .contains("LOCAL LIVE MODE NOTE")
    );
    context.permission_mode = Some("dontAsk".into());
    assert!(host.read_pane("notes", &context).is_err());
    assert_eq!(host.scope.mode, PermissionMode::Default);
    std::fs::write(
        f.home.join("permissions.toml"),
        "[allow]\ntools=['Read(notes.md)']\n",
    )
    .unwrap();
    assert!(
        host.read_pane("notes", &context)
            .unwrap()
            .text
            .contains("LOCAL LIVE MODE NOTE")
    );
    host.scope.disallowlist.push("Read".into());
    context.permission_mode = Some("default".into());
    assert!(host.read_pane("notes", &context).is_err());
    context.permission_mode = Some("unsupported-mode".into());
    assert!(matches!(
        host.read_pane("notes", &context),
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        std::fs::read(f.home.join("customization.json")).unwrap(),
        stored
    );
}

#[test]
fn review_regression_count_snapshot_read_ask_does_not_disclose_file_inventory() {
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::Snapshot {
        snapshot: SnapshotKind::Evidence,
    }));
    std::fs::create_dir(f.workspace.join("evidence")).unwrap();
    std::fs::write(f.workspace.join("evidence/private.txt"), b"private proof").unwrap();
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\nask=['Read(evidence/private.txt)']\n",
    )
    .unwrap();
    assert_actual_ask_rule(&f, "evidence/private.txt");
    assert!(matches!(
        read_pane(&f.home, &f.workspace, "notes", &PaneContext::default()),
        Err(Error::UnsafePath(_))
    ));
    std::fs::remove_file(f.home.join("settings.toml")).unwrap();
    assert!(
        read_pane(&f.home, &f.workspace, "notes", &PaneContext::default())
            .unwrap()
            .text
            .contains("Files: 1")
    );
}

#[test]
fn review_regression_absolute_read_rules_override_inherited_allow_on_every_pane_mode() {
    use orbit_tools::permissions::{RuleEffect, RuleSet};
    let f = Fixture::new();
    f.save(&f.pane(PaneSource::MarkdownFile {
        path: "notes.md".into(),
    }));
    let path = f.workspace.join("notes.md");
    std::fs::write(&path, b"PRIVATE ABSOLUTE RULE NOTE").unwrap();
    let before = std::fs::read(f.home.join("customization.json")).unwrap();
    for (effect, expected) in [("ask", RuleEffect::Ask), ("deny", RuleEffect::Deny)] {
        let rule = format!("Read({})", path.display());
        std::fs::write(
            f.home.join("settings.toml"),
            format!("[permissions]\n{effect}=[{rule:?}]\n"),
        )
        .unwrap();
        let sourced = orbit_tools::executor::load_sourced_rules_in(&f.home, &f.workspace).unwrap();
        let rules = RuleSet {
            rules: sourced
                .into_iter()
                .filter(|rule| !rule.shadowed)
                .map(|rule| rule.rule)
                .collect(),
        };
        assert_eq!(
            rules.evaluate("Read", path.to_str().unwrap()),
            Some(expected)
        );
        for mode in ["default", "dontAsk", "bypass"] {
            let scope = PermissionScope::from_flags(Some(mode), Some("Read"), None);
            let error = read_pane_scoped(
                &f.home,
                &f.workspace,
                "notes",
                &PaneContext::default(),
                &scope,
            )
            .unwrap_err();
            assert!(
                matches!(error, Error::UnsafePath(_)),
                "{effect} {mode}: {error}"
            );
            assert!(!error.to_string().contains("PRIVATE ABSOLUTE RULE NOTE"));
            assert_eq!(std::fs::read(&path).unwrap(), b"PRIVATE ABSOLUTE RULE NOTE");
            assert_eq!(
                std::fs::read(f.home.join("customization.json")).unwrap(),
                before
            );
        }
    }
    std::fs::remove_file(f.home.join("settings.toml")).unwrap();
    let scope = PermissionScope::from_flags(Some("dontAsk"), Some("Read"), None);
    assert!(
        read_pane_scoped(
            &f.home,
            &f.workspace,
            "notes",
            &PaneContext::default(),
            &scope
        )
        .unwrap()
        .text
        .contains("PRIVATE ABSOLUTE RULE NOTE")
    );
}

#[test]
fn builtin_reactor_pane_needs_no_profile_entry_and_never_prints_unreported_as_zero() {
    let f = Fixture::new();
    let saved = f.save(&Profile::default());
    assert!(saved.profile.panes.is_empty());
    let context = PaneContext {
        model: "claude-opus-5-5".into(),
        phase: Some("respond".into()),
        input_tokens: 412_880,
        output_tokens: 18_204,
        used_tokens: Some(412_000),
        window_tokens: Some(1_000_000),
        cost_microcents: 840_000,
        turns: Some(12),
        ..PaneContext::default()
    };
    let text = reactor_snapshot(&context, false);
    assert!(text.starts_with("REACTOR · claude-opus-5-5  RESPOND\n"));
    assert!(text.contains("tok/s   —"));
    assert!(text.contains("18,204"));
    assert!(text.contains("412,880"));
    assert!(text.contains("cache   —\n"));
    let cached = reactor_snapshot(
        &PaneContext {
            cache_read_tokens: Some(1_204_113),
            cache_write_tokens: Some(88_020),
            reasoning_tokens: Some(0),
            ..PaneContext::default()
        },
        false,
    );
    assert!(cached.contains("cache   read 1,204,113  write 88,020  reason 0  (this run)"));
    assert!(text.contains("412k / 1M  41%"));
    assert!(text.contains("$0.8400  turns 12  tools —"));
    let ascii = reactor_snapshot(&PaneContext::default(), true);
    assert!(ascii.is_ascii());
    assert!(ascii.contains("ctx     -"));
    let uncertain = reactor_snapshot(
        &PaneContext {
            cost_uncertain: true,
            ..PaneContext::default()
        },
        true,
    );
    assert!(uncertain.contains("(uncertain)"));
    let metered = reactor_snapshot(
        &PaneContext {
            rate_milli: Some(42_700),
            peak_rate_milli: Some(118_000),
            ..PaneContext::default()
        },
        false,
    );
    assert!(metered.contains("tok/s   42.7"));
    assert!(metered.contains("peak 118.0"));
    assert!(!metered.contains("rate    "));
    let history = PaneContext {
        rate_history: vec![10_000, 50_000, 100_000],
        ..PaneContext::default()
    };
    assert!(reactor_snapshot(&history, false).contains("rate    ▁▄█\n"));
    assert!(reactor_snapshot(&history, true).is_ascii());
    let live = reactor_snapshot(
        &PaneContext {
            rate_milli: Some(42_700),
            live_rate_milli: Some(38_250),
            ..PaneContext::default()
        },
        false,
    );
    assert!(live.contains("≈38.2 live"));
    let out = read_pane(&f.home, &f.workspace, "reactor", &context).unwrap();
    assert_eq!(out.id, "reactor");
    assert_eq!(out.state, PaneState::Ready);
    assert!(out.actions.contains(&PaneAction::Refresh));
    assert!(read_pane(&f.home, &f.workspace, "unknown", &context).is_err());
}

#[test]
fn council_snapshot_reports_missing_error_ready_and_idle_states() {
    let f = Fixture::new();
    let path = f.root.join("state.json");
    let (state, text) = council_snapshot_at(&path, 0.0, false);
    assert_eq!(state, PaneState::Missing);
    assert_eq!(text, "No council has run");

    std::fs::write(&path, b"{not json").unwrap();
    assert_eq!(council_snapshot_at(&path, 0.0, false).0, PaneState::Error);
    std::fs::write(&path, br#"{"ts":1.0,"seats":[]}"#).unwrap();
    assert_eq!(council_snapshot_at(&path, 0.0, false).0, PaneState::Error);
    std::fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
    assert_eq!(council_snapshot_at(&path, 0.0, false).0, PaneState::Error);

    std::fs::write(
        &path,
        br#"{"ts":1000.0,"phase":"DELIBERATING","note":"","seats":[
            {"model":"claude-haiku-5-5","status":"online","verdict":"APPROVE"},
            {"model":"deepseek-v4-pro","status":"computing","verdict":null},
            {"model":"claude-glm-5.3-flash","status":"reported","verdict":"CONDITIONAL"},
            {"model":"minimax-m3","status":"computing","verdict":null},
            {"model":"other\u001b[31m","status":"error","verdict":null}]}"#,
    )
    .unwrap();
    let (state, text) = council_snapshot_at(&path, 1010.0, false);
    assert_eq!(state, PaneState::Ready);
    assert!(text.starts_with("MAGI · 심의 DELIBERATE\n"));
    assert!(text.contains("심의  1/5 응답 · 표 2"));
    assert!(text.contains("● 승인 YES"));
    assert!(text.contains("신호없음"));
    assert!(text.contains("KARINA·01"));
    assert!(text.contains("ANTHROPIC"));
    assert!(text.contains("haiku-5-5"));
    assert!(text.contains("ZHIPU      glm-5.3-flash"));
    assert!(text.contains("AE·05"));
    assert!(!text.contains('\u{1b}'));
    assert_eq!(text.lines().count(), 7);

    let (state, ascii) = council_snapshot_at(&path, 1010.0, true);
    assert_eq!(state, PaneState::Ready);
    assert!(ascii.is_ascii());
    assert!(ascii.contains("KARINA-01"));
    assert!(ascii.contains("* APPROVE"));
    assert!(ascii.contains("* HOLD"));
    assert!(ascii.contains(". deliberating"));

    let (state, idle) = council_snapshot_at(&path, 1421.0, false);
    assert_eq!(state, PaneState::Ready);
    assert!(idle.starts_with("MAGI · 대기 IDLE\n"));
    assert!(!idle.contains("최근"));
    std::fs::write(
        f.root.join("history.jsonl"),
        concat!(
            r#"{"ts":1.0,"final":"FINAL: Older decision","answers":{}}"#,
            "\n",
            r#"{"ts":2.0,"final":"FINAL: Adopt SQLite in WAL mode\nmore detail","answers":{}}"#,
            "\n",
            r#"{"ts":3.0,"final":"","answers":{}}"#,
            "\nnot json\n"
        ),
    )
    .unwrap();
    let (_, idle) = council_snapshot_at(&path, 1421.0, false);
    assert!(idle.ends_with("최근  Adopt SQLite in WAL mode\n"));
    let (_, busy) = council_snapshot_at(&path, 1010.0, false);
    assert!(!busy.contains("최근"));

    std::fs::write(
        &path,
        br#"{"ts":1000.0,"phase":"VERDICT","note":"FINAL: Adopt SQLite in WAL mode","seats":[
            {"model":"claude-haiku-5-5","status":"reported","verdict":"APPROVE"},
            {"model":"deepseek-v4-pro","status":"reported","verdict":"APPROVE"},
            {"model":"glm-5.3-flash","status":"reported","verdict":"REJECT"}]}"#,
    )
    .unwrap();
    let (_, verdict) = council_snapshot_at(&path, 1001.0, false);
    assert!(verdict.contains("다수결  승인 YES · 2/3"));
    assert!(verdict.contains("nævis  Adopt SQLite in WAL mode"));
    assert!(verdict.contains("거부 NO"));
}

#[test]
fn council_snapshot_refuses_a_symlinked_state_file() {
    let f = Fixture::new();
    let real = f.root.join("real.json");
    std::fs::write(&real, br#"{"ts":1.0,"phase":"VERDICT","seats":[]}"#).unwrap();
    let link = f.root.join("state.json");
    symlink(&real, &link).unwrap();
    assert_eq!(council_snapshot_at(&link, 1.0, false).0, PaneState::Error);
    assert_eq!(council_snapshot_at(&real, 1.0, false).0, PaneState::Ready);
}

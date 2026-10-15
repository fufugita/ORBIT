use orbit_frontend_protocol::customization::*;
use orbit_hud_tui::{
    customization::{profile_tree, ActionEffect, CustomizationSession},
    proto::{
        app::App,
        core::Tier,
        layout::{LayoutFile, Node, View},
        scenario::Scenario,
        shell::{self, DrawIn, Fx},
    },
};
use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "orbit-rc-pane-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Host {
    profile: Mutex<ResolvedProfile>,
    text: Mutex<String>,
    reads: AtomicUsize,
    writes: AtomicUsize,
    fail: Mutex<Option<CustomizationError>>,
}
impl Host {
    fn new() -> Arc<Self> {
        let mut profile = Profile::default();
        profile.panes.push(PaneDef {
            id: "notes".into(),
            title: "Engagement notes".into(),
            surfaces: vec![Surface::Terminal],
            source: PaneSource::Text {
                text: "proof".into(),
            },
            actions: vec![
                PaneAction::Refresh,
                PaneAction::InsertPrompt {
                    text: "review this evidence".into(),
                },
                PaneAction::FocusConversation,
                PaneAction::OwnerCancel,
            ],
        });
        profile.layout.tree = LayoutNode::Split {
            direction: Direction::Right,
            shares: vec![1, 1],
            children: vec![
                LayoutNode::panel(orbit_frontend_protocol::customization::View::Conversation),
                LayoutNode::Custom {
                    pane_id: "notes".into(),
                },
            ],
        };
        Arc::new(Self {
            profile: Mutex::new(ResolvedProfile {
                profile,
                sources: BTreeMap::new(),
                revision: "1".into(),
                capabilities: CustomizationCapabilities::default(),
            }),
            text: Mutex::new("Local proof survives refresh".into()),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            fail: Mutex::new(None),
        })
    }
}
impl ProfileHost for Host {
    fn load(&self) -> Result<ResolvedProfile, CustomizationError> {
        Ok(self.profile.lock().unwrap().clone())
    }
    fn replace(
        &self,
        profile: Profile,
        expected: &str,
    ) -> Result<ResolvedProfile, CustomizationError> {
        let mut state = self.profile.lock().unwrap();
        if state.revision != expected {
            return Err(CustomizationError::Busy);
        }
        profile.validate()?;
        state.profile = profile;
        state.revision = format!("{}", self.writes.fetch_add(1, Ordering::SeqCst) + 2);
        Ok(state.clone())
    }
    fn reset(&self, expected: &str) -> Result<ResolvedProfile, CustomizationError> {
        self.replace(Profile::default(), expected)
    }
    fn read_pane(&self, id: &str, _: &PaneContext) -> Result<PaneOutput, CustomizationError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.fail.lock().unwrap().clone() {
            return Err(error);
        }
        let state = self.profile.lock().unwrap();
        let pane = state.profile.panes.iter().find(|p| p.id == id).unwrap();
        Ok(PaneOutput {
            id: id.into(),
            title: pane.title.clone(),
            state: PaneState::Ready,
            text: self.text.lock().unwrap().clone(),
            truncated: false,
            actions: pane.actions.clone(),
        })
    }
}
fn session(host: &Arc<Host>) -> CustomizationSession {
    let mut s = CustomizationSession::open(host.clone()).unwrap();
    s.refresh_all();
    s
}
fn render(
    s: &CustomizationSession,
    width: u16,
    height: u16,
    focus: usize,
) -> (Buffer, Vec<shell::hits::Hit>) {
    let mut app = App::new("/tmp/orbit-rc-pane-unused-home".into(), true);
    app.tree = profile_tree(&s.resolved.profile).unwrap();
    app.focus = focus;
    let scenario = Scenario {
        custom_panes: s.outputs.clone(),
        ..Scenario::new()
    };
    let mut t = Terminal::new(TestBackend::new(width, height)).unwrap();
    let mut hits = Vec::new();
    t.draw(|f| {
        hits = shell::draw_with_profile(
            f,
            &DrawIn {
                app: &app,
                fx: &Fx::default(),
                scenario: &scenario,
                composer: "ordinary draft",
                completion_sel: 0,
                file_completion: None,
                history_search: None,
                now_ms: 5000,
                reduced: true,
                mono: false,
                tier: Tier::TrueColor,
                scroll_offset: 0,
                scrolls: &[],
                selection: None,
                brand: orbit_hud_tui::proto::welcome::BrandTier::Static,
                toast: None,
                overlay: None,
            },
            &s.resolved.profile,
        )
    })
    .unwrap();
    (t.backend().buffer().clone(), hits)
}
fn text(b: &Buffer) -> String {
    b.content.iter().map(|c| c.symbol()).collect()
}

#[test]
fn pane_named_host_content_has_real_placement() {
    let h = Host::new();
    let s = session(&h);
    let (b, _) = render(&s, 160, 30, 1);
    assert!(text(&b).contains("Engagement notes"));
    assert!(text(&b).contains("Local proof survives refresh"));
    assert!(text(&b).contains("ordinary draft"));
}
#[test]
fn pane_narrow_switcher_keeps_stable_title() {
    let h = Host::new();
    let s = session(&h);
    let (b, _) = render(&s, 90, 24, 1);
    assert!(text(&b).contains("Engagement notes"));
    assert!(text(&b).contains("Local proof survives refresh"));
    let (c, _) = render(&s, 90, 24, 0);
    assert!(text(&c).contains("ordinary draft"));
}
#[test]
fn pane_button_hit_map_targets_exact_leaf_and_action() {
    let h = Host::new();
    let s = session(&h);
    let (_, hits) = render(&s, 160, 30, 1);
    let hit = hits
        .iter()
        .find(|h| {
            h.click
                == shell::hits::Click::CustomAction {
                    panel: 1,
                    action: 1,
                }
        })
        .expect("insert-draft button");
    assert_eq!(
        shell::hits::at(&hits, hit.rect.x, hit.rect.y),
        Some(shell::hits::Click::CustomAction {
            panel: 1,
            action: 1
        })
    );
}
#[test]
fn pane_insert_action_only_returns_a_local_draft() {
    let h = Host::new();
    let mut s = session(&h);
    assert_eq!(
        s.action("notes", 1).unwrap(),
        ActionEffect::InsertDraft("review this evidence".into())
    );
    assert_eq!(h.writes.load(Ordering::SeqCst), 0);
    assert_eq!(h.reads.load(Ordering::SeqCst), 1);
}
#[test]
fn pane_cancel_without_controller_refuses() {
    let h = Host::new();
    let mut s = session(&h);
    s.context.controller = false;
    assert!(s.action("notes", 3).is_err());
    assert_eq!(h.writes.load(Ordering::SeqCst), 0);
}
#[test]
fn pane_cancel_with_controller_returns_authorized_action() {
    let h = Host::new();
    let mut s = session(&h);
    s.context.controller = true;
    assert_eq!(s.action("notes", 3).unwrap(), ActionEffect::OwnerCancel);
}
#[test]
fn pane_focus_conversation_uses_existing_tree() {
    let h = Host::new();
    let mut s = session(&h);
    assert_eq!(
        s.action("notes", 2).unwrap(),
        ActionEffect::FocusConversation
    );
    let mut app = App::new("/tmp/orbit-rc-pane-unused-home".into(), true);
    app.tree = profile_tree(&s.resolved.profile).unwrap();
    app.focus = 1;
    orbit_hud_tui::customization::focus_conversation(&mut app);
    assert_eq!(app.focused_view(), View::Conversation);
}
#[test]
fn pane_explicit_refresh_changes_actual_rendered_text() {
    let h = Host::new();
    let mut s = session(&h);
    *h.text.lock().unwrap() = "refreshed exact proof".into();
    assert!(!text(&render(&s, 160, 30, 1).0).contains("refreshed exact proof"));
    s.action("notes", 0).unwrap();
    assert!(text(&render(&s, 160, 30, 1).0).contains("refreshed exact proof"));
    assert_eq!(h.reads.load(Ordering::SeqCst), 2);
}
#[test]
fn pane_host_error_visible_and_conversation_survives() {
    let h = Host::new();
    *h.fail.lock().unwrap() = Some(CustomizationError::Io("missing notes.md".into()));
    let s = session(&h);
    let t = text(&render(&s, 160, 30, 1).0);
    assert!(t.contains("missing notes.md"));
    assert!(t.contains("ordinary draft"));
}
#[test]
fn pane_hostile_markdown_and_ansi_remain_inert() {
    let h = Host::new();
    *h.text.lock().unwrap() =
        "<script>send()</script>\n\u{1b}[31mred\u{1b}[0m\n[link](javascript:run())".into();
    let s = session(&h);
    let t = text(&render(&s, 160, 30, 1).0);
    assert!(!t.contains('\u{1b}'));
    assert!(t.contains("<script>send()</script>"));
    assert_eq!(h.writes.load(Ordering::SeqCst), 0);
}
#[test]
fn pane_oversized_host_data_fails_visibly() {
    let h = Host::new();
    *h.text.lock().unwrap() = "x".repeat(MAX_PANE_OUTPUT_BYTES + 1);
    let s = session(&h);
    assert_eq!(s.outputs["notes"].state, PaneState::Error);
    assert!(text(&render(&s, 160, 30, 1).0).contains("bounds"));
}
#[test]
fn pane_profile_tree_survives_reopen_with_same_identity() {
    let h = Host::new();
    let s = session(&h);
    let before = profile_tree(&s.resolved.profile).unwrap();
    let again = session(&h);
    assert_eq!(before, profile_tree(&again.resolved.profile).unwrap());
    assert_eq!(before.custom_id_at(1).as_deref(), Some("notes"));
    assert!(text(&render(&again, 90, 24, 1).0).contains("Engagement notes"));
}
#[test]
fn pane_stale_profile_revision_does_not_lose_other_edit() {
    let h = Host::new();
    let mut a = session(&h);
    let mut b = session(&h);
    let tree = Node::default_tree();
    a.persist_tree(&tree).unwrap();
    let before = h.load().unwrap();
    assert!(b.persist_tree(&tree).is_err());
    assert_eq!(h.load().unwrap(), before);
    assert_eq!(h.writes.load(Ordering::SeqCst), 1);
}
#[test]
fn layout_valid_save_preserves_unrelated_tables_and_reopens() {
    let d = Temp::new();
    write_private(
        d.0.join("tui.toml"),
        "[color]\nmode='16'\n[unrelated]\nanswer=42\n",
    )
    .unwrap();
    let snap = LayoutFile::load_checked(&d.0).unwrap();
    let file = LayoutFile {
        tree: Some(Node::default_tree()),
        from_preset: "columns".into(),
    };
    file.save_checked(&d.0, snap.revision.as_deref()).unwrap();
    let value: toml::Value =
        toml::from_str(&std::fs::read_to_string(d.0.join("tui.toml")).unwrap()).unwrap();
    assert_eq!(value["unrelated"]["answer"].as_integer(), Some(42));
    assert_eq!(value["color"]["mode"].as_str(), Some("16"));
    assert_eq!(
        LayoutFile::load_checked(&d.0).unwrap().layout.tree,
        file.tree
    );
}
#[test]
fn layout_malformed_toml_is_never_rewritten() {
    let d = Temp::new();
    let original = b"[layout\nsecret='keep'\n";
    write_private(d.0.join("tui.toml"), original).unwrap();
    assert!(LayoutFile::load_checked(&d.0).is_err());
    let f = LayoutFile {
        tree: Some(Node::default_tree()),
        from_preset: "columns".into(),
    };
    assert!(f.save(&d.0).is_err());
    assert_eq!(std::fs::read(d.0.join("tui.toml")).unwrap(), original);
}
#[test]
fn layout_wrong_type_is_never_rewritten() {
    let d = Temp::new();
    let original = b"layout=42\n";
    write_private(d.0.join("tui.toml"), original).unwrap();
    let f = LayoutFile {
        tree: Some(Node::default_tree()),
        from_preset: "columns".into(),
    };
    assert!(f.save(&d.0).is_err());
    assert_eq!(std::fs::read(d.0.join("tui.toml")).unwrap(), original);
}
#[test]
fn layout_stale_bytes_refuse_without_mutation() {
    let d = Temp::new();
    write_private(d.0.join("tui.toml"), "[extra]\nx=1\n").unwrap();
    let old = LayoutFile::load_checked(&d.0).unwrap();
    let changed = b"[extra]\nx=2\n";
    write_private(d.0.join("tui.toml"), changed).unwrap();
    let f = LayoutFile {
        tree: Some(Node::default_tree()),
        from_preset: "columns".into(),
    };
    assert!(f.save_checked(&d.0, old.revision.as_deref()).is_err());
    assert_eq!(std::fs::read(d.0.join("tui.toml")).unwrap(), changed);
}
#[cfg(unix)]
#[test]
fn layout_symlink_refuses_and_preserves_outside_file() {
    use std::os::unix::fs::symlink;
    let d = Temp::new();
    let outside = d.0.join("outside");
    write_private(&outside, "unchanged").unwrap();
    symlink(&outside, d.0.join("tui.toml")).unwrap();
    assert!(LayoutFile::load_checked(&d.0).is_err());
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "unchanged");
}
#[test]
fn layout_missing_conversation_refuses_before_write() {
    let d = Temp::new();
    let f = LayoutFile {
        tree: Some(Node::Panel {
            view: View::Terminal,
            agent: String::new(),
        }),
        from_preset: "bad".into(),
    };
    assert!(f.save(&d.0).is_err());
    assert!(!d.0.join("tui.toml").exists());
}
#[test]
fn layout_last_conversation_cannot_close_or_change() {
    let mut tree = Node::default_tree();
    assert!(!tree.close(1));
    assert!(!tree.set_view(1, View::Terminal));
    assert!(tree.close(0));
    assert!(tree.leaves().iter().any(|(_, v)| *v == View::Conversation));
}

fn runtime_fixture(host: &Arc<Host>) -> (orbit_hud_tui::proto::runtime::Tui, Scenario) {
    let session = session(host);
    let mut tui = orbit_hud_tui::proto::runtime::Tui::new();
    tui.app.tree = profile_tree(&session.resolved.profile).unwrap();
    tui.app.focus = 1;
    tui.profile = session.resolved.profile.clone();
    let scenario = Scenario {
        custom_panes: session.outputs.clone(),
        ..Scenario::new()
    };
    tui.customization = Some(session);
    tui.sync_focus();
    (tui, scenario)
}

#[test]
fn pane_real_key_inserts_draft_and_consumes_action_without_submission() {
    let host = Host::new();
    let (mut tui, mut scenario) = runtime_fixture(&host);
    let mut draft = String::new();
    let mut toast = None;
    let handled = orbit_hud_tui::proto::runtime::handle_custom_key(
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('2'),
            crossterm::event::KeyModifiers::NONE,
        ),
        &mut tui,
        &mut scenario,
        &mut draft,
        None,
        &mut toast,
        5000,
        false,
    );
    assert!(handled);
    assert_eq!(draft, "review this evidence");
    assert_eq!(tui.app.focused_view(), View::Conversation);
    assert_eq!(host.writes.load(Ordering::SeqCst), 0);
    assert!(!scenario.turn_live);
    assert!(scenario.transcript.is_empty());
}

#[test]
fn pane_real_key_cancel_uses_the_existing_controller_callback_once() {
    let host = Host::new();
    let (mut tui, mut scenario) = runtime_fixture(&host);
    let calls = Arc::new(AtomicUsize::new(0));
    let captured = calls.clone();
    let cancel: orbit_hud_tui::worker::CancelHandle = Arc::new(move || {
        captured.fetch_add(1, Ordering::SeqCst);
    });
    let mut draft = String::new();
    let mut toast = None;
    assert!(orbit_hud_tui::proto::runtime::handle_custom_key(
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('4'),
            crossterm::event::KeyModifiers::NONE
        ),
        &mut tui,
        &mut scenario,
        &mut draft,
        Some(&cancel),
        &mut toast,
        5000,
        false
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn pane_real_key_cancel_without_authority_is_visible_and_does_nothing() {
    let host = Host::new();
    let (mut tui, mut scenario) = runtime_fixture(&host);
    let mut draft = "kept draft".into();
    let mut toast = None;
    assert!(orbit_hud_tui::proto::runtime::handle_custom_key(
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('4'),
            crossterm::event::KeyModifiers::NONE
        ),
        &mut tui,
        &mut scenario,
        &mut draft,
        None,
        &mut toast,
        5000,
        false
    ));
    assert_eq!(draft, "kept draft");
    assert!(toast.unwrap().text.contains("controller authority"));
    assert_eq!(host.writes.load(Ordering::SeqCst), 0);
}

fn write_private(
    path: impl AsRef<std::path::Path>,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes.as_ref())
}

#[cfg(unix)]
#[test]
fn layout_owned_0644_legacy_reads_and_saves_as_private_0600() {
    use std::os::unix::fs::PermissionsExt;
    let home = Temp::new();
    let path = home.0.join("tui.toml");
    write_private(&path, "[color]\nmode='16'\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let snapshot = LayoutFile::load_checked(&home.0).unwrap();
    LayoutFile {
        tree: Some(Node::default_tree()),
        from_preset: "columns".into(),
    }
    .save_checked(&home.0, snapshot.revision.as_deref())
    .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let doc: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(doc["color"]["mode"].as_str(), Some("16"));
}

#[test]
fn layout_profile_change_makes_legacy_revision_stale() {
    let home = Temp::new();
    write_private(home.0.join("tui.toml"), "[color]\nmode='16'\n").unwrap();
    write_private(home.0.join("customization.json"), "{}").unwrap();
    let snapshot = LayoutFile::load_checked(&home.0).unwrap();
    let before = std::fs::read(home.0.join("tui.toml")).unwrap();
    write_private(home.0.join("customization.json"), "{\"name\":\"Changed\"}").unwrap();
    assert!(LayoutFile {
        tree: Some(Node::default_tree()),
        from_preset: "columns".into()
    }
    .save_checked(&home.0, snapshot.revision.as_deref())
    .is_err());
    assert_eq!(std::fs::read(home.0.join("tui.toml")).unwrap(), before);
}

#[test]
fn layout_uses_the_profile_stores_shared_exclusive_lock() {
    let home = Temp::new();
    write_private(home.0.join(".customization.lock"), "").unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.0.join(".customization.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    assert!(LayoutFile {
        tree: Some(Node::default_tree()),
        from_preset: "columns".into()
    }
    .save(&home.0)
    .is_err());
    assert!(!home.0.join("tui.toml").exists());
}

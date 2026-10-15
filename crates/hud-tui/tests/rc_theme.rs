use orbit_frontend_protocol::customization::{ColorMode, Density, Glyphs, Profile};
use orbit_hud_tui::proto::{
    app::App,
    core::Tier,
    scenario::{LineKind, Scenario, TranscriptLine},
    shell::{self, canvas::Cv, pal::Palette, DrawIn, Fx},
};
use ratatui::{backend::TestBackend, buffer::Buffer, layout::Rect, style::Color, Terminal};

fn profile(theme: &str) -> Profile {
    Profile {
        theme: theme.into(),
        ..Profile::default()
    }
}
fn rgb(c: (u8, u8, u8)) -> Color {
    Color::Rgb(c.0, c.1, c.2)
}
fn has(buf: &Buffer, c: Color) -> bool {
    buf.content.iter().any(|v| v.fg == c || v.bg == c)
}
fn text(buf: &Buffer) -> String {
    buf.content.iter().map(|v| v.symbol()).collect()
}
fn render(
    p: &Profile,
    s: &Scenario,
    tier: Tier,
    overlay: Option<shell::overlays::Overlay<'_>>,
    w: u16,
    h: u16,
    time: u64,
) -> Buffer {
    p.validate().unwrap();
    let app = App::new(
        std::path::PathBuf::from("/tmp/orbit-rc-theme-unused-home"),
        p.reduced_motion,
    );
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| {
            shell::draw_with_profile(
                f,
                &DrawIn {
                    app: &app,
                    fx: &Fx::default(),
                    scenario: s,
                    composer: "draft remains local",
                    completion_sel: 0,
                    file_completion: None,
                    history_search: None,
                    now_ms: time,
                    reduced: false,
                    mono: tier >= Tier::T16,
                    tier,
                    scroll_offset: 0,
                    scrolls: &[],
                    selection: None,
                    brand: orbit_hud_tui::proto::welcome::BrandTier::Static,
                    toast: None,
                    overlay,
                },
                p,
            );
        })
        .unwrap();
    terminal.backend().buffer().clone()
}
fn screen(p: &Profile) -> Buffer {
    render(p, &Scenario::new(), Tier::TrueColor, None, 160, 40, 5000)
}
fn drawn(p: &Profile, paint: impl FnOnce(&mut Cv)) -> Buffer {
    let mut b = Buffer::empty(Rect::new(0, 0, 90, 8));
    let mut cv = Cv::with_profile(&mut b, p);
    paint(&mut cv);
    b
}
fn override_one(k: &str, v: &str) -> Profile {
    let mut p = Profile::default();
    p.token_overrides.insert(k.into(), v.into());
    p
}

#[test]
fn palette_default_keeps_prior_actual_screen() {
    let p = Profile::default();
    let s = Scenario::new();
    let app = App::new("/tmp/orbit-rc-theme-unused-home".into(), false);
    let mut term = Terminal::new(TestBackend::new(160, 40)).unwrap();
    term.draw(|f| {
        shell::draw(
            f,
            &DrawIn {
                app: &app,
                fx: &Fx::default(),
                scenario: &s,
                composer: "draft remains local",
                completion_sel: 0,
                file_completion: None,
                history_search: None,
                now_ms: 5000,
                reduced: false,
                mono: false,
                tier: Tier::TrueColor,
                scroll_offset: 0,
                scrolls: &[],
                selection: None,
                brand: orbit_hud_tui::proto::welcome::BrandTier::Static,
                toast: None,
                overlay: None,
            },
        )
    })
    .unwrap();
    assert_eq!(&screen(&p), term.backend().buffer());
}
#[test]
fn palette_midnight_changes_actual_background() {
    let b = screen(&profile("midnight"));
    assert_eq!(b[(0, 1)].bg, rgb((5, 12, 25)));
    assert_ne!(b, screen(&Profile::default()));
}
#[test]
fn palette_paper_is_light_and_dark_ink() {
    let p = profile("paper");
    let b = screen(&p);
    assert_eq!(b[(0, 1)].bg, rgb((245, 243, 235)));
    assert!(has(&b, rgb((37, 34, 29))));
}
#[test]
fn palette_canvas_override_is_visible() {
    assert_eq!(
        screen(&override_one("bg", "#123456"))[(0, 1)].bg,
        rgb((18, 52, 86))
    );
}
#[test]
fn palette_ink_override_is_visible() {
    assert!(has(
        &screen(&override_one("ink", "#123456")),
        rgb((18, 52, 86))
    ));
}
#[test]
fn palette_legacy_text_alias_is_visible() {
    assert!(has(
        &screen(&override_one("text", "#123456")),
        rgb((18, 52, 86))
    ));
}
#[test]
fn palette_canonical_alias_wins_in_real_cells() {
    let mut p = override_one("text", "#123456");
    p.token_overrides.insert("ink".into(), "#654321".into());
    assert!(has(&screen(&p), rgb((101, 67, 33))));
}
#[test]
fn palette_collision_keeps_semantic_roles_separate() {
    let mut p = override_one("magenta", "#5CC6DD");
    p.token_overrides.insert("cyan".into(), "#010203".into());
    let b = drawn(&p, |cv| {
        let c = cv.palette;
        orbit_hud_tui::proto::shell::frame::keycap(cv, 0, 0, "y", true);
        cv.text(0, 1, "composer", c.cyan, None);
    });
    assert_eq!(b[(0, 0)].bg, rgb((92, 198, 221)));
    assert_eq!(b[(0, 1)].fg, rgb((1, 2, 3)));
}
#[test]
fn palette_collision_is_resolved_before_derived_tint() {
    let mut p = override_one("surface", "#5CC6DD");
    p.token_overrides.insert("cyan".into(), "#010203".into());
    let b = drawn(&p, |cv| {
        let c = cv.palette;
        orbit_hud_tui::proto::shell::diffrows::draw(
            cv,
            0,
            0,
            20,
            &[('+', "proof".into())],
            c.panel,
        );
    });
    let c = Palette::from_profile(&p);
    assert_eq!(
        b[(0, 0)].bg,
        rgb(shell::canvas::tint(c.green, (92, 198, 221), 0.1))
    );
}
#[test]
fn palette_brand_gradient_uses_overridden_endpoints() {
    let p = override_one("magenta", "#123456");
    let b = drawn(&p, |cv| {
        let c = cv.palette;
        let mut opts = shell::mark::MarkOpts::rest(c.panel);
        opts.star_col = c.magenta_hi;
        shell::mark::draw_mark(cv, 0, 0, &opts);
    });
    assert_eq!(
        b[(3, 0)].fg,
        rgb(Palette::from_profile(&p).brand_at(3.0 / 32.0))
    );
}
#[test]
fn palette_error_badge_uses_red_override() {
    let p = override_one("red", "#123456");
    let b = drawn(&p, |cv| {
        let parts = shell::frame::badge_themed(
            cv.palette,
            shell::frame::BadgeState::Failed,
            None,
            5000,
            true,
        );
        cv.spans(0, 0, &parts, None);
    });
    assert_eq!(b[(0, 0)].fg, rgb((18, 52, 86)));
}
#[test]
fn palette_success_badge_uses_green_override() {
    let p = override_one("green", "#123456");
    let b = drawn(&p, |cv| {
        let parts = shell::frame::badge_themed(
            cv.palette,
            shell::frame::BadgeState::Done,
            None,
            5000,
            true,
        );
        cv.spans(0, 0, &parts, None);
    });
    assert_eq!(b[(0, 0)].fg, rgb((18, 52, 86)));
}
#[test]
fn palette_diff_addition_uses_selected_role() {
    let p = override_one("green", "#123456");
    let b = drawn(&p, |cv| {
        let c = cv.palette;
        shell::diffrows::draw(cv, 0, 0, 30, &[('+', "new proof".into())], c.panel);
    });
    assert_eq!(b[(0, 0)].fg, rgb((18, 52, 86)));
    assert!(text(&b).contains("+ new proof"));
}
#[test]
fn palette_diff_deletion_uses_selected_role() {
    let p = override_one("red", "#123456");
    let b = drawn(&p, |cv| {
        let c = cv.palette;
        shell::diffrows::draw(cv, 0, 0, 30, &[('-', "old proof".into())], c.panel);
    });
    assert_eq!(b[(0, 0)].fg, rgb((18, 52, 86)));
}
#[test]
fn palette_diff_hunk_uses_selected_role() {
    let p = override_one("violet", "#123456");
    let b = drawn(&p, |cv| {
        let c = cv.palette;
        shell::diffrows::draw(cv, 0, 0, 30, &[('@', "@@ proof @@".into())], c.panel);
    });
    assert_eq!(b[(0, 0)].fg, rgb((18, 52, 86)));
}
#[test]
fn palette_no_global_state_between_frames() {
    let a = screen(&profile("paper"));
    let _ = screen(&profile("midnight"));
    assert_eq!(a, screen(&profile("paper")));
    assert_ne!(a, screen(&Profile::default()));
}
#[test]
fn shell_frame_and_bars_follow_theme() {
    let p = override_one("rule", "#123456");
    assert!(has(&screen(&p), rgb((18, 52, 86))));
}
#[test]
fn shell_palette_overlay_follows_theme() {
    let p = profile("paper");
    let b = render(
        &p,
        &Scenario::new(),
        Tier::TrueColor,
        Some(shell::overlays::Overlay::Palette {
            query: "",
            sel: 0,
            sel_prev: 0,
            opened_ms: 0,
            sel_ms: 0,
        }),
        160,
        40,
        5000,
    );
    assert!(text(&b).contains("commands"));
    assert!(has(&b, rgb(Palette::from_profile(&p).ink)));
}
#[test]
fn shell_help_overlay_follows_theme() {
    let p = profile("midnight");
    let b = render(
        &p,
        &Scenario::new(),
        Tier::TrueColor,
        Some(shell::overlays::Overlay::Help { opened_ms: 0 }),
        160,
        40,
        5000,
    );
    assert!(has(&b, rgb(Palette::from_profile(&p).panel)));
    assert!(text(&b).contains("esc"));
}
#[test]
fn shell_quit_overlay_follows_theme() {
    let p = override_one("magenta", "#123456");
    let b = render(
        &p,
        &Scenario::new(),
        Tier::TrueColor,
        Some(shell::overlays::Overlay::Quit { turn_live: true }),
        160,
        40,
        5000,
    );
    assert!(text(&b).contains("quit"));
    assert!(has(&b, rgb((18, 52, 86))));
}
#[test]
fn shell_256_conversion_happens_after_theme() {
    let b = render(
        &profile("paper"),
        &Scenario::new(),
        Tier::T256,
        None,
        160,
        40,
        5000,
    );
    assert!(b.content.iter().any(|c| matches!(c.fg, Color::Indexed(_))));
    assert!(!b
        .content
        .iter()
        .any(|c| matches!(c.fg, Color::Rgb(..)) || matches!(c.bg, Color::Rgb(..))));
}
#[test]
fn shell_16_conversion_happens_after_theme() {
    let b = render(
        &profile("paper"),
        &Scenario::new(),
        Tier::T16,
        None,
        160,
        40,
        5000,
    );
    assert!(!b
        .content
        .iter()
        .any(|c| matches!(c.fg, Color::Rgb(..) | Color::Indexed(_))
            || matches!(c.bg, Color::Rgb(..) | Color::Indexed(_))));
}
#[test]
fn shell_mono_keeps_labels_without_colors() {
    let b = render(
        &profile("paper"),
        &Scenario::new(),
        Tier::None,
        None,
        160,
        40,
        5000,
    );
    assert!(text(&b).contains("draft remains local"));
    assert_eq!(
        text(&b),
        text(&render(
            &profile("paper"),
            &Scenario::new(),
            Tier::TrueColor,
            None,
            160,
            40,
            5000
        ))
    );
    assert!(b
        .content
        .iter()
        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
}
#[test]
fn shell_profile_mono_reduces_detected_truecolor() {
    let mut p = profile("paper");
    p.color_mode = ColorMode::Mono;
    let b = screen(&p);
    assert!(b
        .content
        .iter()
        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
}
#[test]
fn shell_no_color_overrules_explicit_truecolor() {
    assert_eq!(
        shell::effective_tier(Tier::TrueColor, ColorMode::Truecolor, true),
        Tier::None
    );
    let mut b = screen(&profile("paper"));
    shell::tier::apply(
        &mut b,
        shell::effective_tier(Tier::TrueColor, ColorMode::Truecolor, true),
    );
    assert!(b
        .content
        .iter()
        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
}
#[test]
fn shell_user_cannot_upgrade_detected_16_color() {
    assert_eq!(
        shell::effective_tier(Tier::T16, ColorMode::Truecolor, false),
        Tier::T16
    );
    let p = Profile {
        color_mode: ColorMode::Truecolor,
        ..Profile::default()
    };
    let b = render(&p, &Scenario::new(), Tier::T16, None, 160, 40, 5000);
    assert!(!b.content.iter().any(|c| matches!(c.fg, Color::Rgb(..))));
}
#[test]
fn shell_ascii_changes_frame_glyphs() {
    let p = Profile {
        glyphs: Glyphs::Ascii,
        ..Profile::default()
    };
    let b = screen(&p);
    assert!(text(&b).contains('+'));
    assert!(!text(&b).chars().any(|c| matches!(
        c,
        '╭' | '╮' | '╰' | '╯' | '┏' | '┓' | '┗' | '┛' | '━' | '│' | '✦'
    )));
}
#[test]
fn shell_narrow_preserves_conversation_and_composer() {
    let b = render(
        &profile("paper"),
        &Scenario::new(),
        Tier::TrueColor,
        None,
        70,
        20,
        5000,
    );
    let t = text(&b);
    assert!(t.contains("Conversation"));
    assert!(t.contains("draft remains local"));
}
#[test]
fn shell_tiny_draw_stays_inside_buffer() {
    let b = render(
        &profile("midnight"),
        &Scenario::new(),
        Tier::TrueColor,
        None,
        20,
        6,
        5000,
    );
    assert_eq!(b.content.len(), 120);
    assert!(has(&b, rgb((5, 12, 25))));
}
#[test]
fn shell_compact_removes_only_decorative_turn_spacing() {
    let mut s = Scenario::new();
    for (kind, text) in [
        (LineKind::User, "first proof"),
        (LineKind::Model, "second proof"),
        (LineKind::User, "third proof"),
    ] {
        s.transcript.push(TranscriptLine {
            kind,
            text: text.into(),
            ..Default::default()
        });
    }
    let a = render(&Profile::default(), &s, Tier::TrueColor, None, 90, 30, 5000);
    let p = Profile {
        density: Density::Compact,
        ..Profile::default()
    };
    let b = render(&p, &s, Tier::TrueColor, None, 90, 30, 5000);
    assert_ne!(a, b);
    for phrase in ["first proof", "second proof", "third proof"] {
        assert!(text(&b).contains(phrase));
    }
}
#[test]
fn shell_reduced_motion_stabilizes_visible_reply() {
    let mut s = Scenario::new();
    s.transcript.push(TranscriptLine {
        kind: LineKind::Model,
        text: "stable proof".into(),
        arrivals: vec![(0, 0)],
        ..Default::default()
    });
    let p = Profile {
        reduced_motion: true,
        ..Profile::default()
    };
    let a = render(&p, &s, Tier::TrueColor, None, 90, 30, 5000);
    let b = render(&p, &s, Tier::TrueColor, None, 90, 30, 10000);
    assert_eq!(a, b);
    assert!(text(&a).contains("stable proof"));
}
#[test]
fn shell_code_syntax_override_reaches_actual_text() {
    let mut s = Scenario::new();
    s.transcript.push(TranscriptLine {
        kind: LineKind::Model,
        text: "```rust\nlet count = 12;\n```".into(),
        ..Default::default()
    });
    let p = override_one("syn_kw", "#123456");
    let b = render(&p, &s, Tier::TrueColor, None, 90, 30, 5000);
    assert!(has(&b, rgb((18, 52, 86))));
    assert!(text(&b).contains("let count = 12;"));
}

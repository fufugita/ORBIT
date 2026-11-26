//! The saved-sessions list, drawn once for the Sessions pane and for the
//! sidebar, so the two cannot disagree about what a row says or which row a
//! click lands on. Every row marks its own region as it is drawn
//! (`Click::Session(i)`, `i` being its place in the whole list), so a row
//! that is clipped away or never drawn has no region.

use super::canvas::{Cv, Seg, clip_text, text_width, tint};
use super::frame::{FocusFx, FrameSpec, empty_state, panel_frame};
use super::hits::Click;
use crate::msg::SavedSession;
use crate::proto::saved_sessions::{SavedSessions, first_visible};
use crate::proto::scenario::Scenario;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

/// The most other sessions the sidebar lists under the open one.
pub const SIDEBAR_MAX: usize = 4;

/// What the open session's row says where the others give their age. Not
/// "now": a session saved a moment ago says that too.
pub const OPEN_TAG: &str = "open";

/// What one row says, apart from where it is drawn.
#[derive(Debug, PartialEq, Eq)]
struct RowText {
    title: String,
    age: String,
    detail: String,
}

/// The last eight characters of an id: enough to tell two sessions apart
/// when neither has a name or a first message to show.
fn short_id(id: &str) -> String {
    let count = id.chars().count();
    id.chars().skip(count.saturating_sub(8)).collect()
}

/// What a saved session is called in a list or a message about it: its
/// name or first words on one line, else what it is without either.
pub fn row_title(row: &SavedSession) -> String {
    // One line, whatever the title holds.
    let title = row.title.split_whitespace().collect::<Vec<_>>().join(" ");
    if !title.is_empty() {
        title
    } else if row.turns == 0 {
        // The session the screen opened on, before anything was said.
        "New session".to_owned()
    } else {
        format!("untitled · {}", short_id(&row.id))
    }
}

fn row_text(row: &SavedSession, current: bool) -> RowText {
    let title = row_title(row);
    let age = if current {
        OPEN_TAG.to_owned()
    } else {
        row.age.clone()
    };
    let mut parts = Vec::new();
    if !row.model.is_empty() {
        parts.push(row.model.clone());
    }
    parts.push(format!(
        "{} turn{}",
        row.turns,
        if row.turns == 1 { "" } else { "s" }
    ));
    RowText {
        title,
        age,
        detail: parts.join(" · "),
    }
}

/// What the Sessions pane needs.
pub struct PaneIn<'a> {
    pub s: &'a Scenario,
    pub num: usize,
    pub focused: bool,
    pub focus_fx: FocusFx,
}

/// The Sessions pane: this folder's saved sessions, newest first. A click on
/// a row resumes it; `j`/`k` move the selection and ⏎ resumes it.
pub fn draw_pane(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let colors = cv.palette;
    let list = &inp.s.saved_sessions;
    let session_id = inp.s.session_id.as_str();
    let badge = if list.loaded() {
        vec![Seg::new(
            list.count_with_open(session_id).to_string(),
            colors.muted,
        )]
    } else {
        vec![Seg::new("…", colors.faint)]
    };
    let Some(inner) = panel_frame(
        cv,
        r,
        &FrameSpec {
            num: inp.num,
            title: "Sessions",
            subtitle: "",
            ident: colors.magenta,
            focused: inp.focused,
            focus_fx: inp.focus_fx,
            badge: Some(badge),
            attention: 0.0,
            footer: vec![("j/k", "move"), ("⏎", "resume"), ("r", "refresh")],
            footer_parts: Vec::new(),
        },
    ) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width.saturating_sub(2),
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        if list.rows.is_empty() {
            if list.loaded() {
                empty_state(
                    cv,
                    inner,
                    "◌",
                    colors.magenta,
                    "No saved sessions",
                    "Talk to ORBIT in this folder and its session is listed here.",
                );
            } else {
                cv.text(
                    inner.x as i32 + 1,
                    inner.y as i32 + 1,
                    "looking for saved sessions…",
                    colors.muted,
                    None,
                );
            }
            return;
        }
        // Two lines a session when there is room for three of them, else
        // one: a short pane shows more sessions than a roomy one would.
        let lines = if inner.height >= 6 { 2 } else { 1 };
        let visible = (inner.height as usize / lines).max(1);
        let first = first_visible(list.selected, visible, list.rows.len());
        let (x, w) = (inner.x as i32, inner.width as i32);
        let (fill_x, fill_w) = (r.x as i32 + 1, r.width as i32 - 2);
        for (n, (i, row)) in list
            .rows
            .iter()
            .enumerate()
            .skip(first)
            .take(visible)
            .enumerate()
        {
            let yy = inner.y as i32 + (n * lines) as i32;
            let current = SavedSessions::is_current(row, session_id);
            let selected = i == list.selected;
            let bg = if selected {
                tint(colors.magenta, colors.panel, 0.12)
            } else {
                colors.panel
            };
            cv.hit(fill_x, yy, fill_w, lines as i32, Click::Session(i));
            cv.fill(fill_x, yy, fill_w, lines as i32, bg);
            if selected {
                for line in 0..lines as i32 {
                    cv.text(fill_x, yy + line, "▌", colors.magenta, Some(bg));
                }
            }
            let mut text = row_text(row, current);
            if current && let Some(live) = inp.s.session_name_or_title() {
                // The screen's own word for the open session: a rename or a
                // first prompt is here before the list is read again. With
                // nothing said yet, the list's own title stands.
                text.title = live;
            }
            let (glyph, glyph_colour) = if current {
                ("●", colors.magenta)
            } else {
                ("○", colors.faint)
            };
            cv.bold(x, yy, glyph, glyph_colour, Some(bg));
            // The age sits at the right edge when the pane is wide enough
            // to keep a readable title beside it.
            let age = compact_age(&text.age);
            let age_w = text_width(age);
            let age_fits = w >= age_w + 8;
            let title_w = if age_fits { w - 2 - age_w - 1 } else { w - 2 };
            let strong = selected || current;
            cv.put(
                x + 2,
                yy,
                &clip_text(&text.title, title_w.max(1)),
                if strong { colors.ink } else { colors.ink2 },
                Some(bg),
                if strong {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                },
            );
            if age_fits {
                if current {
                    cv.bold(x + w - age_w, yy, age, colors.magenta, Some(bg));
                } else {
                    cv.text(x + w - age_w, yy, age, colors.muted, Some(bg));
                }
            }
            if lines == 2 {
                cv.text(
                    x + 2,
                    yy + 1,
                    &clip_text(&text.detail, (w - 2).max(1)),
                    colors.muted,
                    Some(bg),
                );
            }
        }
    });
}

/// How many other sessions the sidebar of height `h` has room for: one at
/// the least, so the list is never hidden, and more as the sidebar grows,
/// without pushing the sections below it off a short screen.
pub fn sidebar_room(h: i32) -> usize {
    (((h - 24) / 2 + 1).max(1) as usize).min(SIDEBAR_MAX)
}

/// An age short enough for the narrow sidebar: "5m", not "5m ago". "just
/// now" becomes "now".
fn compact_age(age: &str) -> &str {
    if age == "just now" {
        "now"
    } else {
        age.trim_end_matches(" ago")
    }
}

/// The sidebar's rows under the open session's own: up to `max` other
/// sessions, one line each, then a line pointing to `/sessions` when the
/// list holds more. (No count: the list is only the newest few of the
/// folder's sessions, so a number would understate how many exist.)
/// Returns the number of lines used.
pub fn draw_sidebar_rows(
    cv: &mut Cv,
    (x, y, w): (i32, i32, i32),
    list: &SavedSessions,
    session_id: &str,
    max: usize,
) -> i32 {
    let colors = cv.palette;
    let others: Vec<(usize, &SavedSession)> = list.others(session_id).collect();
    let mut used = 0;
    for (i, row) in others.iter().take(max) {
        let yy = y + used;
        let text = row_text(row, false);
        let age = compact_age(&text.age);
        let age_w = text_width(age);
        cv.hit(x, yy, w, 1, Click::Session(*i));
        cv.text(x + 2, yy, "○", colors.faint, Some(colors.sidebar));
        cv.text(
            x + 4,
            yy,
            &clip_text(&text.title, (w - 6 - age_w).max(1)),
            colors.ink2,
            Some(colors.sidebar),
        );
        cv.text(
            x + w - 1 - age_w,
            yy,
            age,
            colors.muted,
            Some(colors.sidebar),
        );
        used += 1;
    }
    if others.len() > max {
        cv.text(
            x + 4,
            y + used,
            &clip_text("more in /sessions", (w - 5).max(1)),
            colors.faint,
            Some(colors.sidebar),
        );
        used += 1;
    }
    used
}

#[cfg(test)]
mod tests {
    use super::super::hits::{self, Hit};
    use super::*;
    use ratatui::buffer::Buffer;

    fn saved(id: &str, title: &str, turns: u64, age: &str) -> SavedSession {
        SavedSession {
            id: id.into(),
            title: title.into(),
            model: "mock/m1".into(),
            turns,
            age: age.into(),
            current: false,
        }
    }

    fn scenario(rows: Vec<SavedSession>, session_id: &str) -> Scenario {
        let mut s = Scenario {
            session_id: session_id.into(),
            ..Default::default()
        };
        s.saved_sessions.receive(rows);
        s
    }

    fn line(buf: &Buffer, y: u16) -> String {
        (0..buf.area.width)
            .map(|x| buf[(x, y)].symbol().to_string())
            .collect::<String>()
    }

    fn screen(buf: &Buffer) -> String {
        (0..buf.area.height)
            .map(|y| line(buf, y))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn render_pane(s: &Scenario, width: u16, height: u16) -> (Buffer, Vec<Hit>) {
        let mut buf = Buffer::empty(Rect::new(0, 0, width, height));
        let mut cv = Cv::new(&mut buf);
        draw_pane(
            &mut cv,
            Rect::new(0, 0, width, height),
            &PaneIn {
                s,
                num: 1,
                focused: true,
                focus_fx: FocusFx::settled(true),
            },
        );
        let hits = cv.take_hits();
        (buf, hits)
    }

    fn three() -> Vec<SavedSession> {
        vec![
            saved("session-c", "Fix the login redirect", 6, "3m ago"),
            saved("session-b", "Rename the config keys", 2, "2h ago"),
            saved("session-a", "", 1, "4d ago"),
        ]
    }

    #[test]
    fn a_row_says_its_title_age_and_what_it_ran_on() {
        let row = saved("session-1", "  Fix\tthe\nlogin  ", 1, "5m ago");
        let t = row_text(&row, false);
        assert_eq!(t.title, "Fix the login", "one line, single spaces");
        assert_eq!(t.age, "5m ago");
        assert_eq!(t.detail, "mock/m1 · 1 turn");
        assert_eq!(
            row_text(&row, true).age,
            OPEN_TAG,
            "the open session says so where the others give their age"
        );
        let untitled = row_text(&saved("session-0123456789abcdef", "", 3, "1h ago"), false);
        assert_eq!(untitled.title, "untitled · 89abcdef");
        assert_eq!(untitled.detail, "mock/m1 · 3 turns");
        let blank = row_text(&saved("session-new", "", 0, "just now"), false);
        assert_eq!(
            blank.title, "New session",
            "nothing said yet: not 'untitled'"
        );
        let mut modelless = saved("s", "x", 0, "now");
        modelless.model.clear();
        assert_eq!(row_text(&modelless, false).detail, "0 turns");
    }

    #[test]
    fn the_pane_lists_every_session_and_each_row_is_one_click_target() {
        let s = scenario(three(), "session-c");
        let (buf, hits) = render_pane(&s, 50, 16);
        let text = screen(&buf);
        for needle in [
            "Sessions",
            "Fix the login redirect",
            "Rename the config keys",
            "untitled · ession-a",
            "6 turns",
            OPEN_TAG,
            "2h",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in\n{text}");
        }
        // two lines a row, so three rows give three regions two high
        let rows: Vec<&Hit> = hits
            .iter()
            .filter(|h| matches!(h.click, Click::Session(_)))
            .collect();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|h| h.rect.height == 2));
        // a click on either line of a row lands on that row
        for (i, hit) in rows.iter().enumerate() {
            assert_eq!(hit.click, Click::Session(i));
            for y in [hit.rect.y, hit.rect.y + 1] {
                assert_eq!(
                    hits::at(&hits, hit.rect.x + 3, y),
                    Some(Click::Session(i)),
                    "row {i}, line {y}"
                );
            }
        }
        // the frame's own hit regions stay outside the rows
        assert!(rows.windows(2).all(|w| w[0].rect.bottom() <= w[1].rect.y));
    }

    #[test]
    fn the_selected_row_is_marked_and_the_open_one_is_bold_with_a_dot() {
        let mut s = scenario(three(), "session-b");
        s.saved_sessions.select(2);
        let (buf, hits) = render_pane(&s, 50, 16);
        let first = hits
            .iter()
            .find(|h| h.click == Click::Session(2))
            .expect("row 2 drawn");
        assert_eq!(buf[(first.rect.x, first.rect.y)].symbol(), "▌");
        let open = hits
            .iter()
            .find(|h| h.click == Click::Session(1))
            .expect("row 1 drawn");
        assert_eq!(
            buf[(open.rect.x + 1, open.rect.y)].symbol(),
            "●",
            "the open session has the filled dot"
        );
        assert_eq!(buf[(first.rect.x + 1, first.rect.y)].symbol(), "○");
    }

    #[test]
    fn a_short_pane_uses_one_line_a_row_and_scrolls_with_the_selection() {
        let rows: Vec<SavedSession> = (0..8)
            .map(|n| saved(&format!("session-{n}"), &format!("topic {n}"), 1, "1m ago"))
            .collect();
        let mut s = scenario(rows, "none");
        // inner height = 6 - 3 = 3 rows: one line each
        let (buf, hits) = render_pane(&s, 50, 6);
        let shown: Vec<usize> = hits
            .iter()
            .filter_map(|h| match h.click {
                Click::Session(i) => Some(i),
                _ => None,
            })
            .collect();
        assert_eq!(shown, [0, 1, 2]);
        assert!(!screen(&buf).contains("topic 3"));
        s.saved_sessions.select(6);
        let (buf, hits) = render_pane(&s, 50, 6);
        let shown: Vec<usize> = hits
            .iter()
            .filter_map(|h| match h.click {
                Click::Session(i) => Some(i),
                _ => None,
            })
            .collect();
        assert_eq!(shown, [4, 5, 6], "the window ends on the selection");
        assert!(screen(&buf).contains("topic 6"));
        assert!(!screen(&buf).contains("topic 0"));
    }

    #[test]
    fn an_unanswered_or_empty_list_says_so_instead_of_drawing_nothing() {
        let mut s = Scenario::default();
        let (buf, hits) = render_pane(&s, 50, 12);
        assert!(screen(&buf).contains("looking for saved sessions"));
        assert!(!hits.iter().any(|h| matches!(h.click, Click::Session(_))));
        s.saved_sessions.receive(Vec::new());
        let (buf, hits) = render_pane(&s, 50, 12);
        assert!(screen(&buf).contains("No saved sessions"));
        assert!(!hits.iter().any(|h| matches!(h.click, Click::Session(_))));
    }

    #[test]
    fn a_narrow_pane_keeps_the_title_and_drops_the_age_instead_of_overlapping() {
        let s = scenario(three(), "x");
        for width in [12u16, 16, 20, 24] {
            let (buf, hits) = render_pane(&s, width, 12);
            for hit in &hits {
                assert!(hit.rect.right() <= width && hit.rect.bottom() <= 12);
            }
            assert!(
                screen(&buf).contains("Fix t"),
                "the title survives at {width} columns:\n{}",
                screen(&buf)
            );
        }
        let (buf, _) = render_pane(&s, 12, 12);
        assert!(
            !screen(&buf).contains("2h"),
            "a 12-column pane has no room for the age:\n{}",
            screen(&buf)
        );
        let (buf, _) = render_pane(&s, 24, 12);
        assert!(
            screen(&buf).contains("2h"),
            "a 24-column pane has:\n{}",
            screen(&buf)
        );
    }

    #[test]
    fn the_sidebar_lists_the_others_and_points_to_the_rest() {
        let rows: Vec<SavedSession> = (0..7)
            .map(|n| saved(&format!("s{n}"), &format!("topic {n}"), 1, "9m ago"))
            .collect();
        let mut s = scenario(rows, "s0");
        s.saved_sessions.select(0);
        let mut buf = Buffer::empty(Rect::new(0, 0, 30, 12));
        let mut cv = Cv::new(&mut buf);
        let used = draw_sidebar_rows(&mut cv, (0, 1, 30), &s.saved_sessions, "s0", 3);
        let hits = cv.take_hits();
        assert_eq!(used, 4, "three sessions and the 'more' line");
        let text = screen(&buf);
        assert!(
            !text.contains("topic 0"),
            "the open session has its own row"
        );
        assert!(text.contains("topic 1") && text.contains("topic 3"));
        assert!(!text.contains("topic 4"));
        assert!(text.contains("more in /sessions"), "{text}");
        assert!(
            !text.contains("+3"),
            "no count that could understate: {text}"
        );
        assert!(text.contains("9m") && !text.contains("9m ago"));
        let clicks: Vec<Click> = hits.iter().map(|h| h.click).collect();
        assert_eq!(
            clicks,
            [Click::Session(1), Click::Session(2), Click::Session(3)],
            "indexes are places in the whole list, the open one skipped"
        );
        assert!(
            hits.iter()
                .all(|h| h.rect.height == 1 && h.rect.width == 30)
        );
    }

    #[test]
    fn the_sidebar_shortens_ages_so_titles_keep_their_room() {
        assert_eq!(compact_age("just now"), "now");
        assert_eq!(compact_age("5m ago"), "5m");
        assert_eq!(compact_age("3h ago"), "3h");
        assert_eq!(compact_age("2d ago"), "2d");
        assert_eq!(compact_age("yesterday"), "yesterday", "other text is kept");
        let rows = vec![
            saved("a", "open one", 1, "just now"),
            saved("b", "Rename the config key", 1, "just now"),
        ];
        let s = scenario(rows, "a");
        let mut buf = Buffer::empty(Rect::new(0, 0, 30, 4));
        let mut cv = Cv::new(&mut buf);
        draw_sidebar_rows(&mut cv, (0, 1, 30), &s.saved_sessions, "a", 4);
        let text = screen(&buf);
        assert!(
            text.contains("Rename the config key"),
            "the whole 21-column title fits beside \"now\":\n{text}"
        );
        assert!(text.contains("now") && !text.contains("just"), "{text}");
    }

    #[test]
    fn the_sidebar_has_no_rows_to_add_until_there_is_a_second_session() {
        let s = scenario(vec![saved("only", "the one", 2, "1m ago")], "only");
        let mut buf = Buffer::empty(Rect::new(0, 0, 30, 6));
        let mut cv = Cv::new(&mut buf);
        assert_eq!(
            draw_sidebar_rows(&mut cv, (0, 1, 30), &s.saved_sessions, "only", 4),
            0
        );
        assert!(cv.take_hits().is_empty());
    }

    #[test]
    fn the_sidebar_makes_room_in_steps_and_never_below_one() {
        assert_eq!(sidebar_room(10), 1);
        assert_eq!(sidebar_room(24), 1);
        assert_eq!(sidebar_room(26), 2);
        assert_eq!(sidebar_room(30), 4);
        assert_eq!(sidebar_room(80), SIDEBAR_MAX);
    }

    /// The first cell of `needle` on row `y`, one cell to a symbol.
    fn find_cells(buf: &Buffer, y: u16, needle: &str) -> Option<u16> {
        let want: Vec<String> = needle.chars().map(String::from).collect();
        (0..buf.area.width.saturating_sub(want.len() as u16)).find(|&x| {
            want.iter()
                .enumerate()
                .all(|(i, symbol)| buf[(x + i as u16, y)].symbol() == symbol)
        })
    }

    /// Where the others give their age, the open session says so, in bold:
    /// "now" would not do, a session saved a moment ago says that too.
    #[test]
    fn only_the_open_row_says_open_and_it_is_bold() {
        let mut rows = three();
        rows[1].age = "just now".into();
        let s = scenario(rows, "session-c");
        let (buf, hits) = render_pane(&s, 50, 16);
        let text = screen(&buf);
        assert_eq!(
            text.matches(OPEN_TAG).count(),
            1,
            "one row is open:\n{text}"
        );
        let first_line = |index: usize| {
            hits.iter()
                .find(|h| h.click == Click::Session(index))
                .map(|h| h.rect.y)
                .expect("row drawn")
        };
        let open_at = find_cells(&buf, first_line(0), OPEN_TAG).expect("the open row says open");
        let open_cell = &buf[(open_at, first_line(0))];
        assert!(open_cell.modifier.contains(Modifier::BOLD), "bold");
        let others_age = find_cells(&buf, first_line(1), "now").expect("a row saved just now");
        let other_cell = &buf[(others_age, first_line(1))];
        assert!(
            !other_cell.modifier.contains(Modifier::BOLD),
            "another row's age is plain"
        );
        assert_ne!(open_cell.fg, other_cell.fg, "the tag has the accent colour");
    }

    /// The open row says what the screen calls the session: a rename, or a
    /// first prompt, is there before the list is read again.
    #[test]
    fn the_open_row_uses_the_screens_label_not_a_stale_listed_title() {
        let mut s = scenario(three(), "session-b");
        s.session_name = Some(("session-b".into(), "Fresh name".into()));
        let (buf, _) = render_pane(&s, 50, 16);
        let text = screen(&buf);
        assert!(text.contains("Fresh name"), "{text}");
        assert!(
            !text.contains("Rename the config keys"),
            "the open row's older listed title is not shown:\n{text}"
        );
        assert!(
            text.contains("Fix the login redirect"),
            "the others keep their listed titles:\n{text}"
        );
    }
}

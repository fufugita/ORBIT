//! The selection menu: one state type behind `/models`, `/sessions`, `/mode`,
//! `/theme`, `/mcp` and every other command that asks you to pick from a list.
//!
//! It holds rows, the selected row, a type-to-filter line and the keys that
//! act on a row. It knows nothing about the terminal: the overlay draws it
//! and the key and mouse handlers drive it, so each rule here can be tested
//! on its own.

/// What a menu chooses between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerKind {
    /// `/models`: a row's value is `provider/model`.
    Models,
    /// `/sessions`: a row's value is a session id.
    Sessions,
    /// Any other menu. A row's value is the command line that choosing it
    /// runs, exactly as if it had been typed (`/mode plan`), so every check
    /// the command makes still applies.
    Command,
}

/// A key that acts on the selected row without choosing it, such as `r`
/// to reconnect an MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowKey {
    pub key: char,
    pub label: String,
    /// The command line it runs.
    pub command: String,
    /// Whether the menu stays open and refreshes after the command, so a
    /// manager can be used again and again. Otherwise the menu closes. A
    /// command that keeps the menu open is one the worker answers with the
    /// refreshed list, which is what the menu waits for.
    pub keep_open: bool,
}

/// One selectable row of a picker.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PickerRow {
    pub label: String,
    /// What choosing the row sends: the model id, the session id, or the
    /// command line to run. Empty means the row is only to read.
    pub value: String,
    pub detail: String,
    /// Longer text about the row, shown under the list while it is selected.
    pub preview: String,
    /// What Enter does to this row, in a word, when that is not the menu's
    /// usual verb (`reconnect`, `enable`).
    pub verb: String,
    /// Whether choosing the row leaves the menu open (it refreshes when the
    /// command is done) instead of closing it.
    pub keep_open: bool,
    pub keys: Vec<RowKey>,
}

impl PickerRow {
    pub fn new(
        label: impl Into<String>,
        value: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            detail: detail.into(),
            ..Self::default()
        }
    }

    pub fn previewing(mut self, preview: impl Into<String>) -> Self {
        self.preview = preview.into();
        self
    }

    pub fn with_verb(mut self, verb: impl Into<String>) -> Self {
        self.verb = verb.into();
        self
    }

    /// Choosing this row runs its command but leaves the menu open.
    pub fn keeping_open(mut self) -> Self {
        self.keep_open = true;
        self
    }

    /// A key that runs `command` on this row and closes the menu.
    pub fn with_key(
        mut self,
        key: char,
        label: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        self.keys.push(RowKey {
            key,
            label: label.into(),
            command: command.into(),
            keep_open: false,
        });
        self
    }

    /// A key that runs `command` on this row and keeps the menu open.
    pub fn with_keep_key(
        mut self,
        key: char,
        label: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        self.keys.push(RowKey {
            key,
            label: label.into(),
            command: command.into(),
            keep_open: true,
        });
        self
    }
}

/// A key the footer names, and what it does. Clicking one presses the key
/// when it is a single key (`⏎`, `esc`, `r`); `↑↓` and `type` only inform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    pub key: String,
    pub label: String,
}

/// The most lines of preview a menu reserves.
pub const PREVIEW_MAX: usize = 6;

/// How many rows PageUp and PageDown move. A menu shows at most twelve, so
/// a page is a little less than a screenful on any terminal.
pub const PAGE_ROWS: usize = 8;

/// The selection overlay behind the menus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picker {
    pub kind: PickerKind,
    pub rows: Vec<PickerRow>,
    /// The selected row, counted among the rows `visible` lists.
    pub sel: usize,
    pub title: String,
    /// Two lines per row (a name, then what it is) instead of one.
    pub two_line: bool,
    /// A line the menu shows in place of its keys until the next key:
    /// what went wrong with the last thing it was asked to do.
    pub notice: Option<String>,
    /// What the menu is waiting on while a key's command runs: shown in
    /// place of the keys until the refreshed list arrives.
    pub working: Option<String>,
    /// `Some` while the filter line is open, even when it is still empty.
    filter: Option<String>,
}

impl Picker {
    pub fn new(kind: PickerKind, rows: Vec<PickerRow>, sel: usize) -> Self {
        let title = match kind {
            PickerKind::Models => "MODELS",
            PickerKind::Sessions => "SESSIONS",
            PickerKind::Command => "CHOOSE",
        };
        Self {
            kind,
            rows,
            sel,
            title: title.into(),
            two_line: kind == PickerKind::Sessions,
            notice: None,
            working: None,
            filter: None,
        }
    }

    pub fn titled(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn two_lines(mut self) -> Self {
        self.two_line = true;
        self
    }

    /// Whether the filter line is open.
    pub fn is_filtering(&self) -> bool {
        self.filter.is_some()
    }

    /// What has been typed into the filter line.
    pub fn filter_text(&self) -> &str {
        self.filter.as_deref().unwrap_or("")
    }

    /// The rows the filter lets through, as indexes into `rows`, in order.
    /// Every word typed must appear in the row's name or detail, in any
    /// case, so `mcp off` finds a disabled MCP server.
    pub fn visible(&self) -> Vec<usize> {
        let text = self.filter_text();
        if text.trim().is_empty() {
            return (0..self.rows.len()).collect();
        }
        let terms: Vec<String> = text.split_whitespace().map(str::to_lowercase).collect();
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                let haystack = format!("{} {}", row.label, row.detail).to_lowercase();
                terms.iter().all(|term| haystack.contains(term.as_str()))
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// How many rows the filter lets through.
    pub fn visible_len(&self) -> usize {
        if self.filter_text().trim().is_empty() {
            self.rows.len()
        } else {
            self.visible().len()
        }
    }

    /// The `n`th row the filter lets through.
    pub fn row_at(&self, n: usize) -> Option<&PickerRow> {
        if self.filter_text().trim().is_empty() {
            self.rows.get(n)
        } else {
            self.visible()
                .get(n)
                .and_then(|&index| self.rows.get(index))
        }
    }

    /// The selected row. A selection that points past the rows (they were
    /// replaced under it) selects nothing: Enter must never choose a row
    /// the person did not pick. Moving brings it back into range.
    pub fn selected_row(&self) -> Option<&PickerRow> {
        self.row_at(self.sel)
    }

    /// Move the selection, stopping at either end.
    pub fn move_by(&mut self, delta: isize) {
        let last = self.visible_len().saturating_sub(1);
        let from = self.sel.min(last);
        self.sel = if delta < 0 {
            from.saturating_sub(delta.unsigned_abs())
        } else {
            from.saturating_add(delta.unsigned_abs()).min(last)
        };
    }

    pub fn home(&mut self) {
        self.sel = 0;
    }

    pub fn end(&mut self) {
        self.sel = self.visible_len().saturating_sub(1);
    }

    /// Open the filter line.
    pub fn start_filter(&mut self) {
        if self.filter.is_none() {
            self.filter = Some(String::new());
            self.sel = 0;
        }
    }

    /// Type a character into the filter line.
    pub fn push_filter(&mut self, c: char) {
        if !c.is_control()
            && let Some(text) = self.filter.as_mut()
        {
            text.push(c);
            self.sel = 0;
        }
    }

    /// Delete the last typed character; with nothing left to delete, close
    /// the line. Returns whether the line is still open.
    pub fn pop_filter(&mut self) -> bool {
        match self.filter.as_mut() {
            Some(text) if !text.is_empty() => {
                text.pop();
                self.sel = 0;
                true
            }
            Some(_) => {
                self.filter = None;
                false
            }
            None => false,
        }
    }

    /// Close the filter line and show every row again.
    pub fn clear_filter(&mut self) {
        if self.filter.take().is_some() {
            self.sel = 0;
        }
    }

    /// The key binding of the selected row for this character, if it has one.
    pub fn row_key(&self, key: char) -> Option<&RowKey> {
        self.selected_row()?
            .keys
            .iter()
            .find(|row_key| row_key.key == key)
    }

    /// Replace the rows (after a refresh) and keep the same row selected:
    /// the one with the same name, else the nearest position.
    pub fn replace_rows(&mut self, rows: Vec<PickerRow>) {
        let name = self.selected_row().map(|row| row.label.clone());
        self.rows = rows;
        let visible = self.visible();
        self.sel = name
            .and_then(|name| {
                visible
                    .iter()
                    .position(|&index| self.rows[index].label == name)
            })
            .unwrap_or_else(|| self.sel.min(visible.len().saturating_sub(1)));
    }

    /// The keys the footer names for the menu as it stands.
    pub fn hints(&self) -> Vec<Hint> {
        let hint = |key: &str, label: &str| Hint {
            key: key.into(),
            label: label.into(),
        };
        if self.is_filtering() {
            return vec![
                hint("type", "to filter"),
                hint("↑↓", "move"),
                hint("⏎", self.choose_label()),
                hint("esc", "all rows"),
            ];
        }
        let mut hints = vec![hint("↑↓", "move")];
        if let Some(row) = self.selected_row() {
            if !row.value.is_empty() {
                let verb = if row.verb.is_empty() {
                    self.choose_label()
                } else {
                    row.verb.as_str()
                };
                hints.push(hint("⏎", verb));
            }
            for row_key in &row.keys {
                // A key that does what Enter does is not named twice.
                if !row.value.is_empty() && row_key.command == row.value {
                    continue;
                }
                hints.push(Hint {
                    key: row_key.key.to_string(),
                    label: row_key.label.clone(),
                });
            }
        }
        if self.rows.len() > 1 {
            hints.push(hint("/", "filter"));
        }
        hints.push(hint("esc", "close"));
        hints
    }

    /// The previews of every row, so the box can reserve room for the
    /// longest and keep its height as the selection moves and the filter
    /// narrows the list.
    pub fn previews(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|row| !row.preview.trim().is_empty())
            .map(|row| row.preview.clone())
            .collect()
    }

    fn choose_label(&self) -> &'static str {
        match self.kind {
            PickerKind::Models => "use",
            PickerKind::Sessions => "resume",
            PickerKind::Command => "choose",
        }
    }
}

/// The first of `shown` rows to draw so the selected row sits in view,
/// with a few rows of context on each side once the list is scrolling.
/// The window follows the selection alone, so moving up and down are
/// mirror images and nothing has to remember where it was.
pub fn window_top(len: usize, sel: usize, shown: usize) -> usize {
    if len <= shown || shown == 0 {
        return 0;
    }
    sel.min(len - 1).saturating_sub(shown / 2).min(len - shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn menu(labels: &[&str]) -> Picker {
        Picker::new(
            PickerKind::Command,
            labels
                .iter()
                .map(|label| PickerRow::new(*label, format!("/do {label}"), "detail"))
                .collect(),
            0,
        )
    }

    #[test]
    fn moving_stops_at_both_ends_and_survives_a_stale_selection() {
        let mut picker = menu(&["a", "b", "c"]);
        picker.move_by(-1);
        assert_eq!(picker.sel, 0);
        picker.move_by(1);
        picker.move_by(1);
        picker.move_by(1);
        assert_eq!(picker.sel, 2);
        // A selection left past the end by a shrunken list selects nothing
        // until it moves, and then moves from the last row.
        picker.sel = usize::MAX;
        assert!(picker.selected_row().is_none());
        picker.move_by(-1);
        assert_eq!(picker.sel, 1);
        picker.end();
        assert_eq!(picker.sel, 2);
        picker.home();
        assert_eq!(picker.sel, 0);
    }

    #[test]
    fn paging_moves_by_a_page_and_stops_at_the_ends() {
        let labels: Vec<String> = (0..30).map(|i| format!("row{i}")).collect();
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let mut picker = menu(&refs);
        picker.move_by(PAGE_ROWS as isize);
        assert_eq!(picker.sel, PAGE_ROWS);
        picker.move_by(100);
        assert_eq!(picker.sel, 29);
        picker.move_by(-(PAGE_ROWS as isize));
        assert_eq!(picker.sel, 29 - PAGE_ROWS);
    }

    #[test]
    fn the_filter_matches_every_word_in_the_name_or_detail_in_any_case() {
        let mut picker = Picker::new(
            PickerKind::Command,
            vec![
                PickerRow::new("github", "/x github", "stdio · enabled"),
                PickerRow::new("Notion", "/x notion", "streamable-http · disabled"),
                PickerRow::new("search", "/x search", "stdio · disabled"),
            ],
            0,
        );
        picker.start_filter();
        for c in "STDIO off".chars() {
            picker.push_filter(c);
        }
        // "off" is not a substring of "disabled": nothing matches both words.
        assert_eq!(picker.visible(), Vec::<usize>::new());
        picker.clear_filter();
        picker.start_filter();
        for c in "stdio disab".chars() {
            picker.push_filter(c);
        }
        assert_eq!(picker.visible(), vec![2]);
        assert_eq!(picker.selected_row().unwrap().label, "search");
        assert_eq!(picker.visible_len(), 1);
    }

    #[test]
    fn a_filtered_menu_selects_among_the_rows_that_remain() {
        let mut picker = menu(&["alpha", "beta", "alphabet", "gamma"]);
        picker.start_filter();
        picker.push_filter('a');
        picker.push_filter('l');
        // alpha and alphabet remain; the selection restarts at the first.
        assert_eq!(picker.visible(), vec![0, 2]);
        assert_eq!(picker.selected_row().unwrap().label, "alpha");
        picker.move_by(1);
        assert_eq!(picker.selected_row().unwrap().label, "alphabet");
        picker.move_by(5);
        assert_eq!(picker.selected_row().unwrap().label, "alphabet");
        // Narrowing again puts the selection back on the first match.
        picker.push_filter('p');
        picker.push_filter('h');
        picker.push_filter('a');
        picker.push_filter('b');
        assert_eq!(picker.sel, 0);
        assert_eq!(picker.selected_row().unwrap().label, "alphabet");
    }

    #[test]
    fn a_filter_that_matches_nothing_leaves_no_selected_row() {
        let mut picker = menu(&["a", "b"]);
        picker.start_filter();
        picker.push_filter('z');
        assert!(picker.selected_row().is_none());
        assert_eq!(picker.visible_len(), 0);
        // Moving in an empty list is harmless.
        picker.move_by(1);
        picker.end();
        assert_eq!(picker.sel, 0);
    }

    #[test]
    fn backspace_deletes_then_closes_and_escape_restores_every_row() {
        let mut picker = menu(&["a", "b"]);
        assert!(!picker.is_filtering());
        picker.start_filter();
        assert!(picker.is_filtering());
        picker.push_filter('a');
        assert!(picker.pop_filter());
        assert!(picker.is_filtering(), "an emptied line is still open");
        assert!(!picker.pop_filter(), "the next backspace closes it");
        assert!(!picker.is_filtering());
        picker.start_filter();
        picker.push_filter('b');
        assert_eq!(picker.visible_len(), 1);
        picker.clear_filter();
        assert_eq!(picker.visible_len(), 2);
        assert!(!picker.is_filtering());
    }

    #[test]
    fn control_characters_never_enter_the_filter_line() {
        let mut picker = menu(&["a"]);
        picker.start_filter();
        picker.push_filter('\u{1b}');
        picker.push_filter('\n');
        picker.push_filter('\u{7}');
        assert_eq!(picker.filter_text(), "");
        // And typing with the line closed is ignored rather than opening it.
        picker.clear_filter();
        picker.push_filter('x');
        assert!(!picker.is_filtering());
    }

    #[test]
    fn row_keys_belong_to_the_selected_row_only() {
        let mut picker = Picker::new(
            PickerKind::Command,
            vec![
                PickerRow::new("one", "/mcp show one", "up").with_key(
                    'r',
                    "reconnect",
                    "/mcp reconnect one",
                ),
                PickerRow::new("two", "/mcp show two", "down"),
            ],
            0,
        );
        assert_eq!(
            picker.row_key('r').map(|key| key.command.as_str()),
            Some("/mcp reconnect one")
        );
        assert!(picker.row_key('x').is_none());
        picker.move_by(1);
        assert!(picker.row_key('r').is_none());
    }

    #[test]
    fn replacing_rows_keeps_the_same_row_selected_by_name() {
        let mut picker = menu(&["a", "b", "c"]);
        picker.move_by(2);
        assert_eq!(picker.selected_row().unwrap().label, "c");
        // The list is refreshed with a row inserted before the selection.
        picker.replace_rows(
            ["a", "x", "b", "c"]
                .iter()
                .map(|label| PickerRow::new(*label, "", ""))
                .collect(),
        );
        assert_eq!(picker.selected_row().unwrap().label, "c");
        // A row that vanished leaves the selection in bounds.
        picker.replace_rows(vec![PickerRow::new("a", "", "")]);
        assert_eq!(picker.selected_row().unwrap().label, "a");
        picker.replace_rows(Vec::new());
        assert!(picker.selected_row().is_none());
    }

    #[test]
    fn previews_lists_only_the_rows_that_have_one() {
        let mut picker = menu(&["a", "b", "c"]);
        assert!(picker.previews().is_empty());
        picker.rows[0].preview = "one\ntwo".into();
        picker.rows[2].preview = "   ".into();
        assert_eq!(picker.previews(), vec!["one\ntwo".to_string()]);
    }

    #[test]
    fn a_key_that_does_what_enter_does_is_named_once() {
        let picker = Picker::new(
            PickerKind::Command,
            vec![
                PickerRow::new("one", "/mcp reconnect one", "x")
                    .with_verb("reconnect")
                    .with_keep_key('r', "reconnect", "/mcp reconnect one")
                    .with_keep_key('e', "disable", "/mcp disable one"),
            ],
            0,
        );
        let names: Vec<_> = picker.hints().iter().map(|h| h.key.clone()).collect();
        assert_eq!(names, ["↑↓", "⏎", "e", "esc"]);
        // The key still works; only the footer is spared the repeat.
        assert!(picker.row_key('r').is_some());
    }

    #[test]
    fn a_rows_own_verb_labels_its_enter_hint() {
        let picker = Picker::new(
            PickerKind::Command,
            vec![PickerRow::new("github", "/mcp reconnect github", "up").with_verb("reconnect")],
            0,
        );
        let enter = picker
            .hints()
            .into_iter()
            .find(|hint| hint.key == "⏎")
            .unwrap();
        assert_eq!(enter.label, "reconnect");
    }

    #[test]
    fn the_footer_names_the_row_keys_and_changes_while_filtering() {
        let mut picker = Picker::new(
            PickerKind::Command,
            vec![
                PickerRow::new("one", "/a", "x").with_key('r', "reconnect", "/mcp reconnect one"),
                PickerRow::new("two", "/b", "y"),
            ],
            0,
        );
        let names = |hints: &[Hint]| hints.iter().map(|h| h.key.clone()).collect::<Vec<_>>();
        assert_eq!(names(&picker.hints()), ["↑↓", "⏎", "r", "/", "esc"]);
        picker.move_by(1);
        assert_eq!(names(&picker.hints()), ["↑↓", "⏎", "/", "esc"]);
        picker.start_filter();
        assert_eq!(names(&picker.hints()), ["type", "↑↓", "⏎", "esc"]);
    }

    #[test]
    fn a_row_with_nothing_to_choose_has_no_enter_hint_and_a_single_row_no_filter_hint() {
        let picker = Picker::new(
            PickerKind::Command,
            vec![PickerRow::new("only", "", "read only")],
            0,
        );
        let names: Vec<_> = picker.hints().iter().map(|h| h.key.clone()).collect();
        assert_eq!(names, ["↑↓", "esc"]);
    }

    #[test]
    fn the_window_keeps_the_selection_in_view_and_never_leaves_blank_rows() {
        // Short lists never scroll.
        assert_eq!(window_top(5, 4, 12), 0);
        assert_eq!(window_top(12, 11, 12), 0);
        // A long list centres the selection once it is past the middle...
        assert_eq!(window_top(40, 0, 12), 0);
        assert_eq!(window_top(40, 5, 12), 0);
        assert_eq!(window_top(40, 20, 12), 14);
        // ...and stops at the end rather than showing empty rows.
        assert_eq!(window_top(40, 39, 12), 28);
        // The selection is inside the window everywhere, going up or down.
        for len in [13usize, 28, 100] {
            for shown in [1usize, 2, 5, 12] {
                for sel in 0..len {
                    let top = window_top(len, sel, shown);
                    assert!(top <= sel && sel < top + shown, "{len} {shown} {sel} {top}");
                    assert!(top + shown <= len);
                }
            }
        }
        // A stale selection past the end and a zero-row window are bounded.
        assert_eq!(window_top(10, usize::MAX, 4), 6);
        assert_eq!(window_top(10, 3, 0), 0);
    }
}

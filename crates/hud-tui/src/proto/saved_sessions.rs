//! The saved-sessions list the sidebar and the Sessions pane show: what the
//! worker last sent, which row is selected, and when to ask again.
//!
//! Asking costs the worker a bounded scan of the newest session files, so it
//! happens only while the list is on screen, never during a turn, and at most
//! once every few seconds. Nothing here runs on a timer of its own.

use crate::msg::SavedSession;

/// The least time between two requests.
pub const MIN_GAP_MS: u64 = 5_000;

/// The most rows kept. The worker sends a handful; this bounds what a
/// frame can ever iterate, whatever arrives.
pub const MAX_ROWS: usize = 64;

#[derive(Debug, Clone, Default)]
pub struct SavedSessions {
    /// The newest saved sessions of this folder, as the worker listed them.
    pub rows: Vec<SavedSession>,
    /// The row the Sessions pane has selected (keys move it, ⏎ resumes it).
    pub selected: usize,
    pending: bool,
    loaded: bool,
    /// When the last request went out, answered or not: the gap is counted
    /// from here, so a worker that never answers is not asked in a loop.
    asked_ms: Option<u64>,
    dirty: bool,
    seen: Option<(String, u64)>,
}

impl SavedSessions {
    /// Note the session the screen is on. A different one, or one more turn
    /// in it, makes the list out of date.
    pub fn observe(&mut self, session_id: &str, turns: u64) {
        let unchanged = self
            .seen
            .as_ref()
            .is_some_and(|(id, seen_turns)| id == session_id && *seen_turns == turns);
        if !unchanged {
            self.seen = Some((session_id.to_owned(), turns));
            self.dirty = true;
        }
    }

    /// Something the list shows changed on disk (a rename, for one).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Ask again as soon as the list is on screen and idle, without waiting
    /// out the gap (the person pressed `r`).
    pub fn refresh_now(&mut self) {
        self.dirty = true;
        self.asked_ms = None;
    }

    /// Whether to ask the worker now: the list is on screen, nothing is
    /// running, no request is out, and either nothing was ever asked or the
    /// list is out of date and was last asked for a few seconds ago.
    pub fn due(&self, visible: bool, busy: bool, now_ms: u64) -> bool {
        visible
            && !busy
            && !self.pending
            && match self.asked_ms {
                None => true,
                Some(at) => self.dirty && now_ms.saturating_sub(at) >= MIN_GAP_MS,
            }
    }

    /// A request is on its way. Anything that changes from now on makes the
    /// list out of date again, so the flag is cleared here, not on arrival.
    pub fn requested(&mut self, now_ms: u64) {
        self.pending = true;
        self.dirty = false;
        self.asked_ms = Some(now_ms);
    }

    /// The request could not be sent. It is tried again after the gap.
    pub fn request_failed(&mut self) {
        self.pending = false;
        self.dirty = true;
    }

    /// The worker's answer. The selection stays on the same session when it
    /// is still listed.
    pub fn receive(&mut self, mut rows: Vec<SavedSession>) {
        rows.truncate(MAX_ROWS);
        let kept = self.rows.get(self.selected).map(|row| row.id.clone());
        self.rows = rows;
        self.selected = kept
            .and_then(|id| self.rows.iter().position(|row| row.id == id))
            .unwrap_or(self.selected)
            .min(self.rows.len().saturating_sub(1));
        self.pending = false;
        self.loaded = true;
    }

    /// Move the selection `delta` rows, staying inside the list.
    pub fn select(&mut self, delta: isize) {
        let last = self.rows.len().saturating_sub(1);
        self.selected = self.selected.saturating_add_signed(delta).min(last);
    }

    /// Select row `index`, or the last row when it is past the end.
    pub fn select_at(&mut self, index: usize) {
        self.selected = index.min(self.rows.len().saturating_sub(1));
    }

    /// The selected row and its index in the list.
    pub fn selected_row(&self) -> Option<(usize, &SavedSession)> {
        self.rows.get(self.selected).map(|row| (self.selected, row))
    }

    /// Whether the worker has answered at least once.
    pub fn loaded(&self) -> bool {
        self.loaded
    }

    /// Whether `row` is the session this screen is on. The live id decides:
    /// the list can be a few seconds older than a resume, and its own flag
    /// would then mark the session the screen has just left. The flag is the
    /// answer only while the screen does not know its id yet.
    pub fn is_current(row: &SavedSession, session_id: &str) -> bool {
        if session_id.is_empty() {
            row.current
        } else {
            row.id == session_id
        }
    }

    /// The row of the session this screen is on, if it is in the list.
    pub fn current_index(&self, session_id: &str) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| Self::is_current(row, session_id))
    }

    /// Every row but the open session's, each with its place in the list:
    /// what the sidebar shows under the open session's own live row.
    pub fn others<'a>(
        &'a self,
        session_id: &'a str,
    ) -> impl Iterator<Item = (usize, &'a SavedSession)> + 'a {
        self.rows
            .iter()
            .enumerate()
            .filter(move |(_, row)| !Self::is_current(row, session_id))
    }

    /// How many sessions the sidebar counts: the listed ones, plus the open
    /// session when it has nothing saved yet (a new one) and so is not listed.
    pub fn count_with_open(&self, session_id: &str) -> usize {
        self.rows.len() + usize::from(self.current_index(session_id).is_none())
    }
}

/// The first of `visible` rows to draw so that `selected` is on screen, in a
/// list of `len` rows: the window that ends on the selection once it passes
/// the bottom (the rule the Changes list follows), and never one that shows
/// empty space below the last row while earlier rows exist.
pub fn first_visible(selected: usize, visible: usize, len: usize) -> usize {
    let visible = visible.max(1);
    let last_first = len.saturating_sub(visible);
    (selected + 1).saturating_sub(visible).min(last_first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, current: bool) -> SavedSession {
        SavedSession {
            id: id.into(),
            title: format!("title of {id}"),
            model: "m".into(),
            turns: 2,
            age: "3m ago".into(),
            current,
        }
    }

    #[test]
    fn nothing_is_requested_while_the_list_is_hidden_or_a_turn_runs() {
        let mut list = SavedSessions::default();
        assert!(!list.due(false, false, 10_000), "hidden");
        assert!(!list.due(true, true, 10_000), "a turn is running");
        assert!(
            list.due(true, false, 10_000),
            "first time, visible and idle"
        );
        list.requested(10_000);
        assert!(!list.due(true, false, 99_000), "a request is already out");
    }

    #[test]
    fn a_fresh_list_stays_until_the_session_changes_and_then_waits_out_the_gap() {
        let mut list = SavedSessions::default();
        list.observe("session-a", 0);
        list.requested(1_000);
        list.receive(vec![row("session-a", true)]);
        assert!(!list.due(true, false, 60_000), "nothing changed since");

        list.observe("session-a", 1); // a turn ended
        assert!(!list.due(true, false, 3_000), "too soon after the last ask");
        assert!(list.due(true, false, 1_000 + MIN_GAP_MS), "after the gap");

        list.requested(7_000);
        list.observe("session-a", 1);
        list.receive(vec![row("session-a", true)]);
        assert!(
            !list.due(true, false, 90_000),
            "an unchanged session adds nothing"
        );

        list.observe("session-b", 0); // resumed another one
        assert!(list.due(true, false, 90_000));
    }

    #[test]
    fn a_change_while_a_request_is_out_asks_again_afterwards() {
        let mut list = SavedSessions::default();
        list.observe("session-a", 0);
        list.requested(0);
        list.observe("session-a", 1);
        list.receive(vec![row("session-a", true)]);
        assert!(list.due(true, false, MIN_GAP_MS));
    }

    #[test]
    fn a_failed_send_is_not_retried_in_a_loop_and_a_rename_marks_the_list_stale() {
        let mut list = SavedSessions::default();
        list.requested(100);
        list.request_failed();
        assert!(
            !list.due(true, false, 150),
            "a dead worker is not asked again on every tick"
        );
        assert!(list.due(true, false, 100 + MIN_GAP_MS), "after the gap");
        list.requested(100 + MIN_GAP_MS);
        list.receive(Vec::new());
        assert!(!list.due(true, false, 200 + MIN_GAP_MS), "unchanged");
        list.mark_dirty();
        assert!(!list.due(true, false, 200 + MIN_GAP_MS), "inside the gap");
        assert!(list.due(true, false, 100 + 2 * MIN_GAP_MS));
    }

    #[test]
    fn a_refresh_asked_for_by_hand_skips_the_gap_but_not_a_running_turn() {
        let mut list = SavedSessions::default();
        list.requested(1_000);
        list.receive(vec![row("a", false)]);
        assert!(!list.due(true, false, 1_200));
        list.refresh_now();
        assert!(list.due(true, false, 1_200), "no waiting");
        assert!(!list.due(true, true, 1_200), "still never during a turn");
        assert!(list.loaded(), "the old rows stay on screen meanwhile");
    }

    #[test]
    fn the_selection_stays_inside_the_list_and_follows_its_session_across_a_refresh() {
        let mut list = SavedSessions::default();
        list.select(1);
        assert_eq!(list.selected_row(), None, "an empty list selects nothing");
        list.receive(vec![row("a", false), row("b", false), row("c", false)]);
        list.select(1);
        list.select(1);
        list.select(1);
        assert_eq!(list.selected, 2, "stops at the last row");
        list.select(-9);
        assert_eq!(list.selected, 0, "and at the first");
        list.select(1);
        assert_eq!(
            list.selected_row().map(|(_, row)| row.id.as_str()),
            Some("b")
        );
        // a refresh that puts a newer session in front: still on "b"
        list.receive(vec![row("new", false), row("a", false), row("b", false)]);
        assert_eq!(list.selected, 2);
        // a refresh without it: clamped
        list.receive(vec![row("x", false)]);
        assert_eq!(list.selected, 0);
    }

    #[test]
    fn the_live_id_decides_which_row_is_current_not_a_stale_flag() {
        let mut list = SavedSessions::default();
        list.receive(vec![row("a", false), row("b", true), row("c", false)]);
        assert_eq!(list.current_index(""), Some(1), "the flag, before an id");
        // the screen has since resumed "c": the flag on "b" is out of date
        assert_eq!(list.current_index("c"), Some(2));
        assert!(!SavedSessions::is_current(&list.rows[1], "c"));
        assert_eq!(list.current_index("not-listed"), None);
        let others: Vec<usize> = list.others("c").map(|(i, _)| i).collect();
        assert_eq!(others, [0, 1], "keeps each row's place in the whole list");
    }

    #[test]
    fn a_runaway_list_is_cut_to_a_bound() {
        let mut list = SavedSessions::default();
        list.receive((0..500).map(|n| row(&format!("s{n}"), false)).collect());
        assert_eq!(list.rows.len(), MAX_ROWS);
        assert_eq!(list.rows[0].id, "s0", "the newest are the ones kept");
    }

    #[test]
    fn a_new_session_that_is_not_listed_yet_still_counts() {
        let mut list = SavedSessions::default();
        list.receive(vec![row("a", false), row("b", false)]);
        assert_eq!(list.count_with_open("fresh"), 3);
        assert_eq!(list.count_with_open("a"), 2);
    }

    #[test]
    fn the_window_moves_only_when_the_selection_leaves_it() {
        // 8 rows, 3 visible
        assert_eq!(first_visible(0, 3, 8), 0);
        assert_eq!(first_visible(2, 3, 8), 0, "last visible row: no move yet");
        assert_eq!(first_visible(3, 3, 8), 1, "one past it: just enough");
        assert_eq!(first_visible(7, 3, 8), 5, "the end shows the last three");
        assert_eq!(first_visible(7, 20, 8), 0, "everything fits");
        assert_eq!(
            first_visible(5, 0, 8),
            5,
            "a zero-height pane acts as one row"
        );
        assert_eq!(first_visible(0, 3, 0), 0);
    }
}

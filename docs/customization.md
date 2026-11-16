# Customize your workspace

ORBIT uses one versioned profile for terminal and browser preferences. Inspect
what is effective, then change a setting or import a portable profile:

```sh
orbit customize show --json
orbit customize capabilities --json
orbit customize theme midnight
orbit customize set theme midnight
orbit customize set colors.accent '#8A91FF'
orbit customize set density compact
orbit customize set glyphs ascii
orbit customize set reduced_motion true
orbit customize set layout.preset review
orbit customize set browser.font_family 'Fira Code, monospace'
orbit customize set browser.font_size_px 15
orbit customize reset colors.accent
```

Themes are `orbit`, `midnight`, `paper`, `aespa-pastel`, and `kwangya-ice`. Color values are `#RRGGBB`; unknown
settings, tokens, and malformed values are refused before saving. `colors.NAME`
and `token_overrides.NAME` address the same validated token. `customize show`
reports effective values and their source. `reset KEY` resets one preference;
`reset` removes the canonical profile and returns to legacy/default preferences.
Legacy `tui.toml` remains intact. To reset the whole profile, run `orbit customize reset`.

In the terminal, `/theme NAME`, `/customize ...`, and `/customize reload` use the
same store. Settings commands do not call a model. Choose pane and layout actions
through the existing arrange controls and command palette. Narrow terminals use
focused panes/tabs. A profile always retains one Conversation pane and composer.

Color is resolved before gradients and terminal conversion. `color_mode` accepts
`auto`, `truecolor`, `256`, `16`, or `mono`; it cannot exceed the terminal's
detected capability, and `NO_COLOR` wins. Density is `comfortable` or `compact`;
glyphs are `auto`, `unicode`, or `ascii`. Reduced motion disables motion effects.

Browser font settings use literal family names already available to your browser,
with up to eight comma-separated names and a size from 10 to 24 pixels. They do
not fetch fonts. **Terminal font family and size belong to your terminal
application**; changing the browser setting cannot change the terminal emulator.

## Keys and vim editing

`$ORBIT_HOME/keybindings.toml` rebinds keys in the terminal. It is read once at
start; a mistake in it is reported in a toast and no bindings apply.

```toml
[keys]
"ctrl+k" = "ctrl+w"   # send another key instead
"f5"     = "/compact" # run a slash command
"alt+m"  = "/model"
"f1"     = "none"     # ignore the key
```

Keys are written as optional `ctrl+`, `alt+` and `shift+` followed by a character
or one of `enter`, `esc`, `tab`, `space`, `backspace`, `delete`, `insert`, `up`,
`down`, `left`, `right`, `home`, `end`, `pageup`, `pagedown`, `plus`, `f1`–`f12`.
A binding replaces the key everywhere, bindings do not chain, and `Ctrl+C` and
`Ctrl+D` cannot be rebound. A key bound to a slash command runs it only when the
composer is focused and empty. Whether a chord with `ctrl` or `alt` reaches ORBIT
at all depends on your terminal. `--safe-customization` skips the file.

`Ctrl+G` opens the draft in `$VISUAL` or `$EDITOR` and takes back what you save.
`Ctrl+S` sets a draft aside, and brings it back when the composer is empty.
`ORBIT_BELL=1` rings the terminal bell after a turn of ten seconds or more;
`ORBIT_BELL=notify` also sends an OSC 9 desktop notification, which only some
terminals show.

Start ORBIT with `ORBIT_VIM=1` for vim-style editing in the composer. `Esc`
enters NORMAL mode, where `h l 0 ^ $ w b e` move, `i a I A` insert, and
`x D C dd cc`, `d`/`c` with a motion, `p P` and one level of `u` edit. It covers
a single line; counts, visual mode, text objects and `.` are not implemented.

## Import and export

```sh
orbit customize export portable-profile.json
orbit customize validate portable-profile.json
orbit customize import portable-profile.json
```

Export creates a new file and refuses to overwrite one. It excludes managed
state and refuses profiles containing detected secret literals or local private
paths. A profile contains appearance, layout, and inert pane declarations; it
contains no signing key, token values, session history, grants, or installation
state. Import validates the complete candidate before replacing stored settings.
Unknown fields, unsafe paths, invalid layout trees, and unsupported versions fail
without changing the old profile.

Malformed stored profile or legacy files produce a visible error. For a temporary
recovery session, start `orbit chat --safe-customization`. This uses read-only
session defaults and preserves the original files for explicit repair.

## Add named panes

A profile is JSON with `schema_version: 1`. Omitted fields take defaults. This
small profile places a named notes pane beside the conversation:

```json
{
  "schema_version": 1,
  "name": "Project notes",
  "theme": "midnight",
  "layout": {
    "preset": "custom",
    "tree": {
      "kind": "split",
      "dir": "right",
      "shares": [70, 30],
      "children": [
        {"kind": "panel", "view": "conversation"},
        {"kind": "custom", "pane_id": "notes"}
      ]
    }
  },
  "panes": [{
    "id": "notes",
    "title": "Notes",
    "surfaces": ["terminal", "browser"],
    "source": {"kind": "markdown_file", "path": "notes.md"},
    "actions": [
      {"kind": "refresh"},
      {"kind": "focus_conversation"},
      {"kind": "insert_prompt", "text": "Review the project notes"}
    ]
  }]
}
```

Sources are literal `text`, a workspace-relative `markdown_file`, or a `snapshot`
of `routing`, `usage`, `agents`, `scope`, `evidence`, `findings`, `council`, or
`reactor`. File reads use
the current workspace's Read permission and display scanning. Missing, denied,
stale, and truncated content is labeled. Counts describe local files, not proof
of a finding. Context snapshots become stale when the session changes.

### Built-in panes: `council` and `reactor`

Two panes exist without a profile entry, so the default profile keeps
`"panes": []`. Place them with `{"kind":"custom","pane_id":"council"}` (or
`"reactor"`) in a layout tree, or pick them in the terminal: while arranging,
`v`/`s`/`p` opens "Show what?", where `9` is Council and `0` is Reactor. A
profile pane that reuses either id replaces the built-in. While the terminal
layout shows a built-in pane it is re-read once a second; other panes refresh
on `r`. The browser renders them as text and refreshes on demand. In the
terminal they are coloured from the active palette: seat identity, verdicts,
and the meters. When the council pane is wide and tall enough (about 15
columns per seat, up to four seats) it draws one card per seat: lab, model, an
equaliser while the seat deliberates, and its verdict. When the reactor pane
is at least 50 columns wide it draws the Kwangya scene beside the meters, with
the output rate in large digits when they fit; the scene moves faster during a
turn. `reduced_motion` holds both still; `glyphs: ascii` keeps the plain text.

- `council` (snapshot `council`) shows the MAGI council: phase, one row per
  seat with its model and verdict, and the latest note. It reads one file,
  `$ORBIT_COUNCIL_STATE` (absolute path) or `~/.local/share/magi/state.json`.
  This is the only pane source outside the workspace. The location comes from
  the environment or the built-in default, never from profile data. The read
  is read-only, capped at 64 KiB, and refuses symlinks and non-regular files.
  A missing file shows "No council has run"; a state older than 120 seconds
  shows as an idle council. While the council is idle, the pane also shows the
  last conclusion from `history.jsonl` beside the state file (same read rules,
  last 256 KiB only).
- `reactor` (snapshot `reactor`) shows the ORBIT session's own token flow:
  model, phase, input and output totals, context fill, cost, turns, and tools
  this turn. It reads session state only. A value the session did not report
  prints as `—`, never `0`. The `cache` line (cache read, cache write and
  reasoning tokens) counts finished turns since ORBIT opened the session in
  this process; it is not saved and starts again on resume. `tok/s` is the
  last finished turn's output tokens over the whole turn, tool time included;
  while text streams it is an estimate marked `≈ … live`; `rate` is a
  sparkline of recent turns. An unpriced or
  incompletely accounted cost is marked `(uncertain)`.

With `glyphs: ascii` both panes print ASCII marks and English labels.

Actions are `refresh`, `focus_conversation`, `insert_prompt`, and `owner_cancel`.
An inserted prompt changes the draft only; sending remains your action.
Cancellation requires the current controller. Profile data cannot execute shell
commands, JavaScript, hooks, or network requests.

Profiles are bounded to 128 KiB, 32 named panes, 24 layout leaves, depth 8, eight
children per split, and eight actions per pane. Literal pane text is at most
16 KiB; Markdown files are at most 64 KiB. Pane output is at most 32 KiB and
512 lines. These bounds keep layout and rendering predictable.

## Instruction mods and signed content

Existing instruction mods still provide guidance text and named prompt commands.
They are separate from declarative appearance/pane profiles. Signed packages
verify stored non-executing content. ORBIT does not implement Claude Mods'
JavaScript component or extension APIs. Use `customize capabilities` to inspect
ORBIT's actual supported surfaces rather than assuming source compatibility.

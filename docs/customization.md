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
same store. `/theme` with no name opens a menu of the themes, with the one in use
marked; choosing a row is the same as typing `/theme NAME`. Settings commands do
not call a model. Choose pane and layout actions
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

### Built-in panes: `council`, `reactor` and `sessions`

Three panes exist without a profile entry, so the default profile keeps
`"panes": []`. Place them with `{"kind":"custom","pane_id":"council"}` (or
`"reactor"`, `"sessions"`) in a layout tree, or pick them in the terminal:
while arranging, `v`/`s`/`p` opens "Show what?", where `9` is Council, `0` is
Reactor and `s` is Sessions. A profile pane that reuses one of these ids
replaces the built-in. While the terminal
layout shows a built-in pane Council state is refreshed once a second;
Reactor follows live turn updates at the animation cadence. Other panes refresh
on `r`. The browser renders them as text and refreshes on demand. In the
terminal they are coloured from the active palette: seat identity, verdicts,
and the meters. The council pane follows the standalone MAGI pane. From 44
columns it draws four cards side by side, one per seat: an accent name plate,
the provider, the model (cut with an ellipsis when it is long), a body that
shows what the seat is doing (a twinkling field at rest, scanning bars during
triage, a sweep while it connects, bars while it deliberates, a large stamp of
its verdict once it has voted) and a footer: YES, NO or HOLD, with a crown on
the seats that carried the last council's choice. Narrower, the fourth seat
becomes a one-line chip below three cards, and a pane too narrow for cards lists
the seats. A strip beneath names the majority, the winner and the judge's
conclusion; the footer shows the phase and the record of past councils, and the
header the local time. The pane keeps the standalone pane's pace: eight frames
a second while a council runs (the verdict included), six for the triage verdict
and for a failure, two at rest so the field still twinkles and the cursor still
blinks, and one every five seconds after ten quiet minutes; a terminal that is
not focused, or `reduced_motion`, stops it. A triage verdict settles back to
idle after 20 seconds. When the reactor pane
is at least 50 columns wide it draws the selected scene beside the meters, with
the output rate in large digits when they fit; the scene moves faster during a
turn. `reduced_motion` holds both still; `glyphs: ascii` keeps the plain text.

- `council` (snapshot `council`) shows phase, seats, configured models and
  verdicts for the current session. In the terminal, run `/council QUESTION` to
  start a native deliberation; its pane action inserts `/council ` into the draft. Opening or
  refreshing the pane makes no provider request. Native state takes priority
  over an external MAGI feed. An explicit `$ORBIT_COUNCIL_STATE` absolute path
  can provide that feed; otherwise a bound session reads
  `~/.local/share/magi/sessions/SESSION_ID/state.json`. The legacy
  `~/.local/share/magi/state.json` is used only without a bound session.
  These external reads are read-only, capped at 64 KiB, and refuse symlinks and
  non-regular files. Missing state shows "No council has run"; external state
  older than 420 seconds appears idle. The matching `history.jsonl` contributes
  the last conclusion (same read rules, last 256 KiB only). Structured state and
  text both pass display scanning before rendering.
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
- `sessions` lists this folder's saved sessions, newest first, two lines each:
  the name (`/rename`) or the first words of the conversation, how long ago it
  was saved, the model and the number of turns. The open session has a filled
  dot. It is drawn by the terminal only (the browser has no such pane). A
  click on a row, or `j`/`k` (or the wheel) and `⏎`, resumes that session like
  `/resume`; while a turn is running it waits. `r` lists again at once. The
  list is read from the newest session files only (at most 48 are opened), only
  while the pane or the sidebar is on screen and never during a turn, and at
  most every 5 seconds. The sidebar's SESSIONS section shows the same list
  (the open session, then up to four others, as many as the height allows) and
  its rows are clickable too, except while the layout is being arranged.

With `glyphs: ascii` every pane prints ASCII marks, and the council and
reactor panes print English labels.

A build only knows the built-in panes it was released with. A saved layout
that places a pane an older build lacks (for example `sessions` in 0.2.2) makes
that build stop at start with `invalid customization: layout.tree: custom pane
reference is unresolved`, and its own `orbit customize reset` cannot repair the
file. Close the pane in a current build, or delete `~/.orbit/customization.json`
(its `.bak` is only the previous write). Running an older build against the
same home as a newer one is where this happens.

### Run a native Council

In terminal chat, `/council QUESTION` runs bounded, tool-free seat requests followed by a judge's
synthesis. The default is three named perspectives using the selected model,
with the same model as judge; the pane shows those configured bindings rather
than claiming different upstream models. Each request uses ordinary managed
accounting. Provider usage can incur charges; no automatic retry or automatic
run occurs when a pane opens. `Esc` cancels the foreground Council and prevents
later seats from starting. The completed answer is saved in the conversation.

In a normal session, the owner's `UserPromptSubmit` policy runs once before
deliberation. A denial stops seat requests; accepted prompt rewrites and context
apply to every participant. Command, HTTP and managed tool-free prompt handlers
are supported for this gate. Asynchronous, agent and MCP submission handlers are
refused before execution. `--bare` suppresses this gate as it does other hooks.
Generated seat and judge requests do not trigger the hooks again.

Council accepts a text question. Attachments and automatic plan prompts receive
an explicit refusal before deliberation. On resume, a saved reply may be shown
with an execution-metadata-unavailable label; ORBIT does not reconstruct past
seat identities or claim a verified Council run from conversation text alone.

For a roster of two to four declared models, create `council.toml` in the ORBIT
home:

```toml
seats = ["provider/model-a", "provider/model-b", "provider/model-c"]
judge = "provider/model-c"
max_output_tokens = 1024
# Optional budget for the whole Council, in microdollars:
# max_cost_microdollars = 500000
```

Every model must already exist in the provider registry. The roster is resolved
before any request; invalid configuration starts no deliberation. Omit `judge`
to use the selected model. `max_output_tokens` accepts 64 through 4096 per
request. The optional whole-Council budget refuses work when historical cost
cannot be established. Council does not launch the external MAGI script or
read Claude credentials.

The browser can display Council state, but native Council execution currently
requires terminal chat. Browser Council run actions return that guidance before
submitting a provider request.

`/clear` starts a fresh saved session and keeps the pane layout, selected art and
configuration. Council switches to the new session; its previous verdict and
Reactor's measured rates are cleared from the live view. The next Council runs
against the new binding, while the previous saved conversation remains available.

Outside bare mode, session-start hooks receive the current `session_id` and
`transcript_path` after clear, interactive resume or fork. Hook-based attachments
should use those values on every start and include `clear` in their matcher.
Current session-start context reaches Council after the owner submission policy's
rewrite and is included in request preflight; it does not import earlier chat or
grant tools. Asynchronous model lifecycle handlers are refused with a diagnostic.
If a model hook or its accounting has not settled, further work waits while the
panes stay bound to the committed session and show unverified cost information.

### Switch Reactor art

Use `/reactor art kwangya|shard|spine|globe|rotate`, or select the Reactor pane's
`next art` action to cycle scenes. `/reactor art next` cycles the same sequence.
`/reactor` with no art opens a menu of the five.
`rotate` changes among the four scenes every 40 seconds. Reduced motion freezes
the scene and rotation; ASCII mode keeps the text-only meter.

The selection is a portable profile setting, so it survives reopening ORBIT
and profile export/import. The command-line equivalent is:

```sh
orbit customize set reactor_art globe
orbit customize set reactor_art next
orbit customize reset reactor_art
```

Changing art is a checked appearance update and sends no provider request.

Actions are `refresh`, `focus_conversation`, `insert_prompt`, `owner_cancel`, and
`cycle_reactor_art`.
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

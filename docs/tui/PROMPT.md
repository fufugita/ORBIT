# ORBIT TUI: build prompt

> **For the person handing this over.** Give the agent this whole file plus every PNG listed in §2 (they are in `docs/tui/img/`) and the golden text frames in `docs/tui/golden/`. If the agent works inside the ORBIT repository, those paths already resolve. Otherwise attach the images and golden files with the same file names. Everything below this box is written to the agent.

---

## 1. Your task

You are implementing the visual and interaction design of **ORBIT's terminal UI**, the ratatui 0.30 + crossterm 0.29 front-end in `crates/hud-tui`, plus the small amount of TUI wiring in `crates/cli/src/tui_worker.rs` and the TUI launch block in `crates/cli/src/main.rs` that the design needs.

The design is finished. Your job is to build it exactly: every colour, glyph, column offset, state and key described here and shown in the reference images. Do not redesign, restyle or "improve" anything. Where this prompt decides something, follow the decision even if you would have chosen differently. Where something is genuinely undecidable from this prompt, the images and the golden frames, stop and ask rather than guess.

You are done when every item in §17 (acceptance checklist) is true, every test in §16 passes, the repository's checks pass (`cargo fmt --check`, `cargo clippy --workspace --tests -- -D warnings`, `cargo test --workspace`, `cargo deny check`), and you have reported back as described in §18.

## 2. Look first: use vision on the reference images

**Use your vision capability to open and study every image below before you write any code.** In Claude Code, open a PNG with the Read tool on its path. Other agents: use whatever image-viewing tool you have. If you cannot view images, stop and say so; do not build this from the text alone.

Work through the images in this order:

1. Read the golden screens (A).
2. Read the layout blueprint.
3. Read the annotated blueprints. Their callout numbers point at the sections of this prompt.
4. Read the component sheets, including the motion sheets, and the motion timeline.
5. Before you implement each component, open its image again.
6. When you compare your output with the design (§16.4), open the images a third time.

All screens were rendered from one component library at real terminal sizes, with the exact token colours of §6. Cell backgrounds and glyph strokes use the exact token colours; only antialiased glyph edges are blends. The text frames in `docs/tui/golden/` are the same screens as plain text, cell for cell. For the true-colour screens, `docs/tui/golden/<name>.styles.json` also gives the token of every cell (§16.2).

**About the cursor in the PNGs.** The thin vertical bar at the composer's insertion point (and after the palette query) depicts the terminal's **real cursor**. It is not a cell. The golden text has a space there, and the `cursor` field of the style map records where the terminal cursor must be.

**A. Golden screens.** These must be reproduced exactly: characters from the text frame, colours from the PNG.

| File | Size (cols × rows) | What it shows |
|---|---|---|
| `wide_idle.png` | 150 × 44 | Wide layout, idle after a verified turn. Conversation focused; Sessions rail unfocused with its cursor row; Workspace plan at `verify 4/5`. |
| `wide_streaming.png` | 150 × 44 | ORBIT working: live (cyan) turn, a running tool with a live output tail behind a cyan rule, a queued tool, a queued prompt, the turning star in the status line. |
| `wide_approval.png` | 150 × 44 | An approval pending: the magenta card replaces the composer, with every optional field supplied (risk badge, facts grid). |
| `narrow.png` | 80 × 30 | Narrow single view: view switcher in row 0, a tool-first live turn, streaming text ending at the cyan live edge, status level 2. |
| `tiers.png` | 4 × (66 × 20) | One compact screen in four capability tiers: true colour, 16 colours, monochrome, monochrome + ASCII. |
| `min_size.png` | 38 × 9 | The size notice shown below 40 × 10. |

**B. Other screens.** These are also golden. Their text frames are in `docs/tui/golden/`.

| File | Size | What it shows |
|---|---|---|
| `welcome.png` | 112 × 34 | Medium layout, empty session: expanded mark, tagline, readiness row (only when data exists, §13), starters, empty Workspace rail. |
| `medium.png` | 120 × 36 | Medium layout: Conversation │ Workspace. |
| `medium_sessions.png` | 120 × 36 | Medium layout while Sessions has focus: Sessions │ Conversation, Workspace hidden. |
| `compact.png` | 70 × 24 | Compact single view: no timestamps, tool meta without durations. |
| `tight.png` | 50 × 20 | Tight single view: no hint row, status level 3, tool-first live turn. |
| `sessions_view.png` | 80 × 24 | Narrow Sessions view at full width. |
| `palette.png` | 150 × 44 | The command palette over the wide idle screen. |
| `help.png` | 150 × 44 | The keys overlay over the wide idle screen. |
| `welcome_waiting.png` | 112 × 34 | The first prompt of an empty session, waiting for its first output (M9). The mark and tagline keep their rows, the readiness row and starters are gone, and the transcript is bottom-anchored. Brand tier `anim`: the star orbits the `O` in cyan, shown at station 6, and the status star shows `◒`. |

**C. Component sheets.** Every state of one component, with a caption above each piece. These are reference, not golden.

| File | What it shows |
|---|---|
| `conv_states.png` | Waiting line, streaming line, every tool-line state (with `◆`/`◈` authority markers, blocked, failed detail), tool lines with *today's* runtime data, error cards, notices, redaction chips. |
| `status_states.png` | The status line in every state, including blank connection slot, turn report, failed turn, standing grant, unpriced model, and levels 1–3. |
| `rail_states.png` | Session rows (cursor focused and unfocused, working, needs you, failed), Activity rows, all eight task states. |
| `composer_states.png` | Composer focused / unfocused, inline `/` completion, multi-line draft, while working with a toast, new-content pill. |
| `approval_variants.png` | Approval card with today's data (no risk, no facts), all optional data, long scroll-gated action, paused while typing, queue + high risk. |
| `quit.png` | Quit card, idle and with a turn running. |
| `logo.png` | Expanded mark, four stations of the star orbiting the `O`, compact mark states with their rates, shutdown line. |
| `motion_states.png` | The status star in every state: still, turning at 2 fps (thinking) and at 4 fps (writing, agents running), its frames, the ASCII frames and reduced motion. |
| `motion_orbit.png` | The 12 stations of the star orbiting the `O` (M9, cyan), with the stations where the star is behind or in front of the `O` marked. |
| `motion_startup.png` | The 17 frames of the startup sequence (M1). |

**D. Annotation drawings.** These are not UI. They have a light paper background, black text and blue callouts.

| File | What it shows |
|---|---|
| `layouts.png` | Column widths per width class with formulas, row structure, and conversation-column offsets. |
| `blueprint_wide_approval.png`, `blueprint_wide_streaming.png`, `blueprint_wide_idle.png`, `blueprint_narrow.png` | The golden screens with column and row rulers and numbered callouts. Each callout names the rule and the section of this prompt that defines it. |
| `motion_timeline.png` | One turn on a time axis: which star moves at which rate, when counters change, and what changes only once. The star ticks follow the exact clock rule of §10.1. |

**Precedence, from strongest to weakest:**

1. **The text of this prompt.** It is normative.
2. **The golden text frames**, for characters and positions. If a rule in this prompt and a golden frame disagree, match the frame for that fixture and report the rule as ambiguous (§18).
3. **The PNGs**, for colour, weight and look. If a PNG and a colour rule disagree, follow the rule and report it.
4. **`docs/tui/DESIGN.md`.** It is background and rationale; where it differs from this prompt, this prompt wins.

**The data in the mockups is illustrative fixture data.** This covers session titles, `shell`/`edit_file` tools, file paths, outcomes like `48 passed`, plans, findings, citations, the verified card, risk levels and approval facts. Much of it has no data source in ORBIT today (§13). Reproduce it only in test fixtures (Appendix B). **Never hardcode it, and never fabricate equivalents at runtime.** Where data is missing, render exactly what §13 says to render when it is absent.

## 3. Hard rules

These are non-negotiable. A change that breaks one is wrong even if every test passes.

1. **Scope.** Work in these places only:
   - `crates/hud-tui/**`, including its `Cargo.toml`
   - `[workspace.dependencies]` in the root `Cargo.toml`, only to add the two unicode crates
   - `crates/cli/src/tui_worker.rs`
   - the TUI launch block of `crates/cli/src/main.rs` (lines 957–984)
   - new files under `docs/tui/` and `crates/hud-tui/tests/`
   - **Do not change:** the gateway, adapters, provider stack, ledger, sandbox, egress, trust, the reactor, `crates/cli/src/tool_runtime.rs` (approval policy, verdict order, ledger events), `crates/cli/src/tools.rs`, the REPL loop in `main.rs`, or `crates/hud` (`display_safe`, `BrandTier`, `Env`).
   - **Do not redesign** the backend, the agent architecture, the security model or the command system.
2. **Chain-of-thought is never displayed.** Nothing between reasoning tags reaches the screen, the Activity rail, copy mode, the shutdown line or any log the TUI writes. Removal happens in the bridge, silently. There is no "reasoning stripped" placeholder, no "thinking…" phrase, and no hint that hidden content exists. Activity shows only structured events.
3. **Every model- or backend-supplied string passes the bridge gates** before it is stored in TUI state, in this order: `strip_cot` → `sanitize_glyphs` → `orbit_hud::display_safe`. This covers streamed text, resumed history, notices, errors, tool summaries, tool error text and session titles.
   - A rejected chunk becomes a **redaction chip**, never asterisks, `▒`, partial values or an empty gap (§9.11).
   - Raw tool arguments and raw tool results are never displayed. The runtime's display-safe summaries are the only argument text.
4. **No emoji in the interface.** Status is carried by the glyphs of §7 plus a word. Model-emitted emoji stay content and keep passing through the existing ASCII map.
5. **No fabricated or optimistic state.**
   - A tool is done or failed only when `ToolCallFinished` says so.
   - A decision is shown only after `ApprovalRegistry::resolve` returns `true`.
   - A connection is online only when a response has succeeded or the runtime reported it.
   - A number is shown only when it was measured or supplied.
6. **Colour is never the only signal.** Every state is glyph + word + colour, and the monochrome render carries the same information.
7. **Magenta appears only in the six places listed in §6.2.**
8. **Only stars move** (§10). The status-line star turns while ORBIT works. The expanded mark's star orbits the `O` only at brand tier `anim`, at startup and while the first prompt of an empty session waits. An idle ORBIT sets no dirty flags.
9. **No new dependencies** except `chrono` (already a workspace dependency), `unicode-width = "0.2"` and `unicode-segmentation = "1"`, which are already in `Cargo.lock` at 0.2.0 and 1.13.3. Keep the forbid-unsafe attribute.
10. **No colour literal outside `theme.rs`, and no glyph literal outside the glyph table module.** Render code asks for tokens and glyph names.

## 4. The codebase today

Read these files before you start. Line numbers are from commit `ccf828f`, the head of `main` when this prompt was written. If `main` has moved, find the same code by content.

| File | What it does now | What you will change |
|---|---|---|
| `crates/hud-tui/src/lib.rs` | Entry `run`, event loop, `Composer` (a `String`), `handle_key`, copy mode | Key routing, composer, cursor, copy mode, capability resolution |
| `crates/hud-tui/src/state.rs` | `App` reducer, `DirtyFlags` (`SESSION_LIST TRANSCRIPT TASKS STATUS LOGO APPROVAL LAYOUT`), `Focus` (`Left Center Right Status`), `LeftTab` (`Sessions Verbose`), transcript as `Vec<TranscriptLine>`, `in_flight: String` | Structured transcript model, turn lifecycle, workspace/sessions/activity models, clocks |
| `crates/hud-tui/src/msg.rs` | `Msg` enum between input, worker and reducer | The protocol of §13.3 |
| `crates/hud-tui/src/render.rs` | Bordered three-pane layout, shimmer, help bar, status bar | Replaced by the layout and components of §8–§9 |
| `crates/hud-tui/src/rich.rs` | Minimal markdown to `Line` | Markdown rules of §9.6 |
| `crates/hud-tui/src/theme.rs` | `ThemeColors` (`accent accent_bright accent_dim composer composer_dim text dim code_bg code_fg error success warning`), percentage layout, spinner styles | Tokens and tiers of §6, config of Appendix C |
| `crates/hud-tui/src/bridge.rs` | `strip_cot`, `sanitize_glyphs`, `safe_text`, `emit_*` | Stateful CoT stripping, structured redaction, new emitters |
| `crates/hud-tui/src/input.rs` | `KeyParser` with `g`/`z` leaders; `/` → `CommandPalette` | Keymap of §11 |
| `crates/hud-tui/src/terminal.rs` | Raw mode, alternate screen, cursor hidden, signal flags, forces `LANG`/`LC_ALL` | Stop forcing locale; cursor style; keyboard enhancement |
| `crates/hud-tui/src/approval.rs` | `ApprovalRegistry` (`register`, `resolve`, `has_pending`, `deny_all`), `ApprovalResponse {Allow, Deny, AllowSession}` | Keep as is |
| `crates/hud-tui/src/coalesce.rs` | 30 ms text coalescer | Keep; flush before structural events |
| `crates/cli/src/tui_worker.rs` | Worker thread: `run_tui_turn`, `TuiApprovalChannel` | Turn lifecycle messages, outcomes, grants lifetime, resume, commands, session save |
| `crates/cli/src/tool_runtime.rs` | `ApprovalRequest {call_id, tool_name, summary}`, `ApprovalVerdict`, `execute_call` | **Read only** |
| `crates/cli/src/tools.rs` | Built-ins `calculator`, `current_session`, `list_models`; `safe_call_summary` → `name(key1, key2)`; `is_known_tool` | **Read only** |
| `crates/cli/src/sessions.rs` | `SessionFile {schema, session_id, model, gate, provider, transcript, turns, input_tokens, output_tokens, cost_microcents, updated_at (unix seconds as a string)}`, `save_session`, `load_session`, `list_sessions` (newest first) | **Read only** |
| `crates/reactor/src/lib.rs` | `Phase {Init, Plan, Execute, Verify, Checkpoint}`; `as_str` returns `init plan exec ver ckpt` | **Read only.** Display labels are `init plan execute verify checkpoint`; do not use `as_str` |

The known defects in this code are listed with exact lines in §14. Fix them as part of the steps in §15.

## 5. Design principles

Use these to settle any small judgement call the rules do not reach. They never override a rule.

1. **You are the centre of gravity; brightness is mass.** The conversation is the brightest, widest mass. Rails are dimmer and the status line is dimmest. *Squint test:* blurred, the screen shows one block of text, one magenta word (the focused title) and at most one cyan thing (only while working).
2. **Ink, not boxes.** Structure comes from alignment, spacing and hairlines. No pane has a border. At most one rounded frame is on screen, and a frame means *this needs you* (approval, quit, palette, help).
3. **Magenta means ORBIT, or you.** See the closed list in §6.2.
4. **Only the star moves.**
5. **Every state has a shape and a word.** Circles are work, diamonds are authority, the star is ORBIT.
6. **Evidence earns green.** Green means a check passed. A claimed "done" gets a neutral `✓`.
7. **Honest words.** Every live number is real. Missing data is left out, never invented.
8. **Degrade by subtraction.** Lower tiers remove colour, glyphs or motion, never meaning or layout.

## 6. Colour

### 6.1 Tokens

Contrast ratios are WCAG 2.x against `bg`.

| Token | True colour | xterm-256 | ANSI-16 | Mono | Role |
|---|---|---|---|---|---|
| `bg` | `#100E16` | 233 | terminal default bg | default | canvas |
| `surface` | `#17141F` | 234 | none | none | user-turn band, composer band, code band, approval-card fill, quit-card fill |
| `surface2` | `#211C2B` | 235 | none | none | chips (inline code, keycaps, redaction), palette and help fill, unfocused cursor row, completion list, new-content pill |
| `wash` | `#2B1631` | 236 | REVERSE | REVERSE | focused cursor row (always with a magenta `▌`) |
| `rule` | `#2D2839` | 236 | default fg + DIM | DIM | hairlines, dividers, scroll track, unfocused header rule, upcoming stepper connectors |
| `rule_hi` | `#463F55` | 239 | default fg + DIM | DIM | focused header rule (heavy), overlay frames (palette, help, quit) |
| `ink` | `#ECE8F3` (15.9:1) | 255 | default fg | default | primary text |
| `ink2` | `#BDB6CA` (9.8:1) | 250 | default fg | default | secondary text: rails, tool names, sources, values |
| `muted` | `#8B8499` (5.3:1) | 103 | default fg + DIM | DIM | metadata, labels, hints, timestamps, scroll thumb |
| `faint` | `#655F73` (3.1:1) | 60 | default fg + DIM | DIM | placeholders, disabled items, session id, code language label |
| `magenta` | `#E356D0` (5.9:1) | 170 | 5 | BOLD | the six uses in §6.2 |
| `magenta_hi` | `#F58CE4` | 212 | 5 | BOLD | startup star flash (one frame of M1) |
| `magenta_dim` | `#8E3C7F` | 96 | 5 + DIM | DIM | the ring of the expanded mark |
| `cyan` | `#5CC6DD` (9.6:1) | 81 | 6 | BOLD on glyphs | live: waiting, streaming, running, the active item |
| `green` | `#62CC8E` (9.6:1) | 78 | 2 | glyph + word | verified results, `● online`, readiness checks |
| `amber` | `#E9B252` (10.0:1) | 179 | 3 | glyph + word | blocked, retest, reconnecting, rate-limited, medium risk, the "turn running" quit warning |
| `red` | `#F06A5E` (6.3:1) | 203 | 1 | BOLD | failed, offline, high risk, error glyph |
| `syn_kw` | `#C3A6FF` | 183 | 4 | none | code keywords |
| `syn_str` | `#A6D6A0` | 151 | 2 | none | code strings |
| `syn_num` | `#EFC08D` | 180 | 3 | none | code numbers |

Code comments are `muted`; all other code is `ink`. Keywords are the Rust set `fn let mut pub use impl if else match return Ok Err Some None self Self struct enum for in while loop async await where const mod crate`. Other languages get no highlighting: code is `ink`, comments `muted` only where the language uses `//` or `#`.

### 6.2 One meaning per colour

- **Magenta:** exactly six uses.
  1. The star of the compact mark when ORBIT is ready or needs you.
  2. ORBIT's settled voice glyph `✦` in the transcript gutter.
  3. The focused pane's title, or the active view in the switcher.
  4. The selection bar `▌`.
  5. Your input: the composer prompt `›`, and the characters your query matched in the palette and completion list.
  6. Authority requests: the `◇` glyph and "awaiting you" meta, the approval card frame and title glyph and tool name, and the `◇ approval needed` status.
  - The expanded mark's ring (`magenta_dim`), its star at rest and during M1 (`magenta`), and the startup flash (`magenta_hi`) belong to use 1. While ORBIT works, both stars are `cyan`, never magenta.
  - Never use magenta for headings, links, decoration, errors or fills larger than one word. `wash` is a tint, not magenta.
- **Cyan** means *now*: anything in progress. Never user text, the composer, or a static accent.
- **Green** means *proven*: a structured check reported a pass (a test result, a retest attestation), or a healthy connection or readiness check. A ledger record alone is not a pass. Never green for a claimed "done".
- **Amber** means *caution*. Never for anything that needs no attention.
- **Red** means *failed*. Never for denials: you said no and nothing failed.

### 6.3 Contrast rules

- Body text is ≥ 7:1 on every surface it can land on.
- Anything carrying meaning is ≥ 4.5:1.
- On cursor rows, `muted` metadata is promoted to `ink2`.
- `faint` (3.1:1) is only for placeholders, disabled items, and facts repeated elsewhere (the session id, code language labels, queued glyphs in rails). It never carries a fact alone.

### 6.4 Tiers

- **True colour.** Paint the `bg` canvas and every surface.
- **256 colours.** Use the xterm column above. Surfaces use the listed grey-ramp steps. Do not map by nearest colour: that would merge `bg` and `surface`.
- **16 colours.**
  - Do not paint the canvas; use the terminal's default background and foreground.
  - `muted`, `faint`, `rule` and `rule_hi` are the default foreground + DIM. Never use ANSI 0, 7, 8 or 15 for text, or the bright variants 9–14.
  - Surfaces disappear:
    - The user band is gone; the gutter `›` stays.
    - Code blocks get a DIM `│` at the content column, with text two columns right.
    - Inline code becomes cyan text.
    - Keycaps become `[y]`.
    - Redaction chips keep `⟨ ⟩`.
  - Selection is REVERSE.
- **Monochrome** (`NO_COLOR`, or config `mono`).
  - Attributes only:
    - BOLD: focus titles, the active item, tool names, keycaps, the words "approval", "failed", "error", and every glyph whose colour carried meaning.
    - DIM: `muted`, `faint`, rules.
    - REVERSE: selection.
    - UNDERLINE: palette and completion matches, and H1.
  - Inline code keeps its backticks and citations keep their brackets.
  - The approval frame is BOLD and is still the only frame.
- **Detection** happens once at startup; see §12.1. Tiers only step down at runtime, never up.

## 7. Glyphs, type and text formats

### 7.1 Glyph table

Ship one `Glyphs` table with `unicode()` and `ascii()` constructors. No render code contains a glyph literal. Every Unicode glyph here is one cell wide in `unicode-width`.

| Name | Unicode | Code point | ASCII | Colour and use |
|---|---|---|---|---|
| orbit | `✦` | U+2726 | `*` | ORBIT voice glyph and mark star. Magenta when settled or ready, cyan while live. |
| you | `›` | U+203A | `>` | User-turn gutter (`muted` bold); composer prompt (`magenta` bold focused, `faint` unfocused) |
| notice | `∙` | U+2219 | `-` | Session notices, list bullet (`muted`) |
| pending | `◌` | U+25CC | `.` | Queued or pending (`faint` in rails, `muted` in tool lines) |
| active | `◉` | U+25C9 | `@` | Running or active (`cyan`) |
| done | `✓` | U+2713 | `+` | Done: `muted` in tool lines, `ink2` for claimed tasks, `green` when verified |
| failed | `✕` | U+2715 | `x` | Failed or offline (`red`) |
| blocked | `⊖` | U+2296 | `#` | Blocked, rate-limited status verb (`amber`) |
| retest | `↻` | U+21BB | `~` | Awaiting retest, reconnecting (`amber`) |
| approval | `◇` | U+25C7 | `?` | Awaiting your decision (`magenta`) |
| allowed | `◆` | U+25C6 | `+` | Allowed once by you (`muted`, before the tool meta) |
| granted | `◈` | U+25C8 | `+` | Ran under a session grant or `--auto-tools` (`muted`) |
| denied | `⊘` | U+2298 | `/` | Denied by you (`muted`; a decision, not a failure) |
| online | `●` | U+25CF | `o` | Connection online (`green`) |
| ratelimit | `◔` | U+25D4 | `%` | Rate-limited (`amber`) |
| collapsed / expanded | `▸` / `▾` | U+25B8 / U+25BE | `>` / `v` | Disclosure (`muted`) |
| bullet2 | `◦` | U+25E6 | `-` | Nested list bullet (`muted`) |
| wrap | `↪` | U+21AA | `>` | Wrapped continuation in code and the approval action (`faint`) |
| ellipsis | `…` | U+2026 | `~` | Truncation (the colour of the text it ends) |
| sel | `▌` | U+258C | `>` | Selection bar (`magenta`) |
| quote | `▎` | U+258E | `\|` | Blockquote bar (`muted`) |
| live edge | `▍` | U+258D | `_` | End of streaming text (`cyan`, steady) |
| risk on / off | `▰` / `▱` | U+25B0 / U+25B1 | `#` / `-` | Risk meter (risk colour) |
| down / up | `↓` / `↑` | U+2193 / U+2191 | `v` / `^` | Tokens in / out; new-content pill; "↑ n more" |
| spinner | `◐ ◓ ◑ ◒` | U+25D0 U+25D3 U+25D1 U+25D2 | `- \ \| /` | The turning status star (M2, §10.1), in this order |
| rule / rule_focus | `─` / `━` | U+2500 / U+2501 | `-` / `=` | Header rules |
| div / thumb | `│` / `┃` | U+2502 / U+2503 | `\|` / `#` | Divider and scroll track / thumb |
| frame | `╭ ╮ ╰ ╯` with `─` `│` | U+256D U+256E U+2570 U+256F | `+ - \|` | Overlay frames only; never `┌┐` or `═` |
| key hints | `⏎` `⇧` | U+23CE U+21E7 | `Enter` `S-` | Composer hints, help, palette footer |
| separator | `·` | U+00B7 | `-` | Between segments, in the colour of the segment it sits in |
| redaction | `⟨ ⟩` | U+27E8 U+27E9 | `< >` | Redaction chip |

**Width safety.** `◇ ◆ ◈ ● … ▌ ▎ ▍ ↓ ↑ ◐ ◑ ⇧ ·` and the box-drawing characters `─ ━ │ ┃ ╭ ╮ ╰ ╯` are East-Asian *ambiguous*. When the width probe (§12.2) finds that ambiguous glyphs render two cells wide, use the ASCII table for every glyph ORBIT draws itself. Content (model text, titles, paths) is never altered.

### 7.2 Type rules

- **Weight.** Regular for body text. Bold for pane titles, tool names, the active task, keycaps, the approval action, and the words listed in §6.4 for mono. Never italic, never blink. Strikethrough never carries meaning.
- **Case.** UPPERCASE only for rail section labels (`TODAY YESTERDAY THIS WEEK OLDER PLAN FINDINGS VERIFICATION`) and overlay section labels (`COMMANDS SESSIONS WORKSPACE ACTIVITY` and the help groups), always `muted`.
- **Spacing.**
  - One blank row between turns and between blocks inside a turn. A tool group has no blank rows between its lines.
  - Two spaces between a tool name and its argument; three spaces between status segments and between key hints.
- **Measure.** Prose wraps at `cw = min(column width − 5, 100)`; see §8.3.

### 7.3 Text formats

All formats use integer arithmetic. "Round" means round half up.

| Value | Format |
|---|---|
| Cost | The integer from the runtime is in the unit the existing code already uses: dollars = value / 1 000 000 (`/usage` and today's status bar divide by 1 000 000). Show 4 decimals: `v = (value + 50) / 100`, then `$` + `v / 10000` + `.` + `v % 10000` zero-padded to 4. If value > 0 and v = 0, show `<$0.0001`. Unpriced model: `cost n/a`. Do not change the unit, even though the type is named `microcents`. |
| Tokens | n < 1 000 → `n`. n < 999 950 → tenths `t = (n + 50) / 100`, shown as `t/10` `.` `t%10` `k` (`18.2k`). Otherwise tenths of a million, `(n + 50 000) / 100 000`, with `M`. |
| Duration | Tenths `t = (ms + 50) / 100`. If `t < 100`: `t/10` `.` `t%10` `s` (`3.9s`). Otherwise seconds `s = (ms + 500) / 1000`: `{s}s` below 60 (`41s`), else `{s/60}m {s%60:02}s` (`2m 05s`). |
| Time of day | Local `HH:MM`, 24-hour, for turns and notices. Local `HH:MM:SS` for Activity rows. Use `chrono::Local` through an injectable clock (§16.1). |
| Recency | < 60 s `now`; < 60 min `{m}m`; < 24 h `{h}h`; < 7 d `{d}d`; < 52 w `{w}w`; else `{y}y`. Floor division. |
| Counts | `1 turn` / `14 turns`; `4/5`; `2 proofs`. |
| Short session id | Session ids are `session-` + a 26-character ULID (`orbit_gateway::new_session_id`). The short id drops a leading `session-` and keeps the next 8 characters: `session-01J8ZK4QX2M7C9RT5VWEHN3B6D` → `01J8ZK4Q`. An id without that prefix keeps its first 8 characters. |

### 7.4 Width and grapheme rules

- Measure with `unicode-width`, segment with `unicode-segmentation` extended grapheme clusters.
- Never split a cluster: no split ZWJ sequences, combining marks or wide characters. A wide character that does not fit at the end of a line moves to the next line.
- `…` follows the last whole cluster that fits. ZWJ emoji count as width 2.
- **End truncation** (titles, rail rows, activity text): keep the head, append `…`.
- **Middle truncation** (tool arguments, and the status-line argument): with `w` columns available, keep the last `ceil((w − 1) / 2)` clusters and the first `w − 1 − that` clusters, joined by `…`.
- Wrapping is greedy on spaces.
  - A line never starts with the spaces at a break; spaces at the end of a broken line are dropped.
  - A word longer than the line is hard-broken at the width.
  - Styled spans keep their style across breaks.
  - Inline-code chips are measured without their backticks.

## 8. Layout and geometry

### 8.1 Rows

| Rows | Default | Tight (W 40–59) | Approval pending |
|---|---|---|---|
| `0` | pane headers (one shared row) or view switcher | view switcher | pane headers |
| `1` | air | air | air |
| body | `2 … H−5`: bodies; the transcript is bottom-anchored | `2 … H−4` | transcript `2 … T−2` |
| air | `H−4` (rails continue through it) | `H−3` | `T−1` |
| composer | `H−3` input (grows upward) and `H−2` hint row | `H−2` input, no hint row | card `T … H−2`, where `T = H − 1 − card height` |
| status | `H−1` status line, full width | `H−1` | `H−1` |

When the composer grows by k rows (§9.13), the body loses k rows at its bottom and the air row moves up.

Row budgets, from last to lose space to first:

1. The status line.
2. The approval card (6 rows minimum; 9 with facts). If the transcript would be left with fewer than 3 rows, the card takes the whole conversation area (rows 2 … H−2) and its action scrolls inside.
3. The composer input row.
4. The hint row, dropped below 16 rows.
5. The pane header row. In single-view layouts it is dropped below 12 rows, and the view name moves into the status-line activity.
6. The transcript, never below 4 rows unless the card has taken the area.

The two air rows go first of all.

### 8.2 Width classes

Open `layouts.png` now.

| Class | Width | Panes | Widths |
|---|---|---|---|
| Wide | W ≥ 140 | Sessions │ Conversation │ Workspace | `L = clamp(28, round(0.20·W), 34)`, `R = clamp(32, round(0.24·W), 44)`, `C = W − L − R − 2`. At 150: 30 │ 82 │ 36, dividers at columns 30 and 113. |
| Medium | 110–139 | Conversation │ Workspace | `R = clamp(30, round(0.30·W), 36)`, `C = W − R − 1`. At 120: 83 │ 36. |
| Medium, Sessions focused | 110–139 | Sessions │ Conversation (Workspace hidden until focus leaves Sessions) | `L = 30`, `C = W − 31`. It is a push, not an overlay: nothing is covered, and the transcript reflows once. |
| Narrow | 80–109 | One view: Sessions, Conversation or Workspace | View switcher in row 0; status level 2 |
| Compact | 60–79 | One view | No transcript timestamps; tool meta keeps the outcome and drops the duration; status level 2 |
| Tight | 40–59 | One view | Status level 3; no hint row (hints via `?`); no code language labels; no session recency |
| Too small | W < 40 or H < 10 | Size notice only (§9.23) | — |

Resize events are debounced 50 ms (H-12) and then reflow instantly. If the focused pane stops existing in the new class, focus goes to the Conversation. If the Sessions rail was focused while the class changes to Medium, it stays open.

### 8.3 The conversation column

Let the column start at `x` with width `w`.

- **Content left:** `cl = x + 3`. If `w − 5 > 100`, add the centring offset: `cl = x + 3 + (w − 5 − 100) / 2`, using integer division.
- **Measure:** `cw = min(w − 5, 100)`. Content occupies columns `cl … cl + cw − 1`.

Every offset below is relative to `cl`. With no centring, `cl − 2 = x + 1` and `cl + cw = x + w − 2`.

| Element | Columns |
|---|---|
| Gutter glyph (`✦ › ✕ ∙`) | `cl − 2` |
| Prose, tool glyph, notice text | from `cl` |
| Right-aligned items (timestamps, tool meta, `queued`, language label, evidence results) | last cell `cl + cw − 1` |
| User band, composer band, approval card | `cl − 2 … cl + cw` |
| Composer | `›` at `cl − 1`; text, cursor and hints start at `cl + 1`; the placeholder starts at `cl + 2` (the cursor cell is `cl + 1`) |
| Code band | `cl − 1 … cl + cw`; code text from `cl + 1`; language label ends at `cl + cw − 1` |
| Tool name | `cl + 2`; the argument starts 2 columns after the name |
| Tool detail | rule `│` at `cl + 1`, text at `cl + 3` |
| Evidence rows | rule `│` at `cl`, text at `cl + 2` |
| Sources wrap | continuation rows start at `cl + 9` |

**Wrap widths:**

- The first prose paragraph of an ORBIT turn whose first row shows a time wraps **every line** at `cw − 7`.
- A user turn that shows a time wraps every line at `cw − 7`. Without a time, it wraps at `cw`.
- A queued-prompt row wraps at `cw − 8`.
- Everything else wraps at `cw`.

### 8.4 Rails

| Rail | Geometry |
|---|---|
| Sessions (width w at x) | Section labels at `x + 2`. Rows: `▌` at `x`, state glyph at `x + 1`, title at `x + 3`, recency right-aligned ending at `x + w − 2`. Title budget `w − 3 − len(recency) − 2`, end-truncated. The cursor fill spans `x … x + w − 1`. |
| Activity | Time at `x + 1` (`faint`, `HH:MM:SS`), kind at `x + 11` (`muted`, one of `plan tool grant ledger cite model warn error`), text at `x + 18`, end-truncated at `x + w − 1`. |
| Workspace | Content at `x + 2`. Right-aligned items end at `x + w − 2`. Task rows: glyph at `x + 2`, title at `x + 4` wrapped to `(x + w − 1) − (x + 4) − (len(tag) + 1 if a tag)`, sub-line at `x + 4` wrapped to `(x + w − 1) − (x + 4)`. |

### 8.5 Pane header and focus

The pane header occupies row 0 at `x … x + w − 1`.

- Tabs start at `x + 1`, two spaces apart.
- The rule starts one space after the last tab and ends one space before the right meta, or at `x + w − 2` when there is no meta.
- The right meta ends at `x + w − 2`.

| | Focused | Unfocused |
|---|---|---|
| Header | Active tab `magenta` bold, heavy `━` in `rule_hi` | Active tab `ink` bold, other tabs `muted`, light `─` in `rule` |
| Cursor row | `wash` fill + `magenta` `▌` at the rail's first column; `muted` metadata promoted to `ink2` | `surface2` fill, no bar |
| Composer | `magenta` `›`, real cursor, hint row visible | `faint` `›`, no cursor, hint row blank (the row stays) |

Focus changes are instant. Headers never show status colour.

### 8.6 Divider and scroll bar

- Each divider is one column of `│` in `rule`, running from row 0 to row H−2.
- The divider immediately right of the transcript is its scroll track, but only on the rows the transcript occupies. With `view` visible rows, `total` content rows and `start` the index of the first visible content row:
  - If `total ≤ view`: no thumb.
  - Otherwise: `th = max(2, (view² + total/2) / total)` and `ty = top + ((view − th)·start·2 + (total − view)) / (2·(total − view))`.
  - The thumb `┃` is `muted`, on rows `ty … ty + th − 1`.
- When the transcript has no divider on its right (Medium with Sessions focused, and single-view layouts), it has no scroll bar.
- `start = max(0, total − view − offset)`, where `offset` is the number of rows scrolled up from the bottom (0 = following new content).

## 9. Components

### 9.1 Pane headers

- **Conversation:** title = the session title (§13.2); right meta `n turns` (`muted`, singular `1 turn`).
  - The title is `New session` before the first prompt, with no meta.
  - `n` counts the turns of this session, including resumed ones and the one running now. A turn counts from its `TurnStarted`, so a queued prompt does not count yet.
  - The title is end-truncated (§7.4) to `w − 7 − (meta width)` columns, which leaves at least three rule cells. The meta ends at `x + w − 2` (§8.5). See `welcome_waiting.png`.
- **Sessions rail:** tabs `Sessions` `Activity`.
- **Workspace:** title `Workspace`, no meta.

Pane titles never take status colour.

### 9.2 View switcher (single-view layouts)

Row 0 reads ` Sessions   Conversation   Workspace n/m ━━━…`.

- Names are three spaces apart, starting at column 1.
- The active view is `magenta` bold; the others are `muted`.
- `Workspace` is `faint` and has no count while the workspace is empty.
- `n/m` is completed/total plan tasks: `cyan` while a plan task is active, `muted` otherwise.
- The heavy `━` rule in `rule_hi` starts one space after the last item and ends at `W − 2`.

### 9.3 New-content pill

When `offset > 0` and rows were added since you scrolled up, show ` ↓ n new · End ` on the last transcript row, right-aligned at `cl + cw − 1`, on `surface2`: `↓` `cyan`, `n new` `ink2`, `· End` `muted`. `n` counts rows added since you left the bottom. The pill disappears when `offset` returns to 0.

### 9.4 User turn

- A `surface` band spans `cl − 2 … cl + cw` on every row of the turn.
- Gutter `›` (`muted` bold) on the first row; text `ink`.
- Inline code in user text renders as a chip. User text renders no other markdown.
- The time is right-aligned on the first row (`muted`). The submit time is shown; history items have none.
- One blank row follows.

### 9.5 ORBIT turn

- **Gutter glyph** `✦` on the first row: `cyan` while the turn is live (waiting, streaming, running tools, waiting for an approval), `magenta` once it settles. It never animates.
- **Before the first token,** the first row reads `waiting for {model}` in `muted`, static.
- **Streaming text** is appended at the 30 ms coalescer flush. Its end carries a steady `cyan` `▍`. Only the last paragraph reflows. An unclosed code fence renders as code until it closes.
- **Blocks** are kept in arrival order: prose, tool group, prose, code, sources, evidence.
  - Before appending a tool line, flush the coalescer and close the current prose block.
  - Text after a tool group starts a new prose block.
- **Time.**
  - While live, the time is the turn's start time; once settled, its end time.
  - It is drawn right-aligned on the first row **only if that row is prose** (including the `waiting for` line). A turn whose first row is a tool line shows no time (see `narrow.png` and `tight.png`).
- **Compact and Tight** show no timestamps anywhere in the transcript.

### 9.6 Markdown in ORBIT prose

| Element | Rendering |
|---|---|
| H1 | Bold + underline. The `#` markers are hidden. |
| H2 | Bold. |
| H3 | Bold `ink2`. |
| Lists | `∙` bullet (`muted`) with a 2-column hanging indent; nested lists use `◦`; ordered markers `1.` are `muted`. |
| Blockquote | `▎` (`muted`) plus `ink2` text. |
| Tables | Bold header row, a `─` rule under it, 2-space column gaps, numbers right-aligned, no vertical bars. |
| Links | Link text underlined; the URL is never shown. |
| Emphasis | Strong renders bold; italics render plain. |
| Inline code | A `surface2` chip, `ink` text, no backticks. In 16 colours cyan text; in mono backticks kept. |
| Citations `[n]` | `cyan`, but only when a structured citation with that index exists for the turn (§13). Otherwise plain text. |

### 9.7 Code block

- One blank row before and after.
- A `surface` band spans `cl − 1 … cl + cw`, with text from `cl + 1`.
- The language label is `faint`, right-aligned on the first row. Tight hides it.
- No line numbers.
- Long lines wrap: the continuation row carries `↪` (`faint`) at `cl` and its text continues from `cl + 1`. Code is never truncated.
- 16 colours and mono: no band; a DIM `│` at `cl`, text from `cl + 2`.

### 9.8 Tool line

`{glyph} {name}  {argument}   …   [marker] {meta}`

| Part | Rule |
|---|---|
| Glyph | At `cl`, colour per state below. |
| Name | At `cl + 2`. `ink` bold while running or awaiting you, `ink2` bold otherwise. |
| Argument | `muted`, starting 2 columns after the name, middle-truncated so at least 2 spaces remain before the marker or meta. Text: the runtime's display-safe summary without its leading `name(` and trailing `)` (today that is the argument key list, `expression`), or nothing when that is empty. |
| Marker | `◆` if you allowed this call once through the card; `◈` if it ran without asking (session grant or `--auto-tools`); none otherwise. `muted`, placed so one space separates it from the meta. |
| Meta | Right-aligned, ending at `cl + cw − 1`. |

| State | Glyph | Meta (colour) |
|---|---|---|
| Queued | `◌` muted | `queued` (muted) |
| Running | `◉` cyan | `running` (cyan) |
| Awaiting you | `◇` magenta bold | `awaiting you` (magenta) |
| Done | `✓` muted | `{outcome} · {duration}`, or `{duration}` when no outcome is supplied (muted) |
| Failed | `✕` red bold | `{outcome} · {duration}`, or `failed · {duration}` (red) |
| Denied by you | `⊘` muted | `denied by you` (muted) |
| Blocked | `⊖` amber | `blocked · unknown tool` (amber) |

- **Duration** is measured by the TUI from the later of `ToolCallStarted` and your approval decision, to `ToolCallFinished`.
- **Compact** drops the duration (and the ` · `).
- **Group:** consecutive tool lines have no blank rows between them; there is one blank row before and after the group.
- **Detail.**
  - Rows sit under the line: rule `│` at `cl + 1`, text at `cl + 3` (`muted`).
  - The rule is `cyan` for a running tool's live output tail (the last 3 lines, event-driven, when the runtime supplies output; it does not today), `red` for a failure, and `rule` otherwise.
  - A failure's detail (the gated error text) is open by default.
  - `z t` toggles the detail of the most recent tool line that has detail.

### 9.9 Evidence card

This is the only green block in the transcript. It is built only from structured verification data, never from model prose; there is none today (§13).

- **Header:** `✓` green bold at `cl`, then `verified` green bold at `cl + 2`, then `  {n} checks · …` in `muted`.
- **Rows:** `│` green at `cl`, check name `ink2` at `cl + 2`, result `muted` right-aligned.

### 9.10 Citations

Only from structured citation data (none today).

- Inline `[n]` is `cyan` (§9.6).
- One `sources` line follows the turn's content: `sources` in `muted` at `cl`, two spaces, then items `[n]` (`cyan`) + ` source` (`ink2`), three spaces apart.
- The line wraps with continuation rows from `cl + 9`.
- More than 4 sources collapse to `▸ n sources` (`muted`).
- Sources are paths, titles or ledger references; URLs never appear.

### 9.11 Notices, errors, redaction

- **Session notice.** `∙` (`muted`) in the gutter, `muted` text, time right-aligned. Examples:
  - `session started · {model} via {provider}`
  - `session resumed · {n} prior turns`
  - `model → {model}`
  - `conversation cleared · earlier turns are no longer sent to the model`
- **Warning notice.** An `amber` glyph and `amber` text, one line, saying what ORBIT is doing about it. Examples: `warning: session not saved · {reason}`, or a connection notice when the runtime reports one.
- **Turn error card.**
  1. Gutter `✕` red bold; `This turn failed` in `ink` bold; two spaces; the error code in `muted` (omitted when there is none); the time right-aligned (`muted`).
  2. The runtime's message after the bridge gates, in `ink2`, followed by ` Your prompt is kept in the transcript.`, as prose from `cl` wrapped at `cw`.
  3. `⏎ on an empty composer resends it`, in `muted`.

  Red is for the glyph only.
- **Redaction chip.** `⟨redacted · credential⟩`, `⟨redacted · url⟩` or `⟨redacted⟩`: a `surface2` chip in `ink2`, standing in for exactly the rejected chunk. The label comes from §13.4. Consecutive redactions with no text between them render as one chip, labelled by the first. A chip never shows a partial value.

### 9.12 Queued prompt row

A prompt sent while a turn runs is not a user turn yet.

- It shows above the composer as: `›` `faint` bold in the gutter, text `ink2` wrapped at `cw − 8`, and `queued` (`muted`) right-aligned on the first row.
- There is no band.
- It becomes a real user turn when the worker sends `TurnStarted` for it.

### 9.13 Composer

- **Band.** `surface`, spanning `cl − 2 … cl + cw`, on the input rows and the hint row.
- **Prompt and cursor.**
  - `›` at `cl − 1`; text from `cl + 1`.
  - The terminal's real cursor, as a steady bar, sits at the insertion point: `SetCursorStyle::SteadyBar` on entry, restored to `DefaultUserShape` on exit and before copy mode. Hide it whenever the composer is not focused or is covered.
  - Never paint a cursor glyph.
- **Placeholder.** `faint`, starting at `cl + 2`:
  - idle: `Ask ORBIT, or type / for commands`
  - while a turn runs: `Add to the queue, or wait for ORBIT`
  - Tight, while a turn runs: `Add to the queue, or wait`
- **Height.** One row, growing upward with the draft to `min(8, floor(0.30·H))` input rows. Beyond that it scrolls internally, keeping the cursor visible, and the hint row appends `↑ n more` (`muted`) for rows hidden above.
- **Hint row.**
  - Starts at `cl + 1`: bold `ink2` key, space, `muted` label, three spaces between hints.
  - While idle: `⏎ send`, `⇧⏎ newline`, `/ commands`, then one context hint.
  - While a turn runs: `⏎ queue`, `⇧⏎ newline`, then one context hint.
  - The context hint is the first that applies:
    1. `tab views` (single-view layouts)
    2. `⇧tab sessions` (Medium, empty conversation)
    3. `↑ history` (idle and history non-empty)
    4. `pgup scroll` (transcript taller than its view)
  - Use `⇧⏎` only when keyboard enhancement is active (§12.4); otherwise the newline hint is `alt+⏎ newline`.
- **Toasts** sit at the right end of the hint row, ending at `cl + cw − 1`. They are `muted` text with an optional green `✓`, one at a time, and last 3 s or until the next keypress. They never report errors or approvals. The only toasts are:
  - `wait for this turn to finish first` (resume or new session attempted during a turn)
  - `✓ resent your last prompt`
- **Inline completion.**
  - Typing `/` into an empty composer opens a list above the composer: at most 6 rows, `surface2` fill across the band width, filtered by prefix. Its last row is the row directly above the first input row (the air row); it grows upward over the transcript.
  - Rows: command at `cl` (typed prefix `magenta` bold, the rest `ink2`), description in `muted` at `cl + 12`. The selected row is `wash` with `▌` at `cl − 2` and its command `ink` bold.
  - The hint row while it is open reads `↑↓ choose   tab complete   ⏎ run   esc close`.
  - Commands, alphabetical:

    | Command | Description |
    |---|---|
    | `/clear` | forget earlier turns (the model stops seeing them) |
    | `/help` | keys and commands |
    | `/model` | switch the model for this session |
    | `/models` | list models from configured providers |
    | `/resume` | continue a saved session by id |
    | `/sessions` | browse and resume earlier sessions |
    | `/usage` | turns, tokens and cost for this session |
- **Approval pending.** The card replaces the composer (§9.14) and the draft is kept untouched.
- **Editing** is grapheme-aware (§11.3).

### 9.14 Approval card

Open `approval_variants.png` and `wide_approval.png`.

- **Placement.**
  - Columns `cl − 2 … cl + cw` of the conversation, with the bottom border on row H−2 and the top on `T = H − 1 − h`. Below, `x = cl − 2` is the card's first column and `w = cw + 3` its width.
  - One air row above; the transcript ends at `T − 2`.
  - It is the only frame on screen: rounded, `magenta`, filled with `surface`.
- **Top border.**
  - At `x + 2`: ` ◇ Allow {tool}? `. The `◇` and `{tool}` are `magenta` bold; `Allow` and `?` are `ink` bold.
  - On the right, only when the request supplies a risk level: ` ▰▱▱ low risk ` (`muted`), ` ▰▰▱ medium risk ` (`amber`) or ` ▰▰▰ high risk ` (`red`), with the meter plain and the words bold, ending 3 columns before the corner.
  - Without a risk level there is no badge. Never default one.
- **Action.**
  - Row `T + 2`, from `x + 3`, `ink` bold: the request's display-safe `summary`, verbatim. Today that is `tool(keys)`, for example `calculator(expression)`.
  - It wraps at `w − 6` (first row) and `w − 8` (continuation rows, which carry `↪` `faint` at `x + 3` and text from `x + 5`). Break at the last space within the row if that space lies past the middle of the row; otherwise hard-break at the width. It is never truncated.
  - If it cannot fit even when the card takes the whole conversation area, the action rows scroll inside the card (`↑`/`↓`/PgUp/PgDn). `y` and `R` stay disabled, and the bottom border shows ` ↓ scroll to review ` (`muted`) at `x + 2`, until the last action row has been displayed once.
- **Facts grid.**
  - Only when the request supplies facts; none do today.
  - One blank row, then two rows of two columns at `x + 3` and `x + 3 + (w − 6)/2`: label `muted`, value `ink2` at label + 9. The order is `runs in`, `sandbox`, `egress`, `ledger`.
  - A fact that is not supplied is left out.
- **Keys.**
  - One blank row, then key groups from `x + 3`:
    1. ` y ` `allow once`
    2. ` R ` `allow {tool} for this session`
    3. ` n ` + ` esc ` `deny`
  - Keycaps are `surface2` chips with `ink` bold letters (`[y]` in 16 colours and mono). Labels are `ink2`.
  - Groups are 4 spaces apart. A group that does not fit moves whole to the next row, and the card grows by one row.
  - A disabled key's cap and label are `faint` (not bold).
  - If the request says session grants are not allowed at its risk level, the `R` label reads `not available for high-risk actions` and is disabled. No request says so today.
- **Paused while typing** (arming).
  - If any key was pressed less than 1000 ms before the card appeared, all decision keys start disabled.
  - Each further keypress restarts the 1000 ms timer. When it expires the keys enable.
  - While paused, the bottom border shows ` paused while you type ` (`muted`) at `x + 2`. The card never changes height when this switches.
- **Queue.** When more than one request is pending, ` 1 of n ` (`muted`) sits on the bottom border, ending 3 columns before the corner. The oldest request is shown first.
- **Height.** `h = 1 + 1 + A + 1 + (3 if facts) + K + 1`, where A is the visible action rows and K the key rows. With one action row and no facts that is 6; with facts, 9.
- **Behaviour.** Keys and the decision flow are in §11.5.

### 9.15 Sessions rail

- **Groups** `TODAY`, `YESTERDAY`, `THIS WEEK` (within 7 local calendar days), `OLDER`, from row 2. There is one blank row between groups; empty groups are omitted.
- **Rows** follow §8.4.
- **State glyph** at `x + 1`, only when known: `◉` cyan (working), `◇` magenta (needs you), `✕` red (failed). Saved sessions carry no state today (§13), so in practice only the open session can show one.
- **Title:** the open session is `ink` bold; others are `ink2`. Recency is `muted`; on the cursor row both are promoted as in §8.5.
- **Order:** newest first. The open session is always listed, even before its first save.
- **Enter** on a row resumes it (§11). Tight hides recency.

### 9.16 Activity rail

- Rows follow §8.4, oldest at the top. The rail follows the newest entry unless scrolled. Keep the last 500 rows.
- **Warnings** colour their text `amber`; **errors** `red`.
- **Kinds and texts** today:

  | Event | Kind | Text |
  |---|---|---|
  | Tool finished | `tool` | `{name} {argument} · {ok\|failed\|denied\|blocked}` |
  | Approval decision | `grant` | `{tool} · once · you`, `{tool} · session · you` or `{tool} · denied · you` |
  | Model at start | `model` | `{model} via {provider}` |
  | Model change | `model` | `model → {model}` |
  | Warning | `warn` | the notice text |
  | Error | `error` | the error code, or `turn failed` |
- `plan`, `ledger` and `cite` have no source today.
- Never model text, never reasoning.

### 9.17 Workspace rail

Open `rail_states.png` and the wide screens.

- **Phase stepper** on row 2:
  - One node per reactor phase, connected by two-cell connectors.
  - Past nodes are `✓` `muted` with `━━` `muted`. The current node is `◉` `cyan`. Upcoming nodes are `◌` `faint` with `──` in `rule`.
  - Then two spaces and the current phase label, `cyan` bold (`init plan execute verify checkpoint`), and `k/5` `muted` right-aligned.
- **Sections** `PLAN`, `FINDINGS`, `VERIFICATION`: a `muted` label with its count right-aligned, one blank row between sections. Empty sections are omitted.
- **Task states:**

  | State | Glyph | Title | Sub-line |
  |---|---|---|---|
  | Pending | `◌` faint | `ink2` | none |
  | Active | `◉` cyan | `ink` bold | `cyan` (what it is doing) |
  | Claimed done | `✓` ink2 | `ink2` | none |
  | Verified | `✓` green | `ink2` | none |
  | Failed | `✕` red | `ink` | `red` (what failed and which turn) |
  | Blocked | `⊖` amber | `ink` | `amber` (by what) |
  | Retest | `↻` amber | `ink` | `amber` (why) |
  | Awaiting approval | `◇` magenta | `ink` | `muted` |

  - Evidence tag, right-aligned: `n proofs` in green (verified) or `no evidence` in `faint` (claimed).
  - At most one sub-line.
- **Findings:** `∙` (`muted`), then `ink2` text followed by its source in `muted`.
- **Verification rows:** glyph + name (`ink2`) + result right-aligned: `48 passed` `muted`, `running` `cyan`, `queued` `muted`, `retest` `amber`.
- **Empty state:** `◌ Nothing planned yet.` (glyph `faint`, text `ink2`) on row 2. After one blank row, at `x + 4`, wrapped to `w − 5` in `muted`: `When a task has steps, the plan, findings and verification evidence collect here.`
- **Collapse order** as height shrinks: FINDINGS, then VERIFICATION, each to label + count. The active PLAN item never collapses.

### 9.18 Status line

Row H−1, no background, no separator glyphs.

- **Left** (from column 1): the mark, three spaces, then the activity.
- **Right:** segments placed right to left, ending at column W−2, three spaces apart.
- **Level 0** (W ≥ 140), right to left:
  - `? keys` (`?` `ink2` bold, `keys` `muted`)
  - short session id (§7.3, `faint`)
  - cost slot (8 columns, right-aligned, `ink2`; `cost n/a` `muted`)
  - token slot (13 columns, right-aligned: `↓{in} ↑{out}` `muted`)
  - connection slot (10 columns, right-aligned: `● online` with `●` green and word `muted`; `↻ retrying` amber; `◔ limited` amber; `✕ offline` red; blank before anything has been reported)
  - grant slot (levels 0 and 1 only), only while grants exist: `◈ {first tool}` (`◈` muted, name `ink2`) plus ` +{n}` for more; `◈ auto-tools` under `--auto-tools`
  - `{model}` `ink2` + ` · {provider}` `muted`
- **Levels:**
  - Level 1 (110–139): drops the session id.
  - Level 2 (60–109): `{model}`, connection glyph only, cost.
  - Level 3 (40–59): cost only, and the tool activity drops its argument (`running {tool} · {elapsed}`).
- **Mark:**
  - Level 0–3 at brand tier `anim`/`static`/`text`: glyph + ` ORBIT` (`muted` bold). At tier `off`: the glyph alone.
  - The glyph is `✦` `magenta` (ready, needs you), turning `◐◓◑◒` `cyan` while ORBIT works (2 fps while waiting for the model, 4 fps while streaming or running a tool; a still `✦` cyan under reduced motion), `✦` `amber` (degraded: reconnecting or rate-limited), or `✦` `red` (offline, or the last turn failed). The exact states, clock and precedence are in §10.1.
- **Activity**, first match wins:

  | State | Text |
  |---|---|
  | Approval pending | `◇ approval needed · {tool}`, all magenta |
  | More than one tool running at once | `running {n} tools` cyan + ` · {elapsed}` muted, counting from the earliest start |
  | One tool running | `running {tool}` cyan + ` · {arg} · {elapsed}` muted. `{arg}` is the tool line's argument's first two space-separated words, middle-truncated to 24 columns, and omitted when empty. |
  | Streaming | `streaming` cyan + ` · {n} tokens` (when the provider sent a usage update this round) or ` · {elapsed}` muted |
  | Waiting | `waiting for {model}` cyan + ` · {latency}` muted |
  | Reconnecting / rate-limited / offline | Only when reported: see `status_states.png` |
  | Turn report | For 2 s after a successful turn, or until the next key: `✓` green + ` done` `ink2` + ` · {duration} · {n} tools · +{turn cost}` muted. Omit ` · 0 tools` and the cost part when unpriced. |
  | Failed | `✕ failed` red + ` · {code}` muted, until the next turn starts |
  | Ready | `ready` muted |
- **Counters** (`{elapsed}`, `{latency}`, countdowns) are sampled once per second and hidden below 1.0 s, together with their ` · ` (§10.4, M3).
- **Truncation.** The left side is end-truncated with `…` so it ends at least 3 columns before the right cluster.
- **Status focus.** When the status line has focus (Tab reaches it in two- and three-pane layouts), `ORBIT` turns `magenta` bold and the right segments get a REVERSE cursor. `←`/`→` move it; `⏎` acts: on the model segment, insert `/model ` into the composer and focus it; on tokens or cost, run `/usage`; on `? keys`, open help. `Esc` returns focus to the Conversation.

### 9.19 Command palette

Open `palette.png`.

- **Frame.** `w = min(78, W − 8)`, `x = (W − w)/2`, top row 5, height `min(17, H − 10)` (at least 8). Rounded `rule_hi` frame, `surface2` fill, and no backdrop dimming.
- **Query row.** `›` `magenta` bold at `x + 2`, query from `x + 4`, real cursor after it; `esc close` `muted` ending at `x + w − 4`. A `─` hairline in `rule` fills the row below from `x + 1` to `x + w − 2`.
- **Sections** `COMMANDS SESSIONS WORKSPACE ACTIVITY` (empty sections hidden), each a `muted` label at `x + 3` with a `faint` count ending at `x + w − 4`, and one blank row between sections.
- **Rows.**
  - Label at `x + 3` in `ink2`, with fuzzy-matched characters `magenta` bold (underlined in mono). Matching is a case-insensitive subsequence.
  - Description in `muted` at `x + 22`; right hint ending at `x + w − 4`: `⏎` on the selected command, recency for sessions, `HH:MM` for activity.
  - The selected row is `wash` with `▌` at `x + 1` and its label `ink` bold.
  - Activity rows use the kind as description.
- **No match:** a single `muted` row, `no matches`.
- **Footer** on row `y + h − 2` at `x + 3`: `↑↓ move   ⏎ run   tab next section`.
- **Enter:** runs a command (§11.6), resumes a session, or closes the palette for workspace and activity rows.

### 9.20 Help overlay

Open `help.png`.

- **Frame.** `w = min(78, W − 8)`, `x = (W − w)/2`, top row 3, `rule_hi` frame, `surface2` fill. Title ` Keys ` `ink` bold on the top border at `x + 2`; ` esc close ` `muted` on the bottom border ending at `x + w − 4`.
- **Columns.** Two columns at `x + 3` and `x + 3 + colw + 1`, where `colw = (w − 6)/2`. Keys are `ink2` bold; descriptions are `muted` at key + 11. Group labels are `muted` uppercase. Content is exactly the text in `help.png`.
- **Narrow screens.** Below `w = 78`, one column (left groups, then right groups), scrolling with `↑`/`↓` when taller than the screen.
- **Closing.** `Esc` or `?` closes it.

### 9.21 Quit card

Open `quit.png`.

- **Frame.** `w = 46`, centred horizontally on the conversation column and vertically on rows 2 … H−5. Rounded `rule_hi` frame, `surface` fill (so keycaps stay visible). Title ` Quit ORBIT? ` `ink` bold on the top border.
- **Idle.** Top border, blank row, keys row, bottom border: 4 rows.
- **Turn running.** Top border, blank row, `A turn is running. Quitting stops it.` in `amber` at `x + 3`, blank row, keys row, bottom border: 6 rows.
- **Keys.** ` y ` `quit`, then ` n ` + ` esc ` `stay` (4 spaces between groups), from `x + 3`.

### 9.22 Welcome (empty session)

Open `welcome.png` and `logo.png`.

- **The block**, centred in the conversation column. Each line's left edge is `x + (w − width)/2`. Its top row is `2 + (free / 3)`, where `free` is the body rows minus the block height. The rows are:
  1. The expanded mark: 3 rows, 33 columns; its box starts 3 columns left of the `O`.
  2. One blank row.
  3. The tagline `the harness that orbits around you`, `muted`.
  4. Two blank rows.
  5. The readiness row: `✓ label` items, `✓` green and label `ink2`, 4 spaces apart. It appears only when readiness data exists; there is none today. Drop it together with the two blank rows above it.
  6. Three blank rows.
  7. `Describe a task below, or start with` (`muted`), starting at `x + (w − 52)/2`.
  8. One blank row.
  9. Three starter rows at that left + 2: `/models` `list models from configured providers`, `/sessions` `browse and resume earlier work`, `?` `keys and commands`. Commands are `ink2` bold; descriptions are `muted` at that left + 14.
- **Mark colours.** Letters are `ink`, the ring `magenta_dim`, the star `magenta`. The star is `cyan` while the first prompt waits (§10.2).
- **Brand tiers:**
  - `anim` plays M1 (§10.3) at launch and then shows the static mark. During the first prompt the star orbits the `O` (M9, §10.2).
  - `static` shows the mark with the star at rest.
  - `text` shows `ORBIT` in bold on the mark's middle row (the other two rows are blank) and keeps the tagline.
  - `off` drops the mark, its gap and the tagline.
- **While the first prompt waits** (see `welcome_waiting.png`), the block keeps only the mark and the tagline, on the same rows. Items 4–9 of the list above are dropped. The transcript is bottom-anchored below them. The fit rule, the orbit and the colours are in §10.2 (M9).
- **Leaving the welcome.** The first output of the first turn removes the block, with no transition (§10.2). Any other transcript item removes it too, for example a command's notice.

The expanded mark, exactly (each row starts at the box's left edge):

```text
   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █
```

### 9.23 Size notice

Below 40 columns or 10 rows, draw only the following (see `min_size.png`):

- `✦` `magenta` at (1, 0).
- From row 2, each line centred at `(W − width)/2`:
  1. `ORBIT needs at least 40 × 10` (`ink` bold)
  2. `this terminal is {W} × {H}` (`muted`)
  3. a blank line
  4. `enlarge the window or run` (`muted`)
  5. `orbit chat --no-tui` (`ink2`)

### 9.24 Shutdown line

After the alternate screen is restored on a normal quit, print two lines to stdout, but only if at least one turn was saved during this run:

```text
✦ ORBIT  session saved · {n} turns · {cost}
         resume with orbit chat --resume {full session id}
```

- `{n}` is the saved total, including resumed turns. Omit ` · {cost}` when unpriced.
- Colour (unless the tier is mono): `✦` magenta, `ORBIT` muted bold, the rest `ink2`, and `orbit chat --resume {id}` `ink` bold.
- Print the **full** session id, `session-` prefix included (`orbit chat --resume session-01J8ZK4QX2M7C9RT5VWEHN3B6D`). The short id cannot be resumed.
- On SIGHUP print nothing. On SIGTERM keep the existing stderr note.

### 9.25 Copy mode (`z y`)

- Leave the alternate screen and print the transcript in the plain grammar below, one event per line with no box drawing or colour. Then wait for any key and return.
- The first line is `ORBIT transcript · session {full id} · select and copy, then press any key to return`.
- The event lines are:

  ```text
  14:02 you: {text}
  14:02 orbit: {prose}
  14:02 tool {name} {argument}: done, 0.1s
  14:06 approval needed: {tool} {summary}. y allow once, R allow {tool} for this session, n deny
  14:06 tool {name} {argument}: denied by you
  14:12 error ORBIT-E0406: {message}
  14:13 status: ready. glm-5.2 via local. online. 18.2k in, 2.9k out. $0.0214
  ```

- Multi-line text continues on following lines indented by two spaces. Items without a time omit the time.
- Redactions print as `[redacted: credential]`, `[redacted: url]` or `[redacted]`.
- Delete the current box header and the `user>` / `orbit>` / `[tool: …]` prefixes.

## 10. Motion and redraw discipline

Open `motion_states.png`, `motion_orbit.png`, `motion_startup.png`, `motion_timeline.png` and `welcome_waiting.png` before you implement this section.

**Only stars move, and motion means ORBIT is working.** Exactly two things may move:

1. **The status star**, the glyph of the compact mark at the left of the status line. It turns while ORBIT works, and its speed tells you what kind of work it is (§10.1). It is a state light, not branding, so it turns at every brand tier, including the default `off`.
2. **The star of the expanded mark**, which orbits the `O` of the wordmark (§10.2). It moves only at brand tier `anim`, and only while the expanded mark is on screen: once at startup (M1), and while the first prompt of an empty session waits for its first output (M9).

Nothing else moves. The transcript, tool lines, rails, overlays, headers, composer and the ORBIT gutter glyph change only when data arrives, and they never animate, blink, pulse, fade, slide or cycle colour. Text landing at the 30 ms coalescer flush is data, not motion. An idle ORBIT draws nothing.

| # | Motion | Trigger | Rate | Ends | Brand tier | Reduced motion |
|---|---|---|---|---|---|---|
| M1 | Startup: the 17 frames of §10.3 in the welcome's mark box | Launch while the welcome is showing | 4 fps (250 ms per frame; F17 at 4 s) | F17. Any key jumps to F17 and is then handled normally. | `anim` only | Not played: F17 at once |
| M2 | Status star `◐ ◓ ◑ ◒` | ORBIT works (§10.1) | 2 fps while thinking; 4 fps while writing or while agents run | Any still state (§10.1) | Every tier | A still `✦` in `cyan` |
| M3 | Counters (latency, elapsed, countdown) | While the activity shows one | At most once per 1000 ms, status line only (§10.4) | State ends | Every tier | Unchanged |
| M4 | Streaming text | `TextDelta` | 30 ms coalescer flush (data, not motion) | Stream ends | Every tier | Reveal whole lines only |
| M5 | Turn report | `TurnEnded { ok: true }` | Shown 2 s | 2 s or the next key | Every tier | Unchanged |
| M6 | Reconnect countdown | Only when the runtime reports it | Text at most once per 1000 ms; glyph still | Reconnected or offline | Every tier | Unchanged |
| M7 | Focus change | Focus moves | Instant | | | |
| M8 | Shutdown | Quit | No frames; the line of §9.24 | | | |
| M9 | Welcome orbit: the star circles the `O` in `cyan` | `TurnStarted` for the first prompt of an empty session, while the welcome is showing | 4 fps: 12 stations, 3 s per orbit | The first output (§10.2): the welcome block is removed in the same draw | `anim` only; at `static` the star stays at rest, `cyan` | The star stays at rest, `cyan` |

### 10.1 What ORBIT is doing, and what the status star does

This section uses four names for ORBIT's work: **thinking, writing, agents running, needs you.** They are design names. **The screen never shows the words "thinking", "writing" or "agent"**: the status activity (§9.18) says `waiting for {model}`, `streaming` and `running {tool}`, and hard rule 2 forbids any "thinking…" phrase.

The status star follows the activity row that is showing. Evaluate the rows in this order; the first match wins (the same order as the table in §9.18):

| # | State | Condition (from the messages of §13.3) | Status star | Activity text (§9.18) |
|---|---|---|---|---|
| 1 | Needs you | An approval is pending | Still `✦`, `magenta` | `◇ approval needed · {tool}` |
| 2 | Agents running | At least one tool call is running: `ToolCallStarted` received, no `ToolCallFinished` yet, and no approval pending for it. ORBIT's agent acts through tool calls; the TUI receives no other kind of agent event, and you must not add one. | Turning, `cyan`, **4 fps** | `running {tool}`, or `running {n} tools` when more than one runs at once |
| 3 | Writing | A turn is live and visible output has arrived since `TurnStarted` or since the last `ToolCallFinished`. Visible output is a `TextDelta` that still has characters after the bridge gates, or a `Redacted` chip. A delta the bridge removes entirely changes nothing: not the state, not the rate. | Turning, `cyan`, **4 fps** | `streaming` |
| 4 | Thinking | A turn is live and nothing above applies: no visible output yet this round, before the first text or after a tool finished | Turning, `cyan`, **2 fps** | `waiting for {model}` |
| 5 | Degraded or offline | Reconnecting, rate-limited or offline, only when reported (nothing reports it today) | Still `✦`: `amber` when reconnecting or rate-limited, `red` when offline | See `status_states.png` |
| 6 | Turn report | For 2 s after `TurnEnded { ok: true }`, or until the next key | Still `✦`, `magenta` | `✓ done · …` |
| 7 | Failed | The last `TurnEnded` had `ok: false`, until the next `TurnStarted` | Still `✦`, `red` | `✕ failed · {code}` |
| 8 | Ready | Otherwise | Still `✦`, `magenta` | `ready` |

**The star clock.** Exact, so tests can assert it:

- **Frames.** `◐ ◓ ◑ ◒` in this order, repeating (ASCII glyph set: `- \ | /`). Each frame is `cyan`.
- **State kept.** A frame index `k` (0–3) and `last`, the time of the last frame change.
- **Starting.** When the star goes from a still state to a turning state (at `TurnStarted`, or when a call starts running after an approval): `k = 0` and `last = now`. The `◐` is drawn in the same draw as the new state's text.
- **Advancing.** On every UI tick (16 ms): if the star is turning and `now − last ≥ period`, set `k = (k + 1) mod 4` and `last = now`, and set `LOGO`. The period is 500 ms while thinking and 250 ms while writing or while agents run. A tick advances at most one frame: a late tick never skips frames to catch up.
- **Changing speed** (thinking ↔ writing ↔ agents running): keep `k` and `last`; only the period changes. The star never jumps to another frame and never restarts from `◐`.
- **Stopping.** Entering a still state draws that state's still `✦`, in its colour, in the same draw as the state's text, and discards `k`.
- **Reduced motion.** Every turning state shows a still `✦` in `cyan`, and the star clock sets no flag.

Worked example (`motion_timeline.png`): `TurnStarted` at 0 ms draws `◐`. With 16 ms ticks the frame changes at 512 and 1024 ms (thinking). The first visible text arrives at 1200 ms; the next change comes at 1280 ms, the first tick where `now − last ≥ 250`, and then every 256 ms. `ApprovalRequested` shows the still magenta `✦` in the next draw. After you allow the call, the star starts again from `◐`. `TurnEnded` shows the still magenta `✦` in the same draw as the turn report.

### 10.2 The star orbiting the O

The expanded mark (§9.22) is the wordmark `ORBIT`, whose `O` is you, with a ring around the `O` (the harness) and a star on the ring (ORBIT, the agent). At rest the star sits on the ring at the upper right of the `O`. At brand tier `anim` the star travels around the `O` along the ring:

- 12 **stations**, one every 250 ms, a full orbit in 3 s.
- Counter-clockwise on screen: from rest over the top of the `O` (passing behind it), down its left side, across the front of its lower stroke, and up its right side back to rest.
- Positions are in box coordinates: column 0 is the left edge of the 33-column mark box, the `O` occupies columns 3–7, and rows 0–2 are the mark's rows.

| Station | Cell (col, row) | Drawn |
|---|---|---|
| 0 (rest) | (10, 0) | `✦` |
| 1 | (8, 0) | `✦` on the ring |
| 2 | (6, 0) | Not drawn: the star is behind the `O`, whose `▀` stays |
| 3 | (3, 0) | Not drawn: behind the `O`, whose `▄` stays |
| 4 | (1, 1) | `✦` on the ring |
| 5 | (0, 1) | `✦` on the ring |
| 6 | (0, 2) | `✦` on the ring |
| 7 | (2, 2) | `✦` on the ring |
| 8 | (4, 2) | `✦` in front of the `O`, covering its `▄` |
| 9 | (7, 2) | `✦` in front of the `O`, covering its `▀` |
| 10 | (9, 1) | `✦` on the ring |
| 11 | (10, 1) | `✦` on the ring |

- **Cells.** Every cell of the box shows the static mark except the star's cell. When the star leaves a cell, that cell shows its static glyph again: ring braille in `magenta_dim`, or a letter stroke in `ink`. While the star is away from rest, the rest cell (10, 0) shows the ring glyph `⣄` in `magenta_dim`. So each step changes at most two cells.
- **Clock.** The same rule as the status star, with a 250 ms period: the station index `s` and `last`; on a UI tick, if `now − last ≥ 250 ms`, `s = (s + 1) mod 12` and `last = now`, and set `LOGO`.
- **Storage.** Keep the three mark rows, the 12-row station table and the startup frames of §10.3 as constants in the glyph table module (hard rule 10). The frames below are the reference; tests compare against them.

**M9, the welcome orbit** (brand tier `anim`, the first prompt of an empty session). See `welcome_waiting.png` and `motion_orbit.png`.

- **While the first prompt waits,** the welcome shrinks to its brand part. As soon as the transcript holds a queued prompt row (at submit), and until the first output, the welcome block keeps only the expanded mark and the tagline, on exactly the rows they had in the full welcome. Everything below the tagline is dropped: the readiness row and the starters. The transcript (the queued row, then your turn and the `waiting for {model}` line) is drawn bottom-anchored as usual (§8.1).
  - **Fit.** If the transcript's top row would be less than 2 rows below the tagline row, drop the welcome block entirely instead.
  - **Brand tiers.** At `text` the bold `ORBIT` and the tagline stay. At `off` there is no mark and no tagline, so nothing of the welcome stays.
- **The orbit.** From the submit the star is `cyan`, still at rest. At `TurnStarted` it starts from station 0, advances one station every 250 ms, and keeps orbiting until the first output.
  - The ring stays `magenta_dim`, and the letters stay `ink`.
  - At brand tier `static` (including reduced motion, which clamps to `static`), the star stays at rest in `cyan`.
- **The first output ends it.** The first output is anything added to the transcript other than a queued prompt row: the first visible text or redaction chip, a tool line, a notice or an error card. `TurnEnded` for any reason also counts. In that same draw the welcome block is removed with no transition. Everything bottom-anchored stays where it was.
- **Only once per session.** M9 runs only for the first prompt of an empty session. A new session (`g n`, §11.6) shows the welcome again, so its first prompt runs M9 again. `/clear` does not: it leaves a notice in the transcript, so the welcome does not return. Later turns show only the status star.
- The status star turns at the same time (thinking, 2 fps). Both clocks start at `TurnStarted`, so the status star changes on every second orbit step.

### 10.3 Frames

**M9 station frames.** The 33-column mark box at each station, with all five letters. The star is `cyan` in M9. Rows are shown without trailing spaces.

```text
── station 0 · cell (10, 0) · rest · 0 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 1 · cell (8, 0) · on the ring · 250 ms after TurnStarted in the first orbit
   ▄▀▀▀▄✦⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 2 · cell (6, 0) · behind the O: no star drawn · 500 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 3 · cell (3, 0) · behind the O: no star drawn · 750 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 4 · cell (1, 1) · on the ring · 1000 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠✦⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 5 · cell (0, 1) · on the ring · 1250 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
✦⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 6 · cell (0, 2) · on the ring · 1500 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
✦⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 7 · cell (2, 2) · on the ring · 1750 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒✦▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 8 · cell (4, 2) · in front of the O · 2000 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀✦▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 9 · cell (7, 2) · in front of the O · 2250 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄✦    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 10 · cell (9, 1) · on the ring · 2500 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠✦⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── station 11 · cell (10, 1) · on the ring · 2750 ms after TurnStarted in the first orbit
   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴✦ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █
```

**M1 startup frames.** At brand tier `anim`, at launch, when the welcome is showing (no `--resume`). The frame times are nominal: with 16 ms ticks and the clock rule of §10.2, each frame is shown for 256 ms.

- F1 is the `O` alone.
- F2 and F3 draw the first third, then two thirds, of the ring.
- F4 closes the ring, and the star appears at rest in `magenta_hi`.
- F5–F15 carry the star, now `magenta`, through stations 1–11. At stations 2 and 3 it is behind the `O`, so F6 and F7 show no star.
- F16 has the star back at rest, and `RBIT` fills in.
- F17 adds the tagline. It is the final state: the static welcome.
- **What changes.** Only the mark box and, at F17, the tagline row change during M1. Everything else is in its final state from F1: the rest of the welcome block, the Workspace rail, the composer, and the still status star.

Frame F17 adds the tagline two rows below the mark (one blank row between), placed by the welcome rule of §9.22, not relative to the box.

```text
── F1 · 0 ms · the O alone: you
   ▄▀▀▀▄
   █   █
   ▀▄▄▄▀

── F2 · 250 ms · a third of the ring
   ▄▀▀▀▄
⣠  █   █
⠙⠒⠒▀▄▄▄▀

── F3 · 500 ms · two thirds of the ring
   ▄▀▀▀▄⠤⠤
⣠⠖⠋█   █
⠙⠒⠒▀▄▄▄▀

── F4 · 750 ms · ring closed, star arrives · star magenta_hi
   ▄▀▀▀▄⠤⠤✦
⣠⠖⠋█   █⣠⠴⠋
⠙⠒⠒▀▄▄▄▀

── F5 · 1000 ms · station 1 · star magenta
   ▄▀▀▀▄✦⠤⣄
⣠⠖⠋█   █⣠⠴⠋
⠙⠒⠒▀▄▄▄▀

── F6 · 1250 ms · station 2 · behind the O · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠⠴⠋
⠙⠒⠒▀▄▄▄▀

── F7 · 1500 ms · station 3 · behind the O · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠⠴⠋
⠙⠒⠒▀▄▄▄▀

── F8 · 1750 ms · station 4 · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠✦⠋█   █⣠⠴⠋
⠙⠒⠒▀▄▄▄▀

── F9 · 2000 ms · station 5 · star magenta
   ▄▀▀▀▄⠤⠤⣄
✦⠖⠋█   █⣠⠴⠋
⠙⠒⠒▀▄▄▄▀

── F10 · 2250 ms · station 6 · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠⠴⠋
✦⠒⠒▀▄▄▄▀

── F11 · 2500 ms · station 7 · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠⠴⠋
⠙⠒✦▀▄▄▄▀

── F12 · 2750 ms · station 8 · in front of the O · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠⠴⠋
⠙⠒⠒▀✦▄▄▀

── F13 · 3000 ms · station 9 · in front of the O · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠⠴⠋
⠙⠒⠒▀▄▄▄✦

── F14 · 3250 ms · station 10 · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠✦⠋
⠙⠒⠒▀▄▄▄▀

── F15 · 3500 ms · station 11 · star magenta
   ▄▀▀▀▄⠤⠤⣄
⣠⠖⠋█   █⣠⠴✦
⠙⠒⠒▀▄▄▄▀

── F16 · 3750 ms · at rest · RBIT fills in · star magenta
   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

── F17 · 4000 ms · tagline · end · star magenta
   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

the harness that orbits around you
```

### 10.4 Clocks, counters and dirty flags

- **UI tick** (16 ms, existing). Poll input and deadlines.
  - **Coalescer flush** (every 30 ms). Sets `TRANSCRIPT`, but only when text was flushed.
  - **Star clocks** (§10.1, §10.2). Set `LOGO`, but only when a frame, station or startup frame changes.
  - **Text clock.** One global clock that fires every 1000 ms from app start. At each firing, and when a state that shows a counter begins, sample every counter in the activity text. Set `STATUS` only when a sample changes the displayed text.
  - **Deadlines** set their flag once, when they pass: turn report 2 s, toast 3 s, approval arming 1 s, Ctrl+C window 2 s.
- **Counters are sampled, not live.**
  - Draws between two samples reuse the last sample. The star redraws the screen 2–4 times a second, but a counter changes at most once a second.
  - A counter is the time since its state began, in the Duration format of §7.3:
    - latency: from `TurnStarted` or the last `ToolCallFinished`
    - tool elapsed: from the later of `ToolCallStarted` and your approval decision
    - streaming elapsed: from the round's first visible output
  - A sample under 1.0 s hides the counter and its ` · `: the activity reads `waiting for glm-5.2` alone.
- **Idle.** With no live turn, no M1 or M9 playing, and no deadline pending, no tick sets any flag. Remove the shimmer, the thinking-phrase rotation, the cost flash and the reconnect glyph rotation.
- **Draw rules.**
  - Draw only when a flag is set, and never draw an empty frame.
  - Scrolling moves by whole rows.
- **Motion budget.** Between two consecutive draws with no worker message and no key in between, the only cells that may differ are:
  - the status star cell;
  - the status activity text, when the text clock sampled a new counter value (at most once per 1000 ms);
  - the cells of the mark box during M1 and M9, and the tagline row at M1's F17.

  `invariant_only_stars_move` (§16.3) checks this.

## 11. Interaction

### 11.1 Focus

- **Targets:** Sessions rail, Conversation (the composer), Workspace rail, Status line.
- **Tab / Shift+Tab** cycle `Sessions → Conversation → Workspace → Status → Sessions`, using the existing `Focus::next`/`prev` order. In single-view layouts they cycle the three views and skip Status.
- **Where Tab does something else:** while the inline completion list is open, Tab completes instead; in the palette, Tab moves to the next section; while an approval card or overlay is open, Tab is ignored.
- **Default focus** is the Conversation.

### 11.2 Keys by context

The first matching context wins:

1. **Quit card, palette or help open.** Only that overlay's keys work (§9.19–9.21). Ctrl+C still works (§11.7).
2. **Approval pending.** The card's keys (§11.5). Ctrl+C, Ctrl+D and PgUp/PgDn (when the action does not need scrolling) still work. Everything else is ignored, and nothing is typed into the hidden composer.
3. **Composer focused.** §11.3.
4. **Rail or status focused:**

   | Key | Action |
   |---|---|
   | `1` `2` `3` | Focus Sessions / Conversation / Workspace |
   | `/` | Palette |
   | `?` | Help |
   | `q` | Quit card |
   | `g s` / `g v` | Sessions / Activity tab |
   | `g n` | New session (§11.6) |
   | `z y` | Copy mode |
   | `z t` | Toggle the last tool detail |
   | `↑` / `↓` | Move the rail cursor |
   | `⏎` | On a session row, resume it (unless it is the open session) |
   | `Esc` | Focus the Conversation |

   Leaders (`g`, `z`) keep the existing two-key parser. **Replace** today's mapping of `/` and `z y` to copy mode.

### 11.3 Composer keys

- **Printable characters** insert at the cursor, including digits and `q g z /`.
  - `?` typed into an **empty** composer opens help instead.
  - `/` typed into an empty composer inserts `/` and opens the completion list.
- **⏎:**
  - completion list open: run the selected command if it takes no argument; otherwise complete it to `/model ` or `/resume `
  - text starts with `/`: the command (§11.6)
  - non-empty: send (queue while a turn runs)
  - empty, and the last turn failed: resend that prompt with toast `✓ resent your last prompt`
  - otherwise: nothing
- **Newline:** Shift+⏎ (reported only with keyboard enhancement, §12.4) and Alt+⏎ (always) insert one.
- **Deleting:** Backspace deletes the previous grapheme cluster. Ctrl+W and Ctrl+Backspace delete the previous word (the whitespace before it, then the non-whitespace run).
- **Moving:**
  - `←`/`→` move by grapheme cluster.
  - `Home`/`End` go to the start/end of the current line. `End` on an empty composer jumps the transcript to the newest row instead.
  - `↑` on the first row recalls the previous history entry (this session's sent prompts, including resumed history, newest first), stashing the draft. `↓` on the last row moves toward newer entries and restores the stash after the newest. Otherwise the arrows move between rows.
- **Scrolling:** PgUp/PgDn scroll the transcript by `view − 2` rows.
- **Esc** closes the completion list if it is open; otherwise it does nothing.

### 11.4 Queue

Prompts sent while a turn runs are queued; the worker already processes its channel in order.

- Each queued prompt shows a queued row (§9.12) until its `TurnStarted`, then becomes a user turn with its submit time.
- Commands sent while a turn runs queue the same way, except the TUI-local ones (`/help`, `/sessions`, `/usage`), which run at once.
- **Never clear or replace the in-flight turn when a prompt is submitted.**

### 11.5 Approval flow

1. On `ApprovalRequested`:
   1. Push the request onto a FIFO queue. In a single-view layout, switch to the Conversation view.
   2. Set the tool line with that `call_id` to awaiting (`◇`).
   3. Open or refresh the card for the oldest request.
   4. Arm or pause per §9.14.
   5. Ring one BEL if `[notify] bell_on_approval = true`.
2. Decision keys:

   | Key | Response |
   |---|---|
   | `y` or `Y` | `ApprovalResponse::Allow` |
   | `R` (Shift+r) | `ApprovalResponse::AllowSession` |
   | `n`, `N` or `Esc` | `ApprovalResponse::Deny` |

   Lowercase `r` does nothing. A key does nothing while disabled.
3. On a decision, call `ApprovalRegistry::resolve(call_id, response)`.
   - **If it returns `true`:**
     - Remove the request and close or refresh the card.
     - Update the tool line: once → `◉ running` with `◆`; session → `◉ running` with `◈`, and add the tool to the grant slot; deny → `⊘ denied by you`.
     - Add an Activity `grant` row.
     - Keep the draft.
   - **If it returns `false`** (the worker is gone): remove the request and add the error notice `approval could not be delivered · the turn has ended`.
4. **Never** send `ToolCallFinished` or any success or failure from the key handler. The line's final state comes only from the worker's `ToolCallFinished`. A `Denied` outcome keeps `⊘`.
5. **Quitting** (card, Ctrl+C twice, or a signal) calls `ApprovalRegistry::deny_all()` first. The signal path already does.

### 11.6 Commands

These are the existing REPL commands; do not add new ones.

- **Run by the TUI itself, at once:**
  - `/help` opens help.
  - `/sessions` focuses the Sessions rail (or view).
  - `/usage` adds a notice: `turns {n} · in {tokens} · out {tokens} · {cost}`.
- **Sent to the worker** as `WorkerRequest::Command`, run in order:
  - `/models` → a notice `models`, then one row per model at `cl`: the model in `ink2`, two spaces, the provider in `muted`. When no providers are configured, the notice reads `no providers configured` instead.
  - `/model` alone → notice `usage: /model <model-id>`.
  - `/model <id>` → `ModelChanged`: notice `model → {id}`, the status model slot, an Activity `model` row.
  - `/clear` → the worker clears its transcript. The TUI clears the transcript view and shows the notice `conversation cleared · earlier turns are no longer sent to the model`. The header turn count is unchanged.
  - `/resume <id>` → `HistoryLoaded` + `Identity`. On failure, an error notice `cannot resume {id}: {reason}`.
- **Unknown `/x`** → notice `unknown command: /x · try /help`. Never send a line starting with `/` to the model.
- **Exact `exit` or `quit`** → the quit card.
- **`g n`, or new session:** the worker keeps nothing of the old conversation, gets a new id from `orbit_gateway::new_session_id()`, resets its grants and sends `Identity`. The TUI clears transcript, counters and grants and shows the welcome. During a turn, show the toast `wait for this turn to finish first` instead.
- **Resume during a turn** shows the same toast.

### 11.7 Quit

- `q` (outside the composer), Ctrl+D, or the first Ctrl+C opens the quit card.
- A second Ctrl+C within 2 s quits immediately.
- In the card: `y` quits; `n` or `Esc` closes it.
- Signals keep today's noninteractive path.

## 12. Capabilities, fallbacks and configuration

Resolve everything once at startup, before entering the alternate screen, into one `Capabilities` value. Values can step down at runtime (for example, a failed write) but never up.

### 12.1 Colour tier

1. **Detect:**
   - `NO_COLOR` present (any value) → mono.
   - Otherwise `COLORTERM` is `truecolor` or `24bit` → true colour.
   - Otherwise `WT_SESSION` set → true colour.
   - Otherwise `TERM` contains `256color` → 256.
   - Otherwise 16.
2. **Config** `[color] mode = "auto" | "truecolor" | "256" | "16" | "mono"` can only **lower** the detected tier. `NO_COLOR` cannot be overridden (H-7).

### 12.2 Glyph set and width probe

1. **Locale.** Take the first non-empty of `LC_ALL`, `LC_CTYPE`, `LANG`. It is UTF-8 if it contains `utf-8` or `utf8` (case-insensitive).
   - If none is set: on Windows it is UTF-8 when `WT_SESSION` is set; everywhere else, not UTF-8.
   - Not UTF-8 → ASCII glyphs. This is a hard downgrade that no config can override.
2. **Config** `[glyphs] set = "auto" | "unicode" | "ascii"`: `ascii` forces ASCII; `unicode` skips the probe (and cannot override step 1).
3. **Width probe** (auto only), before the alternate screen and in raw mode:
   1. Write `\r●`.
   2. Read `crossterm::cursor::position()`. If the column is 2, ambiguous glyphs are wide → ASCII.
   3. Write `\r` and clear the line.
   4. If `position()` returns an error → keep Unicode.
4. **Delete** the `LANG`/`LC_ALL` forcing in `terminal.rs`.

### 12.3 Brand tier and reduced motion

- **Brand tier.** Config `[brand] tier = "off" | "text" | "static" | "anim"`, default **`off`** (H-4 stays locked until DR-20 is amended; see `DESIGN.md` §8.5). Clamp with the `BrandTier` order (`Anim < Static < Text < Off`; larger is more degraded):
  - `NO_COLOR` → at least `Text`
  - reduced motion → at least `Static`
  - ASCII glyphs → at least `Text`
- **What the tiers move.**
  - `anim` plays M1 at launch and M9 during the first prompt (§10.2–10.3).
  - `static` shows the same mark, still, with the star at rest.
  - The status star (M2) is not brand motion. It turns at every brand tier and stops only under reduced motion.
- **Reduced motion:** `ORBIT_REDUCED_MOTION=1` or `[motion] reduced = true`.
- **Golden tests** render at `Static` (§16.2).

### 12.4 Terminal setup

- **Keyboard enhancement.** If `crossterm::terminal::supports_keyboard_enhancement()` returns `Ok(true)`, push `KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES` after entering raw mode. Pop it on exit and around copy mode.
- **Cursor style.** Steady bar on entry; restore it on exit (in `Drop`, so it also happens on panic).
- **Mouse capture** stays off.

### 12.5 Launch gating

In the TUI block of `main.rs`, also fall back to the REPL when any of these hold (H-7):

- `TERM` is `dumb`
- `CI` is set
- `ORBIT_SCREEN_READER` is `1`

`NO_COLOR` does **not** prevent launch; it selects mono.

Pass the CLI's resolved `home` into the TUI. Today `lib.rs` re-derives `ORBIT_HOME` with a relative `.orbit` fallback; stop doing that and load `tui.toml` from the CLI's `home`.

### 12.6 Configuration

Appendix C lists every key.

- A user theme may recolour tokens. It may not add colours, animate anything or change glyph meanings.
- Old keys keep working for one release and log one deprecation line to stderr, after the alternate screen closes.

## 13. Data contract and protocol

### 13.1 What exists and what to render

| Element | Source today | When absent or not supplied |
|---|---|---|
| Streamed text | `ProviderEventKind::TextDelta` via the bridge | — |
| Output tokens mid-stream | `ProviderEventKind::UsageUpdate`, if the provider sends it; forward it | Show elapsed time instead |
| Tokens, cost per turn | `run_turn` outcome | — |
| Priced or not | `ProvidersConfig::pricing_for_model(model).is_some()` in the worker | `cost n/a` |
| Tool name | `call.name` | — |
| Tool argument | Display-safe summary `name(keys)` from `safe_call_summary` | Nothing after the name |
| Tool outcome words (`48 passed`) | None | Meta is the duration only |
| Tool live output tail | None | No detail while running |
| Tool error text | Result JSON `"error"` field, through the bridge gates | `failed` |
| Blocked (unknown tool) | `crate::tools::is_known_tool(&call.name) == false` | — |
| Approval request | `call_id`, `tool_name`, `summary` | No risk badge, no facts grid |
| Grants | Your R decisions; `auto_tools` from `TuiTurnConfig` | No grant slot |
| Connection | Nothing sends `ConnectionChanged` | Blank slot until the first successful turn, then `● online`. A failed turn leaves the slot unchanged. |
| Reconnect attempt and countdown, rate limit | None | Not shown |
| Session list | `sessions::list_sessions(home)` in the worker | The open session alone |
| Session title | First user message: first line, whitespace collapsed, bridge gates | Short session id (§7.3) in `faint` |
| Session state (saved sessions) | None | No glyph |
| Resumed history | `SessionFile.transcript`, **through the bridge gates** (saved text can contain reasoning tags) | — |
| Workspace (phase, plan, findings, verification) | None | Empty state (§9.17); switcher `Workspace` faint |
| Citations, sources | None | `[n]` stays plain text; no sources line |
| Evidence card | None | Not shown |
| Readiness checks (welcome) | None | Row omitted |
| Ledger counts | None | Not shown anywhere |

The TUI's state keeps a model for every row of this table (workspace, citations, evidence, risk, facts, readiness, session states, tool outcomes), so the fixtures in Appendix B can fill them. Nothing at runtime fills the ones marked "None". Do not add backend features to fill them.

### 13.2 Turn model in `App`

Replace `transcript: Vec<TranscriptLine>` and `in_flight: String` with an ordered list of items:

- **User turn:** text, submit time, prompt id.
- **ORBIT turn:** start time, end time, live/settled, and an ordered list of blocks. Blocks are prose (with inline segments text, code and redaction), tool line, code, sources and evidence.
- **Notice:** kind, text, time.
- **Error card.**
- **Queued prompt.**

Cache wrapped lines per item per width, so rendering cost follows the visible rows, not the session length.

**Delete** `TranscriptLine::Stripped` and the `[tool] …` lines. Session title and turn count live in `App`; the header derives from them.

### 13.3 Messages

Replace the data-bearing `Msg` variants with this set. Control variants (`Quit`, `Resize`, `Tick`, `KeyAction`, `ComposerChanged`, `CtrlC`, `EnterCopyMode`, `RequestQuit`, `ConfirmQuit`, `CancelQuit`, `SignalShutdown`) stay.

**Worker → TUI** (all text already through the bridge gates):

| Message | Fields | Sent when | Reducer effect |
|---|---|---|---|
| `Identity` | `model`, `provider`, `session_id` (full), `auto_tools`, `priced` | Worker start, after resume and new session | Status slots; short id per §7.3 |
| `SessionsListed` | `Vec<SessionSummary { id, title: Option<String>, updated_at_unix: u64, turns: u64, state: Option<SessionState> }>` | Worker start and after every save | Sessions rail |
| `HistoryLoaded` | `items: Vec<HistoryItem>`, `turns`, `input_tokens`, `output_tokens`, `cost` | Start with `--resume`, `/resume` | Replace transcript and counters |
| `TurnStarted` | `prompt_id: u64` | Worker takes a prompt from the channel | Queued row → user turn; open a live ORBIT turn (waiting); start the status star (§10.1) and, for the first prompt of an empty session, M9 |
| `TextDelta` | `String` | Stream | Coalesce into the current prose block |
| `Redacted` | `kind: Option<RedactionKind>` (`Credential`, `Url`) | Bridge rejected a chunk | Flush the coalescer, append a chip |
| `UsageUpdate` | `output_tokens: u64` | Provider sent usage mid-stream | Status `n tokens` |
| `ToolCallQueued` | `call_id`, `name`, `summary` | For every call of a round, in order, before any executes | `◌ queued` lines |
| `ToolCallStarted` | `call_id`, `name`, `summary` | As each call begins | `◉ running` |
| `ApprovalRequested` | `call_id`, `tool_name`, `summary`, `risk: Option<Risk>`, `facts: Vec<(String, String)>` | Runtime asks (both optional fields empty today) | §11.5 |
| `ToolCallFinished` | `call_id`, `name`, `outcome: ToolOutcome` (`Ok { summary: Option<String> }`, `Failed { summary: Option<String>, error: String }`, `Denied`, `Blocked { reason: String }`) | After `execute_call` returns | Final line state and detail; Activity `tool` row |
| `CostUpdated` | `turn_cost: u64` | After each provider round | Status cost = committed + this |
| `TurnEnded` | `ok`, `input_tokens`, `output_tokens`, `cost`, `error: Option<TurnError { code: Option<String>, message: String }>` | **Exactly once per `TurnStarted`**, on success and on every failure path | Commit counters; settle the turn; M5 report or failed state and error card; ends M9 |
| `Notice` | `kind` (`Info`, `Warn`, `Error`), `text` | Command output, save warnings | Notice row; Activity row for Warn and Error |
| `ModelChanged` | `model`, `priced` | `/model <id>` | Status, notice, Activity |
| `ConversationCleared` | — | `/clear` | Clear the view, notice |
| `ConnectionChanged` | `ConnectionState` (`Online`, `Reconnecting`, `RateLimited`, `Offline`) | Nothing sends it today | Connection slot |

**TUI → worker:** change the prompt channel from `String` to `WorkerRequest`:

- `Prompt { prompt_id, text }`
- `Command { text }`
- `NewSession`

Remove `Msg::TextSubmitted`'s double role: the input handler sends the request on the channel and posts a local `Msg` that only adds the queued row.

**`HistoryItem`:**

- `User { text }` for user messages.
- `Assistant { text }` for assistant content, through the bridge gates.
- `Tool { call_id, name, summary, ok: Option<bool> }` for assistant tool calls, with the summary from `safe_call_summary(name, parsed args)` and `ok` from the matching `Tool` message's `"ok":true`.

History items carry no times.

**Resolving `ToolOutcome` in the worker:**

- `Blocked { reason: "unknown tool" }` when `!is_known_tool(name)`.
- `Denied` when `TuiApprovalChannel` returned `Deny` for this call id. Record the verdict per call id in the channel.
- `Ok` when the result JSON has `"ok":true`.
- `Failed { error }` otherwise, where `error` is the result's `"error"` string. An `Err(e)` from `execute_call` is also `Failed`.

Summaries are `None` today.

### 13.4 Bridge

- **Stateful CoT stripping.** Keep state across the deltas of one turn. Once an opening reasoning tag is seen, drop everything until its closing tag, across chunks. A trailing partial tag (`<`, `<thi`) is held back until the next delta decides it. Reset at `TurnEnded`. The tags are the existing `COT_TAGS`, case-insensitive.
- **Redaction.** `safe_text` stays the gate. When it rejects, emit `Redacted` instead of the literal `[redacted]`. The kind is chosen by the bridge from the rejected text:
  - `Credential` if it contains `api_key`, `apikey`, `authorization`, `x-api-key` or `bearer ` (case-insensitive)
  - `Url` if it contains `://`
  - otherwise none
- **Errors.** Split `ORBIT-E1234: message` / `E1234: message` into `code` + `message` **before** gating, so the code survives a redacted message.

### 13.5 Worker changes (`tui_worker.rs`)

1. **Grants.** Create `AutoGrants` once per session: in `worker_main`, reset on resume and new session. Do not create it per provider round (line 218), so `R` means what its label says. The REPL's per-turn lifetime (`main.rs:1102`) is out of scope; report it, do not change it.
2. **Turns.** Send `TurnStarted` before each prompt and `TurnEnded` exactly once after it, including every error path.
   - The current `emit_error` turn failures become `TurnEnded { ok: false, error }`.
   - Stop sending `ResponseFinished` with an empty `output`.
3. **Tools.** Send `ToolCallQueued` for every call of a round before executing any. Send `ToolCallStarted` and `ToolCallFinished` with `call_id` and the resolved outcome.
4. **Usage.** Forward `UsageUpdate` from the observer.
5. **Saving.** Save the session with **cumulative** `turns`, `input_tokens`, `output_tokens` and `cost` (resumed values plus this run). Today it saves `turns = 0` and per-turn totals (lines 256–267). Send `SessionsListed` after each save and a `Warn` notice if saving fails.
6. **Resume.** Load the resumed session (from `main.rs`'s `resumed_file`, passed through `TuiTurnConfig`) into the worker transcript and send `HistoryLoaded`. Today the TUI starts with an empty transcript (line 43) and then overwrites the saved file with only the new turns.
7. **Commands and new session** per §11.6.

## 14. Defects to fix

All of these are present in the current code. Each has a test in §16.3.

| # | Where | Defect | Fix |
|---|---|---|---|
| D1 | `lib.rs:446` vs `lib.rs:470` | `KeyParser::parse` returns `Some(Unknown)` for `y n R Esc`, so `handle_key` returns before the approval block. Approvals can never be answered. | Route keys by context (§11.2); the approval context comes before the parser |
| D2 | `state.rs:333` | Every `ToolCallStarted` pushes a fake pending approval `call-{n}`, ahead of the real one | Delete; approvals come only from `ApprovalRequested` |
| D3 | `lib.rs:470–509` | Pressing `y`/`R` sends `ToolCallFinished { ok: true }` before the tool runs; `n`/`Esc` report a denial as an error; lowercase `r` grants the session | §11.5 |
| D4 | `state.rs:356–362` | `TextSubmitted` appends the prompt and clears `in_flight` mid-stream; the streamed text is lost (`ResponseFinished.output` is empty, `tui_worker.rs:67`) | Queue (§11.4); never touch the live turn |
| D5 | `state.rs:381` + `state.rs:320` | `CostUpdated` overwrites the total and `ResponseFinished` adds the turn cost again: double counting within a turn, lost history across turns | Committed + current-turn cost (§13.3) |
| D6 | `bridge.rs` `strip_cot` | Stateless per delta: when the opening tag arrives alone, the reasoning in later deltas is displayed | §13.4 |
| D7 | `bridge.rs` `safe_text` | Returns the literal `[redacted]`, indistinguishable from content | `Redacted` message and chip |
| D8 | `tui_worker.rs:218` | `AutoGrants` is recreated per provider round, so `R` lasts one round | §13.5 |
| D9 | `tui_worker.rs:256–267` | Saves `turns = 0` and per-turn totals | §13.5 |
| D10 | `tui_worker.rs:43` | `--resume` in the TUI starts with an empty context, then overwrites the saved session | §13.5 |
| D11 | `lib.rs` (`TextSubmitted` path) | `/models` and every `/command` is sent to the model as a prompt | §11.6 |
| D12 | `input.rs` + `lib.rs:462` | `/` and `z y` both map to `CommandPalette`, which enters copy mode | `/` palette, `z y` copy mode |
| D13 | `terminal.rs:112–118` | Forces `LANG`/`LC_ALL` to `en_US.UTF-8`, hiding non-UTF-8 terminals | Detect (§12.2) |
| D14 | `lib.rs:297` | `Composer::pop` removes one `char`, which breaks graphemes | §11.3 |
| D15 | `render.rs:268` | Prints `[tool: name] (reasoning stripped)` | Delete (§3, rule 2) |
| D16 | `state.rs:265–280` | Shimmer every 8 ticks redraws the whole layout while idle; the thinking phrases rotate | Delete (§10) |
| D17 | `lib.rs:59–62` | Loads `tui.toml` from `ORBIT_HOME` or a relative `.orbit` | Use the CLI's home (§12.5) |
| D18 | `main.rs:833` | An unpriced or incompletely priced model costs `0`, shown as `$0.0000` | The TUI shows `cost n/a` when unpriced (§13.1). Incomplete rates stay `0`: report, do not fix. |

## 15. Build plan

Work in this order. Commit after each step with a message naming the step. Run the checks of §1 after each step, and do not start the next step with a failing check.

1. **Foundations.**
   - Theme tokens and tiers (§6), `Glyphs` (§7.1), text formats (§7.3), grapheme utilities (§7.4), `Capabilities` (§12).
   - Delete the shimmer, phrases, cost flash and reconnect rotation.
   - Unit tests for every formatter and for tier and glyph resolution.
2. **Protocol and bridge.** `Msg` (§13.3), `WorkerRequest`, bridge changes (§13.4), worker changes (§13.5), turn model (§13.2), reducer. Fix D2, D4–D11. Tests with a scripted worker.
3. **Layout and chrome.** Rows, width classes, conversation column, rails geometry, headers and switcher, dividers and scroll bar, status line with the star clock and counter sampling (§8, §9.1–9.3, §9.18, §10.1, §10.4).
4. **Transcript.** User turn, ORBIT turn, markdown, code, tool lines, evidence, citations, notices, errors, redaction, queued rows (§9.4–9.12).
5. **Composer and approval.** Composer, completion, toasts, the approval card with arming and scroll-gating, the key routing and approval flow. Fix D1, D3, D12, D14.
6. **Rails, overlays and brand.** Sessions, Activity, Workspace (§9.15–9.17), palette, help, quit, welcome with M1 and M9, size notice, shutdown line, copy mode (§9.19–9.25, §10.2–10.3).
7. **Goldens and invariants** (§16). Make every golden pass. Run the vision comparison (§16.4).

## 16. Tests and verification

### 16.1 Test seams

- **Clock.** An injectable clock (`now` for times, recency and deadlines).
- **Capabilities.** A constructor that takes explicit values, so no test reads the environment.
- **Worker.** A scripted worker that plays a list of `Msg`s into the reducer.
- **Terminal.** Render with `ratatui::backend::TestBackend`.
- **Motion.** Motion tests drive the injected clock in 16 ms UI ticks, as the app does, and record which flags each tick sets. Golden fixtures set motion state directly (star frame, orbit station, counter samples) instead of playing time forward.

### 16.2 Golden frames

- **Fixtures.** Build each fixture of Appendix B, render at its size, and compare with the matching file in `docs/tui/golden/`. Copy those files into `crates/hud-tui/tests/golden/`.
- **Comparison.** Symbols: trim trailing spaces per row. The buffer is the full size; the golden file has one line per row.
- **Cursor.** Assert the terminal cursor against the style map's `cursor` field: `[col, row]` means shown there, and `null` means hidden.
- **Brand tier.** Goldens use `Static`, except where the fixture says otherwise.
- **Colour.** For every true-colour golden, also compare each cell with `<name>.styles.json`. The file lists, for each row, runs of `[first_col, last_col, fg, bg, flags]`. `fg` and `bg` are token names (`fg` is `null` for spaces, where only the background counts), and `flags` is a string of `b` (bold) and `u` (underline). Your true-colour buffer's RGB must equal the token's hex from §6.1. The 16-colour and mono tiers are compared by symbols only.
- **Failures.** When a golden fails, print a row-by-row diff with column numbers.

### 16.3 Invariants and behaviour tests

| Test | Asserts |
|---|---|
| `invariant_one_frame_max` | At most one rounded frame in any buffer: count `╭` corners |
| `invariant_magenta_closed_list` | In every golden buffer, every magenta cell belongs to one of the six uses of §6.2 (check by position) |
| `invariant_idle_draws_nothing` | After a turn settles and the 2 s report expires, 1,000 ticks set no dirty flag |
| `invariant_only_stars_move` | Play the turn of `motion_timeline.png` with the scripted worker in 16 ms ticks, at brand tier `anim`, from an empty session. Between consecutive draws with no message or key in between, only the cells of the motion budget (§10.4) differ |
| `status_star_cadence` | The worked example of §10.1: frame changes at 512 and 1024 ms while thinking, then at 1280 ms and every 256 ms after the first visible text; `k` is kept across speed changes; the still magenta `✦` in the same draw as `ApprovalRequested` and as `TurnEnded`; restart at `◐` after the approval; a delta the bridge removes entirely changes neither state nor rate |
| `welcome_orbit` | Brand `anim`, empty session, first prompt: at `TurnStarted` the mark box equals station 0 with a cyan star; after each further 16 ticks it equals the next station frame of §10.3. The first visible text removes the mark and tagline in the same draw, and the transcript rows do not move. Brand `static`: the rest frame with a cyan star for the whole wait, and no `LOGO` flag. Brand `off`: no welcome rows after submit. A fit failure (a tall first prompt) drops the block at once. |
| `startup_sequence` | Brand `anim`, launch into an empty session: the mark box shows F1…F17 of §10.3 in order, each for 16 ticks, then nothing changes. A key at 600 ms shows F17 in the next draw and the key's character is in the composer. Brand `static`, reduced motion or `--resume`: F17 or no welcome from the first draw, and no `LOGO` flag |
| `counters_sample_once_a_second` | While waiting for 3.5 s, the activity text changes at most once per 1000 ms and shows no counter below 1.0 s; the star's draws in between do not change it |
| `reduced_motion_no_frames` | Reduced motion with brand `anim` configured: the scripted turn sets no `LOGO` flag; the status star is a still cyan `✦` while live; no M1, no M9 |
| `invariant_ascii_tier_is_ascii` | With ASCII glyphs, every cell ORBIT draws itself is printable ASCII; fixture content is exempt |
| `invariant_no_truncated_approval` | The approval summary appears in full at every width from 40 to 250 (with scrolling, across the scroll positions) |
| `approval_keys_reach_registry` | D1, D3: `y`, `R`, `n`, `Esc` resolve the right call id with the right response; `r` does nothing |
| `no_fake_approval` | D2 |
| `approval_paused_while_typing` | A key 500 ms before the request → `y` ignored; after 1000 ms idle → `y` works |
| `approval_scroll_gate` | A long summary keeps `y`/`R` disabled until the last row has been shown |
| `no_optimistic_tool_state` | After `y`, the line is `◉` + `◆`, never `✓`, until `ToolCallFinished` |
| `denied_is_not_failed` | `Denied` → `⊘ denied by you`, no red cell |
| `blocked_unknown_tool` | `Blocked` → `⊖ … blocked · unknown tool` in amber |
| `submit_during_stream_queues` | D4: the live turn keeps its text; the queued row appears; `TurnStarted` converts it |
| `cost_accounting` | D5: two turns with round costs → committed totals, never double |
| `cot_split_across_deltas` | D6: `"<think>"`, `"secret plan"`, `"</think>answer"` → only `answer` reaches state; also split tags `"<thi"` + `"nk>"` |
| `resume_history_is_gated` | Saved assistant text with reasoning tags displays without them |
| `redaction_chip` | D7: rejected chunks render `⟨redacted · credential⟩` / `⟨redacted · url⟩`, never the text |
| `grants_last_the_session` | D8: after `R`, later rounds and turns do not ask; resume and new session reset |
| `session_saved_cumulative` | D9 |
| `slash_commands_never_reach_model` | D11: `/models`, `/model x`, `/nope` never become prompts |
| `grapheme_backspace` | D14: `e` + U+0301, a ZWJ family emoji and a CJK character each delete as one unit |
| `layout_breakpoints` | Widths 39, 40, 59, 60, 79, 80, 109, 110, 139, 140, 150 and 250 × heights 9, 10, 16, 24 and 44 produce the class and geometry of §8 |
| `scroll_thumb_formula` | `wide_idle`: view 38, total 39, start 1 → rows 3–39. `wide_streaming`: 38, 41, 3 → rows 5–39. `wide_approval`: 31, 35, 4 → rows 6–32. `total ≤ view` → no thumb. |
| `formats` | Cost, tokens, duration, recency and truncation per §7.3–7.4, including `<$0.0001` and `cost n/a` |
| `tiers_resolution` | The env/config matrix of §12.1–12.3, including `NO_COLOR` not overridable, and config never raising a tier |

### 16.4 Vision comparison

Do this once your goldens pass.

1. Export each golden buffer as HTML: one `<span>` per style run, a monospace font, `line-height: 1.2`, the token colours, `bg` as the page background.
2. Screenshot it with a headless browser.
3. Use vision to compare each screenshot side by side with the reference PNG of the same name: colours per region, weights, rules, chips, bands, frame.
4. List every difference you see, fix the ones that are yours, and report any you believe are the reference's.

If you cannot run a browser, compare cell styles against the colour tables in §6 and §9 and say so in your report.

## 17. Acceptance checklist

1. Every golden in `docs/tui/golden/` passes at its size; every invariant and behaviour test in §16.3 passes; the four repository checks pass.
2. Every image in §2 has been opened with vision and compared (§16.4), and the differences are reported.
3. Every true-colour golden matches its `.styles.json` cell for cell, and `invariant_magenta_closed_list` passes.
4. No emoji and no glyph literal outside the glyph table; no colour literal outside `theme.rs`.
5. With `NO_COLOR=1`, the TUI runs in mono and the ASCII/mono golden matches in symbols. With `TERM=dumb`, `CI=1` or `ORBIT_SCREEN_READER=1`, the REPL runs instead.
6. With the default config, the brand tier is `off`: the status mark shows the star alone, and there is no expanded mark.
7. Idle CPU: no redraws while idle (the invariant test). Motion: only the stars of §10 move, at the rates of §10.1–10.2.
8. A manual run against `crates/mock-provider`, or any configured provider that issues tool calls. If none can, drive the same steps with the scripted worker and say so.
   1. Send a prompt.
   2. Queue a second one mid-stream.
   3. Approve a `calculator` call with `y`, deny one with `n`, grant one with `R` and see it not asked again. Watch the status star: 2 fps while waiting, 4 fps while streaming or running a tool, still while the card is open.
   4. Run `/models`, `/model x`, `/usage`, `/clear`, `/resume <id>`.
   5. Resize across every class.
   6. With `[brand] tier = "anim"`, start with an empty session: watch M1, then send a first prompt and watch the star orbit the `O` until the first output.
   7. Quit and read the shutdown line.

   Write down what you saw.

## 18. What to report back

1. What you built, by step, and the commits.
2. The test results (counts), and the four check outputs.
3. The vision comparison: for each image, "matches" or a list of differences, and which side you believe is wrong.
4. Every place this prompt was ambiguous or contradicted a golden, and what you did.
5. Anything you could not do and why, including anything out of scope that the design needs (for example, backend data for the workspace, citations, risk and approval facts; the REPL's per-turn grants; incomplete pricing reported as 0).

Do not push or open a pull request unless you are told to.

---

## Appendix A. Golden frames

These are the text of the golden screens: every row of the terminal, with trailing spaces trimmed. The full set is in `docs/tui/golden/`. The frames below are the ones you will look at most.

### A1. `wide_idle` — 150 × 44

```text
 Sessions  Activity ───────── │ Restore keeps chain head ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 14 turns │ Workspace ────────────────────────
                              │                                                                                  │
  TODAY                       │                                                                                  │  ✓━━✓━━✓━━◉──◌  verify         4/5
   Restore keeps chain h… now │ › Before touching anything: plan how you would investigate the restore    13:59  ┃
   Display gate: URL dige… 2h │   bug.                                                                           ┃  PLAN                          4/5
   Plugin pool eviction t… 5h │                                                                                  ┃  ✓ Reproduce restore failure
                              │ ✦ Plan is in the workspace. Short version: reproduce on a clean home,     13:59  ┃  ✓ Find where the chain resets
  YESTERDAY                   │   find where the restored namespace builds its chain, fix, then prove it         ┃  ✓ Seed chain from exported head
   Provider TLS pin rotat… 1d │   with the unit suite and the clean-machine script.                              ┃  ✓ Add restore_preserves_head
 ✕ Cost rounding in µ¢     1d │                                                                                  ┃  ◌ Run clean-machine e2e
                              │ › orbit verify-ledger fails right after orbit restore on a clean home.    14:02  ┃
  THIS WEEK                   │   Can you find out why?                                                          ┃  FINDINGS                        2
   WASI kill lifecycle     3d │                                                                                  ┃  ∙ restore writes a fresh genesis
   Migrator: workflow v2 … 4d │ ✦ The restored namespace starts a brand-new chain: restore writes a       14:02  ┃    record restore.rs:88
   Coalescer at 30 ms      5d │   fresh genesis record, so the head no longer matches the digest in the          ┃  ∙ bundle already carries the head
   Signal guard for SIGHUP 6d │   export bundle and verify-ledger reports a break at record 1 [1].               ┃    digest bundle.rs:41
   Approval surface polish 6d │                                                                                  ┃
                              │   ✓ read_file  crates/export/src/restore.rs                    212 lines · 0.1s  ┃  VERIFICATION                  2/3
                              │   ✓ grep  "genesis" crates/ledger/src                             3 hits · 0.2s  ┃  ✓ unit · orbit-export   48 passed
                              │                                                                                  ┃  ✓ ledger · restored     7 records
                              │   The bundle already carries the head digest [2], so the fix is to seed the      ┃    home
                              │   restored chain from it instead of from genesis:                                ┃  ↻ e2e · clean machine      retest
                              │                                                                                  ┃
                              │    let head = bundle.ledger_head()?;                                       rust  ┃
                              │    ledger.seed_from(head, bundle.records())?; // keep the chain continuous       ┃
                              │                                                                                  ┃
                              │   sources  [1] export/src/restore.rs:88   [2] export/src/bundle.rs:41            ┃
                              │                                                                                  ┃
                              │ › Do it, and add a regression test.                                       14:06  ┃
                              │                                                                                  ┃
                              │ ✦ Done. Restore now seeds the chain from the exported head, and           14:09  ┃
                              │   restore_preserves_head covers the regression.                                  ┃
                              │                                                                                  ┃
                              │   ✓ edit_file  crates/export/src/restore.rs                        +9 −3 · 0.1s  ┃
                              │   ✓ shell  cargo test -p orbit-export                          48 passed · 3.9s  ┃
                              │   ✓ shell  orbit verify-ledger --home /tmp/orbit-restored      7 records · 0.4s  ┃
                              │                                                                                  ┃
                              │   ✓ verified  2 checks · retest attestation recorded                             ┃
                              │   │ cargo test -p orbit-export                                        48 passed  ┃
                              │   │ orbit verify-ledger                              7 records · head 0913…a0c3  ┃
                              │                                                                                  │
                              │  ›  Ask ORBIT, or type / for commands                                            │
                              │    ⏎ send   ⇧⏎ newline   / commands   ↑ history                                  │
 ✦ ORBIT   ready                                                          glm-5.2 · local     ● online    ↓18.2k ↑2.9k    $0.0214   01J8ZK4Q   ? keys
```

### A2. `wide_streaming` — 150 × 44

```text
 Sessions  Activity ───────── │ Restore keeps chain head ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 14 turns │ Workspace ────────────────────────
                              │                                                                                  │
  TODAY                       │   bug.                                                                           │  ✓━━✓━━◉──◌──◌  execute        3/5
   Restore keeps chain h… now │                                                                                  │
   Display gate: URL dige… 2h │ ✦ Plan is in the workspace. Short version: reproduce on a clean home,     13:59  │  PLAN                          2/5
   Plugin pool eviction t… 5h │   find where the restored namespace builds its chain, fix, then prove it         ┃  ✓ Reproduce restore failure
                              │   with the unit suite and the clean-machine script.                              ┃  ✓ Find where the chain resets
  YESTERDAY                   │                                                                                  ┃  ◉ Seed chain from exported head
   Provider TLS pin rotat… 1d │ › orbit verify-ledger fails right after orbit restore on a clean home.    14:02  ┃    running shell · cargo test
 ✕ Cost rounding in µ¢     1d │   Can you find out why?                                                          ┃  ◌ Add restore_preserves_head
                              │                                                                                  ┃  ◌ Run clean-machine e2e
  THIS WEEK                   │ ✦ The restored namespace starts a brand-new chain: restore writes a       14:02  ┃
   WASI kill lifecycle     3d │   fresh genesis record, so the head no longer matches the digest in the          ┃  FINDINGS                        2
   Migrator: workflow v2 … 4d │   export bundle and verify-ledger reports a break at record 1 [1].               ┃  ∙ restore writes a fresh genesis
   Coalescer at 30 ms      5d │                                                                                  ┃    record restore.rs:88
   Signal guard for SIGHUP 6d │   ✓ read_file  crates/export/src/restore.rs                    212 lines · 0.1s  ┃  ∙ bundle already carries the head
   Approval surface polish 6d │   ✓ grep  "genesis" crates/ledger/src                             3 hits · 0.2s  ┃    digest bundle.rs:41
                              │                                                                                  ┃
                              │   The bundle already carries the head digest [2], so the fix is to seed the      ┃  VERIFICATION                  0/3
                              │   restored chain from it instead of from genesis:                                ┃  ◉ unit · orbit-export     running
                              │                                                                                  ┃  ◌ ledger · restored home   queued
                              │    let head = bundle.ledger_head()?;                                       rust  ┃  ◌ e2e · clean machine      queued
                              │    ledger.seed_from(head, bundle.records())?; // keep the chain continuous       ┃
                              │                                                                                  ┃
                              │   sources  [1] export/src/restore.rs:88   [2] export/src/bundle.rs:41            ┃
                              │                                                                                  ┃
                              │ › Do it, and add a regression test.                                       14:06  ┃
                              │                                                                                  ┃
                              │ ✦ Seeding the restored chain from the exported head. I will change        14:06  ┃
                              │   restore.rs, add the test, then run the export suite.                           ┃
                              │                                                                                  ┃
                              │   ✓ edit_file  crates/export/src/restore.rs                        +9 −3 · 0.1s  ┃
                              │   ✓ edit_file  crates/export/tests/restore.rs                        +31 · 0.1s  ┃
                              │   ◉ shell  cargo test -p orbit-export                                   running  ┃
                              │    │    Compiling orbit-export v0.1.0 (crates/export)                            ┃
                              │    │     Finished test profile in 2.71s                                          ┃
                              │    │      Running unittests src/lib.rs                                           ┃
                              │   ◌ shell  orbit verify-ledger --home /tmp/orbit-restored                queued  ┃
                              │                                                                                  ┃
                              │ › also check that export still refuses a bundle with a forged head       queued  ┃
                              │                                                                                  │
                              │  ›  Add to the queue, or wait for ORBIT                                          │
                              │    ⏎ queue   ⇧⏎ newline   pgup scroll                                            │
 ◐ ORBIT   running shell · cargo test · 3.2s                              glm-5.2 · local     ● online    ↓15.9k ↑2.1k    $0.0183   01J8ZK4Q   ? keys
```

### A3. `wide_approval` — 150 × 44

```text
 Sessions  Activity ───────── │ Restore keeps chain head ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 14 turns │ Workspace ────────────────────────
                              │                                                                                  │
  TODAY                       │                                                                                  │  ✓━━✓━━✓━━◉──◌  verify         4/5
   Restore keeps chain h… now │ ✦ Plan is in the workspace. Short version: reproduce on a clean home,     13:59  │
   Display gate: URL dige… 2h │   find where the restored namespace builds its chain, fix, then prove it         │  PLAN                          4/5
   Plugin pool eviction t… 5h │   with the unit suite and the clean-machine script.                              │  ✓ Reproduce restore failure
                              │                                                                                  ┃  ✓ Find where the chain resets
  YESTERDAY                   │ › orbit verify-ledger fails right after orbit restore on a clean home.    14:02  ┃  ✓ Seed chain from exported head
   Provider TLS pin rotat… 1d │   Can you find out why?                                                          ┃  ✓ Add restore_preserves_head
 ✕ Cost rounding in µ¢     1d │                                                                                  ┃  ◇ Run clean-machine e2e
                              │ ✦ The restored namespace starts a brand-new chain: restore writes a       14:02  ┃    waiting on your approval
  THIS WEEK                   │   fresh genesis record, so the head no longer matches the digest in the          ┃
   WASI kill lifecycle     3d │   export bundle and verify-ledger reports a break at record 1 [1].               ┃  FINDINGS                        2
   Migrator: workflow v2 … 4d │                                                                                  ┃  ∙ restore writes a fresh genesis
   Coalescer at 30 ms      5d │   ✓ read_file  crates/export/src/restore.rs                    212 lines · 0.1s  ┃    record restore.rs:88
   Signal guard for SIGHUP 6d │   ✓ grep  "genesis" crates/ledger/src                             3 hits · 0.2s  ┃  ∙ bundle already carries the head
   Approval surface polish 6d │                                                                                  ┃    digest bundle.rs:41
                              │   The bundle already carries the head digest [2], so the fix is to seed the      ┃
                              │   restored chain from it instead of from genesis:                                ┃  VERIFICATION                  2/3
                              │                                                                                  ┃  ✓ unit · orbit-export   48 passed
                              │    let head = bundle.ledger_head()?;                                       rust  ┃  ✓ ledger · restored     7 records
                              │    ledger.seed_from(head, bundle.records())?; // keep the chain continuous       ┃    home
                              │                                                                                  ┃  ↻ e2e · clean machine      retest
                              │   sources  [1] export/src/restore.rs:88   [2] export/src/bundle.rs:41            ┃
                              │                                                                                  ┃
                              │ › Do it, and add a regression test.                                       14:06  ┃
                              │                                                                                  ┃
                              │ ✦ Unit suite and ledger check pass. Last step is the clean-machine        14:06  ┃
                              │   script, which needs your go-ahead.                                             ┃
                              │                                                                                  ┃
                              │   ✓ shell  cargo test -p orbit-export                          48 passed · 3.9s  ┃
                              │   ✓ shell  orbit verify-ledger --home /tmp/orbit-restored      7 records · 0.4s  ┃
                              │   ◇ shell  scripts/e2e-clean-machine.sh --keep-home                awaiting you  ┃
                              │                                                                                  │
                              │ ╭─ ◇ Allow shell? ────────────────────────────────────────── ▰▰▱ medium risk ──╮ │
                              │ │                                                                              │ │
                              │ │  scripts/e2e-clean-machine.sh --keep-home                                    │ │
                              │ │                                                                              │ │
                              │ │  runs in  ~/src/orbit                 sandbox  landlock · rw /tmp only       │ │
                              │ │  egress   none                        ledger   decision is recorded          │ │
                              │ │                                                                              │ │
                              │ │   y  allow once     R  allow shell for this session     n   esc  deny        │ │
                              │ ╰──────────────────────────────────────────────────────────────────────────────╯ │
 ✦ ORBIT   ◇ approval needed · shell                                      glm-5.2 · local     ● online    ↓17.6k ↑2.7k    $0.0209   01J8ZK4Q   ? keys
```

### A4. `narrow` — 80 × 30

```text
 Sessions   Conversation   Workspace 2/5 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


 ✦ The restored namespace starts a brand-new chain: restore writes a     14:02
   fresh genesis record, so the head no longer matches the digest in
   the export bundle and verify-ledger reports a break at record 1 [1].

   ✓ read_file  crates/export/src/restore.rs                  212 lines · 0.1s
   ✓ grep  "genesis" crates/ledger/src                           3 hits · 0.2s

   The bundle already carries the head digest [2], so the fix is to seed the
   restored chain from it instead of from genesis:

    let head = bundle.ledger_head()?;                                     rust
    ledger.seed_from(head, bundle.records())?; // keep the chain continuous

   sources  [1] export/src/restore.rs:88   [2] export/src/bundle.rs:41

 › Do it, and add a regression test.                                     14:06

 ✦ ✓ edit_file  crates/export/src/restore.rs                      +9 −3 · 0.1s
   ✓ shell  cargo test -p orbit-export                        48 passed · 3.9s

   Both checks pass. The restored chain now starts from the exported head
   0913…a0c3, so verify-ledger walks all 7 records without a break. Next I
   would run the clean-machine▍

  ›  Add to the queue, or wait for ORBIT
    ⏎ queue   ⇧⏎ newline   tab views
 ◐ ORBIT   streaming · 212 tokens                        glm-5.2   ●    $0.0196
```

### A5. `tier_ascii_mono` — 66 × 20 (ASCII glyphs, monochrome)

```text
 Sessions   Conversation   Workspace 4/5 ========================


 > Do it, and add a regression test.

 * Done. `restore_preserves_head` covers it [1]:

   | ledger.seed_from(head, bundle.records())?;             rust

   + shell  cargo test -p orbit-export                 48 passed
   ? shell  scripts/e2e-clean-machine.sh            awaiting you

 +- ? Allow shell? -------------------------- ##- medium risk --+
 |                                                              |
 |  scripts/e2e-clean-machine.sh --keep-home                    |
 |                                                              |
 |  [y] allow once    [R] allow shell for this session          |
 |  [n] [esc] deny                                              |
 +--------------------------------------------------------------+
 * ORBIT   ? approval needed - shell       glm-5.2   o    $0.0214
```

### A6. `min_size` — 38 × 9

```text
 ✦

     ORBIT needs at least 40 × 10
       this terminal is 38 × 9

      enlarge the window or run
         orbit chat --no-tui
```

**Other golden files** (same rules): `welcome.txt`, `welcome_waiting.txt`, `medium.txt`, `medium_sessions.txt`, `compact.txt`, `tight.txt`, `sessions_view.txt`, `palette.txt`, `help.txt`, `tier_truecolor.txt`, `tier_ansi16.txt`, `tier_mono.txt` (a `.styles.json` sits beside every true-colour golden: all of these except `tier_ansi16` and `tier_mono`).

## Appendix B. Fixture data for the golden frames

The fixture day's clock is **14:10 local**. All fixtures:

- Identity `glm-5.2` via `local`, session id `session-01J8ZK4QX2M7C9RT5VWEHN3B6D` (short id `01J8ZK4Q`), priced, `ConnectionChanged(Online)` delivered.
- Brand tier `Static`, true colour, Unicode glyphs.
- Keyboard enhancement active, so the hints show `⇧⏎`.
- Following the bottom (no scroll offset).

Strings in backticks inside the texts below are inline code; `[n]` are citations that exist.

### B1. Sessions (wide, medium and narrow Sessions view)

| Group | Title | Updated | State |
|---|---|---|---|
| TODAY | Restore keeps chain head *(the open session)* | now | — |
| TODAY | Display gate: URL digests | 2 h ago | — |
| TODAY | Plugin pool eviction test | 5 h ago | — |
| YESTERDAY | Provider TLS pin rotation | 1 d ago | — |
| YESTERDAY | Cost rounding in µ¢ | 1 d ago | failed |
| THIS WEEK | WASI kill lifecycle | 3 d ago | — |
| THIS WEEK | Migrator: workflow v2 fields | 4 d ago | — |
| THIS WEEK | Coalescer at 30 ms | 5 d ago | — |
| THIS WEEK | Signal guard for SIGHUP | 6 d ago | — |
| THIS WEEK | Approval surface polish | 6 d ago | — |

Cursor on the first row. The Sessions rail is unfocused in every wide golden (focus is on the Conversation). In `medium_sessions` and `sessions_view` it is focused.

### B2. Conversation history

The header title is `Restore keeps chain head` and the meta `14 turns` in every wide and medium golden.

1. Notice `session started · glm-5.2 via local`, 13:58.
2. User, 13:59: `Before touching anything: plan how you would investigate the restore bug.`
3. ORBIT, settled, 13:59, prose: `Plan is in the workspace. Short version: reproduce on a clean home, find where the restored namespace builds its chain, fix, then prove it with the unit suite and the clean-machine script.`
4. User, 14:02: `` `orbit verify-ledger` fails right after `orbit restore` on a clean home. Can you find out why? ``
5. ORBIT, settled, 14:02:
   - prose: ``The restored namespace starts a brand-new chain: `restore` writes a fresh genesis record, so the head no longer matches the digest in the export bundle and `verify-ledger` reports a break at record 1 [1].``
   - tool `read_file`, argument `crates/export/src/restore.rs`, Ok, summary `212 lines`, 0.1 s
   - tool `grep`, argument `"genesis" crates/ledger/src`, Ok, summary `3 hits`, 0.2 s
   - prose: `The bundle already carries the head digest [2], so the fix is to seed the restored chain from it instead of from genesis:`
   - code `rust`: `let head = bundle.ledger_head()?;` / `ledger.seed_from(head, bundle.records())?; // keep the chain continuous`
   - sources `[1] export/src/restore.rs:88`, `[2] export/src/bundle.rs:41`
6. User, 14:06: `Do it, and add a regression test.`

### B3. The last ORBIT turn per fixture

**`wide_idle`** — settled, 14:09.

- Prose: ``Done. Restore now seeds the chain from the exported head, and `restore_preserves_head` covers the regression.``
- Tools, all Ok with no marker:
  - `edit_file` `crates/export/src/restore.rs` `+9 −3` 0.1 s
  - `shell` `cargo test -p orbit-export` `48 passed` 3.9 s
  - `shell` `orbit verify-ledger --home /tmp/orbit-restored` `7 records` 0.4 s
- Evidence: `2 checks · retest attestation recorded`; rows `cargo test -p orbit-export` → `48 passed`, `orbit verify-ledger` → `7 records · head 0913…a0c3`.
- Status: ready; tokens 18 200 / 2 900; cost 21 400.

**`wide_streaming`** — live, started 14:06.

- Prose: ``Seeding the restored chain from the exported head. I will change `restore.rs`, add the test, then run the export suite.``
- Tools:
  - `edit_file` `crates/export/src/restore.rs` Ok `+9 −3` 0.1 s
  - `edit_file` `crates/export/tests/restore.rs` Ok `+31` 0.1 s
  - `shell` `cargo test -p orbit-export` running, live tail open: `   Compiling orbit-export v0.1.0 (crates/export)` / `    Finished test profile in 2.71s` / `     Running unittests src/lib.rs`
  - `shell` `orbit verify-ledger --home /tmp/orbit-restored` queued
- Queued prompt: `also check that export still refuses a bundle with a forged head`.
- Composer placeholder while working.
- Status: working, spinner frame `◐`, running `shell`, argument `cargo test -p orbit-export`, elapsed 3.2 s; tokens 15 900 / 2 100; cost 18 300.

**`wide_approval`** — live, started 14:06.

- Prose: `Unit suite and ledger check pass. Last step is the clean-machine script, which needs your go-ahead.`
- Tools:
  - `shell` `cargo test -p orbit-export` Ok `48 passed` 3.9 s
  - `shell` `orbit verify-ledger --home /tmp/orbit-restored` Ok `7 records` 0.4 s
  - `shell` `scripts/e2e-clean-machine.sh --keep-home` awaiting you
- Approval request: tool `shell`, summary `scripts/e2e-clean-machine.sh --keep-home`, risk medium, facts `runs in` `~/src/orbit`, `sandbox` `landlock · rw /tmp only`, `egress` `none`, `ledger` `decision is recorded`. Armed.
- Status: approval; tokens 17 600 / 2 700; cost 20 900.

**Workspace** (phases `init plan execute verify checkpoint`):

| Fixture | Phase | PLAN (in order) | VERIFICATION |
|---|---|---|---|
| idle | verify (4/5) | verified `Reproduce restore failure`; claimed `Find where the chain resets`; verified `Seed chain from exported head`; verified `Add restore_preserves_head`; pending `Run clean-machine e2e` — count `4/5` | `unit · orbit-export` verified `48 passed`; `ledger · restored home` verified `7 records`; `e2e · clean machine` retest `retest` — `2/3` |
| streaming | execute (3/5) | verified, claimed, **active** `Seed chain from exported head` (sub `running shell · cargo test`), pending, pending — `2/5` | `unit · orbit-export` active `running`; `ledger · restored home` pending `queued`; `e2e · clean machine` pending `queued` — `0/3` |
| approval | verify (4/5) | verified, claimed, verified, verified, awaiting `Run clean-machine e2e` (sub `waiting on your approval`) — `4/5` | as idle |

In every fixture, FINDINGS has `2` items: `restore writes a fresh genesis record` (source `restore.rs:88`) and `bundle already carries the head digest` (source `bundle.rs:41`).

**`narrow`** (80 × 30, Conversation view; the workspace is the streaming one, so the switcher meta is `2/5` in cyan).

- History from B2 item 4 on (items 1–3 are scrolled above).
- The last turn is live and tool-first, so it shows no time. Tools:
  - `edit_file` `crates/export/src/restore.rs` Ok `+9 −3` 0.1 s
  - `shell` `cargo test -p orbit-export` Ok `48 passed` 3.9 s
- Then streaming prose ending at the live edge: ``Both checks pass. The restored chain now starts from the exported head `0913…a0c3`, so `verify-ledger` walks all 7 records without a break. Next I would run the clean-machine``
- Status level 2: working `◐`, streaming with usage `212` output tokens, cost 19 600.

**`tier_*`** (66 × 20, Compact).

- View Conversation; switcher `Workspace 4/5` muted.
- User `Do it, and add a regression test.` (no time in Compact).
- Live ORBIT turn:
  - Prose ``Done. `restore_preserves_head` covers it [1]:``
  - Code `rust` `ledger.seed_from(head, bundle.records())?;`
  - `shell` `cargo test -p orbit-export` Ok `48 passed` 3.9 s (Compact drops the duration)
  - `shell` `scripts/e2e-clean-machine.sh` awaiting you
- Approval: `shell`, summary `scripts/e2e-clean-machine.sh --keep-home`, risk medium, no facts.
- Status level 2: approval, cost 21 400.
- The four files differ only by tier: `tier_truecolor`, `tier_ansi16`, `tier_mono`, `tier_ascii_mono`.

**`min_size`**: a 38 × 9 terminal.

**Others.** Each is built the same way from the pieces above. The exact content is visible in the golden file and PNG of the same name:

- `welcome`: medium 112 × 34, empty session, readiness `✓ trust root`, `✓ ledger · 7 records`, `✓ local · glm-5.2`; status level 1 with connection online, tokens 0/0, cost 0 → `$0.0000`.
- `welcome_waiting`: the `welcome` fixture, then the first prompt `Why does verify-ledger fail right after a restore on a clean home?` submitted at 14:02 and started (`TurnStarted`), with no output yet.
  - Brand tier `anim`. Motion state set directly: M9 at station 6, status star frame `◒` (`k = 3`), latency sample 1.5 s.
  - The session title is the prompt's first line, and the header meta is `1 turn`.
  - The readiness data is still present, so the mark keeps the rows it has in `welcome`.
- `medium`: 120 × 36, the idle workspace; history from B2 item 4, last turn as `wide_idle`.
- `medium_sessions`: the same, with Sessions focused.
- `compact`: 70 × 24, idle, the idle workspace (switcher `Workspace 4/5` muted). B2 item 6, then the `wide_idle` turn without times or durations and with a shorter evidence card: header `2 checks`, rows → `48 passed` and → `7 records`.
- `tight`: 50 × 20, the streaming workspace (switcher `Workspace 2/5` in cyan), working: `edit_file` Ok `+9 −3`, `shell` running, streaming prose `Running the export suite now.`, status level 3, cost 18 300, elapsed 3.2 s.
- `sessions_view`: 80 × 24.
- `palette`: over `wide_idle`, query `mod`, first command selected, one activity row `model → glm-5.2` at 13:58 of kind `model`.
- `help`: over `wide_idle`.

## Appendix C. Config keys (`$ORBIT_HOME/tui.toml`, loaded from the CLI's home)

| Key | Values | Default |
|---|---|---|
| `[color] mode` | `auto` `truecolor` `256` `16` `mono` (only lowers the detected tier) | `auto` |
| `[glyphs] set` | `auto` `unicode` `ascii` | `auto` |
| `[motion] reduced` | bool | `false` |
| `[brand] tier` | `off` `text` `static` `anim` | `off` |
| `[notify] bell_on_approval` | bool | `false` |
| `[colors] <token>` | `#RRGGBB` for any token of §6.1 except `magenta_hi` | the table |
| `[layout] rail_left`, `rail_right`, `measure` | columns (still clamped to §8.2's bounds; measure 60–120) | formulas / 100 |

Migration from the current keys (log one deprecation line each):

| Old key | New key |
|---|---|
| `colors.accent` | `colors.magenta` |
| `colors.accent_bright` | removed |
| `colors.accent_dim` | `colors.magenta_dim` |
| `colors.composer`, `colors.composer_dim` | removed |
| `colors.text` | `colors.ink` |
| `colors.dim` | `colors.muted` |
| `colors.code_bg` | `colors.surface` |
| `colors.code_fg` | removed |
| `colors.error` | `colors.red` |
| `colors.success` | `colors.green` |
| `colors.warning` | `colors.amber` |
| `spinner.style`, `spinner.phrases` | removed |
| `layout.left_pct` / `right_pct` | `layout.rail_left` / `rail_right` (columns) |
| `layout.center_pct`, `header_lines`, `status_lines`, `help_lines`, `composer_lines`, `tabs.show_help_bar` | removed (fixed by this design) |

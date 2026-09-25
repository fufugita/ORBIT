# ORBIT TUI — Visual System (staged 2026-09-26)

> **Status:** ACCEPTED DRAFT — staged from the winning design-review submission.
> This is the normative design spec for the `crates/hud-tui` visual system.
> It supersedes DR-21's cut elements (see §12) while keeping the founder-locked
> white + magenta brand. DR-20's architecture locks (L1–L12) remain
> authoritative: this spec changes presentation, not process model, approval
> pipeline, or display-safety seams.
>
> Provenance: winning entry in a two-model design review (vs a competing
> desktop-app spec and TUI mockups). Amended with four concrete contributions
> from the competing TUI mockups, marked **[GPT-AMEND]** below.
> Rendered reference with color swatches and 11 PNG renders at real terminal
> sizes (150×44, 80×30): preserved alongside this file (original HTML
> deliverable).

# ORBIT TUI ✦ visual system

One opinionated visual language for ORBIT's ratatui front-end: white and magenta on violet-black, ink instead of boxes, circles for work and diamonds for authority, and exactly one moving part.

- 11 true-colour renders at real terminal sizes

- tokens for true colour, 256, 16 and mono

- golden text frames for TestBackend

Wide layout, idle · 150 × 44 · the conversation is the brightest mass; the rails and status line orbit it


Sections

- 1. Design thesis

- 2. Visual hierarchy

- 3. Colour system

- 4. Typography and glyph vocabulary

- 5. Layout

- 6. Components

- 7. Motion

- 8. Logo and brand

- 9. Mockups

- 10. State matrix

- 11. Accessibility and terminal compatibility

- 12. Anti-patterns and cuts

- 13. Implementation handoff

- Why this is ORBIT



## 1. Design thesis

- You are the centre of gravity. ORBIT is "the harness that orbits around you", so the screen is built the same way. The conversation is the heaviest, brightest mass in the middle. The rails circle it in dimmer ink, and the status line is the outermost orbit. Brightness is mass: nothing at the edge may outshine the centre.

- Ink, not boxes. Structure comes from a strict gutter, alignment, spacing and hairlines. No pane has a border. At most one rounded frame is on screen at a time, and a frame always means this needs you: an approval, the palette, a confirmation.

- Magenta means ORBIT, or you. Magenta marks six things and nothing else: the mark, ORBIT's settled voice glyph, the focused pane title, the selection bar, your input (the › prompt and the palette characters your query matched), and requests for your authority. It never decorates, and it never fills an area larger than a word (the selection wash is a tint, not the colour).

- Only the star moves. The whole interface has one animated cell: the star in the status-line mark, which turns at 4 fps while ORBIT works. Everything else changes only when data arrives, so a still screen is a finished screen. This is the spec's "4 fps logo, 0 fps body" (ORBIT-F-HUD-003) applied to the TUI.

- Every state has a shape and a word. Colour is the third signal, never the first. States come from two small glyph families (circles for work, diamonds for authority) and always travel with a word. The monochrome render carries the same information as the true-colour one.

- Evidence earns green. "Done" is a claim; "verified" is a proof. Green is reserved for outcomes backed by evidence: a passing check, a ledger record, a retest attestation. A task marked done without evidence gets a neutral check and says no evidence.

- Honest words. Every live label is a real value: time to first token, elapsed time, attempt 2 of 5, retry in 4 s, the actual cost of the last turn. There are no rotating "thinking…" phrases, no fake progress, and no placeholder hinting at hidden reasoning.

- Degrade by subtraction. Every lower capability tier is the same design with something taken away: true colour → 256 → 16 colours → attributes, Unicode → ASCII, motion → still. The layout and the meaning never change between tiers.

Deliberately avoided: neon glow and "hacker" green; gradients; boxes inside boxes; focus shimmer; the sparkle or twinkle that has become the generic AI icon; emoji as UI; ASCII art outside the welcome screen; dimmed or "transparent" overlays; blinking; and any chrome brighter than the conversation.

## 2. Visual hierarchy

 |

 | Level
 | What sits here
 | How it earns attention

 | 1
 | The newest ORBIT turn and the composer caret. When an approval is pending, the approval card replaces the composer and takes this level.
 | ink (15.9:1), the widest column, the bottom of the screen where the eye rests. The approval card is the only frame on screen.

 | 2
 | The focused pane's title, the active task, the running tool line, the cursor row.
 | A magenta title; cyan for anything live; bold for the one active item.

 | 3
 | Rail contents, tool metadata, timestamps, counts, the status line.
 | ink2, muted and faint; numbers right-aligned; no bold.

Squint test. Blur the screen. You should see one block of text in the middle, one magenta word at the top of the focused pane, at most one cyan thing (only while ORBIT works) and nothing else. If a rail or the status line survives the blur, it is too loud.

How chrome stays subordinate:

- Global chrome is two rows: the shared pane-header row and the status line. The current build spends 11 rows of the conversation column on chrome (3-row header, pane borders, a boxed composer, a 2-row help bar). The new layout spends 6, which takes a 24-row terminal from 13 transcript rows to 18.

- No pane borders. A one-row header with a hairline, plus a full-height divider that doubles as the scrollbar.

- Filled areas exist for content only: user turns, code, the composer and chips sit on surface. Chrome is never filled.

- The status line has no background. Everything in it is muted except the mark and the one live verb.

## 3. Colour system

## 3.1 Tokens (true colour)

A near-black with a violet cast; white ink; magenta for identity and authority; cyan for "now"; green, amber and red for outcomes. Contrast ratios are WCAG 2.x, measured against bg, surface, surface2 and wash.

 |

 | Token
 | Hex
 | Role
 | on bg
 | on surface
 | on surface2
 | on wash

 | bg
 | #100E16
 | Background: the canvas (violet-black)
 |
 |
 |
 |

 | surface
 | #17141F
 | Surface: bands for user turns, composer, code blocks, approval fill
 |
 |
 |
 |

 | surface2
 | #211C2B
 | Chips (inline code, keycaps, redaction), palette fill, unfocused cursor row
 |
 |
 |
 |

 | wash
 | #2B1631
 | Selection: the focused cursor row (magenta-tinted)
 |
 |
 |
 |

 | rule
 | #2D2839
 | Hairlines, dividers, unfocused header rule
 | 1.3
 | 1.3
 | 1.2
 | 1.2

 | rule_hi
 | #463F55
 | Focus rule (heavy), overlay frames, scroll thumb
 | 1.9
 | 1.8
 | 1.7
 | 1.7

 | ink
 | #ECE8F3
 | Primary text
 | 15.9
 | 15.1
 | 13.8
 | 13.8

 | ink2
 | #BDB6CA
 | Secondary text: rails, tool names, sources
 | 9.8
 | 9.3
 | 8.5
 | 8.5

 | muted
 | #8B8499
 | Muted text: metadata, labels, hints
 | 5.3
 | 5.1
 | 4.6
 | 4.6

 | faint
 | #655F73
 | Placeholders, disabled items, session id
 | 3.1
 | 3.0
 | 2.7
 | 2.7

 | magenta
 | #E356D0
 | Brand, focus title, selection bar, authority
 | 5.9
 | 5.6
 | 5.1
 | 5.2

 | magenta_hi
 | #F58CE4
 | Startup star flash (one frame)
 | 8.9
 | 8.4
 | 7.7
 | 7.7

 | magenta_dim
 | #8E3C7F
 | The ring in the expanded mark (decorative)
 | 2.8
 | 2.7
 | 2.5
 | 2.5

 | cyan
 | #5CC6DD
 | Secondary accent: live (working, running, streaming)
 | 9.6
 | 9.1
 | 8.4
 | 8.4

 | green
 | #62CC8E
 | Success: verified outcomes, healthy connection
 | 9.6
 | 9.1
 | 8.3
 | 8.4

 | amber
 | #E9B252
 | Warning: blocked, retest, degraded, medium risk
 | 10.0
 | 9.5
 | 8.7
 | 8.7

 | red
 | #F06A5E
 | Error: failed, offline, high risk
 | 6.3
 | 6.0
 | 5.5
 | 5.5

 | syn_kw
 | #C3A6FF
 | Code: keywords
 | 9.3
 | 8.8
 | 8.1
 | 8.1

 | syn_str
 | #A6D6A0
 | Code: strings
 | 11.6
 | 11.0
 | 10.1
 | 10.1

 | syn_num
 | #EFC08D
 | Code: numbers and literals
 | 11.5
 | 10.9
 | 10.0
 | 10.0

Code comments use muted; all other code tokens use ink. Syntax highlighting gets three colours plus muted, and none of them is magenta.

## 3.2 One meaning per colour

 |

 | Colour
 | Means
 | Never used for

 | magenta
 | ORBIT, or you: the mark, the settled voice glyph, focus, the selection bar, your input, authority requests
 | headings, links, decoration, errors

 | cyan
 | now: anything in progress
 | user text, the composer, static accents

 | green
 | proven: verified results, a healthy connection
 | "done" without evidence

 | amber
 | caution: blocked, retest, reconnecting, rate-limited, medium risk
 | anything that needs no attention

 | red
 | failed: errors, failed checks, offline, high risk
 | denials (you said no; nothing failed)

The gap between magenta and red is deliberate: red is shifted toward coral (hue ≈ 5°) so it never reads as a darker magenta (hue ≈ 308°).

## 3.3 Contrast policy

- Body text is ≥ 7:1 on every surface it can land on (ink 13.8–15.9, ink2 8.5–9.8).

- Anything that carries meaning is ≥ 4.5:1 on every surface it appears on. The tightest pairing is muted on surface2 or wash (4.6).

- On cursor rows, muted metadata is promoted to ink2, which keeps approximated palettes above 4.5.

- faint (3.1) is reserved for placeholders, disabled items and information repeated elsewhere, such as the session id, which the Sessions rail also shows. It is never the only carrier of a fact.

- Rules are decorative (1.2–1.9) and are never the only focus cue; the magenta title is.

## 3.4 256-colour fallback

Surfaces take explicit grey-ramp steps so bands stay distinguishable. Nearest-match mapping would put bg and surface both on 233 and erase the user-turn band. Text tokens use the perceptually nearest cube colour.

 |

 | Token
 | xterm
 | Token
 | xterm
 | Token
 | xterm

 | bg
 | 233
 | ink
 | 255
 | cyan
 | 81

 | surface
 | 234
 | ink2
 | 250
 | green
 | 78

 | surface2
 | 235
 | muted
 | 103
 | amber
 | 179

 | wash
 | 236 + magenta bar
 | faint
 | 60
 | red
 | 203

 | rule
 | 236
 | magenta
 | 170
 | syn_kw
 | 183

 | rule_hi
 | 239
 | magenta_hi
 | 212
 | syn_str
 | 151

 |
 |
 | magenta_dim
 | 96
 | syn_num
 | 180

## 3.5 16-colour fallback

- Don't paint the canvas. Use the terminal's default background and foreground. The user's theme then decides legibility, light or dark.

- Text (ink, ink2) uses the default foreground. muted, faint and rules use the default foreground plus DIM (SGR 2). ANSI 0, 7, 8 and 15 are never used for text; bright black is invisible in popular themes.

- Accents use the normal hues only: magenta 5, cyan 6, green 2, amber 3 (yellow), red 1. Code keywords 4, strings 2, numbers 3. Bright variants (9–14) are unreadable on light themes.

- Surfaces disappear.

- User turns keep the › gutter without a band.

- Code blocks get a DIM │ left rule.

- Inline code becomes cyan text.

- Keycaps become [y].

- Redaction chips keep their ⟨ ⟩.

- Selection is REVERSE; focus is a bold magenta title plus the heavy rule.

## 3.6 Monochrome (NO_COLOR, or color = "mono")

- Attributes only:

- BOLD: focus titles, the active item, tool names, keycaps, and the words "approval", "failed" and "error".

- DIM: metadata.

- REVERSE: selection.

- UNDERLINE: palette matches and H1.

- Meaning already travels as glyph plus word, so nothing is lost.

- Inline code keeps its backticks and citations keep their brackets: when a style can't be shown, the markup that carries its meaning stays.

- The approval frame is drawn in bold. It is still the only frame on screen.

## 3.7 Detection

Resolved once at startup, most specific first:

- tui.toml [color] mode

- NO_COLOR (→ mono)

- COLORTERM=truecolor|24bit (→ true colour)

- TERM contains 256color (→ 256)

- otherwise 16 colours

TERM=dumb never reaches the TUI. Tiers only step down at runtime, never up (H-5 / H-7).

## 3.8 Colour-vision check

CIELAB ΔE between status colours, normal and simulated (Machado 2009, full severity). Below about 20 the pair is at risk; every at-risk pair already differs by glyph and word.

 |

 | Pair
 | Normal
 | Protan
 | Deutan
 | Tritan
 | Separated by

 | green / red
 | 97
 | 23
 | 21
 | 111
 | ✓ vs ✕, "passed" vs "failed"

 | magenta / cyan
 | 95
 | 39
 | 12
 | 102
 | the mark's star turns into a spinning planet when working (✦ → ◐); ◇ vs ◉

 | cyan / green
 | 47
 | 45
 | 42
 | 8
 | ◉ running vs ✓ 48 passed

 | amber / red
 | 49
 | 39
 | 22
 | 38
 | ↻ / ⊖ vs ✕

 | magenta / red
 | 71
 | 70
 | 68
 | 22
 | ◇ approval vs ✕ failed

 | green / amber
 | 64
 | 28
 | 38
 | 75
 | ✓ vs ↻ / ⊖

## 4. Typography and glyph vocabulary

## 4.1 Type in a terminal

In a terminal, weight, case, ink level and spacing are the only typographic tools.

- Weight. Regular for body text. Bold for pane titles, tool names, the active task, keycaps, the approval action and the focused title. Never italic (unreliable across terminals) and never blink. Strikethrough never carries meaning.

- Case. UPPERCASE only for rail section labels (TODAY, PLAN, FINDINGS, VERIFICATION), always in muted; that is the terminal's small caps. Sentence case everywhere else.

- Spacing.

- One blank row between turns.

- One blank row around code blocks, tool groups and sources.

- A 3-column gutter: glyph at column 1, text at column 3.

- Two spaces between a tool name and its argument; three between status segments.

- Numbers. Always right-aligned in meta columns, with units attached: 3.9s, 48 passed, 18.2k. Costs show 4 decimals ($0.0214); under $0.0001 they show <$0.0001. The ledger keeps µ¢; the UI never does float maths.

- Measure. Prose wraps at min(column − 5, 100). Code, tables and tool lines may use the full column.

## 4.2 Lines and frames

 |

 | Element
 | Glyph
 | Token
 | Where

 | Header rule
 | ─
 | rule
 | Unfocused pane headers

 | Focus rule
 | ━
 | rule_hi
 | The focused pane header only (a heavy line is the shape cue that survives monochrome)

 | Divider / scroll track
 | │ / thumb ┃
 | rule / muted
 | Between panes, full height; the thumb shows the transcript's position

 | Card rule
 | │
 | meaning colour
 | Tool detail, evidence, error detail: a left rule, never a box

 | Quote bar
 | ▎
 | muted
 | Markdown blockquotes

 | Frame
 | ╭─╮ │ ╰─╯
 | magenta (approval) or rule_hi (palette, confirm, help)
 | Overlays only; never nested, never ┌┐, never ═

## 4.3 Glyphs

One small vocabulary. Circles are work, diamonds are authority, the star is ORBIT. A glyph means the same thing wherever it appears (✕ is always broken, ↻ always again), and each has a plain-ASCII twin.

 |

 | Family
 | Meaning
 | Unicode
 | ASCII
 | Colour

 | Roles
 | ORBIT (voice, mark)
 | ✦
 | *
 | magenta when settled, cyan while live

 |
 | you
 | ›
 | >
 | muted (gutter); magenta (composer prompt)

 |
 | notice
 | ∙
 | -
 | muted

 | Work
 | pending / queued
 | ◌
 | .
 | faint

 |
 | active / running
 | ◉
 | @
 | cyan

 |
 | done (claimed)
 | ✓
 | +
 | ink2 (neutral)

 |
 | verified
 | ✓ + verified / n proofs
 | +
 | green

 |
 | failed
 | ✕
 | x
 | red

 |
 | blocked
 | ⊖
 | #
 | amber

 |
 | awaiting retest
 | ↻
 | ~
 | amber

 | Authority
 | awaiting your decision
 | ◇
 | ?
 | magenta

 |
 | allowed once
 | ◆
 | +
 | muted

 |
 | allowed for this session
 | ◈
 | +
 | muted

 |
 | denied by you
 | ⊘
 | /
 | muted (a decision, not a failure)

 | Connection
 | online / retrying / rate-limited / offline
 | ● / ↻ / ◔ / ✕
 | o / ~ / % / x
 | green / amber / amber / red

 | Structure
 | disclosure collapsed / expanded
 | ▸ / ▾
 | > / v
 | muted

 |
 | bullet / nested bullet
 | ∙ / ◦
 | -
 | muted

 |
 | wrap continuation
 | ↪
 | >
 | faint

 |
 | truncation
 | …
 | ~
 | same as text

 |
 | selection bar
 | ▌
 | >
 | magenta

 |
 | risk meter
 | ▰▰▱
 | ##-
 | risk colour

 |
 | tokens
 | ↓ ↑
 | v ^
 | muted

 | Motion
 | the working star
 | ◐ ◓ ◑ ◒
 | - \ \| /
 | cyan

Spinner and progress frames. There is exactly one spinner, the working star, with frames ◐ ◓ ◑ ◒ at 4 fps (one turn per second). There are no progress bars: ORBIT can't know how long a model or tool will take, so it shows elapsed time instead of a fake fraction. Plan progress is a count (4/5) and the phase stepper (§6.10).

## 4.4 Width rules

- Every glyph above is one cell in unicode-width.

- The work and role glyphs were chosen from East-Asian-neutral code points: ✦ › ∙ ◌ ◉ ✓ ✕ ⊖ ↻ ⊘ ▸ ▾ ◓ ◒.

- Box drawing, ● ◇ ◆ ◈ ◐ ◑ ▌ … ↓ ↑ are East-Asian-ambiguous and render two cells wide in terminals set to "ambiguous = wide", which is common with CJK locales. ORBIT detects this at startup (§11.3) and switches to the ASCII set rather than render a misaligned grid.

- No emoji anywhere in the interface. Model-emitted emoji stay content: they pass through the existing ASCII emoji map in bridge.rs (on by default) and never carry status.

## 5. Layout

## 5.1 Grid

row 0          pane headers (one shared row across all panes)
row 1          air
rows 2..H-5    pane bodies (the transcript is bottom-anchored)
row H-4        air above the composer (the rails continue through it)
rows H-3..H-2  composer: input rows grow upward (conversation column only)
row H-1        status line (full width)

Columns, left to right: sessions rail │ conversation │ workspace rail. Each divider is one column of │.

## 5.2 Breakpoints

 |

 | Class
 | Width
 | What is visible
 | Rails

 | Wide
 | ≥ 140
 | Sessions │ Conversation │ Workspace
 | left clamp(28, 0.20·W, 34), right clamp(32, 0.24·W, 44)

 | Medium
 | 110–139
 | Conversation │ Workspace
 | Sessions becomes a drawer (30 columns, solid surface2, opens over the conversation's left edge). Right clamp(30, 0.30·W, 36)

 | Narrow
 | 80–109
 | One view at a time
 | The header row becomes a view switcher Sessions  Conversation  Workspace 2/5; 1 2 3 or Tab switch views

 | Compact
 | 60–79
 | One view
 | Transcript timestamps hidden; tool meta keeps the outcome and drops the duration; status level 2

 | Tight
 | 40–59
 | One view
 | Status level 3; composer hint row hidden (hints via ?); code language labels and session recency hidden

 | Too small
 | < 40 × 10
 | Size notice only
 | "ORBIT needs at least 40 × 10 · this terminal is 38 × 9" plus orbit chat --no-tui

Rails get fixed column widths, not percentages. Percentages make rails absurdly wide at 250 columns and starve them at 140. Extra width goes to the conversation until the prose measure (100) is reached, then to the rails up to their maximums. Past that, the content block centres itself in the conversation column so wide terminals keep a reading column, not a ragged right edge.

Resizing is debounced 50 ms (H-12) and reflows instantly. If the focused pane turns into a drawer or view, it opens as that drawer or view and keeps focus.

## 5.3 Priorities

Rows, from last to lose space to first:

- Status line: always 1 row.

- The approval card, when present: 6 rows minimum, 9 with the facts grid. It takes transcript rows first; if it doesn't fit alongside 3 transcript rows, it takes the whole conversation area.

- Composer: 1 input row plus 1 hint row. The hint row goes first, below 16 rows.

- Pane header row: dropped below 12 rows in single-view layouts. The view name then moves into the status line.

- Transcript: everything left over, never below 4 rows.

The two air rows (row 1 and row H-4) go before any of these.

Workspace sections collapse to header-plus-count in this order as height shrinks: FINDINGS, then VERIFICATION. The active PLAN item never collapses.

Columns: the conversation keeps ≥ 60 columns before anything else gets space, then the workspace, then sessions.

## 5.4 Focus

 |

 |
 | Focused pane
 | Unfocused pane

 | Header
 | Title magenta bold, heavy ━ rule in rule_hi
 | Active tab ink bold, other tabs muted, light ─ rule in rule

 | Cursor row
 | wash fill + magenta ▌ bar
 | surface2 fill, no bar (shows where you'll land)

 | Composer
 | Magenta ›, real terminal cursor, hint row visible
 | Faint ›, no cursor, hint row blank (the row stays, so nothing jumps)

Tab / Shift-Tab cycle panes (views, in narrow layouts). 1 2 3 jump, as the existing keymap does. Focus moves instantly (§7).

## 5.5 Composer behaviour

- Position. A surface band at the bottom of the conversation column. The prompt › sits in the gutter, and text starts at the transcript's text column, so the composer reads as the next turn being drafted.

- Height. One input row minimum. It grows upward to min(8, 30% of H) rows, then scrolls internally with ↑ 3 more in the hint row.

- Hint row. Left side: context keys in muted (⏎ send   ⇧⏎ newline   / commands   ↑ history). Right side: transient acknowledgements (§6.12).

- While a turn runs. The placeholder becomes "Add to the queue, or wait for ORBIT" and ⏎ queue replaces ⏎ send. The worker's prompt channel already queues. A queued prompt appears above the composer as a faint › … queued row, not as a user turn, and becomes a real user turn only when dispatched. (Today Msg::TextSubmitted appends it to the transcript immediately and clears in_flight, so a prompt sent mid-stream erases the part of the answer already streamed; the worker's ResponseFinished carries an empty output, so that text never comes back.)

- While an approval is pending. The approval card takes the composer's place and the draft is kept. This makes the existing behaviour honest: y, n and R already stop reaching the composer while approvals are pending.

- / at column 0. Opens an inline completion list (≤ 6 rows) above the composer, on surface2, styled like palette rows.

- Editing is grapheme-aware. Backspace and cursor movement act on extended grapheme clusters. The real terminal cursor, a steady bar, sits at the insertion point so IME pre-edit renders in place. The painted █ cursor goes.

## 6. Components

## 6.1 Pane header

Title  Tab ━━━━━━━━━━━━━━━━━━━━━━ meta on row 0, inset 1 column. Tabs are 2 spaces apart. Right meta is muted (14 turns, 4/5). Focus rules are in §5.4. Pane titles never carry status colour; a failing session doesn't turn its header red.

## 6.2 User turn

- A surface band spanning the content area.

- Gutter › in muted bold; text in ink, regular weight.

- Time on the first row, right-aligned, muted.

- Wraps at the measure minus the time's width.

- One blank row after.

## 6.3 ORBIT turn

- Gutter: ✦ in cyan while the turn is live (waiting, streaming, running tools) and magenta once it settles. The glyph never animates; the status line carries the motion.

- Before the first token: one static line, ✦ waiting for <local-gateway-model>, in muted. The latency counter ticks in the status line, not here.

- Streaming: text appears in place at the 30 ms coalescing tick. The live edge is a steady cyan ▍. Only the last paragraph reflows. An unclosed code fence renders as code until it closes.

- Markdown:

- H1 is bold and underlined; H2 bold; H3 bold ink2.

- Lists use a ∙ bullet (muted) with a 2-column hanging indent; nested lists use ◦; numbers 1. are muted.

- Quotes use ▎ in muted with ink2 text.

- Tables: bold header, a ─ rule under it, 2-space column gaps, numbers right-aligned, no vertical bars.

- Links show the text underlined; the URL itself is never shown (the display gate rejects it).

- Emphasis renders as bold; italics render plain.

## 6.4 Inline code and code blocks

- Inline code: a surface2 chip with ink text and no backticks. In 16 colours it becomes cyan text; in monochrome the backticks stay.

- Code blocks:

- A surface band from one column left of the text to one column past the measure, with 1 column of inner padding.

- The language label sits right-aligned on the first row, in faint.

- No line numbers.

- Long lines wrap with ↪ in faint in the padding column. Code never truncates silently.

- Syntax colours per §3.1.

## 6.5 Tool-call line

The tool "card" is a row, and only grows a body when it needs one.

  ◉ shell  cargo test -p orbit-export                               running
  ✓ read_file  crates/export/src/restore.rs                212 lines · 0.1s

- Anatomy: state glyph, then the name (ink2 bold; ink bold while running or awaiting), then the argument in muted, then meta right-aligned in muted (outcome · duration).

- Truncation: arguments truncate in the middle (crates/…/restore.rs). The end of a path or command is its most specific part.

- States:

- queued: ◌ queued (faint)

- running: ◉ running (cyan)

- awaiting: ◇ awaiting you (magenta)

- done: ✓ 48 passed · 3.9s (muted)

- failed: ✕ 1 failed · 4.1s (red, detail open by default)

- denied: ⊘ denied by you (muted)

- Session grants. A call that ran under a session grant, and so skipped asking, shows ◈ before its meta. Standing permissions stay visible where they are used.

- Detail (z t, or automatically on failure): lines indented to the name column behind a left rule. The rule is neutral, red for failures, or cyan for a running tool's live output tail (last 3 lines, event-driven).

- Grouping: consecutive tool lines stack with no blank rows between them, and have one blank row before and after the group.

## 6.6 Evidence card (verified)

  ✓ verified  2 checks · retest attestation recorded
  │ cargo test -p orbit-export                                    48 passed
  │ orbit verify-ledger                          7 records · head 0913…a0c3

The header word is green bold; the rest is muted. Rows sit behind a green left rule: check name in ink2, result right-aligned in muted. The card is built only from structured verification data (RTA, ledger), never from model prose. It is the only green block in the transcript.

## 6.7 Citations

- Inline markers [1] in cyan, not superscript (superscript digits have mixed widths).

- A sources line after the turn's content: sources  [1] export/src/restore.rs:88   [2] export/src/bundle.rs:41. The label is muted, the index cyan, the source ink2. It wraps with a hanging indent.

- More than 4 sources collapse to ▸ 6 sources.

- Sources are paths, document titles or ledger references. URLs never appear; the display gate rejects them.

## 6.8 Notices, errors, redaction

- Session notice: ∙ plus muted text plus time (model → <local-gateway-model> · session resumed).

- Connection and rate-limit notices: amber glyph and amber text, one line. They say what ORBIT is doing about it: "retrying 2/5 in 4s · your draft is kept", "resumes in 38s, no action needed".

- Error: a red ✕ in the gutter, then:

- a bold ink headline with the error code in muted (ORBIT-E0406);

- a body in ink2 stating what happened and what is preserved;

- a last row in muted with the recovery keys.
  Red is for the glyph only; red paragraphs are hard to read. One small backend hook: ⏎ on an empty composer resends the last prompt.

- Redaction: ⟨redacted · credential⟩ as a surface2 chip in ink2, naming the category when the gate knows it, otherwise ⟨redacted⟩. Never asterisks or ▒▒▒ (those read as rendering corruption) and never partial values.

## 6.9 Sessions and Activity rail

- Session row:

- column 0: the ▌ cursor bar;

- column 1: the state glyph (◉ working, ◇ needs you, ✕ failed; blank when idle);

- column 3: the title in ink2; the open session is bold ink;

- right-aligned recency in muted (now, 12m, 2h, 1d, 3w).
  Titles truncate at the end, by grapheme, with ….

- Groups: TODAY, YESTERDAY, THIS WEEK, OLDER, with one blank row between groups.

- Activity row: 14:06:12  grant   shell · once · you. Time in faint, kind in muted (fixed 6 columns: plan, tool, grant, ledger, cite, model, warn, error), text in ink2. Warnings and errors colour their text amber or red. Activity shows structured events only: no model text and no reasoning, ever.

## 6.10 Workspace rail

- Phase stepper: ✓━━✓━━◉──◌──◌  execute  3/5, covering the reactor's five phases. Done nodes are muted with heavy connectors; the current node is cyan and the phase name cyan bold; upcoming nodes are faint with light connectors.

- Sections: PLAN, FINDINGS, VERIFICATION, each a muted label with a count on the right, separated by one blank row.

- Task rows: glyph plus title with a 2-column hanging indent, and at most one sub-line:

- active: bold title, sub-line in cyan (what it is doing now);

- blocked: amber sub-line (by what);

- failed: red sub-line (what failed, and which turn to look at);

- retest: amber sub-line (why);

- awaiting approval: magenta ◇ with a muted sub-line.

- Evidence tag, right-aligned: 2 proofs in green (verified) or no evidence in faint (claimed).

- Findings: ∙ plus ink2 text plus a muted inline source (restore.rs:88).

- Verification rows: glyph plus check name in ink2, with the result right-aligned.

## 6.11 Status line

- Left side, what is happening. It changes often and grows rightward into free space:

- the mark (✦ ORBIT, §8);

- the activity: a coloured verb plus muted detail (running shell · cargo test · 3.2s).

- Right side, stable facts. Fixed slots whose values update in place, so nothing ever shifts: model · provider, a 10-column connection slot, a 13-column token slot, an 8-column cost slot, the session id in faint, and ? keys.

- No background and no separator glyphs; three spaces between segments.

- The left side truncates with … 3 columns before the right cluster.

- Standing session grants appear as a ◈ shell slot before the connection slot while at least one exists.

- After a turn, the left side reports it for 2 s (✓ done · 41s · 3 tools · +$0.0031) while the total cost on the right updates in place.

- Level 1 drops the session id. Level 2 keeps the mark, activity, model, connection glyph and cost. Level 3 keeps the mark, activity and cost.

## 6.12 Toasts

Toasts appear on the right of the composer's hint row: muted text with an optional green ✓ (✓ copied 42 lines). They last 3 s or until the next keypress, one at a time. They never float over content and never report errors or approvals; those belong in the transcript.

## 6.13 Command palette

- An overlay 78 columns wide (or W − 8), top edge on row 5, with a rule_hi rounded frame and surface2 fill.

- A query row with a magenta › and esc close on the right, then a hairline.

- Sections COMMANDS · SESSIONS · WORKSPACE · ACTIVITY, each a muted label plus count.

- Rows: the label in ink2, with fuzzy-matched characters in magenta bold (underlined in mono); the description in muted at column 22; a hint on the right.

- The selected row is wash with a ▌.

- A footer of keys.

- The background is not dimmed. Open and close are instant.

## 6.14 Scroll position

- The divider to the right of the transcript is its scrollbar: a │ track with a ┃ thumb in muted (minimum 2 rows).

- When you've scrolled up and new content arrives, a pill appears at the transcript's bottom right: ↓ 12 new · End (surface2, cyan arrow). Nothing appears if nothing new arrived.

## 6.15 Approval prompt

Approval required

- Placement. Docked where the composer was, the full conversation width minus 1-column margins. It is the only frame on screen, rounded and magenta, filled with surface. The request is ORBIT asking for your authority, so it wears the brand colour, not a warning colour, and doesn't look like an OS error dialog.

- Top border: ◇ Allow shell? with the tool name in magenta, and on the right the risk badge ▰▰▱ medium risk (▰▱▱ low muted, ▰▰▱ medium amber, ▰▰▰ high red). Severity lives in the badge; the frame stays magenta.

- The exact action, bold ink, in full. It wraps with ↪ and is never truncated. If it's taller than the space available, the card scrolls, and y and R stay faint (disabled) with scroll to review ↓ until the end of the action has been shown. You can't approve what you haven't seen.

- Facts grid: two columns of label (muted) and value (ink2): runs in, sandbox, egress, ledger. Each row appears only when the backend supplies it from structured data (capability card, sandbox profile, egress check), never from model text. Today the request carries only a tool name and summary, so the grid is empty and the card is 6 rows.

- Keys row: keycaps (surface2 chips) in this order:

- y allow once

- R allow shell for this session (the scope is spelled out)

- n  esc deny. Both deny today, so they share one honest label.
  If policy doesn't allow session grants at the current risk level, R shows faint with "not available for high-risk actions".

- Queue: 1 of 3 on the bottom border, only when more than one request is waiting.

- After a decision, the card closes and the transcript's tool line updates to ◆ once, ◈ session or ⊘ denied. A grant event lands in Activity.

- Backend hook needed: a risk level on the approval request. It is the one field this design can't draw without.

## 6.16 Confirm and help overlays

Quit: a small rule_hi rounded card with "Quit ORBIT?" in bold. If a turn is running, a second amber line says so. Keys y quit   n stay. No backdrop dimming.

Help (?): the same frame, with two columns of keys grouped by pane. It replaces the permanent 2-row help bar.

## 7. Motion

One clock and one moving cell. A 4 Hz orbit clock drives the only ambient animation. A 1 Hz text clock updates counters in the status line. Everything else is event-driven. An idle ORBIT draws zero frames.

 |

 | #
 | Motion
 | Trigger
 | Frames / cadence
 | Ends
 | Reduced motion

 | M1
 | Startup sequence (§8.3)
 | Launch at brand tier anim
 | 6 frames at 4 fps (1.25 s), then a 500 ms hold
 | Any key or completion
 | Skipped; final frame shown

 | M2
 | Working star
 | ORBIT is waiting, streaming or running a tool
 | ◐ ◓ ◑ ◒ at 4 fps: one turn per second, one cell
 | Turn ends, or it needs you
 | Static cyan ✦

 | M3
 | Counters
 | Elapsed time, time to first token, retry countdown
 | Text update at 1 Hz, status line only
 | State ends
 | Unchanged (text, not motion)

 | M4
 | Streaming text
 | Provider deltas
 | Coalesced every 30 ms (existing data tick)
 | Stream ends
 | Revealed by whole lines, ≤ 250 ms (the H-10 bound)

 | M5
 | Turn report (cost acknowledgement)
 | Turn finishes
 | Left status shows ✓ done · 41s · 3 tools · +$0.0031
 | 2 s, or the next keypress
 | Unchanged

 | M6
 | Reconnecting
 | Connection lost
 | Countdown text at 1 Hz; ↻ stays still
 | Reconnected or offline
 | Unchanged

 | M7
 | Focus transition
 | Focus moves
 | 0 frames: instant
 |
 |

 | M8
 | Shutdown
 | Quit confirmed
 | No frames. One summary line printed after the alternate screen closes (§8.4)
 |
 |

What stays static, strictly:

- Nothing animates in the transcript, the rails or the overlays.

- No blinking, including the cursor (a steady bar).

- No colour cycling or shimmer.

- Drawers, palettes and cards open and close instantly.

- Scrolling moves by lines.

Focus in particular is instant. It's the most frequent interaction, so any transition adds latency to everything, and the magenta title plus heavy rule already say where focus went.

Why 4 fps. It's the spec's logo rate. A quarter-turn per frame reads as deliberate rotation, like a clock rather than a buzz. It costs four one-cell updates a second while ORBIT works, and nothing at all while it's idle.

What changes in the current code:

- shimmer_phase sets DirtyFlags::LAYOUT every 8 ticks (128 ms), so an idle ORBIT re-renders every pane about 8 times a second. Remove it.

- The rotating thinking phrases go.

- cost_flash_frames (8 × 16 ms, a 128 ms ↗ that's hard to see) is replaced by M5.

- The ↻↺ reconnect rotation becomes a still glyph plus a countdown.

## 8. Logo and brand

## 8.1 The mark

Logo sheet

    ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀
 ⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █
 ⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █

    the harness that orbits around you

Concept. The O is you, the fixed centre. The dotted, tilted ring is the harness in orbit around you; it passes behind the planet, so the letterform stays intact. The ✦ is ORBIT, riding its orbit. Letters are ink, the ring magenta_dim, the star magenta, and the tagline "the harness that orbits around you" sits beneath in muted.

Expanded mark, 3 rows × 31 columns:

- Half-block letterforms (▄ ▀ █).

- A braille ring tilted −14°, hidden wherever it crosses a stroke.

- The star at the ring's upper right.

It appears only on the welcome screen of an empty session. It isn't pinned; the first turn replaces it.

Compact mark: ✦ ORBIT, at the far left of the status line in every layout. The word is muted bold. The star is ORBIT's state light:

 |

 | State
 | Star

 | Ready, or needs you
 | Magenta

 | Working
 | Cyan, turning ◐◓◑◒ (M2)

 | Degraded
 | Amber

 | Offline
 | Red

The activity next to it always says the same thing in words.

## 8.2 Where the motif appears, exhaustively

- The expanded mark (welcome screen).

- The compact mark (status line).

- ✦ as ORBIT's voice glyph.

- The turning star.

- The circle family of work states (◌ ◉).

Nowhere else: no rings around panes, no stars as bullets, no orbit animations in loaders, no constellation backgrounds, no logo in pane headers.

## 8.3 Startup → steady

At tier anim, the welcome area plays six frames at 4 fps:

- The O alone: you.

- A third of the ring.

- Two thirds of the ring: the orbit forming around you.

- The ring complete, and the star arrives in magenta_hi.

- RBIT fills in and the star settles to magenta.

- The tagline appears. Hold.

The compact mark is in the status line, static, from frame 1. Any key jumps to the last frame; at tier static, the last frame is all there is. Sending the first turn swaps the welcome block for the transcript with no transition.

## 8.4 Shutdown

After the alternate screen is restored, ORBIT prints one line to the normal scrollback, coloured only if colour is allowed:

✦ ORBIT  session saved · 14 turns · ledger 9 records · $0.0214
         resume with orbit chat --resume 01J8ZK4Q

It uses the existing --resume flag. On SIGHUP nothing is printed (the terminal is gone); on SIGTERM the existing one-line stderr note stays.

## 8.5 Brand tiers (H-4, H-5, H-15)

The TUI honours the existing BrandTier ladder. The tier is resolved once at startup and only ever steps down:

- NO_COLOR → at most text

- reduced motion → at most static

- ASCII glyphs → at most text

- TERM=dumb → no TUI

 |

 | Tier
 | Welcome
 | Status line
 | Motion

 | anim
 | Expanded mark, startup sequence
 | ✦ ORBIT
 | M1 + M2

 | static
 | Expanded mark, still
 | ✦ ORBIT
 | M2

 | text
 | ORBIT in bold plus tagline
 | ✦ ORBIT
 | M2

 | off
 | Readiness checks and starters only
 | The state star alone, with no word
 | M2

Decision needed
 H-4 locks the brand to default-off, and ORBIT-F-HUD-009 says the lock can't be relaxed by patches. Recommendation: amend DR-20 to scope H-4 to line-mode HUD output and make the TUI default to static, with anim opt-in. The TUI only launches on an interactive TTY, so its brand never reaches scripts, logs or CI output. Until that decision is made, ship off. Every screen here still reads correctly at off, because identity comes from the palette, the voice glyph and the layout, not from the mark.

## 9. Mockups

Rendered at 150 × 44 (wide) and 80 × 30 (narrow). The PNGs show colour; the text is the same frame, which makes a golden fixture for ratatui's TestBackend.

## 9.1 Wide: idle conversation with history

Wide idle
Plain-text frame · 150 × 44

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
                              │  › ▏Ask ORBIT, or type / for commands                                            │
                              │    ⏎ send   ⇧⏎ newline   / commands   ↑ history                                  │
 ✦ ORBIT   ready                                                          <local-gateway-model> · local     ● online    ↓18.2k ↑2.9k    $0.0214   01J8ZK4Q   ? keys

## 9.2 Wide: streaming, with a tool running

The live turn's star is cyan, the running tool is a still ◉ running with its output tail streaming beneath it, and a queued prompt waits above the composer. The one moving part is the star in the status line (◐), next to the only ticking counter.
Wide streaming
Plain-text frame · 150 × 44

 Sessions  Activity ───────── │ Restore keeps chain head ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 13 turns │ Workspace ────────────────────────
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
                              │  › ▏Add to the queue, or wait for ORBIT                                          │
                              │    ⏎ queue   ⇧⏎ newline   pgup scroll                                            │
 ◐ ORBIT   running shell · cargo test · 3.2s                              <local-gateway-model> · local     ● online    ↓15.9k ↑2.1k    $0.0183   01J8ZK4Q   ? keys

## 9.3 Approval required

The card replaces the composer, and it is the only frame on screen. The tool line, the workspace task and the status line all show ◇; ORBIT's star is at rest (magenta) because it is waiting on you.
Plain-text frame · 150 × 44

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
                              │                                                                                  ┃
                              │ ╭─ ◇ Allow shell? ────────────────────────────────────────── ▰▰▱ medium risk ──╮ ┃
                              │ │                                                                              │ │
                              │ │  scripts/e2e-clean-machine.sh --keep-home                                    │ │
                              │ │                                                                              │ │
                              │ │  runs in  ~/src/orbit                 sandbox  landlock · rw /tmp only       │ │
                              │ │  egress   none                        ledger   decision is recorded          │ │
                              │ │                                                                              │ │
                              │ │   y  allow once     R  allow shell for this session     n   esc  deny        │ │
                              │ ╰──────────────────────────────────────────────────────────────────────────────╯ │
 ✦ ORBIT   ◇ approval needed · shell                                      <local-gateway-model> · local     ● online    ↓17.6k ↑2.7k    $0.0209   01J8ZK4Q   ? keys

## 9.4 Narrow terminal (80 × 30)

A single view with the view switcher in the header row. Streaming text ends at the live cursor. The status line drops to level 2.
Narrow
Plain-text frame · 80 × 30

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

 ✦ ✓ edit_file  crates/export/src/restore.rs                             +9 −3
   ✓ shell  cargo test -p orbit-export                               48 passed

   Both checks pass. The restored chain now starts from the exported head
   0913…a0c3, so verify-ledger walks all 7 records without a break. Next I
   would run the clean-machine▍

  › ▏Add to the queue, or wait for ORBIT
    ⏎ queue   ⇧⏎ newline   tab views
 ◐ ORBIT   streaming · 212 tokens                        <local-gateway-model>   ●    $0.0196

## 9.5 Also rendered

 |

 | Welcome, medium layout (112 × 34)
 | Command palette over the wide layout

 |
 |

 |

 | Status line in every state
 | Conversation states

 |
 |

 |

 | Rails in every state
 | The same screen in four tiers: true colour, 16 colours, mono, ASCII

 |
 |

ASCII tier, monochrome, as plain text:

 Restore keeps chain head ============================== 14 turns

 > Do it, and add a regression test.                       14:06

 * Done. `restore_preserves_head` covers it [1].           14:09

   + shell  cargo test -p orbit-export                 48 passed
   ? shell  scripts/e2e-clean-machine.sh            awaiting you

 +- ? Allow shell? -------------------------------- ##- medium -+
 | scripts/e2e-clean-machine.sh --keep-home                     |
 | [y] once   [R] session   [n] deny                            |
 +--------------------------------------------------------------+

>  Restore keeps chain head   now
 x Cost rounding in µ¢         1d

 * ORBIT   ? approval                      <local-gateway-model>   o    $0.0214

## 10. State matrix

 |

 | Component
 | Unfocused
 | Focused
 | Idle
 | Selected / cursor
 | Active / live
 | Disabled
 | Error

 | Pane header
 | Active tab ink bold, others muted, ─ rule
 | Title magenta bold, ━ rule_hi
 | —
 | —
 | — (headers never show status)
 | Tab faint when its view is empty
 | — (errors never recolour headers)

 | Session row
 | Title ink2, recency muted
 | Same; the cursor gains the bar
 | No glyph
 | wash + ▌ when focused; surface2 when not; REVERSE in 16 colours and mono; metadata promoted to ink2
 | ◉ cyan
 | Archived: title faint
 | ✕ red glyph; title unchanged

 | Task row
 | Glyph by state, title ink2
 | Cursor row as sessions
 | ◌ faint
 | wash + ▌
 | ◉ cyan, bold title, cyan sub-line
 | Skipped: faint title, ⊘
 | ✕ red + red sub-line; ⊖ amber when blocked

 | Tool line
 | —
 | Transcript cursor: surface2 row, ▸/▾ shown
 | ✓ muted with outcome
 | surface2 + detail toggle
 | ◉ cyan running
 | ◌ faint queued
 | ✕ red, detail open, red rule

 | Composer
 | Faint ›, no cursor, blank hint row
 | Magenta ›, real cursor, hints
 | Faint placeholder
 | — (text selection is the terminal's)
 | "Add to the queue…" placeholder, ⏎ queue
 | Replaced by the approval card; draft kept
 | Draft kept; the error is a transcript notice

 | Approval card
 | — (always holds input)
 | Magenta frame
 | —
 | —
 | —
 | y/R faint until the whole action has been seen
 | If the tool fails after approval, its line shows ✕

 | Palette row
 | —
 | —
 | Label ink2
 | wash + ▌, label ink bold
 | —
 | faint plus a reason ("needs a provider")
 | A single muted "no matches" row

 | Status line
 | Default
 | Focus::Status: the word ORBIT turns magenta bold and segments get a REVERSE cursor
 | Magenta star, ready
 | Segment REVERSE
 | Cyan turning star, cyan verb
 | —
 | Red star, red verb

## 11. Accessibility and terminal compatibility

## 11.1 Colour blindness

Every state is glyph + word + colour (§4.3), and §3.8 lists the pairs that fall below ΔE 20 under simulation together with the shapes that separate them. Two consequences:

- The working star changes shape (✦ → ◐◓◑◒), not just colour, because deuteranopes can barely tell magenta from cyan (ΔE 12).

- Green means verified, and ✓ versus ✕ still separates results from failures when green and red collapse (protan 23, deutan 21).

## 11.2 No colour

NO_COLOR selects the monochrome tier (§3.6). The TUI still runs, since NO_COLOR is about colour, not interactivity. Brand is clamped to text.

## 11.3 ASCII and Unicode width

- Auto-select the ASCII set when:
  1. the locale isn't UTF-8; or
  2. a startup probe finds that ambiguous-width glyphs render wide.

The probe runs before entering the alternate screen: print ● at column 0, ask for the cursor position (ESC[6n, which crossterm exposes as cursor::position()), check whether the cursor moved one column or two, then erase the line. It has a 100 ms timeout; with no answer, assume narrow. Override with [glyphs] set = "unicode" | "ascii".
- Stop forcing UTF-8. terminal.rs currently sets LANG and LC_ALL to en_US.UTF-8 when they're empty. That hides non-UTF-8 terminals, which H-7 lists as a hard downgrade. Detect instead of forcing.
- Text is measured and cut by grapheme cluster:
  - unicode-segmentation for clusters, unicode-width for widths.
  - Never split a ZWJ sequence, a combining mark or a wide character.
  - A wide character that doesn't fit at a line end moves to the next line.
  - … follows the last whole cluster that fits.
  - ZWJ emoji count as width 2.
- Composer: backspace deletes a whole grapheme (today Composer::pop removes one char, which leaves orphaned combining marks and half-deleted emoji). The real cursor sits at the insertion point for IME.

## 11.4 Screen readers and plain, log-friendly output

The alternate-screen TUI is not a screen-reader surface. orbit chat --no-tui is the accessible path. The TUI should also honour H-7's screen-reader downgrade: with ORBIT_SCREEN_READER=1 it doesn't launch. Copy mode (z y), the REPL and non-TTY output share one plain grammar: one event per line, words instead of glyphs, no box drawing, a timestamp on each line.
Plain-text frame · 150 × 7

14:02 you: orbit verify-ledger fails right after orbit restore on a clean home. Can you find out why?
14:02 orbit: The restored namespace starts a brand-new chain: restore writes a fresh genesis record, …
14:02 tool read_file crates/export/src/restore.rs: done, 212 lines, 0.1s
14:06 approval needed: shell scripts/e2e-clean-machine.sh --keep-home (medium risk). y allow once, R allow shell for this session, n deny
14:06 tool shell rm -rf target/: denied by you
14:09 verified: 2 checks. cargo test -p orbit-export: 48 passed. orbit verify-ledger: 7 records, head 0913…a0c3
14:09 status: ready. <local-gateway-model> via local. online. 18.2k in, 2.9k out. $0.0214

This replaces today's user> and orbit> prefixes and the [tool: name] line.

## 11.5 Reduced motion

Enable it with ORBIT_REDUCED_MOTION=1 or [motion] reduced = true:

- M1 is skipped.

- M2 becomes a still cyan star.

- Streaming reveals whole lines.

Nothing else moves anyway.

## 11.6 Terminals without true colour

§3.4–3.7 cover this.

- tmux: add set -ga terminal-overrides ",*:RGB" to get true colour, or ORBIT drops to 256 colours.

- Windows Terminal: true colour (WT_SESSION).

- Legacy conhost: 16 colours plus ASCII.

- Light themes: fine everywhere. True colour and 256 paint their own canvas; 16 colours and mono inherit the user's theme.

## 11.7 Keyboard and attention

- Keyboard: everything is reachable by keyboard. Mouse capture stays off, so native selection works.

- Bell: opt-in [notify] bell_on_approval = true rings one BEL when an approval opens, so the terminal can flag a waiting ORBIT in a background tab. This is the only sound, and it's off by default.

- Minimum size: below 40 × 10, ORBIT shows the size notice instead of a broken grid.

## 12. Anti-patterns and cuts

What goes, from the current build and from the brief itself:

 |

 | Cut
 | Why
 | Instead

 | Pastel pink #FFB3D9 + "Miku blue" #A0D8EF
 | Conflicts with the locked white + magenta brand (ORBIT-F-HUD-003/009) and reads as a theme, not a product
 | §3 palette

 | Rounded borders around all three panes, the header and the composer
 | Five boxes compete with the content; borders cost 2 rows and 2 columns per pane
 | Hairline headers, one divider, zero frames at rest

 | Focus shimmer (accent/bright toggle every 128 ms)
 | Decoration; re-renders the whole layout about 8 times a second while idle; the brief rejects it
 | Magenta title + heavy rule, static

 | Rotating "Orbiting… / Gathering context…" phrases
 | Fake progress; implies a thought process ORBIT doesn't show
 | waiting for <local-gateway-model> + a real latency counter

 | ✦✧⋆· twinkle spinner (and the moon style)
 | The generic AI sparkle; the moon frames are width-2 emoji
 | The turning star, in one place

 | ✹ ORBIT header with a shimmering wordmark, 3 rows
 | Brand competing with work on every screen
 | The compact mark in the status line; the expanded mark on welcome only

 | Permanent 2-row help bar
 | Chrome for something you learn once
 | Context hints in the composer row, ? overlay

 | user> / orbit> prefixes, blue user text
 | Wordy; uses the "live" colour for static text
 | Gutter glyphs, surface band, ink

 | [tool: name] (reasoning stripped) line
 | Advertises hidden content and adds noise
 | The tool line alone. Stripping stays in the bridge, silently

 | Painted █ cursor
 | Breaks IME and assistive tech
 | The real terminal cursor, steady bar

 | DIM overlay behind the quit modal
 | Fake transparency; repaints the whole screen twice
 | A solid card, no backdrop

 | " ↗" 128 ms cost flash
 | Too short to see, carries no number
 | The M5 turn report

 | Coloured markdown headings (pink/blue)
 | Spends accent colour on structure
 | Weight only

 | Brief: "focus transition" motion
 | Adds latency to the most frequent action
 | Instant (M7)

 | Brief: "bubble softness" everywhere
 | Softness in quantity turns into clutter
 | Three uses only: rounded overlay corners, surface bands, chips

 | Brief: logo states as decoration
 | A permanent animated logo is noise
 | The star is the state light; motion only while working

Also rejected up front: gradients on the wordmark; emoji status; sparklines of cost or tokens; per-turn token footers; constellation or starfield backgrounds; animated borders; spinners inside tool lines; a second accent colour for "brand variety"; sound beyond the opt-in bell.

## 13. Implementation handoff

## 13.1 Token table

 |

 | Token
 | True colour
 | xterm-256
 | ANSI-16
 | Mono
 | Used for

 | bg
 | #100E16
 | 233
 | default bg
 | default
 | canvas

 | surface
 | #17141F
 | 234
 | —
 | —
 | user band, composer, code, approval fill

 | surface2
 | #211C2B
 | 235
 | —
 | —
 | chips, palette fill, unfocused cursor

 | wash
 | #2B1631
 | 236
 | REVERSE
 | REVERSE
 | focused cursor row

 | rule
 | #2D2839
 | 236
 | DIM
 | DIM
 | hairlines, dividers

 | rule_hi
 | #463F55
 | 239
 | DIM
 | DIM
 | focus rule, overlay frames, thumb

 | ink
 | #ECE8F3
 | 255
 | default fg
 | default
 | primary text

 | ink2
 | #BDB6CA
 | 250
 | default fg
 | default
 | secondary text

 | muted
 | #8B8499
 | 103
 | DIM
 | DIM
 | metadata, labels, hints

 | faint
 | #655F73
 | 60
 | DIM
 | DIM
 | placeholder, disabled

 | magenta
 | #E356D0
 | 170
 | 5
 | BOLD
 | brand, focus, selection bar, authority

 | magenta_hi
 | #F58CE4
 | 212
 | 5
 | BOLD
 | startup star flash

 | magenta_dim
 | #8E3C7F
 | 96
 | 5 + DIM
 | DIM
 | expanded-mark ring

 | cyan
 | #5CC6DD
 | 81
 | 6
 | BOLD (glyph)
 | live

 | green
 | #62CC8E
 | 78
 | 2
 | — (glyph + word)
 | verified, online

 | amber
 | #E9B252
 | 179
 | 3
 | — (glyph + word)
 | caution

 | red
 | #F06A5E
 | 203
 | 1
 | BOLD
 | failure

 | syn_kw / syn_str / syn_num
 | #C3A6FF / #A6D6A0 / #EFC08D
 | 183 / 151 / 180
 | 4 / 2 / 3
 | —
 | code

## 13.2 Glyph table

§4.3 is normative. Ship it as one Glyphs struct with unicode() and ascii() constructors. No render code may contain a glyph literal.

## 13.3 Component checklist

- [ ] Theme. Replace ThemeColors with the §13.1 tokens and resolve once per tier (true colour, 256, 16, mono). No colour literal outside theme.rs (true today; keep it).

- [ ] Capabilities. Resolve colour tier, glyph set, brand tier and reduced motion once at startup (§3.7, §11.3). They can step down at runtime but never up.

- [ ] Layout. Breakpoints and rail widths from §5.2. Row priorities from §5.3. Prose measure min(col − 5, 100). Content centred past measure + 16.

- [ ] Pane header (§6.1) replaces pane_block: no Borders::ALL, a ━ rule when focused, no ▶.

- [ ] Divider and scrollbar (§6.14): full-height │, ┃ thumb, the ↓ n new · End pill.

- [ ] Transcript. Bottom-anchored; turns per §6.2–6.8; a blank row between turns; gutter 3; tool lines middle-truncated; detail rules coloured by meaning.

- [ ] Markdown per §6.3–6.4: headings by weight, ∙/◦ bullets, surface code bands with ↪ wrap, three syntax colours.

- [ ] Composer per §5.5: a band, not a box; auto-height; real cursor; grapheme editing; a queued-prompt row; replaced by the approval card.

- [ ] Approval card per §6.15: docked, magenta, the exact action never truncated, y/R disabled until fully seen, risk badge, facts only from structured data.

- [ ] Status line per §6.11: a dynamic left side, a fixed-slot right side, levels 0–3, the M5 turn report.

- [ ] Workspace per §6.10: stepper, sections, eight task states, evidence tags.

- [ ] Sessions and Activity per §6.9. Rename the Verbose tab to Activity (keep g v) and the Tasks pane to Workspace.

- [ ] Palette, confirm, help per §6.13 and §6.16: solid, framed, no backdrop dimming.

- [ ] Motion per §7:

- delete the shimmer and the phrase rotation;

- the 4 Hz clock sets DirtyFlags::LOGO only while working;

- the 1 Hz clock sets STATUS only while a counter is visible;

- idle sets nothing.

- [ ] Brand per §8: compact mark, expanded mark, startup frames, shutdown line, tier table.

- [ ] Plain grammar (§11.4) for copy mode, the REPL and non-TTY output.

- [ ] Remove the LANG/LC_ALL forcing; add the width probe.

## 13.4 tui.toml migration

Old keys keep working for one release and log a deprecation line.

 |

 | Old key
 | New

 | colors.accent
 | colors.magenta

 | colors.accent_bright
 | removed (magenta_hi is startup-only and not themeable)

 | colors.accent_dim
 | colors.magenta_dim

 | colors.composer, colors.composer_dim
 | removed: the composer uses magenta for its prompt and ink for text; the dim state is faint

 | colors.text / colors.dim
 | colors.ink / colors.muted

 | colors.code_bg / colors.code_fg
 | colors.surface / removed (code uses ink plus the syn_* tokens)

 | colors.error / success / warning
 | colors.red / green / amber

 | spinner.style, spinner.phrases
 | removed: one working glyph set, no phrases

 | layout.left_pct / center_pct / right_pct
 | layout.rail_left, layout.rail_right (columns, clamped), layout.measure (default 100)

 | layout.header_lines / status_lines / help_lines / composer_lines
 | fixed at 1 / 1 / 0 / auto

 | tabs.show_help_bar
 | removed (? overlay)

 | new
 | [color] mode, [glyphs] set, [motion] reduced, [brand] tier, [notify] bell_on_approval

A user theme may recolour tokens. It may not add colours, animate anything, or change glyph meanings.

## 13.5 Design invariants as tests

Encode the thesis as tests, so the design can't drift one tweak at a time:

- golden_*: render §9's four frames into TestBackend at 150 × 44 and 80 × 30, and compare against the text in this document.

- golden_orbit_letterform_4frames: back the existing placeholder test with the startup frames from §8.3.

- invariant_one_frame_max: at most one rounded frame in any buffer.

- invariant_magenta_closed_list: magenta cells only at the six places listed in §1, principle 3.

- invariant_idle_draws_nothing: after a response settles, 1,000 ticks set no dirty flags.

- invariant_single_moving_cell: while working, consecutive frames differ only in the mark cell and status counters, unless data arrived.

- invariant_ascii_tier_is_ascii: with the ASCII glyph set, every cell ORBIT draws itself (glyphs, rules, frames, labels) is printable ASCII. Content passes through untouched; the µ¢ in §9.5's session title is a user's title, not chrome.

- invariant_no_truncated_approval: the approval action text appears in the buffer in full at every supported size.

## Why this is ORBIT

The layout is the name. You sit at the centre with the brightest ink, and everything else orbits you in progressively dimmer rings, out to the status line. Magenta isn't a theme colour; it is ORBIT's own voice and your authority. That makes the one magenta frame ORBIT ever draws, the approval card, the product's thesis made visible: the user is the locus of authority, and the harness asks. Green has to be earned with evidence, because ORBIT exists to prove what an agent did. The only thing that moves is the star, turning while ORBIT works and still otherwise, so a still screen can be trusted as a finished one.

Take the logo off and the product is still recognisable: circles for work, diamonds for authority, honest counters instead of theatre, and a quiet white-and-magenta grid built around your conversation. It isn't a dashboard of equally loud panes, and it isn't another sparkle-and-spinner AI CLI.

Source: docs/tui/DESIGN.md on branch claude/sweet-maxwell-csjqp5 of the ORBIT repository. The Markdown there is the normative copy; this page adds colour swatches and larger renders.
---

# Amendments from the competing TUI mockups (2026-09-26)

Four concrete contributions adopted from the losing entry. Each strengthens §6.15 or the workspace rail:

1. **[GPT-AMEND] Scope-honesty line in the approval card.** Under the facts
   grid, one mandatory line whenever a session-wide grant would be broader
   than the request: `Session permission covers <tool>, not only this
   command.` Never let a session grant be implied to be scoped to the current
   target. (Mirrors the desktop spec's session-grant scope-honesty rule.)

2. **[GPT-AMEND] Exact command + working directory rendering.** The "exact
   action" in §6.15 renders as the verbatim command (e.g.
   `git push origin HEAD:refs/heads/retry-fix`) followed by
   `Working directory: /work/orbit` — both in full, both never truncated, both
   subject to the scroll-to-review rule.

3. **[GPT-AMEND] Evidence counters in the Workspace rail.** The workspace rail
   shows a compact evidence summary block (Tests 42/42 · Lint 0 warnings ·
   CI not run) — counters only from structured verification events; "not run"
   is a valid, honest value, never omitted.

4. **[GPT-AMEND] Post-decision line under the approval card.** While a
   decision is pending, the line under the keys row reads
   `Action not executed · no approval option is preselected` — making both
   facts explicit until a verdict is applied.

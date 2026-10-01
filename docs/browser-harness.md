# ORBIT Browser Harness — Architecture

> Status: **implemented** (crates/web + `orbit web`). The Rust core is the
> single source of truth; the browser is a thin view.
>
> Verified: `scripts/web_harness_test.py` — 13/13 (SPA, SSE identity, WS
> actions, streaming, approval, persistence, resume) against the mock
> provider, plus 6 router unit tests in crates/web/tests/.

## Goal

A browser front-end for ORBIT that reuses the exact same Rust core, protocol,
and trust/ledger/tool-runtime as the TUI — so the operator can switch between
terminal and browser without losing session state, approvals, or audit
provenance. The browser is **not** a second harness; it is a second projection
of the same harness.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Browser (any modern browser, local or remote)            │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Single-page app (TypeScript, no framework)         │  │
│  │  • three-pane layout (Sessions · Chat · Tasks)      │  │
│  │  • streaming transcript (SSE)                        │  │
│  │  • composer with slash commands                      │  │
│  │  • approval modal (y / n / R)                        │  │
│  │  • status bar (model · provider · session · cost)    │  │
│  │  • theme (CSS custom properties, same palette)       │  │
│  └───────────────────────┬────────────────────────────┘  │
│                          │ WebSocket (actions) + SSE (events) │
│  ┌───────────────────────┴────────────────────────────┐  │
│  │  orbit-web (Rust, axum) — the bridge server          │  │
│  │  • serves the SPA (static assets)                    │  │
│  │  • WebSocket: browser → Rust actions (prompt, cancel, │  │
│  │    approve, quit)                                    │  │
│  │  • SSE: Rust → browser events (identity, delta,      │  │
│  │    tool_call_started, cost, finished, error)         │  │
│  │  • reuses run_turn + tool_runtime + sessions          │  │
│  └───────────────────────┬────────────────────────────┘  │
│                          │ in-process (same binary)        │
│  ┌───────────────────────┴────────────────────────────┐  │
│  │  Rust core (untouched):                              │  │
│  │  gateway · ledger · trust · tool runtime · sessions  │  │
│  │  egress · cancel · provider adapters · HUD gate      │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

## Protocol (same JSON shapes as the Go TUI bridge)

### Rust → Browser (SSE)

```
event: identity
data: {"model":"...","provider":"...","session":"..."}

event: delta
data: {"text":"chunk"}

event: tool_call_started
data: {"call_id":"...","name":"...","summary":"..."}

event: tool_call_finished
data: {"call_id":"...","name":"...","ok":true}

event: cost
data: {"microcents":2500,"input_tokens":12,"output_tokens":34}

event: finished
data: {"output":"...","input_tokens":12,"output_tokens":34,"cost_microcents":2500}

event: error
data: {"message":"ORBIT-E0401: ..."}

event: cancelled
data: {}
```

### Browser → Rust (WebSocket)

```json
{"type":"prompt","text":"what is 2+2"}
{"type":"cancel"}
{"type":"approve","call_id":"call-0","verdict":"allow"}
{"type":"approve","call_id":"call-0","verdict":"deny"}
{"type":"approve","call_id":"call-0","verdict":"session"}
{"type":"quit"}
```

This is **identical** to the Go TUI's Unix-socket protocol, just over
WebSocket + SSE instead of a Unix socket. The Rust `run_turn` + tool loop
is shared verbatim — only the transport changes.

## Security model

- **Loopback-only by default.** The bridge server binds `127.0.0.1:PORT`.
  Remote access requires an explicit `--bind 0.0.0.0` flag + a bearer token
  (same `ORBIT_GATE_TOKEN` contract; never stored, never logged).
- **Display-safety gate (H-3) applies.** All text sent to the browser passes
  through `orbit_hud::display_safe` — secrets, URLs, and control chars are
  redacted before they leave Rust. The browser never sees raw credentials.
- **No prompt bytes in the Ledger.** Same as the TUI — the browser sends
  prompts over WebSocket, Rust processes them through the four-gate pipeline,
  and prompt bytes never enter the Ledger, exports, or logs.
- **Approvals are server-side.** The browser sends an `approve` action, but
  the actual grant/deny decision is recorded in the Ledger by the Rust core.
  The browser cannot bypass the approval flow — it can only send a verdict
  that Rust applies.
- **CORS: none.** The SPA is served from the same origin as the WebSocket/SSE.
  No cross-origin requests.

## Session continuity

- The browser and TUI share the same `$ORBIT_HOME/sessions/` directory.
- `--resume <session-id>` works from both front-ends — the browser loads the
  prior transcript and continues the conversation.
- A session started in the TUI can be resumed in the browser and vice versa.
- The Ledger records every turn regardless of which front-end initiated it.

## Theming

- The browser uses CSS custom properties that mirror the TUI's `tui.toml`
  palette: `--accent`, `--composer`, `--text`, `--dim`, `--error`, etc.
- A `theme.toml` (or the existing `tui.toml` extended with a `[browser]`
  section) maps the same colors to CSS values.
- Dark mode is the default (matches the terminal); light mode is opt-in.
- The orbital logo is an SVG animation (same star-on-ring motif, CSS-driven).

## Implementation plan (next milestone)

1. **`crates/web/`** — new crate. Axum server with:
   - `GET /` → serve the SPA (static HTML/JS/CSS from `crates/web/assets/`)
   - `GET /events` → SSE stream (Rust → browser)
   - `WS /actions` → WebSocket (browser → Rust)
   - Reuses `run_turn` + `tool_runtime` + `sessions` from the CLI crate
2. **`crates/web/assets/`** — the SPA:
   - `index.html` — three-pane layout, composer, status bar, approval modal
   - `app.ts` — WebSocket + SSE client, state machine, rendering
   - `styles.css` — theme via custom properties
   - `logo.svg` — animated orbital logo
3. **`orbit web`** — new CLI command. Starts the bridge server and opens the
   browser (or prints the URL). Flags: `--port`, `--bind`, `--no-browser`.
4. **E2E test** — `scripts/web_harness_test.py` (stdlib-only: raw-socket WS
   client + SSE reader) exercises the live server end-to-end. The harness
   modules (run_turn, tool runtime, sessions) were extracted from the cli
   binary into `orbit-cli`'s lib so the web crate reuses them verbatim —
   the same code path the TUI and Go bridge drive.

## What stays untouched

- The entire Rust core: gateway, ledger, trust, tool runtime, sessions, egress.
- The TUI (both ratatui and Go Bubble Tea) — they remain first-class.
- The JSON protocol — shared across all three front-ends (TUI, Go TUI, browser).
- The display-safety gate, approval flow, and Ledger provenance.

## Why not just a web-based TUI?

The terminal TUI is the primary surface (operators live in the terminal). The
browser harness is for:
- Rich markdown rendering (code blocks with syntax highlighting, tables, images)
- Multi-session dashboards (side-by-side conversations)
- Mobile access (resume a session from a phone)
- Collaboration (share a read-only view of a session with a teammate)

The browser never replaces the TUI — it complements it. The Rust core is the
harness; the front-ends are projections.

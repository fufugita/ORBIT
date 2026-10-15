# Browser harness

The browser harness uses ORBIT's session owner, provider adapters, tool permissions
and saved conversations. Configure a provider through [setup](setup.md), then
start the browser from the workspace you want to use:

```sh
orbit web --model PROVIDER/MODEL
```

The default address is `http://127.0.0.1:4173`. ORBIT attempts to open it in your
browser. Use `--no-browser` to open the address yourself, `--port 4180` to choose
another port, or `--port 0 --no-browser` to let the system choose a port and print
the actual address. The matching `orbit-web` executable must be installed beside
`orbit`; see [setup and installation](setup.md).

## Work with a conversation

Send a prompt with Enter; Shift+Enter inserts a newline. The transcript shows
streamed responses, tool activity and approval requests. Cancel stops the current
turn. An approval offers allow once, allow for this session, or deny; the owner
applies the decision through the normal tool runtime and permission rules.

The status bar identifies the provider, model and session, with usage and cost.
Use the sessions list or `/resume SESSION_ID` to switch to a saved conversation.
To start directly in one:

```sh
orbit web --resume SESSION_ID
```

Saved sessions use the same home as the terminal harness. A private session lease
is acquired before loading the saved conversation. A session already owned by
another process is refused; ORBIT does not create a replacement session. Close
the previous owner before moving that conversation between terminal and browser.

Use `/model PROVIDER/MODEL` to pin a declared model. `/route status` shows routing
information; `/route auto` clears the manual pin so configured routes can apply.
Configure phase and difficulty mappings with `orbit route` outside the browser.
The effort control and `/effort VALUE` use the selected model's declared
capabilities; `/effort default` returns to its default. Unsupported values fail
without changing the current setting.

## Change appearance and panes

Open **Appearance and panes** to select `orbit`, `midnight` or `paper`, adjust
colors, spacing, symbols and reduced motion, choose a layout, or set a browser
font and size. Fonts are names already available to the browser; ORBIT does not
download them. Terminal font settings belong to the terminal application.

The same profile is available through `/theme NAME`, `/customize ...` and the
`orbit customize` commands. Settings also expose the layout tree, named panes and
explicit profile validation, import and export. Paths refer to the machine
running ORBIT. See [customization](customization.md) for the schema and examples.

A profile retains one Conversation pane and composer. Named panes can show inert
text, bounded workspace Markdown, or routing, usage, agent and engagement
snapshots. Refresh reads current permitted data. Declared actions can focus the
conversation, insert a draft, refresh, or cancel through the controlling owner.
Inserting a draft never submits it. File reads retain inherited allow/deny rules
and the owner's current permission mode.

Changes validate the whole profile and its revision before saving. A stale or
invalid edit produces an error and preserves the stored settings. Session changes
mark old pane snapshots stale; replies from an earlier session cannot restore
them. On narrow screens, the pane tabs select the active view. Repeated references
to the same named pane keep separate tab identities.

If stored customization is malformed, start a temporary recovery session:

```sh
orbit web --safe-customization
```

This uses read-only session defaults without rewriting the profile or legacy
`tui.toml`. Repair the original files explicitly before returning to normal mode.

## Connections and access

Loopback access needs no browser token by default. To require one, set
`ORBIT_WEB_TOKEN` or pass `--token`; open the page with that value in its
`?token=...` query. The automatic browser opener includes the configured token.
This is a **browser access token**. Provider credentials remain separate ENV
references in `providers.toml`; `ORBIT_GATE_TOKEN` is not the browser token.

An explicit non-loopback `--bind` requires a nonempty browser token. The bridge
serves HTTP; it does not configure TLS. Protected event, action and customization
requests check the token when configured, the Host and actual listening port,
and a matching Origin when present. Loopback listeners reject non-loopback Host
names. Use the listening address rather than an unrelated hostname or proxy URL.

One WebSocket connection holds controller authority at a time. Additional event
streams can observe the owner, but cannot submit prompts or approve tools.
Closing a tab releases its controller connection; it does not stop the shared
owner or replay a prompt. Closing the server ends that owner.

After a disconnect the page reconnects and asks the owner for recovery using an
instance/sequence cursor. ORBIT supplies retained events or a full snapshot when
the cursor is too old or belongs to another owner instance. Pending responses,
approvals, request state and usage come from that recovery. A submitted prompt is
not automatically resent; inspect the recovered state before submitting it again.

## Implementation and local validation

`orbit-web` serves the static JavaScript application from `crates/web/assets`.
`GET /events` projects ordered owner events over SSE; `/actions` accepts bounded,
typed WebSocket actions. Prompts carry request IDs for owner-side duplicate
handling. WebSocket acknowledgements report action acceptance; only the ordered
SSE recovery/event stream updates conversation state and its cursor. The browser
does not run a separate provider or tool loop.

`GET /customization` provides an authorized, display-safe profile and pane view.
Profile edits and pane actions require current controller authority. The server
checks revisions and displayed action declarations, and obtains pane context and
session identity together from the owner. Profiles and file content are scanned
before browser projection; rendering uses inert text and checked style values.

Local release checks include 26 production-script scenarios on a controlled DOM,
the original 18 browser-control scenarios, 13 customization backend scenarios and
19 existing owner/browser backend scenarios. These establish local fixture
behavior, including recovery, authority, drafts and settings. The actual HTTP
harness also passes 13 scenarios against a local fixture, covering streaming,
approval, tool events, persistence and resumed transcripts. Native browser
interaction and real-provider use
remain separate acceptance steps; these checks do not establish visual parity
with the terminal or another harness.

Current browser startup flags are `--home`, `--model`, `--provider`, `--effort`,
`--gate`, `--resume`, `--bind`, `--port`, `--token`, `--no-browser`,
`--permission-mode`, `--allowedTools`, `--disallowedTools`, `--auto-tools`,
`--bare` and `--safe-customization`. A supplied `--gate` must match the selected
configured provider URL; it cannot redirect a qualified model to another gateway.

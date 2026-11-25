# MCP tools, owned sessions and signed packages

ORBIT connects local programs and remote MCP servers through its shared tool
runtime. This guide covers Unix stdio, Streamable HTTP and legacy SSE MCP,
on-demand language-server diagnostics, a foreground session owner, and a durable
local signed-package catalog. Configure your provider first using [setup](setup.md).

## Configure MCP servers

Put user configuration in `$ORBIT_HOME/mcp.json` (default `~/.orbit/mcp.json`). A
trusted workspace can add `.orbit/mcp.json`; an entry with the same server name
replaces the user entry. Project MCP configuration is ignored until that folder
is trusted with `orbit folder trust`. Review a folder's configuration before
trusting it.

`orbit mcp` edits these files for you. It only changes configuration: no server
is started or contacted.

```console
$ orbit mcp add files --env ROOT=/srv -- npx -y @acme/files
$ orbit mcp add tracker --transport http --header 'Authorization: Bearer …' https://mcp.example.com/mcp
$ orbit mcp list
$ orbit mcp remove tracker
```

Everything after `--` is the server's own command line. `--scope project`
writes `.orbit/mcp.json` instead. `orbit mcp list` shows the names of a
server's environment variables and headers, never their values. It also hides
what a URL or a command line keeps secret: the values in a URL's query and its
user information (`https://host/mcp?key=<hidden>`), the word after a
credential flag (`--api-key <hidden>`, `--token=<hidden>`, `API_KEY=<hidden>`)
and the value of a credential header (`--header Authorization: <hidden>`). A
word of a command line longer than 100 characters is cut there. The file keeps
what it was given. In the terminal chat, `/mcp add`, `/mcp get`, `/mcp list`
and `/mcp remove` take the same arguments, split on spaces.

For an already installed browser MCP executable, a configuration has this shape:

```json
{
  "servers": {
    "browser": {
      "transport": "stdio",
      "command": "/path/to/existing/browser-mcp-server",
      "args": [],
      "enabled": true,
      "tools": ["browser_navigate", "browser_snapshot", "browser_click", "browser_close"],
      "timeout_ms": 30000,
      "initialize_timeout_ms": 5000
    }
  }
}
```

Replace the executable, argument vector and exact tool names with those supported
by your server. ORBIT does not install the executable. It launches enabled stdio
servers to initialize them and discover tools, then reuses their connections. This
launch may happen before a tool-call approval is shown. Stdio servers inherit the
launching environment; export required credential variables there. The optional
`env` map supplies literal process environment values. One exception: the
variables your model providers read their own credentials from (`env = "NAME"`
in `providers.toml`) are not inherited, so a server never sees the model
provider's key by accident. A server that needs one of them gets it through its
own `env` entry.

For a remote server, use its actual endpoint and select its transport:

```json
{
  "servers": {
    "docs": {
      "transport": "streamable-http",
      "url": "https://mcp.example/mcp",
      "enabled": true,
      "timeout_ms": 30000,
      "initialize_timeout_ms": 5000
    }
  }
}
```

Use `"transport": "sse"` for a legacy SSE endpoint. Remote entries accept optional
literal `headers`, including authentication headers when required by that server;
they reject stdio-only `command`, `args` and `env`. Stdio entries reject remote
URL/header fields. Remote URLs require HTTPS or loopback HTTP, without URL
userinfo or fragments, and redirects are disabled. A server that needs a browser
login is covered by [Sign in to a remote MCP server](#sign-in-to-a-remote-mcp-server).
Provider API-key storage is a separate feature and does not supply remote MCP
authentication.

`tools` contains the server's original tool names: omitting it exposes all of that
server's discovered tools, while `[]` exposes none. `"enabled": false` disables the
server. Agent tool selections can narrow exposure further; operator allowlists
also restrict which calls can execute.
The two timeout values are milliseconds, each between 1 and 600000. Initialization
has its own ceiling within the overall request budget. Restart the chat after
changing the server's advertised tool selection.

The model sees names such as `mcp__browser__browser_snapshot`. Server-wide policy
uses `mcp__browser__*`, matched against the configured server identity. It does not
match a neighboring server merely because its name shares a prefix. Ambiguous
server/tool identities are refused. MCP rules support exact tools and this one
server-wide selector; argument-specific grants and arbitrary name wildcards are
not supported. Transport selection does not bypass these tool-permission rules.

## Search large MCP tool sets

Every declared tool's schema is sent with each request. When the enabled
servers expose more than 40 tools, ORBIT declares two tools in their place:

- `McpToolSearch` finds tools by keyword, server name, or `select:<name>`, and
  returns each match's name, description and input schema.
- `McpToolCall` runs one of them by its full `mcp__<server>__<tool>` name.

A wrapped call is unwrapped before anything else happens, so the ledger,
hooks, permission rules and approval cards all see the real tool, exactly as
for a direct call. The declared tool list does not change during a session.

Set `ORBIT_TOOL_SEARCH` to change this: `off` always declares every tool, `on`
defers whenever there is at least one, and a number sets the threshold.

### Claude Code's MCP files

In a trusted project, servers from `.mcp.json` (`mcpServers`) are added to
ORBIT's own; an ORBIT entry of the same name wins, and an entry ORBIT cannot
use is left out. `${VAR}` and `${VAR:-default}` are expanded from the
environment. `orbit --mcp-config <file>` adds one more file in either format for
that run; every entry in it must be valid.

### See which servers are running

`/mcp` in the chat lists every configured server with what happened when it
was last asked for its tools: `running · 4 tools`, `starts when a prompt
needs it`, or `not available:` and the reason. A server that does not come
up is also named once in the conversation (on standard error in a headless
run) with how its process ended and the last thing it wrote to standard
error, for example `its process ended before answering (exit status: 2):
python3: can't open file ...`. Its tools are left out and the session goes
on. `orbit mcp list` shows the servers of a project's `.mcp.json` too, and
`orbit doctor` checks that each server's command exists (a command that is a
link, as `python3` and `npx` often are, counts).

A server's own `instructions`, given at its handshake, are part of the
system prompt under the server's name.

### What a server may print or send

Real servers are not tidy, and ORBIT reads them the way the official clients do.

- A line on a stdio server's standard output that is not JSON and does not
  begin with `{` (a dotenv banner, a log line, a usage text) is skipped. A line
  that begins with `{` and does not parse is a frame cut off in the middle, and
  ends the session as a broken server; so does JSON that is not an object.
- A reply with no `id` answers nothing ORBIT sent (a server that takes the
  `notifications/initialized` notification for a request answers it with an
  error like that) and is ignored. `"id": null` is how JSON-RPC says the server
  could not read a request, and stays an error.
- When a server never answers, or ends without a word on standard error, the
  last line it printed on standard output (control characters removed, 160
  characters at most) is named in the message: `its process ended before
  answering (exit status: 2); the last line on its standard output was:
  usage: …`.
- A server's reply may be up to 16 MiB: one stdio frame, an HTTP body, an SSE
  stream, and the sum of the pages of one `tools/list` (one real server's list
  of 229 tools is 3.5 MB). What ORBIT sends stays within 1 MiB, and the model
  is never shown more than 64 KiB of a result: the rest is cut and the result
  is marked `truncated`.
- The enabled servers are started together when ORBIT lists their tools, eight
  at a time, so the first prompt waits for the slowest server and not for all of
  them in turn (29 real servers took 22.5 s one after another). A server that
  does not come up costs only itself.

## Read MCP resources and run MCP prompts

`/mcp prompts` lists the prompts your enabled servers offer, and
`/mcp prompt <server> <name> [key=value …]` sends one as your prompt. Only the
text of a prompt is used.

When at least one MCP server is enabled, the model also has
`ListMcpResources {server}` and `ReadMcpResource {server, uri}`. They call the
server's `resources/list` and `resources/read`. For rules and approvals they are
the tools `mcp__<server>__resources_list` and `mcp__<server>__resources_read`, so
`mcp__<server>__*` covers them and a narrower rule can name either one. MCP
channels are not supported.

## Sign in to a remote MCP server

For a `streamable-http` or `sse` server that uses OAuth, run this in the terminal
chat:

```text
/mcp login <server>
/mcp login <server> <client-id>
/mcp logout <server>
```

`/mcp login` discovers the server's authorization server, registers ORBIT as a
public client when the server allows it, prints the consent URL and tries to open
it in your browser, then waits up to three minutes for the browser to return to a
loopback port. The wait runs beside the session, so you can keep working;
`/mcp login cancel` stops it, and the outcome arrives as a message. One sign-in
runs at a time. Pass a client ID as the second word for a server that does not
register clients itself.

The tokens are stored in `$ORBIT_HOME/mcp-oauth/` with owner-only permissions and
are never written to `mcp.json`, the ledger or the transcript. A token is sent
only to the exact URL it was issued for, is refreshed shortly before it expires,
and is not used when the server's configuration has its own `Authorization`
header. `/mcp` shows whether a sign-in is stored. `/mcp logout` deletes it locally;
it does not revoke the token at the server.

On Unix, the store must be an owned directory with mode `0700` and each token
an owned regular file with mode `0600`. Linked or exposed records are refused;
ORBIT does not silently repair their permissions. The ORBIT home must be owned
by the current user and not writable by other users. Private OAuth storage on
non-Unix platforms is not supported yet.

Sign-in uses the authorization-code flow with PKCE (S256) only. Every endpoint
must be HTTPS or loopback HTTP, and redirects are refused. Servers that need a
client secret, a device code, or a fixed redirect port are not supported.

Published resource metadata must identify the exact configured MCP URL and name
an authorization server. Missing or mismatched identities stop sign-in before
contacting that server; malformed metadata does not trigger the legacy fallback.
Authorization server metadata must also identify its issuer exactly. Tenant
issuers support both inserted and appended OpenID Connect discovery paths.
The older same-origin discovery fallback is used only when no resource metadata
is found. These checks follow [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html#section-3.3)
and the [MCP discovery sequence](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#authorization-server-metadata-discovery).

## Answer an MCP server's questions

A server may ask you for input while one of its tools runs (MCP elicitation).
ORBIT tells servers it supports this and answers in this order:

1. An `Elicitation` hook for that server, if one decides (see
   [hooks](#run-hooks)).
2. In the terminal chat, approval cards: the first shows the request (`y` to
   answer, `n` to decline), then one card per field. Answer a yes-or-no field
   with `y` or `n`; for a choice press `y` on the option you want; for text or
   a number press `n` and type the value as the card's note (`y` takes the
   default). Leaving a required field unanswered dismisses the whole request.
   A request for a page visit shows the URL; `y` confirms you are done.
3. Anywhere nobody can be asked (a headless prompt, a session reached through
   `orbit serve`), the request is dismissed unless a hook answered.

A form of more than 12 fields is declined. For a stdio server the time you
take is not charged to the tool call. Over the HTTP transports your answer must
arrive within the server's `timeout_ms`.

## Choose a permission mode

`/mode <name>`, `Shift+Tab` and `--permission-mode` select one of `default`,
`acceptEdits`, `plan`, `auto`, `dontAsk` and `bypass`.

In `auto`, rules still decide first: a deny rule denies, an allow rule allows,
and an `ask` rule always reaches you. Edits run as in `acceptEdits`. A call that
no rule covers goes to a classifier model, which sees the tool name, its
arguments, the working directory and your most recent messages, and answers one
of three ways:

- allow: the call runs and the ledger records that auto mode allowed it;
- block: the call is refused and the model is told the reason;
- ask: you get the usual approval card.

High-risk and destructive calls are never classified; they always ask. So does
anything the classifier fails to answer cleanly, or a call whose serialized
arguments exceed 4,000 characters: automatic permission requires the complete
call. After three blocks in a row the next call goes to you. Without a terminal
to ask, an "ask" is a denial.

The classifier runs on the `explore` role's model when `[roles]` sets one, and
otherwise on the session's model. Each classified call is one extra request.
The request never sees tool results or file contents, only what you typed.

## Auto mode and `/btw` accounting

In a session with managed accounting, the auto-mode classifier's requests and
`/btw` answers are billed to the session's housekeeping subtotal: they appear
in `/usage` and the session totals without being counted as ordinary
conversation cost. In a session without managed accounting they still run, but
their cost is not recorded anywhere.

## Schedule prompts

The model can schedule prompts for the project it is working in:

- `CronCreate {cron, prompt, durable?}`: a five-field cron expression in local
  time (`*/30 * * * *`, `0 9 * * 1-5`).
- `ScheduleWakeup {delay_seconds, prompt}`: once, between one minute and seven
  days from now.
- `CronList` and `CronDelete {id}`.

Jobs are stored in `$ORBIT_HOME/schedules.json`, so they survive a restart. A
job fires only while a terminal session is open and idle in the directory it
was created in; the session checks every ten seconds and sends a due prompt as
if you had queued it. Nothing runs while ORBIT is closed: a recurring run missed
by more than ten minutes is skipped, a missed one-shot fires when a session next
opens. A recurring job expires after seven days unless `durable` is set. There
are at most 32 jobs. Creating a job asks for approval in the default mode;
listing and deleting do not. A file lock makes sure a job fires in only one of
several sessions open in the same directory.

`TaskOutput {task_id}` returns the last lines of a background command started
with Bash `run_in_background`, and on Linux whether it is still running.

`Monitor {task_id, pattern?}` watches such a command and wakes the session with
its new output. `pattern` keeps only lines containing it (case-insensitive, `|`
between alternatives). Output is marked as data and scanned for secrets, and is
sent at most every 15 seconds, 40 lines and 50 times per monitor, four monitors
at once. While a turn is running tool calls, it reaches the model with the next
tool result, as a `background_events` field beside the result's own. Otherwise
it arrives as a prompt when a terminal session open in that directory is next
idle; a headless run or the plain chat has no such moment and drops it. The
monitor ends when the command ends (on Linux), after `TaskStop`, or after 30
minutes without output. Starting one asks for approval in the default mode.

## Run subagents in the background

`Task` accepts `run_in_background: true`. The call returns at once with the
agent's name, the agent keeps working, and `AgentOutput {agent}` reports its
status and, when it has finished, its report. At most four background agents run
at a time. A background agent cannot show an approval card: a call that would
ask is denied (or classified, in `auto` mode). `AgentStop {agent}` stops one at
its next cancellation point. Both calls also accept `agent_id` for the same
target. A call that names two different agents in `agent` and `agent_id` is
refused, so the permission rule that is checked is always the agent that is
acted on. In the terminal chat, `/tasks agents` lists the
agents this session has started, `/tasks show <agent>` prints one agent's own
conversation (what it was asked, what it said, which tools it called and what
came back, long texts cut), and `/tasks stop <agent>` stops a background one.

## Inspect and change tool permissions

Merge rules into `[permissions]` in `$ORBIT_HOME/settings.toml`, preserving your
existing settings and deny rules. For example:

```toml
[permissions]
ask = ["mcp__browser__*"]
```

In the ordinary TUI or plain chat, use:

```text
/permissions
/permissions mcp__browser__browser_navigate
/permissions mcp__browser__*
/permissions ask mcp__browser__*
/permissions allow mcp__browser__browser_snapshot
/permissions deny mcp__browser__browser_click
/permissions reset mcp__browser__browser_snapshot
```

The report shows the effective decision, its source and any same-selector rules
replaced by an operator override. Sources include user, project, project-local,
legacy and operator-override rules. Overrides are saved in
`$ORBIT_HOME/permission-overrides.toml`; reset removes that overlay for the named
selector and reveals the underlying rules again. Failed saves report an error.
These commands inspect policy; they are not an MCP tool catalog or a tool call.

In normal permission modes, matching Deny wins, then explicit Ask, then Allow.
An exact Allow does not erase a surviving server-wide Ask or an independent Deny.
An intentional override replaces underlying Ask/Allow for the same selector;
inspect the returned effective verdict before relying on it. A remembered grant,
legacy Allow or `--auto-tools` does not skip a surviving explicit Ask. A headless
run cannot answer that Ask and executes no such call. Plan mode refuses MCP calls
because the runtime cannot establish their effects from a server description.

`--permission-mode bypass` is a separate explicit mode: it skips the prompts
the mode itself would raise, so anything no rule speaks about runs. Your rules
still hold in it, as in Claude Code: a deny rule from any settings file denies,
and a rule that asks still asks (a headless run cannot answer and does not run
that call). The legacy `permissions.toml` deny barrier, operator scope
exclusions and tool exposure/profile restrictions apply as before. It is not
equivalent to `--auto-tools`.

Approval captures the configured tool and policy. If either changes before
dispatch, the call is refused and requires fresh confirmation. Tool results,
including structured MCP data, pass through output scanning; they remain untrusted
content rather than instructions.

The [browser MCP template](../examples/browser-mcp.toml) explains how to translate
its reference TOML into the actual JSON and permission files. The template itself
is not loaded by ORBIT. Browser origin/file flags configure that server and do not
replace ORBIT policy. The [browser harness guide](browser-harness.md) describes the
separate ORBIT web frontend. Using that frontend does not by itself configure or
validate a browser MCP server.

## Run hooks

A hook is a shell command ORBIT runs at a point in the session. Add hooks to
`settings.toml` in the ORBIT home; a trusted project may add its own in
`.orbit/settings.toml`.

```toml
[[hooks]]
event = "PreToolUse"
matcher = "Write|Edit"
command = "/path/to/check-edit"
timeout_secs = 30
```

ORBIT fires all 33 of Claude Code's events:

| Event | When | Can block |
|---|---|---|
| `Setup` | `orbit --init`, `--init-only` (run the hooks and stop) or `--maintenance`, before the session starts (matcher: `init`, `maintenance`) | No |
| `SessionStart`, `SessionEnd` | A session opens and closes: the terminal chat, the plain chat (`--no-tui`) and headless runs all fire them. What a `SessionStart` hook prints is context for the model in each (`source`: `startup` or `resume`) | No |
| `InstructionsLoaded` | Once per instruction or rule file at session start (`load_reason`: `session_start`) | No |
| `UserPromptSubmit` | Before a prompt is sent | Yes: the prompt is refused |
| `UserPromptExpansion` | A custom command file is about to become a prompt (matcher: the command name) | Yes |
| `PreToolUse` | Before a tool call: built-in tools and MCP tools (`mcp__server__tool`) alike, after the permission verdict. A hook may deny, ask, rewrite the input or add context; the context is attached to MCP results | Yes |
| `PermissionRequest` | You are about to be asked | No |
| `PermissionDenied` | A call was refused, by a rule, the mode, auto mode or you | No |
| `PostToolUse`, `PostToolUseFailure` | Built-in registry and MCP tools fire `PostToolUse` on success with `tool_response`, or `PostToolUseFailure` on failure with `error`. Both events carry the effective `tool_input`. Denied and cancelled calls skip these events. Hook context goes to the model with the result, along with any complaint from a success hook | No |
| `PostToolBatch` | All of a round's tool calls have returned | Yes: the turn ends |
| `TaskCreated`, `TaskCompleted` | `TaskCreate`, or `TaskUpdate` marking a task done | Yes |
| `Stop` | The model finished its reply | Yes: it keeps working |
| `StopFailure` | The turn failed, or its output was filtered, incomplete or truncated | No |
| `SubagentStart` | A subagent starts (matcher: its type) | No |
| `SubagentStop` | A subagent finished its reply (matcher: its type) | Yes: it keeps working |
| `TeammateIdle` | A background agent finished its turn and is about to wait | Yes: it keeps working |
| `PreCompact` | Before compaction (matcher: `manual`, `auto`) | Yes: nothing is summarised |
| `PostCompact` | After compaction | No |
| `CwdChanged` | `/cd` or a worktree tool moved the working directory (`old_cwd`, `new_cwd`) | No |
| `WorktreeCreate` | `EnterWorktree` is about to make a worktree | Yes, and it can supply the directory |
| `WorktreeRemove` | `ExitWorktree` is about to remove one | Yes: the worktree is kept |
| `Elicitation` | An MCP server asks you for input (matcher: the server) | Yes, and it can answer |
| `ElicitationResult` | Your answer, before the server gets it (matcher: the server) | Yes, and it can replace it |
| `PreModelSwitch`, `PostModelSwitch` | `/model` (matcher: the target model) | Pre: yes |
| `DirectoryAdded` | `/add-dir` (matcher: `slash_command`) | No |
| `MessageDisplay` | The reply for a turn is complete (`message`) | No |
| `ConfigChange` | `/mods refresh` or `/output-style` reloaded a setting (matcher: `mods`, `output_style`) | No |
| `FileChanged` | A watched file was created, modified or deleted since the previous prompt | No |
| `Notification` | ORBIT raises a notice, such as truncated output | No |

A `FileChanged` hook's matcher names the files to watch, literally and relative
to the working directory (`.env|.envrc`). They are compared by modification
time when you send a prompt, not continuously.

A blocked `Stop`, `SubagentStop` or `TeammateIdle` sends the hook's reason
back to the model, which keeps working, at most three times a turn unless you
raise that (`stop_hook_max_continuations`, below). A blocked
automatic `PreCompact` skips the summary while the request still fits the
model's window; once it no longer fits, the turn stops with the hook's reason.
ORBIT has no agent teams: `TeammateIdle` fires for a background agent started
with `Task` and `run_in_background`.

A `WorktreeCreate` hook replaces `git worktree add`: it prints the absolute
path of the directory it made (or `hookSpecificOutput.worktreePath` in JSON),
and any failing hook fails `EnterWorktree`. An `Elicitation` or
`ElicitationResult` hook answers with
`{"hookSpecificOutput": {"action": "accept", "content": {…}}}`, or `decline`
or `cancel` as the action.

The hook receives one JSON object on standard input with `hook_event_name`,
`cwd`, and the event's own fields. Tool events carry `tool` and `arguments`,
and the same values as `tool_name` and `tool_input`. Exit code 2 blocks the
action and gives the hook's standard error to the model. The default timeout
is 60 seconds.

Hooks run with `CLAUDE_PROJECT_DIR` set to the working directory (unless it is
already set), and with `CLAUDE_SESSION_ID`, `CLAUDE_CODE_SESSION_ID` and
`ORBIT_SESSION_ID` set to the session's id, the same as the payload's
`session_id`. The id replaces any value ORBIT inherited from the shell that
started it. `CLAUDE_ENV_FILE` is not supported.

`matcher` limits a hook to some tools (for the other events, to the subject in
the table above). Write names separated by `|` or `,`, with `*` (or `.*`) as a
wildcard: `Write|Edit`, `mcp__github__*`. Each name is compared whole.

A matcher may also be a regular expression, as in Claude Code. One that
contains any of `^ $ ( ) [ ] { } + ? \` is also searched as one, anywhere in the
name and case-sensitively, so write `^…$` to pin it: `mcp__.*(exa|tavily)`
matches `mcp__tavily__search`, and `^(startup|resume)$` matches those two
session sources and nothing longer. Claude Code hooks registered with such
matchers (`WebSearch|WebFetch|mcp__.*(exa|tavily)`) run unchanged. The language
is Rust's `regex`, which has no look-around and no back-references. A name list
never turns into a regular expression by accident: `Bash` still means exactly
`Bash`, and a name that happens to contain one of those characters (`[id].tsx`)
still matches itself.

A pattern that is not a valid regular expression is not silent. ORBIT names it
among the hook trouble when the hooks load (once for each hook, with the reason
and the hook's command), `orbit doctor` reports it as invalid, and `/hooks`
flags it. Until you fix it only the plain names in it can match, so a hook that
depends on the pattern does not run. Without a matcher the hook runs for every
tool.

Standard output may be JSON, in ORBIT's form or Claude Code's:

```json
{"type": "deny", "reason": "no force pushes"}
{"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": "no force pushes"}}
{"hookSpecificOutput": {"permissionDecision": "allow", "updatedInput": {"command": "ls -la"}}}
{"decision": "block", "reason": "tests fail"}
```

- A deny or block stops the action; for `UserPromptSubmit` it refuses the prompt.
  A deny that gives no reason takes the hook's `systemMessage` as its reason, which
  is where hookify's rules explain a block, so what you and the model are told is
  that text. A `systemMessage` on a hook that does not deny is not shown.
- `updatedInput` (or ORBIT's `{"type": "rewrite", "input": …}`) on `PreToolUse`
  replaces the tool input. Permission rules are evaluated on the rewritten
  input; the transcript keeps the model's original call.
- For `SessionStart` and `UserPromptSubmit`, `additionalContext`, or plain text
  printed by a hook that exits 0, is given to the model as context (up to
  8 KiB in all, unless `hook_context_max_bytes` says otherwise, below).
- An `ask` decision on `PreToolUse` opens the approval card, unless you already
  approved that same call. Where nothing can ask (headless runs, background
  agents) it is a denial.
- A `Stop` hook that blocks (exit 2 or a deny) sends its reason back to the
  model, which keeps working. This happens at most three times a turn unless
  `stop_hook_max_continuations` says otherwise, and the payload's
  `stop_hook_active` is true once it has happened.

A turn cannot be held forever: a stop hook may send the model back to work 3
times a turn, and no more. A guard that needs longer raises that with a
top-level key in `$ORBIT_HOME/settings.toml` (above any `[table]`), or in a
`--settings` TOML file, which wins for that run:

```toml
stop_hook_max_continuations = 150
```

It takes a whole number from 0 to 1000; `0` means a block is never obeyed. Each
continuation also uses one of the turn's rounds, so a limit of 150 needs a round
limit above it. A turn has 100 rounds in the terminal chat, which has no setting
for that; `--max-turns` sets it for a headless run. Only your
own settings count: a project's `.orbit/settings.toml` cannot raise it. When the
limit, or the round limit, ends a turn while a hook still blocks, ORBIT says so
(in the transcript in the terminal chat, on standard error at the end of a
headless run). A value it cannot use keeps the default and is reported the same
way, and so is the key written under a `[table]`, where it is not read.

Two more keys narrow or detach a hook:

```toml
[[hooks]]
event = "PostToolUse"
command = "/path/to/log-pushes"
if = "Bash(git push *)"
async = true
```

A hook can be an HTTP endpoint instead of a command. The payload is POSTed as
JSON and the response body is read the way a command's standard output is:

```toml
[[hooks]]
event = "PreToolUse"
matcher = "Bash"
url = "https://hooks.example.com/pre-tool"
header = "X-Team: core"
timeout_secs = 10
```

The URL must be HTTPS, or HTTP on localhost. The request is made with `curl`,
which must be installed; redirects are not followed. An HTTP hook blocks only
through a decision in a successful response: a failed request or an error
status is reported and never blocks. In a Claude Code `settings.json`,
`type: "http"` handlers are read with their `headers`, and `$NAME` in a header
value is filled only for names listed in `allowedEnvVars`.

A hook can also ask a model, ask a read-only agent, or call an MCP tool:

```toml
[[hooks]]
event = "Stop"
prompt = "Were the tests run after the last code change? $ARGUMENTS"
model = "anthropic/claude-haiku-4-5"

[[hooks]]
event = "Stop"
agent = "Read the test output under target/ and confirm nothing failed."

[[hooks]]
event = "PostToolUse"
matcher = "Write|Edit"
mcp_server = "scanner"
mcp_tool = "scan"
mcp_input = '{"file_path": "${tool_input.file_path}"}'
```

- `prompt` sends one request with no tools. `$ARGUMENTS` is replaced by the
  event's JSON, which is appended when the prompt does not name it. The model
  answers `{"ok": true}` or `{"ok": false, "reason": "…"}`; not-ok blocks the
  way exit code 2 does. Default timeout 30 seconds.
- `agent` asks the same question of a model that may first call `Read`,
  `Grep` and `Glob`, inside the session's working directories only, for up to
  12 rounds. Default timeout 60 seconds.
- `mcp_server` / `mcp_tool` call one tool on a configured, enabled server.
  `${path}` in `mcp_input` is filled from the event's JSON. The tool's text is
  read the way a command's standard output is; a tool error blocks nothing.
  The hook never starts a sign-in.

`model` is optional: without it the check runs on the `explore` role's model,
else the session's. These requests are billed to the session's housekeeping
subtotal, and hooks are switched off while one runs, so a `Stop` hook that
asks a model does not fire for its own request. A check that fails to run (no
provider, an unreadable answer, a timeout) is reported and blocks nothing.

`if` takes `Tool(pattern)` (or a bare tool name; several separated by `|`) and
is matched against the tool and its main argument: a Bash command, a file path
or a URL. `async = true` starts the hook without waiting, so it can neither
block nor add context. When a session ends, ORBIT waits up to 5 seconds for async
hooks that are still running, so a hook started just before the end still receives
its payload; one that runs longer is left to finish on its own, and a line on
standard error says how many were still running. Every payload carries `session_id`,
`transcript_path` and `permission_mode`, in the chat and in headless runs
alike. `UserPromptSubmit` fires for a prompt you submit, not for the task a
subagent is given. A hook that runs past its `timeout_secs` is stopped and
blocks nothing; the chat says so in a line, and a headless run on standard
error.


### Give hooks more room

What hooks add to the model's context at one event (a `SessionStart` or
`UserPromptSubmit` hook, a `SubagentStart` hook, a tool hook's feedback) is
bounded: 8 KiB for all the hooks of that event together, the first hook first.
A set of hooks that prints more loses the later ones. Hooks that print as much as
yours may need a larger bound, which is a top-level key in your own settings
(above any `[table]`, in `$ORBIT_HOME/settings.toml` or a `--settings` TOML
file, which wins for that run):

```toml
hook_context_max_bytes = 65536
```

It takes a whole number of bytes from 0 to 262144 (256 KiB); `0` means hooks add
no context. Only your own settings count: a project's `.orbit/settings.toml`
cannot raise it, because the text is not yours. What does not fit is cut at a
character boundary and the context ends in a line that says so
(`… (hook context cut at 8192 bytes)`), so the model knows it has part of it.
You are told once per run, with each hook's size in the order the hooks ran,
which is the order `/hooks` lists them, so the hooks that were cut can be
recognised. A value that cannot be used keeps the default and is reported with
the rest of the hook trouble.

### Run the hooks of an imported plugin

An imported plugin's command hooks never run on their own: they come in a
package, not from you. To run them, name the plugin in your own settings,
above any `[table]`:

```toml
plugin_hooks = ["hookify", "semgrep@8f3a1c9d"]
```

A plugin's hook is a program that runs with your privileges, outside the Bash
sandbox, each time its event fires, so name only plugins whose code you trust, and
pin the digest of the copy you looked at. Importing one runs nothing.

A name matches an imported, enabled, user-scope plugin (`orbit plugin list`).
An `@` and the first 8 or more hex digits of its digest pin the stored copy you
looked at, so an upgrade cannot slip in under the same name. Only your own
settings count (`$ORBIT_HOME/settings.toml`, then a `--settings` TOML file,
which adds to it): a project's `.orbit/settings.toml` cannot switch a plugin's
hooks on, a plugin imported for one project never contributes any, and `--bare`
runs none.

The hook runs from the stored copy. `CLAUDE_PLUGIN_ROOT` is that folder and
`CLAUDE_PLUGIN_DATA` is a private state folder for the plugin (made when one of
its hooks first runs, never by looking at it), next to what every hook gets.
`${CLAUDE_PLUGIN_ROOT}` and `${CLAUDE_PLUGIN_DATA}` written in a command are
replaced by those paths, as Claude Code does. `matcher`, `timeout`, `if` and
`async` are kept.

Some hooks are left out, each named with its reason and never run in some other
form: `asyncRewake` (it wakes the model when a background hook finishes, and
ORBIT has nothing that does that), a handler written for a shell other than
bash, `once` on an event other than `SessionStart`, `SessionEnd` and `Setup`,
and an event ORBIT does not have. A plugin you named that is not imported, not
enabled, damaged or not the pinned copy runs nothing and is reported once per
run. `orbit doctor` has a `plugins.hooks` check that lists, for each named
plugin, the events that run and what was left out (never a command), and
`/hooks` marks each of these hooks `(plugin NAME)`.

A plugin's hooks are checked against the stored copy's digest when they are
first resolved in a run, and again whenever the store changes (an import, upgrade,
enable, disable or remove), not before every call.

#### A damaged stored copy

A hook must not write inside `CLAUDE_PLUGIN_ROOT`: that folder is the verified
copy, and what a hook keeps belongs in `CLAUDE_PLUGIN_DATA`. ORBIT points Python's
bytecode cache (`PYTHONPYCACHEPREFIX`) at a folder in that data folder, so a Python
hook that imports a file beside it does not change its copy. Anything else that
changes a file in the copy makes it fail its check (`store_file_unsafe` or
`store_package_tampered`), the plugin's hooks stop running, and ORBIT says so once
per run. `orbit plugin remove NAME` does not clear that, because the package
folder is kept and an identical import is refused. To restore the plugin, remove it,
delete its folder under `$ORBIT_HOME/plugins/portable/packages/NAME/` (the folder
and its files are read-only; `chmod -R u+rwx` first), and import it again.

### Use your Claude Code configuration

Put `claude_compat = true` at the top of `$ORBIT_HOME/settings.toml` (before any
`[table]`), or set `ORBIT_CLAUDE_COMPAT=1`, to also read your own Claude Code
files:

- hooks from `~/.claude/settings.json`, and from `.claude/settings.json` and
  `.claude/settings.local.json` in a trusted project;
- skills from `~/.claude/skills/`;
- commands from `~/.claude/commands/`;
- your user memory file, `~/.claude/CLAUDE.md`, as an instruction file (see
  [Write project instructions](#write-project-instructions)).

`$CLAUDE_CONFIG_DIR` replaces `~/.claude` when set. `command`, `http`,
`prompt`, `agent` and `mcp_tool` handlers are taken, with their `if` and
`async` settings, and the `statusLine` command is used when ORBIT's own
`status_line` is not set. Hooks get `CLAUDE_PROJECT_DIR` set to the working directory, and the session's
id as `CLAUDE_SESSION_ID` and `CLAUDE_CODE_SESSION_ID`. The
`transcript_path` they receive is ORBIT's session file, which is not in Claude
Code's transcript format. This is off by default because those files were
written for another program.

Permission rules in a Claude Code `settings.json` are not applied on their
own. `orbit config import-claude` lists the rules in `~/.claude/settings.json`
and in this project's `.claude/settings.json` and `.claude/settings.local.json`,
with the ORBIT rule each becomes; `--apply` adds those to your own
`settings.toml` (the project's go to `.orbit/settings.local.toml`). `Bash`
rules, whole-tool rules with equivalent coverage and MCP rules carry over
(`Bash(npm test:*)` becomes `Bash(npm test *)`, `mcp__github` becomes
`mcp__github__*`). Bare `Read`/`Edit` rules and their path patterns are listed
as not carried over, because the programs group file tools and interpret paths
differently. Migrate those policies by hand. If any ask or deny rule cannot be
carried over, `--apply` refuses the whole batch before writing any settings;
the preview remains available.

Project-level Claude Code files need no switch, only folder trust where noted:
`CLAUDE.md`, `.claude/CLAUDE.md` and `CLAUDE.local.md` are read as instructions,
and `.claude/rules/`, `.claude/skills/` and `.claude/commands/` work as their
`.orbit/` counterparts do.

### Add settings for one run

`orbit --settings FILE` reads one more settings file for that run, after your
own `settings.toml`. A TOML file may hold `[[hooks]]`, `[permissions]` rules,
`output_style` and `status_line`. A Claude Code `settings.json` contributes its
hooks and its `statusLine` command, without the compatibility switch, because
you named the file yourself.

### Show your own status line

```toml
status_line = "~/.config/orbit/statusline.sh"
```

Put this at the top of `settings.toml`, before any `[table]`. The command gets
one JSON object on standard input (`model`, `workspace.current_dir`,
`workspace.project_dir`, `cost.total_cost_usd`, `permission_mode`, `turns`,
`tokens`, `session_id`), and the first line it prints is shown in the bottom bar
beside the activity. It runs after each command the session handles and is
stopped after 3 seconds. Colour escapes are removed: the bar draws plain text.

## Write project instructions

ORBIT reads, in this order: `/etc/orbit/ORBIT.md`, your Claude Code user file
`~/.claude/CLAUDE.md` (only with `claude_compat`; `$CLAUDE_CONFIG_DIR/CLAUDE.md`
when that is set), `$ORBIT_HOME/ORBIT.md`, then in the working directory
`ORBIT.md`, `.orbit/ORBIT.md`, `.orbit/ORBIT.local.md`, `AGENTS.md`, `CLAUDE.md`,
`.claude/CLAUDE.md` and `CLAUDE.local.md`. A later file has the last word, so
`ORBIT.md` in your home can correct what `~/.claude/CLAUDE.md` says. Only regular
files are read (a named pipe or a folder with one of these names is skipped), at
most 1 MiB of each, and a file that two names reach, through a link or because
`AGENTS.md` points at `CLAUDE.md`, is read once.

A link may not lead just anywhere. A file in the working directory arrives with
the repository, and the prompt goes to the provider, so a link in one must stay
inside the working directory (a link from a sub-folder up to the repository root
does not); and no instruction file, yours included, may lead to what the
deny-read list names (`~/.ssh`, `.env`, `*.pem`, `id_rsa*` and the rest). A file
that does is refused before any of it is read. ORBIT names it once per run
(`/work/repo/CLAUDE.md is not read: its real path /home/you/.ssh/id_ed25519 is on
the deny-read list`), `/memory` lists it with the reason, and `orbit doctor`
counts it apart from the files read. Your own files, `ORBIT.md` in your home and
the Claude Code user file, may be links to anything else (a dotfiles repository,
say), and `AGENTS.md` pointing at `CLAUDE.md` inside one project is unchanged.
Imported files already followed the same rule.

Each file is capped at 200 lines or 25 KB, and a cut is never silent. The text
the model reads ends in `… (truncated at 200 lines)` or `… (truncated at 25 KB)`;
ORBIT names the file once per run (`/home/you/.claude/CLAUDE.md is cut: ORBIT
reads the first 200 of its 231 lines`); `/memory` marks it; and `orbit doctor` has
an `instructions` check that counts the files read and names each one the cap
cuts, without showing any of their text. Imported files and rules are held to the
same cap and named the same way.

Without `claude_compat`, link the file instead:
`ln -s ~/.claude/CLAUDE.md ~/.orbit/ORBIT.md`. `/memory add` and `/memory remove`
refuse a linked file rather than follow the link; edit the file it points to.
`orbit migrate --from claude` lists the user file as a source, and says what reads it.

A file can import another with `@path`, relative to itself (or `~/…`), up to five
levels deep and 24 files in all. An import is honoured only when the target is a
regular file inside the working directory or the importing file's own folder,
and is not on the deny-read list; anything else stays as text. `@` inside code
spans and fenced blocks is ignored.

Files in `.orbit/rules/*.md` and `.claude/rules/*.md` are added too. A rule whose
front matter has `paths:` is listed in the prompt with its patterns, and its
text is added to the result of the first `Read`, `Edit` or `Write` of a matching
file, once per session. Patterns are relative to the working directory; `**`
spans directories, `{a,b}` is expanded, and a pattern with no `/` matches at any
depth.

## Add your own slash commands

`/name args` that is not a built-in command or a skill runs `name.md` from, in
order: `.orbit/commands/` and `.claude/commands/` in a trusted project,
`$ORBIT_HOME/commands/`, and `~/.claude/commands/` when `claude_compat` is on.
`/a:b` is `a/b.md`. The file's body is sent as your prompt, without its front
matter. `$ARGUMENTS` becomes the argument text and `$1`–`$9` its words; if the
body uses neither, the arguments are appended. `@file` in the text is expanded
the way it is in a typed prompt, through the Read tool. Custom commands also
work in the plain chat (`orbit chat` without the terminal interface).

`model:` in the front matter (`model: provider/model`, or a model's id alone)
runs the turn the command starts on that model; the chat says "this command
runs on …", and your next prompt is back on the session's model. `inherit`,
or no `model:`, changes nothing. A model that no configured provider declares
is not used: the chat says so and the command runs on the session's model.
`argument-hint:` is shown before the description in the `/` list and the
command palette.

`` !`command` `` in the body runs the command before the prompt is sent and
puts its output in that place:

```markdown
---
allowed-tools: Bash(git status:*), Bash(git log:*)
---
Status: !`git status --short`
Last commits: !`git log --oneline -n $1`
Write the release note for these.
```

A command runs only when all of this holds; otherwise the text is sent as
written with a note saying why:

- the file's `allowed-tools` names `Bash`, or a `Bash(pattern)` that matches
  the command after your arguments were put in. `Bash(git status:*)` and
  `Bash(git status *)` mean the same. A pattern speaks for one command: a line
  with `;`, `&&` or a pipe needs a pattern that spells out the whole line;
- none of your permission rules denies it or asks about it, and no `PreToolUse`
  hook blocks it (the hook sees `"source": "command-file"`);
- the shell sandbox is available, and the command runs inside it;
- the session is not in plan mode and `Bash` is not excluded with
  `--disallowedTools` or left out of `--allowedTools`.

At most 8 commands run per use, each for at most 20 seconds, and each output
is cut at 8,192 characters and scanned for secrets. A command that arrives
inside your arguments is never run.

The file's `allowed-tools` also cover the turn the command starts: a call it
names (`Edit`, `Bash(cargo test:*)`, `mcp__server__tool`) is not put to you
while that turn is running. Deny rules, rules that ask,
plan mode and an explicit `--allowedTools` scope still decide first; a
subagent the turn starts does not inherit it; it ends with your next prompt.

`/name` also runs a skill, and `/plugin:skill` a skill from an installed
plugin, in the terminal and in the plain chat. The `/` list and the command
palette offer your command files and skills after the built-in commands.

When no file of that name exists, `/init`, `/review` (or `/code-review`) and
`/security-review` run built-in prompts.

`/mods`, `/mods refresh`, `/mod <name>` and a mod's `/name:command` also work in
the terminal chat. Other chat commands added for people coming from Claude Code:

| Command | What it does |
|---|---|
| `/copy` | Copies the last reply to the clipboard |
| `/export [file]` | Writes the conversation, as the pane shows it, to a new Markdown file |
| `/context` | The context-window breakdown |
| `/memory` | Lists the instruction and rule files in use |
| `/memory add [--user\|--local] <text>` | Appends one line to `ORBIT.md` in the project (`--user`: `$ORBIT_HOME/ORBIT.md`; `--local`: `.orbit/ORBIT.local.md`). It is read from the next prompt |
| `/memory remove [--user\|--local] <text>` | Removes the lines that say exactly that |
| `/memory edit [--user\|--local]` | Opens that file in `$VISUAL` or `$EDITOR`, creating it when it is not there, then says what was saved |
| `/config` | Shows the model, effort, permission mode and home |
| `/config set <key> <value>`, `/config unset <key>` | Changes `claude_compat`, `output_style` or `status_line` in `settings.toml`, leaving the rest of the file as it is |
| `/config edit` | Opens `settings.toml` in `$VISUAL` or `$EDITOR`, then says whether it still reads as TOML. A file that does not is left as you saved it and its settings are not applied |
| `/rename [name]` | Names this session (shown in `/sessions`); no name clears it |
| `/add-dir [path]` | Adds a working directory for this session, which sandboxed commands may write to |
| `/btw <question>` | Answers a side question from the conversation without adding to it |
| `/find <text>` | Lists where the text occurs in this conversation |
| `/find next`, `/find prev` | Moves the conversation to a match of the last search: the newest first, then older; `prev` goes back. What was searched is shown in reverse video until the view returns to the newest rows (a match broken across two rows by wrapping is not marked) |
| `/fork` | Continues this chat in a copy of the conversation; the original stays as it was and `/resume <id>` returns to it |
| `/goal <condition>` | Keeps working until the condition is met. After each round a second model (the `explore` role, else the session's) judges the last reply; without one, a reply starting `GOAL MET` ends it |
| `/tasks` | Background commands, background agents, monitors and scheduled prompts |

`/memory add | remove | edit` and `/config set | unset | edit` also work in the
plain chat (`--no-tui`). There an editor is started only when the chat is at a
terminal; with piped input the chat names the file instead.

`/btw` works only between turns and runs no tools. In a session with managed
accounting its tokens are billed to the session's housekeeping subtotal; see
[Auto mode and `/btw` accounting](#auto-mode-and-btw-accounting).

`orbit --append-system-prompt <text>` (or `--append-system-prompt-file <path>`)
adds instructions for one run. An output style is selected with
`--output-style <name>` or a top-level `output_style = "name"` in
`settings.toml`: `explanatory` and `learning` are built in, and any other name
is a Markdown file in `.orbit/output-styles/`, `.claude/output-styles/` or
`$ORBIT_HOME/output-styles/`. In the terminal chat, `/output-style <name>`
changes it for the following turns.

`orbit --add-dir <path>` (repeatable) adds working directories for the run, as
`/add-dir` does in the chat. More chat commands: `/status`, `/sandbox`, `/plan`
(the same as `/mode plan`), `/vim` (toggles vim editing), `/keybindings`
(`reload` rereads the file) and `/recap`.

## Move the working directory

A session stays bound to the folder it was opened in: its files, its lease and
its project settings do not move. What can move is where its tools run.

- `/cd <path>` in the terminal chat moves the working directory to a directory
  inside the session's working directories (`/add-dir` adds one). Bash starts
  there and relative paths resolve there; `/cd` alone shows where you are.
- `EnterWorktree` and `ExitWorktree` are tools the model can call, offered
  inside a git repository. `EnterWorktree` creates `.orbit/worktrees/<name>`
  on branch `orbit/<name>` (the same place `orbit --worktree` uses) and moves
  into it. `ExitWorktree` returns; with `"remove"` it deletes the worktree and
  its branch, and refuses while there are uncommitted changes unless
  `discard_changes` is true. An unmerged branch is kept.

Both tools ask for approval by default and are refused in plan mode.

Your project's permission rules, MCP servers and folder trust are still those
of the folder the session was opened in, wherever its tools run. A worktree
that git made is entered only if it resolves inside the project; a
`WorktreeCreate` hook of yours may put one elsewhere, and the sandbox then
allows writes there while the session is in it. Worktree names the model
chooses are letters, digits, `-`, `_` and `.`.

## Use a fallback model

```console
$ orbit -p "summarise the open issues" --fallback-model anthropic/claude-haiku-4-5
$ orbit --fallback-model anthropic/claude-haiku-4-5        # the terminal chat
```

When the selected model cannot be reached after its retries (rate limit,
capacity, timeout or transport failure) and has produced nothing, the prompt
runs once more on the fallback model. That run is a session of its own: the
failed request stays on the first session until you inspect it
(`orbit recovery status`), and ORBIT bills nothing more to a session in that
state. A conversation you were resuming continues as a fork. Any other failure
is reported as it is.

In the terminal chat the same failure is handled without leaving the chat: the
conversation is copied into a fork without the unanswered prompt, the chat
switches to the fork and to the fallback model, and the prompt is asked again.
This happens once per chat; the status line says so, and the fallback stays
selected until you change it with `/model`.

The plain chat (`--no-tui`) does the same by handing over to a new plain chat
on the fork: it prints which model is unavailable and the fork's id, the new
chat asks the prompt again (`(asking again) …`) and then reads on from the
same input. The first chat's summary line is printed before the second
starts. On Unix the second chat takes the first one's place as the same
process, so MCP servers the first chat started end and are started again.

## Let an MCP server push messages into the session

```console
$ orbit --channels alerts,chat
```

names configured **stdio** MCP servers as channels for this run, in Claude
Code's form: when such a server sends `notifications/claude/channel` with
`content` and optional `meta`, the session receives

```text
<channel source="alerts" severity="high">
build failed on main
</channel>
```

Only letters, digits and `_` are kept in `meta` keys. The message reaches a
running turn with its next tool result; otherwise it arrives as a prompt when
the terminal session is idle (a headless run drops it). A server is a channel
only because you named it: the same notification from any other server is
ignored. Who may send through a channel is for the server to decide, and your
permission rules still decide every tool call a message leads to. What the
server says about itself at its handshake (`instructions`) is added to the
system prompt of the terminal chat under the server's name.

### Let a channel answer approval prompts

```console
$ orbit --channels chat --channel-permissions chat
```

also lets the channel `chat` allow or deny the approval prompts of this run,
in Claude Code's `claude/channel/permission` form. Claude Code relays to every
channel that declares the capability; ORBIT asks for the second flag as well,
because whoever can write to that channel can then approve tool calls. Only
name a channel whose server checks who is sending.

All of this must hold: the server is named in both flags, it declared
`experimental["claude/channel/permission"]` at its handshake (as an object;
`false` does not count), and the run asks for approvals (the terminal chat, or
the plain chat at a terminal; a headless run asks for none). The session's start says, per channel, whether it will be asked.

When a prompt opens, each such channel is sent
`notifications/claude/channel/permission_request`:

| Field | What it holds |
|---|---|
| `request_id` | Five letters of `a`–`z` without `l` |
| `tool_name` | The tool, for example `Bash` |
| `description` | The one-line summary the prompt shows |
| `input_preview` | The call's arguments as JSON text, one string per top-level field |

Secrets ORBIT recognises are redacted, direction-override and invisible
characters are removed, whitespace is folded, and a text longer than 3,500
characters is sent as its start and its end around `⋯ N code points elided ⋯`.

The prompt stays open where you are. The first answer wins: a
`notifications/claude/channel/permission` with that `request_id` and
`behavior` `allow` or `deny`, from a channel that was asked, while the prompt
is open, answers that one call like `y` or `n`. Anything else (another id, a
server that was not asked, an answer after you answered) is dropped. The
conversation says `allowed from the channel chat`, the tool card of a refusal
says `denied by the channel chat`, and the ledger's verdict reads `approved
through the channel chat (--channel-permissions)`. A verdict never grants a
rule or a later call, and a call that a deny rule, plan mode or a hook
refused is never put to a channel. A confirmation that a `PreToolUse` hook
asks for, a server's question, folder trust and the MCP sign-in prompt are
not relayed: those are answered at the terminal.

## Export usage with OpenTelemetry

Off by default. To turn it on:

```console
$ export ORBIT_ENABLE_TELEMETRY=1
$ export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
$ export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer …"     # optional
```

After each turn ORBIT posts to `<endpoint>/v1/metrics` and
`<endpoint>/v1/logs` (or to `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` /
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`), in the form `OTEL_EXPORTER_OTLP_PROTOCOL`
names:

| `OTEL_EXPORTER_OTLP_PROTOCOL` | What is sent |
|---|---|
| unset, `http/json` | OTLP/HTTP with a JSON body |
| `http/protobuf` | OTLP/HTTP with a protobuf body (`application/x-protobuf`) |
| `grpc` | OTLP/gRPC over HTTP/2 to the collector's address (`http://host:4317`); the service path is added, also to a signal's own endpoint. `http://` is spoken as HTTP/2 without TLS, `https://` with it. The collector's status is not read |

Any other value exports nothing. `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` and
`OTEL_EXPORTER_OTLP_LOGS_PROTOCOL` choose the form for one signal; a value
that is not one of the three stops that signal only. The same records go out
in every form:

| Signal | Name | Attributes |
|---|---|---|
| Counter | `orbit.session.count` | `session.id` |
| Counter | `orbit.token.usage` | `type` (`input`, `output`, `cacheRead`, `cacheCreation`), `model`, `session.id` |
| Counter | `orbit.cost.usage` (USD) | `model`, `session.id` |
| Event | `orbit.api_request` | one per turn: `model`, `provider`, token counts, `cost_usd`, `rounds`, `success` |
| Event | `orbit.tool_result` | `tool_name`, `success`, `duration_ms` |

Spans are a separate choice, made with the standard variable:

```console
$ export OTEL_TRACES_EXPORTER=otlp
```

Each turn is then one trace: a root span `orbit.turn` (model, provider, token
counts, cost, rounds, whether it succeeded) with a child span `orbit.tool` for
every tool call (the tool's name, whether it succeeded, how long it took).
They go to `<endpoint>/v1/traces`, or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, in
the form `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` or the general variable names.
A headless run that takes a second turn to repair its output reports that
turn as a span of its own with no duration.

Prompts, replies, tool arguments, tool results and file paths are never sent.
With `claude_compat` on, `CLAUDE_CODE_ENABLE_TELEMETRY=1` turns it on as well; the
names stay `orbit.*`. Exports use `curl`, take at most five seconds each and
are dropped when they fail.

## Install plugins from a marketplace

A marketplace is a directory or git repository with
`.claude-plugin/marketplace.json`, in Claude Code's format.

```console
$ orbit plugin marketplace add acme/claude-plugins     # GitHub owner/repo, a git URL, or a directory
$ orbit plugin marketplace list
$ orbit plugin install formatter@acme-plugins
$ orbit plugin marketplace update
$ orbit plugin marketplace remove acme-plugins
```

A git marketplace is cloned (shallow) under `$ORBIT_HOME/marketplaces/`; a
directory is read where it is. Nothing is fetched except when you add or
update one. `install NAME@MARKETPLACE` hands the plugin's directory to the
ordinary importer, so the package is stored as an immutable snapshot, no
package code runs, its hooks stay off until you name the plugin
([`plugin_hooks`](#run-the-hooks-of-an-imported-plugin)), and its credentials
and MCP servers are not activated. Plugin sources other than a path inside the marketplace or a git
repository are refused. The same commands work in the terminal chat as
`/plugin …`; a plugin installed there is used by sessions started afterwards.

## Import the plugins Claude Code has enabled

```console
$ orbit plugin import --from-claude --dry-run    # what would happen; writes nothing
$ orbit plugin import --from-claude              # import them
$ orbit plugin import --from-claude --only hookify --only semgrep
```

This reads two records in Claude Code's config folder (`$CLAUDE_CONFIG_DIR`,
else `~/.claude`): `plugins/installed_plugins.json` (format version 2; another
version is refused, not guessed at) and the `enabledPlugins` map of
`settings.json`. Nothing else in that folder is read, and it is where Claude Code
keeps its credentials. Each plugin that is enabled and installed for you goes
through the ordinary importer, read the way Claude Code reads plugins
(`--lenient`, below), at user scope. Nothing runs, and nothing is written outside
`$ORBIT_HOME/plugins`.

One line per plugin says what happened and what it holds: `imported`, `already`
(the stored copy is identical, or differs only by the session markers described
under `--lenient` below), `changed` (Claude Code's copy has moved on; ORBIT's
is left as it is, and the line gives the `orbit plugin upgrade` command that takes
the new one), `kept` (ORBIT holds it with other settings, for example disabled, and
leaves it), `refused` with its code (the importer's, or `install_path_outside`
for an install path that is not inside Claude Code's plugin folder: a path in a
registry is no reason to copy some other folder into a store), or `skipped` with
the reason (not installed for the user, or a second marketplace's copy of a name
that was already imported). One refusal does not stop the others. A plugin's command hooks and MCP servers are counted and
marked as staying off; the last line says how to turn hooks on.

Importing everything has a cost. ORBIT checks each stored copy against its digest
whenever it builds a session's skill list and when the Skill tool or a plugin
command runs, so a store of seventy plugins (118 MiB here) is verified at every
start: about half a second with a release build on the machine this was measured
on, and several times that with a debug build. The import itself took half a
minute. `orbit plugin disable NAME` takes a plugin out of that without removing it.

`--lenient` is also a flag of `orbit plugin inspect`, `import` and `upgrade`. A
strict read refuses the whole plugin for one skill, command or agent file it cannot
parse; a lenient read leaves that file out and names it (`component_skipped`).
It reads YAML the way Claude Code does when a value holds a colon or a bracket
(`argument-hint: [--strict] [--json]`), accepts a list for `argument-hint`, a
`.mcp.json` without the `mcpServers` wrapper, and a `hooks.json` that also lists
`modules`, and skips symbolic links, `node_modules`, `.venv`, `venv` and
`__pycache__` instead of refusing the package. It also leaves out `.in_use`, the
folder at the top of a plugin in which Claude Code keeps one file per running
session. That folder is no part of the plugin and changes whenever a session starts
or ends, so taking it in would change the plugin's digest each time, and the
digest is what a `plugin_hooks` pin names. It is not listed as left out, and a
strict read still takes it as content. A copy stored by an earlier build holds
those files: it keeps verifying under its own digest, and `import --from-claude`
does not call it changed for them. The choice is stored with the
plugin, and an upgrade keeps it. A package is at most 64 MiB with files of at most
16 MiB, and the store holds 256 MiB in all.

## Keep a session running with serve and attach

From your workspace, start one foreground owner using a declared provider/model:

```sh
orbit serve --socket "$HOME/.orbit-run/owner.sock" --session work --model first/small
```

`first/small` must match your provider configuration. `--session work` names a new
session; reopen a saved one with `--resume work` instead. Do not combine those
flags. The owner uses its startup working directory for tools. It creates a missing
socket directory privately; an existing parent must be owned by you with mode 0700.
The socket is local and private. Unsafe paths, another live endpoint, or an
already-owned saved session are refused. This starts no background service or
multi-session manager.

In another terminal:

```sh
orbit attach --socket "$HOME/.orbit-run/owner.sock"
```

Plain text submits a prompt. The attach shell supports these local controls:

| Command | Effect |
|---|---|
| `/status`, `/logs` | Inspect the owner snapshot or bounded event view. |
| `/detach`, `/quit` | Disconnect the client and leave work running. EOF also detaches. |
| `/cancel` | Interrupt the active turn while retaining the owner. |
| `/stop` | Stop the owner and clean up active work. |
| `/approve ID once`, `/deny ID note` | Resolve a currently displayed approval; stale IDs fail. |
| `/model`, `/model first/small` | Inspect identity or select a declared model when idle. |
| `/effort`, `/effort default` | Inspect effort or restore the selected model's default. |
| `/route status`, `/route auto` | Inspect routing or clear a manual model pin. |
| `/models`, `/sessions`, `/resume ID` | List configured models/saved sessions or switch an idle owner. |
| `/mode default` | Select a permission mode when the owner permits a configuration change. |

Approvals also accept `session`, `rule` or `always` after the approval ID where
the offered grant supports it. Ordinary chat slash commands such as `/permissions`
are not attach-shell commands.

Only one client controls the owner. Other clients can read status and logs:

```sh
orbit attach --socket "$HOME/.orbit-run/owner.sock" --status
orbit attach --socket "$HOME/.orbit-run/owner.sock" --logs
```

The `--cancel` and `--stop` forms require controller ownership and are refused
while another controlling client is attached. Use `/cancel` or `/stop` in that
client, or detach it first. Starting another turn or changing configuration while
the session is busy can be refused rather than queued.

Run attach again after detaching or losing the connection. Recovery supplies a
consistent snapshot or sequenced events, including visible conversation, current
state and pending approvals. An expired replay cursor requires a fresh snapshot.
Disconnecting does not cancel a turn. Prompt request IDs prevent duplicate
dispatch; reusing an ID with different text is refused. If an acknowledgement is
lost, the client reports an unknown outcome: inspect status and conversation
before deciding what to do. It does not automatically resubmit. Restarting a
stopped owner with `--resume` loads its saved conversation when accounting permits
admission. Pending uncertain work is refused; use `orbit recovery status --session
SESSION_ID` to inspect it. Reconnecting or restarting does not replay a provider
request.

## Enable language-server diagnostics and navigation

Diagnostics are off by default. Put an explicitly enabled configuration in
`$ORBIT_HOME/lsp.toml`, owned by you and not writable by other users:

```toml
enabled = true

[[servers]]
name = "rust"
command = "/path/to/existing/rust-analyzer"
args = []
language_id = "rust"
extensions = ["rs"]
workspace_root = "."
timeout_ms = 5000
```

Use your installed server's executable and arguments. A relative workspace root
is resolved against the current tool working directory, not the configuration
file's directory. The server runs with that root as its working directory. A
trusted project's `.orbit/lsp.toml` can replace an already-enabled user
configuration or disable it; it cannot activate diagnostics by itself. A user home
inside an untrusted workspace also cannot self-activate this integration.

The exposed model tool is `LspDiagnostics`, with arguments such as:

```json
{"file_path":"src/main.rs","server":"rust"}
```

There is no separate `orbit lsp` or `/lsp` command. For example, after configuring
a provider, ask a tool-enabled headless turn to use it:

```sh
orbit -p "Use LspDiagnostics on src/main.rs with server rust; report its status and freshness." --allowedTools LspDiagnostics
```

That prompt sends an ordinary model request; the model chooses the tool call.
The optional `server` argument disambiguates matching configurations. The file
must match a configured extension, remain inside the configured root and inherited
workspace scope, and pass tool permissions and Read/deny-read rules before server
launch or document transmission. Child agents cannot widen their inherited tool
scope. `--bare` skips integration discovery.

Each call launches an on-demand server, initializes it, opens one UTF-8 document,
requests pull diagnostics when supported or waits for matching-URI push
diagnostics, then closes/shuts down and performs bounded child cleanup. Cancellation
and a single request deadline cover the exchange; cleanup also handles timeout
and cancellation. No executable download, watcher, server edit or server-command
execution is provided. A trusted launch configuration authorizes a local process;
it does not confine that process to one file or sandbox its own filesystem/network
access.

Read the result's `status`, `freshness`, `reason`, `position_encoding` and
`truncated` fields, not just the diagnostics array:

| Result | Meaning |
|---|---|
| `received` with an empty array | A usable response was actually received with no diagnostics. |
| `stale` | A push response identified another document version. |
| `unavailable` | No usable result arrived before the deadline; this is not a clean-file verdict. |
| `freshness: unconfirmed` | Push diagnostics omitted a version, so freshness cannot be confirmed. |

Ranges retain the negotiated UTF-8/UTF-16/UTF-32 position encoding. Severity,
message, code and source are preserved subject to output scanning and bounds.
Configuration is capped at 64 KiB/16 servers, a document at 1 MiB, diagnostics at 100
and report output at 60 KiB. `timeout_ms` must be 100–30000. Protocol/IO failures may
return an error rather than a diagnostic report. Native Unix launch support does
not establish compatibility with every language server.

### Navigate with the language server

The same tool takes an `operation`: `definition`, `references` or `hover` at a
1-based `line` and `character`, `document_symbols` for the file, or
`workspace_symbols` with a `query`. Results give a path relative to the
server's workspace and a 1-based line and character.

The file you ask about passes the same checks as for diagnostics. Each file a
result names is checked the same way, and a result in a file the session may
not read is counted in `withheld` instead of being named. Hover text is
scanned for secrets like any other output. A server is started for each
request, so on a large project it may still be loading when the deadline
passes: the request is repeated until then, and the result says so if nothing
arrived. Raise `timeout_ms` (up to 30000) for servers that index slowly.

## Install and inspect signed content

Signed packages use a private store separate from active instruction mods. Begin
with an initialized home, a publisher's signed manifest and the matching package
bytes. After independently checking the publisher's Ed25519 public key, set
`ISSUER_PUBLIC_KEY` to its 64-character hexadecimal value and use:

```sh
orbit mod allow-issuer "$ISSUER_PUBLIC_KEY"
orbit mod issuers
orbit mod install ./package.wasm --manifest ./package-manifest.json --yes
orbit mod list
orbit mod search example
orbit mod status example-package
```

Replace the paths and package name with the signed content you reviewed. `--yes`
is the explicit installation confirmation. The manifest contains `name`, `version`,
`issuer_public_key`, `content_digest`, `signature` and `declared_imports`; extra or
duplicate fields are refused. ORBIT checks bounded regular inputs, the issuer
signature, trusted-issuer membership, content digest and allowed declared imports
before publishing an installation. Packages are limited to 16 MiB and manifests
to 32 KiB.

Content and manifests are stored by digest beneath
`$ORBIT_HOME/signed-packages`, with a durable installed record and a matching
`PluginInstall` ledger proof. Identical retries can reuse the verified proof;
conflicting or unsafe stored state is refused. If publication is reported
uncertain, inspect status before retrying. Listing in a fresh process rechecks
bytes, signature, current issuer trust and proof, and reports `verified`,
`missing_content`, `tampered`, `untrusted_issuer`, `missing_proof` or `invalid_proof`.
The catalog includes name, version, content/manifest digests, issuer, install ID
and ledger record hash. `mod issuers` lists trusted issuers separately;
`mod status` selects an exact installed name.

Installation stores and verifies signed content. It does not execute WASM
exports, activate an instruction bundle, grant tool permissions or fetch a remote
marketplace. Instruction mods under `$ORBIT_HOME/mods` remain a separate feature.
Local fixtures and a configured browser/server workflow establish only the
behavior they exercise; use your existing servers to check real compatibility.

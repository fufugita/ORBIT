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
`env` map supplies literal process environment values.

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
userinfo or fragments, and redirects are disabled. Automatic MCP OAuth, browser
login and token refresh are not provided by this configuration. Provider API-key
storage is a separate feature and does not supply remote MCP authentication.

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

`--permission-mode bypass` is a separate explicit mode: it skips ordinary
Ask/Allow/Deny evaluation. The legacy `permissions.toml` deny barrier, operator
scope exclusions and tool exposure/profile restrictions still apply. It is not
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
stopped owner with `--resume` loads saved conversation and labels interrupted or
uncertain work; it does not replay a provider request.

## Enable language-server diagnostics

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

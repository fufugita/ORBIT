# Move a Claude Code project to ORBIT

Start with a separate trial session in the same project. Keep existing
conversation history in its original harness while you check configuration,
permissions and provider access.

## Check the selected home and project

Run these from the project directory:

```sh
orbit doctor
orbit migrate --from claude
```

Both commands inspect local configuration without sending provider requests or
executing imported hooks, commands or MCP servers. Add `--json` for structured
output. `--home DIR` selects a specific ORBIT home; otherwise the normal home
selection applies: `ORBIT_HOME`, an existing `~/.orbit`, an existing project
`.orbit`, then `~/.orbit` for a new installation.

The migration report distinguishes missing sources from malformed, oversized or
unsafe files. Fix blocking configuration errors before applying permissions.
An offline readiness result does not establish provider connectivity or complete
behavioral parity with another harness.

## Review permissions before importing them

Preview the permission rules that can retain their meaning:

```sh
orbit config import-claude
```

Review every rule that is left out, especially path-sensitive rules. When the
preview matches the access you intend to allow, apply it explicitly:

```sh
orbit config import-claude --apply
```

If an ask or deny rule cannot retain its behavior, automatic application stops
before writing any settings, and the migration check requires review. Migrate
that policy manually. The preview still lists portable rules and omissions.

Importing permission rules does not transfer provider credentials, conversation
history, project trust, or permission to relay approval prompts through channels.

Read/Edit rules need a separate review, including bare tool names. Claude's
[file permission rules](https://code.claude.com/docs/en/permissions#read-and-edit)
group several file operations, use settings-dependent path anchors and check
resolved symlink targets. ORBIT's native selectors match individual tools and
their path arguments; identical text does not imply identical coverage. Keep
omitted rules out until their intended scope has been expressed and tested with
ORBIT's tools.

`WebFetch(domain:...)` rules also require manual migration. Claude's domain
normalization and wildcard rules can affect its shell sandbox network policy;
an ORBIT selector for one tool does not establish equivalent network access.
Matching the initial URL alone is insufficient evidence of equivalent policy.

## Check instructions, commands, skills and hooks

ORBIT reads project instructions such as `CLAUDE.md` and `AGENTS.md`. Claude
settings, command and skill compatibility is opt-in. Review executable hook
commands and project configuration before enabling compatibility for a trial:

```sh
ORBIT_CLAUDE_COMPAT=1 orbit
```

Try one representative command and skill, and check each hook you rely on.
Hooks that parse Claude-specific transcripts may require adaptation. See the
[compatibility inventory](claude-code-parity.md) and
[integration documentation](integrations.md) for supported settings and limits.
Project trust and explicit permission rules continue to apply.
The read-only migration inventory skips symlinks. A skipped link does not by
itself mean the skill is unavailable: the compatibility catalog can load a
linked directory's root `SKILL.md`. Check that the target is the intended
directory and that its frontmatter parses. A directory containing a collection
of skills, without its own root `SKILL.md`, is not itself an invocable skill.
Model-based hooks require managed accounting. A child session without a managed
hook namespace reports a hook error and does not send a model request; include
that case in your trial if your workflow relies on child model hooks.

## Check providers and integrations

Use `orbit provider list` and `orbit doctor` to inspect configured providers and
credential bindings. If credentials need setup, use `orbit provider login NAME`
or the declared environment variable for that provider. Keep credentials in the
supported credential store rather than copying another harness's auth files.

Council works with the model already selected in terminal chat. `/council QUESTION`
runs three reviewer perspectives and a judge using that model: four managed
requests, with no extra model configuration required. A mixed-model roster is
optional; see [Council configuration](customization.md#run-a-native-council) for
the bounded `council.toml` settings. Opening its pane starts no requests.

Use `orbit mcp list` to inspect MCP configuration. Then test the harmless read
operations you need in a trial chat. OAuth sign-in, remote integrations and
channel approval relays require their own setup; a configuration file being
present does not establish a working authenticated connection.

## Run a daily-use trial

With the installed candidate and your chosen provider, check:

- A short prompt and a harmless file-read task complete with truthful usage.
- Cancelling a provider request or permission check returns control promptly.
- The next turn works after cancellation, and resuming restores the session.
- `/clear` keeps Council and Reactor panes attached to the fresh session, resets
  their old live observations and preserves layout/art; the next turn works.
- `/compact` retains recent exchanges and preserves accurate accounting.
- Your permission rules, selected model, hooks and MCP tools behave as expected.

Start new ORBIT sessions with reviewed context from the old project. Existing
Claude conversations are not imported as ORBIT durable sessions. Keep historical
exports available separately.

For an initial provider smoke test, `--bare` suppresses automatic hooks, skills,
instruction bundles, MCP servers, channels, status commands and memory-file
discovery across headless, interactive and owned sessions. Provider credentials,
permission rules and explicitly appended system instructions still apply.
Test your integrations separately in a normal session after reviewing them.
An `--allowedTools` selection limits tool execution; native
allow rules and convenience grants cannot widen it, and hook-rewritten inputs
must remain inside that scope. `McpToolSearch` can start servers and therefore
uses the same permission and accounting checks as other tool calls.

If you roll back ORBIT after using model hooks or automatic permissions, keep
the home with the binary version that understands its housekeeping receipts.
Older builds may refuse those newer records. Preserve the original home and
historical exports rather than rewriting accounting data for a downgrade.

## Shell completion

Completion commands emit scripts directly:

```sh
orbit completions bash
orbit completions zsh
orbit completions fish
```

Source the script for your shell from its startup configuration. Use `--json`
only when a program needs the script inside a JSON response.
For zsh, load it after your usual `compinit` initialization.

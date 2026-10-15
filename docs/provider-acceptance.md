# First real-provider trial

Run this checklist with a disposable home and project before using ORBIT on an
engagement. Local fixture checks establish the harness's behavior; this trial
checks your actual endpoints, credentials, model capabilities, and terminal.

Keep credential values in your shell or secret manager. Provider configuration
contains only their environment-variable names. Use the exact model IDs your
provider accepts, including any slash characters.

## Start with one provider

1. Run `orbit setup`, then `orbit doctor`. Resolve required checks first. A
   configured integration marked `not_tested` still needs its own connection test.
2. Declare one inexpensive model and its endpoint. Check `orbit provider list`
   and `orbit route status` before sending a prompt.
3. Start a session with `orbit chat --model provider/model`. Ask for one short
   reply. Check the displayed provider, model, usage, and cost. Configured prices
   are estimates; compare usage with the provider's account page.
4. Query `/effort`, select a supported value, then use `/effort default`. Check
   that the model accepts both requests. An unsupported choice should fail
   visibly before a request.
5. Interrupt a response, then resume the session. Confirm the partial reply is
   visibly interrupted and the old prompt is not automatically sent again.

## Compare two providers

Declare a second provider and model. Use exact qualified names where model IDs
overlap. Start with small prompts and a spending limit appropriate to your account.

```sh
orbit route setup --easy first/small --hard second/strong
orbit route test "Implement a comprehensive parser"
orbit route status
```

Check that the preview names the expected phase, difficulty, target, and source.
An explicit `--model`, `ORBIT_MODEL`, or `/model` selection pins the session even
when it equals the default. Use `/route auto` to enable automatic selection in
that session. Send the previewed prompt and compare the actual selected provider
and raw model ID. A routed turn keeps the base selection and its effort override
for later turns; a different model uses its own declared defaults and limits.

Resume the session and repeat a short prompt. Confirm the pin or automatic mode
survived. Do not infer support for one provider's effort levels from another's.

## Exercise the frontends

- Terminal: check your preferred theme, layout, fonts in the terminal application,
  file completion, multiline history, approvals, cancellation, and clean exit.
- Plain/headless: run one short prompt and inspect its exit status and output.
- Owner/attach: start a private local owner, attach, query settings, submit one
  prompt, detach, and reconnect. Confirm there is one conversation and one call.
- Browser: launch with `orbit web`, use the printed local address, and check model
  and effort controls, reconnect, cancellation, and the saved conversation.

A disconnected frontend must never replay a prompt automatically. Reconnecting
should recover the owner's current state before you decide whether to submit again.

## Exercise permissions in a disposable project

Create a harmless text file. Ask ORBIT to read it, propose an edit, and run a
small local command. Verify that an approval names the actual operation, that
Deny prevents it, and that a remembered grant has the scope you selected. Repeat
with a configured MCP tool's explicit Ask and Deny rules. Enable LSP or browser
MCP only when you intend to test that integration; setup and doctor do not start
configured servers.

Create a disposable workspace with `orbit pentest init ./engagement`. Check that
its scope starts empty and that existing evidence survives a second
initialization. Import its profile explicitly and inspect the evidence/findings
panes. The generated engagement panes offer refresh and conversation focus.
To test draft insertion, add or import the notes pane example from
[customization](customization.md), which declares an `insert_prompt` action.
Use that pane's draft action and confirm it does not submit the prompt. Folder
trust, tool permissions, scans, and external requests remain separate explicit
actions.

## Record the outcome

Record executable version, operating system, terminal/browser, provider kind,
exact model IDs, supported effort choices, request counts, cancellation behavior,
and any error messages with credential values removed. Preserve a failing
session for diagnosis before changing configuration. Verify its ledger with
`orbit verify-ledger` and use `orbit replay --dry` for a local replay plan.

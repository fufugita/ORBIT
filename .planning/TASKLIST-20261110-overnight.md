# OVERNIGHT TASKLIST — 2026-11-10 (hard mode, operator asleep)

GOAL: work the REA-derived gap list + wizard polish autonomously. Each task:
implement → verify (fmt/clippy/tests) → commit operator identity → push main+branch.
DO NOT: touch LPAC fix B / hosted curl|sh / Source69 / closure docs (operator-gated).

## T1 [DONE 65a64f1 — meter already existed (gap-list false claim); added tokens-left alongside %] — Context-remaining meter (P1, S)
bars.rs cost chip gains "ctx NN%" segment: last request usage vs model context
window (presets config). Protect: cost chip width logic (bars.rs:226), 40x11 floor.
Verify: hud-tui tests + a new unit test for the percentage math.

## T2 [DONE 8d7605a — additionalProperties enforced, 10 unsupported keywords rejected, 4 tests] — FX-03 schema dialect enforcement (P1, S/M)
main.rs validator: reject (not ignore) additionalProperties:false violations +
unsupported keywords; re-validate post-repair response against the SCHEMA.
Protect: single bounded repair retry (:2741), cost accounting for both calls.
Verify: new validator unit tests (valid/invalid/extra-props/unsupported keyword).

## T3 [DONE cb1b23a — restore hash-verifies, refuses missing targets, all-or-nothing w/ rollback; remove_created added] — FX-02 checkpoint restore coherence (P0, M)
Checkpoints::restore (engine/src/transcript.rs:210): hash-compare current bytes
vs checkpoint pre-image before overwrite; deletion preimages for created files
(record at snapshot time in tool_runtime); all-or-nothing apply with rollback;
refuse conflicting external edits. Protect: /rewind UX (tui_worker.rs:1732-69),
Rewound event semantics.
Verify: new transcript restore tests (conflict, created-file, mid-failure rollback).

## T4 [DONE 084cd62 — browser sign-in headline leads provider stage; all 75 journeys green] — Wizard item 3: easiest-path first screen (M)
onboarding.rs selected_provider: when any preset supports_browser_login, offer a
headline choice "Sign in with a provider account (browser)" ABOVE the preset list.
Plain/nonTTY keeps the numbered grammar unchanged (headline becomes choice 1 in
the numbered list). Protect: all 65 onboarding PTY journeys; scripted grammar.
Verify: full onboarding_test.py --group all; add one rich + one plain journey.

## T5 [DONE 0089083 — redesign: opt-in `setup --customize` (auto-offer hung scripted journeys)] — Wizard item 5: optional theme stage after save (M)
After credential-ready save, ask "Customize appearance now? [y/N]" (default N,
skip in nonTTY/scripted). y → jump into existing /theme flow. Stage counter
stays 6 unless accepted. Protect: scripted journeys byte-identical.
Verify: PTY journeys incl. one decline + one accept.

## T6 [DONE 58cbe27+d9fd18b — completions bash/zsh/fish + README verify/completions docs] — orbit completions subcommand + docs (S)
orbit completions bash|zsh|fish → emit static completion scripts (hand-rolled
parser so no clap dependency). README/docs: --version verify step + completions
section. Verify: snapshot tests of emitted scripts contain known commands.

## T7 [DONE 669b26c — ASCII wordmark rich-only; plain journeys byte-identical (75/75)] — Wizard item 10: ASCII wordmark rich-only (S)
onboarding.rs:877 header: small ASCII "ORBIT" wordmark when
rich_choices_available(), plain text header unchanged otherwise.
Verify: plain journeys byte-identical; add rich header assertion.

## T8 [DONE d193bb5 — armed marker on save; next fresh interactive launch runs doctor inline once, 1h TTL] — Wizard item 9: doctor auto-suggest (S)
Gate block (main.rs): after a successful save, next fresh interactive launch
within 1h offers `orbit doctor` inline once (marker file in home; never in
scripted/nonTTY). Verify: PTY journey covering offer+decline+accept-once.

## T9 [DONE 30e6dea — pdf_oxide text extraction (NOT rasterize: pure-Rust rasterizer too heavy; text serves the model goal), 8-page cap, honest scanned-PDF error] — PDF→vision (P2, M) — only if time remains
turn.rs image_block_of path: detect application/pdf in fs_tools read, rasterize
first N (4) pages bounded into image blocks. Requires a rasterizer dep — CHECK
LICENSE/size impact first; if heavy, SKIP and note.
Verify: wire tests at turn.rs:2740-2768 extended.

## T10 [DONE — REA report received] — OMP REA pass + task-list refresh
After T1-T9: run REA on Oh My Posh (JanDeDobbeleer/oh-my-posh) — prompts, tools,
commands, features vs ORBIT TUI (render pipeline, themes, segments, hooks,
transient prompts, right prompt, tooltip, upstream/upstream_template, layout).
Update THIS tasklist with the gap items found, then implement what's tractable.

## RULES (standing)
- fmt + clippy -D warnings + relevant test groups green before every commit.
- Push main AND branch after each commit (pin 140.82.112.4 via
  http.curloptResolve only if github.com unreachable — retry normal first).
- loop-state + STATE.md checkpoint before walking away.
- No operator-gated items. No AI artifacts in commits. Operator identity only.

## REA (Oh My Posh) gap items — second wave, recommendation order

Agent verified from OMP source (main, Nov 2026): ~100 segments, 123 themes, CLI: init, debug, print, config edit/export, font, notice, toggle/enable/disable, statusline, cache, upgrade, get, claude.

## G1 [DONE 960960a] — Segment toggling (OMP #1) (M)
`orbit toggle <chip|panel>` persisting in home config; top bar honors it.
Protect: top_bar tests, cost-chip width logic.
## G2 [DONE 71fba87] — Git status depth (OMP #3) (M)
Branch chip gains ahead/behind + rebase/merge/cherry-pick state; git plumbing only.
## G3 [DONE 03d3a37] — Width-responsive chips (OMP #2) (M)
Optional min/max terminal width per chip/panel in presets.
## G4 [DONE 83376d4] — Theme live-preview selector (OMP #5) (L)
`orbit theme` no-arg → interactive selector cycling themes in the real TUI.
## G5 [DEFERRED — needs release-channel decision] — Update check notice (OMP #4) (M, opt-in)
Deferred: needs a release channel decision — flag for operator.
## G6 [DONE 6f3d156] — Config backup-on-write (OMP #6a) (S)
Back up providers.toml/customization before overwrite. Layering (G6b) = operator decision.
## G7 [DONE ed68b62] — Cache introspection (OMP #8) (S)
doctor extension listing discovery/ledger cache paths+sizes.
NOT APPLICABLE (prompt-engine specific, do not implement): transient/right prompts, tooltips, go-templates, init shell-integration, hot reload, multi-format config, statusline/claude, lifestyle segments, font installer, glyph migration.

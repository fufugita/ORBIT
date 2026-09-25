# ORBIT Desktop — Visual System (staged 2026-09-26)

> **Status:** ACCEPTED DRAFT for the future Tauri/desktop front-end.
> Two review entries were compared: one written specification and one
> rendered visual system. This staged doc reconciles them: the written spec
> supplies the normative rules; the rendered frames (in `renders/`) are the
> canonical visual reference. Where they disagree, the shared design law
> (`../DESIGN-PRINCIPLES.md`) wins, then the written rules.
>
> The desktop front-end is NOT the current implementation target. The
> ratatui TUI (`../tui/DESIGN.md`) ships first; this doc is the design
> reference for when the desktop shell begins. The typed
> FrontendAction/FrontendEvent protocol extraction is the prerequisite
> shared by both.

## Design direction: quiet gravity

ORBIT's desktop application is a precise instrument arranged around a
conversation — not a chatbot surrounded by administration. Signature:
uninterrupted near-black reading canvas, confident white typography,
selective magenta emphasis, and supporting surfaces that appear when they
become useful.

The rendered reference set (`renders/`, from the winning visual submission):

| Frame | What it demonstrates |
|---|---|
| Foundations | Brand marks (expanded 144×40, header 24px, compact, tray 16px), type scale in situ, full color-token swatches with contrast ratios, status vocabulary, control states |
| A — Idle session 1440×900 | Unboxed assistant prose, restrained user-message surface, status footer, discoverable Workspace |
| B — Streaming, two tools running | Live tool rows with elapsed time, provisional-results honesty, inspector open on request |
| C — Medium-risk approval | Inline approval surface: action/targets/change/scope/why/effect/record + Allow once / Deny / session-wide |
| D — Destructive approval | Centered modal, type-the-phrase confirmation, no-undo stated, denial pre-focused |
| E — Completed with evidence | Verification block, related receipts, "not run" honesty, bounded completion claim |
| F — Replay, read-only | Cyan mode marker, event transport replacing composer, as-of-event accounting, receipt integrity separate from results |
| G — Compact 1100×700 | Utility rail, reading lane preserved, inspector as overlay sheet |
| H — Narrow 800×700 | Navigation collapsed into top bar, single surface |

## Color tokens (from the Foundations frame — canonical)

Surfaces: canvas `#111015` · navigation `#15131A` · panel `#1B1821` ·
raised `#24202C` · hover `#2D2736` · pressed `#221E29` · code `#0D0C11`
Text: primary `#F5F2F7` (17.1:1) · secondary `#C4BECF` · muted `#9B92A8` ·
disabled `#72697F` · onBrand `#1A1020`
Brand: default `#F36BD6` (7.1:1) · hover `#FA89E0` · pressed `#DB57BF` ·
focus ring `#FFA0E8` · selection `#3A213B`
Status: live `#86CFE8` · success `#85D6AC` · warning `#E8BF7A` · error `#FF9A9F` ·
destructive `#AD2746`
Borders/tints: subtle `#342D3D` · control `#85788F` (3.85:1) · tint.success/warning/error

## Typography

Inter (UI + prose) · JetBrains Mono (code, paths, hashes). Scale: 20/28
session title · 18/26 message heading · 16/24 section · 16/26 prose ·
14/20 UI label · 13/20 supporting · 12/18 metadata · 13/20 code.
Reading measure ≤72ch/760px, lane ≤800px. Tabular numerals for all
changing values.

## Layout (normative rules from the written spec)

48px top bar · 28px status footer · navigation 200–288px expanded / 56px
utility rail / hidden <960px · inspector 320–480px docked, 360px overlay,
closed by default in idle sessions regardless of width. Conversation
retains ≥640px before inspector switches to overlay. Breakpoints:
960 / 1280 / 1680px. Min window 800×600; no CSS-minimum that defeats
zoom-reflow.

## Approval experience (shared law, desktop rendering)

Risk-tiered presentation (low: compact inline → medium: expanded inline →
high: inline summary + modal review → destructive: modal + type-the-target).
Fixed hierarchy: action → target → scope → why → effect → evidence-recorded
→ choices. Session-wide grant always displays its true broader scope.
No approval steals keyboard focus from a typing user. No choice recorded
optimistically.

## Motion

fast 100ms (hover) · standard 160ms · spatial 220ms · notice 260ms · brand
≤420ms (startup only) · working 1200ms indeterminate only. Nothing moves in
steady idle. Reduced-motion removes translation/rotation; state labels and
values remain fully functional.

## Implementation order (when this front-end begins)

1. Typed frontend protocol extraction (shared with TUI bridge)
2. Foundations + shell (tokens, top bar, navigation, responsive regions)
3. Conversation + composer (markdown, streaming, draft preservation)
4. Operational components (tools, workspace, approvals, grants)
5. Evidence + replay (timeline, receipts, artifacts)
6. Hardening (contrast, scaling, screen readers, platform chrome)

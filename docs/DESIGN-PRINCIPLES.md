# ORBIT — Shared Design Law

> The nine principles both design-review submissions converged on
> independently. They bind every front-end — ratatui TUI, Go Bubble Tea,
> future Tauri desktop, browser projection. When a surface's spec conflicts
> with a principle, the principle wins.

1. **The conversation is the destination.** It gets the brightest ink, the
   widest surface, the most stable reading position. Chrome never competes
   with content; nothing at the edge outshines the center.

2. **Magenta means intent, authority, and ORBIT itself — never general
   activity.** Magenta marks the brand, the primary action, selection, focus,
   and requests for the user's authority. Running tools do not turn the
   interface pink. It never decorates and never fills more than a word-sized
   area.

3. **Color is never the sole signal.** Every state travels with a glyph and a
   word. The monochrome render carries the same information as the
   true-color render.

4. **Evidence must be earned.** "Done" is a claim; "verified" is a proof.
   Green is reserved for outcomes backed by evidence — a passing check, a
   ledger record, a retest attestation. Unevidenced completion gets a neutral
   marker and says so.

5. **Honesty under stress.** No fake progress, no rotating "thinking…"
   phrases, no fabricated values. "Not provided", "not run", "provisional",
   "unavailable" are valid, explicit states. Requested-vs-confirmed and
   pending-vs-denied are always distinguishable. Evidence and ledger
   integrity are separate axes.

6. **Authority appears at the moment of consequence.** Approvals present
   action → target → scope → why → effect → evidence-recorded → choices,
   together, in plain language. Scope honesty is absolute: a session grant
   displays its actual broader scope, never implied to be limited to the
   current target. You cannot approve what you have not fully seen. The
   approval surface wears the brand color — it is ORBIT asking for authority,
   not an error dialog.

7. **Motion must explain a change.** Nothing moves during steady idle. A
   still screen is a finished screen. Every capability tier is the same
   design with something taken away — degradation is subtraction, never a
   different design.

8. **Density comes from alignment, not noise.** Compact rows, predictable
   columns, restrained type. No boxes inside boxes; at most one frame on
   screen, and a frame always means "this needs you."

9. **Backend-authoritative presentation.** The UI never infers a grant, a
   risk level, a success, or a scope. Risk labels, approval scopes,
   verification results, and ledger status come from structured backend
   data; a missing value renders as "not provided", never a guess.

---

Provenance: two independent model submissions (terminal-native spec + desktop
visual system), compared 2026-09-26. Cross-references: `docs/tui/DESIGN.md`
(terminal front-end, normative), the desktop visual system (staged for the
future Tauri front-end). DR-20 architecture locks remain authoritative for
process model, approval pipeline, and display-safety seams.

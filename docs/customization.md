# Customize your workspace

ORBIT uses one versioned profile for terminal and browser preferences. Inspect
what is effective, then change a setting or import a portable profile:

```sh
orbit customize show --json
orbit customize capabilities --json
orbit customize theme midnight
orbit customize set theme midnight
orbit customize set colors.accent '#8A91FF'
orbit customize set density compact
orbit customize set glyphs ascii
orbit customize set reduced_motion true
orbit customize set layout.preset review
orbit customize set browser.font_family 'Fira Code, monospace'
orbit customize set browser.font_size_px 15
orbit customize reset colors.accent
```

Themes are `orbit`, `midnight`, and `paper`. Color values are `#RRGGBB`; unknown
settings, tokens, and malformed values are refused before saving. `colors.NAME`
and `token_overrides.NAME` address the same validated token. `customize show`
reports effective values and their source. `reset KEY` resets one preference;
`reset` removes the canonical profile and returns to legacy/default preferences.
Legacy `tui.toml` remains intact. To reset the whole profile, run `orbit customize reset`.

In the terminal, `/theme NAME`, `/customize ...`, and `/customize reload` use the
same store. Settings commands do not call a model. Choose pane and layout actions
through the existing arrange controls and command palette. Narrow terminals use
focused panes/tabs. A profile always retains one Conversation pane and composer.

Color is resolved before gradients and terminal conversion. `color_mode` accepts
`auto`, `truecolor`, `256`, `16`, or `mono`; it cannot exceed the terminal's
detected capability, and `NO_COLOR` wins. Density is `comfortable` or `compact`;
glyphs are `auto`, `unicode`, or `ascii`. Reduced motion disables motion effects.

Browser font settings use literal family names already available to your browser,
with up to eight comma-separated names and a size from 10 to 24 pixels. They do
not fetch fonts. **Terminal font family and size belong to your terminal
application**; changing the browser setting cannot change the terminal emulator.

## Import and export

```sh
orbit customize export portable-profile.json
orbit customize validate portable-profile.json
orbit customize import portable-profile.json
```

Export creates a new file and refuses to overwrite one. It excludes managed
state and refuses profiles containing detected secret literals or local private
paths. A profile contains appearance, layout, and inert pane declarations; it
contains no signing key, token values, session history, grants, or installation
state. Import validates the complete candidate before replacing stored settings.
Unknown fields, unsafe paths, invalid layout trees, and unsupported versions fail
without changing the old profile.

Malformed stored profile or legacy files produce a visible error. For a temporary
recovery session, start `orbit chat --safe-customization`. This uses read-only
session defaults and preserves the original files for explicit repair.

## Add named panes

A profile is JSON with `schema_version: 1`. Omitted fields take defaults. This
small profile places a named notes pane beside the conversation:

```json
{
  "schema_version": 1,
  "name": "Project notes",
  "theme": "midnight",
  "layout": {
    "preset": "custom",
    "tree": {
      "kind": "split",
      "dir": "right",
      "shares": [70, 30],
      "children": [
        {"kind": "panel", "view": "conversation"},
        {"kind": "custom", "pane_id": "notes"}
      ]
    }
  },
  "panes": [{
    "id": "notes",
    "title": "Notes",
    "surfaces": ["terminal", "browser"],
    "source": {"kind": "markdown_file", "path": "notes.md"},
    "actions": [
      {"kind": "refresh"},
      {"kind": "focus_conversation"},
      {"kind": "insert_prompt", "text": "Review the project notes"}
    ]
  }]
}
```

Sources are literal `text`, a workspace-relative `markdown_file`, or a `snapshot`
of `routing`, `usage`, `agents`, `scope`, `evidence`, or `findings`. File reads use
the current workspace's Read permission and display scanning. Missing, denied,
stale, and truncated content is labeled. Counts describe local files, not proof
of a finding. Context snapshots become stale when the session changes.

Actions are `refresh`, `focus_conversation`, `insert_prompt`, and `owner_cancel`.
An inserted prompt changes the draft only; sending remains your action.
Cancellation requires the current controller. Profile data cannot execute shell
commands, JavaScript, hooks, or network requests.

Profiles are bounded to 128 KiB, 32 named panes, 24 layout leaves, depth 8, eight
children per split, and eight actions per pane. Literal pane text is at most
16 KiB; Markdown files are at most 64 KiB. Pane output is at most 32 KiB and
512 lines. These bounds keep layout and rendering predictable.

## Instruction mods and signed content

Existing instruction mods still provide guidance text and named prompt commands.
They are separate from declarative appearance/pane profiles. Signed packages
verify stored non-executing content. ORBIT does not implement Claude Mods'
JavaScript component or extension APIs. Use `customize capabilities` to inspect
ORBIT's actual supported surfaces rather than assuming source compatibility.

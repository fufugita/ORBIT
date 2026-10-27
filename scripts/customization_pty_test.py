#!/usr/bin/env python3
"""Actual ANSI/cell, key and file customization workflows; run in in-jail.sh."""
import argparse
import json
import os
from pathlib import Path
import time

from pty_tui_test import PtySession, pyte
from rc_customize_test import Fixture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(Path(__file__).resolve().parents[1] / "target/debug/orbit"))
    args = parser.parse_args()
    if pyte is None:
        raise SystemExit("pyte is required for actual terminal cell assertions")
    # The positive color cases emulate a known truecolor terminal. Test the
    # inherited NO_COLOR ceiling separately below, without changing the caller.
    inherited_no_color = os.environ.pop("NO_COLOR", None)
    inherited_umask = os.umask(0o002)
    scenarios = {}
    session = None

    def checked(name, *conditions):
        assert conditions and all(conditions), (name, conditions, getattr(f, "preservation_error", None),
                                               session.screen_text() if session else "")
        scenarios[name] = {"passed": True, "assertions": len(conditions)}
        print("PASS " + name, flush=True)

    def wait(probe, label):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            session.read(0.15)
            if probe():
                f.observe_pty(session)
                return
            if session.proc.poll() is not None:
                break
        raise AssertionError((label, session.proc.poll(), session.screen_text(), session.raw_log[-1200:]))

    def has(text):
        return text in session.screen_text()

    def conversation_visible():
        # An empty Conversation panel is titled "New session" by the renderer.
        # Check its actual composer too, rather than a nonexistent title.
        return has("New session") and has("Ask ORBIT")

    def colors():
        return {str(value).lower() for row in session.screen.buffer.values() for cell in row.values()
                for value in (cell.fg, cell.bg)}

    def command(text):
        visible, screen = session.type_until_visible(text, timeout=5, interval=0.05)
        assert visible, ("command was not accepted into the composer", text, screen)
        session.key("enter")
        session.read(0.4)

    def focus(text):
        wait(lambda: session.find_text(text) is not None, "find " + text)
        session.click(*session.find_text(text))
        session.read(0.2)

    def clear_draft():
        for _ in range(len("draft evidence only")):
            session.key("backspace")
            session.read(0.05)

    try:
        with Fixture(args.binary) as f:
            profile = f.profile()
            profile.update(theme="orbit", reduced_motion=False, color_mode="truecolor")
            profile["panes"] = [{"id": "proof", "title": "Proof pane", "surfaces": ["terminal", "browser"],
                                 "source": {"kind": "markdown_file", "path": "proof.md"},
                                 "actions": [{"kind": "refresh"}, {"kind": "insert_prompt", "text": "draft evidence only"},
                                             {"kind": "focus_conversation"}]}]
            profile["layout"] = {"preset": "custom", "tree": {"kind": "split", "dir": "right", "shares": [2, 1],
                "children": [{"kind": "panel", "view": "conversation", "agent": ""}, {"kind": "custom", "pane_id": "proof"}]}}
            seed = f.work / "seed.json"
            seed.write_text(json.dumps(profile))
            proof = f.work / "proof.md"
            proof.write_text("LOCAL PROOF ONE\n")
            f.command("import", "seed.json")
            legacy = b'[color]\nmode="mono"\nreduced=true\n[keep]\nvalue="untouched"\n'
            (f.home / "tui.toml").write_bytes(legacy)
            (f.home / "tui.toml").chmod(0o644)

            def start(extra=(), env=None, cols=160):
                before = f.launch_snapshot("pty")
                opened = PtySession([f.binary, "--home", str(f.home), "--model", "fixture/local", *extra],
                                    env={**f.env, "TERM": "xterm-256color", "COLORTERM": "truecolor", **(env or {})},
                                    cwd=f.work, rows=40, cols=cols)
                f.sessions.append(opened)
                f.register_launch(opened.proc, "pty", before)
                return opened

            def stop(opened):
                if opened.master is not None:
                    opened.terminate()
                f.finish_launch(f.record_for(opened.proc))

            session = start()
            wait(lambda: has("Proof pane") and conversation_visible(), "custom layout startup")
            checked("startup_consumes_canonical_profile_over_conflicting_legacy_with_truecolor_cells",
                    "eeeaF5".lower() in colors() or any(len(color) == 6 for color in colors()),
                    f.profile()["color_mode"] == "truecolor", conversation_visible(), not f.calls)
            focus("Proof pane")
            session.type("r")
            wait(lambda: has("LOCAL PROOF ONE"), "explicit file refresh")
            checked("named_markdown_pane_keyboard_refresh_reads_workspace_file", has("LOCAL PROOF ONE"), not f.calls)
            proof.write_text("LOCAL PROOF TWO\n")
            session.type("r")
            wait(lambda: has("LOCAL PROOF TWO") and not has("LOCAL PROOF ONE"), "updated file refresh")
            checked("refresh_reloads_changed_file_without_stale_previous_content", not has("LOCAL PROOF ONE"), f.unchanged(allow_new_sessions=True))
            session.type("2")
            wait(lambda: has("draft evidence only"), "draft action")
            checked("declared_digit_action_inserts_draft_and_focuses_conversation_without_submit",
                    has("draft evidence only"), not f.calls)
            clear_draft()
            command("/theme paper")
            wait(lambda: f.profile()["theme"] == "paper" and "25221d" in colors(), "hot theme cells")
            checked("slash_theme_changes_real_cells_and_persists_offline", "25221d" in colors(), not f.calls)
            command("/customize set token_overrides.ink #123456")
            wait(lambda: "123456" in colors(), "hot semantic token")
            checked("slash_semantic_color_changes_actual_frame_cells", "123456" in colors(),
                    f.profile()["token_overrides"].get("ink") == "#123456", not f.calls)
            for key, value in [("density", "compact"), ("glyphs", "ascii"), ("reduced_motion", "true")]:
                command(f"/customize set {key} {value}")
            wait(lambda: f.profile()["glyphs"] == "ascii" and f.profile()["density"] == "compact", "capability reload")
            checked("density_glyphs_and_motion_reload_with_visible_ascii_furniture",
                    f.profile()["reduced_motion"] is True, "+" in session.screen_text() or "|" in session.screen_text(), not f.calls)
            before = f.stored()
            command("/customize set theme does-not-exist")
            wait(lambda: has("theme") and (has("unsupported") or has("unknown") or has("invalid")), "visible invalid profile")
            checked("invalid_slash_candidate_preserves_exact_saved_profile_and_current_palette",
                    f.stored() == before, "123456" in colors(), not f.calls)
            session.resize(32, 90)
            wait(lambda: has("Proof pane"), "narrow named pane switcher")
            focus("Proof pane")
            session.type("r")
            wait(lambda: has("LOCAL PROOF TWO"), "narrow custom pane")
            checked("narrow_layout_switcher_reaches_and_refreshes_named_pane", has("LOCAL PROOF TWO"), not f.calls)
            session.resize(40, 160)
            session.key("tab")
            session.read(0.3)
            stop(session)
            session = start()
            wait(lambda: has("Proof pane") and "123456" in colors(), "restart customization")
            checked("restart_retains_theme_color_density_glyphs_and_custom_layout",
                    f.profile()["theme"] == "paper", f.profile()["density"] == "compact",
                    f.profile()["glyphs"] == "ascii", has("Proof pane"), f.unchanged(allow_new_sessions=True))
            command("/customize set layout.preset review")
            wait(lambda: f.profile()["layout"]["preset"] == "review" and has("Review"), "layout preset reload")
            checked("slash_layout_preset_changes_the_actual_panel_tree", has("Review"), not f.calls)
            stop(session)
            session = start(env={"NO_COLOR": "1"})
            wait(conversation_visible, "no-color startup")
            checked("no_color_overrules_persisted_truecolor_in_real_terminal_cells",
                    not any(len(color) == 6 for color in colors()), f.profile()["color_mode"] == "truecolor", not f.calls)
            stop(session)
            malformed_legacy = b"[legacy broken\n"
            malformed_profile = b"{broken profile"
            (f.home / "tui.toml").write_bytes(malformed_legacy)
            (f.home / "customization.json").write_bytes(malformed_profile)
            session = start(extra=("--safe-customization",))
            wait(lambda: conversation_visible() and has("ORBIT"), "explicit safe session defaults")
            command("/theme paper")
            wait(lambda: has("Session-only defaults cannot write") or has("repair the stored file"), "safe session refuses write")
            checked("explicit_safe_session_bypasses_both_malformed_files_and_refuses_mutation",
                    (f.home / "tui.toml").read_bytes() == malformed_legacy,
                    (f.home / "customization.json").read_bytes() == malformed_profile,
                    not has("Proof pane"), f.unchanged(allow_new_sessions=True))
            stop(session)
            session = None
            checked("all_four_customization_tui_leases_release_without_inode_replacement",
                    len(f.chat_records) == 4,
                    all(item["launch_mode"] == "pty" and item["finished"] for item in f.chat_records),
                    f.unchanged(allow_new_sessions=True), not f.calls)
    finally:
        if session and session.master is not None:
            stop(session)
        if inherited_no_color is not None:
            os.environ["NO_COLOR"] = inherited_no_color
        os.umask(inherited_umask)
    print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": scenarios}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

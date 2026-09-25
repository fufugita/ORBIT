// Help bar — a compact keybinding strip at the bottom of the TUI.
// Keys are highlighted in accent; descriptions are dim.

package main

import (
	"strings"
)

type keyBinding struct {
	keys string
	desc string
}

var shortBindings = []keyBinding{
	{"enter", "send"},
	{"tab", "focus"},
	{"/", "commands"},
	{"^c", "cancel"},
	{"^d", "quit"},
	{"?", "help"},
}

var fullBindings = []keyBinding{
	{"enter", "send prompt"},
	{"shift+enter", "newline"},
	{"tab", "cycle focus"},
	{"1/2/3", "jump to pane"},
	{"/", "command palette"},
	{"/help", "this help"},
	{"/model <M>", "switch model"},
	{"/clear", "clear transcript"},
	{"/cancel", "cancel turn"},
	{"/quit", "quit"},
	{"^c", "cancel stream"},
	{"^d", "quit"},
	{"?", "toggle help"},
}

type HelpBar struct {
	showFull bool
}

func NewHelpBar() HelpBar {
	return HelpBar{}
}

func (h *HelpBar) Render() string {
	var parts []string
	for _, b := range shortBindings {
		parts = append(parts,
			helpKeyStyle.Render(b.keys)+" "+dimStyle.Render(b.desc),
		)
	}
	return " " + strings.Join(parts, "  ") + " "
}

func (h *HelpBar) RenderFull() string {
	var lines []string
	lines = append(lines, "")
	lines = append(lines, titleStyle.Render("  ORBIT — Keybindings"))
	lines = append(lines, dimStyle.Render("  ────────────────────"))
	for _, b := range fullBindings {
		lines = append(lines, "  "+helpKeyStyle.Render(b.keys)+dimStyle.Render(" — ")+dimStyle.Render(b.desc))
	}
	return strings.Join(lines, "\n")
}

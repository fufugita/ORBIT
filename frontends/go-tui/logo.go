// Logo — compact, readable ORBIT wordmark. No animated ring characters are
// printed outside the header; animation happens only in the status glyph.
// The previous 8-row orbit animation relied on partial-frame diff rendering
// and sliced the wordmark in real terminals. This version is deterministic.

package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The wordmark is deliberately 3 rows, not a fragile 5/8-row particle grid.
// It renders identically on xterm, screen, tmux, Kitty, WezTerm, and VS Code.
var orbitWordmark = []string{
	"  ██████  ██████  ██████  ██ ████████  ",
	" ██    ██ ██   ██ ██   ██ ██    ██     ",
	"  ██████  ██████  ██████  ██    ██     ",
}

// compactWordmark is used on narrow terminals.
var compactWordmark = []string{
	"◉  O R B I T",
}

// renderLogo returns a stable, centered brand header. `frame` animates only
// the leading status glyph, never the geometry, so there is no slicing/bleed.
func renderLogo(frame, width int) string {
	if width <= 0 {
		width = 80
	}

	if width < 72 {
		glyphs := []string{"◉", "◎", "◌", "◍"}
		line := glyphs[frame%len(glyphs)] + "  O R B I T"
		return lipgloss.NewStyle().
			Width(width).
			Align(lipgloss.Center).
			Foreground(accent).
			Bold(true).
			Render(line)
	}

	var lines []string
	for i, line := range orbitWordmark {
		style := logoAccent
		if i == 1 {
			style = logoComposer
		}
		lines = append(lines,
			lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(style.Render(line)),
		)
	}

	// Thin, stable brand rule — changes color at the center, never geometry.
	ruleWidth := width - 4
	if ruleWidth > 80 {
		ruleWidth = 80
	}
	if ruleWidth < 20 {
		ruleWidth = 20
	}
	// Guard against negative repeat counts (width=0 on first frame).
	leftHalf := ruleWidth/2 - 3
	rightHalf := ruleWidth - leftHalf - 7
	if leftHalf < 0 {
		leftHalf = 0
	}
	if rightHalf < 0 {
		rightHalf = 0
	}
	left := strings.Repeat("─", leftHalf)
	right := strings.Repeat("─", rightHalf)
	rule := logoComposer.Render(left) + " " + logoStar.Render("●") + " " +
		logoAccent.Render("ORBIT") + " " + logoStar.Render("●") + " " + logoComposer.Render(right)
	lines = append(lines,
		lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(rule),
	)
	return strings.Join(lines, "\n")
}

// logoHeight reports the exact rendered header height for layout math.
func logoHeight(width int) int {
	if width < 72 {
		return 1
	}
	return 4
}

// Status bar — a single styled line at the bottom of the TUI.
// Shows: model · provider · session · tool-state · connection · tokens · cost.
// Each field is individually styled so the operator can scan it at a glance.

package main

import (
	"fmt"
	"strings"
)

type StatusBar struct {
	cost         uint64
	inputTokens  uint64
	outputTokens uint64
}

func NewStatusBar() StatusBar {
	return StatusBar{}
}

func (s *StatusBar) SetCost(microcents, in, out uint64) {
	s.cost = microcents
	s.inputTokens = in
	s.outputTokens = out
}

func (s *StatusBar) Render(model, provider, session string, busy bool, streaming bool) string {
	// Tool state with a colored glyph
	var toolState string
	if streaming {
		toolState = successStyle.Render("◐ streaming")
	} else if busy {
		toolState = warnStyle.Render("◉ busy")
	} else {
		toolState = dimStyle.Render("◯ idle")
	}

	// Connection — always online for now
	conn := successStyle.Render("● online")

	// Cost
	costStr := fmt.Sprintf("$%d.%06d", s.cost/1_000_000, s.cost%1_000_000)

	// Tokens
	tokens := fmt.Sprintf("↓%s ↑%s", formatCount(s.inputTokens), formatCount(s.outputTokens))

	// Build the bar with styled segments and dim separators
	sep := dimStyle.Render(" │ ")

	parts := []string{
		titleStyle.Render(model),
		dimStyle.Render(provider),
		dimStyle.Render(session),
		toolState,
		conn,
		dimStyle.Render(tokens),
		boldStyle.Render(costStr),
	}

	return " " + strings.Join(parts, sep) + " "
}

func formatCount(n uint64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

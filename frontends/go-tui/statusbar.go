// Status bar — lipgloss-styled single line with model · provider · session ·
// tool-state · connection · tokens · cost.

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
	toolState := "◯ idle"
	if streaming {
		toolState = "◐ stream"
	} else if busy {
		toolState = "◉ busy"
	}
	conn := "● online"

	costStr := fmt.Sprintf("$%d.%06d", s.cost/1_000_000, s.cost%1_000_000)
	tokens := fmt.Sprintf("↓%s ↑%s", formatCount(s.inputTokens), formatCount(s.outputTokens))

	parts := []string{
		titleStyle.Render(model),
		dimStyle.Render(provider),
		dimStyle.Render(session),
		dimStyle.Render(toolState),
		dimStyle.Render(conn),
		dimStyle.Render(tokens),
		statusStyle.Render(costStr),
	}
	return " " + strings.Join(parts, " │ ") + " "
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

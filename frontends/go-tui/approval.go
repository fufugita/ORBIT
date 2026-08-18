// Approval modal — huh-style form with focusable y/n/R buttons.

package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type ApprovalModal struct {
	call   ToolCall
	button int // 0 = y, 1 = n, 2 = R
	width  int
	height int
	queued int // additional pending tool calls behind this one (M3)
}

func NewApprovalModal(call ToolCall) *ApprovalModal {
	return &ApprovalModal{call: call, button: 0}
}

// Update handles keys while the modal is open. Returns the updated model.
func (a *ApprovalModal) Update(m Model, msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h", "shift+tab":
		// Move backward (left). Previously left/right were swapped (H5).
		a.button = (a.button + 2) % 3
	case "right", "l", "tab":
		// Move forward (right).
		a.button = (a.button + 1) % 3
	case "y", "Y":
		sendAction(Action{Type: "approve", CallID: a.call.CallID, Verdict: "allow"})
		m.approval = nil
	case "n", "N":
		sendAction(Action{Type: "approve", CallID: a.call.CallID, Verdict: "deny"})
		m.approval = nil
	case "r", "R":
		sendAction(Action{Type: "approve", CallID: a.call.CallID, Verdict: "session"})
		m.approval = nil
	case "enter":
		verdict := []string{"allow", "deny", "session"}[a.button]
		sendAction(Action{Type: "approve", CallID: a.call.CallID, Verdict: verdict})
		m.approval = nil
	case "esc":
		// Escape is fail-closed: dismissing the approval UI denies the tool.
		// The footer says "Esc denies" so the visible contract matches the
		// verdict sent to the Rust core.
		sendAction(Action{Type: "approve", CallID: a.call.CallID, Verdict: "deny"})
		m.approval = nil
	}
	return m, nil
}

func (a *ApprovalModal) Render(w, h int) string {
	a.width = w
	a.height = h

	btn := func(label string, focused bool) string {
		if focused {
			return accentStyleBold.Render("[" + label + "]")
		}
		return dimStyle.Render("[" + label + "]")
	}

	labels := []string{"y once", "n deny", "R session"}
	var buttons []string
	for i, l := range labels {
		buttons = append(buttons, btn(l, i == a.button))
	}

	footer := "  Esc denies"
	if a.queued > 0 {
		footer = fmt.Sprintf("  Esc denies   (+%d more)", a.queued)
	}

	lines := []string{
		" ? Approval Required ",
		"",
		"  " + titleStyle.Render(a.call.Name),
		"  " + a.call.Summary,
		"",
		"  " + strings.Join(buttons, "   "),
		"",
		footer,
	}

	// Center in a rounded box.
	width := 52
	if a.width > 0 && a.width < width {
		width = a.width - 4
	}
	box := accentBox(lines, width)
	return box
}

// accentBox draws a rounded border around the given lines.
func accentBox(lines []string, width int) string {
	var sb strings.Builder
	sb.WriteString("╭" + strings.Repeat("─", width) + "╮\n")
	for _, l := range lines {
		padded := l
		if len(padded) > width {
			padded = padded[:width]
		}
		sb.WriteString("│" + padRight(padded, width) + "│\n")
	}
	sb.WriteString("╰" + strings.Repeat("─", width) + "╯")
	return sb.String()
}

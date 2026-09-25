// Approval modal — a centered overlay with the tool name, summary, and
// three buttons (y/n/R). Tab/arrows cycle; Enter confirms; Esc denies.

package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ApprovalModal struct {
	call   ToolCall
	button int // 0 = y, 1 = n, 2 = R
	width  int
	height int
	queued int
}

func NewApprovalModal(call ToolCall) *ApprovalModal {
	return &ApprovalModal{call: call, button: 0}
}

func (a *ApprovalModal) Update(m Model, msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h", "shift+tab":
		a.button = (a.button + 2) % 3
	case "right", "l", "tab":
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
		sendAction(Action{Type: "approve", CallID: a.call.CallID, Verdict: "deny"})
		m.approval = nil
	}
	return m, nil
}

func (a *ApprovalModal) Render(w, h int) string {
	a.width = w
	a.height = h

	labels := []string{"y allow", "n deny", "R session"}
	var buttons []string
	for i, l := range labels {
		if i == a.button {
			buttons = append(buttons, approvalButtonActive.Render("["+l+"]"))
		} else {
			buttons = append(buttons, approvalButtonInactive.Render("["+l+"]"))
		}
	}

	footer := dimStyle.Render("  Esc denies")
	if a.queued > 0 {
		footer = fmt.Sprintf("  %s   %s", dimStyle.Render("Esc denies"), warnStyle.Render(fmt.Sprintf("+%d more", a.queued)))
	}

	lines := []string{
		titleStyle.Render("  ⚠ Approval Required"),
		"",
		"  " + boldStyle.Render(a.call.Name),
		"  " + lipgloss.NewStyle().Foreground(text).Render(a.call.Summary),
		"",
		"  " + strings.Join(buttons, "  "),
		"",
		footer,
	}

	// Wrap in a styled box
	content := strings.Join(lines, "\n")
	return approvalStyle.Render(content)
}

// Tasks — right pane. A simple table showing the workspace task list.
// Styled with accent headers and dim cells.

package main

import (
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
)

type TasksPane struct {
	table.Model
}

func NewTasksPane() TasksPane {
	columns := []table.Column{
		{Title: "Phase", Width: 6},
		{Title: "Task", Width: 14},
		{Title: "Status", Width: 8},
	}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows([]table.Row{
			{"A", "Trust Spine", "✓ done"},
			{"B", "Phase Router", "✓ done"},
			{"C", "HUD Harness", "✓ done"},
			{"D", "Trace/Replay", "→ next"},
			{"E", "Go TUI", "→ next"},
			{"F", "Browser", "○ plan"},
		}),
		table.WithFocused(true),
		table.WithHeight(8),
	)
	s := table.Styles{
		Header:   tableHeaderStyle,
		Selected: lipgloss.NewStyle().Foreground(accent).Bold(true),
		Cell:     tableCellStyle,
	}
	t.SetStyles(s)
	return TasksPane{Model: t}
}

func (t *TasksPane) SetSize(w, h int) {
	if w < 10 {
		w = 10
	}
	if h < 3 {
		h = 3
	}
	t.Model.SetWidth(w - 2)
	t.Model.SetHeight(h - 2)
}

func (t *TasksPane) Render() string {
	return paneStyle.Render(t.Model.View())
}

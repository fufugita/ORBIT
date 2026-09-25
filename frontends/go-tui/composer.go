// Composer — the primary input surface. A rounded box with a blinking cursor,
// placeholder text, and a prompt glyph. Focused = bright blue border;
// unfocused = dim border. This is the clearest focus indicator in the TUI.

package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Composer struct {
	textarea.Model
	focused bool
}

func NewComposer() Composer {
	t := textarea.New()
	t.Placeholder = "ask orbit…  (type / for commands, ? for help)"
	t.Prompt = ""
	t.CharLimit = 4000
	t.SetWidth(60)
	t.SetHeight(1)
	t.ShowLineNumbers = false
	return Composer{Model: t}
}

func (c *Composer) SetSize(w int) {
	if w < 10 {
		w = 10
	}
	// Account for the border (2) + padding (2) = 4 cells
	c.Model.SetWidth(w - 4)
}

func (c *Composer) Focus() tea.Cmd {
	c.focused = true
	return c.Model.Focus()
}

func (c *Composer) FocusNow() {
	c.focused = true
	c.Model.Focus()
}

func (c *Composer) Blur() {
	c.focused = false
	c.Model.Blur()
}

func (c *Composer) IsFocused() bool { return c.focused }

func (c *Composer) IsCommand() bool {
	return strings.HasPrefix(strings.TrimSpace(c.Value()), "/")
}

func (c *Composer) CommandText() string {
	v := strings.TrimSpace(c.Value())
	return strings.TrimPrefix(v, "/")
}

func (c *Composer) Update(m Model, msg tea.KeyMsg) (Model, tea.Cmd) {
	var cmd tea.Cmd
	m.composer.Model, cmd = m.composer.Model.Update(msg)
	return m, cmd
}

func (c *Composer) Render() string {
	glyph := "▸"
	glyphStyle := lipgloss.NewStyle().Foreground(composer).Bold(true)
	borderStyle := composerFocusedStyle

	if !c.focused {
		glyph = "▹"
		glyphStyle = dimStyle
		borderStyle = composerStyle
	}

	var content string
	if c.Value() == "" {
		content = glyphStyle.Render(glyph) + " " + dimStyle.Render(c.Placeholder)
	} else {
		content = glyphStyle.Render(glyph) + " " + lipgloss.NewStyle().Foreground(text).Render(c.Value())
	}

	if c.focused {
		content += lipgloss.NewStyle().Foreground(composer).Render("█")
	}

	return borderStyle.Render(content)
}

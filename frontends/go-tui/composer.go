// Composer — bubbles/textarea wrapper with focus management and command
// detection. The composer is the primary input surface.

package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
)

type Composer struct {
	textarea.Model
	focused bool
}

func NewComposer() Composer {
	t := textarea.New()
	t.Placeholder = "ask orbit…  (type / for commands)"
	t.Prompt = "▸ "
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
	c.Model.SetWidth(w)
}

// Focus gives the composer keyboard focus (textarea.Focus returns a cmd).
func (c *Composer) Focus() tea.Cmd {
	c.focused = true
	return c.Model.Focus()
}

// FocusNow focuses without returning a cmd (called from the constructor so
// the model starts focused — Init()'s cmd runs on a copy and the focus
// would otherwise be lost).
func (c *Composer) FocusNow() {
	c.focused = true
	c.Model.Focus()
}

// Blur removes keyboard focus.
func (c *Composer) Blur() {
	c.focused = false
	c.Model.Blur()
}

func (c *Composer) IsFocused() bool { return c.focused }

// IsCommand reports whether the current input starts with "/".
func (c *Composer) IsCommand() bool {
	return strings.HasPrefix(strings.TrimSpace(c.Value()), "/")
}

// CommandText returns the command line (without the leading slash).
func (c *Composer) CommandText() string {
	v := strings.TrimSpace(c.Value())
	return strings.TrimPrefix(v, "/")
}

// Update routes a key to the textarea, returning the updated model.
func (c *Composer) Update(m Model, msg tea.KeyMsg) (Model, tea.Cmd) {
	var cmd tea.Cmd
	m.composer.Model, cmd = m.composer.Model.Update(msg)
	return m, cmd
}

func (c *Composer) Render() string {
	if c.focused {
		return composerFocusedStyle.Render(c.Model.View())
	}
	return composerStyle.Render(c.Model.View())
}

// Help — bubbles/help keybinding display for the bottom bar + /help overlay.

package main

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
)

type keyMap struct {
	Send     key.Binding
	Newline  key.Binding
	Focus    key.Binding
	Panes    key.Binding
	Commands key.Binding
	Cancel   key.Binding
	Copy     key.Binding
	Quit     key.Binding
}

func newKeyMap() keyMap {
	return keyMap{
		Send:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "send")),
		Newline:  key.NewBinding(key.WithKeys("shift+enter"), key.WithHelp("↵", "newline")),
		Focus:    key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "focus")),
		Panes:    key.NewBinding(key.WithKeys("1", "2", "3"), key.WithHelp("1/2/3", "panes")),
		Commands: key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "commands")),
		Cancel:   key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("^c", "cancel")),
		Copy:     key.NewBinding(key.WithKeys("z", "y"), key.WithHelp("z y", "copy")),
		Quit:     key.NewBinding(key.WithKeys("ctrl+d"), key.WithHelp("^d", "quit")),
	}
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Send, k.Focus, k.Commands, k.Cancel, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Send, k.Newline, k.Focus, k.Panes},
		{k.Commands, k.Cancel, k.Copy, k.Quit},
	}
}

type HelpBar struct {
	help.Model
	keys keyMap
}

func NewHelpBar() HelpBar {
	h := help.New()
	h.ShowAll = false
	return HelpBar{Model: h, keys: newKeyMap()}
}

func (h *HelpBar) Render() string {
	return helpStyle.Render(h.Model.View(h.keys))
}

// RenderFull returns the full /help overlay content without mutating the
// shared model (M5): View must stay pure in Bubble Tea.
func (h *HelpBar) RenderFull() string {
	tmp := *h
	tmp.ShowAll = true
	return tmp.Model.View(tmp.keys)
}

// Session list — bubbles/list wrapper with bubble-style items.

package main

import (
	"github.com/charmbracelet/bubbles/list"
)

type SessionItem struct {
	ID     string
	Model  string
	Active bool
}

func (i SessionItem) Title() string       { return "● " + i.ID }
func (i SessionItem) Description() string { return "model: " + i.Model }
func (i SessionItem) FilterValue() string { return i.ID }

type SessionList struct {
	list.Model
}

func NewSessionList() SessionList {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.Foreground(accent).Bold(true)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.Foreground(accentDim)
	l := list.New([]list.Item{}, delegate, 20, 20)
	l.Title = "Sessions"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	return SessionList{Model: l}
}

// SetItems replaces the session list contents.
func (s *SessionList) SetItems(items []SessionItem) {
	converted := make([]list.Item, len(items))
	for i, it := range items {
		converted[i] = it
	}
	s.Model.SetItems(converted)
}

func (s *SessionList) SetSize(w, h int) {
	if w < 10 {
		w = 10
	}
	if h < 3 {
		h = 3
	}
	s.Model.SetSize(w, h)
}

func (s *SessionList) Render() string {
	return s.Model.View()
}

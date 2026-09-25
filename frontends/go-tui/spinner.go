// Spinner — Braille dot spinner for streaming/busy indicators.

package main

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type Spinner struct {
	frames []string
	index  int
	busy   bool
}

func NewSpinner() Spinner {
	return Spinner{
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	}
}

func (s *Spinner) Init() tea.Cmd { return s.tick() }

func (s *Spinner) tick() tea.Cmd {
	return tea.Tick(spinnerTickDuration, func(time.Time) tea.Msg {
		return spinnerTickMsg{}
	})
}

func (s *Spinner) Running() bool { return s.busy }
func (s *Spinner) Start()        { s.busy = true }
func (s *Spinner) Stop()         { s.busy = false }

func (s *Spinner) Advance() {
	if len(s.frames) == 0 {
		return
	}
	s.index = (s.index + 1) % len(s.frames)
}

func (s *Spinner) Frame() string {
	if s.index < len(s.frames) {
		return s.frames[s.index]
	}
	return "·"
}

const spinnerTickDuration = 100 * time.Millisecond

type spinnerTickMsg struct{}

func (s *Spinner) Update(msg tea.Msg) (Spinner, tea.Cmd) {
	switch msg.(type) {
	case spinnerTickMsg:
		s.Advance()
		return *s, s.tick()
	}
	return *s, nil
}

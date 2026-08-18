// Spinner — bubbles/spinner wrapper with the Braille dot set.

package main

import (
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type Spinner struct {
	spinner.Model
	busy  bool
	frame int
}

func NewSpinner() Spinner {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle
	return Spinner{Model: s, frame: 0}
}

func (s *Spinner) Init() tea.Cmd { return s.Model.Tick }
func (s *Spinner) Running() bool { return s.busy }
func (s *Spinner) Start()        { s.busy = true }
func (s *Spinner) Stop()         { s.busy = false }

// Advance moves the frame counter forward (called each spinner tick).
func (s *Spinner) Advance() {
	if len(s.Spinner.Frames) == 0 {
		return
	}
	s.frame = (s.frame + 1) % len(s.Spinner.Frames)
}

// Frame is the current frame index (drives the logo orbit + spinner glyph).
func (s *Spinner) Frame() int { return s.frame }

// Viewport — bubbles/viewport wrapper with glamour markdown rendering for
// assistant messages and a streaming progress bar.

package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/glamour"
)

type Viewport struct {
	viewport.Model
	renderer *glamour.TermRenderer
}

func NewViewport() Viewport {
	v := viewport.New(60, 20)
	v.Style = focusedPaneStyle
	r, _ := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(80),
	)
	return Viewport{Model: v, renderer: r}
}

func (v *Viewport) SetContent(lines string) {
	v.Model.SetContent(lines)
}

func (v *Viewport) SetSize(w, h int) {
	if w < 10 {
		w = 10
	}
	if h < 3 {
		h = 3
	}
	v.Model.Width = w
	v.Model.Height = h
}

func (v *Viewport) ScrollBy(lines int) {
	v.Model.LineDown(lines)
}

func (v *Viewport) Render() string {
	return v.Model.View()
}

// renderTranscript builds the transcript with speaker gutters and glamour
// markdown for assistant messages. The renderer is reused (H4) — allocating a
// fresh glamour renderer per delta made streaming O(M·N).
func renderTranscript(items []TranscriptItem) string {
	return renderTranscriptWith(items, nil)
}

func renderTranscriptWith(items []TranscriptItem, renderer *glamour.TermRenderer) string {
	var sb strings.Builder
	for _, item := range items {
		switch item.Speaker {
		case "you":
			sb.WriteString("▌ ")
			sb.WriteString(composerStyleBold.Render("you"))
			sb.WriteString("\n")
			for _, line := range strings.Split(item.Text, "\n") {
				sb.WriteString("▌ ")
				sb.WriteString(line)
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		case "orbit":
			sb.WriteString("▌ ")
			sb.WriteString(titleStyle.Render("orbit"))
			sb.WriteString("\n")
			// Render markdown for assistant messages.
			md, err := renderMarkdownWith(item.Text, renderer)
			if err == nil {
				for _, line := range strings.Split(strings.TrimSuffix(md, "\n"), "\n") {
					sb.WriteString("▌ ")
					sb.WriteString(line)
					sb.WriteString("\n")
				}
			} else {
				for _, line := range strings.Split(item.Text, "\n") {
					sb.WriteString("▌ ")
					sb.WriteString(line)
					sb.WriteString("\n")
				}
			}
			sb.WriteString("\n")
		case "tool":
			sb.WriteString("  ⚡ ")
			sb.WriteString(dimStyle.Render(item.Text))
			sb.WriteString("\n\n")
		case "system":
			sb.WriteString(dimStyle.Render(item.Text))
			sb.WriteString("\n\n")
		}
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

// renderMarkdown renders markdown text via glamour.
func renderMarkdown(text string) (string, error) {
	return renderMarkdownWith(text, nil)
}

func renderMarkdownWith(text string, renderer *glamour.TermRenderer) (string, error) {
	r := renderer
	if r == nil {
		var err error
		r, err = glamour.NewTermRenderer(
			glamour.WithAutoStyle(),
			glamour.WithWordWrap(80),
		)
		if err != nil {
			return text, err
		}
	}
	out, err := r.Render(text)
	if err != nil {
		return text, err
	}
	return out, nil
}

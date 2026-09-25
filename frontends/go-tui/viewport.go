// Viewport — the conversation transcript. A scrollable pane with speaker
// gutters, markdown rendering, and auto-scroll to bottom.

package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

type Viewport struct {
	viewport.Model
	renderer *glamour.TermRenderer
}

func NewViewport() Viewport {
	v := viewport.New(60, 20)
	v.Style = paneStyle
	r, _ := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(78),
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
// markdown for assistant messages.
func renderTranscript(items []TranscriptItem) string {
	return renderTranscriptWith(items, nil)
}

func renderTranscriptWith(items []TranscriptItem, renderer *glamour.TermRenderer) string {
	var sb strings.Builder
	for _, item := range items {
		switch item.Speaker {
		case "you":
			sb.WriteString(userGutter.Render("▌ "))
			sb.WriteString(userLabelStyle.Render("you"))
			sb.WriteString("\n")
			for _, line := range strings.Split(item.Text, "\n") {
				sb.WriteString(userGutter.Render("▌ "))
				sb.WriteString(lipgloss.NewStyle().Foreground(text).Render(line))
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		case "orbit":
			sb.WriteString(orbitGutter.Render("▌ "))
			sb.WriteString(orbitLabelStyle.Render("orbit"))
			sb.WriteString("\n")
			md, err := renderMarkdownWith(item.Text, renderer)
			if err == nil {
				for _, line := range strings.Split(strings.TrimSuffix(md, "\n"), "\n") {
					sb.WriteString(orbitGutter.Render("▌ "))
					sb.WriteString(line)
					sb.WriteString("\n")
				}
			} else {
				for _, line := range strings.Split(item.Text, "\n") {
					sb.WriteString(orbitGutter.Render("▌ "))
					sb.WriteString(lipgloss.NewStyle().Foreground(text).Render(line))
					sb.WriteString("\n")
				}
			}
			sb.WriteString("\n")
		case "tool":
			sb.WriteString("  ")
			sb.WriteString(toolLabelStyle.Render("⚡ "+item.Text))
			sb.WriteString("\n\n")
		case "system":
			sb.WriteString(systemLabelStyle.Render(item.Text))
			sb.WriteString("\n\n")
		}
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

func renderMarkdown(text string) (string, error) {
	return renderMarkdownWith(text, nil)
}

func renderMarkdownWith(text string, renderer *glamour.TermRenderer) (string, error) {
	r := renderer
	if r == nil {
		var err error
		r, err = glamour.NewTermRenderer(
			glamour.WithAutoStyle(),
			glamour.WithWordWrap(78),
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

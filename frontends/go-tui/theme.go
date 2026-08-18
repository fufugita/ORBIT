// Theme — lipgloss styles for the ORBIT Bubble Tea harness.
// Brand: pastel pink + Miku blue + white. Every style reads from here.

package main

import "github.com/charmbracelet/lipgloss"

// Colors (ORBIT brand).
var (
	accent         = lipgloss.Color("#FFB3D9") // pastel pink
	accentBright   = lipgloss.Color("#FFC9E6") // brighter pink
	accentDim      = lipgloss.Color("#B87AA0") // dim pink
	composer       = lipgloss.Color("#A0D8EF") // pastel blue
	composerDim    = lipgloss.Color("#6FA8C7") // dim pastel blue
	text           = lipgloss.Color("#E0E0E0") // white
	dim            = lipgloss.Color("#888888") // gray
	codeBg         = lipgloss.Color("#1E1E28") // dark navy
	codeFg         = lipgloss.Color("#78DCE8") // light cyan
	errColor       = lipgloss.Color("#FF5555") // red
	successColor   = lipgloss.Color("#50C878") // green
	warningColor   = lipgloss.Color("#FFC832") // yellow
	paneDim        = lipgloss.Color("#3C3C48") // unfocused border
	mikuCyan       = lipgloss.Color("#39C5BB") // Miku cyan
	mikuCyanBright = lipgloss.Color("#7FE3D9")
	statusBg       = lipgloss.Color("#1A1A24")
)

// Styles.
var (
	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(paneDim).
			Padding(0, 1)

	focusedPaneStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(accent).
				Padding(0, 1).
				Bold(true)

	statusStyle = lipgloss.NewStyle().
			Foreground(text).
			Background(statusBg).
			Padding(0, 1)

	dimStyle = lipgloss.NewStyle().Foreground(dim)

	titleStyle = lipgloss.NewStyle().
			Foreground(accent).
			Bold(true)

	composerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(composer).
			Padding(0, 1)

	composerFocusedStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(mikuCyan).
				Padding(0, 1)

	logoAccent   = lipgloss.NewStyle().Foreground(accent).Bold(true)
	logoComposer = lipgloss.NewStyle().Foreground(composer).Bold(true)
	logoDim      = lipgloss.NewStyle().Foreground(dim)

	accentStyleBold   = lipgloss.NewStyle().Foreground(accent).Bold(true)
	composerStyleBold = lipgloss.NewStyle().Foreground(composer).Bold(true)

	spinnerStyle = lipgloss.NewStyle().Foreground(composer)

	// Progress bar (streaming indicator).
	progressStyle = lipgloss.NewStyle().
			Foreground(mikuCyan).
			Background(lipgloss.Color("#2A2A3A"))

	// Table (Tasks pane).
	tableHeaderStyle = lipgloss.NewStyle().
				Foreground(accent).
				Bold(true).
				Padding(0, 1)

	tableCellStyle = lipgloss.NewStyle().
			Padding(0, 1)

	// Help (keybindings).
	helpStyle = lipgloss.NewStyle().
			Foreground(dim).
			Padding(0, 1)

	// Error toast.
	errorStyle = lipgloss.NewStyle().
			Foreground(errColor).
			Bold(true)

	// Empty state.
	emptyStyle = lipgloss.NewStyle().
			Foreground(dim).
			Italic(true)
)

// lipStyle wraps a pane body in the appropriate pane style.
func lipStyle(w int) lipgloss.Style {
	if w <= 0 {
		w = 10
	}
	return paneStyle.Width(w)
}

// focusStyle returns the pane style for a focused/unfocused state.
func focusStyle(focused bool) lipgloss.Style {
	if focused {
		return focusedPaneStyle
	}
	return paneStyle
}

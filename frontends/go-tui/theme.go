// Theme — ORBIT brand colors and lipgloss styles.
// Pastel pink + Miku blue + white on a dark navy background.
// Every component reads from here; no hardcoded colors elsewhere.

package main

import "github.com/charmbracelet/lipgloss"

// ── Color palette ────────────────────────────────────────────────────────────

// Brand colors. The accent is a warm pastel pink; the composer/secondary
// is a cool pastel blue (Miku blue). Together they give ORBIT its identity.
var (
	// Primary accent — pink. Used for the logo, focused borders, titles.
	accent       = lipgloss.Color("#FF79C6") // Dracula pink — vivid, visible
	accentBright = lipgloss.Color("#FFB3D9") // lighter pink for highlights
	accentDim    = lipgloss.Color("#B87AA0") // muted pink for unfocused

	// Secondary — blue. Used for the composer, user messages, links.
	composer    = lipgloss.Color("#8BE9FD") // Dracula cyan — bright, readable
	composerDim = lipgloss.Color("#6272A4") // dim blue-gray for unfocused

	// Neutrals
	text     = lipgloss.Color("#F8F8F2") // near-white
	dim      = lipgloss.Color("#6272A4") // muted blue-gray
	bg       = lipgloss.Color("#282A36") // Dracula bg — dark navy
	bgDarker = lipgloss.Color("#21222C") // darker for status bar
	bgPane   = lipgloss.Color("#2B2D3E") // slightly lighter for panes

	// Semantic
	success = lipgloss.Color("#50FA7B") // green
	warning = lipgloss.Color("#F1FA8C") // yellow
	errColor = lipgloss.Color("#FF5555") // red

	// Code
	codeFg = lipgloss.Color("#BD93F9") // purple for inline code
	codeBg = lipgloss.Color("#343746") // dark slate for code blocks

	// Pane borders
	paneDim = lipgloss.Color("#44475A") // unfocused border
)

// ── Styles ───────────────────────────────────────────────────────────────────

// Pane styles — focused vs unfocused. The focused pane gets a bright accent
// border + bold title; unfocused gets a dim border. This is the primary
// focus indicator.
var (
	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(paneDim).
			Background(bgPane).
			Padding(0, 1)

	focusedPaneStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(accent).
				Background(bgPane).
				Padding(0, 1).
				Bold(true)

	// Status bar — dark bg, full width
	statusStyle = lipgloss.NewStyle().
			Foreground(text).
			Background(bgDarker).
			Padding(0, 1)

	// Composer — rounded box, blue border when focused
	composerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(composerDim).
			Background(bgPane).
			Padding(0, 1)

	composerFocusedStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(composer).
				Background(bgPane).
				Padding(0, 1)

	// Text styles
	dimStyle    = lipgloss.NewStyle().Foreground(dim)
	titleStyle  = lipgloss.NewStyle().Foreground(accent).Bold(true)
	boldStyle   = lipgloss.NewStyle().Bold(true)
	errorStyle  = lipgloss.NewStyle().Foreground(errColor).Bold(true)
	successStyle = lipgloss.NewStyle().Foreground(success)
	warnStyle   = lipgloss.NewStyle().Foreground(warning)

	// Speaker labels in the transcript
	userLabelStyle    = lipgloss.NewStyle().Foreground(composer).Bold(true)
	orbitLabelStyle   = lipgloss.NewStyle().Foreground(accent).Bold(true)
	systemLabelStyle  = lipgloss.NewStyle().Foreground(dim).Italic(true)
	toolLabelStyle    = lipgloss.NewStyle().Foreground(warning)

	// Gutter bars
	userGutter  = lipgloss.NewStyle().Foreground(composer)
	orbitGutter = lipgloss.NewStyle().Foreground(accent)

	// Code
	codeStyle = lipgloss.NewStyle().Foreground(codeFg).Background(codeBg)

	// Logo
	logoAccent   = lipgloss.NewStyle().Foreground(accent).Bold(true)
	logoComposer = lipgloss.NewStyle().Foreground(composer).Bold(true)
	logoDim      = lipgloss.NewStyle().Foreground(dim)
	logoStar     = lipgloss.NewStyle().Foreground(accentBright).Bold(true)

	// Spinner
	spinnerStyle = lipgloss.NewStyle().Foreground(composer)

	// Help bar
	helpStyle = lipgloss.NewStyle().Foreground(dim)
	helpKeyStyle = lipgloss.NewStyle().Foreground(accent).Bold(true)

	// Approval modal
	approvalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(warning).
			Background(bgDarker).
			Padding(1, 2)

	approvalButtonActive = lipgloss.NewStyle().
				Background(accent).
				Foreground(bg).
				Bold(true).
				Padding(0, 2)

	approvalButtonInactive = lipgloss.NewStyle().
				Foreground(dim).
				Padding(0, 2)

	// Table (Tasks pane)
	tableHeaderStyle = lipgloss.NewStyle().
				Foreground(accent).
				Bold(true).
				Padding(0, 1)

	tableCellStyle = lipgloss.NewStyle().Padding(0, 1)

	// Session list
	sessionActiveStyle = lipgloss.NewStyle().
				Foreground(success).
				Bold(true)

	sessionModelStyle = lipgloss.NewStyle().
				Foreground(dim)
)

// focusStyle returns the pane style for a focused/unfocused state.
func focusStyle(focused bool) lipgloss.Style {
	if focused {
		return focusedPaneStyle
	}
	return paneStyle
}

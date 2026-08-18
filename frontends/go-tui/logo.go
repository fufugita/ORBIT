// Orbital logo — rich animated ORBIT wordmark with gradient ring and pulsing star.

package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// 3-row block wordmark — denser and more polished than the original 2-row mark.
const (
	wordmarkTop = "╭─╮ ╭─╮ ╭─╮ ┬ ╭─╮"
	wordmarkMid = "│ │ ├┬╯ ├─┤ │  │ "
	wordmarkBot = "╰─╯ ┴╰─ ╰─╯ ┴  ┴ "
)

// Ring positions in an 8-row × 27-col grid, clockwise.
var orbitRing = [16][2]int{
	{0, 13}, {0, 18}, {1, 23}, {2, 26},
	{4, 26}, {6, 23}, {7, 18}, {7, 13},
	{7, 8}, {6, 3}, {4, 0}, {2, 0},
	{1, 3}, {0, 8}, {0, 10}, {0, 12},
}

var starFrames = []rune{'✹', '✦', '⋆', '✦'}
var ringGlyphs = []rune{'·', '◦', '•'}

// renderLogo draws the animated orbital logo. Height is exactly 8 rows; the
// main layout measures it with lipgloss.Height() and reserves that space.
func renderLogo(frame int, width ...int) string {
	w := 60
	if len(width) > 0 && width[0] > 0 {
		w = width[0]
	}

	rows := make([][]rune, 8)
	for i := range rows {
		rows[i] = []rune(strings.Repeat(" ", 27))
	}

	// Wordmark rows 2-4.
	place(rows, 2, 3, wordmarkTop)
	place(rows, 3, 3, wordmarkMid)
	place(rows, 4, 3, wordmarkBot)

	// Ring with gradient glyphs + moving pulsing star.
	starIdx := frame % len(orbitRing)
	for i, pos := range orbitRing {
		r, c := pos[0], pos[1]
		if i == starIdx {
			rows[r][c] = starFrames[frame%len(starFrames)]
		} else {
			distance := (i - starIdx + len(orbitRing)) % len(orbitRing)
			glyph := ringGlyphs[0]
			if distance <= 2 || distance >= len(orbitRing)-2 {
				glyph = ringGlyphs[2]
			} else if distance <= 5 || distance >= len(orbitRing)-5 {
				glyph = ringGlyphs[1]
			}
			rows[r][c] = glyph
		}
	}

	// Underline glow (subtle center trail).
	glow := "      ─ ─ ─  ORBIT  ─ ─ ─      "
	place(rows, 6, 0, glow)

	var lines []string
	for _, row := range rows {
		line := strings.TrimRight(string(row), " ")
		lines = append(lines, colorLogoLine(line))
	}
	block := strings.Join(lines, "\n")
	// Center WITHOUT trailing whitespace: lipgloss.Align(Center) pads with
	// trailing spaces that Bubble Tea's diff renderer treats as changes on
	// every star-orbit frame, causing rows to bleed below the view. Manual
	// centering with TrimRight keeps each frame byte-identical except the
	// star position.
	return centerBlock(block, w)
}

// centerBlock centers each line of a block to `width` using leading spaces
// only (no trailing padding), so the diff renderer sees stable lines.
// The pad is computed from the RAW (pre-ANSI) line length so the position is
// stable even when the star glyph changes the visible width.
func centerBlock(block string, width int) string {
	lines := strings.Split(block, "\n")
	for i, l := range lines {
		raw := stripANSI(l)
		pad := (width - len(raw)) / 2
		if pad > 0 {
			lines[i] = strings.Repeat(" ", pad) + l
		}
	}
	return strings.Join(lines, "\n")
}

// colorLogoLine applies a rich gradient by glyph class.
func colorLogoLine(line string) string {
	var sb strings.Builder
	for _, ch := range line {
		switch ch {
		case '╭', '╮', '╰', '╯', '─', '│', '├', '┬', '┴':
			sb.WriteString(logoComposer.Render(string(ch)))
		case '✹', '✦', '⋆':
			sb.WriteString(lipgloss.NewStyle().Foreground(accentBright).Bold(true).Render(string(ch)))
		case '•':
			sb.WriteString(lipgloss.NewStyle().Foreground(accent).Render(string(ch)))
		case '◦':
			sb.WriteString(lipgloss.NewStyle().Foreground(composer).Render(string(ch)))
		case '·':
			sb.WriteString(logoDim.Render(string(ch)))
		case 'O', 'R', 'B', 'I', 'T':
			sb.WriteString(accentStyleBold.Render(string(ch)))
		default:
			sb.WriteRune(ch)
		}
	}
	return sb.String()
}

// stripANSI removes ANSI escapes for visible-width measurement.
func stripANSI(s string) string {
	var sb strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func place(rows [][]rune, row, col int, word string) {
	i := 0
	for _, ch := range word {
		if row < len(rows) && col+i < len(rows[row]) {
			rows[row][col+i] = ch
		}
		i++
	}
}

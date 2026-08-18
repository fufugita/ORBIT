// orbit-go-tui — a professional Bubble Tea front-end for ORBIT.
//
// The Rust CLI spawns this binary as a child and talks over a Unix socket
// (newline-delimited JSON). stdin/stdout stay the real TTY so Bubble Tea
// owns rendering, input, and animation. The Rust core owns providers, ledger,
// trust, and tool execution.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Bridge ───────────────────────────────────────────────────────────────────

// Event is a JSON message from the Rust core.
type Event struct {
	Type           string `json:"type"`
	Model          string `json:"model,omitempty"`
	Provider       string `json:"provider,omitempty"`
	Session        string `json:"session,omitempty"`
	Text           string `json:"text,omitempty"`
	Output         string `json:"output,omitempty"`
	Name           string `json:"name,omitempty"`
	Summary        string `json:"summary,omitempty"`
	Ok             *bool  `json:"ok,omitempty"`
	Microcents     uint64 `json:"microcents,omitempty"`
	InputTokens    uint64 `json:"input_tokens,omitempty"`
	OutputTokens   uint64 `json:"output_tokens,omitempty"`
	CostMicrocents uint64 `json:"cost_microcents,omitempty"`
	Message        string `json:"message,omitempty"`
	CallID         string `json:"call_id,omitempty"`
	Verdict        string `json:"verdict,omitempty"`
}

// Action is a JSON message to the Rust core.
type Action struct {
	Type    string `json:"type"`
	Text    string `json:"text,omitempty"`
	CallID  string `json:"call_id,omitempty"`
	Verdict string `json:"verdict,omitempty"`
}

// conn is the Unix socket to the Rust core.
var conn net.Conn

// sendAction writes an action to the Rust bridge. Returns false on failure
// so callers can roll back UI state (restore the composer, stop the spinner)
// instead of silently losing input (M2/M8).
func sendAction(a Action) bool {
	if conn == nil {
		fmt.Fprintln(os.Stderr, "orbit-go-tui: sendAction: conn is nil")
		return false
	}
	b, _ := json.Marshal(a)
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		fmt.Fprintf(os.Stderr, "orbit-go-tui: sendAction write: %v\n", err)
		return false
	}
	return true
}

// ── Messages ────────────────────────────────────────────────────────────────

type eventMsg Event

// ── Focus ───────────────────────────────────────────────────────────────────

type Focus int

const (
	FocusSessions Focus = iota
	FocusChat
	FocusTasks
)

func (f Focus) next() Focus {
	return (f + 1) % 3
}

// ── Model ───────────────────────────────────────────────────────────────────

type Model struct {
	reader *bufio.Scanner

	identitySet bool
	model       string
	provider    string
	session     string
	transcript  []TranscriptItem
	streamBuf   string
	queued      []string
	toolPending map[string]ToolCall

	spinner  Spinner
	composer Composer
	viewport Viewport
	sessions SessionList
	tasks    TasksPane
	status   StatusBar
	help     HelpBar

	approval *ApprovalModal
	showHelp bool

	focus     Focus
	width     int
	height    int
	cancelled bool
}

// TranscriptItem is one rendered line in the conversation.
type TranscriptItem struct {
	Speaker string // "you" | "orbit" | "tool" | "system"
	Text    string
}

// ToolCall is a pending tool approval.
type ToolCall struct {
	CallID  string
	Name    string
	Summary string
}

func initialModel() Model {
	m := Model{
		toolPending: make(map[string]ToolCall),
		spinner:     NewSpinner(),
		composer:    NewComposer(),
		viewport:    NewViewport(),
		sessions:    NewSessionList(),
		tasks:       NewTasksPane(),
		status:      NewStatusBar(),
		help:        NewHelpBar(),
		focus:       FocusChat,
	}
	// Focus the composer synchronously so the initial model starts focused.
	// Init()'s Focus() cmd runs on a copy and the focus would be lost.
	m.composer.FocusNow()
	return m
}

// ── Init ────────────────────────────────────────────────────────────────────

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		readBridge(m.reader),
		m.spinner.Init(),
	)
}

// readBridge blocks on the JSON reader and emits events. This is a ONE-SHOT
// cmd: it reads exactly one frame and returns. The Update loop re-schedules it
// after each eventMsg, so exactly one reader is outstanding at a time — never
// two goroutines blocked on the same bufio.Scanner (that would corrupt the
// event stream).
func readBridge(scanner *bufio.Scanner) tea.Cmd {
	return func() tea.Msg {
		if scanner.Scan() {
			var ev Event
			if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				return eventMsg(Event{Type: "error", Message: "bad bridge frame: " + err.Error()})
			}
			return eventMsg(ev)
		}
		return tea.Quit()
	}
}

// ── Update ──────────────────────────────────────────────────────────────────

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Exact height budget (no overflow → no diff-bleed):
		//   logo 8 rows + 1 blank + body + 1 blank + composer 3
		//   + 1 blank + status 1 + 1 blank + help 1 = 16 + body.
		// The body panes each add 2 rows for their own borders, so the
		// viewport inner height is body-2.
		bodyH := msg.Height - 16
		if bodyH < 5 {
			bodyH = 5
		}
		leftW := msg.Width * 18 / 100
		centerW := msg.Width*62/100 - 2
		rightW := msg.Width * 20 / 100
		m.viewport.SetSize(centerW-2, bodyH-2)
		m.composer.SetSize(msg.Width - 4)
		m.sessions.SetSize(leftW-2, bodyH-2)
		m.tasks.SetSize(rightW-2, bodyH-2)
		return m, nil

	case tea.KeyMsg:
		if m.approval != nil {
			return m.approval.Update(m, msg)
		}
		if m.showHelp {
			switch msg.String() {
			case "q", "esc", "?", "ctrl+c":
				m.showHelp = false
			}
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c":
			if m.streamBuf != "" || len(m.transcript) > 0 {
				sendAction(Action{Type: "cancel"})
				m.cancelled = true
				m.streamBuf = ""
				m.spinner.Stop()
			}
			return m, nil
		case "ctrl+d":
			sendAction(Action{Type: "quit"})
			return m, tea.Quit
		case "tab":
			// Cycle focus.
			m.focus = m.focus.next()
			switch m.focus {
			case FocusSessions:
				m.composer.Blur()
			case FocusChat:
				cmds = append(cmds, m.composer.Focus())
			case FocusTasks:
				m.composer.Blur()
			}
			return m, tea.Batch(cmds...)
		case "1":
			m.focus = FocusSessions
			m.composer.Blur()
			return m, nil
		case "2":
			m.focus = FocusChat
			cmds = append(cmds, m.composer.Focus())
			return m, tea.Batch(cmds...)
		case "3":
			m.focus = FocusTasks
			m.composer.Blur()
			return m, nil
		case "?":
			m.showHelp = true
			return m, nil
		case "enter":
			// Only the chat pane submits. A stale draft must not be sent when
			// focus is on Sessions/Tasks (H1).
			if m.focus != FocusChat {
				return m, nil
			}
			// Command or prompt?
			if m.composer.IsCommand() {
				return m.runCommand(), nil
			}
			text := strings.TrimSpace(m.composer.Value())
			if text == "" {
				return m, nil
			}
			m.composer.SetValue("")
			if m.streamBuf != "" {
				m.queued = append(m.queued, text)
			} else {
				m.transcript = append(m.transcript, TranscriptItem{Speaker: "you", Text: text})
				if sendAction(Action{Type: "prompt", Text: text}) {
					m.spinner.Start()
				} else {
					// Bridge is dead — restore the draft and surface the error
					// instead of losing the prompt (M8).
					m.composer.SetValue(text)
					m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "error: bridge write failed"})
				}
			}
			m.viewport.SetContent(renderTranscriptWith(m.transcript, m.viewport.renderer))
			m.viewport.GotoBottom()
			return m, nil
		default:
			// Route to the focused component.
			switch m.focus {
			case FocusSessions:
				var cmd tea.Cmd
				m.sessions.Model, cmd = m.sessions.Model.Update(msg)
				return m, cmd
			case FocusTasks:
				var cmd tea.Cmd
				m.tasks.Model, cmd = m.tasks.Model.Update(msg)
				return m, cmd
			default:
				return m.composer.Update(m, msg)
			}
		}

	case eventMsg:
		ev := Event(msg)
		switch ev.Type {
		case "identity":
			m.model = ev.Model
			m.provider = ev.Provider
			m.session = ev.Session
			m.identitySet = true
			m.sessions.SetItems([]SessionItem{{
				ID:     ev.Session,
				Model:  ev.Model,
				Active: true,
			}})
		case "delta":
			m.streamBuf += ev.Text
			// Render partial output immediately. Previously deltas only mutated
			// streamBuf, so users saw a spinner until the final frame instead of
			// the promised live token stream.
			items := append([]TranscriptItem(nil), m.transcript...)
			if m.streamBuf != "" {
				items = append(items, TranscriptItem{Speaker: "orbit", Text: m.streamBuf})
			}
			m.viewport.SetContent(renderTranscriptWith(items, m.viewport.renderer))
			m.viewport.GotoBottom()
			m.status.SetCost(ev.Microcents, ev.InputTokens, ev.OutputTokens)
		case "tool_call_started":
			m.toolPending[ev.CallID] = ToolCall{CallID: ev.CallID, Name: ev.Name, Summary: ev.Summary}
			if m.approval == nil {
				m.approval = NewApprovalModal(ToolCall{CallID: ev.CallID, Name: ev.Name, Summary: ev.Summary})
			}
			// If a modal is already open, show the queued count in its footer
			// so concurrent tool calls are visible (M3).
			if m.approval != nil {
				m.approval.queued = len(m.toolPending) - 1
			}
		case "tool_call_finished":
			delete(m.toolPending, ev.CallID)
			// If the call in the current modal finished (e.g. timeout), close
			// the modal so the user can't approve a dead call (M4).
			if m.approval != nil && m.approval.call.CallID == ev.CallID {
				m.approval = nil
			}
		case "cost":
			m.status.SetCost(ev.Microcents, ev.InputTokens, ev.OutputTokens)
		case "finished":
			text := m.streamBuf
			if ev.Output != "" {
				text = ev.Output
			}
			if text != "" {
				m.transcript = append(m.transcript, TranscriptItem{Speaker: "orbit", Text: text})
			} else {
				// Bridge finished with no output — record it so the turn is
				// visible and the next queued prompt isn't sent invisibly (H3).
				m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "<no output>"})
			}
			if m.cancelled {
				m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "⏹ cancelled by operator"})
				m.cancelled = false
			}
			m.streamBuf = ""
			m.spinner.Stop()
			if len(m.queued) > 0 {
				next := m.queued[0]
				m.queued = m.queued[1:]
				m.transcript = append(m.transcript, TranscriptItem{Speaker: "you", Text: next})
				sendAction(Action{Type: "prompt", Text: next})
				m.spinner.Start()
			}
			m.viewport.SetContent(renderTranscriptWith(m.transcript, m.viewport.renderer))
			m.viewport.GotoBottom()
		case "error":
			m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "error: " + ev.Message})
			m.spinner.Stop()
			m.viewport.SetContent(renderTranscriptWith(m.transcript, m.viewport.renderer))
			m.viewport.GotoBottom()
		case "cancelled":
			// Mark the transcript immediately and reset the flag — a later
			// `finished` (for a fresh turn) must not stamp a stale cancel (H2).
			m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "⏹ cancelled by operator"})
			m.cancelled = false
			m.streamBuf = ""
			m.spinner.Stop()
			m.viewport.SetContent(renderTranscriptWith(m.transcript, m.viewport.renderer))
			m.viewport.GotoBottom()
		}
		// Exactly one bridge read is outstanding at a time: schedule the next
		// read only after the current event was consumed.
		cmds = append(cmds, readBridge(m.reader))

	case spinner.TickMsg:
		m.spinner.Advance()
		var cmd tea.Cmd
		m.spinner.Model, cmd = m.spinner.Model.Update(msg)
		cmds = append(cmds, cmd)
	}

	// readBridge is a one-shot cmd. eventMsg schedules the next read above;
	// other updates (keys, ticks, resize) must not schedule extra readers.
	return m, tea.Batch(cmds...)
}

// runCommand executes a "/" command.
func (m Model) runCommand() Model {
	cmdText := m.composer.CommandText()
	m.composer.SetValue("")
	parts := strings.Fields(cmdText)
	if len(parts) == 0 {
		return m
	}
	switch parts[0] {
	case "help", "?":
		m.showHelp = true
	case "clear":
		m.transcript = nil
		m.streamBuf = ""
		m.viewport.SetContent("")
	case "model":
		if len(parts) > 1 {
			m.model = parts[1]
			m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "switched model → " + parts[1]})
			m.viewport.SetContent(renderTranscript(m.transcript))
		}
	case "provider":
		if len(parts) > 1 {
			m.provider = parts[1]
			m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "switched provider → " + parts[1]})
			m.viewport.SetContent(renderTranscript(m.transcript))
		}
	case "sessions":
		m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "session: " + m.session})
		m.viewport.SetContent(renderTranscript(m.transcript))
	case "cancel":
		sendAction(Action{Type: "cancel"})
		m.cancelled = true
		m.streamBuf = ""
		m.spinner.Stop()
	case "quit", "exit":
		sendAction(Action{Type: "quit"})
	default:
		m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "unknown command: /" + parts[0]})
		m.viewport.SetContent(renderTranscript(m.transcript))
	}
	return m
}

// ── View ────────────────────────────────────────────────────────────────────

func (m Model) View() string {
	if m.approval != nil {
		// Sizes are set on a local copy (View is value-receiver), so renderApp
		// computes pane sizes from m.width/m.height instead of mutating the
		// shared model (H9).
		m2 := m
		m2.approval = nil
		base := m2.renderAppLocked()
		modal := m.approval.Render(m.width, m.height)
		return overlay(base, modal, m.width, m.height)
	}
	return m.renderAppLocked()
}

// renderAppLocked is the shared render body. It recomputes pane sizes from
// the last WindowSizeMsg rather than mutating the model (View must stay pure).
func (m *Model) renderAppLocked() string {
	var sb strings.Builder

	// Header: orbital logo (animated), measured height.
	sb.WriteString(renderLogo(m.spinner.Frame(), m.width))
	sb.WriteString("\n")

	// Body: three panes joined horizontally. Widths total <= terminal so no
	// pane is clipped; 1-cell gutters between.
	bodyWidth := m.width
	leftW := bodyWidth * 18 / 100
	centerW := bodyWidth * 62 / 100
	rightW := bodyWidth * 20 / 100
	// Reserve 2 columns for the gutters so the total fits the terminal.
	centerW = centerW - 2
	bodyH := m.height - 16

	m.viewport.SetSize(centerW-2, bodyH-2)
	m.sessions.SetSize(leftW-2, bodyH-2)
	m.tasks.SetSize(rightW-2, bodyH-2)

	left := m.sessions.Render()
	center := m.viewport.Render()
	right := m.tasks.Render()
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, " ", center, " ", right))
	sb.WriteString("\n")

	// Queue summary (kept inside the composer line budget).
	if len(m.queued) > 0 {
		sb.WriteString(dimStyle.Render(fmt.Sprintf("⏳ %d queued", len(m.queued))))
		sb.WriteString(" ")
	}

	// Composer (3 rows including rounded border).
	sb.WriteString(m.composer.Render())

	// Status bar (spinner state includes streaming).
	sb.WriteString("\n")
	sb.WriteString(m.status.Render(m.model, m.provider, m.session, m.spinner.Running(), m.streamBuf != ""))

	// Help bar.
	sb.WriteString("\n")
	sb.WriteString(m.help.Render())

	if m.showHelp {
		sb.WriteString("\n\n")
		sb.WriteString(m.help.RenderFull())
	}

	// Pad to exactly the terminal height so Bubble Tea's diff renderer has
	// no rows below the content to write changed lines into (prevents the
	// star-orbit bleed).
	out := sb.String()
	rows := strings.Count(out, "\n") + 1
	if rows < m.height {
		out += strings.Repeat("\n", m.height-rows)
	}
	return out
}

// overlay centers the modal on top of the base view.
func overlay(base, modal string, w, h int) string {
	baseLines := strings.Split(base, "\n")
	modalLines := strings.Split(modal, "\n")
	startY := (len(baseLines) - len(modalLines)) / 2
	if startY < 0 {
		startY = 0
	}
	startX := (w - maxLineWidth(modalLines)) / 2
	if startX < 0 {
		startX = 0
	}
	for i, line := range modalLines {
		row := startY + i
		if row >= len(baseLines) {
			break
		}
		baseLines[row] = padRight(baseLines[row], w)
		r := []rune(baseLines[row])
		m := []rune(line)
		for j, ch := range m {
			if startX+j < len(r) {
				r[startX+j] = ch
			}
		}
		baseLines[row] = string(r)
	}
	return strings.Join(baseLines, "\n")
}

func maxLineWidth(lines []string) int {
	max := 0
	for _, l := range lines {
		if len(l) > max {
			max = len(l)
		}
	}
	return max
}

func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ── Main ────────────────────────────────────────────────────────────────────

func main() {
	sockPath := os.Getenv("ORBIT_GO_SOCKET")
	if sockPath == "" {
		fmt.Fprintln(os.Stderr, "orbit-go-tui: ORBIT_GO_SOCKET not set")
		os.Exit(1)
	}
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "orbit-go-tui: connect socket: %v\n", err)
		os.Exit(1)
	}
	conn = c

	scanner := bufio.NewScanner(c)
	// 16 MB max line — large LLM outputs (full code blocks, long replies)
	// must not terminate the TUI with bufio.ErrTooLong (H7).
	scanner.Buffer(make([]byte, 4096), 16*1024*1024)

	m := initialModel()
	m.reader = scanner

	p := tea.NewProgram(m, tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "orbit-go-tui: %v\n", err)
		os.Exit(1)
	}
}

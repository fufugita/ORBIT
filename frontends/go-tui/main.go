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
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Bridge ───────────────────────────────────────────────────────────────────

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

type Action struct {
	Type    string `json:"type"`
	Text    string `json:"text,omitempty"`
	CallID  string `json:"call_id,omitempty"`
	Verdict string `json:"verdict,omitempty"`
}

var conn net.Conn

func sendAction(a Action) bool {
	if conn == nil {
		return false
	}
	b, _ := json.Marshal(a)
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return false
	}
	return true
}

// ── Messages ────────────────────────────────────────────────────────────────

type eventMsg Event
type tickMsg struct{}

// ── Focus ───────────────────────────────────────────────────────────────────

type Focus int

const (
	FocusSessions Focus = iota
	FocusChat
	FocusTasks
)

func (f Focus) next() Focus  { return (f + 1) % 3 }
func (f Focus) prev() Focus  { return (f + 2) % 3 }
func (f Focus) String() string {
	switch f {
	case FocusSessions:
		return "Sessions"
	case FocusChat:
		return "Chat"
	case FocusTasks:
		return "Tasks"
	}
	return "?"
}

// ── Model ───────────────────────────────────────────────────────────────────

type Model struct {
	reader *bufio.Scanner

	model    string
	provider string
	session  string

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

type TranscriptItem struct {
	Speaker string
	Text    string
}

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
	m.composer.FocusNow()
	return m
}

// ── Init ────────────────────────────────────────────────────────────────────

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		readBridge(m.reader),
		m.spinner.Init(),
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg {
		return tickMsg{}
	})
}

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
		return m, nil

	case tickMsg:
		m.spinner.Advance()
		cmds = append(cmds, tickCmd())

	case spinnerTickMsg:
		m.spinner.Advance()
		cmds = append(cmds, m.spinner.tick())

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
		case "shift+tab":
			m.focus = m.focus.prev()
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
			m.showHelp = !m.showHelp
			return m, nil
		case "enter":
			if m.focus != FocusChat {
				return m, nil
			}
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
					m.composer.SetValue(text)
					m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "error: bridge write failed"})
				}
			}
			return m, nil
		default:
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
			m.sessions.SetItems([]SessionItem{{
				ID:     ev.Session,
				Model:  ev.Model,
				Active: true,
			}})
		case "delta":
			m.streamBuf += ev.Text
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
			if m.approval != nil {
				m.approval.queued = len(m.toolPending) - 1
			}
		case "tool_call_finished":
			delete(m.toolPending, ev.CallID)
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
			m.transcript = append(m.transcript, TranscriptItem{Speaker: "system", Text: "⏹ cancelled by operator"})
			m.cancelled = false
			m.streamBuf = ""
			m.spinner.Stop()
			m.viewport.SetContent(renderTranscriptWith(m.transcript, m.viewport.renderer))
			m.viewport.GotoBottom()
		}
		cmds = append(cmds, readBridge(m.reader))
	}

	return m, tea.Batch(cmds...)
}

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
	if m.width == 0 || m.height == 0 {
		return "" // wait for WindowSizeMsg before rendering
	}

	// Layout budget:
	//   logo: 4 rows (3 wordmark + 1 rule)
	//   1 blank
	//   body: fill
	//   1 blank
	//   composer: 3 rows (border + content + border)
	//   status: 1 row
	//   help: 1 row
	// Total fixed: 10
	logoH := logoHeight(m.width)
	fixedH := logoH + 1 + 3 + 1 + 1 + 1 // logo + gap + composer + gap + status + help
	bodyH := m.height - fixedH
	if bodyH < 5 {
		bodyH = 5
	}

	// Widths: 18% / 62% / 20% with 1-cell gutters
	leftW := m.width * 18 / 100
	centerW := m.width * 62 / 100
	rightW := m.width * 20 / 100
	// Adjust for gutters
	if leftW+centerW+rightW+2 > m.width {
		centerW = m.width - leftW - rightW - 2
	}
	if centerW < 20 {
		centerW = 20
	}

	// ── Build the view ────────────────────────────────────────────────────────
	var sb strings.Builder

	// Logo header
	sb.WriteString(renderLogo(m.spinner.index, m.width))
	sb.WriteString("\n\n")

	// Body: three panes with focus-aware borders
	m.viewport.SetSize(centerW-4, bodyH-2)
	m.sessions.SetSize(leftW-2, bodyH-2)
	m.tasks.SetSize(rightW-2, bodyH-2)

	// Render each pane with its focus style
	left := focusStyle(m.focus == FocusSessions).
		Width(leftW - 2).
		Height(bodyH).
		Render(m.sessions.Render())
	center := focusStyle(m.focus == FocusChat).
		Width(centerW - 2).
		Height(bodyH).
		Render(m.viewport.Render())
	right := focusStyle(m.focus == FocusTasks).
		Width(rightW - 2).
		Height(bodyH).
		Render(m.tasks.Render())

	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, " ", center, " ", right))
	sb.WriteString("\n")

	// Queue indicator
	if len(m.queued) > 0 {
		sb.WriteString(warnStyle.Render(fmt.Sprintf("  ⏳ %d queued", len(m.queued))))
		sb.WriteString("\n")
	}

	// Composer
	m.composer.SetSize(m.width)
	sb.WriteString(m.composer.Render())
	sb.WriteString("\n")

	// Status bar
	sb.WriteString(statusStyle.Width(m.width).Render(
		m.status.Render(m.model, m.provider, m.session, m.spinner.Running(), m.streamBuf != ""),
	))
	sb.WriteString("\n")

	// Help bar
	sb.WriteString(helpStyle.Width(m.width).Render(m.help.Render()))

	// Help overlay
	if m.showHelp {
		sb.WriteString("\n")
		sb.WriteString(m.help.RenderFull())
	}

	// Approval modal overlay
	if m.approval != nil {
		base := sb.String()
		modal := m.approval.Render(m.width, m.height)
		return overlay(base, modal, m.width, m.height)
	}

	return sb.String()
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
		mr := []rune(line)
		for j, ch := range mr {
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
	scanner.Buffer(make([]byte, 4096), 16*1024*1024)

	m := initialModel()
	m.reader = scanner

	p := tea.NewProgram(m, tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "orbit-go-tui: %v\n", err)
		os.Exit(1)
	}
}

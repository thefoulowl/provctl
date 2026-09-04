package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/thefoulowl/provctl/internal/store"
)

// pollInterval controls how often top re-reads the store. provctl watch
// itself batches writes every 150ms (see internal/cli/watch.go), so
// polling much faster than that would just show the same data twice.
const pollInterval = 500 * time.Millisecond

// activityBacklog bounds how many feed lines top *displays and keeps in
// memory* — this is a live view, not a substitute for `provctl trace` or
// `timeline`, which query the full history.
const activityBacklog = 500

// activityCatchUpLimit bounds each incremental poll query, but must not be
// the same small number as activityBacklog: a single chatty process (a
// busy browser polling /proc, observed in testing generating 1000+ events
// in well under a second) can outpace a 500-row-per-tick fetch, so the
// poll cursor would fall further behind every tick and the feed would
// permanently lag "now" instead of catching up between bursts. This limit
// exists only to cap a single query's worst case, not to throttle how
// current the view can get; what's actually *shown* stays bounded by
// activityBacklog regardless of how many rows a poll fetches.
const activityCatchUpLimit = 50_000

var (
	borderStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240"))
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	footerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	kindColor   = map[string]lipgloss.Color{
		"FORK":    lipgloss.Color("36"),
		"EXEC":    lipgloss.Color("32"),
		"EXIT":    lipgloss.Color("31"),
		"OPEN":    lipgloss.Color("34"),
		"CONNECT": lipgloss.Color("35"),
	}
)

func runTop(args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath(), "sqlite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	m := newTopModel(st, *dbPath)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

type topModel struct {
	store     *store.Store
	dbPath    string
	startedAt time.Time

	width, height int
	focusRight    bool // which pane arrow keys / j,k scroll

	tree     viewport.Model
	feed     viewport.Model
	feedLine []string // rendered activity lines, capped at activityBacklog

	cursor    int64 // highest activity_log id seen so far
	procCount int
	err       error
}

func newTopModel(st *store.Store, dbPath string) topModel {
	return topModel{
		store:     st,
		dbPath:    dbPath,
		startedAt: time.Now(),
		tree:      viewport.New(0, 0),
		feed:      viewport.New(0, 0),
	}
}

func (m topModel) Init() tea.Cmd {
	return m.pollCmd()
}

type pollResultMsg struct {
	procLines []string
	procCount int
	newEvents []store.ActivityEntry
	err       error
}

func (m topModel) pollCmd() tea.Cmd {
	return tea.Tick(pollInterval, func(time.Time) tea.Msg {
		procs, err := m.store.AllProcesses(true)
		if err != nil {
			return pollResultMsg{err: fmt.Errorf("query processes: %w", err)}
		}

		var newEvents []store.ActivityEntry
		if m.cursor == 0 {
			newEvents, err = m.store.RecentActivity(activityBacklog)
		} else {
			newEvents, err = m.store.ActivityAfter(m.cursor, activityCatchUpLimit)
		}
		if err != nil {
			return pollResultMsg{err: fmt.Errorf("query activity: %w", err)}
		}

		return pollResultMsg{
			procLines: renderProcessTree(procs),
			procCount: len(procs),
			newEvents: newEvents,
		}
	})
}

func (m topModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		paneW, paneH := m.paneSize()
		m.tree.Width, m.tree.Height = paneW, paneH
		m.feed.Width, m.feed.Height = paneW, paneH
		return m, nil

	case pollResultMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, m.pollCmd()
		}
		m.err = nil
		m.procCount = msg.procCount
		m.tree.SetContent(strings.Join(msg.procLines, "\n"))

		if len(msg.newEvents) > 0 {
			atBottom := m.feed.AtBottom()
			for _, e := range msg.newEvents {
				m.feedLine = append(m.feedLine, renderActivityLine(e, m.feed.Width))
				m.cursor = e.ID
			}
			if over := len(m.feedLine) - activityBacklog; over > 0 {
				m.feedLine = m.feedLine[over:]
			}
			m.feed.SetContent(strings.Join(m.feedLine, "\n"))
			if atBottom {
				m.feed.GotoBottom()
			}
		}
		return m, m.pollCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.focusRight = !m.focusRight
			return m, nil
		}
		var cmd tea.Cmd
		if m.focusRight {
			m.feed, cmd = m.feed.Update(msg)
		} else {
			m.tree, cmd = m.tree.Update(msg)
		}
		return m, cmd
	}
	return m, nil
}

// paneSize computes each side-by-side pane's inner content size, accounting
// for the border (2 cols + 2 rows per pane) and the header/footer lines.
func (m topModel) paneSize() (width, height int) {
	const (
		headerLines = 2
		footerLines = 2
		borderCols  = 2
		borderRows  = 2
	)
	width = m.width/2 - borderCols
	height = m.height - headerLines - footerLines - borderRows
	if width < 1 {
		width = 1
	}
	if height < 1 {
		height = 1
	}
	return width, height
}

func (m topModel) View() string {
	if m.width == 0 {
		return "starting…"
	}

	header := titleStyle.Render("provctl top") + "  " +
		footerStyle.Render(fmt.Sprintf("db=%s", m.dbPath))

	treeFocus, feedFocus := " Processes ", " Live Activity "
	treeBorder, feedBorder := borderStyle, borderStyle
	if m.focusRight {
		feedBorder = feedBorder.BorderForeground(lipgloss.Color("39"))
	} else {
		treeBorder = treeBorder.BorderForeground(lipgloss.Color("39"))
	}

	panes := lipgloss.JoinHorizontal(lipgloss.Top,
		treeBorder.Render(treeFocus+"\n"+m.tree.View()),
		feedBorder.Render(feedFocus+"\n"+m.feed.View()),
	)

	status := fmt.Sprintf("processes: %d  uptime: %s", m.procCount, time.Since(m.startedAt).Round(time.Second))
	if m.err != nil {
		status = fmt.Sprintf("%s  error: %v", status, m.err)
	}
	footer := footerStyle.Render(status) + "\n" +
		footerStyle.Render("tab: switch pane  ↑/↓,j/k: scroll  q: quit")

	return header + "\n" + panes + "\n" + footer
}

// renderActivityLine formats one feed entry. availWidth is the feed pane's
// content width (0 before the first WindowSizeMsg arrives, in which case
// no truncation is applied — the initial resize-triggered poll fixes this
// immediately after).
//
// The free-text portion (e.Text — usually a path) is truncated from the
// *left*, keeping its tail, rather than left to bubbles/viewport's own
// per-line MaxWidth clipping, which truncates from the right: for a path
// like /home/user/.cache/very/deeply/nested/dir/payload.exe, a right-clip
// keeps the directory prefix and drops exactly the filename — the one
// detail a forensics view can't afford to hide.
func renderActivityLine(e store.ActivityEntry, availWidth int) string {
	ts := e.At.Format("15:04:05")
	color, ok := kindColor[e.Kind]
	if !ok {
		color = lipgloss.Color("15")
	}
	label := lipgloss.NewStyle().Foreground(color).Render(fmt.Sprintf("%-7s", e.Kind))
	prefix := fmt.Sprintf("%s %s ", footerStyle.Render(ts), label)

	text := e.Text
	if availWidth > 0 {
		if room := availWidth - lipgloss.Width(prefix); room > 1 && lipgloss.Width(text) > room {
			runes := []rune(text)
			// keep the last (room-1) runes, room for a leading ellipsis.
			// Clamped: a rune count can be smaller than lipgloss.Width for
			// wide (multi-cell) characters, so this isn't always exact,
			// but it can never index negatively.
			keep := room - 1
			if keep > len(runes) {
				keep = len(runes)
			}
			text = "…" + string(runes[len(runes)-keep:])
		}
	}

	return prefix + text
}

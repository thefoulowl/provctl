package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/thefoulowl/provctl/internal/store"
)

func TestRenderActivityLinePreservesTailNotPrefix(t *testing.T) {
	// A long path's filename — the forensically interesting part — must
	// survive truncation. Right-truncation (bubbles/viewport's own
	// per-line MaxWidth clipping) would keep the directory prefix and cut
	// exactly this off; renderActivityLine must not reproduce that bug.
	e := store.ActivityEntry{
		At:   time.Unix(0, 0),
		Kind: "OPEN",
		PID:  100,
		Text: "bash (pid 100) opened /home/user/.cache/very/deeply/nested/directory/structure/payload.exe",
	}

	line := renderActivityLine(e, 40)
	plain := stripANSI(line)

	if !strings.Contains(plain, "payload.exe") {
		t.Errorf("truncated line dropped the filename: %q", plain)
	}
	if strings.Contains(plain, "/home/user/.cache") {
		t.Errorf("line wasn't actually truncated (still contains the far prefix): %q", plain)
	}
	if !strings.Contains(plain, "…") {
		t.Errorf("truncated line has no ellipsis marker: %q", plain)
	}
}

func TestRenderActivityLineNoTruncationWhenItFits(t *testing.T) {
	e := store.ActivityEntry{At: time.Unix(0, 0), Kind: "EXIT", PID: 1, Text: "sh (pid 1) exited (code 0)"}
	line := renderActivityLine(e, 200)
	plain := stripANSI(line)
	if strings.Contains(plain, "…") {
		t.Errorf("short line was truncated unnecessarily: %q", plain)
	}
	if !strings.Contains(plain, "sh (pid 1) exited (code 0)") {
		t.Errorf("short line's text was altered: %q", plain)
	}
}

func TestRenderActivityLineZeroWidthSkipsTruncation(t *testing.T) {
	// availWidth == 0 means no WindowSizeMsg has arrived yet; must not
	// truncate (or panic) in that window.
	e := store.ActivityEntry{At: time.Unix(0, 0), Kind: "OPEN", PID: 1, Text: strings.Repeat("x", 500)}
	line := renderActivityLine(e, 0)
	if !strings.Contains(line, strings.Repeat("x", 500)) {
		t.Error("availWidth=0 should not truncate the text")
	}
}

func TestRenderActivityLineExtremelyNarrowPaneDoesNotPanic(t *testing.T) {
	e := store.ActivityEntry{At: time.Unix(0, 0), Kind: "CONNECT", PID: 1, Text: "curl (pid 1) connected to 1.2.3.4:443"}
	for _, w := range []int{0, 1, 2, 5, 10, 15, 20} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("renderActivityLine(width=%d) panicked: %v", w, r)
				}
			}()
			renderActivityLine(e, w)
		}()
	}
}

func TestRenderActivityLineUnknownKindDoesNotPanic(t *testing.T) {
	e := store.ActivityEntry{At: time.Unix(0, 0), Kind: "SOMETHING_NEW", PID: 1, Text: "x"}
	line := renderActivityLine(e, 80)
	if !strings.Contains(stripANSI(line), "SOMETHING_NEW") {
		t.Errorf("unknown kind label missing from line: %q", line)
	}
}

func stripANSI(s string) string {
	// lipgloss.Width already understands how to measure past ANSI codes,
	// but for content assertions we want the plain text; a minimal strip
	// is enough here since these tests only assert Contains on literal
	// runs of characters that never overlap coloring.
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestPaneSizeNeverGoesNegative(t *testing.T) {
	for _, size := range []struct{ w, h int }{
		{0, 0}, {1, 1}, {5, 3}, {200, 50},
	} {
		m := topModel{width: size.w, height: size.h}
		w, h := m.paneSize()
		if w < 1 || h < 1 {
			t.Errorf("paneSize() at terminal %dx%d = (%d, %d), want both >= 1", size.w, size.h, w, h)
		}
	}
}

func TestLipglossWidthSanity(t *testing.T) {
	// Guards the assumption renderActivityLine's room calculation depends
	// on: that Width() measures visible width, not byte length, so
	// embedded ANSI color codes don't get counted as visible characters.
	styled := lipgloss.NewStyle().Foreground(lipgloss.Color("32")).Render("EXEC")
	if got := lipgloss.Width(styled); got != 4 {
		t.Errorf("lipgloss.Width(%q) = %d, want 4 (ANSI codes must not count)", styled, got)
	}
}

// Package ui holds small presentation helpers shared by provctl's
// terminal-facing subcommands (the plain scrolling log in `watch`, and the
// `top` TUI).
package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// Enabled reports whether ANSI color should be used for w, honoring the
// NO_COLOR convention (https://no-color.org) and only coloring when w is
// actually a terminal — piping `watch` to a file or into systemd/journald
// must produce plain text, not escape codes.
func Enabled(f *os.File) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

const (
	colorCyan    = 36
	colorGreen   = 32
	colorRed     = 31
	colorBlue    = 34
	colorMagenta = 35
	colorGray    = 90
)

// Colorer applies (or, when disabled, does not apply) ANSI color to text.
// Construct one with Enabled and reuse it for a whole run rather than
// re-checking the terminal on every line.
type Colorer struct{ on bool }

func NewColorer(on bool) Colorer { return Colorer{on: on} }

func (c Colorer) code(code int, s string) string {
	if !c.on {
		return s
	}
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", code, s)
}

func (c Colorer) Fork(s string) string    { return c.code(colorCyan, s) }
func (c Colorer) Exec(s string) string    { return c.code(colorGreen, s) }
func (c Colorer) Exit(s string) string    { return c.code(colorRed, s) }
func (c Colorer) Open(s string) string    { return c.code(colorBlue, s) }
func (c Colorer) Connect(s string) string { return c.code(colorMagenta, s) }
func (c Colorer) Dim(s string) string     { return c.code(colorGray, s) }

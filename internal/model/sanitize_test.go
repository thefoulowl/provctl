package model

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// hasTerminalControl reports whether s still carries something a terminal could
// act on: a C0 control other than TAB, DEL, a C1 control, or an invalid byte
// (a lone 0x9B is an 8-bit CSI).
func hasTerminalControl(s string) bool {
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if (c < 0x20 && c != '\t') || c == 0x7f {
				return true
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || r <= 0x9f {
			return true
		}
		i += size
	}
	return false
}

// An unprivileged process controls comm (prctl(PR_SET_NAME)) and the exec/open
// path; neither may carry terminal control sequences into a decoded Event or
// its rendered line, or it could rewrite the `provctl watch` feed / drive the
// operator's terminal.
func TestDecodeNeutralizesTerminalControlBytes(t *testing.T) {
	raw := buildRecord(rawEvent{
		typ:      uint8(TypeExec),
		pid:      1337,
		comm:     "\x1b[2K\rsshd",                                      // CSI erase-line + CR
		filename: "/tmp/x/\x1b]0;PWNED\x07\x1b]52;c;cHduZWQ=\x07\x9bp", // OSC + a lone 8-bit CSI
	})

	ev, err := Decode(raw, Clock{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	for name, s := range map[string]string{"Comm": ev.Comm, "Filename": ev.Filename, "Describe()": ev.Describe()} {
		if hasTerminalControl(s) {
			t.Errorf("%s still contains a terminal control byte: %q", name, s)
		}
	}
	if !strings.Contains(ev.Comm, "sshd") || !strings.Contains(ev.Filename, "PWNED") {
		t.Errorf("printable content must be preserved: Comm=%q Filename=%q", ev.Comm, ev.Filename)
	}
}

func TestSanitizeDisplayPreservesValidText(t *testing.T) {
	// clean ASCII, embedded TAB, accented Latin (trailing byte lands in
	// 0x80..0x9f: À = C3 80), CJK, emoji, an already-present U+FFFD
	for _, s := range []string{"", "curl", "/usr/bin/curl", "a\tb", "ÀÉØ café", "日本語/payload", "run 🚀", "x�y"} {
		if got := SanitizeDisplay(s); got != s {
			t.Errorf("SanitizeDisplay(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestSanitizeDisplayNeutralizesControls(t *testing.T) {
	for _, s := range []string{
		"\x1b[31m", // ESC
		"a\x00b",   // NUL
		"a\nb",     // LF
		"a\rb",     // CR
		"\x07",     // BEL
		"\x7f",     // DEL
		"2K",      // C1 CSI as valid UTF-8 (C2 9B)
		"a\x9bb",   // C1 CSI as a lone invalid byte
		"\xc0\x80", // overlong NUL — must not slip through
	} {
		if got := SanitizeDisplay(s); hasTerminalControl(got) {
			t.Errorf("SanitizeDisplay(%q) still has a control byte: %q", s, got)
		}
	}
}

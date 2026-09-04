// Package model defines the userspace representation of provctl's capture
// events and the wire decoder for the raw bytes handed back by the BPF ring
// buffer. The byte layout here is a manual mirror of the C struct in
// internal/bpf/provctl.h — decoded by explicit offset rather than relying on
// Go struct field alignment matching C alignment, so the two can never
// silently drift apart without a hard error.
package model

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// Type identifies which BPF hook produced an Event.
type Type uint8

const (
	TypeExec     Type = 1
	TypeExit     Type = 2
	TypeFork     Type = 3
	TypeFileOpen Type = 4
	TypeConnect  Type = 5
)

func (t Type) String() string {
	switch t {
	case TypeExec:
		return "EXEC"
	case TypeExit:
		return "EXIT"
	case TypeFork:
		return "FORK"
	case TypeFileOpen:
		return "OPEN"
	case TypeConnect:
		return "CONNECT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
	}
}

const (
	afInet  = 2
	afInet6 = 10

	commLen     = 16
	filenameLen = 264

	// wireSize must match sizeof(struct event) in provctl.h, including the
	// compiler's trailing padding (the struct is 8-byte aligned due to the
	// leading u64, so its true size rounds up from 332 to 336).
	wireSize = 336

	offTimestamp = 0
	offPid       = 8
	offPpid      = 12
	offUid       = 16
	offGid       = 20
	offExitCode  = 24
	offDaddrV4   = 28
	offDaddrV6   = 32
	offDport     = 48
	offType      = 50
	offFamily    = 51
	offComm      = 52
	offFilename  = 52 + commLen
)

// Event is the decoded, Go-native form of a single capture record.
type Event struct {
	Time     time.Time
	Type     Type
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	ExitCode uint32
	Comm     string
	Filename string // EXEC / OPEN: resolved path
	DstIP    net.IP // CONNECT only
	DstPort  uint16 // CONNECT only
}

// Clock converts a BPF-reported monotonic timestamp (bpf_ktime_get_ns, which
// is CLOCK_MONOTONIC) into wall-clock time. Construct one at startup, before
// events start flowing, and reuse it for every decode.
type Clock struct {
	// wallAtMonoZero is the wall-clock instant corresponding to
	// monotonic clock reading 0.
	wallAtMonoZero time.Time
}

// NewClock samples CLOCK_MONOTONIC and the wall clock together so later
// bpf_ktime_get_ns() values can be converted to time.Time.
func NewClock(monotonicNowNs uint64, wallNow time.Time) Clock {
	return Clock{wallAtMonoZero: wallNow.Add(-time.Duration(monotonicNowNs))}
}

func (c Clock) ToWall(monotonicNs uint64) time.Time {
	return c.wallAtMonoZero.Add(time.Duration(monotonicNs))
}

// Decode parses one ring-buffer record into an Event.
func Decode(raw []byte, clock Clock) (Event, error) {
	if len(raw) < wireSize {
		return Event{}, fmt.Errorf("model: short event record: got %d bytes, want >= %d", len(raw), wireSize)
	}

	e := Event{
		Time:     clock.ToWall(binary.LittleEndian.Uint64(raw[offTimestamp:])),
		Type:     Type(raw[offType]),
		PID:      binary.LittleEndian.Uint32(raw[offPid:]),
		PPID:     binary.LittleEndian.Uint32(raw[offPpid:]),
		UID:      binary.LittleEndian.Uint32(raw[offUid:]),
		GID:      binary.LittleEndian.Uint32(raw[offGid:]),
		ExitCode: binary.LittleEndian.Uint32(raw[offExitCode:]),
		Comm:     sanitizeField(cString(raw[offComm : offComm+commLen])),
		Filename: sanitizeField(cString(raw[offFilename : offFilename+filenameLen])),
	}

	if e.Type == TypeConnect {
		e.DstPort = binary.LittleEndian.Uint16(raw[offDport:])
		switch raw[offFamily] {
		case afInet:
			e.DstIP = net.IPv4(raw[offDaddrV4], raw[offDaddrV4+1], raw[offDaddrV4+2], raw[offDaddrV4+3])
		case afInet6:
			ip := make(net.IP, 16)
			copy(ip, raw[offDaddrV6:offDaddrV6+16])
			e.DstIP = ip
		}
	}

	return e, nil
}

// sanitizeField neutralizes terminal control/escape bytes in kernel-supplied
// strings (comm, filename) before they can reach anywhere that renders as
// text: watch's live stdout, the SQLite store, and every read-only viewer
// that plays that store back (trace/timeline/ps/top). comm is attacker-set
// via prctl(PR_SET_NAME) or argv[0], and a path component can hold any byte
// except '/' and NUL — the kernel itself does not filter ESC, CR, or BEL —
// so an unprivileged process can otherwise inject ANSI/OSC sequences into a
// higher-privileged operator's terminal (this exact path was reported,
// reproduced, and credited: GHSA-7q6w-fvrx-6pqq).
//
// This only ever narrows what's displayed, never widens it: every C0
// control below 0x20 (tab excepted, which drives no terminal behavior) and
// every C1 control (0x80-0x9F) becomes U+FFFD. It does not touch the raw
// bytes stored anywhere else — this runs once, in Decode, before an Event
// exists at all, so there's no unsanitized copy to reach any sink from.
func sanitizeField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || (r >= 0x20 && r != 0x7f && !(r >= 0x80 && r <= 0x9f)) {
			return r
		}
		return '\uFFFD' // Unicode replacement character
	}, s)
}

// cString trims a fixed-width, NUL-padded C char array to a Go string.
// Searching the byte slice directly matters here: this runs twice per
// event (comm + filename), and converting to string first would copy all
// 264 filename bytes just to locate the terminator.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

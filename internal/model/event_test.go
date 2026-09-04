package model

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildRecord assembles a raw ring-buffer record the same way the eBPF side
// does, so these tests fail loudly if the Go offsets in event.go ever drift
// from the C struct in internal/bpf/provctl.h.
type rawEvent struct {
	timestampNs uint64
	pid, ppid   uint32
	uid, gid    uint32
	exitCode    uint32
	daddrV4     [4]byte
	daddrV6     [16]byte
	dport       uint16
	typ, family uint8
	comm        string
	filename    string
}

func buildRecord(r rawEvent) []byte {
	b := make([]byte, wireSize)
	binary.LittleEndian.PutUint64(b[offTimestamp:], r.timestampNs)
	binary.LittleEndian.PutUint32(b[offPid:], r.pid)
	binary.LittleEndian.PutUint32(b[offPpid:], r.ppid)
	binary.LittleEndian.PutUint32(b[offUid:], r.uid)
	binary.LittleEndian.PutUint32(b[offGid:], r.gid)
	binary.LittleEndian.PutUint32(b[offExitCode:], r.exitCode)
	copy(b[offDaddrV4:], r.daddrV4[:])
	copy(b[offDaddrV6:], r.daddrV6[:])
	binary.LittleEndian.PutUint16(b[offDport:], r.dport)
	b[offType] = r.typ
	b[offFamily] = r.family
	copy(b[offComm:offComm+commLen], r.comm)
	copy(b[offFilename:offFilename+filenameLen], r.filename)
	return b
}

// The layout constants must match `sizeof(struct event)` and the field
// offsets emitted by the C compiler for internal/bpf/provctl.h. These were
// verified against clang on x86_64; this test pins them so a change to
// provctl.h without a matching change here is caught immediately.
func TestWireLayoutConstants(t *testing.T) {
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"wireSize", wireSize, 336},
		{"offTimestamp", offTimestamp, 0},
		{"offPid", offPid, 8},
		{"offPpid", offPpid, 12},
		{"offUid", offUid, 16},
		{"offGid", offGid, 20},
		{"offExitCode", offExitCode, 24},
		{"offDaddrV4", offDaddrV4, 28},
		{"offDaddrV6", offDaddrV6, 32},
		{"offDport", offDport, 48},
		{"offType", offType, 50},
		{"offFamily", offFamily, 51},
		{"offComm", offComm, 52},
		{"offFilename", offFilename, 68},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (does it still match internal/bpf/provctl.h?)", c.name, c.got, c.want)
		}
	}
}

func TestDecodeExec(t *testing.T) {
	clock := NewClock(1_000_000_000, time.Unix(100, 0))
	raw := buildRecord(rawEvent{
		timestampNs: 2_000_000_000,
		pid:         4242,
		ppid:        1,
		uid:         1000,
		gid:         1000,
		typ:         uint8(TypeExec),
		comm:        "curl",
		filename:    "/usr/bin/curl",
	})

	ev, err := Decode(raw, clock)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if ev.Type != TypeExec {
		t.Errorf("Type = %v, want EXEC", ev.Type)
	}
	if ev.PID != 4242 || ev.PPID != 1 {
		t.Errorf("pid/ppid = %d/%d, want 4242/1", ev.PID, ev.PPID)
	}
	if ev.UID != 1000 || ev.GID != 1000 {
		t.Errorf("uid/gid = %d/%d, want 1000/1000", ev.UID, ev.GID)
	}
	if ev.Comm != "curl" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "curl")
	}
	if ev.Filename != "/usr/bin/curl" {
		t.Errorf("Filename = %q, want %q", ev.Filename, "/usr/bin/curl")
	}
	// monotonic 2s, sampled at monotonic 1s == wall 100s, so wall == 101s.
	if want := time.Unix(101, 0); !ev.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", ev.Time, want)
	}
}

func TestDecodeConnectIPv4(t *testing.T) {
	raw := buildRecord(rawEvent{
		typ:     uint8(TypeConnect),
		family:  afInet,
		pid:     10,
		daddrV4: [4]byte{185, 199, 109, 133},
		dport:   443,
		comm:    "curl",
	})

	ev, err := Decode(raw, Clock{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := ev.DstIP.String(); got != "185.199.109.133" {
		t.Errorf("DstIP = %s, want 185.199.109.133", got)
	}
	if ev.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", ev.DstPort)
	}
}

func TestDecodeConnectIPv6(t *testing.T) {
	// 2606:4700:10::ac42:93f3
	v6 := [16]byte{0x26, 0x06, 0x47, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0xac, 0x42, 0x93, 0xf3}
	raw := buildRecord(rawEvent{
		typ:     uint8(TypeConnect),
		family:  afInet6,
		daddrV6: v6,
		dport:   443,
	})

	ev, err := Decode(raw, Clock{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := ev.DstIP.String(); got != "2606:4700:10::ac42:93f3" {
		t.Errorf("DstIP = %s, want 2606:4700:10::ac42:93f3", got)
	}
}

// A non-CONNECT event must not be given a destination address, even though
// those bytes exist in the record.
func TestDecodeNonConnectHasNoAddress(t *testing.T) {
	raw := buildRecord(rawEvent{
		typ:     uint8(TypeExit),
		daddrV4: [4]byte{1, 2, 3, 4},
		dport:   9999,
	})

	ev, err := Decode(raw, Clock{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if ev.DstIP != nil {
		t.Errorf("DstIP = %v, want nil for a non-CONNECT event", ev.DstIP)
	}
	if ev.DstPort != 0 {
		t.Errorf("DstPort = %d, want 0 for a non-CONNECT event", ev.DstPort)
	}
}

func TestDecodeShortRecordFails(t *testing.T) {
	if _, err := Decode(make([]byte, wireSize-1), Clock{}); err == nil {
		t.Fatal("Decode accepted a short record; want an error")
	}
}

// A comm/filename that exactly fills its fixed-width field has no NUL
// terminator, and must not be truncated or run into the next field.
func TestDecodeUnterminatedStrings(t *testing.T) {
	full := "0123456789abcdef" // exactly commLen
	raw := buildRecord(rawEvent{typ: uint8(TypeExec), comm: full})

	ev, err := Decode(raw, Clock{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if ev.Comm != full {
		t.Errorf("Comm = %q, want %q", ev.Comm, full)
	}
}

func TestTypeString(t *testing.T) {
	for _, c := range []struct {
		typ  Type
		want string
	}{
		{TypeExec, "EXEC"},
		{TypeExit, "EXIT"},
		{TypeFork, "FORK"},
		{TypeFileOpen, "OPEN"},
		{TypeConnect, "CONNECT"},
		{Type(99), "UNKNOWN(99)"},
	} {
		if got := c.typ.String(); got != c.want {
			t.Errorf("Type(%d).String() = %q, want %q", uint8(c.typ), got, c.want)
		}
	}
}

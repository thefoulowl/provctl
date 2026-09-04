package procscan

import (
	"os"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	// Field layout per proc(5); starttime is field 22 overall.
	cases := []struct {
		name      string
		line      string
		wantComm  string
		wantPPID  int
		wantStart uint64
		wantErr   bool
	}{
		{
			name:      "ordinary process",
			line:      "1234 (bash) S 1200 1234 1234 34816 1234 4194304 0 0 0 0 1 2 3 4 20 0 1 0 987654 0 0",
			wantComm:  "bash",
			wantPPID:  1200,
			wantStart: 987654,
		},
		{
			// A process can set an arbitrary name, including one with
			// spaces and parentheses — splitting the whole line on spaces
			// would mis-locate every field after it.
			name:      "comm containing spaces and parens",
			line:      "77 (my (weird) proc) S 42 77 77 0 0 0 0 0 0 0 1 2 3 4 20 0 1 0 555 0 0",
			wantComm:  "my (weird) proc",
			wantPPID:  42,
			wantStart: 555,
		},
		{
			name:      "kernel thread style name",
			line:      "9 (kworker/0:1-events) I 2 0 0 0 -1 69238880 0 0 0 0 0 5 0 0 20 0 1 0 17 0 0",
			wantComm:  "kworker/0:1-events",
			wantPPID:  2,
			wantStart: 17,
		},
		{
			name:    "no parens",
			line:    "1234 bash S 1200",
			wantErr: true,
		},
		{
			name:    "truncated before starttime",
			line:    "1234 (bash) S 1200 1234",
			wantErr: true,
		},
		{
			name:    "non-numeric ppid",
			line:    "1234 (bash) S notapid 1234 1234 0 0 0 0 0 0 0 1 2 3 4 20 0 1 0 555 0 0",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comm, ppid, start, err := parseStat(c.line)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseStat(%q) succeeded, want error", c.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStat: %v", err)
			}
			if comm != c.wantComm {
				t.Errorf("comm = %q, want %q", comm, c.wantComm)
			}
			if ppid != c.wantPPID {
				t.Errorf("ppid = %d, want %d", ppid, c.wantPPID)
			}
			if start != c.wantStart {
				t.Errorf("starttime = %d, want %d", start, c.wantStart)
			}
		})
	}
}

func TestBootTimeIsPlausible(t *testing.T) {
	bt, err := bootTime()
	if err != nil {
		t.Fatalf("bootTime: %v", err)
	}
	// Sanity: the machine booted in the past, and after 2000-01-01.
	if bt.Unix() < 946684800 {
		t.Errorf("boot time %v is implausibly early", bt)
	}
	if bt.After(time.Now()) {
		t.Errorf("boot time %v is in the future", bt)
	}
}

// Snapshot runs against the real /proc, so assert only invariants that
// hold on any Linux system rather than anything machine-specific.
func TestSnapshotFindsSelfAndSkipsSelfPID(t *testing.T) {
	self := os.Getpid()

	all, err := Snapshot(-1) // -1 never matches a real pid, so nothing is skipped
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("Snapshot found no processes")
	}

	var foundSelf bool
	for _, ev := range all {
		if ev.PID == uint32(self) {
			foundSelf = true
			if ev.Comm == "" {
				t.Error("our own process has an empty comm")
			}
			if ev.Filename == "" {
				t.Error("our own process has an empty exe path")
			}
		}
		if ev.Type != 0 && ev.Time.IsZero() {
			t.Errorf("pid %d has a zero start time", ev.PID)
		}
	}
	if !foundSelf {
		t.Errorf("Snapshot(-1) did not include the running test process (pid %d)", self)
	}

	excluded, err := Snapshot(self)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for _, ev := range excluded {
		if ev.PID == uint32(self) {
			t.Fatalf("Snapshot(%d) still included pid %d", self, self)
		}
	}
}

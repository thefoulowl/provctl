package store

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thefoulowl/provctl/internal/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

var base = time.Unix(1_700_000_000, 0)

func at(offset time.Duration) time.Time { return base.Add(offset) }

func applyAll(t *testing.T, st *Store, events ...model.Event) {
	t.Helper()
	if err := st.ApplyBatch(events); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}
}

// The canonical scenario provctl exists to reconstruct: a browser-ish
// process connects out, writes a file, a shell opens it, execs it, and the
// resulting process phones home.
func downloadAndExecuteScenario(t *testing.T, st *Store) string {
	t.Helper()
	const payload = "/home/u/Downloads/payload.sh"

	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 100, PPID: 1, Comm: "curl"},
		model.Event{Type: model.TypeExec, Time: at(1 * time.Second), PID: 100, PPID: 1, Comm: "curl", Filename: "/usr/bin/curl"},
		model.Event{Type: model.TypeConnect, Time: at(2 * time.Second), PID: 100, Comm: "curl",
			DstIP: net.ParseIP("185.199.109.133"), DstPort: 443},
		model.Event{Type: model.TypeFileOpen, Time: at(3 * time.Second), PID: 100, Comm: "curl", Filename: payload},
		model.Event{Type: model.TypeExit, Time: at(4 * time.Second), PID: 100, Comm: "curl", ExitCode: 0},

		// a shell opens it, then execs it as a new process
		model.Event{Type: model.TypeFork, Time: at(5 * time.Second), PID: 200, PPID: 50, Comm: "bash"},
		model.Event{Type: model.TypeFileOpen, Time: at(6 * time.Second), PID: 200, Comm: "bash", Filename: payload},
		model.Event{Type: model.TypeFork, Time: at(7 * time.Second), PID: 300, PPID: 200, Comm: "bash"},
		model.Event{Type: model.TypeExec, Time: at(8 * time.Second), PID: 300, PPID: 200, Comm: "payload.sh", Filename: payload},

		// what the executed payload did next
		model.Event{Type: model.TypeFork, Time: at(9 * time.Second), PID: 400, PPID: 300, Comm: "curl"},
		model.Event{Type: model.TypeConnect, Time: at(10 * time.Second), PID: 300, Comm: "payload.sh",
			DstIP: net.ParseIP("172.66.147.243"), DstPort: 443},
		model.Event{Type: model.TypeExit, Time: at(11 * time.Second), PID: 300, Comm: "payload.sh", ExitCode: 0},
	)
	return payload
}

func TestProvenanceReconstructsDownloadExecuteChain(t *testing.T) {
	st := newTestStore(t)
	payload := downloadAndExecuteScenario(t, st)

	hops, err := st.Provenance(payload)
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}

	joined := make([]string, len(hops))
	for i, h := range hops {
		joined[i] = h.Text
	}
	all := strings.Join(joined, "\n")

	for _, want := range []string{
		"curl (pid 100)",                   // the process that first wrote it
		"connected to 185.199.109.133:443", // where it likely came from
		"opened " + payload,
		"opened by bash (pid 200)", // reopened before execution
		"executed as payload.sh (pid 300)",
		"connected to 172.66.147.243:443", // what the execution did next
		"spawned curl (pid 400)",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("provenance chain missing %q; got:\n%s", want, all)
		}
	}
}

func TestProvenanceUnknownPath(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Provenance("/nope/never/seen"); err == nil {
		t.Fatal("Provenance on an unrecorded path succeeded; want an error")
	}
}

// The download source is only credited when the connection is close enough
// in time to plausibly be the source of the file.
func TestProvenanceIgnoresConnectionOutsideWindow(t *testing.T) {
	st := newTestStore(t)
	const p = "/tmp/f"
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 10, PPID: 1, Comm: "curl"},
		model.Event{Type: model.TypeConnect, Time: at(0), PID: 10, Comm: "curl",
			DstIP: net.ParseIP("1.2.3.4"), DstPort: 80},
		// well past downloadWindow after the connection
		model.Event{Type: model.TypeFileOpen, Time: at(downloadWindow + time.Minute), PID: 10, Comm: "curl", Filename: p},
	)

	hops, err := st.Provenance(p)
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	for _, h := range hops {
		if strings.Contains(h.Text, "1.2.3.4") {
			t.Errorf("credited a connection %v before the write as the source; hop: %q",
				downloadWindow+time.Minute, h.Text)
		}
	}
}

func TestTimelineOrdersFullProcessLife(t *testing.T) {
	st := newTestStore(t)
	downloadAndExecuteScenario(t, st)

	entries, err := st.Timeline(300)
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}

	var kinds []string
	for i, e := range entries {
		kinds = append(kinds, e.Kind)
		if i > 0 && e.At.Before(entries[i-1].At) {
			t.Errorf("timeline not sorted: entry %d (%v) precedes %d (%v)", i, e.At, i-1, entries[i-1].At)
		}
	}

	want := []string{"started", "spawned", "connected", "exited"}
	got := strings.Join(kinds, ",")
	for _, k := range want {
		if !strings.Contains(got, k) {
			t.Errorf("timeline missing a %q entry; got %s", k, got)
		}
	}
	if kinds[0] != "started" {
		t.Errorf("timeline starts with %q, want \"started\"", kinds[0])
	}
	if kinds[len(kinds)-1] != "exited" {
		t.Errorf("timeline ends with %q, want \"exited\"", kinds[len(kinds)-1])
	}
}

func TestTimelineUnknownPID(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Timeline(99999); err == nil {
		t.Fatal("Timeline for an unrecorded pid succeeded; want an error")
	}
}

// Regression test: if an exit event is missed (a full ring buffer drops
// events) the old lifetime row stays open. When the kernel later recycles
// that pid, a new exec must not rewrite the *old* process's identity —
// doing so would misattribute everything the old process did to the new
// binary, which is the worst possible failure for a forensics tool.
func TestPIDReuseDoesNotRewriteEarlierLifetime(t *testing.T) {
	st := newTestStore(t)

	// First lifetime of pid 500 — note: no exit event, simulating a drop.
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 500, PPID: 1, Comm: "victim"},
		model.Event{Type: model.TypeExec, Time: at(1 * time.Second), PID: 500, PPID: 1,
			Comm: "victim", Filename: "/usr/bin/victim"},
		model.Event{Type: model.TypeFileOpen, Time: at(2 * time.Second), PID: 500,
			Comm: "victim", Filename: "/etc/secret"},
	)

	// pid 500 is recycled much later by an unrelated binary.
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(time.Hour), PID: 500, PPID: 2, Comm: "attacker"},
		model.Event{Type: model.TypeExec, Time: at(time.Hour + time.Second), PID: 500, PPID: 2,
			Comm: "attacker", Filename: "/tmp/attacker"},
	)

	// The process that opened /etc/secret must still be the original one.
	owner, err := st.ProcessAt(500, at(2*time.Second))
	if err != nil {
		t.Fatalf("ProcessAt: %v", err)
	}
	if owner == nil {
		t.Fatal("ProcessAt returned no process for the first lifetime")
	}
	if owner.ExePath != "/usr/bin/victim" || owner.Comm != "victim" {
		t.Errorf("first lifetime was rewritten by the recycled pid: comm=%q exe=%q, want victim//usr/bin/victim",
			owner.Comm, owner.ExePath)
	}

	// And the newest lifetime is the attacker.
	latest, err := st.LatestProcess(500)
	if err != nil {
		t.Fatalf("LatestProcess: %v", err)
	}
	if latest.ExePath != "/tmp/attacker" {
		t.Errorf("latest lifetime exe = %q, want /tmp/attacker", latest.ExePath)
	}
}

// Likewise, an exit must close only the newest open lifetime.
func TestExitClosesOnlyNewestLifetime(t *testing.T) {
	st := newTestStore(t)
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 600, PPID: 1, Comm: "first"},
		model.Event{Type: model.TypeFork, Time: at(time.Hour), PID: 600, PPID: 1, Comm: "second"},
		model.Event{Type: model.TypeExit, Time: at(time.Hour + time.Second), PID: 600, ExitCode: 3},
	)

	all, err := st.AllProcesses(false)
	if err != nil {
		t.Fatalf("AllProcesses: %v", err)
	}
	var open, closed int
	for _, p := range all {
		if p.PID != 600 {
			continue
		}
		if p.ExitedAt == nil {
			open++
		} else {
			closed++
		}
	}
	if open != 1 || closed != 1 {
		t.Errorf("after one exit across two lifetimes: %d open / %d closed, want 1/1", open, closed)
	}
}

func TestAncestorsWalksParentChain(t *testing.T) {
	st := newTestStore(t)
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 10, PPID: 1, Comm: "sshd"},
		model.Event{Type: model.TypeFork, Time: at(time.Second), PID: 20, PPID: 10, Comm: "bash"},
		model.Event{Type: model.TypeFork, Time: at(2 * time.Second), PID: 30, PPID: 20, Comm: "curl"},
	)

	chain, err := st.Ancestors(30, 10)
	if err != nil {
		t.Fatalf("Ancestors: %v", err)
	}
	var comms []string
	for _, p := range chain {
		comms = append(comms, p.Comm)
	}
	if got := strings.Join(comms, ","); got != "curl,bash,sshd" {
		t.Errorf("Ancestors = %s, want curl,bash,sshd", got)
	}
}

// Ancestors must terminate even if the recorded data forms a parent cycle.
func TestAncestorsTerminatesOnCycle(t *testing.T) {
	st := newTestStore(t)
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 10, PPID: 20, Comm: "a"},
		model.Event{Type: model.TypeFork, Time: at(time.Second), PID: 20, PPID: 10, Comm: "b"},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := st.Ancestors(10, 100); err != nil {
			t.Errorf("Ancestors: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Ancestors did not terminate on a parent cycle")
	}
}

func TestApplyAndApplyBatchAgree(t *testing.T) {
	single := newTestStore(t)
	batched := newTestStore(t)

	events := []model.Event{
		{Type: model.TypeFork, Time: at(0), PID: 7, PPID: 1, Comm: "sh"},
		{Type: model.TypeExec, Time: at(time.Second), PID: 7, PPID: 1, Comm: "sh", Filename: "/bin/sh"},
		{Type: model.TypeFileOpen, Time: at(2 * time.Second), PID: 7, Comm: "sh", Filename: "/etc/passwd"},
		{Type: model.TypeExit, Time: at(3 * time.Second), PID: 7, Comm: "sh", ExitCode: 1},
	}

	for _, e := range events {
		if err := single.Apply(e); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}
	if err := batched.ApplyBatch(events); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}

	a, err := single.LatestProcess(7)
	if err != nil {
		t.Fatalf("LatestProcess: %v", err)
	}
	b, err := batched.LatestProcess(7)
	if err != nil {
		t.Fatalf("LatestProcess: %v", err)
	}
	if a.Comm != b.Comm || a.ExePath != b.ExePath || a.PPID != b.PPID {
		t.Errorf("Apply and ApplyBatch disagree: %+v vs %+v", a, b)
	}
	if a.ExitCode == nil || b.ExitCode == nil || *a.ExitCode != *b.ExitCode {
		t.Errorf("exit codes disagree: %v vs %v", a.ExitCode, b.ExitCode)
	}
}

func TestApplyBatchEmptyIsNoop(t *testing.T) {
	st := newTestStore(t)
	if err := st.ApplyBatch(nil); err != nil {
		t.Fatalf("ApplyBatch(nil): %v", err)
	}
}

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
// Regression test: reproduces a real bug found while building a demo of
// this exact scenario. The kernel's exec tracepoint reports the raw
// execve() argument verbatim -- for `./payload.sh`, that's the literal
// relative string, not an absolute path -- while Provenance (via
// ExecEventsForPath) matches on an exact absolute path. Left unresolved,
// this silently drops "who executed this, and what did that run do next"
// for the ordinary case of running a local script or binary, which is
// most of them. security_file_open, by contrast, is always resolved by
// the kernel via bpf_d_path() before it reaches us.
func TestExecWithRelativePathResolvesViaFileOpen(t *testing.T) {
	st := newTestStore(t)
	const absPath = "/home/user/demo/payload.sh"

	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 700, PPID: 1, Comm: "bash"},
		// The kernel opens a script twice while resolving its shebang
		// (observed directly): once to detect the interpreter, again to
		// load it as the interpreter's argument. Both carry the fully
		// resolved absolute path.
		model.Event{Type: model.TypeFileOpen, Time: at(1 * time.Millisecond), PID: 700, Filename: absPath},
		model.Event{Type: model.TypeFileOpen, Time: at(2 * time.Millisecond), PID: 700, Filename: absPath},
		// The exec event itself reports only the raw, relative argument.
		model.Event{Type: model.TypeExec, Time: at(3 * time.Millisecond), PID: 700, PPID: 1,
			Comm: "payload.sh", Filename: "./payload.sh"},
	)

	p, err := st.LatestProcess(700)
	if err != nil {
		t.Fatalf("LatestProcess: %v", err)
	}
	if p.ExePath != absPath {
		t.Errorf("ExePath = %q, want resolved %q", p.ExePath, absPath)
	}

	// And the whole point: Provenance must now find this execution when
	// asked about the absolute path.
	hops, err := st.Provenance(absPath)
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	var sawExec bool
	for _, h := range hops {
		if strings.Contains(h.Text, "executed as") {
			sawExec = true
		}
	}
	if !sawExec {
		t.Error("Provenance chain has no \"executed as\" hop despite a matching relative-path exec")
	}
}

// When no matching file_events row exists (e.g. a statically invoked ELF
// the kernel never had to reopen), the raw path is kept as-is rather than
// silently dropped or left empty.
func TestExecWithRelativePathNoMatchKeepsRawPath(t *testing.T) {
	st := newTestStore(t)
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 800, PPID: 1, Comm: "sh"},
		model.Event{Type: model.TypeExec, Time: at(time.Millisecond), PID: 800, PPID: 1,
			Comm: "a.out", Filename: "./a.out"},
	)
	p, err := st.LatestProcess(800)
	if err != nil {
		t.Fatalf("LatestProcess: %v", err)
	}
	if p.ExePath != "./a.out" {
		t.Errorf("ExePath = %q, want the unresolved raw path %q kept as a fallback", p.ExePath, "./a.out")
	}
}

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

// Regression test: Seed exists specifically so the /proc startup backfill
// doesn't flood provctl top's live feed with hundreds of synthetic "exec"
// entries every time watch starts. If Seed ever starts writing to
// activity_log the same way Apply does, that guarantee silently breaks.
func TestSeedDoesNotWriteActivityLog(t *testing.T) {
	st := newTestStore(t)

	seedEvents := []model.Event{
		{Type: model.TypeExec, Time: at(0), PID: 1, Comm: "systemd", Filename: "/usr/lib/systemd/systemd"},
		{Type: model.TypeExec, Time: at(time.Second), PID: 2, Comm: "bash", Filename: "/usr/bin/bash"},
	}
	if err := st.Seed(seedEvents); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	entries, err := st.RecentActivity(10)
	if err != nil {
		t.Fatalf("RecentActivity: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Seed wrote %d activity_log entries, want 0: %+v", len(entries), entries)
	}

	// but the processes table itself must still be populated normally
	p, err := st.LatestProcess(1)
	if err != nil {
		t.Fatalf("LatestProcess: %v", err)
	}
	if p == nil || p.Comm != "systemd" {
		t.Errorf("Seed did not populate the processes table: %+v", p)
	}
}

func TestApplyWritesActivityLogInOrder(t *testing.T) {
	st := newTestStore(t)

	events := []model.Event{
		{Type: model.TypeFork, Time: at(0), PID: 10, PPID: 1, Comm: "sh"},
		{Type: model.TypeExec, Time: at(time.Second), PID: 10, PPID: 1, Comm: "sh", Filename: "/bin/sh"},
		{Type: model.TypeExit, Time: at(2 * time.Second), PID: 10, Comm: "sh", ExitCode: 0},
	}
	applyAll(t, st, events...)

	entries, err := st.RecentActivity(10)
	if err != nil {
		t.Fatalf("RecentActivity: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d activity_log entries, want 3", len(entries))
	}
	wantKinds := []string{"FORK", "EXEC", "EXIT"}
	for i, e := range entries {
		if e.Kind != wantKinds[i] {
			t.Errorf("entry %d kind = %q, want %q", i, e.Kind, wantKinds[i])
		}
		if i > 0 && e.ID <= entries[i-1].ID {
			t.Errorf("entry %d id %d not increasing after %d", i, e.ID, entries[i-1].ID)
		}
	}
}

func TestActivityAfterOnlyReturnsNewerEntries(t *testing.T) {
	st := newTestStore(t)
	applyAll(t, st,
		model.Event{Type: model.TypeFork, Time: at(0), PID: 1, PPID: 0, Comm: "a"},
		model.Event{Type: model.TypeFork, Time: at(time.Second), PID: 2, PPID: 0, Comm: "b"},
		model.Event{Type: model.TypeFork, Time: at(2 * time.Second), PID: 3, PPID: 0, Comm: "c"},
	)

	first, err := st.RecentActivity(10)
	if err != nil {
		t.Fatalf("RecentActivity: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("got %d entries, want 3", len(first))
	}

	cursor := first[1].ID // pretend we've already seen the first two
	next, err := st.ActivityAfter(cursor, 10)
	if err != nil {
		t.Fatalf("ActivityAfter: %v", err)
	}
	if len(next) != 1 || next[0].PID != 3 {
		t.Fatalf("ActivityAfter(%d) = %+v, want just pid 3's entry", cursor, next)
	}

	if empty, err := st.ActivityAfter(next[0].ID, 10); err != nil {
		t.Fatalf("ActivityAfter: %v", err)
	} else if len(empty) != 0 {
		t.Errorf("ActivityAfter at the latest id returned %d entries, want 0", len(empty))
	}
}

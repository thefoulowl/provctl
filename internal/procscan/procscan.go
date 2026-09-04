// Package procscan seeds the store with processes that were already
// running when `provctl watch` started.
//
// Without this, the first thing a fresh daemon sees is a file being opened
// by a pid it has never heard of — so `provctl trace` can say a path was
// opened but not by whom, which is precisely the question it exists to
// answer. Most real activity right after startup involves long-lived
// processes (shells, browsers, desktop apps) that forked long before the
// daemon did.
//
// These are a best-effort snapshot, not observed events: /proc can only
// tell us a process's *current* identity, so a process that exec'd several
// times before we looked shows only its latest image.
package procscan

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/thefoulowl/provctl/internal/model"
)

// userHZ is the fixed scale of the starttime field in /proc/<pid>/stat.
// The kernel always reports these in USER_HZ (100), independent of the
// kernel's internal CONFIG_HZ.
const userHZ = 100

// Snapshot enumerates /proc and returns one synthetic EXEC event per live
// process, timestamped with that process's real start time so ordering
// against subsequently observed events stays correct. selfPID is skipped
// (provctl doesn't trace itself).
//
// Individual unreadable processes are skipped rather than failing the
// whole scan: pids come and go while we walk, and kernel threads deny
// access to some of these files.
func Snapshot(selfPID int) ([]model.Event, error) {
	bootTime, err := bootTime()
	if err != nil {
		return nil, fmt.Errorf("procscan: %w", err)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("procscan: read /proc: %w", err)
	}

	var out []model.Event
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == selfPID {
			continue // not a pid directory, or it's us
		}
		ev, ok := scanPID(pid, bootTime)
		if !ok {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

func scanPID(pid int, boot time.Time) (model.Event, bool) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return model.Event{}, false // exited between ReadDir and now
	}
	comm, ppid, startTicks, err := parseStat(string(raw))
	if err != nil {
		return model.Event{}, false
	}

	ev := model.Event{
		Type: model.TypeExec,
		Time: boot.Add(time.Duration(startTicks) * time.Second / userHZ),
		PID:  uint32(pid),
		PPID: uint32(ppid),
		// comm from /proc/<pid>/stat is attacker-set (prctl) and the kernel
		// escapes only newline/NUL there, so neutralize it the same way
		// Decode does for ring-buffer events.
		Comm: model.SanitizeDisplay(comm),
	}

	// The executable path is unavailable for kernel threads and for
	// processes we can't read; comm alone is still worth recording.
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		ev.Filename = model.SanitizeDisplay(exe)
	}

	if fi, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ev.UID, ev.GID = st.Uid, st.Gid
		}
	}

	return ev, true
}

// parseStat extracts comm, ppid, and starttime from a /proc/<pid>/stat
// line. The comm field is wrapped in parentheses and may itself contain
// spaces and parentheses (a process can set an arbitrary name), so the
// fields after it are located from the *last* ')' rather than by splitting
// the whole line on spaces.
func parseStat(line string) (comm string, ppid int, startTicks uint64, err error) {
	openIdx := strings.IndexByte(line, '(')
	closeIdx := strings.LastIndexByte(line, ')')
	if openIdx < 0 || closeIdx < 0 || closeIdx < openIdx {
		return "", 0, 0, fmt.Errorf("procscan: malformed stat line")
	}
	comm = line[openIdx+1 : closeIdx]

	// Fields after comm, 1-indexed as in proc(5): [0]=state(3), [1]=ppid(4),
	// ... starttime is field 22, i.e. index 19 here.
	rest := strings.Fields(line[closeIdx+1:])
	const (
		ppidIdx      = 1
		starttimeIdx = 19
	)
	if len(rest) <= starttimeIdx {
		return "", 0, 0, fmt.Errorf("procscan: stat line has %d fields after comm, want > %d", len(rest), starttimeIdx)
	}
	if ppid, err = strconv.Atoi(rest[ppidIdx]); err != nil {
		return "", 0, 0, fmt.Errorf("procscan: parse ppid: %w", err)
	}
	if startTicks, err = strconv.ParseUint(rest[starttimeIdx], 10, 64); err != nil {
		return "", 0, 0, fmt.Errorf("procscan: parse starttime: %w", err)
	}
	return comm, ppid, startTicks, nil
}

// bootTime reads the wall-clock instant the system booted, which
// /proc/<pid>/stat's starttime is relative to.
func bootTime() (time.Time, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		field, value, ok := strings.Cut(line, " ")
		if !ok || field != "btime" {
			continue
		}
		secs, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse btime: %w", err)
		}
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, fmt.Errorf("no btime field in /proc/stat")
}

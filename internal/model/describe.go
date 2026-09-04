package model

import "fmt"

// Describe renders a single human-readable line for an event, with no
// timestamp or color — callers prepend those as needed. This is the one
// place that turns an Event into text, shared by watch's scrolling log and
// the activity_log table `provctl top` reads, so the two views can never
// drift out of sync with each other.
func (e Event) Describe() string {
	switch e.Type {
	case TypeFork:
		return fmt.Sprintf("%s(%d) forked -> pid %d", e.Comm, e.PPID, e.PID)
	case TypeExec:
		return fmt.Sprintf("%s (pid %d) exec'd %s", e.Comm, e.PID, e.Filename)
	case TypeExit:
		return fmt.Sprintf("%s (pid %d) exited (code %d)", e.Comm, e.PID, e.ExitCode)
	case TypeFileOpen:
		return fmt.Sprintf("%s (pid %d) opened %s", e.Comm, e.PID, e.Filename)
	case TypeConnect:
		return fmt.Sprintf("%s (pid %d) connected to %s:%d", e.Comm, e.PID, e.DstIP, e.DstPort)
	default:
		return fmt.Sprintf("pid %d: %s", e.PID, e.Type)
	}
}

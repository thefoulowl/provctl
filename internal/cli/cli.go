// Package cli implements provctl's subcommands: watch, trace, timeline, ps.
package cli

import (
	"context"
	"fmt"
	"os"
)

func defaultDBPath() string {
	if v := os.Getenv("PROVCTL_DB"); v != "" {
		return v
	}
	return "/var/lib/provctl/events.db"
}

// Run dispatches to a subcommand based on args[0].
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return fmt.Errorf("no subcommand given")
	}

	switch args[0] {
	case "watch":
		return runWatch(ctx, args[1:])
	case "trace":
		return runTrace(args[1:])
	case "timeline":
		return runTimeline(args[1:])
	case "ps":
		return runPS(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `provctl — eBPF process/file/network provenance and flight recorder

Usage:
  provctl watch    [--db path] [--quiet]   capture live events, persist them, print as they arrive
  provctl trace    <path>      [--db path] reconstruct a file's provenance: where it came from, who ran it
  provctl timeline <pid>       [--db path] show everything recorded about one process's life
  provctl ps                   [--db path] list recorded processes as a tree

Flags:
  --db path   sqlite database path (default: $PROVCTL_DB or /var/lib/provctl/events.db)

"watch" attaches eBPF probes and requires root (or CAP_BPF+CAP_PERFMON) plus
a kernel exposing BTF at /sys/kernel/btf/vmlinux. The other subcommands only
read the database watch has written and need no privileges beyond file access.
`)
}

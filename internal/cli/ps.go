package cli

import (
	"flag"
	"fmt"

	"github.com/thefoulowl/provctl/internal/store"
)

func runPS(args []string) error {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath(), "sqlite database path")
	all := fs.Bool("all", false, "include exited processes (default: live only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	procs, err := st.AllProcesses(!*all)
	if err != nil {
		return err
	}
	if len(procs) == 0 {
		fmt.Println("(no processes recorded yet — is `provctl watch` running?)")
		return nil
	}

	byParent := map[uint32][]store.Process{}
	known := map[uint32]bool{}
	for _, p := range procs {
		known[p.PID] = true
	}
	for _, p := range procs {
		byParent[p.PPID] = append(byParent[p.PPID], p)
	}

	var roots []store.Process
	for _, p := range procs {
		if !known[p.PPID] {
			roots = append(roots, p)
		}
	}

	seen := map[uint32]bool{}
	for _, r := range roots {
		printTree(r, byParent, 0, seen)
	}
	return nil
}

func printTree(p store.Process, byParent map[uint32][]store.Process, depth int, seen map[uint32]bool) {
	if seen[p.PID] {
		return // guards against a cycle in malformed/replayed data
	}
	seen[p.PID] = true

	status := "running"
	if p.ExitedAt != nil {
		code := 0
		if p.ExitCode != nil {
			code = *p.ExitCode
		}
		status = fmt.Sprintf("exited(%d)", code)
	}

	prefix := ""
	for i := 0; i < depth; i++ {
		prefix += "  "
	}
	if depth > 0 {
		prefix += "└─ "
	}
	fmt.Printf("%s%s (pid %d, %s)\n", prefix, p.Comm, p.PID, status)

	for _, c := range byParent[p.PID] {
		printTree(c, byParent, depth+1, seen)
	}
}

package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/thefoulowl/provctl/internal/store"
)

func runTrace(args []string) error {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath(), "sqlite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: provctl trace <path>")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	// bpf_d_path() records fully resolved kernel paths, so a symlinked
	// argument would never match. Resolve it when we can — but fall back
	// to the absolute path when we can't, which is the *normal* forensic
	// case: the file being traced has often already been deleted.
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	hops, err := st.Provenance(path)
	if err != nil {
		return err
	}

	for i, h := range hops {
		ts := h.At.Format("15:04:05")
		switch {
		case i == 0:
			fmt.Printf("%s\n", h.Text)
		case h.Depth == 0:
			fmt.Printf("  ↓ %-50s (%s)\n", h.Text, ts)
		default:
			fmt.Printf("%s-> %-46s (%s)\n", strings.Repeat("    ", h.Depth+1), h.Text, ts)
		}
	}
	return nil
}

package cli

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/thefoulowl/provctl/internal/store"
)

func runTimeline(args []string) error {
	fs := flag.NewFlagSet("timeline", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath(), "sqlite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: provctl timeline <pid>")
	}
	pid, err := strconv.ParseUint(fs.Arg(0), 10, 32)
	if err != nil {
		return fmt.Errorf("invalid pid %q: %w", fs.Arg(0), err)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	entries, err := st.Timeline(uint32(pid))
	if err != nil {
		return err
	}

	for _, e := range entries {
		fmt.Printf("%s %s\n", e.At.Format("15:04:05"), e.Text)
	}
	return nil
}

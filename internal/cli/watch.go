package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thefoulowl/provctl/internal/engine"
	"github.com/thefoulowl/provctl/internal/model"
	"github.com/thefoulowl/provctl/internal/store"
)

func runWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath(), "sqlite database path")
	quiet := fs.Bool("quiet", false, "persist events without printing them")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		return fmt.Errorf("cli: create db directory: %w", err)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	eng, err := engine.Open()
	if err != nil {
		return fmt.Errorf("%w (provctl watch needs root, or CAP_BPF+CAP_PERFMON, and kernel BTF)", err)
	}
	defer eng.Close()

	events := make(chan model.Event, 4096)
	errCh := make(chan error, 1)
	go func() { errCh <- eng.Events(ctx, events) }()

	fmt.Fprintf(os.Stderr, "provctl: watching (db=%s) — Ctrl+C to stop\n", *dbPath)

	for {
		select {
		case ev := <-events:
			if err := st.Apply(ev); err != nil {
				fmt.Fprintln(os.Stderr, "provctl: store error:", err)
				continue
			}
			if !*quiet {
				printEvent(ev)
			}
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func printEvent(ev model.Event) {
	ts := ev.Time.Format("15:04:05.000")
	switch ev.Type {
	case model.TypeFork:
		fmt.Printf("%s FORK    ppid=%d -> pid=%d (%s)\n", ts, ev.PPID, ev.PID, ev.Comm)
	case model.TypeExec:
		fmt.Printf("%s EXEC    pid=%d ppid=%d %s (%s)\n", ts, ev.PID, ev.PPID, ev.Filename, ev.Comm)
	case model.TypeExit:
		fmt.Printf("%s EXIT    pid=%d code=%d (%s)\n", ts, ev.PID, ev.ExitCode, ev.Comm)
	case model.TypeFileOpen:
		fmt.Printf("%s OPEN    pid=%d %s (%s)\n", ts, ev.PID, ev.Filename, ev.Comm)
	case model.TypeConnect:
		fmt.Printf("%s CONNECT pid=%d -> %s:%d (%s)\n", ts, ev.PID, ev.DstIP, ev.DstPort, ev.Comm)
	}
}

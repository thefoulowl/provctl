package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/thefoulowl/provctl/internal/engine"
	"github.com/thefoulowl/provctl/internal/model"
	"github.com/thefoulowl/provctl/internal/store"
)

// Events are batched into one SQLite transaction instead of one fsync per
// event, flushed on whichever limit hits first — this bounds both the
// worst-case write latency (batchInterval) and memory use (batchMax) while
// absorbing bursts (a single exec can produce dozens of file opens in the
// same millisecond).
const (
	batchMax      = 256
	batchInterval = 150 * time.Millisecond
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

	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	batch := make([]model.Event, 0, batchMax)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := st.ApplyBatch(batch); err != nil {
			fmt.Fprintln(os.Stderr, "provctl: store error:", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-events:
			if !*quiet {
				printEvent(ev)
			}
			batch = append(batch, ev)
			if len(batch) >= batchMax {
				flush()
			}
		case <-ticker.C:
			flush()
		case err := <-errCh:
			flush()
			return err
		case <-ctx.Done():
			flush()
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

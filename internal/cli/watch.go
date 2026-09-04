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
	"github.com/thefoulowl/provctl/internal/procscan"
	"github.com/thefoulowl/provctl/internal/store"
	"github.com/thefoulowl/provctl/internal/ui"
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

	// Seed the store with processes that already exist, so events from
	// long-lived processes (shells, browsers) can be attributed to a named
	// process instead of a bare pid we never saw start.
	if snapshot, err := procscan.Snapshot(os.Getpid()); err != nil {
		fmt.Fprintln(os.Stderr, "provctl: /proc snapshot failed, pre-existing processes will show as bare pids:", err)
	} else if err := st.Seed(snapshot); err != nil {
		return fmt.Errorf("cli: seed store from /proc: %w", err)
	} else {
		fmt.Fprintf(os.Stderr, "provctl: seeded %d already-running processes from /proc\n", len(snapshot))
	}

	eng, err := engine.Open()
	if err != nil {
		return fmt.Errorf("%w (provctl watch needs root, or CAP_BPF+CAP_PERFMON, and kernel BTF)", err)
	}
	defer eng.Close()

	events := make(chan model.Event, 4096)
	errCh := make(chan error, 1)
	go func() { errCh <- eng.Events(ctx, events) }()

	fmt.Fprintf(os.Stderr, "provctl: watching (db=%s) — Ctrl+C to stop\n", *dbPath)

	colorer := ui.NewColorer(ui.Enabled(os.Stdout))

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
				printEvent(ev, colorer)
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

// eventColumnWidth is the padded width of the event-type label, so the
// description text lines up in a column regardless of which event fired.
const eventColumnWidth = 7 // len("CONNECT")

func printEvent(ev model.Event, c ui.Colorer) {
	ts := c.Dim(ev.Time.Format("15:04:05.000"))
	label := fmt.Sprintf("%-*s", eventColumnWidth, ev.Type.String())

	var colored string
	switch ev.Type {
	case model.TypeFork:
		colored = c.Fork(label)
	case model.TypeExec:
		colored = c.Exec(label)
	case model.TypeExit:
		colored = c.Exit(label)
	case model.TypeFileOpen:
		colored = c.Open(label)
	case model.TypeConnect:
		colored = c.Connect(label)
	default:
		colored = label
	}

	fmt.Printf("%s %s %s\n", ts, colored, ev.Describe())
}

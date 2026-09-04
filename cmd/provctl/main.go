// Command provctl captures process/file/network provenance via eBPF and
// answers "where did this come from" and "what did this process do" from
// the recorded history. See `provctl help`.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/thefoulowl/provctl/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "provctl:", err)
		os.Exit(1)
	}
}

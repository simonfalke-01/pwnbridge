package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pwnbridge/pwnbridge/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer stop()
	app, err := cli.New()
	if err == nil {
		err = app.Root().ExecuteContext(ctx)
	}
	// A signal may kill an in-flight ssh/scp child before that layer can wrap
	// context.Canceled. The process-level signal context remains authoritative.
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pwnbridge:", err)
		os.Exit(cli.ExitCode(err))
	}
}

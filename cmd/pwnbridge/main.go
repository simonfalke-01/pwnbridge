package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/simonfalke-01/pwnbridge/internal/cli"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

func main() {
	if err := version.CheckRuntimeToolchain(); err != nil {
		fmt.Fprintln(os.Stderr, filepath.Base(os.Args[0])+":", err)
		os.Exit(1)
	}
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
		fmt.Fprintln(os.Stderr, filepath.Base(os.Args[0])+":", err)
		os.Exit(cli.ExitCode(err))
	}
}

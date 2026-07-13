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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := cli.New()
	if err == nil {
		err = app.Root().ExecuteContext(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pwnbridge:", err)
		os.Exit(cli.ExitCode(err))
	}
}

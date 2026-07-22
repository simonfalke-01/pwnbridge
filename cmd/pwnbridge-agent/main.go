package main

import (
	"fmt"
	"os"

	"github.com/simonfalke-01/pwnbridge/internal/agent"
	"github.com/simonfalke-01/pwnbridge/internal/version"
)

func main() {
	if err := version.CheckRuntimeToolchain(); err != nil {
		fmt.Fprintln(os.Stderr, "pwnbridge-agent:", err)
		os.Exit(1)
	}
	if err := agent.Main(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pwnbridge-agent:", err)
		os.Exit(1)
	}
}

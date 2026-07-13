package main

import (
	"fmt"
	"os"

	"github.com/pwnbridge/pwnbridge/internal/agent"
)

func main() {
	if err := agent.Main(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pwnbridge-agent:", err)
		os.Exit(1)
	}
}

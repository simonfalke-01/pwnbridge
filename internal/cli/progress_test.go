package cli

import (
	"bytes"
	"testing"
)

func TestLaunchProgressIsSilentForNonTerminalWriters(t *testing.T) {
	var output bytes.Buffer
	progress := newLaunchProgress(&output)
	progress.Stage("Connecting")
	progress.Stop()
	if output.Len() != 0 {
		t.Fatalf("non-terminal progress output = %q", output.String())
	}
}

package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
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

func TestRecoveryProgressIsVisibleAndErasedOnTerminal(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	readDone := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(master)
		readDone <- data
	}()
	progress := newLaunchProgress(slave)
	display := &recoveryProgressDisplay{progress: progress}
	display.Update(recoveryVerificationProgress{Index: 1, Total: 2, Bytes: 0, TotalBytes: 100})
	time.Sleep(2*launchProgressDelay + 100*time.Millisecond)
	display.Update(recoveryVerificationProgress{Index: 1, Total: 2, Bytes: 50, TotalBytes: 100})
	time.Sleep(recoveryProgressRefresh + 100*time.Millisecond)
	display.Update(recoveryVerificationProgress{Index: 1, Total: 2, Bytes: 100, TotalBytes: 100, Done: true})
	time.Sleep(100 * time.Millisecond)
	progress.Stop()
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	var data []byte
	select {
	case data = <-readDone:
	case <-time.After(time.Second):
		t.Fatal("timed out reading terminal recovery progress")
	}
	output := string(data)
	for _, expected := range []string{"Verifying recovery 1/2", "(50%)", "(100%)", "\r\x1b[2K"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("terminal recovery progress missing %q: %q", expected, output)
		}
	}
}

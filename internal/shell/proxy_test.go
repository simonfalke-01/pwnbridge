package shell

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestInputControllerBuffersPastedCommands(t *testing.T) {
	var terminal bytes.Buffer
	barriers := 0
	controller := &inputController{
		pty: &terminal,
		barrier: func(context.Context) error {
			barriers++
			return nil
		},
		err: &bytes.Buffer{}, atPrompt: true,
	}
	controller.Input(context.Background(), []byte("first\rsecond\r"))
	if got := terminal.String(); got != "first\r" {
		t.Fatalf("pasted remainder escaped first command barrier: %q", got)
	}
	controller.Prompt(context.Background())
	if got := terminal.String(); got != "first\rsecond\r" || barriers != 2 {
		t.Fatalf("buffered paste was not replayed safely: output=%q barriers=%d", got, barriers)
	}
}

func TestInputControllerPreservesPasteWhenBarrierFails(t *testing.T) {
	var terminal, diagnostics bytes.Buffer
	fail := true
	controller := &inputController{
		pty: &terminal,
		barrier: func(context.Context) error {
			if fail {
				return errors.New("conflict")
			}
			return nil
		},
		err: &diagnostics, atPrompt: true,
	}
	controller.Input(context.Background(), []byte("first\rsecond\r"))
	if terminal.String() != "first" || !bytes.Contains(diagnostics.Bytes(), []byte("conflict")) {
		t.Fatalf("failed barrier handling: terminal=%q diagnostic=%q", terminal.String(), diagnostics.String())
	}
	fail = false
	controller.Input(context.Background(), []byte("\r"))
	controller.Prompt(context.Background())
	if terminal.String() != "first\rsecond\r" {
		t.Fatalf("paste was lost after recovery: %q", terminal.String())
	}
}

package shell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/creack/pty"
	"golang.org/x/term"
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

func TestProxyRestoresTerminalAfterTransportExit(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	err = (Proxy{In: slave, Out: io.Discard, Err: io.Discard}).Run(context.Background(), exec.Command("sh", "-c", "exit 255"))
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 255 {
		t.Fatalf("transport status was not preserved: %v", err)
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("PTY state changed after failure: before=%#v after=%#v", before, after)
	}
}

func TestExitNoticeFilterSuppressesBannerAcrossChunksWithoutBufferingOutput(t *testing.T) {
	var output bytes.Buffer
	filter := newExitNoticeFilter(&output, "[mosh is exiting.]")
	if _, err := filter.Write([]byte("normal output\r\n")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "normal output\r\n" {
		t.Fatalf("ordinary output was delayed: %q", got)
	}
	for _, chunk := range []string{"[mosh is", " exiting.]", "\r", "\n"} {
		if _, err := filter.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := filter.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "normal output\r\n" {
		t.Fatalf("filtered output = %q", got)
	}

	output.Reset()
	filter = newExitNoticeFilter(&output, "[mosh is exiting.]")
	_, _ = filter.Write([]byte("program printed [mosh is exiting!] but kept running\r\nreal error\r\n"))
	if err := filter.Flush(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "[mosh is exiting!]") || !strings.Contains(output.String(), "real error") {
		t.Fatalf("non-terminal output was suppressed: %q", output.String())
	}
}

func TestEchoPredictorRendersInputAndSuppressesMatchingRemoteEcho(t *testing.T) {
	var output bytes.Buffer
	predictor := &echoPredictor{out: &output}
	predictor.Predict([]byte("typed"))
	if got := output.String(); got != "typed" {
		t.Fatalf("prediction was not rendered immediately: %q", got)
	}
	if _, err := predictor.Write([]byte("typed\r\nresult\r\n")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "typed\r\nresult\r\n" {
		t.Fatalf("remote echo was not reconciled: %q", got)
	}
}

func TestEchoPredictorLeavesControlsAndRemoteCorrectionsAuthoritative(t *testing.T) {
	var output bytes.Buffer
	predictor := &echoPredictor{out: &output}
	predictor.Predict([]byte("ok\x1b[D\x7f\r"))
	if got := output.String(); got != "ok" {
		t.Fatalf("control input was predicted: %q", got)
	}
	_, _ = predictor.Write([]byte("oX\bK"))
	if got := output.String(); got != "okX\bK" {
		t.Fatalf("remote correction was hidden: %q", got)
	}
}

func TestEchoPredictorLeavesBracketedPasteRedisplayAuthoritative(t *testing.T) {
	var output bytes.Buffer
	predictor := &echoPredictor{out: &output}
	predictor.Predict([]byte("before "))
	_, _ = predictor.Write([]byte("before "))
	for _, chunk := range []string{"\x1b[2", "00~pasted", "\ntext\x1b[20", "1~"} {
		predictor.Predict([]byte(chunk))
	}
	if got := output.String(); got != "before " {
		t.Fatalf("paste body was locally predicted: %q", got)
	}
	remote := []byte("\x1b[7mpasted\r\ntext\x1b[27m")
	if _, err := predictor.Write(remote); err != nil {
		t.Fatal(err)
	}
	predictor.Predict([]byte(" after"))
	_, _ = predictor.Write([]byte(" after"))
	if got := output.String(); got != "before "+string(remote)+" after" {
		t.Fatalf("Readline redisplay was duplicated or hidden: %q", got)
	}
}

func TestInputControllerDoesNotTreatPastedNewlinesAsSubmissions(t *testing.T) {
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
	for _, chunk := range []string{"\x1b[20", "0~first\nsecond", "\x1b[201", "~\r"} {
		controller.Input(context.Background(), []byte(chunk))
	}
	if got := terminal.String(); got != "\x1b[200~first\nsecond\x1b[201~\r" {
		t.Fatalf("paste bytes changed: %q", got)
	}
	if barriers != 1 {
		t.Fatalf("paste triggered %d barriers, want one final submission", barriers)
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

func TestInputControllerHoldsAllInputDuringPostCommandBarrier(t *testing.T) {
	var terminal bytes.Buffer
	barriers := 0
	controller := &inputController{
		pty: &terminal,
		barrier: func(context.Context) error {
			barriers++
			return nil
		},
		err: &bytes.Buffer{},
	}
	controller.BeginPrompt()
	controller.Input(context.Background(), []byte("next-command\r"))
	if terminal.Len() != 0 {
		t.Fatalf("input escaped the post-command barrier: %q", terminal.String())
	}
	controller.Prompt(context.Background())
	if got := terminal.String(); got != "next-command\r" || barriers != 1 {
		t.Fatalf("buffered input was not replayed safely: output=%q barriers=%d", got, barriers)
	}
}

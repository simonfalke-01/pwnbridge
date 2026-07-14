package subprocess

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCommandContextSetsWaitDelay(t *testing.T) {
	cmd := CommandContext(t.Context(), "unused")
	if cmd.WaitDelay != WaitDelay {
		t.Fatalf("WaitDelay = %v, want %v", cmd.WaitDelay, WaitDelay)
	}
}

func TestCaptureBoundsStructuredOutputAndRetainsDiagnosticTail(t *testing.T) {
	ctx := t.Context()
	cmd := CommandContext(ctx, "sh", "-c", "printf 123456789; printf abcdefghi >&2")
	result, err := Capture(ctx, cmd, 8, 5)
	var limitErr *OutputLimitError
	if !errors.As(err, &limitErr) || limitErr.Limit != 8 {
		t.Fatalf("overflow error = %v", err)
	}
	if string(result.Stdout) != "12345678" || !result.StdoutTruncated {
		t.Fatalf("stdout result = %#v", result)
	}
	if string(result.Stderr) != "efghi" || !result.StderrTruncated {
		t.Fatalf("stderr result = %#v", result)
	}
	if detail := result.Diagnostic(); !strings.HasPrefix(detail, "[output truncated]\n") || !strings.HasSuffix(detail, "efghi") {
		t.Fatalf("diagnostic = %q", detail)
	}

	cmd = CommandContext(ctx, "sh", "-c", "printf 12345678; printf abcde >&2")
	result, err = Capture(ctx, cmd, 8, 5)
	if err != nil || result.StdoutTruncated || result.StderrTruncated {
		t.Fatalf("exact-limit capture = %#v, %v", result, err)
	}
}

func TestCaptureRejectsInvalidConfigurationWithoutStarting(t *testing.T) {
	marker := t.TempDir() + "/started"
	for _, test := range []struct {
		name   string
		ctx    context.Context
		cmd    *exec.Cmd
		stdout int
		stderr int
	}{
		{name: "nil context", cmd: exec.Command("sh", "-c", "touch \"$1\"", "sh", marker), stdout: 1, stderr: 1},
		{name: "nil command", ctx: t.Context(), stdout: 1, stderr: 1},
		{name: "zero stdout", ctx: t.Context(), cmd: exec.Command("sh", "-c", "touch \"$1\"", "sh", marker), stderr: 1},
		{name: "zero stderr", ctx: t.Context(), cmd: exec.Command("sh", "-c", "touch \"$1\"", "sh", marker), stdout: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Capture(test.ctx, test.cmd, test.stdout, test.stderr); err == nil {
				t.Fatal("invalid capture succeeded")
			}
		})
	}
	cmd := exec.Command("sh", "-c", "touch \"$1\"", "sh", marker)
	cmd.Stdout = &bytes.Buffer{}
	if _, err := Capture(t.Context(), cmd, 1, 1); err == nil {
		t.Fatal("preconfigured stdout succeeded")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid capture started its command: %v", err)
	}
}

func TestCapturePrefersContextAndBoundsInheritedPipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result, err := Capture(ctx, CommandContext(ctx, "sh", "-c", "while :; do printf x; printf y >&2; done"), 32, 32)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled capture error = %v", err)
	}
	if len(result.Stdout) > 32 || len(result.Stderr) > 32 {
		t.Fatalf("cancelled capture sizes = %d/%d", len(result.Stdout), len(result.Stderr))
	}

	started := time.Now()
	result, err = Capture(context.Background(), exec.Command("sh", "-c", "sleep 4 & printf done"), 32, 32)
	if !errors.Is(err, exec.ErrWaitDelay) || string(result.Stdout) != "done" {
		t.Fatalf("inherited capture = %q, %v", result.Stdout, err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("inherited capture took %v", elapsed)
	}
}

func TestBoundedWriterConcurrentFlood(t *testing.T) {
	writer := newBoundedWriter(1024, true)
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			for iteration := 0; iteration < 1000; iteration++ {
				if _, err := writer.Write(bytes.Repeat([]byte{value}, 128)); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(byte('a' + index))
	}
	wait.Wait()
	output, truncated := writer.snapshot()
	if len(output) != 1024 || !truncated {
		t.Fatalf("snapshot length/truncation = %d/%t", len(output), truncated)
	}
}

func TestDiagnosticWriterBoundsAndMarksTail(t *testing.T) {
	writer := NewDiagnosticWriter()
	if written, err := writer.Write(bytes.Repeat([]byte("x"), DiagnosticLimit+1)); err != nil || written != DiagnosticLimit+1 {
		t.Fatalf("diagnostic write = %d, %v", written, err)
	}
	if _, err := writer.Write([]byte("final")); err != nil {
		t.Fatal(err)
	}
	detail := writer.Diagnostic()
	if !strings.HasPrefix(detail, "[output truncated]\n") || !strings.HasSuffix(detail, "final") {
		t.Fatalf("diagnostic = %q", detail)
	}
	if got := (&OutputLimitError{Limit: 12}).Error(); got != "stdout exceeded 12-byte limit" {
		t.Fatalf("limit error = %q", got)
	}
}

func FuzzBoundedWriter(f *testing.F) {
	f.Add([]byte("abcdefghi"), uint8(5), true)
	f.Add([]byte("exact"), uint8(5), false)
	f.Fuzz(func(t *testing.T, data []byte, rawLimit uint8, tail bool) {
		limit := int(rawLimit%64) + 1
		writer := newBoundedWriter(limit, tail)
		for offset := 0; offset < len(data); {
			chunk := 1 + (offset % 17)
			if chunk > len(data)-offset {
				chunk = len(data) - offset
			}
			if written, err := writer.Write(data[offset : offset+chunk]); err != nil || written != chunk {
				t.Fatalf("write = %d, %v", written, err)
			}
			offset += chunk
		}
		output, truncated := writer.snapshot()
		want := data
		if len(want) > limit {
			if tail {
				want = want[len(want)-limit:]
			} else {
				want = want[:limit]
			}
		}
		if !bytes.Equal(output, want) || truncated != (len(data) > limit) {
			t.Fatalf("output=%x truncated=%t, want=%x/%t", output, truncated, want, len(data) > limit)
		}
	})
}

func BenchmarkCommandContext(b *testing.B) {
	ctx := context.Background()
	b.Run("standard", func(b *testing.B) {
		for b.Loop() {
			_ = exec.CommandContext(ctx, "unused")
		}
	})
	b.Run("bounded", func(b *testing.B) {
		for b.Loop() {
			_ = CommandContext(ctx, "unused")
		}
	})
}

var benchmarkWriterBytes int

func BenchmarkWriter32MiB(b *testing.B) {
	block := bytes.Repeat([]byte("x"), 32<<10)
	b.Run("bytes-buffer", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(32 << 20)
		for b.Loop() {
			var writer bytes.Buffer
			for written := 0; written < 32<<20; written += len(block) {
				_, _ = writer.Write(block)
			}
			benchmarkWriterBytes = writer.Len()
		}
	})
	b.Run("bounded-tail-64KiB", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(32 << 20)
		for b.Loop() {
			writer := newBoundedWriter(64<<10, true)
			for written := 0; written < 32<<20; written += len(block) {
				_, _ = writer.Write(block)
			}
			output, _ := writer.snapshot()
			benchmarkWriterBytes = len(output)
		}
	})
}

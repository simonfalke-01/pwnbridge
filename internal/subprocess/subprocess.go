// Package subprocess provides consistently bounded context-aware commands.
package subprocess

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// WaitDelay bounds shutdown and inherited I/O pipes after cancellation or
// after the direct child exits. It does not limit normally running commands.
const WaitDelay = time.Second

// DiagnosticLimit is the maximum subprocess detail incorporated into an
// error. Structured stdout can have a larger caller-specific limit without
// turning a failed command into an equally large terminal error.
const DiagnosticLimit = 64 << 10

func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = WaitDelay
	return cmd
}

// CaptureResult holds bounded output from Capture. Stdout is retained from the
// beginning for structured decoding; stderr is retained from the end so the
// final diagnostic survives a long progress stream.
type CaptureResult struct {
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
}

// DiagnosticWriter is a bounded tail writer for commands whose stdout is
// streamed directly to the user. It retains only DiagnosticLimit bytes.
type DiagnosticWriter struct{ output *boundedWriter }

func NewDiagnosticWriter() *DiagnosticWriter {
	return &DiagnosticWriter{output: newBoundedWriter(DiagnosticLimit, true)}
}

func (w *DiagnosticWriter) Write(data []byte) (int, error) {
	return w.output.Write(data)
}

func (w *DiagnosticWriter) Diagnostic() string {
	data, truncated := w.output.snapshot()
	return (CaptureResult{Stderr: data, StderrTruncated: truncated}).Diagnostic()
}

// Diagnostic returns a bounded human error detail. It intentionally favors
// the end of the combined data, where command-line tools normally put their
// final failure, and marks every form of omission.
func (r CaptureResult) Diagnostic() string {
	combined := append([]byte(nil), r.Stdout...)
	if len(combined) > 0 && len(r.Stderr) > 0 {
		combined = append(combined, '\n')
	}
	combined = append(combined, r.Stderr...)
	truncated := r.StdoutTruncated || r.StderrTruncated
	if len(combined) > DiagnosticLimit {
		combined = combined[len(combined)-DiagnosticLimit:]
		truncated = true
	}
	detail := strings.TrimSpace(strings.ToValidUTF8(string(combined), "�"))
	if truncated {
		if detail == "" {
			return "[output truncated]"
		}
		return "[output truncated]\n" + detail
	}
	return detail
}

// OutputLimitError reports a structured stdout response that cannot be safely
// decoded in full.
type OutputLimitError struct{ Limit int }

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("stdout exceeded %d-byte limit", e.Limit)
}

// Capture drains both command output streams while retaining only bounded
// snapshots. The command must not already have stdout or stderr configured.
// A truncated stdout response is always an error; truncated stderr remains
// available as marked diagnostic context when the command itself fails.
func Capture(ctx context.Context, cmd *exec.Cmd, stdoutLimit, stderrLimit int) (CaptureResult, error) {
	if ctx == nil {
		return CaptureResult{}, errors.New("capture context is nil")
	}
	if cmd == nil {
		return CaptureResult{}, errors.New("capture command is nil")
	}
	if stdoutLimit <= 0 || stderrLimit <= 0 {
		return CaptureResult{}, errors.New("capture limits must be positive")
	}
	if cmd.Stdout != nil || cmd.Stderr != nil {
		return CaptureResult{}, errors.New("capture command output is already configured")
	}
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = WaitDelay
	}
	stdout := newBoundedWriter(stdoutLimit, false)
	stderr := newBoundedWriter(stderrLimit, true)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	stdoutData, stdoutTruncated := stdout.snapshot()
	stderrData, stderrTruncated := stderr.snapshot()
	result := CaptureResult{
		Stdout: stdoutData, Stderr: stderrData,
		StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, ctxErr
	}
	if stdoutTruncated {
		return result, errors.Join(runErr, &OutputLimitError{Limit: stdoutLimit})
	}
	return result, runErr
}

// boundedWriter is a synchronized drain that retains either the first or last
// limit bytes. Tail mode uses a ring buffer, so repeated output after the cap
// does not cause allocations or quadratic copying.
type boundedWriter struct {
	mu    sync.Mutex
	data  []byte
	limit int
	tail  bool
	total int64
	next  int
}

func newBoundedWriter(limit int, tail bool) *boundedWriter {
	return &boundedWriter{limit: limit, tail: tail}
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	length := len(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(length)
	if !w.tail {
		remaining := w.limit - len(w.data)
		if remaining > len(data) {
			remaining = len(data)
		}
		if remaining > 0 {
			w.data = append(w.data, data[:remaining]...)
		}
		return length, nil
	}
	if remaining := w.limit - len(w.data); remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		w.data = append(w.data, data[:remaining]...)
		data = data[remaining:]
		if len(w.data) == w.limit {
			w.next = 0
		}
	}
	for len(data) > 0 {
		written := copy(w.data[w.next:], data)
		w.next = (w.next + written) % w.limit
		data = data[written:]
	}
	return length, nil
}

func (w *boundedWriter) snapshot() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	truncated := w.total > int64(w.limit)
	if !w.tail {
		return append([]byte(nil), w.data...), truncated
	}
	length := int(w.total)
	if length > w.limit {
		length = w.limit
	}
	if length == 0 {
		return nil, false
	}
	if !truncated {
		return append([]byte(nil), w.data[:length]...), false
	}
	result := make([]byte, 0, w.limit)
	result = append(result, w.data[w.next:]...)
	result = append(result, w.data[:w.next]...)
	return result, true
}

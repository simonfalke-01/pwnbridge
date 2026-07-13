package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

type Barrier func(context.Context) error

type Proxy struct {
	In      *os.File
	Out     io.Writer
	Err     io.Writer
	Barrier Barrier
	Nonce   string
	// PredictEcho enables pwnbridge's lightweight local echo prediction for
	// prompt input. Remote echo is reconciled before it reaches Out.
	PredictEcho bool
	// ExitNotice suppresses this exact banner when a transport emits it.
	ExitNotice string
}

func (p Proxy) Run(ctx context.Context, cmd *exec.Cmd) error {
	if p.In == nil {
		p.In = os.Stdin
	}
	if p.Out == nil {
		p.Out = os.Stdout
	}
	if p.Err == nil {
		p.Err = os.Stderr
	}
	if p.Barrier == nil {
		p.Barrier = func(context.Context) error { return nil }
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start terminal transport PTY: %w", err)
	}
	defer ptmx.Close()

	var oldState *term.State
	if term.IsTerminal(int(p.In.Fd())) {
		oldState, err = term.MakeRaw(int(p.In.Fd()))
		if err != nil {
			_ = cmd.Process.Kill()
			return err
		}
		defer term.Restore(int(p.In.Fd()), oldState)
		_ = pty.InheritSize(p.In, ptmx)
	}
	resize := make(chan os.Signal, 1)
	signal.Notify(resize, syscall.SIGWINCH)
	defer signal.Stop(resize)
	go func() {
		for range resize {
			_ = pty.InheritSize(p.In, ptmx)
		}
	}()

	var predictor *echoPredictor
	if p.PredictEcho {
		predictor = &echoPredictor{out: p.Out}
	}
	writeOutput := func(data []byte) {
		if predictor != nil {
			_, _ = predictor.Write(data)
		} else {
			_, _ = p.Out.Write(data)
		}
	}
	controller := &inputController{pty: ptmx, barrier: p.Barrier, err: p.Err, predictor: predictor}
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		if p.Nonce == "" {
			if p.ExitNotice == "" {
				_, _ = io.Copy(p.Out, ptmx)
				return
			}
			filter := newExitNoticeFilter(p.Out, p.ExitNotice)
			_, _ = io.Copy(filter, ptmx)
			_ = filter.Flush()
			return
		}
		parser := NewMarkerParser(p.Nonce)
		buffer := make([]byte, 32*1024)
		for {
			n, readErr := ptmx.Read(buffer)
			if n > 0 {
				for _, event := range parser.Feed(buffer[:n]) {
					if event.Prompt {
						if predictor != nil {
							predictor.Reset()
						}
						controller.BeginPrompt()
						if err := p.Barrier(ctx); err != nil {
							fmt.Fprintf(p.Err, "\r\npwnbridge: post-command sync blocked: %v\r\n", err)
						}
						controller.Prompt(ctx)
					} else {
						writeOutput(event.Data)
					}
				}
			}
			if readErr != nil {
				if tail := parser.Flush(); len(tail) > 0 {
					writeOutput(tail)
				}
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			n, readErr := p.In.Read(buffer)
			if n > 0 {
				controller.Input(ctx, buffer[:n])
			}
			if readErr != nil {
				return
			}
		}
	}()

	err = cmd.Wait()
	_ = ptmx.Close()
	<-outputDone
	if oldState != nil {
		_ = term.Restore(int(p.In.Fd()), oldState)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return &ExitError{Code: exit.ExitCode()}
	}
	return err
}

type exitNoticeFilter struct {
	out     io.Writer
	notice  []byte
	pending []byte
	after   bool
}

func newExitNoticeFilter(out io.Writer, notice string) *exitNoticeFilter {
	return &exitNoticeFilter{out: out, notice: []byte(notice)}
}

func (f *exitNoticeFilter) Write(data []byte) (int, error) {
	written := make([]byte, 0, len(data))
	for _, value := range data {
		if f.after {
			if value == '\r' || value == '\n' {
				continue
			}
			f.after = false
		}
		f.pending = append(f.pending, value)
		for len(f.pending) > 0 && !bytes.HasPrefix(f.notice, f.pending) {
			written = append(written, f.pending[0])
			f.pending = f.pending[1:]
		}
		if bytes.Equal(f.pending, f.notice) {
			f.pending = nil
			f.after = true
		}
	}
	if len(written) > 0 {
		if _, err := f.out.Write(written); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func (f *exitNoticeFilter) Flush() error {
	_, err := f.out.Write(f.pending)
	f.pending = nil
	return err
}

// echoPredictor renders ordinary prompt text immediately, then removes the
// corresponding remote terminal echo. The remote stream remains authoritative:
// any mismatch cancels the outstanding prediction and is displayed verbatim.
type echoPredictor struct {
	mu       sync.Mutex
	out      io.Writer
	expected []byte
	escape   int
}

func (p *echoPredictor) Predict(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	local := make([]byte, 0, len(data))
	for _, value := range data {
		switch p.escape {
		case 1:
			if value == '[' {
				p.escape = 2
			} else {
				p.escape = 0
			}
			continue
		case 2:
			if value >= 0x40 && value <= 0x7e {
				p.escape = 0
			}
			continue
		}
		if value == 0x1b {
			p.escape = 1
			continue
		}
		if value >= 0x20 && value != 0x7f {
			local = append(local, value)
		}
	}
	if len(local) == 0 {
		return
	}
	p.expected = append(p.expected, local...)
	_, _ = p.out.Write(local)
}

func (p *echoPredictor) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	remote := make([]byte, 0, len(data))
	for _, value := range data {
		if len(p.expected) > 0 && value == p.expected[0] {
			p.expected = p.expected[1:]
			continue
		}
		if len(p.expected) > 0 {
			p.expected = nil
		}
		remote = append(remote, value)
	}
	if len(remote) == 0 {
		return len(data), nil
	}
	_, err := p.out.Write(remote)
	return len(data), err
}

func (p *echoPredictor) Reset() {
	p.mu.Lock()
	p.expected = nil
	p.escape = 0
	p.mu.Unlock()
}

type ExitError struct{ Code int }

func (e *ExitError) Error() string {
	return fmt.Sprintf("remote process exited with status %d", e.Code)
}

type inputController struct {
	mu        sync.Mutex
	pty       io.Writer
	barrier   Barrier
	err       io.Writer
	atPrompt  bool
	syncing   bool
	pending   []byte
	predictor *echoPredictor
}

func (c *inputController) Input(ctx context.Context, data []byte) {
	c.mu.Lock()
	if c.syncing {
		c.pending = append(c.pending, data...)
		c.mu.Unlock()
		return
	}
	if !c.atPrompt {
		_, _ = c.pty.Write(data)
		c.mu.Unlock()
		return
	}
	for index, value := range data {
		if value != '\r' && value != '\n' {
			continue
		}
		if c.predictor != nil {
			c.predictor.Predict(data[:index])
		}
		_, _ = c.pty.Write(data[:index])
		rest := append([]byte(nil), data[index+1:]...)
		c.pending = append(c.pending, rest...)
		c.syncing = true
		c.mu.Unlock()
		barrierErr := c.barrier(ctx)
		if barrierErr != nil {
			fmt.Fprintf(c.err, "\r\npwnbridge: execution blocked by sync barrier: %v\r\n", barrierErr)
			c.mu.Lock()
			c.syncing = false
			c.atPrompt = true
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		_, _ = c.pty.Write([]byte{value})
		c.syncing = false
		c.atPrompt = false
		c.mu.Unlock()
		return
	}
	if c.predictor != nil {
		c.predictor.Predict(data)
	}
	_, _ = c.pty.Write(data)
	c.mu.Unlock()
}

func (c *inputController) BeginPrompt() {
	c.mu.Lock()
	c.syncing = true
	c.atPrompt = false
	c.mu.Unlock()
}

func (c *inputController) Prompt(ctx context.Context) {
	c.mu.Lock()
	c.syncing = false
	c.atPrompt = true
	pending := append([]byte(nil), c.pending...)
	c.pending = nil
	c.mu.Unlock()
	if len(pending) > 0 {
		c.Input(ctx, pending)
	}
}

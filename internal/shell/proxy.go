package shell

import (
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
		return fmt.Errorf("start SSH PTY: %w", err)
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

	controller := &inputController{pty: ptmx, barrier: p.Barrier, err: p.Err}
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		parser := NewMarkerParser(p.Nonce)
		buffer := make([]byte, 32*1024)
		for {
			n, readErr := ptmx.Read(buffer)
			if n > 0 {
				for _, event := range parser.Feed(buffer[:n]) {
					if event.Prompt {
						controller.BeginPrompt()
						if err := p.Barrier(ctx); err != nil {
							fmt.Fprintf(p.Err, "\r\npwnbridge: post-command sync blocked: %v\r\n", err)
						}
						controller.Prompt(ctx)
					} else {
						_, _ = p.Out.Write(event.Data)
					}
				}
			}
			if readErr != nil {
				if tail := parser.Flush(); len(tail) > 0 {
					_, _ = p.Out.Write(tail)
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

type ExitError struct{ Code int }

func (e *ExitError) Error() string {
	return fmt.Sprintf("remote process exited with status %d", e.Code)
}

type inputController struct {
	mu       sync.Mutex
	pty      io.Writer
	barrier  Barrier
	err      io.Writer
	atPrompt bool
	syncing  bool
	pending  []byte
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

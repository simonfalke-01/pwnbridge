package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

const launchProgressDelay = 250 * time.Millisecond

// launchProgress is deliberately a single, transient status line. Fast
// launches print nothing; slow launches show the current stage and erase it
// before handing the terminal to the remote process.
type launchProgress struct {
	writer  io.Writer
	enabled bool

	mu       sync.Mutex
	stage    string
	shown    bool
	stopped  bool
	wake     chan struct{}
	done     chan struct{}
	finished chan struct{}
}

func newLaunchProgress(writer io.Writer) *launchProgress {
	progress := &launchProgress{writer: writer}
	file, ok := writer.(*os.File)
	progress.enabled = ok && term.IsTerminal(int(file.Fd()))
	if progress.enabled {
		progress.wake = make(chan struct{}, 1)
		progress.done = make(chan struct{})
		progress.finished = make(chan struct{})
		go progress.run()
	}
	return progress
}

func (p *launchProgress) Stage(stage string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	if !p.stopped {
		p.stage = stage
	}
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *launchProgress) Stop() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	close(p.done)
	p.mu.Unlock()
	<-p.finished
}

func (p *launchProgress) run() {
	defer close(p.finished)
	timer := time.NewTimer(launchProgressDelay)
	defer timer.Stop()
	select {
	case <-p.done:
		return
	case <-p.wake:
	case <-timer.C:
	}

	// The first Stage normally arrives immediately. Delay from that point so
	// commands that feel instant remain visually quiet.
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(launchProgressDelay)
	select {
	case <-p.done:
		return
	case <-timer.C:
	}

	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(90 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		p.mu.Lock()
		stage := p.stage
		p.shown = true
		p.mu.Unlock()
		if stage != "" {
			fmt.Fprintf(p.writer, "\r\x1b[2K\x1b[2mpwnbridge\x1b[0m %s %s…", frames[frame], stage)
		}
		select {
		case <-p.done:
			fmt.Fprint(p.writer, "\r\x1b[2K")
			return
		case <-p.wake:
		case <-ticker.C:
			frame = (frame + 1) % len(frames)
		}
	}
}

package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/config"
)

func TestUpdateGlobalSerializesFreshReadModifyWrite(t *testing.T) {
	app, _ := testApp(t)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := app.updateGlobal(context.Background(), func(effective *config.Effective) error {
			close(firstEntered)
			<-releaseFirst
			effective.Global.Hosts["first"] = testGlobalHost("first-host")
			return nil
		})
		firstDone <- err
	}()
	<-firstEntered

	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		_, err := app.updateGlobal(context.Background(), func(effective *config.Effective) error {
			close(secondEntered)
			effective.Global.Hosts["second"] = testGlobalHost("second-host")
			return nil
		})
		secondDone <- err
	}()
	select {
	case <-secondEntered:
		t.Fatal("second global transaction entered while the first held the lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	effective, err := config.LoadGlobal(app.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Global.Hosts["first"].Destination != "first-host" || effective.Global.Hosts["second"].Destination != "second-host" {
		t.Fatalf("serialized updates lost data: %#v", effective.Global.Hosts)
	}
	if info, err := filepath.Glob(filepath.Join(app.Paths.State, "global-config.lock")); err != nil || len(info) != 1 {
		t.Fatalf("global lock path = %#v, %v", info, err)
	}
}

func TestUpdateGlobalCancellationAndCallbackFailureDoNotWrite(t *testing.T) {
	app, _ := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := app.updateGlobal(ctx, func(*config.Effective) error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancelled update = called %t, error %v", called, err)
	}
	want := errors.New("refuse mutation")
	if _, err := app.updateGlobal(context.Background(), func(*config.Effective) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback failure = %v", err)
	}
	if _, err := config.LoadGlobal(app.Paths); err != nil {
		t.Fatal(err)
	}
	if matches, err := filepath.Glob(filepath.Join(app.Paths.Config, "config.toml")); err != nil || len(matches) != 0 {
		t.Fatalf("failed updates wrote config: %#v, %v", matches, err)
	}
}

func testGlobalHost(destination string) config.Host {
	return config.Host{
		Destination: destination, Platform: "linux/amd64",
		WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn",
		ShellTransport: "auto", MoshPort: "60000:61000",
	}
}

package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfalke-01/pwnbridge/internal/transport"
)

func TestNoSudoPlan(t *testing.T) {
	plan := Plan(Options{NoSudo: true})
	if len(plan) == 0 {
		t.Fatal("empty plan")
	}
	for _, command := range plan {
		if strings.Contains(command, "sudo") {
			t.Fatalf("sudo leaked: %s", command)
		}
	}
}

func TestBootstrapPreflightReportsDiskFailure(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case " $* " in
  *" -R 127.0.0.1:0:127.0.0.1:9 "*) exit 0 ;;
  *"df -Pk"*) printf 'insufficient-disk-kib:1\n'; exit 22 ;;
  *"__PWNBRIDGE_HOME__"*) printf '__PWNBRIDGE_HOME__/home/test\n__PWNBRIDGE_OS__Linux\n__PWNBRIDGE_ARCH__x86_64\n'; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	client := transport.Client{SSH: ssh, Destination: "fake"}
	err := Run(context.Background(), client, Options{DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "insufficient-disk-kib:1") {
		t.Fatalf("disk preflight failure was not preserved: %v", err)
	}
}

func TestPinnedPwntools(t *testing.T) {
	if got := strings.Join(Plan(Options{}), "\n"); !strings.Contains(got, "pwntools==4.15.0") {
		t.Fatal("pwntools must be pinned")
	}
	if !strings.Contains(strings.Join(Packages, " "), "mosh") {
		t.Fatal("bootstrap must install mosh-server")
	}
}

func TestPinnedPwndbgIsPortableAndDoesNotModifyDotfiles(t *testing.T) {
	got := strings.Join(Plan(Options{WithPwndbg: true}), "\n")
	for _, required := range []string{PwndbgVersion, PwndbgURL, PwndbgSHA256, "sha256sum -c", "pwndbg/bin/pwndbg"} {
		if !strings.Contains(got, required) {
			t.Fatalf("pwndbg plan is missing %q", required)
		}
	}
	for _, forbidden := range []string{"~/.gdbinit", "$HOME/.gdbinit", "git clone", "./setup.sh"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("pwndbg plan must be isolated from user configuration; found %q", forbidden)
		}
	}
	if strings.Contains(got, `ln -sfn "$pwndbg" "$envbin/gdb"`) {
		t.Fatal("optional pwndbg must not replace the default gdb executable")
	}
	if !strings.Contains(got, ` -nx "$@"`) {
		t.Fatal("the isolated pwndbg entrypoint must not load a conflicting user gdb plugin")
	}
}

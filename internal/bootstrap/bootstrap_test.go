package bootstrap

import (
	"strings"
	"testing"
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

func TestPinnedPwntools(t *testing.T) {
	if got := strings.Join(Plan(Options{}), "\n"); !strings.Contains(got, "pwntools==4.15.0") {
		t.Fatal("pwntools must be pinned")
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

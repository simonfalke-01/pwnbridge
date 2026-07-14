package recipe

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadUsesBoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "recipe.toml")
	link := filepath.Join(dir, "recipe-link.toml")
	data := "schema=1\nname='minimal'\ncomponents=['core']\n"
	if err := os.WriteFile(target, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if loaded, err := Load(link); err != nil || loaded.Name != "minimal" {
		t.Fatalf("load symlinked recipe = %#v, %v", loaded, err)
	}
	oversized := data + "#" + strings.Repeat("x", maxRecipeBytes)
	if err := os.WriteFile(target, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(target); err == nil {
		t.Fatal("oversized recipe was accepted")
	}
}

func TestLoadRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recipe.toml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := Load(path); err == nil {
		t.Fatal("FIFO recipe was accepted")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO recipe rejection took %v", elapsed)
	}
}

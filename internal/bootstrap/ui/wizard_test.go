package ui

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
)

func TestAccessibleWizardUsesInlinePromptsAndConfirms(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	input := &oneByteReader{Reader: strings.NewReader("1\n0\n\n\n\nN\ny\n")}
	var output bytes.Buffer
	result, err := Run(context.Background(), Options{Input: input, Output: &output, Accessible: true, Inventory: healthyInventory(), Profiles: map[string]bootstrap.Recipe{}})
	if err != nil {
		t.Fatalf("%v\n%s", err, output.String())
	}
	if !result.Confirmed || result.Recipe.Name != "pwn" {
		t.Fatalf("result = %#v", result)
	}
	if strings.Contains(output.String(), "\x1b[2J") || strings.Contains(output.String(), "\x1b[?1049") {
		t.Fatal("wizard cleared the terminal or entered alternate screen")
	}
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatal("NO_COLOR output contained ANSI styling")
	}
	if !strings.Contains(output.String(), "Choose a recipe") || !strings.Contains(output.String(), "Apply this exact plan") {
		t.Fatalf("missing inline prompts: %s", output.String())
	}
}

func TestAccessibleWizardCancelBeforeApply(t *testing.T) {
	input := &oneByteReader{Reader: strings.NewReader("2\n0\n\n\n\nN\nN\n")}
	var output bytes.Buffer
	result, err := Run(context.Background(), Options{Input: input, Output: &output, Accessible: true, Inventory: healthyInventory(), Profiles: map[string]bootstrap.Recipe{}})
	if err == nil || result.Confirmed {
		t.Fatalf("cancel result=%#v err=%v", result, err)
	}
}

type oneByteReader struct{ *strings.Reader }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func healthyInventory() bootstrap.Inventory {
	tools := map[string]bool{}
	for _, component := range bootstrap.Catalog() {
		for _, tool := range component.Tools {
			tools[tool] = true
		}
	}
	return bootstrap.Inventory{Host: "lab", OS: "linux", Architecture: "amd64", Distro: "debian", PackageManager: bootstrap.ManagerAPT, Libc: "glibc 2.41", DiskAvailableKiB: 2 * 1024 * 1024, InodesAvailable: 2000, HomeWritable: true, SudoAvailable: true, Tools: tools, PwntoolsVersion: bootstrap.PwntoolsVersion}
}

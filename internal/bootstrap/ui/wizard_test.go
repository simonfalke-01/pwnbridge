package ui

import (
	"bytes"
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
)

func TestAccessibleWizardUsesInlinePromptsAndConfirms(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	input := &oneByteReader{Reader: strings.NewReader("1\n\n\n\n\ny\n")}
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
	if !strings.Contains(output.String(), "Choose a recipe") || !strings.Contains(output.String(), "Apply this exact plan?") {
		t.Fatalf("missing inline prompts: %s", output.String())
	}
}

func TestAccessibleWizardCancelBeforeApply(t *testing.T) {
	input := &oneByteReader{Reader: strings.NewReader("2\n\n\n\n\nn\n")}
	var output bytes.Buffer
	result, err := Run(context.Background(), Options{Input: input, Output: &output, Accessible: true, Inventory: healthyInventory(), Profiles: map[string]bootstrap.Recipe{}})
	if err == nil || result.Confirmed {
		t.Fatalf("cancel result=%#v err=%v", result, err)
	}
}

func TestChoiceHasVisibleSelectionWithoutColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	model := newChoiceModel("Apply this exact plan?", "", "Confirm", []choiceOption{{Label: "Apply", Value: "yes"}, {Label: "Cancel", Value: "no"}}, "no")
	model.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	view := model.View().Content
	if !strings.Contains(view, "› Cancel") {
		t.Fatalf("selected choice has no visible cursor:\n%s", view)
	}
	if strings.Contains(view, "\x1b[") {
		t.Fatalf("NO_COLOR decision contained ANSI styling: %q", view)
	}
}

func TestFinalizeChoicesAreVerticalAndRecipeBindingIsSkippedWhenUnnamed(t *testing.T) {
	model := newFinalizeModel(func(string) error { return nil })
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	model.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if model.page != 2 {
		t.Fatalf("blank recipe name opened page %d, want confirmation page", model.page)
	}
	view := model.View().Content
	if !strings.Contains(view, "  Apply\n› Cancel") {
		t.Fatalf("decisions are not a stable vertical list:\n%s", view)
	}
	if strings.Contains(view, "Bind recipe") {
		t.Fatalf("unnamed recipe showed binding prompt:\n%s", view)
	}
}

func TestChoiceRespondsToNarrowResizeWithoutAlternateScreen(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	model := newChoiceModel("Apply this exact plan?", "No changes happen before confirmation.", "Review  •  3 / 3", []choiceOption{
		{Label: "Apply a deliberately long option label", Value: "yes"},
		{Label: "Cancel", Value: "no"},
	}, "no")
	model.Update(tea.WindowSizeMsg{Width: 24, Height: 12})
	view := model.View()
	if view.AltScreen {
		t.Fatal("inline wizard requested the alternate screen")
	}
	for _, line := range strings.Split(view.Content, "\n") {
		if width := ansi.StringWidth(line); width > 24 {
			t.Errorf("line width %d exceeds terminal width 24: %q", width, line)
		}
	}
}

func TestSpaceTogglesPwndbgComponent(t *testing.T) {
	model := newConfigureModel([]toggleOption{{
		Label: "Pwndbg",
		Value: bootstrap.ComponentPwndbg,
	}}, "", "", func([]string) error { return nil })
	if model.options[0].Selected {
		t.Fatal("Pwndbg unexpectedly starts selected")
	}
	model.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeySpace, Text: " "}))
	if !model.options[0].Selected {
		t.Fatal("space did not select Pwndbg")
	}
	model.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeySpace, Text: " "}))
	if model.options[0].Selected {
		t.Fatal("second space did not deselect Pwndbg")
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

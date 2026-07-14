package ui

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestChoiceHandlesUnicodeGraphemesAtNarrowWidths(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	model := newChoiceModel("選択 👩‍👩‍👧‍👦", "Combining e\u0301 and flag 🏳️‍🌈 remain measurable.", "1 / 4  Recipe", []choiceOption{
		{Label: "界界界界界 joined 👩‍💻", Value: "wide"},
		{Label: "plain", Value: "plain"},
	}, "wide")
	model.Update(tea.WindowSizeMsg{Width: 24, Height: 12})
	view := model.View()
	if view.AltScreen {
		t.Fatal("Unicode choice requested the alternate screen")
	}
	if !strings.Contains(view.Content, "› ") {
		t.Fatalf("Unicode choice lost its visible selection:\n%s", view.Content)
	}
	for _, line := range strings.Split(view.Content, "\n") {
		if width := ansi.StringWidth(line); width > 24 {
			t.Errorf("line width %d exceeds terminal width 24: %q", width, line)
		}
	}
}

func TestInteractiveChoiceRunsWithPipeInput(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	session := newPromptSession(context.Background(), strings.NewReader("\r"), &output, false)
	selected, err := session.choose("Choose 界", "emoji 👩‍👩‍👧‍👦", "1 / 1", []choiceOption{{Label: "pwn 🧰", Value: "pwn"}}, "pwn")
	if err != nil || selected != "pwn" {
		t.Fatalf("pipe-input choice = %q, %v\n%s", selected, err, output.String())
	}
	if strings.Contains(output.String(), "\x1b[?1049") {
		t.Fatal("pipe-input choice entered the alternate screen")
	}
}

type quitOnInitModel struct{ *choiceModel }

func (m quitOnInitModel) Init() tea.Cmd { return tea.Quit }

func TestInteractiveChoiceRestoresWithInputDisabled(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	model := quitOnInitModel{newChoiceModel("Choose 界", "emoji 👩‍👩‍👧‍👦", "1 / 1", []choiceOption{{Label: "pwn", Value: "pwn"}}, "pwn")}
	var output bytes.Buffer
	final, err := tea.NewProgram(model, tea.WithInput(nil), tea.WithOutput(&output)).Run()
	if err != nil {
		t.Fatal(err)
	}
	if final == nil || strings.Contains(output.String(), "\x1b[?1049") {
		t.Fatalf("disabled-input program final=%T output=%q", final, output.String())
	}
}

func FuzzChoiceModelUnicode(f *testing.F) {
	f.Setenv("NO_COLOR", "1")
	for _, seed := range []string{"plain", "界界界", "e\u0301", "👩‍👩‍👧‍👦", "🏳️‍🌈 pwn", "العربية"} {
		f.Add(seed, uint8(24))
	}
	f.Fuzz(func(t *testing.T, label string, rawWidth uint8) {
		if len(label) > 4096 {
			t.Skip()
		}
		label = strings.Map(func(r rune) rune {
			if r < 32 || r == 127 {
				return ' '
			}
			return r
		}, label)
		width := 20 + int(rawWidth%69)
		result := make(chan string, 1)
		go func() { result <- validateChoiceView(label, width) }()
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case problem := <-result:
			if problem != "" {
				t.Fatal(problem)
			}
		case <-timer.C:
			t.Fatalf("choice rendering exceeded 250ms for width %d and label %q", width, label)
		}
	})
}

func validateChoiceView(label string, width int) string {
	model := newChoiceModel("Choose a recipe", "Unicode bootstrap option", "1 / 4  Recipe", []choiceOption{{Label: label, Value: "value"}}, "value")
	model.Update(tea.WindowSizeMsg{Width: width, Height: 12})
	view := model.View()
	if view.AltScreen {
		return "choice requested the alternate screen"
	}
	if !strings.Contains(view.Content, "› ") || strings.Contains(view.Content, "\x1b[") {
		return fmt.Sprintf("plain view lost selection or added styling: %q", view.Content)
	}
	for _, line := range strings.Split(view.Content, "\n") {
		if lineWidth := ansi.StringWidth(line); lineWidth > width {
			return fmt.Sprintf("line width %d exceeds terminal width %d: %q", lineWidth, width, line)
		}
	}
	return ""
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

var benchmarkChoiceView tea.View

func BenchmarkChoiceModelViewUnicode(b *testing.B) {
	b.Setenv("NO_COLOR", "1")
	model := newChoiceModel(
		"Choose a bootstrap recipe 界",
		"Combining e\u0301 · family 👩‍👩‍👧‍👦 · flag 🏳️‍🌈",
		"1 / 4  Recipe",
		[]choiceOption{
			{Label: "pwn — complete default tool set 🧰", Value: "pwn"},
			{Label: "minimal — mandatory capabilities only", Value: "minimal"},
		},
		"pwn",
	)
	model.Update(tea.WindowSizeMsg{Width: 48, Height: 20})
	b.ReportAllocs()
	for b.Loop() {
		benchmarkChoiceView = model.View()
	}
}

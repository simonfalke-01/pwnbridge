// Package ui contains the small inline Bubble Tea adapter used by the Darwin
// client. It is never linked into the Linux agent.
package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
)

type Options struct {
	Input                                io.Reader
	Output                               io.Writer
	Inventory                            bootstrap.Inventory
	Profiles                             map[string]bootstrap.Recipe
	InitialProfile                       string
	With, Without                        []string
	SystemPackages, PipPackages          []string
	NoSudo, AcceptDockerRisk, Accessible bool
}

type Result struct {
	Recipe           bootstrap.Recipe
	Plan             bootstrap.ResolvedPlan
	SaveName         string
	BindHost         bool
	Confirmed        bool
	AcceptDockerRisk bool
}

func Run(ctx context.Context, options Options) (Result, error) {
	if options.Input == nil || options.Output == nil {
		return Result{}, errors.New("wizard requires terminal input and output")
	}
	accessible := options.Accessible || os.Getenv("PWNBRIDGE_ACCESSIBLE") == "1"
	prompts := newPromptSession(ctx, options.Input, options.Output, accessible)
	profile := options.InitialProfile
	if profile == "" {
		profile = "pwn"
	}
	profileOptions := []choiceOption{{Label: "pwn — complete default tool set", Value: "pwn"}, {Label: "minimal — mandatory capabilities only", Value: "minimal"}}
	names := make([]string, 0, len(options.Profiles))
	for name := range options.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		profileOptions = append(profileOptions, choiceOption{Label: name + " — saved recipe", Value: name})
	}
	profileOptions = append(profileOptions, choiceOption{Label: "custom — start from mandatory components", Value: "custom"})
	intro := fmt.Sprintf("Host %s · %s %s · %s · %s/%s\nDisk %d KiB · inodes %d · root=%t sudo=%t",
		options.Inventory.Host, options.Inventory.Distro, options.Inventory.DistroVersion, options.Inventory.PackageManager,
		options.Inventory.OS, options.Inventory.Architecture, options.Inventory.DiskAvailableKiB, options.Inventory.InodesAvailable,
		options.Inventory.Root, options.Inventory.SudoAvailable)
	var err error
	profile, err = prompts.choose("Choose a recipe", intro, "1 / 4  Recipe", profileOptions, profile)
	if err != nil {
		return Result{}, normalizeAbort(err)
	}

	var value bootstrap.Recipe
	var ok bool
	if profile == "custom" {
		value, _ = bootstrap.BuiltinRecipe("minimal")
		value.Name = "custom"
	} else if value, ok = bootstrap.BuiltinRecipe(profile); !ok {
		value, ok = options.Profiles[profile]
	}
	if !ok {
		return Result{}, fmt.Errorf("selected recipe %q no longer exists", profile)
	}
	value, _, err = bootstrap.ResolveRecipe(value, options.With, options.Without, options.SystemPackages, options.PipPackages)
	if err != nil {
		return Result{}, err
	}
	selected := append([]string(nil), value.Components...)
	lockedWith, lockedWithout := stringSet(options.With), stringSet(options.Without)
	componentOptions := make([]toggleOption, 0)
	selectedSet := stringSet(selected)
	for _, component := range bootstrap.Catalog() {
		label := component.Name
		if component.Mandatory {
			label += " (required)"
		} else if lockedWith[component.ID] {
			label += " (locked on by flag)"
		} else if lockedWithout[component.ID] {
			label += " (locked off by flag)"
		}
		componentOptions = append(componentOptions, toggleOption{Label: label, Value: component.ID, Selected: selectedSet[component.ID], Locked: component.Mandatory || lockedWith[component.ID] || lockedWithout[component.ID]})
	}
	systemText, pipText := strings.Join(value.SystemPackages, "\n"), strings.Join(value.PipPackages, "\n")
	selected, systemText, pipText, err = prompts.configure(componentOptions, systemText, pipText, func(values []string) error {
		set := stringSet(values)
		for _, id := range []string{bootstrap.ComponentCore, bootstrap.ComponentGDB, bootstrap.ComponentPython, bootstrap.ComponentPwntools} {
			if !set[id] {
				return fmt.Errorf("%s is mandatory", id)
			}
		}
		for id := range lockedWith {
			if !set[id] {
				return fmt.Errorf("%s is locked on by --with", id)
			}
		}
		for id := range lockedWithout {
			if set[id] {
				return fmt.Errorf("%s is locked off by --without", id)
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, normalizeAbort(err)
	}
	value.Components = selected
	value.SystemPackages, value.PipPackages = nonemptyLines(systemText), nonemptyLines(pipText)
	if stringSet(selected)[bootstrap.ComponentDocker] && !options.Inventory.Root && !options.AcceptDockerRisk {
		accepted, err := prompts.decision(
			"Docker group membership is root-equivalent",
			"A Docker-group member can obtain full root access on this host.",
			"I accept", "Cancel")
		if err != nil {
			return Result{}, normalizeAbort(err)
		}
		if !accepted {
			return Result{}, errors.New("docker root-equivalent group risk was not accepted")
		}
		options.AcceptDockerRisk = true
	}
	value, explanations, err := bootstrap.ResolveRecipe(value, options.With, options.Without, nil, nil)
	if err != nil {
		return Result{}, err
	}
	plan, err := bootstrap.BuildPlan(options.Inventory, value, explanations, bootstrap.PlanOptions{NoSudo: options.NoSudo, AcceptDockerRootRisk: options.AcceptDockerRisk})
	if err != nil {
		return Result{}, err
	}
	fmt.Fprintln(options.Output)
	bootstrap.PrintPlan(options.Output, plan)

	saveName := ""
	bind := false
	confirmed := false
	saveName, bind, confirmed, err = prompts.finalize(func(name string) error {
		if name == "" {
			return nil
		}
		if name == "pwn" || name == "minimal" {
			return errors.New("built-in recipe names are reserved")
		}
		if !validName(name) {
			return errors.New("use only letters, digits, '.', '_', or '-'")
		}
		return nil
	})
	if err != nil {
		return Result{}, normalizeAbort(err)
	}
	if !confirmed {
		return Result{Recipe: value, Plan: plan}, errors.New("bootstrap cancelled before apply")
	}
	if saveName == "" {
		bind = false
	} else {
		value.Name = saveName
	}
	return Result{Recipe: value, Plan: plan, SaveName: saveName, BindHost: bind, Confirmed: true, AcceptDockerRisk: options.AcceptDockerRisk}, nil
}

// FailureChoice returns retry, log, or exit using the same inline/accessibility
// guarantees as the main wizard.
func FailureChoice(ctx context.Context, input io.Reader, output io.Writer, accessible bool, logPath string) (string, error) {
	prompts := newPromptSession(ctx, input, output, accessible || os.Getenv("PWNBRIDGE_ACCESSIBLE") == "1")
	choice, err := prompts.choose("Bootstrap did not complete", "Healthy work is verified and skipped when retrying. Log: "+logPath, "Recovery", []choiceOption{
		{Label: "Retry / resume", Value: "retry"},
		{Label: "Show sanitized log", Value: "log"},
		{Label: "Exit", Value: "exit"},
	}, "retry")
	if err != nil {
		return "exit", normalizeAbort(err)
	}
	return choice, nil
}

func normalizeAbort(err error) error {
	if errors.Is(err, errWizardAborted) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("bootstrap cancelled: %w", context.Canceled)
	}
	return err
}
func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}
func nonemptyLines(value string) []string {
	var result []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}
func validateSystemList(value string) error {
	for _, item := range nonemptyLines(value) {
		candidate := bootstrap.Recipe{Schema: 1, Name: "validate", Components: []string{bootstrap.ComponentCore}, SystemPackages: []string{item}}
		if err := bootstrap.ValidateRecipe(candidate); err != nil {
			return err
		}
	}
	return nil
}
func validatePipList(value string) error {
	for _, item := range nonemptyLines(value) {
		candidate := bootstrap.Recipe{Schema: 1, Name: "validate", Components: []string{bootstrap.ComponentCore}, PipPackages: []string{item}}
		if err := bootstrap.ValidateRecipe(candidate); err != nil {
			return err
		}
	}
	return nil
}
func validName(name string) bool {
	candidate := bootstrap.Recipe{Schema: 1, Name: name, Components: []string{bootstrap.ComponentCore}}
	return bootstrap.ValidateRecipe(candidate) == nil
}

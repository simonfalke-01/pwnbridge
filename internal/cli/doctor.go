package cli

import (
	"context"
	"errors"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/diagnostics"
	"github.com/simonfalke-01/pwnbridge/internal/syncer"
)

const (
	doctorLocalTimeout      = 10 * time.Second
	doctorInventoryTimeout  = 20 * time.Second
	doctorForwardingTimeout = 15 * time.Second
)

type doctorTimeouts struct {
	Local      time.Duration
	Inventory  time.Duration
	Forwarding time.Duration
}

var defaultDoctorTimeouts = doctorTimeouts{
	Local: doctorLocalTimeout, Inventory: doctorInventoryTimeout, Forwarding: doctorForwardingTimeout,
}

type doctorRemoteClient interface {
	RawBounded(context.Context, string, int) ([]byte, error)
	CheckRemoteForwarding(context.Context) error
}

type remoteDoctorOptions struct {
	Recipe             bootstrap.Recipe
	RecipeExplanations []string
	RecipeError        error
	ContainerEngine    string
	ShellTransport     string
	RequireForwarding  bool
	Timeouts           doctorTimeouts
}

func collectLocalDoctor(ctx context.Context, mutagen syncer.Mutagen, shellTransport string, timeouts doctorTimeouts) ([]diagnostics.Check, bool, error) {
	probeContext, cancel := context.WithTimeout(ctx, timeouts.Local)
	checks := diagnostics.Local(probeContext, mutagen, shellTransport)
	probeErr := probeContext.Err()
	cancel()
	complete := true
	if probeErr != nil {
		checks[len(checks)-1] = diagnostics.Failure("mutagen", probeErr, "brew install mutagen-io/mutagen/mutagen", timeouts.Local)
		complete = false
	}
	if err := ctx.Err(); err != nil {
		return checks, false, err
	}
	return checks, complete, nil
}

func collectRemoteDoctor(ctx context.Context, client doctorRemoteClient, options remoteDoctorOptions) ([]diagnostics.Check, bool, error) {
	checks := make([]diagnostics.Check, 0, 32)
	complete := true

	inventoryContext, cancelInventory := context.WithTimeout(ctx, options.Timeouts.Inventory)
	inventory, inventoryErr := bootstrap.Inspect(inventoryContext, client)
	cancelInventory()
	if inventoryErr != nil {
		checks = append(checks, diagnostics.Failure(
			"remote-inventory", inventoryErr,
			"verify destination, key authentication, host key, and a POSIX remote shell", options.Timeouts.Inventory,
		))
		complete = false
	} else if options.RecipeError != nil {
		checks = append(checks, diagnostics.Failure("bootstrap-profile", options.RecipeError, "select an existing bootstrap profile", 0))
		complete = false
	} else {
		plan, err := bootstrap.BuildPlan(inventory, options.Recipe, options.RecipeExplanations, bootstrap.PlanOptions{AcceptDockerRootRisk: true})
		if err != nil {
			checks = append(checks, diagnostics.Failure("bootstrap-plan", err, "validate the selected bootstrap profile", 0))
			complete = false
		} else {
			checks = append(checks, diagnostics.Bootstrap(inventory, plan)...)
			checks = append(checks, configuredRemoteChecks(inventory, options.ContainerEngine, options.ShellTransport)...)
		}
	}
	if err := ctx.Err(); err != nil {
		return checks, false, err
	}

	forwardContext, cancelForward := context.WithTimeout(ctx, options.Timeouts.Forwarding)
	forwardErr := client.CheckRemoteForwarding(forwardContext)
	cancelForward()
	checks = append(checks, forwardingDiagnostic(forwardErr, options.RequireForwarding, options.Timeouts.Forwarding))
	if options.RequireForwarding && (errors.Is(forwardErr, context.DeadlineExceeded) || errors.Is(forwardErr, context.Canceled)) {
		complete = false
	}
	if err := ctx.Err(); err != nil {
		return checks, false, err
	}
	return checks, complete, nil
}

func configuredRemoteChecks(inventory bootstrap.Inventory, containerEngine, shellTransport string) []diagnostics.Check {
	var checks []diagnostics.Check
	if shellTransport == "mosh" {
		ok := inventory.Tools["mosh-server"]
		checks = append(checks, diagnostics.Check{
			Name: "remote-mosh-server", OK: ok, Detail: availabilityDetail(ok), Remediation: "run pwnbridge host bootstrap",
			Component: "mosh", Severity: "error", State: capabilityState(ok),
		})
	}
	if containerEngine != "" {
		ok := inventory.Tools[containerEngine]
		detail := containerEngine
		if containerEngine == "auto" {
			ok = inventory.Tools["podman"] || inventory.Tools["docker"]
			detail = "podman or docker"
		}
		checks = append(checks, diagnostics.Check{
			Name: "remote-container-engine", OK: ok, Detail: detail, Remediation: "install the configured rootless container engine",
			Component: "containers", Severity: "error", State: capabilityState(ok),
		})
	}
	return checks
}

func forwardingDiagnostic(err error, required bool, timeout time.Duration) diagnostics.Check {
	if err == nil {
		return diagnostics.Check{Name: "ssh-reverse-forwarding", OK: true, Detail: "loopback reverse TCP forwarding available", Severity: "error", State: "available"}
	}
	check := diagnostics.Failure("ssh-reverse-forwarding", err, "enable AllowTcpForwarding for this SSH account, or configure terminal.scope=remote", timeout)
	if !required {
		check.OK = true
		check.Detail = "unavailable; terminal.scope=remote does not require it"
		check.Remediation = ""
		check.Severity = "info"
		check.State = "unavailable-optional"
	}
	return check
}

func capabilityState(ok bool) string {
	if ok {
		return "installed"
	}
	return "missing"
}

func availabilityDetail(ok bool) string {
	if ok {
		return "available=true"
	}
	return "available=false"
}

func resolveDoctorRecipe(profile string, profiles map[string]bootstrap.Recipe) (bootstrap.Recipe, []string, error) {
	if profile == "" {
		profile = "pwn"
	}
	value, err := resolveBootstrapRecipe(profile, profiles)
	if err != nil {
		return bootstrap.Recipe{}, nil, err
	}
	return bootstrap.ResolveRecipe(value, nil, nil, nil, nil)
}

func (a *App) emitDoctor(report diagnostics.Report, asJSON bool) error {
	if asJSON {
		return writeJSON(a.Out, report)
	}
	return diagnostics.Render(a.Out, report)
}

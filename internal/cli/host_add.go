package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/simonfalke-01/pwnbridge/internal/bootstrap"
	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/diagnostics"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
)

type hostAddOptions struct {
	ShellTransport string
	MoshPort       string
	Check          bool
	Replace        bool
	Default        bool
	JSON           bool
}

type hostAddResult struct {
	Name        string              `json:"name"`
	Destination string              `json:"destination"`
	Persisted   bool                `json:"persisted"`
	Replaced    bool                `json:"replaced"`
	Default     bool                `json:"default"`
	Check       *diagnostics.Report `json:"check,omitempty"`
}

func (a *App) addHost(ctx context.Context, name, destination string, options hostAddOptions) error {
	if !config.ValidHostName(name) {
		return errors.New("host name must be 1-64 ASCII letters, digits, '.', '_', or '-'")
	}
	effective, err := config.LoadGlobal(a.Paths)
	if err != nil {
		return err
	}
	_, exists := effective.Global.Hosts[name]
	if exists && !options.Replace {
		return fmt.Errorf("host %q already exists; pass --replace to replace it", name)
	}

	candidate := config.Host{
		Destination: destination, Platform: "linux/amd64",
		WorkspaceRoot: "~/.local/share/pwnbridge/workspaces", BootstrapProfile: "pwn",
		ShellTransport: options.ShellTransport, MoshPort: options.MoshPort,
	}
	effective.Global.Hosts[name] = candidate
	if effective.Global.DefaultHost == "" || options.Default {
		effective.Global.DefaultHost = name
	}
	effective.SelectedHost = effective.Global.DefaultHost
	if err := effective.Validate(); err != nil {
		return err
	}

	result := hostAddResult{
		Name: name, Destination: destination, Replaced: exists,
		Default: effective.Global.DefaultHost == name,
	}
	checkedTerminalScope := effective.Global.Terminal.Scope
	if options.Check {
		client := transport.New(destination, "")
		checks, complete, cause := collectHostRegistration(ctx, client, effective.Global.Terminal.Scope != "remote", defaultDoctorTimeouts)
		report := diagnostics.NewReport(checks, complete)
		result.Check = &report
		if !report.OK || cause != nil {
			if err := writeHostAddResult(a.Out, result, options.JSON); err != nil {
				return err
			}
			if cause != nil {
				return cause
			}
			return errors.New("host check failed; configuration was not changed")
		}
	}

	_, err = a.updateGlobal(ctx, func(latest *config.Effective) error {
		if options.Check && latest.Global.Terminal.Scope != checkedTerminalScope {
			return errors.New("global terminal scope changed while the host check was running; retry the checked registration")
		}
		_, result.Replaced = latest.Global.Hosts[name]
		if result.Replaced && !options.Replace {
			return fmt.Errorf("host %q was added while the check was running; retry with --replace only if replacement is intentional", name)
		}
		latest.Global.Hosts[name] = candidate
		if latest.Global.DefaultHost == "" || options.Default {
			latest.Global.DefaultHost = name
		}
		result.Default = latest.Global.DefaultHost == name
		return nil
	})
	if err != nil {
		return err
	}
	result.Persisted = true
	var output bytes.Buffer
	if err := writeHostAddResult(&output, result, options.JSON); err != nil {
		return err
	}
	_, err = output.WriteTo(a.Out)
	return err
}

func collectHostRegistration(ctx context.Context, client doctorRemoteClient, requireForwarding bool, timeouts doctorTimeouts) ([]diagnostics.Check, bool, error) {
	checks := make([]diagnostics.Check, 0, 10)
	complete := true

	inventoryContext, cancelInventory := context.WithTimeout(ctx, timeouts.Inventory)
	inventory, inventoryErr := bootstrap.Inspect(inventoryContext, client)
	cancelInventory()
	if inventoryErr != nil {
		checks = append(checks, diagnostics.Failure(
			"remote-inventory", inventoryErr,
			"verify destination, authentication, host key, and a POSIX remote shell", timeouts.Inventory,
		))
		complete = false
	} else {
		recipe, ok := bootstrap.BuiltinRecipe("pwn")
		if !ok {
			return checks, false, errors.New("built-in pwn bootstrap profile is unavailable")
		}
		resolved, explanations, err := bootstrap.ResolveRecipe(recipe, nil, nil, nil, nil)
		if err != nil {
			checks = append(checks, diagnostics.Failure("bootstrap-plan", err, "validate the built-in pwn bootstrap profile", 0))
			complete = false
		} else if plan, err := bootstrap.BuildPlan(inventory, resolved, explanations, bootstrap.PlanOptions{}); err != nil {
			checks = append(checks, diagnostics.Failure("bootstrap-plan", err, "validate the built-in pwn bootstrap profile", 0))
			complete = false
		} else {
			checks = append(checks, diagnostics.Registration(inventory, plan)...)
		}
	}
	if err := ctx.Err(); err != nil {
		return checks, false, err
	}

	forwardContext, cancelForward := context.WithTimeout(ctx, timeouts.Forwarding)
	forwardErr := client.CheckRemoteForwarding(forwardContext)
	cancelForward()
	checks = append(checks, forwardingDiagnostic(forwardErr, requireForwarding, timeouts.Forwarding))
	if requireForwarding && (errors.Is(forwardErr, context.DeadlineExceeded) || errors.Is(forwardErr, context.Canceled)) {
		complete = false
	}
	if err := ctx.Err(); err != nil {
		return checks, false, err
	}
	return checks, complete, nil
}

func writeHostAddResult(out io.Writer, result hostAddResult, asJSON bool) error {
	if asJSON {
		return writeJSON(out, result)
	}
	if result.Check != nil {
		if err := diagnostics.RenderStatus(out, *result.Check, "host check"); err != nil {
			return err
		}
	}
	if !result.Persisted {
		return nil
	}
	verb := "added"
	if result.Replaced {
		verb = "replaced"
	}
	defaultSuffix := ""
	if result.Default {
		defaultSuffix = "; default"
	}
	_, err := fmt.Fprintf(out, "%s host %s (%s%s)\n", verb, result.Name, result.Destination, defaultSuffix)
	return err
}

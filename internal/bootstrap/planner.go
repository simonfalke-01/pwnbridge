package bootstrap

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type ActionState string

const (
	ActionInstall     ActionState = "install"
	ActionRepair      ActionState = "repair"
	ActionSkip        ActionState = "skip"
	ActionWarning     ActionState = "warning"
	ActionUnsupported ActionState = "unsupported"
)

type Action struct {
	Component   string      `json:"component"`
	State       ActionState `json:"state"`
	Detail      string      `json:"detail"`
	Packages    []string    `json:"packages,omitempty"`
	Privileged  bool        `json:"privileged"`
	Network     bool        `json:"network"`
	Alternative string      `json:"alternative,omitempty"`
}

type Step struct {
	ID          string            `json:"id"`
	Component   string            `json:"component"`
	Description string            `json:"description"`
	Argv        []string          `json:"argv"`
	Environment map[string]string `json:"environment,omitempty"`
	Sudo        bool              `json:"sudo"`
	Network     bool              `json:"network"`
	VerifyArgv  []string          `json:"verify_argv,omitempty"`
}

type ResolvedPlan struct {
	Recipe       Recipe    `json:"recipe"`
	Inventory    Inventory `json:"inventory"`
	Actions      []Action  `json:"actions"`
	Steps        []Step    `json:"steps"`
	Warnings     []string  `json:"warnings,omitempty"`
	Blockers     []string  `json:"blockers,omitempty"`
	Explanations []string  `json:"explanations,omitempty"`
	Downloads    bool      `json:"downloads"`
}

type PlanOptions struct {
	NoSudo               bool
	AcceptDockerRootRisk bool
}

func BuildPlan(inventory Inventory, value Recipe, explanations []string, options PlanOptions) (ResolvedPlan, error) {
	if err := validateCatalog(); err != nil {
		return ResolvedPlan{}, err
	}
	if err := ValidateRecipe(value); err != nil {
		return ResolvedPlan{}, err
	}
	plan := ResolvedPlan{Recipe: value, Inventory: inventory, Explanations: append([]string(nil), explanations...)}
	if inventory.OS != "linux" || inventory.Architecture != "amd64" {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("bootstrap supports linux/amd64; detected %s/%s", inventory.OS, inventory.Architecture))
	}
	if !inventory.HomeWritable {
		plan.Blockers = append(plan.Blockers, "remote home is not writable")
	}
	if inventory.DiskAvailableKiB != 0 && inventory.DiskAvailableKiB < 1024*1024 {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("at least 1 GiB free is required; detected %d KiB", inventory.DiskAvailableKiB))
	}
	if inventory.InodesAvailable != 0 && inventory.InodesAvailable < 1000 {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("at least 1000 free inodes are required; detected %d", inventory.InodesAvailable))
	}
	selected := map[string]bool{}
	for _, id := range value.Components {
		selected[id] = true
	}
	var packages []string
	for _, id := range componentOrder {
		if !selected[id] {
			continue
		}
		component := catalog[id]
		action := Action{Component: id, Privileged: component.Privileged && inventory.PackageManager != ManagerNix, Network: component.Network, Alternative: component.Alternative}
		healthy := componentHealthy(inventory, id, component.Tools)
		switch {
		case id == ComponentPwndbg && strings.Contains(strings.ToLower(inventory.Libc), "musl"):
			action.State, action.Detail = ActionUnsupported, "portable Pwndbg is incompatible with musl"
			action.Alternative = "use a glibc-based Docker/Podman container or install a compatible debugger manually"
			plan.Warnings = append(plan.Warnings, action.Detail+"; "+action.Alternative)
			plan.Blockers = append(plan.Blockers, id+" is unsupported on this host; "+action.Alternative)
		case healthy:
			action.State, action.Detail = ActionSkip, "already healthy"
		case id == ComponentPwntools && inventory.PwntoolsVersion != "":
			action.State, action.Detail = ActionRepair, "managed pwntools version is "+inventory.PwntoolsVersion+", want 4.15.0"
		case id == ComponentPwndbg && inventory.PwndbgVersion != "":
			action.State, action.Detail = ActionRepair, "managed Pwndbg installation is incomplete or outdated"
		case inventory.Immutable && inventory.PackageManager != ManagerNix && component.Privileged:
			action.State, action.Detail = ActionUnsupported, "immutable host has no safe Nix user-profile adapter"
			action.Alternative = containerAlternative(inventory)
			plan.Warnings = append(plan.Warnings, id+": "+action.Detail+"; "+action.Alternative)
			plan.Blockers = append(plan.Blockers, id+" is unsupported on this immutable host; "+action.Alternative)
		case component.Privileged:
			mapped, ok := component.Packages[inventory.PackageManager]
			if !ok && id != ComponentPwntools {
				action.State, action.Detail = ActionUnsupported, "no safe package mapping for "+string(inventory.PackageManager)
				action.Alternative = containerAlternative(inventory)
				plan.Warnings = append(plan.Warnings, id+": "+action.Detail+"; "+action.Alternative)
				plan.Blockers = append(plan.Blockers, id+" has no supported "+string(inventory.PackageManager)+" mapping; "+action.Alternative)
			} else {
				action.State, action.Detail, action.Packages = ActionInstall, "missing required capability", append([]string(nil), mapped...)
				packages = append(packages, mapped...)
			}
		default:
			action.State, action.Detail = ActionInstall, "missing required capability"
			// The apt pwn preset historically included distro pwntools in
			// addition to the authoritative pinned venv. Preserve that package
			// set without making it a prerequisite for --no-sudo operation.
			if id == ComponentPwntools && inventory.PackageManager == ManagerAPT && !options.NoSudo {
				action.Packages = append([]string(nil), component.Packages[ManagerAPT]...)
				packages = append(packages, action.Packages...)
			}
		}
		if action.State != ActionSkip {
			plan.Downloads = plan.Downloads || action.Network
		}
		plan.Actions = append(plan.Actions, action)
	}

	packages = stableUniqueStrings(append(packages, value.SystemPackages...))
	if len(value.SystemPackages) > 0 && inventory.PackageManager == ManagerUnknown {
		plan.Blockers = append(plan.Blockers, "extra system packages require a supported package manager")
	}
	if len(packages) > 0 {
		if inventory.PackageManager == ManagerUnknown {
			plan.Blockers = append(plan.Blockers, "no supported package manager detected (apt, dnf/yum, pacman, zypper, apk, xbps, emerge, or Nix)")
		} else {
			refresh, install := packageSteps(inventory.PackageManager, packages)
			plan.Steps = append(plan.Steps, refresh...)
			plan.Steps = append(plan.Steps, install)
		}
	}

	needsPwntools := !componentHealthy(inventory, ComponentPwntools, nil) || len(value.PipPackages) > 0
	if selected[ComponentPwntools] && needsPwntools {
		plan.Steps = append(plan.Steps, pwntoolsSteps(value.PipPackages)...)
	}
	if selected[ComponentPwndbg] && !componentHealthy(inventory, ComponentPwndbg, nil) && !strings.Contains(strings.ToLower(inventory.Libc), "musl") {
		plan.Steps = append(plan.Steps, pwndbgSteps()...)
	}
	if selected[ComponentDocker] && !componentHealthy(inventory, ComponentDocker, nil) {
		if inventory.ServiceManager == "" || inventory.ServiceManager == "unknown" || inventory.ServiceManager == "runit" {
			plan.Warnings = append(plan.Warnings, "Docker daemon enablement is unsupported for service manager "+inventory.ServiceManager)
			plan.Blockers = append(plan.Blockers, "enable and start the distro Docker service manually, then rerun bootstrap")
		}
		if !inventory.Root {
			warning := "Docker group membership is root-equivalent: members can obtain full root access"
			plan.Warnings = append(plan.Warnings, warning)
			if !options.AcceptDockerRootRisk {
				plan.Blockers = append(plan.Blockers, warning+"; pass --accept-docker-root-risk after reviewing it")
			} else {
				plan.Steps = append(plan.Steps, dockerSetupSteps(inventory)...)
			}
		} else {
			plan.Steps = append(plan.Steps, dockerSetupSteps(inventory)...)
		}
	}
	if options.NoSudo {
		var missing []string
		for _, action := range plan.Actions {
			if action.Privileged && (action.State == ActionInstall || action.State == ActionRepair) {
				missing = append(missing, action.Component)
			}
		}
		if len(value.SystemPackages) > 0 && inventory.PackageManager != ManagerNix {
			missing = append(missing, "extra system packages")
		}
		if len(missing) > 0 {
			plan.Blockers = append(plan.Blockers, "--no-sudo cannot satisfy missing privileged prerequisites: "+strings.Join(stableUniqueStrings(missing), ", "))
		}
		plan.Steps = filterUserSteps(plan.Steps)
	}
	if !inventory.Root && inventory.PackageManager != ManagerNix && hasSudoSteps(plan.Steps) && !inventory.SudoAvailable {
		plan.Blockers = append(plan.Blockers, "privileged steps are required but sudo is unavailable")
	}
	sort.Strings(plan.Blockers)
	plan.Blockers = stableUniqueStrings(plan.Blockers)
	return plan, nil
}

func componentHealthy(inventory Inventory, id string, tools []string) bool {
	switch id {
	case ComponentPwntools:
		return inventory.PwntoolsVersion == "4.15.0"
	case ComponentPwndbg:
		return inventory.PwndbgVersion == PwndbgVersion
	case ComponentDocker:
		return inventory.Tools["docker"] && (inventory.Root || inventory.Tools["docker-group"])
	case ComponentPodman:
		return inventory.Tools["podman"]
	}
	if len(tools) == 0 {
		return false
	}
	for _, tool := range tools {
		if !inventory.Tools[tool] {
			return false
		}
	}
	return true
}

func packageSteps(manager Manager, packages []string) ([]Step, Step) {
	sudo := manager != ManagerNix
	refresh := []Step{}
	var argv []string
	switch manager {
	case ManagerAPT:
		refresh = append(refresh, Step{ID: "packages-repair", Component: "system", Description: "Repair an interrupted dpkg transaction", Argv: []string{"dpkg", "--configure", "-a"}, Sudo: true})
		refresh = append(refresh, Step{ID: "packages-refresh", Component: "system", Description: "Refresh apt metadata", Argv: []string{"apt-get", "update"}, Sudo: true, Network: true})
		argv = append([]string{"apt-get", "-o", "DPkg::Lock::Timeout=120", "install", "-y"}, packages...)
	case ManagerDNF:
		argv = append([]string{"dnf", "install", "-y"}, packages...)
	case ManagerYUM:
		argv = append([]string{"yum", "install", "-y"}, packages...)
	case ManagerPacman:
		argv = append([]string{"pacman", "-Sy", "--needed", "--noconfirm"}, packages...)
	case ManagerZypper:
		refresh = append(refresh, Step{ID: "packages-refresh", Component: "system", Description: "Refresh zypper metadata", Argv: []string{"zypper", "--non-interactive", "refresh"}, Sudo: true, Network: true})
		argv = append([]string{"zypper", "--non-interactive", "install", "--no-recommends"}, packages...)
	case ManagerAPK:
		argv = append([]string{"apk", "add"}, packages...)
	case ManagerXBPS:
		argv = append([]string{"xbps-install", "-S", "-y"}, packages...)
	case ManagerEmerge:
		argv = append([]string{"emerge", "--ask=n", "--nospinner"}, packages...)
	case ManagerNix:
		argv = append([]string{"nix-env", "-iA"}, prefixed(packages, "nixpkgs.")...)
	}
	environment := map[string]string{}
	if manager == ManagerAPT {
		environment["DEBIAN_FRONTEND"] = "noninteractive"
	}
	return refresh, Step{ID: "packages-install", Component: "system", Description: "Install mapped system packages", Argv: argv, Environment: environment, Sudo: sudo, Network: true}
}

func pwntoolsSteps(extra []string) []Step {
	root := "$HOME/.local/share/pwnbridge/envs/pwn-v1"
	steps := []Step{
		{ID: "pwntools-venv", Component: ComponentPwntools, Description: "Create or repair managed Python environment", Argv: []string{"python3", "-m", "venv", "--system-site-packages", root}},
		{ID: "pwntools-base", Component: ComponentPwntools, Description: "Install pinned pwntools", Argv: []string{root + "/bin/pip", "install", "--upgrade", "pip", "wheel", "pwntools==4.15.0"}, Network: true},
	}
	if len(extra) > 0 {
		steps = append(steps, Step{ID: "pip-extra", Component: ComponentPwntools, Description: "Install extra pip requirements", Argv: append([]string{root + "/bin/pip", "install"}, extra...), Network: true})
	}
	steps = append(steps,
		Step{ID: "pip-check", Component: ComponentPwntools, Description: "Verify Python dependencies", Argv: []string{root + "/bin/pip", "check"}},
		Step{ID: "pwntools-verify", Component: ComponentPwntools, Description: "Verify pinned pwntools", Argv: []string{root + "/bin/python", "-c", `import importlib.metadata as m; assert m.version("pwntools") == "4.15.0"`}},
	)
	return steps
}

func pwndbgSteps() []Step {
	return []Step{{ID: "pwndbg-install", Component: ComponentPwndbg, Description: "Install verified portable Pwndbg", Network: true, Argv: []string{"pwnbridge-internal-pwndbg-install", PwndbgVersion, PwndbgURL, PwndbgSHA256}}}
}

func dockerSetupSteps(inventory Inventory) []Step {
	var steps []Step
	switch inventory.ServiceManager {
	case "systemd":
		steps = append(steps, Step{ID: "docker-service", Component: ComponentDocker, Description: "Enable and start Docker", Argv: []string{"systemctl", "enable", "--now", "docker"}, Sudo: true})
	case "openrc":
		steps = append(steps, Step{ID: "docker-enable", Component: ComponentDocker, Description: "Enable Docker with OpenRC", Argv: []string{"rc-update", "add", "docker", "default"}, Sudo: true}, Step{ID: "docker-service", Component: ComponentDocker, Description: "Start Docker with OpenRC", Argv: []string{"rc-service", "docker", "start"}, Sudo: true})
	case "sysv":
		steps = append(steps, Step{ID: "docker-service", Component: ComponentDocker, Description: "Start Docker service", Argv: []string{"service", "docker", "start"}, Sudo: true})
	default:
		// Package installation remains useful, but daemon enablement is an
		// explicit manual prerequisite for unknown/runit layouts.
	}
	if !inventory.Root {
		steps = append(steps, Step{ID: "docker-group", Component: ComponentDocker, Description: "Add current user to root-equivalent Docker group", Argv: []string{"usermod", "-aG", "docker", "$USER"}, Sudo: true})
	}
	return steps
}

func filterUserSteps(steps []Step) []Step {
	result := steps[:0]
	for _, step := range steps {
		if !step.Sudo {
			result = append(result, step)
		}
	}
	return result
}
func hasSudoSteps(steps []Step) bool {
	for _, step := range steps {
		if step.Sudo {
			return true
		}
	}
	return false
}
func prefixed(values []string, prefix string) []string {
	result := make([]string, len(values))
	for i, value := range values {
		if strings.HasPrefix(value, "nixpkgs.") {
			result[i] = value
		} else {
			result[i] = prefix + value
		}
	}
	return result
}
func stableUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func containerAlternative(inventory Inventory) string {
	if inventory.Tools["podman"] {
		return "use the detected Podman container engine"
	}
	if inventory.Tools["docker"] {
		return "use the detected Docker container engine"
	}
	return "install the listed prerequisites manually or use a supported container host"
}

var ErrPlanBlocked = errors.New("bootstrap plan has blockers")

func (p ResolvedPlan) ValidateExecutable() error {
	if len(p.Blockers) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrPlanBlocked, strings.Join(p.Blockers, "; "))
}

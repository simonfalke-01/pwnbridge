package bootstrap

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	bootstraprecipe "github.com/simonfalke-01/pwnbridge/internal/bootstrap/recipe"
)

type Recipe = bootstraprecipe.Recipe

type Manager string

const (
	ManagerAPT     Manager = "apt"
	ManagerDNF     Manager = "dnf"
	ManagerYUM     Manager = "yum"
	ManagerPacman  Manager = "pacman"
	ManagerZypper  Manager = "zypper"
	ManagerAPK     Manager = "apk"
	ManagerXBPS    Manager = "xbps"
	ManagerEmerge  Manager = "emerge"
	ManagerNix     Manager = "nix"
	ManagerUnknown Manager = "unknown"
)

const (
	ComponentCore        = "core"
	ComponentGDB         = "gdb"
	ComponentPython      = "python"
	ComponentPwntools    = "pwntools"
	ComponentPatching    = "patching"
	ComponentTracing     = "tracing"
	ComponentPaneNetwork = "pane-network"
	ComponentMosh        = "mosh"
	ComponentPwndbg      = "pwndbg"
	ComponentPodman      = "podman"
	ComponentDocker      = "docker"
)

var componentOrder = []string{
	ComponentCore, ComponentGDB, ComponentPython, ComponentPwntools,
	ComponentPatching, ComponentTracing, ComponentPaneNetwork, ComponentMosh,
	ComponentPwndbg, ComponentPodman, ComponentDocker,
}

var mandatoryComponents = []string{ComponentCore, ComponentGDB, ComponentPython, ComponentPwntools}

type Component struct {
	ID           string               `json:"id"`
	Name         string               `json:"name"`
	Mandatory    bool                 `json:"mandatory"`
	Dependencies []string             `json:"dependencies,omitempty"`
	Tools        []string             `json:"tools,omitempty"`
	Packages     map[Manager][]string `json:"packages,omitempty"`
	Network      bool                 `json:"network"`
	Privileged   bool                 `json:"privileged"`
	Alternative  string               `json:"alternative,omitempty"`
}

var catalog = map[string]Component{
	ComponentCore: component(ComponentCore, "Core toolchain", true, nil, []string{"bash", "cc", "cmake", "file", "readelf", "git", "curl", "xz"}, map[Manager][]string{
		ManagerAPT:    {"build-essential", "cmake", "file", "binutils", "git", "curl", "ca-certificates", "xz-utils"},
		ManagerDNF:    {"gcc", "gcc-c++", "make", "cmake", "file", "binutils", "git", "curl", "ca-certificates", "xz"},
		ManagerYUM:    {"gcc", "gcc-c++", "make", "cmake", "file", "binutils", "git", "curl", "ca-certificates", "xz"},
		ManagerPacman: {"base-devel", "cmake", "file", "binutils", "git", "curl", "ca-certificates", "xz"},
		ManagerZypper: {"gcc", "gcc-c++", "make", "cmake", "file", "binutils", "git", "curl", "ca-certificates", "xz"},
		ManagerAPK:    {"build-base", "cmake", "file", "binutils", "git", "curl", "ca-certificates", "xz"},
		ManagerXBPS:   {"base-devel", "cmake", "file", "binutils", "git", "curl", "ca-certificates", "xz"},
		ManagerEmerge: {"sys-devel/gcc", "dev-build/cmake", "sys-apps/file", "sys-devel/binutils", "dev-vcs/git", "net-misc/curl", "app-arch/xz-utils"},
		ManagerNix:    {"gcc", "gnumake", "cmake", "file", "binutils", "git", "curl", "cacert", "xz"},
	}, true),
	ComponentGDB: component(ComponentGDB, "GDB", true, []string{ComponentCore}, []string{"gdb", "gdbserver"}, map[Manager][]string{
		ManagerAPT: {"gdb", "gdbserver", "gdb-multiarch", "libc6-dbg"}, ManagerDNF: {"gdb", "gdb-gdbserver"}, ManagerYUM: {"gdb", "gdb-gdbserver"},
		ManagerPacman: {"gdb"}, ManagerZypper: {"gdb", "gdbserver"}, ManagerAPK: {"gdb"}, ManagerXBPS: {"gdb"}, ManagerEmerge: {"sys-devel/gdb"}, ManagerNix: {"gdb"},
	}, true),
	ComponentPython: component(ComponentPython, "Python", true, []string{ComponentCore}, []string{"python3"}, map[Manager][]string{
		ManagerAPT: {"python3", "python3-dev", "python3-venv", "python3-pip", "libssl-dev", "libffi-dev"},
		ManagerDNF: {"python3", "python3-devel", "python3-pip", "openssl-devel", "libffi-devel"}, ManagerYUM: {"python3", "python3-devel", "python3-pip", "openssl-devel", "libffi-devel"},
		ManagerPacman: {"python", "python-pip", "openssl", "libffi"}, ManagerZypper: {"python3", "python3-devel", "python3-pip", "libopenssl-devel", "libffi-devel"},
		ManagerAPK: {"python3", "python3-dev", "py3-pip", "py3-virtualenv", "openssl-dev", "libffi-dev"}, ManagerXBPS: {"python3", "python3-devel", "python3-pip", "openssl-devel", "libffi-devel"},
		ManagerEmerge: {"dev-lang/python", "dev-python/pip", "dev-python/virtualenv", "dev-libs/openssl", "dev-libs/libffi"}, ManagerNix: {"python3", "python3Packages.pip", "openssl", "libffi"},
	}, true),
	ComponentPwntools: {ID: ComponentPwntools, Name: "Pinned pwntools 4.15.0", Mandatory: true, Dependencies: []string{ComponentPython, ComponentCore}, Packages: map[Manager][]string{ManagerAPT: {"python3-pwntools"}}, Network: true},
	ComponentPatching: component(ComponentPatching, "Patching and checksec", false, []string{ComponentCore}, []string{"patchelf", "checksec"}, map[Manager][]string{
		ManagerAPT: {"patchelf", "checksec"}, ManagerDNF: {"patchelf", "checksec"}, ManagerYUM: {"patchelf"}, ManagerPacman: {"patchelf", "checksec"},
		ManagerZypper: {"patchelf", "checksec"}, ManagerAPK: {"patchelf", "checksec"}, ManagerXBPS: {"patchelf", "checksec"}, ManagerEmerge: {"dev-util/patchelf", "sys-apps/checksec"}, ManagerNix: {"patchelf", "checksec"},
	}, true),
	ComponentTracing: component(ComponentTracing, "Tracing", false, nil, []string{"strace", "ltrace"}, map[Manager][]string{
		ManagerAPT: {"strace", "ltrace"}, ManagerDNF: {"strace", "ltrace"}, ManagerYUM: {"strace", "ltrace"}, ManagerPacman: {"strace", "ltrace"},
		ManagerZypper: {"strace", "ltrace"}, ManagerAPK: {"strace", "ltrace"}, ManagerXBPS: {"strace", "ltrace"}, ManagerEmerge: {"dev-debug/strace", "dev-debug/ltrace"}, ManagerNix: {"strace", "ltrace"},
	}, true),
	ComponentPaneNetwork: component(ComponentPaneNetwork, "Pane and network support", false, nil, []string{"tmux", "socat", "nc"}, map[Manager][]string{
		ManagerAPT: {"tmux", "socat", "netcat-openbsd"}, ManagerDNF: {"tmux", "socat", "nmap-ncat"}, ManagerYUM: {"tmux", "socat", "nmap-ncat"}, ManagerPacman: {"tmux", "socat", "openbsd-netcat"},
		ManagerZypper: {"tmux", "socat", "netcat-openbsd"}, ManagerAPK: {"tmux", "socat", "netcat-openbsd"}, ManagerXBPS: {"tmux", "socat", "openbsd-netcat"}, ManagerEmerge: {"app-misc/tmux", "net-misc/socat", "net-analyzer/openbsd-netcat"}, ManagerNix: {"tmux", "socat", "netcat-openbsd"},
	}, true),
	ComponentMosh:   component(ComponentMosh, "Mosh server", false, nil, []string{"mosh-server"}, allPackages("mosh"), true),
	ComponentPwndbg: {ID: ComponentPwndbg, Name: "Pwndbg", Dependencies: []string{ComponentGDB, ComponentPython}, Network: true, Alternative: "use Pwndbg in a glibc-based container or install it manually"},
	ComponentPodman: component(ComponentPodman, "Rootless Podman", false, nil, []string{"podman"}, map[Manager][]string{
		ManagerAPT: {"podman", "uidmap", "slirp4netns", "fuse-overlayfs"}, ManagerDNF: {"podman", "slirp4netns", "fuse-overlayfs"}, ManagerYUM: {"podman", "slirp4netns", "fuse-overlayfs"},
		ManagerPacman: {"podman", "slirp4netns", "fuse-overlayfs"}, ManagerZypper: {"podman", "slirp4netns", "fuse-overlayfs"}, ManagerAPK: {"podman", "shadow-subids", "slirp4netns", "fuse-overlayfs"},
		ManagerXBPS: {"podman", "slirp4netns", "fuse-overlayfs"}, ManagerEmerge: {"app-containers/podman", "net-misc/slirp4netns", "sys-fs/fuse-overlayfs"}, ManagerNix: {"podman", "slirp4netns", "fuse-overlayfs"},
	}, true),
	ComponentDocker: component(ComponentDocker, "Docker Engine", false, nil, []string{"docker"}, map[Manager][]string{
		ManagerAPT: {"docker.io"}, ManagerDNF: {"moby-engine"}, ManagerYUM: {"docker"}, ManagerPacman: {"docker"}, ManagerZypper: {"docker"},
		ManagerAPK: {"docker"}, ManagerXBPS: {"docker"}, ManagerEmerge: {"app-containers/docker"}, ManagerNix: {"docker"},
	}, true),
}

func component(id, name string, mandatory bool, deps, tools []string, packages map[Manager][]string, network bool) Component {
	return Component{ID: id, Name: name, Mandatory: mandatory, Dependencies: deps, Tools: tools, Packages: packages, Network: network, Privileged: true}
}

func allPackages(name string) map[Manager][]string {
	result := map[Manager][]string{}
	for _, manager := range []Manager{ManagerAPT, ManagerDNF, ManagerYUM, ManagerPacman, ManagerZypper, ManagerAPK, ManagerXBPS, ManagerEmerge, ManagerNix} {
		result[manager] = []string{name}
	}
	return result
}

func Catalog() []Component {
	result := make([]Component, 0, len(componentOrder))
	for _, id := range componentOrder {
		result = append(result, catalog[id])
	}
	return result
}

func BuiltinRecipe(name string) (Recipe, bool) {
	var components []string
	switch name {
	case "minimal":
		components = mandatoryComponents
	case "pwn":
		components = []string{ComponentCore, ComponentGDB, ComponentPython, ComponentPwntools, ComponentPatching, ComponentTracing, ComponentPaneNetwork, ComponentMosh}
	default:
		return Recipe{}, false
	}
	return bootstraprecipe.New(name, components...), true
}

func ResolveRecipe(value Recipe, with, without, systemPackages, pipPackages []string) (Recipe, []string, error) {
	selected := map[string]bool{}
	for _, id := range value.Components {
		if _, ok := catalog[id]; !ok {
			return Recipe{}, nil, fmt.Errorf("unknown bootstrap component %q", id)
		}
		selected[id] = true
	}
	for _, id := range mandatoryComponents {
		selected[id] = true
	}
	for _, id := range with {
		if _, ok := catalog[id]; !ok {
			return Recipe{}, nil, fmt.Errorf("unknown bootstrap component %q", id)
		}
		selected[id] = true
	}
	withoutSet := map[string]bool{}
	for _, id := range without {
		component, ok := catalog[id]
		if !ok {
			return Recipe{}, nil, fmt.Errorf("unknown bootstrap component %q", id)
		}
		if component.Mandatory {
			return Recipe{}, nil, fmt.Errorf("mandatory component %q cannot be disabled", id)
		}
		withoutSet[id] = true
		delete(selected, id)
	}
	var explanations []string
	changed := true
	for changed {
		changed = false
		for _, id := range componentOrder {
			if !selected[id] {
				continue
			}
			for _, dependency := range catalog[id].Dependencies {
				if withoutSet[dependency] {
					return Recipe{}, nil, fmt.Errorf("component %q requires explicitly disabled %q", id, dependency)
				}
				if !selected[dependency] {
					selected[dependency] = true
					changed = true
					explanations = append(explanations, fmt.Sprintf("selected %s because %s depends on it", dependency, id))
				}
			}
		}
	}
	// Allocate a new slice so resolution never mutates the caller's recipe
	// through a shared backing array.
	value.Components = make([]string, 0, len(selected))
	for _, id := range componentOrder {
		if selected[id] {
			value.Components = append(value.Components, id)
		}
	}
	value.SystemPackages = append(value.SystemPackages, systemPackages...)
	value.PipPackages = append(value.PipPackages, pipPackages...)
	value = bootstraprecipe.Normalize(value)
	if err := bootstraprecipe.ValidatePortable(value); err != nil {
		return Recipe{}, nil, err
	}
	return value, explanations, nil
}

func ValidateRecipe(value Recipe) error {
	if err := bootstraprecipe.ValidatePortable(value); err != nil {
		return err
	}
	_, _, err := ResolveRecipe(value, nil, nil, nil, nil)
	return err
}

func AvailableComponentIDs() []string { return append([]string(nil), componentOrder...) }

func ParseRecipe(data []byte) (Recipe, error)    { return bootstraprecipe.Parse(data) }
func LoadRecipe(path string) (Recipe, error)     { return bootstraprecipe.Load(path) }
func MarshalRecipe(value Recipe) ([]byte, error) { return bootstraprecipe.Marshal(value) }

func ParseComponentList(values []string) ([]string, error) {
	var result []string
	for _, value := range values {
		for _, id := range strings.Split(value, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if _, ok := catalog[id]; !ok {
				return nil, fmt.Errorf("unknown bootstrap component %q (choose from %s)", id, strings.Join(componentOrder, ", "))
			}
			result = append(result, id)
		}
	}
	return result, nil
}

func validateCatalog() error {
	seen := map[string]bool{}
	for _, id := range componentOrder {
		if seen[id] || catalog[id].ID != id {
			return errors.New("invalid component catalog ordering")
		}
		seen[id] = true
		for _, dependency := range catalog[id].Dependencies {
			if _, ok := catalog[dependency]; !ok {
				return fmt.Errorf("component %s has unknown dependency %s", id, dependency)
			}
		}
	}
	if len(seen) != len(catalog) {
		keys := make([]string, 0, len(catalog))
		for id := range catalog {
			keys = append(keys, id)
		}
		sort.Strings(keys)
		return fmt.Errorf("component order does not cover catalog: %v", keys)
	}
	return nil
}

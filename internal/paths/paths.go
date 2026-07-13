package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct {
	Config string
	State  string
	Data   string
	Cache  string
}

func Resolve() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve home directory: %w", err)
	}
	return Paths{
		Config: resolveXDG("XDG_CONFIG_HOME", filepath.Join(home, ".config")),
		State:  resolveXDG("XDG_STATE_HOME", filepath.Join(home, ".local", "state")),
		Data:   resolveXDG("XDG_DATA_HOME", filepath.Join(home, ".local", "share")),
		Cache:  resolveXDG("XDG_CACHE_HOME", filepath.Join(home, ".cache")),
	}, nil
}

func resolveXDG(name, fallback string) string {
	if value := os.Getenv(name); value != "" && filepath.IsAbs(value) {
		return filepath.Join(value, "pwnbridge")
	}
	return filepath.Join(fallback, "pwnbridge")
}

func (p Paths) Ensure() error {
	for _, dir := range []string{p.Config, p.State, p.Data, p.Cache} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("secure %s: %w", dir, err)
		}
	}
	return nil
}

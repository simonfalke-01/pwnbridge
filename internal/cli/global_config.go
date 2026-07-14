package cli

import (
	"context"
	"path/filepath"

	"github.com/simonfalke-01/pwnbridge/internal/config"
	"github.com/simonfalke-01/pwnbridge/internal/workspace"
)

// updateGlobal serializes CLI read-modify-write transactions and reloads the
// latest durable file while holding the lock. Slow network and UI work must be
// completed before entering the callback.
func (a *App) updateGlobal(ctx context.Context, update func(*config.Effective) error) (config.Effective, error) {
	if err := ctx.Err(); err != nil {
		return config.Effective{}, err
	}
	lock, err := workspace.AcquireLock(filepath.Join(a.Paths.State, "global-config.lock"))
	if err != nil {
		return config.Effective{}, err
	}
	defer lock.Close()
	if err := ctx.Err(); err != nil {
		return config.Effective{}, err
	}
	effective, err := config.LoadGlobal(a.Paths)
	if err != nil {
		return config.Effective{}, err
	}
	if err := update(&effective); err != nil {
		return config.Effective{}, err
	}
	effective.SelectedHost = effective.Global.DefaultHost
	if err := effective.Validate(); err != nil {
		return config.Effective{}, err
	}
	if err := ctx.Err(); err != nil {
		return config.Effective{}, err
	}
	if err := config.SaveGlobal(effective.GlobalPath, effective.Global); err != nil {
		return config.Effective{}, err
	}
	return effective, nil
}

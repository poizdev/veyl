//go:build linux

package app

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/poizdev/veyl/internal/mountpoint"
	"github.com/poizdev/veyl/internal/storage"
)

// OriginalLocation records the physical objects approved at setup. It does not
// refer to plaintext storage: the original target must remain empty forever.
type OriginalLocation struct {
	ParentDevice uint64 `json:"parent_device"`
	ParentInode  uint64 `json:"parent_inode"`
	TargetDevice uint64 `json:"target_device"`
	TargetInode  uint64 `json:"target_inode"`
}

func inspectOriginal(target string) (*OriginalLocation, error) {
	parent := filepath.Dir(target)
	if parent == "/" || parent == os.Getenv("HOME") || target == os.Getenv("HOME") {
		return nil, errors.New("Refusing to cover HOME or the system root. Choose an empty target in a dedicated owned parent.")
	}
	if storage.ValidateDirectory(parent, false) != nil || storage.ValidateDirectory(target, false) != nil {
		return nil, errors.New("Original target and parent must be owned directories without symlinks or unsafe permissions.")
	}
	if _, err := mountpoint.Validate(target); err != nil {
		return nil, errors.New("Original-path setup requires an empty directory. Populated targets and legacy workspaces are refused; no migration is performed.")
	}
	mounted, err := storage.HasMountsUnder(parent)
	if err != nil || mounted {
		return nil, errors.New("Original parent contains an existing mount or stale mount. Inspect mount metadata and recover it before activation.")
	}
	if err := mountpoint.ValidatePublicTree(parent); err != nil {
		return nil, err
	}
	p, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	t, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	ps := p.Sys().(*syscall.Stat_t)
	ts := t.Sys().(*syscall.Stat_t)
	return &OriginalLocation{uint64(ps.Dev), ps.Ino, uint64(ts.Dev), ts.Ino}, nil
}

func (c Config) validateOriginalMount() error {
	location, err := inspectOriginal(filepath.Join(c.Mountpoint, c.HiddenName))
	if err != nil {
		return err
	}
	if *location != *c.Original {
		return errors.New("Original parent or target was replaced. Nothing was adopted; inspect the registered paths before recovery.")
	}
	if storage.ValidateDirectory(c.RuntimeDir, true) != nil {
		return errRuntime
	}
	for _, p := range []string{c.RuntimeDir, c.Store} {
		if beneath(c.Mountpoint, p) || beneath(p, c.Mountpoint) {
			return errConfig
		}
		if mounted, err := storage.HasMountsUnder(p); err != nil || mounted {
			return errCleanupPending
		}
	}
	return nil
}

//go:build linux

package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/poizdev/veyl/internal/storage"
)

type serviceFiles struct{ directory, registration, unit string }

func userServiceFiles() (serviceFiles, error) {
	base, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(base) || filepath.Clean(base) != base || strings.ContainsAny(base, "\x00\r\n") {
		return serviceFiles{}, errors.New("Cannot determine a safe user configuration directory. Check XDG_CONFIG_HOME.")
	}
	directory := filepath.Join(base, "veyl")
	return serviceFiles{directory: directory, registration: filepath.Join(directory, "default-config"), unit: filepath.Join(base, "systemd", "user", "veyl.service")}, nil
}

// The registration is an owned pointer to an unchanged version 1 config.
// LoadConfig still opens the target with O_NOFOLLOW; config symlinks are rejected.
func registeredConfig() (string, error) {
	files, err := userServiceFiles()
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(files.registration)
	if os.IsNotExist(err) {
		return "", os.ErrNotExist
	}
	if err != nil || storage.ValidateDirectory(files.directory, true) != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("Cannot read Veyl's default configuration registration. Inspect the private user configuration directory.")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return "", errConfig
	}
	path, err := os.Readlink(files.registration)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return "", errConfig
	}
	return path, nil
}

func discoverConfig(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	// Do not probe protected contents merely to discover configuration. Apart
	// from prompting, a local document named veyl.json is not management data.
	// PWD is only a discovery hint, never an authorization or safety decision.
	if path, err := registeredConfig(); err == nil {
		if c, err := LoadConfig(path); err == nil && c.Original != nil {
			pwd := os.Getenv("PWD")
			if filepath.IsAbs(pwd) && filepath.Clean(pwd) == pwd && beneath(filepath.Join(c.Mountpoint, c.HiddenName), pwd) {
				return path, nil
			}
		}
	}
	local, err := filepath.Abs("veyl.json")
	if err != nil {
		return "", errConfig
	}
	if _, err := os.Lstat(local); err == nil {
		return local, nil
	} else if !os.IsNotExist(err) {
		return "", errConfig
	}
	path, err := registeredConfig()
	if os.IsNotExist(err) {
		return "", errors.New("No configuration found. Run veyl init here, pass --config FILE, or enable a default with veyl service enable --config FILE.")
	}
	return path, err
}

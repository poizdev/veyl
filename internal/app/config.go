//go:build linux

package app

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/poizdev/veyl/internal/mountpoint"
	"github.com/poizdev/veyl/internal/policy"
	"github.com/poizdev/veyl/internal/storage"
	"golang.org/x/sys/unix"
)

type Config struct {
	Original        *OriginalLocation `json:"original,omitempty"`
	ExplicitUnlock  bool              `json:"explicit_unlock,omitempty"`
	Parent          string            `json:"parent,omitempty"`
	ReadOnly        *bool             `json:"read_only,omitempty"`
	Version         int               `json:"version"`
	Store           string            `json:"store"`
	Mountpoint      string            `json:"mountpoint"`
	HiddenName      string            `json:"hidden_name"`
	RuntimeDir      string            `json:"runtime_dir"`
	CredentialAgent string            `json:"credential_agent"`
}

var errConfig = errors.New("Invalid configuration. Use an owned version 1 or original-path version 2 config with absolute, separate paths; see veyl help mount.")

func LoadConfig(path string) (Config, error) {
	var c Config
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return c, errConfig
	}
	f := os.NewFile(uintptr(fd), "veyl-config")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 || info.Mode().Perm()&0022 != 0 {
		return c, errConfig
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return c, errConfig
	}
	dec := json.NewDecoder(io.LimitReader(f, 16385))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil {
		return c, errConfig
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return c, errConfig
	}
	if c.HiddenName == "" {
		c.HiddenName = policy.GhostName
	}
	if c.CredentialAgent == "" {
		c.CredentialAgent = "auto"
	}
	if (c.Version != 1 && c.Version != 2) || (c.Version == 2) != (c.Original != nil) || !validName(c.HiddenName) || (c.Version == 1 && c.HiddenName == policy.VisibleName) {
		return c, errConfig
	}
	if c.Original != nil && (c.Parent != "" || c.Original.ParentInode == 0 || c.Original.TargetInode == 0) {
		return c, errConfig
	}
	paths := []string{c.Store, c.Mountpoint, c.RuntimeDir}
	if c.Parent != "" {
		paths = append(paths, c.Parent)
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return c, errConfig
		}
	}
	for i, p := range paths {
		for j, q := range paths {
			if i != j && beneath(p, q) {
				return c, errConfig
			}
		}
	}
	if c.CredentialAgent != "auto" && c.CredentialAgent != "none" && (!filepath.IsAbs(c.CredentialAgent) || beneath(c.Mountpoint, c.CredentialAgent)) {
		return c, errConfig
	}
	absolute, err := filepath.Abs(path)
	if err != nil || beneath(c.Mountpoint, absolute) {
		return c, errConfig
	}
	return c, nil
}
func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00\r\n")
}
func beneath(parent, path string) bool {
	return path == parent || strings.HasPrefix(path, parent+"/") || parent == "/"
}
func (c Config) validateMount() error {
	if c.Mountpoint == "/" || c.Mountpoint == os.Getenv("HOME") {
		return errors.New("Choose an empty mountpoint outside your home directory itself.")
	}
	if c.Original != nil {
		return c.validateOriginalMount()
	}
	if _, err := mountpoint.Validate(c.Mountpoint); err != nil {
		return errors.New("Mountpoint must be an existing empty directory without symlinks. Choose a new empty directory.")
	}
	if storage.ValidateDirectory(c.Mountpoint, false) != nil || storage.ValidateDirectory(c.RuntimeDir, true) != nil {
		return errors.New("Mountpoint must be owned and controlled by you; runtime directory must be owned by you with mode 0700.")
	}
	for _, p := range []string{c.Mountpoint, c.RuntimeDir} {
		mounted, err := storage.HasMountsUnder(p)
		if err != nil || mounted {
			return errors.New("An existing mount or cleanup residue prevents startup. Inspect veyl status and finish cleanup first.")
		}
	}
	if c.Parent != "" {
		if storage.ValidateDirectory(c.Parent, false) != nil {
			return errors.New("Managed parent must be a separate directory owned by you, without symlinks or shared write permissions.")
		}
		if mounted, err := storage.HasMountsUnder(c.Parent); err != nil || mounted {
			return errors.New("Managed parent must not contain mounts. Choose a separate backing directory to avoid namespace loops.")
		}
		if _, err := os.Lstat(filepath.Join(c.Parent, c.HiddenName)); !os.IsNotExist(err) {
			return errors.New("Managed parent contains the reserved hidden name. No files were moved; choose a separate backing directory without that name.")
		}
	}
	return nil
}

// Missing read_only preserves existing release-candidate configurations.
func (c Config) Writable() bool { return c.ReadOnly != nil && !*c.ReadOnly }

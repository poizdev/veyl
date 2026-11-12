//go:build linux

package storage

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type mountEntry struct {
	ID                 uint64
	Path, Type, Source string
}

func parseMountInfo(text string) ([]mountEntry, error) {
	var entries []mountEntry
	unescape := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		split := -1
		for i, value := range fields {
			if value == "-" {
				split = i
				break
			}
		}
		if len(fields) < 10 || split < 6 || split+3 >= len(fields) {
			return nil, ErrUnsafe
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 {
			return nil, ErrUnsafe
		}
		entries = append(entries, mountEntry{ID: id, Path: unescape.Replace(fields[4]), Type: fields[split+1], Source: unescape.Replace(fields[split+2])})
	}
	return entries, nil
}
func readMountInfo() ([]mountEntry, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, ErrUnsafe
	}
	return parseMountInfo(string(data))
}
func within(parent, path string) bool {
	return path == parent || strings.HasPrefix(path, parent+string(os.PathSeparator))
}

// Only root or this uid may control the path. Sticky shared parents such as
// /tmp protect our owned child entries; nonsticky shared-writable parents do not.
func safeAncestors(path string) error {
	// A user namespace can report the read-only system root's owner as an
	// unmapped uid. Trust read-only system ancestors, and that system owner's
	// sticky shared directory (e.g. /tmp), without trusting writable strangers.
	root, err := os.Stat("/")
	if err != nil {
		return ErrUnsafe
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrUnsafe
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return ErrUnsafe
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUnsafe
		}
		sticky := info.Mode()&os.ModeSticky != 0
		if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			var filesystem syscall.Statfs_t
			if err := syscall.Statfs(current, &filesystem); err != nil {
				return ErrUnsafe
			}
			readonly := filesystem.Flags&syscall.MS_RDONLY != 0
			if !readonly && !(sticky && stat.Uid == rootStat.Uid) {
				return ErrUnsafe
			}
		}
		if info.Mode().Perm()&0022 != 0 && !sticky {
			return ErrUnsafe
		}
		if current == "/" {
			break
		}
	}
	return nil
}

func safeDirectory(path string, private bool) (os.FileInfo, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafe
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, ErrUnsafe
	}
	if err := safeAncestors(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return nil, ErrUnsafe
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return nil, ErrUnsafe
	}
	if private && info.Mode().Perm() != 0700 {
		return nil, ErrUnsafe
	}
	return info, nil
}
func (b *Backend) validatePaths() error {
	if _, err := safeDirectory(b.cfg.Store, false); err != nil {
		return err
	}
	if _, err := safeDirectory(b.cfg.RuntimeDir, true); err != nil {
		return err
	}
	if within(b.cfg.Store, b.cfg.RuntimeDir) || within(b.cfg.RuntimeDir, b.cfg.Store) {
		return ErrUnsafe
	}
	info, err := os.Lstat(filepath.Join(b.cfg.Store, "gocryptfs.conf"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return ErrUnsafe
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrUnsafe
	}
	entries, err := b.ops.mounts()
	if err != nil {
		return ErrUnsafe
	}
	for _, entry := range entries {
		if entry.Path == b.cfg.Store || within(b.cfg.RuntimeDir, entry.Path) || entry.Type == "fuse.gocryptfs" && entry.Source == b.cfg.Store {
			return ErrBusy
		}
	}
	return nil
}

// A pathname unmount cannot safely select among stacked mounts. Reject
// ambiguity instead of guessing which mountinfo record is topmost.
func findMount(entries []mountEntry, path string) (mountEntry, bool, error) {
	var match mountEntry
	found := false
	for _, entry := range entries {
		if entry.Path == path {
			if found {
				return mountEntry{}, false, ErrUnsafe
			}
			match = entry
			found = true
		}
	}
	return match, found, nil
}
func (b *Backend) entry(path string) (mountEntry, bool, error) {
	entries, err := b.ops.mounts()
	if err != nil {
		return mountEntry{}, false, ErrUnsafe
	}
	return findMount(entries, path)
}

func (b *Backend) owns(m *mount, entry mountEntry) bool {
	return entry.Type == "fuse.gocryptfs" && entry.Source == b.cfg.Store && (m.id == 0 || m.id == entry.ID)
}
func lockStore(path string) (*os.File, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, ErrUnsafe
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		dir.Close()
		return nil, ErrBusy
	}
	return dir, nil
}

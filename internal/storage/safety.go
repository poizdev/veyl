//go:build linux

package storage

// ValidateDirectory reuses backend path ownership and ancestor checks for the
// foreground host's private runtime and explicit mountpoint.
func ValidateDirectory(path string, private bool) error {
	_, err := safeDirectory(path, private)
	return err
}

// HasMountsUnder reports mount-table entries at or beneath path, without reading
// their contents. Hosts use this to reject existing mounts and orphan residues.
func HasMountsUnder(path string) (bool, error) {
	entries, err := readMountInfo()
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if within(path, entry.Path) {
			return true, nil
		}
	}
	return false, nil
}

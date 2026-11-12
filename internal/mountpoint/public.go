package mountpoint

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ValidatePublicTree is a pre-mount compatibility gate, not migration. Inspect
// only names/types, never contents or symlink targets. Covering an existing IPC
// endpoint with a view that cannot serve it would silently break a sibling.
func ValidatePublicTree(parent string) error {
	return filepath.WalkDir(parent, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("Cannot inspect original-parent siblings safely; nothing was mounted.")
		}
		if entry.IsDir() || entry.Type().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return fmt.Errorf("Original parent contains an unsupported sibling object at %q (FIFO, socket, or device). Choose a dedicated parent; nothing was mounted or moved.", path)
	})
}

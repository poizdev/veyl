// Package mountpoint validates a caller-supplied directory without modifying it.
package mountpoint

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Validate requires an existing empty directory with no symlink components.
// The caller must prevent concurrent replacement of this path or its parents.
func Validate(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("an explicit mountpoint is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("mountpoint: %w", err)
	}
	if resolved != absolute {
		return "", fmt.Errorf("mountpoint must not contain symlinks")
	}
	dir, err := os.Open(absolute)
	if err != nil {
		return "", fmt.Errorf("open mountpoint: %w", err)
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("mountpoint must be a directory")
	}
	_, err = dir.Readdirnames(1)
	if err == nil {
		return "", fmt.Errorf("mountpoint must be empty")
	}
	if err != io.EOF {
		return "", fmt.Errorf("read mountpoint: %w", err)
	}
	return absolute, nil
}

//go:build linux

package storage

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// Initialize initializes only an owned, private, empty directory. It never
// mounts or deletes anything; callers retain any partial encrypted output.
// Credentials use the same anonymous inherited pipe as ordinary mounts.
func Initialize(ctx context.Context, store string, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validPassword(password) {
		return ErrCredentials
	}
	if _, err := safeDirectory(store, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(store)
	if err != nil || len(entries) != 0 {
		return ErrUnsafe
	}
	binary, err := resolveBinary("", "gocryptfs")
	if err != nil {
		return err
	}
	p, err := startCommand(binary, []string{"-init", "-q", "-nosyslog", "-passfile", credentialFD, "--", store}, password)
	if err != nil {
		return err
	}
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	select {
	case <-p.Done():
	case <-ctx.Done():
		b := &Backend{cfg: Config{StopTimeout: 3 * time.Second}}
		if !b.stopChild(p) {
			return ErrCleanup
		}
		return ctx.Err()
	case <-timer.C:
		b := &Backend{cfg: Config{StopTimeout: 3 * time.Second}}
		if !b.stopChild(p) {
			return ErrCleanup
		}
		return context.DeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.ExitCode() != 0 {
		return ErrMount
	}
	info, err := os.Lstat(filepath.Join(store, "gocryptfs.conf"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return ErrUnsafe
	}
	return nil
}

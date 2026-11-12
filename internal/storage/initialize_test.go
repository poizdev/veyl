//go:build linux

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeRefusesDataAndCancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keep")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(context.Background(), dir, []byte("synthetic")); err == nil {
		t.Fatal("nonempty store accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("data changed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Initialize(ctx, dir, []byte("synthetic")); err != context.Canceled {
		t.Fatal(err)
	}
}

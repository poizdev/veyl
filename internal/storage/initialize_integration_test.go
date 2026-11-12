//go:build integration && linux

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeRealStore(t *testing.T) {
	realBinary(t)
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic-initialization-password")
	defer clear(password)
	if err := Initialize(context.Background(), dir, password); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "gocryptfs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(context.Background(), dir, password); err == nil {
		t.Fatal("existing store accepted")
	}
	after, err := os.ReadFile(filepath.Join(dir, "gocryptfs.conf"))
	if err != nil || string(before) != string(after) {
		t.Fatal("existing configuration changed", err)
	}
}

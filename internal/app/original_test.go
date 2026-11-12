//go:build linux

package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOriginalInitRefusesPopulatedTarget(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "keep")
	if err := os.WriteFile(sentinel, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"init", "--dir", dir}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "empty") {
		t.Fatalf("%d: %s", code, &errs)
	}
	if out.Len() != 0 {
		t.Fatal("prompted before rejecting source")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "source" {
		t.Fatal("source changed", err)
	}
}

func TestOriginalConfigAllowsOnlyIdentifiedEmptyTarget(t *testing.T) {
	c, path := fixtureConfig(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "test")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	c.Version = 2
	c.Mountpoint = parent
	c.HiddenName = "test"
	var err error
	c.Original, err = inspectOriginal(target)
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, path, c)
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.validateMount(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "source"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if loaded.validateMount() == nil {
		t.Fatal("accepted populated target")
	}
}

func TestOriginalDiscoveryAvoidsProtectedLocalConfigProbe(t *testing.T) {
	c, path := fixtureConfig(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "test")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	c.Version = 2
	c.Mountpoint = parent
	c.HiddenName = "test"
	var err error
	c.Original, err = inspectOriginal(target)
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, path, c)
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	files, err := userServiceFiles()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(files.directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, files.registration); err != nil {
		t.Fatal(err)
	}
	t.Chdir(target)
	t.Setenv("PWD", target)
	// A protected document called veyl.json must not become a config, nor
	// should discovery touch it and request authentication after lock.
	if err := os.WriteFile(filepath.Join(target, "veyl.json"), []byte("ordinary encrypted document"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := discoverConfig("")
	if err != nil || got != path {
		t.Fatal(got, err)
	}
}

func TestOriginalInitRefusesUnsupportedSiblingBeforePrompt(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	parent := t.TempDir()
	target := filepath.Join(parent, "test")
	neighbor := filepath.Join(parent, "neighbor")
	for _, p := range []string{target, neighbor} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(neighbor, "ipc"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"init", "--dir", target}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "unsupported") || out.Len() != 0 {
		t.Fatalf("%d: %s %s", code, &out, &errs)
	}
}

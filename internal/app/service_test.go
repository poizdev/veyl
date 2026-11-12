//go:build linux

package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigDiscovery(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	xdg := filepath.Join(root, "config")
	if err := os.Mkdir(xdg, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"status"}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "configuration") {
		t.Fatalf("missing config: %d %s", code, &errs)
	}
	c, path := fixtureConfig(t)
	registration := filepath.Join(xdg, "veyl", "default-config")
	if err := os.Mkdir(filepath.Dir(registration), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, registration); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := Run(context.Background(), []string{"status"}, &out, &errs); code != 3 {
		t.Fatalf("registered config: %d %s", code, &errs)
	}
	writeConfig(t, filepath.Join(root, "veyl.json"), c)
	out.Reset()
	errs.Reset()
	if code := Run(context.Background(), []string{"status"}, &out, &errs); code != 3 {
		t.Fatalf("local config: %d %s", code, &errs)
	}
}

func TestServiceHelp(t *testing.T) {
	for _, args := range [][]string{{"service", "--help"}, {"help", "service"}} {
		var out, errs bytes.Buffer
		if code := Run(context.Background(), args, &out, &errs); code != 0 || !strings.Contains(out.String(), "enable") || !strings.Contains(out.String(), "disable") {
			t.Fatalf("%v: %d %s %s", args, code, &out, &errs)
		}
	}
}

//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureConfig(t *testing.T) (Config, string) {
	t.Helper()
	base := t.TempDir()
	c := Config{Version: 1, Store: filepath.Join(base, "cipher"), Mountpoint: filepath.Join(base, "mount"), RuntimeDir: filepath.Join(base, "runtime"), HiddenName: ".vault", CredentialAgent: "none"}
	for _, p := range []string{c.Store, c.Mountpoint, c.RuntimeDir} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(c.Store, "gocryptfs.conf"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "config.json")
	writeConfig(t, path, c)
	return c, path
}
func writeConfig(t *testing.T, path string, c Config) {
	t.Helper()
	data, _ := json.Marshal(c)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestCLIHelpAndInvalidCommands(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}, {"help", "mount"}, {"version"}} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, &out, &errOut); code != 0 || out.Len() == 0 {
			t.Fatalf("%v: %d %s", args, code, errOut.String())
		}
	}
	for _, args := range [][]string{nil, {"unknown"}, {"/tmp/not-a-command"}, {"mount", "--config"}, {"unlock", "--password", "never-accept"}} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, &out, &errOut); code != 2 || errOut.Len() == 0 {
			t.Fatalf("%v: %d %s", args, code, errOut.String())
		}
		if strings.Contains(errOut.String(), "never-accept") {
			t.Fatal("unknown arguments echoed")
		}
	}
}
func TestConfigAndMountSafety(t *testing.T) {
	c, path := fixtureConfig(t)
	loaded, err := LoadConfig(path)
	if err != nil || loaded.HiddenName != ".vault" {
		t.Fatal("load config", err)
	}
	if err := loaded.validateMount(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Mountpoint, "data"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := loaded.validateMount(); err == nil {
		t.Fatal("nonempty target accepted")
	}
	os.Remove(filepath.Join(c.Mountpoint, "data"))
	t.Setenv("HOME", c.Mountpoint)
	if err := loaded.validateMount(); err == nil {
		t.Fatal("HOME accepted")
	}
	t.Setenv("HOME", filepath.Dir(c.Mountpoint))
	for _, mutate := range []func(*Config){func(c *Config) { c.Version = 2 }, func(c *Config) { c.HiddenName = "../escape" }, func(c *Config) { c.Store = "relative" }, func(c *Config) { c.RuntimeDir = c.Store }, func(c *Config) { c.Mountpoint = filepath.Join(c.Store, "nested") }} {
		bad := c
		mutate(&bad)
		writeConfig(t, path, bad)
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestStatusWithoutProcessAndWithResidue(t *testing.T) {
	c, path := fixtureConfig(t)
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"status", "--config", path}, &out, &errOut); code != 3 {
		t.Fatalf("absent instance: %d %s", code, errOut.String())
	}
	if err := os.MkdirAll(filepath.Join(c.RuntimeDir, "views", "residue"), 0700); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"status", "--config", path}, &out, &errOut); code != 5 {
		t.Fatalf("residue ignored: %d %s", code, errOut.String())
	}
}

func TestManagedParentConfiguration(t *testing.T) {
	c, path := fixtureConfig(t)
	c.Parent = filepath.Join(filepath.Dir(path), "siblings")
	if err := os.Mkdir(c.Parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Parent, "neighbor"), []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, path, c)
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Writable() {
		t.Fatal("legacy config became writable")
	}
	if err := loaded.validateMount(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(c.Parent, c.HiddenName), 0700); err != nil {
		t.Fatal(err)
	}
	if err := loaded.validateMount(); err == nil {
		t.Fatal("reserved name collision allowed")
	}
	c.Parent = filepath.Dir(c.Mountpoint)
	writeConfig(t, path, c)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("nested managed paths allowed")
	}
}

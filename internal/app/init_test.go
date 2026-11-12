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

func TestInitExistingWorkspaceCancellation(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "current directory"
		if explicit {
			name = "explicit directory"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sentinel := filepath.Join(dir, "keep")
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(dir)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			args := []string{"init", "--legacy-workspace", "--tty"}
			if explicit {
				args = append(args, "--dir", dir)
			}
			var out, errs bytes.Buffer
			if code := Run(ctx, args, &out, &errs); code != 4 {
				t.Fatalf("%d: %s", code, &errs)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "keep" {
				t.Fatalf("workspace changed: %v %v", entries, err)
			}
			data, err := os.ReadFile(sentinel)
			if err != nil || string(data) != "unchanged" {
				t.Fatal("existing data changed", err)
			}
		})
	}
}

func TestInitRefusesManagedConflicts(t *testing.T) {
	for _, name := range []string{"store", "mount", "runtime", "veyl.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			conflict := filepath.Join(dir, name)
			var err error
			switch name {
			case "store":
				err = os.Mkdir(conflict, 0700)
			case "mount":
				err = os.Symlink("missing-target", conflict)
			default:
				err = os.WriteFile(conflict, []byte("preserve"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var out, errs bytes.Buffer
			if code := Run(context.Background(), []string{"init", "--legacy-workspace", "--dir", dir}, &out, &errs); code != 2 {
				t.Fatalf("%d: %s", code, &errs)
			}
			if !strings.Contains(errs.String(), name) || out.Len() != 0 {
				t.Fatalf("conflict not explained before prompting: %s %s", &out, &errs)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != name {
				t.Fatal("conflict changed", entries, err)
			}
			if name == "runtime" || name == "veyl.json" {
				data, err := os.ReadFile(conflict)
				if err != nil || string(data) != "preserve" {
					t.Fatal("existing file changed", err)
				}
			}
		})
	}
}

func TestInitRejectsSymlinkWorkspace(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "workspace")
	link := filepath.Join(parent, "link")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"init", "--legacy-workspace", "--dir", link}, &out, &errs); code != 2 || out.Len() != 0 {
		t.Fatalf("%d: %s", code, &errs)
	}
	entries, err := os.ReadDir(real)
	if err != nil || len(entries) != 0 {
		t.Fatal("symlink target changed", err)
	}
}

func TestInitCanceledBeforeCreation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errs bytes.Buffer
	code := Run(ctx, []string{"init", "--legacy-workspace", "--dir", dir, "--tty"}, &out, &errs)
	if code != 4 {
		t.Fatalf("%d: %s", code, &errs)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("canceled setup created destination", err)
	}
}

func TestSetupPasswordConfirmationAndCancellation(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		first, second := []byte("synthetic-setup-password"), []byte("synthetic-setup-password")
		if mismatch {
			second[0] = 'X'
		}
		calls := 0
		proof, result := setupPassword(context.Background(), func(context.Context) ([]byte, error) {
			calls++
			if calls == 1 {
				return first, nil
			}
			return second, nil
		}, &bytes.Buffer{})
		if calls != 2 || (result.Code != 0) != mismatch {
			t.Fatal("confirmation", result)
		}
		if mismatch && len(bytes.Trim(first, "\x00")) != 0 {
			t.Fatal("rejected password retained")
		}
		if len(bytes.Trim(second, "\x00")) != 0 {
			t.Fatal("confirmation retained")
		}
		clear(proof)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, result := setupPassword(ctx, func(ctx context.Context) ([]byte, error) { return nil, ctx.Err() }, &bytes.Buffer{})
	if result.Code != 4 {
		t.Fatal(result)
	}
}

func TestInitHelpDescribesWorkspace(t *testing.T) {
	for _, args := range [][]string{{"init", "--help"}, {"help", "init"}} {
		var out, errs bytes.Buffer
		if code := Run(context.Background(), args, &out, &errs); code != 0 || errs.Len() != 0 {
			t.Fatalf("%v: %d %s", args, code, &errs)
		}
		for _, want := range []string{"[--dir PATH]", "current working directory", "store/", "mount/", "runtime/", "veyl.json", "Unrelated workspace files"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%v: help missing %q", args, want)
			}
		}
	}
}

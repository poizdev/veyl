//go:build integration && linux

package ghostfs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
)

// A non-dot fixture is necessary: GNOME already hides mounts below dot paths.
// No personal parent is covered. Do not scan the repository during this test.
func TestDesktopMountVisibility(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("native FUSE required")
	}
	if _, err := exec.LookPath("gio"); err != nil {
		t.Skip("gio unavailable")
	}
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(project, "veyl-desktop-test-")
	if err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(base, "parent")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(mount); err != nil {
			t.Error(err)
		}
		if err := os.Remove(base); err != nil {
			t.Error(err)
		}
	})
	for _, hide := range []bool{false, true} {
		opts := OptionsForDesktop(true, hide)
		server, err := fs.Mount(mount, &Root{}, opts)
		if err != nil {
			if hide {
				t.Skipf("native helper cannot mount with the optional visibility hint: %v", err)
			}
			t.Fatal("fusermount option compatibility", err)
		}
		func() {
			defer func() {
				if err := server.Unmount(); err != nil {
					t.Fatal("unmount", err)
				}
				server.Wait()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			metadata, err := exec.CommandContext(ctx, "findmnt", "-n", "-o", "OPTIONS", "--mountpoint", mount).Output()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("hide=%v merged mount metadata=%s", hide, strings.TrimSpace(string(metadata)))
			output, err := exec.CommandContext(ctx, "gio", "mount", "-li").Output()
			if err != nil {
				t.Fatal("GIO volume monitor", err)
			}
			displayed := strings.Contains(string(output), "file://"+mount)
			t.Logf("hide=%v GIO volume monitor lists fixture=%v", hide, displayed)
			if hide && displayed {
				t.Log("LIMITATION: this helper/desktop does not hide the mount; no sidebar success claimed")
			}
			if data, err := os.ReadFile(filepath.Join(mount, "visible.txt")); err != nil || string(data) != VisibleContent {
				t.Fatal("visibility hint changed pathname access", err)
			}
		}()
	}
}

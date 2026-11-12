//go:build integration && linux

package storage

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/ghostfs"
	"github.com/poizdev/veyl/internal/policy"
)

func TestWritableEncryptedPersistence(t *testing.T)      { testWritableEncryptedPersistence(t, false) }
func TestManagedParentEncryptedPersistence(t *testing.T) { testWritableEncryptedPersistence(t, true) }

func TestOriginalParentEncryptedPersistence(t *testing.T) {
	testWritableEncryptedPersistence(t, true, true)
}

func testWritableEncryptedPersistence(t *testing.T, managed bool, originalMode ...bool) {
	original := len(originalMode) != 0 && originalMode[0]
	hiddenName := ".troll"
	if original {
		hiddenName = "test"
	}
	binary := realBinary(t)
	if f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0); err != nil {
		t.Skip("native FUSE required")
	} else {
		f.Close()
	}
	if _, err := exec.LookPath("fusermount3"); err != nil {
		t.Skip("fusermount3 unavailable")
	}
	store, run, password := temporaryStore(t, binary)
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	mountpoint, err := os.MkdirTemp(project, ".veyl-bridge-test-")
	if err != nil {
		t.Fatal(err)
	}
	var parent string
	if managed {
		if original {
			parent = mountpoint
			err = os.Mkdir(filepath.Join(parent, hiddenName), 0700)
		} else {
			parent, err = os.MkdirTemp(project, ".veyl-parent-test-")
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if mounted, err := HasMountsUnder(parent); err != nil || mounted {
				t.Error("retaining mounted parent fixture")
				return
			}
			if err := os.RemoveAll(parent); err != nil {
				t.Error(err)
			}
		})
		if err := os.Mkdir(filepath.Join(parent, "neighbor"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, "neighbor", "notes"), []byte("public"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	var root *ghostfs.Root
	var backend *Backend
	var server interface {
		Unmount() error
		Wait()
	}
	var agent *bridgeAgent
	start := func() {
		root = &ghostfs.Root{Writable: true, HiddenName: hiddenName}
		if managed {
			var pinErr error
			if original {
				pinErr = root.SetOriginalParent(parent)
			} else {
				pinErr = root.SetParent(parent)
			}
			if err := pinErr; err != nil {
				t.Fatal(err)
			}
		}
		var err error
		backend, err = New(Config{Store: store, RuntimeDir: run, Binary: binary, BeforeUnmount: root.CloseBacking}, &root.State)
		if err != nil {
			t.Fatal(err)
		}
		agent = &bridgeAgent{proof: password}
		root.Backing = backend
		root.Auth = auth.NewTransactional(&root.State, agent, func(ctx context.Context, ticket policy.Challenge, response auth.Response) (auth.Transaction, error) {
			candidate, err := backend.Prepare(ctx, ticket, response.Proof)
			if candidate == nil {
				return nil, err
			}
			return candidate, err
		}, 30*time.Second)
		server, err = fs.Mount(mountpoint, root, ghostfs.OptionsFor(true))
		if err != nil {
			t.Fatal(err)
		}
		if original {
			if err := root.ConfirmOriginalMount(); err != nil {
				t.Fatal(err)
			}
		}
	}
	stop := func() {
		root.State.Lock()
		if err := backend.Close(); err != nil {
			t.Fatal("backend cleanup", err)
		}
		if err := server.Unmount(); err != nil {
			t.Fatal("Veyl unmount", err)
		}
		server.Wait()
		server = nil
		if err := root.CloseParent(); err != nil {
			t.Fatal(err)
		}
	}
	if original {
		if err := os.Symlink("neighbor", filepath.Join(parent, "public-link")); err != nil {
			t.Fatal(err)
		}
	}
	start()
	if original {
		if data, err := os.ReadFile(filepath.Join(mountpoint, "public-link", "notes")); err != nil || string(data) != "public" {
			t.Fatal("existing sibling link", err)
		}
		if err := os.Symlink("neighbor", filepath.Join(mountpoint, "created-link")); err != nil {
			t.Fatal("create public link", err)
		}
	}
	t.Cleanup(func() {
		if server != nil {
			root.State.Lock()
			if err := backend.Close(); err != nil {
				t.Error(err)
			}
			if err := server.Unmount(); err != nil {
				t.Error(err)
			} else {
				server.Wait()
			}
		}
		if root != nil {
			if err := root.CloseParent(); err != nil {
				t.Error(err)
			}
		}
		if original {
			return
		}
		if err := os.Remove(mountpoint); err != nil {
			t.Error(err)
		}
	})
	hidden := filepath.Join(mountpoint, hiddenName)
	assertHidden := func() {
		entries, err := os.ReadDir(mountpoint)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Name() == hiddenName {
				t.Fatal("protected name enumerated")
			}
		}
	}
	assertHidden()
	if managed {
		sibling := filepath.Join(mountpoint, "neighbor", "notes")
		if data, err := os.ReadFile(sibling); err != nil || string(data) != "public" {
			t.Fatal("sibling read", err)
		}
		if err := os.WriteFile(sibling, []byte("sibling edit"), 0640); err != nil {
			t.Fatal("sibling write", err)
		}
		if !root.State.IsLocked() {
			t.Fatal("sibling access authenticated")
		}
		if err := os.WriteFile(filepath.Join(parent, "external"), []byte("new sibling"), 0600); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(filepath.Join(mountpoint, "external")); err != nil || string(data) != "new sibling" {
			t.Fatal("external changes", err)
		}
		if !original {
			if err := os.Symlink("neighbor", filepath.Join(parent, "link")); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(mountpoint, "link", "notes")); err == nil {
				t.Fatal("symlink traversal allowed")
			}
		}
		if err := os.Rename(filepath.Join(mountpoint, "external"), filepath.Join(mountpoint, "renamed-public")); err != nil {
			t.Fatal("public root rename", err)
		}
		if err := os.Rename(filepath.Join(mountpoint, "renamed-public"), filepath.Join(mountpoint, "neighbor", "external")); err != nil {
			t.Fatal("public root-to-child move", err)
		}
		if err := os.Rename(filepath.Join(mountpoint, "neighbor", "external"), filepath.Join(mountpoint, "external")); err != nil {
			t.Fatal("public child-to-root move", err)
		}
		directory, err := os.Open(mountpoint)
		if err != nil {
			t.Fatal(err)
		}
		if err := directory.Sync(); err != nil {
			t.Fatal("root directory fsync", err)
		}
		directory.Close()
	}
	agent.wrong.Store(true)
	if _, err := os.Stat(hidden); !errors.Is(err, syscall.EACCES) {
		t.Fatal("wrong credentials", err)
	}
	agent.wrong.Store(false)
	if err := os.Mkdir(filepath.Join(hidden, "projects"), 0750); err != nil {
		t.Fatal("mkdir", err)
	}
	path := filepath.Join(hidden, "projects", "notes.txt")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0640)
	if err != nil {
		t.Fatal("create", err)
	}
	if _, err := f.WriteString("hello"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal("fsync", err)
	}
	moved := filepath.Join(hidden, "projects", "moved.txt")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal("rename", err)
	}
	if _, err := f.WriteAt([]byte("!"), 5); err != nil {
		t.Fatal("open handle after rename", err)
	}
	if info, err := f.Stat(); err != nil || info.Size() != 6 {
		t.Fatal("fstat renamed", err)
	}
	if err := os.Rename(filepath.Join(hidden, "projects"), filepath.Join(hidden, "renamed")); err != nil {
		t.Fatal("rename directory", err)
	}
	moved = filepath.Join(hidden, "renamed", "moved.txt")
	appendFile, err := os.OpenFile(moved, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendFile.WriteString(" appended"); err != nil {
		t.Fatal("append", err)
	}
	if err := appendFile.Close(); err != nil {
		t.Fatal("flush append", err)
	}
	if err := os.Truncate(moved, 6); err != nil {
		t.Fatal("truncate", err)
	}
	if err := os.Chmod(moved, 0600); err != nil {
		t.Fatal("chmod", err)
	}
	if info, err := os.Stat(moved); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("permissions", err)
	}
	// Atomic replacement save, followed by open-after-unlink behavior.
	temporary := filepath.Join(hidden, "renamed", ".save")
	if err := os.WriteFile(temporary, []byte("persisted editor save"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, moved); err != nil {
		t.Fatal("replace save", err)
	}
	if _, err := f.WriteAt([]byte("old"), 0); err != nil {
		t.Fatal("open replaced file", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Exercise the documented shell workflow through the real mounted namespace.
	for _, shell := range []string{"sh", "fish"} {
		binary, err := exec.LookPath(shell)
		if err != nil {
			t.Log(shell + " unavailable; shell smoke check not run")
			continue
		}
		command := exec.Command(binary, "-c", "touch shell-hello && mkdir shell-projects && printf '%s\\n' 'shell edit' > shell-notes && mv shell-notes shell-projects/notes && cat shell-projects/notes && rm shell-hello shell-projects/notes && rmdir shell-projects")
		command.Dir = hidden
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s workflow: %v %s", shell, err, output)
		}
	}
	expected := "persisted editor save"
	if editor, err := exec.LookPath("nvim"); err == nil {
		command := exec.Command(editor, "--headless", "-u", "NONE", "-i", "NONE", "-n", moved, "-c", "call setline(1, 'native editor save')", "-c", "wq")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("native editor save: %v %s", err, output)
		}
		expected = "native editor save\n"
	} else {
		t.Log("nvim unavailable; editor smoke check not run")
	}
	held, err := os.OpenFile(moved, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertHidden()
	if managed {
		if err := os.Rename(moved, filepath.Join(mountpoint, "escaped")); !errors.Is(err, syscall.EXDEV) {
			t.Fatal("protected-to-public rename", err)
		}
		if err := os.Rename(filepath.Join(mountpoint, "external"), filepath.Join(hidden, "imported")); !errors.Is(err, syscall.EXDEV) {
			t.Fatal("public-to-protected rename", err)
		}
		if err := os.Rename(hidden, filepath.Join(mountpoint, "renamed-secret")); !errors.Is(err, syscall.EPERM) {
			t.Fatal("reserved anchor rename", err)
		}
		if !original {
			if err := os.Mkdir(filepath.Join(parent, ".troll"), 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := os.ReadDir(mountpoint); err == nil {
				t.Fatal("collision did not fail closed")
			}
			if err := os.Remove(filepath.Join(parent, ".troll")); err != nil {
				t.Fatal(err)
			}
			movedParent := parent + "-moved"
			if err := os.Rename(parent, movedParent); err != nil {
				t.Fatal(err)
			}
			if _, err := os.ReadDir(mountpoint); err == nil {
				t.Fatal("source replacement not detected")
			}
			if err := os.Rename(movedParent, parent); err != nil {
				t.Fatal(err)
			}
		}
	}
	root.State.Lock()
	if err := backend.Unmount(context.Background()); err != nil {
		t.Fatal("lock cleanup", err)
	}
	if _, err := held.WriteAt([]byte("denied"), 0); !errors.Is(err, syscall.EACCES) {
		t.Fatal("revoked write", err)
	}
	if data, err := os.ReadFile(moved); err != nil || string(data) != expected {
		t.Fatal("lock/unlock persistence", err)
	}
	if _, err := held.WriteAt([]byte("denied"), 0); !errors.Is(err, syscall.EACCES) {
		t.Fatal("old handle revived", err)
	}
	held.Close()
	if err := os.Mkdir(filepath.Join(hidden, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(hidden, "empty")); err != nil {
		t.Fatal("rmdir", err)
	}
	stop()
	start()
	if !root.State.IsLocked() {
		t.Fatal("restart did not start locked")
	}
	if data, err := os.ReadFile(moved); err != nil || string(data) != expected {
		t.Fatal("unmount/remount persistence", err)
	}
	if err := os.Remove(moved); err != nil {
		t.Fatal("unlink", err)
	}
	if err := os.Remove(filepath.Join(hidden, "renamed")); err != nil {
		t.Fatal("rmdir", err)
	}
	assertHidden()
	if managed {
		if data, err := os.ReadFile(filepath.Join(mountpoint, "neighbor", "notes")); err != nil || string(data) != "sibling edit" {
			t.Fatal("sibling persistence", err)
		}
		if info, err := os.Stat(filepath.Join(parent, "neighbor")); err != nil || info.Mode().Perm() != 0750 {
			t.Fatal("sibling permissions changed", err)
		}
	}
	stop()
}

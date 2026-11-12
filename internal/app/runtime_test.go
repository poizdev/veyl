//go:build linux

package app

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRuntimeOwnershipAndResidue(t *testing.T) {
	c, _ := fixtureConfig(t)
	owner, err := claimRuntime(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claimRuntime(c); !errors.Is(err, errAlreadyRunning) {
		t.Fatalf("duplicate owner: %v", err)
	}
	if err := owner.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(c.RuntimeDir, "control.sock")); !os.IsNotExist(err) {
		t.Fatal("socket leaked")
	}
	if err := os.Mkdir(filepath.Join(c.RuntimeDir, "views", "residue"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := claimRuntime(c); !errors.Is(err, errCleanupPending) {
		t.Fatalf("residue ignored: %v", err)
	}
}
func TestStaleSocketOnlyOwnedSocketRemoved(t *testing.T) {
	c, _ := fixtureConfig(t)
	socket := filepath.Join(c.RuntimeDir, "control.sock")
	if err := os.WriteFile(socket, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := claimRuntime(c); err == nil {
		t.Fatal("ordinary file accepted as stale socket")
	}
	data, _ := os.ReadFile(socket)
	if string(data) != "preserve" {
		t.Fatal("file removed")
	}
	os.Remove(socket)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skip("Unix sockets unavailable in sandbox")
		}
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	os.Chmod(socket, 0600)
	listener.Close()
	owner, err := claimRuntime(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.release(); err != nil {
		t.Fatal(err)
	}
}

func TestUnixControlSocketLifecycle(t *testing.T) {
	c, _ := fixtureConfig(t)
	probe, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(c.RuntimeDir, "probe.sock"), Net: "unix"})
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skip("Unix sockets unavailable in sandbox")
		}
		t.Fatal(err)
	}
	probe.Close()
	owner, err := claimRuntime(c)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.release()
	if err := owner.listen(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(c.RuntimeDir, "control.sock"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket not private")
	}
	i, _ := testInstance(t)
	i.runtime = owner
	server := serveControl(owner, i)
	defer server.close()
	for _, op := range []string{"status", "unlock", "status", "lock", "unmount"} {
		result := clientCommand(context.Background(), c, op, false)
		if result.Code != 0 {
			t.Fatal(op, result)
		}
	}
	<-i.done
	if _, err := os.Lstat(filepath.Join(c.RuntimeDir, "control.sock")); !os.IsNotExist(err) {
		t.Fatal("socket leaked")
	}
}

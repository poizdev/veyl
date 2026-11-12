//go:build linux

package app

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestServiceReadinessNotification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skip("Unix sockets unavailable")
		}
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	listener.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1024)
	n, _, err := listener.ReadFromUnix(buffer)
	if err != nil || !strings.HasPrefix(string(buffer[:n]), "READY=1\nSTATUS=") {
		t.Fatal("readiness", string(buffer[:n]), err)
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "absent"))
	if err := notifyReady(); err == nil {
		t.Fatal("missing systemd endpoint accepted")
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifyReady(); err != nil {
		t.Fatal("foreground mode needs no notification", err)
	}
}

func TestServiceUnitPreservesUnknownFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "veyl.service")
	original := []byte("[Service]\nExecStart=/bin/true\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readServiceUnit(path); err == nil {
		t.Fatal("unrecognized service accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(original) {
		t.Fatal("unrelated service modified", err)
	}
}

//go:build linux

package storage

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const pipePassword = "synthetic-pipe-password"

func TestFDChild(t *testing.T) {
	active := false
	for _, arg := range os.Args {
		if arg == "veyl-fd-child" {
			active = true
		}
	}
	if !active {
		return
	}
	for _, item := range append(append([]string{}, os.Args...), os.Environ()...) {
		if strings.Contains(item, pipePassword) {
			os.Exit(3)
		}
	}
	target, err := os.Readlink("/proc/self/fd/3")
	if err != nil || !strings.HasPrefix(target, "pipe:[") {
		os.Exit(4)
	}
	data, err := os.ReadFile("/proc/self/fd/3")
	if err != nil || string(data) != pipePassword+"\n" {
		os.Exit(5)
	}
	os.Exit(0)
}
func TestAnonymousFDCredentialTransport(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	password := []byte(pipePassword)
	before := append([]byte(nil), password...)
	p, err := startCommand(executable, []string{"-test.run=^TestFDChild$", "--", "veyl-fd-child"}, password)
	if err != nil {
		t.Fatal(err)
	}
	receive(t, p.Done())
	if p.ExitCode() != 0 {
		t.Fatalf("FD helper exit: %d", p.ExitCode())
	}
	if !bytes.Equal(password, before) {
		t.Fatal("caller credential buffer mutated")
	}
}
func TestMountInfoEscapes(t *testing.T) {
	entries, err := parseMountInfo("42 1 0:5 / /private/a\\040b rw - fuse.gocryptfs /cipher/a\\040b rw\n")
	if err != nil || len(entries) != 1 || entries[0].Path != "/private/a b" || entries[0].Source != "/cipher/a b" || entries[0].ID != 42 {
		t.Fatalf("mount parsing: %+v, %v", entries, err)
	}
	if _, err := parseMountInfo("malformed"); err == nil {
		t.Fatal("malformed mount table accepted")
	}
}

func TestGroupLeader(t *testing.T) {
	mode, path := "", ""
	for i, arg := range os.Args {
		if (arg == "group-leader" || arg == "group-helper") && i+1 < len(os.Args) {
			mode, path = arg, os.Args[i+1]
		}
	}
	if mode == "" {
		return
	}
	if mode == "group-helper" {
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(6)
		}
		for {
			syscall.Pause()
		}
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(7)
	}
	cmd := exec.Command(executable, "-test.run=^TestGroupLeader$", "--", "group-helper", path)
	if err := cmd.Start(); err != nil {
		os.Exit(8)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			os.Exit(0)
		}
		if time.Now().After(deadline) {
			os.Exit(9)
		}
		runtime.Gosched()
	}
}
func TestLeaderExitDrainsSurvivingHelpers(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "helper.pid")
	p, err := startCommand(executable, []string{"-test.run=^TestGroupLeader$", "--", "group-leader", marker}, []byte(pipePassword))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Signal(syscall.SIGKILL)
	receive(t, p.Done())
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		fields := strings.Fields(string(stat)[strings.LastIndexByte(string(stat), ')')+1:])
		if len(fields) > 0 && fields[0] != "Z" && fields[0] != "X" {
			t.Fatal("leader completion left a live helper")
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

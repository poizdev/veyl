//go:build integration && linux

package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/policy"
)

func realBinary(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("gocryptfs")
	if err != nil {
		t.Skip("gocryptfs binary unavailable")
	}
	return binary
}
func temporaryStore(t *testing.T, binary string) (string, string, []byte) {
	t.Helper()
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(project, ".veyl-storage-test-")
	if err != nil {
		t.Fatal(err)
	}
	// Remove only empty directories at cleanup: never recursively remove a view.
	t.Cleanup(func() {
		mounts, err := readMountInfo()
		if err != nil {
			t.Errorf("cannot verify safe test cleanup; retaining %s", base)
			return
		}
		for _, entry := range mounts {
			if within(base, entry.Path) {
				t.Errorf("test mount retained at %s; refusing recursive cleanup", entry.Path)
				return
			}
		}
		entries, err := os.ReadDir(base)
		if err != nil {
			t.Error(err)
			return
		}
		for _, entry := range entries {
			if entry.Name() == "cipher" {
				if err := os.RemoveAll(filepath.Join(base, "cipher")); err != nil {
					t.Error(err)
				}
			}
		}
		if err := os.Remove(filepath.Join(base, "runtime")); err != nil {
			t.Errorf("runtime retained (possible mount): %v", err)
		}
		if err := os.Remove(base); err != nil {
			t.Errorf("test directory retained: %v", err)
		}
	})
	store, run := filepath.Join(base, "cipher"), filepath.Join(base, "runtime")
	for _, path := range []string{store, run} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	password := []byte("temporary-integration-password")
	// Lower scrypt work only for this throwaway fixture, never backend mounts.
	p, err := startCommand(binary, []string{"-init", "-q", "-scryptn", "10", "-passfile", "/proc/self/fd/3", "--", store}, password)
	if err != nil {
		t.Fatal(err)
	}
	receive(t, p.Done())
	if p.ExitCode() != 0 {
		t.Fatalf("real inherited-FD initialization failed: exit %d", p.ExitCode())
	}
	return store, run, password
}

// This credential-transport probe needs no FUSE device. It proves the real
// installed binary accepts the inherited anonymous descriptor during init.
func TestGocryptfsFDInitialization(t *testing.T) {
	binary := realBinary(t)
	store, _, _ := temporaryStore(t, binary)
	info, err := os.Stat(filepath.Join(store, "gocryptfs.conf"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("FD initialization: %v", err)
	}
}

func TestGocryptfsEncryptedRoundTrip(t *testing.T) {
	binary := realBinary(t)
	device, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("real gocryptfs mount unavailable: %v", err)
	}
	device.Close()
	if _, err := exec.LookPath("fusermount3"); err != nil {
		t.Skip("fusermount3 unavailable")
	}
	store, run, password := temporaryStore(t, binary)
	state := &policy.State{}
	b, err := New(Config{Store: store, RuntimeDir: run, Binary: binary}, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("real backend cleanup: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := b.Mount(ctx, ticket(t, state), []byte("wrong-integration-password")); !errors.Is(err, ErrCredentials) {
		t.Fatalf("real wrong password: %v", err)
	}
	empty(t, run)
	v, err := b.Mount(ctx, ticket(t, state), password)
	if err != nil {
		t.Fatal(err)
	}
	name := "plain-test-name.txt"
	plaintext := []byte("isolated plaintext payload, never real user data")
	if err := os.WriteFile(filepath.Join(v.Path, name), plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(v.Path, name))
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip: %v", err)
	}
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal(err)
	}
	empty(t, run)
	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	encryptedFiles := 0
	for _, entry := range entries {
		if entry.Name() == name {
			t.Fatal("plaintext filename in ciphertext store")
		}
		data, err := os.ReadFile(filepath.Join(store, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, password) || bytes.Contains(data, plaintext) {
			t.Fatal("plaintext secret or payload persisted")
		}
		if entry.Name() != "gocryptfs.conf" && entry.Name() != "gocryptfs.diriv" {
			encryptedFiles++
		}
	}
	if encryptedFiles == 0 {
		t.Fatal("no encrypted file persisted")
	}
	v, err = b.Mount(ctx, ticket(t, state), password)
	if err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(v.Path, name))
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("encrypted persistence: %v", err)
	}
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestGocryptfsTransactionalLifecycle uses only a freshly initialized synthetic
// store. A successful standalone mount is not a Veyl production authorization
// boundary: same-UID processes can directly read its path while mounted.
func TestGocryptfsTransactionalLifecycle(t *testing.T) {
	binary := realBinary(t)
	device, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("real transactional gocryptfs mount unavailable: %v", err)
	}
	device.Close()
	if _, err := exec.LookPath("fusermount3"); err != nil {
		t.Skip("fusermount3 unavailable")
	}
	store, run, password := temporaryStore(t, binary)
	state := &policy.State{}
	b, err := New(Config{Store: store, RuntimeDir: run, Binary: binary}, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("transaction cleanup: %v", err)
		}
	})

	for _, kind := range []string{"adopt", "cancel", "reject", "invalid password"} {
		t.Run(kind, func(t *testing.T) {
			attempt, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var candidate *Candidate
			var plainPath string
			proof := password
			if kind == "invalid password" {
				proof = []byte("wrong-synthetic-password")
			}
			broker := auth.NewTransactional(state, credentialAgent{proof: proof}, func(ctx context.Context, ticket policy.Challenge, response auth.Response) (auth.Transaction, error) {
				c, err := b.Prepare(ctx, ticket, response.Proof)
				if c == nil {
					return nil, err
				}
				candidate = c
				plainPath = filepath.Join(c.View().Path, "transaction-synthetic.txt")
				if err == nil {
					if err := os.WriteFile(plainPath, []byte("synthetic transaction payload"), 0600); err != nil {
						return c, err
					}
					switch kind {
					case "cancel":
						cancel()
					case "reject":
						state.Lock()
					}
				}
				return c, err
			}, 30*time.Second)
			err := broker.RequestAccess(attempt)
			if kind == "adopt" {
				if err != nil {
					t.Fatal(err)
				}
				cancel() // Broker has also canceled its own attempt before RequestAccess returns.
				if state.IsLocked() || !b.Mounted() {
					t.Fatal("attempt completion lost session")
				}
				if data, err := os.ReadFile(plainPath); err != nil || string(data) != "synthetic transaction payload" {
					t.Fatalf("adopted read: %v", err)
				}
				epoch, _ := state.Session()
				state.Lock()
				if state.Valid(epoch) {
					t.Fatal("old session survives lock")
				}
				if err := candidate.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || !state.IsLocked() {
					t.Fatalf("rejected transaction: %v", err)
				}
				// Cancellation can return before rollback. Observe natural cleanup;
				// explicit unmount here would conceal a missing broker rollback.
				if candidate != nil {
					receive(t, candidate.View().Done())
					if candidate.Owned() || errors.Is(candidate.View().Err(), ErrCleanup) {
						t.Fatal("rejected transaction retained incomplete cleanup")
					}
				}
			}
			if b.Mounted() {
				t.Fatal("rejected/revoked transaction left a mounted view")
			}
			if plainPath != "" {
				if _, err := os.ReadFile(plainPath); !os.IsNotExist(err) {
					t.Fatalf("decrypted payload still reachable: %v", err)
				}
			}
			empty(t, run)
		})
	}
}

//go:build linux

package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/ghostfs"
	"github.com/poizdev/veyl/internal/policy"
)

func TestBrokerProtectedBridge(t *testing.T) {
	for _, kind := range []string{"success and crash", "wrong password", "cancel after verification", "retained cleanup"} {
		t.Run(kind, func(t *testing.T) {
			cfg, _, f := fixture(t)
			root := &ghostfs.Root{}
			b, err := New(cfg, &root.State)
			if err != nil {
				t.Fatal(err)
			}
			b.ops = operations{start: f.start, mounts: f.mounts, unmount: func(ctx context.Context, path string) error {
				f.mu.Lock()
				failed := f.failUnmount
				f.mu.Unlock()
				if !failed {
					if err := os.Remove(filepath.Join(path, "payload")); err != nil && !os.IsNotExist(err) {
						return err
					}
				}
				return f.unmount(ctx, path)
			}}
			useFixtureMountID(b, f, true)
			t.Cleanup(func() {
				f.mu.Lock()
				f.failUnmount = false
				f.mu.Unlock()
				if err := b.Close(); err != nil {
					t.Error(err)
				}
			})
			attempt, cancel := context.WithCancel(context.Background())
			defer cancel()
			proof := []byte("synthetic-password")
			if kind == "wrong password" {
				proof = []byte("incorrect")
			}
			root.Backing = b
			root.Auth = auth.NewTransactional(&root.State, credentialAgent{proof: proof}, func(ctx context.Context, ticket policy.Challenge, response auth.Response) (auth.Transaction, error) {
				c, err := b.Prepare(ctx, ticket, response.Proof)
				if c == nil {
					return nil, err
				}
				if err != nil {
					return c, err
				}
				if err := os.WriteFile(filepath.Join(c.View().Path, "payload"), []byte("bridge synthetic payload"), 0600); err != nil {
					return c, err
				}
				if kind == "cancel after verification" {
					cancel()
				}
				return c, nil
			}, time.Second)
			fs.NewNodeFS(root, ghostfs.Options())
			n, e := root.Lookup(attempt, policy.GhostName, &fuse.EntryOut{})
			if kind == "wrong password" || kind == "cancel after verification" {
				if e != syscall.EACCES || n != nil {
					t.Fatal("rejected authentication published tree")
				}
				deadline := time.After(time.Second)
				for b.Retained() != nil {
					select {
					case <-deadline:
						t.Fatal("rollback incomplete")
					default:
						time.Sleep(time.Millisecond)
					}
				}
				if !root.State.IsLocked() {
					t.Fatal("rejected authentication authorized")
				}
				empty(t, cfg.RuntimeDir)
				return
			}
			if e != 0 {
				t.Fatal(e)
			}
			file, e := n.Operations().(fs.NodeLookuper).Lookup(context.Background(), "payload", &fuse.EntryOut{})
			if e != 0 {
				t.Fatal(e)
			}
			fh, _, e := file.Operations().(fs.NodeOpener).Open(context.Background(), 0)
			if e != 0 {
				t.Fatal(e)
			}
			result, e := file.Operations().(fs.NodeReader).Read(context.Background(), fh, make([]byte, 64), 0)
			if e != 0 {
				t.Fatal(e)
			}
			data, status := result.Bytes(make([]byte, 64))
			result.Done()
			if status != fuse.OK || string(data) != "bridge synthetic payload" {
				t.Fatal("backing payload")
			}
			c := b.Retained()
			if kind == "retained cleanup" {
				f.mu.Lock()
				f.failUnmount = true
				f.mu.Unlock()
				if err := c.Close(); !errors.Is(err, ErrCleanup) {
					t.Fatal(err)
				}
				if !c.Owned() {
					t.Fatal("cleanup owner lost")
				}
				if n, e := root.Lookup(context.Background(), policy.GhostName, &fuse.EntryOut{}); e != syscall.EACCES || n != nil {
					t.Fatal("cleanup residue authorized new tree")
				}
			} else {
				f.mu.Lock()
				p := f.child
				f.mu.Unlock()
				p.exit(2)
				receive(t, c.View().Done())
			}
			if result, e := file.Operations().(fs.NodeReader).Read(context.Background(), fh, make([]byte, 32), 0); e != syscall.EACCES {
				if result != nil {
					result.Done()
				}
				t.Fatalf("revoked bridge read: %v", e)
			}
		})
	}
}

//go:build integration && linux

package ghostfs

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/auth"
)

// Feed an interactive reader through a pseudo-terminal. No cd is executed:
// merely typing a known path lets fish's asynchronous highlighting inspect it.
func TestFishAuthenticationProbesAndExplicitMitigation(t *testing.T) {
	for _, binary := range []string{"fish", "script"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skip(binary + " unavailable")
		}
	}
	for _, explicit := range []bool{false, true} {
		r := &Root{ExplicitUnlock: explicit}
		var calls atomic.Int64
		r.Auth = auth.New(&r.State, mockAgent(func(context.Context, auth.Request) (auth.Response, error) {
			calls.Add(1)
			return auth.Response{}, auth.ErrCanceled
		}), mockVerifier{}, time.Second)
		mount := mountFilesystem(t, r)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "script", "-q", "-c", "fish --no-config --features=no-query-term --interactive", "/dev/null")
		cmd.Env = append(os.Environ(), "TERM=xterm-256color", "XDG_CONFIG_HOME="+t.TempDir(), "XDG_DATA_HOME="+t.TempDir())
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		input, err := cmd.StdinPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
		for range 4 {
			_, _ = input.Write([]byte("cd " + filepath.Join(mount, ".troll")))
			time.Sleep(250 * time.Millisecond)
			_, _ = input.Write([]byte{21})
			time.Sleep(100 * time.Millisecond)
		}
		typedCalls := calls.Load()
		for range 3 {
			_, _ = input.Write([]byte("test -d " + filepath.Join(mount, ".troll") + "\n"))
			time.Sleep(150 * time.Millisecond)
		}
		_, _ = input.Write([]byte("exit\n"))
		input.Close()
		err = cmd.Wait()
		cancel()
		if err != nil {
			t.Fatalf("interactive fish: %v %s", err, &output)
		}
		if explicit && calls.Load() != 0 {
			t.Fatalf("mitigation prompted %d times", calls.Load())
		}
		if !explicit {
			t.Logf("Typing without executing cd caused %d authentication requests; explicit path probes caused %d more. The reported typing flood is reproduced only if the first count exceeds one.", typedCalls, calls.Load()-typedCalls)
			if calls.Load() < 3 {
				t.Fatal("filesystem authentication probes were not exercised")
			}
		}
	}
}

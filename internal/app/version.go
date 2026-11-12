//go:build linux

package app

import (
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// Release builds set these through -ldflags. Ordinary installs retain the
// candidate version and use Go's embedded VCS revision when available.
var (
	version     = "0.1.0-rc.1"
	buildCommit string
	buildDate   string
)

func printVersion(out io.Writer) {
	info, _ := debug.ReadBuildInfo()
	commit, built := versionMetadata(info)
	fmt.Fprintf(out, "Veyl\n\nVersion   %s\nCommit    %s\nBuilt     %s\nPlatform  %s/%s\nGo        %s\nSource    github.com/poizdev/veyl\n", version, commit, built, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func versionMetadata(info *debug.BuildInfo) (string, string) {
	revision := buildCommit
	if revision == "" && info != nil {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value
				break
			}
		}
	}
	commit := "unknown"
	if len(revision) == 40 || len(revision) == 64 {
		if _, err := hex.DecodeString(revision); err == nil {
			commit = strings.ToLower(revision[:12])
		}
	}
	built := "unknown"
	// vcs.time is the commit timestamp, not the time this executable was built.
	if timestamp, err := time.Parse(time.RFC3339, buildDate); err == nil {
		built = timestamp.UTC().Format(time.RFC3339)
	}
	return commit, built
}

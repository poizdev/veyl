//go:build linux

package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// A cosmetic hint must not break otherwise supported older FUSE helpers.
// 3.17.4 is a conservatively verified upstream release with x-* extraction.
// Unknown/older versions simply retain ordinary mount presentation. Check both
// the outer go-fuse helper and gocryptfs's sanitized /usr/bin:/bin helper path.
func desktopMountHint(ctx context.Context) bool {
	outer, err := exec.LookPath("fusermount3")
	if err != nil {
		return false
	}
	backing := "/usr/bin/fusermount3"
	if _, err := os.Stat(backing); err != nil {
		backing = "/bin/fusermount3"
	}
	for _, helper := range []string{outer, backing} {
		query, cancel := context.WithTimeout(ctx, 2*time.Second)
		command := exec.CommandContext(query, helper, "--version")
		command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		output, err := command.Output()
		cancel()
		if err != nil || !gvfsHideVersion(string(output)) {
			return false
		}
	}
	return true
}

func gvfsHideVersion(output string) bool {
	const prefix = "fusermount3 version: "
	output = strings.TrimSpace(output)
	if !strings.HasPrefix(output, prefix) {
		return false
	}
	version := strings.TrimPrefix(output, prefix)
	var major, minor, patch int
	var extra string
	// Three components, and no unrecognized trailing output. Conservative
	// omission is safer than probing mount options on the user's real parent.
	count, _ := fmt.Sscanf(version, "%d.%d.%d%s", &major, &minor, &patch, &extra)
	if count != 3 || major < 0 || minor < 0 || patch < 0 {
		return false
	}
	return major > 3 || major == 3 && (minor > 17 || minor == 17 && patch >= 4)
}

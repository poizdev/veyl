//go:build linux

package mountpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// VeylIdentity reads only mount metadata. Never open a path inside the FUSE
// namespace from a request callback: that can recursively wait on this server.
func VeylIdentity(path string) (uint64, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, err
	}
	unescape := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	var id uint64
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		split := -1
		for i, f := range fields {
			if f == "-" {
				split = i
				break
			}
		}
		if len(fields) < 10 || split < 6 || split+3 >= len(fields) {
			return 0, fmt.Errorf("invalid mount metadata")
		}
		mount := unescape.Replace(fields[4])
		if strings.HasPrefix(mount, path+"/") {
			return 0, fmt.Errorf("unexpected child mount")
		}
		if mount != path {
			continue
		}
		if id != 0 || fields[split+1] != "fuse.veyl" || unescape.Replace(fields[split+2]) != "veyl" {
			return 0, fmt.Errorf("unexpected or stacked mount")
		}
		id, err = strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 {
			return 0, fmt.Errorf("invalid mount identity")
		}
	}
	if id == 0 {
		return 0, fmt.Errorf("Veyl mount missing")
	}
	return id, nil
}

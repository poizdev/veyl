//go:build linux

package app

import (
	"bytes"
	"context"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionOutput(t *testing.T) {
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &out, &errs); code != 0 || errs.Len() != 0 {
		t.Fatalf("version: %d %s", code, &errs)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 8 || lines[0] != "Veyl" || lines[1] != "" {
		t.Fatalf("unexpected version layout: %q", out.String())
	}
	for i, label := range []string{"Version   ", "Commit    ", "Built     ", "Platform  ", "Go        ", "Source    "} {
		if !strings.HasPrefix(lines[i+2], label) || strings.TrimPrefix(lines[i+2], label) == "" {
			t.Fatalf("missing version field %q: %q", label, lines[i+2])
		}
	}
	for _, want := range []string{"Version   0.1.0-rc.1", "Platform  " + runtime.GOOS + "/" + runtime.GOARCH, "Go        " + runtime.Version(), "Source    github.com/poizdev/veyl"} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Fatalf("missing %q in %q", want, out.String())
		}
	}
}

func TestHelpUsesInitializedConfig(t *testing.T) {
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"help"}, &out, &errs); code != 0 {
		t.Fatal(code, &errs)
	}
	for _, want := range []string{"veyl init [--dir PATH]", "--legacy-workspace", "external configuration path", "absolute original path", "explicit-unlock"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing original-path guidance %q", want)
		}
	}

}

func TestVersionMetadata(t *testing.T) {
	originalCommit, originalDate := buildCommit, buildDate
	defer func() { buildCommit, buildDate = originalCommit, originalDate }()
	// Hashes and dates here are synthetic fixtures, never release defaults.
	const revision = "0123456789abcdef0123456789abcdef01234567"
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: revision}, {Key: "vcs.time", Value: "2020-01-01T00:00:00Z"}}}
	for _, tc := range []struct {
		name, commit, date, wantCommit, wantBuilt string
		info                                      *debug.BuildInfo
	}{
		{name: "no metadata", wantCommit: "unknown", wantBuilt: "unknown"},
		{name: "embedded revision but no build time", info: info, wantCommit: "0123456789ab", wantBuilt: "unknown"},
		{name: "linker metadata takes precedence", info: info, commit: "abcdef0123456789abcdef0123456789abcdef01", date: "2026-01-02T04:04:05+01:00", wantCommit: "abcdef012345", wantBuilt: "2026-01-02T03:04:05Z"},
		{name: "invalid metadata", commit: "not-a-revision", date: "not-a-date", wantCommit: "unknown", wantBuilt: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buildCommit, buildDate = tc.commit, tc.date
			commit, built := versionMetadata(tc.info)
			if commit != tc.wantCommit || built != tc.wantBuilt {
				t.Fatalf("got %q %q; want %q %q", commit, built, tc.wantCommit, tc.wantBuilt)
			}
		})
	}
}

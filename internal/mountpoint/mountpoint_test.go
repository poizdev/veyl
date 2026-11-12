package mountpoint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	base := t.TempDir()
	empty := filepath.Join(base, "empty")
	full := filepath.Join(base, "full")
	for _, dir := range []string{empty, full} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(full, "keep")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(empty, link); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(base, "parent-link")
	if err := os.Symlink(base, parentLink); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		ok         bool
	}{
		{"required", "", false}, {"empty", empty, true}, {"nonempty", full, false},
		{"file", sentinel, false}, {"missing", filepath.Join(base, "missing"), false},
		{"symlink", link, false}, {"symlink parent", filepath.Join(parentLink, "empty"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.path)
			if (err == nil) != tc.ok {
				t.Fatalf("Validate(%q): %v, want success %v", tc.path, err, tc.ok)
			}
		})
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "untouched" {
		t.Fatalf("sentinel changed: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(base, "missing")); !os.IsNotExist(err) {
		t.Fatal("created missing mountpoint")
	}
}

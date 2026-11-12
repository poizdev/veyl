//go:build linux

package app

import "testing"

func TestGVfsHideHelperCompatibility(t *testing.T) {
	for _, tc := range []struct {
		output string
		want   bool
	}{
		{"fusermount3 version: 3.18.3\n", true},
		{"fusermount3 version: 3.17.4\n", true},
		{"fusermount3 version: 3.16.2\n", false},
		{"fusermount3 version: 3.17.3\n", false},
		{"fusermount version: 2.9.9\n", false},
		{"unknown", false}, {"fusermount3 version: 3.18.bad", false},
	} {
		if got := gvfsHideVersion(tc.output); got != tc.want {
			t.Errorf("%q: got %v want %v", tc.output, got, tc.want)
		}
	}
}

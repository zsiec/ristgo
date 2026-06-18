//go:build darwin

package tun

import "testing"

// TestUtunUnit checks the macOS "utunN" name → connect-unit mapping (no privilege
// needed; pure parsing).
func TestUtunUnit(t *testing.T) {
	cases := []struct {
		name    string
		want    int
		wantErr bool
	}{
		{"", 0, false},      // auto-assign
		{"utun0", 1, false}, // unit = N+1
		{"utun3", 4, false},
		{"utun42", 43, false},
		{"eth0", 0, true},   // wrong prefix
		{"utun", 0, true},   // no number
		{"utunx", 0, true},  // non-numeric
		{"utun-1", 0, true}, // negative
	}
	for _, c := range cases {
		got, err := utunUnit(c.name)
		if c.wantErr {
			if err == nil {
				t.Errorf("utunUnit(%q) = %d, want error", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("utunUnit(%q) unexpected error: %v", c.name, err)
		} else if got != c.want {
			t.Errorf("utunUnit(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}

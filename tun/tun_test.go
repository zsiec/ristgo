package tun_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/zsiec/ristgo/tun"
)

// TestTunLifecycle exercises the full device lifecycle: open, query the name, set the
// MTU, bring it up, and close. Creating a TUN device needs root/CAP_NET_ADMIN, so the
// test SKIPS when Open fails (the unprivileged / unsupported case) — run it as root
// (e.g. `sudo go test -run TestTunLifecycle ./tun/`) to exercise the device path.
func TestTunLifecycle(t *testing.T) {
	dev, err := tun.Open("")
	if err != nil {
		if errors.Is(err, tun.ErrUnsupported) {
			t.Skipf("TUN unsupported on this platform: %v", err)
		}
		t.Skipf("cannot open a TUN device (needs root?): %v", err)
	}
	defer dev.Close()

	name := dev.Name()
	if name == "" {
		t.Fatal("Open returned an empty device name")
	}
	if !strings.HasPrefix(name, "tun") && !strings.HasPrefix(name, "utun") {
		t.Fatalf("unexpected device name %q", name)
	}
	t.Logf("opened TUN device %q", name)

	if err := tun.SetMTU(name, 1400); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}
	if err := tun.SetIP(name, "10.99.99.1", 24); err != nil {
		t.Fatalf("SetIP: %v", err)
	}
	if err := tun.BringUp(name); err != nil {
		t.Fatalf("BringUp: %v", err)
	}
}

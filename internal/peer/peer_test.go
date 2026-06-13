package peer

import (
	"net"
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

func TestExpiry(t *testing.T) {
	p := New(2000 * clock.Millisecond)

	// Never seen: not expired (session still forming).
	if p.Expired(10_000) {
		t.Fatal("unseen peer reported expired")
	}
	if p.Seen() {
		t.Fatal("Seen() true before any Observe")
	}

	seen := clock.Timestamp(1_000_000)
	p.Observe(seen)
	if !p.Seen() {
		t.Fatal("Seen() false after Observe")
	}
	boundary := seen.Add(2000 * clock.Millisecond)
	// Within the timeout window (at exactly the boundary: not expired, > not >=).
	if p.Expired(boundary) {
		t.Fatal("expired exactly at the timeout boundary (want >, not >=)")
	}
	// Past the timeout.
	if !p.Expired(boundary.Add(1)) {
		t.Fatal("not expired past the timeout")
	}
	// A fresh observation resets the clock.
	p.Observe(5_000_000)
	if p.Expired(5_500_000) {
		t.Fatal("expired after a fresh observation")
	}
}

func TestLearnAddressesOnce(t *testing.T) {
	p := New(clock.Second)
	a := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 100}
	b := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 200}

	p.LearnMedia(a)
	p.LearnMedia(b) // must not overwrite
	if p.Media != a {
		t.Fatalf("Media = %v, want first-learned %v", p.Media, a)
	}
	p.LearnRTCP(b)
	p.LearnRTCP(a)
	if p.RTCP != b {
		t.Fatalf("RTCP = %v, want first-learned %v", p.RTCP, b)
	}
}

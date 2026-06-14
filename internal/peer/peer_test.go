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
	// RTCP candidates must share the media host (10.0.0.1); LearnRTCP rejects a
	// foreign host once media is known (see TestLearnRTCPRejectsForeignHost).
	rtcp1 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 200}
	rtcp2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 300}
	p.LearnRTCP(rtcp1)
	p.LearnRTCP(rtcp2)
	if p.RTCP != rtcp1 {
		t.Fatalf("RTCP = %v, want first-learned %v", p.RTCP, rtcp1)
	}
}

// TestLearnRTCPRejectsForeignHost verifies that once the media return address is
// known, an RTCP source on a different host is rejected (feedback-redirection /
// reflection guard), while a same-host RTCP source on a different port is
// accepted.
func TestLearnRTCPRejectsForeignHost(t *testing.T) {
	media := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 5000}
	attacker := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 5001}
	legit := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 5001}

	p := New(2000)
	p.LearnMedia(media)
	p.LearnRTCP(attacker)
	if p.RTCP != nil {
		t.Fatalf("RTCP = %v, want nil (foreign-host spoof rejected)", p.RTCP)
	}
	p.LearnRTCP(legit)
	if p.RTCP != legit {
		t.Fatalf("RTCP = %v, want %v (same-host RTCP accepted)", p.RTCP, legit)
	}

	// With no media known yet, first-source-wins still applies.
	q := New(2000)
	q.LearnRTCP(attacker)
	if q.RTCP != attacker {
		t.Fatalf("RTCP = %v, want %v (first-wins before media known)", q.RTCP, attacker)
	}
}

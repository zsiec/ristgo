package peer

import (
	"net/netip"
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

// ap builds a netip.AddrPort from an IPv4 quad and port.
func ap(a, b, c, d byte, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{a, b, c, d}), port)
}

func TestLearnAddressesOnce(t *testing.T) {
	p := New(clock.Second)
	a := ap(10, 0, 0, 1, 100)
	b := ap(10, 0, 0, 2, 200)

	p.LearnMedia(a)
	p.LearnMedia(b) // must not overwrite
	if p.Media != a {
		t.Fatalf("Media = %v, want first-learned %v", p.Media, a)
	}
	// RTCP candidates must share the media host (10.0.0.1); LearnRTCP rejects a
	// foreign host once media is known (see TestLearnRTCPRejectsForeignHost).
	rtcp1 := ap(10, 0, 0, 1, 200)
	rtcp2 := ap(10, 0, 0, 1, 300)
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
	media := ap(192, 0, 2, 10, 5000)
	attacker := ap(198, 51, 100, 9, 5001)
	legit := ap(192, 0, 2, 10, 5001)

	p := New(2000)
	p.LearnMedia(media)
	p.LearnRTCP(attacker)
	if p.RTCP.IsValid() {
		t.Fatalf("RTCP = %v, want invalid (foreign-host spoof rejected)", p.RTCP)
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

// TestLearnRTCPUnmapsIPv4in6 verifies the anti-spoof host check treats an IPv4
// source seen as 4-in-6 (dual-stack socket) as the same host as its plain IPv4
// media address — the net.IP.Equal semantics the netip migration preserves.
func TestLearnRTCPUnmapsIPv4in6(t *testing.T) {
	media := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 10}), 5000)
	// Same host, but expressed as an IPv4-mapped IPv6 address on a different port.
	mapped := netip.AddrPortFrom(netip.AddrFrom16(netip.AddrFrom4([4]byte{192, 0, 2, 10}).As16()), 5001)

	p := New(2000)
	p.LearnMedia(media)
	p.LearnRTCP(mapped)
	if !p.RTCP.IsValid() {
		t.Fatal("RTCP = invalid, want accepted (4-in-6 same host must match plain IPv4)")
	}
}

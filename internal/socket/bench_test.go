package socket

import (
	"net/netip"
	"testing"
)

// BenchmarkReadMediaAllocs proves the per-datagram receive path is
// allocation-free. ReadMedia reads via (*net.UDPConn).ReadFromUDPAddrPort, which
// returns the source as a netip.AddrPort value rather than heap-allocating a
// *net.UDPAddr the way the old ReadFromUDP did (perf-1). Run with -benchmem; the
// allocs/op gate below fails the benchmark if a heap allocation creeps back into
// the hot path.
//
// A loopback sender writes one datagram per iteration into the receiver's media
// socket; the receiver reads it back with ReadMedia. Both sockets and the read
// buffer are allocated once, outside the timed loop, so the only thing measured
// is the read itself.
func BenchmarkReadMediaAllocs(b *testing.B) {
	rx, err := ListenEphemeral("127.0.0.1")
	if err != nil {
		b.Fatalf("ListenEphemeral rx: %v", err)
	}
	defer rx.Close()
	tx, err := ListenEphemeral("127.0.0.1")
	if err != nil {
		b.Fatalf("ListenEphemeral tx: %v", err)
	}
	defer tx.Close()

	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(rx.MediaPort()))
	payload := []byte("the quick brown fox jumps over the lazy dog")
	buf := make([]byte, 2048)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := tx.WriteMedia(payload, dst); err != nil {
			b.Fatalf("WriteMedia: %v", err)
		}
		n, src, err := rx.ReadMedia(buf)
		if err != nil {
			b.Fatalf("ReadMedia: %v", err)
		}
		if n != len(payload) || !src.IsValid() {
			b.Fatalf("ReadMedia returned n=%d src=%v", n, src)
		}
	}
	b.StopTimer()

	// Gate: the receive path must allocate nothing per datagram. AllocsPerOp is a
	// float averaged over b.N; anything at or above 1 means a per-datagram heap
	// allocation (e.g. a regressed *net.UDPAddr return) slipped back in.
	if apo := testing.AllocsPerRun(100, func() {
		if err := tx.WriteMedia(payload, dst); err != nil {
			b.Fatalf("WriteMedia: %v", err)
		}
		if _, _, err := rx.ReadMedia(buf); err != nil {
			b.Fatalf("ReadMedia: %v", err)
		}
	}); apo != 0 {
		b.Fatalf("receive path allocated %g allocs/op, want 0 (alloc-free ReadFromUDPAddrPort)", apo)
	}
}

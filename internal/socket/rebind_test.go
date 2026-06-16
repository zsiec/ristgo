package socket

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestConnRebindSwapsSocket verifies Rebind binds a fresh local port, advances the
// generation, and that the new socket receives datagrams while the old one is gone.
func TestConnRebindSwapsSocket(t *testing.T) {
	c, err := ListenEphemeralSingle("127.0.0.1")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer c.Close()
	p1, g1 := c.MediaPort(), c.RebindGen()

	if err := c.Rebind(); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if got := c.RebindGen(); got != g1+1 {
		t.Fatalf("rebind generation = %d, want %d", got, g1+1)
	}
	if p2 := c.MediaPort(); p2 == p1 {
		t.Fatalf("rebind kept the same local port %d (expected a fresh ephemeral port)", p2)
	}

	// The fresh socket receives a datagram sent to its new port.
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.MediaPort()))
	sender, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("after-rebind")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.media.Load().SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := c.ReadMedia(buf)
	if err != nil {
		t.Fatalf("read after rebind: %v", err)
	}
	if string(buf[:n]) != "after-rebind" {
		t.Fatalf("read %q, want %q", buf[:n], "after-rebind")
	}
}

// TestConnRebindRejected confirms Rebind refuses a non-single (Simple even/odd)
// transport (DTLS is covered by its own gating in Rebind).
func TestConnRebindRejected(t *testing.T) {
	c, err := ListenEphemeral("127.0.0.1") // even/odd pair, single == false
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer c.Close()
	if err := c.Rebind(); err == nil {
		t.Fatal("Rebind on a non-single transport succeeded; want an error")
	}
}

// TestConnRebindConcurrentReader runs a reader goroutine that mirrors the session's
// readRebindable loop while the main goroutine rebinds repeatedly and sends a
// datagram on each fresh socket — exercising the atomic socket swap under the race
// detector and proving delivery survives a rebind.
func TestConnRebindConcurrentReader(t *testing.T) {
	c, err := ListenEphemeralSingle("127.0.0.1")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer c.Close()

	got := make(chan string, 8)
	stop := make(chan struct{})
	go func() {
		gen := c.RebindGen()
		buf := make([]byte, 64)
		for {
			n, _, err := c.ReadMedia(buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				if g := c.RebindGen(); g != gen { // a rebind swapped the socket
					gen = g
					continue
				}
				return
			}
			got <- string(buf[:n])
		}
	}()

	send := func(msg string) {
		dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.MediaPort()))
		s, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer s.Close()
		_, _ = s.Write([]byte(msg))
	}

	for i := 0; i < 3; i++ {
		if err := c.Rebind(); err != nil {
			t.Fatalf("rebind %d: %v", i, err)
		}
		send("ping")
		select {
		case m := <-got:
			if m != "ping" {
				t.Fatalf("got %q, want ping", m)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no datagram received after rebind %d", i)
		}
	}
	close(stop)
}

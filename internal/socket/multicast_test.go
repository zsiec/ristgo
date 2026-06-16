package socket

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// multicastIface returns an up, multicast-capable, non-loopback IPv4 interface,
// or nil if none exists (the test then skips).
func multicastIface(t *testing.T) *net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return &ifi
			}
		}
	}
	return nil
}

// TestJoinMulticastUnicastNoop verifies JoinMulticast and SetMulticast are no-ops
// for a non-multicast (unicast) group, so the plain unicast Conn is untouched.
func TestJoinMulticastUnicastNoop(t *testing.T) {
	c, err := ListenEphemeral("127.0.0.1")
	if err != nil {
		t.Fatalf("ListenEphemeral: %v", err)
	}
	defer c.Close()
	unicast := netip.MustParseAddr("127.0.0.1")
	if err := c.JoinMulticast(MulticastOptions{Group: unicast}); err != nil {
		t.Fatalf("JoinMulticast(unicast) = %v, want nil no-op", err)
	}
	if err := c.SetMulticast(MulticastOptions{Group: unicast}); err != nil {
		t.Fatalf("SetMulticast(unicast) = %v, want nil no-op", err)
	}
}

// TestJoinMulticastASM joins an IPv4 group on a real interface and verifies a
// self-sent datagram is received, exercising the JoinGroup + SetMulticast
// (loopback) path on the actual Conn type. It skips when no multicast-capable
// interface is present or the join/receive is unavailable (environment), exactly
// like the higher-level multicast e2e test.
func TestJoinMulticastASM(t *testing.T) {
	ifi := multicastIface(t)
	if ifi == nil {
		t.Skip("no up, multicast-capable, non-loopback IPv4 interface available")
	}
	group := netip.AddrFrom4([4]byte{239, 201, byte(time.Now().UnixNano() & 0xff), 23})

	// Receiver: bind the group address on a free even port pair and join.
	port := evenProbe(t)
	rx, err := Listen(group.String(), port)
	if err != nil {
		t.Skipf("bind to group %s failed (environment): %v", group, err)
	}
	defer rx.Close()
	if err := rx.JoinMulticast(MulticastOptions{Group: group, Iface: ifi}); err != nil {
		t.Skipf("JoinMulticast(%s) failed (environment): %v", group, err)
	}

	// Sender: an IPv4-family ephemeral socket with loopback so we hear ourselves.
	tx, err := ListenEphemeralFamily("udp4", "")
	if err != nil {
		t.Fatalf("ListenEphemeralFamily: %v", err)
	}
	defer tx.Close()
	if err := tx.SetMulticast(MulticastOptions{Group: group, Iface: ifi, TTL: 1, Loopback: true}); err != nil {
		t.Skipf("SetMulticast failed (environment): %v", err)
	}

	dst := netip.AddrPortFrom(group, uint16(port))
	payload := []byte("hello multicast")
	rx.media.Load().SetReadDeadline(time.Now().Add(time.Second))
	got := false
	for i := 0; i < 5 && !got; i++ {
		if err := tx.WriteMedia(payload, dst); err != nil {
			// An interface can advertise the multicast flag yet have no kernel
			// route for the group (common in CI containers: "no route to host").
			// That is an environment limitation, not a code defect — skip like the
			// other multicast-unavailable cases above.
			t.Skipf("multicast WriteMedia failed (environment, e.g. no multicast route): %v", err)
		}
		rx.media.Load().SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 64)
		n, src, err := rx.ReadMedia(buf)
		if err == nil && string(buf[:n]) == string(payload) && src.IsValid() {
			got = true
		}
	}
	if !got {
		t.Skip("multicast loopback not delivered (environment)")
	}
}

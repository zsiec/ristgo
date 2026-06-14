package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
	"golang.org/x/net/ipv4"
)

// multicastCapableIface returns the name of an up, multicast-capable,
// non-loopback interface with an IPv4 address, or "" if none exists. Multicast
// on the loopback interface is unreliable across platforms (macOS in particular
// does not forward IP multicast on lo0), so a real interface is required for a
// loopback-style multicast test where one host both sends and receives.
func multicastCapableIface(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 ||
			ifi.Flags&net.FlagMulticast == 0 ||
			ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return ifi.Name
			}
		}
	}
	return ""
}

// canJoinMulticast probes whether the environment actually lets us join an IPv4
// multicast group on iface and receive a self-sent datagram with loopback on. It
// returns false (so the caller t.Skips) when the join, the loopback send, or the
// receive is unavailable — exactly the way the interop suite skips when its tools
// are absent. Everything uses a short deadline so a non-multicast environment
// cannot hang the test.
func canJoinMulticast(t *testing.T, ifaceName string, group netip.Addr, port int) bool {
	t.Helper()
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false
	}
	gaddr := &net.UDPAddr{IP: net.IP(group.AsSlice()), Port: port}

	// Bind the receiver to the group address and port, then join.
	rc, err := net.ListenUDP("udp4", gaddr)
	if err != nil {
		return false
	}
	defer rc.Close()
	rp := ipv4.NewPacketConn(rc)
	if err := rp.JoinGroup(ifi, gaddr); err != nil {
		return false
	}
	defer rp.LeaveGroup(ifi, gaddr)

	// Sender: egress on iface with loopback on so we receive our own datagram.
	sc, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return false
	}
	defer sc.Close()
	sp := ipv4.NewPacketConn(sc)
	_ = sp.SetMulticastInterface(ifi)
	_ = sp.SetMulticastTTL(1)
	if err := sp.SetMulticastLoopback(true); err != nil {
		return false
	}

	probe := []byte("multicast-probe")
	deadline := time.Now().Add(750 * time.Millisecond)
	_ = rc.SetReadDeadline(deadline)
	// Send a couple of probes; multicast joins can take a moment to take effect.
	for i := 0; i < 3; i++ {
		if _, err := sc.WriteToUDP(probe, gaddr); err != nil {
			return false
		}
		buf := make([]byte, 64)
		_ = rc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := rc.ReadFromUDP(buf)
		if err == nil && string(buf[:n]) == string(probe) {
			return true
		}
	}
	return false
}

// freeMulticastPort finds an even UDP port free for the Simple-profile media/RTCP
// pair, suitable for binding a multicast group (the bind is wildcard-port; the
// group join is separate).
func freeMulticastPort(t *testing.T) int {
	t.Helper()
	return freeEvenPort(t) // reuse the Simple even/odd probe from e2e_test.go
}

// TestMulticastLoopbackIntegrity is the multicast counterpart of
// TestE2ELoopbackIntegrity: a Simple-profile sender transmits to an IPv4
// multicast group on a real interface (with multicast loopback on) and a receiver
// that JOINED the group recovers the stream byte-exact (SHA-256).
//
// Multicast on a single host is environment-dependent (it needs a real
// multicast-capable interface and OS support for self-loopback), so the test
// t.Skips gracefully — exactly like the interop tests skip when their tools are
// absent — when no such interface exists or a probe join/send/receive fails. It
// uses short deadlines throughout so a non-multicast environment can never hang
// it.
func TestMulticastLoopbackIntegrity(t *testing.T) {
	ifaceName := multicastCapableIface(t)
	if ifaceName == "" {
		t.Skip("no up, multicast-capable, non-loopback IPv4 interface available")
	}
	// Use a randomized admin-scoped (239.x) group to avoid colliding with any
	// real multicast traffic on the network.
	group := netip.AddrFrom4([4]byte{239, 200, byte(time.Now().UnixNano() & 0xff), 17})
	port := freeMulticastPort(t)

	if !canJoinMulticast(t, ifaceName, group, port) {
		t.Skipf("multicast join/loopback not available on %s for group %s (environment)", ifaceName, group)
	}

	// A modest payload keeps this test's CPU/socket footprint small: it shares the
	// package's parallel pool with the other (timing-sensitive) e2e sessions, and
	// a heavy multicast stream under -race can starve them. 16 KiB is still many
	// RTP packets — enough to exercise packetization, the join, real timers, and
	// in-order playout with a byte-exact SHA-256 check.
	const totalBytes = 16 * 1024
	const chunk = 1316

	addr := fmt.Sprintf("%s:%d", group, port)

	rxCfg := fastConfig()
	rxCfg.Interface = ifaceName
	rx, err := ristgo.NewReceiver(addr, rxCfg)
	if err != nil {
		t.Fatalf("NewReceiver(%s): %v", addr, err)
	}
	defer rx.Close()

	txCfg := fastConfig()
	txCfg.Interface = ifaceName
	txCfg.MulticastTTL = 1 // link-local is enough for a same-host loopback test
	txCfg.MulticastLoopback = true
	tx, err := ristgo.NewSender(addr, txCfg)
	if err != nil {
		t.Fatalf("NewSender(%s): %v", addr, err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wantHash := sha256.Sum256(payload)

	type result struct {
		hash [32]byte
		n    int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(8 * time.Second))
		got := make([]byte, 0, totalBytes)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < totalBytes {
			n, err := rx.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				got = append(got, buf[:n]...)
			}
			if err != nil {
				done <- result{n: len(got), err: err}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- result{hash: sum, n: len(got)}
	}()

	tx.SetWriteDeadline(time.Now().Add(8 * time.Second))
	for off := 0; off < totalBytes; off += chunk {
		end := off + chunk
		if end > totalBytes {
			end = totalBytes
		}
		if _, err := tx.Write(payload[off:end]); err != nil {
			t.Fatalf("Write at %d: %v", off, err)
		}
		if off%(chunk*16) == 0 {
			time.Sleep(time.Millisecond)
		}
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("receive ended after %d/%d bytes: %v", r.n, totalBytes, r.err)
		}
		if r.n != totalBytes {
			t.Fatalf("received %d bytes, want %d", r.n, totalBytes)
		}
		if r.hash != wantHash {
			t.Fatalf("received stream hash mismatch:\n got %x\nwant %x", r.hash, wantHash)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("timed out waiting for the multicast stream")
	}
}

// TestMulticastSourceOnUnicastRejected verifies that setting MulticastSource
// (SSM) on a receiver whose bind address is a plain unicast address is rejected
// at construction — a source filter is meaningless without a multicast group.
func TestMulticastSourceOnUnicastRejected(t *testing.T) {
	port := freeEvenPort(t)
	cfg := fastConfig()
	cfg.MulticastSource = "10.0.0.1"
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if rx, err := ristgo.NewReceiver(addr, cfg); err == nil {
		rx.Close()
		t.Fatal("NewReceiver accepted MulticastSource on a unicast bind")
	}
}

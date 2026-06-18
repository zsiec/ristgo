//go:build interop

// Simple-profile multicast interop tests against the libRIST reference CLI tools,
// mirroring libRIST's multicast send_receive cases. A RIST flow runs over an IPv4
// multicast group on a real interface (libRIST takes the group/interface in the
// rist:// URL via ?miface=, ristgo via Config.Interface), and the bytes are
// verified end-to-end. Like the multicast e2e test these are environment-
// dependent — they need a real multicast-capable interface and host multicast
// loopback — so they t.Skip gracefully when that is unavailable, on top of the
// usual libRIST-tools skip. They reuse the multicast probe helpers from
// multicast_e2e_test.go and the tool helpers from interop_test.go.
package ristgo_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// interopMcastGroup picks a randomized admin-scoped (239.x) group so concurrent
// runs and any real network traffic do not collide. salt distinguishes the two
// directions' groups within one test binary.
func interopMcastGroup(salt byte) netip.Addr {
	return netip.AddrFrom4([4]byte{239, 201, byte(time.Now().UnixNano() & 0xff), salt})
}

// TestInteropMulticastGoRxFromLibristTx: libRIST ristsender -> IPv4 multicast
// group <- ristgo Receiver (joined on the same interface). Proves ristgo joins
// and decodes a libRIST Simple-profile multicast stream byte-exact.
func TestInteropMulticastGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	iface := multicastCapableIface(t)
	if iface == "" {
		t.Skip("no up, multicast-capable, non-loopback IPv4 interface available")
	}
	group := interopMcastGroup(0x11)
	port := freeMulticastPort(t)
	if !canJoinMulticast(t, iface, group, port) {
		t.Skipf("multicast join/loopback not available on %s for %s (environment)", iface, group)
	}
	feedPort := freeUDPPort(t, port, port+1)

	rxCfg := fastConfig()
	rxCfg.Interface = iface
	rxCfg.BufferMin = 300 * time.Millisecond
	rxCfg.BufferMax = 300 * time.Millisecond
	rx, err := ristgo.NewReceiver(fmt.Sprintf("%s:%d", group, port), rxCfg)
	if err != nil {
		t.Fatalf("NewReceiver(%s:%d): %v", group, port, err)
	}
	defer rx.Close()

	// libRIST sends to the group on the chosen interface; ?miface= sets its egress
	// interface so the loopback copy reaches ristgo's joined socket on this host.
	spawnTool(t, sender, "-p", "0", "-b", "300",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://%s:%d?miface=%s", group, port, iface))
	waitToolReady(t, feedPort, 5*time.Second)

	data, want := randomData(t, interopN)
	go feedUDP(t, feedPort, data)

	got := readN(t, rx, len(data))
	if len(got) != len(data) || sha256.Sum256(got) != want {
		t.Fatalf("multicast GoRx: got %d/%d bytes, hash-exact=%v (recovered=%d lost=%d)",
			len(got), len(data), sha256.Sum256(got) == want, rx.Stats().Recovered, rx.Stats().Lost)
	}
	t.Logf("multicast byte-exact: ristgo received %d bytes from libRIST over %s", len(got), group)
}

// TestInteropMulticastLibristRxFromGoTx: ristgo Sender -> IPv4 multicast group <-
// libRIST ristreceiver (joined on the same interface). Proves libRIST joins and
// decodes a ristgo Simple-profile multicast stream byte-exact. The ristgo sender
// enables multicast loopback so its datagrams reach libRIST's joined socket on
// this host.
func TestInteropMulticastLibristRxFromGoTx(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	iface := multicastCapableIface(t)
	if iface == "" {
		t.Skip("no up, multicast-capable, non-loopback IPv4 interface available")
	}
	group := interopMcastGroup(0x12)
	port := freeMulticastPort(t)
	if !canJoinMulticast(t, iface, group, port) {
		t.Skipf("multicast join/loopback not available on %s for %s (environment)", iface, group)
	}
	capPort := freeUDPPort(t, port, port+1)

	// Simple profile has no handshake, so libRIST anchors its receive flow on the first RTP
	// packet it gets over the group; a brief paced warmup lets it anchor before the counted
	// data, which we then assert is intact at the capture tail (see TestInteropLibristRxFromGoTx).
	const warmup = 24
	data, _ := randomData(t, interopN)
	capt := newUDPCapture(t, capPort, (warmup+interopN)*interopChunk)
	spawnTool(t, receiver, "-p", "0", "-b", "300",
		"-i", fmt.Sprintf("rist://@%s:%d?miface=%s", group, port, iface),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	// waitToolReady probes a unicast bind, which a multicast group bind does not
	// hold, so give libRIST a fixed moment to join the group instead.
	time.Sleep(1500 * time.Millisecond)

	txCfg := fastConfig()
	txCfg.Interface = iface
	txCfg.MulticastTTL = 1
	txCfg.MulticastLoopback = true
	txCfg.BufferMin = 300 * time.Millisecond
	txCfg.BufferMax = 300 * time.Millisecond
	tx, err := ristgo.NewSender(fmt.Sprintf("%s:%d", group, port), txCfg)
	if err != nil {
		t.Fatalf("NewSender(%s:%d): %v", group, port, err)
	}
	defer tx.Close()

	filler := bytes.Repeat([]byte{0xAA}, interopChunk)
	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	go func() {
		for i := 0; i < warmup; i++ {
			tx.Write(filler) // let libRIST anchor before the counted data
			time.Sleep(3 * time.Millisecond)
		}
		for off := 0; off < len(data); off += interopChunk {
			tx.Write(data[off : off+interopChunk])
			if (off/interopChunk)%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	got := capt.wait(20 * time.Second)
	if len(got) < len(data) {
		t.Fatalf("multicast LibristRx: libRIST received %d/%d bytes", len(got), len(data))
	}
	if !bytes.Equal(got[len(got)-len(data):], data) {
		t.Fatalf("multicast LibristRx: data not intact at libRIST capture tail over %s", group)
	}
	t.Logf("multicast byte-exact: libRIST received %d bytes from ristgo over %s", len(data), group)
}

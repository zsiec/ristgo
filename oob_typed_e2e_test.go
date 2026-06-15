package ristgo_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2EOOBTypedTunnel proves any-protocol encapsulation end to end: on one
// connection the sender tunnels two payloads under different GRE protocol types
// (the default 0x0800 via WriteOOB, and an arbitrary EtherType via WriteOOBTyped),
// and the receiver demultiplexes them with ReadOOBTyped, recovering each payload
// under its own protocol tag. This is the dispatch-by-protocol behavior the typed
// tunnel adds over the opaque OOB channel.
func TestE2EOOBTypedTunnel(t *testing.T) {
	const protoIPv6 uint16 = 0x86DD // an arbitrary tunnelled EtherType (ristgo<->ristgo)
	payloadIP := []byte("default-OOB payload (IPv4/0x0800) \x00\x47\xff")
	payloadV6 := []byte("typed-tunnel payload (IPv6/0x86DD) \x01\x02\x03")

	cases := []struct {
		name string
		cfg  func() ristgo.Config
	}{
		{"main", func() ristgo.Config { return mainConfig("ristgo-typedoob-secret", 256) }},
		{"advanced", func() ristgo.Config { return advConfig("ristgo-typedoob-secret", 256, false) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
			rx, err := ristgo.NewReceiver(addr, tc.cfg())
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()
			tx, err := ristgo.NewSender(addr, tc.cfg())
			if err != nil {
				t.Fatalf("NewSender: %v", err)
			}
			defer tx.Close()

			// Reader: collect one payload per protocol tag until both are seen.
			type tagged struct {
				proto uint16
				data  []byte
			}
			seen := make(chan tagged, 8)
			go func() {
				rx.SetReadDeadline(time.Now().Add(8 * time.Second))
				buf := make([]byte, 4096)
				for {
					n, proto, rerr := rx.ReadOOBTyped(buf)
					if rerr != nil {
						return
					}
					seen <- tagged{proto, append([]byte(nil), buf[:n]...)}
				}
			}()

			// OOB is fire-and-forget (no ARQ): resend both until each tag arrives.
			deadline := time.Now().Add(8 * time.Second)
			tx.SetWriteDeadline(deadline)
			gotIP, gotV6 := false, false
			for time.Now().Before(deadline) && !(gotIP && gotV6) {
				if err := tx.WriteOOB(payloadIP); err != nil { // default 0x0800
					t.Fatalf("WriteOOB: %v", err)
				}
				if err := tx.WriteOOBTyped(protoIPv6, payloadV6); err != nil {
					t.Fatalf("WriteOOBTyped: %v", err)
				}
				select {
				case g := <-seen:
					switch g.proto {
					case ristgo.OOBProtocolIP:
						if !bytes.Equal(g.data, payloadIP) {
							t.Fatalf("0x0800 payload mismatch: got %q want %q", g.data, payloadIP)
						}
						gotIP = true
					case protoIPv6:
						if !bytes.Equal(g.data, payloadV6) {
							t.Fatalf("0x86DD payload mismatch: got %q want %q", g.data, payloadV6)
						}
						gotV6 = true
					default:
						t.Fatalf("received unexpected OOB protocol 0x%04X", g.proto)
					}
				case <-time.After(25 * time.Millisecond):
				}
			}
			if !gotIP || !gotV6 {
				t.Fatalf("did not demultiplex both tunnels: got 0x0800=%v 0x86DD=%v", gotIP, gotV6)
			}
		})
	}
}

// TestOOBTypedReservedRejected verifies WriteOOBTyped refuses a GRE protocol type
// RIST uses for its own framing (which the peer's demux would misroute), returning
// ErrOOBProtocol, while a non-reserved type and the default are accepted.
func TestOOBTypedReservedRejected(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	tx, err := ristgo.NewSender(addr, mainConfig("ristgo-typedoob-secret", 256))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	// Reserved RIST GRE protocol types: REDUCED, KEEPALIVE, EAPOL, VSF.
	for _, reserved := range []uint16{0x88B6, 0x88B5, 0x888E, 0xCCE0} {
		if err := tx.WriteOOBTyped(reserved, []byte("x")); !errors.Is(err, ristgo.ErrOOBProtocol) {
			t.Fatalf("WriteOOBTyped(0x%04X) = %v, want ErrOOBProtocol", reserved, err)
		}
	}
	// A non-reserved EtherType and the default are accepted (enqueued; dropped
	// silently here since no peer is learned, but no validation error).
	if err := tx.WriteOOBTyped(0x86DD, []byte("x")); err != nil {
		t.Fatalf("WriteOOBTyped(0x86DD) rejected: %v", err)
	}
	if err := tx.WriteOOBTyped(ristgo.OOBProtocolIP, []byte("x")); err != nil {
		t.Fatalf("WriteOOBTyped(OOBProtocolIP) rejected: %v", err)
	}
}

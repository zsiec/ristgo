package ristgo_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// ipChecksum is the standard 16-bit one's-complement header checksum (RFC 1071).
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildIPv4UDP builds a complete, valid IPv4+UDP datagram addressed to
// dstIP:dstPort carrying payload, with a correct IP header checksum. It mirrors
// what libRIST's tools/oob_shared.c (oob_build_api_payload -> populate_ip_header)
// puts on the out-of-band channel, so the test proves ristgo carries a whole IP
// packet, headers and all, the way RIST's IP-preservation path does.
func buildIPv4UDP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	pkt := make([]byte, total)
	// IPv4 header (20 bytes, no options).
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:], 0x1234) // identification
	pkt[6] = 0x40                               // flags: Don't Fragment
	pkt[8] = 64                                 // TTL
	pkt[9] = 17                                 // protocol = UDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:20]))
	// UDP header (8 bytes) + payload. UDP checksum left zero (optional on IPv4).
	binary.BigEndian.PutUint16(pkt[20:], srcPort)
	binary.BigEndian.PutUint16(pkt[22:], dstPort)
	binary.BigEndian.PutUint16(pkt[24:], uint16(udpLen))
	copy(pkt[28:], payload)
	return pkt
}

// TestE2EOOBPreservesFullIPPacket proves "stream IP preservation": a complete
// IPv4+UDP packet addressed to a multicast group is carried verbatim through the
// Main and Advanced out-of-band channel and arrives byte-identical, headers and
// multicast destination intact. ristgo frames OOB as GRE FULL (protocol type
// 0x0800), byte-identical to libRIST's RIST_PAYLOAD_TYPE_DATA_OOB, which is how
// libRIST itself passes a complete IP packet through the tunnel.
func TestE2EOOBPreservesFullIPPacket(t *testing.T) {
	// A complete IP packet whose destination is a multicast group (239.1.2.3:5004).
	// Preserving this destination end to end is the point of the feature.
	srcIP := [4]byte{192, 0, 2, 10}
	mcastDst := [4]byte{239, 1, 2, 3}
	ipPacket := buildIPv4UDP(srcIP, mcastDst, 40000, 5004, []byte("RIST IP-preserved multicast payload \x00\x47\xff"))

	cases := []struct {
		name string
		cfg  func() ristgo.Config
	}{
		{"main", func() ristgo.Config { return mainConfig("ristgo-ippres-secret", 256) }},
		{"advanced", func() ristgo.Config { return advConfig("ristgo-ippres-secret", 256, false) }},
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

			got := make(chan []byte, 1)
			go func() {
				rx.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4096)
				n, rerr := rx.ReadOOB(buf)
				if rerr != nil {
					got <- nil
					return
				}
				got <- append([]byte(nil), buf[:n]...)
			}()

			// OOB is fire-and-forget (no ARQ); resend until the receiver reads it.
			deadline := time.Now().Add(5 * time.Second)
			tx.SetWriteDeadline(deadline)
			for time.Now().Before(deadline) {
				if err := tx.WriteOOB(ipPacket); err != nil {
					t.Fatalf("WriteOOB: %v", err)
				}
				select {
				case out := <-got:
					if !bytes.Equal(out, ipPacket) {
						t.Fatalf("IP packet not preserved:\n got  %x\nwant %x", out, ipPacket)
					}
					// Explicitly confirm the multicast destination survived.
					if !bytes.Equal(out[16:20], mcastDst[:]) {
						t.Fatalf("multicast destination corrupted: got %v, want %v", out[16:20], mcastDst)
					}
					return
				case <-time.After(25 * time.Millisecond):
				}
			}
			t.Fatal("OOB IP packet not received within the deadline")
		})
	}
}

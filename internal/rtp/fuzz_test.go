package rtp

import (
	"bytes"
	"testing"
)

// fuzzSeeds returns wire-format seeds for the fuzz corpus: every golden
// packet plus truncations and bit-flips around the interesting boundaries.
func fuzzSeeds() [][]byte {
	seeds := [][]byte{
		nil,
		{0x80},
		bytes.Repeat([]byte{0xFF}, 16),
	}
	for _, g := range goldenPackets {
		seeds = append(seeds, g.wire, g.wire[:len(g.wire)/2])
	}
	return seeds
}

// FuzzHeaderUnmarshal feeds arbitrary bytes to Header.Unmarshal. It must
// never panic; on success the header must re-encode and re-decode to an
// identical header, byte-stably.
func FuzzHeaderUnmarshal(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var h Header
		n, err := h.Unmarshal(data)
		if err != nil {
			return
		}
		if n < FixedHeaderSize || n > len(data) {
			t.Fatalf("Unmarshal consumed %d of %d bytes", n, len(data))
		}
		if size := h.MarshalSize(); size != n {
			t.Fatalf("MarshalSize() = %d, but Unmarshal consumed %d", size, n)
		}

		wire, err := h.AppendTo(nil)
		if err != nil {
			t.Fatalf("re-encode of decoded header failed: %v", err)
		}

		var h2 Header
		n2, err := h2.Unmarshal(wire)
		if err != nil {
			t.Fatalf("decode of re-encoded header failed: %v", err)
		}
		if n2 != len(wire) {
			t.Fatalf("re-decode consumed %d of %d bytes", n2, len(wire))
		}
		if !headerEqual(&h, &h2) {
			t.Fatalf("decode(encode(h)) != h:\n h  %+v\n h2 %+v", h, h2)
		}

		// Byte-stable re-encode of encoder output.
		wire2, err := h2.AppendTo(nil)
		if err != nil {
			t.Fatalf("second re-encode failed: %v", err)
		}
		if !bytes.Equal(wire, wire2) {
			t.Fatalf("re-encode not byte-stable:\n %x\n %x", wire, wire2)
		}
	})
}

// FuzzPacketUnmarshal feeds arbitrary bytes to Packet.Unmarshal. It must
// never panic; on success the packet must re-encode and re-decode to an
// identical packet, byte-stably. (encode(decode(data)) may differ from data
// itself only in non-final padding octets, which the codec does not store.)
func FuzzPacketUnmarshal(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Packet
		if err := p.Unmarshal(data); err != nil {
			return
		}
		if size := p.MarshalSize(); size != len(data) {
			t.Fatalf("MarshalSize() = %d, input was %d bytes", size, len(data))
		}

		buf := make([]byte, p.MarshalSize())
		n, err := p.MarshalTo(buf)
		if err != nil {
			t.Fatalf("re-encode of decoded packet failed: %v", err)
		}
		if n != len(buf) {
			t.Fatalf("MarshalTo wrote %d of %d sized bytes", n, len(buf))
		}

		var p2 Packet
		if err := p2.Unmarshal(buf); err != nil {
			t.Fatalf("decode of re-encoded packet failed: %v", err)
		}
		if !packetEqual(&p, &p2) {
			t.Fatalf("decode(encode(p)) != p:\n p  %+v\n p2 %+v", p, p2)
		}

		// Byte-stable re-encode of encoder output.
		buf2, err := p2.AppendTo(nil)
		if err != nil {
			t.Fatalf("second re-encode failed: %v", err)
		}
		if !bytes.Equal(buf, buf2) {
			t.Fatalf("re-encode not byte-stable:\n %x\n %x", buf, buf2)
		}
	})
}

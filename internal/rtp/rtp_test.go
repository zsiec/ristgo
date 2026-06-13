package rtp

import (
	"bytes"
	"errors"
	"testing"
)

// headerEqual compares two headers field by field, treating nil and empty
// slices as equal (Unmarshal yields nil/empty depending on input shape).
func headerEqual(a, b *Header) bool {
	if a.Version != b.Version || a.Padding != b.Padding || a.Extension != b.Extension ||
		a.CSRCCount != b.CSRCCount || a.Marker != b.Marker || a.PayloadType != b.PayloadType ||
		a.SequenceNumber != b.SequenceNumber || a.Timestamp != b.Timestamp || a.SSRC != b.SSRC ||
		a.ExtensionProfile != b.ExtensionProfile {
		return false
	}
	if len(a.CSRC) != len(b.CSRC) {
		return false
	}
	for i := range a.CSRC {
		if a.CSRC[i] != b.CSRC[i] {
			return false
		}
	}
	return bytes.Equal(a.ExtensionPayload, b.ExtensionPayload)
}

// packetEqual compares two packets field by field with the same nil/empty
// slice semantics as headerEqual.
func packetEqual(a, b *Packet) bool {
	return headerEqual(&a.Header, &b.Header) &&
		bytes.Equal(a.Payload, b.Payload) &&
		a.PaddingSize == b.PaddingSize
}

// goldenPackets are hand-built packets with the exact wire bytes derived
// from the RFC 3550 §5.1 layout, used by the golden, round-trip, and fuzz
// seed tests.
var goldenPackets = []struct {
	name string
	pkt  Packet
	wire []byte
}{
	{
		// Minimal RIST media packet, mirroring how libRIST builds MPEG-TS
		// data packets (src/udp.c:216-230: flags = RTP_MPEGTS_FLAGS 0x80,
		// payload_type = RTP_PTYPE_MPEGTS 0x21, ssrc = adv_flow_id).
		//
		// Byte 0: V=2 (binary 10), P=0, X=0, CC=0 -> 1000_0000 = 0x80
		//         (== RTP_MPEGTS_FLAGS, librist src/proto/rtp.h:106).
		// Byte 1: M=0, PT=0x21 (binary 0100001)  -> 0010_0001 = 0x21.
		// Seq 0x1234, TS 0xDEADBEEF, SSRC 0x4D4F4F56 (even = base flow),
		// big-endian per RFC 3550 §5.1. Payload starts with the MPEG-TS
		// sync byte 0x47.
		name: "mpegts-minimal",
		pkt: Packet{
			Header: Header{
				Version:        2,
				PayloadType:    PayloadTypeMPEGTS,
				SequenceNumber: 0x1234,
				Timestamp:      0xDEADBEEF,
				SSRC:           0x4D4F4F56,
			},
			Payload: []byte{0x47, 0x11, 0x22, 0x33},
		},
		wire: []byte{
			0x80, 0x21, 0x12, 0x34, // V/P/X/CC, M/PT, sequence number
			0xDE, 0xAD, 0xBE, 0xEF, // timestamp
			0x4D, 0x4F, 0x4F, 0x56, // SSRC
			0x47, 0x11, 0x22, 0x33, // payload
		},
	},
	{
		// RIST retransmission of mpegts-minimal: the ORIGINAL packet —
		// same seq, timestamp, and payload — with only the SSRC LSB set
		// (librist src/udp.c:227, ssrc = htobe32(adv_flow_id | 0x01)).
		// 0x4D4F4F56 | 1 = 0x4D4F4F57. NOT RFC 4588.
		name: "mpegts-retransmit",
		pkt: Packet{
			Header: Header{
				Version:        2,
				PayloadType:    PayloadTypeMPEGTS,
				SequenceNumber: 0x1234,
				Timestamp:      0xDEADBEEF,
				SSRC:           0x4D4F4F57,
			},
			Payload: []byte{0x47, 0x11, 0x22, 0x33},
		},
		wire: []byte{
			0x80, 0x21, 0x12, 0x34,
			0xDE, 0xAD, 0xBE, 0xEF,
			0x4D, 0x4F, 0x4F, 0x57, // SSRC with retransmit LSB set
			0x47, 0x11, 0x22, 0x33,
		},
	},
	{
		// Fully loaded header: 2 CSRCs, classic RFC 3550 extension with
		// the RIST NPD profile 0x5249 "RI" (librist src/proto/rtp.h:132)
		// and one 32-bit word of payload, plus 2 bytes of padding.
		//
		// Byte 0: V=2, P=1, X=1, CC=2 -> 1011_0010 = 0xB2.
		// Byte 1: M=1, PT=96 (binary 1100000) -> 1110_0000 = 0xE0.
		// Extension header (RFC 3550 §5.3.1): profile 0x5249, length
		// 0x0001 in 32-bit words. Padding (RFC 3550 §5.1): one zero
		// octet then the count octet 0x02.
		name: "csrc-extension-padding",
		pkt: Packet{
			Header: Header{
				Version:          2,
				Padding:          true,
				Extension:        true,
				CSRCCount:        2,
				Marker:           true,
				PayloadType:      96,
				SequenceNumber:   0xFFFF,
				Timestamp:        0x01020304,
				SSRC:             0x11223344,
				CSRC:             []uint32{0x55667788, 0x99AABBCC},
				ExtensionProfile: ExtensionProfileRIST,
				ExtensionPayload: []byte{0x80, 0x00, 0xAB, 0xCD},
			},
			Payload:     []byte{0xDE, 0xAD},
			PaddingSize: 2,
		},
		wire: []byte{
			0xB2, 0xE0, 0xFF, 0xFF, // V=2|P|X|CC=2, M|PT=96, seq 0xFFFF
			0x01, 0x02, 0x03, 0x04, // timestamp
			0x11, 0x22, 0x33, 0x44, // SSRC
			0x55, 0x66, 0x77, 0x88, // CSRC[0]
			0x99, 0xAA, 0xBB, 0xCC, // CSRC[1]
			0x52, 0x49, 0x00, 0x01, // ext profile 0x5249 "RI", length 1 word
			0x80, 0x00, 0xAB, 0xCD, // ext payload (opaque here; NPD-shaped)
			0xDE, 0xAD, // payload
			0x00, 0x02, // padding: zero filler, count octet = 2
		},
	},
	{
		// Zero-length classic extension: valid per RFC 3550 §5.3.1 (the
		// length field counts words and may be zero). Byte 0: V=2, P=0,
		// X=1, CC=0 -> 1001_0000 = 0x90.
		name: "empty-extension",
		pkt: Packet{
			Header: Header{
				Version:          2,
				Extension:        true,
				PayloadType:      33,
				SequenceNumber:   0x0001,
				Timestamp:        0x00000002,
				SSRC:             0x00000004,
				ExtensionProfile: ExtensionProfileRIST,
				ExtensionPayload: []byte{},
			},
			Payload: []byte{0xAA},
		},
		wire: []byte{
			0x90, 0x21, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x02,
			0x00, 0x00, 0x00, 0x04,
			0x52, 0x49, 0x00, 0x00, // ext profile, length 0 words
			0xAA,
		},
	},
}

func TestPacketGoldenMarshal(t *testing.T) {
	for _, tc := range goldenPackets {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := tc.pkt.MarshalSize(), len(tc.wire); got != want {
				t.Fatalf("MarshalSize() = %d, want %d", got, want)
			}

			buf := make([]byte, tc.pkt.MarshalSize())
			n, err := tc.pkt.MarshalTo(buf)
			if err != nil {
				t.Fatalf("MarshalTo: %v", err)
			}
			if n != len(tc.wire) {
				t.Fatalf("MarshalTo wrote %d bytes, want %d", n, len(tc.wire))
			}
			if !bytes.Equal(buf[:n], tc.wire) {
				t.Fatalf("MarshalTo:\n got %x\nwant %x", buf[:n], tc.wire)
			}

			// AppendTo after a prefix must produce the same bytes.
			prefix := []byte{0x01, 0x02, 0x03}
			out, err := tc.pkt.AppendTo(prefix)
			if err != nil {
				t.Fatalf("AppendTo: %v", err)
			}
			if !bytes.Equal(out[:3], prefix[:3]) || !bytes.Equal(out[3:], tc.wire) {
				t.Fatalf("AppendTo:\n got %x\nwant %x%x", out, prefix, tc.wire)
			}
		})
	}
}

func TestPacketGoldenUnmarshal(t *testing.T) {
	for _, tc := range goldenPackets {
		t.Run(tc.name, func(t *testing.T) {
			var got Packet
			if err := got.Unmarshal(tc.wire); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !packetEqual(&got, &tc.pkt) {
				t.Fatalf("Unmarshal:\n got %+v\nwant %+v", got, tc.pkt)
			}
			if got.CSRCCount != uint8(len(tc.pkt.CSRC)) {
				t.Fatalf("CSRCCount = %d, want %d", got.CSRCCount, len(tc.pkt.CSRC))
			}
		})
	}
}

func TestPacketGoldenRoundTrip(t *testing.T) {
	for _, tc := range goldenPackets {
		t.Run(tc.name, func(t *testing.T) {
			// decode(encode(x)) == x.
			buf := make([]byte, tc.pkt.MarshalSize())
			n, err := tc.pkt.MarshalTo(buf)
			if err != nil {
				t.Fatalf("MarshalTo: %v", err)
			}
			var decoded Packet
			if err := decoded.Unmarshal(buf[:n]); err != nil {
				t.Fatalf("Unmarshal(encode(x)): %v", err)
			}
			if !packetEqual(&decoded, &tc.pkt) {
				t.Fatalf("decode(encode(x)):\n got %+v\nwant %+v", decoded, tc.pkt)
			}

			// Byte-stable re-encode: encode(decode(wire)) == wire.
			re := make([]byte, decoded.MarshalSize())
			m, err := decoded.MarshalTo(re)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(re[:m], tc.wire) {
				t.Fatalf("re-encode not byte-stable:\n got %x\nwant %x", re[:m], tc.wire)
			}
		})
	}
}

func TestHeaderGolden(t *testing.T) {
	// The header of each golden packet, alone, must round-trip through
	// the Header API with the same leading bytes.
	for _, tc := range goldenPackets {
		t.Run(tc.name, func(t *testing.T) {
			hdrLen := tc.pkt.Header.MarshalSize()

			buf := make([]byte, hdrLen)
			n, err := tc.pkt.Header.MarshalTo(buf)
			if err != nil {
				t.Fatalf("Header.MarshalTo: %v", err)
			}
			if n != hdrLen {
				t.Fatalf("Header.MarshalTo wrote %d, want %d", n, hdrLen)
			}
			if !bytes.Equal(buf, tc.wire[:hdrLen]) {
				t.Fatalf("Header.MarshalTo:\n got %x\nwant %x", buf, tc.wire[:hdrLen])
			}

			var h Header
			consumed, err := h.Unmarshal(tc.wire)
			if err != nil {
				t.Fatalf("Header.Unmarshal: %v", err)
			}
			if consumed != hdrLen {
				t.Fatalf("Header.Unmarshal consumed %d, want %d", consumed, hdrLen)
			}
			if !headerEqual(&h, &tc.pkt.Header) {
				t.Fatalf("Header.Unmarshal:\n got %+v\nwant %+v", h, tc.pkt.Header)
			}

			out, err := tc.pkt.Header.AppendTo(nil)
			if err != nil {
				t.Fatalf("Header.AppendTo: %v", err)
			}
			if !bytes.Equal(out, tc.wire[:hdrLen]) {
				t.Fatalf("Header.AppendTo:\n got %x\nwant %x", out, tc.wire[:hdrLen])
			}
		})
	}
}

func TestHeaderRoundTripTable(t *testing.T) {
	// Synthetic headers exercising each field independently; every entry
	// must survive encode -> decode -> re-encode byte-stably.
	tests := []struct {
		name string
		hdr  Header
	}{
		{"zero-version", Header{}},
		{"version-3", Header{Version: 3}},
		{"padding-bit-only", Header{Version: 2, Padding: true}},
		{"marker", Header{Version: 2, Marker: true, PayloadType: 0x7F}},
		{"pt-max", Header{Version: 2, PayloadType: 127}},
		{"seq-max", Header{Version: 2, SequenceNumber: 0xFFFF}},
		{"ts-max", Header{Version: 2, Timestamp: 0xFFFFFFFF}},
		{"ssrc-max", Header{Version: 2, SSRC: 0xFFFFFFFF}},
		{"one-csrc", Header{Version: 2, CSRCCount: 1, CSRC: []uint32{42}}},
		{"max-csrc", Header{Version: 2, CSRCCount: 15, CSRC: make([]uint32, 15)}},
		{
			"rist-npd-shape",
			Header{
				Version:          2,
				Extension:        true,
				PayloadType:      PayloadTypeMPEGTS,
				SequenceNumber:   0x8000,
				Timestamp:        90000,
				SSRC:             0x0000CCE0,
				ExtensionProfile: ExtensionProfileRIST,
				ExtensionPayload: []byte{0xC0, 0x7F, 0x00, 0x01},
			},
		},
		{
			"long-extension",
			Header{
				Version:          2,
				Extension:        true,
				ExtensionProfile: 0xBEDE, // carried opaquely, not parsed as RFC 8285
				ExtensionPayload: bytes.Repeat([]byte{0x5A}, 64),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tc.hdr.AppendTo(nil)
			if err != nil {
				t.Fatalf("AppendTo: %v", err)
			}
			if len(wire) != tc.hdr.MarshalSize() {
				t.Fatalf("AppendTo wrote %d bytes, MarshalSize says %d", len(wire), tc.hdr.MarshalSize())
			}

			var got Header
			n, err := got.Unmarshal(wire)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if n != len(wire) {
				t.Fatalf("Unmarshal consumed %d of %d bytes", n, len(wire))
			}
			if !headerEqual(&got, &tc.hdr) {
				t.Fatalf("round trip:\n got %+v\nwant %+v", got, tc.hdr)
			}

			re, err := got.AppendTo(nil)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(re, wire) {
				t.Fatalf("re-encode not byte-stable:\n got %x\nwant %x", re, wire)
			}
		})
	}
}

func TestPacketUnmarshalPadding(t *testing.T) {
	tests := []struct {
		name        string
		wire        []byte
		wantErr     error
		wantPayload []byte
		wantPad     uint8
	}{
		{
			// P=1 (byte 0 = 0xA0): 3 padding octets, 1 payload byte.
			name:        "padding-3",
			wire:        []byte{0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0xEE, 0x00, 0x00, 0x03},
			wantPayload: []byte{0xEE},
			wantPad:     3,
		},
		{
			// Padding consumes everything after the header: empty payload.
			name:        "padding-consumes-all",
			wire:        []byte{0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0x00, 0x02},
			wantPayload: []byte{},
			wantPad:     2,
		},
		{
			// P=1 but nothing after the header to read the count from.
			name:    "padding-no-count-octet",
			wire:    []byte{0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4},
			wantErr: ErrPacketTooShort,
		},
		{
			// Count octet zero is invalid when P is set (RFC 3550 §5.1).
			name:    "padding-count-zero",
			wire:    []byte{0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0x00},
			wantErr: ErrInvalidPadding,
		},
		{
			// Count octet claims more padding than bytes after the header.
			name:    "padding-count-too-large",
			wire:    []byte{0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0xEE, 0x05},
			wantErr: ErrInvalidPadding,
		},
		{
			// P=0: a trailing 0x03 is payload, not padding.
			name:        "no-padding-bit",
			wire:        []byte{0x80, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0xEE, 0x03},
			wantPayload: []byte{0xEE, 0x03},
			wantPad:     0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p Packet
			err := p.Unmarshal(tc.wire)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Unmarshal error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !bytes.Equal(p.Payload, tc.wantPayload) {
				t.Fatalf("Payload = %x, want %x", p.Payload, tc.wantPayload)
			}
			if p.PaddingSize != tc.wantPad {
				t.Fatalf("PaddingSize = %d, want %d", p.PaddingSize, tc.wantPad)
			}
		})
	}
}

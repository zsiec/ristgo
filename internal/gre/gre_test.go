package gre

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// goldenHeaders carries hand-derived wire bytes for every GRE base-header
// variant. Each vector cites the libRIST source that fixes the layout; the
// bytes were written out by hand from gre.c, not produced by the encoder.
var goldenHeaders = []struct {
	name string
	hdr  Header
	want []byte
}{
	{
		// Unencrypted, seq-only, version 1 (the WP6b default). flags1 has
		// only S (bit 4) -> 0x10; flags2 = (1 & 0x7) << 3 -> 0x08
		// (gre.c:48,60). prot_type written directly at version 1
		// (gre.c:85-86): REDUCED 0x88B6. seq big-endian (gre.c:63-66).
		name: "unencrypted-seq-v1-reduced",
		hdr:  Header{Version: 1, HasSeq: true, ProtType: ProtoReduced, Seq: 0x01020304},
		want: []byte{0x10, 0x08, 0x88, 0xB6, 0x01, 0x02, 0x03, 0x04},
	},
	{
		// Encrypted, key+seq, 128-bit (H=0), version 1. flags1 has K (bit 5)
		// and S (bit 4) -> 0x30 (gre.c:60,133); flags2 = 0x08, H clear
		// since key is 128-bit (gre.c:52-55). nonce at offset 4
		// (gre.c:47,135), seq immediately after (gre.c:61-67).
		name: "encrypted-key-seq-h0-v1",
		hdr: Header{
			Version: 1, HasKey: true, HasSeq: true,
			Nonce: [4]byte{0xAA, 0xBB, 0xCC, 0xDD}, Seq: 0x01020304,
			ProtType: ProtoReduced,
		},
		want: []byte{0x30, 0x08, 0x88, 0xB6, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04},
	},
	{
		// Encrypted, key+seq, 256-bit (H=1), version 1. flags2 = 0x08 |
		// (1<<6) = 0x48 (gre.c:54: H set when gre_version && key_size==256).
		name: "encrypted-key-seq-h1-v1",
		hdr: Header{
			Version: 1, HasKey: true, HasSeq: true, KeySize256: true,
			Nonce: [4]byte{0xAA, 0xBB, 0xCC, 0xDD}, Seq: 0x01020304,
			ProtType: ProtoReduced,
		},
		want: []byte{0x30, 0x48, 0x88, 0xB6, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04},
	},
	{
		// Version 2 VSF wrapper, unencrypted seq-only. flags1 = 0x10;
		// flags2 = (2 & 0x7) << 3 = 0x10 (gre.c:48); prot_type = VSF 0xCCE0
		// (gre.c:84). The VSFProto bytes (type/subtype) are appended
		// separately by VSFProto.AppendTo, so the base header alone is 8
		// bytes here.
		name: "vsf-base-v2-seq",
		hdr:  Header{Version: 2, HasSeq: true, ProtType: ProtoVSF, Seq: 0x01020304},
		want: []byte{0x10, 0x10, 0xCC, 0xE0, 0x01, 0x02, 0x03, 0x04},
	},
}

func TestHeaderAppendToGolden(t *testing.T) {
	for _, tc := range goldenHeaders {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.hdr.AppendTo(nil)
			if err != nil {
				t.Fatalf("AppendTo: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("AppendTo =\n %x\nwant\n %x", got, tc.want)
			}
			if tc.hdr.Size() != len(tc.want) {
				t.Fatalf("Size() = %d, want %d", tc.hdr.Size(), len(tc.want))
			}
		})
	}
}

func TestHeaderParseGolden(t *testing.T) {
	for _, tc := range goldenHeaders {
		t.Run(tc.name, func(t *testing.T) {
			h, off, err := Parse(tc.want)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if off != len(tc.want) {
				t.Fatalf("Parse offset = %d, want %d", off, len(tc.want))
			}
			if !reflect.DeepEqual(h, tc.hdr) {
				t.Fatalf("Parse =\n %+v\nwant\n %+v", h, tc.hdr)
			}
		})
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	for _, tc := range goldenHeaders {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tc.hdr.AppendTo(nil)
			if err != nil {
				t.Fatalf("AppendTo: %v", err)
			}
			h, off, err := Parse(wire)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if off != len(wire) {
				t.Fatalf("offset %d != %d", off, len(wire))
			}
			if !reflect.DeepEqual(h, tc.hdr) {
				t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", h, tc.hdr)
			}
			wire2, err := h.AppendTo(nil)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(wire, wire2) {
				t.Fatalf("re-encode not byte-stable:\n %x\n %x", wire, wire2)
			}
		})
	}
}

// TestReducedGolden freezes the reduced-overhead header bytes for the default
// virtual ports: src=1971 (0x07B3), dst=1968 (0x07B0), src first on the wire
// (gre.c:90-93; parse rist-common.c:3071-3072).
func TestReducedGolden(t *testing.T) {
	r := ReducedHeader{SrcPort: DefaultVirtSrcPort, DstPort: DefaultVirtDstPort}
	want := []byte{0x07, 0xB3, 0x07, 0xB0}
	got := r.AppendTo(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendTo = %x, want %x", got, want)
	}
	parsed, n, err := ParseReduced(got)
	if err != nil {
		t.Fatalf("ParseReduced: %v", err)
	}
	if n != ReducedHeaderSize {
		t.Fatalf("ParseReduced consumed %d, want %d", n, ReducedHeaderSize)
	}
	if parsed != r {
		t.Fatalf("ParseReduced = %+v, want %+v", parsed, r)
	}
}

// TestVSFProtoGolden freezes the VSF wrapper bytes for each subtype. type is
// always 0x0000 (RIST); REDUCED subtype 0x0000, KEEPALIVE 0x8000,
// BUFFER_NEGOTIATION 0x8002 (gre.c:74-82, big-endian).
func TestVSFProtoGolden(t *testing.T) {
	cases := []struct {
		name    string
		subtype uint16
		want    []byte
	}{
		{"reduced", VSFSubtypeReduced, []byte{0x00, 0x00, 0x00, 0x00}},
		{"keepalive", VSFSubtypeKeepalive, []byte{0x00, 0x00, 0x80, 0x00}},
		{"buffer-negotiation", VSFSubtypeBufferNegotiation, []byte{0x00, 0x00, 0x80, 0x02}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := VSFProto{Type: VSFTypeRIST, Subtype: tc.subtype}
			got := v.AppendTo(nil)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("AppendTo = %x, want %x", got, tc.want)
			}
			parsed, n, err := ParseVSFProto(got)
			if err != nil {
				t.Fatalf("ParseVSFProto: %v", err)
			}
			if n != VSFProtoSize {
				t.Fatalf("consumed %d, want %d", n, VSFProtoSize)
			}
			if parsed != v {
				t.Fatalf("ParseVSFProto = %+v, want %+v", parsed, v)
			}
		})
	}
}

// TestKeepaliveGolden freezes the standard libRIST keep-alive body: MAC, then
// cap1 with bits 0,2,5 (N|E|B = 0x25) and cap2 with bit 5 (V = 0x20)
// (gre.c:231-236).
func TestKeepaliveGolden(t *testing.T) {
	mac := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	k := Keepalive{MAC: mac, Caps: StandardCapabilities()}
	want := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x25, 0x20}
	got := k.AppendTo(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendTo = %x, want %x", got, want)
	}

	parsed, err := ParseKeepalive(got)
	if err != nil {
		t.Fatalf("ParseKeepalive: %v", err)
	}
	if parsed.MAC != mac {
		t.Fatalf("MAC = %x, want %x", parsed.MAC, mac)
	}
	if parsed.Caps != StandardCapabilities() {
		t.Fatalf("Caps = %+v, want %+v", parsed.Caps, StandardCapabilities())
	}
	if parsed.HasAdvExt {
		t.Fatalf("HasAdvExt = true, want false")
	}
	if parsed.JSON != nil {
		t.Fatalf("JSON = %q, want nil", parsed.JSON)
	}
}

// TestKeepaliveAdvExtAndJSON exercises the optional Advanced extended block
// (I bit = 0x80, gre.c:242) followed by a JSON payload, and round-trips it.
func TestKeepaliveAdvExtAndJSON(t *testing.T) {
	json := []byte(`{"cname":"ristgo"}`)
	k := Keepalive{
		MAC:       [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		Caps:      StandardCapabilities(),
		HasAdvExt: true,
		AdvExt:    AdvExtCaps{I: true},
		JSON:      json,
	}
	wire := k.AppendTo(nil)

	// Byte 8 (first extended octet) must be 0x80 (I bit), bytes 9-11 zero.
	if wire[8] != 0x80 || wire[9] != 0 || wire[10] != 0 || wire[11] != 0 {
		t.Fatalf("ext block = %x, want 80 00 00 00", wire[8:12])
	}
	if !bytes.Equal(wire[12:], json) {
		t.Fatalf("json bytes = %q, want %q", wire[12:], json)
	}

	parsed, err := ParseKeepalive(wire)
	if err != nil {
		t.Fatalf("ParseKeepalive: %v", err)
	}
	if !parsed.HasAdvExt || !parsed.AdvExt.I || parsed.AdvExt.G || parsed.AdvExt.C {
		t.Fatalf("AdvExt = %+v (HasAdvExt=%v), want only I", parsed.AdvExt, parsed.HasAdvExt)
	}
	if !bytes.Equal(parsed.JSON, json) {
		t.Fatalf("parsed JSON = %q, want %q", parsed.JSON, json)
	}
}

func TestParseReservedBitRejection(t *testing.T) {
	cases := []struct {
		name  string
		flags [2]byte
	}{
		// flags1 bit 6 reserved must be zero (rist-common.c:2927).
		{"flags1-bit6", [2]byte{1 << 6, 0x08}},
		// flags2 low three bits must be zero: GRE version bit 0...
		{"flags2-bit0", [2]byte{0x10, 0x08 | 0x01}},
		{"flags2-bit1", [2]byte{0x10, 0x08 | 0x02}},
		{"flags2-bit2", [2]byte{0x10, 0x08 | 0x04}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := []byte{tc.flags[0], tc.flags[1], 0x88, 0xB6, 0, 0, 0, 0}
			if _, _, err := Parse(b); !errors.Is(err, ErrNonConformant) {
				t.Fatalf("Parse err = %v, want ErrNonConformant", err)
			}
		})
	}
}

func TestParseShortBuffer(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"three-bytes", []byte{0x10, 0x08, 0x88}},
		// S bit set but only base header present (needs 4 more bytes).
		{"seq-truncated", []byte{0x10, 0x08, 0x88, 0xB6, 0x01}},
		// K and S set but only nonce present (needs 8 bytes after base).
		{"key-seq-truncated", []byte{0x30, 0x08, 0x88, 0xB6, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Parse(tc.b); !errors.Is(err, ErrShortBuffer) {
				t.Fatalf("Parse err = %v, want ErrShortBuffer", err)
			}
		})
	}
}

package gre

import (
	"bytes"
	"reflect"
	"testing"
)

// fuzzSeeds returns wire-format seeds for the fuzz corpus: every golden header
// plus a handful of degenerate and boundary inputs.
func fuzzSeeds() [][]byte {
	seeds := [][]byte{
		nil,
		{0x10},
		{0x10, 0x08, 0x88},
		bytes.Repeat([]byte{0xFF}, 4),
		bytes.Repeat([]byte{0xFF}, 16),
	}
	for _, g := range goldenHeaders {
		seeds = append(seeds, g.want, g.want[:len(g.want)/2])
	}
	return seeds
}

// FuzzParse feeds arbitrary bytes to Parse. It must never panic; on success
// the header must re-encode and re-decode identically and byte-stably.
func FuzzParse(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		h, off, err := Parse(data)
		if err != nil {
			return
		}
		if off < BaseHeaderSize || off > len(data) {
			t.Fatalf("Parse consumed %d of %d bytes", off, len(data))
		}

		// Re-encode. The C (checksum) bit is never emitted by AppendTo, so
		// a parsed header that skipped a checksum will re-encode shorter;
		// in that case Size() already excludes the checksum, so compare
		// against Size(), not off.
		wire, err := h.AppendTo(nil)
		if err != nil {
			t.Fatalf("re-encode of parsed header failed: %v", err)
		}
		if len(wire) != h.Size() {
			t.Fatalf("AppendTo wrote %d bytes, Size() = %d", len(wire), h.Size())
		}

		h2, off2, err := Parse(wire)
		if err != nil {
			t.Fatalf("re-parse of encoded header failed: %v", err)
		}
		if off2 != len(wire) {
			t.Fatalf("re-parse consumed %d of %d bytes", off2, len(wire))
		}
		if !reflect.DeepEqual(h, h2) {
			t.Fatalf("Parse(AppendTo(h)) != h:\n h  %+v\n h2 %+v", h, h2)
		}

		wire2, err := h2.AppendTo(nil)
		if err != nil {
			t.Fatalf("second re-encode failed: %v", err)
		}
		if !bytes.Equal(wire, wire2) {
			t.Fatalf("re-encode not byte-stable:\n %x\n %x", wire, wire2)
		}
	})
}

// FuzzParseReduced feeds arbitrary bytes to ParseReduced; it must never panic
// and must round-trip byte-stably on success.
func FuzzParseReduced(f *testing.F) {
	f.Add([]byte{0x07, 0xB3, 0x07, 0xB0})
	f.Add([]byte(nil))
	f.Add(bytes.Repeat([]byte{0xFF}, 8))

	f.Fuzz(func(t *testing.T, data []byte) {
		r, n, err := ParseReduced(data)
		if err != nil {
			return
		}
		if n != ReducedHeaderSize {
			t.Fatalf("consumed %d, want %d", n, ReducedHeaderSize)
		}
		wire := r.AppendTo(nil)
		if !bytes.Equal(wire, data[:ReducedHeaderSize]) {
			t.Fatalf("re-encode %x != input %x", wire, data[:ReducedHeaderSize])
		}
	})
}

// FuzzParseVSFProto feeds arbitrary bytes to ParseVSFProto; no panics, and a
// stable round-trip on success.
func FuzzParseVSFProto(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x80, 0x00})
	f.Add([]byte(nil))
	f.Add([]byte{0x00, 0x01, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		v, n, err := ParseVSFProto(data)
		if err != nil {
			return
		}
		if n != VSFProtoSize {
			t.Fatalf("consumed %d, want %d", n, VSFProtoSize)
		}
		wire := v.AppendTo(nil)
		if !bytes.Equal(wire, data[:VSFProtoSize]) {
			t.Fatalf("re-encode %x != input %x", wire, data[:VSFProtoSize])
		}
	})
}

// FuzzParseKeepalive feeds arbitrary bytes to ParseKeepalive; it must never
// panic. On success, re-encoding the parsed form and re-parsing must yield an
// identical parse (the wire form is canonical even though the bare-JSON vs
// advExt+JSON split is inherently ambiguous, so we fix-point on the parse).
func FuzzParseKeepalive(f *testing.F) {
	f.Add([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x25, 0x20})
	f.Add(append([]byte{0, 1, 2, 3, 4, 5, 0x25, 0x20, 0x80, 0, 0, 0}, []byte(`{"a":1}`)...))
	f.Add([]byte(nil))
	f.Add(bytes.Repeat([]byte{0xFF}, 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := ParseKeepalive(data)
		if err != nil {
			return
		}
		wire := k.AppendTo(nil)
		if len(wire) != k.Size() {
			t.Fatalf("AppendTo wrote %d, Size() = %d", len(wire), k.Size())
		}
		k2, err := ParseKeepalive(wire)
		if err != nil {
			t.Fatalf("re-parse of encoded keepalive failed: %v", err)
		}
		if !keepaliveEqual(k, k2) {
			t.Fatalf("ParseKeepalive(AppendTo(k)) != k:\n k  %+v\n k2 %+v", k, k2)
		}
		wire2 := k2.AppendTo(nil)
		if !bytes.Equal(wire, wire2) {
			t.Fatalf("re-encode not byte-stable:\n %x\n %x", wire, wire2)
		}
	})
}

// keepaliveEqual compares two keepalives, treating nil and empty JSON as
// equal.
func keepaliveEqual(a, b Keepalive) bool {
	if a.MAC != b.MAC || a.Caps != b.Caps || a.HasAdvExt != b.HasAdvExt || a.AdvExt != b.AdvExt {
		return false
	}
	return bytes.Equal(a.JSON, b.JSON)
}

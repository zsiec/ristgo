package npd

import (
	"bytes"
	"testing"
)

// fuzzExtSeeds returns wire-format seeds for the ParseExt corpus.
func fuzzExtSeeds() [][]byte {
	return [][]byte{
		nil,
		{0x52, 0x49, 0x00, 0x01, 0x80, 0x40, 0x12, 0x34},
		{0x52, 0x49, 0x00, 0x01, 0xC0, 0x7F, 0xFF, 0xFF},
		{0x52, 0x49, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		{0x52, 0x48, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00}, // bad id
		{0x52, 0x49, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00}, // bad len
		{0x52, 0x49, 0x00, 0x01, 0x80},                   // short
		bytes.Repeat([]byte{0xFF}, 16),
	}
}

// FuzzParseExt asserts ParseExt never panics on arbitrary bytes, and that any
// successfully parsed Ext re-encodes byte-stably (the bitmap masked to 7 bits).
func FuzzParseExt(f *testing.F) {
	for _, s := range fuzzExtSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		e, n, err := ParseExt(data)
		if err != nil {
			if n != 0 {
				t.Fatalf("ParseExt consumed %d on error", n)
			}
			return
		}
		if n != ExtSize {
			t.Fatalf("ParseExt consumed %d, want %d", n, ExtSize)
		}
		// The model round-trips: re-encoding a parsed Ext and parsing it
		// again yields the same Ext, and that second encoding is
		// byte-stable. (The first encoding is NOT asserted byte-identical
		// to the input: only flags bit 7 and npd_bits are modeled, so
		// undefined flag bits and bitmap high bits are normalized away.)
		enc := e.AppendTo(nil)
		e2, n2, err := ParseExt(enc)
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if n2 != ExtSize {
			t.Fatalf("re-parse consumed %d, want %d", n2, ExtSize)
		}
		if e2 != e {
			t.Fatalf("re-parse %+v != %+v", e2, e)
		}
		if enc2 := e2.AppendTo(nil); !bytes.Equal(enc2, enc) {
			t.Fatalf("re-encode not byte-stable: % x vs % x", enc2, enc)
		}
	})
}

// FuzzExpand asserts Expand never panics on arbitrary input bytes and an
// arbitrary npd_bits byte. The output, when produced, must be a whole number
// of packets of the size the bitmap selects.
func FuzzExpand(f *testing.F) {
	f.Add([]byte(nil), byte(0))
	f.Add(make([]byte, SizeTS188), byte(1<<6))
	f.Add(make([]byte, 2*SizeTS204), byte(NPDSize204|1<<5))
	f.Add(bytes.Repeat([]byte{0x47}, 7*SizeTS188), byte(0x7F))
	f.Fuzz(func(t *testing.T, data []byte, npdBits byte) {
		out, err := Expand(nil, data, npdBits)
		if err != nil {
			return
		}
		if npdBits&NullBitmapMask == 0 {
			// No nulls named: Expand is a pure pass-through (it mirrors
			// libRIST returning 0 without inspecting the payload;
			// src/mpegts.c:64-65), so the output equals the input
			// verbatim and need not be TS-aligned.
			if !bytes.Equal(out, data) {
				t.Fatalf("no-null Expand altered input: % x", out)
			}
			return
		}
		size := SizeTS188
		if npdBits&NPDSize204 != 0 {
			size = SizeTS204
		}
		if len(out)%size != 0 {
			t.Fatalf("Expand output %d not a multiple of %d", len(out), size)
		}
		if len(out)/size > MaxPackets {
			t.Fatalf("Expand produced %d packets, > %d", len(out)/size, MaxPackets)
		}
	})
}

// FuzzSuppressExpandRoundTrip generates TS-shaped buffers from arbitrary bytes
// and asserts that Suppress followed by Expand reproduces the original exactly
// whenever Suppress succeeds, and that neither call panics.
func FuzzSuppressExpandRoundTrip(f *testing.F) {
	f.Add([]byte(nil), false)
	f.Add(make([]byte, SizeTS188), false)
	f.Add(make([]byte, 7*SizeTS188), false)
	f.Add(make([]byte, 3*SizeTS204), true)
	f.Fuzz(func(t *testing.T, seed []byte, use204 bool) {
		size := SizeTS188
		if use204 {
			size = SizeTS204
		}
		// Derive a 0..7 packet count from the seed; build well-formed TS
		// packets, marking some null based on seed bytes.
		count := 0
		if len(seed) > 0 {
			count = int(seed[0]) % (MaxPackets + 1)
		}
		var orig []byte
		for i := 0; i < count; i++ {
			makeNull := i < len(seed) && seed[i]&1 == 1
			if makeNull {
				orig = append(orig, nullPacket(size)...)
			} else {
				orig = append(orig, tsPacket(size, uint16(0x100+i), byte(i))...)
			}
		}

		out, npdBits, _, err := Suppress(nil, orig)
		if err != nil {
			return
		}
		got, err := Expand(nil, out, npdBits)
		if err != nil {
			t.Fatalf("Expand after successful Suppress: %v", err)
		}
		if !bytes.Equal(got, orig) {
			t.Fatalf("round-trip mismatch\n got: % x\nwant: % x", got, orig)
		}
	})
}

// FuzzSuppress feeds Suppress truly arbitrary bytes (not the well-formed TS
// packets FuzzSuppressExpandRoundTrip constructs), asserting the documented
// no-panic guarantee on malformed input — short buffers, non-multiple lengths,
// over-long payloads, and bad sync bytes must all return an error, never panic.
// (A full Suppress/Expand round-trip is NOT asserted here: a non-canonical null
// packet — valid sync + PID 0x1FFF but arbitrary body — is reconstructed in
// canonical form by Expand, so the inverse holds only for canonical nulls,
// which FuzzSuppressExpandRoundTrip covers.)
func FuzzSuppress(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(bytes.Repeat([]byte{0x47}, SizeTS188))      // valid sync, not null
	f.Add(bytes.Repeat([]byte{0x47}, 8*SizeTS188))    // >7 packets
	f.Add(make([]byte, SizeTS188-1))                  // non-multiple length
	f.Add(append([]byte{0x00}, make([]byte, 187)...)) // bad sync byte
	f.Fuzz(func(t *testing.T, data []byte) {
		out, _, suppressed, err := Suppress(nil, data)
		if err != nil {
			return
		}
		// On success every byte is accounted for: kept output plus suppressed
		// bytes equals the input length (each null packet removes exactly one
		// packet-size worth of bytes).
		if len(out)+suppressed != len(data) {
			t.Fatalf("Suppress lost bytes: len(out)=%d + suppressed=%d != len(in)=%d", len(out), suppressed, len(data))
		}
	})
}

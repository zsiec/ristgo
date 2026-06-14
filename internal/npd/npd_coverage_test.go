package npd

import (
	"bytes"
	"testing"
)

// TestExpandRoundTripFromSuppressAllPositions exhaustively covers every null
// subset of a 7-packet 188-byte buffer: Suppress then Expand must reproduce
// the original for all 128 masks.
func TestExpandRoundTripFromSuppressAllPositions(t *testing.T) {
	const n = 7
	for mask := 0; mask < (1 << n); mask++ {
		var orig []byte
		for i := 0; i < n; i++ {
			if mask&(1<<i) != 0 {
				orig = append(orig, nullPacket(SizeTS188)...)
			} else {
				orig = append(orig, tsPacket(SizeTS188, uint16(0x100+i), byte(i))...)
			}
		}
		out, npdBits, suppressed, err := Suppress(nil, orig)
		if err != nil {
			t.Fatalf("mask %#x: Suppress: %v", mask, err)
		}
		// suppressed byte count must equal popcount(mask) * 188.
		wantNulls := bits7(mask)
		if suppressed != wantNulls*SizeTS188 {
			t.Fatalf("mask %#x: suppressed=%d, want %d", mask, suppressed, wantNulls*SizeTS188)
		}
		got, err := Expand(nil, out, npdBits)
		if err != nil {
			t.Fatalf("mask %#x: Expand: %v", mask, err)
		}
		if !bytes.Equal(got, orig) {
			t.Fatalf("mask %#x: round-trip mismatch", mask)
		}
	}
}

// bits7 counts the set bits in the low 7 bits of v.
func bits7(v int) int {
	n := 0
	for v &= 0x7F; v != 0; v &= v - 1 {
		n++
	}
	return n
}

// TestSuppressEmptyInput confirms an empty payload is a zero-packet, no-op
// success (0 % 188 == 0, count 0, no nulls).
func TestSuppressEmptyInput(t *testing.T) {
	out, npdBits, suppressed, err := Suppress(nil, nil)
	if err != nil {
		t.Fatalf("Suppress(nil): %v", err)
	}
	if len(out) != 0 || npdBits != 0 || suppressed != 0 {
		t.Fatalf("Suppress(nil) = out %d, npdBits %#x, suppressed %d", len(out), npdBits, suppressed)
	}
}

// TestExpandEmptyInput confirms an empty input with a zero bitmap is a no-op.
func TestExpandEmptyInput(t *testing.T) {
	out, err := Expand(nil, nil, 0)
	if err != nil {
		t.Fatalf("Expand(nil,0): %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("Expand(nil,0) = %d bytes, want 0", len(out))
	}
}

// TestExpandSizeBitOnlyNoNulls confirms the 204 size bit alone (no null bits)
// is a pass-through.
func TestExpandSizeBitOnlyNoNulls(t *testing.T) {
	in := tsPacket(SizeTS204, 0x100, 0x55)
	out, err := Expand(nil, in, NPDSize204)
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("output altered")
	}
}

// TestParseExtConsumesExactly checks ParseExt consumes exactly 8 bytes even
// when the buffer is longer (trailing bytes are the RTP payload).
func TestParseExtConsumesExactly(t *testing.T) {
	buf := []byte{0x52, 0x49, 0x00, 0x01, 0x80, 0x40, 0x00, 0x07, 0xAA, 0xBB}
	e, n, err := ParseExt(buf)
	if err != nil {
		t.Fatalf("ParseExt: %v", err)
	}
	if n != ExtSize {
		t.Fatalf("consumed %d, want %d", n, ExtSize)
	}
	if !e.NPD || e.Size204 || e.NullBitmap != 0x40 || e.SeqExt != 0x0007 {
		t.Fatalf("parsed = %+v", e)
	}
}

// TestSuppressBadSyncMidStream confirms a bad sync byte on a later packet
// fails the whole payload (libRIST `fail` clears NPD).
func TestSuppressBadSyncMidStream(t *testing.T) {
	orig := append(nullPacket(SizeTS188), tsPacket(SizeTS188, 0x100, 0x00)...)
	orig[SizeTS188] = 0x00 // corrupt second packet's sync byte
	_, _, _, err := Suppress(nil, orig)
	if err == nil {
		t.Fatal("expected error for bad sync byte mid-stream")
	}
}

// TestExpandSuppressedSizeMatch confirms Expand uses 204-byte packets when the
// size bit is set and reconstructs full 204-byte nulls.
func TestExpand204Null(t *testing.T) {
	got, err := Expand(nil, nil, NPDSize204|byte(1<<6))
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(got) != SizeTS204 {
		t.Fatalf("len = %d, want %d", len(got), SizeTS204)
	}
	want := nullPacket(SizeTS204)
	if !bytes.Equal(got, want) {
		t.Fatalf("204 null = % x", got)
	}
}

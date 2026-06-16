package fec

import (
	"bytes"
	"testing"
)

// TestHeader5MatchesSpecLayout pins the SMPTE ST 2022-5:2012 §7.3 (Figure 4) FEC
// header byte layout: it encodes distinctive field values and asserts the exact
// 16 octets, so the wire format is verified against the published standard and can
// never silently regress. The reference bytes are hand-derived from Figure 4:
//
//	byte 0  = E(0) R(0) P X CC[4]      P=1 X=0 CC=0xA            -> 0x2A
//	byte 1  = M PT[7]                  M=1 PT=0x55               -> 0xD5
//	byte 2-3  = SN Base[16]            0x1234                    -> 12 34
//	byte 4-7  = TS Recovery[32]        0xAABBCCDD                -> AA BB CC DD
//	byte 8-9  = Length Recovery[16]    0x0102                    -> 01 02
//	byte 10-11 = Reserved                                        -> 00 00
//	byte 12-13 = Offset[10]<<6 | Rsvd  0x2AA<<6 = 0xAA80         -> AA 80
//	byte 14-15 = NA[10]<<6 | Reserved  0x155<<6 = 0x5540         -> 55 40
func TestHeader5MatchesSpecLayout(t *testing.T) {
	h := Header5{
		PRecovery:      true,
		XRecovery:      false,
		CCRecovery:     0x0A,
		MRecovery:      true,
		PTRecovery:     0x55,
		SNBase:         0x1234,
		TSRecovery:     0xAABBCCDD,
		LengthRecovery: 0x0102,
		Offset:         0x2AA, // 10-bit
		NA:             0x155, // 10-bit
	}
	want := []byte{0x2A, 0xD5, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x00, 0x00, 0xAA, 0x80, 0x55, 0x40}

	got := h.AppendTo(nil)
	if len(got) != HeaderSize || len(want) != HeaderSize {
		t.Fatalf("encoded len = %d (want %d) / reference len = %d", len(got), HeaderSize, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ST 2022-5 §7.3 layout mismatch:\n got = % X\nwant = % X", got, want)
	}

	// Round-trip: ParseHeader5 must recover every field exactly.
	back, off, err := ParseHeader5(got)
	if err != nil || off != HeaderSize {
		t.Fatalf("ParseHeader5 = (_, %d, %v), want (_, %d, nil)", off, err, HeaderSize)
	}
	if back != h {
		t.Fatalf("round-trip mismatch:\n got = %+v\nwant = %+v", back, h)
	}

	// The E and R flags (top two bits of byte 0) and the 6 reserved low bits of the
	// Offset/NA words are sender-set-to-zero per §7.3 and must stay clear.
	if got[0]&0xC0 != 0 {
		t.Errorf("byte 0 E/R bits set: %#02x", got[0])
	}
	if got[13]&0x3F != 0 || got[15]&0x3F != 0 {
		t.Errorf("reserved low bits of Offset/NA set: offset=%#02x na=%#02x", got[13], got[15])
	}
}

// TestHeader5OffsetNAFullRange checks the 10-bit Offset and NA fields round-trip at
// their maximum (1020 per dimension, the ST 2022-5 matrix ceiling) without bleeding
// into the reserved bits.
func TestHeader5OffsetNAFullRange(t *testing.T) {
	h := Header5{Offset: na10Max, NA: na10Max} // 0x3FF, the full 10-bit range
	got := h.AppendTo(nil)
	back, _, err := ParseHeader5(got)
	if err != nil {
		t.Fatalf("ParseHeader5: %v", err)
	}
	if back.Offset != na10Max || back.NA != na10Max {
		t.Fatalf("Offset/NA = %d/%d, want %d/%d", back.Offset, back.NA, na10Max, na10Max)
	}
	if got[13]&0x3F != 0 || got[15]&0x3F != 0 {
		t.Errorf("max Offset/NA bled into reserved bits: %#02x %#02x", got[13], got[15])
	}
}

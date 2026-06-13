package npd

import (
	"bytes"
	"errors"
	"testing"
)

// tsPacket builds a synthetic 188- or 204-byte MPEG-TS packet with the given
// 13-bit PID. The two bytes after the sync byte carry the flags1 word; for a
// null packet (PID 0x1FFF) the whole word is 0x1FFF, matching libRIST's
// be16toh(hdr->flags1) == 0x1FFF test (src/mpegts.c:30).
func tsPacket(size int, pid uint16, fill byte) []byte {
	p := make([]byte, size)
	p[0] = SyncByte
	p[1] = byte(pid >> 8)
	p[2] = byte(pid)
	p[3] = 0x10 // arbitrary flags2 for media packets
	for i := 4; i < size; i++ {
		p[i] = fill
	}
	return p
}

// nullPacket builds a TS null packet exactly as libRIST reconstructs one in
// expand_null_packets (src/mpegts.c:88-92): 0x47, 0x1FFF, flags2 bit4, 0xFF
// fill. This is the canonical form Expand must reproduce.
func nullPacket(size int) []byte {
	p := make([]byte, size)
	p[0] = SyncByte
	p[1] = 0x1F
	p[2] = 0xFF
	p[3] = byte(flags2Bit4)
	for i := tsHeaderSize; i < size; i++ {
		p[i] = 0xFF
	}
	return p
}

// TestExtGolden asserts the 8-byte wire encoding of the header extension
// byte-for-byte (librist src/proto/rtp.h:131-137).
func TestExtGolden(t *testing.T) {
	tests := []struct {
		name string
		ext  Ext
		want []byte
	}{
		{
			// NPD present, 188-byte packets, packets 0 and 2 null
			// (bits 6 and 4 set => 0x50), seq_ext 0x1234.
			name: "npd 188 two nulls",
			ext:  Ext{NPD: true, Size204: false, NullBitmap: 0x50, SeqExt: 0x1234},
			want: []byte{0x52, 0x49, 0x00, 0x01, 0x80, 0x50, 0x12, 0x34},
		},
		{
			// NPD present, 204-byte packets (npd_bits bit7 => +0x80),
			// packet 0 null (bit6 => 0x40) => npd_bits 0xC0.
			name: "npd 204 one null",
			ext:  Ext{NPD: true, Size204: true, NullBitmap: 0x40, SeqExt: 0xABCD},
			want: []byte{0x52, 0x49, 0x00, 0x01, 0x80, 0xC0, 0xAB, 0xCD},
		},
		{
			// No NPD, no nulls, zero seq_ext: flags and npd_bits clear.
			name: "empty",
			ext:  Ext{},
			want: []byte{0x52, 0x49, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		},
		{
			// NullBitmap with high bits set is masked to 7 bits; the
			// size bit comes only from Size204.
			name: "bitmap masked",
			ext:  Ext{NPD: true, NullBitmap: 0xFF, SeqExt: 0x0001},
			want: []byte{0x52, 0x49, 0x00, 0x01, 0x80, 0x7F, 0x00, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ext.AppendTo(nil)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("AppendTo = % x, want % x", got, tt.want)
			}
			// Round-trip parse; the masked bitmap is what comes back.
			back, n, err := ParseExt(got)
			if err != nil {
				t.Fatalf("ParseExt: %v", err)
			}
			if n != ExtSize {
				t.Fatalf("ParseExt consumed %d, want %d", n, ExtSize)
			}
			wantBack := tt.ext
			wantBack.NullBitmap &= NullBitmapMask
			if back != wantBack {
				t.Fatalf("ParseExt = %+v, want %+v", back, wantBack)
			}
		})
	}
}

// TestAppendToPreservesPrefix verifies AppendTo appends to existing content.
func TestAppendToPreservesPrefix(t *testing.T) {
	prefix := []byte{0xDE, 0xAD}
	got := Ext{NPD: true, SeqExt: 0x0102}.AppendTo(prefix)
	want := []byte{0xDE, 0xAD, 0x52, 0x49, 0x00, 0x01, 0x80, 0x00, 0x01, 0x02}
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendTo with prefix = % x, want % x", got, want)
	}
}

// TestParseExtErrors covers every rejection path of ParseExt.
func TestParseExtErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"nil", nil, ErrShortExt},
		{"short", []byte{0x52, 0x49, 0x00, 0x01, 0x80, 0x00, 0x12}, ErrShortExt},
		{"bad identifier", []byte{0x52, 0x48, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00}, ErrBadIdentifier},
		{"bad length 0", []byte{0x52, 0x49, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00}, ErrBadLength},
		{"bad length 2", []byte{0x52, 0x49, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00}, ErrBadLength},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, n, err := ParseExt(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseExt err = %v, want %v", err, tt.want)
			}
			if n != 0 {
				t.Fatalf("ParseExt consumed %d on error, want 0", n)
			}
		})
	}
}

// TestNPDBits asserts the npd_bits assembly helper.
func TestNPDBits(t *testing.T) {
	tests := []struct {
		size204 bool
		bitmap  byte
		want    byte
	}{
		{false, 0x00, 0x00},
		{false, 0x40, 0x40},
		{true, 0x40, 0xC0},
		{true, 0x00, 0x80},
		{false, 0xFF, 0x7F}, // high bit masked off the bitmap
		{true, 0xFF, 0xFF},
	}
	for _, tt := range tests {
		if got := NPDBits(tt.size204, tt.bitmap); got != tt.want {
			t.Fatalf("NPDBits(%v, %#x) = %#x, want %#x", tt.size204, tt.bitmap, got, tt.want)
		}
	}
}

// TestSuppressExpandRoundTrip drives a table of TS-packet buffers (1..7
// packets, various null subsets, 188 and 204 byte sizes) through Suppress then
// Expand and asserts the original bytes are reproduced exactly.
func TestSuppressExpandRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		nullMask  []bool // per-position: true => that packet is a null
		wantSupp  int    // expected suppressed byte count
		wantNPD   bool   // whether NPD applies (suppressed > 0)
		wantBitmp byte   // expected npd_bits (size bit + bitmap)
	}{
		{"single media", SizeTS188, []bool{false}, 0, false, 0x00},
		{"single null", SizeTS188, []bool{true}, SizeTS188, true, 0x40},
		{"two: null,media", SizeTS188, []bool{true, false}, SizeTS188, true, 0x40},
		{"two: media,null", SizeTS188, []bool{false, true}, SizeTS188, true, 0x20},
		{"seven all media", SizeTS188, []bool{false, false, false, false, false, false, false}, 0, false, 0x00},
		{"seven all null", SizeTS188, []bool{true, true, true, true, true, true, true}, 7 * SizeTS188, true, 0x7F},
		{"seven mixed", SizeTS188, []bool{false, true, false, true, false, true, false}, 3 * SizeTS188, true, 0x2A},
		{"204 single null", SizeTS204, []bool{true}, SizeTS204, true, 0x80 | 0x40},
		{"204 mixed", SizeTS204, []bool{true, false, true}, 2 * SizeTS204, true, 0x80 | 0x40 | 0x10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the original payload. Null positions use the
			// canonical libRIST null form so Expand can reproduce
			// them byte-for-byte.
			var orig []byte
			for i, isNull := range tt.nullMask {
				if isNull {
					orig = append(orig, nullPacket(tt.size)...)
				} else {
					orig = append(orig, tsPacket(tt.size, uint16(0x100+i), byte(i))...)
				}
			}

			out, npdBits, suppressed, err := Suppress(nil, orig)
			if err != nil {
				t.Fatalf("Suppress: %v", err)
			}
			if suppressed != tt.wantSupp {
				t.Fatalf("suppressed = %d, want %d", suppressed, tt.wantSupp)
			}
			if npdBits != tt.wantBitmp {
				t.Fatalf("npdBits = %#x, want %#x", npdBits, tt.wantBitmp)
			}
			if (suppressed > 0) != tt.wantNPD {
				t.Fatalf("NPD applies = %v, want %v", suppressed > 0, tt.wantNPD)
			}
			// Suppressed output is the kept packets only.
			wantKept := len(orig) - suppressed
			if len(out) != wantKept {
				t.Fatalf("kept output = %d bytes, want %d", len(out), wantKept)
			}

			// Expand must reproduce the original exactly.
			got, err := Expand(nil, out, npdBits)
			if err != nil {
				t.Fatalf("Expand: %v", err)
			}
			if !bytes.Equal(got, orig) {
				t.Fatalf("round-trip mismatch\n got: % x\nwant: % x", got, orig)
			}
		})
	}
}

// TestSuppressNoNullsCopiesThrough verifies a payload with no nulls is copied
// unchanged and reports suppressed == 0 (NPD not applied).
func TestSuppressNoNullsCopiesThrough(t *testing.T) {
	orig := append(tsPacket(SizeTS188, 0x100, 0x11), tsPacket(SizeTS188, 0x200, 0x22)...)
	out, npdBits, suppressed, err := Suppress(nil, orig)
	if err != nil {
		t.Fatalf("Suppress: %v", err)
	}
	if suppressed != 0 {
		t.Fatalf("suppressed = %d, want 0", suppressed)
	}
	if npdBits != 0 {
		t.Fatalf("npdBits = %#x, want 0", npdBits)
	}
	if !bytes.Equal(out, orig) {
		t.Fatalf("output altered: % x", out)
	}
}

// TestSuppressErrors covers the rejection paths of Suppress.
func TestSuppressErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"not multiple of 188 or 204", make([]byte, 100), ErrPayloadSize},
		{"eight 188-byte packets", make([]byte, 8*SizeTS188), ErrTooManyPackets},
		{"bad sync byte", func() []byte {
			p := tsPacket(SizeTS188, 0x100, 0x00)
			p[0] = 0x48
			return p
		}(), ErrSyncByte},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := Suppress(nil, tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Suppress err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestSuppress204NotMultipleOf188 confirms a 204-multiple length that is not a
// 188-multiple selects the 204 path and sets the size bit.
func TestSuppress204NotMultipleOf188(t *testing.T) {
	// 3*204 = 612, which is not a multiple of 188.
	if (3*SizeTS204)%SizeTS188 == 0 {
		t.Skip("612 happens to be a multiple of 188 on this build")
	}
	orig := bytes.Join([][]byte{
		nullPacket(SizeTS204),
		tsPacket(SizeTS204, 0x100, 0x33),
		nullPacket(SizeTS204),
	}, nil)
	_, npdBits, suppressed, err := Suppress(nil, orig)
	if err != nil {
		t.Fatalf("Suppress: %v", err)
	}
	if npdBits&NPDSize204 == 0 {
		t.Fatalf("size bit not set: npdBits=%#x", npdBits)
	}
	if suppressed != 2*SizeTS204 {
		t.Fatalf("suppressed = %d, want %d", suppressed, 2*SizeTS204)
	}
}

// TestExpandNoNullsCopiesThrough verifies Expand passes input through when the
// bitmap names no nulls.
func TestExpandNoNullsCopiesThrough(t *testing.T) {
	in := append(tsPacket(SizeTS188, 0x100, 0x11), tsPacket(SizeTS188, 0x200, 0x22)...)
	got, err := Expand(nil, in, 0x00)
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("output altered: % x", got)
	}
}

// TestExpandTruncated verifies Expand reports an error (no panic) when the
// kept-packet input is shorter than the bitmap requires.
func TestExpandTruncated(t *testing.T) {
	// Bitmap names position 1 as kept (bits: pos0 null, pos2 null) but
	// supply no kept packet at all.
	in := []byte{} // no kept packets
	npdBits := byte(1<<6) | byte(1<<4) | byte(1<<3)
	// total = ts(0) + nulls(3) = 3; positions 0,2,3 from the high end.
	// Position (6-1)=bit5 is the kept slot but input is empty.
	_, err := Expand(nil, in, npdBits)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("Expand err = %v, want %v", err, ErrTruncated)
	}
}

// TestExpandRejectsOverflow verifies Expand rejects a bitmap+input that would
// reconstruct more than 7 packets.
func TestExpandRejectsOverflow(t *testing.T) {
	// 5 kept 188-byte packets plus 3 null bits => 8 > 7.
	in := make([]byte, 5*SizeTS188)
	for i := 0; i < 5; i++ {
		copy(in[i*SizeTS188:], tsPacket(SizeTS188, uint16(0x100+i), byte(i)))
	}
	npdBits := byte(1<<6) | byte(1<<5) | byte(1<<4)
	_, err := Expand(nil, in, npdBits)
	if !errors.Is(err, ErrTooManyPackets) {
		t.Fatalf("Expand err = %v, want %v", err, ErrTooManyPackets)
	}
}

// TestNullPacketCanonicalForm pins the reconstructed null packet bytes to the
// exact libRIST form (src/mpegts.c:88-92).
func TestNullPacketCanonicalForm(t *testing.T) {
	got, err := Expand(nil, nil, byte(1<<6)) // one null, no kept
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(got) != SizeTS188 {
		t.Fatalf("len = %d, want %d", len(got), SizeTS188)
	}
	if got[0] != 0x47 || got[1] != 0x1F || got[2] != 0xFF || got[3] != 0x10 {
		t.Fatalf("null header = % x, want 47 1f ff 10", got[:4])
	}
	for i := tsHeaderSize; i < SizeTS188; i++ {
		if got[i] != 0xFF {
			t.Fatalf("null fill byte %d = %#x, want 0xff", i, got[i])
		}
	}
}

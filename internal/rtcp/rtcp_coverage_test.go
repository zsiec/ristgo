package rtcp

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestParseFramingErrors hunts the hard-error boundary of the framing
// layer: anything that cannot even be skipped safely.
func TestParseFramingErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"nil", nil, ErrShortPacket},
		{"1 byte", []byte{0x80}, ErrShortPacket},
		{"3 bytes", []byte{0x80, 0xC8, 0x00}, ErrShortPacket},
		{"version 0", []byte{0x00, 0xC8, 0x00, 0x00}, ErrBadVersion},
		{"version 1", []byte{0x40, 0xC8, 0x00, 0x00}, ErrBadVersion},
		{"version 3", []byte{0xC0, 0xC8, 0x00, 0x00}, ErrBadVersion},
		{"length one word past end", []byte{0x80, 0xC8, 0x00, 0x01, 0, 0, 0}, ErrShortPacket},
		{"length far past end", []byte{0x80, 0xC8, 0xFF, 0xFF, 0, 0, 0, 0}, ErrShortPacket},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, n, err := Parse(tt.in)
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse error = %v, want %v", err, tt.want)
			}
			if pkt != nil || n != 0 {
				t.Errorf("Parse = (%v, %d) alongside error, want (nil, 0)", pkt, n)
			}
		})
	}
}

// TestParseRawFallback hunts every "well-framed but not a RIST shape" path:
// each input must come back as Raw preserving the exact bytes.
func TestParseRawFallback(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		// Minimal 4-byte packet (length=0): no RIST shape is that small.
		{"minimal header only", []byte{0x80, 0xC8, 0x00, 0x00}},
		// TR-06-1 §5.2.2 fixes SR at RC=0, length=6.
		{"SR with RC=1", append([]byte{0x81, 0xC8, 0x00, 0x0C}, make([]byte, 48)...)},
		{"SR with wrong length", append([]byte{0x80, 0xC8, 0x00, 0x07}, make([]byte, 28)...)},
		// TR-06-1 §5.2.3/§5.2.4 allow only the RC=0/len=1 and RC=1/len=7 RRs.
		{"RR with RC=2", append([]byte{0x82, 0xC9, 0x00, 0x0D}, make([]byte, 52)...)},
		{"RR RC=0 with full length", append([]byte{0x80, 0xC9, 0x00, 0x07}, make([]byte, 28)...)},
		{"RR RC=1 with empty length", []byte{0x81, 0xC9, 0x00, 0x01, 0, 0, 0, 0}},
		// TR-06-1 §5.2.5 fixes SC=1 and one CNAME item.
		{"SDES with SC=2", append([]byte{0x82, 0xCA, 0x00, 0x04}, make([]byte, 16)...)},
		{"SDES with SC=0 (empty)", []byte{0x80, 0xCA, 0x00, 0x00}},
		{"SDES item not CNAME", []byte{0x81, 0xCA, 0x00, 0x02, 0, 0, 0, 7, 0x02, 0x01, 'x', 0x00}},
		{"SDES name overruns packet", []byte{0x81, 0xCA, 0x00, 0x02, 0, 0, 0, 7, 0x01, 0xFF, 'x', 0x00}},
		{"SDES nonzero after name", []byte{0x81, 0xCA, 0x00, 0x02, 0, 0, 0, 7, 0x01, 0x01, 'x', 0x09}},
		{"SDES no room for terminator", []byte{0x81, 0xCA, 0x00, 0x02, 0, 0, 0, 7, 0x01, 0x02, 'x', 'y'}},
		// APP packets need 12 bytes and the "RIST" name (RFC 3550 §6.7).
		{"APP too short for name", []byte{0x80, 0xCC, 0x00, 0x01, 0, 0, 0, 1}},
		{"APP foreign name", []byte{0x80, 0xCC, 0x00, 0x02, 0, 0, 0, 1, 'S', 'R', 'T', '!'}},
		{"APP unknown subtype 4", []byte{0x84, 0xCC, 0x00, 0x02, 0, 0, 0, 1, 'R', 'I', 'S', 'T'}},
		{"APP subtype 31", []byte{0x9F, 0xCC, 0x00, 0x02, 0, 0, 0, 1, 'R', 'I', 'S', 'T'}},
		// TR-06-2 §8.4 fixes EXTSEQ at length=3.
		{"extseq wrong length", append([]byte{0x81, 0xCC, 0x00, 0x04}, []byte{0, 0, 0, 1, 'R', 'I', 'S', 'T', 0, 2, 0, 0, 0, 0, 0, 0}...)},
		// TR-06-1 §5.2.6 echo needs length >= 5.
		{"echo too short", append([]byte{0x82, 0xCC, 0x00, 0x04}, []byte{0, 0, 0, 1, 'R', 'I', 'S', 'T', 0, 0, 0, 0, 0, 0, 0, 0}...)},
		// TR-06-1 §5.3.2.1 bitmask NACK is FMT=1 only.
		{"PT 205 with FMT=2", append([]byte{0x82, 0xCD, 0x00, 0x03}, make([]byte, 12)...)},
		{"PT 205 too short for SSRCs", []byte{0x81, 0xCD, 0x00, 0x01, 0, 0, 0, 1}},
		// Unknown payload types.
		{"PT 203 BYE", []byte{0x80, 0xCB, 0x00, 0x01, 0, 0, 0, 1}},
		{"PT 77 XR", append([]byte{0x80, 0x4D, 0x00, 0x03}, make([]byte, 12)...)},
		{"PT 0", []byte{0x80, 0x00, 0x00, 0x00}},
		// TR-06-1 §5.2 requires P=0 on every RIST packet; a set P bit
		// drops the packet to Raw even if the rest matches a shape.
		{"SR with P bit", func() []byte {
			b := SenderReport{SSRC: 1}.AppendTo(nil)
			b[0] |= 0x20
			return b
		}()},
		{"range NACK with P bit", func() []byte {
			b := RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{Start: 2}}}.AppendTo(nil)
			b[0] |= 0x20
			return b
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, n, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if n != len(tt.in) {
				t.Errorf("Parse consumed %d, want %d", n, len(tt.in))
			}
			raw, ok := pkt.(Raw)
			if !ok {
				t.Fatalf("Parse = %#v, want Raw", pkt)
			}
			if !bytes.Equal(raw, tt.in) {
				t.Errorf("Raw = %x, want %x", []byte(raw), tt.in)
			}
			// Raw is byte-stable by construction.
			if re := raw.AppendTo(nil); !bytes.Equal(re, tt.in) {
				t.Errorf("Raw re-encode = %x, want %x", re, tt.in)
			}
		})
	}
}

// TestParseConsumesOnlyDeclaredLength asserts Parse stops at the length
// field's boundary so compound iteration can continue.
func TestParseConsumesOnlyDeclaredLength(t *testing.T) {
	buf := EmptyReceiverReport{SSRC: 1}.AppendTo(nil)
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF) // unrelated trailing bytes

	pkt, n, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if n != emptyRRSize {
		t.Errorf("Parse consumed %d, want %d", n, emptyRRSize)
	}
	if want := (EmptyReceiverReport{SSRC: 1}); pkt != want {
		t.Errorf("Parse = %#v, want %#v", pkt, want)
	}
}

// TestSDESPaddingTable pins the §5.2.5 termination rule across name lengths:
// 1 to 4 zero bytes, total size a multiple of 4 (the libRIST formula
// ((10+n+1)+3)&~3).
func TestSDESPaddingTable(t *testing.T) {
	tests := []struct {
		nameLen  int
		wantSize int
		wantPad  int
	}{
		{0, 12, 2}, {1, 12, 1}, {2, 16, 4}, {3, 16, 3}, {4, 16, 2},
		{5, 16, 1}, {6, 20, 4}, {7, 20, 3}, {253, 264, 1}, {254, 268, 4}, {255, 268, 3},
	}
	for _, tt := range tests {
		name := string(bytes.Repeat([]byte{'n'}, tt.nameLen))
		p := SDES{SSRC: 1, CNAME: name}
		enc := p.AppendTo(nil)
		if len(enc) != tt.wantSize {
			t.Errorf("nameLen %d: size = %d, want %d", tt.nameLen, len(enc), tt.wantSize)
			continue
		}
		pad := len(enc) - sdesFixedSize - tt.nameLen
		if pad != tt.wantPad {
			t.Errorf("nameLen %d: pad = %d, want %d", tt.nameLen, pad, tt.wantPad)
		}
		if pad < 1 || pad > 4 {
			t.Errorf("nameLen %d: pad %d outside the 1..4 rule of §5.2.5", tt.nameLen, pad)
		}
		for _, b := range enc[sdesFixedSize+tt.nameLen:] {
			if b != 0 {
				t.Errorf("nameLen %d: nonzero terminator byte", tt.nameLen)
			}
		}
	}
}

// TestEncodeZeroAllocs gates the hot encode path: AppendTo into a buffer
// with spare capacity must not allocate, for every packet type.
func TestEncodeZeroAllocs(t *testing.T) {
	buf := make([]byte, 0, 2048)
	tests := []struct {
		name   string
		encode func()
	}{
		{"SenderReport", func() { SenderReport{SSRC: 1, NTP: 2}.AppendTo(buf[:0]) }},
		{"EmptyReceiverReport", func() { EmptyReceiverReport{SSRC: 1}.AppendTo(buf[:0]) }},
		{"ReceiverReport", func() { ReceiverReport{SenderSSRC: 1}.AppendTo(buf[:0]) }},
		{"SDES", func() { SDES{SSRC: 1, CNAME: "cname"}.AppendTo(buf[:0]) }},
		{"RangeNACK", func() {
			RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{1, 2}, {9, 0}}}.AppendTo(buf[:0])
		}},
		{"BitmaskNACK", func() {
			BitmaskNACK{MediaSSRC: 1, FCIs: []NackPair{{1, 2}, {99, 0}}}.AppendTo(buf[:0])
		}},
		{"EchoRequest", func() { EchoRequest{SSRC: 1, Timestamp: 2}.AppendTo(buf[:0]) }},
		{"EchoResponse", func() { EchoResponse{SSRC: 1, Timestamp: 2, ProcessingDelay: 3}.AppendTo(buf[:0]) }},
		{"ExtSeq", func() { ExtSeq{SSRC: 1, SeqHigh: 2}.AppendTo(buf[:0]) }},
		{"Raw", func() { Raw{0x80, 0xC8, 0x00, 0x00}.AppendTo(buf[:0]) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if allocs := testing.AllocsPerRun(100, tt.encode); allocs != 0 {
				t.Errorf("AppendTo allocated %.1f times per run, want 0", allocs)
			}
		})
	}
}

// TestPacketInterfaceSealed asserts (at compile time) that every packet
// type satisfies Packet by value, the way Parse returns them.
var _ = []Packet{
	SenderReport{}, EmptyReceiverReport{}, ReceiverReport{}, SDES{},
	RangeNACK{}, BitmaskNACK{}, EchoRequest{}, EchoResponse{}, ExtSeq{},
	Raw(nil),
}

// TestNackPairAppendSeqs covers BLP expansion order and wrap.
func TestNackPairAppendSeqs(t *testing.T) {
	tests := []struct {
		name string
		pair NackPair
		want []uint32
	}{
		{"PID only", NackPair{PID: 5}, []uint32{5}},
		{"all bits", NackPair{PID: 10, BLP: 0xFFFF}, seqSpan(10, 17)},
		{"high bit only", NackPair{PID: 7, BLP: 0x8000}, []uint32{7, 23}},
		{"wrap", NackPair{PID: 65535, BLP: 0x0003}, []uint32{65535, 0, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pair.AppendSeqs(nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AppendSeqs = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRangeNACKDecodeRecordCount asserts the record count follows the
// length field exactly.
func TestRangeNACKDecodeRecordCount(t *testing.T) {
	for _, n := range []int{0, 1, 2, 16, 17, 100} {
		ranges := make([]NackRange, n)
		for i := range ranges {
			ranges[i] = NackRange{Start: uint16(i * 10), Extra: uint16(i)}
		}
		pkt := RangeNACK{MediaSSRC: 1, Ranges: ranges}
		if n == 0 {
			pkt.Ranges = nil
		}
		dec, _, err := Parse(pkt.AppendTo(nil))
		if err != nil {
			t.Fatalf("n=%d: Parse: %v", n, err)
		}
		got, ok := dec.(RangeNACK)
		if !ok {
			t.Fatalf("n=%d: Parse = %T, want RangeNACK", n, dec)
		}
		if len(got.Ranges) != n {
			t.Errorf("n=%d: decoded %d records", n, len(got.Ranges))
		}
	}
}

// TestRangeNACKExpansionBounded verifies a crafted range NACK whose records
// each request a full 16-bit run cannot expand into a multi-million-entry slice
// on the sender (memory/CPU amplification guard, see maxNackExpand).
func TestRangeNACKExpansionBounded(t *testing.T) {
	// 370 records, each spanning the whole 16-bit ring (Extra=0xFFFF): a naive
	// expansion would be 370*65536 = ~24M entries.
	ranges := make([]NackRange, 370)
	for i := range ranges {
		ranges[i] = NackRange{Start: uint16(i), Extra: 0xFFFF}
	}
	pkt := RangeNACK{MediaSSRC: 1, Ranges: ranges}
	got := pkt.MissingSeqs()
	if len(got) > maxNackExpand {
		t.Fatalf("MissingSeqs expanded to %d, want <= %d (amplification guard)", len(got), maxNackExpand)
	}

	// A conforming small request is never truncated.
	small := RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{Start: 100, Extra: 4}, {Start: 200, Extra: 0}}}
	if seqs := small.MissingSeqs(); len(seqs) != 6 {
		t.Fatalf("small request expanded to %d seqs, want 6 (no truncation)", len(seqs))
	}
}

// TestBitmaskNACKExpansionBounded verifies the bitmask path is likewise bounded.
func TestBitmaskNACKExpansionBounded(t *testing.T) {
	fcis := make([]NackPair, 5000)
	for i := range fcis {
		fcis[i] = NackPair{PID: uint16(i), BLP: 0xFFFF}
	}
	pkt := BitmaskNACK{MediaSSRC: 1, FCIs: fcis}
	// Each FCI appends up to 17 seqs after the cap check, so the bound is
	// maxNackExpand rounded up by at most one FCI window.
	if got := pkt.MissingSeqs(); len(got) > maxNackExpand+17 {
		t.Fatalf("MissingSeqs expanded to %d, want <= %d", len(got), maxNackExpand+17)
	}
}

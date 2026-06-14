package adv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// TestSeqSplitJoin exercises SplitSeq/JoinSeq across the wrap boundaries.
func TestSeqSplitJoin(t *testing.T) {
	cases := []struct {
		seq       uint32
		low, high uint16
	}{
		{0, 0, 0},
		{1, 1, 0},
		{0xFFFF, 0xFFFF, 0},
		{0x10000, 0, 1},
		{0x1FFFF, 0xFFFF, 1},
		{0x12345678, 0x5678, 0x1234},
		{0xFFFFFFFE, 0xFFFE, 0xFFFF},
		{0xFFFFFFFF, 0xFFFF, 0xFFFF},
	}
	for _, c := range cases {
		low, high := SplitSeq(c.seq)
		if low != c.low || high != c.high {
			t.Errorf("SplitSeq(%#x) = (%#x, %#x), want (%#x, %#x)", c.seq, low, high, c.low, c.high)
		}
		if got := JoinSeq(high, low); got != c.seq {
			t.Errorf("JoinSeq(%#x, %#x) = %#x, want %#x", high, low, got, c.seq)
		}
	}
}

// TestFlowIDWire verifies the exact 4-byte Flow ID wire packing mirrors
// libRIST (test_flow_id_roundtrip: inner_hi=0xAB,
// inner_lo_sub=0xC5 -> inner=0xABC, sub=0x5).
func TestFlowIDWire(t *testing.T) {
	f := FlowID{Outer: 0x1234, Inner: 0xABC, Sub: 0x5}
	wire := f.appendTo(nil)
	want := []byte{0x12, 0x34, 0xAB, 0xC5}
	if !bytes.Equal(wire, want) {
		t.Fatalf("FlowID wire = %x, want %x", wire, want)
	}
	got := parseFlowID(wire)
	if got != f {
		t.Fatalf("parseFlowID = %+v, want %+v", got, f)
	}
}

// TestFlowIDVirtPortMapping mirrors
// test_flow_id_virt_port_mapping: the inner 12-bit field truncates source
// ports above 0xFFF.
func TestFlowIDVirtPortMapping(t *testing.T) {
	dstPort := uint16(5000)
	srcPort := uint16(1971)
	f := FlowID{Outer: dstPort, Inner: srcPort & 0xFFF, Sub: 0}
	wire := f.appendTo(nil)
	got := parseFlowID(wire)
	if got.Outer != dstPort {
		t.Errorf("Outer = %d, want %d", got.Outer, dstPort)
	}
	if got.Inner != srcPort&0xFFF {
		t.Errorf("Inner = %d, want %d", got.Inner, srcPort&0xFFF)
	}

	// Ephemeral source port: only low 12 bits survive.
	src2 := uint16(32768 + 7)
	f2 := FlowID{Outer: 1968, Inner: src2 & 0xFFF, Sub: 0}
	got2 := parseFlowID(f2.appendTo(nil))
	if got2.Outer != 1968 {
		t.Errorf("Outer = %d, want 1968", got2.Outer)
	}
	if got2.Inner != src2&0xFFF {
		t.Errorf("Inner = %#x, want %#x", got2.Inner, src2&0xFFF)
	}
}

// TestFlowIDInnerTruncation verifies Build drops Inner bits above 12 and Sub
// bits above 4 rather than corrupting adjacent fields.
func TestFlowIDInnerTruncation(t *testing.T) {
	f := FlowID{Outer: 0xFFFF, Inner: 0xFFFF, Sub: 0xFF}
	got := parseFlowID(f.appendTo(nil))
	if got.Inner != 0xFFF {
		t.Errorf("Inner = %#x, want 0xFFF", got.Inner)
	}
	if got.Sub != 0x0F {
		t.Errorf("Sub = %#x, want 0x0F", got.Sub)
	}
}

// TestPFDWire verifies the 4-bit type / 28-bit value packing
// (test_pfd_roundtrip).
func TestPFDWire(t *testing.T) {
	p := PFD{IDType: 1, IDValue: 0x0ABCDEF}
	wire := p.appendTo(nil)
	want := binary.BigEndian.AppendUint32(nil, uint32(1)<<28|0x0ABCDEF)
	if !bytes.Equal(wire, want) {
		t.Fatalf("PFD wire = %x, want %x", wire, want)
	}
	if got := parsePFD(wire); got != p {
		t.Fatalf("parsePFD = %+v, want %+v", got, p)
	}

	// Value truncation: only low 28 bits.
	big := PFD{IDType: 0xF, IDValue: 0xFFFFFFFF}
	got := parsePFD(big.appendTo(nil))
	if got.IDType != 0xF {
		t.Errorf("IDType = %#x, want 0xF", got.IDType)
	}
	if got.IDValue != 0x0FFFFFFF {
		t.Errorf("IDValue = %#x, want 0x0FFFFFFF", got.IDValue)
	}
}

// TestParseDynamicPayloadType verifies a dynamic RTP PT (>=96) is accepted and
// a PT below 96 (other than 127) is rejected.
func TestParseDynamicPayloadType(t *testing.T) {
	params := Params{Seq: 1, EncType: TypeDirect, FirstFrag: true, LastFrag: true}
	wire, err := Build(nil, params, []byte{0x01})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Patch PT to a dynamic value (96) — must still parse.
	wire[1] = 96
	if _, err := Parse(wire); err != nil {
		t.Errorf("dynamic PT 96 rejected: %v", err)
	}

	// PT 95 (< 96, not 127) — must be rejected.
	wire[1] = 95
	if _, err := Parse(wire); !errors.Is(err, ErrInvalidPayloadType) {
		t.Errorf("PT 95: err = %v, want ErrInvalidPayloadType", err)
	}

	// Marker bit (0x80) set with PT 127 must still parse (PT masks to 0x7F).
	wire[1] = 0x80 | PayloadType
	if _, err := Parse(wire); err != nil {
		t.Errorf("marker+PT127 rejected: %v", err)
	}
}

// TestParseRTPExtensionSkip verifies the parser skips an RFC 3550 RTP header
// extension when X=1, reaching the profile-defined extension
// after it.
func TestParseRTPExtensionSkip(t *testing.T) {
	// Build a packet by hand: RTP with X=1, a 1-word RTP header extension,
	// then the profile extension and a payload.
	var b []byte
	b = append(b, 0x90, PayloadType)             // V=2, X=1
	b = binary.BigEndian.AppendUint16(b, 0x0042) // rtp seq low
	b = binary.BigEndian.AppendUint32(b, 7)      // timestamp
	b = binary.BigEndian.AppendUint32(b, 0x10)   // ssrc
	// RFC 3550 RTP header extension: profile + length(words)=1 + 4-byte body.
	b = append(b, 0xBE, 0xDE, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD)
	// Profile-defined extension: seq_ext=0, flags=F|L, params=Type DIRECT.
	b = append(b, 0x00, 0x00, FlagF|FlagL, TypeDirect)
	b = append(b, 0x99) // payload

	p, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.RTPExtPresent {
		t.Error("RTPExtPresent not set")
	}
	if p.Seq != 0x42 {
		t.Errorf("Seq = %#x, want 0x42", p.Seq)
	}
	if p.EncType != TypeDirect {
		t.Errorf("EncType = %d, want %d", p.EncType, TypeDirect)
	}
	if !bytes.Equal(p.Payload, []byte{0x99}) {
		t.Errorf("Payload = %x, want 99", p.Payload)
	}
}

// TestParseTruncationBoundaries checks that a valid packet truncated by one
// byte at every optional-field boundary returns ErrShortBuffer and never
// panics.
func TestParseTruncationBoundaries(t *testing.T) {
	params := Params{
		Seq:         0x10000,
		EncType:     TypeDirect,
		PSKMode:     PSKAESCTRHMAC, // hash+nonce+iv
		LPCMode:     LPCFieldPresent,
		FirstFrag:   true,
		LastFrag:    true,
		FlowID:      &FlowID{Outer: 1, Inner: 2, Sub: 3},
		PSKHash:     bytes.Repeat([]byte{1}, 16),
		PSKNonce:    bytes.Repeat([]byte{2}, 4),
		PSKIV:       bytes.Repeat([]byte{3}, 4),
		Compression: []byte{4, 4, 4, 4},
		PFD:         &PFD{IDType: 1, IDValue: 9},
		HdrExt:      []byte{0x52, 0x49, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD},
	}
	wire, err := Build(nil, params, []byte{0xFF, 0xFF})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Truncate to every length below the full header; payload start is the
	// only safe truncation (payload may legitimately be empty).
	header := HeaderSize(params)
	for n := 0; n < header; n++ {
		if _, err := Parse(wire[:n]); err == nil {
			t.Errorf("Parse(wire[:%d]) succeeded, want error", n)
		}
	}
	// Truncating exactly at the header (empty payload) must succeed.
	if _, err := Parse(wire[:header]); err != nil {
		t.Errorf("Parse(wire[:header]) = %v, want success", err)
	}
}

// TestParseHdrExtTruncation verifies a RIST header extension whose announced
// length runs past the buffer is rejected.
func TestParseHdrExtTruncation(t *testing.T) {
	var b []byte
	b = append(b, 0x80, PayloadType)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, 0x00, 0x00, FlagF|FlagL|FlagH, TypeDirect)
	// Header extension announcing 4 words (16 bytes) but only 4 present.
	b = append(b, 0x52, 0x49, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD)
	if _, err := Parse(b); !errors.Is(err, ErrShortBuffer) {
		t.Errorf("err = %v, want ErrShortBuffer", err)
	}
}

// TestParseRTPExtTruncation verifies an RTP header extension whose announced
// length runs past the buffer is rejected.
func TestParseRTPExtTruncation(t *testing.T) {
	var b []byte
	b = append(b, 0x90, PayloadType) // X=1
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, 0)
	// RTP ext announcing 4 words but truncated.
	b = append(b, 0xBE, 0xDE, 0x00, 0x04, 0xAA)
	if _, err := Parse(b); !errors.Is(err, ErrShortBuffer) {
		t.Errorf("err = %v, want ErrShortBuffer", err)
	}
}

// TestBuildFieldRange verifies Build rejects out-of-range fields and
// mis-sized PSK slices.
func TestBuildFieldRange(t *testing.T) {
	base := Params{Seq: 1, EncType: TypeDirect, FirstFrag: true, LastFrag: true}

	cases := []struct {
		name   string
		mutate func(*Params)
	}{
		{"enc_type>15", func(p *Params) { p.EncType = 16 }},
		{"psk_mode>7", func(p *Params) { p.PSKMode = 8 }},
		{"lpc_mode>3", func(p *Params) { p.LPCMode = 4 }},
		{"hash wrong size", func(p *Params) { p.PSKMode = PSKAESGCM; p.PSKHash = []byte{1} }},
		{"nonce wrong size", func(p *Params) { p.PSKMode = PSKAESCTR; p.PSKNonce = []byte{1, 2, 3} }},
		{"iv wrong size", func(p *Params) { p.PSKMode = PSKAESCTR; p.PSKIV = []byte{1} }},
		{"comp wrong size", func(p *Params) { p.LPCMode = LPCFieldPresent; p.Compression = []byte{1, 2} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := base
			c.mutate(&p)
			if _, err := Build(nil, p, nil); !errors.Is(err, ErrFieldRange) {
				t.Errorf("err = %v, want ErrFieldRange", err)
			}
		})
	}
}

// TestBuildZeroFillsRequiredPSK verifies that a required-but-nil PSK field is
// zero-filled so the result round-trips (the documented deviation from
// libRIST, which would omit the field).
func TestBuildZeroFillsRequiredPSK(t *testing.T) {
	params := Params{
		Seq:       1,
		EncType:   TypeDirect,
		PSKMode:   PSKAESGCM, // requires hash+nonce+iv
		FirstFrag: true,
		LastFrag:  true,
		// No PSK bytes supplied.
	}
	wire, err := Build(nil, params, []byte{0xAB})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(wire) != HeaderSize(params)+1 {
		t.Fatalf("len = %d, want %d", len(wire), HeaderSize(params)+1)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(p.PSKHash, make([]byte, 16)) {
		t.Errorf("PSKHash = %x, want zeros", p.PSKHash)
	}
	if !bytes.Equal(p.PSKNonce, make([]byte, 4)) {
		t.Errorf("PSKNonce = %x, want zeros", p.PSKNonce)
	}
	if !bytes.Equal(p.PSKIV, make([]byte, 4)) {
		t.Errorf("PSKIV = %x, want zeros", p.PSKIV)
	}
	if !bytes.Equal(p.Payload, []byte{0xAB}) {
		t.Errorf("Payload = %x, want AB", p.Payload)
	}
}

// TestBuildAppendsToNonEmpty verifies Build appends to an existing slice
// without disturbing its prefix (append-style house contract).
func TestBuildAppendsToNonEmpty(t *testing.T) {
	prefix := []byte{0xDE, 0xAD}
	params := Params{Seq: 1, EncType: TypeDirect, FirstFrag: true, LastFrag: true}
	out, err := Build(prefix, params, []byte{0x01})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.Equal(out[:2], prefix) {
		t.Errorf("prefix disturbed: %x", out[:2])
	}
	p, err := Parse(out[2:])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(p.Payload, []byte{0x01}) {
		t.Errorf("Payload = %x", p.Payload)
	}
}

// TestParseEmptyPayload verifies a header-only packet (no payload) parses with
// an empty, non-nil-or-nil payload slice.
func TestParseEmptyPayload(t *testing.T) {
	params := Params{Seq: 1, EncType: TypeDirect, FirstFrag: true, LastFrag: true}
	wire, err := Build(nil, params, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(p.Payload))
	}
}

// TestParseCSRCSkip verifies the parser skips a CSRC list when CC>0,
// even though RIST never emits one.
func TestParseCSRCSkip(t *testing.T) {
	var b []byte
	b = append(b, 0x82, PayloadType) // V=2, CC=2
	b = binary.BigEndian.AppendUint16(b, 0x0007)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, 1, 1, 1, 1, 2, 2, 2, 2) // 2 CSRC entries
	b = append(b, 0x00, 0x00, FlagF|FlagL, TypeDirect)
	b = append(b, 0x77)

	p, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Seq != 0x0007 {
		t.Errorf("Seq = %#x, want 0x0007", p.Seq)
	}
	if !bytes.Equal(p.Payload, []byte{0x77}) {
		t.Errorf("Payload = %x, want 77", p.Payload)
	}
}

// TestParseCSRCTruncation verifies a CC count that runs past the buffer is
// rejected.
func TestParseCSRCTruncation(t *testing.T) {
	b := make([]byte, HeaderMin)
	b[0] = 0x8F // V=2, CC=15 — needs 60 CSRC bytes that aren't there
	b[1] = PayloadType
	if _, err := Parse(b); !errors.Is(err, ErrShortBuffer) {
		t.Errorf("err = %v, want ErrShortBuffer", err)
	}
}

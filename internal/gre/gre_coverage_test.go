package gre

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestHeaderChecksumSkip verifies the parser honors the C (checksum) bit by
// skipping four bytes even though libRIST never emits a checksum
// (rist-common.c:2945-2947). The encoder never sets the C bit, so this is a
// parse-only edge case constructed by hand.
func TestHeaderChecksumSkip(t *testing.T) {
	// flags1 = C(bit7)|S(bit4) = 0x90; flags2 = 0x08 (version 1).
	// Layout: base(4) + checksum(4) + seq(4).
	b := []byte{
		0x90, 0x08, 0x88, 0xB6, // flags + REDUCED
		0xDE, 0xAD, 0xBE, 0xEF, // checksum (ignored)
		0x01, 0x02, 0x03, 0x04, // seq
	}
	h, off, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if off != 12 {
		t.Fatalf("offset = %d, want 12", off)
	}
	if h.Seq != 0x01020304 {
		t.Fatalf("Seq = %#x, want 0x01020304", h.Seq)
	}
	if h.HasKey {
		t.Fatalf("HasKey = true, want false")
	}
}

// TestHeaderChecksumKeySeq verifies the full optional-field stack: checksum,
// key/nonce, and sequence (rist-common.c:2945-2960 accumulates payload_offset
// in that order).
func TestHeaderChecksumKeySeq(t *testing.T) {
	// flags1 = C(7)|K(5)|S(4) = 0xB0; flags2 = 0x08.
	b := []byte{
		0xB0, 0x08, 0x88, 0xB6,
		0x11, 0x22, 0x33, 0x44, // checksum (skipped)
		0xAA, 0xBB, 0xCC, 0xDD, // nonce
		0x01, 0x02, 0x03, 0x04, // seq
	}
	h, off, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if off != 16 {
		t.Fatalf("offset = %d, want 16", off)
	}
	if h.Nonce != [4]byte{0xAA, 0xBB, 0xCC, 0xDD} {
		t.Fatalf("Nonce = %x", h.Nonce)
	}
	if h.Seq != 0x01020304 {
		t.Fatalf("Seq = %#x", h.Seq)
	}
}

// TestHeaderNoSeqNoKey covers the all-options-clear base header (RFC 1 figure
// 1: no sequence, no key), which is a legal four-byte header.
func TestHeaderNoSeqNoKey(t *testing.T) {
	h := Header{Version: 1, ProtType: ProtoFull}
	wire, err := h.AppendTo(nil)
	if err != nil {
		t.Fatalf("AppendTo: %v", err)
	}
	want := []byte{0x00, 0x08, 0x08, 0x00}
	if !bytes.Equal(wire, want) {
		t.Fatalf("AppendTo = %x, want %x", wire, want)
	}
	got, off, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if off != BaseHeaderSize {
		t.Fatalf("offset = %d, want %d", off, BaseHeaderSize)
	}
	if !reflect.DeepEqual(got, h) {
		t.Fatalf("Parse = %+v, want %+v", got, h)
	}
}

// TestHeaderKeyOnlyNoSeq covers K set with S clear: a four-byte base header
// plus a 4-byte nonce, no sequence.
func TestHeaderKeyOnlyNoSeq(t *testing.T) {
	h := Header{
		Version: 1, HasKey: true,
		Nonce: [4]byte{0x01, 0x02, 0x03, 0x04}, ProtType: ProtoReduced,
	}
	wire, err := h.AppendTo(nil)
	if err != nil {
		t.Fatalf("AppendTo: %v", err)
	}
	// flags1 = K(bit5) = 0x20.
	want := []byte{0x20, 0x08, 0x88, 0xB6, 0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(wire, want) {
		t.Fatalf("AppendTo = %x, want %x", wire, want)
	}
	got, off, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if off != 8 || !reflect.DeepEqual(got, h) {
		t.Fatalf("round-trip off=%d got=%+v want=%+v", off, got, h)
	}
}

// TestHeaderVersionOverflow rejects a version that does not fit the 3-bit
// RVer field on encode.
func TestHeaderVersionOverflow(t *testing.T) {
	h := Header{Version: 8, HasSeq: true, ProtType: ProtoReduced}
	if _, err := h.AppendTo(nil); !errors.Is(err, ErrNonConformant) {
		t.Fatalf("AppendTo err = %v, want ErrNonConformant", err)
	}
}

// TestHeaderVersion7 confirms the maximum 3-bit version round-trips.
func TestHeaderVersion7(t *testing.T) {
	h := Header{Version: 7, HasSeq: true, ProtType: ProtoReduced, Seq: 1}
	wire, err := h.AppendTo(nil)
	if err != nil {
		t.Fatalf("AppendTo: %v", err)
	}
	// flags2 = (7 & 0x7) << 3 = 0x38.
	if wire[1] != 0x38 {
		t.Fatalf("flags2 = %#x, want 0x38", wire[1])
	}
	got, _, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Version != 7 {
		t.Fatalf("Version = %d, want 7", got.Version)
	}
}

// TestAppendToPreservesPrefix verifies AppendTo appends to (rather than
// overwrites) an existing buffer, like the rtp/rtcp codecs.
func TestAppendToPreservesPrefix(t *testing.T) {
	prefix := []byte{0xCA, 0xFE}
	h := Header{Version: 1, HasSeq: true, ProtType: ProtoReduced, Seq: 0x01020304}
	got, err := h.AppendTo(prefix)
	if err != nil {
		t.Fatalf("AppendTo: %v", err)
	}
	want := []byte{0xCA, 0xFE, 0x10, 0x08, 0x88, 0xB6, 0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendTo = %x, want %x", got, want)
	}
}

// TestAppendToErrorUnchanged verifies AppendTo returns the input slice
// unchanged on error.
func TestAppendToErrorUnchanged(t *testing.T) {
	prefix := []byte{0xAA, 0xBB}
	h := Header{Version: 99}
	got, err := h.AppendTo(prefix)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !bytes.Equal(got, prefix) {
		t.Fatalf("buffer mutated on error: %x", got)
	}
}

// TestParseVSFRejectNonRIST verifies a non-RIST VSF type is rejected
// (rist-common.c:3037-3040).
func TestParseVSFRejectNonRIST(t *testing.T) {
	b := []byte{0x00, 0x01, 0x00, 0x00} // type = 1
	if _, _, err := ParseVSFProto(b); !errors.Is(err, ErrUnsupportedVSFProto) {
		t.Fatalf("err = %v, want ErrUnsupportedVSFProto", err)
	}
}

func TestParseVSFShort(t *testing.T) {
	if _, _, err := ParseVSFProto([]byte{0x00, 0x00, 0x80}); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("err = %v, want ErrShortBuffer", err)
	}
}

func TestParseReducedShort(t *testing.T) {
	if _, _, err := ParseReduced([]byte{0x07, 0xB3, 0x07}); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("err = %v, want ErrShortBuffer", err)
	}
}

func TestParseKeepaliveShort(t *testing.T) {
	if _, err := ParseKeepalive([]byte{0, 1, 2, 3, 4, 5, 6}); !errors.Is(err, ErrBadKeepalive) {
		t.Fatalf("err = %v, want ErrBadKeepalive", err)
	}
}

// TestKeepaliveAllCaps round-trips a fully populated capability set, checking
// every bit maps to the libRIST position (gre.c:259-271).
func TestKeepaliveAllCaps(t *testing.T) {
	caps := Capabilities{
		N: true, L: true, E: true, P: true, A: true, B: true, R: true, X: true,
		F: true, J: true, V: true, T: true, D: true,
	}
	k := Keepalive{MAC: [6]byte{1, 2, 3, 4, 5, 6}, Caps: caps}
	wire := k.AppendTo(nil)
	// cap1 all bits set = 0xFF; cap2 bits 3..7 set = 0xF8.
	if wire[6] != 0xFF {
		t.Fatalf("cap1 = %#x, want 0xFF", wire[6])
	}
	if wire[7] != 0xF8 {
		t.Fatalf("cap2 = %#x, want 0xF8", wire[7])
	}
	parsed, err := ParseKeepalive(wire)
	if err != nil {
		t.Fatalf("ParseKeepalive: %v", err)
	}
	if parsed.Caps != caps {
		t.Fatalf("Caps = %+v, want %+v", parsed.Caps, caps)
	}
}

// TestKeepaliveAdvExtNoJSON covers an extended block with no trailing JSON
// (exactly KeepaliveSize+AdvExtSize bytes).
func TestKeepaliveAdvExtNoJSON(t *testing.T) {
	k := Keepalive{MAC: [6]byte{1, 2, 3, 4, 5, 6}, Caps: StandardCapabilities(), HasAdvExt: true, AdvExt: AdvExtCaps{I: true, G: true, C: true}}
	wire := k.AppendTo(nil)
	if len(wire) != KeepaliveSize+AdvExtSize {
		t.Fatalf("len = %d, want %d", len(wire), KeepaliveSize+AdvExtSize)
	}
	// I|G|C = 0x80|0x40|0x20 = 0xE0.
	if wire[8] != 0xE0 {
		t.Fatalf("ext = %#x, want 0xE0", wire[8])
	}
	parsed, err := ParseKeepalive(wire)
	if err != nil {
		t.Fatalf("ParseKeepalive: %v", err)
	}
	if !parsed.HasAdvExt || parsed.JSON != nil {
		t.Fatalf("HasAdvExt=%v JSON=%q", parsed.HasAdvExt, parsed.JSON)
	}
	if parsed.AdvExt != (AdvExtCaps{I: true, G: true, C: true}) {
		t.Fatalf("AdvExt = %+v", parsed.AdvExt)
	}
}

// TestKeepaliveJSONNoAdvExt covers fewer than AdvExtSize trailing bytes, which
// libRIST treats as JSON, not an extended block (gre.c:280-284).
func TestKeepaliveJSONNoAdvExt(t *testing.T) {
	// 3 trailing bytes -> JSON, since < AdvExtSize (4).
	k := Keepalive{MAC: [6]byte{1, 2, 3, 4, 5, 6}, Caps: StandardCapabilities(), JSON: []byte("xyz")}
	wire := k.AppendTo(nil)
	parsed, err := ParseKeepalive(wire)
	if err != nil {
		t.Fatalf("ParseKeepalive: %v", err)
	}
	if parsed.HasAdvExt {
		t.Fatalf("HasAdvExt = true, want false (only 3 trailing bytes)")
	}
	if !bytes.Equal(parsed.JSON, []byte("xyz")) {
		t.Fatalf("JSON = %q, want xyz", parsed.JSON)
	}
}

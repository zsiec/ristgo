package rtcp

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// fillLQM returns a 44-byte Link Quality Message extension filled with b, for
// the round-trip table's edge values.
func fillLQM(b byte) [LQMExtensionSize]byte {
	var a [LQMExtensionSize]byte
	for i := range a {
		a[i] = b
	}
	return a
}

// rampLQM returns a 44-byte LQM extension with a distinct value per byte, so a
// mis-sliced decode (off-by-one, wrong offset) is caught rather than masked by a
// uniform fill.
func rampLQM() [LQMExtensionSize]byte {
	var a [LQMExtensionSize]byte
	for i := range a {
		a[i] = byte(i + 1)
	}
	return a
}

// TestLinkQualityReportWireFormat pins the on-the-wire shape of the LQM RR
// (TR-06-4 Part 1 Figure 4): an empty Receiver Report header (PT=201, RC=0,
// length field 12 → 52 bytes) followed by the reporter SSRC and the 44-byte LQM
// extension. A non-adaptive peer must be able to read it as a well-formed RR.
func TestLinkQualityReportWireFormat(t *testing.T) {
	p := LinkQualityReport{SSRC: 0xABCD1234, LQM: rampLQM()}
	enc := p.AppendTo(nil)

	if len(enc) != lqmReportSize || lqmReportSize != 52 {
		t.Fatalf("encoded size %d, want %d (52)", len(enc), lqmReportSize)
	}
	if v := enc[0] >> 6; v != 2 {
		t.Errorf("version = %d, want 2", v)
	}
	if rc := enc[0] & 0x1F; rc != 0 {
		t.Errorf("reception count = %d, want 0 (empty RR)", rc)
	}
	if enc[1] != PTReceiverReport {
		t.Errorf("payload type = %d, want %d (RR)", enc[1], PTReceiverReport)
	}
	if l := binary.BigEndian.Uint16(enc[2:4]); l != 12 {
		t.Errorf("length field = %d, want 12 (52/4 - 1)", l)
	}
	if ssrc := binary.BigEndian.Uint32(enc[4:8]); ssrc != p.SSRC {
		t.Errorf("SSRC = %#x, want %#x", ssrc, p.SSRC)
	}
	if !bytes.Equal(enc[8:], p.LQM[:]) {
		t.Errorf("LQM extension bytes:\n got %x\nwant %x", enc[8:], p.LQM[:])
	}
}

// TestLinkQualityReportNotEmptyRR guards the count==0 discrimination: an empty RR
// (8 bytes) and an LQM RR (52 bytes) share PT=201/RC=0 and are told apart only by
// the length field, so each must decode back to its own type, never the other.
func TestLinkQualityReportNotEmptyRR(t *testing.T) {
	lqm := LinkQualityReport{SSRC: 7, LQM: rampLQM()}
	empty := EmptyReceiverReport{SSRC: 7}

	gotLQM, _, err := Parse(lqm.AppendTo(nil))
	if err != nil {
		t.Fatalf("Parse LQM: %v", err)
	}
	if _, ok := gotLQM.(LinkQualityReport); !ok {
		t.Fatalf("LQM decoded as %T, want LinkQualityReport", gotLQM)
	}

	gotEmpty, _, err := Parse(empty.AppendTo(nil))
	if err != nil {
		t.Fatalf("Parse empty RR: %v", err)
	}
	if _, ok := gotEmpty.(EmptyReceiverReport); !ok {
		t.Fatalf("empty RR decoded as %T, want EmptyReceiverReport", gotEmpty)
	}
}

// TestLinkQualityReportCompound verifies an LQM RR leads a valid compound paired
// with SDES (the exact datagram the Simple/Main source-adaptation path sends) and
// round-trips through BuildCompound/ParseCompound.
func TestLinkQualityReportCompound(t *testing.T) {
	want := []Packet{
		LinkQualityReport{SSRC: 0x42, LQM: rampLQM()},
		SDES{SSRC: 0x42, CNAME: "ristgo"},
	}
	buf, err := BuildCompound(nil, want)
	if err != nil {
		t.Fatalf("BuildCompound: %v", err)
	}
	got, err := ParseCompound(buf)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compound round-trip:\n got %#v\nwant %#v", got, want)
	}
}

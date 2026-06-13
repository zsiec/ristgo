package wire_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/zsiec/ristgo/internal/wire"
)

// Compile-time assertions that every variant satisfies Feedback, both by
// value and by pointer. If a variant loses its marker method, the package
// fails to compile here rather than at a distant type switch.
var (
	_ wire.Feedback = wire.NackRequest{}
	_ wire.Feedback = wire.RttEchoRequest{}
	_ wire.Feedback = wire.RttEchoResponse{}
	_ wire.Feedback = wire.SenderReport{}
	_ wire.Feedback = wire.Keepalive{}
	_ wire.Feedback = wire.ExtSeq{}

	_ wire.Feedback = (*wire.NackRequest)(nil)
	_ wire.Feedback = (*wire.RttEchoRequest)(nil)
	_ wire.Feedback = (*wire.RttEchoResponse)(nil)
	_ wire.Feedback = (*wire.SenderReport)(nil)
	_ wire.Feedback = (*wire.Keepalive)(nil)
	_ wire.Feedback = (*wire.ExtSeq)(nil)
)

// feedbackName exhaustively dispatches over the sealed variant set, the way
// a profile strategy encoder would. The default branch is unreachable as
// long as the set in this test matches the set in the package.
func feedbackName(f wire.Feedback) string {
	switch f.(type) {
	case wire.NackRequest:
		return "NackRequest"
	case wire.RttEchoRequest:
		return "RttEchoRequest"
	case wire.RttEchoResponse:
		return "RttEchoResponse"
	case wire.SenderReport:
		return "SenderReport"
	case wire.Keepalive:
		return "Keepalive"
	case wire.ExtSeq:
		return "ExtSeq"
	default:
		return "unknown"
	}
}

func TestFeedbackTypeSwitch(t *testing.T) {
	tests := []struct {
		name string
		f    wire.Feedback
	}{
		{"NackRequest", wire.NackRequest{SSRC: 0x1234, Missing: []uint32{1, 2, 3}}},
		{"RttEchoRequest", wire.RttEchoRequest{Timestamp: 42}},
		{"RttEchoResponse", wire.RttEchoResponse{Timestamp: 42, ProcessingDelay: 7}},
		{"SenderReport", wire.SenderReport{NTP: 99, RTPTime: 100}},
		{"Keepalive", wire.Keepalive{}},
		{"ExtSeq", wire.ExtSeq{SeqHigh: 0x1234}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := feedbackName(tt.f); got != tt.name {
				t.Errorf("feedbackName(%#v) = %q, want %q", tt.f, got, tt.name)
			}
		})
	}
}

func TestFeedbackNilInterface(t *testing.T) {
	var f wire.Feedback
	if f != nil {
		t.Errorf("zero-value Feedback = %v, want nil", f)
	}

	f = wire.Keepalive{}
	if f == nil {
		t.Error("Feedback holding Keepalive{} compares equal to nil")
	}
}

func TestMediaPacketZeroValue(t *testing.T) {
	var p wire.MediaPacket

	if p.Seq != 0 {
		t.Errorf("zero MediaPacket.Seq = %d, want 0", p.Seq)
	}
	if p.SourceTime != 0 {
		t.Errorf("zero MediaPacket.SourceTime = %d, want 0", p.SourceTime)
	}
	if p.SSRC != 0 {
		t.Errorf("zero MediaPacket.SSRC = %d, want 0", p.SSRC)
	}
	if p.Payload != nil {
		t.Errorf("zero MediaPacket.Payload = %v, want nil", p.Payload)
	}
	if len(p.Payload) != 0 {
		t.Errorf("len(zero MediaPacket.Payload) = %d, want 0", len(p.Payload))
	}
	if p.Retransmit {
		t.Error("zero MediaPacket.Retransmit = true, want false")
	}
	if p.PathID != 0 {
		t.Errorf("zero MediaPacket.PathID = %d, want 0", p.PathID)
	}
}

func TestMediaPacketFieldWidths(t *testing.T) {
	// Boundary values for every field width; catches an accidental
	// narrowing of a field type.
	tests := []struct {
		name string
		p    wire.MediaPacket
	}{
		{
			name: "all max",
			p: wire.MediaPacket{
				Seq:        math.MaxUint32,
				SourceTime: math.MaxUint64,
				SSRC:       math.MaxUint32,
				Payload:    []byte{0xFF},
				Retransmit: true,
				PathID:     math.MaxUint8,
			},
		},
		{
			name: "all min",
			p:    wire.MediaPacket{},
		},
		{
			name: "16-bit RTP seq widened past one rollover",
			p: wire.MediaPacket{
				// Rollover count 1, RTP seq 0x0005: the codec's widening
				// must survive the waist untouched.
				Seq:        1<<16 | 0x0005,
				SourceTime: 0x0000_0001_8000_0000, // 1.5s in NTP-64 units
				SSRC:       0xDEADBEEE,            // even base SSRC
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p // struct copy must preserve every field
			if got.Seq != tt.p.Seq || got.SourceTime != tt.p.SourceTime ||
				got.SSRC != tt.p.SSRC || got.Retransmit != tt.p.Retransmit ||
				got.PathID != tt.p.PathID {
				t.Errorf("copied MediaPacket = %+v, want %+v", got, tt.p)
			}
			if len(got.Payload) != len(tt.p.Payload) {
				t.Errorf("copied Payload length = %d, want %d", len(got.Payload), len(tt.p.Payload))
			}
		})
	}
}

func TestMediaPacketPayloadIsReference(t *testing.T) {
	// The doc contract says Payload is a reference, not a copy: a struct
	// copy of MediaPacket shares the payload backing array.
	backing := []byte{1, 2, 3}
	a := wire.MediaPacket{Payload: backing}
	b := a

	b.Payload[0] = 9
	if a.Payload[0] != 9 {
		t.Errorf("a.Payload[0] = %d after writing through copy, want 9 (shared backing array)", a.Payload[0])
	}
	if backing[0] != 9 {
		t.Errorf("backing[0] = %d after writing through copy, want 9", backing[0])
	}
}

func TestNackRequestZeroValue(t *testing.T) {
	var n wire.NackRequest

	if n.SSRC != 0 {
		t.Errorf("zero NackRequest.SSRC = %d, want 0", n.SSRC)
	}
	if n.Missing != nil {
		t.Errorf("zero NackRequest.Missing = %v, want nil", n.Missing)
	}
	if len(n.Missing) != 0 {
		t.Errorf("len(zero NackRequest.Missing) = %d, want 0", len(n.Missing))
	}

	// A zero value must be usable: ranging and appending work on nil.
	for range n.Missing {
		t.Error("ranging over nil Missing yielded an element")
	}
	n.Missing = append(n.Missing, 1, math.MaxUint32)
	if len(n.Missing) != 2 {
		t.Errorf("len(Missing) after append = %d, want 2", len(n.Missing))
	}
}

func TestFeedbackZeroValues(t *testing.T) {
	// Every variant's zero value must be a valid Feedback; flow and the
	// profile strategies construct these without constructors.
	tests := []struct {
		name string
		f    wire.Feedback
	}{
		{"NackRequest", wire.NackRequest{}},
		{"RttEchoRequest", wire.RttEchoRequest{}},
		{"RttEchoResponse", wire.RttEchoResponse{}},
		{"SenderReport", wire.SenderReport{}},
		{"Keepalive", wire.Keepalive{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.f == nil {
				t.Fatal("zero-value variant boxed as Feedback is nil")
			}
			if got := feedbackName(tt.f); got != tt.name {
				t.Errorf("feedbackName(zero %s) = %q, want %q", tt.name, got, tt.name)
			}
		})
	}
}

func TestFeedbackVariantFieldWidths(t *testing.T) {
	// Boundary values per field width on every variant; mirrors
	// TestMediaPacketFieldWidths for the control side of the waist.
	nack := wire.NackRequest{SSRC: math.MaxUint32, Missing: []uint32{0, math.MaxUint32}}
	if nack.SSRC != math.MaxUint32 {
		t.Errorf("NackRequest.SSRC = %#x, want %#x", nack.SSRC, uint32(math.MaxUint32))
	}
	if nack.Missing[1] != math.MaxUint32 {
		t.Errorf("NackRequest.Missing[1] = %#x, want %#x", nack.Missing[1], uint32(math.MaxUint32))
	}

	req := wire.RttEchoRequest{Timestamp: math.MaxUint64}
	if req.Timestamp != math.MaxUint64 {
		t.Errorf("RttEchoRequest.Timestamp = %#x, want %#x", req.Timestamp, uint64(math.MaxUint64))
	}

	resp := wire.RttEchoResponse{Timestamp: math.MaxUint64, ProcessingDelay: math.MaxUint32}
	if resp.Timestamp != math.MaxUint64 {
		t.Errorf("RttEchoResponse.Timestamp = %#x, want %#x", resp.Timestamp, uint64(math.MaxUint64))
	}
	if resp.ProcessingDelay != math.MaxUint32 {
		t.Errorf("RttEchoResponse.ProcessingDelay = %#x, want %#x", resp.ProcessingDelay, uint32(math.MaxUint32))
	}

	sr := wire.SenderReport{NTP: math.MaxUint64, RTPTime: math.MaxUint32}
	if sr.NTP != math.MaxUint64 {
		t.Errorf("SenderReport.NTP = %#x, want %#x", sr.NTP, uint64(math.MaxUint64))
	}
	if sr.RTPTime != math.MaxUint32 {
		t.Errorf("SenderReport.RTPTime = %#x, want %#x", sr.RTPTime, uint32(math.MaxUint32))
	}
}

func TestRttEchoResponseEchoesRequest(t *testing.T) {
	// The waist contract: a responder copies the request timestamp verbatim.
	tests := []struct {
		name string
		ts   uint64
	}{
		{"zero", 0},
		{"typical", 0x83AA7E80_40000000}, // NTP-64: some seconds + 0.25s
		{"max", math.MaxUint64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := wire.RttEchoRequest{Timestamp: tt.ts}
			resp := wire.RttEchoResponse{Timestamp: req.Timestamp, ProcessingDelay: 150}
			if resp.Timestamp != tt.ts {
				t.Errorf("RttEchoResponse.Timestamp = %#x, want %#x", resp.Timestamp, tt.ts)
			}
		})
	}
}

func TestFeedbackComparability(t *testing.T) {
	// All variants except NackRequest (which holds a slice) are comparable,
	// so they can key maps and be compared through the interface. This
	// pins down that adding a non-comparable field is a deliberate choice.
	tests := []struct {
		name string
		a, b wire.Feedback
		want bool
	}{
		{"equal keepalives", wire.Keepalive{}, wire.Keepalive{}, true},
		{"equal echo requests", wire.RttEchoRequest{Timestamp: 5}, wire.RttEchoRequest{Timestamp: 5}, true},
		{"different echo requests", wire.RttEchoRequest{Timestamp: 5}, wire.RttEchoRequest{Timestamp: 6}, false},
		{"equal echo responses", wire.RttEchoResponse{Timestamp: 1, ProcessingDelay: 2}, wire.RttEchoResponse{Timestamp: 1, ProcessingDelay: 2}, true},
		{"equal sender reports", wire.SenderReport{NTP: 1, RTPTime: 2}, wire.SenderReport{NTP: 1, RTPTime: 2}, true},
		{"different variants", wire.Keepalive{}, wire.RttEchoRequest{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a == tt.b; got != tt.want {
				t.Errorf("(%#v == %#v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ExampleFeedback shows how a profile strategy dispatches over the sealed
// Feedback set when encoding the flow core's control output onto the wire.
func ExampleFeedback() {
	outputs := []wire.Feedback{
		wire.NackRequest{SSRC: 0x4242, Missing: []uint32{17, 18, 19}},
		wire.RttEchoRequest{Timestamp: 0x83AA7E80_00000000},
		wire.Keepalive{},
	}

	for _, f := range outputs {
		switch f := f.(type) {
		case wire.NackRequest:
			fmt.Printf("encode NACK for SSRC %#x covering %d seqs\n", f.SSRC, len(f.Missing))
		case wire.RttEchoRequest:
			fmt.Printf("encode RTT echo request, ts=%#x\n", f.Timestamp)
		case wire.RttEchoResponse:
			fmt.Printf("encode RTT echo response, delay=%dus\n", f.ProcessingDelay)
		case wire.SenderReport:
			fmt.Printf("encode sender report, rtp=%d\n", f.RTPTime)
		case wire.Keepalive:
			fmt.Println("encode keepalive")
		}
	}
	// Output:
	// encode NACK for SSRC 0x4242 covering 3 seqs
	// encode RTT echo request, ts=0x83aa7e8000000000
	// encode keepalive
}

// ExampleMediaPacket shows the receive-side waist crossing: the codec has
// already widened the 16-bit RTP sequence and folded the retransmit
// SSRC-LSB toggle into the Retransmit flag, so the flow core works with
// clean 32-bit, profile-free data.
func ExampleMediaPacket() {
	pkt := wire.MediaPacket{
		Seq:        1<<16 | 12, // RTP seq 12, one rollover already counted
		SourceTime: 0x83AA7E80_80000000,
		SSRC:       0xDEADBEEE, // even base SSRC; LSB toggle already cleared
		Payload:    []byte{0x47, 0x00, 0x11},
		Retransmit: true, // codec saw SSRC|1 on the wire
		PathID:     1,    // second 2022-7 path
	}

	fmt.Printf("seq=%d retransmit=%v path=%d payload=%d bytes\n",
		pkt.Seq, pkt.Retransmit, pkt.PathID, len(pkt.Payload))
	// Output:
	// seq=65548 retransmit=true path=1 payload=3 bytes
}

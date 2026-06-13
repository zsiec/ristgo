package rtcp

import (
	"fmt"
	"reflect"
	"testing"
)

// widenWithExtSeq performs the session-side widening of TR-06-2 §8.4: the
// EXTSEQ packet's SeqHigh is prepended to every 16-bit sequence number
// expanded from the NACK packet that follows it.
func widenWithExtSeq(seqHigh uint16, narrow []uint32) []uint32 {
	wide := make([]uint32, len(narrow))
	for i, s := range narrow {
		wide[i] = uint32(seqHigh)<<16 | s
	}
	return wide
}

// TestExtSeqWideningScenario walks the full TR-06-2 §8.4 compound stack —
// RR, CNAME, EXTSEQ, NACK, EXTSEQ, NACK — through bytes and back, widening
// each NACK with its preceding EXTSEQ. This is the exact flow a Main
// profile session uses when losses straddle a 16-bit rollover: entries with
// different upper halves "shall be sent as different NACK request packets
// and shall be separated with a new EXTSEQ packet".
func TestExtSeqWideningScenario(t *testing.T) {
	const media = 0xDEADBEEE
	// 32-bit missing seqs straddling the 0x0002FFFF -> 0x00030000 rollover.
	wantWide := []uint32{0x0002FFFE, 0x0002FFFF, 0x00030000, 0x00030001, 0x00030010}

	// Sender side (receiver of media): split by upper half, encode each
	// group behind its own EXTSEQ.
	pkts := []Packet{
		EmptyReceiverReport{SSRC: media},
		SDES{SSRC: media, CNAME: "widen"},
	}
	groups := map[uint16][]uint32{}
	var order []uint16
	for _, s := range wantWide {
		hi := uint16(s >> 16)
		if _, seen := groups[hi]; !seen {
			order = append(order, hi)
		}
		groups[hi] = append(groups[hi], s&0xFFFF)
	}
	for _, hi := range order {
		pkts = append(pkts, ExtSeq{SSRC: media, SeqHigh: hi})
		for _, nack := range EncodeRangeNACK(0, media, groups[hi]) {
			pkts = append(pkts, nack)
		}
	}

	buf, err := BuildCompound(nil, pkts)
	if err != nil {
		t.Fatalf("BuildCompound: %v", err)
	}

	// Receiver side (media sender): parse, widen each NACK with the
	// EXTSEQ in force.
	parsed, err := ParseCompound(buf)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	var (
		gotWide []uint32
		seqHigh uint16
	)
	for _, p := range parsed {
		if e, ok := p.(ExtSeq); ok {
			seqHigh = e.SeqHigh
			continue
		}
		if narrow, ok := DecodeNACK(p); ok {
			gotWide = append(gotWide, widenWithExtSeq(seqHigh, narrow)...)
		}
	}
	if !reflect.DeepEqual(gotWide, wantWide) {
		t.Errorf("widened seqs = %v, want %v", gotWide, wantWide)
	}
}

// TestHugeNACKFraming exercises the framing edge near the 16-bit length
// field's ceiling: a range NACK with 65533 records is the largest packet
// the format can express (length = 2+n = 65535). Parsing must be exact and
// must not over-allocate beyond the actual input size.
func TestHugeNACKFraming(t *testing.T) {
	n := 65533
	ranges := make([]NackRange, n)
	for i := range ranges {
		ranges[i] = NackRange{Start: uint16(i), Extra: 0}
	}
	pkt := RangeNACK{MediaSSRC: 1, Ranges: ranges}
	enc := pkt.AppendTo(nil)
	if want := appFixedSize + 4*n; len(enc) != want {
		t.Fatalf("encoded size = %d, want %d", len(enc), want)
	}

	dec, consumed, err := Parse(enc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if consumed != len(enc) {
		t.Errorf("consumed %d, want %d", consumed, len(enc))
	}
	got, ok := dec.(RangeNACK)
	if !ok {
		t.Fatalf("Parse = %T, want RangeNACK", dec)
	}
	if len(got.Ranges) != n {
		t.Errorf("decoded %d records, want %d", len(got.Ranges), n)
	}

	// Truncating the buffer by one record must fail framing, not decode a
	// short record list.
	if _, _, err := Parse(enc[:len(enc)-4]); err == nil {
		t.Error("Parse of truncated huge NACK succeeded, want error")
	}
}

// TestEchoPaddingEchoContract pins the §5.2.6 request/response padding
// relationship: a responder copies the request's padding bytes into its
// response, and both sides agree byte-for-byte through the wire.
func TestEchoPaddingEchoContract(t *testing.T) {
	req := EchoRequest{
		SSRC:      7,
		Timestamp: 0xAABBCCDD_11223344,
		Padding:   []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04},
	}
	dec, _, err := Parse(req.AppendTo(nil))
	if err != nil {
		t.Fatalf("Parse(request): %v", err)
	}
	gotReq, ok := dec.(EchoRequest)
	if !ok {
		t.Fatalf("Parse = %T, want EchoRequest", dec)
	}

	// Responder behavior per TR-06-1 §5.2.6: echo timestamp verbatim, echo
	// the padding bytes, add its processing delay.
	resp := EchoResponse{
		SSRC:            gotReq.SSRC,
		Timestamp:       gotReq.Timestamp,
		ProcessingDelay: 250,
		Padding:         gotReq.Padding,
	}
	dec2, _, err := Parse(resp.AppendTo(nil))
	if err != nil {
		t.Fatalf("Parse(response): %v", err)
	}
	gotResp, ok := dec2.(EchoResponse)
	if !ok {
		t.Fatalf("Parse = %T, want EchoResponse", dec2)
	}
	if gotResp.Timestamp != req.Timestamp {
		t.Errorf("response timestamp = %#x, want %#x", gotResp.Timestamp, req.Timestamp)
	}
	if !reflect.DeepEqual(gotResp.Padding, req.Padding) {
		t.Errorf("response padding = %x, want %x", gotResp.Padding, req.Padding)
	}
	if gotResp.MarshalSize() < gotReq.MarshalSize() {
		t.Errorf("response size %d smaller than request %d; §5.2.6 requires at least as much padding", gotResp.MarshalSize(), gotReq.MarshalSize())
	}
}

// ExampleBuildCompound shows the receiver-side compound a session emits
// when it has retransmission requests pending: the TR-06-1 §5.2.1 receiver
// stack with the libRIST packet order (src/udp.c:736-815).
func ExampleBuildCompound() {
	const flowID = 0x0F0F0F02
	missing := []uint32{100, 101, 102, 250} // 16-bit seqs already narrowed

	pkts := []Packet{
		EmptyReceiverReport{SSRC: flowID},
		SDES{SSRC: flowID, CNAME: "ristgo"},
	}
	for _, nack := range EncodeRangeNACK(0, flowID, missing) {
		pkts = append(pkts, nack)
	}

	datagram, err := BuildCompound(nil, pkts)
	if err != nil {
		panic(err)
	}
	fmt.Printf("compound is %d bytes in %d packets\n", len(datagram), len(pkts))

	parsed, _ := ParseCompound(datagram)
	for _, p := range parsed {
		if seqs, ok := DecodeNACK(p); ok {
			fmt.Printf("peer asks for %v\n", seqs)
		}
	}
	// Output:
	// compound is 48 bytes in 3 packets
	// peer asks for [100 101 102 250]
}

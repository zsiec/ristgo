package rtcp

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestBuildCompoundOrdering(t *testing.T) {
	sr := SenderReport{SSRC: 1}
	rr := ReceiverReport{SenderSSRC: 1}
	emptyRR := EmptyReceiverReport{SSRC: 1}
	sdes := SDES{SSRC: 1, CNAME: "c"}
	rnack := RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{Start: 5}}}
	bnack := BitmaskNACK{MediaSSRC: 1, FCIs: []NackPair{{PID: 5}}}
	ext := ExtSeq{SSRC: 1, SeqHigh: 3}
	echoReq := EchoRequest{SSRC: 1, Timestamp: 9}
	echoResp := EchoResponse{SSRC: 1, Timestamp: 9}
	xr := Raw{0x80, 0x4D, 0x00, 0x01, 0, 0, 0, 1} // PT=77 XR-ish filler

	tests := []struct {
		name string
		pkts []Packet
		ok   bool
	}{
		// TR-06-1 §5.2.1 sender stack.
		{"SR+SDES", []Packet{sr, sdes}, true},
		{"SR+SDES+echo req", []Packet{sr, sdes, echoReq}, true},
		{"emptyRR+SDES+echo resp", []Packet{emptyRR, sdes, echoResp}, true},
		// TR-06-1 §5.2.1 receiver stack.
		{"RR+SDES", []Packet{rr, sdes}, true},
		{"RR+SDES+range NACK", []Packet{rr, sdes, rnack}, true},
		{"emptyRR+SDES+bitmask NACK+echo", []Packet{emptyRR, sdes, bnack, echoReq}, true},
		{"both NACK encodings", []Packet{emptyRR, sdes, rnack, bnack}, true},
		{"raw XR before echo, like libRIST udp.c:678-680", []Packet{rr, sdes, xr, echoReq}, true},
		{"multiple echoes at tail", []Packet{sr, sdes, echoReq, echoResp}, true},
		// TR-06-2 §8.4 stack: RR, CNAME, EXTSEQ, NACK, EXTSEQ, NACK.
		{"extseq+nack", []Packet{rr, sdes, ext, rnack}, true},
		{"extseq+nack twice", []Packet{rr, sdes, ext, rnack, ext, rnack}, true},
		{"extseq+bitmask nack", []Packet{rr, sdes, ext, bnack, echoReq}, true},

		// Violations.
		{"empty", nil, false},
		{"report alone", []Packet{sr}, false},
		{"SDES first", []Packet{sdes, sr}, false},
		{"NACK first", []Packet{rnack, sdes}, false},
		{"echo first", []Packet{echoReq, sdes}, false},
		{"missing SDES", []Packet{sr, echoReq}, false},
		{"second report in tail", []Packet{sr, sdes, emptyRR}, false},
		{"second SDES in tail", []Packet{sr, sdes, sdes}, false},
		{"NACK after echo", []Packet{emptyRR, sdes, echoReq, rnack}, false},
		{"raw after echo", []Packet{rr, sdes, echoReq, xr}, false},
		{"trailing extseq", []Packet{rr, sdes, ext}, false},
		{"extseq before echo", []Packet{rr, sdes, ext, echoReq}, false},
		{"extseq before extseq", []Packet{rr, sdes, ext, ext, rnack}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := []byte{0xEE}
			got, err := BuildCompound(prefix, tt.pkts)
			if tt.ok {
				if err != nil {
					t.Fatalf("BuildCompound: %v", err)
				}
				if !bytes.Equal(got[:1], prefix[:1]) {
					t.Error("BuildCompound clobbered the buffer prefix")
				}
				if len(got) != 1+CompoundMarshalSize(tt.pkts) {
					t.Errorf("built %d bytes, want %d", len(got)-1, CompoundMarshalSize(tt.pkts))
				}
				// Everything BuildCompound accepts must parse back to the
				// same packet sequence.
				back, err := ParseCompound(got[1:])
				if err != nil {
					t.Fatalf("ParseCompound: %v", err)
				}
				if !reflect.DeepEqual(back, tt.pkts) {
					t.Errorf("ParseCompound = %#v, want %#v", back, tt.pkts)
				}
			} else {
				if !errors.Is(err, ErrCompoundOrder) {
					t.Fatalf("BuildCompound error = %v, want ErrCompoundOrder", err)
				}
				if len(got) != len(prefix) {
					t.Errorf("buffer modified on error: %d bytes added", len(got)-len(prefix))
				}
			}
		})
	}
}

func TestParseCompoundErrors(t *testing.T) {
	valid := EmptyReceiverReport{SSRC: 1}.AppendTo(nil)

	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrEmptyCompound},
		{"short header", []byte{0x80, 0xC9}, ErrShortPacket},
		{"bad version first", []byte{0x40, 0xC9, 0x00, 0x01, 0, 0, 0, 1}, ErrBadVersion},
		{"length overruns buffer", []byte{0x80, 0xC9, 0x00, 0x02, 0, 0, 0, 1}, ErrShortPacket},
		{"trailing garbage after valid packet", append(append([]byte{}, valid...), 0x80, 0xC9), ErrShortPacket},
		{"bad version in second packet", append(append([]byte{}, valid...), 0x00, 0x00, 0x00, 0x00), ErrBadVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkts, err := ParseCompound(tt.in)
			if !errors.Is(err, tt.want) {
				t.Errorf("ParseCompound error = %v, want %v", err, tt.want)
			}
			if pkts != nil {
				t.Errorf("ParseCompound returned packets %v alongside error", pkts)
			}
		})
	}
}

// TestParseCompoundForeignPacket asserts a well-framed non-RIST packet in
// the middle of a compound becomes Raw without disturbing its neighbors.
func TestParseCompoundForeignPacket(t *testing.T) {
	foreign := []byte{0x80, 0x4D, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD} // PT=77
	var buf []byte
	buf = SenderReport{SSRC: 5}.AppendTo(buf)
	buf = append(buf, foreign...)
	buf = SDES{SSRC: 5, CNAME: "x"}.AppendTo(buf)

	pkts, err := ParseCompound(buf)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	want := []Packet{
		SenderReport{SSRC: 5},
		Raw(foreign),
		SDES{SSRC: 5, CNAME: "x"},
	}
	if !reflect.DeepEqual(pkts, want) {
		t.Errorf("ParseCompound = %#v, want %#v", pkts, want)
	}
}

// TestLibristCompoundShapes round-trips the four compound stacks libRIST
// actually transmits, so the builder provably accepts the interop peer's
// shapes:
//
//   - receiver periodic: full RR + SDES + echo request
//     (rist_receiver_periodic_rtcp, src/udp.c:671-682)
//   - receiver NACK: empty RR + SDES + NACK
//     (rist_receiver_send_nacks, src/udp.c:720-816)
//   - sender periodic: SR + SDES + echo request
//     (rist_sender_periodic_rtcp, src/udp.c:822-832)
//   - echo response: empty RR + SDES + echo response
//     (rist_respond_echoreq, src/udp.c:834-847)
func TestLibristCompoundShapes(t *testing.T) {
	const flowID = 0x1234ABCC
	shapes := []struct {
		name string
		pkts []Packet
	}{
		{"receiver periodic", []Packet{
			ReceiverReport{SenderSSRC: flowID, LSR: 0x11223344, DLSR: 0x00010000},
			SDES{SSRC: flowID, CNAME: "librist"},
			EchoRequest{SSRC: flowID, Timestamp: 0xE3D15C00_00000000},
		}},
		{"receiver nack", []Packet{
			EmptyReceiverReport{SSRC: flowID},
			SDES{SSRC: flowID, CNAME: "librist"},
			RangeNACK{MediaSSRC: flowID, Ranges: []NackRange{{Start: 88, Extra: 11}}},
		}},
		{"sender periodic", []Packet{
			SenderReport{SSRC: flowID, NTP: 0xE3D15C00_80000000, RTPTime: 0x00BC614E},
			SDES{SSRC: flowID, CNAME: "librist"},
			EchoRequest{SSRC: flowID, Timestamp: 0xE3D15C00_80000000},
		}},
		{"echo response", []Packet{
			EmptyReceiverReport{SSRC: flowID},
			SDES{SSRC: flowID, CNAME: "librist"},
			EchoResponse{SSRC: flowID, Timestamp: 0xE3D15C00_00000000, ProcessingDelay: 0},
		}},
	}

	for _, tt := range shapes {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := BuildCompound(nil, tt.pkts)
			if err != nil {
				t.Fatalf("BuildCompound: %v", err)
			}
			back, err := ParseCompound(buf)
			if err != nil {
				t.Fatalf("ParseCompound: %v", err)
			}
			if !reflect.DeepEqual(back, tt.pkts) {
				t.Errorf("round trip = %#v, want %#v", back, tt.pkts)
			}
		})
	}
}

// TestBuildCompoundZeroAlloc asserts the compound builder does not allocate
// when the destination buffer has capacity (the periodic-RTCP hot path).
func TestBuildCompoundZeroAlloc(t *testing.T) {
	pkts := []Packet{
		EmptyReceiverReport{SSRC: 1},
		SDES{SSRC: 1, CNAME: "cname"},
		RangeNACK{MediaSSRC: 1, Ranges: []NackRange{{Start: 5, Extra: 2}}},
	}
	buf := make([]byte, 0, 1500)
	allocs := testing.AllocsPerRun(100, func() {
		var err error
		_, err = BuildCompound(buf[:0], pkts)
		if err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("BuildCompound allocated %.1f times per run, want 0", allocs)
	}
}

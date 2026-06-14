package rtcp

import (
	"bytes"
	"reflect"
	"testing"
)

// goldenVectors carries hand-derived wire bytes for every RIST RTCP packet
// type. Each vector cites the spec section and/or libRIST source that fixes
// the layout; the bytes were written out by hand from those sources, not by
// running the encoder.
var goldenVectors = []struct {
	name string
	pkt  Packet
	want []byte
}{
	{
		// TR-06-1 §5.2.2: V=2,P=0,RC=0 -> 0x80; PT=200 (0xC8); length=6.
		// libRIST rist_rtcp_write_sr emits the same
		// header (RTCP_SR_FLAGS=0x80) then NTP msw/lsw, RTP ts,
		// packet count, octet count, all big-endian.
		name: "SenderReport",
		pkt: SenderReport{
			SSRC:        0x12345678,
			NTP:         0x83AA7E80_40000000, // 2070-01-01-ish secs + 0.25s
			RTPTime:     0x00015180,          // 86400 in the 90kHz clock
			PacketCount: 256,
			OctetCount:  8192,
		},
		want: []byte{
			0x80, 0xC8, 0x00, 0x06, // V=2 RC=0 | PT=200 | length=6
			0x12, 0x34, 0x56, 0x78, // SSRC
			0x83, 0xAA, 0x7E, 0x80, // NTP msw
			0x40, 0x00, 0x00, 0x00, // NTP lsw
			0x00, 0x01, 0x51, 0x80, // RTP timestamp
			0x00, 0x00, 0x01, 0x00, // sender packet count
			0x00, 0x00, 0x20, 0x00, // sender octet count
		},
	},
	{
		// TR-06-1 §5.2.3: V=2,P=0,RC=0 -> 0x80; PT=201 (0xC9); length=1;
		// header + SSRC only. libRIST rist_rtcp_write_empty_rr.
		name: "EmptyReceiverReport",
		pkt:  EmptyReceiverReport{SSRC: 0xDEADBEEF},
		want: []byte{
			0x80, 0xC9, 0x00, 0x01,
			0xDE, 0xAD, 0xBE, 0xEF,
		},
	},
	{
		// TR-06-1 §5.2.4: V=2,P=0,RC=1 -> 0x81 (RTCP_RR_FULL_FLAGS);
		// PT=201; length=7; one report block (struct rist_rtcp_rr_pkt).
		name: "ReceiverReport",
		pkt: ReceiverReport{
			SenderSSRC:     0x00000001,
			MediaSSRC:      0xCAFEBABE,
			FractionLost:   0x10,
			CumulativeLost: 0x000102,
			HighestSeq:     0x00010003, // one wrap, RTP seq 3
			Jitter:         32,
			LSR:            0x7E804000,
			DLSR:           0x00010000, // 1s in 1/65536 units
		},
		want: []byte{
			0x81, 0xC9, 0x00, 0x07, // V=2 RC=1 | PT=201 | length=7
			0x00, 0x00, 0x00, 0x01, // SSRC of packet sender
			0xCA, 0xFE, 0xBA, 0xBE, // received stream SSRC
			0x10, 0x00, 0x01, 0x02, // fraction lost | cumulative lost (24-bit)
			0x00, 0x01, 0x00, 0x03, // extended highest sequence
			0x00, 0x00, 0x00, 0x20, // interarrival jitter
			0x7E, 0x80, 0x40, 0x00, // LSR
			0x00, 0x01, 0x00, 0x00, // DLSR
		},
	},
	{
		// TR-06-1 §5.2.5: V=2,P=0,SC=1 -> 0x81 (RTCP_SDES_FLAGS);
		// PT=202 (0xCA); CNAME item type 1; 6-byte name
		// "ristgo"; packet size ((10+6+1)+3)&~3 = 20 so length=4 and four
		// zero terminator/pad bytes (libRIST rist_rtcp_write_sdes).
		name: "SDES",
		pkt:  SDES{SSRC: 0x11223344, CNAME: "ristgo"},
		want: []byte{
			0x81, 0xCA, 0x00, 0x04,
			0x11, 0x22, 0x33, 0x44,
			0x01, 0x06, 'r', 'i', // CNAME=1 | name length=6 | name...
			's', 't', 'g', 'o',
			0x00, 0x00, 0x00, 0x00, // chunk terminator + 32-bit padding
		},
	},
	{
		// TR-06-1 §5.2.5 note: between 1 and 4 zero bytes close the chunk.
		// A 5-byte name needs exactly one: ((10+5+1)+3)&~3 = 16, length=3.
		name: "SDES one-byte terminator",
		pkt:  SDES{SSRC: 0x11223344, CNAME: "abcde"},
		want: []byte{
			0x81, 0xCA, 0x00, 0x03,
			0x11, 0x22, 0x33, 0x44,
			0x01, 0x05, 'a', 'b',
			'c', 'd', 'e', 0x00,
		},
	},
	{
		// TR-06-1 §5.3.2.2: V=2,P=0,subtype=0 -> 0x80
		// (RTCP_NACK_RANGE_FLAGS); PT=204 (0xCC);
		// length=n+2 with n=2 records; media SSRC; name "RIST"
		// (0x52495354); records {start,extra} big-endian (libRIST
		// rist_receiver_send_nacks). extra=4 requests
		// 200..204 inclusive.
		name: "RangeNACK",
		pkt: RangeNACK{
			MediaSSRC: 0x0000CAFE,
			Ranges:    []NackRange{{Start: 100, Extra: 0}, {Start: 200, Extra: 4}},
		},
		want: []byte{
			0x80, 0xCC, 0x00, 0x04,
			0x00, 0x00, 0xCA, 0xFE,
			0x52, 0x49, 0x53, 0x54, // "RIST"
			0x00, 0x64, 0x00, 0x00, // start=100, extra=0
			0x00, 0xC8, 0x00, 0x04, // start=200, extra=4
		},
	},
	{
		// TR-06-1 §5.3.2.1 / RFC 4585 §6.2.1: V=2,P=0,FMT=1 -> 0x81
		// (RTCP_NACK_BITMASK_FLAGS); PT=205 (0xCD);
		// length=n+2 with n=1 FCI; sender SSRC (libRIST transmits 0)
		// then media SSRC; FCI {PID,BLP}. BLP=0x0005 sets
		// bits 0 and 2: packets 1001 and 1003 lost in addition to PID 1000.
		name: "BitmaskNACK",
		pkt: BitmaskNACK{
			SenderSSRC: 0,
			MediaSSRC:  0x0000CAFE,
			FCIs:       []NackPair{{PID: 1000, BLP: 0x0005}},
		},
		want: []byte{
			0x81, 0xCD, 0x00, 0x03,
			0x00, 0x00, 0x00, 0x00, // SSRC of packet sender
			0x00, 0x00, 0xCA, 0xFE, // SSRC of media source
			0x03, 0xE8, 0x00, 0x05, // PID=1000, BLP=0b101
		},
	},
	{
		// TR-06-1 §5.2.6: subtype=2 -> flags 0x82 (RTCP_ECHOEXT_REQ_FLAGS);
		// PT=204; length=5 (no padding); 64-bit
		// timestamp; processing delay zero-filled in requests (libRIST
		// rist_rtcp_write_echoreq).
		name: "EchoRequest",
		pkt:  EchoRequest{SSRC: 0x0000BEEF, Timestamp: 0xE3D15C00_80000000},
		want: []byte{
			0x82, 0xCC, 0x00, 0x05,
			0x00, 0x00, 0xBE, 0xEF,
			0x52, 0x49, 0x53, 0x54,
			0xE3, 0xD1, 0x5C, 0x00, // timestamp msw
			0x80, 0x00, 0x00, 0x00, // timestamp lsw
			0x00, 0x00, 0x00, 0x00, // processing delay: zero in requests
		},
	},
	{
		// TR-06-1 §5.2.6: with X=4 padding bytes the length is 5+X/4 = 6.
		name: "EchoRequest with padding",
		pkt: EchoRequest{
			SSRC:      0x0000BEEF,
			Timestamp: 0xE3D15C00_80000000,
			Padding:   []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		want: []byte{
			0x82, 0xCC, 0x00, 0x06,
			0x00, 0x00, 0xBE, 0xEF,
			0x52, 0x49, 0x53, 0x54,
			0xE3, 0xD1, 0x5C, 0x00,
			0x80, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0xAA, 0xBB, 0xCC, 0xDD,
		},
	},
	{
		// TR-06-1 §5.2.6: subtype=3 -> flags 0x83 (RTCP_ECHOEXT_RESP_FLAGS);
		// timestamp echoed verbatim; processing delay
		// 1500us (libRIST rist_rtcp_write_echoresp).
		name: "EchoResponse",
		pkt: EchoResponse{
			SSRC:            0x0000BEEF,
			Timestamp:       0xE3D15C00_80000000,
			ProcessingDelay: 1500,
		},
		want: []byte{
			0x83, 0xCC, 0x00, 0x05,
			0x00, 0x00, 0xBE, 0xEF,
			0x52, 0x49, 0x53, 0x54,
			0xE3, 0xD1, 0x5C, 0x00,
			0x80, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x05, 0xDC, // 1500us
		},
	},
	{
		// TR-06-2 §8.4 Figure 16: V=2,P=0,subtype=1 -> 0x81; PT=204;
		// length=3; media SSRC; "RIST"; sequence number extension; 16-bit
		// reserved=0. (libRIST does not implement this packet; TR-06-2 is
		// the authority.)
		name: "ExtSeq",
		pkt:  ExtSeq{SSRC: 0xCAFEBABE, SeqHigh: 0x0102},
		want: []byte{
			0x81, 0xCC, 0x00, 0x03,
			0xCA, 0xFE, 0xBA, 0xBE,
			0x52, 0x49, 0x53, 0x54,
			0x01, 0x02, 0x00, 0x00, // seq extension | reserved=0
		},
	},
}

// TestGoldenEncode asserts AppendTo produces exactly the hand-derived bytes.
func TestGoldenEncode(t *testing.T) {
	for _, tt := range goldenVectors {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkt.AppendTo(nil)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("AppendTo:\n got %x\nwant %x", got, tt.want)
			}
			if size := tt.pkt.MarshalSize(); size != len(tt.want) {
				t.Errorf("MarshalSize() = %d, want %d", size, len(tt.want))
			}
		})
	}
}

// TestGoldenDecode asserts Parse recovers exactly the source values from the
// hand-derived bytes.
func TestGoldenDecode(t *testing.T) {
	for _, tt := range goldenVectors {
		t.Run(tt.name, func(t *testing.T) {
			got, n, err := Parse(tt.want)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if n != len(tt.want) {
				t.Errorf("Parse consumed %d bytes, want %d", n, len(tt.want))
			}
			if !reflect.DeepEqual(got, tt.pkt) {
				t.Errorf("Parse = %#v, want %#v", got, tt.pkt)
			}
		})
	}
}

// TestGoldenAppendPreservesPrefix asserts AppendTo appends after existing
// content rather than overwriting it.
func TestGoldenAppendPreservesPrefix(t *testing.T) {
	prefix := []byte{0x01, 0x02, 0x03}
	for _, tt := range goldenVectors {
		t.Run(tt.name, func(t *testing.T) {
			buf := append([]byte(nil), prefix...)
			buf = tt.pkt.AppendTo(buf)
			if !bytes.Equal(buf[:len(prefix)], prefix) {
				t.Fatalf("AppendTo clobbered prefix: %x", buf[:len(prefix)])
			}
			if !bytes.Equal(buf[len(prefix):], tt.want) {
				t.Errorf("AppendTo after prefix:\n got %x\nwant %x", buf[len(prefix):], tt.want)
			}
		})
	}
}

// TestGoldenCompound mirrors the libRIST receiver NACK compound assembly
// (rist_receiver_send_nacks): empty RR, SDES, then the
// NACK — the TR-06-1 §5.2.1 receiver stack.
func TestGoldenCompound(t *testing.T) {
	pkts := []Packet{
		EmptyReceiverReport{SSRC: 0x0F0F0F02},
		SDES{SSRC: 0x0F0F0F02, CNAME: "go"},
		RangeNACK{MediaSSRC: 0x0F0F0F02, Ranges: []NackRange{{Start: 7, Extra: 2}}},
	}
	want := []byte{
		// Empty RR (TR-06-1 §5.2.3)
		0x80, 0xC9, 0x00, 0x01,
		0x0F, 0x0F, 0x0F, 0x02,
		// SDES "go": ((10+2+1)+3)&~3 = 16, length=3, 4 zero bytes
		// (TR-06-1 §5.2.5)
		0x81, 0xCA, 0x00, 0x03,
		0x0F, 0x0F, 0x0F, 0x02,
		0x01, 0x02, 'g', 'o',
		0x00, 0x00, 0x00, 0x00,
		// Range NACK for 7,8,9 (TR-06-1 §5.3.2.2)
		0x80, 0xCC, 0x00, 0x03,
		0x0F, 0x0F, 0x0F, 0x02,
		0x52, 0x49, 0x53, 0x54,
		0x00, 0x07, 0x00, 0x02,
	}

	got, err := BuildCompound(nil, pkts)
	if err != nil {
		t.Fatalf("BuildCompound: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("BuildCompound:\n got %x\nwant %x", got, want)
	}
	if size := CompoundMarshalSize(pkts); size != len(want) {
		t.Errorf("CompoundMarshalSize = %d, want %d", size, len(want))
	}

	back, err := ParseCompound(want)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	if !reflect.DeepEqual(back, pkts) {
		t.Errorf("ParseCompound = %#v, want %#v", back, pkts)
	}
}

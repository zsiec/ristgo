package rtcp

import (
	"bytes"
	"reflect"
	"testing"
)

// roundTripPackets holds canonical packet values (every type, plus edge
// values per field width) for which decode(encode(x)) == x must hold
// exactly, alongside byte-stable re-encoding.
var roundTripPackets = []struct {
	name string
	pkt  Packet
}{
	{"SR zero", SenderReport{}},
	{"SR max", SenderReport{SSRC: 0xFFFFFFFF, NTP: 0xFFFFFFFF_FFFFFFFF, RTPTime: 0xFFFFFFFF, PacketCount: 0xFFFFFFFF, OctetCount: 0xFFFFFFFF}},
	{"SR typical", SenderReport{SSRC: 1, NTP: 0x83AA7E80_00000000, RTPTime: 90000, PacketCount: 10, OctetCount: 13160}},

	{"empty RR zero", EmptyReceiverReport{}},
	{"empty RR max", EmptyReceiverReport{SSRC: 0xFFFFFFFF}},

	{"RR zero", ReceiverReport{}},
	{"RR max", ReceiverReport{
		SenderSSRC: 0xFFFFFFFF, MediaSSRC: 0xFFFFFFFF, FractionLost: 0xFF,
		CumulativeLost: 0x00FFFFFF, // 24-bit field at its max
		HighestSeq:     0xFFFFFFFF, Jitter: 0xFFFFFFFF, LSR: 0xFFFFFFFF, DLSR: 0xFFFFFFFF,
	}},

	{"SDES empty name", SDES{SSRC: 7}},
	{"SDES name len 1", SDES{SSRC: 7, CNAME: "a"}},
	{"SDES name len 2", SDES{SSRC: 7, CNAME: "ab"}},
	{"SDES name len 3", SDES{SSRC: 7, CNAME: "abc"}},
	{"SDES name len 4", SDES{SSRC: 7, CNAME: "abcd"}},
	{"SDES name len 255", SDES{SSRC: 7, CNAME: string(bytes.Repeat([]byte{'x'}, 255))}},
	{"SDES binary name", SDES{SSRC: 7, CNAME: "\x01\xFF\x00z"}},

	{"range NACK no records", RangeNACK{MediaSSRC: 9}},
	{"range NACK one", RangeNACK{MediaSSRC: 9, Ranges: []NackRange{{Start: 0xFFFF, Extra: 1}}}},
	{"range NACK whole ring", RangeNACK{MediaSSRC: 9, Ranges: []NackRange{{Start: 3, Extra: 0xFFFF}}}},
	{"range NACK many", RangeNACK{MediaSSRC: 9, Ranges: []NackRange{{1, 0}, {5, 2}, {100, 65534}, {0, 0}}}},

	{"bitmask NACK no FCIs", BitmaskNACK{SenderSSRC: 1, MediaSSRC: 2}},
	{"bitmask NACK one", BitmaskNACK{SenderSSRC: 1, MediaSSRC: 2, FCIs: []NackPair{{PID: 0xFFFF, BLP: 0xFFFF}}}},
	{"bitmask NACK many", BitmaskNACK{MediaSSRC: 2, FCIs: []NackPair{{0, 0}, {17, 0x8001}, {65535, 1}}}},

	{"echo request bare", EchoRequest{SSRC: 3, Timestamp: 0x0102030405060708}},
	{"echo request padded", EchoRequest{SSRC: 3, Timestamp: 1, Padding: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
	{"echo response bare", EchoResponse{SSRC: 3, Timestamp: 0xFFFFFFFF_FFFFFFFF, ProcessingDelay: 0xFFFFFFFF}},
	{"echo response padded", EchoResponse{SSRC: 3, Timestamp: 2, ProcessingDelay: 1, Padding: []byte{0xAA, 0xBB, 0xCC, 0xDD}}},

	{"extseq zero", ExtSeq{}},
	{"extseq max", ExtSeq{SSRC: 0xFFFFFFFF, SeqHigh: 0xFFFF}},
	{"extseq typical", ExtSeq{SSRC: 0xCAFEBABE, SeqHigh: 2}},

	{"LQM zero", LinkQualityReport{}},
	{"LQM max", LinkQualityReport{SSRC: 0xFFFFFFFF, LQM: fillLQM(0xFF)}},
	{"LQM typical", LinkQualityReport{SSRC: 0xABCD1234, LQM: rampLQM()}},
}

// TestRoundTrip asserts decode(encode(x)) == x and that re-encoding the
// decoded value reproduces the same bytes.
func TestRoundTrip(t *testing.T) {
	for _, tt := range roundTripPackets {
		t.Run(tt.name, func(t *testing.T) {
			enc := tt.pkt.AppendTo(nil)
			if len(enc) != tt.pkt.MarshalSize() {
				t.Errorf("len(AppendTo) = %d, MarshalSize = %d", len(enc), tt.pkt.MarshalSize())
			}
			if len(enc)%4 != 0 {
				t.Errorf("encoded size %d is not 32-bit aligned", len(enc))
			}

			dec, n, err := Parse(enc)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if n != len(enc) {
				t.Errorf("Parse consumed %d, want %d", n, len(enc))
			}
			if !reflect.DeepEqual(dec, tt.pkt) {
				t.Errorf("decode(encode(x)):\n got %#v\nwant %#v", dec, tt.pkt)
			}

			re := dec.AppendTo(nil)
			if !bytes.Equal(re, enc) {
				t.Errorf("re-encode not byte-stable:\n got %x\nwant %x", re, enc)
			}
		})
	}
}

// TestRoundTripCompound concatenates all round-trip packets behind a valid
// report+SDES prefix and asserts ParseCompound recovers every value.
func TestRoundTripCompound(t *testing.T) {
	var buf []byte
	var want []Packet
	want = append(want, EmptyReceiverReport{SSRC: 0x42}, SDES{SSRC: 0x42, CNAME: "rt"})
	for _, tt := range roundTripPackets {
		want = append(want, tt.pkt)
	}
	for _, p := range want {
		buf = p.AppendTo(buf)
	}

	got, err := ParseCompound(buf)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseCompound mismatch:\n got %#v\nwant %#v", got, want)
	}
}

// TestEncodeNormalization pins the cases where the encoder canonicalizes
// rather than reproducing the struct verbatim: these are the documented
// deviations from decode(encode(x)) == x.
func TestEncodeNormalization(t *testing.T) {
	t.Run("RR cumulative lost masked to 24 bits", func(t *testing.T) {
		in := ReceiverReport{CumulativeLost: 0xFF_ABCDEF}
		dec, _, err := Parse(in.AppendTo(nil))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if got := dec.(ReceiverReport).CumulativeLost; got != 0xABCDEF {
			t.Errorf("CumulativeLost = %#x, want %#x", got, 0xABCDEF)
		}
	})

	t.Run("SDES CNAME truncated to 255 bytes", func(t *testing.T) {
		in := SDES{CNAME: string(bytes.Repeat([]byte{'c'}, 300))}
		enc := in.AppendTo(nil)
		if len(enc) != in.MarshalSize() {
			t.Errorf("len(AppendTo) = %d, MarshalSize = %d", len(enc), in.MarshalSize())
		}
		dec, _, err := Parse(enc)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if got := len(dec.(SDES).CNAME); got != 255 {
			t.Errorf("decoded CNAME length = %d, want 255", got)
		}
	})

	t.Run("echo padding zero-filled to multiple of 4", func(t *testing.T) {
		in := EchoRequest{Timestamp: 5, Padding: []byte{0xAA, 0xBB}}
		enc := in.AppendTo(nil)
		if len(enc) != echoFixedSize+4 {
			t.Fatalf("encoded size = %d, want %d", len(enc), echoFixedSize+4)
		}
		if enc[26] != 0 || enc[27] != 0 {
			t.Errorf("padding fill bytes = %x, want zeros", enc[24:28])
		}
		dec, _, err := Parse(enc)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		want := EchoRequest{Timestamp: 5, Padding: []byte{0xAA, 0xBB, 0, 0}}
		if !reflect.DeepEqual(dec, want) {
			t.Errorf("decode = %#v, want %#v", dec, want)
		}
	})

	t.Run("echo request delay field ignored on decode", func(t *testing.T) {
		// Hand-build a request whose delay field is nonzero; TR-06-1
		// §5.2.6 says the receiver shall ignore it.
		raw := EchoRequest{SSRC: 1, Timestamp: 2}.AppendTo(nil)
		raw[20], raw[21], raw[22], raw[23] = 0xDE, 0xAD, 0xBE, 0xEF
		dec, _, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !reflect.DeepEqual(dec, EchoRequest{SSRC: 1, Timestamp: 2}) {
			t.Errorf("decode = %#v, want delay-free EchoRequest", dec)
		}
		// Second-generation encode is stable even though it differs from
		// the doctored input.
		re := dec.AppendTo(nil)
		dec2, _, err := Parse(re)
		if err != nil {
			t.Fatalf("Parse(re-encode): %v", err)
		}
		if !bytes.Equal(dec2.AppendTo(nil), re) {
			t.Error("re-encode of decoded request is not byte-stable")
		}
	})

	t.Run("extseq reserved field ignored on decode", func(t *testing.T) {
		raw := ExtSeq{SSRC: 1, SeqHigh: 2}.AppendTo(nil)
		raw[14], raw[15] = 0x12, 0x34 // doctor the reserved field
		dec, _, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !reflect.DeepEqual(dec, ExtSeq{SSRC: 1, SeqHigh: 2}) {
			t.Errorf("decode = %#v, want ExtSeq{SSRC:1, SeqHigh:2}", dec)
		}
	})

	t.Run("SDES with extra zero padding decodes and re-encodes canonically", func(t *testing.T) {
		// Hand-build an SDES whose chunk is closed by 8 zero bytes instead
		// of the canonical 4 (legal under RFC 3550 §6.5 null-item padding).
		raw := []byte{
			0x81, 0xCA, 0x00, 0x04, // length=4 -> 20 bytes (canonical is 16)
			0x00, 0x00, 0x00, 0x07,
			0x01, 0x02, 'g', 'o',
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		dec, n, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if n != 20 {
			t.Fatalf("consumed %d, want 20", n)
		}
		want := SDES{SSRC: 7, CNAME: "go"}
		if !reflect.DeepEqual(dec, want) {
			t.Fatalf("decode = %#v, want %#v", dec, want)
		}
		// Canonical re-encode is the 16-byte form.
		if got := dec.AppendTo(nil); len(got) != 16 {
			t.Errorf("re-encode size = %d, want canonical 16", len(got))
		}
	})
}

// TestDecodeDoesNotAliasInput asserts decoded packets survive the caller
// recycling its receive buffer.
func TestDecodeDoesNotAliasInput(t *testing.T) {
	src := []Packet{
		SDES{SSRC: 1, CNAME: "alias-check"},
		EchoRequest{SSRC: 2, Timestamp: 3, Padding: []byte{9, 9, 9, 9}},
		Raw{0x80, 0xC8, 0x00, 0x01, 0, 0, 0, 0}, // SR with bad length -> Raw
	}
	var buf []byte
	for _, p := range src {
		buf = p.AppendTo(buf)
	}

	pkts, err := ParseCompound(buf)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	snapshot := make([][]byte, len(pkts))
	for i, p := range pkts {
		snapshot[i] = p.AppendTo(nil)
	}

	for i := range buf {
		buf[i] = 0xFF // scribble over the receive buffer
	}

	for i, p := range pkts {
		if got := p.AppendTo(nil); !bytes.Equal(got, snapshot[i]) {
			t.Errorf("packet %d changed after input buffer was scribbled:\n got %x\nwant %x", i, got, snapshot[i])
		}
	}
}

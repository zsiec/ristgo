package rtp

import "testing"

// benchPacket is a representative RIST media packet: NPD-shaped extension
// plus seven 188-byte MPEG-TS cells.
var benchPacket = Packet{
	Header: Header{
		Version:          2,
		Extension:        true,
		PayloadType:      PayloadTypeMPEGTS,
		SequenceNumber:   0x1234,
		Timestamp:        0xDEADBEEF,
		SSRC:             0x4D4F4F56,
		ExtensionProfile: ExtensionProfileRIST,
		ExtensionPayload: []byte{0x80, 0x00, 0xAB, 0xCD},
	},
	Payload: make([]byte, 7*188),
}

// TestEncodeZeroAlloc is the allocation gate for the hot encode path:
// MarshalTo into a caller buffer, and AppendTo into a buffer with capacity,
// must not allocate.
func TestEncodeZeroAlloc(t *testing.T) {
	buf := make([]byte, benchPacket.MarshalSize())

	if allocs := testing.AllocsPerRun(100, func() {
		if _, err := benchPacket.MarshalTo(buf); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Errorf("Packet.MarshalTo allocates %v times per op, want 0", allocs)
	}

	if allocs := testing.AllocsPerRun(100, func() {
		if _, err := benchPacket.Header.MarshalTo(buf); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Errorf("Header.MarshalTo allocates %v times per op, want 0", allocs)
	}

	appendBuf := make([]byte, 0, benchPacket.MarshalSize())
	if allocs := testing.AllocsPerRun(100, func() {
		out, err := benchPacket.AppendTo(appendBuf)
		if err != nil {
			t.Fatal(err)
		}
		_ = out
	}); allocs != 0 {
		t.Errorf("Packet.AppendTo with capacity allocates %v times per op, want 0", allocs)
	}
}

// TestDecodeZeroAlloc is the allocation gate for the hot decode path: a
// reused Packet decoding a CSRC-free packet must not allocate (Payload and
// ExtensionPayload alias the input).
func TestDecodeZeroAlloc(t *testing.T) {
	wire := make([]byte, benchPacket.MarshalSize())
	if _, err := benchPacket.MarshalTo(wire); err != nil {
		t.Fatal(err)
	}

	var p Packet
	if allocs := testing.AllocsPerRun(100, func() {
		if err := p.Unmarshal(wire); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Errorf("Packet.Unmarshal (reused) allocates %v times per op, want 0", allocs)
	}
}

func BenchmarkHeaderMarshalTo(b *testing.B) {
	buf := make([]byte, benchPacket.Header.MarshalSize())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := benchPacket.Header.MarshalTo(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPacketMarshalTo(b *testing.B) {
	buf := make([]byte, benchPacket.MarshalSize())
	b.SetBytes(int64(benchPacket.MarshalSize()))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := benchPacket.MarshalTo(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPacketAppendTo(b *testing.B) {
	buf := make([]byte, 0, benchPacket.MarshalSize())
	b.SetBytes(int64(benchPacket.MarshalSize()))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := benchPacket.AppendTo(buf)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

func BenchmarkPacketUnmarshal(b *testing.B) {
	wire := make([]byte, benchPacket.MarshalSize())
	if _, err := benchPacket.MarshalTo(wire); err != nil {
		b.Fatal(err)
	}
	var p Packet
	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := p.Unmarshal(wire); err != nil {
			b.Fatal(err)
		}
	}
}

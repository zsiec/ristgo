package gre

import "testing"

// Encode benchmarks: AppendTo into a reused buffer is the per-packet GRE
// framing hot path; the -benchmem numbers must show 0 allocs/op (also gated
// by TestEncodeZeroAllocs).

func BenchmarkHeaderAppendTo(b *testing.B) {
	h := Header{Version: 1, HasSeq: true, ProtType: ProtoReduced, Seq: 0x01020304}
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = h.AppendTo(buf[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = buf
}

func BenchmarkHeaderParse(b *testing.B) {
	wire := []byte{0x30, 0x08, 0x88, 0xB6, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Parse(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReducedAppendTo(b *testing.B) {
	r := ReducedHeader{SrcPort: DefaultVirtSrcPort, DstPort: DefaultVirtDstPort}
	buf := make([]byte, 0, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = r.AppendTo(buf[:0])
	}
	_ = buf
}

// TestEncodeZeroAllocs gates the hot-path encoders at 0 allocs/op when writing
// into a pre-sized, reused buffer.
func TestEncodeZeroAllocs(t *testing.T) {
	h := Header{Version: 1, HasKey: true, HasSeq: true, Nonce: [4]byte{1, 2, 3, 4}, Seq: 5, ProtType: ProtoReduced}
	buf := make([]byte, 0, 64)
	if n := testing.AllocsPerRun(100, func() {
		buf, _ = h.AppendTo(buf[:0])
	}); n != 0 {
		t.Fatalf("Header.AppendTo: %v allocs/op, want 0", n)
	}

	r := ReducedHeader{SrcPort: DefaultVirtSrcPort, DstPort: DefaultVirtDstPort}
	rbuf := make([]byte, 0, 16)
	if n := testing.AllocsPerRun(100, func() {
		rbuf = r.AppendTo(rbuf[:0])
	}); n != 0 {
		t.Fatalf("ReducedHeader.AppendTo: %v allocs/op, want 0", n)
	}
}

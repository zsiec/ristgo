package lpc

import (
	"bytes"
	"testing"
)

// benchTSPayload builds an MPEG-TS-shaped payload (the realistic Advanced-Profile
// LPC input): seven 188-byte TS packets with sync bytes and semi-structured
// bodies, the typical RIST media payload size.
func benchTSPayload() []byte {
	out := make([]byte, 0, 7*188)
	for p := 0; p < 7; p++ {
		pkt := make([]byte, 188)
		pkt[0] = 0x47
		pkt[1] = byte(0x40 | (p & 0x1f))
		pkt[3] = 0x10
		for i := 4; i < 188; i++ {
			pkt[i] = byte((i*3 + p) & 0xff)
		}
		out = append(out, pkt...)
	}
	return out
}

func BenchmarkCompressTS(b *testing.B) {
	src := benchTSPayload()
	dst := make([]byte, 0, CompressBound(len(src)))
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		dst, err = Compress(dst[:0], src)
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = dst
}

func BenchmarkCompressHighlyCompressible(b *testing.B) {
	src := bytes.Repeat([]byte("RISTRISTRIST"), 110) // ~1320 bytes, very repetitive
	dst := make([]byte, 0, CompressBound(len(src)))
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		dst, err = Compress(dst[:0], src)
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = dst
}

func BenchmarkDecompressTS(b *testing.B) {
	src := benchTSPayload()
	block, _ := Compress(nil, src)
	dst := make([]byte, 0, len(src))
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		dst, err = Decompress(dst[:0], block, len(src))
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = dst
}

// TestCompressReusedBufferZeroAllocs gates Compress at 0 allocs/op when writing
// into a pre-sized, reused buffer: the match-finder hash table is a stack-local
// array (16 KB) and the dst path reuses caller capacity, so the hot path makes
// no heap allocations.
func TestCompressReusedBufferZeroAllocs(t *testing.T) {
	src := benchTSPayload()
	dst := make([]byte, 0, CompressBound(len(src)))
	if n := testing.AllocsPerRun(100, func() {
		dst, _ = Compress(dst[:0], src)
	}); n != 0 {
		t.Fatalf("Compress into reused buffer: %v allocs/op, want 0", n)
	}
}

// TestDecompressReusedBufferZeroAllocs gates Decompress at 0 allocs/op when
// decoding into a pre-grown, reused buffer.
func TestDecompressReusedBufferZeroAllocs(t *testing.T) {
	src := benchTSPayload()
	block, _ := Compress(nil, src)
	dst := make([]byte, 0, len(src))
	if n := testing.AllocsPerRun(100, func() {
		dst, _ = Decompress(dst[:0], block, len(src))
	}); n != 0 {
		t.Fatalf("Decompress into reused buffer: %v allocs/op, want 0", n)
	}
}

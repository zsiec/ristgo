package lpc

import (
	"bytes"
	"testing"
)

// fuzzDecompressSeeds returns block-shaped seeds for the Decompress corpus:
// the foreign KAT blocks, our own output, and deliberately malformed bytes.
func fuzzDecompressSeeds() [][]byte {
	seeds := [][]byte{
		nil,
		{},
		{0x00},                         // empty literals-only sequence
		{0x40, 1, 2, 3, 4},             // 4 literals, terminating
		{0x50, 1, 2, 3, 4},             // claims 5 literals, only 4 present (truncated)
		{0x1f, 0x47, 0x01, 0x00},       // literal+match but offset only partial / overlong match
		{0x0f, 0x01, 0x00, 0xff},       // match-length continuation that never terminates
		{0xf0},                         // literal continuation that never terminates
		{0x40, 1, 2, 3, 4, 0x00, 0x00}, // offset 0 after a literal run (invalid)
	}
	seeds = append(seeds, mustHexBytes("6e68656c6c6f2006005c776f726c640600506c64212121"))
	seeds = append(seeds, mustHexBytes("1f470100ff78504747474747"))
	c, _ := Compress(nil, bytes.Repeat([]byte("abcdefgh"), 100))
	seeds = append(seeds, c)
	return seeds
}

// mustHexBytes decodes a hex literal used only in fuzz seeds; it ignores
// errors (the literals here are known-good) to keep the seed list terse.
func mustHexBytes(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			}
		}
		out[i] = b
	}
	return out
}

// FuzzDecompress asserts Decompress never panics and never writes past its
// bound on arbitrary input bytes with an arbitrary (here, uint16-derived)
// maxOut. When decode succeeds, the output length must respect the bound; when
// it fails, dst must be returned unextended.
func FuzzDecompress(f *testing.F) {
	for _, s := range fuzzDecompressSeeds() {
		f.Add(s, uint16(2048))
		f.Add(s, uint16(0))
	}
	f.Fuzz(func(t *testing.T, data []byte, maxOut16 uint16) {
		maxOut := int(maxOut16)
		// Pass a non-empty dst to confirm the dst prefix is preserved on both
		// success and error.
		prefix := []byte{0xDE, 0xAD}
		dst := append([]byte(nil), prefix...)
		out, err := Decompress(dst, data, maxOut)
		if !bytes.HasPrefix(out, prefix) {
			t.Fatalf("dst prefix not preserved: % x", out)
		}
		if err != nil {
			// On error the returned slice must be exactly the original dst
			// (no partial output leaked to the caller).
			if len(out) != len(prefix) {
				t.Fatalf("error path extended dst by %d bytes", len(out)-len(prefix))
			}
			return
		}
		produced := len(out) - len(prefix)
		if produced < 0 || produced > maxOut {
			t.Fatalf("produced %d bytes, bound was %d", produced, maxOut)
		}
	})
}

// FuzzCompressRoundTrip asserts that every input round-trips: Decompress of
// Compress reproduces the input exactly, neither call panics, and the block
// never exceeds CompressBound. A negative-free maxOut equal to len(src) is the
// tightest valid bound and must always suffice.
func FuzzCompressRoundTrip(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		{0x00},
		[]byte("A"),
		[]byte("the quick brown fox the quick brown fox the quick brown fox"),
		bytes.Repeat([]byte{0x47}, 400),
		bytes.Repeat([]byte{0xab, 0xcd}, 300),
		bytes.Repeat([]byte("MPEGTS"), 200),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		comp, err := Compress(nil, src)
		if err != nil {
			t.Fatalf("Compress returned error: %v", err)
		}
		if len(comp) > CompressBound(len(src)) {
			t.Fatalf("block %d bytes > CompressBound %d", len(comp), CompressBound(len(src)))
		}
		got, err := Decompress(nil, comp, len(src))
		if err != nil {
			t.Fatalf("Decompress own block: %v", err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(src))
		}
		// A tighter bound (len(src)-1) must reject (unless src is empty).
		if len(src) > 0 {
			if _, err := Decompress(nil, comp, len(src)-1); err == nil {
				t.Fatalf("decode succeeded under too-tight bound %d", len(src)-1)
			}
		}
	})
}

package lpc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand"
	"testing"
)

// mustHex decodes a hex string in a test, failing on any error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// foreignKATs holds LZ4 blocks produced by an independent LZ4 implementation —
// libRIST's vendored lz4 (Yann Collet's reference lz4) via
// LZ4_compress_default, the exact call libRIST's Advanced-Profile send path
// uses. Decompressing each block must yield the recorded plaintext,
// proving this package decodes foreign blocks (and therefore libRIST's), not
// only its own output. These bytes were captured by compiling a small driver
// against libRIST's vendored lz4.
var foreignKATs = []struct {
	name  string
	block string // raw LZ4 block, hex
	plain string // expected plaintext, hex
}{
	{
		// "hello hello hello hello world world world world!!!": exercises a
		// literal run, two back-references (offset 6), and a final
		// literals-only sequence.
		name:  "repetitive",
		block: "6e68656c6c6f2006005c776f726c640600506c64212121",
		plain: "68656c6c6f2068656c6c6f2068656c6c6f2068656c6c6f20776f726c6420776f726c6420776f726c6420776f726c64212121",
	},
	{
		// "ABCD": four incompressible bytes — a single literals-only sequence
		// (token 0x40 then the four bytes). Confirms the terminating-sequence
		// path of a foreign encoder.
		name:  "literals_only",
		block: "4041424344",
		plain: "41424344",
	},
	{
		// 400 bytes of 0x47: exercises the extended match-length continuation
		// (token low nibble 15, then 0xFF 0x78), an offset-1 overlapping
		// run, and trailing literals.
		name:  "long_run_0x47",
		block: "1f470100ff78504747474747",
		plain: "47474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747",
	},
}

// TestDecompressForeignKAT decodes blocks produced by libRIST's reference LZ4
// and asserts the recovered plaintext matches.
func TestDecompressForeignKAT(t *testing.T) {
	for _, kat := range foreignKATs {
		t.Run(kat.name, func(t *testing.T) {
			block := mustHex(t, kat.block)
			want := mustHex(t, kat.plain)
			got, err := Decompress(nil, block, len(want))
			if err != nil {
				t.Fatalf("Decompress: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("plaintext mismatch\n got %d bytes\nwant %d bytes", len(got), len(want))
			}
			// And our own Compress must produce something libRIST-style
			// decodable: re-compressing and decoding round-trips.
			rc, _ := Compress(nil, want)
			back, err := Decompress(nil, rc, len(want))
			if err != nil {
				t.Fatalf("re-Decompress own block: %v", err)
			}
			if !bytes.Equal(back, want) {
				t.Fatalf("own round-trip mismatch for %s", kat.name)
			}
		})
	}
}

// TestDecompressForeignDivergentBlock is the load-bearing foreign-block test:
// the foreignKATs above use libRIST's reference fast compressor, whose framing
// the local fast finder happens to reproduce byte-for-byte for those inputs, so
// they don't actually exercise framing the local encoder cannot generate. This
// block is from libRIST's lz4hc (high-compression, level 12), which produces
// genuinely different framing — proving the decoder handles foreign blocks, not
// only its own output.
func TestDecompressForeignDivergentBlock(t *testing.T) {
	// lz4hc level 12 block for a 300-byte
	// "abcdefgh..." pattern (p[i] = 'a'+i%8) with bytes [100]=0x5a, [101]=0x59,
	// [200]=0x51 overridden.
	hc := mustHex(t, "8f61626364656667680800494f5a59676868004d1f5160004b506861626364")
	got, err := Decompress(nil, hc, 4096)
	if err != nil {
		t.Fatalf("Decompress HC block: %v", err)
	}
	if len(got) != 300 {
		t.Fatalf("HC decode = %d bytes, want 300", len(got))
	}
	for i := 0; i < len(got); i++ {
		want := byte('a' + i%8)
		switch i {
		case 100:
			want = 0x5a
		case 101:
			want = 0x59
		case 200:
			want = 0x51
		}
		if got[i] != want {
			t.Fatalf("HC decode byte[%d] = %#x, want %#x", i, got[i], want)
		}
	}
	// It must be genuinely foreign: the local fast compressor produces DIFFERENT
	// framing for the same plaintext, so this is not a self-encode.
	rc, _ := Compress(nil, got)
	if bytes.Equal(rc, hc) {
		t.Fatal("HC block is not foreign — local Compress reproduced it byte-for-byte")
	}
	// And the local codec round-trips the foreign-decoded plaintext.
	back, err := Decompress(nil, rc, 4096)
	if err != nil || !bytes.Equal(back, got) {
		t.Fatalf("local round-trip of the HC plaintext failed: err=%v", err)
	}
}

// TestDecompressRejectsTrailingMatch verifies a block that ends on a match (no
// literals-only terminator) is rejected with ErrCorrupt, matching libRIST's
// LZ4_decompress_safe, which returns -2 for the identical bytes.
func TestDecompressRejectsTrailingMatch(t *testing.T) {
	// token 0x44 = 4 literals + matchLen 8; literals "ABCD"; offset 1; the match
	// consumes the rest of the input with no trailing literals — malformed.
	block := mustHex(t, "44414243440100")
	if _, err := Decompress(nil, block, 64); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("trailing-match block: err = %v, want ErrCorrupt", err)
	}
}

// roundTripInputs returns a spread of payloads spanning the cases the codec
// must handle: empty, tiny (below minLength), highly compressible, random,
// long runs, and MPEG-TS-shaped data.
func roundTripInputs(t *testing.T) map[string][]byte {
	t.Helper()
	in := map[string][]byte{
		"empty":              nil,
		"one_byte":           {0x41},
		"four_bytes":         {1, 2, 3, 4},
		"minLength_minus1":   bytes.Repeat([]byte{0x5a}, minLength-1),
		"minLength":          bytes.Repeat([]byte{0x5a}, minLength),
		"text":               []byte("the quick brown fox jumps over the lazy dog, the quick brown fox"),
		"zeros_4k":           make([]byte, 4096),
		"run_0x47_400":       bytes.Repeat([]byte{0x47}, 400),
		"alternating":        bytes.Repeat([]byte{0xab, 0xcd}, 600),
		"period7":            bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7}, 300),
		"offset1_overlap":    append([]byte{0x99}, make([]byte, 500)...),
		"max_offset_window":  makeOffsetWindow(),
		"two_blocks_pattern": bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), 256),
	}
	// MPEG-TS-like payload: 7 TS packets, sync byte 0x47, semi-structured.
	ts := make([]byte, 0, 7*188)
	for p := 0; p < 7; p++ {
		pkt := make([]byte, 188)
		pkt[0] = 0x47
		pkt[1] = byte(0x40 | (p & 0x1f))
		pkt[2] = byte(p)
		pkt[3] = 0x10
		for i := 4; i < 188; i++ {
			pkt[i] = byte((i + p) & 0xff)
		}
		ts = append(ts, pkt...)
	}
	in["mpegts_7pkt"] = ts

	// Pseudo-random (incompressible) buffer of various sizes.
	r := rand.New(rand.NewSource(0x5715))
	for _, n := range []int{16, 256, 1500, 9000} {
		b := make([]byte, n)
		r.Read(b)
		in["random_"+itoa(n)] = b
	}
	return in
}

// makeOffsetWindow builds a buffer with a repeated 64KB-spanning pattern so
// matches near and at the maxOffset window boundary are exercised.
func makeOffsetWindow() []byte {
	const block = 200
	pat := make([]byte, block)
	for i := range pat {
		pat[i] = byte(i*7 + 3)
	}
	out := make([]byte, 0, maxOffset+block*4)
	for len(out) < maxOffset+block*4 {
		out = append(out, pat...)
	}
	return out
}

// itoa is a tiny helper to keep test map keys readable without strconv noise.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestRoundTrip asserts Decompress(Compress(x)) == x across the input spread.
func TestRoundTrip(t *testing.T) {
	for name, in := range roundTripInputs(t) {
		t.Run(name, func(t *testing.T) {
			comp, err := Compress(nil, in)
			if err != nil {
				t.Fatalf("Compress: %v", err)
			}
			if len(comp) > CompressBound(len(in)) {
				t.Fatalf("block %d bytes exceeds CompressBound %d", len(comp), CompressBound(len(in)))
			}
			got, err := Decompress(nil, comp, len(in))
			if err != nil {
				t.Fatalf("Decompress: %v", err)
			}
			if !bytes.Equal(got, in) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(in))
			}
		})
	}
}

// TestCompressBound checks the worst-case-size formula against LZ4_compressBound.
func TestCompressBound(t *testing.T) {
	cases := []struct {
		n    int
		want int
	}{
		{0, 16},
		{1, 17},
		{255, 256},     // 255 + 1 + 16 ... 255 + 255/255(=1) + 16 = 272? check below
		{254, 270},     // 254 + 0 + 16
		{256, 273},     // 256 + 1 + 16
		{-1, 0},        // negative -> 0
		{1500, 1521},   // 1500 + 5 + 16
		{65535, 65808}, // 65535 + 257 + 16
	}
	// recompute expectations directly from the documented formula to avoid
	// hand-arithmetic mistakes in the table above.
	for _, c := range cases {
		got := CompressBound(c.n)
		var want int
		if c.n < 0 {
			want = 0
		} else {
			want = c.n + c.n/255 + 16
		}
		if got != want {
			t.Fatalf("CompressBound(%d)=%d, want %d", c.n, got, want)
		}
	}
}

// TestDecompressMaxOutExact confirms decoding succeeds when maxOut equals the
// exact plaintext size, and that the appended output begins at len(dst).
func TestDecompressMaxOutExact(t *testing.T) {
	plain := bytes.Repeat([]byte("xyz123"), 100)
	comp, _ := Compress(nil, plain)

	prefix := []byte("PREFIX")
	out, err := Decompress(append([]byte(nil), prefix...), comp, len(plain))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.HasPrefix(out, prefix) {
		t.Fatalf("Decompress clobbered dst prefix")
	}
	if !bytes.Equal(out[len(prefix):], plain) {
		t.Fatalf("appended output mismatch")
	}
}

// TestDecompressEmptyBlock confirms an empty src is a valid empty block.
func TestDecompressEmptyBlock(t *testing.T) {
	out, err := Decompress(nil, nil, 100)
	if err != nil {
		t.Fatalf("Decompress(empty): %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("empty block produced %d bytes", len(out))
	}
}

// TestErrorsAreSentinels confirms the documented errors are matchable.
func TestErrorsAreSentinels(t *testing.T) {
	// A token claiming 5 literals with only 2 bytes present: truncated.
	if _, err := Decompress(nil, []byte{0x50, 0x01, 0x02}, 100); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated literals: got %v, want ErrCorrupt", err)
	}
	// 6 literals into a 1-byte bound: too large.
	blk, _ := Compress(nil, []byte("AAAAAA"))
	if _, err := Decompress(nil, blk, 1); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("over-bound: got %v, want ErrOutputTooLarge", err)
	}
}

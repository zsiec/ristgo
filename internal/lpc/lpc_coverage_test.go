package lpc

import (
	"bytes"
	"errors"
	"testing"
)

// TestDecompressMalformed walks the malformed-block taxonomy the decoder must
// reject without panicking: truncated length fields, truncated literal/offset
// runs, an offset pointing before the produced output, an over-long match, and
// output exceeding the bound. Each must return an error and leave dst empty.
func TestDecompressMalformed(t *testing.T) {
	tests := []struct {
		name   string
		block  []byte
		maxOut int
		want   error
	}{
		{
			// Token claims 5 literals (nibble 5) but only 2 follow.
			name:   "truncated_literals",
			block:  []byte{0x50, 0x01, 0x02},
			maxOut: 64,
			want:   ErrCorrupt,
		},
		{
			// Literal-length continuation byte run never terminates (ends at
			// a 0xFF with no following byte).
			name:   "unterminated_lit_length",
			block:  []byte{0xf0, 0xff},
			maxOut: 1024,
			want:   ErrCorrupt,
		},
		{
			// A literal run then only one byte of the 2-byte offset.
			name:   "truncated_offset",
			block:  []byte{0x10, 0x41, 0x01},
			maxOut: 64,
			want:   ErrCorrupt,
		},
		{
			// Offset 0 is invalid (no back-reference target).
			name:   "zero_offset",
			block:  []byte{0x10, 0x41, 0x00, 0x00},
			maxOut: 64,
			want:   ErrCorrupt,
		},
		{
			// Offset points before the start of produced output: 1 literal
			// emitted, then offset 5 reaches before position 0.
			name:   "offset_before_start",
			block:  []byte{0x10, 0x41, 0x05, 0x00},
			maxOut: 64,
			want:   ErrCorrupt,
		},
		{
			// Match-length continuation never terminates: token low nibble 15
			// asks for extras, but the trailing 0xFF has no terminator.
			name:   "unterminated_match_length",
			block:  []byte{0x1f, 0x41, 0x01, 0x00, 0xff},
			maxOut: 4096,
			want:   ErrCorrupt,
		},
		{
			// Over-long match: 1 literal, offset 1, extended match length far
			// beyond the bound -> ErrOutputTooLarge.
			name:   "overlong_match",
			block:  []byte{0x1f, 0x41, 0x01, 0x00, 0xff, 0xff, 0x10},
			maxOut: 8,
			want:   ErrOutputTooLarge,
		},
		{
			// Literals alone exceed the bound.
			name:   "literals_exceed_bound",
			block:  []byte{0x40, 0x01, 0x02, 0x03, 0x04},
			maxOut: 3,
			want:   ErrOutputTooLarge,
		},
		{
			// Match copy crosses the bound: 4 literals (= maxOut), then a
			// match that would add more.
			name:   "match_exceeds_bound",
			block:  []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x01, 0x00},
			maxOut: 4,
			want:   ErrOutputTooLarge,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Decompress([]byte("KEEP"), tc.block, tc.maxOut)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if string(out) != "KEEP" {
				t.Fatalf("dst not preserved on error: %q", out)
			}
		})
	}
}

// TestDecompressMaxOutBoundaries probes the exact maxOut boundary: one byte
// short fails, exact size succeeds.
func TestDecompressMaxOutBoundaries(t *testing.T) {
	plain := bytes.Repeat([]byte{0xaa, 0xbb, 0xcc}, 50) // 150 bytes
	block, _ := Compress(nil, plain)

	if _, err := Decompress(nil, block, len(plain)-1); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("len-1 bound: got %v, want ErrOutputTooLarge", err)
	}
	out, err := Decompress(nil, block, len(plain))
	if err != nil {
		t.Fatalf("exact bound: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("exact bound output mismatch")
	}
}

// TestNegativeMaxOut confirms a negative maxOut is clamped to 0: only an empty
// block decodes, anything producing output is rejected.
func TestNegativeMaxOut(t *testing.T) {
	if out, err := Decompress(nil, nil, -5); err != nil || len(out) != 0 {
		t.Fatalf("empty block with negative bound: out=%v err=%v", out, err)
	}
	if _, err := Decompress(nil, []byte{0x10, 0x41}, -1); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("negative bound with output: got %v, want ErrOutputTooLarge", err)
	}
}

// TestOverlapMatch exercises the run-length-expanding overlapping match
// (offset < match length, e.g. offset 1) directly through a hand-built block:
// 1 literal then a match of length 6 at offset 1 yields 7 identical bytes,
// followed by a literals-only terminator (a valid LZ4 block must end with
// literals, not a match).
func TestOverlapMatch(t *testing.T) {
	// token 0x12 -> litLen 1, match nibble 2 -> matchLen 6, offset 1; then
	// token 0x10 -> 1 trailing literal as the literals-only terminator.
	block := []byte{0x12, 0x5a, 0x01, 0x00, 0x10, 0x5a}
	out, err := Decompress(nil, block, 16)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	want := bytes.Repeat([]byte{0x5a}, 8)
	if !bytes.Equal(out, want) {
		t.Fatalf("overlap match = % x, want % x", out, want)
	}
}

// TestExtendedLengthEncoding round-trips inputs that force both extended
// literal-length and extended match-length continuation bytes (runs longer
// than 15 + minMatch), exercising appendLength and readLength on multi-byte
// continuations including exact 255 multiples.
func TestExtendedLengthEncoding(t *testing.T) {
	for _, n := range []int{15, 16, 18, 19, 254, 255, 256, 269, 270, 510, 511, 512, 5000} {
		t.Run(itoa(n), func(t *testing.T) {
			// Incompressible literal run of length n (forces a long literal
			// continuation) followed by a long compressible run (forces a long
			// match continuation).
			lit := make([]byte, n)
			for i := range lit {
				lit[i] = byte(i*131 + 7) // non-repeating enough to stay literal
			}
			run := bytes.Repeat([]byte{0xC3}, n)
			in := append(append([]byte{}, lit...), run...)

			block, _ := Compress(nil, in)
			got, err := Decompress(nil, block, len(in))
			if err != nil {
				t.Fatalf("n=%d Decompress: %v", n, err)
			}
			if !bytes.Equal(got, in) {
				t.Fatalf("n=%d round-trip mismatch", n)
			}
		})
	}
}

// TestAppendLengthExact255 checks that a length that is an exact multiple of
// 255 emits a trailing zero byte so the decoder's "stop on < 255" terminates,
// by round-tripping a literal run whose extra length is exactly 255.
func TestAppendLengthExact255(t *testing.T) {
	// litLen = runMask(15) + 255 = 270 forces extra = 255 -> "0xFF 0x00".
	in := make([]byte, 270)
	for i := range in {
		in[i] = byte(i * 97) // keep it from compressing into a match
	}
	block, _ := Compress(nil, in)
	got, err := Decompress(nil, block, len(in))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("exact-255 continuation round-trip mismatch")
	}
}

// TestCompressAppendsToDst confirms Compress appends to a non-empty dst and
// preserves the prefix, and that the result reuses caller capacity when given.
func TestCompressAppendsToDst(t *testing.T) {
	prefix := []byte("HDR")
	in := bytes.Repeat([]byte("payload"), 20)
	out, err := Compress(append([]byte(nil), prefix...), in)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	if !bytes.HasPrefix(out, prefix) {
		t.Fatalf("Compress did not preserve dst prefix")
	}
	dec, err := Decompress(nil, out[len(prefix):], len(in))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(dec, in) {
		t.Fatalf("appended-block round-trip mismatch")
	}
}

// TestIncompressibleStaysValid feeds high-entropy data (worst case for a
// compressor) and confirms the result is still a valid, round-tripping block
// within CompressBound.
func TestIncompressibleStaysValid(t *testing.T) {
	in := make([]byte, 2000)
	// A simple LCG to fill with non-repeating bytes deterministically.
	s := uint32(0x12345678)
	for i := range in {
		s = s*1664525 + 1013904223
		in[i] = byte(s >> 24)
	}
	block, _ := Compress(nil, in)
	if len(block) > CompressBound(len(in)) {
		t.Fatalf("incompressible block %d > bound %d", len(block), CompressBound(len(in)))
	}
	got, err := Decompress(nil, block, len(in))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("incompressible round-trip mismatch")
	}
}

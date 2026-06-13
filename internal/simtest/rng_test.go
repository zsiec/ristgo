package simtest

import "testing"

// TestRngGolden pins the SplitMix64 output stream for known seeds. The
// seed-0 vector matches Vigna's reference splitmix64.c test values and
// srtrust's simulator PRNG (crates/srt-protocol/tests/sim/mod.rs), so a
// change to any constant or to the mixing function fails this test.
func TestRngGolden(t *testing.T) {
	tests := []struct {
		name string
		seed uint64
		want [5]uint64
	}{
		{
			name: "seed 0 (canonical reference vector)",
			seed: 0,
			want: [5]uint64{
				0xe220a8397b1dcdaf, 0x6e789e6aa1b965f4, 0x06c45d188009454f,
				0xf88bb8a8724c81ec, 0x1b39896a51a8749b,
			},
		},
		{
			name: "seed 1",
			seed: 1,
			want: [5]uint64{
				0x910a2dec89025cc1, 0xbeeb8da1658eec67, 0xf893a2eefb32555e,
				0x71c18690ee42c90b, 0x71bb54d8d101b5b9,
			},
		},
		{
			name: "seed 0xdeadbeef",
			seed: 0xdeadbeef,
			want: [5]uint64{
				0x4adfb90f68c9eb9b, 0xde586a3141a10922, 0x021fbc2f8e1cfc1d,
				0x7466ce737be16790, 0x3bfa8764f685bd1c,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRng(tt.seed)
			for i, want := range tt.want {
				if got := r.Next(); got != want {
					t.Errorf("Next() #%d = %#016x, want %#016x", i, got, want)
				}
			}
		})
	}
}

// TestRngZeroValue verifies the zero value is a valid PRNG seeded with 0.
func TestRngZeroValue(t *testing.T) {
	var zero Rng
	ref := NewRng(0)
	for i := 0; i < 16; i++ {
		if got, want := zero.Next(), ref.Next(); got != want {
			t.Fatalf("zero-value Next() #%d = %#x, want %#x", i, got, want)
		}
	}
}

// TestRngSameSeedSameStream verifies two PRNGs with the same seed produce
// identical streams, and different seeds diverge.
func TestRngSameSeedSameStream(t *testing.T) {
	a, b := NewRng(42), NewRng(42)
	for i := 0; i < 1000; i++ {
		if got, want := a.Next(), b.Next(); got != want {
			t.Fatalf("streams diverged at draw %d: %#x != %#x", i, got, want)
		}
	}
	c, d := NewRng(42), NewRng(43)
	same := true
	for i := 0; i < 8; i++ {
		if c.Next() != d.Next() {
			same = false
		}
	}
	if same {
		t.Error("seeds 42 and 43 produced identical first 8 outputs")
	}
}

// TestRngUnit verifies Unit stays in [0, 1) and is roughly uniform.
func TestRngUnit(t *testing.T) {
	r := NewRng(7)
	const n = 100_000
	sum := 0.0
	for i := 0; i < n; i++ {
		u := r.Unit()
		if u < 0 || u >= 1 {
			t.Fatalf("Unit() #%d = %v, want in [0, 1)", i, u)
		}
		sum += u
	}
	mean := sum / n
	// Uniform mean is 0.5 with sigma ≈ 1/sqrt(12n) ≈ 0.0009; 0.01 is >10σ.
	if mean < 0.49 || mean > 0.51 {
		t.Errorf("mean of %d Unit() draws = %v, want ≈ 0.5", n, mean)
	}
}

// TestRngBelow verifies Below stays in [0, n) for a spread of ranges.
func TestRngBelow(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
	}{
		{name: "n=1 (always zero)", n: 1},
		{name: "n=2", n: 2},
		{name: "n=10", n: 10},
		{name: "n=large", n: 1 << 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRng(99)
			for i := 0; i < 10_000; i++ {
				if got := r.Below(tt.n); got >= tt.n {
					t.Fatalf("Below(%d) #%d = %d, want < %d", tt.n, i, got, tt.n)
				}
			}
		})
	}
}

// TestRngBelowZeroPanics verifies the documented programming-error panic.
func TestRngBelowZeroPanics(t *testing.T) {
	defer func() {
		got := recover()
		if got == nil {
			t.Fatal("Below(0) did not panic")
		}
		if want := "simtest: Rng.Below called with n == 0"; got != want {
			t.Fatalf("panic value = %v, want %q", got, want)
		}
	}()
	NewRng(1).Below(0)
}

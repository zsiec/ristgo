package simtest

// Rng is a tiny deterministic PRNG (SplitMix64). Seeding it fixes the
// entire output stream, so any loss/jitter/duplication pattern is exactly
// reproducible across runs. The constants match srtrust's simulator
// (crates/srt-protocol/tests/sim/mod.rs) and Sebastiano Vigna's reference
// SplitMix64, so the two harnesses produce identical streams from the same
// seed.
//
// The zero value is a valid Rng seeded with 0; NewRng makes the seed
// explicit at construction.
type Rng struct {
	s uint64
}

// SplitMix64 constants (Vigna's reference implementation; identical in
// srtrust crates/srt-protocol/tests/sim/mod.rs).
const (
	splitMix64Gamma = 0x9E3779B97F4A7C15
	splitMix64Mul1  = 0xBF58476D1CE4E5B9
	splitMix64Mul2  = 0x94D049BB133111EB
)

// NewRng creates a PRNG whose stream is fully determined by seed.
func NewRng(seed uint64) *Rng {
	return &Rng{s: seed}
}

// Next returns the next 64-bit output and advances the stream (SplitMix64).
func (r *Rng) Next() uint64 {
	r.s += splitMix64Gamma
	z := r.s
	z = (z ^ (z >> 30)) * splitMix64Mul1
	z = (z ^ (z >> 27)) * splitMix64Mul2
	return z ^ (z >> 31)
}

// Unit returns a uniform float64 in [0, 1) using the top 53 bits of the
// next output as the mantissa. A 53-bit integer and 2^53 are both exactly
// representable in float64, so the conversion loses no bits.
func (r *Rng) Unit() float64 {
	return float64(r.Next()>>11) / float64(uint64(1)<<53)
}

// Below returns a uniform integer in [0, n). n must be non-zero; calling
// Below(0) is a programming error and panics. The modulo bias is irrelevant
// for a test harness's small ranges (matching the srtrust source).
func (r *Rng) Below(n uint64) uint64 {
	if n == 0 {
		panic("simtest: Rng.Below called with n == 0")
	}
	return r.Next() % n
}

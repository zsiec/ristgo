package rtt

import (
	"fmt"
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

// TestObserveVectors replays libRIST's exact integer arithmetic
// step-by-step against hand-computed expectations. Every line of the
// expected columns below was derived by hand from the C statements:
//
//	init:    etr = rttMin * 8
//	observe: etr = etr - etr/8 + sample   (each division truncating)
//	read:    smoothed = etr / 8           (truncating)
//
// Vector "defaults-5ms" (rttMin = 5000us, the libRIST 5ms default, so
// etr0 = 40000):
//
//	step 1, sample 10000:  etr/8 = 40000/8 = 5000
//	                       etr   = 40000 - 5000 + 10000      = 45000
//	                       smoothed = 45000/8                 = 5625
//	step 2, sample 10000:  etr/8 = 45000/8 = 5625
//	                       etr   = 45000 - 5625 + 10000      = 49375
//	                       smoothed = 49375/8 = 6171.875 ->    6171
//	step 3, sample 3:      etr/8 = 49375/8 = 6171.875 -> 6171
//	                       etr   = 49375 - 6171 + 3          = 43207
//	                       smoothed = 43207/8 = 5400.875 ->    5400
//	step 4, sample 0:      etr/8 = 43207/8 = 5400
//	                       etr   = 43207 - 5400 + 0          = 37807
//	                       smoothed = 37807/8 = 4725.875 ->    4725
//	step 5, sample 1000000: etr/8 = 37807/8 = 4725
//	                       etr   = 37807 - 4725 + 1000000    = 1033082
//	                       smoothed = 1033082/8 = 129135.25 -> 129135
//
// Vector "zero-init-truncation" (rttMin = 0, etr0 = 0; constant sample 7
// exposes the truncating divisions on small values):
//
//	step 1: etr = 0  - 0/8(=0) + 7 = 7;   smoothed = 7/8  = 0
//	step 2: etr = 7  - 7/8(=0) + 7 = 14;  smoothed = 14/8 = 1
//	step 3: etr = 14 - 14/8(=1) + 7 = 20; smoothed = 20/8 = 2
//	step 4: etr = 20 - 20/8(=2) + 7 = 25; smoothed = 25/8 = 3
//	step 5: etr = 25 - 25/8(=3) + 7 = 29; smoothed = 29/8 = 3
//	step 6: etr = 29 - 29/8(=3) + 7 = 33; smoothed = 33/8 = 4
//
// Vector "decay-from-above" (rttMin = 100000us, etr0 = 800000; constant
// sample 0 decays by exactly etr/8 per step):
//
//	step 1: etr = 800000 - 100000 + 0 = 700000; smoothed = 87500
//	step 2: etr = 700000 - 87500  + 0 = 612500; smoothed = 76562 (76562.5)
//	step 3: etr = 612500 - 76562  + 0 = 535938; smoothed = 66992 (66992.25)
//
// Vector "negative-sample-pinned" (rttMin = 1000, etr0 = 8000; a negative
// sample is pinned to 0 — the calculate_rtt_delay guard):
//
//	step 1, sample -5: treated as 0: etr = 8000 - 1000 + 0 = 7000
//	                   smoothed = 7000/8 = 875
func TestObserveVectors(t *testing.T) {
	type step struct {
		sample       clock.Microseconds
		wantEight    clock.Microseconds // etr after Observe
		wantSmoothed clock.Microseconds // etr/8 after Observe
	}
	tests := []struct {
		name     string
		rttMin   clock.Microseconds
		wantInit clock.Microseconds // etr after New
		steps    []step
	}{
		{
			name:     "defaults-5ms",
			rttMin:   5000,
			wantInit: 40000,
			steps: []step{
				{sample: 10000, wantEight: 45000, wantSmoothed: 5625},
				{sample: 10000, wantEight: 49375, wantSmoothed: 6171},
				{sample: 3, wantEight: 43207, wantSmoothed: 5400},
				{sample: 0, wantEight: 37807, wantSmoothed: 4725},
				{sample: 1000000, wantEight: 1033082, wantSmoothed: 129135},
			},
		},
		{
			name:     "zero-init-truncation",
			rttMin:   0,
			wantInit: 0,
			steps: []step{
				{sample: 7, wantEight: 7, wantSmoothed: 0},
				{sample: 7, wantEight: 14, wantSmoothed: 1},
				{sample: 7, wantEight: 20, wantSmoothed: 2},
				{sample: 7, wantEight: 25, wantSmoothed: 3},
				{sample: 7, wantEight: 29, wantSmoothed: 3},
				{sample: 7, wantEight: 33, wantSmoothed: 4},
			},
		},
		{
			name:     "decay-from-above",
			rttMin:   100000,
			wantInit: 800000,
			steps: []step{
				{sample: 0, wantEight: 700000, wantSmoothed: 87500},
				{sample: 0, wantEight: 612500, wantSmoothed: 76562},
				{sample: 0, wantEight: 535938, wantSmoothed: 66992},
			},
		},
		{
			name:     "negative-sample-pinned",
			rttMin:   1000,
			wantInit: 8000,
			steps: []step{
				{sample: -5, wantEight: 7000, wantSmoothed: 875},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(tt.rttMin)
			if e.eightTimesRTT != tt.wantInit {
				t.Fatalf("New(%d): eightTimesRTT = %d, want %d",
					tt.rttMin, e.eightTimesRTT, tt.wantInit)
			}
			if got, want := e.Smoothed(), tt.wantInit/8; got != want {
				t.Fatalf("New(%d).Smoothed() = %d, want %d", tt.rttMin, got, want)
			}
			for i, s := range tt.steps {
				e = e.Observe(s.sample)
				if e.eightTimesRTT != s.wantEight {
					t.Fatalf("step %d: Observe(%d): eightTimesRTT = %d, want %d",
						i+1, s.sample, e.eightTimesRTT, s.wantEight)
				}
				if got := e.Smoothed(); got != s.wantSmoothed {
					t.Fatalf("step %d: Smoothed() = %d, want %d",
						i+1, got, s.wantSmoothed)
				}
			}
		})
	}
}

// TestNewNegativeRTTMin checks that an out-of-domain (negative) rttMin is
// pinned to 0 rather than seeding a negative EWMA.
func TestNewNegativeRTTMin(t *testing.T) {
	e := New(-1)
	if e.eightTimesRTT != 0 {
		t.Fatalf("New(-1): eightTimesRTT = %d, want 0", e.eightTimesRTT)
	}
	if got := e.Smoothed(); got != 0 {
		t.Fatalf("New(-1).Smoothed() = %d, want 0", got)
	}
}

// TestConvergence checks the EWMA fixed point: feeding a constant sample c
// drives eight_times_rtt into the band [8c, 8c+7] (every value there is a
// fixed point of etr - etr/8 + c under truncating division), so Smoothed()
// converges to exactly c and then never moves again.
func TestConvergence(t *testing.T) {
	const maxIters = 2000
	tests := []struct {
		name   string
		rttMin clock.Microseconds
		sample clock.Microseconds
	}{
		{"up-from-zero", 0, 12345},
		{"up-from-default", 5000, 250000},
		{"down-from-default", 5000, 100},
		{"down-from-max", 500000, 1000},
		{"already-there", 5000, 5000},
		{"to-zero", 5000, 0},
		{"one-microsecond", 0, 1},
		{"large", 0, 100_000_000}, // 100s, far beyond rtt_max; arithmetic still converges
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(tt.rttMin)
			converged := -1
			for i := 0; i < maxIters; i++ {
				e = e.Observe(tt.sample)
				if e.Smoothed() == tt.sample {
					converged = i + 1
					break
				}
			}
			if converged < 0 {
				t.Fatalf("Smoothed() = %d after %d constant samples of %d; never converged",
					e.Smoothed(), maxIters, tt.sample)
			}
			// Once in the fixed band, the estimate must be pinned there.
			for i := 0; i < 64; i++ {
				e = e.Observe(tt.sample)
				if got := e.Smoothed(); got != tt.sample {
					t.Fatalf("after convergence (+%d extra samples): Smoothed() = %d, want %d",
						i+1, got, tt.sample)
				}
			}
			lo, hi := 8*tt.sample, 8*tt.sample+7
			if e.eightTimesRTT < lo || e.eightTimesRTT > hi {
				t.Fatalf("converged eightTimesRTT = %d, want within fixed band [%d, %d]",
					e.eightTimesRTT, lo, hi)
			}
			t.Logf("converged in %d iterations (eightTimesRTT=%d)", converged, e.eightTimesRTT)
		})
	}
}

// estimatorWithSmoothed builds an Estimator whose Smoothed() reading is
// exactly v, via the New seeding identity etr = 8v.
func estimatorWithSmoothed(v clock.Microseconds) Estimator {
	return Estimator{eightTimesRTT: 8 * v}
}

// TestClamped covers the boundary behavior of the [rttMin, rttMax] clamp,
// including libRIST's exact else-if semantics for degenerate (min > max)
// bounds. All rttMin values here are at or above the 3 ms RIST_RTT_MIN floor
// that Clamped applies, so the floor does not alter these results (it is
// exercised separately in TestRTTMinFloor).
func TestClamped(t *testing.T) {
	const min, max = 5000, 500000 // libRIST defaults, in microseconds
	tests := []struct {
		name     string
		smoothed clock.Microseconds
		min, max clock.Microseconds
		want     clock.Microseconds
	}{
		{"below-min", 4999, min, max, 5000},
		{"at-min", 5000, min, max, 5000},
		{"just-above-min", 5001, min, max, 5001},
		{"mid-range", 123456, min, max, 123456},
		{"just-below-max", 499999, min, max, 499999},
		{"at-max", 500000, min, max, 500000},
		{"above-max", 500001, min, max, 500000},
		{"zero-reading", 0, min, max, 5000},
		{"degenerate-min-equals-max", 7770, 4000, 4000, 4000},
		{"degenerate-min-equals-max-above", 5000, 4000, 4000, 4000},
		// min > max is rejected by Config validation but must not panic
		// here; the C's else-if makes the min branch win for low readings
		// even though the result exceeds max. Both bounds stay above the
		// 3 ms floor so only the else-if (not the floor) governs the result.
		{"inverted-bounds-low-reading", 3100, 4000, 3500, 4000},
		{"inverted-bounds-mid-reading", 3700, 4000, 3500, 4000},
		{"inverted-bounds-high-reading", 5000, 4000, 3500, 3500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := estimatorWithSmoothed(tt.smoothed)
			if got := e.Clamped(tt.min, tt.max); got != tt.want {
				t.Errorf("Clamped(%d, %d) with smoothed %d = %d, want %d",
					tt.min, tt.max, tt.smoothed, got, tt.want)
			}
		})
	}
}

// TestLastSample verifies the raw last_rtt tracking: 0 before any sample,
// the most recent sample after Observe, and the non-negative pin.
func TestLastSample(t *testing.T) {
	if got := New(5000).Last(); got != 0 {
		t.Errorf("Last() before any sample = %d, want 0 (libRIST last_rtt starts at 0)", got)
	}
	e := New(5000).Observe(120000)
	if got := e.Last(); got != 120000 {
		t.Errorf("Last() after Observe(120000) = %d, want 120000", got)
	}
	e = e.Observe(40000) // most recent wins (raw, not averaged)
	if got := e.Last(); got != 40000 {
		t.Errorf("Last() after Observe(40000) = %d, want 40000", got)
	}
	if got := New(5000).Observe(-7).Last(); got != 0 {
		t.Errorf("Last() after negative sample = %d, want 0 (pinned)", got)
	}
}

// TestLastClamped exercises the sender retransmit-gate value (libRIST
// peer->last_rtt clamped): the same clamp branch as
// Clamped, applied to the raw last sample rather than the EWMA.
func TestLastClamped(t *testing.T) {
	const min, max = 5000, 500000
	tests := []struct {
		name     string
		last     clock.Microseconds
		min, max clock.Microseconds
		want     clock.Microseconds
	}{
		{"no-sample-pins-to-min", 0, min, max, 5000},
		{"below-min", 4999, min, max, 5000},
		{"at-min", 5000, min, max, 5000},
		{"mid-range", 123456, min, max, 123456},
		{"at-max", 500000, min, max, 500000},
		{"above-max", 500001, min, max, 500000},
		// Both bounds above the 3 ms floor so the else-if (not the floor)
		// governs: a reading above the inverted max clamps down to max.
		{"inverted-bounds-high-reading", 5000, 4000, 3500, 3500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Estimator{lastSample: tt.last}
			if got := e.LastClamped(tt.min, tt.max); got != tt.want {
				t.Errorf("LastClamped(%d, %d) with last %d = %d, want %d",
					tt.min, tt.max, tt.last, got, tt.want)
			}
		})
	}
}

// TestLastVsSmoothedDiverge pins the reason the two readings are kept
// separate: after a single large sample the raw last value and the EWMA
// differ, so the sender gate (LastClamped) and the receiver retry interval
// (Clamped) read genuinely different RTTs, exactly as libRIST intends.
func TestLastVsSmoothedDiverge(t *testing.T) {
	const min, max = 5000, 500000
	e := New(min).Observe(100000)
	// eight_times_rtt = 5000*8 - 5000 + 100000 = 135000 -> smoothed 16875.
	if got := e.Clamped(min, max); got != 16875 {
		t.Fatalf("Clamped = %d, want 16875 (EWMA)", got)
	}
	if got := e.LastClamped(min, max); got != 100000 {
		t.Fatalf("LastClamped = %d, want 100000 (raw last sample)", got)
	}
}

// TestRetryInterval verifies the 1.1x retry spacing against hand-computed
// truncations of the C expression (uint64_t)(rtt * 1.1).
// Expected values are floor(rtt * 11/10):
//
//	clamped 5000   -> 5500    (cold start at the 5ms default: 1.1 * rttMin)
//	clamped 100000 -> 110000
//	clamped 3009   -> 3309    (3309.9 truncates: the cast drops the fraction)
//	clamped 3015   -> 3316    (3316.5 truncates to 3316)
//	clamped 500000 -> 550000  (reading above max clamps first, then scales)
//
// The truncation cases use clamped values above the 3 ms RIST_RTT_MIN floor so
// the floor does not lift them; the .9/.5 fractions still exercise the cast.
func TestRetryInterval(t *testing.T) {
	const min, max = 5000, 500000
	tests := []struct {
		name     string
		smoothed clock.Microseconds
		min, max clock.Microseconds
		want     clock.Microseconds
	}{
		{"cold-start-at-min", 5000, min, max, 5500},
		{"below-min-clamps-first", 0, min, max, 5500},
		{"mid-range", 100000, min, max, 110000},
		{"above-max-clamps-first", 1000000, min, max, 550000},
		// rttMin 0 floors to the 3 ms RIST_RTT_MIN; the smoothed reading is
		// above that, so it passes through and the 1.1x cast truncates.
		{"truncates-3309.9-to-3309", 3009, 0, max, 3309},
		{"truncates-3316.5-to-3316", 3015, 0, max, 3316},
		// A sub-floor reading is lifted to 3 ms first: 3000 * 1.1 = 3300.
		{"below-floor-lifts-to-3ms", 0, 0, max, 3300},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := estimatorWithSmoothed(tt.smoothed)
			if got := e.RetryInterval(tt.min, tt.max); got != tt.want {
				t.Errorf("RetryInterval(%d, %d) with smoothed %d = %d, want %d",
					tt.min, tt.max, tt.smoothed, got, tt.want)
			}
		})
	}
}

// TestRetryIntervalIntegerIdentity sweeps clamped values and asserts the
// float expression Go shares with the C — truncate(float64(v) * 1.1) —
// equals the pure integer v + v/10 (== floor(v*11/10)). The identity holds
// for every v this package can produce (IEEE-754 double 1.1 exceeds 11/10
// by ~8.9e-17 relative, far too small to push the product across an
// integer boundary below 2^49); the sweep documents and enforces it.
func TestRetryIntervalIntegerIdentity(t *testing.T) {
	check := func(v clock.Microseconds) {
		t.Helper()
		// rttMin = 3 ms RIST_RTT_MIN floor, rttMax wide open: for v >= floor the
		// clamp passes v through unchanged, so the reading equals v.
		e := estimatorWithSmoothed(v)
		got := e.RetryInterval(rttMinFloor, 1<<40)
		if want := v + v/10; got != want {
			t.Fatalf("RetryInterval identity broken at v=%d: float path %d, integer path %d",
				v, got, want)
		}
	}
	// Sweep from the 3 ms floor (clamped == v holds only at or above it).
	for v := rttMinFloor; v <= 100000; v++ {
		check(v)
	}
	// Spot-check the full configurable range (MaxRTT is 1s = 1e6 us).
	for _, v := range []clock.Microseconds{500000, 999999, 1000000, 10_000_000} {
		check(v)
	}
}

// TestValueSemantics confirms Observe is pure: the receiver is left
// untouched and only the returned Estimator carries the update.
func TestValueSemantics(t *testing.T) {
	a := New(5000)
	b := a.Observe(10000)
	if a.eightTimesRTT != 40000 {
		t.Errorf("receiver mutated: eightTimesRTT = %d, want 40000", a.eightTimesRTT)
	}
	if b.eightTimesRTT != 45000 {
		t.Errorf("returned estimator: eightTimesRTT = %d, want 45000", b.eightTimesRTT)
	}
}

// TestZeroValue documents that the zero Estimator is usable: it reads as
// smoothed 0, which Clamped pins to rttMin.
func TestZeroValue(t *testing.T) {
	var e Estimator
	if got := e.Smoothed(); got != 0 {
		t.Errorf("zero value Smoothed() = %d, want 0", got)
	}
	if got := e.Clamped(5000, 500000); got != 5000 {
		t.Errorf("zero value Clamped(5000, 500000) = %d, want 5000", got)
	}
	if got := e.RetryInterval(5000, 500000); got != 5500 {
		t.Errorf("zero value RetryInterval(5000, 500000) = %d, want 5500", got)
	}
}

// TestRTTMinFloor verifies the 3 ms RIST_RTT_MIN hard floor (ristRTTMinFloorMs)
// on the effective rtt_min used by Clamped/LastClamped/RetryInterval. A
// configured rtt_min below 3 ms is raised to 3 ms before it bounds the reading,
// so cold-start NACK retry spacing (and the sender retransmit gate) never
// collapses below 3 ms; a configured rtt_min at or above 3 ms is untouched.
func TestRTTMinFloor(t *testing.T) {
	const floor = clock.Microseconds(ristRTTMinFloorMs) * clock.Millisecond // 3000us
	if rttMinFloor != floor {
		t.Fatalf("rttMinFloor const = %d, want %d (3 ms)", rttMinFloor, floor)
	}
	const max = 500 * clock.Millisecond
	tests := []struct {
		name           string
		smoothed, last clock.Microseconds
		rttMin         clock.Microseconds
		wantClamped    clock.Microseconds
		wantLast       clock.Microseconds
		wantRetry      clock.Microseconds
	}{
		// rttMin below the floor: a sub-floor reading is lifted to 3 ms.
		{"min-1ms-reading-0", 0, 0, 1 * clock.Millisecond, floor, floor, 3300},
		{"min-0-reading-0", 0, 0, 0, floor, floor, 3300},
		// A reading above the floor passes through even when rttMin < floor.
		{"min-1ms-reading-10ms", 10000, 10000, 1 * clock.Millisecond, 10000, 10000, 11000},
		// rttMin at/above the floor is unchanged (the libRIST 5 ms default).
		{"min-5ms-reading-0", 0, 0, 5 * clock.Millisecond, 5000, 5000, 5500},
		{"min-5ms-reading-2ms", 2000, 2000, 5 * clock.Millisecond, 5000, 5000, 5500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Estimator{eightTimesRTT: 8 * tt.smoothed, lastSample: tt.last}
			if got := e.Clamped(tt.rttMin, max); got != tt.wantClamped {
				t.Errorf("Clamped(%d, max) = %d, want %d", tt.rttMin, got, tt.wantClamped)
			}
			if got := e.LastClamped(tt.rttMin, max); got != tt.wantLast {
				t.Errorf("LastClamped(%d, max) = %d, want %d", tt.rttMin, got, tt.wantLast)
			}
			if got := e.RetryInterval(tt.rttMin, max); got != tt.wantRetry {
				t.Errorf("RetryInterval(%d, max) = %d, want %d", tt.rttMin, got, tt.wantRetry)
			}
		})
	}
}

func ExampleEstimator() {
	// One estimator per path, seeded with the configured rtt_min
	// (libRIST default: 5ms).
	const rttMin, rttMax = 5 * clock.Millisecond, 500 * clock.Millisecond

	e := New(rttMin)
	for _, sample := range []clock.Microseconds{12000, 11000, 13000} {
		e = e.Observe(sample)
	}
	// By hand: etr = 40000 -> 40000-5000+12000 = 47000
	//              -> 47000-5875+11000 = 52125
	//              -> 52125-6515+13000 = 58610; smoothed = 58610/8 = 7326.
	fmt.Println(e.Smoothed(), e.Clamped(rttMin, rttMax), e.RetryInterval(rttMin, rttMax))
	// Output: 7326 7326 8058
}

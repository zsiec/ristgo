package clock

import (
	"testing"
	"time"
)

func TestNTPTimeFromTime(t *testing.T) {
	tests := []struct {
		name     string
		t        time.Time
		wantSec  uint32
		wantFrac uint32
	}{
		{
			name:     "Unix epoch",
			t:        time.Unix(0, 0).UTC(),
			wantSec:  2208988800, // 70 years incl. 17 leap days
			wantFrac: 0,
		},
		{
			name:     "Unix billennium",
			t:        time.Unix(1_000_000_000, 0).UTC(), // 2001-09-09 01:46:40 UTC
			wantSec:  3208988800,
			wantFrac: 0,
		},
		{
			name:     "half second",
			t:        time.Unix(1, 500_000_000).UTC(),
			wantSec:  2208988801,
			wantFrac: 0x80000000,
		},
		{
			name:     "quarter second",
			t:        time.Unix(1, 250_000_000).UTC(),
			wantSec:  2208988801,
			wantFrac: 0x40000000,
		},
		{
			name:     "one nanosecond rounds to nearest fraction unit",
			t:        time.Unix(0, 1).UTC(),
			wantSec:  2208988800,
			wantFrac: 4, // round(1 * 2^32 / 1e9) = round(4.295)
		},
		{
			name:     "NTP era rollover wraps seconds",
			t:        time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC), // NTP seconds = 2^32
			wantSec:  0,
			wantFrac: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NTPTimeFromTime(tt.t)
			if n.Seconds() != tt.wantSec {
				t.Errorf("Seconds() = %d, want %d", n.Seconds(), tt.wantSec)
			}
			if n.Fraction() != tt.wantFrac {
				t.Errorf("Fraction() = 0x%08X, want 0x%08X", n.Fraction(), tt.wantFrac)
			}
		})
	}
}

func TestNTPTimeTimeRoundTrip(t *testing.T) {
	// time.Time -> NTPTime -> time.Time must be exact at nanosecond
	// precision: NTP fraction resolution (~233 ps) is finer than 1 ns
	// and both conversions round to nearest.
	secs := []int64{0, 1, 1_000_000_000, 1_770_000_000}
	nanos := []int{0, 1, 2, 3, 499, 1000, 499_999_999, 500_000_000, 500_000_001, 999_999_998, 999_999_999}

	for _, sec := range secs {
		for _, ns := range nanos {
			want := time.Unix(sec, int64(ns)).UTC()
			got := NTPTimeFromTime(want).Time()
			if !got.Equal(want) {
				t.Errorf("round trip %v: got %v", want, got)
			}
		}
	}
}

func TestNTPTimeFractionPrecisionViaTime(t *testing.T) {
	// NTPTime -> time.Time -> NTPTime goes through the coarser
	// nanosecond unit. Error bound: ±0.5 ns from the first rounding
	// (= 0.5 * 2^32/1e9 ≈ 2.15 fraction units) plus ±0.5 from the
	// second, so at most 3 fraction units in total.
	const maxDelta = 3
	const sec = uint64(3_600_000_000) << 32 // mid-range, era-safe

	fracs := []uint64{
		0, 1, 2, 3, 4, 5,
		0x00000400, 0x12345678, 0x7FFFFFFF, 0x80000000,
		0xDEADBEEF, 0xFFFFFFF0, 0xFFFFFFFE, 0xFFFFFFFF,
	}
	for _, frac := range fracs {
		n := NTPTime(sec | frac)
		n2 := NTPTimeFromTime(n.Time())
		delta := int64(n2 - n) // linear across a seconds carry
		if delta < 0 {
			delta = -delta
		}
		if delta > maxDelta {
			t.Errorf("frac 0x%08X: |delta| = %d fraction units, want <= %d", frac, delta, maxDelta)
		}
	}
}

func TestNTPTimeFromTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		ts       Timestamp
		wantSec  uint32
		wantFrac uint32
	}{
		{name: "zero", ts: 0, wantSec: 0, wantFrac: 0},
		{name: "negative clamps to zero", ts: -5, wantSec: 0, wantFrac: 0},
		{name: "one second", ts: Timestamp(Second), wantSec: 1, wantFrac: 0},
		{name: "one and a half seconds", ts: Timestamp(Second + Second/2), wantSec: 1, wantFrac: 0x80000000},
		{name: "quarter second", ts: 250_000, wantSec: 0, wantFrac: 0x40000000},
		{
			name:    "one microsecond rounds to nearest fraction unit",
			ts:      1,
			wantSec: 0,
			// round(1 * 2^32 / 1e6) = round(4294.967296)
			wantFrac: 4295,
		},
		{
			name:     "max microsecond fraction",
			ts:       999_999,
			wantSec:  0,
			wantFrac: uint32(((uint64(999_999) << 32) + usPerSecond/2) / usPerSecond),
		},
		{
			name:     "seconds beyond 32 bits wrap (NTP era semantics)",
			ts:       Timestamp(int64(1<<32)*int64(Second) + 500_000), // 2^32 s + 0.5 s
			wantSec:  0,
			wantFrac: 0x80000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NTPTimeFromTimestamp(tt.ts)
			if n.Seconds() != tt.wantSec {
				t.Errorf("Seconds() = %d, want %d", n.Seconds(), tt.wantSec)
			}
			if n.Fraction() != tt.wantFrac {
				t.Errorf("Fraction() = %d (0x%08X), want %d (0x%08X)",
					n.Fraction(), n.Fraction(), tt.wantFrac, tt.wantFrac)
			}
		})
	}
}

func TestNTPTimeTimestampRoundTrip(t *testing.T) {
	// Timestamp -> NTPTime -> Timestamp must be exact at microsecond
	// precision: NTP fraction resolution is ~4295x finer than 1 µs and
	// both conversions round to nearest.
	secs := []int64{0, 1, 77, 4_000_000_000} // last is within the 2^32-second era
	micros := []int64{0, 1, 2, 3, 499, 1000, 499_999, 500_000, 500_001, 999_998, 999_999}

	for _, sec := range secs {
		for _, us := range micros {
			want := Timestamp(sec*int64(Second) + us)
			got := NTPTimeFromTimestamp(want).Timestamp()
			if got != want {
				t.Errorf("round trip %d: got %d", want, got)
			}
		}
	}
}

func TestNTPTimeFractionPrecisionViaTimestamp(t *testing.T) {
	// NTPTime -> Timestamp -> NTPTime goes through the much coarser
	// microsecond unit. Error bound: ±0.5 µs from the first rounding
	// (= 0.5 * 2^32/1e6 ≈ 2147.5 fraction units) plus ±0.5 from the
	// second, so at most 2148 fraction units (~0.5 µs) in total.
	const maxDelta = 2148
	const sec = uint64(12345) << 32

	fracs := []uint64{
		0, 1, 1000, 2147, 2148,
		0x12345678, 0x7FFFFFFF, 0x80000000,
		0xDEADBEEF, 0xFFFFF000, 0xFFFFFFFF,
	}
	for _, frac := range fracs {
		n := NTPTime(sec | frac)
		n2 := NTPTimeFromTimestamp(n.Timestamp())
		delta := int64(n2 - n) // linear across a seconds carry
		if delta < 0 {
			delta = -delta
		}
		if delta > maxDelta {
			t.Errorf("frac 0x%08X: |delta| = %d fraction units, want <= %d", frac, delta, maxDelta)
		}
	}
}

func TestNTPTimeFields(t *testing.T) {
	n := NTPTime(0x123456789ABCDEF0)
	if got := n.Seconds(); got != 0x12345678 {
		t.Errorf("Seconds() = 0x%08X, want 0x12345678", got)
	}
	if got := n.Fraction(); got != 0x9ABCDEF0 {
		t.Errorf("Fraction() = 0x%08X, want 0x9ABCDEF0", got)
	}
}

func TestNTPTimeMiddle32(t *testing.T) {
	tests := []struct {
		name string
		n    NTPTime
		want uint32
	}{
		{name: "zero", n: 0, want: 0},
		{name: "pattern", n: NTPTime(0x123456789ABCDEF0), want: 0x56789ABC},
		{name: "seconds only", n: NTPTime(0x00012345) << 32, want: 0x23450000},
		{name: "fraction only", n: NTPTime(0xABCD0000), want: 0x0000ABCD},
		{name: "all ones", n: NTPTime(0xFFFFFFFFFFFFFFFF), want: 0xFFFFFFFF},
		{name: "half second resolution", n: NTPTime(0x80000000), want: 0x00008000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.n.Middle32(); got != tt.want {
				t.Errorf("Middle32() = 0x%08X, want 0x%08X", got, tt.want)
			}
		})
	}

	t.Run("matches field composition", func(t *testing.T) {
		// Middle32 must equal low 16 bits of Seconds + high 16 bits of
		// Fraction (the RTCP LSR/DLSR definition).
		for _, n := range []NTPTime{0, 1, NTPTime(0xCAFEBABE12345678), NTPTimeFromTimestamp(90 * Timestamp(Second))} {
			want := (n.Seconds()&0xFFFF)<<16 | n.Fraction()>>16
			if got := n.Middle32(); got != want {
				t.Errorf("n=0x%016X: Middle32() = 0x%08X, want 0x%08X", uint64(n), got, want)
			}
		}
	})
}

// Allocation gates: these conversions sit on the RTCP hot path and
// must stay allocation-free.

var (
	sinkNTP  NTPTime
	sinkTime time.Time
	sinkTS   Timestamp
	sinkU32  uint32
)

func TestNTPAllocationFree(t *testing.T) {
	now := time.Now()
	n := NTPTimeFromTime(now)

	tests := []struct {
		name string
		fn   func()
	}{
		{"NTPTimeFromTime", func() { sinkNTP = NTPTimeFromTime(now) }},
		{"Time", func() { sinkTime = n.Time() }},
		{"NTPTimeFromTimestamp", func() { sinkNTP = NTPTimeFromTimestamp(123_456_789) }},
		{"Timestamp", func() { sinkTS = n.Timestamp() }},
		{"Middle32", func() { sinkU32 = n.Middle32() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if allocs := testing.AllocsPerRun(100, tt.fn); allocs != 0 {
				t.Errorf("allocs = %v, want 0", allocs)
			}
		})
	}
}

// Benchmarks

func BenchmarkNTPTimeFromTime(b *testing.B) {
	now := time.Now()
	for b.Loop() {
		sinkNTP = NTPTimeFromTime(now)
	}
}

func BenchmarkNTPTimeFromTimestamp(b *testing.B) {
	ts := Timestamp(5_000_000_000)
	for b.Loop() {
		sinkNTP = NTPTimeFromTimestamp(ts)
	}
}

func BenchmarkNTPTimeTimestamp(b *testing.B) {
	n := NTPTimeFromTimestamp(5_000_000_000)
	for b.Loop() {
		sinkTS = n.Timestamp()
	}
}

func BenchmarkNTPTimeMiddle32(b *testing.B) {
	n := NTPTimeFromTimestamp(5_000_000_000)
	for b.Loop() {
		sinkU32 = n.Middle32()
	}
}

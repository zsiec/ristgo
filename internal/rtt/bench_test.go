package rtt

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

// Sinks defeat dead-code elimination in the benchmarks below.
var (
	sinkEstimator Estimator
	sinkDuration  clock.Microseconds
)

// TestZeroAlloc is the hot-path allocation gate: the estimator runs inside
// internal/flow per received echo response and per NACK scheduling pass,
// so every method must be allocation-free. This gate runs under plain
// `go test`, not only under -benchmem.
func TestZeroAlloc(t *testing.T) {
	e := New(5 * clock.Millisecond)
	if allocs := testing.AllocsPerRun(1000, func() {
		e = e.Observe(12345)
		sinkDuration = e.Smoothed()
		sinkDuration = e.Clamped(5*clock.Millisecond, 500*clock.Millisecond)
		sinkDuration = e.RetryInterval(5*clock.Millisecond, 500*clock.Millisecond)
	}); allocs != 0 {
		t.Fatalf("estimator hot path allocates: %v allocs/op, want 0", allocs)
	}
}

func BenchmarkObserve(b *testing.B) {
	e := New(5 * clock.Millisecond)
	b.ReportAllocs()
	for b.Loop() {
		e = e.Observe(12345)
	}
	sinkEstimator = e
}

func BenchmarkObserveSmoothed(b *testing.B) {
	e := New(5 * clock.Millisecond)
	b.ReportAllocs()
	for b.Loop() {
		e = e.Observe(12345)
		sinkDuration = e.Smoothed()
	}
	sinkEstimator = e
}

func BenchmarkRetryInterval(b *testing.B) {
	e := New(5 * clock.Millisecond).Observe(12345)
	b.ReportAllocs()
	for b.Loop() {
		sinkDuration = e.RetryInterval(5*clock.Millisecond, 500*clock.Millisecond)
	}
}

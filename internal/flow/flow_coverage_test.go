package flow

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

// TestReturnBandwidthThrottlesNackEmission verifies the return-bandwidth limiter
// (libRIST return-bandwidth, enforced as an interop-safe ristgo enhancement): a
// receiver with a tight return budget spends its burst on the first NACK pass
// and is throttled on a second pass at the SAME instant (no token refill), while
// an unlimited receiver services the next group. Throttled NACKs are left due,
// not dropped, so recovery is only slowed.
func TestReturnBandwidthThrottlesNackEmission(t *testing.T) {
	run := func(retKbps int) uint64 {
		cfg := testConfig()
		cfg.ReturnMaxBitrate = retKbps
		cfg.MaxRetries = 100 // keep entries alive across passes
		f := New(RoleReceiver, cfg)
		f.Feed(0, 0, mkPkt(0, 0, nil))           // start
		f.Feed(1_000, 0, mkPkt(500, 1_000, nil)) // 499 missing (more than one NACK group)
		drainOutputs(f)
		// All entries are due well before the recovery-buffer abandon horizon.
		const now = clock.Timestamp(100_000)
		f.HandleTimer(now, TimerNack)
		f.HandleTimer(now, TimerNack) // same instant: the limiter gets no refill
		return f.Stats().NacksSent
	}
	limited := run(5)   // ~156 NACK-seqs/s, burst 200
	unlimited := run(0) // no return-bandwidth cap

	if limited >= unlimited {
		t.Fatalf("return-bandwidth did not throttle: limited NacksSent %d >= unlimited %d", limited, unlimited)
	}
	if limited > ristMaxNacks {
		t.Fatalf("limited NacksSent %d exceeded one burst (%d) — the limiter did not cap the second pass", limited, ristMaxNacks)
	}
	if unlimited <= ristMaxNacks {
		t.Fatalf("unlimited NacksSent %d did not exceed one group (%d) — the control needs two serviced passes", unlimited, ristMaxNacks)
	}
}

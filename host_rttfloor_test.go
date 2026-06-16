package ristgo

import (
	"testing"
	"time"

	"github.com/zsiec/ristgo/internal/clock"
)

// TestEffectiveRTTBoundsBufferFloor pins libRIST's "rtt_min is too small for the
// buffer size" floor (store_peer_settings): the effective recovery_rtt_min handed
// to the core is raised to recovery_length_min / max_retries when the configured
// rtt_min sits below it. The default config's 5 ms rtt_min must therefore reach
// the core as 50 ms (1000 ms / 20), so the NACK retry cadence and the max_retries
// abandon budget stay commensurate with the playout buffer.
func TestEffectiveRTTBoundsBufferFloor(t *testing.T) {
	ms := func(d time.Duration) clock.Microseconds { return clock.FromDuration(d) }
	tests := []struct {
		name                      string
		rttMin, rttMax, bufferMin time.Duration
		maxRetries                int
		wantMin, wantMax          clock.Microseconds
	}{
		{
			name:   "default raises 5ms to 1000/20=50ms",
			rttMin: 5 * time.Millisecond, rttMax: 500 * time.Millisecond,
			bufferMin: 1000 * time.Millisecond, maxRetries: 20,
			wantMin: ms(50 * time.Millisecond), wantMax: ms(500 * time.Millisecond),
		},
		{
			name:   "tight buffer floor equals configured rtt_min (100/20=5ms)",
			rttMin: 5 * time.Millisecond, rttMax: 500 * time.Millisecond,
			bufferMin: 100 * time.Millisecond, maxRetries: 20,
			wantMin: ms(5 * time.Millisecond), wantMax: ms(500 * time.Millisecond),
		},
		{
			name:   "configured rtt_min above the floor is left alone",
			rttMin: 30 * time.Millisecond, rttMax: 500 * time.Millisecond,
			bufferMin: 100 * time.Millisecond, maxRetries: 20,
			wantMin: ms(30 * time.Millisecond), wantMax: ms(500 * time.Millisecond),
		},
		{
			name:   "floor above rtt_max raises rtt_max to match (degenerate config)",
			rttMin: 5 * time.Millisecond, rttMax: 100 * time.Millisecond,
			bufferMin: 1000 * time.Millisecond, maxRetries: 2,
			wantMin: ms(500 * time.Millisecond), wantMax: ms(500 * time.Millisecond),
		},
		{
			name:   "max_retries zero disables the floor (no divide-by-zero)",
			rttMin: 5 * time.Millisecond, rttMax: 500 * time.Millisecond,
			bufferMin: 1000 * time.Millisecond, maxRetries: 0,
			wantMin: ms(5 * time.Millisecond), wantMax: ms(500 * time.Millisecond),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				RTTMin: tc.rttMin, RTTMax: tc.rttMax,
				BufferMin: tc.bufferMin, MaxRetries: tc.maxRetries,
			}
			gotMin, gotMax := effectiveRTTBounds(cfg)
			if gotMin != tc.wantMin {
				t.Errorf("rttMin = %d us, want %d us", gotMin, tc.wantMin)
			}
			if gotMax != tc.wantMax {
				t.Errorf("rttMax = %d us, want %d us", gotMax, tc.wantMax)
			}
		})
	}
}

// TestToFlowConfigAppliesBufferFloor confirms the floor reaches the deterministic
// core through the real config seam: a validated DefaultConfig (1000 ms buffer,
// 20 retries) hands the flow core a 50 ms rtt_min, while the public cfg.RTTMin
// stays at its reported 5 ms (libRIST does not mutate the user's setting).
func TestToFlowConfigAppliesBufferFloor(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	fc := toFlowConfig(cfg)
	if want := clock.FromDuration(50 * time.Millisecond); fc.RTTMin != want {
		t.Errorf("flow RTTMin = %d us, want %d us (1000ms/20)", fc.RTTMin, want)
	}
	if cfg.RTTMin != DefaultRTTMin {
		t.Errorf("public cfg.RTTMin mutated to %v, want it left at %v", cfg.RTTMin, DefaultRTTMin)
	}
}

package flow

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/rtt"
)

// ms builds a millisecond duration in the core's clock.Microseconds unit.
func ms(n int) clock.Microseconds { return clock.Microseconds(n) * clock.Millisecond }

// windowedReceiver builds a receiver flow with a windowed recovery buffer
// (BufferMin != BufferMax) so dynamic auto-scaling is eligible. Its static
// midpoint is (1000-200)/2 + 200 = 600 ms.
func windowedReceiver() *Flow {
	cfg := DefaultConfig()
	cfg.RecoveryBufferMin = ms(200)
	cfg.RecoveryBufferMax = ms(1000)
	cfg.ReorderBuffer = ms(15)
	cfg.RTTMultiplier = 7
	return New(RoleReceiver, cfg)
}

// converge runs the auto-scaler to a steady value: the decrease is rate-limited
// to 50 ms per recalc (libRIST), so reaching a target below the initial 600 ms
// midpoint takes several recalcs. Loss snapshots after the first call, so with no
// fresh loss the modifier is 1 and the buffer steps monotonically to its clamp.
func converge(f *Flow) {
	prev := clock.Microseconds(-1)
	for i := 0; i < 64 && f.recoveryBuffer != prev; i++ {
		prev = f.recoveryBuffer
		f.autoScaleBuffer()
	}
}

// TestAutoScaleBuffer exercises the receiver recovery-buffer auto-scaling
// (libRIST _librist_receiver_buffer_calc): the gating, the RTT*multiplier+reorder
// sizing, the [min,max] and sender-max clamps, loss-driven growth, the high-loss
// jump, and the rate-limited decrease.
func TestAutoScaleBuffer(t *testing.T) {
	t.Run("no sender max holds the static midpoint", func(t *testing.T) {
		f := windowedReceiver()
		f.est = rtt.New(ms(100))
		f.autoScaleBuffer()
		if f.recoveryBuffer != ms(600) {
			t.Fatalf("buffer = %v, want 600ms (scaling must not activate before a sender max is learned)", f.recoveryBuffer)
		}
	})

	t.Run("scales to rtt*multiplier + reorder", func(t *testing.T) {
		f := windowedReceiver()
		f.SetSenderMaxBuffer(ms(1000))
		f.est = rtt.New(ms(100)) // smoothed 100ms -> 100*7 + 15 = 715ms
		f.autoScaleBuffer()
		if f.recoveryBuffer != ms(715) {
			t.Fatalf("buffer = %v, want 715ms", f.recoveryBuffer)
		}
		if want := clock.Microseconds(float64(ms(715)) * 1.1); f.recoveryBuffer110 != want {
			t.Fatalf("buffer110 = %v, want %v (must track the dynamic buffer)", f.recoveryBuffer110, want)
		}
	})

	t.Run("clamps up to BufferMin", func(t *testing.T) {
		f := windowedReceiver()
		f.SetSenderMaxBuffer(ms(1000))
		f.est = rtt.New(ms(20)) // 20*7 + 15 = 155ms, below the 200ms floor
		converge(f)
		if f.recoveryBuffer != ms(200) {
			t.Fatalf("buffer = %v, want 200ms (clamped to BufferMin)", f.recoveryBuffer)
		}
	})

	t.Run("clamps down to the sender max", func(t *testing.T) {
		f := windowedReceiver()
		f.SetSenderMaxBuffer(ms(500))
		f.est = rtt.New(ms(100)) // 715ms desired, but the sender retains only 500ms
		f.autoScaleBuffer()
		if f.recoveryBuffer != ms(500) {
			t.Fatalf("buffer = %v, want 500ms (clamped to sender max)", f.recoveryBuffer)
		}
	})

	t.Run("sender max below BufferMin disables scaling", func(t *testing.T) {
		f := windowedReceiver()
		f.SetSenderMaxBuffer(ms(100)) // < BufferMin 200ms: libRIST disables negotiation
		f.est = rtt.New(ms(100))
		f.autoScaleBuffer()
		if f.recoveryBuffer != ms(600) {
			t.Fatalf("buffer = %v, want 600ms (sender max below min disables scaling)", f.recoveryBuffer)
		}
	})

	t.Run("loss grows the buffer", func(t *testing.T) {
		f := windowedReceiver()
		f.SetSenderMaxBuffer(ms(1000))
		f.est = rtt.New(ms(50)) // base 50*7 + 15 = 365ms
		converge(f)             // settle to the loss-free base
		if f.recoveryBuffer != ms(365) {
			t.Fatalf("base buffer = %v, want 365ms", f.recoveryBuffer)
		}
		f.stats.Lost += 5 // 5 lost this period -> modifier 1 + 5*0.05 = 1.25
		f.autoScaleBuffer()
		if want := clock.Microseconds(float64(ms(365)) * 1.25); f.recoveryBuffer != want {
			t.Fatalf("buffer = %v, want %v (loss-grown)", f.recoveryBuffer, want)
		}
	})

	t.Run("heavy loss jumps to the sender max", func(t *testing.T) {
		f := windowedReceiver()
		f.SetSenderMaxBuffer(ms(900))
		f.est = rtt.New(ms(50))
		f.autoScaleBuffer() // snapshot
		f.stats.Lost += 30  // > 25 -> has_high_loss
		f.autoScaleBuffer()
		if f.recoveryBuffer != ms(900) {
			t.Fatalf("buffer = %v, want 900ms (heavy-loss jump to sender max)", f.recoveryBuffer)
		}
	})

	t.Run("decrease is rate-limited to 50ms per recalc", func(t *testing.T) {
		f := windowedReceiver()
		f.SetSenderMaxBuffer(ms(1000))
		f.est = rtt.New(ms(100)) // 715ms
		f.autoScaleBuffer()
		f.est = rtt.New(ms(20)) // desired drops to 155ms (-> clamp 200ms), a 515ms fall
		f.autoScaleBuffer()
		if f.recoveryBuffer != ms(665) { // 715 - 50, the single-step decrease cap
			t.Fatalf("buffer = %v, want 665ms (decrease capped at 50ms/recalc)", f.recoveryBuffer)
		}
	})

	t.Run("equal min/max disables scaling", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.RecoveryBufferMin = ms(500)
		cfg.RecoveryBufferMax = ms(500)
		cfg.RTTMultiplier = 7
		f := New(RoleReceiver, cfg)
		f.SetSenderMaxBuffer(ms(1000))
		f.est = rtt.New(ms(100)) // would scale to 715ms if enabled
		f.autoScaleBuffer()
		if f.recoveryBuffer != ms(500) {
			t.Fatalf("buffer = %v, want 500ms (non-windowed buffer must not scale)", f.recoveryBuffer)
		}
	})
}

// TestAvgBufferTime verifies the avg_buffer_time gauge: it reports the constant
// buffer for a static receiver (even before any sample) and the running mean of the
// sampled levels for a windowed one, and 0 on a sender.
func TestAvgBufferTime(t *testing.T) {
	// Static (non-windowed) receiver: the gauge is the constant buffer.
	cfg := DefaultConfig()
	cfg.RecoveryBufferMin = ms(500)
	cfg.RecoveryBufferMax = ms(500)
	f := New(RoleReceiver, cfg)
	if got := f.avgBufferTimeUs(); got != int64(ms(500)) {
		t.Fatalf("pre-sample static = %d, want %d", got, int64(ms(500)))
	}
	for i := 0; i < 4; i++ {
		f.autoScaleBuffer() // samples 500ms each tick, never scales
	}
	if got := f.avgBufferTimeUs(); got != int64(ms(500)) {
		t.Fatalf("static mean = %d, want %d", got, int64(ms(500)))
	}

	// Windowed receiver scaling 600 -> 715ms: the running mean lies between the two
	// sampled levels (600 sampled pre-scale, then 715).
	f = windowedReceiver()
	f.SetSenderMaxBuffer(ms(1000))
	f.est = rtt.New(ms(100))
	f.autoScaleBuffer() // samples 600, grows to 715
	f.autoScaleBuffer() // samples 715
	if got, want := f.avgBufferTimeUs(), (int64(ms(600))+int64(ms(715)))/2; got != want {
		t.Fatalf("windowed mean = %d, want %d", got, want)
	}

	// A sender flow always reports 0.
	if got := New(RoleSender, DefaultConfig()).avgBufferTimeUs(); got != 0 {
		t.Fatalf("sender avg_buffer_time = %d, want 0", got)
	}
}

// TestSetRTTMultiplier verifies the runtime setter (BondedReceiver/Receiver.
// SetRTTMultiplier, libRIST rist_recovery_rtt_multiplier_set): a changed multiplier
// is read live by the next auto-scale pass, and 0 disables scaling.
func TestSetRTTMultiplier(t *testing.T) {
	f := windowedReceiver()
	f.SetSenderMaxBuffer(ms(1000))
	f.est = rtt.New(ms(100)) // mult 7 -> 100*7 + 15 = 715ms
	f.autoScaleBuffer()
	if f.recoveryBuffer != ms(715) {
		t.Fatalf("buffer = %v, want 715ms (mult 7)", f.recoveryBuffer)
	}

	// A runtime change is read live: mult 3 -> 100*3 + 15 = 315ms (within [200,1000]).
	// The decrease is rate-limited to 50ms/recalc, so converge to the new steady value.
	f.SetRTTMultiplier(3)
	converge(f)
	if f.recoveryBuffer != ms(315) {
		t.Fatalf("buffer = %v, want 315ms (mult 3 after runtime set)", f.recoveryBuffer)
	}

	// 0 disables auto-scaling: the buffer freezes wherever it was.
	f.SetRTTMultiplier(0)
	f.est = rtt.New(ms(500)) // would be huge if scaling were live
	f.autoScaleBuffer()
	if f.recoveryBuffer != ms(315) {
		t.Fatalf("buffer = %v, want 315ms (mult 0 freezes the buffer)", f.recoveryBuffer)
	}
}

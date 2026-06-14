package adapt

import "testing"

// simCfg is a controller config sized for the closed-loop simulation (smaller
// ceiling and step so the AIMD sawtooth tracks the modeled capacities tightly).
func simCfg() ControllerConfig {
	return ControllerConfig{
		MinKbps:      500,
		MaxKbps:      15000,
		InitialKbps:  15000,
		TargetLoss:   0.01,
		IncreaseKbps: 200,
		DecreaseGain: 2.0,
	}
}

// TestControllerMonotoneInLoss is the headline property (TR-06-4 §6): from one
// fixed starting rate, a larger reported loss must never yield a higher target
// than a smaller loss. Checked across a sweep of loss values.
func TestControllerMonotoneInLoss(t *testing.T) {
	losses := []float64{0, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0}
	prev := -1
	for _, loss := range losses {
		c := NewController(simCfg()) // same start each time
		got := c.Observe(loss)
		if prev >= 0 && got > prev {
			t.Fatalf("non-monotone: loss %.3f -> %d kbps, but a lower loss gave %d kbps", loss, got, prev)
		}
		prev = got
	}
}

// TestControllerProbesUpWhenClean checks repeated clean reports drive the rate
// up additively toward MaxKbps (and never past it).
func TestControllerProbesUpWhenClean(t *testing.T) {
	cfg := simCfg()
	cfg.InitialKbps = cfg.MinKbps
	c := NewController(cfg)
	last := c.Target()
	for i := 0; i < 1000; i++ {
		got := c.Observe(0)
		if got < last {
			t.Fatalf("clean report decreased the rate: %d -> %d", last, got)
		}
		last = got
	}
	if last != cfg.MaxKbps {
		t.Fatalf("clean probing converged at %d kbps, want MaxKbps %d", last, cfg.MaxKbps)
	}
}

// TestControllerClamp checks the target never escapes [MinKbps, MaxKbps].
func TestControllerClamp(t *testing.T) {
	cfg := simCfg()
	c := NewController(cfg)
	// Hammer with heavy loss, then clean, many times; the target must stay in
	// range throughout.
	for i := 0; i < 2000; i++ {
		var got int
		if i%2 == 0 {
			got = c.Observe(0.9)
		} else {
			got = c.Observe(0)
		}
		if got < cfg.MinKbps || got > cfg.MaxKbps {
			t.Fatalf("target %d out of [%d, %d] at step %d", got, cfg.MinKbps, cfg.MaxKbps, i)
		}
	}
}

// TestControllerNormalizesBadConfig checks a misconfigured controller (floor
// above ceiling, negative floor, negative step) is normalized so the target
// always stays within sane, consistent bounds rather than escaping them.
func TestControllerNormalizesBadConfig(t *testing.T) {
	// MinKbps > MaxKbps: degenerates to a fixed rate at the floor.
	c := NewController(ControllerConfig{MinKbps: 10000, MaxKbps: 5000, InitialKbps: 1, TargetLoss: 0.01, IncreaseKbps: 100, DecreaseGain: 2})
	for i := 0; i < 50; i++ {
		got := c.Observe(0.5) // heavy loss would normally cut below the floor
		if got != 10000 {
			t.Fatalf("inverted-config target = %d, want a fixed 10000 (floor==ceiling)", got)
		}
	}
	// Negative floor is treated as 0; negative step is treated as 0 (no increase).
	c2 := NewController(ControllerConfig{MinKbps: -5, MaxKbps: 1000, InitialKbps: 500, TargetLoss: 0.01, IncreaseKbps: -10, DecreaseGain: 2})
	if got := c2.Observe(0); got != 500 {
		t.Fatalf("negative IncreaseKbps should not change the rate: got %d, want 500", got)
	}
	if got := c2.Observe(0.9); got < 0 {
		t.Fatalf("negative-floor config produced a negative target: %d", got)
	}
}

// simLink models a constant-capacity link: at or below capacity there is no
// loss; above it, the loss fraction is the overage divided by the offered rate.
func simLink(rate, capacity int) float64 {
	if rate <= capacity {
		return 0
	}
	return float64(rate-capacity) / float64(rate)
}

// convergedRate runs the controller against a fixed-capacity link and returns
// the mean target over the final tail of the run.
func convergedRate(capacity, steps, tail int) float64 {
	c := NewController(simCfg())
	var sum float64
	cnt := 0
	for i := 0; i < steps; i++ {
		c.Observe(simLink(c.Target(), capacity))
		if i >= steps-tail {
			sum += float64(c.Target())
			cnt++
		}
	}
	return sum / float64(cnt)
}

// TestControllerClosedLoopTracksCapacity is the closed-loop gate: driven by a
// simulated link, the controller's steady rate tracks the link capacity and is
// monotone in it (more capacity => less loss => higher steady rate). This is the
// end-to-end expression of "rate target monotone in loss".
func TestControllerClosedLoopTracksCapacity(t *testing.T) {
	caps := []int{2000, 5000, 10000}
	const steps, tail = 600, 200
	var prev float64 = -1
	for _, capacity := range caps {
		mean := convergedRate(capacity, steps, tail)
		// Tracks the capacity within a band (AIMD oscillates around it).
		if mean < 0.6*float64(capacity) || mean > 1.4*float64(capacity) {
			t.Fatalf("capacity %d: steady rate %.0f kbps outside [0.6, 1.4]x", capacity, mean)
		}
		// Monotone non-decreasing in capacity (== monotone non-increasing in loss).
		if prev >= 0 && mean < prev {
			t.Fatalf("non-monotone steady rate: capacity %d -> %.0f, lower capacity gave %.0f", capacity, mean, prev)
		}
		prev = mean
	}
}

// TestObserveLQMUsesUnrecoveredSignal locks in the TR-06-4 §6.1 two-signal
// rule: probe up only when unrecovered==0 AND original loss <= target; back off
// when unrecovered>0 even if raw loss is below target; and hold (do not probe
// up) on a zero-accounting stall report.
func TestObserveLQMUsesUnrecoveredSignal(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.InitialKbps = 50_000
	cfg.MaxKbps = 100_000

	// Thin loss (under the 0.5% target) but a packet went unrecovered: must NOT
	// probe up — it must back off.
	c := NewController(cfg)
	got := c.ObserveLQM(LQM{SourceReceived: 100_000, OriginalLost: 100, Unrecovered: 1})
	if got >= 50_000 {
		t.Errorf("target=%d after unrecovered>0 with thin loss; want a decrease below 50000", got)
	}

	// Same thin loss but everything recovered (unrecovered==0, loss<=target):
	// probe up.
	c = NewController(cfg)
	got = c.ObserveLQM(LQM{SourceReceived: 100_000, OriginalLost: 100, Unrecovered: 0})
	if got <= 50_000 {
		t.Errorf("target=%d after clean recovery; want an increase above 50000", got)
	}

	// Total stall: no packets accounted for. Must hold, not ratchet up.
	c = NewController(cfg)
	got = c.ObserveLQM(LQM{})
	if got != 50_000 {
		t.Errorf("target=%d on a zero-accounting stall report; want held at 50000", got)
	}
}

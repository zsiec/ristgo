// Package rtt implements the libRIST round-trip-time state as a pure value
// type: the eight_times_rtt EWMA (weight 1/8, truncating integer division)
// and the raw last_rtt sample, the [rttMin, rttMax] clamp applied at every
// read, and the 1.1x NACK retry interval derived from the clamped EWMA.
// libRIST keeps both values per peer and uses each for a different job — the
// EWMA for the receiver's NACK retry cadence, the raw last sample for the
// sender's retransmit gate — and this package preserves that split.
//
// Every arithmetic step replicates libRIST v0.2.18 exactly (integer
// semantics included):
//
//   - init:    eight_times_rtt = recovery_rtt_min * 8
//     (init_peer_settings)
//   - observe: eight_times_rtt -= eight_times_rtt / 8;
//     eight_times_rtt += sample
//   - read:    rtt = eight_times_rtt / 8, then clamp to
//     [recovery_rtt_min, recovery_rtt_max]
//     (rist_process_nack)
//   - retry:   next_nack = now + (uint64_t)(rtt * 1.1)
//
// libRIST stores eight_times_rtt as a uint64_t of NTP ticks
// (RIST_CLOCK ticks per millisecond); this package uses clock.Microseconds
// instead.
// The estimator arithmetic is unit-agnostic — only truncating division by
// 8 and the 1.1 multiply touch the values — so results correspond exactly
// modulo the unit choice. Values stay non-negative by construction, so Go's
// truncating signed division matches C's unsigned division at every step.
//
// An Estimator is an immutable value: Observe returns the updated estimator
// rather than mutating in place, no method allocates, and time never enters
// implicitly — the package is safe for use inside the deterministic
// internal/flow core. Hold one Estimator per path (libRIST keeps one
// eight_times_rtt per peer).
package rtt

import "github.com/zsiec/ristgo/internal/clock"

// ristRTTMinFloorMs is libRIST's RIST_RTT_MIN: the hard 3 ms floor enforced on
// the effective recovery_rtt_min. A configured rtt_min below this is raised to
// 3 ms before it bounds the smoothed or raw RTT, so cold-start NACK retry
// spacing (and the sender's retransmit gate) never collapses to a sub-3 ms
// interval — roughly an order of magnitude too tight — before the EWMA climbs.
const ristRTTMinFloorMs = 3

// rttMinFloor is the 3 ms RIST_RTT_MIN floor in clock.Microseconds.
const rttMinFloor = clock.Microseconds(ristRTTMinFloorMs) * clock.Millisecond

// effectiveRTTMin raises a configured rtt_min to the 3 ms RIST_RTT_MIN hard
// floor. It is applied at every clamped read (Clamped/LastClamped, and so
// RetryInterval), so the floor holds wherever the RTT actually bounds a value,
// regardless of the configured rtt_min. The raw New seed is left unfloored to
// document libRIST's exact init arithmetic.
func effectiveRTTMin(rttMin clock.Microseconds) clock.Microseconds {
	if rttMin < rttMinFloor {
		return rttMinFloor
	}
	return rttMin
}

// Estimator holds the two RTT values libRIST keeps per peer: the
// eight_times_rtt EWMA and the most recent raw sample (last_rtt). libRIST
// uses them for different jobs — the EWMA paces the receiver's NACK retry
// interval (a stable estimate avoids cadence oscillation), while the raw
// last sample drives the sender's retransmit gate ("is the prior retransmit
// still in flight?", which the freshest sample answers best). This type keeps
// both so each call site can match libRIST exactly.
//
// The zero value behaves like New(0): smoothed RTT 0 and no sample yet, both
// of which the clamped readers pin to rttMin — the same cold-start reading
// libRIST gets before the first echo response. Proper construction is
// New(rttMin), matching libRIST's init_peer_settings.
type Estimator struct {
	// eightTimesRTT is libRIST's peer->eight_times_rtt: eight times the
	// smoothed RTT, kept premultiplied so the 1/8-weight EWMA needs only
	// integer ops.
	eightTimesRTT clock.Microseconds

	// lastSample is libRIST's peer->last_rtt: the most recent RTT sample,
	// raw (not smoothed) and pinned non-negative. It is 0 until the first
	// Observe, exactly as libRIST leaves last_rtt at 0 before the first echo
	// response; the clamped reader then pins that 0 up to rttMin.
	lastSample clock.Microseconds
}

// New returns an Estimator seeded for cold start:
// eight_times_rtt = rttMin * 8, so the first Smoothed() reading is exactly
// rttMin (init_peer_settings). The seed replicates libRIST's raw init
// arithmetic verbatim; the 3 ms RIST_RTT_MIN hard floor is applied later, at
// every clamped read (Clamped/LastClamped), so a configured rtt_min below 3 ms
// still yields an effective floor of 3 ms wherever the value is actually used.
//
// A negative rttMin is pinned to 0. libRIST cannot express one
// (recovery_rtt_min is unsigned), and Config validation rejects it before
// it reaches this package; pinning keeps the no-panic-on-input contract.
func New(rttMin clock.Microseconds) Estimator {
	if rttMin < 0 {
		rttMin = 0
	}
	return Estimator{eightTimesRTT: rttMin * 8}
}

// Observe folds one RTT sample into the EWMA and returns the updated
// estimator. The arithmetic is exactly libRIST's:
//
//	eight_times_rtt -= eight_times_rtt / 8;   // truncating division
//	eight_times_rtt += sample;
//
// which is a weight-1/8 exponential moving average kept premultiplied by 8.
//
// A negative sample is pinned to 0. libRIST cannot produce one: its
// samples are unsigned, and calculate_rtt_delay returns 0 whenever the
// echo timestamps would go negative. Pinning applies the same guard at this
// boundary.
func (e Estimator) Observe(sample clock.Microseconds) Estimator {
	if sample < 0 {
		sample = 0
	}
	e.lastSample = sample
	e.eightTimesRTT -= e.eightTimesRTT / 8
	e.eightTimesRTT += sample
	return e
}

// Smoothed returns the current smoothed RTT estimate,
// eight_times_rtt / 8 with truncating division, exactly as libRIST reads
// it.
func (e Estimator) Smoothed() clock.Microseconds {
	return e.eightTimesRTT / 8
}

// clamp applies libRIST's exact RTT-clamp branch structure:
//
//	if (rtt < rtt_min)      rtt = rtt_min;
//	else if (rtt > rtt_max) rtt = rtt_max;
//
// The 3 ms RIST_RTT_MIN floor is applied by the Clamped/LastClamped callers
// (which raise rttMin via effectiveRTTMin), not here, so this helper documents
// the bare libRIST branch — including the else-if's load-bearing behavior for
// degenerate bounds: when rttMin > rttMax (rejected by Config validation, but
// accepted here without panicking) a value below rttMin returns rttMin even
// though it exceeds rttMax, just as the C does.
func clamp(rtt, rttMin, rttMax clock.Microseconds) clock.Microseconds {
	if rtt < rttMin {
		rtt = rttMin
	} else if rtt > rttMax {
		rtt = rttMax
	}
	return rtt
}

// Clamped returns Smoothed() clamped to [rttMin, rttMax], where rttMin is first
// raised to the 3 ms RIST_RTT_MIN hard floor (effectiveRTTMin). This is the
// value libRIST's receiver uses for the NACK retry interval; the floor keeps
// cold-start retry spacing from collapsing below 3 ms before the EWMA climbs.
func (e Estimator) Clamped(rttMin, rttMax clock.Microseconds) clock.Microseconds {
	return clamp(e.Smoothed(), effectiveRTTMin(rttMin), rttMax)
}

// Last returns the most recent raw RTT sample (libRIST peer->last_rtt), 0
// before the first Observe.
func (e Estimator) Last() clock.Microseconds { return e.lastSample }

// LastClamped returns the most recent raw sample clamped to [rttMin, rttMax],
// with rttMin first raised to the 3 ms RIST_RTT_MIN hard floor (effectiveRTTMin).
// This is the value libRIST's sender uses for the per-packet retransmit gate
// (peer->last_rtt clamped): deliberately the freshest sample, not the EWMA, so
// the gate tracks the current round-trip time. Before the first echo response
// lastSample is 0, which clamps up to the effective rtt_min (>= 3 ms), matching
// libRIST's cold-start gate.
func (e Estimator) LastClamped(rttMin, rttMax clock.Microseconds) clock.Microseconds {
	return clamp(e.lastSample, effectiveRTTMin(rttMin), rttMax)
}

// RetryInterval returns the NACK retry spacing: 1.1 times Clamped(rttMin,
// rttMax), computed exactly as libRIST does:
//
//	b->next_nack = now + (uint64_t)(rtt * 1.1);
//
// i.e. a float64 multiply by the double literal 1.1 followed by truncation
// toward zero — Go's float64-to-integer conversion and C's (uint64_t) cast
// truncate identically. For every value this package can produce
// (non-negative, far below 2^49 microseconds) the result equals the pure
// integer expression rtt + rtt/10; the float form is kept so the semantics
// are literally the C's. The first attempt for a missing seq is scheduled
// at insertionTime + Smoothed() instead — that cadence lives in
// internal/flow; this method only supplies the retry spacing.
func (e Estimator) RetryInterval(rttMin, rttMax clock.Microseconds) clock.Microseconds {
	return clock.Microseconds(float64(e.Clamped(rttMin, rttMax)) * 1.1)
}

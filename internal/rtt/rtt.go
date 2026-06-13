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
//     (src/rist-common.c:374, init_peer_settings)
//   - observe: eight_times_rtt -= eight_times_rtt / 8;
//     eight_times_rtt += sample
//     (src/rist-common.c:2208-2209; same update at 2260-2261 and
//     2320-2321)
//   - read:    rtt = eight_times_rtt / 8, then clamp to
//     [recovery_rtt_min, recovery_rtt_max]
//     (src/rist-common.c:863-868, rist_process_nack; also 2126-2132)
//   - retry:   next_nack = now + (uint64_t)(rtt * 1.1)
//     (src/rist-common.c:880)
//
// libRIST stores eight_times_rtt as a uint64_t of NTP ticks
// (src/rist-private.h:585, RIST_CLOCK ticks per millisecond,
// src/proto/rist_time.h:9); this package uses clock.Microseconds instead.
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
// New(rttMin), matching libRIST's init_peer_settings (src/rist-common.c:374).
type Estimator struct {
	// eightTimesRTT is libRIST's peer->eight_times_rtt
	// (src/rist-private.h:585): eight times the smoothed RTT, kept
	// premultiplied so the 1/8-weight EWMA needs only integer ops.
	eightTimesRTT clock.Microseconds

	// lastSample is libRIST's peer->last_rtt: the most recent RTT sample,
	// raw (not smoothed) and pinned non-negative. It is 0 until the first
	// Observe, exactly as libRIST leaves last_rtt at 0 before the first echo
	// response; the clamped reader then pins that 0 up to rttMin.
	lastSample clock.Microseconds
}

// New returns an Estimator seeded for cold start:
// eight_times_rtt = rttMin * 8, so the first Smoothed() reading is exactly
// rttMin (src/rist-common.c:374, init_peer_settings).
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
// estimator. The arithmetic is exactly libRIST's
// (src/rist-common.c:2208-2209):
//
//	eight_times_rtt -= eight_times_rtt / 8;   // truncating division
//	eight_times_rtt += sample;
//
// which is a weight-1/8 exponential moving average kept premultiplied by 8.
//
// A negative sample is pinned to 0. libRIST cannot produce one: its
// samples are unsigned, and calculate_rtt_delay returns 0 whenever the
// echo timestamps would go negative (src/proto/rist_time.c:96-103).
// Pinning applies the same guard at this boundary.
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
// it (src/rist-common.c:863 and 2126).
func (e Estimator) Smoothed() clock.Microseconds {
	return e.eightTimesRTT / 8
}

// clamp applies libRIST's exact RTT-clamp branch structure
// (src/rist-common.c:863-868 and src/udp.c:1255-1258):
//
//	if (rtt < rtt_min)      rtt = rtt_min;
//	else if (rtt > rtt_max) rtt = rtt_max;
//
// The else-if is load-bearing for degenerate bounds: when rttMin > rttMax
// (rejected by Config validation, but accepted here without panicking) a
// value below rttMin returns rttMin even though it exceeds rttMax, just as
// the C does.
func clamp(rtt, rttMin, rttMax clock.Microseconds) clock.Microseconds {
	if rtt < rttMin {
		rtt = rttMin
	} else if rtt > rttMax {
		rtt = rttMax
	}
	return rtt
}

// Clamped returns Smoothed() clamped to [rttMin, rttMax]. This is the value
// libRIST's receiver uses for the NACK retry interval (src/rist-common.c:863).
func (e Estimator) Clamped(rttMin, rttMax clock.Microseconds) clock.Microseconds {
	return clamp(e.Smoothed(), rttMin, rttMax)
}

// Last returns the most recent raw RTT sample (libRIST peer->last_rtt), 0
// before the first Observe.
func (e Estimator) Last() clock.Microseconds { return e.lastSample }

// LastClamped returns the most recent raw sample clamped to [rttMin, rttMax].
// This is the value libRIST's sender uses for the per-packet retransmit gate
// (src/udp.c:1254-1262, peer->last_rtt clamped): deliberately the freshest
// sample, not the EWMA, so the gate tracks the current round-trip time. Before
// the first echo response lastSample is 0, which clamps up to rttMin, matching
// libRIST's cold-start gate.
func (e Estimator) LastClamped(rttMin, rttMax clock.Microseconds) clock.Microseconds {
	return clamp(e.lastSample, rttMin, rttMax)
}

// RetryInterval returns the NACK retry spacing: 1.1 times Clamped(rttMin,
// rttMax), computed exactly as libRIST does (src/rist-common.c:880):
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

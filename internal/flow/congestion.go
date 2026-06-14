package flow

import "github.com/zsiec/ristgo/internal/clock"

// Congestion control + NACK pacing, ported from libRIST v0.2.18 and kept pure:
// time enters only via explicit `now clock.Timestamp` arguments, so the whole
// mechanism lives in the sans-I/O core without a clock read.

// CongestionMode selects the sender's recovery_maxbitrate pacing behaviour,
// mirroring libRIST's congestion_control setting.
type CongestionMode uint8

const (
	// CongestionOff disables the sender bandwidth gate (libRIST OFF).
	CongestionOff CongestionMode = iota
	// CongestionNormal paces retransmits against recovery_maxbitrate using the
	// slow (1s) data-rate EWMA plus the fast (100ms) retry-rate EWMA — the
	// default (libRIST congestion_control = NORMAL).
	CongestionNormal
	// CongestionAggressive uses the fast EWMA for both the data and retry rate,
	// reacting quicker but pacing harder (libRIST AGGRESSIVE).
	CongestionAggressive
)

// libRIST congestion-control constants.
const (
	// ristHeaderOverheadBytes is sizeof(rist_gre_seq)+sizeof(rist_rtp_hdr)+
	// sizeof(uint32) = 8+12+4, the per-packet overhead libRIST divides by when
	// sizing missing_counter_max and estimating wire bytes.
	ristHeaderOverheadBytes = 24

	// ristNackMtuAssumed is the fixed MTU libRIST assumes in the
	// max_nacksperloop derivation.
	ristNackMtuAssumed = 1400

	// ristMaxJitterMs is RIST_MAX_JITTER, the 5 ms receiver-loop bound used in
	// the max_nacksperloop derivation.
	ristMaxJitterMs = 5

	// ristMaxNacks is RIST_MAX_NACKS: the cap on sequence numbers in a single
	// emitted NackRequest (libRIST's receiver_nack_output maxcounter).
	ristMaxNacks = 200

	// bitrateSlowWindowUs / bitrateFastWindowUs are the EWMA window lengths
	// (1 s and 100 ms) libRIST uses for eight_times_bitrate / _fast.
	bitrateSlowWindowUs = 1_000_000
	bitrateFastWindowUs = 100_000
)

// deriveMissingCounterMax replicates libRIST init_peer_settings:
//
//	missing_counter_max = recovery_buffer_ms * max(1, recovery_maxbitrate/1000) / 24
//
// (recovery_maxbitrate is in kbps, so /1000 is kbps->Mbps floored at 1). With
// the defaults (1000 ms, 100000 kbps) this is 1000*100/24 = 4166. It bounds how
// many missing entries the receiver queues before it stops marking new gaps —
// the buffer-bloat / overflow guard.
func deriveMissingCounterMax(cfg Config) uint32 {
	recoveryMs := int64(cfg.RecoveryBuffer()) / int64(clock.Millisecond)
	mbps := int64(cfg.RecoveryMaxBitrate) / 1000
	if mbps < 1 {
		mbps = 1
	}
	v := recoveryMs * mbps / ristHeaderOverheadBytes
	if v < 0 {
		return 0
	}
	return uint32(v)
}

// deriveMaxNacksPerLoop replicates libRIST init_peer_settings (sender branch):
//
//	n = recovery_maxbitrate(kbps) * 5 / (8*1400)   // packets fitting 5ms at maxrate
//	n = n * 1000 / recovery_length_max(ms)
//	if n == 0 { n = 1 }
//	max_nacksperloop = n * 2                        // "effective buffer is 50%"
//
// With the defaults (100000 kbps, 1000 ms) this is 88. It caps the number of
// retransmissions actually emitted per sender service pass.
func deriveMaxNacksPerLoop(cfg Config) int {
	kbps := int64(cfg.RecoveryMaxBitrate)
	if kbps <= 0 {
		kbps = 100000
	}
	bufMaxMs := int64(cfg.RecoveryBufferMax) / int64(clock.Millisecond)
	if bufMaxMs <= 0 {
		bufMaxMs = 1000
	}
	n := kbps * ristMaxJitterMs / (8 * ristNackMtuAssumed)
	n = n * 1000 / bufMaxMs
	if n == 0 {
		n = 1
	}
	return int(n * 2)
}

// bitrateEWMA tracks libRIST's eight_times_bitrate / eight_times_bitrate_fast
// pair: two 1/8-weight exponential moving averages of the byte rate over a slow
// (1 s) and a fast (100 ms) window, kept premultiplied by 8. It is fed the
// on-wire byte count of each emitted packet (and a zero-length refresh so the
// window-expiry decay fires between packets), and reports the smoothed bit rate.
// Time enters only via the explicit now argument.
type bitrateEWMA struct {
	bytesSlow, bytesFast int64
	lastSlow, lastFast   clock.Timestamp
	eightTimesSlow       int64 // smoothed bits/sec * 8, 1 s window
	eightTimesFast       int64 // smoothed bits/sec * 8, 100 ms window
	seeded               bool
}

// feed folds n on-wire bytes observed at now into both windows. n == 0 performs
// only the window-expiry decay (libRIST refreshes with len 0 at the top of
// rist_retry_dequeue so a stale-but-high estimate decays between retransmits).
func (b *bitrateEWMA) feed(now clock.Timestamp, n int) {
	if !b.seeded {
		b.lastSlow, b.lastFast, b.seeded = now, now, true
	}
	b.bytesSlow += int64(n)
	b.bytesFast += int64(n)
	if elapsed := int64(now.Sub(b.lastSlow)); elapsed >= bitrateSlowWindowUs {
		sample := 8 * b.bytesSlow * 1_000_000 / elapsed // bits/sec over the window
		b.eightTimesSlow += sample - b.eightTimesSlow/8 // EWMA, weight 1/8
		b.lastSlow = now
		b.bytesSlow = 0
	}
	if elapsed := int64(now.Sub(b.lastFast)); elapsed >= bitrateFastWindowUs {
		sample := 8 * b.bytesFast * 1_000_000 / elapsed
		b.eightTimesFast += sample - b.eightTimesFast/8
		b.lastFast = now
		b.bytesFast = 0
	}
}

// slowBps and fastBps return the smoothed bit rates (eight_times_* / 8).
func (b *bitrateEWMA) slowBps() int64 { return b.eightTimesSlow / 8 }
func (b *bitrateEWMA) fastBps() int64 { return b.eightTimesFast / 8 }

// overBudget reports whether emitting another packet would exceed
// recovery_maxbitrate under the configured congestion-control mode: current
// bitrate = data-rate + retry-rate, compared against recovery_maxbitrate*1000
// (kbps -> bps). The mode selects which window each rate reads (NORMAL: data
// slow + retry fast; AGGRESSIVE: both fast). CongestionOff never gates.
func overBudget(mode CongestionMode, data, retry *bitrateEWMA, maxKbps int) bool {
	switch mode {
	case CongestionOff:
		return false
	case CongestionAggressive:
		return data.fastBps()+retry.fastBps() > int64(maxKbps)*1000
	default: // CongestionNormal
		return data.slowBps()+retry.fastBps() > int64(maxKbps)*1000
	}
}

// wireBytes estimates the on-wire UDP-payload size of a media packet from its
// media payload length plus the RIST per-packet header overhead, for the
// bitrate EWMAs. It is an estimate (the exact framing is the codec's), which is
// sufficient for the recovery_maxbitrate pacing comparison.
func wireBytes(payloadLen int) int { return payloadLen + ristHeaderOverheadBytes }

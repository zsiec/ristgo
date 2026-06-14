package flow

import (
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// senderSlot is one entry of the sender history ring: a transmitted packet
// retained so it can be re-sent on NACK. It mirrors the libRIST
// struct rist_buffer fields the retransmit path reads (seq_rtp, source_time,
// transmit_count, last_retry_request).
type senderSlot struct {
	// payload is the retained media payload, re-sent verbatim on retransmit
	// (the producer must not mutate it after PushApp; see the package
	// ownership note).
	payload []byte

	// sourceTime is the NTP-64 media timestamp stamped at first send and
	// repeated unchanged on every retransmit, so the receiver maps a
	// recovered packet onto its original playout slot.
	sourceTime uint64

	// seq is the 32-bit sequence occupying this slot; a NACK whose seq does
	// not match means the entry has aged out (the ring wrapped) and the
	// request is unserviceable.
	seq uint32

	// transmitCount is the number of retransmissions so far (the first
	// transmission is not counted). The packet is abandoned once it reaches
	// MaxRetries (libRIST buffer->transmit_count vs max_retries).
	transmitCount int

	// lastRetry is the instant of the most recent retransmission; the gate
	// suppresses another within one clamped RTT (libRIST
	// buffer->last_retry_request). Meaningful only when retried is true.
	lastRetry clock.Timestamp

	// retried reports whether lastRetry has been set, mirroring libRIST's
	// `last_retry_request != 0` guard: the first retransmit is never gated.
	retried bool

	// state is slotEmpty or slotFilled.
	state slotState
}

// senderState is the sender half's mutable state.
type senderState struct {
	ring []senderSlot
	mask uint32

	// started reports whether the first PushApp has armed the RTT-echo
	// schedule.
	started bool

	// ssrc is the base (even) flow SSRC stamped into every outgoing
	// MediaPacket; the codec sets its LSB on retransmissions, never the core
	// (hdr->rtp.ssrc = adv_flow_id | 0x01).
	ssrc uint32

	// nextSeq is the 32-bit sequence assigned to the next PushApp packet,
	// incrementing by one per packet. The codec narrows it to the 16-bit RTP
	// wire field; the core works in 32 bits throughout.
	nextSeq uint32

	// txPath is the network path first transmissions and retransmissions
	// leave on. Single-path this stage (always 0); multi-path transmission
	// (identical packets on N paths) is bonding's job (WP8).
	txPath uint8

	// dataBW and retryBW are the 1/8-weight bitrate EWMAs that drive the
	// recovery_maxbitrate pacing gate: dataBW is fed every first transmission,
	// retryBW every emitted retransmission (libRIST's cli_bw / retry_bw).
	dataBW  bitrateEWMA
	retryBW bitrateEWMA
}

// pushApp is the sender-role body of PushApp: assign the next sequence, store
// the packet in the history ring, and emit its first transmission. It mirrors
// rist_sender_enqueue followed by the data send.
func (f *Flow) pushApp(now clock.Timestamp, payload []byte) {
	s := &f.sender
	if !s.started {
		s.started = true
		// Originate RTT echo requests so the retransmit gate has a real RTT.
		// libRIST's sender gates origination on peer->echo_enabled, which
		// flips true only after an inbound echo req/resp; the deterministic
		// core has no inbound-echo precondition to track, so origination is
		// intentionally ungated. This matches libRIST end-to-end because its
		// receiver originates echo requests unconditionally, flipping the
		// peer sender's echo_enabled within one cadence.
		f.outputs.push(SetTimer{ID: TimerRttEcho, Deadline: now.Add(rttEchoInterval)})
	}

	seqn := s.nextSeq
	s.nextSeq++
	sourceTime := uint64(clock.NTPTimeFromTimestamp(now))

	sl := &s.ring[seqn&s.mask]
	// Lazy eviction: a new sequence reusing this slot simply overwrites the
	// stale entry, exactly as libRIST's ring overwrites aged packets. A
	// later NACK for the overwritten sequence finds a mismatched slot and is
	// reported unserviceable.
	sl.state = slotFilled
	sl.seq = seqn
	sl.sourceTime = sourceTime
	sl.payload = payload
	sl.transmitCount = 0
	sl.retried = false
	sl.lastRetry = 0

	f.outputs.push(SendMedia{
		Path: s.txPath,
		Pkt: wire.MediaPacket{
			Seq:        seqn,
			SourceTime: sourceTime,
			SSRC:       s.ssrc,
			Payload:    payload,
			Retransmit: false,
			PathID:     s.txPath,
		},
	})
	s.dataBW.feed(now, wireBytes(len(payload))) // recovery_maxbitrate data-rate EWMA
	f.stats.Sent++
}

// serviceNack retransmits every requested sequence still resendable, applying
// the libRIST sender gates in libRIST's own evaluation order — the RTT/bloat
// suppression gate (rist_retry_enqueue) first, then the rist_retry_dequeue
// gates in their own order (bandwidth cap before the max-retries cap):
//
//   - slot empty or holding a different seq -> aged out, unserviceable
//     (RetransmitSkipped);
//   - last retransmit < one clamped RTT ago (2*RTT under AGGRESSIVE) ->
//     suppressed (RetransmitSuppressed);
//   - over the recovery_maxbitrate ceiling  -> BandwidthSkipped;
//   - transmitCount >= MaxRetries           -> abandoned (RetransmitExhausted);
//   - otherwise                             -> re-send with Retransmit set.
//
// Evaluating suppression before the dequeue gates matches libRIST's counter
// attribution: a sequence both past MaxRetries and re-NACKed within one RTT is
// counted suppressed (libRIST increments bloat_skip at enqueue and never
// reaches the dequeue cap), not exhausted. Within the dequeue gates the
// bandwidth cap precedes the max-retries cap, mirroring rist_retry_dequeue
// (bandwidth_skip then the transmit_count >= max_retries retrans_skip), so a
// sequence both over budget and past MaxRetries is attributed BandwidthSkipped.
// The outcome (no re-send) is the same either way; only the stat differs.
//
// The gate clamps the most recent raw RTT sample (libRIST peer->last_rtt),
// deliberately the freshest sample rather than the EWMA the receiver uses for
// its retry interval — libRIST splits the two and so do we (see internal/rtt).
//
// Two libRIST gates have no analog here because this core services NACKs
// synchronously (no asynchronous retry queue): retry_queued guards a request
// already sitting in the queue, and the retry-age gate (retry_age >
// recovery_length_max) measures queue dwell time. Both would read ~0 when the
// retransmit is emitted within the same call, so last_retry_request alone is
// the gate.
//
// Congestion control (libRIST congestion_control): before emitting a
// retransmit the sender checks the recovery_maxbitrate bandwidth gate
// (data-rate + retry-rate vs recovery_maxbitrate*1000); over budget, the entry
// is left resendable and counted in BandwidthSkipped (libRIST's bandwidth_skip,
// which does NOT advance transmit_count). The number of retransmits actually
// emitted in one pass is capped at maxNacksPerLoop (libRIST sender_send_nacks);
// remaining sequences are dropped this pass and re-NACKed by the receiver.
// min_retries is unused on the sender — libRIST validates it at config time but
// never consults it in the retransmit decision.
func (f *Flow) serviceNack(now clock.Timestamp, req wire.NackRequest) {
	s := &f.sender
	rtt := f.est.LastClamped(f.cfg.RTTMin, f.cfg.RTTMax)
	if f.cfg.CongestionControl == CongestionAggressive {
		// Aggressive congestion control allows a retransmit only every 2*RTT
		// (libRIST rist_retry_enqueue doubles the suppression spacing under
		// AGGRESSIVE). NORMAL (the default) keeps the 1*RTT spacing.
		rtt *= 2
	}
	// Refresh the bitrate windows so a stale-but-high estimate decays even when
	// no new bytes have flowed since the last pass (libRIST refreshes with len 0
	// at the top of rist_retry_dequeue).
	s.dataBW.feed(now, 0)
	s.retryBW.feed(now, 0)
	emitted := 0
	for _, missing := range req.Missing {
		sl := &s.ring[missing&s.mask]
		switch {
		case sl.state != slotFilled || sl.seq != missing:
			f.stats.RetransmitSkipped++
		case sl.retried && now.Sub(sl.lastRetry) < rtt:
			f.stats.RetransmitSuppressed++
		case overBudget(f.cfg.CongestionControl, &s.dataBW, &s.retryBW, f.cfg.RecoveryMaxBitrate):
			// Over the recovery_maxbitrate ceiling: refuse without advancing the
			// retry state, so the receiver re-NACKs and we accept it once the
			// rate decays (libRIST returns before touching transmit_count). The
			// bandwidth gate is evaluated BEFORE the max-retries cap, matching
			// libRIST's rist_retry_dequeue order (bandwidth_skip then the
			// transmit_count >= max_retries retrans_skip).
			f.stats.BandwidthSkipped++
		case sl.transmitCount >= f.cfg.MaxRetries:
			f.stats.RetransmitExhausted++
		default:
			sl.lastRetry = now
			sl.retried = true
			sl.transmitCount++
			f.outputs.push(SendMedia{
				Path: s.txPath,
				Pkt: wire.MediaPacket{
					Seq:        sl.seq,
					SourceTime: sl.sourceTime,
					SSRC:       s.ssrc,
					Payload:    sl.payload,
					Retransmit: true,
					PathID:     s.txPath,
				},
			})
			s.retryBW.feed(now, wireBytes(len(sl.payload)))
			f.stats.Retransmitted++
			emitted++
			if emitted >= f.maxNacksPerLoop {
				return // per-pass retransmit budget exhausted; receiver re-NACKs the rest
			}
		}
	}
}

// senderHandleTimer services the sender's TimerRttEcho: originate one RTT echo
// request on the transmit path and re-arm the cadence. Mirrors the receiver's
// TimerRttEcho handling so both peers measure RTT symmetrically.
func (f *Flow) senderHandleTimer(now clock.Timestamp, id TimerID) {
	switch id {
	case TimerRttEcho:
		if f.sender.started {
			f.outputs.push(SendFeedback{
				Path: f.sender.txPath,
				FB:   wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(now))},
			})
			f.outputs.push(SetTimer{ID: TimerRttEcho, Deadline: now.Add(rttEchoInterval)})
		}
	default:
		// A timer ID the sender did not arm (e.g. a receiver-only ID):
		// nothing to do.
	}
}

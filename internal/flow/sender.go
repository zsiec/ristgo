package flow

import (
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// senderSlot is one entry of the sender history ring: a transmitted packet
// retained so it can be re-sent on NACK. It mirrors the libRIST
// struct rist_buffer fields the retransmit path reads (seq_rtp, source_time,
// transmit_count, last_retry_request — src/rist-private.h:85-112).
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
	// MaxRetries (libRIST buffer->transmit_count vs max_retries,
	// src/udp.c:1168-1174).
	transmitCount int

	// lastRetry is the instant of the most recent retransmission; the gate
	// suppresses another within one clamped RTT (libRIST
	// buffer->last_retry_request, src/udp.c:1241-1272). Meaningful only when
	// retried is true.
	lastRetry clock.Timestamp

	// retried reports whether lastRetry has been set, mirroring libRIST's
	// `last_retry_request != 0` guard (src/udp.c:1241): the first retransmit
	// is never gated.
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
	// (src/udp.c:227, hdr->rtp.ssrc = adv_flow_id | 0x01).
	ssrc uint32

	// nextSeq is the 32-bit sequence assigned to the next PushApp packet,
	// incrementing by one per packet. The codec narrows it to the 16-bit RTP
	// wire field; the core works in 32 bits throughout.
	nextSeq uint32

	// txPath is the network path first transmissions and retransmissions
	// leave on. Single-path this stage (always 0); multi-path transmission
	// (identical packets on N paths) is bonding's job (WP8).
	txPath uint8
}

// pushApp is the sender-role body of PushApp: assign the next sequence, store
// the packet in the history ring, and emit its first transmission. It mirrors
// rist_sender_enqueue (src/udp.c:869-929) followed by the data send.
func (f *Flow) pushApp(now clock.Timestamp, payload []byte) {
	s := &f.sender
	if !s.started {
		s.started = true
		// Originate RTT echo requests so the retransmit gate has a real RTT.
		// libRIST's sender gates origination on peer->echo_enabled
		// (src/udp.c:828), which flips true only after an inbound echo
		// req/resp (src/rist-common.c:2194-2195, :2202); the deterministic
		// core has no inbound-echo precondition to track, so origination is
		// intentionally ungated. This matches libRIST end-to-end because its
		// receiver originates echo requests unconditionally (src/udp.c:678),
		// flipping the peer sender's echo_enabled within one cadence.
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
	f.stats.Sent++
}

// serviceNack retransmits every requested sequence still resendable, applying
// the libRIST sender gates in libRIST's own evaluation order — the RTT/bloat
// suppression gate (rist_retry_enqueue) before the max-retries cap
// (rist_retry_dequeue), because enqueue runs before dequeue:
//
//   - slot empty or holding a different seq -> aged out, unserviceable
//     (RetransmitSkipped, src/udp.c:1086-1103);
//   - last retransmit < one clamped RTT ago -> suppressed
//     (RetransmitSuppressed, src/udp.c:1241-1272);
//   - transmitCount >= MaxRetries           -> abandoned (RetransmitExhausted,
//     src/udp.c:1168-1174);
//   - otherwise                             -> re-send with Retransmit set.
//
// Evaluating suppression before exhaustion matches libRIST's counter
// attribution: a sequence both past MaxRetries and re-NACKed within one RTT is
// counted suppressed (libRIST increments bloat_skip at enqueue and never
// reaches the dequeue cap), not exhausted. The outcome (no re-send) is the
// same either way; only the stat differs.
//
// The gate clamps the most recent raw RTT sample (libRIST peer->last_rtt,
// src/udp.c:1254-1262), deliberately the freshest sample rather than the EWMA
// the receiver uses for its retry interval — libRIST splits the two and so do
// we (see internal/rtt).
//
// Two libRIST gates have no analog here because this core services NACKs
// synchronously (no asynchronous retry queue): retry_queued (src/udp.c:1242)
// guards a request already sitting in the queue, and the retry-age gate
// (retry_age > recovery_length_max, src/udp.c:1147-1155) measures queue dwell
// time. Both would read ~0 when the retransmit is emitted within the same
// call, so last_retry_request alone is the gate.
//
// DEVIATION(librist src/udp.c:1110-1141): the recovery_maxbitrate bandwidth
// gate is not replicated. It requires a time-windowed bitrate estimator and
// is a rate-limit refinement, not an ARQ-correctness property; it is deferred
// (host-level, with the rest of congestion control) just as the receiver
// defers SR-based offset refinement to WP4. min_retries is likewise unused on
// the sender — libRIST validates it at config time but never consults it in
// the retransmit decision.
func (f *Flow) serviceNack(now clock.Timestamp, req wire.NackRequest) {
	s := &f.sender
	rtt := f.est.LastClamped(f.cfg.RTTMin, f.cfg.RTTMax)
	for _, missing := range req.Missing {
		sl := &s.ring[missing&s.mask]
		switch {
		case sl.state != slotFilled || sl.seq != missing:
			f.stats.RetransmitSkipped++
		case sl.retried && now.Sub(sl.lastRetry) < rtt:
			f.stats.RetransmitSuppressed++
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
			f.stats.Retransmitted++
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

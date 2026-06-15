package flow

import (
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/seq"
	"github.com/zsiec/ristgo/internal/wire"
)

// Source-clock wrap constants (libRIST receiver_calculate_packet_time).
//
// A source media timestamp that jumps backward by more than half the 32-bit
// timestamp space is a true wrap of the 32-bit RTP-derived counter, not jitter
// or reordering. SourceTime crosses the wire as NTP-64; one full wrap of the
// 32-bit MPEG-TS counter at 90 kHz spans (2^32 / 90000) seconds of media time:
//
//   - srcWrapPeriodNTP is that span in NTP-64 ticks ((UINT32_MAX << 32) /
//     90000), matching libRIST's bump amount ((UINT32_MAX << 32) /
//     RTP_PTYPE_MPEGTS_CLOCKHZ) exactly. The offset is bumped by this on a wrap
//     so playout stays continuous, rather than snapped to now.
//   - srcWrapPeriodMicros is the same span in microseconds (2^32 * 100 / 9),
//     added to the stored offset (which the core keeps in microseconds).
//   - srcWrapHalfNTP is half that span: a backward source-time delta exceeding
//     it identifies a genuine wrap (libRIST's (max_source_time - source_time) >
//     UINT32_MAX/2 test, scaled to the NTP-64 SourceTime domain). The half-span
//     also far exceeds libRIST's ~10-hour offset-diff sanity floor, so that
//     inner guard is subsumed.
//
// The 90 kHz figure is a constant, not a profile import: the core stays
// profile-agnostic (it imports only seq/clock/rtt/wire) and never branches on
// payload type.
const (
	srcWrapPeriodNTP    uint64             = (uint64(0xFFFFFFFF) << 32) / 90000
	srcWrapHalfNTP      uint64             = srcWrapPeriodNTP / 2
	srcWrapPeriodMicros clock.Microseconds = (clock.Microseconds(1) << 32) * 100 / 9
)

// slotState is the occupancy state of one ring slot.
type slotState uint8

const (
	slotEmpty slotState = iota
	slotFilled
)

// slot is one entry of the receiver ring: the buffered packet plus the
// timing and path bookkeeping the playout and dedup logic need. It mirrors
// libRIST's struct rist_buffer fields used by receiver_enqueue and the
// output thread (seq, source_time, packet_time, target_output_time).
type slot struct {
	// payload is the retained reference to the media payload (see the
	// package ownership note).
	payload []byte

	// sourceTime is the sender's NTP-64 media timestamp; together with seq
	// it forms the duplicate-validation key.
	sourceTime uint64

	// arrival is the local instant the first accepted copy was fed.
	arrival clock.Timestamp

	// packetTime is sourceTime mapped into the local clock domain via the
	// offset locked at the first packet.
	packetTime clock.Timestamp

	// outputTime is packetTime + recoveryBuffer: the playout deadline
	// (receiver_insert_queue_packet).
	outputTime clock.Timestamp

	// pathSeen is a bitset of the paths that delivered a copy of this
	// packet (bit index path&63). It is diagnostic: dedup correctness does
	// not depend on it. Path IDs >= 64 alias onto bit (path mod 64);
	// practical 2022-7 deployments use single-digit path counts.
	pathSeen uint64

	// seq is the widened 32-bit sequence number occupying this slot.
	seq uint32

	// frag is the fragment role carried by the packet in this slot, emitted
	// on Deliver so the host can reassemble. The zero value FragStandalone is
	// an unfragmented payload.
	frag wire.FragRole

	// state is slotEmpty or slotFilled.
	state slotState
}

// missingEntry is one queued retransmission request, libRIST's struct
// rist_missing_buffer: FIFO-linked, retried on the NACK cadence until
// recovered or abandoned.
type missingEntry struct {
	next          *missingEntry
	seq           uint32
	path          uint8
	nackCount     int
	insertionTime clock.Timestamp
	nextNack      clock.Timestamp
}

// receiverState is the receiver half's mutable state.
type receiverState struct {
	ring []slot
	mask uint32

	// started reports whether the first packet has locked the clock
	// offset and initialized the cursors.
	started bool
	// offset maps source timestamps into the local clock domain:
	// packetTime = sourceTime(us) + offset. Locked at the first packet,
	// exactly as libRIST sets time_offset = now - source_time on the
	// first packet of a flow.
	// DEVIATION(librist): libRIST refines the offset with a median over
	// 2048 in-order samples to counter clock drift; offset refinement (via
	// RTCP SR) is deferred to WP4.
	offset clock.Microseconds

	// ssrc is the media stream SSRC learned from the first packet, echoed
	// in NackRequest feedback.
	ssrc uint32

	// lastFound is libRIST's last_seq_found: the newest in-order sequence
	// accepted, the anchor of missing-detection walks.
	lastFound uint32
	// maxSourceTime and lastPacketTime mirror libRIST's max_source_time /
	// last_packet_ts pair: the newest source timestamp seen and its mapped
	// local packet time.
	maxSourceTime  uint64
	lastPacketTime clock.Timestamp

	// lastResync is libRIST's time_offset_changed_ts: the instant the source
	// clock offset was last (re-)anchored. It gates the wrap re-anchor by a
	// dwell guard (>= 3*recoveryBuffer since the last change) so a single
	// out-of-order or anomalous timestamp cannot trigger repeated resyncs.
	lastResync clock.Timestamp

	// highest is the newest (circularly greatest) sequence inserted; it
	// bounds the playout scan.
	highest uint32

	// deliverNext is the in-order playout cursor: the next sequence to
	// hand to the application (libRIST's receiver_queue_output_idx, kept
	// as a sequence number instead of a ring index).
	deliverNext uint32
	// pendingDiscontinuity marks that sequences immediately before the
	// next delivery were abandoned.
	pendingDiscontinuity bool

	// lastPath is the path of the most recently accepted media packet;
	// feedback leaves on it.
	// DEVIATION(librist rist_nack_peer_preferred): libRIST picks the
	// NACK peer by priority then lowest RTT; per-path selection lands with
	// bonding (WP8).
	lastPath uint8

	// missingHead/missingTail/missingCount form the FIFO missing queue
	// (libRIST f->missing / f->missing_tail / f->missing_counter).
	missingHead  *missingEntry
	missingTail  *missingEntry
	missingCount int

	// Requested-timer shadows so steady-state Feed emits nothing.
	playoutArmed    bool
	playoutDeadline clock.Timestamp
	nackArmed       bool

	// nackBatch is the reusable scratch buffer for one NACK pass.
	nackBatch []uint32

	// Return-bandwidth limiter (libRIST return-bandwidth): a token bucket capping
	// the rate of NACK sequence numbers emitted on the return channel, so the
	// receiver's NACK traffic stays within a configured upstream budget on an
	// asymmetric link. nackSeqsPerSec == 0 means unlimited. A NACK seq that has no
	// token is left due (its nextNack is not advanced) and re-serviced on the next
	// pass, exactly like the RIST_MAX_NACKS per-pass cap — so recovery slows but
	// is never broken. Deterministic: tokens refill from the explicit `now`.
	nackSeqsPerSec float64
	nackTokenBurst float64
	nackTokens     float64
	nackTokensTime clock.Timestamp
}

// pathBit returns the pathSeen bit for a path index (aliasing mod 64; see
// slot.pathSeen).
func pathBit(path uint8) uint64 {
	return 1 << (path & 63)
}

// mapSourceTime converts a packet's NTP-64 source timestamp into the local
// clock domain using the offset locked at the first packet.
func (f *Flow) mapSourceTime(sourceTime uint64) clock.Timestamp {
	return clock.NTPTime(sourceTime).Timestamp().Add(f.receiver.offset)
}

// feed is the receiver-role body of Feed. It follows receiver_enqueue
// step for step: first-packet initialization, packet-time mapping, too-late
// shedding, (seq, sourceTime) dedup, insert, missing-detection, then timer
// scheduling.
func (f *Flow) feed(now clock.Timestamp, path uint8, pkt wire.MediaPacket) {
	r := &f.receiver
	if !r.started {
		// A flow cannot start on a retransmit.
		if pkt.Retransmit {
			return
		}
		f.start(now, path, pkt)
		return
	}

	// Count every retransmit-flagged copy that reaches the started flow, before
	// any too-late / dedup / cursor test sheds it — so RetransmittedReceived
	// tallies all retransmits actually received (including late and duplicate
	// ones), separately from the gaps-filled-by-ARQ Recovered counter.
	if pkt.Retransmit {
		f.stats.RetransmittedReceived++
	}

	// packetTime is the local-clock instant playout is scheduled from. In SOURCE
	// timing it is the media source timestamp mapped into the local clock (so
	// inter-packet spacing follows the source clock); in ARRIVAL timing it is the
	// local arrival instant (so each packet is held a fixed recovery buffer from
	// when it arrived, regardless of the source clock).
	var packetTime clock.Timestamp
	if f.cfg.TimingMode == TimingArrival {
		// ARRIVAL timing: the source timestamp still feeds the (Seq, SourceTime)
		// dedup/merge below, but does not drive playout — so the source-clock
		// re-anchor and the source-time reorder/too-late test are skipped, and
		// shedding falls to the seq-based playout-cursor guard plus each packet's
		// own arrival-anchored outputTime.
		packetTime = now
	} else {
		packetTime = f.mapSourceTime(pkt.SourceTime)

		// Source-clock re-anchor (libRIST receiver_calculate_packet_time wrap
		// fix-up). The 32-bit RTP-derived source counter wraps every ~13h at 90 kHz;
		// after a wrap the offset locked at the first packet is one wrap period stale,
		// so every subsequent packet would map into the past and be shed as too-late
		// — a permanent stall. libRIST detects only a TRUE BACKWARD wrap, not a packet
		// merely far from now: a fresh non-retransmit whose source time fell backward
		// by more than half the 32-bit space (maxSourceTime - sourceTime >
		// UINT32_MAX/2), gated by a dwell guard so a single anomalous or out-of-order
		// timestamp cannot trigger it. On a wrap it BUMPS the offset by one wrap
		// period (keeping playout continuous) rather than snapping to now.
		//
		//   - backward-wrap test: source time fell by more than half the wrap span.
		//     Ordinary jitter/reordering moves it by milliseconds, far below the
		//     ~6.6h half-span, so they never trigger it. A forward jump (or a packet
		//     that is merely late) never triggers it either.
		//   - dwell guard: at least 3*recoveryBuffer must have elapsed since the last
		//     re-anchor (libRIST: now - time_offset_changed_ts > 3*recovery_buffer),
		//     so a wrap is corrected at most once per dwell window.
		//   - bump, don't snap: offset += one wrap period, so the wrapped source time
		//     maps to ~now and playout continues without a timing discontinuity.
		if !pkt.Retransmit && pkt.SourceTime < r.maxSourceTime &&
			r.maxSourceTime-pkt.SourceTime > srcWrapHalfNTP &&
			now.Sub(r.lastResync) >= 3*f.recoveryBuffer {
			r.offset += srcWrapPeriodMicros
			packetTime = f.mapSourceTime(pkt.SourceTime)
			r.maxSourceTime = pkt.SourceTime
			r.lastPacketTime = packetTime
			r.lastResync = now
			f.stats.ClockResync++
		}
	}

	// Track the newest source timestamp and its packet time, mirroring
	// calculate_packet_time. The update runs before the out-of-order
	// comparison, exactly as in libRIST, so the packet advancing the clock
	// can never compare against itself. (In ARRIVAL timing lastPacketTime is
	// not read — the source-time reorder test below is skipped — but tracking
	// it is harmless.)
	if pkt.SourceTime > r.maxSourceTime {
		r.maxSourceTime = pkt.SourceTime
		r.lastPacketTime = packetTime
	}

	// Out-of-order / too-late shedding by SOURCE time: only packets older than
	// the newest packet time and not the immediate successor of lastFound are
	// candidates. Skipped in ARRIVAL timing, where playout is not source-paced
	// (the seq-based cursor guard below sheds the unrecoverable ones instead).
	// DEVIATION(librist): libRIST computes the expected successor as
	// (last_seq_found+1) & (UINT16_MAX-1) — the 0xFFFE mask clears bit 0
	// and looks like a typo for & UINT16_MAX; we compare against the true
	// widened successor.
	outOfOrder := false
	if f.cfg.TimingMode == TimingSource && packetTime.Before(r.lastPacketTime) && pkt.Seq != r.lastFound+1 {
		if now.After(packetTime.Add(f.recoveryBuffer110)) {
			// now > packetTime + recoveryBuffer*1.1.
			f.stats.TooLate++
			if pkt.Retransmit {
				f.stats.TooLateRetransmit++
			}
			return
		}
		if !pkt.Retransmit {
			outOfOrder = true
		}
	}

	// Playout-cursor guard: a packet circularly behind deliverNext can
	// never be delivered in order again.
	// DEVIATION(librist): libRIST approximates this with its reader_idx
	// buffer-full check and lets other late packets strand in the ring
	// until a wrap overwrites them; comparing against the playout cursor
	// sheds them deterministically and keeps the no-late-delivery invariant
	// exact. The full-buffer drop itself is unnecessary here because the
	// cursor guard subsumes it.
	if seq.Num32(pkt.Seq).Less(seq.Num32(r.deliverNext)) {
		f.stats.TooLate++
		if pkt.Retransmit {
			f.stats.TooLateRetransmit++
		}
		return
	}

	s := &r.ring[pkt.Seq&r.mask]
	if s.state == slotFilled {
		if s.seq == pkt.Seq && s.sourceTime == pkt.SourceTime {
			// Duplicate: an ARQ re-send or another 2022-7 path's copy.
			// Record the path and drop. This is the entire multipath merge.
			s.pathSeen |= pathBit(path)
			f.stats.Duplicates++
			return
		}
		// Same slot, different (seq, sourceTime): stale entry from a
		// sequence discontinuity or ring wrap — overwrite.
		f.stats.Overwritten++
	}
	s.state = slotFilled
	s.seq = pkt.Seq
	s.sourceTime = pkt.SourceTime
	s.payload = pkt.Payload
	s.frag = pkt.Frag
	s.arrival = now
	s.packetTime = packetTime
	s.outputTime = packetTime.Add(f.recoveryBuffer)
	s.pathSeen = pathBit(path)
	f.stats.Received++
	if outOfOrder {
		f.stats.Reordered++
	}
	if seq.Num32(r.highest).Less(seq.Num32(pkt.Seq)) {
		r.highest = pkt.Seq
	}
	r.lastPath = path

	// Missing detection and lastFound advance, gated exactly as libRIST's:
	// retransmits never trigger either; out-of-order packets trigger
	// neither but still fill their hole.
	if !pkt.Retransmit {
		if !outOfOrder && pkt.Seq-1 != r.lastFound {
			f.markMissing(now, path, pkt.Seq, packetTime)
		}
		if !outOfOrder {
			r.lastFound = pkt.Seq
		}
	}

	f.armPlayout(s.outputTime)
	f.scheduleNack(now)
}

// start performs first-packet initialization, mirroring receiver_enqueue's
// !receiver_queue_has_items branch: lock the clock offset, seed the
// cursors, insert the packet, and start the playout and RTT-echo schedules.
// The first packet never triggers missing detection.
func (f *Flow) start(now clock.Timestamp, path uint8, pkt wire.MediaPacket) {
	r := &f.receiver
	src := clock.NTPTime(pkt.SourceTime).Timestamp()
	r.offset = now.Sub(src)
	r.started = true
	r.ssrc = pkt.SSRC
	r.lastFound = pkt.Seq
	r.maxSourceTime = pkt.SourceTime
	r.lastPacketTime = now // == src + offset by construction
	r.lastResync = now     // dwell anchor for the wrap re-anchor guard
	r.highest = pkt.Seq
	r.deliverNext = pkt.Seq
	r.lastPath = path

	s := &r.ring[pkt.Seq&r.mask]
	s.state = slotFilled
	s.seq = pkt.Seq
	s.sourceTime = pkt.SourceTime
	s.payload = pkt.Payload
	s.frag = pkt.Frag
	s.arrival = now
	s.packetTime = now
	s.outputTime = now.Add(f.recoveryBuffer)
	s.pathSeen = pathBit(path)
	f.stats.Received++

	f.armPlayout(s.outputTime)
	// NoRecovery (one-way) transport has no return channel, so the receiver
	// originates no RTT echo requests.
	if !f.cfg.NoRecovery {
		f.outputs.push(SetTimer{ID: TimerRttEcho, Deadline: now.Add(rttEchoInterval)})
	}
}

// markMissing queues missing entries for every sequence in (lastFound,
// current), following receiver_mark_missing: the per-entry nack time is
// interpolated linearly between the two known packet times.
func (f *Flow) markMissing(now clock.Timestamp, path uint8, current uint32, packetTimeNow clock.Timestamp) {
	r := &f.receiver
	// NoRecovery (one-way) transport has no return channel: never queue
	// missing entries, so no NACKs are ever requested. The lastFound cursor
	// still advances at the call site, and the playout timer still reclaims
	// the hole at its deadline (recovery by playout-skip, not ARQ).
	if f.cfg.NoRecovery {
		return
	}
	gap := uint64(current - r.lastFound)
	// Wraparound guard pinned to seq.MaxGap16 (32768) for flows widened
	// from 16-bit sequences, matching libRIST's
	// `if (missing_count > 32768) return`.
	// See ORCHESTRATION.md, 2026-06-12 WP3 binding.
	//
	// CONSEQUENCE for native 32-bit Advanced (TR-06-3) flows: this 16-bit
	// threshold is applied uniformly (libRIST likewise masks missing_count to
	// 16 bits via & UINT16_MAX before the test), so a *contiguous* loss burst
	// wider than 32768 sequences is mistaken for a backward wrap and never
	// NACKed — those packets are recovered only by playout skip, not ARQ. This
	// is kept deliberately bug-compatible with libRIST for interop parity; a
	// burst that large already exceeds any realistic recovery window, so the
	// packets would age out before they could be recovered regardless.
	if gap > seq.MaxGap16 {
		return
	}
	// DEVIATION(librist): gap == 0 means a re-keyed packet for lastFound
	// itself; libRIST's walk would loop until its queue-size guard and mark
	// ~2^16 bogus entries. Return early instead.
	if gap == 0 {
		return
	}

	// Interpolate per-packet time between the anchors, assuming CBR.
	// When the anchor slot is gone libRIST substitutes the current wall
	// clock; `now` is this core's equivalent.
	packetTimeLast := now
	if ls := &r.ring[r.lastFound&r.mask]; ls.state == slotFilled && ls.seq == r.lastFound {
		packetTimeLast = ls.packetTime
	}
	delta := packetTimeNow.Sub(packetTimeLast)
	if delta < 0 {
		// libRIST's unsigned subtraction would wrap enormous here; a
		// non-positive spread degenerates to zero spacing instead.
		delta = 0
	}
	interpacket := delta / clock.Microseconds(gap+1)

	nackTime := packetTimeLast
	count := uint64(1)
	for m := r.lastFound + 1; m != current; m++ {
		// Buffer-bloat / overflow guard (libRIST init_peer_settings): stop
		// queuing new missing entries once the missing queue exceeds
		// missing_counter_max. The already-queued entries keep being retried;
		// this gap is truncated here (libRIST breaks the same walk in place),
		// which bounds receiver memory under sustained loss instead of letting
		// the ring fill unboundedly.
		if r.missingCount > int(f.missingCounterMax) {
			break
		}
		nackTime = nackTime.Add(interpacket)
		f.addMissing(now, path, m, nackTime)
		count++
		if count == uint64(len(r.ring)) {
			// Safety bound, libRIST's `counter == receiver_queue_max`
			// break.
			break
		}
	}
}

// addMissing appends one missing entry, following rist_receiver_missing:
// the insertion time is the interpolated nack time clamped into
// [now-recoveryBuffer, now] — out-of-range values become now, exactly as
// the C does.
//
// The first NACK is scheduled at now + max(clamp(rtt)/2, reorder_buffer),
// matching libRIST's rist_receiver_missing (next_nack = now + rtt, where the
// caller derives rtt = clamp(eight_times_rtt/8, rtt_min, rtt_max), halves it,
// then floors it at recovery_reorder_buffer — "optimal dynamic time for the
// first retry is rtt/2"). The clamp+floor make the interval inherently bounded:
// it never drops below reorder_buffer (default 15 ms) even when the EWMA
// collapses toward zero, so a merely-reordered packet is not NACKed before its
// in-order copy can arrive within the reorder window.
func (f *Flow) addMissing(now clock.Timestamp, path uint8, missingSeq uint32, nackTime clock.Timestamp) {
	r := &f.receiver
	insertion := nackTime
	if insertion.After(now) {
		insertion = now
	} else if insertion.Before(now.Add(-f.recoveryBuffer)) {
		insertion = now
	}
	firstRTT := f.est.Clamped(f.cfg.RTTMin, f.cfg.RTTMax) / 2
	if firstRTT < f.cfg.ReorderBuffer {
		firstRTT = f.cfg.ReorderBuffer
	}
	e := &missingEntry{
		seq:           missingSeq,
		path:          path,
		insertionTime: insertion,
		nextNack:      now.Add(firstRTT),
	}
	if r.missingTail == nil {
		r.missingHead = e
	} else {
		r.missingTail.next = e
	}
	r.missingTail = e
	r.missingCount++
	f.stats.Missing++
}

// scheduleNack arms the NACK cadence timer when missing entries are queued
// and the timer is idle. The cadence is libRIST's RIST_MAX_JITTER = 5 ms
// receiver-loop bound.
func (f *Flow) scheduleNack(now clock.Timestamp) {
	r := &f.receiver
	if r.missingCount == 0 || r.nackArmed {
		return
	}
	r.nackArmed = true
	f.outputs.push(SetTimer{ID: TimerNack, Deadline: now.Add(nackCadence)})
}

// processNacks walks the missing queue once, mirroring the
// rist_receiver_nack_output loop and rist_process_nack:
//
//   - slot filled with the entry's seq  -> recovered, remove
//     (count Recovered only when at least one NACK went out);
//   - slot filled with another seq      -> stale entry, remove;
//   - nackCount >= MaxRetries           -> abandon;
//   - age > recoveryBuffer*1.1          -> abandon;
//   - now >= nextNack                   -> NACK it: nextNack = now +
//     1.1*clamp(smoothed, RTTMin, RTTMax), nackCount++.
//
// All sequences NACKed in one pass leave as a single NackRequest, like
// libRIST's nacks.array group (send_nack_group).
func (f *Flow) processNacks(now clock.Timestamp) {
	r := &f.receiver
	if r.missingCount == 0 {
		return
	}
	// Refill the return-bandwidth token bucket from the elapsed time (sans-I/O:
	// the rate is applied against the explicit `now`, not a wall clock). The
	// bucket starts full (one burst), so the first pass — whatever `now` is —
	// just clamps at the burst cap.
	if r.nackSeqsPerSec > 0 {
		if elapsed := now.Sub(r.nackTokensTime); elapsed > 0 {
			r.nackTokens += float64(elapsed) / 1e6 * r.nackSeqsPerSec
			if r.nackTokens > r.nackTokenBurst {
				r.nackTokens = r.nackTokenBurst
			}
		}
		r.nackTokensTime = now
	}

	batch := r.nackBatch[:0]
	var prev *missingEntry
	for e := r.missingHead; e != nil; {
		next := e.next
		remove := false
		s := &r.ring[e.seq&r.mask]
		switch {
		case s.state == slotFilled && s.seq == e.seq:
			if e.nackCount > 0 {
				f.stats.Recovered++
			}
			remove = true
		case s.state == slotFilled:
			// Slot reused by another sequence.
			remove = true
		case e.nackCount >= f.cfg.MaxRetries:
			f.stats.Abandoned++
			remove = true
		case now.Sub(e.insertionTime) > f.recoveryBuffer110:
			f.stats.Abandoned++
			remove = true
		case !now.Before(e.nextNack):
			// Cap one emitted NackRequest at RIST_MAX_NACKS sequences (libRIST
			// receiver_nack_output maxcounter) AND at the return-bandwidth token
			// budget. When either is full the entry is left due — its nextNack is
			// not advanced — so it is serviced on the next 5 ms pass rather than
			// dropped (recovery slows, nothing is lost).
			if len(batch) < ristMaxNacks && (r.nackSeqsPerSec == 0 || r.nackTokens >= 1) {
				e.nextNack = now.Add(f.est.RetryInterval(f.cfg.RTTMin, f.cfg.RTTMax))
				e.nackCount++
				batch = append(batch, e.seq)
				f.stats.NacksSent++
				if r.nackSeqsPerSec > 0 {
					r.nackTokens--
				}
			}
		}
		if remove {
			if prev == nil {
				r.missingHead = next
			} else {
				prev.next = next
			}
			if e == r.missingTail {
				r.missingTail = prev
			}
			r.missingCount--
		} else {
			prev = e
		}
		e = next
	}
	r.nackBatch = batch[:0]
	if len(batch) > 0 {
		missing := make([]uint32, len(batch))
		copy(missing, batch)
		f.outputs.push(SendFeedback{
			Path: r.lastPath,
			FB:   wire.NackRequest{SSRC: r.ssrc, Missing: missing},
		})
	}
}

// deliverDue performs time-driven in-order delivery at instant now,
// following the output-thread loop: the slot at the cursor is delivered
// once now >= outputTime; a hole is skipped only when the next buffered
// packet is itself due, at which point the skipped sequences are counted
// lost and the next delivery carries a discontinuity flag.
//
// DEVIATION(librist): the pathological-delay resets (forced output past
// 2*recoveryBuffer, flow reset on repeated late output) are host-level
// recovery policies and are not replicated in the deterministic core.
func (f *Flow) deliverDue(now clock.Timestamp) {
	r := &f.receiver
	if !r.started {
		return
	}
	for {
		s := &r.ring[r.deliverNext&r.mask]
		if s.state == slotFilled && s.seq == r.deliverNext {
			if now.Before(s.outputTime) {
				f.armPlayout(s.outputTime)
				return
			}
			f.emitDeliver(s)
			continue
		}

		// Hole at the cursor: find the next buffered packet.
		dist := seq.Num32(r.deliverNext).Distance(seq.Num32(r.highest))
		if dist <= 0 {
			// Nothing buffered ahead of the cursor.
			f.disarmPlayout()
			return
		}
		limit := dist
		if ringN := int64(len(r.ring)); limit > ringN {
			limit = ringN
		}
		foundSeq := uint32(0)
		found := false
		for k := int64(1); k <= limit; k++ {
			n := r.deliverNext + uint32(k)
			if sl := &r.ring[n&r.mask]; sl.state == slotFilled && sl.seq == n {
				foundSeq = n
				found = true
				break
			}
		}
		if !found {
			if dist > int64(len(r.ring)) {
				// The ring lapped the cursor without any packet for a
				// whole ring span: those sequences are unrecoverable.
				f.skipTo(r.deliverNext + uint32(len(r.ring)))
				continue
			}
			f.disarmPlayout()
			return
		}
		sl := &r.ring[foundSeq&r.mask]
		if now.Before(sl.outputTime) {
			// The hole may still be recovered until the next packet is
			// due; wake then (or earlier, if a retransmit lands).
			f.armPlayout(sl.outputTime)
			return
		}
		f.skipTo(foundSeq)
	}
}

// emitDeliver hands the slot's payload to the application and advances the
// cursor. The payload reference moves into the event; the slot is cleared.
func (f *Flow) emitDeliver(s *slot) {
	r := &f.receiver
	f.events.push(Deliver{
		Seq:           s.seq,
		Payload:       s.payload,
		Discontinuity: r.pendingDiscontinuity,
		Frag:          s.frag,
	})
	r.pendingDiscontinuity = false
	f.stats.Delivered++
	s.state = slotEmpty
	s.payload = nil
	r.deliverNext++
}

// skipTo abandons every sequence in [deliverNext, target) as lost, clears
// any stale slots passed over, and marks the discontinuity for the next
// delivery.
func (f *Flow) skipTo(target uint32) {
	r := &f.receiver
	lost := uint64(target - r.deliverNext)
	for n := r.deliverNext; n != target; n++ {
		if sl := &r.ring[n&r.mask]; sl.state == slotFilled {
			sl.state = slotEmpty
			sl.payload = nil
		}
	}
	r.deliverNext = target
	r.pendingDiscontinuity = true
	f.stats.Lost += lost
	f.stats.Discontinuities++
}

// armPlayout requests the playout timer for deadline unless an earlier or
// equal request is already outstanding. In-order steady state therefore
// emits nothing from Feed.
func (f *Flow) armPlayout(deadline clock.Timestamp) {
	r := &f.receiver
	if r.playoutArmed && !deadline.Before(r.playoutDeadline) {
		return
	}
	r.playoutArmed = true
	r.playoutDeadline = deadline
	f.outputs.push(SetTimer{ID: TimerPlayout, Deadline: deadline})
}

// disarmPlayout cancels an outstanding playout timer request.
func (f *Flow) disarmPlayout() {
	r := &f.receiver
	if !r.playoutArmed {
		return
	}
	r.playoutArmed = false
	f.outputs.push(ClearTimer{ID: TimerPlayout})
}

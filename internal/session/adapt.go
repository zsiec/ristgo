package session

import (
	"github.com/zsiec/ristgo/internal/adapt"
	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file is the host wiring for RIST source adaptation (TR-06-4 Part 1): the
// receiver periodically measures link quality from the flow's running counters
// and sends a Link Quality Message to the sender; the sender feeds each LQM to a
// rate controller and reports the new target to the application's encoder-rate
// callback. The wire format and the controller live in internal/adapt; this file
// computes the per-period deltas, frames the LQM in each profile's encapsulation,
// and routes inbound LQMs to the controller.
//
// All three profiles are wired. Reception is unified at the waist: every codec
// decodes its LQM encapsulation into a wire.LinkQuality feedback value, and
// feedFeedback intercepts it on the way to the flow core. Emission is
// profile-specific (sendLQM):
//   - Simple (§5.2): a [LinkQualityReport, SDES] RTCP compound on the RTCP
//     socket, the LQM as an RR profile-specific extension (RFC 3550 §6.4.2).
//   - Main (§5.3): the same LinkQualityReport RR, carried transparently over the
//     GRE tunnel on the single media socket.
//   - Advanced (§5.4): a native Type=Control message, Control Index 0x0002
//     (Global LQM), on the single media socket.
//
// Both ends drive this from the existing liveness ticker, so it adds no new
// goroutine or timer. It is opt-in: a receiver emits LQMs only when AdaptLQM is
// set, and a sender adapts only when a RateController and OnRateAdapt callback
// are configured — so default sessions are byte-for-byte unchanged.

// lqmKbps converts a per-period byte count into kilobits per second, rounded to
// the nearest kbps (the previous floor-truncation under-reported every period).
// bits/ms == kbit/s, so the value is bytes*8/periodMS with round-to-nearest.
func lqmKbps(deltaBytes uint64, periodMS uint32) uint32 {
	if periodMS == 0 {
		return 0
	}
	bits := deltaBytes * 8
	p := uint64(periodMS)
	return uint32((bits + p/2) / p)
}

// computeLQM builds the Link Quality Message for the reporting period that ends
// at now, from the deltas in the flow's counters since the previous report. The
// loss-related fields are exact; the bandwidth fields are derived from the
// RTP-level bytes metered this period (NPD makes them uncomputable from packet
// counts, per the spec, so they are measured directly in observeRx). Source and
// retransmission bandwidth are reported separately (TR-06-4 Part 1 §5.1).
func (s *Session) computeLQM(now clock.Timestamp) adapt.LQM {
	st := s.flow.Stats()
	prev := s.lqmPrev
	s.lqmPrev = st

	periodMS := uint32(int64(now.Sub(s.lqmLast)) / int64(clock.Millisecond))
	s.lqmLast = now

	bytes := s.rxBytes
	prevBytes := s.lqmPrevBytes
	s.lqmPrevBytes = bytes
	retransBytes := s.rxRetransBytes
	prevRetrans := s.lqmPrevRetransBytes
	s.lqmPrevRetransBytes = retransBytes

	// FEC-recovered packets are fed into the flow like any arrival, so the flow
	// counts them in Received but not in Recovered (which is ARQ-only). TR-06-4 §5.1
	// requires the LQM's recovered count to include packets recovered "through
	// retransmission OR FEC", so move this period's FEC recoveries from
	// SourceReceived into Recovered.
	fecNow := s.fecRecovered.Load()
	fecDelta := uint32(fecNow - s.lqmPrevFEC)
	s.lqmPrevFEC = fecNow
	srcReceived := uint32(st.Received - prev.Received)
	if fecDelta <= srcReceived {
		srcReceived -= fecDelta
	}

	s.lqmSeq++
	return adapt.LQM{
		SequenceNumber:    s.lqmSeq,
		ReportingPeriodMS: periodMS,
		NACKWindowMS:      uint32(int64(s.cfg.Flow.RecoveryBuffer()) / int64(clock.Millisecond)),
		SourceReceived:    srcReceived,
		OriginalLost:      uint32(st.Missing - prev.Missing),
		// RetransmittedReceived counts all retransmits actually received this
		// period (the flow's dedicated counter, distinct from Recovered, which
		// counts gaps filled by ARQ). TR-06-4 §5.1 treats these as two fields.
		RetransmittedReceived: uint32(st.RetransmittedReceived - prev.RetransmittedReceived),
		Recovered:             uint32(st.Recovered-prev.Recovered) + fecDelta,
		Unrecovered:           uint32(st.Lost - prev.Lost),
		// Late counts original packets that arrived too late, excluding
		// retransmitted packets received late (§5.1): subtract the too-late
		// retransmits the flow tracks separately from the total too-late count.
		Late:                        uint32((st.TooLate - st.TooLateRetransmit) - (prev.TooLate - prev.TooLateRetransmit)),
		DataBandwidthKbps:           lqmKbps(bytes-prevBytes, periodMS),
		RetransmissionBandwidthKbps: lqmKbps(retransBytes-prevRetrans, periodMS),
	}
}

// sendLQM emits one Link Quality Message to the sender for the period ending at
// now, encoded in the active profile's encapsulation (see the file comment).
// Receiver role only; a no-op until the sender's return address is learned. A
// bonded receiver fans the same message (same sequence number) out to every live
// path, per TR-06-4 Part 1 §5.5.
func (s *Session) sendLQM(now clock.Timestamp) {
	// Skip a degenerate sub-millisecond reporting period (e.g. two ticks at the
	// same instant): the period would floor to 0 ms, making the bandwidth fields
	// uncomputable and the report meaningless. Wait for the next tick (lqm-8).
	if int64(now.Sub(s.lqmLast)) < int64(clock.Millisecond) {
		return
	}

	b, mediaSock, ok := s.encodeLQM(now)
	if !ok {
		return
	}

	if s.bond != nil {
		s.writeBondLQM(b, mediaSock, now)
		return
	}
	if !s.peer.RTCP.IsValid() {
		return
	}
	var werr error
	if mediaSock {
		werr = s.conn.WriteMedia(b, s.peer.RTCP)
	} else {
		werr = s.writeFeedback(b)
	}
	if werr != nil {
		s.logf("adapt: write LQM: %v", werr)
		return
	}
	s.lastTx = now
}

// encodeLQM computes the LQM for the period ending at now and frames it in the
// active profile's encapsulation. It returns the encoded datagram, whether it is
// written on the media socket (single-socket profiles) versus the Simple RTCP
// socket, and ok=false if encoding failed (already logged).
func (s *Session) encodeLQM(now clock.Timestamp) (b []byte, mediaSock bool, ok bool) {
	raw := s.computeLQM(now).Marshal()
	s.rtcpBuf = s.rtcpBuf[:0]

	var err error
	switch {
	case s.adv != nil:
		// Advanced (§5.4): native Type=Control, Control Index 0x0002 (Global LQM).
		//
		// INTEROP: TR-06-4 Part 1 assigns this CI for the LQM, but libRIST v0.2.18
		// has not implemented TR-06-4 source adaptation — its Advanced control
		// dispatcher has no case for 0x0002 and replies with an Unsupported Response
		// (CI 0x8020), which ristgo's receive path ignores (decodeAdvControl's
		// default case). So Advanced-profile LQM is effectively a ristgo extension
		// when the peer is libRIST: it is harmless (media/NACK/RTT are unaffected)
		// but yields no rate feedback. It only emits when SourceAdaptation/AdaptLQM
		// is explicitly enabled, so default sessions never send it.
		b, err = s.adv.frameControl(s.rtcpBuf, adv.BuildControl(nil, adv.CILQMGlobal, raw), advCtrlTS(now))
		mediaSock = true
	case s.main != nil:
		// Main (§5.3): the Simple LinkQualityReport RR, GRE-tunnelled.
		lqr := rtcp.LinkQualityReport{SSRC: s.cfg.SSRC}
		copy(lqr.LQM[:], raw)
		b, err = s.main.encodeMainFeedback(s.rtcpBuf, lqr, nil, s.cfg.Bitmask)
		mediaSock = true
	default:
		// Simple (§5.2): [LinkQualityReport, SDES] compound on the RTCP socket.
		lqr := rtcp.LinkQualityReport{SSRC: s.cfg.SSRC}
		copy(lqr.LQM[:], raw)
		b, err = rtcp.BuildCompound(s.rtcpBuf, []rtcp.Packet{lqr, rtcp.SDES{SSRC: s.cfg.SSRC, CNAME: s.cfg.CNAME}})
	}
	if err != nil {
		s.logf("adapt: encode LQM: %v", err)
		return nil, false, false
	}
	s.rtcpBuf = b
	return b, mediaSock, true
}

// writeBondLQM fans one encoded Link Quality Message out to every live bonded
// path, mirroring sendBondKeepalive: TR-06-4 Part 1 §5.5 requires the receiver
// to send the Global LQM on every link with the same sequence number (the
// message is encoded once, so the sequence number is shared).
func (s *Session) writeBondLQM(b []byte, mediaSock bool, now clock.Timestamp) {
	sent := false
	for i := range s.bond.peers {
		p := s.bond.peers[i]
		if !p.RTCP.IsValid() {
			continue // path's return address not learned yet
		}
		var werr error
		if mediaSock {
			werr = s.bond.conns[i].WriteMedia(b, p.RTCP)
		} else {
			werr = s.bond.conns[i].WriteRTCP(b, p.RTCP)
		}
		if werr != nil {
			s.logf("adapt: write LQM path %d: %v", i, werr)
			continue
		}
		sent = true
	}
	if sent {
		s.lastTx = now
	}
}

// feedFeedback routes one batch of drained inbound feedback to the flow core,
// intercepting any Link Quality Message (TR-06-4) to drive the rate controller
// instead — an LQM is a host-level source-adaptation signal, not flow input. All
// profile receive paths funnel their decoded feedback through here so LQM
// handling is profile-agnostic.
func (s *Session) feedFeedback(now clock.Timestamp, fbs []wire.Feedback) {
	for _, fb := range fbs {
		if lq, ok := fb.(wire.LinkQuality); ok {
			s.handleLQM(lq.LQM)
			continue
		}
		s.flow.FeedFeedback(now, fb)
	}
}

// handleLQM drives the rate controller from one inbound Link Quality Message and
// reports the new encoder-rate target to the application callback. A no-op unless
// a controller is configured (a sender with adaptation enabled). It never panics
// on a malformed LQM.
func (s *Session) handleLQM(raw [44]byte) {
	if s.cfg.RateController == nil {
		return
	}
	m, err := adapt.Parse(raw[:])
	if err != nil {
		return
	}
	target := s.cfg.RateController.ObserveLQM(m)
	if s.cfg.OnRateAdapt != nil {
		s.cfg.OnRateAdapt(target)
	}
}

// adaptEmitsLQM reports whether this session should emit periodic LQMs (an
// opted-in receiver, any profile). One-way transport has no return channel, so
// it never emits LQM.
func (s *Session) adaptEmitsLQM() bool { return s.cfg.AdaptLQM && !s.sender && !s.cfg.OneWay }

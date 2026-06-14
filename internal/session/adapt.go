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

// observeRxBytes accumulates received media bytes for the LQM's measured data
// bandwidth. The host calls it as each media datagram arrives.
func (s *Session) observeRxBytes(n int) { s.rxBytes += uint64(n) }

// computeLQM builds the Link Quality Message for the reporting period that ends
// at now, from the deltas in the flow's counters since the previous report. The
// loss-related fields are exact; the data-bandwidth field is derived from the
// bytes received this period (NPD makes it uncomputable from packet counts, per
// the spec, so it is measured directly).
func (s *Session) computeLQM(now clock.Timestamp) adapt.LQM {
	st := s.flow.Stats()
	prev := s.lqmPrev
	s.lqmPrev = st

	periodMS := uint32(int64(now.Sub(s.lqmLast)) / int64(clock.Millisecond))
	s.lqmLast = now

	bytes := s.rxBytes
	prevBytes := s.lqmPrevBytes
	s.lqmPrevBytes = bytes
	var dataKbps uint32
	if periodMS > 0 {
		// bits / ms == kbits/sec.
		dataKbps = uint32((bytes - prevBytes) * 8 / uint64(periodMS))
	}

	s.lqmSeq++
	return adapt.LQM{
		SequenceNumber:    s.lqmSeq,
		ReportingPeriodMS: periodMS,
		NACKWindowMS:      uint32(int64(s.cfg.Flow.RecoveryBuffer()) / int64(clock.Millisecond)),
		SourceReceived:    uint32(st.Received - prev.Received),
		OriginalLost:      uint32(st.Missing - prev.Missing),
		// ristgo does not separately count retransmitted packets received; the
		// recovered count is the closest available proxy (retransmits that filled
		// a gap), which is what the sender's controller does not depend on.
		RetransmittedReceived:       uint32(st.Recovered - prev.Recovered),
		Recovered:                   uint32(st.Recovered - prev.Recovered),
		Unrecovered:                 uint32(st.Lost - prev.Lost),
		Late:                        uint32(st.TooLate - prev.TooLate),
		DataBandwidthKbps:           dataKbps,
		RetransmissionBandwidthKbps: 0,
	}
}

// sendLQM emits one Link Quality Message to the sender for the period ending at
// now, encoded in the active profile's encapsulation (see the file comment).
// Receiver role only; a no-op until the sender's return address is learned.
func (s *Session) sendLQM(now clock.Timestamp) {
	if s.peer.RTCP == nil {
		return
	}
	raw := s.computeLQM(now).Marshal()
	s.rtcpBuf = s.rtcpBuf[:0]

	var (
		b         []byte
		err       error
		mediaSock bool // single-socket profiles write on the media conn
	)
	switch {
	case s.adv != nil:
		// Advanced (§5.4): native Type=Control, Control Index 0x0002 (Global LQM).
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
		return
	}
	s.rtcpBuf = b

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
// opted-in receiver, any profile).
func (s *Session) adaptEmitsLQM() bool { return s.cfg.AdaptLQM && !s.sender }

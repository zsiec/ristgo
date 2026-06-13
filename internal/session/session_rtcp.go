package session

import (
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/wire"
)

// rxStats accumulates receiver-side RTP reception statistics for the Receiver
// Report (RFC 3550 §6.4.1). It is loop-owned (single goroutine).
type rxStats struct {
	baseSet     bool
	baseSeq     uint32
	highest     uint32 // extended (32-bit) highest sequence received
	mediaSSRC   uint32 // the sender's flow SSRC, learned from media
	jitter      float64
	transit     int64
	haveTransit bool

	// snapshots at the previous report, for the per-interval fraction lost.
	lastExpected uint64
	lastReceived uint64
}

// observeRx folds one accepted media packet into the reception statistics: it
// extends the highest sequence and updates the interarrival jitter estimate.
// The jitter is computed in 90 kHz RTP ticks; because it measures the change
// in transit time, the (constant) sender/receiver clock offset cancels.
func (s *Session) observeRx(now clock.Timestamp, pkt wire.MediaPacket) {
	r := &s.rx
	r.mediaSSRC = pkt.SSRC
	if !r.baseSet {
		r.baseSet = true
		r.baseSeq = pkt.Seq
		r.highest = pkt.Seq
	} else if seqAfter(pkt.Seq, r.highest) {
		r.highest = pkt.Seq
	}
	arrival := rtpTicksFromMicros(int64(now))
	rtpTS := rtpTicksFromMicros(int64(clock.NTPTime(pkt.SourceTime).Timestamp()))
	transit := arrival - rtpTS
	if r.haveTransit {
		d := transit - r.transit
		if d < 0 {
			d = -d
		}
		r.jitter += (float64(d) - r.jitter) / 16
	}
	r.transit = transit
	r.haveTransit = true
}

// receiverReport builds a full RFC 3550 Receiver Report from the accumulated
// reception statistics (libRIST sends a full RR, len=7, in periodic RTCP;
// rist_rtcp_write_rr, src/proto/rtp.c:21-39). Cumulative loss is expected
// minus the flow's accepted count; LSR/DLSR stay zero because ristgo measures
// RTT via the echo mechanism, not the SR/RR loop.
func (s *Session) receiverReport() rtcp.ReceiverReport {
	r := &s.rx
	received := s.flow.Stats().Received
	var expected uint64
	if r.baseSet {
		expected = uint64(r.highest-r.baseSeq) + 1
	}
	var cumLost uint32
	if expected > received {
		cumLost = uint32(expected-received) & 0x00FFFFFF
	}
	var fraction uint8
	if expInterval := expected - r.lastExpected; expInterval > 0 {
		if rcvInterval := received - r.lastReceived; expInterval > rcvInterval {
			fraction = uint8(((expInterval - rcvInterval) << 8) / expInterval)
		}
	}
	r.lastExpected = expected
	r.lastReceived = received
	return rtcp.ReceiverReport{
		SenderSSRC:     s.cfg.SSRC,
		MediaSSRC:      r.mediaSSRC,
		FractionLost:   fraction,
		CumulativeLost: cumLost,
		HighestSeq:     r.highest,
		Jitter:         uint32(r.jitter),
	}
}

// sendKeepalive emits one periodic RTCP compound — a Sender Report (sender) or
// full Receiver Report (receiver) plus SDES and an RTT echo request — to the
// peer's RTCP address. It matches libRIST's unconditional periodic RTCP
// (src/udp.c:671-682, 822-833) and keeps the session alive while idle; the
// echo request also lets RTT track even with no media in flight. The ticker
// only calls it when the flow has not transmitted for a full interval, so it
// does not double the flow's own echo cadence.
func (s *Session) sendKeepalive(now clock.Timestamp) {
	if s.peer.RTCP == nil {
		return // return path not learned yet
	}
	echo := []wire.Feedback{wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(now))}}
	s.rtcpBuf = s.rtcpBuf[:0]
	b, err := encodeFeedback(s.rtcpBuf, s.keepaliveLead(now), s.cfg.SSRC, s.cfg.CNAME, echo, s.cfg.Bitmask)
	if err != nil {
		s.logf("encode keepalive: %v", err)
		return
	}
	s.rtcpBuf = b
	if err := s.conn.WriteRTCP(b, s.peer.RTCP); err != nil {
		s.logf("write keepalive: %v", err)
	}
	s.lastTx = now
}

// keepaliveLead returns the leading report for a periodic RTCP compound: a
// Sender Report on the sender, a full Receiver Report on the receiver.
func (s *Session) keepaliveLead(now clock.Timestamp) rtcp.Packet {
	if s.sender {
		return rtcp.SenderReport{
			SSRC:    s.cfg.SSRC,
			NTP:     uint64(clock.NTPTimeFromTimestamp(now)),
			RTPTime: uint32(rtpTicksFromMicros(int64(now))),
		}
	}
	return s.receiverReport()
}

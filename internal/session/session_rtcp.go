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

// lqmRTPHeaderBytes is the RTP header size, in bytes, attributed to each
// received media packet for the Link Quality Message bandwidth fields. TR-06-4
// Part 1 §5.1 defines the measured bandwidth over RTP payload + RTP header bits
// and excludes encapsulation overhead outside the RTP headers; the codec strips
// the 12-byte RTP header on decode, so it is added back here while the GRE/DTLS/
// Advanced envelope is (correctly) left out.
const lqmRTPHeaderBytes = 12

// feedMedia hands one decoded media packet to the flow core and folds it into
// the reception statistics — but only once the data channel is authenticated.
// Before the EAP-SRP handshake completes (authenticator role) authed is false,
// so media from an as-yet-unauthenticated peer is dropped instead of driving the
// receiver ring or eliciting reflected NACK/echo feedback toward a possibly
// spoofed source (M7). A legitimate sender holds its own media until it
// authenticates, so nothing recoverable is lost. For sessions without
// authentication authed is always true, making this a transparent pass-through.
func (s *Session) feedMedia(now clock.Timestamp, path uint8, pkt wire.MediaPacket) {
	if !s.authed.Load() {
		return
	}
	s.flow.Feed(now, path, pkt)
	s.observeRx(now, pkt)
}

// observeRx folds one accepted media packet into the reception statistics: it
// extends the highest sequence, updates the interarrival jitter estimate, and
// meters the packet's RTP-level bytes for the Link Quality Message bandwidth
// fields (source vs retransmission kept separate, per TR-06-4 Part 1 §5.1).
// The jitter is computed in 90 kHz RTP ticks; because it measures the change
// in transit time, the (constant) sender/receiver clock offset cancels.
func (s *Session) observeRx(now clock.Timestamp, pkt wire.MediaPacket) {
	// LQM bandwidth metering: count RTP payload + RTP header only (not the
	// encapsulation the spec excludes), and attribute retransmitted packets to
	// the separate Retransmission Bandwidth so Data Bandwidth reflects source
	// packets alone.
	rtpBytes := uint64(len(pkt.Payload) + lqmRTPHeaderBytes)
	if pkt.Retransmit {
		s.rxRetransBytes += rtpBytes
	} else {
		s.rxBytes += rtpBytes
	}

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
// rist_rtcp_write_rr). Cumulative loss is expected minus the flow's accepted
// count; LSR/DLSR stay zero because ristgo measures RTT via the echo
// mechanism, not the SR/RR loop.
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
// peer's RTCP address. It matches libRIST's unconditional periodic RTCP and
// keeps the session alive while idle; the echo request also lets RTT track
// even with no media in flight. The ticker only calls it when the flow has not
// transmitted for a full interval, so it does not double the flow's own echo
// cadence.
func (s *Session) sendKeepalive(now clock.Timestamp) {
	if s.cfg.OneWay {
		return // one-way transport emits no RTCP, only media
	}
	if s.bond != nil {
		s.sendBondKeepalive(now)
		return
	}
	if !s.peer.RTCP.IsValid() {
		return // return path not learned yet
	}
	// Advanced profile: send the Main-profile GRE+RTCP handshake (authenticates
	// this peer to libRIST and keeps the control plane alive) plus the native
	// adv keep-alive (I-bit, for capability negotiation) and RTT echo.
	if s.adv != nil {
		s.sendAdvGREHandshake(now)
		s.sendAdvKeepalive(now)
		return
	}
	echo := []wire.Feedback{wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(now))}}
	s.rtcpBuf = s.rtcpBuf[:0]
	b, err := s.encodeCompound(s.rtcpBuf, s.keepaliveLead(now), echo)
	if err != nil {
		s.logf("encode keepalive: %v", err)
		return
	}
	s.rtcpBuf = b
	if err := s.writeFeedback(b); err != nil {
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
			NTP:     s.wallNTP(now), // absolute wall-clock NTP (RFC 3550); see wallNTP
			RTPTime: uint32(rtpTicksFromMicros(int64(now))),
		}
	}
	return s.receiverReport()
}

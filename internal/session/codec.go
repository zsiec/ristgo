package session

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/rtp"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file is the Simple-profile (VSF TR-06-1) codec strategy: it translates
// between the flow core's normalized wire.MediaPacket / wire.Feedback values
// and on-the-wire RTP and compound RTCP bytes. The flow core only ever sees
// 32-bit sequence numbers and NTP-64 source times; the 16-bit RTP sequence and
// 32-bit 90 kHz RTP timestamp are widened back here (and narrowed on encode),
// and the retransmit SSRC-LSB toggle is folded into MediaPacket.Retransmit.

// rtpClockHz is the MPEG-TS RTP timestamp clock (rtp.ClockRateMPEGTS, 90 kHz).
const rtpClockHz = rtp.ClockRateMPEGTS

// rtpTicksFromMicros converts microseconds to 90 kHz RTP ticks. 90000/1e6 =
// 9/100; the 9/100 form keeps the product small enough to never overflow int64
// for any realistic session-relative timestamp.
func rtpTicksFromMicros(us int64) int64 { return us * 9 / 100 }

// microsFromRTPTicks is the inverse of rtpTicksFromMicros.
func microsFromRTPTicks(ticks int64) int64 { return ticks * 100 / 9 }

// rtpTSFromSource maps an NTP-64 source time to the 32-bit RTP timestamp.
func rtpTSFromSource(src uint64) uint32 {
	us := int64(clock.NTPTime(src).Timestamp())
	return uint32(rtpTicksFromMicros(us))
}

// encodeMedia encodes a normalized MediaPacket as a Simple-profile RTP packet,
// appending to dst and returning the extended slice. The base (even) SSRC gets
// its LSB set on a retransmission (the only wire difference for a re-send;
// librist src/udp.c:227); the sequence is narrowed to 16 bits and the source
// time to the 32-bit 90 kHz RTP timestamp.
func encodeMedia(dst []byte, pkt wire.MediaPacket) ([]byte, error) {
	ssrc := pkt.SSRC
	if pkt.Retransmit {
		ssrc = rtp.MarkRetransmit(ssrc)
	}
	p := rtp.Packet{
		Header: rtp.Header{
			Version:        rtp.Version,
			PayloadType:    rtp.PayloadTypeMPEGTS,
			SequenceNumber: uint16(pkt.Seq),
			Timestamp:      rtpTSFromSource(pkt.SourceTime),
			SSRC:           ssrc,
		},
		Payload: pkt.Payload,
	}
	return p.AppendTo(dst)
}

// mediaDecoder reconstructs the flow core's 32-bit sequence and NTP-64 source
// time from a Simple-profile RTP packet's 16-bit sequence and 32-bit timestamp.
// It is stateful (one per receiving flow) and not safe for concurrent use.
//
// Both reconstructions are reference-based, anchored at the first packet and
// thereafter resolved to the value nearest the previous packet's. Within the
// recovery window (~1 s) neither the sequence (wraps every 2^16 packets) nor
// the timestamp (wraps every ~13 h at 90 kHz) can roll, so a retransmit and its
// original always reconstruct to the same (seq, sourceTime) pair — which is
// exactly what the core's duplicate test relies on.
//
// The reconstructed sourceTime is DEDUP-STABLE (a given wire timestamp always
// maps to the same value within the window), not a faithful copy of the
// sender's wall clock: it is quantized to the 90 kHz RTP clock and offset by
// the receiver's own anchor. That is sufficient because the flow core uses
// sourceTime only for relative playout spacing and dedup — its offset-lock
// absorbs the absolute difference (absolute wall-clock sync via the RTCP SR is
// deferred).
type mediaDecoder struct {
	started  bool
	refSeq   uint32
	refTicks int64
}

// decode parses one RTP packet and returns the normalized MediaPacket fed to
// the flow core. Payload aliases b (the core retains it; see the flow package
// ownership note), so the caller must not reuse b until the packet is delivered.
func (d *mediaDecoder) decode(b []byte) (wire.MediaPacket, error) {
	var p rtp.Packet
	if err := p.Unmarshal(b); err != nil {
		return wire.MediaPacket{}, err
	}
	if p.Version != rtp.Version {
		return wire.MediaPacket{}, fmt.Errorf("rist: rtp version %d, want 2", p.Version)
	}
	var seq32 uint32
	var ticks int64
	if !d.started {
		d.started = true
		seq32 = uint32(p.SequenceNumber)
		ticks = int64(p.Timestamp)
	} else {
		seq32 = widenSeq(p.SequenceNumber, d.refSeq)
		ticks = widenTicks(p.Timestamp, d.refTicks)
	}
	d.refSeq = seq32
	d.refTicks = ticks
	src := uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(microsFromRTPTicks(ticks))))
	return wire.MediaPacket{
		Seq:        seq32,
		SourceTime: src,
		SSRC:       rtp.NormalizeSSRC(p.SSRC),
		Payload:    p.Payload,
		Retransmit: rtp.IsRetransmit(p.SSRC),
	}, nil
}

// widenSeq reconstructs a 32-bit sequence from a 16-bit wire value, choosing
// the interpretation nearest ref (the previous widened sequence).
func widenSeq(wire16 uint16, ref uint32) uint32 {
	cand := ref&0xFFFF0000 | uint32(wire16)
	switch diff := int64(cand) - int64(ref); {
	case diff > 1<<15:
		return cand - (1 << 16)
	case diff < -(1 << 15):
		return cand + (1 << 16)
	default:
		return cand
	}
}

// widenTicks reconstructs a 64-bit RTP tick count from a 32-bit wire timestamp,
// choosing the interpretation nearest ref (the previous reconstructed value).
func widenTicks(wire32 uint32, ref int64) int64 {
	cand := ref&^0xFFFFFFFF | int64(wire32)
	switch diff := cand - ref; {
	case diff > 1<<31:
		return cand - (1 << 32)
	case diff < -(1 << 31):
		return cand + (1 << 32)
	default:
		return cand
	}
}

// encodeFeedback builds one Simple-profile compound RTCP datagram from the
// flow's drained feedback effects, appending to dst. lead is the mandatory
// first packet (an EmptyReceiverReport on the receiver, a SenderReport on the
// sender); SDES/CNAME follows; then NACKs and finally echo packets, satisfying
// the TR-06-1 §5.2.1 ordering enforced by rtcp.BuildCompound. bitmask selects
// the NACK encoding.
func encodeFeedback(dst []byte, lead rtcp.Packet, ssrc uint32, cname string, fbs []wire.Feedback, bitmask bool) ([]byte, error) {
	pkts := []rtcp.Packet{lead, rtcp.SDES{SSRC: ssrc, CNAME: cname}}
	var nacks, echoes []rtcp.Packet
	for _, fb := range fbs {
		switch f := fb.(type) {
		case wire.NackRequest:
			if bitmask {
				for _, p := range rtcp.EncodeBitmaskNACK(ssrc, f.SSRC, f.Missing) {
					nacks = append(nacks, p)
				}
			} else {
				for _, p := range rtcp.EncodeRangeNACK(ssrc, f.SSRC, f.Missing) {
					nacks = append(nacks, p)
				}
			}
		case wire.RttEchoRequest:
			echoes = append(echoes, rtcp.EchoRequest{SSRC: ssrc, Timestamp: f.Timestamp})
		case wire.RttEchoResponse:
			echoes = append(echoes, rtcp.EchoResponse{SSRC: ssrc, Timestamp: f.Timestamp, ProcessingDelay: f.ProcessingDelay})
		}
	}
	pkts = append(pkts, nacks...)
	pkts = append(pkts, echoes...)
	return rtcp.BuildCompound(dst, pkts)
}

// decodeFeedback parses a compound RTCP datagram into the normalized feedback
// the flow core consumes. NACK sequences arrive 16-bit on the wire and are
// widened to 32 bits nearest nackRef (the sender's current send position) so
// they match the sender's history keys. SR/RR/SDES are dropped here; the core
// has no use for them this stage.
func decodeFeedback(b []byte, nackRef uint32) ([]wire.Feedback, error) {
	pkts, err := rtcp.ParseCompound(b)
	if err != nil {
		return nil, err
	}
	var out []wire.Feedback
	for _, p := range pkts {
		switch pk := p.(type) {
		case rtcp.RangeNACK:
			out = append(out, nackToWire(pk.MediaSSRC, pk.MissingSeqs(), nackRef))
		case rtcp.BitmaskNACK:
			out = append(out, nackToWire(pk.MediaSSRC, pk.MissingSeqs(), nackRef))
		case rtcp.EchoRequest:
			out = append(out, wire.RttEchoRequest{Timestamp: pk.Timestamp})
		case rtcp.EchoResponse:
			out = append(out, wire.RttEchoResponse{Timestamp: pk.Timestamp, ProcessingDelay: pk.ProcessingDelay})
		case rtcp.LinkQualityReport:
			// Source adaptation (TR-06-4 Part 1): the LQM rides as an RR
			// profile-specific extension; cross the waist as wire.LinkQuality so
			// the host routes it to the rate controller, not the flow core.
			out = append(out, wire.LinkQuality{LQM: pk.LQM})
		}
	}
	return out, nil
}

// nackToWire widens a NACK's 16-bit sequence list to the sender's 32-bit
// space. A NACK only ever requests a sequence at or before the sender's send
// position, so each is widened to the value AT MOST nackRef (the highest sent
// sequence) — this resolves the full 2^16 history ring, where the symmetric
// "nearest" rule would mis-map a sequence more than 2^15 behind the cursor.
func nackToWire(ssrc uint32, narrow []uint32, nackRef uint32) wire.NackRequest {
	wide := make([]uint32, len(narrow))
	for i, s := range narrow {
		wide[i] = widenSeqAtMost(uint16(s), nackRef)
	}
	return wire.NackRequest{SSRC: ssrc, Missing: wide}
}

// widenSeqAtMost reconstructs the 32-bit sequence with low 16 bits wire16 that
// is greatest while still <= ref. Used for NACK sequences, which are never in
// the future relative to the sender's send position.
func widenSeqAtMost(wire16 uint16, ref uint32) uint32 {
	cand := ref&0xFFFF0000 | uint32(wire16)
	if cand > ref {
		cand -= 1 << 16
	}
	return cand
}

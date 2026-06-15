package session

import (
	"net"
	"net/netip"

	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/fec"
	"github.com/zsiec/ristgo/internal/rtp"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file wires the SMPTE ST 2022-1 FEC core (internal/fec) into the session.
//
// On the Advanced profile FEC is computed over the FULL wire datagram (after
// compression and PSK encryption), as TR-06-3 §5.3.5 requires: a recovery is the
// missing packet's exact bytes, re-injected through the normal decode path so it
// carries every header field (fragment role, flow id) and decrypts correctly. This
// makes FEC compose with fragmentation, encryption, and flow identification. On the
// Simple profile FEC is standard ST 2022-1 over the RTP payload (recovering the RTP
// header fields), the form a conforming ST 2022-1 receiver interoperates with.
// Either way a recovered packet re-enters the one seq-indexed flow ring like an ARQ
// retransmit.
//
// Carriage (TR-06-3 §5.3.5): either Advanced in-band control messages (Control
// Index 0x0022 row / 0x0023 column) on the data port, or standard ST 2022-1 RTP
// packets on dedicated UDP ports (media port + 2 column, + 4 row).

// FECParams sizes the FEC matrix, selects column-only vs 2-D, and chooses the
// carriage (in-band Advanced control messages, or standard ST 2022-1 on separate
// UDP ports).
type FECParams struct {
	Cols          int // L: columns
	Rows          int // D: rows
	ColumnOnly    bool
	SeparatePorts bool // carry FEC on dedicated UDP ports (else Advanced in-band)
}

// fecPayloadSize bounds the protected payload the FEC matrix accumulates; it must
// be at least the largest media payload (recovered payloads are truncated to the
// recovered length, which is <= this).
const fecPayloadSize = 1500

// fecPT is the RTP payload type fed to the FEC for its recovery field; ristgo does
// not use it for delivery, so a constant on both ends keeps the XOR consistent.
const fecPT = 127

// fecColumnPortOffset and fecRowPortOffset place the separate-port FEC streams
// relative to the media port (the SMPTE 2022-1 convention).
const (
	fecColumnPortOffset = 2
	fecRowPortOffset    = 4
)

// fecEnabled reports whether FEC is configured for this session.
func (s *Session) fecEnabled() bool { return s.cfg.FEC != nil }

func (s *Session) fecConfig() fec.Config {
	return fec.Config{Cols: s.cfg.FEC.Cols, Rows: s.cfg.FEC.Rows, ColumnOnly: s.cfg.FEC.ColumnOnly}
}

// fecSourceSimple reconstructs the normalized source time of a Simple-profile
// recovered packet from its sequence and recovered RTP timestamp, matching what the
// codec would produce for the real packet (so the flow's (Seq, SourceTime) dedup
// absorbs a duplicate). The Advanced profile re-decodes the recovered datagram
// instead, so it needs no equivalent.
func (s *Session) fecSourceSimple(wireTS uint32) uint64 {
	ticks := widenTicks(wireTS, s.mdec.refTicks) // widen against the decoder's reference
	return uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(microsFromRTPTicks(ticks))))
}

// fecOnSend clips one original (non-retransmit) media unit into the FEC matrix and
// emits any completed FEC packets via the configured carriage.
//
// On the Advanced profile it protects the FULL wire datagram (post-compression and
// -encryption), as TR-06-3 §5.3.5 requires, so a recovery is the missing packet's
// exact bytes — re-decoded through the normal path it carries every header field
// (fragment role, flow id) and decrypts correctly. On Simple it is standard
// ST 2022-1 over the RTP payload, recovering the RTP header fields, which a
// conforming ST 2022-1 receiver interoperates with.
func (s *Session) fecOnSend(now clock.Timestamp, pkt wire.MediaPacket, datagram []byte) {
	if pkt.Retransmit {
		return // FEC protects original transmissions, fed in sequence order
	}
	if s.fecEnc == nil {
		s.fecEnc = fec.NewEncoder(s.fecConfig(), fecPayloadSize, pkt.Seq)
	}
	var fps []fec.Packet
	if s.adv != nil {
		fps = s.fecEnc.Push(pkt.Seq, 0, 0, datagram) // recover exact wire bytes
	} else {
		fps = s.fecEnc.Push(pkt.Seq, rtpTSFromSource(pkt.SourceTime), fecPT, pkt.Payload)
	}
	for _, fp := range fps {
		s.sendFEC(now, fp)
	}
}

// sendFEC transmits one FEC packet via the configured carriage.
func (s *Session) sendFEC(now clock.Timestamp, fp fec.Packet) {
	if !s.peer.Media.IsValid() {
		return
	}
	if s.cfg.FEC.SeparatePorts {
		s.sendFECSeparate(fp)
		return
	}
	ci := adv.CIFEC20221Col
	if fp.Direction == fec.Row {
		ci = adv.CIFEC20221Row
	}
	b, err := s.adv.frameControl(s.fecBuf[:0], adv.BuildControl(nil, ci, fp.Data), advCtrlTS(now))
	if err != nil {
		s.logf("fec: frame control: %v", err)
		return
	}
	s.fecBuf = b
	if err := s.conn.WriteMedia(b, s.peer.Media); err != nil {
		s.logAt(LogWarning, CatSocket, "fec: write: %v", err)
	}
}

// sendFECSeparate wraps a FEC packet in an RTP header (standard ST 2022-1) and
// sends it to the receiver's column/row FEC port.
func (s *Session) sendFECSeparate(fp fec.Packet) {
	seqp := &s.fecColSeq
	off := fecColumnPortOffset
	if fp.Direction == fec.Row {
		seqp = &s.fecRowSeq
		off = fecRowPortOffset
	}
	dst := netip.AddrPortFrom(s.peer.Media.Addr(), s.peer.Media.Port()+uint16(off))
	p := rtp.Packet{
		Header:  rtp.Header{Version: rtp.Version, PayloadType: fecPT, SequenceNumber: *seqp, SSRC: s.cfg.SSRC},
		Payload: fp.Data,
	}
	*seqp++
	b, err := p.AppendTo(s.fecBuf[:0])
	if err != nil {
		s.logf("fec: rtp wrap: %v", err)
		return
	}
	s.fecBuf = b
	if err := s.conn.WriteMedia(b, dst); err != nil {
		s.logAt(LogWarning, CatSocket, "fec: write separate: %v", err)
	}
}

// fecIsControlIndex reports whether ci is one of the SMPTE 2022 FEC control indices.
func fecIsControlIndex(ci uint16) bool {
	switch ci {
	case adv.CIFEC20221Row, adv.CIFEC20221Col, adv.CIFEC20225Row, adv.CIFEC20225Col:
		return true
	default:
		return false
	}
}

// fecRecvSimple feeds one received Simple-profile media packet (its RTP payload and
// raw on-the-wire timestamp) into the decoder and delivers any packets it recovers.
func (s *Session) fecRecvSimple(now clock.Timestamp, wireTS uint32, pkt wire.MediaPacket) {
	if s.fecDec == nil {
		s.fecDec = fec.NewDecoder(s.fecConfig(), fecPayloadSize, pkt.Seq)
	}
	s.fecMediaSSRC = pkt.SSRC
	for _, r := range s.fecDec.PushMedia(pkt.Seq, wireTS, fecPT, pkt.Payload) {
		s.fecHandleRecovered(now, r)
	}
}

// fecRecvAdv feeds one received Advanced-profile wire datagram (the raw bytes) into
// the decoder, keyed by its decoded sequence, and delivers any it recovers.
func (s *Session) fecRecvAdv(now clock.Timestamp, seq uint32, datagram []byte) {
	if s.fecDec == nil {
		s.fecDec = fec.NewDecoder(s.fecConfig(), fecPayloadSize, seq)
	}
	for _, r := range s.fecDec.PushMedia(seq, 0, 0, datagram) {
		s.fecHandleRecovered(now, r)
	}
}

// fecOnRecvFEC feeds a received FEC packet's body (2022-1 header + XOR payload) to
// the decoder and delivers any recovered packets.
func (s *Session) fecOnRecvFEC(now clock.Timestamp, fecBody []byte) {
	if s.fecDec == nil {
		return // no media seen yet; cannot place the FEC group
	}
	for _, r := range s.fecDec.PushFEC(fecBody) {
		s.fecHandleRecovered(now, r)
	}
}

// fecHandleRecovered delivers one recovered packet. On the Advanced profile it
// re-injects the recovered wire datagram through the normal decode path, so the
// packet's full header (fragment role, flow id) and PSK decryption are honored
// exactly as for a packet that arrived on the wire — re-feeding it to the decoder
// is a no-op because the FEC and flow layers both dedup it. On Simple it
// reconstructs the wire.MediaPacket from the recovered RTP fields.
func (s *Session) fecHandleRecovered(now clock.Timestamp, r fec.Recovered) {
	s.fecRecovered.Add(1)
	if s.adv != nil {
		s.handleAdvInbound(now, r.Payload)
		return
	}
	s.feedMedia(now, 0, wire.MediaPacket{
		Seq:        r.Seq,
		SourceTime: s.fecSourceSimple(r.Timestamp),
		SSRC:       s.fecMediaSSRC,
		Payload:    r.Payload,
	})
}

// readFEC reads RTP-wrapped FEC packets from one separate-port FEC socket, strips
// the RTP header, and forwards the FEC body to the event loop (which owns the FEC
// decoder).
func (s *Session) readFEC(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		var p rtp.Packet
		if p.Unmarshal(buf[:n]) != nil {
			continue
		}
		select {
		case s.fecIn <- append([]byte(nil), p.Payload...):
		case <-s.done:
			return
		}
	}
}

// FECRecovered returns the number of media packets reconstructed by FEC. It is
// safe to call concurrently.
func (s *Session) FECRecovered() uint64 { return s.fecRecovered.Load() }

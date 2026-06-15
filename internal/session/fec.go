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
// FEC is computed over the protected media in the normalized domain (cleartext
// payload plus the on-the-wire RTP timestamp), so a recovered packet is rebuilt
// directly into the same wire.MediaPacket the codec would have produced and fed
// into the flow like an ARQ retransmit — FEC is just another source of packets
// into the one seq-indexed ring.
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

// fecWireTS maps a source time to the on-the-wire RTP timestamp for the active
// profile — the exact value the codec stamps and the receiver reads, so the FEC
// XOR is consistent end to end.
func (s *Session) fecWireTS(src uint64) uint32 {
	if s.adv != nil {
		return advTSFromSource(src)
	}
	return rtpTSFromSource(src)
}

// fecSource reconstructs the normalized source time of a recovered packet from its
// sequence and recovered wire timestamp, matching what the codec would produce for
// the real packet (so the flow's (Seq, SourceTime) dedup absorbs a duplicate).
func (s *Session) fecSource(seq, wireTS uint32) uint64 {
	if s.adv != nil {
		return uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(s.adv.advSourceMicros(seq, wireTS))))
	}
	ticks := widenTicks(wireTS, s.mdec.refTicks) // widen against the decoder's reference
	return uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(microsFromRTPTicks(ticks))))
}

// fecOnSend clips one original (non-retransmit) media packet into the FEC matrix
// and emits any completed FEC packets via the configured carriage.
func (s *Session) fecOnSend(now clock.Timestamp, pkt wire.MediaPacket) {
	if pkt.Retransmit {
		return // FEC protects original transmissions, fed in sequence order
	}
	if s.fecEnc == nil {
		s.fecEnc = fec.NewEncoder(s.fecConfig(), fecPayloadSize, pkt.Seq)
	}
	for _, fp := range s.fecEnc.Push(pkt.Seq, s.fecWireTS(pkt.SourceTime), fecPT, pkt.Payload) {
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

// fecOnRecvMedia clips a received media packet into the decoder (cleartext payload
// and the raw on-the-wire timestamp) and delivers any packets its arrival recovers.
func (s *Session) fecOnRecvMedia(now clock.Timestamp, wireTS uint32, pkt wire.MediaPacket) {
	if s.fecDec == nil {
		s.fecDec = fec.NewDecoder(s.fecConfig(), fecPayloadSize, pkt.Seq)
	}
	s.fecMediaSSRC = pkt.SSRC
	for _, r := range s.fecDec.PushMedia(pkt.Seq, wireTS, fecPT, pkt.Payload) {
		s.fecDeliver(now, r)
	}
}

// fecOnRecvFEC feeds a received FEC packet's body (2022-1 header + XOR payload) to
// the decoder and delivers any recovered packets.
func (s *Session) fecOnRecvFEC(now clock.Timestamp, fecBody []byte) {
	if s.fecDec == nil {
		return // no media seen yet; cannot place the FEC group
	}
	for _, r := range s.fecDec.PushFEC(fecBody) {
		s.fecDeliver(now, r)
	}
}

// fecDeliver reconstructs the recovered packet as the exact wire.MediaPacket the
// codec would have produced and feeds it into the flow.
func (s *Session) fecDeliver(now clock.Timestamp, r fec.Recovered) {
	s.fecRecovered.Add(1)
	s.feedMedia(now, 0, wire.MediaPacket{
		Seq:        r.Seq,
		SourceTime: s.fecSource(r.Seq, r.Timestamp),
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

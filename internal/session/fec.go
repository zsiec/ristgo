package session

import (
	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/fec"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file wires the SMPTE ST 2022-1 FEC core (internal/fec) into the session.
// FEC is computed over the protected media in the normalized domain (cleartext
// payload plus the on-the-wire RTP timestamp), so a recovered packet is rebuilt
// directly into the same wire.MediaPacket the codec would have produced and fed
// into the flow like an ARQ retransmit — FEC is just another source of packets
// into the one seq-indexed ring.
//
// Carriage (Phase 2): Advanced in-band, the FEC packets ride the data port as
// Advanced control messages (Control Index 0x0022 row / 0x0023 column, TR-06-3
// §5.3.5). The separate-UDP-port carriage (standard 2022-1, all profiles) is a
// follow-on.

// FECParams sizes the FEC matrix and selects column-only vs 2-D.
type FECParams struct {
	Cols       int // L: columns
	Rows       int // D: rows
	ColumnOnly bool
}

// fecPayloadSize bounds the protected payload the FEC matrix accumulates; it must
// be at least the largest media payload (recovered payloads are truncated to the
// recovered length, which is <= this).
const fecPayloadSize = 1500

// fecPT is the RTP payload type fed to the FEC for the recovery field. ristgo does
// not use it for delivery (the flow keys on Seq/SourceTime), so a constant on both
// ends keeps the XOR consistent.
const fecPT = 127

// fecEnabled reports whether FEC is configured for this session.
func (s *Session) fecEnabled() bool { return s.cfg.FEC != nil && s.adv != nil }

// fecConfig converts the session params to the core matrix config.
func (s *Session) fecConfig() fec.Config {
	return fec.Config{Cols: s.cfg.FEC.Cols, Rows: s.cfg.FEC.Rows, ColumnOnly: s.cfg.FEC.ColumnOnly}
}

// fecOnSend clips one original (non-retransmit) media packet into the FEC matrix
// and emits any completed FEC packets via the Advanced in-band carriage. It feeds
// the on-the-wire timestamp (advTSFromSource) and the cleartext payload, the same
// values the receiver clips, so the XOR recovers the lost packet exactly.
func (s *Session) fecOnSend(now clock.Timestamp, pkt wire.MediaPacket) {
	if pkt.Retransmit {
		return // FEC protects original transmissions, fed in sequence order
	}
	if s.fecEnc == nil {
		s.fecEnc = fec.NewEncoder(s.fecConfig(), fecPayloadSize, pkt.Seq)
	}
	for _, fp := range s.fecEnc.Push(pkt.Seq, advTSFromSource(pkt.SourceTime), fecPT, pkt.Payload) {
		s.sendFEC(now, fp)
	}
}

// sendFEC frames one FEC packet as an Advanced control message and transmits it on
// the data port. Column FEC uses Control Index 0x0023, row FEC 0x0022.
func (s *Session) sendFEC(now clock.Timestamp, fp fec.Packet) {
	if !s.peer.Media.IsValid() {
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

// fecOnRecvFEC feeds a received FEC control message's payload to the decoder and
// delivers any recovered packets.
func (s *Session) fecOnRecvFEC(now clock.Timestamp, fecData []byte) {
	if s.fecDec == nil {
		return // no media seen yet; cannot place the FEC group
	}
	for _, r := range s.fecDec.PushFEC(fecData) {
		s.fecDeliver(now, r)
	}
}

// fecDeliver reconstructs the recovered packet as the exact wire.MediaPacket the
// codec would have produced (same SourceTime mapping as decodeMediaAdv) and feeds
// it into the flow. The flow's (Seq, SourceTime) dedup absorbs a duplicate if the
// real packet also arrives.
func (s *Session) fecDeliver(now clock.Timestamp, r fec.Recovered) {
	src := uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(s.adv.advSourceMicros(r.Seq, r.Timestamp))))
	s.fecRecovered.Add(1)
	s.feedMedia(now, 0, wire.MediaPacket{
		Seq:        r.Seq,
		SourceTime: src,
		SSRC:       s.fecMediaSSRC,
		Payload:    r.Payload,
	})
}

// FECRecovered returns the number of media packets reconstructed by FEC. It is
// safe to call concurrently.
func (s *Session) FECRecovered() uint64 { return s.fecRecovered.Load() }

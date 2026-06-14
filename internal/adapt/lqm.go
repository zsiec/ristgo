// Package adapt implements RIST source adaptation (VSF TR-06-4 Part 1): the
// Link Quality Message (LQM) the stream receiver sends back to the sender, and
// a deterministic rate controller that turns those messages into encoder
// bit-rate targets.
//
// The LQM is profile-independent (Figure 2): a fixed 44-byte block of eleven
// 32-bit big-endian counters. Its ENCAPSULATION is profile-dependent and lives
// outside this package: in Simple/Main profile it is appended to an RTCP
// Receiver Report as a profile-specific extension (RFC 3550 §6.4.2,
// TR-06-4 §5.2–5.3); in Advanced profile it is the body of a Type=Control
// message with Control Index 0x0002 (Global) or 0x0003 (Link-Specific)
// (TR-06-4 §5.4, Table 1). This package owns only the 44-byte block and the
// controller, so both are pure and exhaustively testable.
//
// TR-06-4 source adaptation has no libRIST implementation, so the conformance
// bar is the spec itself: byte-exact Marshal/Parse round-trips and the field
// layout of Figure 2, plus a closed-loop simulation showing the rate target is
// monotone in observed loss.
package adapt

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// LQMSize is the wire size of a Link Quality Message: eleven 32-bit fields
// (TR-06-4 Part 1, Figure 2).
const LQMSize = 44

// ErrShortLQM is returned by Parse when the input is shorter than LQMSize.
var ErrShortLQM = errors.New("rist: adapt: short link quality message")

// LQM is a Link Quality Message (TR-06-4 Part 1 §5.1, Figure 2): the receiver's
// per-reporting-period feedback to the sender. All fields are 32-bit; on the
// wire they are big-endian in the order below.
type LQM struct {
	// SequenceNumber is a monotonically increasing per-LQM counter (there is no
	// retransmission for lost LQMs; it lets the sender detect loss/duplication).
	SequenceNumber uint32
	// ReportingPeriodMS is the duration of this report's period, in
	// milliseconds. Consecutive periods are contiguous in time.
	ReportingPeriodMS uint32
	// NACKWindowMS is the receiver's current NACK (recovery) window, in ms.
	NACKWindowMS uint32
	// SourceReceived is the count of source packets received this period
	// (originals, FEC, RTT-echo responses, keep-alives, flow-attr control).
	SourceReceived uint32
	// OriginalLost is the count of original packets lost this period — the link
	// congestion signal the controller adapts to.
	OriginalLost uint32
	// RetransmittedReceived is the count of retransmitted packets received.
	RetransmittedReceived uint32
	// Recovered is the count of originally-lost packets recovered (retransmit or
	// FEC) within the NACK window.
	Recovered uint32
	// Unrecovered is the count of packets not recovered within the NACK window.
	Unrecovered uint32
	// Late is the count of source packets received too late to use (behind the
	// last packet released from the NACK buffer; excludes late retransmits).
	Late uint32
	// DataBandwidthKbps is the measured source data bandwidth (payload + RTP
	// header bits / period), rounded to the nearest 1000 bits/sec.
	DataBandwidthKbps uint32
	// RetransmissionBandwidthKbps is the measured retransmission bandwidth, same
	// units.
	RetransmissionBandwidthKbps uint32
}

// AppendTo appends the 44-byte wire form of the LQM to dst (big-endian, field
// order per Figure 2) and returns the extended slice.
func (m LQM) AppendTo(dst []byte) []byte {
	var b [LQMSize]byte
	be := binary.BigEndian
	be.PutUint32(b[0:4], m.SequenceNumber)
	be.PutUint32(b[4:8], m.ReportingPeriodMS)
	be.PutUint32(b[8:12], m.NACKWindowMS)
	be.PutUint32(b[12:16], m.SourceReceived)
	be.PutUint32(b[16:20], m.OriginalLost)
	be.PutUint32(b[20:24], m.RetransmittedReceived)
	be.PutUint32(b[24:28], m.Recovered)
	be.PutUint32(b[28:32], m.Unrecovered)
	be.PutUint32(b[32:36], m.Late)
	be.PutUint32(b[36:40], m.DataBandwidthKbps)
	be.PutUint32(b[40:44], m.RetransmissionBandwidthKbps)
	return append(dst, b[:]...)
}

// Marshal returns the 44-byte wire form of the LQM.
func (m LQM) Marshal() []byte { return m.AppendTo(nil) }

// Parse decodes a Link Quality Message from the first LQMSize bytes of b
// (trailing bytes are ignored, so it works on an RR profile-specific extension
// or an Advanced control body). Arbitrary short input returns ErrShortLQM and
// never panics.
func Parse(b []byte) (LQM, error) {
	if len(b) < LQMSize {
		return LQM{}, fmt.Errorf("%w: %d < %d bytes", ErrShortLQM, len(b), LQMSize)
	}
	be := binary.BigEndian
	return LQM{
		SequenceNumber:              be.Uint32(b[0:4]),
		ReportingPeriodMS:           be.Uint32(b[4:8]),
		NACKWindowMS:                be.Uint32(b[8:12]),
		SourceReceived:              be.Uint32(b[12:16]),
		OriginalLost:                be.Uint32(b[16:20]),
		RetransmittedReceived:       be.Uint32(b[20:24]),
		Recovered:                   be.Uint32(b[24:28]),
		Unrecovered:                 be.Uint32(b[28:32]),
		Late:                        be.Uint32(b[32:36]),
		DataBandwidthKbps:           be.Uint32(b[36:40]),
		RetransmissionBandwidthKbps: be.Uint32(b[40:44]),
	}, nil
}

// LossFraction is the link's original-loss rate this period —
// OriginalLost / (SourceReceived + OriginalLost) — the congestion signal the
// rate controller adapts to. It is 0 when no source packets were accounted for.
func (m LQM) LossFraction() float64 {
	denom := uint64(m.SourceReceived) + uint64(m.OriginalLost)
	if denom == 0 {
		return 0
	}
	return float64(m.OriginalLost) / float64(denom)
}

// ResidualLossFraction is the fraction of packets still unrecovered after ARQ —
// Unrecovered / (SourceReceived + OriginalLost) — i.e. loss the application
// actually sees. It is 0 when no source packets were accounted for.
func (m LQM) ResidualLossFraction() float64 {
	denom := uint64(m.SourceReceived) + uint64(m.OriginalLost)
	if denom == 0 {
		return 0
	}
	return float64(m.Unrecovered) / float64(denom)
}

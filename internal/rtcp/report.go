package rtcp

import "encoding/binary"

// Encoded sizes of the fixed-shape report packets.
const (
	senderReportSize   = 28 // (6+1)*4, TR-06-1 §5.2.2: length=6
	emptyRRSize        = 8  // (1+1)*4, TR-06-1 §5.2.3: length=1
	receiverReportSize = 32 // (7+1)*4, TR-06-1 §5.2.4: length=7
)

// SenderReport is the RIST RTCP Sender Report (TR-06-1 §5.2.2): PT=200,
// RC=0, length=6, with no reception report blocks. libRIST builds it in
// rist_rtcp_write_sr (src/proto/rtp.c:42-66).
type SenderReport struct {
	// SSRC identifies the originator of the report (libRIST sends the
	// flow ID, src/proto/rtp.c:50).
	SSRC uint32

	// NTP is the sender wallclock at report generation in NTP-64 format:
	// upper 32 bits whole seconds since the 1900 epoch, lower 32 bits the
	// fractional second.
	NTP uint64

	// RTPTime is the RTP timestamp corresponding to the same instant as
	// NTP, in the media clock rate.
	RTPTime uint32

	// PacketCount is the total RTP data packets sent since transmission
	// started.
	PacketCount uint32

	// OctetCount is the total RTP payload octets sent since transmission
	// started.
	OctetCount uint32
}

// MarshalSize returns the encoded size: always 28 bytes.
func (SenderReport) MarshalSize() int { return senderReportSize }

// AppendTo appends the 28-byte encoding to buf and returns the extended
// slice.
func (p SenderReport) AppendTo(buf []byte) []byte {
	buf = appendHeader(buf, 0, PTSenderReport, 6)
	buf, w := grow(buf, senderReportSize-headerSize)
	binary.BigEndian.PutUint32(w[0:4], p.SSRC)
	binary.BigEndian.PutUint64(w[4:12], p.NTP)
	binary.BigEndian.PutUint32(w[12:16], p.RTPTime)
	binary.BigEndian.PutUint32(w[16:20], p.PacketCount)
	binary.BigEndian.PutUint32(w[20:24], p.OctetCount)
	return buf
}

func (SenderReport) isPacket() {}

// decodeSenderReport decodes a PT=200 packet. RIST SRs carry no reception
// report blocks (TR-06-1 §5.2.2: RC=0, length=6); anything else is not a
// RIST shape.
func decodeSenderReport(h header, body []byte) (Packet, bool) {
	if h.count != 0 || h.size != senderReportSize {
		return nil, false
	}
	return SenderReport{
		SSRC:        binary.BigEndian.Uint32(body[4:8]),
		NTP:         binary.BigEndian.Uint64(body[8:16]),
		RTPTime:     binary.BigEndian.Uint32(body[16:20]),
		PacketCount: binary.BigEndian.Uint32(body[20:24]),
		OctetCount:  binary.BigEndian.Uint32(body[24:28]),
	}, true
}

// EmptyReceiverReport is the empty RR of TR-06-1 §5.2.3: PT=201, RC=0,
// length=1 — just the header and the reporter SSRC. RIST senders may use it
// in place of an SR purely to keep NAT state alive, and libRIST leads every
// receiver NACK compound with one (rist_rtcp_write_empty_rr,
// src/proto/rtp.c:9-19; src/udp.c:736).
type EmptyReceiverReport struct {
	// SSRC identifies the originator of the report.
	SSRC uint32
}

// MarshalSize returns the encoded size: always 8 bytes.
func (EmptyReceiverReport) MarshalSize() int { return emptyRRSize }

// AppendTo appends the 8-byte encoding to buf and returns the extended
// slice.
func (p EmptyReceiverReport) AppendTo(buf []byte) []byte {
	buf = appendHeader(buf, 0, PTReceiverReport, 1)
	buf, w := grow(buf, emptyRRSize-headerSize)
	binary.BigEndian.PutUint32(w, p.SSRC)
	return buf
}

func (EmptyReceiverReport) isPacket() {}

// ReceiverReport is the full RR of TR-06-1 §5.2.4: PT=201, RC=1, length=7,
// with exactly one reception report block describing the RIST sender's
// stream. libRIST builds it in rist_rtcp_write_rr (src/proto/rtp.c:21-40).
type ReceiverReport struct {
	// SenderSSRC identifies the originator of this report (the RIST
	// receiver).
	SenderSSRC uint32

	// MediaSSRC is the SSRC of the received stream the report block
	// describes.
	MediaSSRC uint32

	// FractionLost is the fraction of packets lost since the previous
	// report, as the 8-bit fixed-point value of RFC 3550 §6.4.1.
	FractionLost uint8

	// CumulativeLost is the 24-bit cumulative number of packets lost.
	// Encoders use only the low 24 bits.
	CumulativeLost uint32

	// HighestSeq is the extended highest sequence number received
	// (RFC 3550 §6.4.1: low 16 bits the highest RTP seq, high 16 bits the
	// wrap count).
	HighestSeq uint32

	// Jitter is the interarrival jitter estimate in RTP timestamp units.
	Jitter uint32

	// LSR is the middle 32 bits of the NTP timestamp of the last SR
	// received (libRIST src/proto/rtp.c:36).
	LSR uint32

	// DLSR is the delay since that SR was received, in 1/65536-second
	// units (libRIST src/proto/rtp.c:38-39).
	DLSR uint32
}

// MarshalSize returns the encoded size: always 32 bytes.
func (ReceiverReport) MarshalSize() int { return receiverReportSize }

// AppendTo appends the 32-byte encoding to buf and returns the extended
// slice. CumulativeLost is masked to its 24-bit field.
func (p ReceiverReport) AppendTo(buf []byte) []byte {
	buf = appendHeader(buf, 1, PTReceiverReport, 7)
	buf, w := grow(buf, receiverReportSize-headerSize)
	binary.BigEndian.PutUint32(w[0:4], p.SenderSSRC)
	binary.BigEndian.PutUint32(w[4:8], p.MediaSSRC)
	binary.BigEndian.PutUint32(w[8:12], p.CumulativeLost&0x00FFFFFF)
	w[8] = p.FractionLost
	binary.BigEndian.PutUint32(w[12:16], p.HighestSeq)
	binary.BigEndian.PutUint32(w[16:20], p.Jitter)
	binary.BigEndian.PutUint32(w[20:24], p.LSR)
	binary.BigEndian.PutUint32(w[24:28], p.DLSR)
	return buf
}

func (ReceiverReport) isPacket() {}

// decodeReceiverReport decodes a PT=201 packet into the empty (RC=0,
// length=1) or full (RC=1, length=7) RIST RR shape.
func decodeReceiverReport(h header, body []byte) (Packet, bool) {
	switch {
	case h.count == 0 && h.size == emptyRRSize:
		return EmptyReceiverReport{SSRC: binary.BigEndian.Uint32(body[4:8])}, true
	case h.count == 1 && h.size == receiverReportSize:
		return ReceiverReport{
			SenderSSRC:     binary.BigEndian.Uint32(body[4:8]),
			MediaSSRC:      binary.BigEndian.Uint32(body[8:12]),
			FractionLost:   body[12],
			CumulativeLost: binary.BigEndian.Uint32(body[12:16]) & 0x00FFFFFF,
			HighestSeq:     binary.BigEndian.Uint32(body[16:20]),
			Jitter:         binary.BigEndian.Uint32(body[20:24]),
			LSR:            binary.BigEndian.Uint32(body[24:28]),
			DLSR:           binary.BigEndian.Uint32(body[28:32]),
		}, true
	case h.count == 0 && h.size == lqmReportSize:
		var p LinkQualityReport
		p.SSRC = binary.BigEndian.Uint32(body[4:8])
		copy(p.LQM[:], body[8:lqmReportSize])
		return p, true
	}
	return nil, false
}

// lqmReportSize is an empty RR (8 bytes) plus a 44-byte Link Quality Message
// profile-specific extension (TR-06-4 Part 1 Figure 4): length field 12.
const lqmReportSize = emptyRRSize + LQMExtensionSize

// LQMExtensionSize is the byte size of the Link Quality Message that rides on an
// RR as an RFC 3550 §6.4.2 profile-specific extension (TR-06-4 Part 1 Figure 2).
const LQMExtensionSize = 44

// LinkQualityReport is an empty RTCP Receiver Report (PT=201, RC=0) carrying a
// 44-byte Link Quality Message as an RFC 3550 §6.4.2 profile-specific extension
// (TR-06-4 Part 1 §5.2, Figure 4). The receiver sends it to the sender for
// source adaptation. The LQM bytes are opaque here — decoded by internal/adapt —
// so this package carries no TR-06-4 dependency.
type LinkQualityReport struct {
	// SSRC identifies the originator (the RIST receiver).
	SSRC uint32
	// LQM is the 44-byte Link Quality Message (internal/adapt encodes/decodes it).
	LQM [LQMExtensionSize]byte
}

// MarshalSize returns the encoded size: always 52 bytes.
func (LinkQualityReport) MarshalSize() int { return lqmReportSize }

// AppendTo appends the empty-RR header (length 12), the reporter SSRC, and the
// 44-byte LQM extension to buf.
func (p LinkQualityReport) AppendTo(buf []byte) []byte {
	buf = appendHeader(buf, 0, PTReceiverReport, lqmReportSize/4-1)
	buf, w := grow(buf, lqmReportSize-headerSize)
	binary.BigEndian.PutUint32(w[0:4], p.SSRC)
	copy(w[4:], p.LQM[:])
	return buf
}

func (LinkQualityReport) isPacket() {}

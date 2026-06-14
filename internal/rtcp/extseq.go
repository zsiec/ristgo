package rtcp

import "encoding/binary"

// extSeqSize is the fixed EXTSEQ packet size: header, SSRC, "RIST" name,
// 16-bit sequence extension, 16-bit reserved — length=3 (TR-06-2 §8.4,
// Figure 16).
const extSeqSize = 16

// ExtSeq is the RIST EXTSEQ packet of VSF TR-06-2 §8.4: an APP packet
// (PT=204, name "RIST") with subtype 1 and length=3, conveying the upper 16
// bits of the 32-bit extended sequence number for the NACK packet(s) that
// follow it in the compound. NACK entries with different upper halves must
// be split into separate NACK packets, each preceded by its own EXTSEQ.
//
// libRIST does not define this packet; the layout here is taken directly from
// TR-06-2 Figure 16 (fields in network byte order).
type ExtSeq struct {
	// SSRC is the "SSRC of media source" the following retransmission
	// request relates to, used exactly as in the NACK packets themselves.
	SSRC uint32

	// SeqHigh is the Sequence Number Extension: the most significant 16
	// bits prepended to every 16-bit starting sequence number in the NACK
	// packets that follow.
	SeqHigh uint16
}

// MarshalSize returns the encoded size: always 16 bytes.
func (ExtSeq) MarshalSize() int { return extSeqSize }

// AppendTo appends the 16-byte encoding to buf and returns the extended
// slice. The reserved field is written as zero per TR-06-2 Figure 16.
func (p ExtSeq) AppendTo(buf []byte) []byte {
	buf = appendHeader(buf, AppSubtypeExtSeq, PTApp, 3)
	buf, w := grow(buf, extSeqSize-headerSize)
	binary.BigEndian.PutUint32(w[0:4], p.SSRC)
	binary.BigEndian.PutUint32(w[4:8], NameRIST)
	binary.BigEndian.PutUint16(w[8:10], p.SeqHigh)
	w[10], w[11] = 0, 0
	return buf
}

func (ExtSeq) isPacket() {}

// decodeExtSeq decodes an APP "RIST" packet of subtype 1. The caller has
// already verified the fixed APP prefix and name. The reserved field is
// accepted with any contents (TR-06-2 defines it as 0 on send) and
// normalizes to zero on re-encode.
func decodeExtSeq(body []byte) (Packet, bool) {
	if len(body) != extSeqSize {
		return nil, false
	}
	return ExtSeq{
		SSRC:    binary.BigEndian.Uint32(body[4:8]),
		SeqHigh: binary.BigEndian.Uint16(body[12:14]),
	}, true
}

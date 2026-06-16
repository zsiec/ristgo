package fec

import "encoding/binary"

// Header5 is the SMPTE ST 2022-5:2013 §7.3 FEC header (16 octets, Figure 4). It is
// the "high bit rate" sibling of the ST 2022-1 [Header]: the XOR matrix is identical
// (column FEC at Offset=L over NA=D datagrams, row FEC at Offset=1 over NA=L), but
// the wire layout differs. The base sequence number is 16 bits (vs 24), Offset and
// NA are 10 bits each (vs 8, raising the matrix ceiling to 1020 per dimension), and
// the header carries explicit recovery bits for the RTP padding, extension, CSRC
// count, and marker fields that ST 2022-1 omits.
//
// TR-06-3 §5.3.5 carries this header in-band under Control Index 0x0020 (row) /
// 0x0021 (column), or on dedicated UDP ports as standard ST 2022-5. The protected
// datagrams are those with sequence numbers SNBase + j*Offset for 0 <= j < NA
// (§7.3); a receiver must derive that set from the header alone and make no
// block-alignment assumption (§7.1, Annex B), which the decoder honors.
type Header5 struct {
	// PRecovery, XRecovery, MRecovery are the XOR of the protected packets' RTP
	// padding, extension, and marker bits; CCRecovery is the XOR of their 4-bit
	// CSRC counts. For RIST media (no padding/extension/CSRC, marker unset) these
	// are zero.
	PRecovery  bool
	XRecovery  bool
	CCRecovery uint8
	MRecovery  bool
	// PTRecovery is the XOR of the protected packets' 7-bit RTP payload types.
	PTRecovery uint8
	// SNBase is the lowest 16-bit sequence number the FEC packet protects.
	SNBase uint16
	// TSRecovery is the XOR of the protected packets' RTP timestamps.
	TSRecovery uint32
	// LengthRecovery is the XOR of the protected packets' 16-bit payload lengths.
	LengthRecovery uint16
	// Offset is the 10-bit spacing between protected packets: L for a column, 1 for
	// a row.
	Offset uint16
	// NA is the 10-bit number of packets protected: D for a column, L for a row.
	NA uint16
}

// na10Max is the largest value the 10-bit Offset and NA fields can hold.
const na10Max = 0x3ff

// AppendTo encodes the header (big-endian, 16 bytes) onto dst and returns the
// extended slice. The E and R flags and all Reserved fields are zero, as the sender
// shall set them (§7.3); Offset and NA occupy the high 10 bits of their octet pairs.
func (h Header5) AppendTo(dst []byte) []byte {
	var b [HeaderSize]byte
	// b[0]: E(0) R(0) P X CC(4)
	b[0] = boolBit(h.PRecovery)<<5 | boolBit(h.XRecovery)<<4 | h.CCRecovery&0x0f
	// b[1]: M PT(7)
	b[1] = boolBit(h.MRecovery)<<7 | h.PTRecovery&0x7f
	binary.BigEndian.PutUint16(b[2:4], h.SNBase)
	binary.BigEndian.PutUint32(b[4:8], h.TSRecovery)
	binary.BigEndian.PutUint16(b[8:10], h.LengthRecovery)
	// b[10:12] Reserved = 0
	binary.BigEndian.PutUint16(b[12:14], (h.Offset&na10Max)<<6)
	binary.BigEndian.PutUint16(b[14:16], (h.NA&na10Max)<<6)
	return append(dst, b[:]...)
}

// ParseHeader5 decodes a SMPTE ST 2022-5 FEC header from the front of b and returns
// it along with the offset of the recovered payload. It never panics on short or
// arbitrary input.
func ParseHeader5(b []byte) (h Header5, payloadOffset int, err error) {
	if len(b) < HeaderSize {
		return Header5{}, 0, ErrShortHeader
	}
	h.PRecovery = b[0]>>5&0x1 == 1
	h.XRecovery = b[0]>>4&0x1 == 1
	h.CCRecovery = b[0] & 0x0f
	h.MRecovery = b[1]>>7&0x1 == 1
	h.PTRecovery = b[1] & 0x7f
	h.SNBase = binary.BigEndian.Uint16(b[2:4])
	h.TSRecovery = binary.BigEndian.Uint32(b[4:8])
	h.LengthRecovery = binary.BigEndian.Uint16(b[8:10])
	h.Offset = binary.BigEndian.Uint16(b[12:14]) >> 6
	h.NA = binary.BigEndian.Uint16(b[14:16]) >> 6
	return h, HeaderSize, nil
}

// boolBit returns 1 for true and 0 for false, for packing flag bits.
func boolBit(v bool) byte {
	if v {
		return 1
	}
	return 0
}

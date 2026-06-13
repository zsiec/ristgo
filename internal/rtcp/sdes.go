package rtcp

import "encoding/binary"

// sdesFixedSize is the SDES bytes before the CNAME string: header, SSRC,
// CNAME item type, and item length (RTCP_SDES_SIZE, libRIST
// src/proto/rtp.h:105).
const sdesFixedSize = 10

// sdesItemCNAME is the SDES item type for CNAME (RFC 3550 §6.5.1).
const sdesItemCNAME = 1

// maxCNAMELen is the largest CNAME the 8-bit item length field can carry.
const maxCNAMELen = 255

// SDES is the RIST Source Description packet of TR-06-1 §5.2.5: PT=202,
// SC=1, a single chunk holding one CNAME item. The chunk is closed by 1-4
// zero bytes that both terminate the item list and pad the packet to a
// 32-bit boundary. libRIST builds it in rist_rtcp_write_sdes
// (src/proto/rtp.c:67-87).
type SDES struct {
	// SSRC identifies the originator of the packet (the RIST sender or
	// receiver).
	SSRC uint32

	// CNAME is the canonical name string. TR-06-1 lets implementations use
	// it freely; libRIST sends its configured cname. Encoders truncate it
	// to 255 bytes, the most the 8-bit length field can describe (libRIST
	// clamps earlier, via strnlen(name, RIST_MAX_STRING_SHORT-1)).
	CNAME string
}

// sdesSize returns the canonical whole-packet size for an n-byte CNAME:
// the 10 fixed bytes plus the name plus at least one zero terminator,
// rounded up to a multiple of 4 — between 1 and 4 zero bytes total, exactly
// as TR-06-1 §5.2.5 requires. The expression matches libRIST
// src/proto/rtp.c:74: ((10 + namelen + 1) + 3) & ~3.
func sdesSize(n int) int { return (sdesFixedSize + n + 1 + 3) &^ 3 }

// MarshalSize returns the encoded size: 12 to 268 bytes depending on the
// CNAME length, always a multiple of 4.
func (p SDES) MarshalSize() int { return sdesSize(min(len(p.CNAME), maxCNAMELen)) }

// AppendTo appends the encoding to buf and returns the extended slice.
func (p SDES) AppendTo(buf []byte) []byte {
	name := p.CNAME
	if len(name) > maxCNAMELen {
		name = name[:maxCNAMELen]
	}
	size := sdesSize(len(name))
	buf = appendHeader(buf, 1, PTSDES, uint16(size/4-1))
	buf, w := grow(buf, size-headerSize)
	binary.BigEndian.PutUint32(w[0:4], p.SSRC)
	w[4] = sdesItemCNAME
	w[5] = byte(len(name))
	copy(w[6:], name)
	for i := 6 + len(name); i < len(w); i++ {
		w[i] = 0
	}
	return buf
}

func (SDES) isPacket() {}

// decodeSDES decodes a PT=202 packet of the RIST shape: SC=1, one CNAME
// item, and an all-zero chunk terminator of at least one byte. Packets with
// more padding than the canonical 1-4 zero bytes are accepted (the chunk
// terminator rule of RFC 3550 §6.5 allows null-item padding to any 32-bit
// boundary) and re-encode canonically.
func decodeSDES(h header, body []byte) (Packet, bool) {
	if h.count != 1 || h.size < sdesFixedSize+1 || body[8] != sdesItemCNAME {
		return nil, false
	}
	n := int(body[9])
	if sdesFixedSize+n+1 > h.size {
		return nil, false
	}
	// Everything after the name must be the zero terminator/padding.
	for _, b := range body[sdesFixedSize+n:] {
		if b != 0 {
			return nil, false
		}
	}
	return SDES{
		SSRC:  binary.BigEndian.Uint32(body[4:8]),
		CNAME: string(body[sdesFixedSize : sdesFixedSize+n]),
	}, true
}

// Package fec implements SMPTE ST 2022-1 forward error correction for RIST: a
// 2-D (row + column) XOR scheme over the protected RTP packets, the FEC method
// the VSF TR-06 family adopts (TR-06-2 §8.4, TR-06-3 §5.3.5). The sender clips
// each media packet into a row group and a column group; when a group fills it
// emits one FEC packet that is the XOR of the group's packets. The receiver
// rebuilds any single packet missing from a row or column by XOR-ing the FEC
// packet with the group's received members, and feeds the recovered packet back
// into the flow exactly like an ARQ retransmit — FEC is just another source of
// packets into the one seq-indexed ring.
//
// # Sans-I/O
//
// Encoder and Decoder are deterministic and own no clock, socket, or goroutine.
// They operate on the encoded RTP datagram bytes (the spec computes FEC over the
// final, post-encryption packets), so the host runs the encoder after media
// encoding and the decoder before media decoding, draining recovered packets as
// returned values.
//
// The XOR matrix logic is ported from the author's pure-Go SRT stack (srtgo's
// internal/filter); the wire framing here is the SMPTE ST 2022-1 FEC header, not
// SRT's, and FEC-level loss reporting is omitted because ristgo's flow core owns
// NACK/dedup/reorder.
package fec

import (
	"encoding/binary"
	"errors"
)

// HeaderSize is the size of the SMPTE ST 2022-1 FEC header (TR-06-2 Figure 17),
// which precedes the recovered payload in every FEC packet.
const HeaderSize = 16

// ErrShortHeader is returned when a buffer is too small to hold a FEC header.
var ErrShortHeader = errors.New("rist: fec: buffer shorter than the FEC header")

// Direction is the FEC dimension a packet protects: column (vertical, every Lth
// packet) or row (horizontal, L consecutive packets).
type Direction uint8

const (
	// Column marks a column (vertical) FEC packet: it protects D packets spaced
	// L apart (Offset=L, NA=D, D-bit=0).
	Column Direction = 0
	// Row marks a row (horizontal) FEC packet: it protects L consecutive packets
	// (Offset=1, NA=L, D-bit=1).
	Row Direction = 1
)

// Header is the SMPTE ST 2022-1 FEC header. The recovery fields are the XOR of
// the corresponding fields of the protected packets, from which the receiver
// reconstructs a single missing packet. SNBase (with SNBaseExt) is the lowest
// 24-bit sequence number the FEC packet protects; Offset and NA describe the
// group geometry so the receiver knows which packets the FEC covers.
type Header struct {
	// SNBase is the low 16 bits of the base (lowest) protected sequence number;
	// SNBaseExt carries the next 8 bits (TR-06-2 §8.6 ties these to the extended
	// sequence number's low 24 bits).
	SNBase uint16
	// LengthRecovery is the XOR of the protected packets' payload lengths.
	LengthRecovery uint16
	// PTRecovery is the XOR of the protected packets' 7-bit RTP payload types.
	PTRecovery uint8
	// TSRecovery is the XOR of the protected packets' RTP timestamps.
	TSRecovery uint32
	// Direction is Column or Row.
	Direction Direction
	// Offset is the spacing between protected packets: L for a column, 1 for a row.
	Offset uint8
	// NA is the number of packets protected: D for a column, L for a row.
	NA uint8
	// SNBaseExt is bits 16-23 of the base sequence number.
	SNBaseExt uint8
}

// AppendTo encodes the header (big-endian, 16 bytes) onto dst and returns the
// extended slice. The E, N, type, index, and Mask fields are zero: ST 2022-1
// uses plain XOR with no RFC 2733 extension or mask.
func (h Header) AppendTo(dst []byte) []byte {
	var b [HeaderSize]byte
	binary.BigEndian.PutUint16(b[0:2], h.SNBase)
	binary.BigEndian.PutUint16(b[2:4], h.LengthRecovery)
	b[4] = h.PTRecovery & 0x7f // E (bit 7) = 0
	// b[5:8] Mask = 0 (ST 2022-1 does not use the RFC 2733 mask)
	binary.BigEndian.PutUint32(b[8:12], h.TSRecovery)
	// b[12]: N(1)=0 | D(1) | type(3)=0 | index(3)=0
	b[12] = byte(h.Direction&0x1) << 6
	b[13] = h.Offset
	b[14] = h.NA
	b[15] = h.SNBaseExt
	return append(dst, b[:]...)
}

// ParseHeader decodes a SMPTE ST 2022-1 FEC header from the front of b and
// returns it along with the offset of the recovered payload. It never panics on
// short or arbitrary input.
func ParseHeader(b []byte) (h Header, payloadOffset int, err error) {
	if len(b) < HeaderSize {
		return Header{}, 0, ErrShortHeader
	}
	h.SNBase = binary.BigEndian.Uint16(b[0:2])
	h.LengthRecovery = binary.BigEndian.Uint16(b[2:4])
	h.PTRecovery = b[4] & 0x7f
	h.TSRecovery = binary.BigEndian.Uint32(b[8:12])
	h.Direction = Direction((b[12] >> 6) & 0x1)
	h.Offset = b[13]
	h.NA = b[14]
	h.SNBaseExt = b[15]
	return h, HeaderSize, nil
}

// base24 returns the 24-bit base sequence number (SNBaseExt<<16 | SNBase).
func (h Header) base24() uint32 {
	return uint32(h.SNBaseExt)<<16 | uint32(h.SNBase)
}

// setBase24 stores the low 24 bits of seq into SNBase and SNBaseExt.
func (h *Header) setBase24(seq uint32) {
	h.SNBase = uint16(seq)
	h.SNBaseExt = uint8(seq >> 16)
}

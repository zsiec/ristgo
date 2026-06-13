// Package rtcp implements the RIST compound RTCP codec: the minimal RTCP
// subset mandated by VSF TR-06-1 §5.2 (Sender Report, Receiver Report, empty
// Receiver Report, SDES/CNAME, and the RTT Echo APP packets), the two NACK
// retransmission-request encodings of TR-06-1 §5.3.2 (RFC 4585 Generic NACK
// bitmask and the RIST APP range NACK), and the EXTSEQ APP packet of
// VSF TR-06-2 §8.4 that widens NACK sequence numbers to 32 bits.
//
// libRIST (src/proto/rtp.h, src/proto/rtp.c, src/udp.c) is the authoritative
// interop reference; where the spec is ambiguous the byte layout here matches
// libRIST and the relevant file:line is cited in a comment.
//
// # Decoding policy
//
// Parse and ParseCompound never panic on arbitrary input. Framing violations
// (truncated buffer, RTCP version other than 2, a length field that overruns
// the datagram) are hard errors. A packet that frames correctly but does not
// match a RIST packet shape (unknown payload type, unknown APP name or
// subtype, an SR with reception report blocks, ...) is returned as a Raw
// packet rather than an error, mirroring RFC 3550's "ignore what you do not
// understand" rule so one foreign packet cannot poison a whole compound.
//
// Decoded packets do not alias the input buffer: strings, padding, and Raw
// bytes are copied, so the caller may recycle its receive buffer immediately.
//
// # Encoding policy
//
// Every packet type encodes through MarshalSize and AppendTo. AppendTo
// appends to a caller-supplied buffer and performs no allocation when the
// buffer already has capacity (the hot path; enforced by tests and
// benchmarks). Encoders are canonical: they always produce the exact byte
// layout RIST mandates, normalizing fields the spec defines as
// zero/reserved. Within the documented per-type field bounds (see each
// packet's field docs — the NACK record counts and echo padding feed a
// 16-bit length field) decode(encode(x)) == x for every value an encoder can
// produce, and re-encoding a decoded packet is byte-stable.
package rtcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// RTCP packet types used by RIST (libRIST src/proto/rtp.h:92-96).
const (
	// PTSenderReport is the RTCP Sender Report packet type
	// (PTYPE_SR = 200, TR-06-1 §5.2.2).
	PTSenderReport = 200

	// PTReceiverReport is the RTCP Receiver Report packet type
	// (PTYPE_RR = 201, TR-06-1 §5.2.3 and §5.2.4).
	PTReceiverReport = 201

	// PTSDES is the RTCP Source Description packet type
	// (PTYPE_SDES = 202, TR-06-1 §5.2.5).
	PTSDES = 202

	// PTApp is the RTCP Application-Defined packet type carrying the RIST
	// range NACK, RTT echo, and EXTSEQ packets
	// (PTYPE_NACK_CUSTOM = 204, TR-06-1 §5.2.6/§5.3.2.2, TR-06-2 §8.4).
	PTApp = 204

	// PTTransportFeedback is the RTCP Transport-Layer Feedback packet type
	// carrying the RFC 4585 Generic NACK bitmask
	// (PTYPE_NACK_BITMASK = 205, TR-06-1 §5.3.2.1).
	PTTransportFeedback = 205
)

// APP packet subtypes under the "RIST" name (libRIST src/proto/rtp.h:100-103
// and TR-06-2 §8.4).
const (
	// AppSubtypeRangeNACK identifies a range-based retransmission request
	// (NACK_FMT_RANGE = 0, TR-06-1 §5.3.2.2).
	AppSubtypeRangeNACK = 0

	// AppSubtypeExtSeq identifies an EXTSEQ sequence-number-extension
	// packet (TR-06-2 §8.4: "using “RIST” as the name and a subtype of 1").
	// libRIST does not implement this packet; TR-06-2 is authoritative.
	AppSubtypeExtSeq = 1

	// AppSubtypeEchoRequest identifies an RTT Echo Request
	// (ECHO_REQUEST = 2, TR-06-1 §5.2.6).
	AppSubtypeEchoRequest = 2

	// AppSubtypeEchoResponse identifies an RTT Echo Response
	// (ECHO_RESPONSE = 3, TR-06-1 §5.2.6).
	AppSubtypeEchoResponse = 3
)

// FMTGenericNACK is the RFC 4585 feedback message type for the Generic NACK,
// carried in the 5-bit count field of a PT=205 packet
// (NACK_FMT_BITMASK = 1, libRIST src/proto/rtp.h:100).
const FMTGenericNACK = 1

// NameRIST is the 32-bit ASCII name "RIST" carried by every RIST APP packet
// (0x52495354, TR-06-1 §5.3.2.2).
const NameRIST uint32 = 0x52495354

// headerSize is the fixed RTCP packet header: flags, packet type, and the
// 16-bit length-in-words-minus-one field.
const headerSize = 4

// appFixedSize is the fixed prefix of every RIST APP packet: header, media
// SSRC, and the 4-byte "RIST" name (RTCP_FB_HEADER_SIZE, libRIST
// src/proto/rtp.h:83).
const appFixedSize = 12

// versionFlag is the V=2, P=0, count=0 flags byte; type-specific subtype/
// count bits are OR-ed in (RTCP_SR_FLAGS = 0x80, libRIST src/proto/rtp.h:107).
const versionFlag = 0x80

// Sentinel errors. Returned errors may wrap these with positional context;
// test with errors.Is.
var (
	// ErrShortPacket is returned when a buffer is too short for the RTCP
	// header or for the size its length field declares.
	ErrShortPacket = errors.New("rist: rtcp packet truncated")

	// ErrBadVersion is returned when a packet's version field is not 2.
	ErrBadVersion = errors.New("rist: rtcp version is not 2")

	// ErrEmptyCompound is returned by ParseCompound for an empty datagram.
	ErrEmptyCompound = errors.New("rist: empty rtcp compound")

	// ErrCompoundOrder is returned by BuildCompound when the packet
	// sequence violates the RIST compound ordering rules (TR-06-1 §5.2.1,
	// TR-06-2 §8.4).
	ErrCompoundOrder = errors.New("rist: rtcp compound order violation")
)

// Packet is one RTCP packet of a RIST compound datagram. The variant set is
// the packet types defined in this package; an exhaustive type switch over
// them should still treat its default case as a reachable programming error
// (see isPacket).
type Packet interface {
	// MarshalSize returns the encoded size in bytes, always a multiple
	// of 4.
	MarshalSize() int

	// AppendTo appends the packet's encoding to buf and returns the
	// extended slice. It does not allocate when buf has spare capacity of
	// at least MarshalSize bytes.
	AppendTo(buf []byte) []byte

	// isPacket is the sealing marker. It is unexported so that no new
	// variant can be defined outside this package. Note the limit of the
	// guarantee: a foreign type CAN satisfy Packet by embedding a variant
	// (e.g. Raw), but its dynamic type matches no case of an exhaustive
	// switch over the variants defined here — so switches must treat their
	// default case as a reachable programming error, not as impossible.
	isPacket()
}

// Raw is an RTCP packet that framed correctly (valid version and length) but
// is not one of the RIST packet shapes — an unknown payload type, an APP
// packet with a foreign name, an SR carrying reception report blocks, and so
// on. It preserves the full packet bytes, header included, so a compound can
// be parsed losslessly and foreign packets skipped per RFC 3550.
//
// A Raw returned by Parse always frames correctly: its embedded RTCP length
// field (bytes 2-3, length-in-words-minus-one) agrees with len(Raw). AppendTo
// copies the bytes verbatim and does not re-validate, so a hand-built Raw must
// preserve that invariant or it will corrupt the framing of any compound it is
// encoded into.
type Raw []byte

// MarshalSize returns the stored packet length in bytes.
func (r Raw) MarshalSize() int { return len(r) }

// AppendTo appends the stored bytes verbatim.
func (r Raw) AppendTo(buf []byte) []byte { return append(buf, r...) }

func (Raw) isPacket() {}

// header is the decoded fixed RTCP header.
type header struct {
	count byte // 5-bit count field: RC, SC, FMT, or APP subtype
	pt    byte
	size  int // whole-packet size in bytes, (length+1)*4
}

// parseHeader validates the fixed header of the packet at the start of b.
// It enforces version 2 and that the declared size fits within b; those are
// the only hard framing errors. The P (padding) bit is not honored as a
// separate concept: TR-06-1 mandates P=0 everywhere, so a set P bit simply
// fails the typed decoders and yields a Raw packet.
func parseHeader(b []byte) (header, error) {
	if len(b) < headerSize {
		return header{}, fmt.Errorf("%w: %d bytes, need %d for header", ErrShortPacket, len(b), headerSize)
	}
	if b[0]>>6 != 2 {
		return header{}, fmt.Errorf("%w: got version %d", ErrBadVersion, b[0]>>6)
	}
	size := (int(binary.BigEndian.Uint16(b[2:4])) + 1) * 4
	if size > len(b) {
		return header{}, fmt.Errorf("%w: length field declares %d bytes, %d available", ErrShortPacket, size, len(b))
	}
	return header{count: b[0] & 0x1F, pt: b[1], size: size}, nil
}

// appendHeader appends the 4-byte fixed header. count carries the 5-bit
// RC/SC/FMT/subtype field; words is the length field (size/4 - 1).
func appendHeader(buf []byte, count, pt byte, words uint16) []byte {
	return append(buf, versionFlag|count, pt, byte(words>>8), byte(words))
}

// Parse decodes the first RTCP packet in b, returning the packet and the
// number of bytes it consumed. Framing violations are errors; well-framed
// packets that are not RIST shapes come back as Raw (see the package
// decoding policy). The returned packet does not alias b.
func Parse(b []byte) (Packet, int, error) {
	h, err := parseHeader(b)
	if err != nil {
		return nil, 0, err
	}
	// Every typed decoder below relies on len(body) == h.size (parseHeader
	// validated h.size <= len(b)) to bound its reads off the length field.
	body := b[:h.size]

	// b[0]&0xE0 == versionFlag requires V=2 (already checked) and P=0
	// (TR-06-1 §5.2: every RIST RTCP packet shall have P=0).
	if p := b[0] & 0x20; p == 0 {
		if pkt, ok := decodeTyped(h, body); ok {
			return pkt, h.size, nil
		}
	}
	return Raw(slices.Clone(body)), h.size, nil
}

// decodeTyped attempts the RIST-shape decoders for a framed packet. A false
// return means "not a RIST shape" and the caller falls back to Raw.
func decodeTyped(h header, body []byte) (Packet, bool) {
	switch h.pt {
	case PTSenderReport:
		return decodeSenderReport(h, body)
	case PTReceiverReport:
		return decodeReceiverReport(h, body)
	case PTSDES:
		return decodeSDES(h, body)
	case PTApp:
		return decodeApp(h, body)
	case PTTransportFeedback:
		return decodeBitmaskNACK(h, body)
	}
	return nil, false
}

// decodeApp dispatches a PT=204 APP packet by its "RIST" subtype. APP
// packets with names other than "RIST" are foreign and rejected to Raw, as
// RFC 3550 §6.7 directs for unrecognized APP names.
func decodeApp(h header, body []byte) (Packet, bool) {
	if len(body) < appFixedSize || binary.BigEndian.Uint32(body[8:12]) != NameRIST {
		return nil, false
	}
	switch h.count {
	case AppSubtypeRangeNACK:
		return decodeRangeNACK(body)
	case AppSubtypeExtSeq:
		return decodeExtSeq(body)
	case AppSubtypeEchoRequest, AppSubtypeEchoResponse:
		return decodeEcho(h.count, body)
	}
	return nil, false
}

// grow extends buf by n bytes and returns the extended slice together with
// the freshly added n-byte window for the caller to fill. It allocates only
// when buf lacks capacity.
func grow(buf []byte, n int) (extended, window []byte) {
	extended = slices.Grow(buf, n)[:len(buf)+n]
	return extended, extended[len(buf):]
}

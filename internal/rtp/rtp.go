// Package rtp implements the RTP packet codec (RFC 3550 §5.1) trimmed to
// what RIST needs: the fixed 12-byte header, CSRC list, the classic RFC 3550
// header extension (16-bit profile + 16-bit length in 32-bit words + opaque
// payload), and trailing padding.
//
// RIST specifics handled here:
//
//   - The header extension is carried as opaque bytes only. RIST NPD (the
//     Simple/Main-profile null-packet-deletion extension, TR-06-2) uses
//     profile 0x5249 ("RI"); its semantics are decoded by a later package
//     (internal/npd), never here.
//   - Retransmissions are NOT RFC 4588: a RIST retransmission is the
//     original RTP packet — same sequence number, same timestamp, same
//     payload — with only the SSRC least-significant bit set. See
//     NormalizeSSRC, MarkRetransmit, and IsRetransmit in ssrc.go.
//
// All multi-byte fields are big-endian (network order). Decoding arbitrary
// bytes returns errors and never panics. Encoding writes into caller-provided
// buffers (MarshalTo/AppendTo) and performs no allocations on the hot path.
//
// Portions ported from github.com/pion/rtp (MIT License, (c) Pion
// contributors); modified for ristgo. See NOTICE.md. Deviations from pion:
// only the classic RFC 3550 extension is supported (RFC 8285 one-/two-byte
// element parsing is dropped — every profile, including 0xBEDE/0x1000, is
// treated as opaque payload), marshalling validates Version and the CSRC
// count instead of silently corrupting the first byte, and decode is
// zero-copy (Payload/ExtensionPayload alias the input buffer).
package rtp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinel errors returned by the codec. Callers should test for them with
// errors.Is, as returned errors may wrap these with additional context.
var (
	// ErrHeaderTooShort is returned by Unmarshal when the buffer cannot
	// hold the fixed RTP header plus the CSRC list announced by the CC
	// field (RFC 3550 §5.1).
	ErrHeaderTooShort = errors.New("rist: rtp: header too short")

	// ErrExtensionTooShort is returned by Unmarshal when the X bit is set
	// but the buffer cannot hold the 4-byte extension header plus the
	// payload length it announces (RFC 3550 §5.3.1).
	ErrExtensionTooShort = errors.New("rist: rtp: header extension truncated")

	// ErrPacketTooShort is returned by Packet.Unmarshal when the P bit is
	// set but no padding byte is present after the header.
	ErrPacketTooShort = errors.New("rist: rtp: packet too short")

	// ErrInvalidPadding is returned when the padding count (the last byte
	// of the packet, RFC 3550 §5.1 "P" bit) is zero or larger than the
	// space after the header, or, on marshal, when Header.Padding and
	// Packet.PaddingSize disagree.
	ErrInvalidPadding = errors.New("rist: rtp: invalid padding")

	// ErrShortBuffer is returned by MarshalTo when the destination buffer
	// is smaller than MarshalSize.
	ErrShortBuffer = errors.New("rist: rtp: short buffer")

	// ErrInvalidVersion is returned by MarshalTo when Header.Version does
	// not fit the 2-bit V field (i.e. Version > 3).
	ErrInvalidVersion = errors.New("rist: rtp: version does not fit 2-bit field")

	// ErrTooManyCSRC is returned by MarshalTo when len(Header.CSRC)
	// exceeds 15, the maximum the 4-bit CC field can express.
	ErrTooManyCSRC = errors.New("rist: rtp: more than 15 CSRC entries")

	// ErrExtensionNotAligned is returned by MarshalTo when the X bit is
	// set and len(ExtensionPayload) is not a multiple of 4: the RFC 3550
	// extension length field counts 32-bit words (RFC 3550 §5.3.1).
	ErrExtensionNotAligned = errors.New("rist: rtp: extension payload not a multiple of 4 bytes")

	// ErrExtensionTooLong is returned by MarshalTo when the extension
	// payload exceeds 65535 32-bit words, the maximum the 16-bit length
	// field can express.
	ErrExtensionTooLong = errors.New("rist: rtp: extension payload longer than 65535 words")
)

const (
	// Version is the RTP version number every RIST packet carries in the
	// 2-bit V field (RFC 3550 §5.1).
	Version = 2

	// FixedHeaderSize is the size in bytes of the fixed RTP header,
	// before any CSRC entries or header extension (RFC 3550 §5.1).
	FixedHeaderSize = 12

	// MaxCSRC is the maximum number of CSRC entries the 4-bit CC field
	// can express (RFC 3550 §5.1).
	MaxCSRC = 15

	// ExtensionProfileRIST is the "defined by profile" value of the RIST
	// NPD header extension: 0x5249, ASCII "RI"
	// (rist_rtp_hdr_ext.identifier; TR-06-2). This package only carries
	// the extension bytes; NPD semantics live in a separate package.
	ExtensionProfileRIST = 0x5249

	// PayloadTypeMPEGTS is the RTP payload type RIST uses for MPEG
	// transport stream media: 33 (RTP_PTYPE_MPEGTS).
	PayloadTypeMPEGTS = 0x21

	// ClockRateMPEGTS is the RTP timestamp clock rate, in Hz, of the
	// MPEG-TS payload type (RTP_PTYPE_MPEGTS_CLOCKHZ).
	ClockRateMPEGTS = 90000
)

// Field layout of the fixed header (RFC 3550 §5.1):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|V=2|P|X|  CC   |M|     PT      |       sequence number         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           timestamp                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           synchronization source (SSRC) identifier            |
//	+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//	|            contributing source (CSRC) identifiers             |
//	|                             ....                              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
const (
	versionShift   = 6
	versionMask    = 0x3
	paddingShift   = 5
	extensionShift = 4
	ccMask         = 0xF
	markerShift    = 7
	ptMask         = 0x7F
	csrcOffset     = 12
	csrcLength     = 4
	extHeaderSize  = 4 // 16-bit profile + 16-bit length in words
)

// Header is a parsed RTP packet header (RFC 3550 §5.1). librist's
// rist_rtp_hdr is the same fixed 12 bytes with the first two octets
// collapsed into flags/payload_type.
type Header struct {
	// Version is the 2-bit V field; always 2 on a valid RIST wire.
	// Unmarshal does not reject other values (matching pion and librist,
	// which never check it); MarshalTo rejects values above 3.
	Version uint8

	// Padding is the P bit: the payload is followed by padding octets,
	// the last of which counts the padding (see Packet.PaddingSize).
	Padding bool

	// Extension is the X bit: exactly one RFC 3550 header extension
	// follows the CSRC list.
	Extension bool

	// CSRCCount is the 4-bit CC field as read off the wire. Unmarshal
	// sets it to len(CSRC); MarshalTo derives the wire CC field from
	// len(CSRC) and ignores this field, so callers building headers by
	// hand need not maintain it.
	CSRCCount uint8

	// Marker is the M bit. RIST MPEG-TS media never sets it
	// (RTP_MPEGTS_FLAGS 0x80 = version 2 only).
	Marker bool

	// PayloadType is the 7-bit PT field. RIST media uses
	// PayloadTypeMPEGTS (33).
	PayloadType uint8

	// SequenceNumber is the 16-bit RTP sequence number. RIST recovers
	// loss against this number; a retransmission repeats it unchanged.
	SequenceNumber uint16

	// Timestamp is the 32-bit RTP timestamp (90 kHz for MPEG-TS).
	Timestamp uint32

	// SSRC identifies the RIST flow. The base flow SSRC is always even;
	// an odd SSRC marks a retransmission (see ssrc.go).
	SSRC uint32

	// CSRC is the contributing-source list, 0-15 entries. RIST does not
	// use CSRCs, but the codec carries them for RFC 3550 completeness.
	CSRC []uint32

	// ExtensionProfile is the 16-bit "defined by profile" field of the
	// RFC 3550 header extension. Only meaningful when Extension is true.
	// RIST NPD uses ExtensionProfileRIST (0x5249).
	ExtensionProfile uint16

	// ExtensionPayload is the extension body excluding the 4-byte
	// extension header; its length is always a multiple of 4 (the wire
	// length field counts 32-bit words). Only meaningful when Extension
	// is true. After Unmarshal it aliases the input buffer.
	ExtensionPayload []byte
}

// Packet is a parsed RTP packet: header, payload, and trailing padding.
type Packet struct {
	Header

	// Payload is the media payload, excluding any padding. After
	// Unmarshal it aliases the input buffer.
	Payload []byte

	// PaddingSize is the total number of padding octets at the end of
	// the packet, including the count octet itself (RFC 3550 §5.1). It
	// is non-zero exactly when Header.Padding is set. Unmarshal fills it
	// from the last octet; MarshalTo emits PaddingSize-1 zero octets
	// followed by the count. (Wire padding octets other than the count
	// are ignored on decode and re-encoded as zeros.)
	PaddingSize uint8
}

// Unmarshal parses an RTP header from buf and stores the result in h,
// returning the number of bytes consumed (fixed header + CSRC list +
// extension, if present). All previous contents of h are overwritten; CSRC
// capacity is reused when possible. ExtensionPayload aliases buf. Arbitrary
// input returns an error rather than panicking.
func (h *Header) Unmarshal(buf []byte) (int, error) {
	if len(buf) < FixedHeaderSize {
		return 0, fmt.Errorf("%w: %d < %d bytes", ErrHeaderTooShort, len(buf), FixedHeaderSize)
	}

	h.Version = buf[0] >> versionShift & versionMask
	h.Padding = buf[0]>>paddingShift&0x1 != 0
	h.Extension = buf[0]>>extensionShift&0x1 != 0
	nCSRC := int(buf[0] & ccMask)
	h.CSRCCount = uint8(nCSRC)

	h.Marker = buf[1]>>markerShift != 0
	h.PayloadType = buf[1] & ptMask

	h.SequenceNumber = binary.BigEndian.Uint16(buf[2:4])
	h.Timestamp = binary.BigEndian.Uint32(buf[4:8])
	h.SSRC = binary.BigEndian.Uint32(buf[8:12])

	n := csrcOffset + nCSRC*csrcLength
	if len(buf) < n {
		return 0, fmt.Errorf("%w: %d < %d bytes with %d CSRCs",
			ErrHeaderTooShort, len(buf), n, nCSRC)
	}
	if cap(h.CSRC) < nCSRC {
		h.CSRC = make([]uint32, nCSRC)
	} else {
		h.CSRC = h.CSRC[:nCSRC]
	}
	for i := range h.CSRC {
		h.CSRC[i] = binary.BigEndian.Uint32(buf[csrcOffset+i*csrcLength:])
	}

	h.ExtensionProfile = 0
	h.ExtensionPayload = nil
	if h.Extension {
		if len(buf) < n+extHeaderSize {
			return 0, fmt.Errorf("%w: %d < %d bytes for extension header",
				ErrExtensionTooShort, len(buf), n+extHeaderSize)
		}
		h.ExtensionProfile = binary.BigEndian.Uint16(buf[n:])
		extLen := int(binary.BigEndian.Uint16(buf[n+2:])) * 4
		n += extHeaderSize
		if len(buf) < n+extLen {
			return 0, fmt.Errorf("%w: %d < %d bytes for %d-byte extension payload",
				ErrExtensionTooShort, len(buf), n+extLen, extLen)
		}
		h.ExtensionPayload = buf[n : n+extLen : n+extLen]
		n += extLen
	}

	return n, nil
}

// MarshalSize returns the number of bytes MarshalTo will write: the fixed
// header, the CSRC list, and, when Extension is set, the 4-byte extension
// header plus ExtensionPayload.
func (h Header) MarshalSize() int {
	size := FixedHeaderSize + len(h.CSRC)*csrcLength
	if h.Extension {
		size += extHeaderSize + len(h.ExtensionPayload)
	}
	return size
}

// MarshalTo serializes the header into buf (RFC 3550 §5.1 layout,
// big-endian) and returns the number of bytes written. The CC field is
// derived from len(CSRC); CSRCCount is ignored. When Extension is false,
// ExtensionProfile and ExtensionPayload are ignored. It performs no
// allocations.
func (h Header) MarshalTo(buf []byte) (int, error) {
	if h.Version > versionMask {
		return 0, fmt.Errorf("%w: %d", ErrInvalidVersion, h.Version)
	}
	if len(h.CSRC) > MaxCSRC {
		return 0, fmt.Errorf("%w: %d", ErrTooManyCSRC, len(h.CSRC))
	}
	if h.Extension {
		if len(h.ExtensionPayload)%4 != 0 {
			return 0, fmt.Errorf("%w: %d bytes", ErrExtensionNotAligned, len(h.ExtensionPayload))
		}
		if len(h.ExtensionPayload)/4 > 0xFFFF {
			return 0, fmt.Errorf("%w: %d words", ErrExtensionTooLong, len(h.ExtensionPayload)/4)
		}
	}
	size := h.MarshalSize()
	if len(buf) < size {
		return 0, fmt.Errorf("%w: %d < %d bytes", ErrShortBuffer, len(buf), size)
	}

	buf[0] = h.Version<<versionShift | uint8(len(h.CSRC))
	if h.Padding {
		buf[0] |= 1 << paddingShift
	}
	if h.Extension {
		buf[0] |= 1 << extensionShift
	}
	buf[1] = h.PayloadType & ptMask
	if h.Marker {
		buf[1] |= 1 << markerShift
	}
	binary.BigEndian.PutUint16(buf[2:4], h.SequenceNumber)
	binary.BigEndian.PutUint32(buf[4:8], h.Timestamp)
	binary.BigEndian.PutUint32(buf[8:12], h.SSRC)

	n := csrcOffset
	for _, csrc := range h.CSRC {
		binary.BigEndian.PutUint32(buf[n:], csrc)
		n += csrcLength
	}

	if h.Extension {
		binary.BigEndian.PutUint16(buf[n:], h.ExtensionProfile)
		binary.BigEndian.PutUint16(buf[n+2:], uint16(len(h.ExtensionPayload)/4))
		n += extHeaderSize
		n += copy(buf[n:], h.ExtensionPayload)
	}

	return n, nil
}

// AppendTo appends the serialized header to buf, growing it as needed, and
// returns the extended slice. When buf already has sufficient capacity no
// allocation occurs. On error buf is returned unchanged.
func (h Header) AppendTo(buf []byte) ([]byte, error) {
	n := len(buf)
	buf = growSlice(buf, h.MarshalSize())
	if _, err := h.MarshalTo(buf[n:]); err != nil {
		return buf[:n], err
	}
	return buf, nil
}

// Unmarshal parses a full RTP packet from buf and stores the result in p.
// When the P bit is set, the padding count is read from the last octet and
// stripped from Payload (RFC 3550 §5.1). Payload and ExtensionPayload alias
// buf. Arbitrary input returns an error rather than panicking.
func (p *Packet) Unmarshal(buf []byte) error {
	n, err := p.Header.Unmarshal(buf)
	if err != nil {
		return err
	}

	end := len(buf)
	if p.Header.Padding {
		if end <= n {
			return fmt.Errorf("%w: no room for padding count octet", ErrPacketTooShort)
		}
		pad := buf[end-1]
		if pad == 0 {
			return fmt.Errorf("%w: padding count is zero", ErrInvalidPadding)
		}
		if int(pad) > end-n {
			return fmt.Errorf("%w: %d padding bytes > %d bytes after header",
				ErrInvalidPadding, pad, end-n)
		}
		p.PaddingSize = pad
		end -= int(pad)
	} else {
		p.PaddingSize = 0
	}

	p.Payload = buf[n:end:end]
	return nil
}

// MarshalSize returns the number of bytes MarshalTo will write: header,
// payload, and padding.
func (p Packet) MarshalSize() int {
	return p.Header.MarshalSize() + len(p.Payload) + int(p.PaddingSize)
}

// MarshalTo serializes the packet into buf and returns the number of bytes
// written. Header.Padding and PaddingSize must agree: padding is emitted as
// PaddingSize-1 zero octets followed by the count octet. It performs no
// allocations.
func (p Packet) MarshalTo(buf []byte) (int, error) {
	if p.Header.Padding != (p.PaddingSize > 0) {
		return 0, fmt.Errorf("%w: P bit %v but PaddingSize %d",
			ErrInvalidPadding, p.Header.Padding, p.PaddingSize)
	}

	n, err := p.Header.MarshalTo(buf)
	if err != nil {
		return 0, err
	}
	if len(buf) < n+len(p.Payload)+int(p.PaddingSize) {
		return 0, fmt.Errorf("%w: %d < %d bytes", ErrShortBuffer,
			len(buf), n+len(p.Payload)+int(p.PaddingSize))
	}

	n += copy(buf[n:], p.Payload)
	if p.PaddingSize > 0 {
		for i := 0; i < int(p.PaddingSize)-1; i++ {
			buf[n+i] = 0
		}
		buf[n+int(p.PaddingSize)-1] = p.PaddingSize
		n += int(p.PaddingSize)
	}

	return n, nil
}

// AppendTo appends the serialized packet to buf, growing it as needed, and
// returns the extended slice. When buf already has sufficient capacity no
// allocation occurs. On error buf is returned unchanged.
func (p Packet) AppendTo(buf []byte) ([]byte, error) {
	n := len(buf)
	buf = growSlice(buf, p.MarshalSize())
	if _, err := p.MarshalTo(buf[n:]); err != nil {
		return buf[:n], err
	}
	return buf, nil
}

// growSlice extends buf by size bytes, reallocating only when capacity is
// insufficient. The added bytes are not zeroed (the caller overwrites them).
func growSlice(buf []byte, size int) []byte {
	n := len(buf)
	if cap(buf)-n >= size {
		return buf[: n+size : cap(buf)]
	}
	grown := make([]byte, n+size)
	copy(grown, buf)
	return grown
}

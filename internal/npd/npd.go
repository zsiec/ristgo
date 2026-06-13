// Package npd implements RIST null-packet-deletion (NPD) and the RIST RTP
// header extension that carries it, byte-exact with libRIST v0.2.18-rc1.
//
// NPD is a Main-profile feature (VSF TR-06-2 §8; the Simple profile, TR-06-1,
// has no RTP header extension and no NPD) that saves bandwidth on MPEG-TS
// payloads: a packetized media payload is a whole number of TS packets (each
// 188 bytes, or 204 when forward-error-correction parity is appended), at most
// 7 of them. TS null packets — PID 0x1FFF, carrying no media — are removed from
// the payload before transmission and reconstructed identically at the
// receiver, with a 7-bit bitmap in the RTP header extension recording which
// positions were nulled.
//
// The RTP header extension is the RFC 3550 profile-specific extension
// (signalled by the RTP X bit) with profile identifier 0x5249 (ASCII "RI",
// big-endian) and length 1 (one 32-bit word of extension payload). Its eight
// wire bytes are: identifier(2) + length(2) + flags(1) + npd_bits(1) +
// seq_ext(2). The flags byte's bit 7 (N) signals NPD is present; npd_bits'
// bit 7 selects 204- vs 188-byte TS packets and bits 6..0 are the null bitmap;
// seq_ext carries the high 16 bits of a 32-bit extended sequence number (the
// Sequence Number Extension, TR-06-2 §8.3; on the wire at
// rist_rtp_hdr_ext.seq_ext, libRIST src/proto/rtp.h:136). libRIST populates and
// reads seq_ext only on the Advanced path, never on Simple/Main, so a
// Main-profile receiver widens the media sequence by 16-bit rollover instead.
//
// # Deliberate deviation from TR-06-2 Figure 15
//
// The spec's flags byte is N|E|Size(3 bits)|0 0 0|T, placing the 188/204 size
// selector (T) in the flags byte (bit 0) and defining an E bit (bit 6,
// "sequence extension in use") and a 3-bit Size field. libRIST instead encodes
// the size selector in npd_bits bit 7 and emits only flags bit 7 (N), never
// setting E, Size, or the spec's T bit (src/mpegts.c:18,23,33). This package
// follows libRIST for interop: NPDSize204 is npd_bits bit 7, the E and Size
// fields are intentionally unmodeled (libRIST neither emits nor reads them),
// and the null-bitmap ordering (MSB = first packet) matches both.
//
// The suppress/expand algorithm is ported from libRIST src/mpegts.c
// (suppress_null_packets / expand_null_packets). This package is pure: it does
// no I/O, reads no clock, and never panics on malformed input — short buffers,
// non-multiple lengths, over-long payloads, and bad sync bytes return errors.
package npd

import (
	"encoding/binary"
	"errors"
)

// Sentinel errors returned by this package. Callers should test for them with
// errors.Is; returned errors may wrap these with additional context.
var (
	// ErrShortExt is returned by ParseExt when the buffer is smaller than
	// the fixed 8-byte RIST RTP header extension.
	ErrShortExt = errors.New("rist: npd: header extension too short")

	// ErrBadIdentifier is returned by ParseExt when the extension profile
	// identifier is not 0x5249, the RIST "RI" value (librist
	// src/proto/rtp.h:132).
	ErrBadIdentifier = errors.New("rist: npd: header extension identifier is not 0x5249")

	// ErrBadLength is returned by ParseExt when the extension length field
	// is not 1, the only value RIST emits (librist src/proto/rtp.h:133).
	ErrBadLength = errors.New("rist: npd: header extension length is not 1")

	// ErrPayloadSize is returned by Suppress when the input is not a whole
	// number of 188- or 204-byte TS packets (librist src/mpegts.c:13-18).
	ErrPayloadSize = errors.New("rist: npd: payload is not a whole number of 188- or 204-byte TS packets")

	// ErrTooManyPackets is returned by Suppress when the input holds more
	// than 7 TS packets, the maximum the 7-bit npd bitmap can address
	// (librist src/mpegts.c:21).
	ErrTooManyPackets = errors.New("rist: npd: more than 7 TS packets")

	// ErrSyncByte is returned by Suppress when a TS packet does not begin
	// with the 0x47 sync byte (librist src/mpegts.c:28).
	ErrSyncByte = errors.New("rist: npd: TS packet missing 0x47 sync byte")

	// ErrTruncated is returned by Expand when the kept-packet input is too
	// short to satisfy the non-null positions the bitmap describes
	// (librist src/mpegts.c:82-83).
	ErrTruncated = errors.New("rist: npd: input too short for npd bitmap")
)

const (
	// Identifier is the RFC 3550 profile-specific extension identifier of
	// the RIST NPD header extension: 0x5249, ASCII "RI" big-endian (librist
	// src/proto/rtp.h:132, rist_rtp_hdr_ext.identifier).
	Identifier = 0x5249

	// Length is the extension length in 32-bit words, always 1: the four
	// extension-payload bytes are flags + npd_bits + seq_ext (librist
	// src/proto/rtp.h:133).
	Length = 1

	// ExtSize is the size in bytes of the encoded RIST RTP header
	// extension: identifier(2) + length(2) + flags(1) + npd_bits(1) +
	// seq_ext(2) (librist src/proto/rtp.h:131-137).
	ExtSize = 8

	// FlagNPD is the bit in the flags byte set when NPD is present
	// (libRIST SET_BIT(header_ext->flags, 7); src/mpegts.c:23).
	FlagNPD = 1 << 7

	// NPDSize204 is the bit in the npd_bits byte set when the TS packets
	// are 204 bytes rather than 188 (libRIST SET_BIT(header_ext->npd_bits,
	// 7); src/mpegts.c:18, expand CHECK_BIT(npd_bits,7); src/mpegts.c:59).
	NPDSize204 = 1 << 7

	// NullBitmapMask masks the low 7 bits of npd_bits: the null-position
	// bitmap (bit 6-i set means TS packet i was a null packet).
	NullBitmapMask = 0x7F

	// MaxPackets is the maximum number of TS packets a single NPD payload
	// may hold, bounded by the 7-bit bitmap (librist src/mpegts.c:21,22).
	MaxPackets = 7

	// SizeTS188 is the standard MPEG-TS packet size in bytes.
	SizeTS188 = 188

	// SizeTS204 is the MPEG-TS packet size in bytes with the 16-byte
	// Reed-Solomon parity trailer (librist src/mpegts.c:15).
	SizeTS204 = 204

	// SyncByte is the MPEG-TS packet sync byte, the first byte of every TS
	// packet (librist src/mpegts.c:28, src/mpegts.h header diagram).
	SyncByte = 0x47

	// NullPID is the MPEG-TS null-packet PID, 0x1FFF, occupying the 13-bit
	// PID field of the 16-bit flags1 word (librist src/mpegts.c:30,
	// src/mpegts.h).
	NullPID = 0x1FFF
)

// tsHeaderSize is the size in bytes of the MPEG-TS packet header libRIST
// reconstructs for a null packet: syncbyte(1) + flags1(2) + flags2(1) (librist
// struct mpegts_header, src/mpegts.h).
const tsHeaderSize = 4

// flags2Bit4 is the bit libRIST sets in the fourth MPEG-TS header byte of a
// reconstructed null packet: SET_BIT(hdr->flags2, 4) (librist
// src/mpegts.c:90). flags2 holds TSC|AF|CC; bit 4 is the low bit of the
// adaptation-field-control field, marking payload present.
const flags2Bit4 = 1 << 4

// Ext models the RIST RTP header extension (rist_rtp_hdr_ext, librist
// src/proto/rtp.h:131-137). It carries the NPD presence flag, the TS packet
// size selector, the 7-bit null bitmap, and the high 16 bits of the extended
// sequence number.
type Ext struct {
	// NPD reports whether the NPD flag (flags bit 7) is set: the payload
	// has had null packets removed and NullBitmap describes them.
	NPD bool

	// Size204 reports whether the TS packets are 204 bytes (npd_bits bit
	// 7) rather than the default 188.
	Size204 bool

	// NullBitmap is the 7-bit null-position map stored in the low 7 bits of
	// npd_bits. Bit (6-i) set means TS packet i (0..6) was a null packet.
	// Only the low 7 bits are significant; AppendTo masks the rest.
	NullBitmap byte

	// SeqExt is the high 16 bits of a 32-bit extended RTP sequence number (the
	// Sequence Number Extension field, TR-06-2 §8.3; on the wire at
	// rist_rtp_hdr_ext.seq_ext, librist src/proto/rtp.h:136). NOTE: libRIST
	// populates and consumes this only in the Advanced profile (its
	// rist_adv_seq32 helper operates on the separate rist_adv_ext struct, not
	// this RFC 3550 extension); on the Simple/Main path it is always 0 and the
	// receiver ignores it, widening by rollover instead.
	SeqExt uint16
}

// AppendTo appends the 8-byte wire encoding of the extension to dst and
// returns the extended slice (librist src/proto/rtp.h:131-137). The byte order
// is: identifier(2, big-endian) + length(2, big-endian) + flags(1) +
// npd_bits(1) + seq_ext(2, big-endian). NullBitmap is masked to 7 bits.
func (e Ext) AppendTo(dst []byte) []byte {
	var flags byte
	if e.NPD {
		flags |= FlagNPD
	}
	npdBits := e.NullBitmap & NullBitmapMask
	if e.Size204 {
		npdBits |= NPDSize204
	}
	dst = binary.BigEndian.AppendUint16(dst, Identifier)
	dst = binary.BigEndian.AppendUint16(dst, Length)
	dst = append(dst, flags, npdBits)
	dst = binary.BigEndian.AppendUint16(dst, e.SeqExt)
	return dst
}

// ParseExt decodes the 8-byte RIST RTP header extension at the start of b,
// returning the parsed Ext, the number of bytes consumed (always ExtSize on
// success), and an error. The identifier must be 0x5249 and the length must be
// 1; any other value, or a buffer shorter than 8 bytes, returns a sentinel
// error and never panics.
func ParseExt(b []byte) (Ext, int, error) {
	if len(b) < ExtSize {
		return Ext{}, 0, ErrShortExt
	}
	if binary.BigEndian.Uint16(b[0:2]) != Identifier {
		return Ext{}, 0, ErrBadIdentifier
	}
	if binary.BigEndian.Uint16(b[2:4]) != Length {
		return Ext{}, 0, ErrBadLength
	}
	flags := b[4]
	npdBits := b[5]
	e := Ext{
		NPD:        flags&FlagNPD != 0,
		Size204:    npdBits&NPDSize204 != 0,
		NullBitmap: npdBits & NullBitmapMask,
		SeqExt:     binary.BigEndian.Uint16(b[6:8]),
	}
	return e, ExtSize, nil
}

// NPDBits assembles the npd_bits byte (size flag in bit 7, null bitmap in bits
// 6..0) from a size selector and a 7-bit bitmap. It is the value Suppress
// returns and Expand consumes, and the value an Ext stores via its Size204 and
// NullBitmap fields.
func NPDBits(size204 bool, bitmap byte) byte {
	b := bitmap & NullBitmapMask
	if size204 {
		b |= NPDSize204
	}
	return b
}

// packetSize reports the TS packet size encoded by npd_bits bit 7 (librist
// src/mpegts.c:59).
func packetSize(npdBits byte) int {
	if npdBits&NPDSize204 != 0 {
		return SizeTS204
	}
	return SizeTS188
}

// Suppress removes MPEG-TS null packets (PID 0x1FFF) from in, appending the
// kept packets to dst, and returns the extended slice, the npd_bits byte to
// place in an Ext (size flag in bit 7, null bitmap in bits 6..0), the number of
// suppressed bytes, and an error. It ports libRIST suppress_null_packets
// (src/mpegts.c:12-56).
//
// in must be a whole number of TS packets, each 188 bytes — or 204 if the
// length is not a multiple of 188 — and at most 7 packets; otherwise an error
// is returned. Each packet must begin with the 0x47 sync byte. When no null
// packets are found, suppressed is 0, npdBits has only the (possibly set) size
// bit, and the whole input is copied to dst unchanged: NPD is not applied. When
// suppressed > 0 the caller sets the Ext NPD flag and emits npdBits.
func Suppress(dst, in []byte) (out []byte, npdBits byte, suppressed int, err error) {
	size := SizeTS188
	if len(in)%size != 0 {
		size = SizeTS204
		if len(in)%size != 0 {
			return dst, 0, 0, ErrPayloadSize
		}
		npdBits = NPDSize204
	}
	count := len(in) / size
	if count > MaxPackets {
		return dst, 0, 0, ErrTooManyPackets
	}

	// First pass: validate sync bytes and record the null bitmap. Match
	// libRIST: a bad sync byte fails the whole payload (src/mpegts.c:28,
	// the `fail` label clears the NPD flag).
	for i := 0; i < count; i++ {
		off := i * size
		if in[off] != SyncByte {
			return dst, 0, 0, ErrSyncByte
		}
		// flags1 is the 2 bytes after the sync byte; a null packet has
		// PID 0x1FFF, and for a null packet the whole flags1 word reads
		// 0x1FFF (librist src/mpegts.c:30).
		if binary.BigEndian.Uint16(in[off+1:off+3]) == NullPID {
			npdBits |= 1 << (6 - i)
			suppressed++
		}
	}

	if suppressed == 0 {
		// No NPD: copy the input through unchanged (the caller will not
		// set the NPD flag). npdBits still carries only the size bit.
		return append(out0(dst), in...), npdBits, 0, nil
	}

	// Second pass: copy only the non-null packets (librist
	// src/mpegts.c:44-50).
	out = out0(dst)
	for i := 0; i < count; i++ {
		if npdBits&(1<<(6-i)) == 0 {
			off := i * size
			out = append(out, in[off:off+size]...)
		}
	}
	return out, npdBits, suppressed * size, nil
}

// out0 returns dst unchanged; it documents that Suppress/Expand append to the
// caller's slice rather than allocating.
func out0(dst []byte) []byte { return dst }

// Expand reinserts MPEG-TS null packets into the kept-packet payload in,
// appending the reconstructed full payload to dst, using npdBits (the size flag
// and 7-bit null bitmap from the Ext). It ports libRIST expand_null_packets
// (src/mpegts.c:58-97).
//
// Each reconstructed null packet matches libRIST byte-for-byte: sync byte 0x47,
// flags1 = 0x1FFF (big-endian), flags2 bit 4 set, and the remaining
// packet_size-4 bytes filled with 0xFF (src/mpegts.c:88-92). packet_size is 204
// when npd_bits bit 7 is set, else 188. When the bitmap names no nulls, in is
// copied through unchanged. An error is returned (never a panic) when in is too
// short for the non-null positions or when the reconstructed packet count would
// exceed 7.
func Expand(dst, in []byte, npdBits byte) (out []byte, err error) {
	size := packetSize(npdBits)

	tsCount := len(in) / size
	bitmap := npdBits & NullBitmapMask
	nullCount := bitsSet(bitmap)

	if nullCount == 0 {
		// No nulls to reinsert: pass the input through unchanged
		// (librist returns 0; src/mpegts.c:65).
		return append(out0(dst), in...), nil
	}

	// npd_bits only encodes 7 positions, so a reconstructed count over 7 means
	// malformed/hostile input. libRIST no-ops here — returns 0, delivering the
	// payload un-expanded (src/mpegts.c:69-71); ristgo instead rejects it
	// defensively with the same sentinel Suppress uses for the over-7 case,
	// rather than delivering a wrongly-expanded payload. A conformant sender
	// never produces this (Suppress caps the count at MaxPackets).
	total := tsCount + nullCount
	if total > MaxPackets {
		return dst, ErrTooManyPackets
	}

	out = out0(dst)
	inOff := 0
	for i := 0; i < total; i++ {
		if bitmap&(1<<(6-i)) == 0 {
			// A kept (non-null) packet: copy it from the input
			// (librist src/mpegts.c:80-85).
			if inOff+size > len(in) {
				return dst, ErrTruncated
			}
			out = append(out, in[inOff:inOff+size]...)
			inOff += size
		} else {
			// Reconstruct a null packet (librist src/mpegts.c:88-92).
			out = appendNullPacket(out, size)
		}
	}
	return out, nil
}

// appendNullPacket appends a single reconstructed null TS packet of size bytes
// to dst, matching libRIST byte-for-byte (src/mpegts.c:88-92): 0x47 sync byte,
// flags1 = 0x1FFF big-endian, flags2 with bit 4 set, then 0xFF fill.
func appendNullPacket(dst []byte, size int) []byte {
	dst = append(dst, SyncByte)            // syncbyte
	dst = append(dst, 0x1F, 0xFF)          // flags1 = htobe16(0x1FFF)
	dst = append(dst, byte(flags2Bit4))    // flags2, SET_BIT(.,4)
	for i := tsHeaderSize; i < size; i++ { // remaining bytes = 0xFF
		dst = append(dst, 0xFF)
	}
	return dst
}

// bitsSet counts the set bits in the low 7 bits of b (librist counts each
// CHECK_BIT position individually; src/mpegts.c:67).
func bitsSet(b byte) int {
	n := 0
	for b &= NullBitmapMask; b != 0; b &= b - 1 {
		n++
	}
	return n
}

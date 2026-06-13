// Package gre implements the RIST Main-profile GRE-over-UDP framing
// (VSF TR-06-2), byte-exact with libRIST v0.2.18-rc1 (src/proto/gre.h and
// src/proto/gre.c).
//
// RIST tunnels its media and control traffic in a stripped-down GRE
// (RFC 2784) header carried directly inside UDP. The header is always at
// least four bytes — two flag octets and a big-endian 16-bit protocol type —
// optionally followed by a 4-byte key/nonce and a 4-byte sequence number. On
// the data channel a 4-byte "reduced overhead" header (a 16-bit virtual
// source/destination port pair) follows the GRE header and precedes the RTP
// payload. Keep-alive control packets carry a 6-byte MAC and two capability
// octets.
//
// This package encodes and parses header *bytes* only. It never reads a
// clock, opens a socket, or performs any encryption: which bytes get
// encrypted (and with what key) is the responsibility of the session/crypto
// layer (WP6b). In particular, when libRIST encrypts a REDUCED data packet it
// encrypts the reduced-overhead header together with the RTP payload — the
// region beginning immediately after the GRE sequence number (gre.c:116-131).
// Callers building encrypted data packets must therefore encrypt the bytes
// this package places after the GRE header, not just the RTP payload.
//
// All multi-byte fields are big-endian (network order). Decoding arbitrary
// bytes returns an error and never panics. Encoding uses append-style
// AppendTo methods that grow caller-provided buffers, matching internal/rtp
// and internal/rtcp.
package gre

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinel errors returned by the codec. Callers should test for them with
// errors.Is, as returned errors may wrap these with additional context.
var (
	// ErrShortBuffer is returned by a Parse function when the input is too
	// short to hold the fixed header or an optional field the header
	// announces (gre.c / rist-common.c length checks).
	ErrShortBuffer = errors.New("rist: gre: short buffer")

	// ErrNonConformant is returned by Parse when a reserved bit that
	// libRIST requires to be zero is set: flags1 bit 6, or any of the low
	// three bits of flags2 (the RFC 2784 GRE-version bit and the two bits
	// above it). libRIST drops such packets as "non conformant main
	// profile" (rist-common.c:2927).
	ErrNonConformant = errors.New("rist: gre: non-conformant main-profile header")

	// ErrUnsupportedVSFProto is returned by ParseVSFProto when the VSF
	// protocol type field is not RIST (0x0000); libRIST logs and drops
	// such packets (rist-common.c:3037-3040).
	ErrUnsupportedVSFProto = errors.New("rist: gre: unsupported VSF protocol type")
)

// GRE protocol-type values carried in the big-endian prot_type field
// (gre.h:7-11).
const (
	// ProtoKeepalive is the protocol type for RIST keep-alive control
	// packets (gre.h:7, RIST_GRE_PROTOCOL_TYPE_KEEPALIVE).
	ProtoKeepalive uint16 = 0x88B5

	// ProtoReduced is the protocol type for reduced-overhead data packets
	// (gre.h:8, RIST_GRE_PROTOCOL_TYPE_REDUCED).
	ProtoReduced uint16 = 0x88B6

	// ProtoFull is the protocol type for full IP payloads carried as
	// out-of-band data (gre.h:9, RIST_GRE_PROTOCOL_TYPE_FULL, 0x0800 =
	// ETHERTYPE_IP).
	ProtoFull uint16 = 0x0800

	// ProtoEAPOL is the protocol type for EAP-over-LAN authentication
	// frames (gre.h:10, RIST_GRE_PROTOCOL_TYPE_EAPOL, 0x888E). EAPOL
	// traffic is never encrypted (gre.c:25).
	ProtoEAPOL uint16 = 0x888E

	// ProtoVSF is the protocol type used for the version >= 2 VSF
	// ethertype wrapper (gre.h:11, RIST_GRE_PROTOCOL_TYPE_VSF, 0xCCE0).
	// When this is the prot_type, a 4-byte VSFProto header (see
	// ParseVSFProto) follows the GRE header and carries the true RIST
	// sub-protocol.
	ProtoVSF uint16 = 0xCCE0
)

// VSF protocol type/subtype values for the version >= 2 wrapper
// (gre.h:17-22). The 16-bit type is always RIST (0x0000); the subtype names
// the inner RIST protocol.
const (
	// VSFTypeRIST is the only defined VSF protocol type (gre.h:17,
	// RIST_VSF_PROTOCOL_TYPE_RIST); any other value is rejected on parse
	// (rist-common.c:3037).
	VSFTypeRIST uint16 = 0x0000

	// VSFSubtypeReduced wraps a reduced-overhead data packet (gre.h:19,
	// RIST_VSF_PROTOCOL_SUBTYPE_REDUCED).
	VSFSubtypeReduced uint16 = 0x0000

	// VSFSubtypeKeepalive wraps a keep-alive control packet (gre.h:20,
	// RIST_VSF_PROTOCOL_SUBTYPE_KEEPALIVE).
	VSFSubtypeKeepalive uint16 = 0x8000

	// VSFSubtypeFutureNonce reserves a subtype for the flow-attribute /
	// future-nonce extension (gre.h:21,
	// RIST_VSF_PROTOCOL_SUBTYPE_FUTURE_NONCE); libRIST does not parse its
	// body (rist-common.c:3047-3049).
	VSFSubtypeFutureNonce uint16 = 0x8001

	// VSFSubtypeBufferNegotiation wraps a buffer-negotiation control
	// message (gre.h:22, RIST_VSF_PROTOCOL_SUBTYPE_BUFFER_NEGOTIATION).
	VSFSubtypeBufferNegotiation uint16 = 0x8002
)

// RIST GRE version numbers carried in the 3-bit RVer field (gre.h:24-25).
const (
	// VersionMin is the minimum and default RIST GRE version (gre.h:25,
	// RIST_GRE_VERSION_MIN). At this version protocol types are written
	// directly into prot_type with no VSF wrapper (gre.c:85-86).
	VersionMin uint8 = 1

	// VersionCur is the highest RIST GRE version this implementation
	// understands (gre.h:24, RIST_GRE_VERSION_CUR). At version >= 2,
	// REDUCED/KEEPALIVE/BUFFER_NEGOTIATION are carried under the VSF
	// ethertype wrapper (gre.c:73-87).
	VersionCur uint8 = 2
)

// Default virtual ports for the reduced-overhead header
// (include/librist/peer.h, RIST_DEFAULT_VIRT_*_PORT).
const (
	// DefaultVirtSrcPort is the default reduced-overhead source port.
	DefaultVirtSrcPort uint16 = 1971

	// DefaultVirtDstPort is the default reduced-overhead destination port.
	DefaultVirtDstPort uint16 = 1968
)

// Header field sizes (gre.h packed structs).
const (
	// BaseHeaderSize is the size of the fixed GRE header: flags1, flags2,
	// and the 16-bit protocol type (gre.h:131-135, rist_gre_hdr).
	BaseHeaderSize = 4

	// nonceSize is the size of the optional key/nonce field.
	nonceSize = 4

	// seqSize is the size of the optional 32-bit sequence number.
	seqSize = 4

	// ReducedHeaderSize is the size of the reduced-overhead header: a
	// source/destination virtual-port pair (gre.h:12,174-177,
	// RIST_GRE_PROTOCOL_REDUCED_SIZE / rist_reduced).
	ReducedHeaderSize = 4

	// VSFProtoSize is the size of the version >= 2 VSF wrapper: a 16-bit
	// type and a 16-bit subtype (gre.h:169-172, rist_vsf_proto).
	VSFProtoSize = 4

	// KeepaliveSize is the size of the fixed keep-alive body: a 6-byte MAC
	// and two capability octets (gre.h:123-129,
	// SIZEOF_GRE_KEEPALIVE / rist_gre_keepalive).
	KeepaliveSize = 8

	// AdvExtSize is the size of the optional Advanced-profile extended
	// capabilities block that may follow the keep-alive body
	// (rist-common.c:273, TR-06-3 §5.3.6).
	AdvExtSize = 4
)

// Bit positions within the two flag octets, in C bit numbering where bit 7 is
// the most significant bit (matching libRIST's SET_BIT/CHECK_BIT, gre.c).
const (
	// flags1 bits.
	bitChecksum = 7 // C: checksum present. libRIST never sets it.
	bitKey      = 5 // K: key/nonce present (gre.c:133).
	bitSeq      = 4 // S: sequence number present (gre.c:60).
	bitReserved = 6 // reserved; receiver rejects when set (rist-common.c:2927).

	// flags2 bits.
	bitH            = 6 // H: AES key length (0 => 128-bit, 1 => 256-bit) (gre.c:54).
	flags2RVerShift = 3 // RVer occupies bits 5,4,3 (gre.c:48).
	flags2RVerMask  = 0x7
	// flags2LowMask covers the low three bits (RFC 2784 GRE version bit
	// plus the two reserved bits above it); the receiver requires them to
	// be zero (rist-common.c:2927, "(gre->flags2 & 0x7) != 0").
	flags2LowMask = 0x7
)

// Header is a parsed RIST GRE base header (gre.h:131-167). It models the
// fixed four bytes plus the optional key/nonce and sequence-number fields
// whose presence the K and S flag bits announce.
type Header struct {
	// Version is the 3-bit RIST GRE version (RVer field). VersionMin (1)
	// is the default; VersionCur (2) selects the VSF ethertype wrapper for
	// REDUCED/KEEPALIVE/BUFFER_NEGOTIATION.
	Version uint8

	// HasKey is the K bit: a 4-byte key/nonce follows the base header.
	// libRIST sets it when transmitting encrypted data (gre.c:133).
	HasKey bool

	// HasSeq is the S bit: a 4-byte sequence number follows the base
	// header (and the key/nonce, if present). libRIST always sets it
	// (gre.c:60).
	HasSeq bool

	// KeySize256 is the H bit: the AES key is 256-bit when set, 128-bit
	// when clear. libRIST sets it only when encrypting with a 256-bit key
	// at version != 0 (gre.c:52-55). Meaningful only when HasKey is set.
	KeySize256 bool

	// Nonce is the 4-byte key/nonce, written verbatim in network byte
	// order from the crypto key (gre.c:135). Meaningful only when HasKey
	// is set.
	Nonce [4]byte

	// Seq is the 32-bit GRE sequence number (gre.c:63-66). Meaningful only
	// when HasSeq is set. It becomes the high 4 bytes of the AES IV
	// (gre.h:51).
	Seq uint32

	// ProtType is the GRE protocol type (one of the Proto* constants). At
	// version >= 2 with a wrapped sub-protocol this is ProtoVSF and the
	// true sub-protocol is in the following VSFProto header.
	ProtType uint16
}

// Size returns the number of bytes AppendTo will write: the four base bytes
// plus the optional key/nonce and sequence-number fields.
func (h Header) Size() int {
	n := BaseHeaderSize
	if h.HasKey {
		n += nonceSize
	}
	if h.HasSeq {
		n += seqSize
	}
	return n
}

// AppendTo appends the serialized base header (flags + protocol type, then
// the optional nonce and sequence number) to dst and returns the extended
// slice. The field order matches gre.c: nonce at offset 4, sequence number
// immediately after (gre.c:47,61-67,135). On error dst is returned unchanged.
func (h Header) AppendTo(dst []byte) ([]byte, error) {
	if h.Version > flags2RVerMask {
		return dst, fmt.Errorf("%w: version %d does not fit 3-bit RVer field", ErrNonConformant, h.Version)
	}

	var flags1, flags2 byte
	flags2 = (h.Version & flags2RVerMask) << flags2RVerShift
	if h.HasSeq {
		flags1 |= 1 << bitSeq
	}
	if h.HasKey {
		flags1 |= 1 << bitKey
		if h.KeySize256 {
			flags2 |= 1 << bitH
		}
	}

	dst = append(dst, flags1, flags2)
	dst = binary.BigEndian.AppendUint16(dst, h.ProtType)
	if h.HasKey {
		dst = append(dst, h.Nonce[:]...)
	}
	if h.HasSeq {
		dst = binary.BigEndian.AppendUint32(dst, h.Seq)
	}
	return dst, nil
}

// Parse decodes a RIST GRE base header from b. It returns the parsed header
// and the byte offset at which the payload (or, for ProtoVSF, the VSFProto
// header) begins, i.e. the number of header bytes consumed. It validates the
// reserved bits exactly as libRIST's receiver does (rist-common.c:2927) and
// requires enough bytes for every optional field the flags announce. Arbitrary
// input returns an error rather than panicking.
func Parse(b []byte) (Header, int, error) {
	if len(b) < BaseHeaderSize {
		return Header{}, 0, fmt.Errorf("%w: %d < %d bytes for base header", ErrShortBuffer, len(b), BaseHeaderSize)
	}

	flags1 := b[0]
	flags2 := b[1]

	// Reject non-conformant headers: flags1 bit 6 reserved, and the low
	// three bits of flags2 (RFC 2784 GRE version + reserved) must be zero
	// (rist-common.c:2927).
	if flags1&(1<<bitReserved) != 0 || flags2&flags2LowMask != 0 {
		return Header{}, 0, fmt.Errorf("%w: flags1=0x%02x flags2=0x%02x", ErrNonConformant, flags1, flags2)
	}

	h := Header{
		Version:  (flags2 >> flags2RVerShift) & flags2RVerMask,
		HasKey:   flags1&(1<<bitKey) != 0,
		HasSeq:   flags1&(1<<bitSeq) != 0,
		ProtType: binary.BigEndian.Uint16(b[2:4]),
	}
	// The H bit selects AES key length and is meaningful only alongside the
	// key bit (rist-common.c:2991-2995 reads it inside the has_key path).
	// Decoding it only when HasKey keeps the struct a faithful, round-trip-
	// stable model of the wire (the encoder emits H only when HasKey).
	if h.HasKey {
		h.KeySize256 = flags2&(1<<bitH) != 0
	}
	hasChecksum := flags1&(1<<bitChecksum) != 0

	// Length check up front, matching rist-common.c:2940.
	off := BaseHeaderSize
	need := BaseHeaderSize
	if hasChecksum {
		need += 4
	}
	if h.HasKey {
		need += nonceSize
	}
	if h.HasSeq {
		need += seqSize
	}
	if len(b) < need {
		return Header{}, 0, fmt.Errorf("%w: %d < %d bytes for announced optional fields", ErrShortBuffer, len(b), need)
	}

	// A checksum is never emitted by libRIST, but the receiver skips four
	// bytes when the C bit is set (rist-common.c:2945-2947).
	if hasChecksum {
		off += 4
	}
	if h.HasKey {
		copy(h.Nonce[:], b[off:off+nonceSize])
		off += nonceSize
	}
	if h.HasSeq {
		h.Seq = binary.BigEndian.Uint32(b[off : off+seqSize])
		off += seqSize
	}

	return h, off, nil
}

// ReducedHeader is the reduced-overhead data-channel header (gre.h:174-177,
// rist_reduced): a virtual source/destination port pair that scopes a media
// flow within a Main-profile multiplex. It follows the GRE header (and the
// VSF wrapper, if any) on REDUCED data packets.
type ReducedHeader struct {
	// SrcPort is the virtual source port (DefaultVirtSrcPort by default).
	SrcPort uint16

	// DstPort is the virtual destination port (DefaultVirtDstPort by
	// default).
	DstPort uint16
}

// AppendTo appends the 4-byte reduced-overhead header to dst and returns the
// extended slice. The wire order is source port then destination port
// (gre.c:90-93 writes the rist_reduced struct, src_port first).
func (r ReducedHeader) AppendTo(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, r.SrcPort)
	dst = binary.BigEndian.AppendUint16(dst, r.DstPort)
	return dst
}

// ParseReduced decodes a reduced-overhead header from b and returns it with
// the number of bytes consumed (always ReducedHeaderSize). It matches the
// receiver's read of src_port then dst_port (rist-common.c:3071-3072).
func ParseReduced(b []byte) (ReducedHeader, int, error) {
	if len(b) < ReducedHeaderSize {
		return ReducedHeader{}, 0, fmt.Errorf("%w: %d < %d bytes for reduced header", ErrShortBuffer, len(b), ReducedHeaderSize)
	}
	return ReducedHeader{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
	}, ReducedHeaderSize, nil
}

// VSFProto is the version >= 2 VSF ethertype wrapper (gre.h:169-172,
// rist_vsf_proto) that follows the GRE header when ProtType is ProtoVSF. The
// 16-bit type is always VSFTypeRIST; the subtype names the inner RIST
// protocol (one of the VSFSubtype* constants).
type VSFProto struct {
	// Type is the VSF protocol type; only VSFTypeRIST (0) is defined.
	Type uint16

	// Subtype is the inner RIST sub-protocol (VSFSubtype* constant).
	Subtype uint16
}

// AppendTo appends the 4-byte VSF wrapper to dst and returns the extended
// slice. Both fields are big-endian (gre.c:74-82); the REDUCED subtype is
// zero and therefore byte-identical regardless of byte order.
func (v VSFProto) AppendTo(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, v.Type)
	dst = binary.BigEndian.AppendUint16(dst, v.Subtype)
	return dst
}

// ParseVSFProto decodes a VSF wrapper from b and returns it with the number
// of bytes consumed (always VSFProtoSize). It rejects any type other than
// VSFTypeRIST, matching the receiver (rist-common.c:3032-3040).
func ParseVSFProto(b []byte) (VSFProto, int, error) {
	if len(b) < VSFProtoSize {
		return VSFProto{}, 0, fmt.Errorf("%w: %d < %d bytes for VSF header", ErrShortBuffer, len(b), VSFProtoSize)
	}
	v := VSFProto{
		Type:    binary.BigEndian.Uint16(b[0:2]),
		Subtype: binary.BigEndian.Uint16(b[2:4]),
	}
	if v.Type != VSFTypeRIST {
		return VSFProto{}, 0, fmt.Errorf("%w: type 0x%04x", ErrUnsupportedVSFProto, v.Type)
	}
	return v, VSFProtoSize, nil
}

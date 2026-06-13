// Package adv implements the RIST Advanced Profile (VSF TR-06-3:2024) tunnel
// packet header codec, byte-exact with libRIST v0.2.18-rc1 (src/proto/adv.h
// and src/adv.c).
//
// An Advanced Profile packet is a standard RTP packet (RFC 3550 §5.1, a fixed
// 12-byte header with payload type 127 and a 1 MHz timestamp clock),
// optionally followed by a classic RFC 3550 RTP header extension (present only
// when the RTP X bit is set), then the ALWAYS-PRESENT four-byte
// profile-defined extension (librist rist_adv_ext, adv.h:67-72):
//
//	seq_ext (16, big-endian) | flags (8) | params (8)
//
// The flags byte carries F (first fragment), L (last fragment), E (expedite),
// R (retransmit), I (flow id present), P (PFD present), H (RIST header
// extension present), and the most-significant bit of the 3-bit PSK field. The
// params byte carries the low two bits of the PSK field, the 2-bit LPC mode,
// and the 4-bit encapsulation Type. Optional fixed fields follow the
// extension in a strict order (adv.c rist_adv_parse / rist_adv_build):
//
//	Flow ID (4 B, if I=1) -> PSK Hash (16 B) -> PSK Nonce (4 B) ->
//	PSK IV (4 B) [each per the PSK mode] -> Payload Compression (4 B, if
//	LPC==3) -> Payload Format Descriptor (4 B, if P=1) -> RIST Header
//	Extension (variable, if H=1) -> Payload.
//
// This codec frames and deframes the header and carries the (already
// processed) payload only. The PSK Hash/Nonce/IV and the Compression field are
// opaque pass-through bytes: encryption (internal/crypto) and compression
// (internal/lpc) are performed by other packages before this codec encodes and
// after it decodes. The 32-bit sequence number is split across the RTP seq
// (low 16) and seq_ext (high 16); SSRC parity marks protected (even) versus
// unprotected (odd) flows.
//
// All multi-byte fields are big-endian (network order). Decoding arbitrary
// bytes returns an error and never panics. Encoding uses append-style AppendTo
// / Build methods that grow caller-provided buffers, matching internal/rtp and
// internal/gre. Optional fields returned by Parse alias the input buffer
// (zero-copy), matching the house style.
package adv

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinel errors returned by the codec. Callers should test for them with
// errors.Is, as returned errors may wrap these with additional context.
var (
	// ErrShortBuffer is returned by Parse when the input is too short to
	// hold the fixed RTP+extension header or an optional field the header
	// announces (adv.c length checks throughout rist_adv_parse).
	ErrShortBuffer = errors.New("rist: adv: short buffer")

	// ErrInvalidVersion is returned by Parse when the RTP version field is
	// not 2 (adv.c:46, "(rtp->flags & 0xC0) != 0x80").
	ErrInvalidVersion = errors.New("rist: adv: RTP version is not 2")

	// ErrInvalidPayloadType is returned by Parse when the RTP payload type
	// is neither 127 nor a dynamic type in the SDP range (>= 96); libRIST
	// drops other payload types (adv.c:50-52).
	ErrInvalidPayloadType = errors.New("rist: adv: RTP payload type not 127 and below 96")

	// ErrFieldRange is returned by Build when enc_type, psk_mode, or
	// lpc_mode does not fit its wire field, or when a structured field
	// (compression, hdr_ext) is malformed.
	ErrFieldRange = errors.New("rist: adv: field out of range")
)

// RTP-level constants for the Advanced Profile (adv.h:60-66).
const (
	// PayloadType is the RTP payload type carried when SDP is not in use:
	// 127 (adv.h:60, RIST_ADV_PT; TR-06-3 §5.2.1).
	PayloadType = 127

	// ClockHz is the default RTP timestamp frequency, 1 MHz (adv.h:63,
	// RIST_ADV_CLOCK_HZ; TR-06-3 §5.2.1).
	ClockHz = 1000000

	// rtpFlags is the default RTP first byte: V=2, P=0, X=0, CC=0 = 0x80
	// (adv.h:66, RIST_ADV_RTP_FLAGS). The profile-defined extension is part
	// of the RTP payload, not an RFC 3550 header extension, so X stays 0
	// unless a real header extension is present.
	rtpFlags = 0x80

	// dynamicPTMin is the lowest dynamic RTP payload type accepted when SDP
	// is in use (adv.c:50, "pt < 96").
	dynamicPTMin = 96
)

// Flag bits of the profile-defined extension flags byte (adv.h:76-83). Bit 7
// is the most significant bit.
const (
	// FlagF marks a first fragment (adv.h:76, RIST_ADV_FLAG_F).
	FlagF = 0x80
	// FlagL marks a last fragment (adv.h:77, RIST_ADV_FLAG_L).
	FlagL = 0x40
	// FlagE is the expedite bit (adv.h:78, RIST_ADV_FLAG_E).
	FlagE = 0x20
	// FlagR is the retransmit bit (adv.h:79, RIST_ADV_FLAG_R).
	FlagR = 0x10
	// FlagI marks a present Flow ID field (adv.h:80, RIST_ADV_FLAG_I).
	FlagI = 0x08
	// FlagP marks a present Payload Format Descriptor (adv.h:81,
	// RIST_ADV_FLAG_P).
	FlagP = 0x04
	// FlagH marks a present RIST Header Extension (adv.h:82,
	// RIST_ADV_FLAG_H).
	FlagH = 0x02
	// flagPSK2 is the MSB (bit 2) of the 3-bit PSK field, carried in the
	// flags byte (adv.h:83, RIST_ADV_PSK2_MASK).
	flagPSK2 = 0x01
)

// Bit-field layout of the profile-defined extension params byte (adv.h:86-91):
// PSK[1:0] in bits 7-6, LPC[1:0] in bits 5-4, Type[3:0] in bits 3-0.
const (
	psk10Shift = 6    // PSK[1:0] in bits 7-6 (adv.h:86)
	psk10Mask  = 0xC0 // adv.h:87
	lpcShift   = 4    // LPC[1:0] in bits 5-4 (adv.h:88)
	lpcMask    = 0x30 // adv.h:89
	typeMask   = 0x0F // Type[3:0] in bits 3-0 (adv.h:90)
)

// Encapsulation Type values for the Type[3:0] field (adv.h:147-156, TR-06-3
// §5.2.3).
const (
	TypeReserved   = 0 // adv.h:147, RIST_ADV_TYPE_RESERVED
	TypeIPv4       = 1 // adv.h:148, RIST_ADV_TYPE_IPV4
	TypeIPv6       = 2 // adv.h:149, RIST_ADV_TYPE_IPV6
	TypeReducedUDP = 3 // adv.h:150, RIST_ADV_TYPE_REDUCED_UDP
	TypeControl    = 4 // adv.h:151, RIST_ADV_TYPE_CONTROL
	TypeDirect     = 5 // adv.h:152, RIST_ADV_TYPE_DIRECT
	TypeLayer2     = 6 // adv.h:153, RIST_ADV_TYPE_LAYER2
	TypeGRERFC2784 = 7 // adv.h:154, RIST_ADV_TYPE_GRE_RFC2784
	TypeGREMain    = 8 // adv.h:155, RIST_ADV_TYPE_GRE_MAIN
)

// Pre-shared-key mode values for the PSK[2:0] field (adv.h:161-168, TR-06-3
// §5.2.3).
const (
	PSKNone               = 0 // No encryption (adv.h:161, RIST_ADV_PSK_NONE)
	PSKAESCTR             = 1 // AES-CTR, Main-profile compatible (adv.h:162)
	PSKHMACSHA256         = 2 // HMAC-SHA256, no encryption (adv.h:163)
	PSKAESCTRHMAC         = 3 // AES-CTR-HMAC-SHA256 (adv.h:164)
	PSKAESGCM             = 4 // AES-GCM (adv.h:165)
	PSKChaCha20Poly       = 5 // CHACHA20-POLY1305 (adv.h:166)
	PSKUserNoHash         = 6 // User-defined, no hash (adv.h:167)
	PSKUserHash           = 7 // User-defined, with hash (adv.h:168)
	pskMaxIncl      uint8 = 7 // PSK is a 3-bit field
)

// Sizes of the PSK header fields (adv.h:174-176, Table 1).
const (
	PSKHashSize  = 16 // adv.h:174, RIST_ADV_PSK_HASH_SIZE
	PSKNonceSize = 4  // adv.h:175, RIST_ADV_PSK_NONCE_SIZE
	PSKIVSize    = 4  // adv.h:176, RIST_ADV_PSK_IV_SIZE
)

// Payload-compression mode values for the LPC[1:0] field (adv.h:209-212,
// TR-06-3 §5.2.3).
const (
	LPCNone         = 0 // No compression (adv.h:209, RIST_ADV_LPC_NONE)
	LPCLZ4          = 1 // LZ4 compression (adv.h:210, RIST_ADV_LPC_LZ4)
	LPCReserved     = 2 // Reserved (adv.h:211, RIST_ADV_LPC_RESERVED)
	LPCFieldPresent = 3 // Compression field present (adv.h:212)
	lpcMaxIncl      = 3 // LPC is a 2-bit field
)

// Control Index values carried in a Type-Control (Type=4) packet's payload
// sub-header (adv.h:217-229, Table 2, TR-06-3 §5.3).
const (
	CINackBitmask uint16 = 0x0000 // adv.h:217, RIST_ADV_CI_NACK_BITMASK
	CINackRange   uint16 = 0x0001 // adv.h:218, RIST_ADV_CI_NACK_RANGE
	CIRTTEchoReq  uint16 = 0x0010 // adv.h:219, RIST_ADV_CI_RTT_ECHO_REQ
	CIRTTEchoResp uint16 = 0x0011 // adv.h:220, RIST_ADV_CI_RTT_ECHO_RESP
	CIFEC20225Row uint16 = 0x0020 // adv.h:221, RIST_ADV_CI_FEC_2022_5_ROW
	CIFEC20225Col uint16 = 0x0021 // adv.h:222, RIST_ADV_CI_FEC_2022_5_COL
	CIFEC20221Row uint16 = 0x0022 // adv.h:223, RIST_ADV_CI_FEC_2022_1_ROW
	CIFEC20221Col uint16 = 0x0023 // adv.h:224, RIST_ADV_CI_FEC_2022_1_COL
	CIKeepalive   uint16 = 0x8000 // adv.h:225, RIST_ADV_CI_KEEPALIVE
	CIFlowAttr    uint16 = 0x8001 // adv.h:226, RIST_ADV_CI_FLOW_ATTR
	CISRPAuth     uint16 = 0x8010 // adv.h:227, RIST_ADV_CI_SRP_AUTH
	CIPSKNonce    uint16 = 0x8011 // adv.h:228, RIST_ADV_CI_PSK_NONCE
	CIUnsupported uint16 = 0x8020 // adv.h:229, RIST_ADV_CI_UNSUPPORTED
)

// Header size constants (adv.h:262-280).
const (
	// RTPSize is the standard RTP header size (adv.h:262,
	// RIST_ADV_RTP_SIZE).
	RTPSize = 12
	// ExtSize is the profile-defined extension size (adv.h:263,
	// RIST_ADV_EXT_SIZE).
	ExtSize = 4
	// HeaderMin is the minimum Advanced Profile header: RTP (12) + ext (4)
	// (adv.h:264, RIST_ADV_HEADER_MIN).
	HeaderMin = RTPSize + ExtSize
	// FlowIDSize is the size of the Flow ID field (adv.h:265,
	// RIST_ADV_FLOW_ID_SIZE).
	FlowIDSize = 4
	// CompressionSize is the size of the Payload Compression field
	// (adv.h:266, RIST_ADV_COMPRESSION_SIZE).
	CompressionSize = 4
	// PFDSize is the size of the Payload Format Descriptor (adv.h:267,
	// RIST_ADV_PFD_SIZE).
	PFDSize = 4
	// MaxFixedHeader is the maximum fixed header: RTP(12)+ext(4)+flow(4)+
	// hash(16)+nonce(4)+iv(4)+comp(4)+pfd(4) = 52, excluding the
	// variable-length RIST header extension (adv.h:271-273).
	MaxFixedHeader = 52
	// CtrlHdrSize is the control-message sub-header size: Control Index (2)
	// + Length (2) (adv.h:276, RIST_ADV_CTRL_HDR_SIZE).
	CtrlHdrSize = 4

	// rtpExtHdrSize is the 4-byte header of an RFC 3550 RTP header
	// extension or RIST header extension: 16-bit profile + 16-bit length in
	// 32-bit words (adv.c:69-72, adv.c:160-167).
	rtpExtHdrSize = 4
)

// PSKHasHash reports whether the given PSK mode carries a 16-byte hash field
// (adv.h:182-185, rist_adv_psk_has_hash): modes 2, 3, 4, 5, 7.
func PSKHasHash(psk uint8) bool {
	return psk == PSKHMACSHA256 || psk == PSKAESCTRHMAC || psk == PSKAESGCM ||
		psk == PSKChaCha20Poly || psk == PSKUserHash
}

// PSKHasNonce reports whether the given PSK mode carries a 4-byte nonce field
// (adv.h:187-190, rist_adv_psk_has_nonce): any mode >= 1.
func PSKHasNonce(psk uint8) bool {
	return psk >= PSKAESCTR
}

// PSKHasIV reports whether the given PSK mode carries a 4-byte IV field
// (adv.h:192-195, rist_adv_psk_has_iv): mode 1 (AES-CTR) or any mode >= 3.
func PSKHasIV(psk uint8) bool {
	return psk == PSKAESCTR || psk >= PSKAESCTRHMAC
}

// PSKHdrSize returns the total number of PSK header bytes (hash + nonce + IV)
// carried for the given PSK mode (adv.h:197-204, rist_adv_psk_hdr_size). The
// per-mode totals are: 0->0, 1->8, 2->20, 3->24, 4->24, 5->24, 6->8, 7->24.
func PSKHdrSize(psk uint8) int {
	sz := 0
	if PSKHasHash(psk) {
		sz += PSKHashSize
	}
	if PSKHasNonce(psk) {
		sz += PSKNonceSize
	}
	if PSKHasIV(psk) {
		sz += PSKIVSize
	}
	return sz
}

// SSRCIsProtected reports whether an SSRC denotes a protected (ARQ-eligible)
// flow. Even SSRCs are protected, odd are unprotected (adv.h:346-349,
// rist_adv_ssrc_is_protected; TR-06-3 §5.2.1).
func SSRCIsProtected(ssrc uint32) bool {
	return ssrc&1 == 0
}

// SSRCProtected returns ssrc with its least-significant bit cleared, yielding
// the protected (even) form (adv.h:351-354, rist_adv_ssrc_protected).
func SSRCProtected(ssrc uint32) uint32 {
	return ssrc &^ 1
}

// SSRCUnprotected returns ssrc with its least-significant bit set, yielding
// the unprotected (odd) form (adv.h:356-359, rist_adv_ssrc_unprotected).
func SSRCUnprotected(ssrc uint32) uint32 {
	return ssrc | 1
}

// SplitSeq returns the low-16 and high-16 halves of a 32-bit sequence number:
// low becomes the RTP seq, high becomes the seq_ext (adv.h:300-307,
// rist_adv_set_seq32).
func SplitSeq(seq uint32) (low, high uint16) {
	return uint16(seq & 0xFFFF), uint16(seq >> 16)
}

// JoinSeq reconstructs a 32-bit sequence number from the seq_ext (high 16) and
// RTP seq (low 16) (adv.h:295-298, rist_adv_seq32).
func JoinSeq(high, low uint16) uint32 {
	return uint32(high)<<16 | uint32(low)
}

// FlowID is the 4-byte Flow ID field (adv.h:236-241, rist_adv_flow_id;
// TR-06-3 §5.2.4, Figure 4): a 16-bit Outer Flow ID, a 12-bit Inner Flow ID,
// and a 4-bit Inner Flow Sub-ID (IFSID). On the wire the inner 12 bits split
// across the third byte (high 8) and the upper nibble of the fourth byte, with
// the sub-ID in the lower nibble of the fourth byte.
type FlowID struct {
	// Outer is the 16-bit Outer Flow ID (adv.h:243-246, rist_adv_flow_outer).
	Outer uint16
	// Inner is the 12-bit Inner Flow ID (adv.h:248-251, rist_adv_flow_inner).
	// Only the low 12 bits are encoded; higher bits are dropped on Build.
	Inner uint16
	// Sub is the 4-bit Inner Flow Sub-ID / IFSID (adv.h:253-256,
	// rist_adv_flow_sub). Only the low 4 bits are encoded.
	Sub uint8
}

// appendTo appends the 4-byte Flow ID wire form to dst (adv.h:236-241 packed
// struct: outer big-endian, inner_hi = inner[11:4], inner_lo_sub =
// inner[3:0]<<4 | sub).
func (f FlowID) appendTo(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, f.Outer)
	dst = append(dst, uint8((f.Inner>>4)&0xFF))
	dst = append(dst, uint8((f.Inner&0x0F)<<4)|(f.Sub&0x0F))
	return dst
}

// parseFlowID decodes a 4-byte Flow ID from b[:FlowIDSize]; the caller
// guarantees the length (adv.h:243-256 accessors).
func parseFlowID(b []byte) FlowID {
	innerHi := b[2]
	innerLoSub := b[3]
	return FlowID{
		Outer: binary.BigEndian.Uint16(b[0:2]),
		Inner: uint16(innerHi)<<4 | uint16(innerLoSub>>4),
		Sub:   innerLoSub & 0x0F,
	}
}

// PFD is the 4-byte Payload Format Descriptor (adv.h:260-272, rist_adv_pfd at
// 260-262 + its accessors at 264-272; TR-06-3 §5.2.7, Figure 6): a 4-bit ID
// Type followed by a
// 28-bit ID Value, packed big-endian into a single 32-bit word.
type PFD struct {
	// IDType is the 4-bit ID Type (adv.h pfd id_type accessor).
	IDType uint8
	// IDValue is the 28-bit ID Value (adv.h pfd id_value accessor); only
	// the low 28 bits are encoded.
	IDValue uint32
}

// appendTo appends the 4-byte PFD wire form to dst (big-endian
// (IDType<<28)|IDValue).
func (p PFD) appendTo(dst []byte) []byte {
	return binary.BigEndian.AppendUint32(dst, uint32(p.IDType&0x0F)<<28|(p.IDValue&0x0FFFFFFF))
}

// parsePFD decodes a 4-byte PFD from b[:PFDSize]; the caller guarantees the
// length.
func parsePFD(b []byte) PFD {
	v := binary.BigEndian.Uint32(b[0:4])
	return PFD{
		IDType:  uint8(v >> 28),
		IDValue: v & 0x0FFFFFFF,
	}
}

// IsUnfragmented reports whether the fragment flags denote a complete,
// unfragmented packet: both F and L set (adv.h:316-321,
// rist_adv_is_unfragmented).
func IsUnfragmented(flags uint8) bool {
	return flags&(FlagF|FlagL) == (FlagF | FlagL)
}

// IsFragmented reports whether the fragment flags denote a fragment of a
// larger packet, i.e. not unfragmented (adv.h:323-326).
func IsFragmented(flags uint8) bool {
	return !IsUnfragmented(flags)
}

// IsFirstFragment reports whether the flags denote a first fragment: F set, L
// clear (adv.h:328-331, rist_adv_is_first_fragment).
func IsFirstFragment(flags uint8) bool {
	return flags&FlagF != 0 && flags&FlagL == 0
}

// IsLastFragment reports whether the flags denote a last fragment: F clear, L
// set (adv.h:333-336, rist_adv_is_last_fragment).
func IsLastFragment(flags uint8) bool {
	return flags&FlagF == 0 && flags&FlagL != 0
}

// Params is the input model for Build, mirroring librist rist_adv_params
// (adv.h:403-431). Optional fields are nil to omit, except the PSK fields,
// whose presence Build derives from PSKMode (a nil PSK slice for a mode that
// requires one is treated as all-zero bytes, matching libRIST when the field
// pointer is set but the data is zeroed — see the per-field notes on Build).
type Params struct {
	// Seq is the full 32-bit sequence number (split into RTP seq + seq_ext).
	Seq uint32
	// Timestamp is the 32-bit RTP timestamp (1 MHz clock).
	Timestamp uint32
	// SSRC identifies the flow; even = protected, odd = unprotected.
	SSRC uint32
	// EncType is the 4-bit encapsulation Type (a Type* constant).
	EncType uint8
	// PSKMode is the 3-bit PSK mode (a PSK* constant).
	PSKMode uint8
	// LPCMode is the 2-bit payload-compression mode (an LPC* constant).
	LPCMode uint8
	// FirstFrag sets the F flag.
	FirstFrag bool
	// LastFrag sets the L flag.
	LastFrag bool
	// Expedite sets the E flag.
	Expedite bool
	// Retransmit sets the R flag.
	Retransmit bool

	// FlowID, when non-nil, is encoded and sets the I flag (adv.c:206-209).
	FlowID *FlowID

	// PSKHash, PSKNonce, PSKIV are opaque pass-through bytes for the PSK
	// header. Build emits each field only when PSKMode requires it; when
	// required and the slice is nil, zero bytes are written (libRIST writes
	// the field only when both the mode requires it and the pointer is set,
	// adv.c:212-227 — see the deviation note in the package tests). When
	// supplied, each must be exactly its field size (PSKHashSize /
	// PSKNonceSize / PSKIVSize) or Build returns ErrFieldRange.
	PSKHash  []byte
	PSKNonce []byte
	PSKIV    []byte

	// Compression is the 4-byte opaque Payload Compression field, encoded
	// only when LPCMode == LPCFieldPresent (adv.c:238). When required and nil,
	// zero bytes are written; when supplied it must be exactly CompressionSize
	// bytes.
	Compression []byte

	// PFD, when non-nil, is encoded and sets the P flag (adv.c:236-239).
	PFD *PFD

	// HdrExt, when non-empty, is the RIST Header Extension (an RFC
	// 3550-style extension: 4-byte header + word-aligned body) copied
	// verbatim, and sets the H flag (adv.c:242-245). Build does not
	// validate its internal length field; it copies len(HdrExt) bytes.
	HdrExt []byte
}

// Parsed is the output model for Parse, mirroring librist rist_adv_parsed
// (adv.h:365-401). Optional slice fields alias the input buffer and are nil
// when the corresponding field is absent.
type Parsed struct {
	// Seq is the full 32-bit sequence number.
	Seq uint32
	// Timestamp is the 32-bit RTP timestamp.
	Timestamp uint32
	// SSRC identifies the flow.
	SSRC uint32
	// RTPExtPresent is the RTP X bit: an RFC 3550 header extension preceded
	// the profile-defined extension and was skipped.
	RTPExtPresent bool
	// RTPPadding is the RTP P bit.
	RTPPadding bool

	// FirstFrag, LastFrag, Expedite, Retransmit are the F/L/E/R flags.
	FirstFrag  bool
	LastFrag   bool
	Expedite   bool
	Retransmit bool

	// PSKMode is the parsed 3-bit PSK mode.
	PSKMode uint8
	// LPCMode is the parsed 2-bit LPC mode.
	LPCMode uint8
	// EncType is the parsed 4-bit encapsulation Type.
	EncType uint8

	// HasFlowID is the I flag; FlowID is set when it is true.
	HasFlowID bool
	// FlowID is the decoded Flow ID, valid only when HasFlowID is true.
	FlowID FlowID

	// HasPSK reports PSKMode > 0.
	HasPSK bool
	// PSKHash, PSKNonce, PSKIV alias the input buffer; each is nil when the
	// PSK mode does not carry that field.
	PSKHash  []byte
	PSKNonce []byte
	PSKIV    []byte

	// HasCompression reports LPCMode == LPCFieldPresent; Compression
	// aliases the input when true.
	HasCompression bool
	Compression    []byte

	// HasPFD is the P flag; PFD is set when it is true.
	HasPFD bool
	PFD    PFD

	// HasHdrExt is the H flag; HdrExt aliases the input (including the
	// 4-byte extension header) when true.
	HasHdrExt bool
	HdrExt    []byte

	// Payload is the remaining bytes after the header; it aliases the input
	// buffer.
	Payload []byte
}

// HeaderSize returns the number of header bytes Build will write for params,
// excluding the payload (librist rist_adv_header_size, adv.c:13-33). It
// matches Build's emission rules exactly: the PSK fields count whenever the
// mode requires them, the Compression field counts only when LPCMode ==
// LPCFieldPresent, and the RIST header extension counts its full length.
func HeaderSize(params Params) int {
	sz := HeaderMin
	if params.FlowID != nil {
		sz += FlowIDSize
	}
	sz += PSKHdrSize(params.PSKMode)
	if params.LPCMode == LPCFieldPresent {
		sz += CompressionSize
	}
	if params.PFD != nil {
		sz += PFDSize
	}
	if len(params.HdrExt) > 0 {
		sz += len(params.HdrExt)
	}
	return sz
}

// Build appends a complete Advanced Profile packet (header + payload) to dst
// and returns the extended slice (librist rist_adv_build, adv.c:170-261). The
// RTP header always carries V=2, PT=127, the 1 MHz timestamp and SSRC; the
// profile-defined extension carries the split sequence number, the F/L/E/R
// flags, and the PSK/LPC/Type fields. Optional fields are emitted in spec
// order. On error dst is returned unchanged and a wrapped sentinel is
// returned. It performs no allocations when dst has sufficient capacity.
//
// Deviation note: HeaderSize and Build derive PSK/Compression field presence
// from PSKMode/LPCMode (the wire-truthful rule), whereas libRIST additionally
// requires the corresponding pointer to be non-NULL before emitting the field
// (adv.c:212-238: PSK fields at 220-235, Compression at 238). To keep Build and
// Parse a faithful round trip — Parse
// always consumes a PSK field whose mode requires it — Build emits zero bytes
// for a required-but-nil field rather than producing a header Parse cannot
// read. Supplying the bytes is the normal path.
func Build(dst []byte, params Params, payload []byte) ([]byte, error) {
	if params.EncType > typeMask {
		return dst, fmt.Errorf("%w: enc_type %d exceeds 4-bit field", ErrFieldRange, params.EncType)
	}
	if params.PSKMode > pskMaxIncl {
		return dst, fmt.Errorf("%w: psk_mode %d exceeds 3-bit field", ErrFieldRange, params.PSKMode)
	}
	if params.LPCMode > lpcMaxIncl {
		return dst, fmt.Errorf("%w: lpc_mode %d exceeds 2-bit field", ErrFieldRange, params.LPCMode)
	}
	if err := checkPSKSlice("psk_hash", params.PSKHash, PSKHashSize); err != nil {
		return dst, err
	}
	if err := checkPSKSlice("psk_nonce", params.PSKNonce, PSKNonceSize); err != nil {
		return dst, err
	}
	if err := checkPSKSlice("psk_iv", params.PSKIV, PSKIVSize); err != nil {
		return dst, err
	}
	if params.Compression != nil && len(params.Compression) != CompressionSize {
		return dst, fmt.Errorf("%w: compression is %d bytes, want %d", ErrFieldRange, len(params.Compression), CompressionSize)
	}

	low, high := SplitSeq(params.Seq)

	// RTP header (12 bytes): flags, PT, seq(low), timestamp, ssrc
	// (adv.c:177-185).
	dst = append(dst, rtpFlags, PayloadType)
	dst = binary.BigEndian.AppendUint16(dst, low)
	dst = binary.BigEndian.AppendUint32(dst, params.Timestamp)
	dst = binary.BigEndian.AppendUint32(dst, params.SSRC)

	// Profile-defined extension (4 bytes): seq_ext, flags, params
	// (adv.c:188-205).
	dst = binary.BigEndian.AppendUint16(dst, high)

	var flags uint8
	if params.FirstFrag {
		flags |= FlagF
	}
	if params.LastFrag {
		flags |= FlagL
	}
	if params.Expedite {
		flags |= FlagE
	}
	if params.Retransmit {
		flags |= FlagR
	}
	if params.FlowID != nil {
		flags |= FlagI
	}
	if params.PFD != nil {
		flags |= FlagP
	}
	if len(params.HdrExt) > 0 {
		flags |= FlagH
	}
	// PSK bit 2 lives in the flags byte (adv.h:113-117, rist_adv_set_psk).
	flags |= (params.PSKMode >> 2) & flagPSK2
	dst = append(dst, flags)

	// params byte: PSK[1:0]<<6 | LPC<<4 | Type (adv.h:113-145).
	pb := (params.PSKMode&0x03)<<psk10Shift | (params.LPCMode&0x03)<<lpcShift | (params.EncType & typeMask)
	dst = append(dst, pb)

	// Optional fields in spec order (adv.c:207-249).

	// Flow ID.
	if params.FlowID != nil {
		dst = params.FlowID.appendTo(dst)
	}

	// PSK Hash / Nonce / IV — presence per mode; zero-fill when nil.
	if PSKHasHash(params.PSKMode) {
		dst = appendOrZero(dst, params.PSKHash, PSKHashSize)
	}
	if PSKHasNonce(params.PSKMode) {
		dst = appendOrZero(dst, params.PSKNonce, PSKNonceSize)
	}
	if PSKHasIV(params.PSKMode) {
		dst = appendOrZero(dst, params.PSKIV, PSKIVSize)
	}

	// Payload Compression field.
	if params.LPCMode == LPCFieldPresent {
		dst = appendOrZero(dst, params.Compression, CompressionSize)
	}

	// Payload Format Descriptor.
	if params.PFD != nil {
		dst = params.PFD.appendTo(dst)
	}

	// RIST Header Extension (verbatim).
	if len(params.HdrExt) > 0 {
		dst = append(dst, params.HdrExt...)
	}

	// Payload.
	dst = append(dst, payload...)

	return dst, nil
}

// checkPSKSlice validates an optional PSK byte slice: nil is allowed (Build
// zero-fills), but a non-nil slice must be exactly size bytes.
func checkPSKSlice(name string, b []byte, size int) error {
	if b != nil && len(b) != size {
		return fmt.Errorf("%w: %s is %d bytes, want %d", ErrFieldRange, name, len(b), size)
	}
	return nil
}

// appendOrZero appends b (when its length equals size) or size zero bytes
// (when b is nil) to dst. Callers validate length up front via checkPSKSlice.
func appendOrZero(dst, b []byte, size int) []byte {
	if b == nil {
		for i := 0; i < size; i++ {
			dst = append(dst, 0)
		}
		return dst
	}
	return append(dst, b...)
}

// Parse decodes an Advanced Profile packet from buf (librist rist_adv_parse,
// adv.c:35-168). It validates the RTP version and payload type, skips any CSRC
// list and RFC 3550 RTP header extension, decodes the profile-defined
// extension, then consumes the optional fixed fields in spec order, leaving
// the remainder as Payload. All optional slice fields (PSKHash/Nonce/IV,
// Compression, HdrExt, Payload) alias buf. Arbitrary input returns an error
// rather than panicking.
func Parse(buf []byte) (Parsed, error) {
	var out Parsed
	if len(buf) < HeaderMin {
		return Parsed{}, fmt.Errorf("%w: %d < %d bytes for RTP+ext header", ErrShortBuffer, len(buf), HeaderMin)
	}

	// RTP header. Validate V=2 (adv.c:45-46).
	flags0 := buf[0]
	if flags0&0xC0 != 0x80 {
		return Parsed{}, fmt.Errorf("%w: flags byte 0x%02x", ErrInvalidVersion, flags0)
	}
	// PT must be 127 or a dynamic type >= 96 (adv.c:49-52).
	pt := buf[1] & 0x7F
	if pt != PayloadType && pt < dynamicPTMin {
		return Parsed{}, fmt.Errorf("%w: pt %d", ErrInvalidPayloadType, pt)
	}

	out.RTPPadding = flags0&0x20 != 0
	out.RTPExtPresent = flags0&0x10 != 0
	cc := int(flags0 & 0x0F)

	rtpSeq := binary.BigEndian.Uint16(buf[2:4])
	out.Timestamp = binary.BigEndian.Uint32(buf[4:8])
	out.SSRC = binary.BigEndian.Uint32(buf[8:12])

	offset := RTPSize

	// Skip CSRC entries (adv.c:62-64). CC should be 0 but be safe.
	offset += cc * 4
	if offset > len(buf) {
		return Parsed{}, fmt.Errorf("%w: %d < %d bytes for %d CSRC entries", ErrShortBuffer, len(buf), offset, cc)
	}

	// Skip the RFC 3550 RTP header extension if X=1 (adv.c:67-75).
	if out.RTPExtPresent {
		if offset+rtpExtHdrSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for RTP ext header", ErrShortBuffer, len(buf), offset+rtpExtHdrSize)
		}
		extWords := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		offset += rtpExtHdrSize + extWords*4
		if offset > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for RTP ext payload", ErrShortBuffer, len(buf), offset)
		}
	}

	// Profile-defined extension (adv.c:77-110).
	if offset+ExtSize > len(buf) {
		return Parsed{}, fmt.Errorf("%w: %d < %d bytes for profile extension", ErrShortBuffer, len(buf), offset+ExtSize)
	}
	seqExt := binary.BigEndian.Uint16(buf[offset : offset+2])
	extFlags := buf[offset+2]
	extParams := buf[offset+3]
	offset += ExtSize

	out.Seq = JoinSeq(seqExt, rtpSeq)
	out.FirstFrag = extFlags&FlagF != 0
	out.LastFrag = extFlags&FlagL != 0
	out.Expedite = extFlags&FlagE != 0
	out.Retransmit = extFlags&FlagR != 0
	out.HasFlowID = extFlags&FlagI != 0
	out.HasPFD = extFlags&FlagP != 0
	out.HasHdrExt = extFlags&FlagH != 0

	// PSK = (flags PSK2 << 2) | (params PSK[1:0]) (adv.h:107-111).
	out.PSKMode = (extFlags&flagPSK2)<<2 | (extParams&psk10Mask)>>psk10Shift
	out.LPCMode = (extParams & lpcMask) >> lpcShift
	out.EncType = extParams & typeMask

	out.HasPSK = out.PSKMode > 0
	out.HasCompression = out.LPCMode == LPCFieldPresent

	// Optional fields in spec order (adv.c:112-160).

	// Flow ID (4 bytes, if I=1).
	if out.HasFlowID {
		if offset+FlowIDSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for flow id", ErrShortBuffer, len(buf), offset+FlowIDSize)
		}
		out.FlowID = parseFlowID(buf[offset : offset+FlowIDSize])
		offset += FlowIDSize
	}

	// PSK Hash / Nonce / IV (variable, per Table 1).
	if PSKHasHash(out.PSKMode) {
		if offset+PSKHashSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for psk hash", ErrShortBuffer, len(buf), offset+PSKHashSize)
		}
		out.PSKHash = buf[offset : offset+PSKHashSize : offset+PSKHashSize]
		offset += PSKHashSize
	}
	if PSKHasNonce(out.PSKMode) {
		if offset+PSKNonceSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for psk nonce", ErrShortBuffer, len(buf), offset+PSKNonceSize)
		}
		out.PSKNonce = buf[offset : offset+PSKNonceSize : offset+PSKNonceSize]
		offset += PSKNonceSize
	}
	if PSKHasIV(out.PSKMode) {
		if offset+PSKIVSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for psk iv", ErrShortBuffer, len(buf), offset+PSKIVSize)
		}
		out.PSKIV = buf[offset : offset+PSKIVSize : offset+PSKIVSize]
		offset += PSKIVSize
	}

	// Payload Compression field (4 bytes, if LPC==3).
	if out.HasCompression {
		if offset+CompressionSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for compression", ErrShortBuffer, len(buf), offset+CompressionSize)
		}
		out.Compression = buf[offset : offset+CompressionSize : offset+CompressionSize]
		offset += CompressionSize
	}

	// Payload Format Descriptor (4 bytes, if P=1).
	if out.HasPFD {
		if offset+PFDSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for pfd", ErrShortBuffer, len(buf), offset+PFDSize)
		}
		out.PFD = parsePFD(buf[offset : offset+PFDSize])
		offset += PFDSize
	}

	// RIST Header Extension (if H=1) — RFC 3550 extension format (adv.c:160-167).
	if out.HasHdrExt {
		if offset+rtpExtHdrSize > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for hdr ext header", ErrShortBuffer, len(buf), offset+rtpExtHdrSize)
		}
		hdrWords := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		total := rtpExtHdrSize + hdrWords*4
		if offset+total > len(buf) {
			return Parsed{}, fmt.Errorf("%w: %d < %d bytes for hdr ext body", ErrShortBuffer, len(buf), offset+total)
		}
		out.HdrExt = buf[offset : offset+total : offset+total]
		offset += total
	}

	// Remaining bytes are payload.
	out.Payload = buf[offset:len(buf):len(buf)]

	return out, nil
}

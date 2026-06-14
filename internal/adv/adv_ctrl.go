package adv

// This file implements the RIST Advanced Profile control-message wire formats
// (VSF TR-06-3:2024 §5.3), byte-exact with libRIST v0.2.18-rc1.
//
// # Control framing
//
// Every control message travels inside a Type=Control (enc_type 4) Advanced
// Profile packet whose payload is a 4-byte sub-header followed by a per-index
// body:
//
//	| Control Index (16, big-endian) | Length (16, big-endian) | body... |
//
// The Length field counts the body bytes only (it excludes the 4-byte
// sub-header). BuildControl frames that sub-header; ParseControl validates and
// strips it. The per-index Build*/Parse* helpers (and the NACK list encoders)
// translate each body to and from typed values. These are pure codec helpers:
// they own no I/O and reference no clock. The outer Type=4 packet itself is
// framed by Build with EncType=TypeControl (see codec_adv.go in the session
// host).
//
// # libRIST fidelity notes
//
//   - libRIST emits exactly ONE entry per NACK control datagram and its receiver
//     reads only the first 12-byte entry (it reads body[0:12] and ignores any
//     trailing entries). EncodeRangeNACK / EncodeBitmaskNACK therefore return a
//     SLICE of single-entry messages — the host sends one datagram each — rather
//     than packing several entries into one body.
//   - The Unsupported message (CI 0x8020) writes 16 body bytes but stamps its
//     Length field as 12. ParseControl tolerates a Length shorter than the bytes
//     present, so this libRIST quirk decodes without error; ristgo does not
//     originate Unsupported.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Control-message sentinel errors. Callers test for them with errors.Is.
var (
	// ErrShortControl is returned when a control payload or body is too short
	// to hold the sub-header or the fixed fields the control index requires.
	ErrShortControl = errors.New("rist: adv: short control message")
)

// Keep-alive capability bits carried in the 32-bit Capabilities word of a
// CIKeepalive body (TR-06-3 §5.3.6).
const (
	// KeepaliveCapI signals Advanced Profile capability (bit 31).
	KeepaliveCapI uint32 = 1 << 31
	// KeepaliveCapG signals GRE key-rotation capability (bit 30).
	KeepaliveCapG uint32 = 1 << 30
	// KeepaliveCapC signals compression capability (bit 29).
	KeepaliveCapC uint32 = 1 << 29
)

// Fixed control-body sizes.
const (
	// nackBodySize is the NACK bitmask/range body: SSRC(4)+PSS(4)+BLP|NALP(4).
	nackBodySize = 12
	// rttEchoBodySize is the RTT echo body: req SSRC(4)+TS MSW(4)+TS LSW(4)+
	// processing delay(4).
	rttEchoBodySize = 16
	// keepaliveBodySize is the keep-alive body: MAC(6)+Capabilities(4).
	keepaliveBodySize = 10
	// pskNonceBodySize is the PSK future-nonce body: Nonce(4)+KeySize(2)+
	// Reserved(2).
	pskNonceBodySize = 8

	// maxNACKDecodeRange bounds the sequences a single range NACK expands to on
	// decode, mirroring libRIST's i<10000 recovery cap so a hostile or corrupt
	// NALP cannot force an unbounded allocation.
	maxNACKDecodeRange = 10000
)

// BuildControl appends one control message — the CI(2) + Length(2) sub-header
// followed by body — to dst and returns the extended slice. Length is set to
// len(body); the caller supplies a body built by one of the per-index helpers
// below.
func BuildControl(dst []byte, ci uint16, body []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, ci)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(body)))
	return append(dst, body...)
}

// ParseControl decodes a Type=4 control payload's sub-header, returning the
// control index and the body slice (which aliases payload). It validates that
// the payload holds the 4-byte sub-header and at least Length body bytes; a
// Length exceeding the available bytes is an error, while a Length SHORTER than
// the trailing bytes is tolerated (the body is trimmed to Length), which
// accepts libRIST's Unsupported-message length quirk. Arbitrary input returns
// an error and never panics.
func ParseControl(payload []byte) (ci uint16, body []byte, err error) {
	if len(payload) < CtrlHdrSize {
		return 0, nil, fmt.Errorf("%w: %d < %d bytes for sub-header", ErrShortControl, len(payload), CtrlHdrSize)
	}
	ci = binary.BigEndian.Uint16(payload[0:2])
	bodyLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if CtrlHdrSize+bodyLen > len(payload) {
		return 0, nil, fmt.Errorf("%w: body length %d exceeds %d available", ErrShortControl, bodyLen, len(payload)-CtrlHdrSize)
	}
	return ci, payload[CtrlHdrSize : CtrlHdrSize+bodyLen : CtrlHdrSize+bodyLen], nil
}

// NackBitmask is a NACK Bitmask control body (CINackBitmask, TR-06-3 §5.3.2):
// a media SSRC, a start sequence (PSS), and a 32-bit lost bitmask (BLP) where
// bit i set marks PSS+1+i missing. PSS itself is always requested.
type NackBitmask struct {
	// MediaSSRC identifies the media stream the missing sequences belong to.
	MediaSSRC uint32
	// PSS is the (always-requested) packet start sequence, a full 32-bit
	// Advanced sequence number.
	PSS uint32
	// BLP is the bitmask of additional lost packets: bit i marks PSS+1+i.
	BLP uint32
}

// appendBody appends the 12-byte NACK Bitmask body to dst.
func (n NackBitmask) appendBody(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, n.MediaSSRC)
	dst = binary.BigEndian.AppendUint32(dst, n.PSS)
	return binary.BigEndian.AppendUint32(dst, n.BLP)
}

// Missing expands the NACK Bitmask to the sorted list of missing sequence
// numbers it requests: PSS plus PSS+1+i for each set bit i.
func (n NackBitmask) Missing() []uint32 {
	out := make([]uint32, 0, 1+32)
	out = append(out, n.PSS)
	for i := uint(0); i < 32; i++ {
		if n.BLP&(1<<i) != 0 {
			out = append(out, n.PSS+1+uint32(i))
		}
	}
	return out
}

// ParseNackBitmask decodes a NACK Bitmask body (>= 12 bytes; trailing bytes are
// ignored, matching libRIST which reads only the first entry).
func ParseNackBitmask(body []byte) (NackBitmask, error) {
	if len(body) < nackBodySize {
		return NackBitmask{}, fmt.Errorf("%w: %d < %d bytes for nack bitmask", ErrShortControl, len(body), nackBodySize)
	}
	return NackBitmask{
		MediaSSRC: binary.BigEndian.Uint32(body[0:4]),
		PSS:       binary.BigEndian.Uint32(body[4:8]),
		BLP:       binary.BigEndian.Uint32(body[8:12]),
	}, nil
}

// NackRange is a NACK Range control body (CINackRange, TR-06-3 §5.3.3): a
// media SSRC, a start sequence (PSS), and a count of additional lost packets
// (NALP). It requests PSS through PSS+NALP inclusive.
type NackRange struct {
	// MediaSSRC identifies the media stream the missing sequences belong to.
	MediaSSRC uint32
	// PSS is the first missing sequence number (full 32-bit).
	PSS uint32
	// NALP is the number of ADDITIONAL consecutive missing packets after PSS;
	// the range covers PSS .. PSS+NALP inclusive (NALP+1 sequences).
	NALP uint32
}

// appendBody appends the 12-byte NACK Range body to dst.
func (n NackRange) appendBody(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, n.MediaSSRC)
	dst = binary.BigEndian.AppendUint32(dst, n.PSS)
	return binary.BigEndian.AppendUint32(dst, n.NALP)
}

// Missing expands the NACK Range to the sorted list PSS .. PSS+NALP inclusive.
// The count is clamped to maxNACKDecodeRange (libRIST's recovery cap) so a
// corrupt NALP cannot force an unbounded allocation.
func (n NackRange) Missing() []uint32 {
	count := n.NALP
	if count > maxNACKDecodeRange {
		count = maxNACKDecodeRange
	}
	out := make([]uint32, 0, count+1)
	for i := uint32(0); i <= count; i++ {
		out = append(out, n.PSS+i)
	}
	return out
}

// ParseNackRange decodes a NACK Range body (>= 12 bytes; trailing bytes ignored).
func ParseNackRange(body []byte) (NackRange, error) {
	if len(body) < nackBodySize {
		return NackRange{}, fmt.Errorf("%w: %d < %d bytes for nack range", ErrShortControl, len(body), nackBodySize)
	}
	return NackRange{
		MediaSSRC: binary.BigEndian.Uint32(body[0:4]),
		PSS:       binary.BigEndian.Uint32(body[4:8]),
		NALP:      binary.BigEndian.Uint32(body[8:12]),
	}, nil
}

// EncodeBitmaskNACK packs a missing-sequence list into the minimum number of
// NACK Bitmask entries (one datagram each), mirroring the RFC-4585-style packing
// libRIST consumes. missing need not be sorted; duplicates are tolerated. Each
// entry covers a 33-sequence window [PSS, PSS+32].
func EncodeBitmaskNACK(mediaSSRC uint32, missing []uint32) []NackBitmask {
	if len(missing) == 0 {
		return nil
	}
	s := append([]uint32(nil), missing...)
	sortSeqsWrap(s)

	var out []NackBitmask
	i := 0
	for i < len(s) {
		pss := s[i]
		var blp uint32
		j := i + 1
		for j < len(s) {
			delta := s[j] - pss
			if delta == 0 { // duplicate of PSS
				j++
				continue
			}
			if delta > 32 {
				break
			}
			blp |= 1 << (delta - 1)
			j++
		}
		out = append(out, NackBitmask{MediaSSRC: mediaSSRC, PSS: pss, BLP: blp})
		i = j
	}
	return out
}

// EncodeRangeNACK packs a missing-sequence list into NACK Range entries (one
// datagram each), one entry per maximal run of consecutive sequences. missing
// need not be sorted; duplicates are coalesced. A run longer than
// maxNACKDecodeRange+1 is split so the peer's recovery cap recovers every
// sequence.
func EncodeRangeNACK(mediaSSRC uint32, missing []uint32) []NackRange {
	if len(missing) == 0 {
		return nil
	}
	s := append([]uint32(nil), missing...)
	sortSeqsWrap(s)

	var out []NackRange
	i := 0
	for i < len(s) {
		pss := s[i]
		j := i
		// Extend the run over strictly consecutive sequences, coalescing dups,
		// while NALP stays within the peer's recovery cap.
		for j+1 < len(s) {
			next := s[j+1]
			if next == s[j] { // duplicate
				j++
				continue
			}
			if next != s[j]+1 { // gap: run ends
				break
			}
			// Split so the emitted NALP never reaches maxNACKDecodeRange: a
			// libRIST receiver's recovery loop is bounded by BOTH i<=NALP AND
			// i<maxNACKDecodeRange, so a NALP of exactly maxNACKDecodeRange would
			// leave PSS+maxNACKDecodeRange un-recovered (a permanent 1-packet
			// hole). Breaking at >= keeps the max emitted NALP at cap-1.
			if next-pss >= maxNACKDecodeRange {
				break
			}
			j++
		}
		out = append(out, NackRange{MediaSSRC: mediaSSRC, PSS: pss, NALP: s[j] - pss})
		i = j + 1
	}
	return out
}

// sortSeqsWrap sorts a missing-sequence list in ascending circular (wrap-aware)
// order. The entries lie within a bounded recovery window (< 2^31 wide), so
// ordering by the signed 32-bit distance from the first element is correct even
// when the window straddles the 2^32 sequence wrap — a raw-value sort would put
// sequences just below and just above the wrap at opposite ends and split one
// consecutive run into two distant NACK entries.
func sortSeqsWrap(s []uint32) {
	if len(s) == 0 {
		return
	}
	pivot := s[0]
	sort.Slice(s, func(i, j int) bool { return int32(s[i]-pivot) < int32(s[j]-pivot) })
}

// RTTEcho is the body shared by the RTT Echo Request (CIRTTEchoReq) and
// Response (CIRTTEchoResp) control messages (TR-06-3 §5.3.4): the requester's
// SSRC, a 64-bit NTP timestamp split into most- and least-significant words,
// and a processing delay in microseconds (zero in a request). The originator
// echoes the timestamp verbatim in the response and computes RTT against its
// own clock, so the timestamp units are the originator's private convention;
// libRIST ignores the requester SSRC on receipt.
type RTTEcho struct {
	// RequesterSSRC is the SSRC of the peer that issued the request.
	RequesterSSRC uint32
	// TimestampMSW and TimestampLSW are the high and low 32 bits of the
	// originator's 64-bit timestamp.
	TimestampMSW uint32
	TimestampLSW uint32
	// ProcessingDelay is the responder's request-to-response delay in
	// microseconds (zero in a request).
	ProcessingDelay uint32
}

// Timestamp returns the originator's 64-bit timestamp (MSW<<32 | LSW).
func (e RTTEcho) Timestamp() uint64 {
	return uint64(e.TimestampMSW)<<32 | uint64(e.TimestampLSW)
}

// appendBody appends the 16-byte RTT echo body to dst.
func (e RTTEcho) appendBody(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, e.RequesterSSRC)
	dst = binary.BigEndian.AppendUint32(dst, e.TimestampMSW)
	dst = binary.BigEndian.AppendUint32(dst, e.TimestampLSW)
	return binary.BigEndian.AppendUint32(dst, e.ProcessingDelay)
}

// RTTEchoFromTimestamp builds an RTTEcho body for the given requester SSRC,
// 64-bit timestamp, and processing delay.
func RTTEchoFromTimestamp(requesterSSRC uint32, ts uint64, processingDelay uint32) RTTEcho {
	return RTTEcho{
		RequesterSSRC:   requesterSSRC,
		TimestampMSW:    uint32(ts >> 32),
		TimestampLSW:    uint32(ts),
		ProcessingDelay: processingDelay,
	}
}

// ParseRTTEcho decodes a 16-byte RTT echo body (request or response).
func ParseRTTEcho(body []byte) (RTTEcho, error) {
	if len(body) < rttEchoBodySize {
		return RTTEcho{}, fmt.Errorf("%w: %d < %d bytes for rtt echo", ErrShortControl, len(body), rttEchoBodySize)
	}
	return RTTEcho{
		RequesterSSRC:   binary.BigEndian.Uint32(body[0:4]),
		TimestampMSW:    binary.BigEndian.Uint32(body[4:8]),
		TimestampLSW:    binary.BigEndian.Uint32(body[8:12]),
		ProcessingDelay: binary.BigEndian.Uint32(body[12:16]),
	}, nil
}

// Keepalive is a keep-alive control body (CIKeepalive, TR-06-3 §5.3.6): a
// 6-byte MAC address and a 32-bit capability word (see the KeepaliveCap*
// bits). libRIST reads only the capability word on receipt.
type Keepalive struct {
	// MAC is the originator's 6-byte hardware address (informational).
	MAC [6]byte
	// Caps is the capability bitmask (KeepaliveCapI/G/C).
	Caps uint32
}

// appendBody appends the 10-byte keep-alive body to dst.
func (k Keepalive) appendBody(dst []byte) []byte {
	dst = append(dst, k.MAC[:]...)
	return binary.BigEndian.AppendUint32(dst, k.Caps)
}

// ParseKeepalive decodes a keep-alive body (>= 10 bytes).
func ParseKeepalive(body []byte) (Keepalive, error) {
	if len(body) < keepaliveBodySize {
		return Keepalive{}, fmt.Errorf("%w: %d < %d bytes for keepalive", ErrShortControl, len(body), keepaliveBodySize)
	}
	var k Keepalive
	copy(k.MAC[:], body[0:6])
	k.Caps = binary.BigEndian.Uint32(body[6:10])
	return k, nil
}

// PSKNonce is a PSK future-nonce announcement (CIPSKNonce, TR-06-3 §5.3.9):
// the 4-byte nonce a sender will rotate to and the AES key size in bits,
// letting the receiver pre-derive the (expensive) PBKDF2 key before the first
// data packet using the new nonce arrives. The nonce's most significant bit
// selects the receiver's even/odd key slot.
type PSKNonce struct {
	// Nonce is the 4-byte future nonce.
	Nonce [4]byte
	// KeyBits is the AES key size in bits (128 or 256).
	KeyBits uint16
}

// appendBody appends the 8-byte PSK nonce body to dst: nonce(4), key bits(2),
// reserved(2).
func (p PSKNonce) appendBody(dst []byte) []byte {
	dst = append(dst, p.Nonce[:]...)
	dst = binary.BigEndian.AppendUint16(dst, p.KeyBits)
	return append(dst, 0, 0) // reserved
}

// ParsePSKNonce decodes an 8-byte PSK future-nonce body.
func ParsePSKNonce(body []byte) (PSKNonce, error) {
	if len(body) < pskNonceBodySize {
		return PSKNonce{}, fmt.Errorf("%w: %d < %d bytes for psk nonce", ErrShortControl, len(body), pskNonceBodySize)
	}
	var p PSKNonce
	copy(p.Nonce[:], body[0:4])
	p.KeyBits = binary.BigEndian.Uint16(body[4:6])
	return p, nil
}

// Convenience builders that frame a complete control payload (sub-header +
// body) for the common message types, appending to dst.

// BuildNackBitmask frames a NACK Bitmask control payload.
func BuildNackBitmask(dst []byte, n NackBitmask) []byte {
	return BuildControl(dst, CINackBitmask, n.appendBody(nil))
}

// BuildNackRange frames a NACK Range control payload.
func BuildNackRange(dst []byte, n NackRange) []byte {
	return BuildControl(dst, CINackRange, n.appendBody(nil))
}

// BuildRTTEchoRequest frames an RTT Echo Request control payload.
func BuildRTTEchoRequest(dst []byte, e RTTEcho) []byte {
	return BuildControl(dst, CIRTTEchoReq, e.appendBody(nil))
}

// BuildRTTEchoResponse frames an RTT Echo Response control payload.
func BuildRTTEchoResponse(dst []byte, e RTTEcho) []byte {
	return BuildControl(dst, CIRTTEchoResp, e.appendBody(nil))
}

// BuildKeepalive frames a keep-alive control payload.
func BuildKeepalive(dst []byte, k Keepalive) []byte {
	return BuildControl(dst, CIKeepalive, k.appendBody(nil))
}

// BuildPSKNonce frames a PSK future-nonce control payload.
func BuildPSKNonce(dst []byte, p PSKNonce) []byte {
	return BuildControl(dst, CIPSKNonce, p.appendBody(nil))
}

// BuildFlowAttr frames a Flow Attribute control payload (CIFlowAttr, TR-06-3
// §5.3.7): a UTF-8 JSON body copied verbatim.
func BuildFlowAttr(dst []byte, json []byte) []byte {
	return BuildControl(dst, CIFlowAttr, json)
}

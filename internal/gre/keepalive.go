package gre

import (
	"errors"
	"fmt"
)

// ErrBadKeepalive is returned by ParseKeepalive when the buffer is too short
// to hold the fixed keep-alive body (gre.c:253-254, the
// buflen < sizeof(struct rist_gre_keepalive) guard).
var ErrBadKeepalive = errors.New("rist: gre: keepalive too short")

// Keep-alive capability bit positions, in C bit numbering (bit 7 is the MSB),
// matching libRIST's CHECK_BIT calls in _librist_proto_gre_parse_keepalive
// (gre.c:259-271). The first capability octet (capabilities1) carries N, L,
// E, P, A, B, R, X (bits 0..7); the second (capabilities2) carries F, J, V,
// T, D in bits 3..7.
const (
	// capabilities1 bits (gre.c:259-266).
	capN = 0 // Null-packet deletion.
	capL = 1 // Pair-split (sender split mode active).
	capE = 2 // SMPTE 2022-7 (multipath bonding redundancy).
	capP = 3
	capA = 4
	capB = 5 // Bonding.
	capR = 6
	capX = 7

	// capabilities2 bits (gre.c:267-271).
	capF = 3
	capJ = 4
	capV = 5 // Reduced-overhead header support.
	capT = 6
	capD = 7
)

// Advanced-profile extended-capability bit positions in the first octet of
// the optional 4-byte extended block (rist-common.c:273-279, TR-06-3 §5.3.6),
// in C bit numbering.
const (
	advI = 7 // Advanced Profile capable.
	advG = 6 // GRE key rotation capable.
	advC = 5 // Compression capable.
)

// Capabilities holds the decoded keep-alive capability bits. The field names
// mirror libRIST's rist_keepalive_info booleans (protocol_gre.h).
type Capabilities struct {
	N bool // Null-packet deletion (capabilities1 bit 0).
	L bool // Pair-split (capabilities1 bit 1).
	E bool // SMPTE 2022-7 (capabilities1 bit 2).
	P bool // capabilities1 bit 3.
	A bool // capabilities1 bit 4.
	B bool // Bonding (capabilities1 bit 5).
	R bool // capabilities1 bit 6.
	X bool // capabilities1 bit 7.
	F bool // capabilities2 bit 3.
	J bool // capabilities2 bit 4.
	V bool // Reduced-overhead support (capabilities2 bit 5).
	T bool // capabilities2 bit 6.
	D bool // capabilities2 bit 7.
}

// StandardCapabilities returns the capability set libRIST's sender advertises
// by default: null-packet deletion (N), SMPTE 2022-7 (E), bonding (B), and
// reduced-overhead support (V) (gre.c:231-236). The pair-split bit (L) is set
// only when the sender's split mode is active and is therefore left clear
// here; callers may set it explicitly.
func StandardCapabilities() Capabilities {
	return Capabilities{N: true, E: true, B: true, V: true}
}

// encode returns the two capability octets (capabilities1, capabilities2) for
// the receiver's bit layout (gre.c:231-236,259-271).
func (c Capabilities) encode() (byte, byte) {
	var c1, c2 byte
	set := func(dst *byte, bit uint, v bool) {
		if v {
			*dst |= 1 << bit
		}
	}
	set(&c1, capN, c.N)
	set(&c1, capL, c.L)
	set(&c1, capE, c.E)
	set(&c1, capP, c.P)
	set(&c1, capA, c.A)
	set(&c1, capB, c.B)
	set(&c1, capR, c.R)
	set(&c1, capX, c.X)
	set(&c2, capF, c.F)
	set(&c2, capJ, c.J)
	set(&c2, capV, c.V)
	set(&c2, capT, c.T)
	set(&c2, capD, c.D)
	return c1, c2
}

// decodeCapabilities decodes the two capability octets into a Capabilities.
func decodeCapabilities(c1, c2 byte) Capabilities {
	bit := func(b byte, pos uint) bool { return b&(1<<pos) != 0 }
	return Capabilities{
		N: bit(c1, capN),
		L: bit(c1, capL),
		E: bit(c1, capE),
		P: bit(c1, capP),
		A: bit(c1, capA),
		B: bit(c1, capB),
		R: bit(c1, capR),
		X: bit(c1, capX),
		F: bit(c2, capF),
		J: bit(c2, capJ),
		V: bit(c2, capV),
		T: bit(c2, capT),
		D: bit(c2, capD),
	}
}

// AdvExtCaps holds the optional Advanced-profile extended capability bits
// carried in the first octet of the 4-byte block after the keep-alive body
// (rist-common.c:273-279).
type AdvExtCaps struct {
	I bool // Advanced Profile capable (byte 8 bit 7).
	G bool // GRE key rotation capable (byte 8 bit 6).
	C bool // Compression capable (byte 8 bit 5).
}

// encode returns the first octet of the extended-capability block. libRIST
// emits the I bit as 0x80 with the remaining three octets zero
// (gre.c:242-245).
func (a AdvExtCaps) encode() byte {
	var b byte
	if a.I {
		b |= 1 << advI
	}
	if a.G {
		b |= 1 << advG
	}
	if a.C {
		b |= 1 << advC
	}
	return b
}

// Keepalive is a parsed RIST keep-alive message body (gre.h:123-129 plus the
// optional TR-06-3 extended block and JSON payload). It is the GRE payload of
// a ProtoKeepalive packet; the GRE header is handled separately by Header.
type Keepalive struct {
	// MAC is the 48-bit MAC address identifying the sending node
	// (gre.h:126, mac_array).
	MAC [6]byte

	// Caps are the negotiated capability bits (gre.h:127-128).
	Caps Capabilities

	// HasAdvExt reports whether the optional 4-byte Advanced-profile
	// extended-capability block is present (rist-common.c:273).
	HasAdvExt bool

	// AdvExt holds the Advanced-profile extended capabilities; meaningful
	// only when HasAdvExt is set.
	AdvExt AdvExtCaps

	// JSON is the optional trailing JSON message payload (gre.h:69). It is
	// nil when absent. After ParseKeepalive it aliases the input buffer.
	JSON []byte
}

// Size returns the number of bytes AppendTo will write: the fixed body, the
// optional 4-byte extended block, and the JSON payload.
func (k Keepalive) Size() int {
	n := KeepaliveSize
	if k.HasAdvExt {
		n += AdvExtSize
	}
	n += len(k.JSON)
	return n
}

// AppendTo appends the serialized keep-alive body to dst and returns the
// extended slice: 6-byte MAC, two capability octets, then the optional
// extended-capability block and JSON payload (gre.c:228-247). It writes only
// the keep-alive payload; the surrounding GRE header is the caller's
// responsibility.
//
// Round-trip caveat: a Keepalive with HasAdvExt false and four or more JSON
// bytes does not round-trip symmetrically — ParseKeepalive reads the first
// four trailing bytes as the extended-capability block (yielding HasAdvExt
// true). This is the format's inherent on-wire ambiguity, faithfully mirrored:
// libRIST's parser uses the same "four trailing bytes => extended block"
// heuristic (gre.c:272) and its sender never attaches a JSON payload.
func (k Keepalive) AppendTo(dst []byte) []byte {
	dst = append(dst, k.MAC[:]...)
	c1, c2 := k.Caps.encode()
	dst = append(dst, c1, c2)
	if k.HasAdvExt {
		dst = append(dst, k.AdvExt.encode(), 0, 0, 0)
	}
	if len(k.JSON) > 0 {
		dst = append(dst, k.JSON...)
	}
	return dst
}

// ParseKeepalive decodes a keep-alive body from b: the 6-byte MAC and
// capability octets, the optional 4-byte Advanced extended block (present
// when at least four trailing bytes follow the fixed body), and any remaining
// bytes as the JSON payload. The returned Keepalive's JSON aliases b. It
// mirrors _librist_proto_gre_parse_keepalive (gre.c:251-286) and never panics
// on short or arbitrary input.
func ParseKeepalive(b []byte) (Keepalive, error) {
	if len(b) < KeepaliveSize {
		return Keepalive{}, fmt.Errorf("%w: %d < %d bytes", ErrBadKeepalive, len(b), KeepaliveSize)
	}

	var k Keepalive
	copy(k.MAC[:], b[0:6])
	k.Caps = decodeCapabilities(b[6], b[7])

	rest := b[KeepaliveSize:]
	if len(rest) >= AdvExtSize {
		k.HasAdvExt = true
		first := rest[0]
		k.AdvExt = AdvExtCaps{
			I: first&(1<<advI) != 0,
			G: first&(1<<advG) != 0,
			C: first&(1<<advC) != 0,
		}
		if json := rest[AdvExtSize:]; len(json) > 0 {
			k.JSON = json
		}
	} else if len(rest) > 0 {
		k.JSON = rest
	}
	return k, nil
}

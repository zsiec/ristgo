// Package ristgo implements the RIST (Reliable Internet Stream Transport)
// protocol — the VSF TR-06 family — in pure Go.
//
// RIST is the broadcast industry's open standard for reliable, low-latency
// transport of live media over lossy IP networks. It composes standard wire
// formats (RTP/RTCP, and GRE-over-UDP for the Main profile) with NACK-based
// retransmission (ARQ) and optional SMPTE 2022-7 packet-level multipath
// reconstruction. This implementation targets wire-level interoperability
// with libRIST, the C reference implementation embedded in FFmpeg, VLC,
// GStreamer, and TSDuck.
//
// # Architecture
//
// The stack is split into three layers around a narrow waist:
//
//   - Codec layer (internal/rtp, internal/rtcp, internal/gre): pure,
//     fuzz-tested encode/decode functions. Each profile's codec translates
//     between wire bytes and a shared normalized packet representation, so
//     profile differences (16- vs 32-bit sequence numbers, range vs bitmask
//     NACK encodings, retransmit SSRC marking) are erased at the boundary.
//   - Deterministic core (internal/flow): a sans-I/O, profile-agnostic
//     engine for ARQ, reordering, deduplication, RTT/NACK cadence, and
//     SMPTE 2022-7 multipath merge. The core never reads a clock, opens a
//     socket, or spawns a goroutine: time enters as an explicit argument
//     and effects (send this, arm that timer) are returned for the host to
//     perform. This makes packet-loss and multipath behavior exhaustively
//     testable with a seeded network simulator.
//   - Goroutine host (internal/session and friends): owns the real clock,
//     timers, and UDP sockets; pumps packets and effects between the wire
//     and the deterministic core.
//
// # Status
//
// ristgo is in early development. This package currently provides the
// configuration surface (Config, DefaultConfig), profile and NACK-type
// enums, sentinel errors, and the Logger interface. The Sender and
// Receiver types — the io-native data path — arrive in a later milestone,
// followed by Main profile (GRE + PSK encryption), the Advanced profile,
// and SMPTE 2022-7 bonding. Only the Simple profile wire format is being
// implemented first; see Config.Profile for the interim default.
package ristgo

// Version is the ristgo library version.
const Version = "0.0.1"

// Profile selects the RIST wire profile. The numeric values match
// libRIST's enum rist_profile so configurations translate directly.
type Profile int

const (
	// ProfileSimple is the Simple profile (VSF TR-06-1): plain RTP on an
	// even UDP port with compound RTCP on the adjacent odd port. No
	// tunneling, no encryption.
	ProfileSimple Profile = 0

	// ProfileMain is the Main profile (VSF TR-06-2): GRE-over-UDP on a
	// single port, with optional PSK encryption and SRP authentication.
	ProfileMain Profile = 1

	// ProfileAdvanced is the Advanced profile (VSF TR-06-3): a compact
	// header with AEAD ciphers, payload compression, and per-fragment
	// retransmission.
	ProfileAdvanced Profile = 2
)

// String returns a human-readable name for the profile.
func (p Profile) String() string {
	switch p {
	case ProfileSimple:
		return "simple"
	case ProfileMain:
		return "main"
	case ProfileAdvanced:
		return "advanced"
	default:
		return "unknown"
	}
}

// NACKType selects the wire encoding used for retransmission requests.
type NACKType int

const (
	// NACKRange encodes losses as RTCP APP ("RIST") packets carrying
	// {start, additional-count} ranges. This is the RIST and libRIST
	// default.
	NACKRange NACKType = 0

	// NACKBitmask encodes losses as RFC 4585 Generic NACK feedback
	// (PT 205, FMT 1) carrying {PID, BLP} 17-packet bitmask ranges.
	NACKBitmask NACKType = 1
)

// String returns a human-readable name for the NACK encoding.
func (n NACKType) String() string {
	switch n {
	case NACKRange:
		return "range"
	case NACKBitmask:
		return "bitmask"
	default:
		return "unknown"
	}
}

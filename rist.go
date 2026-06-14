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
// # Getting started
//
// A Sender reads media (e.g. MPEG-TS) and transmits it; a Receiver recovers and
// delivers the in-order stream. Both are io-native and take a context plus
// functional options:
//
//	tx, err := ristgo.Dial(ctx, "203.0.113.7:5000")
//	if err != nil { ... }
//	defer tx.Close()
//	tx.Write(mpegtsChunk) // up to MaxMediaPayload bytes per call
//
//	rx, err := ristgo.Listen(ctx, ":5000")
//	if err != nil { ... }
//	defer rx.Close()
//	n, err := rx.Read(buf) // in-order, ARQ-recovered media
//
// Cancelling ctx closes the session (aborting a pending handshake and unblocking
// Read/Write). Options configure the common knobs — for example
// ristgo.WithProfile(ristgo.ProfileMain), ristgo.WithSecret("…"),
// ristgo.WithDTLS(…) — and WithConfig passes a full [Config] for anything else.
// The Config-based [NewSender]/[NewReceiver] constructors remain for callers who
// prefer the struct; either form also accepts a rist:// URL as the address,
// configuring from its query string.
//
// # Profiles and features
//
// All three RIST profiles are implemented and interoperate with libRIST:
//
//   - Simple (VSF TR-06-1): RTP media with compound RTCP on an even/odd UDP port
//     pair.
//   - Main (VSF TR-06-2): GRE-over-UDP on a single port, PSK AES-CTR encryption,
//     EAP-SRP authentication, null-packet deletion, and optional pure-Go DTLS 1.2
//     transport security ([Config.DTLS]).
//   - Advanced (VSF TR-06-3): compact RTP-based framing with AEAD ciphers and LZ4
//     payload compression.
//
// Across every profile: NACK-based ARQ retransmission (range or bitmask), SMPTE
// 2022-7 link bonding ([BondedSender]/[BondedReceiver]) for seamless multipath
// reconstruction, and source adaptation (VSF TR-06-4 Part 1) that feeds link
// quality back to an encoder-rate callback.
package ristgo

// Version is the ristgo library version.
const Version = "0.1.0"

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
	// RTP-based header with AEAD ciphers and LZ4 payload compression.
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

// Package ristgo implements the RIST (Reliable Internet Stream Transport)
// protocol (the VSF TR-06 family) in pure Go.
//
// RIST is an open standard for reliable, low-latency transport of live media
// over lossy IP networks. It composes standard wire formats (RTP/RTCP, and
// GRE-over-UDP for the Main profile) with NACK-based retransmission (ARQ) and
// optional SMPTE 2022-7 packet-level multipath reconstruction. This
// implementation targets wire-level interoperability with libRIST, the C
// reference implementation embedded in FFmpeg, VLC, GStreamer, and TSDuck.
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
// Read/Write). Options configure the common knobs, for example
// ristgo.WithProfile(ristgo.ProfileMain), ristgo.WithSecret("..."), and
// ristgo.WithDTLS(...); WithConfig passes a full [Config] for anything else.
// The Config-based [NewSender]/[NewReceiver] constructors remain for callers who
// prefer the struct, and either form also accepts a rist:// URL as the address,
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
//   - Advanced (VSF TR-06-3): compact RTP-based framing with AEAD ciphers, LZ4
//     payload compression, and payload fragmentation ([Config.FragmentSize]).
//
// Across every profile: NACK-based ARQ retransmission (range or bitmask), SMPTE
// 2022-7 link bonding ([BondedSender]/[BondedReceiver]) for seamless multipath
// reconstruction, SMPTE ST 2022-1 and ST 2022-5 forward error correction
// ([Config.FEC], [WithFEC]) that recovers losses with no NACK round trip, source
// adaptation (VSF TR-06-4 Part 1) that feeds link quality back to an encoder-rate
// callback, and IP multicast (group membership, multicast TTL, egress interface,
// and source-specific filtering via [Config.Interface], [Config.MulticastTTL],
// [Config.MulticastSource], and [Config.MulticastLoopback]).
//
// # Connection roles
//
// The protocol role can be decoupled from the connection direction: a Receiver
// can dial a listening Sender ([NewReceiverCaller], [DialReceiver]) and a Sender
// can bind and wait for a receiver to connect ([NewListenerSender],
// [ListenSender]). One-way transport with no return channel is available via
// [NewOneWaySender] and [NewOneWayReceiver]: the sender keeps no retransmit
// history and emits no RTCP, and the receiver emits no RTCP and requests no
// retransmissions.
//
// A [MultiReceiver] binds one port and demultiplexes the several media flows
// arriving on it into independent receivers, one per flow (stream
// multiplexing): the Simple profile demuxes by RTP SSRC and the Main/Advanced
// profiles by source address, matching libRIST's per-flow model.
//
// # Limitations
//
// A few capabilities are ristgo to ristgo only, because libRIST does not
// implement them: payload fragmentation and reassembly ([Config.FragmentSize]),
// one-way (no-return-channel) transport ([NewOneWaySender],
// [NewOneWayReceiver]), and the Advanced-profile AEAD ciphers (AES-GCM and
// ChaCha20-Poly1305 are built to the TR-06-3 spec, but libRIST Advanced
// implements AES-CTR only). DTLS and EAP-SRP are not available in the
// reversed-role, one-way, or bonded modes.
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

// CongestionControl selects how the sender paces retransmissions against the
// recovery bitrate (MaxBitrate) — libRIST's congestion_control. The zero value
// is CongestionNormal, the libRIST default, so a zero Config behaves like
// DefaultConfig.
//
// NOTE: these constant values are ristgo's own API encoding (chosen so the zero
// value is the default), NOT libRIST's wire/URL numbering, which is
// off=0/normal=1/aggressive=2. ParseURL maps the libRIST congestion-control=N
// query value to the right constant.
type CongestionControl int

const (
	// CongestionNormal paces retransmissions against MaxBitrate using the slow
	// bandwidth EWMA — the libRIST default (congestion_control = NORMAL). As the
	// zero value it applies to a zero Config.
	CongestionNormal CongestionControl = 0

	// CongestionAggressive uses the fast EWMA for both the data and the
	// retransmit rate, recovering loss faster at the cost of burstier
	// retransmission (libRIST congestion_control = AGGRESSIVE).
	CongestionAggressive CongestionControl = 1

	// CongestionOff disables MaxBitrate pacing of retransmissions entirely
	// (libRIST congestion_control = OFF).
	CongestionOff CongestionControl = 2
)

// String returns a human-readable name for the congestion-control mode.
func (c CongestionControl) String() string {
	switch c {
	case CongestionNormal:
		return "normal"
	case CongestionAggressive:
		return "aggressive"
	case CongestionOff:
		return "off"
	default:
		return "unknown"
	}
}

// SplitMode selects libRIST's packet-split bonding on the sender (split=): each
// Write is spread across a consecutive even/odd sequence pair carrying the same
// source time, so a bonded pair of links can each carry half and a merge=-configured
// receiver recombines them. The zero value SplitOff disables it. Works on every
// profile and interoperates with libRIST.
type SplitMode int

const (
	// SplitOff sends each payload whole — no splitting (the default, zero value).
	SplitOff SplitMode = 0
	// SplitAuto splits on a 188-byte MPEG-TS boundary at the midpoint when the
	// payload is TS-aligned, otherwise at the byte midpoint (libRIST split=auto).
	SplitAuto SplitMode = 1
	// SplitHalf always splits at the byte midpoint (libRIST split=half).
	SplitHalf SplitMode = 2
)

// String returns a human-readable name for the split mode (the libRIST URL word).
func (m SplitMode) String() string {
	switch m {
	case SplitAuto:
		return "auto"
	case SplitHalf:
		return "half"
	case SplitOff:
		return "off"
	default:
		return "unknown"
	}
}

// MergeMode selects libRIST's packet-merge bonding on the receiver (merge=), the
// counterpart to SplitMode: it recombines a split pair — an even sequence and its
// same-source-time seq+1 partner — back into the original payload. MergeAuto only
// does so once the peer advertises pair-splitting (the GRE keepalive L bit). The zero
// value MergeOff disables it. Works on every profile and interoperates with libRIST.
type MergeMode int

const (
	// MergeOff delivers each packet as received — no merging (the default).
	MergeOff MergeMode = 0
	// MergePairs recombines every even/odd consecutive same-source-time pair
	// (libRIST merge=pairs).
	MergePairs MergeMode = 1
	// MergeAuto recombines only once the peer advertises pair-splitting via the GRE
	// keepalive L bit (libRIST merge=auto).
	MergeAuto MergeMode = 2
)

// String returns a human-readable name for the merge mode (the libRIST URL word).
func (m MergeMode) String() string {
	switch m {
	case MergePairs:
		return "pairs"
	case MergeAuto:
		return "auto"
	case MergeOff:
		return "off"
	default:
		return "unknown"
	}
}

// TimingMode selects how the receiver schedules media playout (libRIST
// timing_mode). The zero value is TimingSource, the libRIST default. These values
// match libRIST's SOURCE=0/ARRIVAL=1/RTC=2 numbering.
type TimingMode int

const (
	// TimingSource paces playout by the media SOURCE timestamps: a packet's
	// playout deadline is its source time plus the recovery buffer, so
	// inter-packet spacing follows the source clock. Default and zero value.
	TimingSource TimingMode = 0

	// TimingArrival paces playout by ARRIVAL time: each packet is held a fixed
	// recovery buffer from when it arrived, ignoring the source timestamps for
	// pacing (they still drive the (Seq, SourceTime) dedup / 2022-7 merge). It is
	// robust to a drifting or absent source clock but does not preserve source
	// inter-packet timing.
	TimingArrival TimingMode = 1

	// TimingRTC (libRIST RIST_TIMING_MODE_RTC) is source-paced like TimingSource but
	// treats the source timestamps as a common NTP wall clock: the sender stamps
	// SourceTime from the real-time clock (Main/Advanced) and the receiver maps it
	// through a fixed offset, with the 32-bit source-clock wrap re-anchor disabled (a
	// 64-bit NTP wall clock does not wrap on that boundary). Scheduling stays on the
	// monotonic clock, so an NTP step cannot jolt the timer wheel.
	TimingRTC TimingMode = 2
)

// String returns a human-readable name for the timing mode.
func (m TimingMode) String() string {
	switch m {
	case TimingSource:
		return "source"
	case TimingArrival:
		return "arrival"
	case TimingRTC:
		return "rtc"
	default:
		return "unknown"
	}
}

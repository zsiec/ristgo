// Package wire defines the narrow-waist types that decouple the profile
// codecs from the deterministic flow core.
//
// # The narrow waist
//
// Every RIST profile speaks a different wire dialect: Simple profile is bare
// RTP/RTCP on an even/odd port pair, Main profile tunnels the same traffic
// over GRE with optional PSK encryption, and Advanced profile replaces RTCP
// with its own control messages. The codec packages (internal/rtp,
// internal/rtcp, internal/gre, internal/adv) own those dialects: they decode
// inbound datagrams into the normalized types in this package, and encode
// the normalized types back into the profile's bytes on the way out.
//
// The deterministic core (internal/flow) consumes and produces only these
// normalized types. It never parses a byte of wire format, never sees a
// 16-bit sequence number, and never learns which profile is in use. That is
// what makes the core profile-agnostic: one ARQ + reorder + dedup +
// SMPTE 2022-7 merge implementation serves all three profiles.
//
// # Extension policy
//
// New profile behavior is expressed as a new field on MediaPacket or a new
// Feedback variant in this package — never as a profile branch inside flow.
// If a future profile needs the core to act differently, the difference must
// be representable as normalized data crossing this waist. Feedback is a
// sealed interface (unexported marker method) so the set of variants is
// enumerable here and exhaustively handled by the profile strategies.
//
// # Import discipline
//
// flow may import only internal/seq, internal/clock, internal/rtt, and this
// package (plus the standard library). A CI gate asserts this with
// `go list -deps ./internal/flow`. This package therefore stays data-only:
// no clocks, no sockets, no profile constants, no behavior that could tempt
// profile logic to accrete at the waist.
package wire

// MediaPacket is the normalized form of one media datagram, regardless of
// which profile carried it or which path delivered it. Codecs produce it on
// receive and consume it on send; flow stores it in the seq-indexed ring and
// deduplicates it by the (Seq, SourceTime) pair.
type MediaPacket struct {
	// Seq is the media sequence number. It is ALWAYS 32-bit at this layer:
	// Simple and Main profile codecs widen the 16-bit RTP sequence number
	// via rollover counting (the upper 16 bits are the wrap count), and the
	// Advanced profile carries a native 32-bit extended sequence. The flow
	// core only ever performs 32-bit wrap-aware arithmetic.
	Seq uint32

	// SourceTime is the sender's media timestamp in NTP-64-compatible
	// units: the upper 32 bits are whole seconds and the lower 32 bits are
	// the fractional second (1/2^32 resolution). flow uses it both for
	// playout scheduling and as the second half of the (Seq, SourceTime)
	// duplicate test that implements the SMPTE 2022-7 merge.
	SourceTime uint64

	// SSRC is the RTP synchronization source identifying the media stream,
	// with the retransmit toggle already cleared: RIST senders use an even
	// base SSRC and set the low bit on retransmissions, and the receiving
	// codec un-toggles it before the packet crosses this waist. All copies
	// of a stream — first transmissions, retransmits, and 2022-7 duplicate
	// paths — therefore carry the same SSRC here.
	SSRC uint32

	// Payload is the media payload (typically MPEG-TS cells). It is a
	// reference, not a copy: the producer hands ownership of the backing
	// array to the consumer when the packet crosses the waist.
	Payload []byte

	// Retransmit reports whether this copy is an ARQ retransmission. It is
	// set by the codec from the SSRC-LSB toggle (retransmits resend the
	// original RTP packet with the same Seq and SSRC|1; the codec detects
	// the odd SSRC, clears the bit into SSRC above, and sets this flag).
	// flow uses it to skip missing-detection for recovered packets and to
	// keep retry statistics honest.
	Retransmit bool

	// PathID identifies which network path delivered (or should carry)
	// this packet. Single-path flows use 0. For SMPTE 2022-7 bonding the
	// session assigns a stable index per registered peer, and flow records
	// per-path arrival without ever knowing what a path is.
	PathID uint8
}

// Feedback is the normalized form of everything that is not media: RTCP
// control traffic in the Simple and Main profiles, and Advanced profile
// control messages. flow emits Feedback values describing intent (for
// example "request retransmission of these sequences") and the session's
// profile strategy runs the matching encoder; inbound control traffic is
// decoded into Feedback before flow sees it.
//
// Feedback is sealed: the unexported marker method means only this package
// can add variants, so profile strategies and flow can type-switch over the
// complete set. To extend, add a new variant here (see the package extension
// policy) — never branch on profile inside flow.
type Feedback interface {
	// isFeedback is the sealing marker. It is intentionally unexported so
	// that no new variant can be added outside this package. Note the
	// limit of the guarantee: a foreign type CAN satisfy Feedback by
	// embedding a variant, but its dynamic type matches no case of an
	// exhaustive switch over the variants defined here — so switches must
	// treat their default case as a reachable programming error, not as
	// impossible.
	isFeedback()
}

// NackRequest asks the sender to retransmit missing media packets. It is
// emitted by flow on the receiving side; the profile strategy chooses the
// wire encoding at send time — RFC 4585 Generic NACK bitmask (RTCP PT 205,
// FMT 1), RIST APP range NACK (RTCP PT 204, name "RIST"), or an Advanced
// profile control message — mirroring libRIST's seq-array dispatch. flow
// never knows which encoding was used.
type NackRequest struct {
	// SSRC identifies the media stream the missing sequences belong to.
	SSRC uint32

	// Missing lists the sequence numbers to retransmit, in the 32-bit
	// widened space of MediaPacket.Seq. Codecs narrow back to 16 bits for
	// the Simple/Main wire encodings.
	Missing []uint32
}

// RttEchoRequest asks the remote peer to echo a timestamp so the requester
// can measure round-trip time. On the Simple and Main profile wire it is an
// RTCP APP packet (PT 204, name "RIST", subtype 2).
type RttEchoRequest struct {
	// Timestamp is the requester's clock sample in NTP-64-compatible units,
	// echoed back verbatim in the matching RttEchoResponse.
	Timestamp uint64
}

// RttEchoResponse answers an RttEchoRequest. On the Simple and Main profile
// wire it is an RTCP APP packet (PT 204, name "RIST", subtype 3). The
// requester computes RTT as (now − Timestamp) − ProcessingDelay.
type RttEchoResponse struct {
	// Timestamp is the requester's original timestamp, echoed verbatim
	// from the RttEchoRequest.
	Timestamp uint64

	// ProcessingDelay is the time in microseconds the responder spent
	// between receiving the request and sending this response, so the
	// requester can subtract it and measure pure network round-trip time.
	ProcessingDelay uint32
}

// SenderReport carries the timing essentials of an RTCP Sender Report
// (PT 200): the mapping between the sender's wallclock and the RTP media
// timeline. The receiver uses it to convert RTP timestamps to sender
// wallclock for playout and inter-stream alignment.
type SenderReport struct {
	// NTP is the sender's wallclock at the moment the report was generated,
	// in NTP-64 format (upper 32 bits seconds since the NTP epoch, lower
	// 32 bits fractional second).
	NTP uint64

	// RTPTime is the RTP timestamp corresponding to the same instant as
	// NTP, in the media clock rate of the stream.
	RTPTime uint32
}

// Keepalive marks a peer as alive without carrying media.
//
// This is a stub for the Main profile, where keepalives are GRE frames
// (VSF EtherType 0xCCE0, subtype 0x8000) carrying a MAC address, capability
// bits, and an optional JSON payload. Those fields will be added here when
// Main profile lands (Phase 2); until then the variant exists so liveness
// plumbing (session_timeout, PathDead detection) can be built and tested
// against the waist without a profile branch.
type Keepalive struct{}

// ExtSeq announces the upper 16 bits of the 32-bit extended sequence space
// that subsequent 16-bit NACK entries belong to. On the Main profile wire it
// is the EXTSEQ RTCP APP packet (PT 204, name "RIST", subtype 1) defined by
// VSF TR-06-2 §8.4, sent immediately before the NACK packet it qualifies.
//
// It exists at the waist because widening is a codec concern: a receiving
// codec folds SeqHigh into the following NackRequest's 32-bit Missing values,
// and a sending codec derives ExtSeq packets by splitting a NackRequest's
// Missing list by upper half. flow itself never emits or consumes ExtSeq —
// it lives here so the profile strategies can exchange it without a profile
// branch.
type ExtSeq struct {
	// SeqHigh is the most significant 16 bits prepended to the 16-bit
	// starting sequence numbers of the NACK entries that follow.
	SeqHigh uint16
}

// Marker-method implementations sealing the Feedback variant set.
func (NackRequest) isFeedback()     {}
func (RttEchoRequest) isFeedback()  {}
func (RttEchoResponse) isFeedback() {}
func (SenderReport) isFeedback()    {}
func (Keepalive) isFeedback()       {}
func (ExtSeq) isFeedback()          {}

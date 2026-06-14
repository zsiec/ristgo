package flow

import (
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// TimerID identifies one declarative timer requested by the core. The core
// never owns a clock or a timer wheel: it emits SetTimer/ClearTimer effects
// carrying these identifiers, and the host calls HandleTimer(now, id) when a
// requested deadline arrives. Re-issuing SetTimer for an armed ID replaces
// its deadline.
type TimerID uint32

// Timer identifiers used by the receiver half. The sender half (next stage)
// extends this list; hosts must treat the set as open-ended and key their
// wheel by value.
const (
	// TimerPlayout wakes the receiver when the earliest buffered packet
	// reaches its outputTime so time-driven in-order delivery can proceed.
	TimerPlayout TimerID = iota

	// TimerNack paces the receiver's NACK processing pass. libRIST bounds
	// the receiver loop's jitter at RIST_MAX_JITTER = 5 ms; the core re-arms
	// this timer at that cadence while missing entries are queued.
	TimerNack

	// TimerRttEcho paces a flow's RTT echo requests at libRIST's
	// RIST_PING_INTERVAL = 100 ms. Both roles originate echo requests to
	// measure their own RTT (the receiver for NACK retry spacing, the sender
	// for the retransmit gate); each runs on its own host timer wheel, so the
	// single ID never collides.
	TimerRttEcho
)

// Output is one side effect the core asks the host to perform. Outputs are
// drained in FIFO order via Flow.PollOutput and must be performed by the
// host; the core never touches a socket or a clock itself.
//
// Output is sealed (unexported marker method): the variant set is enumerable
// here so hosts can type-switch exhaustively. A host's default case should
// be treated as a programming error (a new variant was added without
// updating the host), not as ignorable input.
type Output interface {
	// isOutput is the sealing marker; only this package can add variants.
	isOutput()
}

// SendMedia asks the host to transmit one media packet on the given path.
// Emitted by the sender half (first transmissions and retransmissions);
// the receiver half never emits it.
type SendMedia struct {
	// Path is the network path index the packet must leave on.
	Path uint8
	// Pkt is the normalized media packet to encode and send.
	Pkt wire.MediaPacket
}

// SendFeedback asks the host to transmit one control message on the given
// path. The host's profile strategy chooses the wire encoding (range NACK,
// bitmask NACK, RTT echo APP packet, ...); the core only speaks the
// normalized wire.Feedback types.
type SendFeedback struct {
	// Path is the network path index the feedback must leave on.
	Path uint8
	// FB is the normalized feedback to encode and send.
	FB wire.Feedback
}

// SetTimer asks the host to arm (or re-arm) the timer ID so that
// Flow.HandleTimer(deadline, ID) is called once the deadline passes.
// Re-arming an already-armed ID replaces its previous deadline.
type SetTimer struct {
	// ID is the timer being armed.
	ID TimerID
	// Deadline is the absolute instant the timer must fire at.
	Deadline clock.Timestamp
}

// ClearTimer asks the host to cancel the timer ID if it is armed; clearing
// an unarmed ID is a no-op.
type ClearTimer struct {
	// ID is the timer being cancelled.
	ID TimerID
}

// Marker-method implementations sealing the Output variant set.
func (SendMedia) isOutput()    {}
func (SendFeedback) isOutput() {}
func (SetTimer) isOutput()     {}
func (ClearTimer) isOutput()   {}

// Event is one application-visible occurrence produced by the core, drained
// in FIFO order via Flow.PollEvent.
//
// Event is sealed (unexported marker method) just like Output; hosts should
// treat an unrecognized variant in a type switch as a programming error.
type Event interface {
	// isEvent is the sealing marker; only this package can add variants.
	isEvent()
}

// Deliver hands one in-order media payload to the application. Payload is
// the same backing array the producer passed into Feed (the core retains
// references, it never copies); after delivery the core drops its reference
// and the consumer owns the bytes.
type Deliver struct {
	// Seq is the 32-bit (widened) sequence number of the delivered packet.
	Seq uint32
	// Payload is the delivered media payload.
	Payload []byte
	// Discontinuity reports that one or more sequence numbers immediately
	// before this packet were abandoned (never recovered before their
	// playout deadline), so the output stream has a gap here. The same
	// information is aggregated in Stats.Discontinuities.
	Discontinuity bool
}

// isEvent seals Deliver into the Event variant set.
func (Deliver) isEvent() {}

// Stats is a snapshot of the flow's counters, returned by value from
// Flow.Stats. Counter semantics mirror libRIST's receiver flow stats where
// an analog exists (stats_instant fields).
type Stats struct {
	// Received counts media packets accepted into the receiver ring
	// (first copies and accepted retransmissions; duplicates and too-late
	// drops are excluded).
	Received uint64

	// Duplicates counts media packets dropped by the (seq, sourceTime)
	// duplicate test — ARQ duplicates and extra SMPTE 2022-7 path copies
	// alike (libRIST stats_instant.dupe).
	Duplicates uint64

	// Reordered counts accepted packets that arrived out of order
	// (libRIST stats_instant.reordered).
	Reordered uint64

	// RetransmittedReceived counts inbound media packets flagged as
	// retransmits (the codec un-toggled the SSRC LSB and set MediaPacket.
	// Retransmit), tallied once per arriving retransmit-flagged packet before
	// the too-late / dedup / cursor tests — so it includes retransmits that
	// are subsequently shed as too-late or dropped as duplicates. It is
	// distinct from Recovered: Recovered counts gaps filled by ARQ (missing
	// entries removed after a NACK), whereas this counts retransmit copies
	// actually received on the wire (libRIST stats_instant.retransmitted vs
	// recovered).
	RetransmittedReceived uint64

	// Overwritten counts ring slots that held a stale entry — same slot,
	// different (seq, sourceTime) — and were overwritten by a newer packet
	// (libRIST's "Invalid Dupe" path).
	Overwritten uint64

	// TooLate counts media packets dropped because they could no longer be
	// delivered: either older than the recovery window per libRIST's
	// now > packetTime + recoveryBuffer*1.1 rule, or already behind the
	// in-order playout cursor. It includes both original and retransmitted
	// packets; TooLateRetransmit isolates the retransmitted subset.
	TooLate uint64

	// TooLateRetransmit counts the subset of TooLate drops that were
	// retransmit-flagged packets (a NACK answered after the deadline). The
	// source-adaptation Link Quality Message "Late" field reports original
	// packets only (TR-06-4 Part 1 §5.1 excludes retransmits received late), so
	// it is computed as TooLate - TooLateRetransmit.
	TooLateRetransmit uint64

	// Missing counts missing entries created by gap detection (each lost
	// sequence number once per detection).
	Missing uint64

	// NacksSent counts individual sequence numbers emitted in NackRequest
	// feedback (retries included; libRIST stats_instant.retries).
	NacksSent uint64

	// Recovered counts missing entries removed because the packet arrived
	// after at least one NACK was sent (libRIST stats_instant.recovered).
	Recovered uint64

	// Abandoned counts missing entries given up on, either after
	// MaxRetries NACKs or after ageing past recoveryBuffer*1.1.
	Abandoned uint64

	// Delivered counts packets handed to the application via Deliver.
	Delivered uint64

	// Lost counts sequence numbers skipped at playout because they never
	// arrived before delivery had to advance (libRIST stats_instant.lost).
	Lost uint64

	// Discontinuities counts contiguous runs of skipped sequence numbers
	// in the delivered stream (one per gap, regardless of its width).
	Discontinuities uint64

	// IgnoredFeedback counts inbound wire.Feedback values the flow had no
	// handler for in its current role/stage (for example a SenderReport
	// before WP4 wires SR-based offset refinement). Counted instead of
	// panicking so additively-introduced wire variants can never crash
	// the core.
	IgnoredFeedback uint64

	// ClockResync counts source-clock re-anchors: a fresh non-retransmit packet
	// whose source time fell backward by more than half the 32-bit timestamp
	// space (a true 32-bit RTP-timestamp wrap, ~13h at 90 kHz), gated by a dwell
	// guard, so the locked offset was bumped by one wrap period to keep playout
	// from stalling (libRIST receiver_calculate_packet_time wrap fix-up). An
	// anomalous-but-not-wrapped or merely-late timestamp does not count here.
	ClockResync uint64

	// --- Sender-half counters ---

	// Sent counts first-transmission media packets emitted by PushApp.
	Sent uint64

	// Retransmitted counts retransmission media packets emitted in response
	// to NackRequest feedback (each accepted sequence once per re-send).
	Retransmitted uint64

	// RetransmitSkipped counts NACKed sequence numbers no longer in the
	// sender history — aged out of the ring or never sent — and therefore
	// not resendable (libRIST stats_sender_instant.retrans_skip).
	RetransmitSkipped uint64

	// RetransmitSuppressed counts NACKed sequence numbers dropped by the
	// per-packet retransmit gate because the previous retransmit was less
	// than one clamped RTT ago (libRIST bloat_skip).
	RetransmitSuppressed uint64

	// RetransmitExhausted counts NACKed sequence numbers refused because the
	// packet had already been retransmitted MaxRetries times.
	RetransmitExhausted uint64

	// BandwidthSkipped counts retransmissions refused by the recovery_maxbitrate
	// pacing gate (libRIST stats_sender_instant.bandwidth_skip). The entry is
	// left resendable, so the receiver re-NACKs it once the rate decays.
	BandwidthSkipped uint64
}

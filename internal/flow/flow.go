// Package flow is the deterministic, sans-I/O core of a RIST flow: ARQ,
// reorder, dedup, RTT/NACK cadence, playout scheduling, and the SMPTE 2022-7
// multipath merge, for every profile.
//
// # Determinism contract
//
// The core never reads a clock, opens a socket, or spawns a goroutine. Time
// enters exclusively as explicit `now clock.Timestamp` arguments on the
// entry points (Feed, FeedFeedback, PushApp, HandleTimer, Tick), and side
// effects leave exclusively as returned values drained from PollOutput
// (SendMedia/SendFeedback/SetTimer/ClearTimer) and PollEvent (Deliver).
// Timers are declarative: the core requests deadlines via SetTimer effects
// and the host calls HandleTimer back when they pass. A CI gate
// (`make check-flow-imports`) asserts the package depends only on
// internal/{seq,clock,rtt,wire} plus the standard library.
//
// # The one ring (the 2022-7 merge)
//
// Every inbound media packet — first transmission, ARQ retransmit, or a
// duplicate copy from another 2022-7 path — lands in one power-of-two ring
// indexed by seq&mask and validated by (seq, sourceTime), exactly as libRIST
// does in receiver_enqueue. A filled slot with
// the same (seq, sourceTime) is a duplicate and is dropped; that single test
// is the entire multipath merge. A filled slot with a different
// (seq, sourceTime) is stale and is overwritten.
//
// # Payload ownership
//
// The core never copies payloads. Feed retains pkt.Payload by reference in
// the ring until the packet is delivered (the reference moves into the
// Deliver event and the consumer owns it) or its slot is overwritten or
// abandoned (the reference is dropped). Producers must not mutate a payload
// after Feed.
//
// # Roles
//
// One Flow plays a single Role. A RoleReceiver ingests media via Feed and
// runs the ring/dedup/missing-detect/playout machinery; a RoleSender accepts
// application payloads via PushApp, keeps a retransmit history, and services
// NackRequest feedback through the per-packet retransmit gate. Both originate
// and answer RTT echoes to maintain their own RTT estimate. The host pairs one
// of each (or, with bonding, N paths onto one receiver) to form a flow.
package flow

import (
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/rtt"
	"github.com/zsiec/ristgo/internal/wire"
)

// Role selects which half of a RIST flow this state machine plays.
type Role int

const (
	// RoleSender is the media-originating half: it accepts application
	// payloads via PushApp and services NackRequest feedback from its
	// retransmit history.
	RoleSender Role = iota

	// RoleReceiver is the media-consuming half: it accepts media via Feed,
	// detects and NACKs missing packets, and delivers in order on the
	// playout schedule.
	RoleReceiver
)

// DefaultRingSize is the FLOOR for the ring capacity in slots when no explicit
// RingSize is configured. libRIST allocates its sender_queue/receiver_queue as a
// flat UINT16_SIZE*8 (2^19) pointer array; ristgo instead derives the size from
// the recovery window and bitrate (deriveRingSize) so memory is proportional to
// need — ristgo's ring slots inline the per-packet metadata (~72 bytes) rather
// than holding a pointer, so a flat 2^19 would be ~37 MB per flow. 2^16 is the
// floor (it comfortably covers the 100 Mbps / 1000 ms default at ~9000 packets);
// high-bitrate or large-window configs round up above it.
const DefaultRingSize = 1 << 16

// maxDerivedRingSize caps the derived ring at 2^21 slots (~150 MB at 72 B/slot)
// so a pathological window×bitrate configuration cannot request unbounded
// memory. Beyond this the caller should set RingSize explicitly.
const maxDerivedRingSize = 1 << 21

// ringPacketBytes is the assumed on-wire packet size used when deriving the ring
// floor from the recovery window and bitrate. It is deliberately on the small
// side of a typical 1316-byte MPEG-TS RIST packet so the derived ring oversizes
// rather than undersizes.
const ringPacketBytes = 1100

// deriveRingSize returns the ring floor that holds a full recovery window's
// worth of in-flight packets at the configured max bitrate: the sender retains
// history for recovery_length_max + 2*rtt_min (libRIST sender_recover_min_time),
// the receiver for the recovery buffer; the larger governs. It is a pure
// function of Config (no clock read) and is floored at DefaultRingSize and
// capped at maxDerivedRingSize. nextPow2 rounding is applied by the caller.
func deriveRingSize(cfg Config) int {
	windowUs := cfg.RecoveryBufferMax + 2*cfg.RTTMin
	if rb := cfg.RecoveryBuffer(); rb > windowUs {
		windowUs = rb
	}
	kbps := cfg.RecoveryMaxBitrate
	if kbps <= 0 {
		kbps = 100000
	}
	// packets = windowSeconds * bits_per_second / (8 * packetBytes)
	//         = (windowUs/1e6) * (kbps*1000) / (8 * ringPacketBytes)
	//         = windowUs * kbps / (8000 * ringPacketBytes)
	packets := int64(windowUs) * int64(kbps) / (8000 * ringPacketBytes)
	if packets < DefaultRingSize {
		return DefaultRingSize
	}
	if packets > maxDerivedRingSize {
		return maxDerivedRingSize
	}
	return int(packets)
}

// Receiver pacing constants from libRIST.
const (
	// nackCadence bounds how long NACK processing may lag: libRIST's
	// receiver loop wakes at least every RIST_MAX_JITTER = 5 ms.
	nackCadence = 5 * clock.Millisecond

	// rttEchoInterval spaces RTT echo requests: RIST_PING_INTERVAL = 100 ms.
	rttEchoInterval = 100 * clock.Millisecond
)

// Config carries the recovery, reorder, RTT, and retry parameters of one
// flow. It is a plain data struct: the caller (the public Config layer)
// validates ranges before constructing a Flow; this package only normalizes
// values it cannot operate without (see New).
type Config struct {
	// RecoveryBufferMin is libRIST's recovery_length_min: the lower bound
	// of the recovery (playout) buffer window.
	RecoveryBufferMin clock.Microseconds

	// RecoveryBufferMax is libRIST's recovery_length_max; must be >=
	// RecoveryBufferMin.
	RecoveryBufferMax clock.Microseconds

	// ReorderBuffer is libRIST's recovery_reorder_buffer. The receiver folds it
	// into the first-NACK delay (max(clamp(rtt)/2, reorder_buffer) — see
	// addMissing), so a merely-reordered packet is not NACKed before its
	// in-order copy can arrive within the reorder window.
	ReorderBuffer clock.Microseconds

	// RTTMin and RTTMax clamp the smoothed RTT whenever it is read for
	// NACK retry spacing (libRIST recovery_rtt_min/recovery_rtt_max).
	RTTMin clock.Microseconds
	RTTMax clock.Microseconds

	// RTTMultiplier is libRIST's recovery_rtt_multiplier (default 7): the factor
	// by which the receiver scales its smoothed RTT when dynamically auto-sizing
	// the recovery (playout) buffer. It is consumed only when the buffer is
	// windowed (RecoveryBufferMin != RecoveryBufferMax) and the peer has
	// advertised a sender max via buffer negotiation; otherwise the buffer is the
	// static midpoint and this value is unused. See Flow.autoScaleBuffer
	// (libRIST _librist_receiver_buffer_calc). 0 disables auto-scaling.
	RTTMultiplier int

	// MinRetries is libRIST's min_retries. It gates congestion-control
	// behavior on the sender side and is unused by the receiver half.
	MinRetries int

	// MaxRetries is libRIST's max_retries: a missing entry is abandoned
	// once it has been NACKed this many times.
	MaxRetries int

	// RecoveryMaxBitrate is libRIST's recovery_maxbitrate in kbps (default
	// 100000 = 100 Mbps). It sizes the ring floor (a window's worth of packets
	// must fit) and drives the sender congestion-control pacing. 0 defaults to
	// 100000.
	RecoveryMaxBitrate int

	// CongestionControl selects the sender's recovery_maxbitrate pacing mode
	// (libRIST congestion_control). The zero value is CongestionOff; the libRIST
	// default is CongestionNormal, set by DefaultConfig and the host.
	CongestionControl CongestionMode

	// ReturnMaxBitrate is libRIST's return-bandwidth in kbps: a cap on the
	// receiver's outbound NACK channel so its retransmission requests stay within
	// an upstream budget on an asymmetric link. 0 (the default) means unlimited.
	// Receiver-side only. NOTE: libRIST v0.2.18 stores but does not enforce this
	// value; ristgo enforces it as an interop-safe enhancement (a sender simply
	// receives fewer NACKs, which is never a protocol violation).
	ReturnMaxBitrate int

	// RingSize is the ring capacity in slots — the receiver history ring and
	// the sender retransmit-history ring alike. Values <= 0 default to a size
	// derived from the recovery window and RecoveryMaxBitrate (so a window's
	// worth of in-flight packets always fits); other values are rounded up to a
	// power of two so seq&mask indexing works.
	RingSize int

	// SSRC is the base flow SSRC the sender half stamps into every outgoing
	// MediaPacket. It must be even — the codec reserves the LSB as the
	// retransmit marker (librist, flow_id &= ~1UL) — but the
	// core does not enforce that; the public Config layer validates it.
	// Sender-only; the receiver learns the SSRC from the first packet.
	SSRC uint32

	// StartSeq is the 32-bit sequence the sender assigns to its first
	// PushApp packet, incrementing by one thereafter. Sender-only; the
	// receiver anchors on whatever sequence first arrives.
	StartSeq uint32

	// TimingMode selects how the receiver schedules playout (libRIST
	// timing_mode). The zero value is TimingSource, the libRIST default.
	// Receiver-only.
	TimingMode TimingMode

	// NoRecovery disables ARQ recovery for one-way / no-return-channel
	// transport. The sender retains no retransmit history and arms no RTT-echo
	// cadence; the receiver queues no missing entries (emits no NACKs) and arms
	// no RTT-echo cadence. The receiver still reorders within the buffer and
	// delivers in order — unrecoverable gaps are reclaimed by playout-skip, not
	// ARQ — so a stream with no return channel still plays out continuously,
	// just without recovery. The zero value keeps full recovery.
	NoRecovery bool
}

// TimingMode selects the receiver playout-scheduling clock.
type TimingMode uint8

const (
	// TimingSource paces playout by the media SOURCE timestamps (libRIST
	// timing_mode SOURCE): a packet's playout deadline is its source time mapped
	// into the local clock plus the recovery buffer, so inter-packet spacing
	// follows the source clock. This is the default and the zero value.
	TimingSource TimingMode = iota

	// TimingArrival paces playout by ARRIVAL time (libRIST timing_mode ARRIVAL):
	// each packet's playout deadline is its own arrival instant plus the recovery
	// buffer, ignoring the source timestamps for pacing (they are still used for
	// the (Seq, SourceTime) dedup / 2022-7 merge). This is robust to a drifting or
	// absent source clock at the cost of not preserving source inter-packet
	// timing.
	TimingArrival
)

// DefaultConfig returns the libRIST defaults:
// recovery_length_min/max = 1000 ms, reorder_buffer = 15 ms, rtt_min = 5 ms,
// rtt_max = 500 ms, min_retries = 6, max_retries = 20, and the 2^16 ring.
func DefaultConfig() Config {
	return Config{
		RecoveryBufferMin:  1000 * clock.Millisecond,
		RecoveryBufferMax:  1000 * clock.Millisecond,
		ReorderBuffer:      15 * clock.Millisecond,
		RTTMin:             5 * clock.Millisecond,
		RTTMax:             500 * clock.Millisecond,
		RTTMultiplier:      7,
		MinRetries:         6,
		MaxRetries:         20,
		RecoveryMaxBitrate: 100000,
		CongestionControl:  CongestionNormal,
		RingSize:           DefaultRingSize,
	}
}

// RecoveryBuffer returns the derived recovery (playout) buffer duration:
// (RecoveryBufferMax-RecoveryBufferMin)/2 + RecoveryBufferMin, exactly as
// libRIST computes recovery_buffer_ticks in init_peer_settings. With the
// default 1000/1000 ms window this is 1000 ms.
func (c Config) RecoveryBuffer() clock.Microseconds {
	return (c.RecoveryBufferMax-c.RecoveryBufferMin)/2 + c.RecoveryBufferMin
}

// mul110 multiplies a microsecond duration by 1.1 with the same float64
// multiply-then-truncate libRIST uses for its too-late / NACK-abandon threshold
// (recovery_buffer_ticks * 1.1). Shared by New and autoScaleBuffer so the static
// and dynamically-resized recovery buffers compute the threshold identically.
func mul110(d clock.Microseconds) clock.Microseconds {
	return clock.Microseconds(float64(d) * 1.1)
}

// Flow is the deterministic state machine for one RIST flow (one role).
// It is not safe for concurrent use; the host serializes all calls.
type Flow struct {
	role Role
	cfg  Config

	// recoveryBuffer is the derived playout budget (RecoveryBuffer()).
	recoveryBuffer clock.Microseconds
	// recoveryBuffer110 is recoveryBuffer*1.1 computed with the same
	// double multiply-and-truncate libRIST uses for its too-late and
	// NACK-abandon thresholds.
	recoveryBuffer110 clock.Microseconds

	// missingCounterMax bounds how many missing entries the receiver queues
	// before it stops marking new gaps (libRIST's buffer-bloat / overflow
	// guard); maxNacksPerLoop caps the retransmissions the sender emits per
	// service pass. Both are pure functions of Config, computed in New.
	missingCounterMax uint32
	maxNacksPerLoop   int

	// est is the libRIST eight_times_rtt estimator. One per flow this
	// stage; per-path attribution lands with bonding (WP8), when feedback
	// carries a path.
	est rtt.Estimator

	outputs fifo[Output]
	events  fifo[Event]

	stats Stats

	receiver receiverState
	sender   senderState
}

// New constructs a Flow for the given role. cfg is taken as-is except for
// normalization the core cannot operate without: RingSize <= 0 becomes
// DefaultRingSize and other sizes round up to the next power of two. Range
// validation is the caller's job (top-level Config.validate); no input to
// New can panic.
//
// The receiver ring is fully pre-allocated here so Feed performs no
// allocation in steady state.
func New(role Role, cfg Config) *Flow {
	f := &Flow{
		role:           role,
		cfg:            cfg,
		recoveryBuffer: cfg.RecoveryBuffer(),
		est:            rtt.New(cfg.RTTMin),
	}
	f.recoveryBuffer110 = mul110(f.recoveryBuffer)
	f.missingCounterMax = deriveMissingCounterMax(cfg)
	f.maxNacksPerLoop = deriveMaxNacksPerLoop(cfg)
	size := cfg.RingSize
	if size <= 0 {
		size = deriveRingSize(cfg)
	}
	size = nextPow2(size)
	switch role {
	case RoleReceiver:
		f.receiver.ring = make([]slot, size)
		f.receiver.mask = uint32(size - 1)
		if cfg.ReturnMaxBitrate > 0 {
			// return-channel bytes/sec divided by bytes-per-NACK-seq = the NACK
			// sequence rate; burst up to one full per-pass NACK group.
			f.receiver.nackSeqsPerSec = float64(cfg.ReturnMaxBitrate) * 1000 / 8 / ristNackBytesPerSeq
			f.receiver.nackTokenBurst = float64(ristMaxNacks)
			f.receiver.nackTokens = f.receiver.nackTokenBurst
		}
	case RoleSender:
		f.sender.ring = make([]senderSlot, size)
		f.sender.mask = uint32(size - 1)
		f.sender.ssrc = cfg.SSRC
		f.sender.nextSeq = cfg.StartSeq
	}
	return f
}

// Role returns which half of the flow this state machine plays.
func (f *Flow) Role() Role { return f.role }

// Stats returns a snapshot of the flow's counters.
func (f *Flow) Stats() Stats { return f.stats }

// Feed ingests one inbound media packet that arrived on the given path at
// instant now. Receiver-role only: it performs the dedup/overwrite/insert
// ring discipline, missing-packet detection, and playout/NACK timer
// scheduling. On a sender-role Flow, media input does not exist and Feed is
// a no-op (the sender half consumes NackRequest feedback and PushApp
// payloads instead).
//
// Feed retains pkt.Payload by reference (see the package ownership note)
// and allocates nothing in steady state for in-order packets.
func (f *Flow) Feed(now clock.Timestamp, path uint8, pkt wire.MediaPacket) {
	if f.role != RoleReceiver {
		return
	}
	f.feed(now, path, pkt)
}

// FeedFeedback ingests one inbound control message at instant now.
//
// Both roles answer an RttEchoRequest immediately (ProcessingDelay 0, since
// the deterministic core responds within the same step) and fold an
// RttEchoResponse round trip into the RTT estimator — the receiver uses its
// RTT for NACK retry spacing, the sender for the retransmit gate.
//
// A NackRequest is serviced from the retransmit history on a sender-role
// Flow and ignored on a receiver-role one. SenderReport handling (playout
// offset refinement) is deferred to WP4, and any variant without a handler is
// counted in Stats.IgnoredFeedback rather than crashing — additive
// wire.Feedback variants must never break the core.
//
// SSRC/flow-id demultiplexing is the host's job (PLAN.md: internal/socket
// demuxes by addr/flow-id; cf. libRIST's per-peer SSRC guard). Feedback
// handed here is trusted to belong to this flow: the RTT estimator update and
// serviceNack apply no additive SSRC check. The echo SSRC that does cross the
// waist (wire.RttEchoRequest/Response.SSRC) is not a demux key — it is the
// requester's SSRC, carried only so the responder can echo it back to satisfy
// the peer's response filter.
func (f *Flow) FeedFeedback(now clock.Timestamp, fb wire.Feedback) {
	switch fb := fb.(type) {
	case wire.RttEchoRequest:
		// Echo the requester's SSRC (and timestamp) back: a libRIST requester
		// drops any response whose SSRC differs from its own, so the response
		// must carry the request's SSRC, not the responder's flow id.
		f.outputs.push(SendFeedback{
			Path: f.feedbackPath(),
			FB:   wire.RttEchoResponse{SSRC: fb.SSRC, Timestamp: fb.Timestamp, ProcessingDelay: 0},
		})
	case wire.RttEchoResponse:
		// sample = (now - echoed timestamp) - processing delay. libRIST's
		// calculate_rtt_delay floors a would-be-negative sample at 0;
		// rtt.Estimator.Observe applies the same pin.
		sent := clock.NTPTime(fb.Timestamp).Timestamp()
		sample := now.Sub(sent) - clock.Microseconds(fb.ProcessingDelay)
		f.est = f.est.Observe(sample)
	case wire.NackRequest:
		if f.role == RoleSender {
			f.serviceNack(now, fb)
		} else {
			// A receiver does not originate retransmissions.
			f.stats.IgnoredFeedback++
		}
	default:
		// SenderReport (WP4 offset refinement), Keepalive (host liveness),
		// and any future additive variant.
		f.stats.IgnoredFeedback++
	}
}

// feedbackPath returns the path control messages leave on: the sender's fixed
// transmit path, or the receiver's most-recent media path (feedback follows
// the media back to its source).
func (f *Flow) feedbackPath() uint8 {
	if f.role == RoleSender {
		return f.sender.txPath
	}
	return f.receiver.lastPath
}

// PushApp accepts one application payload for transmission. Sender-role only:
// it assigns the next sequence number, stores the packet in the retransmit
// history, and emits the first-transmission SendMedia effect. On a
// receiver-role Flow it is a no-op (the receiver consumes media via Feed).
//
// PushApp retains payload by reference (see the package ownership note) so it
// can be re-sent on NACK; the producer must not mutate it afterward.
func (f *Flow) PushApp(now clock.Timestamp, payload []byte) {
	f.PushAppFrag(now, payload, wire.FragStandalone)
}

// PushAppFrag is PushApp for one fragment of a payload the host has split
// across consecutive sequences (Advanced profile): frag tags this piece's role
// (FragFirst/FragMiddle/FragLast), which the core carries through onto the
// outgoing MediaPacket and re-sends unchanged on retransmission, but never
// interprets. wire.FragStandalone is a whole, unfragmented payload — the case
// PushApp delegates here.
func (f *Flow) PushAppFrag(now clock.Timestamp, payload []byte, frag wire.FragRole) {
	if f.role != RoleSender {
		return
	}
	f.pushApp(now, payload, frag)
}

// HandleTimer must be called by the host when a deadline previously
// requested via a SetTimer effect passes; now is the (fake or real) instant
// the timer fired. Unknown or no-longer-relevant IDs are ignored.
func (f *Flow) HandleTimer(now clock.Timestamp, id TimerID) {
	if f.role == RoleSender {
		f.senderHandleTimer(now, id)
		return
	}
	switch id {
	case TimerPlayout:
		f.receiver.playoutArmed = false
		f.deliverDue(now)
	case TimerNack:
		f.receiver.nackArmed = false
		f.processNacks(now)
		f.scheduleNack(now)
	case TimerRttEcho:
		if f.receiver.started {
			f.outputs.push(SendFeedback{
				Path: f.receiver.lastPath,
				FB:   wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(now))},
			})
			f.outputs.push(SetTimer{ID: TimerRttEcho, Deadline: now.Add(rttEchoInterval)})
			// Re-size the recovery buffer on this guaranteed ~100 ms receiver heartbeat
			// (libRIST recomputes its buffer on a periodic timer, not on echo receipt),
			// so it keeps adapting to loss even if echo responses stop arriving. A no-op
			// unless the buffer is windowed and a sender max has been negotiated.
			f.autoScaleBuffer()
		}
	default:
		// A timer ID this stage did not arm (e.g. a stale or future
		// sender-half ID): nothing to do.
	}
}

// Tick gives the core an opportunity to perform any due time-driven work at
// instant now without a specific timer firing: in-order playout delivery
// and a NACK processing pass. Hosts that faithfully honor SetTimer effects
// do not need to call Tick, but it must always be safe to.
func (f *Flow) Tick(now clock.Timestamp) {
	if f.role != RoleReceiver {
		return
	}
	f.deliverDue(now)
	f.processNacks(now)
}

// PollOutput removes and returns the next pending side effect. ok is false
// when no effects are pending. The host must drain outputs after every
// entry-point call.
func (f *Flow) PollOutput() (out Output, ok bool) {
	return f.outputs.pop()
}

// PollEvent removes and returns the next pending application event. ok is
// false when no events are pending.
func (f *Flow) PollEvent() (ev Event, ok bool) {
	return f.events.pop()
}

// nextPow2 rounds n up to the next power of two (n must be > 0).
func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// fifo is a slice-backed FIFO that reuses its backing array once drained,
// so a drain-after-every-call host reaches a steady state with no
// per-element allocation beyond the boxed values themselves.
type fifo[T any] struct {
	items []T
	head  int
}

// push appends v to the queue.
func (q *fifo[T]) push(v T) {
	q.items = append(q.items, v)
}

// pop removes and returns the oldest element; ok is false when empty.
// Popped slots are zeroed so the queue drops references promptly.
func (q *fifo[T]) pop() (v T, ok bool) {
	var zero T
	if q.head >= len(q.items) {
		return zero, false
	}
	v = q.items[q.head]
	q.items[q.head] = zero
	q.head++
	if q.head == len(q.items) {
		q.items = q.items[:0]
		q.head = 0
	}
	return v, true
}

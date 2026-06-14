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

// DefaultRingSize is the default receiver ring capacity in slots, matching
// libRIST's receiver_queue_max of 2^16 entries (UINT16_SIZE).
const DefaultRingSize = 1 << 16

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

	// ReorderBuffer is libRIST's recovery_reorder_buffer. The receiver
	// half does not consume it directly this stage (libRIST folds it into
	// the rtt value used for the first NACK — see the DEVIATION note at
	// addMissing); it is carried here so the sender half and later stages
	// share one Config.
	ReorderBuffer clock.Microseconds

	// RTTMin and RTTMax clamp the smoothed RTT whenever it is read for
	// NACK retry spacing (libRIST recovery_rtt_min/recovery_rtt_max).
	RTTMin clock.Microseconds
	RTTMax clock.Microseconds

	// MinRetries is libRIST's min_retries. It gates congestion-control
	// behavior on the sender side and is unused by the receiver half.
	MinRetries int

	// MaxRetries is libRIST's max_retries: a missing entry is abandoned
	// once it has been NACKed this many times.
	MaxRetries int

	// RingSize is the ring capacity in slots — the receiver history ring and
	// the sender retransmit-history ring alike. Values <= 0 default to
	// DefaultRingSize; other values are rounded up to a power of two so
	// seq&mask indexing works.
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
}

// DefaultConfig returns the libRIST defaults:
// recovery_length_min/max = 1000 ms, reorder_buffer = 15 ms, rtt_min = 5 ms,
// rtt_max = 500 ms, min_retries = 6, max_retries = 20, and the 2^16 ring.
func DefaultConfig() Config {
	return Config{
		RecoveryBufferMin: 1000 * clock.Millisecond,
		RecoveryBufferMax: 1000 * clock.Millisecond,
		ReorderBuffer:     15 * clock.Millisecond,
		RTTMin:            5 * clock.Millisecond,
		RTTMax:            500 * clock.Millisecond,
		MinRetries:        6,
		MaxRetries:        20,
		RingSize:          DefaultRingSize,
	}
}

// RecoveryBuffer returns the derived recovery (playout) buffer duration:
// (RecoveryBufferMax-RecoveryBufferMin)/2 + RecoveryBufferMin, exactly as
// libRIST computes recovery_buffer_ticks in init_peer_settings. With the
// default 1000/1000 ms window this is 1000 ms.
func (c Config) RecoveryBuffer() clock.Microseconds {
	return (c.RecoveryBufferMax-c.RecoveryBufferMin)/2 + c.RecoveryBufferMin
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
	// Same arithmetic as libRIST's (recovery_buffer_ticks * 1.1) double
	// multiply with truncation.
	f.recoveryBuffer110 = clock.Microseconds(float64(f.recoveryBuffer) * 1.1)
	size := cfg.RingSize
	if size <= 0 {
		size = DefaultRingSize
	}
	size = nextPow2(size)
	switch role {
	case RoleReceiver:
		f.receiver.ring = make([]slot, size)
		f.receiver.mask = uint32(size - 1)
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
// serviceNack apply no additive SSRC check, and wire.RttEchoResponse
// intentionally carries no SSRC field.
func (f *Flow) FeedFeedback(now clock.Timestamp, fb wire.Feedback) {
	switch fb := fb.(type) {
	case wire.RttEchoRequest:
		f.outputs.push(SendFeedback{
			Path: f.feedbackPath(),
			FB:   wire.RttEchoResponse{Timestamp: fb.Timestamp, ProcessingDelay: 0},
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
	if f.role != RoleSender {
		return
	}
	f.pushApp(now, payload)
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

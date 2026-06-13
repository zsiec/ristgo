package simtest

import (
	"sort"

	"github.com/zsiec/ristgo/internal/clock"
)

// LinkConfig holds the network impairment parameters for a single
// direction of a simulated link.
type LinkConfig struct {
	// Delay is the base one-way propagation delay applied to every
	// datagram. Negative values are treated as zero-cost delay (the sum
	// with jitter still moves the deliver-at instant backward only if the
	// caller asks for it; tests should use non-negative delays).
	Delay clock.Microseconds

	// Jitter is the upper bound of extra delay drawn uniformly from
	// [0, Jitter] per datagram; nonzero jitter can reorder datagrams
	// relative to send order. Values <= 0 disable the jitter draw
	// entirely, so the RNG stream is identical to a jitter-free link.
	Jitter clock.Microseconds

	// Loss is the independent drop probability per datagram, in [0, 1].
	// Values <= 0 disable the loss roll entirely (no RNG draw is
	// consumed), so loss patterns stay stable as other knobs change;
	// values >= 1 drop everything.
	Loss float64

	// DupProb is the independent duplication probability per datagram,
	// in [0, 1]: with probability DupProb a surviving datagram is
	// scheduled twice, each copy with its own jitter draw. Values <= 0
	// disable the duplication roll entirely (no RNG draw is consumed).
	// This extends the srtrust source, which has no duplication knob;
	// it models the duplicate-delivery impairment SMPTE 2022-7 merge
	// logic must absorb.
	DupProb float64
}

// PerfectLink returns a 10 ms link with no loss, no jitter, and no
// duplication: in-order, lossless delivery (srtrust's LinkConfig::PERFECT).
func PerfectLink() LinkConfig {
	return LinkConfig{Delay: 10 * clock.Millisecond}
}

// pendingDatagram is one scheduled delivery. seq is a monotonically
// increasing insertion index used as a stable tiebreaker so equal delivery
// times keep insertion order deterministically.
type pendingDatagram[T any] struct {
	deliverAt clock.Timestamp
	seq       uint64
	payload   T
}

// Link is one directional simulated link carrying datagrams of type T:
// datagrams enter at a send time, are dropped or scheduled for delivery on
// the fake clock (possibly duplicated), and drain out in delivery order. All
// randomness comes from an internal seeded Rng, so a Link's behavior is
// exactly reproducible from (config, seed, input sequence).
//
// T is the payload type. The standalone Link unit tests use Link[[]byte]; the
// N-path Fabric instantiates Link with a wire-level datagram type so the
// simulator routes the flow core's normalized wire.MediaPacket/wire.Feedback
// values without an intervening codec.
//
// Payloads are held by value (copied into the pending queue); a duplicated
// datagram therefore shares whatever the value references (for a slice or
// pointer payload, the backing data), so callers must not mutate data a
// payload references after Send.
type Link[T any] struct {
	cfg     LinkConfig
	rng     Rng
	pending []pendingDatagram[T]
	nextSeq uint64

	dropped   uint64
	delivered uint64

	// dropFilter is an optional deterministic drop predicate, consulted
	// before the probabilistic loss roll; true drops the datagram. It
	// lets a test target a specific packet ("the first transmission of
	// seq N") instead of hunting for a seed.
	dropFilter func(payload T) bool
}

// NewLink creates a link with the given impairments, its PRNG seeded by
// seed. The payload type must be supplied explicitly, e.g.
// NewLink[[]byte](cfg, seed).
func NewLink[T any](cfg LinkConfig, seed uint64) *Link[T] {
	return &Link[T]{cfg: cfg, rng: Rng{s: seed}}
}

// SetDropFilter installs a deterministic per-datagram drop predicate
// (true = drop), consulted before the probabilistic loss roll so targeted
// drops are independent of the seeded RNG stream. A filter drop consumes
// no RNG draw. Passing nil removes the filter.
func (l *Link[T]) SetDropFilter(filter func(payload T) bool) {
	l.dropFilter = filter
}

// Send offers a datagram to the link at fake-clock instant now. Its fate
// is decided in a fixed order so RNG consumption — and therefore every
// seeded pattern — is stable as unrelated knobs change:
//
//  1. drop filter (no RNG draw),
//  2. loss roll (only if Loss > 0),
//  3. duplication roll (only if DupProb > 0),
//  4. per-copy uniform jitter draw (only if Jitter > 0); each copy is
//     scheduled at now + Delay + jitter.
//
// In particular the loss roll is taken first, unconditionally for every
// surviving datagram, so a datagram's fate depends only on its position in
// the stream — not on whether jitter or duplication is enabled (the
// srtrust source's invariant, extended to the duplication knob).
func (l *Link[T]) Send(now clock.Timestamp, payload T) {
	if l.dropFilter != nil && l.dropFilter(payload) {
		l.dropped++
		return
	}
	if l.cfg.Loss > 0 && l.rng.Unit() < l.cfg.Loss {
		l.dropped++
		return
	}
	dup := l.cfg.DupProb > 0 && l.rng.Unit() < l.cfg.DupProb
	l.schedule(now, payload)
	if dup {
		l.schedule(now, payload)
	}
}

// schedule queues one delivery of payload at now + Delay + jitter, drawing
// the jitter for this copy if jitter is enabled.
func (l *Link[T]) schedule(now clock.Timestamp, payload T) {
	var extra clock.Microseconds
	if l.cfg.Jitter > 0 {
		extra = clock.Microseconds(l.rng.Below(uint64(l.cfg.Jitter) + 1))
	}
	delay := l.cfg.Delay
	if delay < 0 {
		delay = 0
	}
	l.pending = append(l.pending, pendingDatagram[T]{
		deliverAt: now.Add(delay + extra),
		seq:       l.nextSeq,
		payload:   payload,
	})
	l.nextSeq++
}

// NextDeadline returns the earliest pending delivery time. ok is false
// when nothing is in flight.
func (l *Link[T]) NextDeadline() (deadline clock.Timestamp, ok bool) {
	for i, p := range l.pending {
		if i == 0 || p.deliverAt.Before(deadline) {
			deadline = p.deliverAt
		}
	}
	return deadline, len(l.pending) > 0
}

// DrainDue removes and returns every datagram due at or before now, in
// delivery order: ascending delivery time, with the insertion index
// breaking ties so simultaneous deliveries keep send order
// deterministically.
func (l *Link[T]) DrainDue(now clock.Timestamp) []T {
	var due []pendingDatagram[T]
	keep := l.pending[:0]
	for _, p := range l.pending {
		if !p.deliverAt.After(now) {
			due = append(due, p)
		} else {
			keep = append(keep, p)
		}
	}
	l.pending = keep
	sort.Slice(due, func(i, j int) bool {
		if due[i].deliverAt != due[j].deliverAt {
			return due[i].deliverAt.Before(due[j].deliverAt)
		}
		return due[i].seq < due[j].seq
	})
	out := make([]T, len(due))
	for i, p := range due {
		out[i] = p.payload
	}
	l.delivered += uint64(len(out))
	return out
}

// Dropped reports how many datagrams this link has dropped so far, by
// either the drop filter or the loss roll.
func (l *Link[T]) Dropped() uint64 {
	return l.dropped
}

// Delivered reports how many datagrams this link has handed out via
// DrainDue so far; a duplicated datagram counts once per delivered copy.
func (l *Link[T]) Delivered() uint64 {
	return l.delivered
}

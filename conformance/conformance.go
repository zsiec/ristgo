// Package conformance is ristgo's public Sans-I/O, bit-deterministic RIST
// Tier-1 conformance harness.
//
// It drives the REAL RIST flow core — a sender flow and a receiver flow — over a
// virtual clock and in-memory links, with no sockets, no wall clock, and no
// goroutines, applying a caller-supplied DETERMINISTIC drop schedule to the
// forward media. It reports the delivered sequence stream, ARQ recovery
// accounting, and the four RIST delivery invariants (no duplicate delivered, in
// order, nothing past the playout deadline, completeness under recoverable
// loss). Identical inputs produce a byte-identical Result on any machine — the
// property that makes this the white-box (Tier-1) counterpart to the black-box
// socket path: a conformance verdict you can golden-diff.
//
// It exposes ristgo's internal deterministic simulator (the same harness the
// flow core's own 1024-seed invariant sweep uses) through a small, stable API,
// so an external conformance runner (e.g. Impair/Transit-WPT) can drive the RIST
// core under an impairment pattern it decides — the seam that lets the impairment
// engine own the loss while the transport core owns the recovery.
package conformance

import (
	"encoding/binary"
	"time"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/simtest"
)

// senderSSRC is an even base SSRC (the codec reserves the LSB as the retransmit
// marker); the value is irrelevant to a single-flow conformance run.
const senderSSRC = 0x0ACE_0AC0

// Options configures a Simple-profile conformance run over one forward/back link
// pair. Zero values pick libRIST-aligned defaults.
type Options struct {
	Packets   int           // media packets to send (default 64; seqs StartSeq..+Packets-1)
	StartSeq  uint32        // first RTP sequence (default 0)
	Interval  time.Duration // source inter-packet spacing (default 1ms)
	FwdDelay  time.Duration // forward one-way base delay (default 10ms)
	BackDelay time.Duration // back-channel (NACK) base delay (default 10ms)
	MaxSteps  int           // simulator step budget (default 200000)

	// RequireContiguous asserts the delivered run has NO internal gaps — the
	// completeness invariant. Set it for a fully-recoverable drop schedule; leave
	// it false when the schedule injects unrecoverable loss (abandoned gaps are
	// then graceful degradation, and no-duplicate / in-order / deadline still hold).
	RequireContiguous bool
}

// DropFunc decides whether to drop a forward media datagram. seq is its RTP
// sequence number; firstTx is true for the original transmission and false for an
// ARQ retransmit — so a caller models a RECOVERABLE loss by dropping only the
// original (firstTx), letting the retransmit through, and an UNRECOVERABLE loss
// by dropping both. Returning false always delivers. It must be a pure function
// of its arguments (and any caller state advanced deterministically) for the run
// to stay bit-reproducible.
type DropFunc func(seq uint32, firstTx bool) bool

// Result is the deterministic outcome of Run.
type Result struct {
	Sent            int
	Delivered       int
	DeliveredSeqs   []uint32
	ForwardDropped  int      // forward media datagrams the drop schedule removed
	Recovered       uint64   // packets the receiver recovered via ARQ retransmit
	RecoveredOneRTT uint64   // subset of Recovered cleared on the first NACK
	Lost            uint64   // sequence numbers abandoned at playout (never recovered)
	Discontinuities uint64   // contiguous runs of skipped sequence numbers
	Invariants      []string // RIST invariant violations; empty == all four held
	Completed       bool     // reached `Packets` delivered before the step budget
}

// PayloadOf returns the 8-byte big-endian source index the harness stamps into
// the i-th media packet, so a caller can verify payload integrity against the
// delivered stream if it wishes.
func PayloadOf(i int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

func (o Options) withDefaults() Options {
	if o.Packets <= 0 {
		o.Packets = 64
	}
	if o.Interval <= 0 {
		o.Interval = time.Millisecond
	}
	if o.FwdDelay <= 0 {
		o.FwdDelay = 10 * time.Millisecond
	}
	if o.BackDelay <= 0 {
		o.BackDelay = 10 * time.Millisecond
	}
	if o.MaxSteps <= 0 {
		o.MaxSteps = 200_000
	}
	return o
}

func us(d time.Duration) clock.Microseconds { return clock.Microseconds(d.Microseconds()) }

// Run drives the conformance scenario to completion (or the step budget) and
// returns the deterministic Result. The back channel is lossless, so NACKs always
// reach the sender; all loss is on the forward media, applied by drop. A nil drop
// is a clean run.
func Run(opts Options, drop DropFunc) Result {
	o := opts.withDefaults()

	scfg := flow.DefaultConfig()
	scfg.SSRC = senderSSRC
	scfg.StartSeq = o.StartSeq
	sender := flow.New(flow.RoleSender, scfg)
	receiver := flow.New(flow.RoleReceiver, flow.DefaultConfig())

	fwd := simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: us(o.FwdDelay)}, 1)
	if drop != nil {
		fwd.SetDropFilter(func(d simtest.Datagram) bool {
			if !d.Media {
				return false // never drop control (NACKs/echoes) on the forward link
			}
			return drop(d.Pkt.Seq, !d.Pkt.Retransmit)
		})
	}
	back := simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: us(o.BackDelay)}, 2)

	fab := simtest.NewFabric(sender, receiver,
		[]*simtest.Link[simtest.Datagram]{fwd},
		[]*simtest.Link[simtest.Datagram]{back})

	at := clock.Timestamp(0)
	for i := 0; i < o.Packets; i++ {
		fab.EnqueueSource(at, PayloadOf(i))
		at = at.Add(us(o.Interval))
	}

	completed := fab.RunUntil(func(f *simtest.Fabric) bool {
		return len(f.DeliveredSeqs()) >= o.Packets
	}, o.MaxSteps)

	// A correctly delivered packet's latency is offset + recoveryBuffer; pin the
	// absolute playout deadline on top of the uniformity check.
	maxLat := flow.DefaultConfig().RecoveryBuffer() + us(o.FwdDelay)
	viol := fab.CheckInvariants(simtest.InvariantOpts{
		LatencyTolerance:  0,
		MaxLatency:        maxLat,
		RequireContiguous: o.RequireContiguous,
	})

	st := receiver.Stats()
	return Result{
		Sent:            o.Packets,
		Delivered:       len(fab.DeliveredSeqs()),
		DeliveredSeqs:   fab.DeliveredSeqs(),
		ForwardDropped:  int(fwd.Dropped()),
		Recovered:       st.Recovered,
		RecoveredOneRTT: st.RecoveredOneRetry,
		Lost:            st.Lost,
		Discontinuities: st.Discontinuities,
		Invariants:      viol,
		Completed:       completed,
	}
}

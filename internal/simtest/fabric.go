package simtest

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/seq"
	"github.com/zsiec/ristgo/internal/wire"
)

// Datagram is the unit a Fabric link carries: either a media packet (sender
// to receiver) or a control message (either direction). The flow core speaks
// these normalized wire types directly, so the simulator routes them without
// an intervening RTP/RTCP codec.
type Datagram struct {
	// Media distinguishes a wire.MediaPacket (true, use Pkt) from a
	// wire.Feedback (false, use FB).
	Media bool
	// Pkt is the media packet; valid only when Media is true.
	Pkt wire.MediaPacket
	// FB is the control message; valid only when Media is false.
	FB wire.Feedback
}

// sourceItem is one scheduled application send into the sender.
type sourceItem struct {
	at      clock.Timestamp
	payload []byte
}

// Fabric is the fake-clock, N-path network simulator that drives a sender
// flow and a receiver flow through impairment Links and declarative
// TimerWheels. Stepping jumps the mock clock to the next event across every
// link, both wheels, and the pending source schedule — there are no sleeps,
// no sockets, and no goroutines, so every run is exactly reproducible from
// the link seeds.
//
// Routing is by role: the sender's effects (first transmissions,
// retransmissions, and its RTT echoes) leave on the forward links; the
// receiver's effects (NACKs and its RTT echoes) leave on the back links. A
// path index selects which link within each direction. WP3 exercises a single
// path; the N-path shape is what bonding/SMPTE 2022-7 (WP8) builds on.
//
// A Fabric is single-goroutine and not safe for concurrent use.
type Fabric struct {
	sender *flow.Flow
	recvr  *flow.Flow

	fwd  []*Link[Datagram] // sender -> receiver, one per path
	back []*Link[Datagram] // receiver -> sender, one per path

	sTimers *TimerWheel
	rTimers *TimerWheel

	now    clock.Timestamp
	source []sourceItem

	delivered     [][]byte
	deliveredSeqs []uint32
	// sendTime and deliverInstant record, per sequence, the instant of its
	// first transmission and of its delivery, so the latency invariant can
	// be checked.
	sendTime        map[uint32]clock.Timestamp
	deliverInstant  map[uint32]clock.Timestamp
	discontinuities int
}

// NewFabric wires a sender and receiver flow to N forward and N back links
// (len(fwd) must equal len(back), one Link per path). The caller builds the
// links so it can seed and impair each path independently and install drop
// filters before the run.
func NewFabric(sender, recvr *flow.Flow, fwd, back []*Link[Datagram]) *Fabric {
	if len(fwd) != len(back) {
		panic("simtest: NewFabric requires len(fwd) == len(back)")
	}
	return &Fabric{
		sender:         sender,
		recvr:          recvr,
		fwd:            fwd,
		back:           back,
		sTimers:        NewTimerWheel(),
		rTimers:        NewTimerWheel(),
		sendTime:       make(map[uint32]clock.Timestamp),
		deliverInstant: make(map[uint32]clock.Timestamp),
	}
}

// EnqueueSource schedules one application payload to be pushed into the
// sender at instant at. Successive calls must use non-decreasing at values;
// the schedule is consumed in order as the clock reaches each instant.
func (f *Fabric) EnqueueSource(at clock.Timestamp, payload []byte) {
	f.source = append(f.source, sourceItem{at: at, payload: payload})
}

// EnqueueCBR schedules n payloads at a constant interval starting at start:
// payloadFn(i) supplies the i-th payload. It is shorthand for n EnqueueSource
// calls and models a constant-bitrate source.
func (f *Fabric) EnqueueCBR(start clock.Timestamp, interval clock.Microseconds, n int, payloadFn func(i int) []byte) {
	at := start
	for i := 0; i < n; i++ {
		f.EnqueueSource(at, payloadFn(i))
		at = at.Add(interval)
	}
}

// Now returns the current mock-clock instant.
func (f *Fabric) Now() clock.Timestamp { return f.now }

// Delivered returns the payloads handed out of the receiver in delivery
// order. The slice aliases the Fabric's record; do not mutate it.
func (f *Fabric) Delivered() [][]byte { return f.delivered }

// DeliveredSeqs returns the sequence numbers delivered, in delivery order.
func (f *Fabric) DeliveredSeqs() []uint32 { return f.deliveredSeqs }

// Discontinuities returns the number of delivered packets that carried a
// discontinuity flag (a gap was abandoned just before them).
func (f *Fabric) Discontinuities() int { return f.discontinuities }

// nextDeadline returns the earliest pending event instant across every link,
// both timer wheels, and the source schedule. ok is false when nothing is
// pending — the network has gone quiescent.
func (f *Fabric) nextDeadline() (clock.Timestamp, bool) {
	var (
		best clock.Timestamp
		ok   bool
	)
	consider := func(t clock.Timestamp) {
		if !ok || t.Before(best) {
			best, ok = t, true
		}
	}
	for _, l := range f.fwd {
		if at, has := l.NextDeadline(); has {
			consider(at)
		}
	}
	for _, l := range f.back {
		if at, has := l.NextDeadline(); has {
			consider(at)
		}
	}
	if at, has := f.sTimers.NextDeadline(); has {
		consider(at)
	}
	if at, has := f.rTimers.NextDeadline(); has {
		consider(at)
	}
	if len(f.source) > 0 {
		consider(f.source[0].at)
	}
	return best, ok
}

// Step advances the mock clock to the next pending event and processes
// everything due at that instant: it delivers due datagrams into the cores,
// pushes any due source payloads, fires due timers, then drains and routes
// every resulting effect. It returns false when the network is quiescent
// (nothing left to do), which is the normal loop-termination signal.
func (f *Fabric) Step() bool {
	next, ok := f.nextDeadline()
	if !ok {
		return false
	}
	f.now = next

	// Deliver due datagrams: forward links into the receiver, back links
	// into the sender. (A sender ignores inbound media; only feedback ever
	// travels the back links in practice.)
	for i, l := range f.fwd {
		for _, d := range l.DrainDue(f.now) {
			if d.Media {
				f.recvr.Feed(f.now, uint8(i), d.Pkt)
			} else {
				f.recvr.FeedFeedback(f.now, d.FB)
			}
		}
	}
	for i, l := range f.back {
		for _, d := range l.DrainDue(f.now) {
			if d.Media {
				f.sender.Feed(f.now, uint8(i), d.Pkt)
			} else {
				f.sender.FeedFeedback(f.now, d.FB)
			}
		}
	}

	// Push due source payloads into the sender.
	for len(f.source) > 0 && !f.source[0].at.After(f.now) {
		item := f.source[0]
		f.source = f.source[1:]
		f.sender.PushApp(f.now, item.payload)
	}

	// Fire due timers.
	for _, id := range f.sTimers.PopDue(f.now) {
		f.sender.HandleTimer(f.now, flow.TimerID(id))
	}
	for _, id := range f.rTimers.PopDue(f.now) {
		f.recvr.HandleTimer(f.now, flow.TimerID(id))
	}

	// Drain and route every effect produced this instant.
	f.drainSender()
	f.drainReceiver()
	return true
}

// RunUntil steps until pred reports done or maxSteps is reached. It returns
// true if pred was satisfied, false if the step budget ran out or the network
// went quiescent first.
//
// RunUntil (not a bare "run to quiescence") is the driver because a started
// flow never goes quiescent: both roles re-arm TimerRttEcho every 100 ms
// forever (sender.go senderHandleTimer, receiver.go HandleTimer), so Step
// always has a next deadline. Tests therefore pace on a completeness or
// clock-deadline predicate.
func (f *Fabric) RunUntil(pred func(*Fabric) bool, maxSteps int) bool {
	for i := 0; i < maxSteps; i++ {
		if pred(f) {
			return true
		}
		if !f.Step() {
			return pred(f)
		}
	}
	return pred(f)
}

// drainSender drains the sender's effects, routing media and feedback onto
// the forward links and timer requests onto the sender's wheel.
func (f *Fabric) drainSender() {
	for {
		out, ok := f.sender.PollOutput()
		if !ok {
			break
		}
		switch o := out.(type) {
		case flow.SetTimer:
			f.sTimers.Set(TimerID(o.ID), o.Deadline)
		case flow.ClearTimer:
			f.sTimers.Clear(TimerID(o.ID))
		case flow.SendMedia:
			if int(o.Path) < len(f.fwd) {
				if !o.Pkt.Retransmit {
					f.sendTime[o.Pkt.Seq] = f.now
				}
				f.fwd[o.Path].Send(f.now, Datagram{Media: true, Pkt: o.Pkt})
			}
		case flow.SendFeedback:
			if int(o.Path) < len(f.fwd) {
				f.fwd[o.Path].Send(f.now, Datagram{FB: o.FB})
			}
		}
	}
	// The sender produces no application events.
}

// drainReceiver drains the receiver's effects, routing feedback onto the back
// links and timer requests onto the receiver's wheel, and records delivered
// packets.
func (f *Fabric) drainReceiver() {
	for {
		out, ok := f.recvr.PollOutput()
		if !ok {
			break
		}
		switch o := out.(type) {
		case flow.SetTimer:
			f.rTimers.Set(TimerID(o.ID), o.Deadline)
		case flow.ClearTimer:
			f.rTimers.Clear(TimerID(o.ID))
		case flow.SendFeedback:
			if int(o.Path) < len(f.back) {
				f.back[o.Path].Send(f.now, Datagram{FB: o.FB})
			}
		case flow.SendMedia:
			// A receiver never originates media; ignore defensively.
		}
	}
	for {
		ev, ok := f.recvr.PollEvent()
		if !ok {
			break
		}
		if d, ok := ev.(flow.Deliver); ok {
			f.delivered = append(f.delivered, d.Payload)
			f.deliveredSeqs = append(f.deliveredSeqs, d.Seq)
			f.deliverInstant[d.Seq] = f.now
			if d.Discontinuity {
				f.discontinuities++
			}
		}
	}
}

// InvariantOpts selects which of the four flow invariants to assert and with
// what tolerance.
type InvariantOpts struct {
	// LatencyTolerance bounds the allowed spread (max - min) in per-packet
	// delivery latency. Under the deterministic core the latency is constant —
	// a packet is delivered at sourceTime + offset + recoveryBuffer regardless
	// of how many retransmits it took, because outputTime is anchored to the
	// source time, not arrival — so 0 is the strict value; a small nonzero
	// tolerance absorbs timer-granularity batching if a future host adds it.
	// This pins latency UNIFORMITY (invariant of retransmits/jitter), not the
	// absolute deadline — set MaxLatency to bound that.
	LatencyTolerance clock.Microseconds

	// MaxLatency, when > 0, additionally asserts that NO delivered packet's
	// latency (deliver instant minus first transmission) exceeds it — the
	// literal "nothing past deadline" check. A uniformly-late stream would
	// pass the spread check but fail this. Set it to recoveryBuffer plus the
	// forward path's worst-case delay (Delay + Jitter): a correctly delivered
	// packet's latency is offset + recoveryBuffer <= that bound.
	MaxLatency clock.Microseconds

	// RequireContiguous asserts the delivered run has no internal gaps (each
	// delivered sequence is exactly one past the previous). It is the
	// completeness invariant for recoverable-loss configurations; leave it
	// false for graceful-degradation tests where abandoned holes are expected
	// (those still satisfy no-duplicate, in-order, and constant-latency).
	RequireContiguous bool
}

// CheckInvariants validates the delivered stream against the flow invariants
// and returns a list of human-readable violations (empty when all hold):
//
//  1. No duplicate delivered — and, together with (2), strictly monotonic.
//  2. In order — each delivered sequence is wrap-aware greater than the last.
//  3. Nothing past deadline — every packet's delivery latency (deliver
//     instant minus first-transmission instant) is identical within
//     LatencyTolerance (uniform, i.e. invariant of retransmits and jitter)
//     and, when MaxLatency is set, no greater than MaxLatency (the absolute
//     playout deadline). The spread check alone proves uniformity, not
//     deadline-conformance; MaxLatency pins the absolute bound.
//  4. Completeness under recoverable loss — no internal gaps (only when
//     RequireContiguous is set).
//
// It is the single shared four-invariant checker the plan calls for, usable
// from every flow and (later) bonding sim test.
func (f *Fabric) CheckInvariants(opts InvariantOpts) []string {
	var v []string
	seqs := f.deliveredSeqs

	// (1)+(2): strictly increasing under wrap-aware compare.
	for i := 1; i < len(seqs); i++ {
		prev, cur := seqs[i-1], seqs[i]
		if prev == cur {
			v = append(v, fmt.Sprintf("duplicate delivery of seq %d at index %d", cur, i))
			continue
		}
		if !seq.Num32(prev).Less(seq.Num32(cur)) {
			v = append(v, fmt.Sprintf("out-of-order delivery: seq %d after %d at index %d", cur, prev, i))
		}
	}

	// (4): contiguity.
	if opts.RequireContiguous {
		for i := 1; i < len(seqs); i++ {
			if seqs[i] != seqs[i-1]+1 {
				v = append(v, fmt.Sprintf("internal gap: seq jumps %d -> %d at index %d", seqs[i-1], seqs[i], i))
			}
		}
	}

	// (3): uniform delivery latency, and (when MaxLatency is set) within the
	// absolute playout deadline.
	if len(seqs) > 0 {
		var minLat, maxLat clock.Microseconds
		have := false
		for _, s := range seqs {
			st, okS := f.sendTime[s]
			dt, okD := f.deliverInstant[s]
			if !okS || !okD {
				v = append(v, fmt.Sprintf("missing send/deliver timestamp for seq %d", s))
				continue
			}
			lat := dt.Sub(st)
			if opts.MaxLatency > 0 && lat > opts.MaxLatency {
				v = append(v, fmt.Sprintf("seq %d delivered late: latency %d us > MaxLatency %d", s, lat, opts.MaxLatency))
			}
			if !have {
				minLat, maxLat, have = lat, lat, true
				continue
			}
			if lat < minLat {
				minLat = lat
			}
			if lat > maxLat {
				maxLat = lat
			}
		}
		if have && maxLat-minLat > opts.LatencyTolerance {
			v = append(v, fmt.Sprintf("delivery latency varied by %d us (min %d, max %d) > tolerance %d",
				maxLat-minLat, minLat, maxLat, opts.LatencyTolerance))
		}
	}

	return v
}

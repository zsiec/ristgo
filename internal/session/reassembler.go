package session

import "github.com/zsiec/ristgo/internal/wire"

// fragReassembler reassembles an Advanced-profile payload that the sender split
// across consecutive sequences. The flow core delivers the fragments in order,
// each carrying its F/L role (wire.FragRole); push folds one fragment into the
// open run and returns the whole payload on the closing FragLast. A
// FragStandalone is a complete payload delivered as-is.
//
// A run is dropped — yielding no payload — whenever it cannot be completed
// correctly: a FragMiddle/FragLast arriving with no open run (its FragFirst was
// lost), or any fragment carrying a Discontinuity (the flow core skipped a
// sequence, so a fragment of this payload was lost and never recovered). The
// application then sees the same gap any unrecovered loss produces. Encountering
// a FragFirst or FragStandalone also abandons any incomplete previous run.
//
// It is loop-owned (single goroutine), reuses its buffer across payloads, and
// allocates nothing in steady state.
type fragReassembler struct {
	buf    []byte
	active bool
	count  int // fragments folded into the open run (bounds the buffer)
}

// MaxReassemblyFragments bounds the fragments one run may absorb before it is
// abandoned. It is also the sender's per-Write split cap (the root package's
// maxFragmentsPerWrite derives from it), so a well-behaved ristgo sender never
// splits a Write into more; a longer run is a peer that never sends FragLast and
// must not be allowed to grow the buffer without bound. Exported so the sender
// cap is a single source of truth: the two cannot drift apart.
const MaxReassemblyFragments = 64

// push folds one delivered fragment into the run. It returns (payload, true)
// when a payload completes — a FragLast closing an open run, or a FragStandalone
// — and (nil, false) otherwise. The returned slice for a FragLast aliases the
// internal buffer, so the caller must copy it before the next push (queueDelivery
// copies synchronously).
func (r *fragReassembler) push(frag wire.FragRole, payload []byte, discontinuity bool) ([]byte, bool) {
	switch frag {
	case wire.FragFirst:
		// Start a fresh run, abandoning any incomplete previous one. A
		// Discontinuity here refers to a prior (already lost) payload, not this
		// run, so it does not invalidate the new run.
		r.buf = append(r.buf[:0], payload...)
		r.active = true
		r.count = 1
		return nil, false
	case wire.FragMiddle:
		if !r.active || discontinuity || r.count >= MaxReassemblyFragments {
			r.reset() // a lost fragment, or an over-long run, broke this payload
			return nil, false
		}
		r.buf = append(r.buf, payload...)
		r.count++
		return nil, false
	case wire.FragLast:
		if !r.active || discontinuity || r.count >= MaxReassemblyFragments {
			r.reset()
			return nil, false
		}
		r.buf = append(r.buf, payload...)
		r.active = false // buffer kept until the next push overwrites/resets it
		return r.buf, true
	default: // FragStandalone
		r.reset()
		return payload, true
	}
}

// reset discards any in-progress run.
func (r *fragReassembler) reset() {
	r.buf = r.buf[:0]
	r.active = false
	r.count = 0
}

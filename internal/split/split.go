// Package split implements the libRIST packet split/merge bonding modes
// (split=/merge=), ported from libRIST rist.c (the sender split) and
// rist-common.c (the receiver merge).
//
// Split/merge spreads one application payload's bytes across two consecutive RIST
// sequences so a bonded pair of links can each carry half. The sender emits two
// packets with consecutive sequence numbers (the first on an even sequence) and the
// same source time; the receiver recombines an even-sequence packet with its seq+1
// partner of identical source time back into the original payload. Unlike the
// Advanced profile's explicit F/L fragmentation markers, this is a marker-less
// pairing keyed on the even/odd sequence and the shared source time, so it works on
// the Simple and Main profiles too.
//
// This package is the byte-exact algorithmic core — the split point and the merge
// predicate (SplitPoint / IsSplitPair) — plus the two thin host-layer adapters the
// session drives: SplitPayload (the send-side split the PushApp site applies) and
// Merger (the receive-side state machine the delivery drain folds split pairs back
// together with). Everything here is pure and unit-tested in isolation (it reads no
// clock and touches no socket). It mirrors the ristrust crate's split module; the
// session plumbing — threading SplitMode/MergeMode from the config, forcing an even
// initial sequence, and the bonded path distribution — lives in internal/session.
package split

const (
	// tsPacketLen is one MPEG-TS packet length (the AUTO split aligns on it).
	tsPacketLen = 188
	// tsSyncByte marks a TS-aligned payload.
	tsSyncByte = 0x47
)

// SplitMode is the sender's packet-split strategy (libRIST split=).
type SplitMode uint8

const (
	// SplitOff disables splitting — one payload, one sequence (the default).
	SplitOff SplitMode = iota
	// SplitAuto splits on an MPEG-TS boundary at the midpoint when the payload is
	// TS-aligned, otherwise at the byte midpoint.
	SplitAuto
	// SplitHalf always splits at the byte midpoint.
	SplitHalf
)

// MergeMode is the receiver's packet-merge strategy (libRIST merge=).
type MergeMode uint8

const (
	// MergeOff delivers each packet as received (the default).
	MergeOff MergeMode = iota
	// MergePairs recombines every even/odd consecutive same-source-time pair.
	MergePairs
	// MergeAuto recombines only when the stream is detected to be split.
	MergeAuto
)

// SplitPoint returns the split of payload under mode as (first, last) byte lengths
// with first+last == len(payload), and ok=false when the payload is not split (mode
// is SplitOff or the payload is too small to halve).
//
// AUTO splits on a 188-byte MPEG-TS boundary at the midpoint when the payload is
// TS-aligned (a multiple of 188, at least two packets, first byte 0x47); otherwise it
// falls back to the byte midpoint, exactly as libRIST does.
func SplitPoint(mode SplitMode, payload []byte) (first, last int, ok bool) {
	n := len(payload)
	if mode == SplitOff || n < 2 {
		return 0, 0, false
	}
	if mode == SplitAuto && n >= 2*tsPacketLen && n%tsPacketLen == 0 && payload[0] == tsSyncByte {
		// Split on a TS boundary at the midpoint; at least one packet on each side.
		tsCount := n / tsPacketLen
		f := tsCount / 2
		if f == 0 {
			f = 1
		}
		first = f * tsPacketLen
	} else {
		// AUTO fallback (not TS-aligned) and HALF both split at the byte midpoint.
		first = n / 2
	}
	return first, n - first, true
}

// IsSplitPair reports whether two delivered packets form a split pair the receiver
// must recombine: the first sequence is even, the second is exactly firstSeq+1, and
// both carry the same source time (libRIST's (seq&1)==0 + seq+1 + equal source_time
// pairing). The combined payload is first‖second.
func IsSplitPair(firstSeq uint32, firstSrc uint64, secondSeq uint32, secondSrc uint64) bool {
	return firstSeq&1 == 0 && secondSeq == firstSeq+1 && firstSrc == secondSrc
}

// SplitPayload is the send-side split of one application payload under mode: the
// even/odd half pair (first, last, ok=true) when mode is active and the payload is
// non-empty, otherwise the payload unchanged with ok=false. The halves subslice the
// input (no copy); the caller pushes them through the flow with the same now, so the
// pair shares a source time and lands on consecutive sequences.
//
// Matching libRIST, an active split always emits a pair: a payload too small for
// SplitPoint to halve (under two bytes) still splits as a zero-byte first half and the
// whole payload as the last half. Always pairing keeps the wire sequence parity stable;
// a slip would strand a later pair's halves across an (odd, even) boundary and the
// receiver would deliver them unmerged.
func SplitPayload(mode SplitMode, payload []byte) (first, last []byte, ok bool) {
	if mode == SplitOff || len(payload) == 0 {
		return payload, nil, false
	}
	at, _, split := SplitPoint(mode, payload)
	if !split {
		at = 0 // a <2-byte payload: (empty, whole), as libRIST pairs it
	}
	return payload[:at], payload[at:], true
}

// Merger is the receive-side packet-merge state machine (libRIST merge=). It
// recombines a split pair — an even-sequence first half held until its seq+1 partner
// of identical source time arrives — back into the original application payload, and
// degrades any mis-pairing to a harmless orphan (the half delivered as received)
// rather than splicing the wrong halves together.
//
// The source-time guard is load-bearing: keying recombination only on even/odd +
// seq+1 (as a first cut did) corrupts the stream, splicing a leftover half of one
// payload onto the first half of the next. Requiring the shared source time makes a
// mis-pair fall through to two orphans instead.
//
// MergeAuto stays dormant until the peer is observed to be pair-splitting (the GRE
// keepalive L bit); MergePairs always merges; MergeOff passes every delivery through.
type Merger struct {
	mode        MergeMode
	autoEnabled bool
	hasHeld     bool
	heldSeq     uint32
	heldSrc     uint64
	heldPayload []byte
}

// NewMerger returns a merger for mode (its initial state holds nothing).
func NewMerger(mode MergeMode) *Merger { return &Merger{mode: mode} }

// SetAutoEnabled records whether the peer is advertising pair-splitting, enabling
// MergeAuto (a no-op in the other modes). Driven by the keepalive L bit.
func (m *Merger) SetAutoEnabled(on bool) { m.autoEnabled = on }

// active reports whether merging is currently on.
func (m *Merger) active() bool {
	switch m.mode {
	case MergePairs:
		return true
	case MergeAuto:
		return m.autoEnabled
	default:
		return false
	}
}

// Deliver processes one in-order delivered packet, returning the application
// payload(s) to hand on (zero, one, or two, in order). discontinuity marks a gap
// immediately before this delivery; srcTime is the packet's source clock.
//
// A held first half is copied (the caller's payload buffer may be reused before the
// partner arrives); the combined payload and any flushed orphan are freshly built.
func (m *Merger) Deliver(seq uint32, srcTime uint64, payload []byte, discontinuity bool) [][]byte {
	if !m.active() {
		return [][]byte{payload}
	}
	// Complete a held pair when this delivery is its in-order, same-source-time
	// partner. The seq+1 check already implies no intervening gap, so a genuine
	// discontinuity can never satisfy it; the explicit guard is defensive.
	if m.hasHeld {
		if !discontinuity && IsSplitPair(m.heldSeq, m.heldSrc, seq, srcTime) {
			combined := make([]byte, 0, len(m.heldPayload)+len(payload))
			combined = append(combined, m.heldPayload...)
			combined = append(combined, payload...)
			m.clearHeld()
			return [][]byte{combined}
		}
		// Not the partner — its partner was lost, or the stream is not split. Flush
		// the orphaned first half, then process this delivery fresh.
		orphan := m.heldPayload
		m.clearHeld()
		return append([][]byte{orphan}, m.fresh(seq, srcTime, payload)...)
	}
	return m.fresh(seq, srcTime, payload)
}

// fresh processes a delivery with no held first half: hold an even sequence as a
// candidate first half (copying it, since the caller's buffer may be reused), deliver
// an odd one straight through.
func (m *Merger) fresh(seq uint32, srcTime uint64, payload []byte) [][]byte {
	if seq&1 == 0 {
		held := make([]byte, len(payload))
		copy(held, payload)
		m.hasHeld, m.heldSeq, m.heldSrc, m.heldPayload = true, seq, srcTime, held
		return nil
	}
	return [][]byte{payload}
}

func (m *Merger) clearHeld() {
	m.hasHeld, m.heldPayload = false, nil
}

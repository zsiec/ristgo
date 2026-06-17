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
// predicate — kept pure and unit-tested in isolation (it reads no clock and touches
// no socket). It mirrors the ristrust crate's split module. Wiring it into the
// per-profile send/deliver paths (sender sequence-parity alignment, the receive-side
// merge at the delivery point, the split=/merge= config/URL knobs, and the bonded
// path distribution) is the tracked follow-up; until then a split/merge mode is a
// no-op.
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

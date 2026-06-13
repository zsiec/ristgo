// Package seq implements wrap-aware sequence-number arithmetic for the two
// widths RIST uses on the wire: the 16-bit RTP sequence number carried by the
// Simple and Main profiles, and the 32-bit extended sequence number produced
// once the codec layer widens 16-bit rollovers (and used natively by the
// Advanced profile).
//
// # Circular order is not total
//
// Sequence numbers live on a ring, so there is no total order: ordering is
// only meaningful between values whose circular distance is at most half the
// sequence space, and transitivity does not hold in general. For that reason
// nothing in this API derives ordering from the raw < operator of the
// underlying integers, and callers must not either: always use Less, Compare,
// or Distance.
//
// # Behavior at exactly half the sequence space
//
// When two values are exact antipodes (their circular distance is exactly
// half the ring: 0x8000 for Num16, 0x80000000 for Num32), "ahead" and
// "behind" are genuinely ambiguous. This package pins the ambiguity the same
// way libRIST does (src/rist-common.c:536, receiver_mark_missing: a forward
// gap is rejected as wraparound only when strictly greater than half the
// space): a gap of exactly half is treated as forward in both directions.
// (libRIST applies that rule with a 16-bit mask and 32768 threshold for all
// widths; this package's 32-bit half-space variant is a deliberate
// generalization — see MaxGap32.) Consequently, for exact antipodes a and b:
//
//   - a.Distance(b) == b.Distance(a) == +half; the antisymmetry
//     Distance(a,b) == -Distance(b,a) holds everywhere else.
//   - a.Less(b) and b.Less(a) are both true; Less antisymmetry holds
//     everywhere else.
//   - a.Compare(b) and b.Compare(a) are both -1.
//
// # Two concrete types rather than one generic type
//
// Num16 and Num32 are separate concrete types backed by a single unexported
// generic implementation. Methods on concrete types keep call sites free of
// instantiation noise (a.Less(b) rather than seq.Less[uint16](a, b)), make
// the width explicit in struct fields and signatures, and prevent the two
// widths from being mixed accidentally. The generics stay inside the package,
// where they deduplicate the arithmetic without leaking into the API.
package seq

const (
	// Max16 is the largest 16-bit sequence number; Max16.Inc() wraps to 0.
	Max16 Num16 = 0xFFFF
	// Half16 is half the 16-bit sequence space (2^15). Two values whose
	// circular distance is exactly Half16 are antipodes; see the package
	// documentation for the pinned ordering at that point.
	Half16 Num16 = 0x8000

	// Max32 is the largest 32-bit sequence number; Max32.Inc() wraps to 0.
	Max32 Num32 = 0xFFFFFFFF
	// Half32 is half the 32-bit sequence space (2^31). Two values whose
	// circular distance is exactly Half32 are antipodes; see the package
	// documentation for the pinned ordering at that point.
	Half32 Num32 = 0x80000000
)

// MaxGap16 is the largest forward gap, in packets, that may be interpreted as
// loss for 16-bit sequence numbers. It encodes libRIST's wraparound guard in
// receiver_mark_missing (src/rist-common.c:555-557):
//
//	uint32_t missing_count = (current_seq - f->last_seq_found) & UINT16_MAX;
//	if (missing_count > 32768)
//		return; // wraparound or reorder, NOT loss
//
// A gap of exactly 32768 is still treated as forward loss; only strictly
// larger gaps indicate a reordered or wrapped packet.
const MaxGap16 uint64 = 1 << 15

// MaxGap32 is the 32-bit analog of MaxGap16: the largest forward gap that may
// be interpreted as loss for 32-bit extended sequence numbers, scaling the
// strictly-greater-than-half-range rule to half the 32-bit space.
//
// This is a deliberate generalization that deviates from libRIST's literal
// code: receiver_mark_missing (src/rist-common.c:555-557) masks the gap to 16
// bits and compares it against 32768 unconditionally, even for 32-bit
// (non-short_seq, i.e. Advanced) flows, so libRIST rejects any gap above
// 32768 as wraparound regardless of sequence width. Callers that must match
// libRIST's reference behavior — in particular internal/flow's
// missing-packet detection on Simple/Main sequences widened from 16 bits —
// must pin their loss threshold to MaxGap16, not MaxGap32. See the
// 2026-06-12 entry in ORCHESTRATION.md's decisions log.
const MaxGap32 uint64 = 1 << 31

// Num16 is a wrapping 16-bit RTP sequence number (Simple/Main profile media
// packets). All arithmetic is modulo 2^16; ordering is circular and not
// total, so callers must use Less, Compare, or Distance rather than the raw
// < operator.
type Num16 uint16

// Num32 is a wrapping 32-bit extended sequence number (codec-widened 16-bit
// rollovers and the Advanced profile). All arithmetic is modulo 2^32;
// ordering is circular and not total, so callers must use Less, Compare, or
// Distance rather than the raw < operator.
type Num32 uint32

// numeric constrains the unsigned widths RIST uses for sequence numbers.
type numeric interface {
	~uint16 | ~uint32
}

// half returns half the sequence space of T (2^15 or 2^31).
func half[T numeric]() T {
	return ^T(0)/2 + 1
}

// distance returns the signed shortest circular distance from a to b, pinned
// to +half at the antipode (see package documentation).
func distance[T numeric](a, b T) int64 {
	d := b - a // wraps modulo the width of T
	if d == 0 || d <= half[T]() {
		return int64(d)
	}
	return int64(d) - int64(^T(0)) - 1 // d - 2^width
}

// less reports whether a is circularly before b: true iff the forward gap
// from a to b is nonzero and at most half the sequence space.
func less[T numeric](a, b T) bool {
	d := b - a
	return d != 0 && d <= half[T]()
}

// compare returns 0 if a == b, -1 if a is circularly before b, +1 otherwise.
func compare[T numeric](a, b T) int {
	switch {
	case a == b:
		return 0
	case less(a, b):
		return -1
	default:
		return 1
	}
}

// forwardGap returns the raw forward gap (b - a) modulo the width of T and
// whether it may be interpreted as forward progress (loss) per the
// strictly-greater-than-half-range rule: libRIST's exact behavior at 16
// bits, a deliberate generalization at 32 bits (see MaxGap32).
func forwardGap[T numeric](a, b T) (uint64, bool) {
	gap := uint64(b - a)
	return gap, gap <= uint64(half[T]())
}

// Value returns the raw uint16 value of the sequence number.
func (a Num16) Value() uint16 { return uint16(a) }

// Inc returns the next sequence number, wrapping from Max16 to 0.
func (a Num16) Inc() Num16 { return a + 1 }

// Dec returns the previous sequence number, wrapping from 0 to Max16.
func (a Num16) Dec() Num16 { return a - 1 }

// Add returns a + n modulo 2^16. n is interpreted modulo 2^16, so negative
// offsets step backward: a.Add(a.Distance(b)) == b for every a, b.
func (a Num16) Add(n int64) Num16 { return a + Num16(n) }

// Sub returns a - n modulo 2^16. n is interpreted modulo 2^16, so
// a.Add(n).Sub(n) == a for every a, n.
func (a Num16) Sub(n int64) Num16 { return a - Num16(n) }

// Distance returns the signed shortest circular distance from a to b:
// positive if b is ahead of a, negative if b is behind a, zero if equal. The
// result is in [-32767, 32768]; exact antipodes return +32768 in both
// directions (see package documentation). a.Add(a.Distance(b)) == b always
// holds.
func (a Num16) Distance(b Num16) int64 { return distance(uint16(a), uint16(b)) }

// Less reports whether a is circularly before b, i.e. whether the forward
// gap from a to b is nonzero and at most Half16. Equivalent to
// a.Distance(b) > 0. Less is not a total order: at exact antipodes both
// a.Less(b) and b.Less(a) are true (see package documentation).
func (a Num16) Less(b Num16) bool { return less(uint16(a), uint16(b)) }

// Compare returns 0 if a == b, -1 if a is circularly before b, and +1
// otherwise; its sign agrees with Distance. Circular order is not total: at
// exact antipodes a.Compare(b) and b.Compare(a) are both -1 (see package
// documentation).
func (a Num16) Compare(b Num16) int { return compare(uint16(a), uint16(b)) }

// ForwardGap returns the raw forward gap (b - a) modulo 2^16 from a to b,
// and whether that gap may be interpreted as forward progress (genuine loss)
// rather than wraparound/reorder. It encodes libRIST's receiver_mark_missing
// guard (src/rist-common.c:555-557): forward is true iff gap <= MaxGap16
// (32768); strictly larger gaps mean b is a reordered or wrapped packet and
// the intervening sequence numbers must NOT be marked missing. When forward
// is true the number of missing packets between a and b is gap-1 (for
// gap >= 1).
func (a Num16) ForwardGap(b Num16) (gap uint64, forward bool) {
	return forwardGap(uint16(a), uint16(b))
}

// Value returns the raw uint32 value of the sequence number.
func (a Num32) Value() uint32 { return uint32(a) }

// Inc returns the next sequence number, wrapping from Max32 to 0.
func (a Num32) Inc() Num32 { return a + 1 }

// Dec returns the previous sequence number, wrapping from 0 to Max32.
func (a Num32) Dec() Num32 { return a - 1 }

// Add returns a + n modulo 2^32. n is interpreted modulo 2^32, so negative
// offsets step backward: a.Add(a.Distance(b)) == b for every a, b.
func (a Num32) Add(n int64) Num32 { return a + Num32(n) }

// Sub returns a - n modulo 2^32. n is interpreted modulo 2^32, so
// a.Add(n).Sub(n) == a for every a, n.
func (a Num32) Sub(n int64) Num32 { return a - Num32(n) }

// Distance returns the signed shortest circular distance from a to b:
// positive if b is ahead of a, negative if b is behind a, zero if equal. The
// result is in [-2147483647, 2147483648]; exact antipodes return +2147483648
// in both directions (see package documentation). a.Add(a.Distance(b)) == b
// always holds.
func (a Num32) Distance(b Num32) int64 { return distance(uint32(a), uint32(b)) }

// Less reports whether a is circularly before b, i.e. whether the forward
// gap from a to b is nonzero and at most Half32. Equivalent to
// a.Distance(b) > 0. Less is not a total order: at exact antipodes both
// a.Less(b) and b.Less(a) are true (see package documentation).
func (a Num32) Less(b Num32) bool { return less(uint32(a), uint32(b)) }

// Compare returns 0 if a == b, -1 if a is circularly before b, and +1
// otherwise; its sign agrees with Distance. Circular order is not total: at
// exact antipodes a.Compare(b) and b.Compare(a) are both -1 (see package
// documentation).
func (a Num32) Compare(b Num32) int { return compare(uint32(a), uint32(b)) }

// ForwardGap returns the raw forward gap (b - a) modulo 2^32 from a to b,
// and whether that gap may be interpreted as forward progress (genuine loss)
// rather than wraparound/reorder: forward is true iff gap <= MaxGap32.
//
// Scaling Num16.ForwardGap's half-range rule to 32 bits is a deliberate
// generalization that deviates from libRIST's literal code:
// receiver_mark_missing (src/rist-common.c:555-557) masks the gap to 16 bits
// and compares it against 32768 unconditionally, even for 32-bit flows.
// Callers that must match libRIST's reference behavior on sequences widened
// from 16 bits must cap the loss threshold at MaxGap16 themselves; see
// MaxGap32.
func (a Num32) ForwardGap(b Num32) (gap uint64, forward bool) {
	return forwardGap(uint32(a), uint32(b))
}

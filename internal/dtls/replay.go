package dtls

// replayWindow is the DTLS sliding-window anti-replay filter (RFC 6347 §4.1.2.6):
// a 64-bit bitmap of accepted record sequence numbers anchored at the highest
// seen. Bit 0 marks the right edge (the highest accepted seq); bit i marks the
// seq i below it. A sequence at or below the window that is already marked, or
// more than 64 below the right edge, is rejected.
type replayWindow struct {
	right  uint64
	bitmap uint64
	seen   bool
}

const replayWindowSize = 64

// check reports whether seq is acceptable (new, within the window, not a
// replay). It does not mutate state; call mark after the record authenticates.
func (w *replayWindow) check(seq uint64) bool {
	if !w.seen || seq > w.right {
		return true
	}
	diff := w.right - seq
	if diff >= replayWindowSize {
		return false // too old to judge; treat as replay
	}
	return w.bitmap&(1<<diff) == 0
}

// mark records seq as accepted, sliding the window forward if seq is the new
// high-water mark.
func (w *replayWindow) mark(seq uint64) {
	if !w.seen {
		w.seen = true
		w.right = seq
		w.bitmap = 1
		return
	}
	if seq > w.right {
		shift := seq - w.right
		if shift >= replayWindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.right = seq
		return
	}
	if diff := w.right - seq; diff < replayWindowSize {
		w.bitmap |= 1 << diff
	}
}

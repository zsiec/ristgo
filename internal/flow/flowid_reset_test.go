package flow

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// TestFlowIDChangeResets covers the libRIST "Detected flow id change ...
// resetting state" behavior: a started receiver that sees a fresh packet with a
// different flow id (SSRC, retransmit bit masked) discards its buffered state and
// re-anchors on the new flow, rather than merging two distinct flows into one
// ring. A retransmit — which carries the retransmit-bit-set SSRC and cannot
// anchor a flow — must never trigger a reset.
func TestFlowIDChangeResets(t *testing.T) {
	const (
		flowA = uint32(0x1000_0000)
		flowB = uint32(0x2000_0000)
		flowC = uint32(0x3000_0000)
	)
	p := func(seq uint32, us clock.Microseconds, ssrc uint32) wire.MediaPacket {
		return wire.MediaPacket{Seq: seq, SourceTime: srcNTP(us), SSRC: ssrc}
	}

	f := New(RoleReceiver, DefaultConfig())

	// Anchor on flow A and buffer a couple of packets.
	f.Feed(10_000, 0, p(100, 0, flowA))
	f.Feed(17_000, 0, p(101, 7_000, flowA))
	if f.receiver.ssrc != flowA {
		t.Fatalf("ssrc = %#x, want %#x (anchored on flow A)", f.receiver.ssrc, flowA)
	}
	if f.stats.FlowResets != 0 {
		t.Fatalf("FlowResets = %d, want 0", f.stats.FlowResets)
	}

	// A retransmit of flow A carries the retransmit-bit-set SSRC (flowA|1). That is
	// the SAME flow id, so it must NOT reset.
	rtA := p(100, 0, flowA|1)
	rtA.Retransmit = true
	f.Feed(18_000, 0, rtA)
	if f.stats.FlowResets != 0 {
		t.Fatalf("a same-flow retransmit (SSRC|1) wrongly reset the flow: FlowResets = %d", f.stats.FlowResets)
	}

	// A fresh packet on flow B is a genuine flow-id change: reset and re-anchor.
	f.Feed(30_000, 0, p(5000, 23_000, flowB))
	if f.stats.FlowResets != 1 {
		t.Fatalf("FlowResets = %d, want 1 after the flow-id change", f.stats.FlowResets)
	}
	if f.receiver.ssrc != flowB {
		t.Fatalf("ssrc = %#x, want %#x (re-anchored on flow B)", f.receiver.ssrc, flowB)
	}
	if !f.receiver.started || f.receiver.deliverNext != 5000 {
		t.Fatalf("re-anchor: started=%v deliverNext=%d, want true/5000", f.receiver.started, f.receiver.deliverNext)
	}
	// Flow A's buffered slot was cleared, so no stale packet can be delivered or
	// deduped against the new flow.
	if slotA, slotB := uint32(100)&f.receiver.mask, uint32(5000)&f.receiver.mask; slotA != slotB {
		if st := f.receiver.ring[slotA].state; st != slotEmpty {
			t.Fatalf("flow A ring slot survived the reset: state = %v", st)
		}
	}
	if f.receiver.missingCount != 0 {
		t.Fatalf("missing queue not cleared on reset: missingCount = %d", f.receiver.missingCount)
	}

	// A retransmit bearing yet another flow id while started on B must NOT reset
	// (a retransmit cannot anchor a flow).
	rtC := p(5000, 23_000, flowC|1)
	rtC.Retransmit = true
	f.Feed(31_000, 0, rtC)
	if f.stats.FlowResets != 1 {
		t.Fatalf("a retransmit triggered a reset: FlowResets = %d, want 1", f.stats.FlowResets)
	}
}

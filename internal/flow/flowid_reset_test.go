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

// TestFramingChangeReanchors covers the TR-06-3 §9 Main↔Advanced interop
// transition: an Advanced receiver anchored on Main (16-bit) framing that sees the
// upgrade to Advanced (32-bit) framing on the SAME SSRC and the continuing sequence
// re-anchors its TIMING baseline for the new timestamp scale while PRESERVING the
// buffered ring, the delivery cursor, and the missing queue. The switch is lossless:
// every packet buffered before the upgrade is still delivered, in order, and nothing
// is counted lost. The SSRC can stay the same across the switch, so the SSRC-change
// reset alone would miss it.
func TestFramingChangeReanchors(t *testing.T) {
	const ssrc = uint32(0x4000_0000)
	pkt := func(seq uint32, us clock.Microseconds, shortSeq bool) wire.MediaPacket {
		return wire.MediaPacket{Seq: seq, SourceTime: srcNTP(us), SSRC: ssrc, ShortSeq: shortSeq}
	}

	f := New(RoleReceiver, DefaultConfig())

	// Anchor on Main (16-bit) framing — the libRIST startup window before upgrade —
	// and buffer two packets (delivery is time-driven, so they stay in the ring).
	f.Feed(10_000, 0, pkt(100, 0, true))
	f.Feed(17_000, 0, pkt(101, 7_000, true))
	if !f.receiver.shortSeq {
		t.Fatalf("anchored shortSeq = false, want true (Main framing)")
	}

	// A retransmit in the other framing must NOT re-anchor (it cannot anchor a flow).
	rt := pkt(100, 0, false)
	rt.Retransmit = true
	f.Feed(18_000, 0, rt)
	if f.stats.FramingResets != 0 {
		t.Fatalf("a retransmit wrongly triggered a framing re-anchor: FramingResets = %d", f.stats.FramingResets)
	}

	// The Main→Advanced upgrade: a fresh 32-bit-framed packet on the SAME SSRC and
	// the continuing sequence (102 = 101+1). Re-anchor timing, but preserve the ring.
	f.Feed(24_000, 0, pkt(102, 17_000, false))
	if f.stats.FramingResets != 1 {
		t.Fatalf("FramingResets = %d, want 1 after the Main→Advanced framing switch", f.stats.FramingResets)
	}
	if f.stats.FlowResets != 0 {
		t.Fatalf("FlowResets = %d, want 0 (SSRC unchanged across the framing switch)", f.stats.FlowResets)
	}
	if f.receiver.shortSeq {
		t.Fatalf("re-anchored shortSeq = true, want false (Advanced framing)")
	}
	// Ring-PRESERVING: the delivery cursor and the buffered slots survive the switch
	// (a ring-clearing reset would have re-anchored deliverNext to 102 and dropped
	// 100/101). Confirm the cursor is unmoved and all three packets are buffered.
	if !f.receiver.started || f.receiver.deliverNext != 100 {
		t.Fatalf("re-anchor moved the cursor: deliverNext = %d, want 100 (ring preserved)", f.receiver.deliverNext)
	}
	for _, seqn := range []uint32{100, 101, 102} {
		if s := &f.receiver.ring[seqn&f.receiver.mask]; s.state != slotFilled || s.seq != seqn {
			t.Fatalf("seq %d not buffered after the switch (state=%v) — ring was cleared", seqn, s.state)
		}
	}

	// Drive playout past the recovery buffer: all three packets deliver in order,
	// none lost — the upgrade is lossless.
	f.deliverDue(24_000 + 2*clock.Timestamp(f.recoveryBuffer))
	var delivered []uint32
	for {
		e, ok := f.PollEvent()
		if !ok {
			break
		}
		if d, isDeliver := e.(Deliver); isDeliver {
			delivered = append(delivered, d.Seq)
		}
	}
	if len(delivered) != 3 || delivered[0] != 100 || delivered[1] != 101 || delivered[2] != 102 {
		t.Fatalf("framing switch was not lossless: delivered %v, want [100 101 102]", delivered)
	}
	if f.stats.Lost != 0 {
		t.Fatalf("framing switch counted %d lost, want 0 (lossless)", f.stats.Lost)
	}
}

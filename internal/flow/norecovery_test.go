package flow

import (
	"reflect"
	"testing"

	"github.com/zsiec/ristgo/internal/wire"
)

// hasNackOrEchoTimer reports whether any output is a NACK/echo feedback or a
// recovery-related timer (the things one-way / NoRecovery transport must never
// emit).
func hasNackOrEchoTimer(outs []Output) bool {
	for _, o := range outs {
		switch v := o.(type) {
		case SendFeedback:
			return true
		case SetTimer:
			if v.ID == TimerNack || v.ID == TimerRttEcho {
				return true
			}
		}
	}
	return false
}

// TestNoRecoverySenderNoHistoryNoEcho asserts a one-way sender transmits media
// but retains no retransmit history, arms no RTT-echo cadence, and refuses to
// retransmit when a (stray) NACK arrives.
func TestNoRecoverySenderNoHistoryNoEcho(t *testing.T) {
	cfg := senderConfig()
	cfg.NoRecovery = true
	f := New(RoleSender, cfg)

	f.PushApp(10_000, []byte("a")) // seq 100
	outs := drainOutputs(f)

	// Only the media send — no TimerRttEcho arm.
	if hasNackOrEchoTimer(outs) {
		t.Fatalf("one-way sender emitted a recovery timer/feedback: %v", outs)
	}
	ms := mediaOutputs(outs)
	if len(ms) != 1 || ms[0].Pkt.Seq != 100 || ms[0].Pkt.Retransmit {
		t.Fatalf("media outputs = %v, want one first-transmission of seq 100", ms)
	}

	// No history retained: the ring slot stays empty.
	if sl := &f.sender.ring[100&f.sender.mask]; sl.state == slotFilled {
		t.Fatalf("one-way sender retained history: slot = %+v", sl)
	}

	// A NACK for seq 100 cannot be serviced (no history) and emits no media.
	f.FeedFeedback(20_000, wire.NackRequest{SSRC: cfg.SSRC, Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 0 {
		t.Fatalf("one-way sender retransmitted %v, want nothing", ms)
	}
	if st := f.Stats(); st.Retransmitted != 0 || st.RetransmitSkipped != 1 {
		t.Fatalf("retransmitted/skipped = %d/%d, want 0/1", st.Retransmitted, st.RetransmitSkipped)
	}
}

// TestNoRecoveryReceiverNoNackStillDelivers asserts a one-way receiver never
// requests retransmission (no NACK, no NACK timer, no RTT echo) yet still
// delivers in order, reclaiming an unrecoverable hole by playout-skip.
func TestNoRecoveryReceiverNoNackStillDelivers(t *testing.T) {
	cfg := testConfig()
	cfg.NoRecovery = true
	f := New(RoleReceiver, cfg)

	// First packet: arms playout only — no RTT-echo cadence.
	f.Feed(10_000, 0, mkPkt(100, 0, []byte("a")))
	first := drainOutputs(f)
	if want := []Output{SetTimer{ID: TimerPlayout, Deadline: 1_010_000}}; !reflect.DeepEqual(first, want) {
		t.Fatalf("first-packet outputs = %v, want only the playout timer", first)
	}

	// A gap (101 never arrives): a normal receiver would queue a missing entry
	// and arm TimerNack. One-way must do neither.
	f.Feed(24_000, 0, mkPkt(102, 14_000, []byte("c")))
	if outs := drainOutputs(f); hasNackOrEchoTimer(outs) {
		t.Fatalf("one-way receiver requested recovery on a gap: %v", outs)
	}
	if f.receiver.missingCount != 0 {
		t.Fatalf("missingCount = %d, want 0 (no missing entries queued)", f.receiver.missingCount)
	}

	// Playout still drives in-order delivery and skips the hole at its deadline.
	f.HandleTimer(1_010_000, TimerPlayout)
	if got := deliveredSeqs(drainEvents(f)); !reflect.DeepEqual(got, []uint32{100}) {
		t.Fatalf("first delivery = %v, want [100]", got)
	}
	drainOutputs(f)
	f.HandleTimer(1_024_000, TimerPlayout)
	evs := drainEvents(f)
	if got := deliveredSeqs(evs); !reflect.DeepEqual(got, []uint32{102}) {
		t.Fatalf("post-skip delivery = %v, want [102]", got)
	}
	if d := evs[0].(Deliver); !d.Discontinuity {
		t.Fatal("delivery after a skipped hole must flag a discontinuity")
	}

	st := f.Stats()
	if st.Delivered != 2 || st.Lost != 1 {
		t.Fatalf("delivered/lost = %d/%d, want 2/1", st.Delivered, st.Lost)
	}
}

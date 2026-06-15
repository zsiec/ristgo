package flow

import (
	"testing"

	"github.com/zsiec/ristgo/internal/wire"
)

// TestSenderStampsFragAndRetransmits asserts PushAppFrag stamps the fragment
// role onto the first transmission and that a retransmit re-sends the same role
// (the core carries it opaquely through the history ring).
func TestSenderStampsFragAndRetransmits(t *testing.T) {
	f := New(RoleSender, senderConfig()) // StartSeq 100, SSRC even
	f.PushAppFrag(10_000, []byte("a"), wire.FragFirst)

	ms := mediaOutputs(drainOutputs(f))
	if len(ms) != 1 || ms[0].Pkt.Frag != wire.FragFirst || ms[0].Pkt.Retransmit {
		t.Fatalf("first send = %+v, want one FragFirst first-transmission", ms)
	}

	f.FeedFeedback(20_000, wire.NackRequest{SSRC: senderConfig().SSRC, Missing: []uint32{100}})
	ms = mediaOutputs(drainOutputs(f))
	if len(ms) != 1 || !ms[0].Pkt.Retransmit || ms[0].Pkt.Frag != wire.FragFirst {
		t.Fatalf("retransmit = %+v, want a FragFirst retransmission", ms)
	}
}

// TestReceiverDeliversFragRole asserts the receiver carries the fragment role
// from the fed packet onto its Deliver event, so the host can reassemble.
func TestReceiverDeliversFragRole(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	p := mkPkt(100, 0, []byte("a"))
	p.Frag = wire.FragLast
	f.Feed(10_000, 0, p)
	f.HandleTimer(1_010_000, TimerPlayout) // release at its playout deadline

	var got *Deliver
	for _, ev := range drainEvents(f) {
		if d, ok := ev.(Deliver); ok {
			got = &d
		}
	}
	if got == nil {
		t.Fatal("no Deliver event")
	}
	if got.Frag != wire.FragLast {
		t.Fatalf("Deliver.Frag = %d, want FragLast", got.Frag)
	}
}

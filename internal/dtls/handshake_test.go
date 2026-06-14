package dtls

import "testing"

// TestReassemblerWindowBound verifies the handshake reassembler drops fragments
// beyond maxPendingMessages ahead of the delivery cursor, so a hostile peer
// cannot pin memory by declaring many distinct future message_seq values
// (epoch-0 handshake memory-exhaustion guard).
func TestReassemblerWindowBound(t *testing.T) {
	r := newReassembler()
	// A fragment far ahead of next (0) must be dropped, not buffered.
	far := parsedFragment{typ: typeCertificate, totalLen: maxHandshakeBody, seq: 1000, fragOff: 0, frag: make([]byte, 1)}
	if err := r.accept(far); err != nil {
		t.Fatalf("accept far fragment: %v", err)
	}
	if len(r.pending) != 0 {
		t.Fatalf("buffered %d out-of-window messages, want 0", len(r.pending))
	}

	// Every seq within the window is accepted; none beyond it.
	for seq := uint16(0); seq < 2*maxPendingMessages; seq++ {
		f := parsedFragment{typ: typeClientHello, totalLen: 1, seq: seq, fragOff: 0, frag: []byte{0x01}}
		if err := r.accept(f); err != nil {
			t.Fatalf("accept seq %d: %v", seq, err)
		}
	}
	if len(r.pending) > maxPendingMessages {
		t.Fatalf("pending=%d exceeds window %d", len(r.pending), maxPendingMessages)
	}

	// The in-order message at the cursor is still deliverable.
	if _, ok := r.nextMessage(); !ok {
		t.Fatal("seq 0 should be deliverable")
	}
}

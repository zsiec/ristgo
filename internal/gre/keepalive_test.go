package gre

import "testing"

func TestBufferNegotiationRoundTrip(t *testing.T) {
	bn := BufferNegotiation{SenderMaxMs: 1010, ReceiverCurMs: 500, ProtoType: 0}
	got, err := ParseBufferNegotiation(bn.AppendTo(nil))
	if err != nil {
		t.Fatalf("ParseBufferNegotiation: %v", err)
	}
	if got != bn {
		t.Fatalf("round-trip = %+v, want %+v", got, bn)
	}
	if _, err := ParseBufferNegotiation([]byte{1, 2, 3}); err == nil {
		t.Fatal("ParseBufferNegotiation(short) = nil error, want error")
	}
}

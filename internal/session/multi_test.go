package session

import "testing"

// FuzzDemuxPeek asserts the demux classifiers never panic on arbitrary bytes:
// they bound their reads off the datagram length and return ok=false on a runt.
func FuzzDemuxPeek(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x80})
	f.Add(make([]byte, 12))
	f.Add([]byte{0x80, 0xC8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07})                         // RTCP-ish
	f.Add([]byte{0x80, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}) // RTP-ish
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = peekMediaSSRC(b)
		_, _ = peekRTCPSSRC(b)
	})
}

// TestDemuxPeekNoAlloc pins the per-datagram demux key extraction as
// allocation-free (the copy a routed datagram needs is separate).
func TestDemuxPeekNoAlloc(t *testing.T) {
	media := make([]byte, 1316)
	rtcp := make([]byte, 60)
	if n := testing.AllocsPerRun(1000, func() {
		_, _ = peekMediaSSRC(media)
		_, _ = peekRTCPSSRC(rtcp)
	}); n != 0 {
		t.Fatalf("demux peek allocated %v times per run, want 0", n)
	}
}

// TestDemuxPeekRunts confirms a short datagram is classified unroutable rather
// than read out of bounds.
func TestDemuxPeekRunts(t *testing.T) {
	for _, b := range [][]byte{nil, {}, make([]byte, 7), make([]byte, 11)} {
		if _, ok := peekRTCPSSRC(b); ok && len(b) < 8 {
			t.Fatalf("peekRTCPSSRC accepted a %d-byte runt", len(b))
		}
		if _, ok := peekMediaSSRC(b); ok && len(b) < rtpHeaderSize {
			t.Fatalf("peekMediaSSRC accepted a %d-byte runt", len(b))
		}
	}
}

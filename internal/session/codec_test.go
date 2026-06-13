package session

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/wire"
)

// srcNTP builds the NTP-64 source time for a microsecond instant.
func srcNTP(us int64) uint64 {
	return uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(us)))
}

func TestEncodeDecodeMediaRoundTrip(t *testing.T) {
	var dec mediaDecoder
	// Three consecutive packets 1 ms apart, even base SSRC.
	for i := 0; i < 3; i++ {
		pkt := wire.MediaPacket{
			Seq:        1000 + uint32(i),
			SourceTime: srcNTP(int64(i) * 1000),
			SSRC:       0x0ACE_0AC0,
			Payload:    []byte{byte(i), 0xAB},
		}
		b, err := encodeMedia(nil, pkt)
		if err != nil {
			t.Fatalf("encodeMedia: %v", err)
		}
		got, err := dec.decode(b)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		// First packet anchors the decoder's 32-bit space at the wire's low
		// 16 bits; subsequent packets increment by one.
		if want := uint32(1000 + i); got.Seq != want {
			t.Fatalf("packet %d Seq = %d, want %d", i, got.Seq, want)
		}
		if got.SSRC != 0x0ACE_0AC0 || got.Retransmit {
			t.Fatalf("packet %d SSRC/retransmit = %#x/%v", i, got.SSRC, got.Retransmit)
		}
		if string(got.Payload) != string(pkt.Payload) {
			t.Fatalf("packet %d payload = %x", i, got.Payload)
		}
	}
}

func TestDecodeMediaSourceTimeSpacing(t *testing.T) {
	var dec mediaDecoder
	first, _ := encodeMedia(nil, wire.MediaPacket{Seq: 1, SourceTime: srcNTP(0), SSRC: 2})
	second, _ := encodeMedia(nil, wire.MediaPacket{Seq: 2, SourceTime: srcNTP(40_000), SSRC: 2}) // +40ms

	d1, _ := dec.decode(first)
	d2, _ := dec.decode(second)
	// The reconstructed source-time delta should track the 40ms spacing
	// within the 90kHz quantization (~11µs).
	delta := clock.NTPTime(d2.SourceTime).Timestamp().Sub(clock.NTPTime(d1.SourceTime).Timestamp())
	if delta < 39_950 || delta > 40_050 {
		t.Fatalf("reconstructed source-time delta = %d us, want ~40000", delta)
	}
}

func TestDecodeRetransmitDedupConsistent(t *testing.T) {
	// A retransmit carries the same wire seq+timestamp as the original; even
	// when decoded out of order around other packets, it must reconstruct to
	// the identical (Seq, SourceTime) so the flow's duplicate test fires.
	var dec mediaDecoder
	orig := wire.MediaPacket{Seq: 500, SourceTime: srcNTP(5_000_000), SSRC: 8}
	encOrig, _ := encodeMedia(nil, orig)

	d0, _ := dec.decode(encOrig)
	// Decode some later packets to advance the decoder's reference.
	for i := uint32(1); i <= 5; i++ {
		b, _ := encodeMedia(nil, wire.MediaPacket{Seq: 500 + i, SourceTime: srcNTP(5_000_000 + int64(i)*1000), SSRC: 8})
		dec.decode(b)
	}
	// Now the retransmit of seq 500 arrives.
	rt := orig
	rt.Retransmit = true
	encRT, _ := encodeMedia(nil, rt)
	dR, _ := dec.decode(encRT)

	if dR.Seq != d0.Seq || dR.SourceTime != d0.SourceTime {
		t.Fatalf("retransmit reconstructed (%d,%d), original (%d,%d) — dedup would fail",
			dR.Seq, dR.SourceTime, d0.Seq, d0.SourceTime)
	}
	if !dR.Retransmit {
		t.Fatal("retransmit flag lost (SSRC LSB not detected)")
	}
}

func TestWidenSeq(t *testing.T) {
	tests := []struct {
		wire uint16
		ref  uint32
		want uint32
	}{
		{100, 100, 100},
		{101, 100, 101},
		{0, 0xFFFF, 0x10000},      // forward across the 16-bit wrap
		{0xFFFF, 0x10000, 0xFFFF}, // backward across the wrap
		{5, 0x0001_0003, 0x0001_0005},
	}
	for _, tt := range tests {
		if got := widenSeq(tt.wire, tt.ref); got != tt.want {
			t.Errorf("widenSeq(%d, %#x) = %#x, want %#x", tt.wire, tt.ref, got, tt.want)
		}
	}
}

func TestWidenTicks(t *testing.T) {
	tests := []struct {
		wire uint32
		ref  int64
		want int64
	}{
		{1000, 1000, 1000},
		{0, 0xFFFFFFFF, 0x1_0000_0000},          // forward across the 32-bit wrap
		{0xFFFFFFFF, 0x1_0000_0000, 0xFFFFFFFF}, // backward across the wrap
	}
	for _, tt := range tests {
		if got := widenTicks(tt.wire, tt.ref); got != tt.want {
			t.Errorf("widenTicks(%d, %#x) = %#x, want %#x", tt.wire, tt.ref, got, tt.want)
		}
	}
}

func TestWidenSeqAtMost(t *testing.T) {
	// NACK widening: resolve a 16-bit seq to the value at-most the send
	// position (ref), addressing the full 2^16 ring.
	tests := []struct {
		wire uint16
		ref  uint32
		want uint32
	}{
		{100, 300, 100},            // same epoch, below ref
		{300, 300, 300},            // equal to ref
		{0x012D, 0x1_012C, 0x012D}, // 301 just above ref's low16 -> previous epoch
		{0xFFFF, 0x1_0005, 0xFFFF}, // previous epoch across the wrap
		{5, 0x1_0005, 0x1_0005},    // current epoch
		{6, 0x1_0005, 6},           // just above ref -> previous epoch
	}
	for _, tt := range tests {
		if got := widenSeqAtMost(tt.wire, tt.ref); got != tt.want {
			t.Errorf("widenSeqAtMost(%d, %#x) = %#x, want %#x", tt.wire, tt.ref, got, tt.want)
		}
	}
}

func TestEncodeDecodeFeedbackRoundTrip(t *testing.T) {
	fbs := []wire.Feedback{
		wire.NackRequest{SSRC: 0x1234_5678, Missing: []uint32{100, 101, 200}},
		wire.RttEchoRequest{Timestamp: 0xDEAD_BEEF},
	}
	lead := rtcp.EmptyReceiverReport{SSRC: 0x1234_5678}
	b, err := encodeFeedback(nil, lead, 0x1234_5678, "cam", fbs, false)
	if err != nil {
		t.Fatalf("encodeFeedback: %v", err)
	}
	// NACK seqs are widened to at-most the sender's send position; the sender
	// has sent past 200 here, so all three resolve in the current epoch.
	out, err := decodeFeedback(b, 300)
	if err != nil {
		t.Fatalf("decodeFeedback: %v", err)
	}

	var gotNack *wire.NackRequest
	var gotEcho bool
	for _, fb := range out {
		switch f := fb.(type) {
		case wire.NackRequest:
			n := f
			gotNack = &n
		case wire.RttEchoRequest:
			if f.Timestamp == 0xDEAD_BEEF {
				gotEcho = true
			}
		}
	}
	if gotNack == nil {
		t.Fatal("NACK not round-tripped")
	}
	if len(gotNack.Missing) != 3 || gotNack.Missing[0] != 100 || gotNack.Missing[2] != 200 {
		t.Fatalf("NACK missing = %v, want [100 101 200]", gotNack.Missing)
	}
	if !gotEcho {
		t.Fatal("echo request not round-tripped")
	}
}

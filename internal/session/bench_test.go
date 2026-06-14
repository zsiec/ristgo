package session

import (
	"testing"

	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/wire"
)

// benchPacket is a representative RIST media packet (1316-byte payload, even
// SSRC).
func benchPacket() wire.MediaPacket {
	return wire.MediaPacket{
		Seq:        0x1234,
		SourceTime: srcNTP(1_000_000),
		SSRC:       0x0ACE_0AC0,
		Payload:    make([]byte, 1316),
	}
}

// TestEncodeMediaZeroAlloc gates the send-side codec hot path: encoding into a
// reused buffer (as the session does with mediaBuf) must not allocate.
func TestEncodeMediaZeroAlloc(t *testing.T) {
	pkt := benchPacket()
	buf := make([]byte, 0, 2048)
	allocs := testing.AllocsPerRun(1000, func() {
		out, err := encodeMedia(buf[:0], pkt)
		if err != nil {
			t.Fatal(err)
		}
		buf = out
	})
	if allocs != 0 {
		t.Errorf("encodeMedia into a reused buffer allocates %v/op, want 0", allocs)
	}
}

// TestDecodeMediaZeroAlloc gates the receive-side codec hot path: decoding is
// zero-copy (the payload aliases the input), so steady-state decode allocates
// nothing.
func TestDecodeMediaZeroAlloc(t *testing.T) {
	var dec mediaDecoder
	enc, err := encodeMedia(nil, benchPacket())
	if err != nil {
		t.Fatal(err)
	}
	dec.decode(enc) // anchor the decoder
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := dec.decode(enc); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("steady-state decode allocates %v/op, want 0", allocs)
	}
}

func BenchmarkEncodeMedia(b *testing.B) {
	pkt := benchPacket()
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := encodeMedia(buf[:0], pkt)
		if err != nil {
			b.Fatal(err)
		}
		buf = out
	}
}

func BenchmarkDecodeMedia(b *testing.B) {
	var dec mediaDecoder
	enc, err := encodeMedia(nil, benchPacket())
	if err != nil {
		b.Fatal(err)
	}
	dec.decode(enc)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.decode(enc); err != nil {
			b.Fatal(err)
		}
	}
}

// TestEncodeMainMediaZeroAlloc gates the Main-profile media encode path —
// cleartext and PSK-encrypted — at zero steady-state allocations into a reused
// buffer. Unlike the Simple path it was previously allocating 1 (cleartext) to
// 3 (encrypted) buffers per packet; the codec now reuses scratch buffers.
func TestEncodeMainMediaZeroAlloc(t *testing.T) {
	pkt := benchPacket()
	dst := make([]byte, 0, 2048)

	run := func(name string, c *mainCodec) {
		for i := 0; i < 4; i++ { // warm the scratch buffers
			out, err := c.encodeMainMedia(dst[:0], pkt)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			dst = out
		}
		allocs := testing.AllocsPerRun(1000, func() {
			out, err := c.encodeMainMedia(dst[:0], pkt)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			dst = out
		})
		if allocs != 0 {
			t.Errorf("%s Main encode allocates %v/op, want 0", name, allocs)
		}
	}

	run("cleartext", newMainCodec(nil, nil, false, 1971, 1968, false, 0x0ACE_0AC0, "x", false))

	key, err := crypto.NewKey([]byte("a-shared-secret"), crypto.KeySize128, 0, false)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	run("encrypted", newMainCodec(key, nil, true, 1971, 1968, false, 0x0ACE_0AC0, "x", false))
}

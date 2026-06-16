package session

import (
	"bytes"
	"testing"

	"github.com/zsiec/ristgo/internal/wire"
)

// TestFECPayloadCanonicalizesNullsForReceiver verifies the TR-06-2 §8.6.2 invariant:
// with null-packet deletion active, the payload the sender feeds to FEC must equal
// the payload the receiver decodes after NPD expansion, so FEC reconstructs exactly
// the bytes the receiver delivers even when the original null packet was
// non-canonical (PID 0x1FFF but a non-0xFF body).
func TestFECPayloadCanonicalizesNullsForReceiver(t *testing.T) {
	const ssrc = 0x00FECA00
	enc, dec := newCodecPair(t, 0, true, ssrc) // NPD on

	// media, NON-canonical null (PID 0x1FFF, 0x5A body), media.
	payload := tsPacket(188, 0x101, 0xBB)
	payload = append(payload, tsPacket(188, 0x1FFF, 0x5A)...)
	payload = append(payload, tsPacket(188, 0x102, 0xCC)...)

	pkt := wire.MediaPacket{
		Seq:        1,
		SourceTime: mainSrcNTP(2_000_000),
		SSRC:       ssrc,
		Payload:    append([]byte(nil), payload...),
	}

	// Sender's FEC input (canonicalized per §8.6.2).
	fecIn := append([]byte(nil), enc.fecPayload(pkt.Payload)...)

	// Receiver's decoded payload (canonical after NPD expansion).
	dg, err := enc.encodeMainMedia(nil, pkt)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, _ := mustMedia(t, dec, dg)

	if !bytes.Equal(fecIn, got.Payload) {
		t.Fatalf("fecPayload != receiver payload (NPD canonicalization broken)\n fecIn: % x\n recv:  % x", fecIn, got.Payload)
	}
	if bytes.Equal(fecIn, payload) {
		t.Fatal("fecPayload returned the raw payload; the non-canonical null was not canonicalized")
	}
}

// TestFECPayloadNoOpWithoutNPD confirms fecPayload is a pass-through when NPD is off,
// so the non-NPD FEC path is unchanged.
func TestFECPayloadNoOpWithoutNPD(t *testing.T) {
	const ssrc = 0x00FECB00
	enc, _ := newCodecPair(t, 0, false, ssrc) // NPD off
	payload := tsPacket(188, 0x101, 0xBB)
	if got := enc.fecPayload(payload); !bytes.Equal(got, payload) {
		t.Fatalf("fecPayload mutated the payload with NPD off:\n got:  % x\n want: % x", got, payload)
	}
}

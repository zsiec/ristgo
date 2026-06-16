package session

import (
	"bytes"
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/gre"
	"github.com/zsiec/ristgo/internal/npd"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/wire"
)

// mainSrcNTP builds the NTP-64 source time for a microsecond instant (the same
// helper the Simple codec tests use, renamed to avoid a redeclaration).
func mainSrcNTP(us int64) uint64 {
	return uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(us)))
}

// pskPair constructs a matched send Key / receive Decryptor for a passphrase
// and key size, plus the keySize256 flag the codec needs. odd is false (the
// even passphrase), matching a single-direction test flow.
func pskPair(t *testing.T, secret string, keyBits int) (*crypto.Key, *crypto.Decryptor, bool) {
	t.Helper()
	k, err := crypto.NewKey([]byte(secret), keyBits, 0, false)
	if err != nil {
		t.Fatalf("crypto.NewKey: %v", err)
	}
	d, err := crypto.NewDecryptor([]byte(secret), keyBits)
	if err != nil {
		t.Fatalf("crypto.NewDecryptor: %v", err)
	}
	return k, d, keyBits == crypto.KeySize256
}

// newCodecPair builds a send-side and receive-side mainCodec for a round-trip
// test. The encryption mode is selected by keyBits (0 disables PSK); npdEnabled
// applies to the send side only (decode auto-detects the extension).
func newCodecPair(t *testing.T, keyBits int, npdEnabled bool, ssrc uint32) (enc, dec *mainCodec) {
	t.Helper()
	if keyBits == 0 {
		enc = newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, npdEnabled, ssrc, "cam", false)
		dec = newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, ssrc, "cam", false)
		return enc, dec
	}
	sk, _, k256 := pskPair(t, "s3cr3t", keyBits)
	// Encoder owns the send Key; decoder owns a Decryptor on the same secret.
	_, rd, _ := pskPair(t, "s3cr3t", keyBits)
	enc = newMainCodec(sk, nil, k256, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, npdEnabled, ssrc, "cam", false)
	dec = newMainCodec(nil, rd, k256, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, ssrc, "cam", false)
	return enc, dec
}

// tsPacket builds a non-null 188- or 204-byte MPEG-TS packet with PID pid.
func tsPacket(size int, pid uint16, fill byte) []byte {
	p := make([]byte, size)
	p[0] = 0x47
	p[1] = byte(pid>>8) & 0x1F
	p[2] = byte(pid)
	p[3] = 0x10 // payload only
	for i := 4; i < size; i++ {
		p[i] = fill
	}
	return p
}

// tsNull builds a 188- or 204-byte MPEG-TS null packet (PID 0x1FFF), matching
// what npd.Expand reconstructs so a suppressed/expanded payload compares equal.
func tsNull(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x47
	p[1] = 0x1F
	p[2] = 0xFF
	p[3] = 1 << 4
	for i := 4; i < size; i++ {
		p[i] = 0xFF
	}
	return p
}

// TestGoldenMainMediaDatagram pins one full Main-profile media datagram
// byte-for-byte (PSK off, no NPD), hand-derived from the GRE/reduced/RTP wire
// formats so the framing is fixed independent of interop:
//
//	GRE   : 10 08 88 b6 00 00 00 00   flags1=S, flags2=ver1, proto=REDUCED, seq=0
//	reduced: 07 b3 07 b0              src=1971, dst=1968
//	RTP   : 80 21 12 34 00 00 00 00   V=2, PT=33, seq=0x1234, ts=0
//	        0a ce 0a c0               SSRC=0x0ACE0AC0
//	        de ad be ef               payload
func TestGoldenMainMediaDatagram(t *testing.T) {
	c := newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, 0x0ACE0AC0, "cam", false)
	pkt := wire.MediaPacket{
		Seq:        0x1234,
		SourceTime: mainSrcNTP(0),
		SSRC:       0x0ACE0AC0,
		Payload:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	got, err := c.encodeMainMedia(nil, pkt)
	if err != nil {
		t.Fatalf("encodeMainMedia: %v", err)
	}
	want := []byte{
		0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00, // GRE
		0x07, 0xB3, 0x07, 0xB0, // reduced 1971/1968
		0x80, 0x21, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, // RTP hdr
		0x0A, 0xCE, 0x0A, 0xC0, // SSRC
		0xDE, 0xAD, 0xBE, 0xEF, // payload
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden datagram mismatch\n got: % x\nwant: % x", got, want)
	}
}

// TestMainMediaRoundTrip walks a media packet through encode -> decode under
// each PSK mode and each NPD mode, checking Seq/SourceTime/SSRC/Payload/
// Retransmit survive. The 90 kHz quantization of SourceTime is tolerated by
// comparing the decoder's own reconstruction against a reference decode.
func TestMainMediaRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		keyBits int
		npd     bool
	}{
		{"clear", 0, false},
		{"clear+npd", 0, true},
		{"aes128", crypto.KeySize128, false},
		{"aes128+npd", crypto.KeySize128, true},
		{"aes256", crypto.KeySize256, false},
		{"aes256+npd", crypto.KeySize256, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const ssrc = 0x0BAD_F00E // even base SSRC
			enc, dec := newCodecPair(t, tc.keyBits, tc.npd, ssrc)

			// Payload: a non-null TS packet followed by a null one. With NPD
			// on this exercises suppression+expansion; with NPD off it rides
			// through verbatim.
			//
			// Seq high bits are zero here: without the NPD media-path EXTSEQ a
			// single first packet's 32-bit sequence is anchored at its low 16
			// bits (rollover counting starts at 0), exactly as the Simple
			// profile widens. The non-zero-high-bits case is exercised in
			// TestMainMediaSeqWrapEXTSEQ, which requires NPD's EXTSEQ.
			payload := append(tsPacket(188, 0x100, 0xAA), tsNull(188)...)
			pkt := wire.MediaPacket{
				Seq:        0x2345,
				SourceTime: mainSrcNTP(1_000_000),
				SSRC:       ssrc,
				Payload:    append([]byte(nil), payload...),
			}
			dg, err := enc.encodeMainMedia(nil, pkt)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			isMedia, got, _, _, err := dec.decodeMain(dg, 0)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !isMedia {
				t.Fatal("decoded as feedback, want media")
			}
			if got.Seq != pkt.Seq {
				t.Errorf("Seq = %#x, want %#x", got.Seq, pkt.Seq)
			}
			if got.SSRC != ssrc {
				t.Errorf("SSRC = %#x, want %#x", got.SSRC, ssrc)
			}
			if got.Retransmit {
				t.Error("Retransmit set on a first transmission")
			}
			if !bytes.Equal(got.Payload, payload) {
				t.Errorf("payload mismatch\n got: % x\nwant: % x", got.Payload, payload)
			}
		})
	}
}

// TestMainMediaSeqWrapRollover checks that the 32-bit media sequence is
// reconstructed by 16-bit rollover counting — NOT from the NPD extension's
// seq_ext, which libRIST never populates on the Main path.
// A stream crossing the 0xFFFF->0 boundary must widen monotonically, the high
// bits are anchored at 0 on the first packet (receiver-relative, exactly like
// the Simple codec), and the bogus high bits placed in pkt.Seq must be ignored
// on both encode (seq_ext is written 0) and decode — proving the seq_ext-based
// widening that a libRIST peer would break has been removed.
func TestMainMediaSeqWrapRollover(t *testing.T) {
	const ssrc = 0x00CA_FE00
	enc, dec := newCodecPair(t, 0, true, ssrc) // NPD on so the extension is present

	lows := []uint16{0xFFFD, 0xFFFE, 0xFFFF, 0x0000, 0x0001, 0x0002}
	var prev uint32
	for i, low := range lows {
		payload := append(tsPacket(188, 0x101, 0xBB), tsNull(188)...)
		pkt := wire.MediaPacket{
			Seq:        0x0003_0000 | uint32(low), // bogus high bits; must be ignored
			SourceTime: mainSrcNTP(2_000_000 + int64(i)*1000),
			SSRC:       ssrc,
			Payload:    append([]byte(nil), payload...),
		}
		dg, err := enc.encodeMainMedia(nil, pkt)
		if err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
		got, _ := mustMedia(t, dec, dg)
		if !bytes.Equal(got.Payload, payload) {
			t.Fatalf("payload[%d] mismatch after NPD expand\n got: % x\nwant: % x", i, got.Payload, payload)
		}
		if i == 0 {
			if got.Seq != uint32(low) { // first packet: high bits anchored at 0, not 3
				t.Fatalf("first Seq = %#x, want %#x (seq_ext must be ignored)", got.Seq, uint32(low))
			}
		} else if got.Seq != prev+1 {
			t.Fatalf("Seq[%d] = %#x, want %#x (monotonic rollover across wrap)", i, got.Seq, prev+1)
		}
		prev = got.Seq
	}
	if prev>>16 != 1 {
		t.Fatalf("high bits after the 0xFFFF wrap = %d, want 1 (final Seq %#x)", prev>>16, prev)
	}
}

// TestMainRetransmitDedup confirms a retransmit and its original reconstruct to
// the identical (Seq, SourceTime) so the flow core's duplicate test fires, just
// as the Simple codec guarantees. Tested with NPD off (the no-extension
// rollover path).
func TestMainRetransmitDedup(t *testing.T) {
	const ssrc = 0x0042_0042
	enc, dec := newCodecPair(t, 0, false, ssrc)

	orig := wire.MediaPacket{Seq: 500, SourceTime: mainSrcNTP(5_000_000), SSRC: ssrc, Payload: []byte{1, 2, 3}}
	dg0, _ := enc.encodeMainMedia(nil, orig)
	d0, _ := mustMedia(t, dec, dg0)

	// Advance the decoder's reference with a few later packets.
	for i := uint32(1); i <= 5; i++ {
		b, _ := enc.encodeMainMedia(nil, wire.MediaPacket{Seq: 500 + i, SourceTime: mainSrcNTP(5_000_000 + int64(i)*1000), SSRC: ssrc, Payload: []byte{byte(i)}})
		mustMedia(t, dec, b)
	}

	rt := orig
	rt.Retransmit = true
	dgRT, _ := enc.encodeMainMedia(nil, rt)
	dR, _ := mustMedia(t, dec, dgRT)

	if dR.Seq != d0.Seq || dR.SourceTime != d0.SourceTime {
		t.Fatalf("retransmit (%d,%d) != original (%d,%d) — dedup would fail", dR.Seq, dR.SourceTime, d0.Seq, d0.SourceTime)
	}
	if !dR.Retransmit {
		t.Fatal("retransmit flag lost (SSRC LSB not detected)")
	}
}

// mustMedia decodes b and fails unless it is a media packet.
func mustMedia(t *testing.T, c *mainCodec, b []byte) (wire.MediaPacket, []wire.Feedback) {
	t.Helper()
	isMedia, pkt, fbs, _, err := c.decodeMain(b, 0)
	if err != nil {
		t.Fatalf("decodeMain: %v", err)
	}
	if !isMedia {
		t.Fatalf("decoded as feedback, want media")
	}
	return pkt, fbs
}

// TestMainFeedbackRoundTrip walks NACK (range and bitmask) and echo
// request/response through encode -> decode under PSK off and on.
func TestMainFeedbackRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		keyBits int
		bitmask bool
	}{
		{"clear-range", 0, false},
		{"clear-bitmask", 0, true},
		{"aes128-range", crypto.KeySize128, false},
		{"aes256-bitmask", crypto.KeySize256, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const ssrc = 0x1234_5678
			enc, dec := newCodecPair(t, tc.keyBits, false, ssrc)

			fbs := []wire.Feedback{
				wire.NackRequest{SSRC: ssrc, Missing: []uint32{100, 101, 200}},
				wire.RttEchoRequest{Timestamp: 0xDEAD_BEEF_0000_0001},
				wire.RttEchoResponse{Timestamp: 0xCAFE_0000_0000_0002, ProcessingDelay: 250},
			}
			lead := rtcp.EmptyReceiverReport{SSRC: ssrc}
			dg, err := enc.encodeMainFeedback(nil, lead, fbs, tc.bitmask)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			// nackRef is the sender's send position (past 200) so the no-EXTSEQ
			// NACK widening resolves in the current epoch. The host supplies it;
			// the media decoder's reference is meaningless on the side that
			// receives NACKs (which never decodes inbound media).
			isMedia, _, out, _, err := dec.decodeMain(dg, 300)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if isMedia {
				t.Fatal("decoded as media, want feedback")
			}

			var nack *wire.NackRequest
			var gotReq, gotResp bool
			for _, fb := range out {
				switch f := fb.(type) {
				case wire.NackRequest:
					n := f
					nack = &n
				case wire.RttEchoRequest:
					gotReq = f.Timestamp == 0xDEAD_BEEF_0000_0001
				case wire.RttEchoResponse:
					gotResp = f.Timestamp == 0xCAFE_0000_0000_0002 && f.ProcessingDelay == 250
				}
			}
			if nack == nil || len(nack.Missing) != 3 || nack.Missing[0] != 100 || nack.Missing[2] != 200 {
				t.Fatalf("NACK = %v, want [100 101 200]", nack)
			}
			if !gotReq {
				t.Error("echo request not round-tripped")
			}
			if !gotResp {
				t.Error("echo response not round-tripped")
			}
		})
	}
}

// TestMainNackEXTSEQ exercises the feedback-path EXTSEQ APP packet: a NACK
// whose Missing sequences straddle a 16-bit rollover is split by upper half,
// each group preceded by its own EXTSEQ, and the decode side folds the high
// bits back into the 32-bit Missing values.
func TestMainNackEXTSEQ(t *testing.T) {
	const ssrc = 0xDEAD_BEEE
	enc, dec := newCodecPair(t, 0, false, ssrc)

	want := []uint32{0x0002_FFFE, 0x0002_FFFF, 0x0003_0000, 0x0003_0001, 0x0003_0010}
	fbs := []wire.Feedback{wire.NackRequest{SSRC: ssrc, Missing: append([]uint32(nil), want...)}}
	dg, err := enc.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: ssrc}, fbs, false)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	isMedia, _, out, _, err := dec.decodeMain(dg, 0)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if isMedia {
		t.Fatal("decoded as media, want feedback")
	}

	var got []uint32
	for _, fb := range out {
		if n, ok := fb.(wire.NackRequest); ok {
			got = append(got, n.Missing...)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("widened seqs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("widened[%d] = %#x, want %#x (all: %v)", i, got[i], want[i], got)
		}
	}
}

// TestMainPTDemux confirms the payload-type-byte demux: a media datagram routes
// to media, an RTCP datagram to feedback, regardless of the reduced-header
// ports (which carry the configured virtual ports either way).
func TestMainPTDemux(t *testing.T) {
	const ssrc = 0x0001_0002
	enc, dec := newCodecPair(t, 0, false, ssrc)

	media, _ := enc.encodeMainMedia(nil, wire.MediaPacket{Seq: 7, SourceTime: mainSrcNTP(0), SSRC: ssrc, Payload: []byte{9}})
	if isMedia, _, _, _, err := dec.decodeMain(media, 0); err != nil || !isMedia {
		t.Fatalf("media datagram: isMedia=%v err=%v", isMedia, err)
	}

	fb, _ := enc.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: ssrc}, []wire.Feedback{wire.RttEchoRequest{Timestamp: 1}}, false)
	if isMedia, _, _, _, err := dec.decodeMain(fb, 0); err != nil || isMedia {
		t.Fatalf("feedback datagram: isMedia=%v err=%v", isMedia, err)
	}
}

// TestMainEncryptedNeedsDecryptor pins the encrypted-without-decryptor guard: an
// encrypted (K-bit) datagram with no decryptor configured errors rather than
// mis-decoding garbage.
func TestMainEncryptedNeedsDecryptor(t *testing.T) {
	const ssrc = 0x5
	sk, _, k256 := pskPair(t, "k", crypto.KeySize128)
	enc := newMainCodec(sk, nil, k256, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, ssrc, "c", false)
	plainDec := newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, ssrc, "c", false)

	dg, _ := enc.encodeMainMedia(nil, wire.MediaPacket{Seq: 1, SourceTime: mainSrcNTP(0), SSRC: ssrc, Payload: []byte{1}})
	if _, _, _, _, err := plainDec.decodeMain(dg, 0); err == nil {
		t.Fatal("encrypted datagram decoded without a decryptor, want error")
	}
}

// TestMainCleartextAcceptedWithDecryptor pins the per-packet K-bit rule: a
// cleartext (no K-bit) datagram is decoded as cleartext even when a decryptor is
// configured, matching libRIST, which keys per-packet on the GRE K bit
// (CHECK_BIT(gre->flags1,5)) — the EAP-SRP use_key_as_passphrase mode sends
// cleartext media while a decryptor for the encrypted feedback direction is
// installed.
func TestMainCleartextAcceptedWithDecryptor(t *testing.T) {
	const ssrc = 0x5
	plainEnc := newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, ssrc, "c", false)
	_, rd, _ := pskPair(t, "k", crypto.KeySize128)
	cipherDec := newMainCodec(nil, rd, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, ssrc, "c", false)
	dg2, _ := plainEnc.encodeMainMedia(nil, wire.MediaPacket{Seq: 1, SourceTime: mainSrcNTP(0), SSRC: ssrc, Payload: []byte{0xAB}})
	isMedia, pkt, _, _, err := cipherDec.decodeMain(dg2, 0)
	if err != nil || !isMedia {
		t.Fatalf("cleartext datagram with decryptor: isMedia=%v err=%v, want cleartext media decode", isMedia, err)
	}
	if len(pkt.Payload) != 1 || pkt.Payload[0] != 0xAB {
		t.Fatalf("cleartext payload mis-decoded: %x", pkt.Payload)
	}
}

// TestMainGreSeqIncrements verifies the GRE sequence counter advances once per
// datagram (media or feedback), which both drives the AES IV and the GRE-layer
// sequence.
func TestMainGreSeqIncrements(t *testing.T) {
	c := newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, 1, "c", false)
	seqOf := func(b []byte) uint32 {
		h, _, err := gre.Parse(b)
		if err != nil {
			t.Fatalf("gre.Parse: %v", err)
		}
		return h.Seq
	}
	m0, _ := c.encodeMainMedia(nil, wire.MediaPacket{Seq: 1, SourceTime: mainSrcNTP(0), SSRC: 1, Payload: []byte{1}})
	f1, _ := c.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: 1}, nil, false)
	m2, _ := c.encodeMainMedia(nil, wire.MediaPacket{Seq: 2, SourceTime: mainSrcNTP(0), SSRC: 1, Payload: []byte{2}})
	if a, b, d := seqOf(m0), seqOf(f1), seqOf(m2); a != 0 || b != 1 || d != 2 {
		t.Fatalf("GRE seqs = %d,%d,%d, want 0,1,2", a, b, d)
	}
}

// TestMainNPDFallback confirms that with NPD enabled, a payload that is not a
// whole number of TS packets (or has no null packets) is sent without the
// extension and still round-trips, matching libRIST's "attach only when
// suppression fired" rule.
func TestMainNPDFallback(t *testing.T) {
	const ssrc = 0x9
	enc, dec := newCodecPair(t, 0, true, ssrc)

	// Not a multiple of 188/204: NPD does not apply.
	odd := bytes.Repeat([]byte{0x55}, 100)
	dg, err := enc.encodeMainMedia(nil, wire.MediaPacket{Seq: 1, SourceTime: mainSrcNTP(0), SSRC: ssrc, Payload: odd})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	isMedia, m, _, _, err := dec.decodeMain(dg, 0)
	if err != nil || !isMedia {
		t.Fatalf("decode: media=%v err=%v", isMedia, err)
	}
	if !bytes.Equal(m.Payload, odd) {
		t.Fatalf("payload mismatch\n got: % x\nwant: % x", m.Payload, odd)
	}
}

// TestMainDecodeShortInputs checks that truncated framing at each layer returns
// an error and never panics.
func TestMainDecodeShortInputs(t *testing.T) {
	c := newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, 1, "c", false)
	cases := [][]byte{
		nil,
		{0x10}, // short GRE
		{0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00},                                           // GRE seq truncated
		{0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00},                                     // no reduced header
		{0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00, 0x07, 0xB3},                         // reduced truncated
		{0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00, 0x07, 0xB3, 0x07, 0xB0},             // empty inner
		{0x10, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0xB3, 0x07, 0xB0, 0x80, 0x21}, // wrong proto
	}
	for i, b := range cases {
		if _, _, _, _, err := c.decodeMain(b, 0); err == nil {
			t.Errorf("case %d: decodeMain(% x) = nil error, want error", i, b)
		}
	}
}

// FuzzDecodeMain asserts decodeMain never panics on arbitrary bytes, with and
// without a configured decryptor. Anything it accepts as media or feedback is
// well-formed enough that re-decoding does not crash.
func FuzzDecodeMain(f *testing.F) {
	// Seed with valid datagrams of every shape.
	clear := newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, true, 0x2, "c", false)
	seedPkts := []wire.MediaPacket{
		{Seq: 1, SourceTime: mainSrcNTP(0), SSRC: 0x2, Payload: []byte{1, 2, 3}},
		{Seq: 0x0003_0001, SourceTime: mainSrcNTP(0), SSRC: 0x2, Payload: append(tsPacket(188, 0x100, 0xAA), tsNull(188)...)},
	}
	for _, p := range seedPkts {
		if b, err := clear.encodeMainMedia(nil, p); err == nil {
			f.Add(b)
		}
	}
	if b, err := clear.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: 0x2}, []wire.Feedback{
		wire.NackRequest{SSRC: 0x2, Missing: []uint32{1, 2, 0x0003_0000}},
		wire.RttEchoRequest{Timestamp: 9},
	}, false); err == nil {
		f.Add(b)
	}
	f.Add([]byte(nil))
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		// Plain decoder: must not panic.
		plain := newMainCodec(nil, nil, false, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, 0x2, "c", false)
		_, _, _, _, _ = plain.decodeMain(b, 0)
		_, _, _, _ = plain.peekOOB(b) // tunnel-type demux must not panic on arbitrary input

		// Encrypting decoder: must not panic on arbitrary ciphertext either.
		_, rd, k256 := pskPair(t, "fuzz", crypto.KeySize128)
		cipher := newMainCodec(nil, rd, k256, gre.DefaultVirtSrcPort, gre.DefaultVirtDstPort, false, 0x2, "c", false)
		_, _, _, _, _ = cipher.decodeMain(b, 0)
		_, _, _, _ = cipher.peekOOB(b)
	})
}

// TestMainExtPayloadBridge sanity-checks the npd.Ext <-> RTP-extension-payload
// bridge helpers used by the media path: appendExtPayload drops the leading
// identifier+length, and extWireBytes restores them so npd.ParseExt accepts the
// result.
func TestMainExtPayloadBridge(t *testing.T) {
	ext := npd.Ext{NPD: true, Size204: true, NullBitmap: 0x42, SeqExt: 0xBEEF}
	payload := appendExtPayload(nil, ext)
	if len(payload) != npd.ExtSize-4 {
		t.Fatalf("ext payload = %d bytes, want %d", len(payload), npd.ExtSize-4)
	}
	got, _, err := npd.ParseExt(extWireBytes(npd.Identifier, payload))
	if err != nil {
		t.Fatalf("ParseExt: %v", err)
	}
	if got != ext {
		t.Fatalf("ext round-trip %+v != %+v", got, ext)
	}
}

// TestDecodeMainVSFWrapper verifies the Main decoder unwraps the version-2 VSF
// proto: a VSF-wrapped REDUCED media datagram decodes as media, and a
// keepalive/buffer-negotiation subtype is accepted (no error, not media)
// instead of being dropped as an undecodable "want reduced" datagram.
func TestDecodeMainVSFWrapper(t *testing.T) {
	const ssrc = 0x0BAD_F00E
	enc, dec := newCodecPair(t, 0, false, ssrc) // cleartext

	// Encode a normal (v1, reduced) media datagram, then rewrap it as a v2 VSF
	// REDUCED datagram by splicing the 4-byte VSF proto after the GRE header.
	pkt := wire.MediaPacket{Seq: 0x2345, SourceTime: mainSrcNTP(1_000_000), SSRC: ssrc, Payload: tsPacket(188, 0x100, 0xAA)}
	dg, err := enc.encodeMainMedia(nil, pkt)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	hdr, off, err := gre.Parse(dg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	hdr.ProtType = gre.ProtoVSF
	hdr.Version = 2
	wrapped, _ := hdr.AppendTo(nil)
	wrapped = gre.VSFProto{Type: gre.VSFTypeRIST, Subtype: gre.VSFSubtypeReduced}.AppendTo(wrapped)
	wrapped = append(wrapped, dg[off:]...)
	isMedia, got, _, _, err := dec.decodeMain(wrapped, 0)
	if err != nil {
		t.Fatalf("decode VSF-reduced: %v", err)
	}
	if !isMedia || got.Seq != pkt.Seq {
		t.Fatalf("VSF-reduced decoded as media=%v seq=%#x, want true/%#x", isMedia, got.Seq, pkt.Seq)
	}

	// A keepalive VSF subtype must be accepted (no error), not dropped as
	// undecodable.
	ka, _ := gre.Header{Version: 2, HasSeq: true, ProtType: gre.ProtoVSF}.AppendTo(nil)
	ka = gre.VSFProto{Type: gre.VSFTypeRIST, Subtype: gre.VSFSubtypeKeepalive}.AppendTo(ka)
	ka = append(ka, 0x00, 0x01, 0x02, 0x03) // arbitrary keepalive body
	if isMedia, _, _, _, err := dec.decodeMain(ka, 0); err != nil || isMedia {
		t.Fatalf("VSF keepalive: isMedia=%v err=%v, want (false, nil)", isMedia, err)
	}
}

// TestOOBRoundTrip verifies the out-of-band codec: encodeOOB/peekOOB round-trip
// cleartext and PSK-encrypted, the GRE protocol type (the default FULL and an
// arbitrary tunnelled EtherType) survives the round trip, and a media datagram is
// not misdetected as OOB.
func TestOOBRoundTrip(t *testing.T) {
	// FULL is libRIST's OOB type; 0x86DD (IPv6) stands in for an arbitrary
	// tunnelled protocol a ristgo peer dispatches on.
	for _, proto := range []uint16{gre.ProtoFull, 0x86DD} {
		for _, keyBits := range []int{0, crypto.KeySize128, crypto.KeySize256} {
			enc, dec := newCodecPair(t, keyBits, false, 0x0BAD_F00E)
			payload := []byte("out-of-band control metadata \x00\x01\xff\x47")
			dg, err := enc.encodeOOB(nil, payload, proto)
			if err != nil {
				t.Fatalf("proto=0x%04X keyBits=%d encodeOOB: %v", proto, keyBits, err)
			}
			got, gotProto, ok, err := dec.peekOOB(dg)
			if !ok || err != nil {
				t.Fatalf("proto=0x%04X keyBits=%d peekOOB: ok=%v err=%v", proto, keyBits, ok, err)
			}
			if gotProto != proto {
				t.Fatalf("OOB protocol type round-trip: got 0x%04X want 0x%04X", gotProto, proto)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("proto=0x%04X keyBits=%d OOB round-trip: got %q want %q", proto, keyBits, got, payload)
			}
			// A media datagram must NOT be detected as OOB (it is GRE reduced/VSF).
			md, err := enc.encodeMainMedia(nil, wire.MediaPacket{Seq: 1, SSRC: 0x0BAD_F00E, Payload: tsPacket(188, 0x100, 0xAA)})
			if err != nil {
				t.Fatalf("encodeMainMedia: %v", err)
			}
			if _, _, ok, _ := dec.peekOOB(md); ok {
				t.Fatalf("proto=0x%04X keyBits=%d media datagram misdetected as OOB", proto, keyBits)
			}
		}
	}
}

// TestGREKeepaliveRoundTrip verifies the GRE keepalive codec: a v1 keepalive
// encodes and decodes with its MAC + capability bits (cleartext and encrypted),
// a v2 keepalive's GRE version is reported (for the monotonic upgrade) even
// though its VSF body is decoded by decodeMain, and media is not misdetected.
func TestGREKeepaliveRoundTrip(t *testing.T) {
	for _, keyBits := range []int{0, crypto.KeySize128} {
		enc, dec := newCodecPair(t, keyBits, false, 0x0BAD_F00E)
		ka := gre.Keepalive{MAC: [6]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}, Caps: gre.StandardCapabilities()}

		dg, err := enc.encodeKeepalive(nil, ka, gre.VersionMin)
		if err != nil {
			t.Fatalf("keyBits=%d encodeKeepalive v1: %v", keyBits, err)
		}
		kind, got, ver, err := dec.peekControl(dg)
		if err != nil || kind != controlKeepalive {
			t.Fatalf("keyBits=%d peekControl v1: kind=%v err=%v", keyBits, kind, err)
		}
		if ver != gre.VersionMin {
			t.Fatalf("v1 keepalive version=%d want %d", ver, gre.VersionMin)
		}
		if got.MAC != ka.MAC || got.Caps != ka.Caps {
			t.Fatalf("keepalive mismatch: got %+v want %+v", got, ka)
		}

		// A v2 keepalive reports version 2 (the upgrade signal); its VSF body is
		// decoded by decodeMain, so peekControl returns controlNone here.
		dg2, err := enc.encodeKeepalive(nil, ka, gre.VersionCur)
		if err != nil {
			t.Fatalf("encodeKeepalive v2: %v", err)
		}
		if _, _, ver2, _ := dec.peekControl(dg2); ver2 != gre.VersionCur {
			t.Fatalf("v2 keepalive version=%d want %d", ver2, gre.VersionCur)
		}

		md, _ := enc.encodeMainMedia(nil, wire.MediaPacket{Seq: 1, SSRC: 0x0BAD_F00E, Payload: tsPacket(188, 0x100, 0xAA)})
		if kind, _, _, _ := dec.peekControl(md); kind == controlKeepalive {
			t.Fatal("media datagram misdetected as keepalive")
		}
	}
}

// TestFeedbackCNAMEGate verifies the NAT-rebind trigger gate (mainCodec.feedbackCNAME): it
// returns the CNAME ONLY for an ENCRYPTED RTCP feedback datagram, and rejects cleartext
// feedback, media, and garbage — so a forger with no key (cannot encrypt) or a cleartext
// sender (use_key_as_passphrase media) cannot supply a CNAME to force a re-association.
func TestFeedbackCNAMEGate(t *testing.T) {
	const ssrc = 0x0ACE0AC0

	// Encrypted RTCP feedback carries the CNAME ("cam" per newCodecPair).
	enc, dec := newCodecPair(t, crypto.KeySize128, false, ssrc)
	dg, err := enc.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: ssrc}, nil, false)
	if err != nil {
		t.Fatalf("encodeMainFeedback: %v", err)
	}
	if cname, ok := dec.feedbackCNAME(dg); !ok || cname != "cam" {
		t.Fatalf("encrypted feedback: got (%q,%v), want (\"cam\",true)", cname, ok)
	}

	// Cleartext feedback (no key) must NOT yield a CNAME — a forger could send this.
	cEnc, cDec := newCodecPair(t, 0, false, ssrc)
	cdg, err := cEnc.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: ssrc}, nil, false)
	if err != nil {
		t.Fatalf("cleartext encodeMainFeedback: %v", err)
	}
	if cname, ok := cDec.feedbackCNAME(cdg); ok {
		t.Fatalf("cleartext feedback yielded CNAME %q; it must be rejected (forgeable)", cname)
	}

	// Encrypted media is not RTCP feedback: no SDES, so no CNAME.
	mdg, err := enc.encodeMainMedia(nil, wire.MediaPacket{Seq: 1, SourceTime: mainSrcNTP(0), SSRC: ssrc, Payload: []byte{0xAB, 0xCD}})
	if err != nil {
		t.Fatalf("encodeMainMedia: %v", err)
	}
	if _, ok := dec.feedbackCNAME(mdg); ok {
		t.Fatal("media datagram yielded a CNAME; it must be rejected")
	}

	// Garbage from a forger.
	if _, ok := dec.feedbackCNAME([]byte("not a valid GRE datagram at all")); ok {
		t.Fatal("garbage yielded a CNAME")
	}
}

// TestDecodeMainCNAMEEmission verifies the steady-state CNAME learn path used by the host's
// learnPeerCNAME: decodeMain surfaces a wire.PeerIdentity ONLY from an ENCRYPTED RTCP
// datagram (a cleartext SDES is forgeable and must not populate the rebind identity key) and
// ONLY when the CNAME changes (so the hot RX feedback path allocates nothing per datagram).
func TestDecodeMainCNAMEEmission(t *testing.T) {
	const ssrc = 0x0ACE0AC0

	countCNAME := func(fbs []wire.Feedback) (string, int) {
		n := 0
		last := ""
		for _, fb := range fbs {
			if pi, ok := fb.(wire.PeerIdentity); ok {
				n++
				last = pi.CNAME
			}
		}
		return last, n
	}

	// Encrypted feedback: the FIRST decode surfaces the CNAME, the SECOND (unchanged) does not.
	enc, dec := newCodecPair(t, crypto.KeySize128, false, ssrc)
	dg, err := enc.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: ssrc}, nil, false)
	if err != nil {
		t.Fatalf("encodeMainFeedback: %v", err)
	}
	_, _, fbs, _, err := dec.decodeMain(dg, 0)
	if err != nil {
		t.Fatalf("decodeMain (encrypted, first): %v", err)
	}
	if cn, n := countCNAME(fbs); n != 1 || cn != "cam" {
		t.Fatalf("first encrypted decode: got (%q, %d PeerIdentity), want (\"cam\", 1)", cn, n)
	}
	dg2, err := enc.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: ssrc}, nil, false)
	if err != nil {
		t.Fatalf("encodeMainFeedback 2: %v", err)
	}
	_, _, fbs2, _, err := dec.decodeMain(dg2, 0)
	if err != nil {
		t.Fatalf("decodeMain (encrypted, second): %v", err)
	}
	if _, n := countCNAME(fbs2); n != 0 {
		t.Fatalf("second encrypted decode emitted %d PeerIdentity for an unchanged CNAME; want 0 (no per-datagram alloc)", n)
	}

	// Cleartext feedback: never surfaces a CNAME (forgeable).
	cEnc, cDec := newCodecPair(t, 0, false, ssrc)
	cdg, err := cEnc.encodeMainFeedback(nil, rtcp.EmptyReceiverReport{SSRC: ssrc}, nil, false)
	if err != nil {
		t.Fatalf("cleartext encodeMainFeedback: %v", err)
	}
	_, _, cfbs, _, err := cDec.decodeMain(cdg, 0)
	if err != nil {
		t.Fatalf("decodeMain (cleartext): %v", err)
	}
	if _, n := countCNAME(cfbs); n != 0 {
		t.Fatalf("cleartext decode surfaced %d PeerIdentity; a cleartext SDES must never populate the rebind identity key", n)
	}
}

package session

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/wire"
)

const advTestSecret = "advanced-codec-test-secret"
const advTestSSRC = 0x0ABCDE00 // even base

// advCodecPair builds a sender codec and a matching receiver codec for the given
// encryption/compression options.
func advCodecPair(t *testing.T, encrypt, compress bool) (tx, rx *advCodec) {
	t.Helper()
	var sendKey *crypto.Key
	var recvKey *crypto.Decryptor
	if encrypt {
		var err error
		sendKey, err = crypto.NewKey([]byte(advTestSecret), crypto.KeySize128, 0, false)
		if err != nil {
			t.Fatalf("NewKey: %v", err)
		}
		recvKey, err = crypto.NewDecryptor([]byte(advTestSecret), crypto.KeySize128)
		if err != nil {
			t.Fatalf("NewDecryptor: %v", err)
		}
	}
	tx = newAdvCodec(sendKey, nil, compress, advTestSSRC, 1971, 1968)
	rx = newAdvCodec(nil, recvKey, false, advTestSSRC, 0, 0)
	return tx, rx
}

// mediaPkt builds a MediaPacket with a stable NTP-64 source time derived from a
// microsecond value (so encode/decode reconstructs a stable value).
func mediaPkt(seq uint32, micros int64, payload []byte, retransmit bool) wire.MediaPacket {
	return wire.MediaPacket{
		Seq:        seq,
		SourceTime: uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(micros))),
		SSRC:       advTestSSRC,
		Payload:    payload,
		Retransmit: retransmit,
	}
}

// TestAdvMediaRoundTrip checks the media path encodes and decodes symmetrically
// across all four encryption/compression combinations, preserving the sequence,
// SSRC, payload, and retransmit flag.
func TestAdvMediaRoundTrip(t *testing.T) {
	// A compressible payload so LZ4 actually shrinks it (and the LZ4 path runs).
	compressible := bytes.Repeat([]byte("MPEG-TS-NULL-CELL"), 80)
	combos := []struct {
		name              string
		encrypt, compress bool
		payload           []byte
	}{
		{"clear", false, false, []byte("hello advanced profile media payload")},
		{"aesctr", true, false, []byte("hello advanced profile media payload")},
		{"lz4", false, true, compressible},
		{"aesctr+lz4", true, true, compressible},
	}
	for _, tc := range combos {
		t.Run(tc.name, func(t *testing.T) {
			tx, rx := advCodecPair(t, tc.encrypt, tc.compress)
			payload := append([]byte(nil), tc.payload...)

			b, err := tx.encodeAdvMedia(nil, mediaPkt(1000, 5_000_000, payload, false))
			if err != nil {
				t.Fatalf("encodeAdvMedia: %v", err)
			}
			isMedia, pkt, _, err := rx.decodeAdv(b)
			if err != nil {
				t.Fatalf("decodeAdv: %v", err)
			}
			if !isMedia {
				t.Fatal("decoded as control, want media")
			}
			if pkt.Seq != 1000 {
				t.Fatalf("Seq = %d, want 1000", pkt.Seq)
			}
			if pkt.SSRC != advTestSSRC {
				t.Fatalf("SSRC = %#x, want %#x", pkt.SSRC, uint32(advTestSSRC))
			}
			if pkt.Retransmit {
				t.Fatal("Retransmit set on a first transmission")
			}
			if !bytes.Equal(pkt.Payload, tc.payload) {
				t.Fatalf("payload mismatch:\n got  %x\n want %x", pkt.Payload, tc.payload)
			}
		})
	}
}

// TestAdvFragRoundTrip checks every fragment role survives the encode↔decode of
// the Advanced media path: the wire fragment role maps onto the header F/L bits
// and back, across the encrypted+compressed combinations.
func TestAdvFragRoundTrip(t *testing.T) {
	roles := []wire.FragRole{wire.FragStandalone, wire.FragFirst, wire.FragMiddle, wire.FragLast}
	combos := []struct {
		name              string
		encrypt, compress bool
	}{
		{"clear", false, false},
		{"aesctr", true, false},
		{"aesctr+lz4", true, true},
	}
	for _, combo := range combos {
		for _, role := range roles {
			t.Run(fmt.Sprintf("%s/role%d", combo.name, role), func(t *testing.T) {
				tx, rx := advCodecPair(t, combo.encrypt, combo.compress)
				pkt := mediaPkt(1234, 5_000_000, bytes.Repeat([]byte("frag-payload"), 8), false)
				pkt.Frag = role

				b, err := tx.encodeAdvMedia(nil, pkt)
				if err != nil {
					t.Fatalf("encodeAdvMedia: %v", err)
				}
				isMedia, got, _, err := rx.decodeAdv(b)
				if err != nil || !isMedia {
					t.Fatalf("decodeAdv: media=%v err=%v", isMedia, err)
				}
				if got.Frag != role {
					t.Fatalf("Frag = %d, want %d", got.Frag, role)
				}
				if !bytes.Equal(got.Payload, pkt.Payload) {
					t.Fatal("payload mismatch")
				}
			})
		}
	}
}

// TestFragBitsMapping pins the role↔(F,L) mapping in both directions.
func TestFragBitsMapping(t *testing.T) {
	cases := []struct {
		role        wire.FragRole
		first, last bool
	}{
		{wire.FragStandalone, true, true},
		{wire.FragFirst, true, false},
		{wire.FragMiddle, false, false},
		{wire.FragLast, false, true},
	}
	for _, c := range cases {
		if f, l := fragBits(c.role); f != c.first || l != c.last {
			t.Errorf("fragBits(%d) = (%v,%v), want (%v,%v)", c.role, f, l, c.first, c.last)
		}
		if got := fragRole(c.first, c.last); got != c.role {
			t.Errorf("fragRole(%v,%v) = %d, want %d", c.first, c.last, got, c.role)
		}
	}
}

// TestAdvRetransmitDedupStable checks a retransmit (R flag, same seq + source
// time) reconstructs to the same (Seq, SourceTime) as its original — the flow
// core's dedup invariant — EVEN when the receiver's reconstruction front has
// advanced past a timestamp wrap between the two. The Advanced wire timestamp
// wraps every ~65 ms (libRIST's 2^16 MHz effective rate), so an arrival-anchored
// reconstruction would resolve the late retransmit into a different epoch; the
// sequence-anchored reconstruction (advSourceMicros) keeps it stable.
func TestAdvRetransmitDedupStable(t *testing.T) {
	tx, rx := advCodecPair(t, true, false)
	payload := []byte("retransmit me")

	first, err := tx.encodeAdvMedia(nil, mediaPkt(2048, 9_000_000, payload, false))
	if err != nil {
		t.Fatalf("encode first: %v", err)
	}
	_, p1, _, err := rx.decodeAdv(first)
	if err != nil {
		t.Fatalf("decode first: %v", err)
	}

	// Intervening CBR media advances the receiver's front ~300 ms (several 65 ms
	// timestamp wraps) before the retransmit arrives — the case the old
	// arrival-anchored reconstruction got wrong.
	for i := 1; i <= 60; i++ {
		b, ierr := tx.encodeAdvMedia(nil, mediaPkt(uint32(2048+i), int64(9_000_000+i*5_000), payload, false))
		if ierr != nil {
			t.Fatalf("encode intervening %d: %v", i, ierr)
		}
		if _, _, _, derr := rx.decodeAdv(b); derr != nil {
			t.Fatalf("decode intervening %d: %v", i, derr)
		}
	}

	// Retransmit of the original (byte-identical wire bytes bar the R flag),
	// decoded with the front far ahead. It must reconstruct the same source time.
	again, err := tx.encodeAdvMedia(nil, mediaPkt(2048, 9_000_000, payload, true))
	if err != nil {
		t.Fatalf("encode retransmit: %v", err)
	}
	_, p2, _, err := rx.decodeAdv(again)
	if err != nil {
		t.Fatalf("decode retransmit: %v", err)
	}

	if p1.Seq != p2.Seq || p1.SourceTime != p2.SourceTime {
		t.Fatalf("retransmit not dedup-stable across timestamp wrap: original (%d,%d) vs retransmit (%d,%d)",
			p1.Seq, p1.SourceTime, p2.Seq, p2.SourceTime)
	}
	if p1.Retransmit {
		t.Fatal("first transmission marked Retransmit")
	}
	if !p2.Retransmit {
		t.Fatal("retransmit not marked Retransmit")
	}
}

// TestAdvSeqWidening32 checks the native 32-bit sequence survives across the
// 16-bit boundary with no widening drift (the seq is split low/high and rejoined
// exactly).
func TestAdvSeqWidening32(t *testing.T) {
	tx, rx := advCodecPair(t, false, false)
	for _, seq := range []uint32{0, 0xFFFF, 0x10000, 0x1FFFE, 0xFFFFFFFF, 0xDEADBEEF} {
		b, err := tx.encodeAdvMedia(nil, mediaPkt(seq, 1_000_000, []byte("x"), false))
		if err != nil {
			t.Fatalf("encode seq %#x: %v", seq, err)
		}
		_, pkt, _, err := rx.decodeAdv(b)
		if err != nil {
			t.Fatalf("decode seq %#x: %v", seq, err)
		}
		if pkt.Seq != seq {
			t.Fatalf("seq round-trip: got %#x, want %#x", pkt.Seq, seq)
		}
	}
}

// TestAdvControlRoundTrip checks feedback encodes into Type=Control datagrams and
// decodes back to the original normalized feedback, for both NACK encodings and
// the RTT echo pair.
func TestAdvControlRoundTrip(t *testing.T) {
	tx, rx := advCodecPair(t, false, false)

	t.Run("nack-range", func(t *testing.T) {
		fb := wire.NackRequest{SSRC: advTestSSRC, Missing: []uint32{500, 501, 502, 700}}
		dgs, err := tx.encodeFeedback([]wire.Feedback{fb}, false, 12345)
		if err != nil {
			t.Fatalf("encodeFeedback: %v", err)
		}
		// Two runs -> two range datagrams.
		if len(dgs) != 2 {
			t.Fatalf("got %d datagrams, want 2", len(dgs))
		}
		var got []uint32
		for _, dg := range dgs {
			isMedia, _, fbs, err := rx.decodeAdv(dg)
			if err != nil || isMedia {
				t.Fatalf("decode control: isMedia=%v err=%v", isMedia, err)
			}
			for _, f := range fbs {
				n, ok := f.(wire.NackRequest)
				if !ok {
					t.Fatalf("feedback type %T, want NackRequest", f)
				}
				if n.SSRC != advTestSSRC {
					t.Fatalf("NACK SSRC = %#x", n.SSRC)
				}
				got = append(got, n.Missing...)
			}
		}
		want := []uint32{500, 501, 502, 700}
		if !equalU32(got, want) {
			t.Fatalf("recovered missing = %v, want %v", got, want)
		}
	})

	t.Run("rtt-echo", func(t *testing.T) {
		req := wire.RttEchoRequest{Timestamp: 0xCAFEF00DDEADBEEF}
		resp := wire.RttEchoResponse{Timestamp: 0x1122334455667788, ProcessingDelay: 0x190}
		dgs, err := tx.encodeFeedback([]wire.Feedback{req, resp}, false, 0)
		if err != nil {
			t.Fatalf("encodeFeedback: %v", err)
		}
		if len(dgs) != 2 {
			t.Fatalf("got %d datagrams, want 2", len(dgs))
		}
		_, _, fbs0, err := rx.decodeAdv(dgs[0])
		if err != nil {
			t.Fatal(err)
		}
		if r, ok := fbs0[0].(wire.RttEchoRequest); !ok || r.Timestamp != req.Timestamp {
			t.Fatalf("echo request round-trip: %+v ok=%v", fbs0, ok)
		}
		_, _, fbs1, err := rx.decodeAdv(dgs[1])
		if err != nil {
			t.Fatal(err)
		}
		r, ok := fbs1[0].(wire.RttEchoResponse)
		if !ok || r.Timestamp != resp.Timestamp || r.ProcessingDelay != resp.ProcessingDelay {
			t.Fatalf("echo response round-trip: %+v ok=%v", fbs1, ok)
		}
	})
}

// TestAdvDecodeErrors checks malformed and policy-violating datagrams return an
// error rather than panicking or silently mis-decoding.
func TestAdvDecodeErrors(t *testing.T) {
	_, rx := advCodecPair(t, true, false) // receiver expects encryption

	// Garbage / too short.
	if _, _, _, err := rx.decodeAdv([]byte{0x80, 0x7f}); err == nil {
		t.Fatal("short datagram decoded without error")
	}

	// Cleartext media to an encrypting receiver must error.
	txClear, _ := advCodecPair(t, false, false)
	clear, err := txClear.encodeAdvMedia(nil, mediaPkt(1, 1, []byte("clear"), false))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := rx.decodeAdv(clear); err == nil {
		t.Fatal("cleartext media decoded by an encrypting receiver without error")
	}

	// A fragmented DIRECT packet (only F set) now decodes, carrying its
	// fragment role for the host to reassemble (rather than being rejected).
	frag, err := adv.Build(nil, adv.Params{
		Seq: 1, SSRC: adv.SSRCProtected(advTestSSRC), EncType: adv.TypeDirect,
		FirstFrag: true, LastFrag: false,
	}, []byte("frag"))
	if err != nil {
		t.Fatal(err)
	}
	rxClear := newAdvCodec(nil, nil, false, advTestSSRC, 0, 0)
	isMedia, pkt, _, err := rxClear.decodeAdv(frag)
	if err != nil || !isMedia {
		t.Fatalf("fragmented media: media=%v err=%v, want a clean media decode", isMedia, err)
	}
	if pkt.Frag != wire.FragFirst {
		t.Fatalf("fragmented media Frag = %d, want FragFirst", pkt.Frag)
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDropAdvEchoRequests verifies the Advanced feedback path drops inbound
// RTT-echo requests (so the flow never answers them) while preserving NACKs,
// echo responses, and link-quality reports. ristgo must not answer an Advanced
// RTT-echo request: libRIST's Advanced RTT-echo response handler mis-scales the
// round-trip (>>16 instead of >>32), so a response poisons its last_rtt and
// jams its retransmit re-queue, permanently losing a packet under loss.
func TestDropAdvEchoRequests(t *testing.T) {
	in := []wire.Feedback{
		wire.RttEchoRequest{Timestamp: 1},
		wire.NackRequest{SSRC: 7, Missing: []uint32{1, 2, 3}},
		wire.RttEchoResponse{Timestamp: 2, ProcessingDelay: 3},
		wire.RttEchoRequest{Timestamp: 4},
		wire.LinkQuality{},
	}
	got := dropAdvEchoRequests(in)
	for _, fb := range got {
		if _, isReq := fb.(wire.RttEchoRequest); isReq {
			t.Fatalf("dropAdvEchoRequests left an RttEchoRequest in %#v", got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("kept %d feedback items, want 3 (NACK, echo response, link quality)", len(got))
	}
}

// TestDecodeControlUnsupported verifies the §5.3.10 dispatch: an unrecognized
// control index is surfaced as a wire.UnsupportedControl (so the host originates a
// response), while an inbound Unsupported (0x8020) is absorbed with no signal so a
// response can never loop.
func TestDecodeControlUnsupported(t *testing.T) {
	_, rx := advCodecPair(t, false, false)

	// An unknown CI with a body → one UnsupportedControl echoing the CI + head.
	const unknownCI = 0x7abc
	body := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03}
	fbs, err := rx.decodeControl(adv.BuildControl(nil, unknownCI, body))
	if err != nil {
		t.Fatalf("decodeControl(unknown): %v", err)
	}
	if len(fbs) != 1 {
		t.Fatalf("unknown CI produced %d feedback, want 1", len(fbs))
	}
	u, ok := fbs[0].(wire.UnsupportedControl)
	if !ok {
		t.Fatalf("unknown CI produced %T, want wire.UnsupportedControl", fbs[0])
	}
	if u.CI != unknownCI {
		t.Errorf("UnsupportedControl.CI = %#x, want %#x", u.CI, unknownCI)
	}
	if want := ([6]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}); u.Head != want {
		t.Errorf("UnsupportedControl.Head = % x, want % x", u.Head, want)
	}

	// An inbound Unsupported must NOT yield a signal (no response loop).
	un := adv.BuildUnsupported(nil, adv.Unsupported{ResponderSSRC: 0x55, IncomingCI: unknownCI})
	fbs, err = rx.decodeControl(un)
	if err != nil {
		t.Fatalf("decodeControl(Unsupported): %v", err)
	}
	if len(fbs) != 0 {
		t.Fatalf("inbound Unsupported produced %d feedback, want 0 (no loop)", len(fbs))
	}
}

// TestAdvSendNonceAnnounce verifies the send-side PSK Future Nonce trigger: when
// the Advanced send key rotates to a fresh nonce on a media packet, the codec
// queues exactly one announcement (the new nonce + key size) for the host.
func TestAdvSendNonceAnnounce(t *testing.T) {
	sendKey, err := crypto.NewKey([]byte("rotate-each-packet"), crypto.KeySize128, 1, false)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	c := newAdvCodec(sendKey, nil, false, advTestSSRC, 1971, 1968)
	pkt := wire.MediaPacket{Seq: 1, SSRC: advTestSSRC, Payload: []byte{1, 2, 3, 4}}

	if _, _, ok := c.takeNonceAnnounce(); ok {
		t.Fatal("announce pending before any encode")
	}
	if _, err := c.encodeAdvMedia(nil, pkt); err != nil {
		t.Fatalf("encode #1: %v", err)
	}
	if _, _, ok := c.takeNonceAnnounce(); ok {
		t.Fatal("announce after the first packet (no rotation expected yet)")
	}

	pkt.Seq = 2
	if _, err := c.encodeAdvMedia(nil, pkt); err != nil {
		t.Fatalf("encode #2: %v", err)
	}
	nonce, bits, ok := c.takeNonceAnnounce()
	if !ok {
		t.Fatal("no announcement queued after the key rotated")
	}
	if bits != crypto.KeySize128 {
		t.Errorf("announced key bits = %d, want %d", bits, crypto.KeySize128)
	}
	if nonce == ([crypto.NonceSize]byte{}) {
		t.Error("announced a zero nonce")
	}
	if _, _, ok := c.takeNonceAnnounce(); ok {
		t.Fatal("announcement not cleared after being taken")
	}
}

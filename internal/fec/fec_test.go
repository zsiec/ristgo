package fec

import (
	"bytes"
	"testing"
)

// TestHeaderRoundTrip checks the SMPTE 2022-1 FEC header encodes and decodes
// byte-stably for both dimensions, and that a short buffer is rejected.
func TestHeaderRoundTrip(t *testing.T) {
	for _, h := range []Header{
		{SNBase: 0x1234, LengthRecovery: 1316, PTRecovery: 96, TSRecovery: 0xDEADBEEF, Direction: Column, Offset: 10, NA: 5, SNBaseExt: 0x07},
		{SNBase: 0xFFFF, LengthRecovery: 0, PTRecovery: 0x7F, TSRecovery: 0, Direction: Row, Offset: 1, NA: 10, SNBaseExt: 0xFF},
	} {
		b := h.AppendTo(nil)
		if len(b) != HeaderSize {
			t.Fatalf("encoded header is %d bytes, want %d", len(b), HeaderSize)
		}
		got, off, err := ParseHeader(b)
		if err != nil || off != HeaderSize {
			t.Fatalf("ParseHeader: off=%d err=%v", off, err)
		}
		if got != h {
			t.Fatalf("header round-trip:\n got  %+v\n want %+v", got, h)
		}
		if got.base24() != uint32(h.SNBaseExt)<<16|uint32(h.SNBase) {
			t.Fatalf("base24 = %#x", got.base24())
		}
	}
	if _, _, err := ParseHeader(make([]byte, HeaderSize-1)); err == nil {
		t.Fatal("ParseHeader accepted a short buffer")
	}
}

// mkPayload builds a deterministic, seq-dependent payload of varying length so
// recovery is verifiable and lengthClip/ptClip/tsClip are all exercised.
func mkPayload(s uint32) []byte {
	n := 80 + int(s%40)
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(s) ^ byte(i*7+1)
	}
	return p
}
func mkTS(s uint32) uint32 { return s*160 + 7 }
func mkPT(s uint32) uint8  { return uint8(96 + s%16) } // dynamic RTP PT, < 128

const testPayloadSize = 200

// testSSRC is a fixed SSRC for media fed in the recovery tests (a FEC matrix is
// per-source, so one stable value suffices except where a test varies it on purpose).
const testSSRC = 0x0CAFE17E

// event is one wire datagram in transmission order: a media packet or a FEC packet.
type event struct {
	isFEC bool
	seq   uint32
	fec   []byte
}

// encodeStream pushes n media packets starting at isn through an Encoder and
// returns the interleaved transmission sequence (media + FEC) plus the original
// media payloads keyed by sequence.
func encodeStream(cfg Config, isn uint32, n int) ([]event, map[uint32][]byte) {
	enc := NewEncoder(cfg, testPayloadSize, isn)
	var events []event
	orig := map[uint32][]byte{}
	for i := 0; i < n; i++ {
		s := seqAdd(isn, i)
		p := mkPayload(s)
		orig[s] = p
		events = append(events, event{seq: s})
		for _, fp := range enc.Push(s, mkTS(s), mkPT(s), p) {
			events = append(events, event{isFEC: true, fec: fp.Data})
		}
	}
	return events, orig
}

// replay feeds the transmission sequence through a Decoder, dropping the media
// packets in drop, and returns the set of recovered sequences with their payloads.
func replay(cfg Config, isn int, events []event, drop map[uint32]bool, orig map[uint32][]byte, t *testing.T) map[uint32]bool {
	_ = isn // the decoder is created lazily from the first received media, like the session
	var dec *Decoder
	recovered := map[uint32]bool{}
	for _, e := range events {
		var rs []Recovered
		if e.isFEC {
			if dec != nil {
				rs = dec.PushFEC(e.fec)
			}
		} else if !drop[e.seq] {
			s := e.seq
			if dec == nil {
				dec = NewDecoder(cfg, testPayloadSize, s) // anchor on the first packet that ARRIVES
			}
			rs = dec.PushMedia(s, mkTS(s), mkPT(s), testSSRC, orig[s])
		}
		for _, r := range rs {
			if want := orig[r.Seq]; want != nil {
				if !bytes.Equal(r.Payload, want) {
					t.Fatalf("recovered seq %d payload mismatch:\n got  %x\n want %x", r.Seq, r.Payload, want)
				}
				if r.Timestamp != mkTS(r.Seq) || r.PayloadType != mkPT(r.Seq) {
					t.Fatalf("recovered seq %d header mismatch: ts=%d/%d pt=%d/%d", r.Seq, r.Timestamp, mkTS(r.Seq), r.PayloadType, mkPT(r.Seq))
				}
			}
			recovered[r.Seq] = true
		}
	}
	return recovered
}

// TestColumnOnlyRecoversOnePerColumn drops one packet from each column of a 4x4
// column-only matrix; every drop must be recovered by its column FEC.
func TestColumnOnlyRecoversOnePerColumn(t *testing.T) {
	cfg := Config{Cols: 4, Rows: 4, ColumnOnly: true}
	const isn = 1000
	events, orig := encodeStream(cfg, isn, 64) // 4 matrices
	// Drop the diagonal of the first matrix: seqs isn+0, isn+5, isn+10, isn+15
	// (column 0 row 0, column 1 row 1, ...), one per column and one per row.
	drop := map[uint32]bool{}
	for k := 0; k < 4; k++ {
		drop[seqAdd(isn, k*cfg.Cols+k)] = true
	}
	rec := replay(cfg, isn, events, drop, orig, t)
	for s := range drop {
		if !rec[s] {
			t.Fatalf("column-only FEC failed to recover dropped seq %d", s)
		}
	}
}

// TestTwoDRecoversSingleLoss drops exactly one packet per matrix; 2-D FEC must
// recover each (by row or column).
func TestTwoDRecoversSingleLoss(t *testing.T) {
	cfg := Config{Cols: 5, Rows: 4}
	const isn = 5000
	events, orig := encodeStream(cfg, isn, cfg.matrixSize()*3)
	drop := map[uint32]bool{seqAdd(isn, 7): true} // middle of the first matrix
	rec := replay(cfg, isn, events, drop, orig, t)
	if !rec[seqAdd(isn, 7)] {
		t.Fatal("2-D FEC failed to recover a single loss")
	}
}

// TestTwoDRecursiveRecovery drops a pattern that no single row or column can
// recover alone, but that cascades: recovering one packet by column leaves its
// row with a single loss, and vice versa.
func TestTwoDRecursiveRecovery(t *testing.T) {
	cfg := Config{Cols: 4, Rows: 4}
	const isn = 200
	events, orig := encodeStream(cfg, isn, cfg.matrixSize()*2)
	// Drop positions r0c0, r0c1, r1c0: row 0 has two losses and column 0 has two
	// losses, but column 1 has one (r0c1) and row 1 has one (r1c0). Recovering
	// r0c1 by column 1 then leaves row 0 with one loss (r0c0); recovering r1c0 by
	// row 1 leaves column 0 with one loss. The cascade recovers all three.
	drop := map[uint32]bool{
		seqAdd(isn, 0): true,
		seqAdd(isn, 1): true,
		seqAdd(isn, 4): true,
	}
	rec := replay(cfg, isn, events, drop, orig, t)
	for s := range drop {
		if !rec[s] {
			t.Fatalf("recursive 2-D FEC failed to recover seq %d", s)
		}
	}
}

// TestDecoderRobustToLostFirstPacket verifies the decoder recovers even when the
// very first media packet (the matrix origin) is lost, so the decoder anchors on a
// misaligned sequence. A decoder that assumed matrix alignment from the first
// received packet would fail every subsequent recovery; the SNBase-driven decoder
// recovers regardless. The dropped first packet is itself recovered by its column.
func TestDecoderRobustToLostFirstPacket(t *testing.T) {
	cfg := Config{Cols: 5, Rows: 5}
	const isn = 9000
	events, orig := encodeStream(cfg, isn, cfg.matrixSize()*3)
	// Drop the matrix origin (isn, column 0 row 0) plus one isolated packet in each
	// of the first two matrices. Each is the single loss of its column, so all are
	// recoverable even though the decoder never saw the true ISN.
	drop := map[uint32]bool{
		seqAdd(isn, 0):                  true, // the lost first packet
		seqAdd(isn, 12):                 true, // column 2 row 2 of matrix 0
		seqAdd(isn, cfg.matrixSize()+8): true, // matrix 1
	}
	rec := replay(cfg, isn, events, drop, orig, t)
	for s := range drop {
		if !rec[s] {
			t.Fatalf("decoder failed to recover seq %d after the first packet was lost", s)
		}
	}
}

// TestUnrecoverable confirms FEC does not fabricate data: two losses in the same
// column with column-only FEC cannot be recovered (ARQ would handle them).
func TestUnrecoverable(t *testing.T) {
	cfg := Config{Cols: 4, Rows: 4, ColumnOnly: true}
	const isn = 0
	events, orig := encodeStream(cfg, isn, cfg.matrixSize()*2)
	drop := map[uint32]bool{
		seqAdd(isn, 0): true, // column 0, row 0
		seqAdd(isn, 4): true, // column 0, row 1 — two in column 0
	}
	rec := replay(cfg, isn, events, drop, orig, t)
	if rec[seqAdd(isn, 0)] || rec[seqAdd(isn, 4)] {
		t.Fatal("column-only FEC wrongly recovered a double column loss")
	}
}

// splitmix64 is a tiny deterministic RNG so the property test reproduces by seed.
type splitmix64 uint64

func (s *splitmix64) next() uint64 {
	*s += 0x9E3779B97F4A7C15
	z := uint64(*s)
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// TestDecoderRandomLossProperty drives many seeded random loss patterns through
// the decoder and asserts the two FEC invariants: no fabricated data (every
// recovered payload/header equals the original — enforced inside replay), and
// completeness under recoverable loss (when at most one packet per matrix is lost,
// 2-D FEC recovers all of them).
func TestDecoderRandomLossProperty(t *testing.T) {
	for seed := uint64(1); seed <= 60; seed++ {
		rng := splitmix64(seed)
		cfg := Config{Cols: 4 + int(rng.next()%5), Rows: 4 + int(rng.next()%5)} // 4..8 each
		matrices := 4
		isn := uint32(rng.next())
		events, orig := encodeStream(cfg, isn, cfg.matrixSize()*matrices)

		// Sparse mode (every 3rd seed): at most one drop per matrix — fully
		// recoverable by 2-D FEC. Otherwise: arbitrary heavier loss, where replay
		// still guarantees nothing is fabricated.
		sparse := seed%3 == 0
		drop := map[uint32]bool{}
		if sparse {
			for m := 1; m < matrices; m++ { // skip matrix 0 so the window aligns
				pos := int(rng.next()) % cfg.matrixSize()
				drop[seqAdd(isn, m*cfg.matrixSize()+pos)] = true
			}
		} else {
			for i := 0; i < cfg.matrixSize()*matrices; i++ {
				if rng.next()%100 < 12 { // ~12% loss
					drop[seqAdd(isn, i)] = true
				}
			}
		}

		rec := replay(cfg, int(isn), events, drop, orig, t) // fatals on any fabricated recovery
		if sparse {
			for s := range drop {
				if !rec[s] {
					t.Fatalf("seed %d (L=%d D=%d): single per-matrix loss seq %d not recovered", seed, cfg.Cols, cfg.Rows, s)
				}
			}
		}
	}
}

// TestHeader5RoundTrip checks the SMPTE 2022-5 FEC header (§7.3) encodes and decodes
// byte-stably across its flag, 16-bit base, and 10-bit Offset/NA fields, and that a
// short buffer is rejected.
func TestHeader5RoundTrip(t *testing.T) {
	for _, h := range []Header5{
		{PTRecovery: 96, SNBase: 0x1234, TSRecovery: 0xDEADBEEF, LengthRecovery: 1316, Offset: 5, NA: 4},
		{PRecovery: true, XRecovery: true, CCRecovery: 0x0f, MRecovery: true, PTRecovery: 0x7F, SNBase: 0xFFFF, TSRecovery: 0, LengthRecovery: 0xFFFF, Offset: 1, NA: 20},
		{Offset: na10Max, NA: na10Max, SNBase: 0x8001}, // 10-bit field maxima
	} {
		b := h.AppendTo(nil)
		if len(b) != HeaderSize {
			t.Fatalf("encoded header is %d bytes, want %d", len(b), HeaderSize)
		}
		got, off, err := ParseHeader5(b)
		if err != nil || off != HeaderSize {
			t.Fatalf("ParseHeader5: off=%d err=%v", off, err)
		}
		if got != h {
			t.Fatalf("2022-5 header round-trip:\n got  %+v\n want %+v", got, h)
		}
	}
	// Reserved bits (b[10:12], low 6 of the Offset/NA octets, E/R) must be ignored:
	// setting them on parse input must not change the decoded fields.
	b := Header5{Offset: 5, NA: 4, SNBase: 7}.AppendTo(nil)
	b[10], b[11] = 0xFF, 0xFF // Reserved
	b[13] |= 0x3f             // Offset's 6 reserved low bits
	b[15] |= 0x3f             // NA's 6 reserved low bits
	b[0] |= 0xc0              // E, R
	got, _, _ := ParseHeader5(b)
	if got.Offset != 5 || got.NA != 4 || got.SNBase != 7 {
		t.Fatalf("reserved bits leaked into fields: %+v", got)
	}
	if _, _, err := ParseHeader5(make([]byte, HeaderSize-1)); err == nil {
		t.Fatal("ParseHeader5 accepted a short buffer")
	}
}

// TestVariant20225Recovers runs the core recovery scenarios through the ST 2022-5
// wire format (Variant20225), proving the high-bit-rate header drives the same XOR
// matrix: column-only single loss, 2-D single loss, and the recursive 2-D cascade.
func TestVariant20225Recovers(t *testing.T) {
	t.Run("column-only", func(t *testing.T) {
		cfg := Config{Cols: 5, Rows: 4, ColumnOnly: true, Variant: Variant20225}
		const isn = 1000
		events, orig := encodeStream(cfg, isn, cfg.matrixSize()*3)
		drop := map[uint32]bool{}
		for k := 0; k < cfg.Cols; k++ {
			drop[seqAdd(isn, k*cfg.Cols+k)] = true // one per column
		}
		rec := replay(cfg, isn, events, drop, orig, t)
		for s := range drop {
			if !rec[s] {
				t.Fatalf("2022-5 column-only failed to recover seq %d", s)
			}
		}
	})
	t.Run("2d-single", func(t *testing.T) {
		cfg := Config{Cols: 5, Rows: 4, Variant: Variant20225}
		const isn = 60000 // near the 16-bit base wrap, to exercise widening
		events, orig := encodeStream(cfg, isn, cfg.matrixSize()*3)
		drop := map[uint32]bool{seqAdd(isn, 7): true}
		rec := replay(cfg, isn, events, drop, orig, t)
		if !rec[seqAdd(isn, 7)] {
			t.Fatal("2022-5 2-D FEC failed to recover a single loss across the 16-bit base wrap")
		}
	})
	t.Run("recursive", func(t *testing.T) {
		cfg := Config{Cols: 4, Rows: 4, Variant: Variant20225}
		const isn = 200
		events, orig := encodeStream(cfg, isn, cfg.matrixSize()*2)
		drop := map[uint32]bool{seqAdd(isn, 0): true, seqAdd(isn, 1): true, seqAdd(isn, 4): true}
		rec := replay(cfg, isn, events, drop, orig, t)
		for s := range drop {
			if !rec[s] {
				t.Fatalf("2022-5 recursive 2-D failed to recover seq %d", s)
			}
		}
	})
}

// TestVariant20225RandomLossProperty drives seeded random loss through the ST 2022-5
// decoder, asserting the same invariants as the 2022-1 property test: nothing
// fabricated, and every single-per-matrix loss recovered.
func TestVariant20225RandomLossProperty(t *testing.T) {
	for seed := uint64(1); seed <= 40; seed++ {
		rng := splitmix64(seed)
		cfg := Config{Cols: 4 + int(rng.next()%5), Rows: 4 + int(rng.next()%5), Variant: Variant20225}
		matrices := 4
		isn := uint32(rng.next())
		events, orig := encodeStream(cfg, isn, cfg.matrixSize()*matrices)
		sparse := seed%3 == 0
		drop := map[uint32]bool{}
		if sparse {
			for m := 1; m < matrices; m++ {
				pos := int(rng.next()) % cfg.matrixSize()
				drop[seqAdd(isn, m*cfg.matrixSize()+pos)] = true
			}
		} else {
			for i := 0; i < cfg.matrixSize()*matrices; i++ {
				if rng.next()%100 < 12 {
					drop[seqAdd(isn, i)] = true
				}
			}
		}
		rec := replay(cfg, int(isn), events, drop, orig, t)
		if sparse {
			for s := range drop {
				if !rec[s] {
					t.Fatalf("seed %d (L=%d D=%d): 2022-5 single per-matrix loss seq %d not recovered", seed, cfg.Cols, cfg.Rows, s)
				}
			}
		}
	}
}

// makeColFEC5 hand-builds one ST 2022-5 column FEC packet protecting the D media
// datagrams {base, base+L, ..., base+(D-1)L}, as an external (e.g. ST 2022-6)
// sender would. It lets a test feed column FEC with arbitrary, staggered bases.
func makeColFEC5(base uint32, L, D int, orig map[uint32][]byte) []byte {
	g := newGroup(base, testPayloadSize)
	for j := 0; j < D; j++ {
		s := seqAdd(base, j*L)
		g.clip(uint16(len(orig[s])), mkPT(s), mkTS(s), orig[s])
	}
	h := Header5{LengthRecovery: g.lengthClip, PTRecovery: g.ptClip, TSRecovery: g.tsClip,
		SNBase: uint16(base), Offset: uint16(L), NA: uint16(D)}
	return append(h.AppendTo(nil), g.payloadClip...)
}

// TestDecoderNonBlockAligned proves the decoder makes no block-alignment assumption
// (ST 2022-5 §7.1 / Annex B, Figure B.1): it recovers from column FEC whose bases are
// staggered (advancing by less than a full block) and overlap, deriving the protected
// set from each header's SNBase + j*Offset alone. This is what interop with a
// traffic-shaping ST 2022-5 sender requires.
func TestDecoderNonBlockAligned(t *testing.T) {
	const (
		L   = 5
		D   = 3
		isn = 0
	)
	// Generate enough media payloads to cover the staggered columns below.
	orig := map[uint32][]byte{}
	for i := 0; i < 40; i++ {
		s := seqAdd(isn, i)
		orig[s] = mkPayload(s)
	}
	// Non-block-aligned column FEC: bases advance by 3 (not by 1 within one block),
	// so the columns are offset in time and overlap. Each protects {base, base+5, base+10}.
	bases := []uint32{0, 3, 6, 9, 12}
	// Drop exactly one media datagram from each staggered column.
	dropFor := map[uint32]uint32{0: 5, 3: 13, 6: 16, 9: 9, 12: 22} // base -> dropped member
	drop := map[uint32]bool{}
	for _, m := range dropFor {
		drop[m] = true
	}

	dec := NewDecoder(Config{Cols: L, Rows: D, Variant: Variant20225}, testPayloadSize, isn)
	recovered := map[uint32]bool{}
	// Feed all (non-dropped) media first, then the FEC, mimicking column FEC arriving
	// after its block.
	for i := 0; i < 40; i++ {
		s := seqAdd(isn, i)
		if drop[s] {
			continue
		}
		for _, r := range dec.PushMedia(s, mkTS(s), mkPT(s), testSSRC, orig[s]) {
			recovered[r.Seq] = true
		}
	}
	for _, base := range bases {
		for _, r := range dec.PushFEC(makeColFEC5(base, L, D, orig)) {
			if !bytes.Equal(r.Payload, orig[r.Seq]) {
				t.Fatalf("non-block-aligned recovery of seq %d corrupt", r.Seq)
			}
			recovered[r.Seq] = true
		}
	}
	for m := range drop {
		if !recovered[m] {
			t.Fatalf("decoder failed to recover staggered-column loss seq %d", m)
		}
	}
}

// makeColFEC1 hand-builds one ST 2022-1 column FEC packet protecting the D members
// {base, base+L, ..., base+(D-1)L} from the given payloads (absent payloads clip as
// zero-length), letting a test craft column FEC with arbitrary bases and contents.
func makeColFEC1(base uint32, L, D int, payloads map[uint32][]byte) []byte {
	g := newGroup(base, testPayloadSize)
	for j := 0; j < D; j++ {
		s := seqAdd(base, j*L)
		g.clip(uint16(len(payloads[s])), mkPT(s), mkTS(s), payloads[s])
	}
	h := Header{LengthRecovery: g.lengthClip, PTRecovery: g.ptClip, TSRecovery: g.tsClip,
		Direction: Column, Offset: uint8(L), NA: uint8(D)}
	h.setBase24(base)
	return append(h.AppendTo(nil), g.payloadClip...)
}

// makeRawFEC builds a ST 2022-1 column FEC packet with an arbitrary (offset, na)
// geometry and payload, as a forged/corrupt packet would, for the fabrication tests.
func makeRawFEC(base uint32, offset, na int, payload []byte) []byte {
	h := Header{Direction: Column, Offset: uint8(offset), NA: uint8(na)}
	h.setBase24(base)
	return append(h.AppendTo(nil), payload...)
}

// TestDecoderRejectsForgedGeometry proves a FEC packet whose geometry does not match the
// configured matrix, or whose group extends past the highest received sequence, cannot
// fabricate a media packet — it would otherwise treat a not-yet-sent member as the single
// "missing" one and XOR it from attacker/corruption-controlled bytes (F2).
func TestDecoderRejectsForgedGeometry(t *testing.T) {
	cfg := Config{Cols: 10, Rows: 10}
	dec := NewDecoder(cfg, testPayloadSize, 0)
	payloads := map[uint32][]byte{}
	for i := uint32(0); i < 200; i++ {
		payloads[i] = mkPayload(i)
		if r := dec.PushMedia(i, mkTS(i), mkPT(i), testSSRC, payloads[i]); len(r) != 0 {
			t.Fatalf("unexpected recovery feeding complete media at %d", i)
		}
	}
	// (a) Off-matrix stride/count: a forged column {SNBase:0, Offset:200, NA:2} over the
	// complete window {0..199} makes member 200 (never sent) the lone "missing" one. The
	// geometry constraint rejects stride=200 (config L=10) before any recovery.
	if r := dec.PushFEC(makeRawFEC(0, 200, 2, []byte("fabricated-future-packet-bytes"))); len(r) != 0 {
		t.Fatalf("off-matrix forged FEC fabricated %d packet(s): %+v", len(r), r)
	}
	if len(dec.fecs) != 0 {
		t.Fatalf("off-matrix FEC was stored (%d); geometry mismatch must be rejected outright", len(dec.fecs))
	}
	// (b) Matrix-shaped but extending past lastSeq: a real column over {110,120,...,200}
	// (newest 200 > lastSeq 199) has all of 110..190 present and only the future seq 200
	// "missing". The upper-bound guard refuses, rather than fabricating seq 200.
	payloads[200] = mkPayload(200) // never fed to the decoder; only mixed into the FEC XOR
	if r := dec.PushFEC(makeColFEC1(110, 10, 10, payloads)); len(r) != 0 {
		t.Fatalf("matrix-shaped future-extending FEC fabricated %d packet(s): %+v", len(r), r)
	}
	if _, ok := dec.media[200]; ok {
		t.Fatal("decoder fabricated and stored not-yet-sent seq 200")
	}
}

// TestDecoderUpperBoundDelaysNotDrops proves the upper-bound guard only DEFERS recovery:
// a column whose newest member is briefly ahead of the front recovers once a later media
// packet advances lastSeq past it (the legitimate tail-of-column case must still work).
func TestDecoderUpperBoundDelaysNotDrops(t *testing.T) {
	cfg := Config{Cols: 5, Rows: 4, ColumnOnly: true}
	dec := NewDecoder(cfg, testPayloadSize, 0)
	payloads := map[uint32][]byte{}
	for i := uint32(0); i < 20; i++ {
		payloads[i] = mkPayload(i)
	}
	// Feed media 0..14 and 16..18 (drop seq 15, the last member of column 0's matrix is 15).
	const dropped = 15
	for _, s := range []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14} {
		dec.PushMedia(s, mkTS(s), mkPT(s), testSSRC, payloads[s])
	}
	// Column 0 protects {0,5,10,15}; its FEC arrives while lastSeq is 14 (< 15). The guard
	// defers recovery (newest member 15 > 14) without dropping the group.
	if r := dec.PushFEC(makeColFEC1(0, 5, 4, payloads)); len(r) != 0 {
		t.Fatalf("recovered before lastSeq advanced: %+v", r)
	}
	// A later in-order packet (seq 16) advances lastSeq past 15; recovery now fires.
	var got []Recovered
	got = append(got, dec.PushMedia(16, mkTS(16), mkPT(16), testSSRC, payloads[16])...)
	if len(got) != 1 || got[0].Seq != dropped {
		t.Fatalf("deferred recovery did not fire after lastSeq advanced: %+v", got)
	}
	if !bytes.Equal(got[0].Payload, payloads[dropped]) {
		t.Fatal("deferred recovery payload mismatch")
	}
}

// TestDecoderFECFloodBounded proves the stored FEC set is capped, so a flood of distinct
// geometry-valid FEC packets whose bases hug the window front (and never age out) cannot
// grow memory without bound (F3).
func TestDecoderFECFloodBounded(t *testing.T) {
	cfg := Config{Cols: 10, Rows: 10}
	dec := NewDecoder(cfg, testPayloadSize, 0)
	payloads := map[uint32][]byte{}
	for i := uint32(0); i < 1000; i++ {
		payloads[i] = mkPayload(i)
		dec.PushMedia(i, mkTS(i), mkPT(i), testSSRC, payloads[i])
	}
	// 200 distinct, geometry-valid column bases near the front (well over maxFECs). Without
	// the cap d.fecs would hold all 200; with it, it stays bounded.
	for base := uint32(800); base < 1000; base++ {
		dec.PushFEC(makeColFEC1(base, 10, 10, payloads))
	}
	if len(dec.fecs) > dec.maxFECs {
		t.Fatalf("d.fecs grew to %d, exceeding cap %d (FEC-flood DoS guard failed)", len(dec.fecs), dec.maxFECs)
	}
}

// TestDecoderFECDedup proves duplicate FEC packets (same base/stride/count, as a bonded
// sender fans to every path) are not stored repeatedly (F3).
func TestDecoderFECDedup(t *testing.T) {
	cfg := Config{Cols: 4, Rows: 4, ColumnOnly: true}
	dec := NewDecoder(cfg, testPayloadSize, 0)
	payloads := map[uint32][]byte{}
	for i := uint32(0); i < 16; i++ {
		payloads[i] = mkPayload(i)
		if i == 5 {
			continue // drop one member so the group cannot resolve immediately
		}
		dec.PushMedia(i, mkTS(i), mkPT(i), testSSRC, payloads[i])
	}
	fecPkt := makeColFEC1(1, 4, 4, payloads)
	dec.PushFEC(fecPkt) // recovers seq 5; the group becomes done
	for n := 0; n < 50; n++ {
		dec.PushFEC(fecPkt) // identical duplicates must not pile up
	}
	if len(dec.fecs) != 1 {
		t.Fatalf("duplicate FEC packets stored %d entries, want 1", len(dec.fecs))
	}
}

// TestDecoderImplausibleLengthDone proves a geometrically-valid but unrecoverable group
// whose recovered length exceeds the payload size is marked done, so recoverAll stops
// rescanning it every push (F10).
func TestDecoderImplausibleLengthDone(t *testing.T) {
	cfg := Config{Cols: 4, Rows: 4, ColumnOnly: true}
	dec := NewDecoder(cfg, testPayloadSize, 0)
	payloads := map[uint32][]byte{}
	for i := uint32(0); i < 16; i++ {
		payloads[i] = mkPayload(i)
	}
	payloads[5] = make([]byte, testPayloadSize*4) // dropped member with an over-large length
	for i := uint32(0); i < 16; i++ {
		if i == 5 {
			continue
		}
		dec.PushMedia(i, mkTS(i), mkPT(i), testSSRC, payloads[i])
	}
	rec := dec.PushFEC(makeColFEC1(1, 4, 4, payloads)) // recovered length == 4*payloadSize > cap
	if len(rec) != 0 {
		t.Fatalf("implausible-length group recovered %d packet(s): %+v", len(rec), rec)
	}
	if len(dec.fecs) != 1 || !dec.fecs[0].done {
		t.Fatalf("implausible-length group not marked done (would be rescanned every push): fecs=%d done=%v",
			len(dec.fecs), len(dec.fecs) == 1 && dec.fecs[0].done)
	}
}

// TestRecoveredCarriesSSRC proves a recovery is stamped with its group's SSRC (carried
// through the decoder) rather than a separate last-seen value (F11).
func TestRecoveredCarriesSSRC(t *testing.T) {
	cfg := Config{Cols: 4, Rows: 4, ColumnOnly: true}
	const groupSSRC = 0xDEADBEEF
	dec := NewDecoder(cfg, testPayloadSize, 0)
	payloads := map[uint32][]byte{}
	for i := uint32(0); i < 16; i++ {
		payloads[i] = mkPayload(i)
		if i == 5 {
			continue
		}
		dec.PushMedia(i, mkTS(i), mkPT(i), groupSSRC, payloads[i])
	}
	rec := dec.PushFEC(makeColFEC1(1, 4, 4, payloads))
	if len(rec) != 1 || rec[0].Seq != 5 {
		t.Fatalf("expected recovery of seq 5, got %+v", rec)
	}
	if rec[0].SSRC != groupSSRC {
		t.Fatalf("recovered SSRC = %#x, want group SSRC %#x", rec[0].SSRC, groupSSRC)
	}
}

// TestEncoderDecoderLargePayload proves the FEC matrix protects a payload larger than the
// legacy 1500-byte clip (an Advanced full datagram reaches ~1512 bytes) when the payload
// size admits it, and that a too-small size truncates and the recovery is rejected (F1).
func TestEncoderDecoderLargePayload(t *testing.T) {
	const big = 1512
	cfg := Config{Cols: 4, Rows: 4, ColumnOnly: true}
	bigPayload := func(s uint32) []byte {
		p := make([]byte, big)
		for k := range p {
			p[k] = byte(s)*7 + byte(k*3+1)
		}
		return p
	}
	run := func(payloadSize int) (recovered, ok bool) {
		enc := NewEncoder(cfg, payloadSize, 0)
		dec := NewDecoder(cfg, payloadSize, 0)
		const dropped = 5
		orig := map[uint32][]byte{}
		var events []event
		for i := uint32(0); i < 16; i++ {
			p := bigPayload(i)
			orig[i] = p
			events = append(events, event{seq: i})
			for _, fp := range enc.Push(i, mkTS(i), mkPT(i), p) {
				events = append(events, event{isFEC: true, fec: fp.Data})
			}
		}
		var got []byte
		for _, e := range events {
			if e.isFEC {
				for _, r := range dec.PushFEC(e.fec) {
					if r.Seq == dropped {
						got = r.Payload
					}
				}
				continue
			}
			if e.seq == dropped {
				continue
			}
			for _, r := range dec.PushMedia(e.seq, mkTS(e.seq), mkPT(e.seq), testSSRC, orig[e.seq]) {
				if r.Seq == dropped {
					got = r.Payload
				}
			}
		}
		return got != nil, got != nil && bytes.Equal(got, orig[dropped])
	}
	if rec, intact := run(2048); !rec || !intact {
		t.Fatalf("large payload not recovered intact with sufficient payload size: recovered=%v intact=%v", rec, intact)
	}
	if rec, _ := run(1500); rec {
		t.Fatal("a 1512-byte payload must not be recoverable with a 1500-byte FEC buffer (truncated XOR / over-length recovery)")
	}
}

// FuzzParseHeader5 asserts the ST 2022-5 header parser never panics on arbitrary input.
func FuzzParseHeader5(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, HeaderSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, off, err := ParseHeader5(b); err == nil {
			if off != HeaderSize {
				t.Fatalf("off=%d on success", off)
			}
			if h.Offset > na10Max || h.NA > na10Max {
				t.Fatalf("10-bit field overflow: %+v", h)
			}
		}
	})
}

// FuzzParseHeader asserts the header parser never panics on arbitrary input.
func FuzzParseHeader(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, HeaderSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, off, err := ParseHeader(b); err == nil {
			_ = h.base24()
			if off != HeaderSize {
				t.Fatalf("off=%d on success", off)
			}
		}
	})
}

// FuzzDecoder asserts the decoder never panics on arbitrary media/FEC input and never
// FABRICATES a future packet: every recovered sequence must be at or behind the highest
// media sequence seen (a forged FEC header must not coerce the decoder into "recovering"
// a not-yet-transmitted sequence from attacker-controlled bytes).
func FuzzDecoder(f *testing.F) {
	f.Add([]byte("fec"), uint32(1), uint32(2), []byte("media"))
	f.Fuzz(func(t *testing.T, fec []byte, s, ts uint32, payload []byte) {
		d := NewDecoder(Config{Cols: 4, Rows: 4}, testPayloadSize, 0)
		noFuture := func(rs []Recovered) {
			for _, r := range rs {
				if seqDiff(d.lastSeq, r.Seq) > 0 {
					t.Fatalf("fabricated future packet: recovered seq %d ahead of lastSeq %d", r.Seq, d.lastSeq)
				}
			}
		}
		noFuture(d.PushMedia(s, ts, uint8(ts), ts, payload))
		noFuture(d.PushFEC(fec))
	})
}

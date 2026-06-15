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
			rs = dec.PushMedia(s, mkTS(s), mkPT(s), orig[s])
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

// FuzzDecoder asserts the decoder never panics on arbitrary media/FEC input.
func FuzzDecoder(f *testing.F) {
	f.Add([]byte("fec"), uint32(1), uint32(2), []byte("media"))
	f.Fuzz(func(t *testing.T, fec []byte, s, ts uint32, payload []byte) {
		d := NewDecoder(Config{Cols: 4, Rows: 4}, testPayloadSize, 0)
		_ = d.PushFEC(fec)
		_ = d.PushMedia(s, ts, uint8(ts), payload)
	})
}

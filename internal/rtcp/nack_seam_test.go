package rtcp

import (
	"math/rand/v2"
	"reflect"
	"testing"
)

// decodeAll concatenates the decoded sequence lists of a series of NACK
// packets, mirroring how the session reassembles a split request.
func decodeAllRange(t *testing.T, pkts []RangeNACK) []uint32 {
	t.Helper()
	var out []uint32
	for _, p := range pkts {
		seqs, ok := DecodeNACK(p)
		if !ok {
			t.Fatalf("DecodeNACK rejected RangeNACK %#v", p)
		}
		out = append(out, seqs...)
	}
	return out
}

func decodeAllBitmask(t *testing.T, pkts []BitmaskNACK) []uint32 {
	t.Helper()
	var out []uint32
	for _, p := range pkts {
		seqs, ok := DecodeNACK(p)
		if !ok {
			t.Fatalf("DecodeNACK rejected BitmaskNACK %#v", p)
		}
		out = append(out, seqs...)
	}
	return out
}

// seamCases are hand-picked sequence sets, all in ascending circular order,
// exercising runs, gaps, and the 65535->0 wrap.
var seamCases = []struct {
	name    string
	missing []uint32
}{
	{"single", []uint32{42}},
	{"pair gap", []uint32{42, 99}},
	{"contiguous run", []uint32{10, 11, 12, 13, 14}},
	{"runs and singles", []uint32{1, 2, 3, 7, 9, 10, 500}},
	{"17-wide bitmask boundary", []uint32{100, 117}},   // exactly PID+17: needs two FCIs
	{"16-wide bitmask boundary", []uint32{100, 116}},   // PID+16: last BLP bit
	{"wrap adjacent", []uint32{65535, 0}},              // run across the wrap
	{"wrap run", []uint32{65534, 65535, 0, 1}},         // 4-long run across the wrap
	{"wrap with gap", []uint32{65530, 65535, 0, 5}},    // gaps straddling the wrap
	{"wrap inside bitmask window", []uint32{65532, 2}}, // d=6 within one FCI
	{"max start", []uint32{65535}},
	{"zero start", []uint32{0}},
	{"long run for one range record", seqSpan(1000, 300)}, // extra=299
	{"33 singles -> 3 bitmask FCI windows", sparse(0, 17, 33)},
}

// seqSpan returns n consecutive seqs starting at s (mod 2^16).
func seqSpan(s, n int) []uint32 {
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(uint16(s + i))
	}
	return out
}

// sparse returns n seqs starting at s, stepping by `step` (mod 2^16).
func sparse(s, step, n int) []uint32 {
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(uint16(s + i*step))
	}
	return out
}

func TestRangeNACKSeamRoundTrip(t *testing.T) {
	for _, tt := range seamCases {
		t.Run(tt.name, func(t *testing.T) {
			pkts := EncodeRangeNACK(0, 0xAB, tt.missing)
			for _, p := range pkts {
				if p.MediaSSRC != 0xAB {
					t.Errorf("MediaSSRC = %#x, want 0xAB", p.MediaSSRC)
				}
				if len(p.Ranges) == 0 || len(p.Ranges) > MaxNackRecordsPerPacket {
					t.Errorf("packet has %d records, want 1..%d", len(p.Ranges), MaxNackRecordsPerPacket)
				}
			}
			if got := decodeAllRange(t, pkts); !reflect.DeepEqual(got, tt.missing) {
				t.Errorf("decode(encode(missing)) = %v, want %v", got, tt.missing)
			}
		})
	}
}

func TestBitmaskNACKSeamRoundTrip(t *testing.T) {
	for _, tt := range seamCases {
		t.Run(tt.name, func(t *testing.T) {
			pkts := EncodeBitmaskNACK(0x11, 0xAB, tt.missing)
			for _, p := range pkts {
				if p.SenderSSRC != 0x11 || p.MediaSSRC != 0xAB {
					t.Errorf("SSRCs = %#x/%#x, want 0x11/0xAB", p.SenderSSRC, p.MediaSSRC)
				}
				if len(p.FCIs) == 0 || len(p.FCIs) > MaxNackRecordsPerPacket {
					t.Errorf("packet has %d FCIs, want 1..%d", len(p.FCIs), MaxNackRecordsPerPacket)
				}
			}
			if got := decodeAllBitmask(t, pkts); !reflect.DeepEqual(got, tt.missing) {
				t.Errorf("decode(encode(missing)) = %v, want %v", got, tt.missing)
			}
		})
	}
}

// TestNACKSeamProperty is the seeded property test: arbitrary strictly
// ascending circular sequence sets (random start, random positive gaps,
// total span < 2^16, freely crossing the 65535->0 wrap) survive
// encode->decode unchanged under both encodings, and additionally survive
// a trip through the wire bytes.
func TestNACKSeamProperty(t *testing.T) {
	for seed := uint64(0); seed < 64; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0x52495354))
		missing := randomMissing(rng)

		rangePkts := EncodeRangeNACK(1, 2, missing)
		if got := decodeAllRange(t, rangePkts); !reflect.DeepEqual(got, missing) {
			t.Fatalf("seed %d: range decode = %v, want %v", seed, got, missing)
		}
		bitmaskPkts := EncodeBitmaskNACK(1, 2, missing)
		if got := decodeAllBitmask(t, bitmaskPkts); !reflect.DeepEqual(got, missing) {
			t.Fatalf("seed %d: bitmask decode = %v, want %v", seed, got, missing)
		}

		// Through the wire: marshal each packet, re-parse, re-expand.
		var viaWire []uint32
		for _, p := range rangePkts {
			dec, _, err := Parse(p.AppendTo(nil))
			if err != nil {
				t.Fatalf("seed %d: Parse(range): %v", seed, err)
			}
			seqs, ok := DecodeNACK(dec)
			if !ok {
				t.Fatalf("seed %d: DecodeNACK(parsed range) rejected %#v", seed, dec)
			}
			viaWire = append(viaWire, seqs...)
		}
		if !reflect.DeepEqual(viaWire, missing) {
			t.Fatalf("seed %d: range via wire = %v, want %v", seed, viaWire, missing)
		}

		viaWire = viaWire[:0]
		for _, p := range bitmaskPkts {
			dec, _, err := Parse(p.AppendTo(nil))
			if err != nil {
				t.Fatalf("seed %d: Parse(bitmask): %v", seed, err)
			}
			seqs, ok := DecodeNACK(dec)
			if !ok {
				t.Fatalf("seed %d: DecodeNACK(parsed bitmask) rejected %#v", seed, dec)
			}
			viaWire = append(viaWire, seqs...)
		}
		if !reflect.DeepEqual(viaWire, missing) {
			t.Fatalf("seed %d: bitmask via wire = %v, want %v", seed, viaWire, missing)
		}
	}
}

// randomMissing draws a strictly ascending circular 16-bit sequence set:
// a random start, then random gaps of 1..512, with the total span kept
// under 2^16 so the set stays well-ordered on the ring. Roughly half the
// draws cross the 65535->0 wrap because the start is uniform.
func randomMissing(rng *rand.Rand) []uint32 {
	n := 1 + rng.IntN(200)
	cur := uint16(rng.IntN(1 << 16))
	span := 0
	out := make([]uint32, 0, n)
	out = append(out, uint32(cur))
	for len(out) < n {
		gap := 1 + rng.IntN(512)
		if span+gap >= 1<<16 {
			break
		}
		span += gap
		cur += uint16(gap) // natural wrap
		out = append(out, uint32(cur))
	}
	return out
}

// TestEncodeNACKEmpty pins the no-loss case: no packets at all, mirroring
// libRIST which only appends a NACK section when array_len > 0
// (src/udp.c:738).
func TestEncodeNACKEmpty(t *testing.T) {
	if got := EncodeRangeNACK(1, 2, nil); got != nil {
		t.Errorf("EncodeRangeNACK(nil) = %v, want nil", got)
	}
	if got := EncodeBitmaskNACK(1, 2, nil); got != nil {
		t.Errorf("EncodeBitmaskNACK(nil) = %v, want nil", got)
	}
}

// TestEncodeNACKSplitting asserts both encoders split at exactly
// MaxNackRecordsPerPacket records (TR-06-1 §5.3.2.2 mandates <= 16 range
// requests per packet; §5.3.2.3 recommends the same for bitmask).
func TestEncodeNACKSplitting(t *testing.T) {
	// 33 isolated seqs -> 33 records -> 16+16+1.
	missing := sparse(100, 100, 33)

	rangePkts := EncodeRangeNACK(0, 1, missing)
	if got := []int{len(rangePkts[0].Ranges), len(rangePkts[1].Ranges), len(rangePkts[2].Ranges)}; len(rangePkts) != 3 || got[0] != 16 || got[1] != 16 || got[2] != 1 {
		t.Errorf("range split = %d packets %v, want [16 16 1]", len(rangePkts), got)
	}

	bitmaskPkts := EncodeBitmaskNACK(0, 1, missing)
	if got := []int{len(bitmaskPkts[0].FCIs), len(bitmaskPkts[1].FCIs), len(bitmaskPkts[2].FCIs)}; len(bitmaskPkts) != 3 || got[0] != 16 || got[1] != 16 || got[2] != 1 {
		t.Errorf("bitmask split = %d packets %v, want [16 16 1]", len(bitmaskPkts), got)
	}
}

// TestEncodeNACKMinimality pins record-level minimality: contiguous runs
// collapse into single range records, and seqs within a 17-packet window
// share one FCI.
func TestEncodeNACKMinimality(t *testing.T) {
	t.Run("range collapses runs", func(t *testing.T) {
		pkts := EncodeRangeNACK(0, 1, []uint32{5, 6, 7, 8, 20})
		want := []NackRange{{Start: 5, Extra: 3}, {Start: 20, Extra: 0}}
		if len(pkts) != 1 || !reflect.DeepEqual(pkts[0].Ranges, want) {
			t.Errorf("ranges = %#v, want %#v", pkts, want)
		}
	})

	t.Run("bitmask packs window into one FCI", func(t *testing.T) {
		// 5 plus all of 6..21 = PID + 16 BLP bits in a single FCI.
		pkts := EncodeBitmaskNACK(0, 1, seqSpan(5, 17))
		want := []NackPair{{PID: 5, BLP: 0xFFFF}}
		if len(pkts) != 1 || !reflect.DeepEqual(pkts[0].FCIs, want) {
			t.Errorf("FCIs = %#v, want %#v", pkts, want)
		}
	})

	t.Run("bitmask BLP bit semantics", func(t *testing.T) {
		// TR-06-1 §5.3.2.1: BLP bit i (LSB = bit 1 in spec numbering) set
		// means PID+i lost. Our NackPair.BLP uses bit index i-1, so seqs
		// {PID, PID+1, PID+16} give BLP bits 0 and 15.
		pkts := EncodeBitmaskNACK(0, 1, []uint32{1000, 1001, 1016})
		want := []NackPair{{PID: 1000, BLP: 0x8001}}
		if len(pkts) != 1 || !reflect.DeepEqual(pkts[0].FCIs, want) {
			t.Errorf("FCIs = %#v, want %#v", pkts, want)
		}
	})

	t.Run("range record splits across the extra=65535 ceiling", func(t *testing.T) {
		// The whole ring as one run: start s, 65535 additional packets.
		pkts := EncodeRangeNACK(0, 1, seqSpan(7, 65536))
		want := []NackRange{{Start: 7, Extra: 65535}}
		if len(pkts) != 1 || !reflect.DeepEqual(pkts[0].Ranges, want) {
			t.Fatalf("ranges = %#v, want %#v", pkts, want)
		}
		if got := decodeAllRange(t, pkts); len(got) != 65536 || got[0] != 7 || got[65535] != 6 {
			t.Errorf("whole-ring decode: len=%d first=%d last=%d", len(got), got[0], got[len(got)-1])
		}
	})
}

// TestNACKSeamOffContractInputs pins what each encoder does when the
// documented "ascending circular order" precondition (nack.go:206,255) is
// violated, so a future change cannot silently alter it. The RANGE encoder is
// order-preserving — every non-consecutive element opens a new {Start, Extra}
// record — so duplicates and out-of-order seqs survive the round trip
// verbatim. The BITMASK encoder is not: it folds any seq within 16 of the
// current PID into one FCI, so an out-of-order seq inside that window is
// re-sorted on decode. Production never hits this (libRIST's
// receiver_mark_missing emits sorted, deduped lists), but the divergence is
// real and worth locking down.
func TestNACKSeamOffContractInputs(t *testing.T) {
	t.Run("range preserves duplicates", func(t *testing.T) {
		got := decodeAllRange(t, EncodeRangeNACK(0, 1, []uint32{5, 5, 6}))
		if !reflect.DeepEqual(got, []uint32{5, 5, 6}) {
			t.Errorf("range dup round-trip = %v, want [5 5 6]", got)
		}
	})
	t.Run("range preserves out-of-order", func(t *testing.T) {
		got := decodeAllRange(t, EncodeRangeNACK(0, 1, []uint32{10, 5, 6}))
		if !reflect.DeepEqual(got, []uint32{10, 5, 6}) {
			t.Errorf("range out-of-order round-trip = %v, want [10 5 6]", got)
		}
	})
	t.Run("bitmask re-sorts within the 17-packet window", func(t *testing.T) {
		// 21 is within 16 of PID 5, so it folds into 5's FCI and decodes
		// before 6's position is honored: input order [5,21,6] is lost.
		got := decodeAllBitmask(t, EncodeBitmaskNACK(0, 1, []uint32{5, 21, 6}))
		if !reflect.DeepEqual(got, []uint32{5, 6, 21}) {
			t.Errorf("bitmask off-order = %v, want [5 6 21] (coalesced)", got)
		}
	})
}

// TestDecodeNACKNonNACK asserts the dispatch helper refuses non-NACK
// packets.
func TestDecodeNACKNonNACK(t *testing.T) {
	for _, p := range []Packet{
		SenderReport{}, EmptyReceiverReport{}, ReceiverReport{}, SDES{},
		EchoRequest{}, EchoResponse{}, ExtSeq{}, Raw{0x80},
	} {
		if seqs, ok := DecodeNACK(p); ok || seqs != nil {
			t.Errorf("DecodeNACK(%T) = %v, %v; want nil, false", p, seqs, ok)
		}
	}
}

// TestAppendMissingSeqsReusesBuffer asserts the Append variants extend the
// caller's slice in place when capacity suffices.
func TestAppendMissingSeqsReusesBuffer(t *testing.T) {
	buf := make([]uint32, 0, 64)

	r := RangeNACK{Ranges: []NackRange{{Start: 9, Extra: 2}}}
	got := r.AppendMissingSeqs(buf)
	if &got[0] != &buf[:1][0] {
		t.Error("RangeNACK.AppendMissingSeqs reallocated despite spare capacity")
	}
	if !reflect.DeepEqual(got, []uint32{9, 10, 11}) {
		t.Errorf("RangeNACK.AppendMissingSeqs = %v, want [9 10 11]", got)
	}

	b := BitmaskNACK{FCIs: []NackPair{{PID: 3, BLP: 0x0002}}}
	got = b.AppendMissingSeqs(buf)
	if &got[0] != &buf[:1][0] {
		t.Error("BitmaskNACK.AppendMissingSeqs reallocated despite spare capacity")
	}
	if !reflect.DeepEqual(got, []uint32{3, 5}) {
		t.Errorf("BitmaskNACK.AppendMissingSeqs = %v, want [3 5]", got)
	}
}

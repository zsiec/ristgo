package split

import "testing"

func TestSplitPointOff(t *testing.T) {
	if _, _, ok := SplitPoint(SplitOff, make([]byte, 376)); ok {
		t.Fatal("SplitOff must not split")
	}
}

func TestSplitPointHalf(t *testing.T) {
	cases := []struct {
		n           int
		first, last int
		ok          bool
	}{
		{100, 50, 50, true},
		{101, 50, 51, true},
		{1, 0, 0, false}, // too small
	}
	for _, c := range cases {
		first, last, ok := SplitPoint(SplitHalf, make([]byte, c.n))
		if ok != c.ok || (ok && (first != c.first || last != c.last)) {
			t.Fatalf("SplitPoint(Half, %d) = (%d,%d,%v), want (%d,%d,%v)",
				c.n, first, last, ok, c.first, c.last, c.ok)
		}
	}
}

func TestSplitPointAutoTSBoundary(t *testing.T) {
	// 7 TS packets, 0x47-synced → 3 packets / 4 packets.
	p := make([]byte, 7*tsPacketLen)
	p[0] = tsSyncByte
	if f, l, ok := SplitPoint(SplitAuto, p); !ok || f != 3*188 || l != 4*188 {
		t.Fatalf("auto TS split = (%d,%d,%v), want (564,752,true)", f, l, ok)
	}
	// 2 TS packets → 1 / 1.
	p2 := make([]byte, 2*tsPacketLen)
	p2[0] = tsSyncByte
	if f, l, ok := SplitPoint(SplitAuto, p2); !ok || f != 188 || l != 188 {
		t.Fatalf("auto 2-TS split = (%d,%d,%v), want (188,188,true)", f, l, ok)
	}
}

func TestSplitPointAutoFallback(t *testing.T) {
	// Not 188-aligned → byte midpoint.
	if f, l, ok := SplitPoint(SplitAuto, make([]byte, 300)); !ok || f != 150 || l != 150 {
		t.Fatalf("auto fallback (300) = (%d,%d,%v), want (150,150,true)", f, l, ok)
	}
	// 188-aligned but wrong sync byte → byte midpoint, not a TS split.
	p := make([]byte, 3*tsPacketLen) // first byte 0x00
	if f, l, ok := SplitPoint(SplitAuto, p); !ok || f != 282 || l != 282 {
		t.Fatalf("auto non-sync (564) = (%d,%d,%v), want (282,282,true)", f, l, ok)
	}
}

func TestIsSplitPair(t *testing.T) {
	if !IsSplitPair(10, 5000, 11, 5000) {
		t.Fatal("even/+1/same-st must pair")
	}
	if IsSplitPair(11, 5000, 12, 5000) {
		t.Fatal("odd first must not pair")
	}
	if IsSplitPair(10, 5000, 12, 5000) {
		t.Fatal("non-consecutive must not pair")
	}
	if IsSplitPair(10, 5000, 11, 6000) {
		t.Fatal("different source time must not pair")
	}
	if !IsSplitPair(0xFFFFFFFE, 1, 0xFFFFFFFF, 1) {
		t.Fatal("even near-wrap must pair")
	}
}

func bytesEq(a, b []byte) bool {
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

func TestSplitPayloadOffIsPassthrough(t *testing.T) {
	first, last, ok := SplitPayload(SplitOff, []byte("hello"))
	if ok || last != nil || !bytesEq(first, []byte("hello")) {
		t.Fatalf("off: got (%q, %v, %v)", first, last, ok)
	}
}

func TestSplitPayloadAlwaysPairsWhenActive(t *testing.T) {
	// A normal payload halves.
	first, last, ok := SplitPayload(SplitHalf, []byte("abcd"))
	if !ok || !bytesEq(first, []byte("ab")) || !bytesEq(last, []byte("cd")) {
		t.Fatalf("half: got (%q, %q, %v)", first, last, ok)
	}
	// A one-byte payload (too small for SplitPoint) still pairs as (empty, whole).
	first, last, ok = SplitPayload(SplitHalf, []byte("x"))
	if !ok || len(first) != 0 || !bytesEq(last, []byte("x")) {
		t.Fatalf("one byte: got (%q, %q, %v)", first, last, ok)
	}
	// An empty payload is the lone passthrough.
	first, last, ok = SplitPayload(SplitAuto, nil)
	if ok || last != nil || len(first) != 0 {
		t.Fatalf("empty: got (%q, %q, %v)", first, last, ok)
	}
}

// drain runs one Merger.Deliver and flattens the result for assertion.
func drain(m *Merger, seq uint32, src uint64, payload string, disc bool) []string {
	var out []string
	for _, p := range m.Deliver(seq, src, []byte(payload), disc) {
		out = append(out, string(p))
	}
	return out
}

func TestMergerOffPassesThrough(t *testing.T) {
	m := NewMerger(MergeOff)
	if got := drain(m, 0, 5, "a", false); len(got) != 1 || got[0] != "a" {
		t.Fatalf("off: %v", got)
	}
}

func TestMergerCombinesPair(t *testing.T) {
	m := NewMerger(MergePairs)
	if got := drain(m, 10, 900, "ab", false); got != nil {
		t.Fatalf("even half should be held: %v", got)
	}
	if got := drain(m, 11, 900, "cd", false); len(got) != 1 || got[0] != "abcd" {
		t.Fatalf("pair should merge: %v", got)
	}
}

func TestMergerSourceTimeGuardPreventsCorruption(t *testing.T) {
	// The pitfall: keying only on even/odd + seq+1 would splice "ab" onto "cd" though
	// they are different payloads (distinct source times). The guard flushes the
	// orphan and delivers the second separately.
	m := NewMerger(MergePairs)
	drain(m, 10, 900, "ab", false) // held
	got := drain(m, 11, 901, "cd", false)
	if len(got) != 2 || got[0] != "ab" || got[1] != "cd" {
		t.Fatalf("source-time mismatch must not merge: %v", got)
	}
}

func TestMergerUnsplitStreamDeliversInOrder(t *testing.T) {
	m := NewMerger(MergePairs)
	var out []string
	for _, c := range []struct {
		seq uint32
		src uint64
		p   string
	}{{0, 1, "p0"}, {1, 2, "p1"}, {2, 3, "p2"}, {3, 4, "p3"}} {
		out = append(out, drain(m, c.seq, c.src, c.p, false)...)
	}
	want := []string{"p0", "p1", "p2", "p3"}
	if len(out) != len(want) {
		t.Fatalf("unsplit stream: %v", out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("unsplit stream: %v", out)
		}
	}
}

func TestMergerLostPartnerFlushesOrphan(t *testing.T) {
	m := NewMerger(MergePairs)
	drain(m, 10, 900, "orphan", false) // held
	if got := drain(m, 12, 901, "ef", true); len(got) != 1 || got[0] != "orphan" {
		t.Fatalf("orphan should flush, seq 12 held: %v", got)
	}
	if got := drain(m, 13, 901, "gh", false); len(got) != 1 || got[0] != "efgh" {
		t.Fatalf("fresh pair after loss should merge: %v", got)
	}
}

func TestMergerAutoDormantUntilEnabled(t *testing.T) {
	m := NewMerger(MergeAuto)
	if got := drain(m, 0, 5, "ab", false); len(got) != 1 || got[0] != "ab" {
		t.Fatalf("auto dormant should pass through: %v", got)
	}
	m.SetAutoEnabled(true)
	if got := drain(m, 2, 7, "ab", false); got != nil {
		t.Fatalf("auto enabled should hold the even half: %v", got)
	}
	if got := drain(m, 3, 7, "cd", false); len(got) != 1 || got[0] != "abcd" {
		t.Fatalf("auto enabled should merge: %v", got)
	}
}

func TestSplitThenMergeRoundTrips(t *testing.T) {
	payloads := [][]byte{[]byte("first-chunk"), []byte("x"), make([]byte, 376), []byte("another payload here")}
	payloads[2][0] = 0x47 // TS-aligned for SplitAuto
	m := NewMerger(MergePairs)
	var seq uint32 // even start
	var got [][]byte
	for i, p := range payloads {
		src := uint64(1000 + i)
		first, last, ok := SplitPayload(SplitAuto, p)
		if !ok {
			t.Fatalf("active split must pair a non-empty payload %d", i)
		}
		for _, half := range [][]byte{first, last} {
			for _, out := range m.Deliver(seq, src, half, false) {
				cp := make([]byte, len(out))
				copy(cp, out)
				got = append(got, cp)
			}
			seq++
		}
	}
	if len(got) != len(payloads) {
		t.Fatalf("round trip count: got %d want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if !bytesEq(got[i], payloads[i]) {
			t.Fatalf("round trip payload %d mismatch", i)
		}
	}
}

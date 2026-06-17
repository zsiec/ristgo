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

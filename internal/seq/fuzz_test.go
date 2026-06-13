package seq

import "testing"

// checkDistance16 asserts the Distance invariants for one 16-bit pair:
//   - Distance(a,a) == 0
//   - Distance(a,b) == -Distance(b,a), except at the exact antipode where
//     both directions are pinned to +Half16 (package doc, librist
//     rist-common.c:555-557 treats a gap of exactly 32768 as forward)
//   - |Distance| <= Half16
//   - Add(a, Distance(a,b)) == b
//   - sign agrees with Less and ForwardGap
func checkDistance16(t *testing.T, a, b Num16) {
	t.Helper()

	if d := a.Distance(a); d != 0 {
		t.Fatalf("(%d).Distance(self) = %d, want 0", a, d)
	}

	dab, dba := a.Distance(b), b.Distance(a)
	if b-a == Half16 {
		// Pinned antipode behavior.
		if dab != int64(Half16) || dba != int64(Half16) {
			t.Fatalf("antipode (%d,%d): Distance = %d/%d, want both +%d", a, b, dab, dba, Half16)
		}
	} else if dab != -dba {
		t.Fatalf("Distance(%d,%d) = %d, but Distance(%d,%d) = %d (want negation)", a, b, dab, b, a, dba)
	}

	if dab > int64(Half16) || dab < -int64(Half16)+1 {
		t.Fatalf("Distance(%d,%d) = %d outside [-32767, 32768]", a, b, dab)
	}

	if got := a.Add(dab); got != b {
		t.Fatalf("(%d).Add(Distance=%d) = %d, want %d", a, dab, got, b)
	}

	if (dab > 0) != a.Less(b) {
		t.Fatalf("Distance(%d,%d)=%d sign disagrees with Less=%v", a, b, dab, a.Less(b))
	}

	gap, forward := a.ForwardGap(b)
	if gap != uint64(Num16(b-a)) {
		t.Fatalf("ForwardGap(%d,%d) gap = %d, want %d", a, b, gap, uint64(Num16(b-a)))
	}
	if forward != (dab >= 0) {
		t.Fatalf("ForwardGap(%d,%d) forward = %v disagrees with Distance %d", a, b, forward, dab)
	}
	if forward && gap != 0 && int64(gap) != dab {
		t.Fatalf("ForwardGap(%d,%d) gap = %d, but Distance = %d", a, b, gap, dab)
	}
}

// checkDistance32 asserts the same invariants for one 32-bit pair.
func checkDistance32(t *testing.T, a, b Num32) {
	t.Helper()

	if d := a.Distance(a); d != 0 {
		t.Fatalf("(%d).Distance(self) = %d, want 0", a, d)
	}

	dab, dba := a.Distance(b), b.Distance(a)
	if b-a == Half32 {
		// Pinned antipode behavior.
		if dab != int64(Half32) || dba != int64(Half32) {
			t.Fatalf("antipode (%d,%d): Distance = %d/%d, want both +%d", a, b, dab, dba, Half32)
		}
	} else if dab != -dba {
		t.Fatalf("Distance(%d,%d) = %d, but Distance(%d,%d) = %d (want negation)", a, b, dab, b, a, dba)
	}

	if dab > int64(Half32) || dab < -int64(Half32)+1 {
		t.Fatalf("Distance(%d,%d) = %d outside [-2147483647, 2147483648]", a, b, dab)
	}

	if got := a.Add(dab); got != b {
		t.Fatalf("(%d).Add(Distance=%d) = %d, want %d", a, dab, got, b)
	}

	if (dab > 0) != a.Less(b) {
		t.Fatalf("Distance(%d,%d)=%d sign disagrees with Less=%v", a, b, dab, a.Less(b))
	}

	gap, forward := a.ForwardGap(b)
	if gap != uint64(Num32(b-a)) {
		t.Fatalf("ForwardGap(%d,%d) gap = %d, want %d", a, b, gap, uint64(Num32(b-a)))
	}
	if forward != (dab >= 0) {
		t.Fatalf("ForwardGap(%d,%d) forward = %v disagrees with Distance %d", a, b, forward, dab)
	}
	if forward && gap != 0 && int64(gap) != dab {
		t.Fatalf("ForwardGap(%d,%d) gap = %d, but Distance = %d", a, b, gap, dab)
	}
}

// checkCompare16 asserts the Compare/Less invariants for one 16-bit pair:
//   - Compare(a,b) == 0 iff a == b; Less is irreflexive
//   - Compare sign agrees with Less
//   - Less antisymmetry (never both, never neither for a != b), except at
//     the exact antipode where both directions are pinned true and Compare
//     is pinned to -1 both ways (package doc)
func checkCompare16(t *testing.T, a, b Num16) {
	t.Helper()

	if a.Less(a) || a.Compare(a) != 0 {
		t.Fatalf("reflexivity violated for %d: Less=%v Compare=%d", a, a.Less(a), a.Compare(a))
	}

	lab, lba := a.Less(b), b.Less(a)
	cab, cba := a.Compare(b), b.Compare(a)

	switch {
	case cab == 0:
		if a != b || lab {
			t.Fatalf("Compare(%d,%d)=0 but a!=b is %v, Less=%v", a, b, a != b, lab)
		}
	case cab == -1:
		if !lab {
			t.Fatalf("Compare(%d,%d)=-1 but Less=false", a, b)
		}
	case cab == 1:
		if lab || a == b {
			t.Fatalf("Compare(%d,%d)=+1 but Less=%v, equal=%v", a, b, lab, a == b)
		}
	default:
		t.Fatalf("Compare(%d,%d) = %d, want -1, 0, or 1", a, b, cab)
	}

	if b-a == Half16 {
		// Pinned antipode behavior: forward in both directions.
		if !lab || !lba || cab != -1 || cba != -1 {
			t.Fatalf("antipode (%d,%d): Less=%v/%v Compare=%d/%d, want true/true -1/-1",
				a, b, lab, lba, cab, cba)
		}
		return
	}
	if a == b {
		if lab || lba {
			t.Fatalf("Less(%d,%d) or Less(%d,%d) true for equal values", a, b, b, a)
		}
		return
	}
	// Away from the antipode the order is antisymmetric and total over the
	// pair: exactly one direction is Less.
	if lab == lba {
		t.Fatalf("Less antisymmetry violated for (%d,%d): both %v", a, b, lab)
	}
	if cab != -cba {
		t.Fatalf("Compare(%d,%d)=%d, Compare(%d,%d)=%d, want negation", a, b, cab, b, a, cba)
	}
}

// checkCompare32 asserts the same invariants for one 32-bit pair.
func checkCompare32(t *testing.T, a, b Num32) {
	t.Helper()

	if a.Less(a) || a.Compare(a) != 0 {
		t.Fatalf("reflexivity violated for %d: Less=%v Compare=%d", a, a.Less(a), a.Compare(a))
	}

	lab, lba := a.Less(b), b.Less(a)
	cab, cba := a.Compare(b), b.Compare(a)

	switch {
	case cab == 0:
		if a != b || lab {
			t.Fatalf("Compare(%d,%d)=0 but a!=b is %v, Less=%v", a, b, a != b, lab)
		}
	case cab == -1:
		if !lab {
			t.Fatalf("Compare(%d,%d)=-1 but Less=false", a, b)
		}
	case cab == 1:
		if lab || a == b {
			t.Fatalf("Compare(%d,%d)=+1 but Less=%v, equal=%v", a, b, lab, a == b)
		}
	default:
		t.Fatalf("Compare(%d,%d) = %d, want -1, 0, or 1", a, b, cab)
	}

	if b-a == Half32 {
		if !lab || !lba || cab != -1 || cba != -1 {
			t.Fatalf("antipode (%d,%d): Less=%v/%v Compare=%d/%d, want true/true -1/-1",
				a, b, lab, lba, cab, cba)
		}
		return
	}
	if a == b {
		if lab || lba {
			t.Fatalf("Less(%d,%d) or Less(%d,%d) true for equal values", a, b, b, a)
		}
		return
	}
	if lab == lba {
		t.Fatalf("Less antisymmetry violated for (%d,%d): both %v", a, b, lab)
	}
	if cab != -cba {
		t.Fatalf("Compare(%d,%d)=%d, Compare(%d,%d)=%d, want negation", a, b, cab, b, a, cba)
	}
}

// seedPairs16 are boundary pairs fed to every 16-bit fuzz target.
var seedPairs16 = [][2]uint16{
	{0, 0},
	{0, 1},
	{1, 0},
	{0, 0x7FFF}, // half - 1
	{0, 0x8000}, // exact antipode
	{0, 0x8001}, // half + 1
	{0, 0xFFFF}, // max
	{0xFFFF, 0}, // wrap crossing 65535 -> 0
	{0xFFFA, 5}, // wrap crossing with gap
	{1000, 2000},
}

// seedPairs32 are boundary pairs fed to every 32-bit fuzz target.
var seedPairs32 = [][2]uint32{
	{0, 0},
	{0, 1},
	{1, 0},
	{0, 0x7FFFFFFF}, // half - 1
	{0, 0x80000000}, // exact antipode
	{0, 0x80000001}, // half + 1
	{0, 0xFFFFFFFF}, // max
	{0xFFFFFFFF, 0}, // wrap crossing
	{0xFFFFFFFA, 5}, // wrap crossing with gap
	{1000, 2000},
}

// FuzzDistance16 fuzzes the 16-bit Distance invariants.
func FuzzDistance16(f *testing.F) {
	for _, p := range seedPairs16 {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b uint16) {
		checkDistance16(t, Num16(a), Num16(b))
	})
}

// FuzzDistance32 fuzzes the 32-bit Distance invariants.
func FuzzDistance32(f *testing.F) {
	for _, p := range seedPairs32 {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b uint32) {
		checkDistance32(t, Num32(a), Num32(b))
	})
}

// FuzzCompare16 fuzzes the 16-bit Less/Compare invariants.
func FuzzCompare16(f *testing.F) {
	for _, p := range seedPairs16 {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b uint16) {
		checkCompare16(t, Num16(a), Num16(b))
	})
}

// FuzzCompare32 fuzzes the 32-bit Less/Compare invariants.
func FuzzCompare32(f *testing.F) {
	for _, p := range seedPairs32 {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b uint32) {
		checkCompare32(t, Num32(a), Num32(b))
	})
}

// FuzzAddSub fuzzes Add/Sub round-trips for both widths with a shared corpus.
func FuzzAddSub(f *testing.F) {
	f.Add(uint32(0), int64(0))
	f.Add(uint32(0), int64(1))
	f.Add(uint32(0xFFFF), int64(1))
	f.Add(uint32(0xFFFFFFFF), int64(1))
	f.Add(uint32(5), int64(-10))
	f.Add(uint32(0), int64(1)<<32)
	f.Add(uint32(100), -int64(1)<<62)
	f.Fuzz(func(t *testing.T, base uint32, n int64) {
		a16 := Num16(base)
		if got := a16.Add(n).Sub(n); got != a16 {
			t.Errorf("(%d).Add(%d).Sub(%d) = %d, want %d", a16, n, n, got, a16)
		}
		a32 := Num32(base)
		if got := a32.Add(n).Sub(n); got != a32 {
			t.Errorf("(%d).Add(%d).Sub(%d) = %d, want %d", a32, n, n, got, a32)
		}
	})
}

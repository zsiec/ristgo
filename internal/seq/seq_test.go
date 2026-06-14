package seq

import (
	"fmt"
	"testing"
)

func TestInc16(t *testing.T) {
	tests := []struct {
		input    Num16
		expected Num16
	}{
		{0, 1},
		{1, 2},
		{100, 101},
		{Half16 - 1, Half16},
		{Half16, Half16 + 1},
		{Max16 - 1, Max16},
		{Max16, 0}, // wrap 65535 -> 0
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			if got := tt.input.Inc(); got != tt.expected {
				t.Errorf("(%d).Inc() = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestInc32(t *testing.T) {
	tests := []struct {
		input    Num32
		expected Num32
	}{
		{0, 1},
		{1, 2},
		{100, 101},
		{Half32 - 1, Half32},
		{Half32, Half32 + 1},
		{Max32 - 1, Max32},
		{Max32, 0}, // wrap 4294967295 -> 0
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			if got := tt.input.Inc(); got != tt.expected {
				t.Errorf("(%d).Inc() = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDec16(t *testing.T) {
	tests := []struct {
		input    Num16
		expected Num16
	}{
		{1, 0},
		{2, 1},
		{Half16, Half16 - 1},
		{Max16, Max16 - 1},
		{0, Max16}, // wrap 0 -> 65535
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			if got := tt.input.Dec(); got != tt.expected {
				t.Errorf("(%d).Dec() = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDec32(t *testing.T) {
	tests := []struct {
		input    Num32
		expected Num32
	}{
		{1, 0},
		{2, 1},
		{Half32, Half32 - 1},
		{Max32, Max32 - 1},
		{0, Max32}, // wrap 0 -> 4294967295
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			if got := tt.input.Dec(); got != tt.expected {
				t.Errorf("(%d).Dec() = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestAdd16(t *testing.T) {
	tests := []struct {
		a        Num16
		n        int64
		expected Num16
	}{
		{0, 0, 0},
		{0, 1, 1},
		{0, 100, 100},
		{Max16 - 1, 1, Max16},
		{Max16, 1, 0},      // wrap
		{Max16 - 5, 10, 4}, // wrap across boundary
		{0, int64(Max16), Max16},
		{1, int64(Max16), 0}, // 1 + 65535 wraps to 0
		{0, 1 << 16, 0},      // full ring is identity
		{5, 3 << 16, 5},      // multiple full rings
		// Negative offsets step backward.
		{0, -1, Max16},
		{10, -10, 0},
		{0, -int64(Half16), Half16}, // -32768 == +32768 mod 2^16
		{100, -(1 << 16), 100},      // -full ring is identity
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d+%d", tt.a, tt.n), func(t *testing.T) {
			if got := tt.a.Add(tt.n); got != tt.expected {
				t.Errorf("(%d).Add(%d) = %d, want %d", tt.a, tt.n, got, tt.expected)
			}
		})
	}
}

func TestAdd32(t *testing.T) {
	tests := []struct {
		a        Num32
		n        int64
		expected Num32
	}{
		{0, 0, 0},
		{0, 1, 1},
		{Max32 - 1, 1, Max32},
		{Max32, 1, 0},      // wrap
		{Max32 - 5, 10, 4}, // wrap across boundary
		{0, int64(Max32), Max32},
		{1, int64(Max32), 0}, // 1 + (2^32-1) wraps to 0
		{0, 1 << 32, 0},      // full ring is identity
		{5, 3 << 32, 5},      // multiple full rings
		// Negative offsets step backward.
		{0, -1, Max32},
		{10, -10, 0},
		{0, -int64(Half32), Half32}, // -2^31 == +2^31 mod 2^32
		{100, -(1 << 32), 100},      // -full ring is identity
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d+%d", tt.a, tt.n), func(t *testing.T) {
			if got := tt.a.Add(tt.n); got != tt.expected {
				t.Errorf("(%d).Add(%d) = %d, want %d", tt.a, tt.n, got, tt.expected)
			}
		})
	}
}

func TestSub16(t *testing.T) {
	tests := []struct {
		a        Num16
		n        int64
		expected Num16
	}{
		{0, 0, 0},
		{1, 1, 0},
		{100, 50, 50},
		{0, 1, Max16},      // wrap
		{5, 10, Max16 - 4}, // wrap across boundary
		{Max16, int64(Max16), 0},
		{0, 1 << 16, 0}, // full ring is identity
		{0, -1, 1},      // subtracting negative steps forward
		{Max16, -1, 0},  // forward across the wrap
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d-%d", tt.a, tt.n), func(t *testing.T) {
			if got := tt.a.Sub(tt.n); got != tt.expected {
				t.Errorf("(%d).Sub(%d) = %d, want %d", tt.a, tt.n, got, tt.expected)
			}
		})
	}
}

func TestSub32(t *testing.T) {
	tests := []struct {
		a        Num32
		n        int64
		expected Num32
	}{
		{0, 0, 0},
		{1, 1, 0},
		{100, 50, 50},
		{0, 1, Max32},      // wrap
		{5, 10, Max32 - 4}, // wrap across boundary
		{Max32, int64(Max32), 0},
		{0, 1 << 32, 0}, // full ring is identity
		{0, -1, 1},      // subtracting negative steps forward
		{Max32, -1, 0},  // forward across the wrap
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d-%d", tt.a, tt.n), func(t *testing.T) {
			if got := tt.a.Sub(tt.n); got != tt.expected {
				t.Errorf("(%d).Sub(%d) = %d, want %d", tt.a, tt.n, got, tt.expected)
			}
		})
	}
}

func TestDistance16(t *testing.T) {
	tests := []struct {
		a, b     Num16
		expected int64
	}{
		// Same value.
		{0, 0, 0},
		{100, 100, 0},
		{Max16, Max16, 0},

		// Normal ordering (no wrap).
		{0, 1, 1},
		{0, 100, 100},
		{100, 200, 100},
		{1, 0, -1},
		{200, 100, -100},

		// Half-range boundaries.
		{0, Half16 - 1, 32767},
		{Half16 - 1, 0, -32767},
		{0, Half16, 32768},      // exact antipode: pinned to +half
		{Half16, 0, 32768},      // exact antipode: pinned to +half (both directions)
		{0, Half16 + 1, -32767}, // one past half: wrapped, behind
		{Half16 + 1, 0, 32767},

		// Crossing the wrap: 65535 -> 0.
		{Max16, 0, 1},
		{0, Max16, -1},
		{Max16 - 5, 5, 11},
		{5, Max16 - 5, -11},
		{65530, 10, 16},
		{10, 65530, -16},

		// Antipodes away from zero.
		{100, 100 + Half16, 32768},
		{100 + Half16, 100, 32768},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("dist(%d,%d)", tt.a, tt.b), func(t *testing.T) {
			if got := tt.a.Distance(tt.b); got != tt.expected {
				t.Errorf("(%d).Distance(%d) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestDistance32(t *testing.T) {
	tests := []struct {
		a, b     Num32
		expected int64
	}{
		// Same value.
		{0, 0, 0},
		{100, 100, 0},
		{Max32, Max32, 0},

		// Normal ordering (no wrap).
		{0, 1, 1},
		{0, 100, 100},
		{1, 0, -1},
		{200, 100, -100},

		// Half-range boundaries.
		{0, Half32 - 1, 2147483647},
		{Half32 - 1, 0, -2147483647},
		{0, Half32, 2147483648},      // exact antipode: pinned to +half
		{Half32, 0, 2147483648},      // exact antipode: pinned to +half (both directions)
		{0, Half32 + 1, -2147483647}, // one past half: wrapped, behind
		{Half32 + 1, 0, 2147483647},

		// Crossing the wrap: 4294967295 -> 0.
		{Max32, 0, 1},
		{0, Max32, -1},
		{Max32 - 5, 5, 11},
		{5, Max32 - 5, -11},

		// Antipodes away from zero.
		{100, 100 + Half32, 2147483648},
		{100 + Half32, 100, 2147483648},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("dist(%d,%d)", tt.a, tt.b), func(t *testing.T) {
			if got := tt.a.Distance(tt.b); got != tt.expected {
				t.Errorf("(%d).Distance(%d) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestLess16(t *testing.T) {
	tests := []struct {
		a, b     Num16
		expected bool
	}{
		// Same value.
		{0, 0, false},
		{100, 100, false},

		// Normal ordering.
		{0, 1, true},
		{1, 0, false},
		{100, 200, true},
		{200, 100, false},

		// Crossing the wrap: Max16 is before 0.
		{Max16, 0, true},
		{0, Max16, false},
		{Max16 - 5, 5, true},
		{5, Max16 - 5, false},

		// Half-range boundaries.
		{0, Half16 - 1, true},
		{Half16 - 1, 0, false},
		{0, Half16, true}, // exact antipode: pinned forward in both directions
		{Half16, 0, true},
		{0, Half16 + 1, false}, // one past half: b is behind a
		{Half16 + 1, 0, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d<%d", tt.a, tt.b), func(t *testing.T) {
			if got := tt.a.Less(tt.b); got != tt.expected {
				t.Errorf("(%d).Less(%d) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestLess32(t *testing.T) {
	tests := []struct {
		a, b     Num32
		expected bool
	}{
		// Same value.
		{0, 0, false},
		{100, 100, false},

		// Normal ordering.
		{0, 1, true},
		{1, 0, false},
		{100, 200, true},
		{200, 100, false},

		// Crossing the wrap: Max32 is before 0.
		{Max32, 0, true},
		{0, Max32, false},
		{Max32 - 5, 5, true},
		{5, Max32 - 5, false},

		// Half-range boundaries.
		{0, Half32 - 1, true},
		{Half32 - 1, 0, false},
		{0, Half32, true}, // exact antipode: pinned forward in both directions
		{Half32, 0, true},
		{0, Half32 + 1, false}, // one past half: b is behind a
		{Half32 + 1, 0, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d<%d", tt.a, tt.b), func(t *testing.T) {
			if got := tt.a.Less(tt.b); got != tt.expected {
				t.Errorf("(%d).Less(%d) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestCompare16(t *testing.T) {
	tests := []struct {
		a, b     Num16
		expected int
	}{
		{0, 0, 0},
		{Max16, Max16, 0},
		{0, 1, -1},
		{1, 0, 1},
		{Max16, 0, -1}, // wrap: Max16 is before 0
		{0, Max16, 1},
		{0, Half16 - 1, -1},
		{Half16 - 1, 0, 1},
		{0, Half16, -1}, // exact antipode: pinned to -1 in both directions
		{Half16, 0, -1},
		{0, Half16 + 1, 1},
		{Half16 + 1, 0, -1},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("cmp(%d,%d)", tt.a, tt.b), func(t *testing.T) {
			if got := tt.a.Compare(tt.b); got != tt.expected {
				t.Errorf("(%d).Compare(%d) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestCompare32(t *testing.T) {
	tests := []struct {
		a, b     Num32
		expected int
	}{
		{0, 0, 0},
		{Max32, Max32, 0},
		{0, 1, -1},
		{1, 0, 1},
		{Max32, 0, -1}, // wrap: Max32 is before 0
		{0, Max32, 1},
		{0, Half32 - 1, -1},
		{Half32 - 1, 0, 1},
		{0, Half32, -1}, // exact antipode: pinned to -1 in both directions
		{Half32, 0, -1},
		{0, Half32 + 1, 1},
		{Half32 + 1, 0, -1},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("cmp(%d,%d)", tt.a, tt.b), func(t *testing.T) {
			if got := tt.a.Compare(tt.b); got != tt.expected {
				t.Errorf("(%d).Compare(%d) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestForwardGap16 pins the libRIST receiver_mark_missing wraparound guard:
// missing_count = (current - last) & UINT16_MAX, and missing_count > 32768
// means wraparound/reorder, not loss.
func TestForwardGap16(t *testing.T) {
	tests := []struct {
		last, current Num16
		gap           uint64
		forward       bool
	}{
		{0, 0, 0, true},                            // same packet
		{0, 1, 1, true},                            // next in order, no loss
		{0, 5, 5, true},                            // gap of 5 -> 4 missing
		{100, 99, 65535, false},                    // one-packet reorder, NOT 65534 lost
		{100, 90, 65526, false},                    // deeper reorder
		{Max16, 0, 1, true},                        // clean wrap 65535 -> 0
		{Max16 - 1, 3, 5, true},                    // loss across the wrap
		{0, Half16, uint64(Half16), true},          // exactly 32768: still forward (librist: > 32768 bails)
		{0, Half16 + 1, uint64(Half16) + 1, false}, // 32769: wraparound/reorder
		{0, Max16, 65535, false},                   // immediately-previous packet
		{12345, 12345 + Half16, 32768, true},       // antipode away from zero
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("gap(%d,%d)", tt.last, tt.current), func(t *testing.T) {
			gap, forward := tt.last.ForwardGap(tt.current)
			if gap != tt.gap || forward != tt.forward {
				t.Errorf("(%d).ForwardGap(%d) = (%d, %v), want (%d, %v)",
					tt.last, tt.current, gap, forward, tt.gap, tt.forward)
			}
		})
	}
}

func TestForwardGap32(t *testing.T) {
	tests := []struct {
		last, current Num32
		gap           uint64
		forward       bool
	}{
		{0, 0, 0, true},
		{0, 1, 1, true},
		{0, 5, 5, true},
		{100, 99, 4294967295, false},               // one-packet reorder
		{Max32, 0, 1, true},                        // clean wrap
		{Max32 - 1, 3, 5, true},                    // loss across the wrap
		{0, Half32, uint64(Half32), true},          // exactly 2^31: still forward
		{0, Half32 + 1, uint64(Half32) + 1, false}, // 2^31+1: wraparound/reorder
		{0, Max32, 4294967295, false},              // immediately-previous packet
		{12345, 12345 + Half32, 1 << 31, true},     // antipode away from zero
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("gap(%d,%d)", tt.last, tt.current), func(t *testing.T) {
			gap, forward := tt.last.ForwardGap(tt.current)
			if gap != tt.gap || forward != tt.forward {
				t.Errorf("(%d).ForwardGap(%d) = (%d, %v), want (%d, %v)",
					tt.last, tt.current, gap, forward, tt.gap, tt.forward)
			}
		})
	}
}

// TestMaxGapConstants pins the guard thresholds to the libRIST values.
func TestMaxGapConstants(t *testing.T) {
	if MaxGap16 != 32768 {
		t.Errorf("MaxGap16 = %d, want 32768", MaxGap16)
	}
	if MaxGap32 != 2147483648 {
		t.Errorf("MaxGap32 = %d, want 2147483648", MaxGap32)
	}
	if uint64(Half16) != MaxGap16 {
		t.Errorf("Half16 (%d) != MaxGap16 (%d)", Half16, MaxGap16)
	}
	if uint64(Half32) != MaxGap32 {
		t.Errorf("Half32 (%d) != MaxGap32 (%d)", Half32, MaxGap32)
	}
}

// boundary16 returns the interesting 16-bit values for property scans.
func boundary16() []Num16 {
	return []Num16{0, 1, 2, 100, Half16 - 1, Half16, Half16 + 1, Max16 - 1, Max16}
}

// boundary32 returns the interesting 32-bit values for property scans.
func boundary32() []Num32 {
	return []Num32{0, 1, 2, 100, Half32 - 1, Half32, Half32 + 1, Max32 - 1, Max32}
}

// TestDistanceLessConsistency16 exhaustively checks, for every 16-bit a and a
// sweep of offsets, that the sign of Distance agrees with Less and Compare.
func TestDistanceLessConsistency16(t *testing.T) {
	offsets := []Num16{0, 1, 2, Half16 - 1, Half16, Half16 + 1, Max16 - 1, Max16}
	for ai := 0; ai <= int(Max16); ai++ {
		a := Num16(ai)
		for _, off := range offsets {
			b := a + off
			d := a.Distance(b)
			if (d > 0) != a.Less(b) {
				t.Fatalf("(%d).Distance(%d)=%d disagrees with Less=%v", a, b, d, a.Less(b))
			}
			switch cmp := a.Compare(b); {
			case d == 0 && cmp != 0:
				t.Fatalf("(%d).Compare(%d)=%d, want 0 (distance 0)", a, b, cmp)
			case d > 0 && cmp != -1:
				t.Fatalf("(%d).Compare(%d)=%d, want -1 (distance %d)", a, b, cmp, d)
			case d < 0 && cmp != 1:
				t.Fatalf("(%d).Compare(%d)=%d, want 1 (distance %d)", a, b, cmp, d)
			}
			if got := a.Add(d); got != b {
				t.Fatalf("(%d).Add(Distance=%d) = %d, want %d", a, d, got, b)
			}
		}
	}
}

// TestDistanceLessConsistency32 checks the same properties for 32-bit over a
// boundary x boundary grid (the full space is too large to scan).
func TestDistanceLessConsistency32(t *testing.T) {
	for _, a := range boundary32() {
		for _, off := range boundary32() {
			b := a + off
			d := a.Distance(b)
			if (d > 0) != a.Less(b) {
				t.Fatalf("(%d).Distance(%d)=%d disagrees with Less=%v", a, b, d, a.Less(b))
			}
			switch cmp := a.Compare(b); {
			case d == 0 && cmp != 0:
				t.Fatalf("(%d).Compare(%d)=%d, want 0 (distance 0)", a, b, cmp)
			case d > 0 && cmp != -1:
				t.Fatalf("(%d).Compare(%d)=%d, want -1 (distance %d)", a, b, cmp, d)
			case d < 0 && cmp != 1:
				t.Fatalf("(%d).Compare(%d)=%d, want 1 (distance %d)", a, b, cmp, d)
			}
			if got := a.Add(d); got != b {
				t.Fatalf("(%d).Add(Distance=%d) = %d, want %d", a, d, got, b)
			}
		}
	}
}

// TestAntisymmetry16 verifies Less/Distance antisymmetry everywhere except
// the documented antipode pin, exhaustively over all 16-bit pairs of
// boundary values and a strided sweep.
func TestAntisymmetry16(t *testing.T) {
	check := func(a, b Num16) {
		t.Helper()
		dab, dba := a.Distance(b), b.Distance(a)
		if b-a == Half16 {
			// Pinned antipode behavior: both +Half16, both Less.
			if dab != int64(Half16) || dba != int64(Half16) {
				t.Fatalf("antipode (%d,%d): Distance = %d/%d, want both %d", a, b, dab, dba, Half16)
			}
			if !a.Less(b) || !b.Less(a) {
				t.Fatalf("antipode (%d,%d): Less = %v/%v, want both true", a, b, a.Less(b), b.Less(a))
			}
			return
		}
		if dab != -dba {
			t.Fatalf("Distance(%d,%d)=%d != -Distance(%d,%d)=%d", a, b, dab, b, a, dba)
		}
		if a != b && a.Less(b) == b.Less(a) {
			t.Fatalf("Less antisymmetry violated for (%d,%d): both %v", a, b, a.Less(b))
		}
	}

	for _, a := range boundary16() {
		for _, b := range boundary16() {
			check(a, b)
		}
	}
	for ai := 0; ai <= int(Max16); ai += 89 { // strided full-ring sweep
		for bi := 0; bi <= int(Max16); bi += 977 {
			check(Num16(ai), Num16(bi))
		}
	}
}

// TestAntisymmetry32 verifies the same on the 32-bit boundary grid.
func TestAntisymmetry32(t *testing.T) {
	for _, a := range boundary32() {
		for _, b := range boundary32() {
			dab, dba := a.Distance(b), b.Distance(a)
			if b-a == Half32 {
				if dab != int64(Half32) || dba != int64(Half32) {
					t.Fatalf("antipode (%d,%d): Distance = %d/%d, want both %d", a, b, dab, dba, Half32)
				}
				if !a.Less(b) || !b.Less(a) {
					t.Fatalf("antipode (%d,%d): Less = %v/%v, want both true", a, b, a.Less(b), b.Less(a))
				}
				continue
			}
			if dab != -dba {
				t.Fatalf("Distance(%d,%d)=%d != -Distance(%d,%d)=%d", a, b, dab, b, a, dba)
			}
			if a != b && a.Less(b) == b.Less(a) {
				t.Fatalf("Less antisymmetry violated for (%d,%d): both %v", a, b, a.Less(b))
			}
		}
	}
}

func TestIncDecRoundtrip(t *testing.T) {
	for _, v := range boundary16() {
		if got := v.Inc().Dec(); got != v {
			t.Errorf("(%d).Inc().Dec() = %d, want %d", v, got, v)
		}
		if got := v.Dec().Inc(); got != v {
			t.Errorf("(%d).Dec().Inc() = %d, want %d", v, got, v)
		}
	}
	for _, v := range boundary32() {
		if got := v.Inc().Dec(); got != v {
			t.Errorf("(%d).Inc().Dec() = %d, want %d", v, got, v)
		}
		if got := v.Dec().Inc(); got != v {
			t.Errorf("(%d).Dec().Inc() = %d, want %d", v, got, v)
		}
	}
}

func TestAddSubRoundtrip(t *testing.T) {
	offsets := []int64{0, 1, 100, -1, -100, 32768, -32768, 65535, 1 << 16, 1 << 31, 1 << 32, -(1 << 32)}
	for _, a := range boundary16() {
		for _, n := range offsets {
			if got := a.Add(n).Sub(n); got != a {
				t.Errorf("(%d).Add(%d).Sub(%d) = %d, want %d", a, n, n, got, a)
			}
		}
	}
	for _, a := range boundary32() {
		for _, n := range offsets {
			if got := a.Add(n).Sub(n); got != a {
				t.Errorf("(%d).Add(%d).Sub(%d) = %d, want %d", a, n, n, got, a)
			}
		}
	}
}

// TestSixteenBitWrapSequence walks a contiguous stream across the 65535 -> 0
// boundary the way a receiver tracking last_seq_found would.
func TestSixteenBitWrapSequence(t *testing.T) {
	last := Num16(65530)
	for i := 0; i < 20; i++ {
		cur := last.Inc()
		if !last.Less(cur) {
			t.Fatalf("stream not monotonic at %d -> %d", last, cur)
		}
		if d := last.Distance(cur); d != 1 {
			t.Fatalf("Distance(%d,%d) = %d, want 1", last, cur, d)
		}
		gap, forward := last.ForwardGap(cur)
		if gap != 1 || !forward {
			t.Fatalf("ForwardGap(%d,%d) = (%d,%v), want (1,true)", last, cur, gap, forward)
		}
		last = cur
	}
	if last != Num16(65550-65536) {
		t.Fatalf("walk ended at %d, want %d", last, 65550-65536)
	}
}

// TestThirtyTwoBitWrapSequence is the 32-bit analog.
func TestThirtyTwoBitWrapSequence(t *testing.T) {
	last := Max32 - 5
	for i := 0; i < 20; i++ {
		cur := last.Inc()
		if !last.Less(cur) {
			t.Fatalf("stream not monotonic at %d -> %d", last, cur)
		}
		if d := last.Distance(cur); d != 1 {
			t.Fatalf("Distance(%d,%d) = %d, want 1", last, cur, d)
		}
		last = cur
	}
	if last != Num32(14) {
		t.Fatalf("walk ended at %d, want 14", last)
	}
}

func TestValue(t *testing.T) {
	if got := Num16(42).Value(); got != 42 {
		t.Errorf("Num16(42).Value() = %d, want 42", got)
	}
	if got := Max16.Value(); got != 0xFFFF {
		t.Errorf("Max16.Value() = %#x, want 0xFFFF", got)
	}
	if got := Num32(42).Value(); got != 42 {
		t.Errorf("Num32(42).Value() = %d, want 42", got)
	}
	if got := Max32.Value(); got != 0xFFFFFFFF {
		t.Errorf("Max32.Value() = %#x, want 0xFFFFFFFF", got)
	}
}

// Benchmarks

func BenchmarkInc16(b *testing.B) {
	n := Num16(0)
	for b.Loop() {
		n = n.Inc()
	}
}

func BenchmarkDistance16(b *testing.B) {
	x, y := Num16(65530), Num16(10)
	for b.Loop() {
		x.Distance(y)
	}
}

func BenchmarkLess16(b *testing.B) {
	x, y := Num16(65530), Num16(10)
	for b.Loop() {
		x.Less(y)
	}
}

func BenchmarkForwardGap16(b *testing.B) {
	x, y := Num16(65530), Num16(10)
	for b.Loop() {
		x.ForwardGap(y)
	}
}

func BenchmarkDistance32(b *testing.B) {
	x, y := Max32-5, Num32(10)
	for b.Loop() {
		x.Distance(y)
	}
}

func BenchmarkLess32(b *testing.B) {
	x, y := Max32-5, Num32(10)
	for b.Loop() {
		x.Less(y)
	}
}

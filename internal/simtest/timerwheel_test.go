package simtest

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

// timerIDsEqual reports whether two TimerID slices are element-wise equal.
func timerIDsEqual(a, b []TimerID) bool {
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

// TestTimerWheelPopDueOrdering verifies PopDue returns due timers sorted
// by (deadline, id) for a spread of arming patterns.
func TestTimerWheelPopDueOrdering(t *testing.T) {
	tests := []struct {
		name string
		arm  map[TimerID]clock.Timestamp
		now  clock.Timestamp
		want []TimerID
	}{
		{
			name: "empty wheel",
			arm:  nil,
			now:  100,
			want: nil,
		},
		{
			name: "nothing due yet",
			arm:  map[TimerID]clock.Timestamp{1: 200, 2: 300},
			now:  100,
			want: nil,
		},
		{
			name: "distinct deadlines fire in time order regardless of id",
			arm:  map[TimerID]clock.Timestamp{5: 100, 1: 300, 9: 200},
			now:  300,
			want: []TimerID{5, 9, 1},
		},
		{
			name: "equal deadlines tie-break by id",
			arm:  map[TimerID]clock.Timestamp{7: 100, 2: 100, 4: 100},
			now:  100,
			want: []TimerID{2, 4, 7},
		},
		{
			name: "mixed: time-major then id-minor",
			arm:  map[TimerID]clock.Timestamp{8: 50, 3: 100, 1: 100, 6: 75, 9: 999},
			now:  100,
			want: []TimerID{8, 6, 1, 3},
		},
		{
			name: "due-at-exactly-now included",
			arm:  map[TimerID]clock.Timestamp{1: 100},
			now:  100,
			want: []TimerID{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewTimerWheel()
			for id, at := range tt.arm {
				w.Set(id, at)
			}
			got := w.PopDue(tt.now)
			if !timerIDsEqual(got, tt.want) {
				t.Errorf("PopDue(%d) = %v, want %v", tt.now, got, tt.want)
			}
		})
	}
}

// TestTimerWheelOrderingDeterminism re-runs an identical many-timer
// scenario repeatedly: Go randomizes map iteration, so any order leak
// from the internal map shows up as run-to-run divergence.
func TestTimerWheelOrderingDeterminism(t *testing.T) {
	build := func() *TimerWheel {
		w := NewTimerWheel()
		for id := TimerID(0); id < 64; id++ {
			// Four distinct deadlines, sixteen ids each: plenty of ties.
			w.Set(id, clock.Timestamp(100+int64(id%4)*10))
		}
		return w
	}
	want := build().PopDue(200)
	if len(want) != 64 {
		t.Fatalf("popped %d timers, want 64", len(want))
	}
	for run := 0; run < 50; run++ {
		if got := build().PopDue(200); !timerIDsEqual(got, want) {
			t.Fatalf("run %d: PopDue order diverged:\n got %v\nwant %v", run, got, want)
		}
	}
	// And the order is exactly (deadline, id): deadline buckets ascending,
	// ids ascending within each.
	for i := 1; i < len(want); i++ {
		di, dj := want[i-1]%4, want[i]%4
		if di > dj || (di == dj && want[i-1] >= want[i]) {
			t.Fatalf("want[%d..%d] = %d, %d violates (deadline, id) order", i-1, i, want[i-1], want[i])
		}
	}
}

// TestTimerWheelSetRearm verifies re-arming replaces the deadline rather
// than queuing a second expiration.
func TestTimerWheelSetRearm(t *testing.T) {
	w := NewTimerWheel()
	w.Set(1, 100)
	w.Set(1, 500) // re-arm later

	if got := w.PopDue(100); len(got) != 0 {
		t.Fatalf("PopDue(100) after re-arm = %v, want none", got)
	}
	if got := w.PopDue(500); !timerIDsEqual(got, []TimerID{1}) {
		t.Fatalf("PopDue(500) = %v, want [1]", got)
	}

	w.Set(2, 500)
	w.Set(2, 100) // re-arm earlier
	if got := w.PopDue(100); !timerIDsEqual(got, []TimerID{2}) {
		t.Fatalf("PopDue(100) after earlier re-arm = %v, want [2]", got)
	}
}

// TestTimerWheelClear verifies Clear cancels an armed timer and is a
// no-op on unarmed ids.
func TestTimerWheelClear(t *testing.T) {
	w := NewTimerWheel()
	w.Set(1, 100)
	w.Set(2, 100)
	w.Clear(1)
	w.Clear(99) // never armed: no-op

	if got := w.PopDue(100); !timerIDsEqual(got, []TimerID{2}) {
		t.Errorf("PopDue(100) = %v, want [2]", got)
	}
}

// TestTimerWheelNextDeadline verifies the minimum-deadline report across
// arming, clearing, and popping.
func TestTimerWheelNextDeadline(t *testing.T) {
	w := NewTimerWheel()
	if _, ok := w.NextDeadline(); ok {
		t.Fatal("empty wheel reported a deadline")
	}

	w.Set(3, 300)
	w.Set(1, 100)
	w.Set(2, 200)
	if at, ok := w.NextDeadline(); !ok || at != 100 {
		t.Fatalf("NextDeadline = %d, %v; want 100, true", at, ok)
	}

	w.Clear(1)
	if at, ok := w.NextDeadline(); !ok || at != 200 {
		t.Fatalf("NextDeadline after Clear(1) = %d, %v; want 200, true", at, ok)
	}

	if got := w.PopDue(200); !timerIDsEqual(got, []TimerID{2}) {
		t.Fatalf("PopDue(200) = %v, want [2]", got)
	}
	if at, ok := w.NextDeadline(); !ok || at != 300 {
		t.Fatalf("NextDeadline after pop = %d, %v; want 300, true", at, ok)
	}

	w.Clear(3)
	if _, ok := w.NextDeadline(); ok {
		t.Fatal("emptied wheel still reports a deadline")
	}
}

// TestTimerWheelPopRemoves verifies popped timers do not fire again and
// not-yet-due timers survive the pop.
func TestTimerWheelPopRemoves(t *testing.T) {
	w := NewTimerWheel()
	w.Set(1, 100)
	w.Set(2, 200)

	if got := w.PopDue(150); !timerIDsEqual(got, []TimerID{1}) {
		t.Fatalf("first PopDue = %v, want [1]", got)
	}
	if got := w.PopDue(150); len(got) != 0 {
		t.Fatalf("second PopDue(150) = %v, want none (already fired)", got)
	}
	if got := w.PopDue(200); !timerIDsEqual(got, []TimerID{2}) {
		t.Fatalf("PopDue(200) = %v, want [2] (survived earlier pop)", got)
	}
}

// TestTimerWheelZeroValue verifies the zero value works without NewTimerWheel.
func TestTimerWheelZeroValue(t *testing.T) {
	var w TimerWheel
	if _, ok := w.NextDeadline(); ok {
		t.Fatal("zero-value wheel reported a deadline")
	}
	if got := w.PopDue(100); len(got) != 0 {
		t.Fatalf("zero-value PopDue = %v, want none", got)
	}
	w.Clear(1) // no-op on nil map must not panic
	w.Set(1, 50)
	if got := w.PopDue(100); !timerIDsEqual(got, []TimerID{1}) {
		t.Fatalf("PopDue after Set on zero value = %v, want [1]", got)
	}
}

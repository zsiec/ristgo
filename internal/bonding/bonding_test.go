package bonding

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

const (
	testTimeout = 2000 * clock.Millisecond // libRIST session_timeout default
	testRTTMin  = 5 * clock.Millisecond
	testRTTMax  = 500 * clock.Millisecond
)

func newGroup() *Group { return NewGroup(testTimeout, testRTTMin, testRTTMax) }

// at converts a microsecond duration into a clock.Timestamp instant.
func at(d clock.Microseconds) clock.Timestamp { return clock.Timestamp(d) }

// TestAddPathUpdate checks AddPath registers a path and re-adding updates its
// weight/priority in place rather than duplicating it.
func TestAddPathUpdate(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 0)
	g.AddPath(1, WeightDuplicate, 5)
	if len(g.Paths()) != 2 {
		t.Fatalf("got %d paths, want 2", len(g.Paths()))
	}
	g.AddPath(1, 3, 9) // update index 1
	if len(g.Paths()) != 2 {
		t.Fatalf("re-add duplicated a path: %d", len(g.Paths()))
	}
	if p := g.path(1); p.Weight != 3 || p.Priority != 9 {
		t.Fatalf("update: weight/priority = %d/%d, want 3/9", p.Weight, p.Priority)
	}
}

// TestLiveness checks Observe marks a path alive, Tick declares it dead after
// the session timeout (reporting the transition once), and a later Observe
// resurrects it.
func TestLiveness(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 0)

	// Never-seen path is not alive and Tick never reports it.
	if g.Alive(0, at(0)) {
		t.Fatal("unseen path reported alive")
	}
	if d := g.Tick(at(testTimeout * 10)); len(d) != 0 {
		t.Fatalf("unseen path reported dead: %v", d)
	}

	g.Observe(0, at(1000*clock.Millisecond))
	if !g.Alive(0, at(1000*clock.Millisecond)) {
		t.Fatal("observed path not alive")
	}
	// Still alive within the timeout.
	if !g.Alive(0, at(1000*clock.Millisecond+testTimeout)) {
		t.Fatal("path dead at exactly the timeout boundary (should be inclusive)")
	}
	if d := g.Tick(at(1000*clock.Millisecond + testTimeout)); len(d) != 0 {
		t.Fatalf("Tick at boundary reported dead: %v", d)
	}

	// Past the timeout: Tick reports the death exactly once.
	dead := g.Tick(at(1000*clock.Millisecond + testTimeout + 1))
	if len(dead) != 1 || dead[0] != 0 {
		t.Fatalf("Tick past timeout = %v, want [0]", dead)
	}
	if d := g.Tick(at(1000*clock.Millisecond + testTimeout*5)); len(d) != 0 {
		t.Fatalf("Tick re-reported an already-dead path: %v", d)
	}
	if g.Alive(0, at(1000*clock.Millisecond+testTimeout*5)) {
		t.Fatal("path still alive after death")
	}

	// Resurrect on a fresh observation; the death edge can fire again later.
	g.Observe(0, at(10_000*clock.Millisecond))
	if !g.Alive(0, at(10_000*clock.Millisecond)) {
		t.Fatal("path not resurrected by Observe")
	}
	if d := g.Tick(at(10_000*clock.Millisecond + testTimeout + 1)); len(d) != 1 || d[0] != 0 {
		t.Fatalf("Tick after resurrection+timeout = %v, want [0] (death edge re-armed)", d)
	}
}

// TestSelectNackPathPriority checks NACK-peer selection prefers the highest
// recovery priority among live paths.
func TestSelectNackPathPriority(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 1)
	g.AddPath(1, WeightDuplicate, 5) // highest priority
	g.AddPath(2, WeightDuplicate, 3)
	now := clock.Timestamp(1000 * clock.Millisecond)
	for i := uint8(0); i < 3; i++ {
		g.Observe(i, now)
	}
	if idx, ok := g.SelectNackPath(now); !ok || idx != 1 {
		t.Fatalf("SelectNackPath = %d (ok=%v), want 1 (highest priority)", idx, ok)
	}
}

// TestSelectNackPathRTTTieBreak checks that, on a priority tie, the lowest-RTT
// live path wins.
func TestSelectNackPathRTTTieBreak(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 2)
	g.AddPath(1, WeightDuplicate, 2) // same priority, will get lower RTT
	now := clock.Timestamp(1000 * clock.Millisecond)
	g.Observe(0, now)
	g.Observe(1, now)
	// Settle each path's EWMA to DISAGREE with its freshest sample, so the
	// tie-break can only pick path 1 if it uses the raw last sample (libRIST
	// last_rtt), not the smoothed EWMA. Path 0: long-low EWMA then one high
	// sample (last high). Path 1: long-high EWMA then one low sample (last low).
	for i := 0; i < 30; i++ {
		g.ObserveRTT(0, 20*clock.Millisecond)
		g.ObserveRTT(1, 300*clock.Millisecond)
	}
	g.ObserveRTT(0, 300*clock.Millisecond) // path 0: last 300ms, EWMA still low
	g.ObserveRTT(1, 20*clock.Millisecond)  // path 1: last 20ms, EWMA still high
	if idx, ok := g.SelectNackPath(now); !ok || idx != 1 {
		t.Fatalf("SelectNackPath = %d (ok=%v), want 1 (raw last RTT 20ms < 300ms; the smoothed EWMA would wrongly pick 0)", idx, ok)
	}
}

// TestSelectNackPathSkipsDead checks dead paths are excluded, even when they
// have the highest priority.
func TestSelectNackPathSkipsDead(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 9) // highest priority, will die
	g.AddPath(1, WeightDuplicate, 1)
	g.Observe(0, at(0))
	now := at(testTimeout + 1) // past path 0's timeout
	g.Observe(1, now)          // path 1 stays fresh; path 0 went silent at t=0
	g.Tick(now)                // path 0 (silent past the timeout) is now dead
	if g.Alive(0, now) {
		t.Fatal("path 0 should be dead")
	}
	if idx, ok := g.SelectNackPath(now); !ok || idx != 1 {
		t.Fatalf("SelectNackPath = %d (ok=%v), want 1 (path 0 dead despite higher priority)", idx, ok)
	}
}

// TestSelectNackPathAllDeadFallback checks that when every path is dead the
// selection falls back to the most-recently-dead path (best recovery chance),
// rather than abandoning the NACK.
func TestSelectNackPathAllDeadFallback(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 0)
	g.AddPath(1, WeightDuplicate, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(1000*clock.Millisecond)) // path 1 seen more recently
	// Age both out.
	late := clock.Timestamp(1000*clock.Millisecond + testTimeout + 1)
	g.Tick(late)
	if g.Alive(0, late) || g.Alive(1, late) {
		t.Fatal("both paths should be dead")
	}
	if idx, ok := g.SelectNackPath(late); !ok || idx != 1 {
		t.Fatalf("all-dead fallback = %d (ok=%v), want 1 (seen most recently)", idx, ok)
	}
}

// TestSelectNackPathAllNeverSeen checks the fallback never routes a NACK to a
// path that has never been observed (no address, no evidence it can answer).
func TestSelectNackPathAllNeverSeen(t *testing.T) {
	g := newGroup()
	g.AddPath(3, WeightDuplicate, 0)
	g.AddPath(7, WeightDuplicate, 0)
	if idx, ok := g.SelectNackPath(at(1000 * clock.Millisecond)); ok {
		t.Fatalf("SelectNackPath returned (%d, true) with only never-seen paths; want ok=false", idx)
	}
}

// TestDuplicateTargets checks the sender-side fan-out set: all duplicate-weight
// paths (including never-seen ones, since a sender transmits before return
// traffic proves liveness), minus any proven dead, and excluding weighted paths.
func TestDuplicateTargets(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 0)
	g.AddPath(1, WeightDuplicate, 0)
	g.AddPath(2, 5, 0) // weighted, not a 2022-7 duplicate target
	now := at(1000 * clock.Millisecond)

	if got := g.DuplicateTargets(now); !equalU8(got, []uint8{0, 1}) {
		t.Fatalf("never-seen DuplicateTargets = %v, want [0 1]", got)
	}

	g.Observe(0, at(0)) // path 0 last seen at t=0 (will be dead at late)
	late := at(testTimeout + 100*clock.Millisecond)
	g.Observe(1, late) // path 1 fresh
	if got := g.DuplicateTargets(late); !equalU8(got, []uint8{1}) {
		t.Fatalf("DuplicateTargets after path 0 death = %v, want [1]", got)
	}
}

func equalU8(a, b []uint8) bool {
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

// TestSelectNackPathNoPaths checks ok=false when no path is registered.
func TestSelectNackPathNoPaths(t *testing.T) {
	g := newGroup()
	if _, ok := g.SelectNackPath(0); ok {
		t.Fatal("SelectNackPath ok=true with no paths registered")
	}
}

package bonding

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

const (
	testTimeout  = 2000 * clock.Millisecond // libRIST session_timeout default
	testDupGrace = 1000 * clock.Millisecond // libRIST hard_dead recovery_buffer grace
	testRTTMin   = 5 * clock.Millisecond
	testRTTMax   = 500 * clock.Millisecond
)

func newGroup() *Group { return NewGroup(testTimeout, testDupGrace, testRTTMin, testRTTMax) }

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

// TestHasPathPreservesPriority checks HasPath reports registration and that the
// "register only if absent" pattern the session uses preserves a priority the
// host pre-set, rather than overwriting it with the default.
func TestHasPathPreservesPriority(t *testing.T) {
	g := newGroup()
	if g.HasPath(0) {
		t.Fatal("HasPath(0) true before any AddPath")
	}
	g.AddPath(0, WeightDuplicate, 7) // host pre-registers path 0 with priority 7
	if !g.HasPath(0) {
		t.Fatal("HasPath(0) false after AddPath")
	}
	// The session registers each path only if absent, so the pre-set priority
	// survives.
	if !g.HasPath(0) {
		g.AddPath(0, WeightDuplicate, 0)
	}
	if p := g.path(0); p.Priority != 7 {
		t.Fatalf("priority = %d, want 7 (HasPath guard must preserve it)", p.Priority)
	}
	// An absent path is registered with the default.
	if !g.HasPath(1) {
		g.AddPath(1, WeightDuplicate, 0)
	}
	if p := g.path(1); p == nil || p.Priority != 0 {
		t.Fatalf("path 1 = %v, want priority 0", p)
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
	if idx, ok := g.SelectNackPath(now, nil); !ok || idx != 1 {
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
	if idx, ok := g.SelectNackPath(now, nil); !ok || idx != 1 {
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
	if idx, ok := g.SelectNackPath(now, nil); !ok || idx != 1 {
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
	if idx, ok := g.SelectNackPath(late, nil); !ok || idx != 1 {
		t.Fatalf("all-dead fallback = %d (ok=%v), want 1 (seen most recently)", idx, ok)
	}
}

// TestSelectNackPathAddrKnownPredicate checks that a path whose return address
// is not yet known is excluded from BOTH the live selection and the all-dead
// fallback, so a NACK is never routed to an unaddressable path.
func TestSelectNackPathAddrKnownPredicate(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 0) // higher-priority candidate, but address unknown
	g.AddPath(1, WeightDuplicate, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))
	// Only path 1 has a known return address.
	known := func(i uint8) bool { return i == 1 }

	// Live selection skips path 0 (unaddressable) and picks path 1.
	if idx, ok := g.SelectNackPath(at(10*clock.Millisecond), known); !ok || idx != 1 {
		t.Fatalf("live select with addrKnown = %d (ok=%v), want 1 (path 0 has no address)", idx, ok)
	}

	// All dead: the fallback also honors the predicate (path 0 excluded).
	late := clock.Timestamp(testTimeout + 1)
	g.Tick(late)
	if idx, ok := g.SelectNackPath(late, known); !ok || idx != 1 {
		t.Fatalf("all-dead fallback with addrKnown = %d (ok=%v), want 1", idx, ok)
	}

	// If the only seen path is unaddressable, no path is selected.
	if idx, ok := g.SelectNackPath(late, func(i uint8) bool { return false }); ok {
		t.Fatalf("SelectNackPath returned (%d, true) with no addressable path; want ok=false", idx)
	}
}

// TestSelectNackPathAllNeverSeen checks the fallback never routes a NACK to a
// path that has never been observed (no address, no evidence it can answer).
func TestSelectNackPathAllNeverSeen(t *testing.T) {
	g := newGroup()
	g.AddPath(3, WeightDuplicate, 0)
	g.AddPath(7, WeightDuplicate, 0)
	if idx, ok := g.SelectNackPath(at(1000*clock.Millisecond), nil); ok {
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

	g.Observe(0, at(0)) // path 0 last seen at t=0 (hard-dead at testTimeout+testDupGrace)
	// Past session_timeout but within the duplicate grace: path 0 is reported dead
	// for liveness/NACK routing, yet its 2022-7 redundancy persists, so it is STILL
	// a duplicate target (libRIST's hard_dead grace).
	inGrace := at(testTimeout + 100*clock.Millisecond)
	g.Observe(1, inGrace) // path 1 fresh
	if g.Alive(0, inGrace) {
		t.Fatal("path 0 still Alive past session_timeout")
	}
	if got := g.DuplicateTargets(inGrace); !equalU8(got, []uint8{0, 1}) {
		t.Fatalf("DuplicateTargets within grace = %v, want [0 1] (redundancy held)", got)
	}
	// Past session_timeout + grace: path 0 is hard-dead and pruned from the fan-out.
	late := at(testTimeout + testDupGrace + 1)
	g.Observe(1, late) // keep path 1 fresh
	if got := g.DuplicateTargets(late); !equalU8(got, []uint8{1}) {
		t.Fatalf("DuplicateTargets after path 0 hard-death = %v, want [1]", got)
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
	if _, ok := g.SelectNackPath(0, nil); ok {
		t.Fatal("SelectNackPath ok=true with no paths registered")
	}
}

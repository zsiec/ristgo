package bonding

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

// tally runs n weighted selections at instant now and counts how many landed on
// each path index (selections that report ok=false are not counted).
func tally(g *Group, now clock.Timestamp, n int) map[uint8]int {
	m := map[uint8]int{}
	for i := 0; i < n; i++ {
		if idx, ok := g.SelectWeighted(now); ok {
			m[idx]++
		}
	}
	return m
}

// TestSelectWeightedNoWeightedPaths confirms a group with only duplicate paths
// reports no weighted target, so a sender duplicates and never load-shares.
func TestSelectWeightedNoWeightedPaths(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 0)
	g.AddPath(1, WeightDuplicate, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))
	if g.HasWeighted() {
		t.Fatal("HasWeighted true with only duplicate paths")
	}
	if _, ok := g.SelectWeighted(at(0)); ok {
		t.Fatal("SelectWeighted reported a target with no weighted path")
	}
}

// TestSelectWeightedProportions verifies the rotation splits packets across the
// weighted paths in proportion to their weights over each round.
func TestSelectWeightedProportions(t *testing.T) {
	g := newGroup()
	g.AddPath(0, 3, 0)
	g.AddPath(1, 1, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))

	// 4 rounds of total-weight 4 = 16 packets: path 0 gets 3/4, path 1 gets 1/4.
	got := tally(g, at(0), 16)
	if got[0] != 12 || got[1] != 4 {
		t.Fatalf("weighted split = %v, want path0=12 path1=4 (3:1)", got)
	}
}

// TestSelectWeightedEqualSmooth verifies equal weights interleave one-for-one
// rather than sending one path's whole share before the other.
func TestSelectWeightedEqualSmooth(t *testing.T) {
	g := newGroup()
	g.AddPath(0, 1, 0)
	g.AddPath(1, 1, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))

	want := []uint8{0, 1, 0, 1, 0, 1}
	for i, w := range want {
		idx, ok := g.SelectWeighted(at(0))
		if !ok || idx != w {
			t.Fatalf("selection %d = (%d,%v), want (%d,true)", i, idx, ok, w)
		}
	}
}

// TestSelectWeightedNeverSeenIsSendable confirms a weighted path that has not yet
// been heard from still receives its share: a sender load-shares from the start,
// before any return traffic proves a path live.
func TestSelectWeightedNeverSeenIsSendable(t *testing.T) {
	g := newGroup()
	g.AddPath(0, 1, 0)
	g.AddPath(1, 1, 0) // never observed
	got := tally(g, at(0), 4)
	if got[0] != 2 || got[1] != 2 {
		t.Fatalf("never-seen path excluded: %v, want path0=2 path1=2", got)
	}
}

// TestSelectWeightedDeadPathRedistributes verifies a weighted path proven dead is
// skipped and its share passes to the surviving weighted path, rather than those
// packets being black-holed.
func TestSelectWeightedDeadPathRedistributes(t *testing.T) {
	g := newGroup()
	g.AddPath(0, 1, 0)
	g.AddPath(1, 1, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))

	// Advance past the session timeout and refresh only path 0, so path 1 is now
	// silent-dead while path 0 is live.
	now := at(testTimeout + clock.Millisecond)
	g.Observe(0, now)
	if !g.Alive(0, now) || g.Alive(1, now) {
		t.Fatalf("liveness setup wrong: alive0=%v alive1=%v", g.Alive(0, now), g.Alive(1, now))
	}
	got := tally(g, now, 5)
	if got[1] != 0 {
		t.Fatalf("dead path 1 still selected %d times", got[1])
	}
	if got[0] != 5 {
		t.Fatalf("surviving path 0 got %d, want all 5 (dead path's share redistributed)", got[0])
	}
}

// TestSelectWeightedAllDead confirms that when every weighted path is dead the
// selection reports no target (the caller falls back to whatever duplicate paths
// remain, or drops the datagram).
func TestSelectWeightedAllDead(t *testing.T) {
	g := newGroup()
	g.AddPath(0, 1, 0)
	g.AddPath(1, 2, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))
	now := at(testTimeout + clock.Millisecond) // both silent past the timeout
	if _, ok := g.SelectWeighted(now); ok {
		t.Fatal("SelectWeighted reported a target with every weighted path dead")
	}
}

// TestSelectWeightedMixedWithDuplicate confirms the weighted rotation only ever
// elects weighted paths: a WeightDuplicate path is carried by ShouldDuplicate and
// must never be returned by SelectWeighted (or it would be double-sent).
func TestSelectWeightedMixedWithDuplicate(t *testing.T) {
	g := newGroup()
	g.AddPath(0, WeightDuplicate, 0) // every packet, via ShouldDuplicate
	g.AddPath(1, 1, 0)
	g.AddPath(2, 1, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))
	g.Observe(2, at(0))

	got := tally(g, at(0), 8)
	if got[0] != 0 {
		t.Fatalf("duplicate path 0 was elected by SelectWeighted %d times", got[0])
	}
	if got[1] != 4 || got[2] != 4 {
		t.Fatalf("weighted split = %v, want path1=4 path2=4", got)
	}
	if !g.ShouldDuplicate(0, at(0)) {
		t.Fatal("ShouldDuplicate(0) false; the duplicate path must still get every packet")
	}
}

// TestSetWeightDynamic verifies a runtime weight change re-proportions the
// rotation from the next round (libRIST rist_peer_weight_set), and that setting a
// weight to 0 returns the path to duplication.
func TestSetWeightDynamic(t *testing.T) {
	g := newGroup()
	g.AddPath(0, 1, 0)
	g.AddPath(1, 1, 0)
	g.Observe(0, at(0))
	g.Observe(1, at(0))

	// Even split first.
	if got := tally(g, at(0), 8); got[0] != 4 || got[1] != 4 {
		t.Fatalf("initial split = %v, want 4/4", got)
	}

	// Promote path 0 to weight 3: the next rounds split 3:1.
	g.SetWeight(0, 3)
	if got := tally(g, at(0), 16); got[0] != 12 || got[1] != 4 {
		t.Fatalf("after SetWeight(0,3) split = %v, want path0=12 path1=4", got)
	}

	// Return path 1 to duplication: only path 0 is weighted now.
	g.SetWeight(1, WeightDuplicate)
	if !g.ShouldDuplicate(1, at(0)) {
		t.Fatal("SetWeight(1,0) did not return path 1 to duplication")
	}
	if got := tally(g, at(0), 5); got[0] != 5 || got[1] != 0 {
		t.Fatalf("after demoting path 1 split = %v, want all on path 0", got)
	}
}

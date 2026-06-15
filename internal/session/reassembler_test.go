package session

import (
	"slices"
	"testing"

	"github.com/zsiec/ristgo/internal/wire"
)

// TestFragReassembler exhaustively drives the fragment reassembler through the
// complete-payload, abandoned-run, and orphaned-fragment paths a fragmented
// Advanced stream produces — the discard logic that a recovering ARQ e2e never
// reaches (it recovers every fragment) but one-way / lossy transport does.
func TestFragReassembler(t *testing.T) {
	type step struct {
		role wire.FragRole
		data string
		disc bool // Discontinuity: the flow core skipped a sequence before this
	}
	cases := []struct {
		name  string
		steps []step
		want  []string // payloads delivered, in order
	}{
		// --- completion paths ---
		{"standalone", []step{{wire.FragStandalone, "abc", false}}, []string{"abc"}},
		{"first-middle-last", []step{
			{wire.FragFirst, "aa", false}, {wire.FragMiddle, "bb", false}, {wire.FragLast, "cc", false},
		}, []string{"aabbcc"}},
		{"first-last no middle", []step{
			{wire.FragFirst, "aa", false}, {wire.FragLast, "bb", false},
		}, []string{"aabb"}},
		{"two runs back to back", []step{
			{wire.FragFirst, "aa", false}, {wire.FragLast, "bb", false},
			{wire.FragFirst, "cc", false}, {wire.FragLast, "dd", false},
		}, []string{"aabb", "ccdd"}},
		{"standalone between runs", []step{
			{wire.FragFirst, "aa", false}, {wire.FragLast, "bb", false},
			{wire.FragStandalone, "xx", false},
			{wire.FragFirst, "cc", false}, {wire.FragLast, "dd", false},
		}, []string{"aabb", "xx", "ccdd"}},
		{"discontinuity on first still delivers", []step{
			{wire.FragFirst, "aa", true}, // a prior payload was lost; this run is intact
			{wire.FragLast, "bb", false},
		}, []string{"aabb"}},

		// --- discard paths (a fragment lost and not recovered) ---
		{"lost first: orphan middle+last dropped", []step{
			{wire.FragMiddle, "bb", true}, {wire.FragLast, "cc", true},
		}, nil},
		{"orphan middle+last, no discontinuity flag, still dropped", []step{
			{wire.FragMiddle, "bb", false}, {wire.FragLast, "cc", false},
		}, nil},
		{"lost middle: last with discontinuity drops the run", []step{
			{wire.FragFirst, "aa", false}, {wire.FragLast, "cc", true},
		}, nil},
		{"lost interior middle: gap resets, trailing last orphaned", []step{
			{wire.FragFirst, "aa", false}, {wire.FragMiddle, "cc", true}, {wire.FragLast, "dd", false},
		}, nil},
		{"lost last: incomplete run abandoned at the next first", []step{
			{wire.FragFirst, "aa", false}, {wire.FragMiddle, "bb", false},
			{wire.FragFirst, "cc", true}, {wire.FragLast, "dd", false}, // new run, prior dropped
		}, []string{"ccdd"}},
		{"standalone abandons a broken open run", []step{
			{wire.FragFirst, "aa", false}, {wire.FragStandalone, "xx", false},
		}, []string{"xx"}},
		{"recover after a dropped run", []step{
			{wire.FragFirst, "aa", false}, {wire.FragLast, "bb", true}, // dropped
			{wire.FragFirst, "cc", false}, {wire.FragLast, "dd", false}, // clean
		}, []string{"ccdd"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r fragReassembler
			var got []string
			for _, s := range c.steps {
				// Copy each output to a string immediately (the FragLast slice
				// aliases the reused buffer), exactly as queueDelivery copies.
				if out, ok := r.push(s.role, []byte(s.data), s.disc); ok {
					got = append(got, string(out))
				}
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("delivered %q, want %q", got, c.want)
			}
		})
	}
}

// TestFragReassemblerBoundsRun verifies a peer that opens a run and then streams
// FragMiddle without ever closing it cannot grow the buffer without bound: once
// the run reaches MaxReassemblyFragments the reassembler abandons it (delivers
// nothing and frees the buffer), and a later FragLast on that dead run is dropped.
func TestFragReassemblerBoundsRun(t *testing.T) {
	var r fragReassembler
	chunk := []byte("0123456789abcdef") // 16 bytes per fragment

	if _, ok := r.push(wire.FragFirst, chunk, false); ok {
		t.Fatal("FragFirst should not complete a payload")
	}
	// Feed far more middles than the cap. None complete, and the buffer must stop
	// growing at the cap rather than accumulating every fragment.
	for i := 0; i < MaxReassemblyFragments*4; i++ {
		if _, ok := r.push(wire.FragMiddle, chunk, false); ok {
			t.Fatalf("FragMiddle %d should not complete a payload", i)
		}
	}
	if got := len(r.buf); got > MaxReassemblyFragments*len(chunk) {
		t.Fatalf("buffer grew to %d bytes, want <= %d (run not bounded)", got, MaxReassemblyFragments*len(chunk))
	}
	// The run was abandoned, so a closing FragLast finds no open run and is dropped.
	if _, ok := r.push(wire.FragLast, chunk, false); ok {
		t.Fatal("FragLast on an over-long (abandoned) run should be dropped, not delivered")
	}

	// A fresh, in-bounds run still completes normally after the abandonment.
	r.push(wire.FragFirst, []byte("aa"), false)
	out, ok := r.push(wire.FragLast, []byte("bb"), false)
	if !ok || string(out) != "aabb" {
		t.Fatalf("recovery run delivered %q ok=%v, want \"aabb\" true", out, ok)
	}
}

// TestFragReassemblerNoAllocSteadyState verifies the reassembler reuses its
// buffer: after a warm-up run sizes it, a same-shape run allocates nothing.
func TestFragReassemblerNoAllocSteadyState(t *testing.T) {
	var r fragReassembler
	first := []byte("first-fragment-payload")
	mid := []byte("middle-fragment-payload")
	last := []byte("last-fragment-payload")
	run := func() {
		r.push(wire.FragFirst, first, false)
		r.push(wire.FragMiddle, mid, false)
		r.push(wire.FragLast, last, false)
	}
	run() // warm up: let the buffer reach its steady-state capacity

	if n := testing.AllocsPerRun(100, run); n != 0 {
		t.Fatalf("reassembler allocated %v times per run, want 0", n)
	}
}

package bonding

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

// FuzzGroupOperations drives a Group through an arbitrary sequence of operations
// derived from the fuzz input and asserts the state machine never panics and
// keeps its core invariant: SelectNackPath, when it reports ok, returns the
// index of a registered path. The bonding state machine takes adversarial,
// out-of-order, and out-of-range inputs from the network (path indices, arrival
// times, RTT samples), so it must be panic-free on any of them.
func FuzzGroupOperations(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 2, 200, 3, 0})
	f.Add([]byte{1, 5, 1, 7, 4, 255, 4, 1, 5, 100})

	f.Fuzz(func(t *testing.T, data []byte) {
		g := NewGroup(2000*clock.Millisecond, 5*clock.Millisecond, 500*clock.Millisecond)
		registered := make(map[uint8]bool)
		var now clock.Timestamp

		// Each iteration consumes a (op, arg) byte pair; the op selects a Group
		// method and arg parameterizes it. Time advances monotonically so Tick and
		// liveness behave as in production.
		for i := 0; i+1 < len(data); i += 2 {
			op, arg := data[i], data[i+1]
			now += clock.Timestamp(uint64(arg) * uint64(clock.Millisecond))
			switch op % 7 {
			case 0:
				g.AddPath(arg, int(arg%4), uint32(arg))
				registered[arg] = true
			case 1:
				g.Observe(arg, now)
			case 2:
				g.ObserveRTT(arg, clock.Microseconds(arg)*clock.Millisecond)
			case 3:
				g.Alive(arg, now)
			case 4:
				for _, idx := range g.Tick(now) {
					if !registered[idx] {
						t.Fatalf("Tick reported dead unregistered path %d", idx)
					}
				}
			case 5:
				if idx, ok := g.SelectNackPath(now, nil); ok && !registered[idx] {
					t.Fatalf("SelectNackPath returned unregistered path %d", idx)
				}
			case 6:
				g.DuplicateTargets(now)
			}
		}
	})
}

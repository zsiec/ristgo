package simtest

import (
	"sort"

	"github.com/zsiec/ristgo/internal/clock"
)

// TimerID identifies one declarative timer requested by a sans-I/O core.
// The flow core requests timers via SetTimer/ClearTimer effects carrying an
// identifier of this shape; the host — here, the simulator — owns the wheel.
// It is defined locally so the wheel needs no dependency on flow's effect
// enum; the Fabric bridges simtest.TimerID and flow.TimerID by explicit
// conversion at the SetTimer/ClearTimer and HandleTimer boundaries (see
// fabric.go drainSender/Step).
type TimerID uint32

// TimerWheel is the I/O side of a core's declarative timers: one deadline
// per TimerID, obeying SetTimer/ClearTimer effects and reporting the
// earliest armed deadline. It never reads a clock; the driver passes
// fake-clock instants in.
//
// The zero value is an empty wheel ready for use.
type TimerWheel struct {
	deadlines map[TimerID]clock.Timestamp
}

// NewTimerWheel creates an empty wheel.
func NewTimerWheel() *TimerWheel {
	return &TimerWheel{}
}

// Set arms (or re-arms) id to fire at deadline, replacing any previous
// deadline for the same id.
func (w *TimerWheel) Set(id TimerID, deadline clock.Timestamp) {
	if w.deadlines == nil {
		w.deadlines = make(map[TimerID]clock.Timestamp)
	}
	w.deadlines[id] = deadline
}

// Clear cancels id if armed; clearing an unarmed id is a no-op.
func (w *TimerWheel) Clear(id TimerID) {
	delete(w.deadlines, id)
}

// NextDeadline returns the earliest armed deadline. ok is false when no
// timer is armed.
func (w *TimerWheel) NextDeadline() (deadline clock.Timestamp, ok bool) {
	for _, at := range w.deadlines {
		if !ok || at.Before(deadline) {
			deadline = at
			ok = true
		}
	}
	return deadline, ok
}

// PopDue removes and returns every timer due at or before now, sorted by
// (deadline, id) so simultaneous expirations fire in a deterministic
// order. (The srtrust source sorts due timers by id alone; ristgo's plan
// pins the stricter deadline-major order so a wheel holding distinct due
// deadlines fires them in time order.)
func (w *TimerWheel) PopDue(now clock.Timestamp) []TimerID {
	type dueTimer struct {
		id TimerID
		at clock.Timestamp
	}
	var due []dueTimer
	for id, at := range w.deadlines {
		if !at.After(now) {
			due = append(due, dueTimer{id: id, at: at})
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if due[i].at != due[j].at {
			return due[i].at.Before(due[j].at)
		}
		return due[i].id < due[j].id
	})
	ids := make([]TimerID, len(due))
	for i, d := range due {
		ids[i] = d.id
		delete(w.deadlines, d.id)
	}
	return ids
}

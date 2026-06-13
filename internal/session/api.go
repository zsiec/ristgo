package session

import (
	"time"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
)

// Write enqueues one application payload for transmission (sender role). It
// copies p — the flow retains the payload in its retransmit history, so the
// caller may reuse its buffer once Write returns. It blocks until the payload
// is accepted by the event loop (back-pressure when the loop is saturated),
// the write deadline passes (ErrTimeout), or the session closes (ErrClosed).
//
// Write is not safe to call from multiple goroutines concurrently.
func (s *Session) Write(p []byte) error {
	cp := make([]byte, len(p))
	copy(cp, p)
	for {
		// A Write on a closed session must report the close reason and never
		// enqueue into a buffer the (exited) loop will not drain.
		select {
		case <-s.done:
			return s.closeReason()
		default:
		}
		timer, expired := s.deadlineTimerFor(s.writeDeadline.Load())
		if expired {
			return s.cfg.ErrTimeout
		}
		var timeout <-chan time.Time
		if timer != nil {
			timeout = timer.C
		}
		select {
		case s.appIn <- cp:
			stopOptTimer(timer)
			return nil
		case <-s.done:
			stopOptTimer(timer)
			return s.closeReason()
		case <-timeout:
			return s.cfg.ErrTimeout
		case <-s.writeWake:
			stopOptTimer(timer) // deadline changed; re-evaluate
		}
	}
}

// Read returns the next in-order, ARQ-recovered media payload (receiver role).
// It has stream semantics: a payload larger than buf is returned across
// successive calls. It blocks until data is available, the read deadline
// passes (ErrTimeout), or the session closes (ErrClosed, after any buffered
// payloads are drained).
//
// Read is not safe to call from multiple goroutines concurrently.
func (s *Session) Read(buf []byte) (int, error) {
	if len(s.leftover) > 0 {
		n := copy(buf, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}
	for {
		// Deliver buffered data ahead of everything else, even after close.
		select {
		case p := <-s.delivery:
			return s.take(buf, p), nil
		default:
		}
		timer, expired := s.deadlineTimerFor(s.readDeadline.Load())
		if expired {
			return 0, s.cfg.ErrTimeout
		}
		var timeout <-chan time.Time
		if timer != nil {
			timeout = timer.C
		}
		select {
		case p := <-s.delivery:
			stopOptTimer(timer)
			return s.take(buf, p), nil
		case <-s.done:
			stopOptTimer(timer)
			select {
			case p := <-s.delivery:
				return s.take(buf, p), nil
			default:
				return 0, s.closeReason()
			}
		case <-timeout:
			return 0, s.cfg.ErrTimeout
		case <-s.readWake:
			stopOptTimer(timer) // deadline changed; re-evaluate
		}
	}
}

// take copies as much of payload as fits into buf, stashing any remainder for
// the next Read (stream semantics for io.Copy).
func (s *Session) take(buf, payload []byte) int {
	n := copy(buf, payload)
	if n < len(payload) {
		s.leftover = payload[n:]
	}
	return n
}

// deadlineTimerFor returns a timer firing at dl, or expired=true when dl is
// already in the past. Both are zero/false when no deadline is set.
func (s *Session) deadlineTimerFor(dl *time.Time) (timer *time.Timer, expired bool) {
	if dl == nil || dl.IsZero() {
		return nil, false
	}
	d := time.Until(*dl)
	if d <= 0 {
		return nil, true
	}
	return time.NewTimer(d), false
}

func stopOptTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// SetReadDeadline sets the deadline for Read; a zero time clears it. A pending
// Read is woken so it observes the new deadline.
func (s *Session) SetReadDeadline(t time.Time) {
	s.readDeadline.Store(&t)
	select {
	case s.readWake <- struct{}{}:
	default:
	}
}

// SetWriteDeadline sets the deadline for Write; a zero time clears it. A
// pending Write is woken so it observes the new deadline.
func (s *Session) SetWriteDeadline(t time.Time) {
	s.writeDeadline.Store(&t)
	select {
	case s.writeWake <- struct{}{}:
	default:
	}
}

// Stats returns the most recent snapshot of the flow's counters.
func (s *Session) Stats() flow.Stats { return *s.stats.Load() }

// MediaPort returns the local media (even) UDP port.
func (s *Session) MediaPort() int { return s.conn.MediaPort() }

// Err returns the reason the session closed, or nil if it is still open.
func (s *Session) Err() error {
	if p := s.closeErr.Load(); p != nil {
		return *p
	}
	return nil
}

// Close shuts the session down: it stops the event loop and reader goroutines,
// closes the sockets, and waits for every goroutine to exit. It is idempotent
// and safe to call concurrently with Read/Write.
func (s *Session) Close() error {
	s.shutdown(s.cfg.ErrClosed)
	s.wg.Wait()
	return nil
}

// shutdown records the close reason and signals every goroutine exactly once.
// It is safe to call from the event loop (on session timeout or buffer
// overflow) or the application goroutine (Close); only Close waits on the
// goroutines.
func (s *Session) shutdown(reason error) {
	s.closeOnce.Do(func() {
		s.closeErr.Store(&reason)
		close(s.done)
		s.conn.Close() // unblock the reader goroutines' blocking ReadFrom
	})
}

// closeReason returns the stored close reason, defaulting to ErrClosed.
func (s *Session) closeReason() error {
	if p := s.closeErr.Load(); p != nil {
		return *p
	}
	return s.cfg.ErrClosed
}

// setTimer records the flow's requested deadline for id.
func (s *Session) setTimer(id flow.TimerID, deadline clock.Timestamp) {
	s.timers[id] = deadline
}

// clearTimer cancels the flow's timer for id.
func (s *Session) clearTimer(id flow.TimerID) {
	delete(s.timers, id)
}

// earliestTimer returns the soonest pending declarative timer.
func (s *Session) earliestTimer() (id flow.TimerID, deadline clock.Timestamp, ok bool) {
	for tid, d := range s.timers {
		if !ok || d.Before(deadline) {
			id, deadline, ok = tid, d, true
		}
	}
	return id, deadline, ok
}

// rearm resets the host time.Timer to the earliest pending declarative
// deadline, or leaves it stopped when none remain.
func (s *Session) rearm(timer *time.Timer, now clock.Timestamp) {
	stopTimer(timer)
	if _, deadline, ok := s.earliestTimer(); ok {
		d := deadline.Sub(now).Duration()
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
	}
}

package session

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/peer"
	"github.com/zsiec/ristgo/internal/socket"
)

// TestMaybeRebindCaller exercises the caller-receiver socket-rebind trigger: an
// eligible (single-socket, non-SRP, non-bonded) caller-receiver re-binds its socket
// once the peer has been silent past max(SessionTimeout, 4×keepalive), while a
// non-eligible session does not (so the loop tears it down instead).
func TestMaybeRebindCaller(t *testing.T) {
	const ka = 100 * clock.Millisecond
	const st = 200 * clock.Millisecond
	t0 := clock.Timestamp(1_000_000) // arbitrary

	conn, err := socket.ListenEphemeralSingle("127.0.0.1")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	newSess := func(eligible bool) *Session {
		s := &Session{
			conn: conn,
			cfg:  Config{SessionTimeout: st, KeepaliveInterval: ka},
			peer: peer.New(st),
		}
		if eligible {
			s.callerRebind = true
			s.main = &mainCodec{} // mark a single-socket Main session
		}
		s.peer.Observe(t0)
		return s
	}

	// Non-eligible: never rebinds (loop will time it out).
	if s := newSess(false); s.maybeRebindCaller(t0.Add(500 * clock.Millisecond)) {
		t.Fatal("non-eligible session reported a rebind/keep-alive; want false (time out)")
	}

	// Eligible but not yet silent enough (< 400 ms): kept alive, no rebind.
	s := newSess(true)
	port0 := conn.MediaPort()
	if !s.maybeRebindCaller(t0.Add(100 * clock.Millisecond)) {
		t.Fatal("eligible session not kept alive before the silence threshold")
	}
	if s.rebindAttempts != 0 || conn.MediaPort() != port0 {
		t.Fatalf("rebound too early: attempts=%d port %d->%d", s.rebindAttempts, port0, conn.MediaPort())
	}

	// Silent past max(SessionTimeout=200ms, 4×keepalive=400ms): rebinds.
	if !s.maybeRebindCaller(t0.Add(500 * clock.Millisecond)) {
		t.Fatal("eligible silent session did not keep alive / rebind")
	}
	if s.rebindAttempts != 1 {
		t.Fatalf("rebindAttempts = %d, want 1", s.rebindAttempts)
	}
	if conn.MediaPort() == port0 {
		t.Fatalf("socket was not rebound (local port still %d)", port0)
	}
}

// eligibleRebindSession builds an eligible caller-receiver for the rebind tests,
// with the peer observed at t0.
func eligibleRebindSession(t *testing.T, t0 clock.Timestamp, st, ka clock.Microseconds) (*Session, *socket.Conn) {
	t.Helper()
	conn, err := socket.ListenEphemeralSingle("127.0.0.1")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &Session{
		conn:         conn,
		cfg:          Config{SessionTimeout: st, KeepaliveInterval: ka},
		peer:         peer.New(st),
		callerRebind: true,
		main:         &mainCodec{},
	}
	s.peer.Observe(t0)
	return s, conn
}

// TestMaybeRebindCallerGivesUp verifies a permanently-gone sender eventually makes
// maybeRebindCaller return false (so the session times out) rather than rebinding
// forever — the backoff caps only the gap between attempts, not their count.
func TestMaybeRebindCallerGivesUp(t *testing.T) {
	const ka = 100 * clock.Millisecond
	const st = 200 * clock.Millisecond
	now := clock.Timestamp(1_000_000)
	s, conn := eligibleRebindSession(t, now, st, ka)
	defer conn.Close()

	minSilence := 4 * ka // max(st, 4*ka)
	gaveUp := false
	for i := 0; i < rebindMaxAttempts+5; i++ {
		// Advance past both the silence threshold and the current backoff gap so the
		// only thing that can stop a rebind is the attempt cap. The peer is never
		// re-observed (sender permanently gone), so the recovery reset never fires.
		mult := clock.Microseconds(s.rebindAttempts)
		if mult > rebindBackoffCap {
			mult = rebindBackoffCap
		}
		adv := minSilence
		if g := mult * st; g > adv {
			adv = g
		}
		now = now.Add(adv + clock.Millisecond)
		if !s.maybeRebindCaller(now) {
			gaveUp = true
			break
		}
	}
	if !gaveUp {
		t.Fatalf("never gave up (rebindAttempts=%d); a permanently-gone sender must eventually time out", s.rebindAttempts)
	}
	if s.rebindAttempts > rebindMaxAttempts {
		t.Fatalf("rebindAttempts = %d, exceeds the cap %d", s.rebindAttempts, rebindMaxAttempts)
	}
}

// TestMaybeRebindCallerRecoveryResets verifies that a rebind which recovers the
// stream (real traffic arrives afterward) resets the attempt counter, so a later
// unrelated silence gets a fresh set of attempts rather than inheriting old ones.
func TestMaybeRebindCallerRecoveryResets(t *testing.T) {
	const ka = 100 * clock.Millisecond
	const st = 200 * clock.Millisecond
	now := clock.Timestamp(1_000_000)
	s, conn := eligibleRebindSession(t, now, st, ka)
	defer conn.Close()

	// First rebind after the silence threshold.
	now = now.Add(500 * clock.Millisecond)
	if !s.maybeRebindCaller(now) || s.rebindAttempts != 1 {
		t.Fatalf("first rebind: attempts=%d, want 1", s.rebindAttempts)
	}
	// The rebind recovered the stream: real traffic arrives after it.
	now = now.Add(50 * clock.Millisecond)
	s.peer.Observe(now)
	// Silent again past the threshold: a fresh event. The counter must have reset on
	// recovery, so this is attempt 1 again (not 2).
	now = now.Add(500 * clock.Millisecond)
	if !s.maybeRebindCaller(now) {
		t.Fatal("did not rebind on the new silence event")
	}
	if s.rebindAttempts != 1 {
		t.Fatalf("rebindAttempts = %d, want 1 (recovery must reset the counter)", s.rebindAttempts)
	}
}

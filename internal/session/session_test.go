package session

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/socket"
)

var (
	errTestClosed   = errors.New("closed")
	errTestTimeout  = errors.New("timeout")
	errTestSessTO   = errors.New("session timeout")
	errTestOverflow = errors.New("overflow")
)

func testConfig() Config {
	fc := flow.DefaultConfig()
	fc.RecoveryBufferMin = 50 * clock.Millisecond
	fc.RecoveryBufferMax = 50 * clock.Millisecond
	return Config{
		Flow:              fc,
		SSRC:              2,
		CNAME:             "test",
		KeepaliveInterval: 1000 * clock.Millisecond,
		SessionTimeout:    2000 * clock.Millisecond,
		ErrClosed:         errTestClosed,
		ErrTimeout:        errTestTimeout,
		ErrSessionTimeout: errTestSessTO,
		ErrBufferOverflow: errTestOverflow,
	}
}

func loopbackConn(t *testing.T) *socket.Conn {
	t.Helper()
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen a: %v", err)
	}
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		a.Close()
		t.Fatalf("listen b: %v", err)
	}
	return socket.FromConns(a, b)
}

// TestWriteAfterCloseReturnsClosed is the regression guard for the close-race
// bug: every Write on a closed sender must return ErrClosed and never silently
// enqueue into the (undrained) appIn buffer.
func TestWriteAfterCloseReturnsClosed(t *testing.T) {
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	s := NewSender(loopbackConn(t), dst, dst, testConfig())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i := 0; i < 200; i++ {
		if err := s.Write([]byte("x")); err != errTestClosed {
			t.Fatalf("Write %d after Close = %v, want ErrClosed", i, err)
		}
	}
}

// TestReadDeadlineWakesBlockedRead is the regression guard for the deadline
// bug: a deadline set while a Read is already blocked must take effect.
func TestReadDeadlineWakesBlockedRead(t *testing.T) {
	s := NewReceiver(loopbackConn(t), testConfig())
	defer s.Close()

	done := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 64)) // blocks: no sender
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let Read park with no deadline

	start := time.Now()
	s.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	select {
	case err := <-done:
		if err != errTestTimeout {
			t.Fatalf("Read = %v, want ErrTimeout", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("Read returned after %v; deadline not honored promptly", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetReadDeadline did not wake the blocked Read")
	}
}

// TestReadUnblockedByClose verifies Close wakes a blocked Read with the close
// reason.
func TestReadUnblockedByClose(t *testing.T) {
	s := NewReceiver(loopbackConn(t), testConfig())
	done := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 64))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	select {
	case err := <-done:
		if err != errTestClosed {
			t.Fatalf("Read after Close = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

// TestTimerWheel unit-tests the declarative timer wheel directly (using a
// session whose event loop is not started, so the map is not shared).
func TestTimerWheel(t *testing.T) {
	conn := loopbackConn(t)
	defer conn.Close()
	s := newSession(conn, testConfig(), false)

	if _, _, ok := s.earliestTimer(); ok {
		t.Fatal("empty wheel reported a timer")
	}
	s.setTimer(flow.TimerPlayout, 100)
	s.setTimer(flow.TimerNack, 50)
	s.setTimer(flow.TimerRttEcho, 200)
	id, deadline, ok := s.earliestTimer()
	if !ok || id != flow.TimerNack || deadline != 50 {
		t.Fatalf("earliest = (%v, %d, %v), want (TimerNack, 50, true)", id, deadline, ok)
	}
	s.clearTimer(flow.TimerNack)
	if id, _, _ := s.earliestTimer(); id != flow.TimerPlayout {
		t.Fatalf("after clearing Nack, earliest = %v, want TimerPlayout", id)
	}
	// Re-arming replaces the deadline.
	s.setTimer(flow.TimerPlayout, 10)
	if id, deadline, _ := s.earliestTimer(); id != flow.TimerPlayout || deadline != 10 {
		t.Fatalf("re-armed earliest = (%v, %d), want (TimerPlayout, 10)", id, deadline)
	}
}

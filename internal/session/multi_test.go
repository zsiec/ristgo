package session

import (
	"errors"
	"testing"

	"github.com/zsiec/ristgo/internal/socket"
)

// TestMultiReceiverFlowCap verifies the demuxer caps concurrent flows at maxFlows:
// once the cap is reached, further keys are dropped (nil session, no stop) and no
// new flow or goroutine is created, so a flood of spurious SSRCs cannot open
// unbounded sessions. It then confirms every per-flow retire goroutine exits on
// close (no goroutine leak).
func TestMultiReceiverFlowCap(t *testing.T) {
	built := 0
	mk := func(_ *socket.Conn, _ Config) (*Session, error) {
		built++
		return &Session{done: make(chan struct{})}, nil // lightweight: retire only needs Done()
	}
	m := newMulti(nil, Config{}, false, mk)

	for i := 0; i < maxFlows; i++ {
		s, stop := m.flowFor(uint32(i), uint32(i))
		if stop || s == nil {
			t.Fatalf("flow %d: got (nil=%v, stop=%v), want a live session", i, s == nil, stop)
		}
	}
	// Past the cap: every further key is dropped, not opened.
	for i := maxFlows; i < maxFlows+64; i++ {
		s, stop := m.flowFor(uint32(i), uint32(i))
		if s != nil || stop {
			t.Fatalf("over-cap flow %d: got (session=%v, stop=%v), want (nil, false)", i, s != nil, stop)
		}
	}
	if built != maxFlows {
		t.Fatalf("built %d sessions, want exactly maxFlows=%d", built, maxFlows)
	}
	if got := len(m.flows); got != maxFlows {
		t.Fatalf("flow map holds %d, want maxFlows=%d", got, maxFlows)
	}

	// Closing must release every retire goroutine; Wait hangs (test timeout) on a leak.
	close(m.done)
	m.wg.Wait()
}

// TestMultiReceiverRetireIdentityGuard pins both branches of retire's identity
// check: a flow that ends is deleted, but a stale retire for an already-replaced
// flow (same key, resumed as a fresh session) must not evict the live one.
func TestMultiReceiverRetireIdentityGuard(t *testing.T) {
	// Ended flow is removed.
	t.Run("ended flow deleted", func(t *testing.T) {
		m := newMulti(nil, Config{}, false, nil)
		s := &Session{done: make(chan struct{})}
		m.flows[uint32(1)] = s
		m.wg.Add(1)
		close(s.done) // the session ended
		go m.retire(uint32(1), s)
		m.wg.Wait()
		if _, ok := m.flows[uint32(1)]; ok {
			t.Fatal("retire did not delete the ended flow")
		}
	})

	// A stale retire for the old session must leave the resumed flow in place.
	t.Run("resumed flow survives stale retire", func(t *testing.T) {
		m := newMulti(nil, Config{}, false, nil)
		old := &Session{done: make(chan struct{})}
		cur := &Session{done: make(chan struct{})}
		m.flows[uint32(2)] = cur // the key was re-created as a fresh session
		m.wg.Add(1)
		close(old.done) // the old session's retire fires
		go m.retire(uint32(2), old)
		m.wg.Wait()
		if m.flows[uint32(2)] != cur {
			t.Fatal("a stale retire evicted the resumed flow")
		}
	})
}

// TestMultiReceiverFactoryErrorDrops verifies a per-flow build failure (e.g. a
// crypto key derivation error) drops that datagram instead of installing a broken
// session or spawning a retire goroutine. The next datagram retries the build.
func TestMultiReceiverFactoryErrorDrops(t *testing.T) {
	fail := true
	mk := func(_ *socket.Conn, _ Config) (*Session, error) {
		if fail {
			return nil, errors.New("derive key: simulated failure")
		}
		return &Session{done: make(chan struct{})}, nil
	}
	m := newMulti(nil, Config{}, false, mk)

	s, stop := m.flowFor(uint32(7), uint32(7))
	if s != nil || stop {
		t.Fatalf("on build error: got (session=%v, stop=%v), want (nil, false)", s != nil, stop)
	}
	if len(m.flows) != 0 {
		t.Fatalf("a failed build left %d flows in the map, want 0", len(m.flows))
	}

	// A later datagram for the same key retries and succeeds.
	fail = false
	s, stop = m.flowFor(uint32(7), uint32(7))
	if s == nil || stop {
		t.Fatalf("retry after recovery: got (nil=%v, stop=%v), want a live session", s == nil, stop)
	}
	if len(m.flows) != 1 {
		t.Fatalf("after a successful retry the map holds %d flows, want 1", len(m.flows))
	}

	close(m.done)
	m.wg.Wait()
}

// FuzzDemuxPeek asserts the demux classifiers never panic on arbitrary bytes:
// they bound their reads off the datagram length and return ok=false on a runt.
func FuzzDemuxPeek(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x80})
	f.Add(make([]byte, 12))
	f.Add([]byte{0x80, 0xC8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07})                         // RTCP-ish
	f.Add([]byte{0x80, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}) // RTP-ish
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = peekMediaSSRC(b)
		_, _ = peekRTCPSSRC(b)
	})
}

// TestDemuxPeekNoAlloc pins the per-datagram demux key extraction as
// allocation-free (the copy a routed datagram needs is separate).
func TestDemuxPeekNoAlloc(t *testing.T) {
	media := make([]byte, 1316)
	rtcp := make([]byte, 60)
	if n := testing.AllocsPerRun(1000, func() {
		_, _ = peekMediaSSRC(media)
		_, _ = peekRTCPSSRC(rtcp)
	}); n != 0 {
		t.Fatalf("demux peek allocated %v times per run, want 0", n)
	}
}

// TestDemuxPeekRunts confirms a short datagram is classified unroutable rather
// than read out of bounds.
func TestDemuxPeekRunts(t *testing.T) {
	for _, b := range [][]byte{nil, {}, make([]byte, 7), make([]byte, 11)} {
		if _, ok := peekRTCPSSRC(b); ok && len(b) < 8 {
			t.Fatalf("peekRTCPSSRC accepted a %d-byte runt", len(b))
		}
		if _, ok := peekMediaSSRC(b); ok && len(b) < rtpHeaderSize {
			t.Fatalf("peekMediaSSRC accepted a %d-byte runt", len(b))
		}
	}
}

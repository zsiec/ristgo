package flow

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// TestRTCPEchoCadenceReq1 pins TR-06-1 §5.2.1 requirement 1 (successive RTCP
// packets ≤ 100 ms apart): once the receiver flow has started, it originates an
// RTT-echo compound every 100 ms and KEEPS doing so with no further media — so the
// RTCP interval stays ≤ 100 ms even on an idle-but-live flow, not just while media
// is actively arriving.
func TestRTCPEchoCadenceReq1(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	f.Feed(10_000, 0, mkPkt(100, 0, []byte("a")))
	drainOutputs(f) // initial TimerPlayout + TimerRttEcho schedule

	// No further media. Fire the echo timer repeatedly; each fire must emit an
	// RTT-echo request and re-arm the next one no more than 100 ms later.
	now := clock.Timestamp(110_000)
	for i := 0; i < 5; i++ {
		f.HandleTimer(now, TimerRttEcho)
		var (
			sawEcho      bool
			nextDeadline clock.Timestamp
		)
		for _, o := range drainOutputs(f) {
			switch v := o.(type) {
			case SendFeedback:
				if _, ok := v.FB.(wire.RttEchoRequest); ok {
					sawEcho = true
				}
			case SetTimer:
				if v.ID == TimerRttEcho {
					nextDeadline = v.Deadline
				}
			}
		}
		if !sawEcho {
			t.Fatalf("iteration %d: no RTT-echo emitted on an idle-but-live flow (Req 1 violated)", i)
		}
		if nextDeadline == 0 {
			t.Fatalf("iteration %d: RTT-echo cadence not re-armed", i)
		}
		if d := nextDeadline.Sub(now); d > 100*clock.Millisecond {
			t.Fatalf("iteration %d: next RTCP %v after the last (> 100 ms; Req 1 violated)", i, d)
		}
		now = nextDeadline
	}
}

package flow

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// drainAll discards every pending output without allocating, for use inside
// allocation-gated loops (drainOutputs builds a slice and would itself count).
func drainAll(f *Flow) {
	for {
		if _, ok := f.PollOutput(); !ok {
			break
		}
	}
	for {
		if _, ok := f.PollEvent(); !ok {
			break
		}
	}
}

// TestReceiverFeedZeroAlloc is the receiver hot-path allocation gate: once the
// flow has started and the playout timer is armed at the earliest deadline,
// every in-order Feed writes its slot and emits nothing (the timer stays armed
// at the oldest packet), so steady-state ingest allocates zero times.
func TestReceiverFeedZeroAlloc(t *testing.T) {
	f := New(RoleReceiver, testConfig())
	payload := make([]byte, 1316) // a typical 7-cell MPEG-TS RTP payload
	seqn := uint32(1000)

	// Warm up: the first packet starts the flow and arms the timers.
	f.Feed(0, 0, wire.MediaPacket{Seq: seqn, SourceTime: srcNTP(0), Payload: payload})
	seqn++
	drainAll(f)

	allocs := testing.AllocsPerRun(2000, func() {
		us := clock.Microseconds(int64(seqn) * 1000)
		f.Feed(clock.Timestamp(us), 0, wire.MediaPacket{Seq: seqn, SourceTime: srcNTP(us), Payload: payload})
		seqn++
		drainAll(f)
	})
	if allocs != 0 {
		t.Errorf("steady-state in-order Feed allocates %v times/op, want 0", allocs)
	}
}

// TestSenderPushAppOneAlloc is the sender hot-path allocation gate: after the
// first PushApp arms the RTT-echo timer, each subsequent PushApp emits exactly
// one SendMedia effect, whose interface boxing into the drain queue is the
// single expected allocation per packet. A regression adding a second per-packet
// allocation (e.g. a payload copy) would trip this gate rather than passing CI.
func TestSenderPushAppOneAlloc(t *testing.T) {
	f := New(RoleSender, senderConfig())
	payload := make([]byte, 1316)

	// Warm up: the first PushApp also pushes a SetTimer; exclude it.
	f.PushApp(0, payload)
	drainAll(f)

	allocs := testing.AllocsPerRun(2000, func() {
		f.PushApp(0, payload)
		drainAll(f)
	})
	if allocs != 1 {
		t.Errorf("steady-state PushApp allocates %v times/op, want 1 (the SendMedia effect box)", allocs)
	}
}

// BenchmarkReceiverFeedInOrder measures the receiver ingest hot path.
func BenchmarkReceiverFeedInOrder(b *testing.B) {
	f := New(RoleReceiver, testConfig())
	payload := make([]byte, 1316)
	seqn := uint32(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		us := clock.Microseconds(int64(seqn) * 1000)
		f.Feed(clock.Timestamp(us), 0, wire.MediaPacket{Seq: seqn, SourceTime: srcNTP(us), Payload: payload})
		seqn++
		drainAll(f)
	}
}

// BenchmarkSenderPushApp measures the sender transmit hot path. It emits one
// SendMedia effect per call; the interface boxing of that effect into the
// drain queue is the expected single allocation per packet, inherent to the
// sans-I/O effect-queue design (the per-byte codec path stays zero-alloc).
func BenchmarkSenderPushApp(b *testing.B) {
	f := New(RoleSender, senderConfig())
	payload := make([]byte, 1316)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.PushApp(clock.Timestamp(int64(i)*1000), payload)
		drainAll(f)
	}
}

// BenchmarkServiceNack measures the retransmit-servicing path: a NACK for a
// run of buffered sequences, spaced beyond the retransmit gate so every
// request resends. MaxRetries is raised out of the way so the steady state
// keeps resending (rather than exhausting the per-packet retry budget).
func BenchmarkServiceNack(b *testing.B) {
	cfg := senderConfig()
	cfg.MaxRetries = 1 << 30
	f := New(RoleSender, cfg)
	payload := make([]byte, 1316)
	const win = 16
	for i := 0; i < win; i++ {
		f.PushApp(clock.Timestamp(int64(i)*1000), payload)
	}
	drainAll(f)
	missing := make([]uint32, win)
	for i := range missing {
		missing[i] = 100 + uint32(i) // senderConfig starts at StartSeq 100
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Advance well past the gate each iteration so all resend.
		f.FeedFeedback(clock.Timestamp(i+1)*clock.Timestamp(clock.Second), wire.NackRequest{Missing: missing})
		drainAll(f)
	}
}

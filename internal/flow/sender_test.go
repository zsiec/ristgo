package flow

import (
	"reflect"
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/wire"
)

// senderConfig returns the libRIST defaults with an even base SSRC and a
// fixed start sequence for deterministic assertions.
func senderConfig() Config {
	c := DefaultConfig()
	c.SSRC = 0x1234_5678 // even: LSB reserved for the retransmit marker
	c.StartSeq = 100
	return c
}

// mediaOutputs extracts SendMedia effects in order.
func mediaOutputs(outs []Output) []SendMedia {
	var ms []SendMedia
	for _, o := range outs {
		if m, ok := o.(SendMedia); ok {
			ms = append(ms, m)
		}
	}
	return ms
}

func TestPushAppFirstPacketArmsEchoAndSends(t *testing.T) {
	f := New(RoleSender, senderConfig())
	f.PushApp(10_000, []byte("a"))

	outs := drainOutputs(f)
	want := []Output{
		SetTimer{ID: TimerRttEcho, Deadline: 110_000}, // now + 100ms
		SendMedia{Path: 0, Pkt: wire.MediaPacket{
			Seq:        100,
			SourceTime: srcNTP(10_000),
			SSRC:       0x1234_5678,
			Payload:    []byte("a"),
		}},
	}
	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("outputs = %v, want %v", outs, want)
	}
	if f.Stats().Sent != 1 {
		t.Fatalf("Sent = %d, want 1", f.Stats().Sent)
	}

	// A stored history entry the retransmit path can find.
	sl := &f.sender.ring[100&f.sender.mask]
	if sl.state != slotFilled || sl.seq != 100 || string(sl.payload) != "a" {
		t.Fatalf("history slot = %+v, want filled seq 100 payload a", sl)
	}

	// Second packet: next sequence, no re-arm, steady state.
	f.PushApp(11_000, []byte("b"))
	outs = drainOutputs(f)
	want2 := []Output{SendMedia{Path: 0, Pkt: wire.MediaPacket{
		Seq:        101,
		SourceTime: srcNTP(11_000),
		SSRC:       0x1234_5678,
		Payload:    []byte("b"),
	}}}
	if !reflect.DeepEqual(outs, want2) {
		t.Fatalf("second outputs = %v, want %v", outs, want2)
	}
}

func TestServiceNackRetransmitsFromHistory(t *testing.T) {
	f := New(RoleSender, senderConfig())
	f.PushApp(10_000, []byte("a")) // seq 100
	f.PushApp(11_000, []byte("b")) // seq 101
	f.PushApp(12_000, []byte("c")) // seq 102
	drainOutputs(f)

	// NACK for 101: retransmit the original bytes with Retransmit set,
	// same seq, same sourceTime, base (even) SSRC — the codec toggles the
	// LSB, never the core.
	f.FeedFeedback(20_000, wire.NackRequest{SSRC: 0x1234_5678, Missing: []uint32{101}})
	ms := mediaOutputs(drainOutputs(f))
	want := []SendMedia{{Path: 0, Pkt: wire.MediaPacket{
		Seq:        101,
		SourceTime: srcNTP(11_000),
		SSRC:       0x1234_5678,
		Payload:    []byte("b"),
		Retransmit: true,
	}}}
	if !reflect.DeepEqual(ms, want) {
		t.Fatalf("retransmit = %v, want %v", ms, want)
	}
	if st := f.Stats(); st.Retransmitted != 1 || st.Sent != 3 {
		t.Fatalf("stats retransmitted/sent = %d/%d, want 1/3", st.Retransmitted, st.Sent)
	}
	if sl := &f.sender.ring[101&f.sender.mask]; sl.transmitCount != 1 || !sl.retried || sl.lastRetry != 20_000 {
		t.Fatalf("slot after retransmit = %+v, want transmitCount 1 retried lastRetry 20000", sl)
	}
}

func TestServiceNackUnknownSeqSkipped(t *testing.T) {
	f := New(RoleSender, senderConfig())
	f.PushApp(10_000, []byte("a")) // seq 100
	drainOutputs(f)

	// 99 never sent; 200 never sent: both unserviceable.
	f.FeedFeedback(20_000, wire.NackRequest{Missing: []uint32{99, 200, 100}})
	ms := mediaOutputs(drainOutputs(f))
	if len(ms) != 1 || ms[0].Pkt.Seq != 100 {
		t.Fatalf("retransmits = %v, want only seq 100", ms)
	}
	if st := f.Stats(); st.RetransmitSkipped != 2 || st.Retransmitted != 1 {
		t.Fatalf("skipped/retransmitted = %d/%d, want 2/1", st.RetransmitSkipped, st.Retransmitted)
	}
}

func TestServiceNackGateSuppressesWithinRTT(t *testing.T) {
	f := New(RoleSender, senderConfig())
	f.PushApp(10_000, []byte("a")) // seq 100
	drainOutputs(f)
	// Cold-start RTT = RTTMin = 5ms, so the gate window is 5ms.

	f.FeedFeedback(20_000, wire.NackRequest{Missing: []uint32{100}}) // retransmit #1
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 1 {
		t.Fatalf("first retransmit missing")
	}

	// Re-NACK 4ms later: inside the 5ms window -> suppressed.
	f.FeedFeedback(24_000, wire.NackRequest{Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 0 {
		t.Fatalf("retransmit within RTT window not suppressed: %v", ms)
	}
	if f.Stats().RetransmitSuppressed != 1 {
		t.Fatalf("RetransmitSuppressed = %d, want 1", f.Stats().RetransmitSuppressed)
	}

	// Re-NACK exactly at the window edge (now - lastRetry == rtt): allowed
	// (gate is strict `<`).
	f.FeedFeedback(25_000, wire.NackRequest{Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 1 {
		t.Fatalf("retransmit at window edge suppressed, want sent")
	}
	if st := f.Stats(); st.Retransmitted != 2 || st.RetransmitSuppressed != 1 {
		t.Fatalf("retransmitted/suppressed = %d/%d, want 2/1", st.Retransmitted, st.RetransmitSuppressed)
	}
}

func TestServiceNackGateUsesRawLastRTT(t *testing.T) {
	// The gate must clamp the raw last RTT sample (libRIST peer->last_rtt), not
	// the EWMA. This test warms the estimator with one large sample so the two
	// bases diverge, then re-NACKs at a delay that only the raw basis
	// suppresses — so it fails if the gate regressed to the smoothed value.
	f := New(RoleSender, senderConfig())
	f.PushApp(10_000, []byte("a")) // seq 100
	drainOutputs(f)

	const warm = 200 * clock.Millisecond
	f.FeedFeedback(1_000_000, wire.RttEchoResponse{
		Timestamp:       uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(1_000_000).Add(-warm))),
		ProcessingDelay: 0,
	})
	// Raw last sample = 200ms; the EWMA smooths it to ~29ms.
	if f.est.Last() != warm {
		t.Fatalf("est.Last() = %d, want %d", f.est.Last(), warm)
	}

	// Retransmit #1 sets lastRetry.
	f.FeedFeedback(2_000_000, wire.NackRequest{Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 1 {
		t.Fatalf("first retransmit = %d, want 1", len(ms))
	}

	// Re-NACK 100ms later: 100ms < clamp(last_rtt=200ms) so it is suppressed.
	// Under the smoothed basis clamp(~29ms) it would NOT be suppressed, so this
	// assertion pins the gate to the raw last sample.
	f.FeedFeedback(2_100_000, wire.NackRequest{Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 0 {
		t.Fatalf("re-NACK at +100ms not suppressed (gate not on raw last_rtt): %v", ms)
	}
	if f.Stats().RetransmitSuppressed != 1 {
		t.Fatalf("RetransmitSuppressed = %d, want 1", f.Stats().RetransmitSuppressed)
	}
}

func TestServiceNackMaxRetriesExhausted(t *testing.T) {
	cfg := senderConfig()
	cfg.MaxRetries = 2
	f := New(RoleSender, cfg)
	f.PushApp(10_000, []byte("a")) // seq 100
	drainOutputs(f)

	// Two retransmits spaced beyond the 5ms gate.
	f.FeedFeedback(20_000, wire.NackRequest{Missing: []uint32{100}})
	f.FeedFeedback(30_000, wire.NackRequest{Missing: []uint32{100}})
	drainOutputs(f)
	if f.Stats().Retransmitted != 2 {
		t.Fatalf("Retransmitted = %d, want 2", f.Stats().Retransmitted)
	}

	// Third: transmitCount(2) >= MaxRetries(2) -> exhausted, no send.
	f.FeedFeedback(40_000, wire.NackRequest{Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 0 {
		t.Fatalf("retransmit past MaxRetries not refused: %v", ms)
	}
	if st := f.Stats(); st.RetransmitExhausted != 1 || st.Retransmitted != 2 {
		t.Fatalf("exhausted/retransmitted = %d/%d, want 1/2", st.RetransmitExhausted, st.Retransmitted)
	}
}

// TestServiceNackBandwidthBeforeExhausted verifies the dequeue-gate order: a
// sequence that is BOTH over the recovery_maxbitrate ceiling AND past MaxRetries
// is attributed to BandwidthSkipped, not RetransmitExhausted — matching libRIST
// rist_retry_dequeue, which checks bandwidth_skip before the transmit_count >=
// max_retries cap. Behaviorally both refuse to re-send; only the stat differs.
func TestServiceNackBandwidthBeforeExhausted(t *testing.T) {
	cfg := senderConfig()
	cfg.MaxRetries = 1
	cfg.CongestionControl = CongestionNormal
	cfg.RecoveryMaxBitrate = 1000 // 1000 kbps -> 1_000_000 bps budget
	f := New(RoleSender, cfg)
	f.PushApp(10_000, []byte("a")) // seq 100
	drainOutputs(f)

	// Retransmit #1 (spaced beyond the 5ms gate, under budget) -> transmitCount 1.
	f.FeedFeedback(20_000, wire.NackRequest{Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 1 {
		t.Fatalf("first retransmit missing")
	}
	if sl := &f.sender.ring[100&f.sender.mask]; sl.transmitCount != 1 {
		t.Fatalf("transmitCount = %d, want 1 (== MaxRetries)", sl.transmitCount)
	}

	// Force the data-rate EWMA over budget (slowBps = eightTimesSlow/8). The
	// re-NACK at +80ms keeps the slow window from expiring, so feed(now,0) does
	// not decay it.
	f.sender.dataBW.eightTimesSlow = 8 * 2_000_000 // slowBps = 2_000_000 > budget

	// Re-NACK: transmitCount(1) >= MaxRetries(1) AND over budget. The bandwidth
	// gate is evaluated first -> BandwidthSkipped, not RetransmitExhausted.
	f.FeedFeedback(100_000, wire.NackRequest{Missing: []uint32{100}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 0 {
		t.Fatalf("over-budget retransmit emitted: %v", ms)
	}
	if st := f.Stats(); st.BandwidthSkipped != 1 || st.RetransmitExhausted != 0 {
		t.Fatalf("bandwidthSkipped/exhausted = %d/%d, want 1/0 (bandwidth attributed before exhaustion)",
			st.BandwidthSkipped, st.RetransmitExhausted)
	}
}

// TestServiceNackAggressiveDoublesRTTSpacing verifies the AGGRESSIVE congestion
// mode suppresses retransmits within 2*RTT, where NORMAL suppresses only within
// 1*RTT (libRIST rist_retry_enqueue doubles the spacing under AGGRESSIVE). The
// same +7.5ms re-NACK (1.5 * cold-start RTT of 5ms) is suppressed under
// AGGRESSIVE but sent under NORMAL.
func TestServiceNackAggressiveDoublesRTTSpacing(t *testing.T) {
	tests := []struct {
		name         string
		mode         CongestionMode
		wantSecondTx int    // media packets emitted by the second NACK
		wantSuppress uint64 // RetransmitSuppressed after the second NACK
	}{
		{"normal sends at 1.5*RTT", CongestionNormal, 1, 0},
		{"aggressive suppresses at 1.5*RTT", CongestionAggressive, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := senderConfig()
			cfg.CongestionControl = tt.mode
			f := New(RoleSender, cfg)
			f.PushApp(10_000, []byte("a")) // seq 100
			drainOutputs(f)
			// Cold-start clamped RTT = RTTMin = 5ms.

			// Retransmit #1 at t=20ms sets lastRetry.
			f.FeedFeedback(20_000, wire.NackRequest{Missing: []uint32{100}})
			if ms := mediaOutputs(drainOutputs(f)); len(ms) != 1 {
				t.Fatalf("first retransmit missing")
			}

			// Re-NACK 7.5ms later (1.5*RTT): inside the 2*RTT(10ms) AGGRESSIVE
			// window but outside the 1*RTT(5ms) NORMAL window.
			f.FeedFeedback(27_500, wire.NackRequest{Missing: []uint32{100}})
			if ms := mediaOutputs(drainOutputs(f)); len(ms) != tt.wantSecondTx {
				t.Fatalf("second NACK emitted %d media, want %d", len(ms), tt.wantSecondTx)
			}
			if got := f.Stats().RetransmitSuppressed; got != tt.wantSuppress {
				t.Fatalf("RetransmitSuppressed = %d, want %d", got, tt.wantSuppress)
			}
		})
	}
}

func TestServiceNackAgedOutAfterWrap(t *testing.T) {
	cfg := senderConfig()
	cfg.RingSize = 16 // tiny ring so a later seq overwrites an old slot
	cfg.StartSeq = 0
	f := New(RoleSender, cfg)
	// Send seq 0, then seq 16 — both map to ring index 0; 16 overwrites 0.
	f.PushApp(10_000, []byte("old"))
	for i := 1; i <= 16; i++ {
		f.PushApp(clock.Timestamp(10_000+int64(i)*1_000), []byte{byte(i)})
	}
	drainOutputs(f)

	// NACK for the overwritten seq 0: its slot now holds seq 16 -> skipped.
	f.FeedFeedback(40_000, wire.NackRequest{Missing: []uint32{0}})
	if ms := mediaOutputs(drainOutputs(f)); len(ms) != 0 {
		t.Fatalf("retransmit of aged-out seq returned %v, want none", ms)
	}
	if f.Stats().RetransmitSkipped != 1 {
		t.Fatalf("RetransmitSkipped = %d, want 1", f.Stats().RetransmitSkipped)
	}
}

func TestSenderRttEchoOriginateAnswerObserve(t *testing.T) {
	f := New(RoleSender, senderConfig())
	f.PushApp(10_000, []byte("a"))
	drainOutputs(f)

	// Origination: TimerRttEcho fires -> request on the transmit path, re-arm.
	f.HandleTimer(110_000, TimerRttEcho)
	outs := drainOutputs(f)
	want := []Output{
		SendFeedback{Path: 0, FB: wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(110_000))}},
		SetTimer{ID: TimerRttEcho, Deadline: 210_000},
	}
	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("echo origination = %v, want %v", outs, want)
	}

	// Answer an inbound request verbatim with zero processing delay.
	f.FeedFeedback(120_000, wire.RttEchoRequest{Timestamp: 0xABCD})
	if got := drainOutputs(f); !reflect.DeepEqual(got, []Output{
		SendFeedback{Path: 0, FB: wire.RttEchoResponse{Timestamp: 0xABCD, ProcessingDelay: 0}},
	}) {
		t.Fatalf("echo answer = %v", got)
	}

	// Observe a response: folds into the estimator used by the gate.
	f.FeedFeedback(120_000, wire.RttEchoResponse{
		Timestamp:       uint64(clock.NTPTimeFromTimestamp(110_000)),
		ProcessingDelay: 2_000,
	})
	// sample = 10000 - 2000 = 8000; eight_times_rtt = 40000 - 5000 + 8000 = 43000 -> 5375.
	if got := f.est.Smoothed(); got != 5_375 {
		t.Fatalf("Smoothed = %d, want 5375", got)
	}
}

func TestSenderIgnoresReceiverEntryPoints(t *testing.T) {
	f := New(RoleSender, senderConfig())
	f.PushApp(10_000, []byte("a"))
	drainOutputs(f)

	// Feed (media in), Tick, and receiver-only timers do nothing on a sender.
	f.Feed(20_000, 0, mkPkt(1, 0, nil))
	f.Tick(30_000)
	f.HandleTimer(40_000, TimerPlayout)
	f.HandleTimer(50_000, TimerNack)
	if outs := drainOutputs(f); outs != nil {
		t.Fatalf("sender emitted on receiver entry points: %v", outs)
	}
	if evs := drainEvents(f); evs != nil {
		t.Fatalf("sender raised events: %v", evs)
	}
}

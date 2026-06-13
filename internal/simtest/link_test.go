package simtest

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
)

// goldenLinkConfig is the impairment set for the golden run: every knob
// (loss, duplication, jitter) enabled so the RNG draw order is pinned.
func goldenLinkConfig() LinkConfig {
	return LinkConfig{
		Delay:   10 * clock.Millisecond,
		Jitter:  3 * clock.Millisecond,
		Loss:    0.2,
		DupProb: 0.1,
	}
}

// runGoldenScenario sends 32 one-byte payloads {0..31} one millisecond
// apart and drains everything, returning the delivered first-bytes in
// delivery order.
func runGoldenScenario(cfg LinkConfig, seed uint64) (delivered []byte, dropped uint64) {
	link := NewLink[[]byte](cfg, seed)
	now := clock.Timestamp(0)
	for i := 0; i < 32; i++ {
		link.Send(now, []byte{byte(i)})
		now = now.Add(clock.Millisecond)
	}
	for _, p := range link.DrainDue(now.Add(clock.Second)) {
		delivered = append(delivered, p[0])
	}
	return delivered, link.Dropped()
}

// TestLinkGoldenRun pins the exact delivery sequence (loss pattern,
// duplications, jitter reordering, tie-breaks) for a fixed seed. Any
// change to the RNG, to the draw order in Send (filter → loss → dup →
// per-copy jitter), or to DrainDue's (deliverAt, insertSeq) ordering
// fails this test.
func TestLinkGoldenRun(t *testing.T) {
	wantDelivered := []byte{
		0, 1, 1, 2, 3, 4, 6, 6, 8, 10, 9, 11, 12, 13, 14, 15,
		18, 21, 22, 21, 23, 25, 26, 27, 28, 30,
	}
	const wantDropped = 9

	delivered, dropped := runGoldenScenario(goldenLinkConfig(), 42)
	if !bytes.Equal(delivered, wantDelivered) {
		t.Errorf("delivered sequence = %v\nwant                 %v", delivered, wantDelivered)
	}
	if dropped != wantDropped {
		t.Errorf("dropped = %d, want %d", dropped, wantDropped)
	}
}

// TestLinkSameSeedByteIdentical verifies the determinism contract: two
// links with identical (config, seed, input) produce byte-identical
// delivery sequences, and a different seed produces a different one.
func TestLinkSameSeedByteIdentical(t *testing.T) {
	a, da := runGoldenScenario(goldenLinkConfig(), 12345)
	b, db := runGoldenScenario(goldenLinkConfig(), 12345)
	if !bytes.Equal(a, b) || da != db {
		t.Errorf("same seed diverged: %v (dropped %d) vs %v (dropped %d)", a, da, b, db)
	}
	c, _ := runGoldenScenario(goldenLinkConfig(), 54321)
	if bytes.Equal(a, c) {
		t.Error("different seeds produced identical delivery sequences")
	}
}

// TestLinkLossRate verifies the empirical drop rate over 100k sends stays
// within a few standard deviations of the configured probability.
func TestLinkLossRate(t *testing.T) {
	const n = 100_000
	tests := []struct {
		name string
		loss float64
		seed uint64
	}{
		{name: "loss 1%", loss: 0.01, seed: 1},
		{name: "loss 10%", loss: 0.10, seed: 2},
		{name: "loss 30%", loss: 0.30, seed: 3},
		{name: "loss 50%", loss: 0.50, seed: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond, Loss: tt.loss}, tt.seed)
			for i := 0; i < n; i++ {
				link.Send(clock.Timestamp(i), []byte{1})
			}
			got := float64(link.Dropped()) / n
			// Binomial sigma = sqrt(p(1-p)/n); allow 5σ.
			tol := 5 * math.Sqrt(tt.loss*(1-tt.loss)/n)
			if math.Abs(got-tt.loss) > tol {
				t.Errorf("empirical loss = %v, want %v ± %v", got, tt.loss, tol)
			}
		})
	}
}

// TestLinkZeroLossDeliversAll verifies Loss = 0 consumes no fate and
// delivers every datagram.
func TestLinkZeroLossDeliversAll(t *testing.T) {
	link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond}, 9)
	const n = 1000
	for i := 0; i < n; i++ {
		link.Send(clock.Timestamp(i), []byte{byte(i)})
	}
	out := link.DrainDue(clock.Timestamp(n).Add(clock.Second))
	if len(out) != n || link.Dropped() != 0 {
		t.Errorf("delivered %d dropped %d, want %d delivered 0 dropped", len(out), link.Dropped(), n)
	}
}

// payload16 encodes a send index as a 2-byte payload.
func payload16(i int) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(i))
	return p
}

// TestLinkJitterReorders verifies nonzero jitter produces at least one
// inversion relative to send order, and zero jitter preserves send order
// exactly.
func TestLinkJitterReorders(t *testing.T) {
	const n = 200
	send := func(jitter clock.Microseconds) []int {
		link := NewLink[[]byte](LinkConfig{Delay: 10 * clock.Millisecond, Jitter: jitter}, 77)
		now := clock.Timestamp(0)
		for i := 0; i < n; i++ {
			link.Send(now, payload16(i))
			now = now.Add(100) // 100 µs apart; jitter range exceeds the gap
		}
		var order []int
		for _, p := range link.DrainDue(now.Add(clock.Second)) {
			order = append(order, int(binary.BigEndian.Uint16(p)))
		}
		return order
	}

	t.Run("jitter reorders", func(t *testing.T) {
		order := send(5 * clock.Millisecond)
		if len(order) != n {
			t.Fatalf("delivered %d, want %d", len(order), n)
		}
		inversions := 0
		for i := 1; i < len(order); i++ {
			if order[i] < order[i-1] {
				inversions++
			}
		}
		if inversions == 0 {
			t.Error("5ms jitter over 100µs send spacing produced no reordering")
		}
	})

	t.Run("no jitter preserves order", func(t *testing.T) {
		order := send(0)
		if len(order) != n {
			t.Fatalf("delivered %d, want %d", len(order), n)
		}
		for i, got := range order {
			if got != i {
				t.Fatalf("order[%d] = %d, want %d (in-order delivery)", i, got, i)
			}
		}
	})
}

// TestLinkDupProb verifies the duplication knob: certainty duplicates
// everything exactly twice, and an intermediate probability lands within
// tolerance over many sends.
func TestLinkDupProb(t *testing.T) {
	t.Run("DupProb 1 delivers exactly twice", func(t *testing.T) {
		link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond, DupProb: 1}, 5)
		const n = 500
		for i := 0; i < n; i++ {
			link.Send(clock.Timestamp(i), payload16(i))
		}
		out := link.DrainDue(clock.Timestamp(n).Add(clock.Second))
		if len(out) != 2*n {
			t.Fatalf("delivered %d, want %d", len(out), 2*n)
		}
		counts := make(map[int]int)
		for _, p := range out {
			counts[int(binary.BigEndian.Uint16(p))]++
		}
		for i := 0; i < n; i++ {
			if counts[i] != 2 {
				t.Fatalf("payload %d delivered %d times, want 2", i, counts[i])
			}
		}
	})

	t.Run("DupProb 0.25 empirical rate", func(t *testing.T) {
		const n = 100_000
		link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond, DupProb: 0.25}, 6)
		for i := 0; i < n; i++ {
			link.Send(clock.Timestamp(i), []byte{1})
		}
		out := link.DrainDue(clock.Timestamp(n).Add(clock.Second))
		dups := len(out) - n
		got := float64(dups) / n
		tol := 5 * math.Sqrt(0.25*0.75/n)
		if math.Abs(got-0.25) > tol {
			t.Errorf("empirical duplication rate = %v, want 0.25 ± %v", got, tol)
		}
	})

	t.Run("DupProb 0 never duplicates", func(t *testing.T) {
		link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond}, 7)
		const n = 1000
		for i := 0; i < n; i++ {
			link.Send(clock.Timestamp(i), payload16(i))
		}
		if out := link.DrainDue(clock.Timestamp(n).Add(clock.Second)); len(out) != n {
			t.Errorf("delivered %d, want %d", len(out), n)
		}
	})
}

// TestLinkDropFilter verifies the deterministic drop predicate hits
// exactly the targeted payloads, independent of the seeded loss roll.
func TestLinkDropFilter(t *testing.T) {
	// Loss = 0 isolates the filter; high-bit payloads are the targets.
	link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond}, 11)
	link.SetDropFilter(func(p []byte) bool { return p[0]&0x80 != 0 })

	var wantDelivered []byte
	var wantDropped uint64
	for i := 0; i < 64; i++ {
		b := byte(i)
		if i%3 == 0 {
			b |= 0x80 // every third payload is targeted
		}
		link.Send(clock.Timestamp(i), []byte{b})
		if b&0x80 != 0 {
			wantDropped++
		} else {
			wantDelivered = append(wantDelivered, b)
		}
	}

	var got []byte
	for _, p := range link.DrainDue(clock.Timestamp(64).Add(clock.Second)) {
		got = append(got, p[0])
	}
	if !bytes.Equal(got, wantDelivered) {
		t.Errorf("delivered = %v, want %v", got, wantDelivered)
	}
	for _, b := range got {
		if b&0x80 != 0 {
			t.Errorf("targeted payload %#x was delivered", b)
		}
	}
	if link.Dropped() != wantDropped {
		t.Errorf("Dropped() = %d, want %d", link.Dropped(), wantDropped)
	}

	t.Run("nil filter restores delivery", func(t *testing.T) {
		link.SetDropFilter(nil)
		link.Send(clock.Timestamp(1000), []byte{0xFF})
		out := link.DrainDue(clock.Timestamp(1000).Add(clock.Second))
		if len(out) != 1 || out[0][0] != 0xFF {
			t.Errorf("after removing filter, delivered %v, want [[0xFF]]", out)
		}
	})
}

// TestLinkDropFilterTargetsOnePacket verifies the headline use-case: drop
// exactly the first occurrence of one specific payload (e.g. "the first
// transmission of seq N"), letting a later identical send through.
func TestLinkDropFilterTargetsOnePacket(t *testing.T) {
	link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond}, 13)
	target := payload16(17)
	armed := true
	link.SetDropFilter(func(p []byte) bool {
		if armed && bytes.Equal(p, target) {
			armed = false
			return true
		}
		return false
	})

	for i := 0; i < 32; i++ {
		link.Send(clock.Timestamp(i), payload16(i))
	}
	link.Send(clock.Timestamp(100), payload16(17)) // the "retransmission"

	out := link.DrainDue(clock.Timestamp(100).Add(clock.Second))
	if len(out) != 32 { // 33 sends − 1 targeted drop
		t.Fatalf("delivered %d, want 32", len(out))
	}
	seen17 := 0
	for _, p := range out {
		if bytes.Equal(p, target) {
			seen17++
		}
	}
	if seen17 != 1 {
		t.Errorf("payload 17 delivered %d times, want exactly 1 (retransmit only)", seen17)
	}
	if link.Dropped() != 1 {
		t.Errorf("Dropped() = %d, want 1", link.Dropped())
	}
}

// TestLinkDeadlinesAndPartialDrain exercises NextDeadline and stepwise
// draining: nothing is released early, drains come out in nondecreasing
// delivery-time order, and the deadline tracks the remaining minimum.
func TestLinkDeadlinesAndPartialDrain(t *testing.T) {
	link := NewLink[[]byte](LinkConfig{Delay: 10 * clock.Millisecond}, 3)

	if _, ok := link.NextDeadline(); ok {
		t.Fatal("empty link reported a deadline")
	}
	if out := link.DrainDue(clock.Timestamp(clock.Second)); len(out) != 0 {
		t.Fatalf("empty link drained %d datagrams", len(out))
	}

	// Three sends at t = 0, 1ms, 2ms → due at 10, 11, 12 ms.
	for i := 0; i < 3; i++ {
		link.Send(clock.Timestamp(i)*clock.Timestamp(clock.Millisecond), []byte{byte(i)})
	}

	at, ok := link.NextDeadline()
	if !ok || at != clock.Timestamp(10*clock.Millisecond) {
		t.Fatalf("NextDeadline = %d, %v; want 10ms, true", at, ok)
	}
	if out := link.DrainDue(at.Add(-1)); len(out) != 0 {
		t.Fatalf("drained %d datagrams before the deadline", len(out))
	}
	if out := link.DrainDue(at); len(out) != 1 || out[0][0] != 0 {
		t.Fatalf("drain at first deadline = %v, want [[0]]", out)
	}
	at, ok = link.NextDeadline()
	if !ok || at != clock.Timestamp(11*clock.Millisecond) {
		t.Fatalf("NextDeadline after drain = %d, %v; want 11ms, true", at, ok)
	}
	if out := link.DrainDue(clock.Timestamp(12 * clock.Millisecond)); len(out) != 2 || out[0][0] != 1 || out[1][0] != 2 {
		t.Fatalf("final drain = %v, want [[1] [2]]", out)
	}
	if _, ok := link.NextDeadline(); ok {
		t.Fatal("drained link still reports a deadline")
	}
}

// TestLinkTieBreakInsertionOrder verifies simultaneous deliveries (same
// send instant, zero jitter) drain in send order via the insertion-index
// tiebreaker.
func TestLinkTieBreakInsertionOrder(t *testing.T) {
	link := NewLink[[]byte](LinkConfig{Delay: 5 * clock.Millisecond}, 1)
	for i := 0; i < 16; i++ {
		link.Send(0, []byte{byte(i)})
	}
	out := link.DrainDue(clock.Timestamp(5 * clock.Millisecond))
	if len(out) != 16 {
		t.Fatalf("delivered %d, want 16", len(out))
	}
	for i, p := range out {
		if p[0] != byte(i) {
			t.Fatalf("out[%d] = %d, want %d (insertion order on ties)", i, p[0], i)
		}
	}
}

// TestLinkCounters verifies Dropped/Delivered bookkeeping across loss,
// duplication, and draining.
func TestLinkCounters(t *testing.T) {
	link := NewLink[[]byte](LinkConfig{Delay: clock.Millisecond, DupProb: 1}, 21)
	for i := 0; i < 10; i++ {
		link.Send(clock.Timestamp(i), []byte{byte(i)})
	}
	if got := link.Delivered(); got != 0 {
		t.Errorf("Delivered() before drain = %d, want 0", got)
	}
	out := link.DrainDue(clock.Timestamp(10).Add(clock.Second))
	if len(out) != 20 {
		t.Fatalf("drained %d, want 20 (10 sends duplicated)", len(out))
	}
	if got := link.Delivered(); got != 20 {
		t.Errorf("Delivered() = %d, want 20", got)
	}
	if got := link.Dropped(); got != 0 {
		t.Errorf("Dropped() = %d, want 0", got)
	}
}

// TestLinkNegativeDelayClampedToZero verifies a (misconfigured) negative
// delay schedules delivery at the send instant rather than in the past.
func TestLinkNegativeDelayClampedToZero(t *testing.T) {
	link := NewLink[[]byte](LinkConfig{Delay: -clock.Millisecond}, 1)
	link.Send(clock.Timestamp(500), []byte{1})
	if at, ok := link.NextDeadline(); !ok || at != 500 {
		t.Fatalf("NextDeadline = %d, %v; want 500, true (clamped to send instant)", at, ok)
	}
	if out := link.DrainDue(500); len(out) != 1 {
		t.Fatalf("delivered %d, want 1", len(out))
	}
}

// TestPerfectLink verifies the convenience config: 10ms delay, in-order,
// lossless, duplicate-free.
func TestPerfectLink(t *testing.T) {
	cfg := PerfectLink()
	if cfg.Delay != 10*clock.Millisecond || cfg.Jitter != 0 || cfg.Loss != 0 || cfg.DupProb != 0 {
		t.Fatalf("PerfectLink() = %+v, want 10ms delay and zero impairments", cfg)
	}
	delivered, dropped := runGoldenScenario(cfg, 1)
	if dropped != 0 || len(delivered) != 32 {
		t.Fatalf("perfect link delivered %d dropped %d, want 32 and 0", len(delivered), dropped)
	}
	for i, b := range delivered {
		if b != byte(i) {
			t.Fatalf("delivered[%d] = %d, want %d", i, b, i)
		}
	}
}

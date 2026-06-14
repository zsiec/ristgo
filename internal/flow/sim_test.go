package flow_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/simtest"
)

// The four-invariant sim suite drives a real sender flow and receiver flow
// through the N-path Fabric, asserting the plan's four invariants
// (no duplicate delivered, in order, nothing past deadline, completeness
// under recoverable loss) over a seed sweep. Every failure is reproducible
// from the reported seed.

const (
	senderSSRC   = 0x0ACE_0AC0 // even base SSRC (LSB reserved for retransmit)
	sweepSeeds   = 1024        // >= 1000 seeds per the WP3 gate
	sweepPackets = 64
)

// seqPayload encodes a 0-based source index as an 8-byte payload so delivered
// payloads can be checked for integrity, not just ordering.
func seqPayload(i int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

// newPair builds a sender flow (even SSRC, the given start sequence) and a
// receiver flow with the libRIST defaults.
func newPair(startSeq uint32) (sender, receiver *flow.Flow) {
	scfg := flow.DefaultConfig()
	scfg.SSRC = senderSSRC
	scfg.StartSeq = startSeq
	return flow.New(flow.RoleSender, scfg), flow.New(flow.RoleReceiver, flow.DefaultConfig())
}

// protectEndpoints returns a forward-link drop filter that drops media with
// probability lossP from its own seeded stream but never drops the anchor
// (first) or the top-anchor (last) sequence, and never drops control. With
// both endpoints guaranteed the receiver anchors at startSeq and every
// interior loss has a delivered successor to trigger its NACK, so all
// recoverable loss is in fact recovered — letting the sweep assert exact
// completeness rather than a bounded gap.
func protectEndpoints(seed uint64, startSeq, lastSeq uint32, lossP float64) func(simtest.Datagram) bool {
	rng := simtest.NewRng(seed ^ 0x9E3779B97F4A7C15)
	return func(d simtest.Datagram) bool {
		if !d.Media {
			return false
		}
		if d.Pkt.Seq == startSeq || d.Pkt.Seq == lastSeq {
			return false
		}
		return rng.Unit() < lossP
	}
}

// expectedSeqs returns the n sequence numbers a sender starting at startSeq
// emits, wrapping at 2^32.
func expectedSeqs(startSeq uint32, n int) []uint32 {
	out := make([]uint32, n)
	for i := range out {
		out[i] = startSeq + uint32(i)
	}
	return out
}

// equalSeqs reports whether a and b are identical.
func equalSeqs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// runRecoverable drives one seeded scenario in which all loss is recoverable
// and asserts the four invariants plus exact completeness. fwdCfg supplies the
// forward impairments (jitter/dup); loss is applied via the endpoint-protecting
// drop filter so completeness is exact. The back channel is lossless so NACKs
// always reach the sender.
func runRecoverable(t *testing.T, seed uint64, startSeq uint32, n int, fwdCfg simtest.LinkConfig, lossP float64, sourceStart, sourceGap clock.Microseconds) {
	t.Helper()
	sender, receiver := newPair(startSeq)
	lastSeq := startSeq + uint32(n-1)

	fwd := simtest.NewLink[simtest.Datagram](fwdCfg, seed)
	fwd.SetDropFilter(protectEndpoints(seed, startSeq, lastSeq, lossP))
	back := simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: 10 * clock.Millisecond}, seed^0x1234)

	fab := simtest.NewFabric(sender, receiver, []*simtest.Link[simtest.Datagram]{fwd}, []*simtest.Link[simtest.Datagram]{back})

	// The first packet is sent sourceStart before the rest so it anchors the
	// flow even when jitter would otherwise let a later packet arrive first.
	fab.EnqueueSource(0, seqPayload(0))
	for i := 1; i < n; i++ {
		off := sourceStart + sourceGap*clock.Microseconds(i-1)
		fab.EnqueueSource(clock.Timestamp(off), seqPayload(i))
	}

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 200_000) {
		t.Fatalf("seed %d: only %d/%d delivered before the step budget (Recovered=%d, Lost=%d)",
			seed, len(fab.DeliveredSeqs()), n, receiver.Stats().Recovered, receiver.Stats().Lost)
	}

	// A correctly delivered packet's latency is offset + recoveryBuffer, where
	// offset is the first packet's forward delay (<= Delay+Jitter); MaxLatency
	// pins the absolute playout deadline on top of the uniformity check.
	maxLat := flow.DefaultConfig().RecoveryBuffer() + fwdCfg.Delay + fwdCfg.Jitter
	if v := fab.CheckInvariants(simtest.InvariantOpts{LatencyTolerance: 0, MaxLatency: maxLat, RequireContiguous: true}); len(v) != 0 {
		t.Fatalf("seed %d: invariant violations: %v", seed, v)
	}
	if got, want := fab.DeliveredSeqs(), expectedSeqs(startSeq, n); !equalSeqs(got, want) {
		t.Fatalf("seed %d: delivered %v, want %v", seed, got, want)
	}
	// Payload integrity: the k-th delivered payload encodes source index k.
	for k, p := range fab.Delivered() {
		if len(p) != 8 || binary.BigEndian.Uint64(p) != uint64(k) {
			t.Fatalf("seed %d: delivered[%d] payload = %x, want index %d", seed, k, p, k)
		}
	}
	rst := receiver.Stats()
	if rst.Lost != 0 || rst.Discontinuities != 0 || rst.Delivered != uint64(n) {
		t.Fatalf("seed %d: receiver lost/disc/delivered = %d/%d/%d, want 0/0/%d",
			seed, rst.Lost, rst.Discontinuities, rst.Delivered, n)
	}
}

// TestFourInvariantsRecoverableLossSweep is the headline gate: 1024 seeds of
// independent forward loss (plus duplication) with a lossless back channel,
// each asserting all four invariants and exact completeness. No jitter, so
// arrival order equals send order; reordering is covered by the jitter sweep.
func TestFourInvariantsRecoverableLossSweep(t *testing.T) {
	fwdCfg := simtest.LinkConfig{Delay: 10 * clock.Millisecond, DupProb: 0.05}
	for seed := uint64(0); seed < sweepSeeds; seed++ {
		runRecoverable(t, seed, 0, sweepPackets, fwdCfg, 0.15, clock.Millisecond, clock.Millisecond)
	}
}

// TestFourInvariantsJitterSweep adds forward jitter (reordering) and
// duplication to the loss, over 256 seeds. The first packet is sent 10 ms
// ahead of the rest — a gap wider than the jitter — so it still anchors the
// flow; interior packets reorder freely and must still be delivered in order,
// deduplicated, complete, and at constant latency.
func TestFourInvariantsJitterSweep(t *testing.T) {
	fwdCfg := simtest.LinkConfig{Delay: 10 * clock.Millisecond, Jitter: 3 * clock.Millisecond, DupProb: 0.05}
	for seed := uint64(0); seed < 256; seed++ {
		runRecoverable(t, seed, 0, sweepPackets, fwdCfg, 0.10, 10*clock.Millisecond, clock.Millisecond)
	}
}

// TestFourInvariantsAcrossSeqWrap runs a flow whose sequence space crosses the
// 32-bit boundary (0xFFFFFFFF -> 0) under loss, exercising the wrap-aware
// comparisons in dedup, missing-detection, and playout. 128 seeds, exact
// completeness.
func TestFourInvariantsAcrossSeqWrap(t *testing.T) {
	const n = 64
	startSeq := uint32(0xFFFFFFFF) - 30 // 31 sequences before the wrap, 33 after
	fwdCfg := simtest.LinkConfig{Delay: 10 * clock.Millisecond, Jitter: 2 * clock.Millisecond, DupProb: 0.05}
	for seed := uint64(0); seed < 128; seed++ {
		runRecoverable(t, seed, startSeq, n, fwdCfg, 0.15, 10*clock.Millisecond, clock.Millisecond)
	}
}

// TestPerfectLinkExactDelivery confirms the no-impairment baseline: every
// packet delivered once, in order, with no retransmissions at all.
func TestPerfectLinkExactDelivery(t *testing.T) {
	const n = 32
	sender, receiver := newPair(1000)
	fwd := simtest.NewLink[simtest.Datagram](simtest.PerfectLink(), 1)
	back := simtest.NewLink[simtest.Datagram](simtest.PerfectLink(), 2)
	fab := simtest.NewFabric(sender, receiver, []*simtest.Link[simtest.Datagram]{fwd}, []*simtest.Link[simtest.Datagram]{back})
	fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 100_000) {
		t.Fatalf("only %d/%d delivered", len(fab.DeliveredSeqs()), n)
	}
	if v := fab.CheckInvariants(simtest.InvariantOpts{RequireContiguous: true, MaxLatency: flow.DefaultConfig().RecoveryBuffer() + 10*clock.Millisecond}); len(v) != 0 {
		t.Fatalf("invariant violations: %v", v)
	}
	if !equalSeqs(fab.DeliveredSeqs(), expectedSeqs(1000, n)) {
		t.Fatalf("delivered %v", fab.DeliveredSeqs())
	}
	if st := sender.Stats(); st.Retransmitted != 0 {
		t.Fatalf("perfect link retransmitted %d packets, want 0", st.Retransmitted)
	}
	if st := receiver.Stats(); st.Recovered != 0 || st.NacksSent != 0 {
		t.Fatalf("perfect link recovered/nacked = %d/%d, want 0/0", st.Recovered, st.NacksSent)
	}
}

// newPairArrival builds a sender flow and an ARRIVAL-timing receiver flow (the
// playout deadline is each packet's arrival instant + recoveryBuffer, not its
// source-mapped time).
func newPairArrival(startSeq uint32) (sender, receiver *flow.Flow) {
	scfg := flow.DefaultConfig()
	scfg.SSRC = senderSSRC
	scfg.StartSeq = startSeq
	rcfg := flow.DefaultConfig()
	rcfg.TimingMode = flow.TimingArrival
	return flow.New(flow.RoleSender, scfg), flow.New(flow.RoleReceiver, rcfg)
}

// TestArrivalTimingPerfectLink validates ARRIVAL-mode playout on a clean link:
// every packet delivered once, in order, complete, and at uniform latency
// (recoveryBuffer from arrival, no retransmits to perturb it).
func TestArrivalTimingPerfectLink(t *testing.T) {
	const n = 64
	sender, receiver := newPairArrival(0)
	fwd := simtest.NewLink[simtest.Datagram](simtest.PerfectLink(), 1)
	back := simtest.NewLink[simtest.Datagram](simtest.PerfectLink(), 2)
	fab := simtest.NewFabric(sender, receiver, []*simtest.Link[simtest.Datagram]{fwd}, []*simtest.Link[simtest.Datagram]{back})
	fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 100_000) {
		t.Fatalf("only %d/%d delivered", len(fab.DeliveredSeqs()), n)
	}
	if v := fab.CheckInvariants(simtest.InvariantOpts{RequireContiguous: true, MaxLatency: flow.DefaultConfig().RecoveryBuffer() + 10*clock.Millisecond}); len(v) != 0 {
		t.Fatalf("arrival perfect-link invariant violations: %v", v)
	}
	if !equalSeqs(fab.DeliveredSeqs(), expectedSeqs(0, n)) {
		t.Fatalf("arrival delivered %v, want full run", fab.DeliveredSeqs())
	}
	if rst := receiver.Stats(); rst.Recovered != 0 || rst.NacksSent != 0 {
		t.Fatalf("arrival perfect link recovered/nacked = %d/%d, want 0/0", rst.Recovered, rst.NacksSent)
	}
}

// TestArrivalTimingRecoverableLoss asserts the four invariants under recoverable
// loss in ARRIVAL mode. Unlike SOURCE timing, arrival timing anchors each
// packet's deadline to its own arrival, so a recovered packet — and the in-order
// packets stalled behind it — are delivered later than the steady-state
// delay+buffer (latency is NOT uniform). The structural invariants still hold:
// no duplicate, in order, complete, and bounded by arrival + buffer + the NACK
// round trip.
func TestArrivalTimingRecoverableLoss(t *testing.T) {
	const (
		n    = 200
		seed = uint64(7)
	)
	sender, receiver := newPairArrival(0)
	fwd := simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: 10 * clock.Millisecond}, seed)
	fwd.SetDropFilter(protectEndpoints(seed, 0, n-1, 0.2))
	back := simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: 10 * clock.Millisecond}, seed^0x1234)
	fab := simtest.NewFabric(sender, receiver, []*simtest.Link[simtest.Datagram]{fwd}, []*simtest.Link[simtest.Datagram]{back})
	fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 400_000) {
		t.Fatalf("only %d/%d delivered (Recovered=%d, Lost=%d)", len(fab.DeliveredSeqs()), n, receiver.Stats().Recovered, receiver.Stats().Lost)
	}
	// LatencyTolerance/MaxLatency are generous because arrival timing legitimately
	// spikes latency around a recovered gap (the NACK round trip), unlike source
	// timing's uniform latency.
	maxLat := flow.DefaultConfig().RecoveryBuffer() + 200*clock.Millisecond
	if v := fab.CheckInvariants(simtest.InvariantOpts{LatencyTolerance: 200 * clock.Millisecond, MaxLatency: maxLat, RequireContiguous: true}); len(v) != 0 {
		t.Fatalf("arrival recoverable-loss invariant violations: %v", v)
	}
	if !equalSeqs(fab.DeliveredSeqs(), expectedSeqs(0, n)) {
		t.Fatalf("arrival incomplete under recoverable loss: %v", fab.DeliveredSeqs())
	}
	if rst := receiver.Stats(); rst.Lost != 0 || rst.Discontinuities != 0 {
		t.Fatalf("arrival lost/disc = %d/%d under recoverable loss, want 0/0", rst.Lost, rst.Discontinuities)
	}
}

// TestSingleLossRecoveredWithOneRetransmit drops exactly the first
// transmission of one interior packet (seed-free, via a one-shot drop filter)
// and asserts it is recovered by a single retransmit — the canonical ARQ
// round trip, asserted exactly.
func TestSingleLossRecoveredWithOneRetransmit(t *testing.T) {
	const n = 16
	const target = uint32(7)
	sender, receiver := newPair(0)

	// 1 ms links: the retransmit round trip (~2 ms) is well under the
	// cold-start NACK retry interval (1.1 x rtt_min = 5.5 ms), so the hole is
	// recovered before the receiver would re-NACK — exactly one retransmit.
	fastLink := simtest.LinkConfig{Delay: clock.Millisecond}
	fwd := simtest.NewLink[simtest.Datagram](fastLink, 1)
	armed := true
	fwd.SetDropFilter(func(d simtest.Datagram) bool {
		if armed && d.Media && !d.Pkt.Retransmit && d.Pkt.Seq == target {
			armed = false // drop only the first transmission of the target
			return true
		}
		return false
	})
	back := simtest.NewLink[simtest.Datagram](fastLink, 2)
	fab := simtest.NewFabric(sender, receiver, []*simtest.Link[simtest.Datagram]{fwd}, []*simtest.Link[simtest.Datagram]{back})
	fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 100_000) {
		t.Fatalf("only %d/%d delivered", len(fab.DeliveredSeqs()), n)
	}
	if v := fab.CheckInvariants(simtest.InvariantOpts{RequireContiguous: true, MaxLatency: flow.DefaultConfig().RecoveryBuffer() + clock.Millisecond}); len(v) != 0 {
		t.Fatalf("invariant violations: %v", v)
	}
	if !equalSeqs(fab.DeliveredSeqs(), expectedSeqs(0, n)) {
		t.Fatalf("delivered %v, want full run", fab.DeliveredSeqs())
	}
	if st := sender.Stats(); st.Retransmitted != 1 {
		t.Fatalf("Retransmitted = %d, want exactly 1", st.Retransmitted)
	}
	if st := receiver.Stats(); st.Recovered != 1 {
		t.Fatalf("Recovered = %d, want 1", st.Recovered)
	}
}

// TestTailLossIsBoundedNotComplete documents the structural limit of pure ARQ:
// a lost final packet has no successor to trigger its NACK, so it is never
// recovered. The delivered run is one short, the gap is bounded (exactly the
// tail), and the always-on invariants (no duplicate, in order, constant
// latency) still hold.
func TestTailLossIsBoundedNotComplete(t *testing.T) {
	const n = 16
	sender, receiver := newPair(0)
	fwd := simtest.NewLink[simtest.Datagram](simtest.PerfectLink(), 1)
	fwd.SetDropFilter(func(d simtest.Datagram) bool {
		// Drop every transmission of the last sequence: unrecoverable.
		return d.Media && d.Pkt.Seq == uint32(n-1)
	})
	back := simtest.NewLink[simtest.Datagram](simtest.PerfectLink(), 2)
	fab := simtest.NewFabric(sender, receiver, []*simtest.Link[simtest.Datagram]{fwd}, []*simtest.Link[simtest.Datagram]{back})
	fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

	// Run past the last deliverable packet's playout (no completeness pred to
	// wait on, since the tail never arrives).
	fab.RunUntil(func(f *simtest.Fabric) bool { return f.Now() >= clock.Timestamp(2*clock.Second) }, 100_000)

	// Structural invariants still hold (the delivered prefix is contiguous);
	// just not contiguity-to-N.
	if v := fab.CheckInvariants(simtest.InvariantOpts{RequireContiguous: true, MaxLatency: flow.DefaultConfig().RecoveryBuffer() + 10*clock.Millisecond}); len(v) != 0 {
		t.Fatalf("invariant violations on the delivered prefix: %v", v)
	}
	if got := fab.DeliveredSeqs(); !equalSeqs(got, expectedSeqs(0, n-1)) {
		t.Fatalf("delivered %v, want exactly [0..%d] (tail %d unrecoverable)", got, n-2, n-1)
	}
}

// TestHeavyLossGracefulDegradation pushes forward loss past what the back
// channel can repair within the budget (the back channel also drops NACKs):
// the core must not crash, must deliver no duplicate and nothing out of order
// and nothing late, and any gap it gives up on is a bounded, accounted
// discontinuity rather than a late or wrong delivery.
//
// Beyond the always-on invariants, the sweep proves ARQ is actually doing
// work — a build with retransmission disabled would leave Retransmitted and
// Recovered at zero and fail the recovery floor below — and that the
// abandon-then-deliver discontinuity path is genuinely exercised.
func TestHeavyLossGracefulDegradation(t *testing.T) {
	const n = 80
	maxLat := flow.DefaultConfig().RecoveryBuffer() + 10*clock.Millisecond // Delay, no jitter
	var totalRetransmitted, totalRecovered, totalDiscontinuities uint64
	for seed := uint64(0); seed < 64; seed++ {
		sender, receiver := newPair(0)
		fwd := simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: 10 * clock.Millisecond, Loss: 0.6}, seed)
		back := simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: 10 * clock.Millisecond, Loss: 0.3}, seed^0x55)
		fab := simtest.NewFabric(sender, receiver, []*simtest.Link[simtest.Datagram]{fwd}, []*simtest.Link[simtest.Datagram]{back})
		fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

		fab.RunUntil(func(f *simtest.Fabric) bool { return f.Now() >= clock.Timestamp(3*clock.Second) }, 500_000)

		// Completeness is NOT required under unrecoverable loss, but the other
		// three are absolute: no duplicate, in order, and nothing late
		// (uniform latency within the deadline). RequireContiguous is omitted
		// because abandoned gaps are expected here.
		if v := fab.CheckInvariants(simtest.InvariantOpts{LatencyTolerance: 0, MaxLatency: maxLat}); len(v) != 0 {
			t.Fatalf("seed %d: invariant violations under heavy loss: %v", seed, v)
		}
		st := receiver.Stats()
		if st.Delivered > uint64(n) {
			t.Fatalf("seed %d: delivered %d > %d sent", seed, st.Delivered, n)
		}
		// The Fabric's own discontinuity tally must agree with the receiver's.
		if uint64(fab.Discontinuities()) != st.Discontinuities {
			t.Fatalf("seed %d: fabric discontinuities %d != receiver %d",
				seed, fab.Discontinuities(), st.Discontinuities)
		}
		totalRetransmitted += sender.Stats().Retransmitted
		totalRecovered += st.Recovered
		totalDiscontinuities += st.Discontinuities
	}
	if totalRetransmitted == 0 || totalRecovered == 0 {
		t.Fatalf("no ARQ activity across the sweep (retransmitted=%d recovered=%d): "+
			"the test would pass even with recovery disabled", totalRetransmitted, totalRecovered)
	}
	if totalDiscontinuities == 0 {
		t.Fatal("heavy-loss sweep never exercised an abandoned-gap discontinuity")
	}
}

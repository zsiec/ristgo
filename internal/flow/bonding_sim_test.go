package flow_test

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/simtest"
)

// The bonding sim suite drives ONE sender flow and ONE receiver flow through an
// N-path Fabric in duplicate-transmit mode (SMPTE 2022-7): the sender's media
// is duplicated across every forward path with identical seq/source_time, and
// the receiver's (seq, source_time) dedup merges the copies into one ordered,
// complete stream. This is the intellectual centerpiece of the project — the
// merge lives entirely in the flow core's receiver ring (one line:
// receiver.go pathSeen |= pathBit(path)), so it is provable here, exhaustively,
// from seeds, with no host or sockets. Every test asserts the four invariants.
//
// It reuses the helpers in sim_test.go (newPair, seqPayload, expectedSeqs,
// equalSeqs, protectEndpoints) — same flow_test package.

// newBondedFabric builds an N-path Fabric in duplicate-TX mode. Each forward
// path gets fwdCfg with an INDEPENDENT seed and an endpoint-protecting drop
// filter (the first and last sequence are never dropped, interior sequences
// drop with probability lossP), so the anchor always lands and the final
// sequence always arrives (every interior loss has a delivered successor to
// trigger its NACK). Back channels are lossless so the NACKs for any
// all-paths-dropped sequence always reach the sender.
func newBondedFabric(sender, recvr *flow.Flow, nPaths int, fwdCfg simtest.LinkConfig, seed uint64, startSeq, lastSeq uint32, lossP float64) *simtest.Fabric {
	fwd := make([]*simtest.Link[simtest.Datagram], nPaths)
	back := make([]*simtest.Link[simtest.Datagram], nPaths)
	for p := 0; p < nPaths; p++ {
		pseed := seed ^ (uint64(p+1) * 0x9E3779B97F4A7C15)
		l := simtest.NewLink[simtest.Datagram](fwdCfg, pseed)
		l.SetDropFilter(protectEndpoints(pseed, startSeq, lastSeq, lossP))
		fwd[p] = l
		back[p] = simtest.NewLink[simtest.Datagram](simtest.LinkConfig{Delay: 10 * clock.Millisecond}, pseed^0xABCD)
	}
	fab := simtest.NewFabric(sender, recvr, fwd, back)
	fab.SetDuplicateTx(true)
	return fab
}

// runBonded drives a bonded scenario and asserts the four invariants plus exact
// completeness: with independent per-path loss, a sequence is delivered when ANY
// path's copy survives (the merge), and the rare all-paths-dropped sequence is
// recovered by ARQ over the lossless back channel.
func runBonded(t *testing.T, seed uint64, nPaths, n int, fwdCfg simtest.LinkConfig, lossP float64) {
	t.Helper()
	sender, receiver := newPair(0)
	lastSeq := uint32(n - 1)
	fab := newBondedFabric(sender, receiver, nPaths, fwdCfg, seed, 0, lastSeq, lossP)

	// Send the first packet a clear margin ahead of the rest so it anchors the
	// flow even when per-path jitter would otherwise let a later sequence's
	// copy arrive first (mirrors the jitter sweep in sim_test.go). The margin
	// must exceed the forward jitter.
	const sourceStart = 10 * clock.Millisecond
	fab.EnqueueSource(0, seqPayload(0))
	for i := 1; i < n; i++ {
		off := sourceStart + clock.Millisecond*clock.Microseconds(i-1)
		fab.EnqueueSource(clock.Timestamp(off), seqPayload(i))
	}

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 500_000) {
		st, rt := sender.Stats(), receiver.Stats()
		t.Fatalf("seed %d (%d paths): only %d/%d delivered (sndSent=%d sndRetx=%d rcvRecv=%d rcvRecovered=%d rcvLost=%d)",
			seed, nPaths, len(fab.DeliveredSeqs()), n, st.Sent, st.Retransmitted, rt.Received, rt.Recovered, rt.Lost)
	}

	maxLat := flow.DefaultConfig().RecoveryBuffer() + fwdCfg.Delay + fwdCfg.Jitter
	if v := fab.CheckInvariants(simtest.InvariantOpts{LatencyTolerance: 0, MaxLatency: maxLat, RequireContiguous: true}); len(v) != 0 {
		t.Fatalf("seed %d (%d paths): invariant violations: %v", seed, nPaths, v)
	}
	if got, want := fab.DeliveredSeqs(), expectedSeqs(0, n); !equalSeqs(got, want) {
		t.Fatalf("seed %d (%d paths): delivered %v, want %v", seed, nPaths, got, want)
	}
	if rst := receiver.Stats(); rst.Lost != 0 || rst.Discontinuities != 0 || rst.Delivered != uint64(n) {
		t.Fatalf("seed %d (%d paths): lost/disc/delivered = %d/%d/%d, want 0/0/%d",
			seed, nPaths, rst.Lost, rst.Discontinuities, rst.Delivered, n)
	}
}

// TestBonding2Path2022_7Sweep is the headline bonding gate: two paths, each with
// independent 30% forward loss, duplicate-TX. Per sequence the merge delivers
// directly unless BOTH paths drop it (~9%), and those are recovered by ARQ — so
// every sequence is delivered exactly once, in order, complete, at uniform
// latency, across a 256-seed sweep.
func TestBonding2Path2022_7Sweep(t *testing.T) {
	fwdCfg := simtest.LinkConfig{Delay: 10 * clock.Millisecond}
	for seed := uint64(0); seed < 256; seed++ {
		runBonded(t, seed, 2, 48, fwdCfg, 0.30)
	}
}

// TestBonding3Path2022_7Sweep raises the per-path loss to 50% over three paths
// (per-sequence all-three-drop ~12.5%, recovered by ARQ), with reordering
// jitter on every path. Proves the merge scales past two paths and tolerates
// reorder.
func TestBonding3Path2022_7Sweep(t *testing.T) {
	fwdCfg := simtest.LinkConfig{Delay: 10 * clock.Millisecond, Jitter: 3 * clock.Millisecond, DupProb: 0.05}
	for seed := uint64(0); seed < 128; seed++ {
		runBonded(t, seed, 3, 48, fwdCfg, 0.50)
	}
}

// TestBonding2022_7ZeroRetransmit is the defining 2022-7 property: when one path
// drops a packet's only transmission but another path carries its copy, the
// receiver delivers it WITHOUT any retransmission — the redundancy covers the
// loss, so the ARQ Recovered count stays zero. Path 0 drops a chosen interior
// sequence (both copies would be the same datagram, so dropping path 0's copy
// leaves path 1's), path 1 is lossless; equal delay and no jitter keep arrival
// in order so missing-detection never even fires.
func TestBonding2022_7ZeroRetransmit(t *testing.T) {
	const n = 32
	const dropSeq = uint32(17)
	sender, receiver := newPair(0)

	cfg := simtest.LinkConfig{Delay: 10 * clock.Millisecond}
	p0 := simtest.NewLink[simtest.Datagram](cfg, 1)
	p0.SetDropFilter(func(d simtest.Datagram) bool { return d.Media && d.Pkt.Seq == dropSeq })
	p1 := simtest.NewLink[simtest.Datagram](cfg, 2) // lossless
	back0 := simtest.NewLink[simtest.Datagram](cfg, 3)
	back1 := simtest.NewLink[simtest.Datagram](cfg, 4)

	fab := simtest.NewFabric(sender, receiver,
		[]*simtest.Link[simtest.Datagram]{p0, p1},
		[]*simtest.Link[simtest.Datagram]{back0, back1})
	fab.SetDuplicateTx(true)

	fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 200_000) {
		t.Fatalf("only %d/%d delivered", len(fab.DeliveredSeqs()), n)
	}
	if v := fab.CheckInvariants(simtest.InvariantOpts{LatencyTolerance: 0, RequireContiguous: true}); len(v) != 0 {
		t.Fatalf("invariant violations: %v", v)
	}
	if got, want := fab.DeliveredSeqs(), expectedSeqs(0, n); !equalSeqs(got, want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
	if rst := receiver.Stats(); rst.Recovered != 0 {
		t.Fatalf("Recovered = %d, want 0: the second path's copy must cover the drop with no retransmit", rst.Recovered)
	}
}

// TestBondingPathDeathSeamless kills one of two paths mid-stream and asserts the
// output is uninterrupted. Path 0 carries 20% loss (recovered by ARQ once it is
// the only survivor); path 1 is lossless until it is killed (DegradePath, 100%
// loss both directions) partway through. Before the kill the redundancy covers
// path 0's losses; after it, single-path ARQ does — and the delivered stream is
// complete, in order, deduplicated, and uniformly timed throughout.
func TestBondingPathDeathSeamless(t *testing.T) {
	const n = 64
	sender, receiver := newPair(0)
	lastSeq := uint32(n - 1)

	cfg := simtest.LinkConfig{Delay: 10 * clock.Millisecond}
	p0 := simtest.NewLink[simtest.Datagram](cfg, 7)
	p0.SetDropFilter(protectEndpoints(7, 0, lastSeq, 0.20))
	p1 := simtest.NewLink[simtest.Datagram](cfg, 8) // lossless until killed
	back0 := simtest.NewLink[simtest.Datagram](cfg, 9)
	back1 := simtest.NewLink[simtest.Datagram](cfg, 10)

	fab := simtest.NewFabric(sender, receiver,
		[]*simtest.Link[simtest.Datagram]{p0, p1},
		[]*simtest.Link[simtest.Datagram]{back0, back1})
	fab.SetDuplicateTx(true)
	fab.EnqueueCBR(0, clock.Millisecond, n, seqPayload)

	// Kill path 1 MID-TRANSMISSION: the source spans ~63 ms at 1 ms CBR and the
	// recovery buffer (~1 s) means nothing is delivered yet at 30 ms, so the
	// sequences sent after the kill reach only path 0 (lossy) and must be
	// carried by single-path ARQ — not by copies already buffered from path 1.
	fab.RunUntil(func(f *simtest.Fabric) bool { return !f.Now().Before(clock.Timestamp(30 * clock.Millisecond)) }, 200_000)
	fab.DegradePath(1, simtest.LinkConfig{Delay: 10 * clock.Millisecond, Loss: 1.0},
		simtest.LinkConfig{Delay: 10 * clock.Millisecond, Loss: 1.0}, 99)

	if !fab.RunUntil(func(f *simtest.Fabric) bool { return len(f.DeliveredSeqs()) >= n }, 500_000) {
		t.Fatalf("only %d/%d delivered after path death (Recovered=%d Lost=%d)",
			len(fab.DeliveredSeqs()), n, receiver.Stats().Recovered, receiver.Stats().Lost)
	}
	maxLat := flow.DefaultConfig().RecoveryBuffer() + cfg.Delay
	if v := fab.CheckInvariants(simtest.InvariantOpts{LatencyTolerance: 0, MaxLatency: maxLat, RequireContiguous: true}); len(v) != 0 {
		t.Fatalf("invariant violations after path death: %v", v)
	}
	if got, want := fab.DeliveredSeqs(), expectedSeqs(0, n); !equalSeqs(got, want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
	rst := receiver.Stats()
	if rst.Lost != 0 || rst.Delivered != uint64(n) {
		t.Fatalf("lost/delivered = %d/%d, want 0/%d", rst.Lost, rst.Delivered, n)
	}
	// The death must have forced genuine single-path ARQ recovery on the
	// surviving lossy path; otherwise the scenario would be vacuous (path 1's
	// redundancy, or pre-buffered copies, could mask every loss).
	if rst.Recovered == 0 {
		t.Fatal("path-death test vacuous: no ARQ recovery occurred after the kill")
	}
}

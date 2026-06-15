package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// distinctMainPorts returns n distinct free single-port (Main/Advanced) loopback
// ports.
func distinctMainPorts(t *testing.T, n int) []int {
	t.Helper()
	seen := map[int]bool{}
	ports := make([]int, 0, n)
	for len(ports) < n {
		p := freeMainPort(t)
		if seen[p] {
			continue
		}
		seen[p] = true
		ports = append(ports, p)
	}
	return ports
}

// weightedBondCfg is a fast Advanced-profile config for the weighted load-share
// e2e tests, with a buffer long enough for ARQ to recover a lossy path.
func weightedBondCfg() ristgo.Config {
	cfg := advConfig("", 0, false)
	cfg.BufferMin = 500 * time.Millisecond
	cfg.BufferMax = 500 * time.Millisecond
	return cfg
}

// TestE2EBondedWeightedLoadShare proves weighted load-sharing end to end: a bonded
// Advanced sender splits one flow across two paths weighted 3:1, each path routed
// through a counting proxy. The receiver reconstructs the stream bit-exact, and the
// per-path media counts confirm the 3:1 split actually happened — which also proves
// the stream was load-shared, not duplicated (duplication would put every packet on
// both paths, a ~1:1 count).
func TestE2EBondedWeightedLoadShare(t *testing.T) {
	const totalBytes = 256 * 1024
	ports := distinctMainPorts(t, 4)
	recvA, recvB, proxyA, proxyB := ports[0], ports[1], ports[2], ports[3]

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", recvA), fmt.Sprintf("127.0.0.1:%d", recvB)}, weightedBondCfg())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	pA := startSinglePortLossyProxy(t, proxyA, recvA, 0, 1)
	defer pA.Close()
	pB := startSinglePortLossyProxy(t, proxyB, recvB, 0, 2)
	defer pB.Close()

	// Path 0 weight 3, path 1 weight 1: path 0 carries three quarters of the stream.
	tx, err := ristgo.NewBondedSenderPeers([]ristgo.BondedPeer{
		{Addr: fmt.Sprintf("127.0.0.1:%d", proxyA), Weight: 3},
		{Addr: fmt.Sprintf("127.0.0.1:%d", proxyB), Weight: 1},
	}, weightedBondCfg())
	if err != nil {
		t.Fatalf("NewBondedSenderPeers: %v", err)
	}
	defer tx.Close()

	payload := advPayload(t, totalBytes, false)
	want := sha256.Sum256(payload)
	if got := streamSHA(t, tx, rx, payload, nil); got != want {
		t.Fatalf("weighted load-share hash mismatch (pathA media=%d pathB media=%d)", pA.Forwarded(), pB.Forwarded())
	}

	fwdA, fwdB := pA.Forwarded(), pB.Forwarded()
	if fwdA == 0 || fwdB == 0 {
		t.Fatalf("a weighted path carried no media: pathA=%d pathB=%d (load not shared)", fwdA, fwdB)
	}
	ratio := float64(fwdA) / float64(fwdB)
	if ratio < 2.3 || ratio > 4.0 {
		t.Fatalf("weighted split = %d:%d (ratio %.2f), want ~3:1; a ~1:1 ratio would mean duplication, not load-share", fwdA, fwdB, ratio)
	}
}

// TestE2EBondedConfigWeightLoadShare proves the uniform-weight surface
// (Config.Weight, set by WithWeight / the ?weight= URL parameter) load-shares the
// []string bonded sender form: a positive Config.Weight makes every path carry an
// equal share rather than the default full duplication. Without it this path would
// silently fall back to duplication.
func TestE2EBondedConfigWeightLoadShare(t *testing.T) {
	const totalBytes = 192 * 1024
	ports := distinctMainPorts(t, 4)
	recvA, recvB, proxyA, proxyB := ports[0], ports[1], ports[2], ports[3]

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", recvA), fmt.Sprintf("127.0.0.1:%d", recvB)}, weightedBondCfg())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	pA := startSinglePortLossyProxy(t, proxyA, recvA, 0, 5)
	defer pA.Close()
	pB := startSinglePortLossyProxy(t, proxyB, recvB, 0, 6)
	defer pB.Close()

	cfg := weightedBondCfg()
	cfg.Weight = 1 // uniform weighted load-share across the []string paths
	tx, err := ristgo.NewBondedSender(
		[]string{fmt.Sprintf("127.0.0.1:%d", proxyA), fmt.Sprintf("127.0.0.1:%d", proxyB)}, cfg)
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	payload := advPayload(t, totalBytes, false)
	want := sha256.Sum256(payload)
	if got := streamSHA(t, tx, rx, payload, nil); got != want {
		t.Fatalf("config-weight load-share hash mismatch (pathA media=%d pathB media=%d)", pA.Forwarded(), pB.Forwarded())
	}

	fwdA, fwdB := pA.Forwarded(), pB.Forwarded()
	if fwdA == 0 || fwdB == 0 {
		t.Fatalf("Config.Weight did not load-share: pathA=%d pathB=%d (duplication or single-path)", fwdA, fwdB)
	}
	ratio := float64(fwdA) / float64(fwdB)
	if ratio < 0.6 || ratio > 1.7 {
		t.Fatalf("uniform-weight split = %d:%d (ratio %.2f), want ~1:1", fwdA, fwdB, ratio)
	}
}

// TestE2EBondedWeightedLossRecovery proves ARQ still recovers under load-sharing
// (not just under 2022-7 duplication): two Advanced paths weighted 1:1, one of them
// 25% lossy, with the reverse NACK channel preserved through the proxy. The stream
// must reconstruct bit-exact, and the receiver must have recovered packets by
// retransmission — load-share has no redundant copy, so a dropped packet can only
// come back via ARQ.
func TestE2EBondedWeightedLossRecovery(t *testing.T) {
	const totalBytes = 192 * 1024
	ports := distinctMainPorts(t, 4)
	recvA, recvB, proxyA, proxyB := ports[0], ports[1], ports[2], ports[3]

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", recvA), fmt.Sprintf("127.0.0.1:%d", recvB)}, weightedBondCfg())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	pA := startSinglePortLossyProxy(t, proxyA, recvA, 0.25, 7) // 25% media loss on path 0
	defer pA.Close()
	pB := startSinglePortLossyProxy(t, proxyB, recvB, 0, 8) // clean path 1
	defer pB.Close()

	tx, err := ristgo.NewBondedSenderPeers([]ristgo.BondedPeer{
		{Addr: fmt.Sprintf("127.0.0.1:%d", proxyA), Weight: 1},
		{Addr: fmt.Sprintf("127.0.0.1:%d", proxyB), Weight: 1},
	}, weightedBondCfg())
	if err != nil {
		t.Fatalf("NewBondedSenderPeers: %v", err)
	}
	defer tx.Close()

	payload := advPayload(t, totalBytes, false)
	want := sha256.Sum256(payload)
	if got := streamSHA(t, tx, rx, payload, nil); got != want {
		st := rx.Stats()
		t.Fatalf("weighted+loss hash mismatch (dropped=%d recovered=%d lost=%d)", pA.Dropped(), st.Recovered, st.Lost)
	}
	if pA.Dropped() == 0 {
		t.Fatal("the lossy path dropped nothing; loss was not exercised")
	}
	if rx.Stats().Recovered == 0 {
		t.Fatal("no packets recovered; ARQ was not exercised under load-share (a dropped packet has no duplicate)")
	}
}

// TestBondedSenderSetWeightDynamic proves the runtime weight change (libRIST
// rist_peer_weight_set): the stream starts split 1:1, then a mid-stream SetWeight
// promotes path 0 to weight 9, so over the whole run path 0 carries the majority.
// The stream still reconstructs bit-exact across the weight change.
func TestBondedSenderSetWeightDynamic(t *testing.T) {
	const totalBytes = 256 * 1024
	ports := distinctMainPorts(t, 4)
	recvA, recvB, proxyA, proxyB := ports[0], ports[1], ports[2], ports[3]

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", recvA), fmt.Sprintf("127.0.0.1:%d", recvB)}, weightedBondCfg())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	pA := startSinglePortLossyProxy(t, proxyA, recvA, 0, 3)
	defer pA.Close()
	pB := startSinglePortLossyProxy(t, proxyB, recvB, 0, 4)
	defer pB.Close()

	tx, err := ristgo.NewBondedSenderPeers([]ristgo.BondedPeer{
		{Addr: fmt.Sprintf("127.0.0.1:%d", proxyA), Weight: 1},
		{Addr: fmt.Sprintf("127.0.0.1:%d", proxyB), Weight: 1},
	}, weightedBondCfg())
	if err != nil {
		t.Fatalf("NewBondedSenderPeers: %v", err)
	}
	defer tx.Close()

	// Bad inputs are rejected without touching the rotation.
	if err := tx.SetWeight(5, 1); err == nil {
		t.Fatal("SetWeight accepted an out-of-range path index")
	}
	if err := tx.SetWeight(0, -1); err == nil {
		t.Fatal("SetWeight accepted a negative weight")
	}

	payload := advPayload(t, totalBytes, false)
	want := sha256.Sum256(payload)
	// Mid-stream, promote path 0 to weight 5 so it carries the large majority from
	// then on (kept off an extreme skew so one slow path cannot pile the reorder
	// buffer under load).
	promote := func() {
		if err := tx.SetWeight(0, 5); err != nil {
			t.Errorf("SetWeight: %v", err)
		}
	}
	if got := streamSHA(t, tx, rx, payload, promote); got != want {
		t.Fatalf("dynamic-weight hash mismatch (pathA media=%d pathB media=%d)", pA.Forwarded(), pB.Forwarded())
	}

	fwdA, fwdB := pA.Forwarded(), pB.Forwarded()
	if fwdA <= fwdB {
		t.Fatalf("after promoting path 0 mid-stream, pathA=%d should exceed pathB=%d", fwdA, fwdB)
	}
}

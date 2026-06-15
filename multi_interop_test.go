//go:build interop

package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestInteropMultiReceiverTwoLibristSenders is the live proof of RIST stream
// multiplexing: two independent libRIST ristsenders (each its own random
// flow_id) stream distinct media to one ristgo MultiReceiver, which
// demultiplexes them by SSRC into two flows and recovers each byte-exact.
func TestInteropMultiReceiverTwoLibristSenders(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeEvenPort(t)
	feedA := freeUDPPort(t, goPort, goPort+1)
	feedB := freeUDPPort(t, goPort, goPort+1, feedA)

	mrx, err := ristgo.NewMultiReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), interopReceiverConfig())
	if err != nil {
		t.Fatalf("NewMultiReceiver: %v", err)
	}
	defer mrx.Close()

	// Two libRIST Simple-profile senders to the same ristgo port. Each picks its
	// own random even flow_id, so the receiver sees two distinct flows.
	spawnTool(t, sender, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedA),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
	spawnTool(t, sender, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedB),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
	waitToolReady(t, feedA, 5*time.Second)
	waitToolReady(t, feedB, 5*time.Second)

	dataA, shaA := randomData(t, interopN)
	dataB, shaB := randomData(t, interopN)
	go feedUDP(t, feedA, dataA)
	go feedUDP(t, feedB, dataB)

	type result struct {
		sha [32]byte
		n   int
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		rx, err := mrx.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		go func(rx *ristgo.Receiver) {
			defer rx.Close()
			got := readN(t, rx, len(dataA)) // both streams are interopN*interopChunk bytes
			results <- result{sha256.Sum256(got), len(got)}
		}(rx)
	}

	seen := map[[32]byte]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.n != len(dataA) {
				t.Fatalf("a flow received %d/%d bytes", r.n, len(dataA))
			}
			seen[r.sha] = true
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for both demultiplexed libRIST flows")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("demux mismatch: the two libRIST flows did not reconstruct as two distinct streams")
	}
}

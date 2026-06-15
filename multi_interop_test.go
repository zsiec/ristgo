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

// TestInteropMultiBondedReceiverTwoLibristSenders proves stream multiplexing and
// SMPTE 2022-7 bonding at once, interoperably: two libRIST -p 0 senders, each
// duplicating its flow to two peers (weight=0), feed one ristgo MultiBondedReceiver
// bound to those two paths. ristgo demultiplexes by SSRC into two flows and merges
// each across both paths, recovering both byte-exact.
func TestInteropMultiBondedReceiverTwoLibristSenders(t *testing.T) {
	sender := libristTool(t, "ristsender")
	pA, pB := twoEvenPorts(t)
	feedA := freeUDPPort(t, pA, pA+1, pB, pB+1)
	feedB := freeUDPPort(t, pA, pA+1, pB, pB+1, feedA)

	mrx, err := ristgo.NewMultiBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewMultiBondedReceiver: %v", err)
	}
	defer mrx.Close()

	spawnTool(t, sender, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedA),
		"-o", libristBondedOut(pA, pB))
	spawnTool(t, sender, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedB),
		"-o", libristBondedOut(pA, pB))
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
			got := readN(t, rx, len(dataA))
			results <- result{sha256.Sum256(got), len(got)}
		}(rx)
	}

	seen := map[[32]byte]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.n != len(dataA) {
				t.Fatalf("a bonded flow received %d/%d bytes", r.n, len(dataA))
			}
			seen[r.sha] = true
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for both bonded libRIST flows")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("bonded demux mismatch: the two libRIST flows did not reconstruct")
	}
}

// TestInteropMultiReceiverTwoLibristMainSenders proves Main-profile multiplexing
// interop with PSK: two libRIST -p 1 AES-256 senders are demultiplexed by source
// address into two Main flows, each decrypted with its own key state and
// recovered byte-exact.
func TestInteropMultiReceiverTwoLibristMainSenders(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	feedA := freeUDPPort(t, goPort)
	feedB := freeUDPPort(t, goPort, feedA)

	mrx, err := ristgo.NewMultiReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), mainInteropConfig(256))
	if err != nil {
		t.Fatalf("NewMultiReceiver: %v", err)
	}
	defer mrx.Close()

	spawnTool(t, sender, "-p", "1", "-s", mainInteropSecret, "-e", "256", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedA),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
	spawnTool(t, sender, "-p", "1", "-s", mainInteropSecret, "-e", "256", "-b", "200",
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
			got := readN(t, rx, len(dataA))
			results <- result{sha256.Sum256(got), len(got)}
		}(rx)
	}

	seen := map[[32]byte]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.n != len(dataA) {
				t.Fatalf("a Main flow received %d/%d bytes", r.n, len(dataA))
			}
			seen[r.sha] = true
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for both libRIST Main flows")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("Main demux mismatch: the two libRIST flows did not reconstruct")
	}
}

// TestInteropMultiReceiverTwoLibristAdvSenders proves Advanced-profile
// multiplexing interop: two libRIST -p 2 senders (distinct sources) are
// demultiplexed by source address into two independent Advanced flows by one
// ristgo MultiReceiver, each recovered byte-exact.
func TestInteropMultiReceiverTwoLibristAdvSenders(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	feedA := freeUDPPort(t, goPort)
	feedB := freeUDPPort(t, goPort, feedA)

	mrx, err := ristgo.NewMultiReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), advInteropConfig(0, false))
	if err != nil {
		t.Fatalf("NewMultiReceiver: %v", err)
	}
	defer mrx.Close()

	spawnTool(t, sender, append(advToolArgs(0),
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedA),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))...)
	spawnTool(t, sender, append(advToolArgs(0),
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedB),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))...)
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
			got := readN(t, rx, len(dataA))
			results <- result{sha256.Sum256(got), len(got)}
		}(rx)
	}

	seen := map[[32]byte]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.n != len(dataA) {
				t.Fatalf("an Advanced flow received %d/%d bytes", r.n, len(dataA))
			}
			seen[r.sha] = true
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for both libRIST Advanced flows")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("Advanced demux mismatch: the two libRIST flows did not reconstruct")
	}
}

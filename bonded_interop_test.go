//go:build interop

// Bonding / SMPTE 2022-7 interop tests against libRIST. A libRIST ristsender
// (-p 0) with two duplicate (weight=0) output peers transmits the identical RTP
// stream to two ports; ristgo's bonded receiver merges them into one
// deduplicated, in-order stream. Proven feasible by capture: libRIST sends the
// same (seq, SSRC) on both peers. Run under -tags interop; t.Skip when the tools
// are absent. Reuses the shared interop helpers (interop_test.go) and the
// bonded-e2e helpers (bonded_e2e_test.go: twoEvenPorts, mediaRelay, bondConfig).
package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// readBonded reads exactly want bytes from a bonded receiver (or until the
// deadline), returning what it got.
func readBonded(t *testing.T, rx *ristgo.BondedReceiver, want int) []byte {
	t.Helper()
	rx.SetReadDeadline(time.Now().Add(20 * time.Second))
	got := make([]byte, 0, want)
	buf := make([]byte, 4096)
	for len(got) < want {
		n, err := rx.Read(buf)
		if n > 0 {
			take := n
			if len(got)+take > want {
				take = want - len(got)
			}
			got = append(got, buf[:take]...)
		}
		if err != nil {
			break
		}
	}
	return got
}

// libristBondedArgs builds the two-duplicate-peer -o argument for ristsender.
func libristBondedOut(pA, pB int) string {
	return fmt.Sprintf("rist://127.0.0.1:%d?weight=0,rist://127.0.0.1:%d?weight=0", pA, pB)
}

// TestInteropBondedGoRxClean: libRIST ristsender (-p 0, two duplicate peers) ->
// ristgo bonded Receiver (two paths). Proves ristgo merges libRIST's duplicated
// RTP into one complete, byte-exact stream.
func TestInteropBondedGoRxClean(t *testing.T) {
	sender := libristTool(t, "ristsender")
	pA, pB := twoEvenPorts(t)
	feedPort := freeUDPPort(t, pA, pA+1, pB, pB+1)

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	spawnTool(t, sender, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", libristBondedOut(pA, pB))
	waitToolReady(t, feedPort, 5*time.Second)

	data, want := randomData(t, interopN)
	go feedUDP(t, feedPort, data)

	got := readBonded(t, rx, len(data))
	if len(got) != len(data) {
		st := rx.Stats()
		t.Fatalf("bonded GoRx: received %d/%d bytes (Received=%d Delivered=%d Duplicates=%d Lost=%d)",
			len(got), len(data), st.Received, st.Delivered, st.Duplicates, st.Lost)
	}
	if sha256.Sum256(got) != want {
		t.Fatal("bonded GoRx: byte mismatch from libRIST sender")
	}
	// Both libRIST peers delivered the stream; ristgo must have deduplicated the
	// second path's copies.
	if st := rx.Stats(); st.Duplicates == 0 {
		t.Fatalf("bonded GoRx: Duplicates=0 — the two paths were not merged (Received=%d Delivered=%d)", st.Received, st.Delivered)
	}
}

// TestInteropBondedGoRxSeamlessLoss: libRIST sender duplicates to two peers, one
// of which goes through a 40%-loss media relay; ristgo's bonded receiver must
// still reconstruct the complete, byte-exact stream from the clean path's copies
// (the defining 2022-7 property), with zero abandoned packets.
func TestInteropBondedGoRxSeamlessLoss(t *testing.T) {
	sender := libristTool(t, "ristsender")
	pA, pB := twoEvenPorts(t)
	relayPort := freeEvenPort(t)
	for relayPort == pA || relayPort == pB {
		relayPort = freeEvenPort(t)
	}
	feedPort := freeUDPPort(t, pA, pA+1, pB, pB+1, relayPort, relayPort+1)

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	// Path 0: libRIST -> 40%-loss relay -> pA. Path 1: libRIST -> pB direct.
	relay := startMediaRelay(t, relayPort, pA, 0.40, 5)
	defer relay.Close()

	spawnTool(t, sender, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", libristBondedOut(relayPort, pB))
	waitToolReady(t, feedPort, 5*time.Second)

	data, want := randomData(t, interopN)
	go feedUDP(t, feedPort, data)

	got := readBonded(t, rx, len(data))
	if len(got) != len(data) || sha256.Sum256(got) != want {
		st := rx.Stats()
		t.Fatalf("bonded GoRx seamless-loss failed: got %d/%d (relay dropped=%d Received=%d Delivered=%d Lost=%d)",
			len(got), len(data), relay.Dropped(), st.Received, st.Delivered, st.Lost)
	}
	if relay.Dropped() == 0 {
		t.Fatal("relay dropped nothing — the loss path was not exercised")
	}
	if st := rx.Stats(); st.Lost != 0 {
		t.Fatalf("Lost=%d — 2022-7 redundancy should cover every one-path drop", st.Lost)
	}
}

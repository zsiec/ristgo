package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// streamChunks writes data to tx in chunk-sized Writes with light pacing, then
// returns. It ignores write errors after a close (the test drives lifetime).
func streamChunks(tx *ristgo.Sender, data []byte, chunk int) {
	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if _, err := tx.Write(data[off:end]); err != nil {
			return
		}
		if (off/chunk)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
}

// TestE2EMultiReceiverMainTwoFlows demultiplexes two cleartext Main-profile
// flows (single GRE port) by source address into two recovered streams.
func TestE2EMultiReceiverMainTwoFlows(t *testing.T) {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileMain
	cfg.BufferMin = 200 * time.Millisecond
	cfg.BufferMax = 200 * time.Millisecond
	runMultiTwoFlows(t, cfg, freeMainPort(t))
}

// TestE2EMultiReceiverMainEAPTwoFlows demultiplexes two EAP-SRP-authenticated
// Main flows: each source authenticates independently via its own per-flow
// authenticator and keys its media from its own SRP session key.
func TestE2EMultiReceiverMainEAPTwoFlows(t *testing.T) {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileMain
	cfg.Username = "rist"
	cfg.Password = "multiflow"
	cfg.BufferMin = 1000 * time.Millisecond
	cfg.BufferMax = 1000 * time.Millisecond
	runMultiTwoFlows(t, cfg, freeMainPort(t))
}

// TestE2EMultiReceiverAdvancedTwoFlows streams two distinct Advanced-profile
// flows from two senders into one bound port and verifies the MultiReceiver
// demultiplexes them (by source address) into two independent recovered streams.
func TestE2EMultiReceiverAdvancedTwoFlows(t *testing.T) {
	cfg := advConfig("", 0, false)
	cfg.BufferMin = 200 * time.Millisecond
	cfg.BufferMax = 200 * time.Millisecond
	runMultiTwoFlows(t, cfg, freeMainPort(t))
}

// TestE2EMultiReceiverAdvancedPSKTwoFlows demultiplexes two PSK-encrypted
// Advanced flows: each demuxed flow gets its own AES key state and decrypts
// independently.
func TestE2EMultiReceiverAdvancedPSKTwoFlows(t *testing.T) {
	cfg := advConfig("ristgo-multi-psk", 256, false)
	cfg.BufferMin = 300 * time.Millisecond
	cfg.BufferMax = 300 * time.Millisecond
	runMultiTwoFlows(t, cfg, freeMainPort(t))
}

// runMultiTwoFlows streams two distinct flows from two senders into one
// MultiReceiver and asserts both reconstruct bit-exact (set equality on SHA-256).
func runMultiTwoFlows(t *testing.T, cfg ristgo.Config, port int) {
	t.Helper()
	const perFlowBytes = 96 * 1024
	const chunk = 1316
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	mrx, err := ristgo.NewMultiReceiver(addr, cfg)
	if err != nil {
		t.Fatalf("NewMultiReceiver: %v", err)
	}
	defer mrx.Close()

	dataA := make([]byte, perFlowBytes)
	dataB := make([]byte, perFlowBytes)
	if _, err := rand.Read(dataA); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(dataB); err != nil {
		t.Fatalf("rand: %v", err)
	}
	shaA := sha256.Sum256(dataA)
	shaB := sha256.Sum256(dataB)

	txA, err := ristgo.NewSender(addr, cfg)
	if err != nil {
		t.Fatalf("NewSender A: %v", err)
	}
	defer txA.Close()
	txB, err := ristgo.NewSender(addr, cfg)
	if err != nil {
		t.Fatalf("NewSender B: %v", err)
	}
	defer txB.Close()

	go streamChunks(txA, dataA, chunk)
	go streamChunks(txB, dataB, chunk)

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
			rx.SetReadDeadline(time.Now().Add(15 * time.Second))
			got := make([]byte, 0, perFlowBytes)
			buf := make([]byte, 4096)
			h := sha256.New()
			for len(got) < perFlowBytes {
				n, rerr := rx.Read(buf)
				if n > 0 {
					take := n
					if len(got)+take > perFlowBytes {
						take = perFlowBytes - len(got)
					}
					h.Write(buf[:take])
					got = append(got, buf[:take]...)
				}
				if rerr != nil {
					break
				}
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			results <- result{sum, len(got)}
		}(rx)
	}

	seen := map[[32]byte]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.n != perFlowBytes {
				t.Fatalf("a flow received %d/%d bytes", r.n, perFlowBytes)
			}
			seen[r.sha] = true
		case <-time.After(25 * time.Second):
			t.Fatal("timed out waiting for both flows")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("demux mismatch: the two flows did not reconstruct the two streams")
	}
}

// TestE2EMultiReceiverLossRecovery sends one flow through a 10%-loss proxy into a
// MultiReceiver and verifies the demuxed flow recovers every byte by ARQ, proving
// the injected session's NACK/retransmit path works through the shared socket.
func TestE2EMultiReceiverLossRecovery(t *testing.T) {
	const totalBytes = 96 * 1024
	const chunk = 1316
	const flushChunks = 24

	recvPort := freeEvenPort(t)
	proxyPort := freeEvenPort(t)
	for proxyPort == recvPort {
		proxyPort = freeEvenPort(t)
	}

	cfg := ristgo.DefaultConfig()
	cfg.BufferMin = 500 * time.Millisecond
	cfg.BufferMax = 500 * time.Millisecond

	mrx, err := ristgo.NewMultiReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewMultiReceiver: %v", err)
	}
	defer mrx.Close()

	proxy := startLossyProxy(t, proxyPort, recvPort, 0.10, 7)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data := make([]byte, totalBytes)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(data)

	go func() {
		streamChunks(tx, data, chunk)
		flush := make([]byte, chunk)
		for i := 0; i < flushChunks; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

	rx, err := mrx.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer rx.Close()
	rx.SetReadDeadline(time.Now().Add(20 * time.Second))
	got := make([]byte, 0, totalBytes)
	buf := make([]byte, 4096)
	h := sha256.New()
	for len(got) < totalBytes {
		n, rerr := rx.Read(buf)
		if n > 0 {
			take := n
			if len(got)+take > totalBytes {
				take = totalBytes - len(got)
			}
			h.Write(buf[:take])
			got = append(got, buf[:take]...)
		}
		if rerr != nil {
			t.Fatalf("Read ended early at %d/%d: %v (recovered=%d lost=%d)", len(got), totalBytes, rerr, rx.Stats().Recovered, rx.Stats().Lost)
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if sum != want {
		t.Fatalf("demuxed flow not recovered: hash mismatch (dropped=%d recovered=%d)", proxy.Dropped(), rx.Stats().Recovered)
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped nothing; loss path not exercised")
	}
	if rx.Stats().Recovered == 0 {
		t.Fatal("no packets recovered; ARQ not exercised through the demuxer")
	}
}

// TestE2EMultiReceiverTwoFlows streams two distinct media flows from two senders
// into one bound port, and verifies the MultiReceiver demultiplexes them into
// two independent receivers that each recover their own stream bit-exact.
func TestE2EMultiReceiverTwoFlows(t *testing.T) {
	const perFlowBytes = 128 * 1024
	const chunk = 1316

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	mrx, err := ristgo.NewMultiReceiver(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewMultiReceiver: %v", err)
	}
	defer mrx.Close()

	dataA := make([]byte, perFlowBytes)
	dataB := make([]byte, perFlowBytes)
	if _, err := rand.Read(dataA); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(dataB); err != nil {
		t.Fatalf("rand: %v", err)
	}
	shaA := sha256.Sum256(dataA)
	shaB := sha256.Sum256(dataB)

	txA, err := ristgo.NewSender(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewSender A: %v", err)
	}
	defer txA.Close()
	txB, err := ristgo.NewSender(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewSender B: %v", err)
	}
	defer txB.Close()

	go streamChunks(txA, dataA, chunk)
	go streamChunks(txB, dataB, chunk)

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
			rx.SetReadDeadline(time.Now().Add(15 * time.Second))
			got := make([]byte, 0, perFlowBytes)
			buf := make([]byte, 4096)
			h := sha256.New()
			for len(got) < perFlowBytes {
				n, rerr := rx.Read(buf)
				if n > 0 {
					take := n
					if len(got)+take > perFlowBytes {
						take = perFlowBytes - len(got)
					}
					h.Write(buf[:take])
					got = append(got, buf[:take]...)
				}
				if rerr != nil {
					break
				}
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			results <- result{sum, len(got)}
		}(rx)
	}

	seen := map[[32]byte]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.n != perFlowBytes {
				t.Fatalf("a flow received %d/%d bytes", r.n, perFlowBytes)
			}
			seen[r.sha] = true
		case <-time.After(25 * time.Second):
			t.Fatal("timed out waiting for both demultiplexed flows")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("demux mismatch: the two flows did not reconstruct the two distinct streams")
	}
}

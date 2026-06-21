package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestMultiReceiverFECRejected verifies a demultiplexing MultiReceiver rejects
// separate-port FEC (Simple/Main) rather than silently binding no FEC sockets and
// recovering nothing. The rejection fires before any socket is bound (F4).
func TestMultiReceiverFECRejected(t *testing.T) {
	cfg := fastConfig() // Simple profile -> FEC resolves to the separate-port carriage
	cfg.FEC = &ristgo.FECConfig{Columns: 5, Rows: 5}

	if rx, err := ristgo.NewMultiReceiver("127.0.0.1:0", cfg); err == nil {
		rx.Close()
		t.Fatal("NewMultiReceiver + separate-port FEC should be rejected")
	} else if !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("NewMultiReceiver error = %v, want ErrInvalidConfig", err)
	}

	if rx, err := ristgo.NewMultiBondedReceiver([]string{"127.0.0.1:0"}, cfg); err == nil {
		rx.Close()
		t.Fatal("NewMultiBondedReceiver + separate-port FEC should be rejected")
	} else if !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("NewMultiBondedReceiver error = %v, want ErrInvalidConfig", err)
	}
}

// TestMultiReceiverCloseNoLeak opens two flows on a MultiReceiver, then closes
// the whole receiver and verifies every goroutine it spawned returns to the
// pre-construction baseline: the two socket reader goroutines, the per-flow
// retire watchers, and each demuxed injected session's event loop. This is the
// most goroutine-dense transport (readers + one watcher and one session per
// flow), and its injected sessions take the no-socket-close shutdown path, so a
// leak here would be unique to multiplexing.
func TestMultiReceiverCloseNoLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()
	const perFlowBytes = 32 * 1024
	const chunk = 1316

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	mrx, err := ristgo.NewMultiReceiver(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewMultiReceiver: %v", err)
	}

	dataA := make([]byte, perFlowBytes)
	dataB := make([]byte, perFlowBytes)
	if _, err := rand.Read(dataA); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(dataB); err != nil {
		t.Fatalf("rand: %v", err)
	}

	txA, err := ristgo.NewSender(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewSender A: %v", err)
	}
	txB, err := ristgo.NewSender(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewSender B: %v", err)
	}
	go streamChunks(txA, dataA, chunk)
	go streamChunks(txB, dataB, chunk)

	// Accept both flows and read one payload from each so the sessions are fully
	// spun up before we tear everything down.
	for i := 0; i < 2; i++ {
		rx, err := mrx.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		rx.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		if _, err := rx.Read(buf); err != nil {
			t.Fatalf("Read flow %d: %v", i, err)
		}
		rx.Close()
	}

	txA.Close()
	txB.Close()
	if err := mrx.Close(); err != nil {
		t.Fatalf("MultiReceiver.Close: %v", err)
	}

	for i := 0; i < 40; i++ {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutines did not return to baseline: have %d, baseline %d", runtime.NumGoroutine(), baseline)
}

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

// streamBonded writes data to a bonded sender in chunk-sized Writes, lightly
// paced.
func streamBonded(tx *ristgo.BondedSender, data []byte, chunk int) {
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

// TestE2EMultiBondedReceiverTwoFlows combines multiplexing and SMPTE 2022-7
// bonding: two bonded senders each duplicate one flow over two paths, and one
// MultiBondedReceiver demultiplexes by SSRC into two flows, each merged across
// both paths, both recovered bit-exact.
func TestE2EMultiBondedReceiverTwoFlows(t *testing.T) {
	const perFlowBytes = 96 * 1024
	const chunk = 1316

	pA, pB := twoEvenPorts(t)
	addrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}

	mrx, err := ristgo.NewMultiBondedReceiver(addrs, bondConfig())
	if err != nil {
		t.Fatalf("NewMultiBondedReceiver: %v", err)
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

	txA, err := ristgo.NewBondedSender(addrs, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender A: %v", err)
	}
	defer txA.Close()
	txB, err := ristgo.NewBondedSender(addrs, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender B: %v", err)
	}
	defer txB.Close()

	go streamBonded(txA, dataA, chunk)
	go streamBonded(txB, dataB, chunk)

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
				t.Fatalf("a bonded flow received %d/%d bytes", r.n, perFlowBytes)
			}
			seen[r.sha] = true
		case <-time.After(25 * time.Second):
			t.Fatal("timed out waiting for both bonded flows")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("bonded demux mismatch: the two flows did not reconstruct")
	}
}

// TestE2EMultiBondedReceiverSeamlessLoss drops 40% on one path of a two-path,
// two-flow bonded multiplex and verifies both flows still reconstruct bit-exact
// with zero loss: each flow's dropped packets on the lossy path are covered by
// the clean path (2022-7 redundancy), per flow, through the demuxer.
func TestE2EMultiBondedReceiverSeamlessLoss(t *testing.T) {
	const perFlowBytes = 64 * 1024
	const chunk = 1316

	pA, pB := twoEvenPorts(t)
	relayPort := freeEvenPort(t)
	for relayPort == pA || relayPort == pB {
		relayPort = freeEvenPort(t)
	}
	recvAddrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}
	sendAddrs := []string{fmt.Sprintf("127.0.0.1:%d", relayPort), fmt.Sprintf("127.0.0.1:%d", pB)}

	mrx, err := ristgo.NewMultiBondedReceiver(recvAddrs, bondConfig())
	if err != nil {
		t.Fatalf("NewMultiBondedReceiver: %v", err)
	}
	defer mrx.Close()

	// Path 0 (relayPort -> pA) loses 40%; path 1 (pB) is clean.
	relay := startMediaRelay(t, relayPort, pA, 0.40, 17)
	defer relay.Close()

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

	txA, err := ristgo.NewBondedSender(sendAddrs, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender A: %v", err)
	}
	defer txA.Close()
	txB, err := ristgo.NewBondedSender(sendAddrs, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender B: %v", err)
	}
	defer txB.Close()

	go streamBonded(txA, dataA, chunk)
	go streamBonded(txB, dataB, chunk)

	type result struct {
		sha  [32]byte
		n    int
		lost uint64
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		rx, err := mrx.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		go func(rx *ristgo.Receiver) {
			defer rx.Close()
			rx.SetReadDeadline(time.Now().Add(20 * time.Second))
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
			results <- result{sum, len(got), rx.Stats().Lost}
		}(rx)
	}

	seen := map[[32]byte]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.n != perFlowBytes {
				t.Fatalf("a bonded flow received %d/%d bytes (lost=%d, relay dropped=%d)", r.n, perFlowBytes, r.lost, relay.Dropped())
			}
			if r.lost != 0 {
				t.Fatalf("flow Lost=%d under one-path loss; the clean path should cover it", r.lost)
			}
			seen[r.sha] = true
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for both bonded flows under loss")
		}
	}
	if !seen[shaA] || !seen[shaB] {
		t.Fatal("bonded demux mismatch under loss")
	}
	if relay.Dropped() == 0 {
		t.Fatal("relay dropped nothing; the loss path was not exercised")
	}
}

// acceptAndMatchTwo accepts two flows, reads perFlowBytes from each, and asserts
// the two reconstructed streams equal the two expected SHA-256s (set equality).
func acceptAndMatchTwo(t *testing.T, mrx *ristgo.MultiReceiver, want1, want2 [32]byte, perFlowBytes int) {
	t.Helper()
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
			rx.SetReadDeadline(time.Now().Add(20 * time.Second))
			got := 0
			buf := make([]byte, 4096)
			h := sha256.New()
			for got < perFlowBytes {
				n, rerr := rx.Read(buf)
				if n > 0 {
					take := n
					if got+take > perFlowBytes {
						take = perFlowBytes - got
					}
					h.Write(buf[:take])
					got += take
				}
				if rerr != nil {
					break
				}
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			results <- result{sum, got}
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
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for both flows")
		}
	}
	if !seen[want1] || !seen[want2] {
		t.Fatal("demux mismatch: the two flows did not reconstruct the two streams")
	}
}

// TestE2EMultiBondedReceiverAdvancedPSK combines PSK-encrypted Advanced with both
// multiplexing and bonding: two AES-256 bonded senders, each duplicating one flow
// over two single-port paths, demultiplexed by source address (no SSRC peek) into
// two flows, each decrypted with its own key and merged across both paths.
func TestE2EMultiBondedReceiverAdvancedPSK(t *testing.T) {
	const perFlowBytes = 64 * 1024
	const chunk = 1316

	pA := freeMainPort(t)
	pB := freeMainPort(t)
	for pB == pA {
		pB = freeMainPort(t)
	}
	addrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}
	cfg := advConfig("ristgo-multibond-psk", 256, false)
	cfg.BufferMin = 400 * time.Millisecond
	cfg.BufferMax = 400 * time.Millisecond

	mrx, err := ristgo.NewMultiBondedReceiver(addrs, cfg)
	if err != nil {
		t.Fatalf("NewMultiBondedReceiver: %v", err)
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

	txA, err := ristgo.NewBondedSender(addrs, cfg)
	if err != nil {
		t.Fatalf("NewBondedSender A: %v", err)
	}
	defer txA.Close()
	txB, err := ristgo.NewBondedSender(addrs, cfg)
	if err != nil {
		t.Fatalf("NewBondedSender B: %v", err)
	}
	defer txB.Close()

	go streamBonded(txA, dataA, chunk)
	go streamBonded(txB, dataB, chunk)

	acceptAndMatchTwo(t, mrx, sha256.Sum256(dataA), sha256.Sum256(dataB), perFlowBytes)
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
	cfg.Profile = ristgo.ProfileSimple // Simple even/odd demuxed-receiver path (DefaultConfig is Advanced)
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

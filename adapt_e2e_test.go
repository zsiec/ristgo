package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// singlePortLossyProxy relays a single-port flow (Main or Advanced profile)
// between a sender that addresses the proxy and a receiver, dropping a fraction
// of forward MEDIA datagrams to force ARQ recovery and make the receiver report
// link loss. Media is identified by size: it is far larger than keepalives, the
// handshake, and control messages, so datagrams below minMediaSize — and all
// return traffic — are relayed reliably, keeping the handshake, NACKs, and Link
// Quality Messages flowing while only media is lossy.
type singlePortLossyProxy struct {
	front        *net.UDPConn // faces the sender (bound to proxyPort)
	back         *net.UDPConn // faces the receiver (ephemeral)
	recvAddr     *net.UDPAddr
	loss         float64
	minMediaSize int
	rng          *mrand.Rand
	dropped      atomic.Uint64
	mu           sync.Mutex
	senderAddr   *net.UDPAddr
	wg           sync.WaitGroup
}

// Dropped reports how many forward media datagrams the proxy has dropped.
func (p *singlePortLossyProxy) Dropped() uint64 { return p.dropped.Load() }

// startSinglePortLossyProxy binds the proxy on proxyPort and relays to the
// receiver on recvPort, dropping forward media-sized datagrams with probability
// loss. The returned proxy must be Closed by the caller.
func startSinglePortLossyProxy(t *testing.T, proxyPort, recvPort int, loss float64, seed uint64) *singlePortLossyProxy {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort})
	if err != nil {
		t.Fatalf("proxy front bind: %v", err)
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		front.Close()
		t.Fatalf("proxy back bind: %v", err)
	}
	p := &singlePortLossyProxy{
		front:        front,
		back:         back,
		recvAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort},
		loss:         loss,
		minMediaSize: 256, // media >> keepalive/handshake/control on the wire
		rng:          mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)),
	}
	p.wg.Add(2)
	go p.relayForward()
	go p.relayBackward()
	return p
}

// relayForward forwards sender->receiver, dropping a fraction of media-sized
// datagrams and learning the sender's address for the return path.
func (p *singlePortLossyProxy) relayForward() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.senderAddr = src
		p.mu.Unlock()
		if n >= p.minMediaSize && p.rng.Float64() < p.loss {
			p.dropped.Add(1)
			continue
		}
		p.back.WriteToUDP(buf[:n], p.recvAddr)
	}
}

// relayBackward forwards receiver->sender (LQMs, NACKs, echoes, handshake)
// reliably to the learned sender address.
func (p *singlePortLossyProxy) relayBackward() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := p.back.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		dst := p.senderAddr
		p.mu.Unlock()
		if dst != nil {
			p.front.WriteToUDP(buf[:n], dst)
		}
	}
}

// Close stops the proxy.
func (p *singlePortLossyProxy) Close() {
	p.front.Close()
	p.back.Close()
	p.wg.Wait()
}

// TestE2ESourceAdaptation drives the full source-adaptation feedback loop
// (VSF TR-06-4 Part 1) over a lossy link on every profile: the receiver
// (SourceAdaptation enabled) sends Link Quality Messages back to the sender, and
// the sender's AIMD controller turns the reported loss into encoder-rate targets
// delivered through OnRateAdapt. Under sustained media loss the reported target
// must fall below the configured ceiling, and the stream itself must still arrive
// bit-exact (ARQ recovers the link loss the LQM reports). The three profiles
// carry the LQM differently — an RR profile-specific extension (Simple), the same
// RR GRE-tunnelled (Main), a native Type=Control message (Advanced) — so running
// all three proves the unified host wiring end to end.
func TestE2ESourceAdaptation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile ristgo.Profile
	}{
		{"Simple", ristgo.ProfileSimple},
		{"Main", ristgo.ProfileMain},
		{"Advanced", ristgo.ProfileAdvanced},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runAdaptScenario(t, tc.profile)
		})
	}
}

// runAdaptScenario streams a paced media flow through a lossy proxy for one
// profile and asserts the adaptation loop ran: OnRateAdapt fired, the proxy
// actually dropped media, the reported targets stayed within the ceiling, and the
// controller backed off below it under loss — all while the stream arrived
// bit-exact.
func runAdaptScenario(t *testing.T, profile ristgo.Profile) {
	const totalBytes = 160 * 1024
	const chunk = 1316
	const maxBitrate = 50000 // kbps ceiling for the controller

	recvPort := freeEvenPort(t)
	proxyPort := freeEvenPort(t)
	for proxyPort == recvPort {
		proxyPort = freeEvenPort(t)
	}

	// Record every rate target the sender's controller reports.
	var mu sync.Mutex
	var targets []int
	mkcfg := func(role string) ristgo.Config {
		c := ristgo.DefaultConfig()
		c.Profile = profile
		c.BufferMin = 400 * time.Millisecond
		c.BufferMax = 400 * time.Millisecond
		c.KeepaliveInterval = 150 * time.Millisecond // fast LQM cadence for the test
		c.MaxBitrate = maxBitrate
		switch role {
		case "rx":
			c.SourceAdaptation = true
		case "tx":
			c.OnRateAdapt = func(kbps int) {
				mu.Lock()
				targets = append(targets, kbps)
				mu.Unlock()
			}
		}
		return c
	}

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), mkcfg("rx"))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	// Simple uses an even/odd port pair; Main and Advanced multiplex one port.
	var proxyDropped func() uint64
	if profile == ristgo.ProfileSimple {
		p := startLossyProxy(t, proxyPort, recvPort, 0.15, 7)
		defer p.Close()
		proxyDropped = p.Dropped
	} else {
		p := startSinglePortLossyProxy(t, proxyPort, recvPort, 0.15, 7)
		defer p.Close()
		proxyDropped = p.Dropped
	}

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), mkcfg("tx"))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
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
				done <- [32]byte{}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- sum
	}()

	// Pace the stream over ~3 s so several LQM reporting periods elapse.
	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < totalBytes; off += chunk {
		end := off + chunk
		if end > totalBytes {
			end = totalBytes
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	flush := make([]byte, chunk)
	for i := 0; i < 24; i++ {
		tx.Write(flush)
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("source-adaptation stream hash mismatch (proxy dropped=%d recovered=%d lost=%d)",
				proxyDropped(), rx.Stats().Recovered, rx.Stats().Lost)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("timed out on the source-adaptation stream")
	}

	mu.Lock()
	got := append([]int(nil), targets...)
	mu.Unlock()

	if len(got) == 0 {
		t.Fatal("OnRateAdapt was never called — the LQM feedback loop did not run")
	}
	if proxyDropped() == 0 {
		t.Fatal("proxy dropped no media — the loss path was not exercised")
	}
	// Under sustained loss the controller must have reduced the target below the
	// ceiling at least once.
	minTarget := got[0]
	for _, v := range got {
		if v < minTarget {
			minTarget = v
		}
		if v > maxBitrate {
			t.Fatalf("reported target %d kbps exceeds the configured ceiling %d", v, maxBitrate)
		}
	}
	if minTarget >= maxBitrate {
		t.Fatalf("controller never backed off under loss: targets=%v (ceiling %d)", got, maxBitrate)
	}
}

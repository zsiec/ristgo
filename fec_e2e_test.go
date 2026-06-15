package ristgo_test

import (
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

// fecLossyProxy is a bidirectional single-port proxy for the FEC e2e: it forwards
// the reverse channel (RTCP/handshake) reliably, and on the forward channel drops
// a fraction of media-sized datagrams AFTER a warmup, so the first media packet
// always arrives and the receiver's FEC matrix aligns to the sender's ISN.
type fecLossyProxy struct {
	front, back *net.UDPConn
	recvAddr    *net.UDPAddr
	loss        float64
	minSize     int
	warmup      int
	rng         *mrand.Rand
	mu          sync.Mutex
	senderAddr  *net.UDPAddr
	seen        int
	dropped     atomic.Uint64
	wg          sync.WaitGroup
}

func startFECLossyProxy(t *testing.T, proxyPort, recvPort int, loss float64, warmup int, seed uint64) *fecLossyProxy {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort})
	if err != nil {
		t.Fatalf("fec proxy front bind: %v", err)
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		front.Close()
		t.Fatalf("fec proxy back bind: %v", err)
	}
	p := &fecLossyProxy{
		front:    front,
		back:     back,
		recvAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort},
		loss:     loss,
		minSize:  256,
		warmup:   warmup,
		rng:      mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)),
	}
	p.wg.Add(2)
	go p.forward()
	go p.backward()
	return p
}

func (p *fecLossyProxy) forward() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.senderAddr = src
		large := n >= p.minSize
		if large {
			p.seen++
		}
		drop := large && p.seen > p.warmup && p.rng.Float64() < p.loss
		p.mu.Unlock()
		if drop {
			p.dropped.Add(1)
			continue
		}
		p.back.WriteToUDP(buf[:n], p.recvAddr)
	}
}

func (p *fecLossyProxy) backward() {
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

func (p *fecLossyProxy) Dropped() uint64 { return p.dropped.Load() }
func (p *fecLossyProxy) Close()          { p.front.Close(); p.back.Close(); p.wg.Wait() }

// TestE2EFECRecoversAdvanced runs an Advanced-profile stream with 2-D SMPTE 2022-1
// FEC over a lossy link and verifies the receiver recovers losses by FEC. The
// stream reconstructs bit-exact and Stats.FECRecovered is non-zero, proving FEC
// (not only ARQ) carried the recovery. ARQ remains the backstop, so completeness
// is guaranteed regardless.
func TestE2EFECRecoversAdvanced(t *testing.T) {
	const totalBytes = 256 * 1024
	const chunk = 1316

	recvPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == recvPort {
		proxyPort = freeMainPort(t)
	}

	cfg := advConfig("", 0, false)
	cfg.BufferMin = 500 * time.Millisecond
	cfg.BufferMax = 500 * time.Millisecond
	cfg.FEC = &ristgo.FECConfig{Columns: 5, Rows: 5} // 2-D, 25-packet matrix

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	// 8% media loss after a one-matrix warmup, so the first packet (and the ISN
	// alignment) survives and FEC has losses to recover.
	proxy := startFECLossyProxy(t, proxyPort, recvPort, 0.08, 25, 0xFEC0)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data := advPayload(t, totalBytes, false)
	want := sha256.Sum256(data)

	go func() {
		tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			if _, werr := tx.Write(data[off:end]); werr != nil {
				return
			}
			if (off/chunk)%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		flush := make([]byte, chunk)
		for i := 0; i < 40; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

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
			st := rx.Stats()
			t.Fatalf("Read ended early at %d/%d: %v (dropped=%d fecRecovered=%d arqRecovered=%d lost=%d)",
				len(got), totalBytes, rerr, proxy.Dropped(), st.FECRecovered, st.Recovered, st.Lost)
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	st := rx.Stats()
	if sum != want {
		t.Fatalf("hash mismatch (dropped=%d fecRecovered=%d arqRecovered=%d)", proxy.Dropped(), st.FECRecovered, st.Recovered)
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped nothing; loss not exercised")
	}
	if st.FECRecovered == 0 {
		t.Fatalf("no packets recovered by FEC (dropped=%d arqRecovered=%d); FEC not effective", proxy.Dropped(), st.Recovered)
	}
	t.Logf("FEC e2e: dropped=%d fecRecovered=%d arqRecovered=%d", proxy.Dropped(), st.FECRecovered, st.Recovered)
}

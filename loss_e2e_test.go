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

// lossyProxy relays a Simple-profile flow between a sender (which addresses the
// proxy) and a receiver, dropping a fraction of forward MEDIA datagrams to
// force ARQ recovery. RTCP is relayed reliably in both directions, so NACKs
// and echoes always get through — isolating recovery over a lossy media path.
type lossyProxy struct {
	mediaSock *net.UDPConn // proxy media port M (sender -> here -> receiver:P)
	rtcpSock  *net.UDPConn // proxy rtcp port M+1 (sender <-> receiver:P+1)
	recvMedia *net.UDPAddr
	recvRTCP  *net.UDPAddr
	loss      float64
	rng       *mrand.Rand
	dropped   atomic.Uint64
	wg        sync.WaitGroup
}

// Dropped reports how many forward media datagrams the proxy has dropped — a
// wire-independent witness that the loss path was actually exercised.
func (p *lossyProxy) Dropped() uint64 { return p.dropped.Load() }

// startLossyProxy binds the proxy on proxyPort/proxyPort+1 and relays to the
// receiver on recvPort/recvPort+1, dropping forward media with probability
// loss. The returned proxy must be Closed by the caller.
func startLossyProxy(t *testing.T, proxyPort, recvPort int, loss float64, seed uint64) *lossyProxy {
	t.Helper()
	ms, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort})
	if err != nil {
		t.Fatalf("proxy media bind: %v", err)
	}
	rs, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort + 1})
	if err != nil {
		ms.Close()
		t.Fatalf("proxy rtcp bind: %v", err)
	}
	p := &lossyProxy{
		mediaSock: ms,
		rtcpSock:  rs,
		recvMedia: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort},
		recvRTCP:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort + 1},
		loss:      loss,
		rng:       mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)),
	}
	p.wg.Add(2)
	go p.relayMedia()
	go p.relayRTCP()
	return p
}

// relayMedia forwards sender->receiver media, dropping a fraction.
func (p *lossyProxy) relayMedia() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := p.mediaSock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if p.rng.Float64() < p.loss {
			p.dropped.Add(1)
			continue // drop
		}
		p.mediaSock.WriteToUDP(buf[:n], p.recvMedia)
	}
}

// relayRTCP relays RTCP both ways: packets from the receiver go to the learned
// sender address; everything else is from the sender and goes to the receiver.
func (p *lossyProxy) relayRTCP() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	var senderRTCP *net.UDPAddr
	for {
		n, src, err := p.rtcpSock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if src.Port == p.recvRTCP.Port && src.IP.Equal(p.recvRTCP.IP) {
			if senderRTCP != nil {
				p.rtcpSock.WriteToUDP(buf[:n], senderRTCP)
			}
			continue
		}
		senderRTCP = src
		p.rtcpSock.WriteToUDP(buf[:n], p.recvRTCP)
	}
}

// Close stops the proxy.
func (p *lossyProxy) Close() {
	p.mediaSock.Close()
	p.rtcpSock.Close()
	p.wg.Wait()
}

// TestE2ELossRecovery sends a stream through a 15%-media-loss proxy and
// verifies every byte is recovered by ARQ (SHA-256 over real UDP, real codec,
// real timers). A 500ms recovery buffer leaves ample time on loopback, and a
// run of trailing flush packets guarantees the payload's tail has a successor
// to trigger its NACK.
func TestE2ELossRecovery(t *testing.T) {
	const totalBytes = 128 * 1024
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

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startLossyProxy(t, proxyPort, recvPort, 0.15, 1)
	defer proxy.Close()

	// The sender addresses the proxy; the proxy relays to the receiver.
	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wantHash := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(20 * time.Second))
		got := make([]byte, 0, totalBytes)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < totalBytes {
			n, err := rx.Read(buf)
			if n > 0 {
				take := n
				if len(got)+take > totalBytes {
					take = totalBytes - len(got)
				}
				h.Write(buf[:take])
				got = append(got, buf[:take]...)
			}
			if err != nil {
				done <- [32]byte{} // signals failure (incomplete)
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- sum
	}()

	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < totalBytes; off += chunk {
		end := off + chunk
		if end > totalBytes {
			end = totalBytes
		}
		if _, err := tx.Write(payload[off:end]); err != nil {
			t.Fatalf("Write at %d: %v", off, err)
		}
		if (off/chunk)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	// Trailing flush so a lost payload tail still has a delivered successor.
	flush := make([]byte, chunk)
	for i := 0; i < flushChunks; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}

	select {
	case gotHash := <-done:
		if gotHash != wantHash {
			st := rx.Stats()
			t.Fatalf("recovered stream hash mismatch (delivered=%d recovered=%d lost=%d):\n got %x\nwant %x",
				st.Delivered, st.Recovered, st.Lost, gotHash, wantHash)
		}
	case <-time.After(25 * time.Second):
		st := rx.Stats()
		t.Fatalf("timed out (delivered=%d recovered=%d lost=%d)", st.Delivered, st.Recovered, st.Lost)
	}

	if st := rx.Stats(); st.Recovered == 0 {
		t.Fatalf("no packets were recovered by ARQ — loss path not exercised (delivered=%d)", st.Delivered)
	}
}

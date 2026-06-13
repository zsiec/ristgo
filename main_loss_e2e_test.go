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

// mainLossyProxy sits on one UDP port between a Main-profile sender and
// receiver, dropping a fraction of forward (sender->receiver) datagrams to
// force ARQ recovery, and relaying reverse (receiver->sender) datagrams intact
// so NACKs and echoes always get through. Because the Main profile is a single
// GRE port and (under PSK) the inner payload-type byte is encrypted, the proxy
// cannot tell media from feedback by content — so it demuxes by SOURCE ADDRESS
// (datagrams from the receiver are reverse, everything else is forward). The
// forward stream is dominated by media, so dropping a fraction of it exercises
// the receiver's NACK -> the sender's GRE+PSK retransmit -> recovery path
// end-to-end over the real wire.
type mainLossyProxy struct {
	sock     *net.UDPConn
	recvAddr *net.UDPAddr
	loss     float64
	rng      *mrand.Rand
	dropped  atomic.Uint64
	mu       sync.Mutex
	sender   *net.UDPAddr
	wg       sync.WaitGroup
}

// startMainLossyProxy binds the proxy on proxyPort and relays to the receiver
// on recvPort, dropping forward datagrams with probability loss.
func startMainLossyProxy(t *testing.T, proxyPort, recvPort int, loss float64, seed uint64) *mainLossyProxy {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort})
	if err != nil {
		t.Fatalf("main proxy bind: %v", err)
	}
	p := &mainLossyProxy{
		sock:     sock,
		recvAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort},
		loss:     loss,
		rng:      mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)),
	}
	p.wg.Add(1)
	go p.relay()
	return p
}

// Dropped reports how many forward datagrams the proxy has dropped — a
// wire-independent witness that loss was actually exercised.
func (p *mainLossyProxy) Dropped() uint64 { return p.dropped.Load() }

func (p *mainLossyProxy) relay() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if src.Port == p.recvAddr.Port && src.IP.Equal(p.recvAddr.IP) {
			// Reverse (receiver -> sender): relay intact so NACKs/echoes survive.
			p.mu.Lock()
			s := p.sender
			p.mu.Unlock()
			if s != nil {
				p.sock.WriteToUDP(buf[:n], s)
			}
			continue
		}
		// Forward (sender -> receiver): learn the sender, drop a fraction.
		p.mu.Lock()
		p.sender = src
		p.mu.Unlock()
		if p.rng.Float64() < p.loss {
			p.dropped.Add(1)
			continue
		}
		p.sock.WriteToUDP(buf[:n], p.recvAddr)
	}
}

// Close stops the proxy.
func (p *mainLossyProxy) Close() { p.sock.Close(); p.wg.Wait() }

// TestE2EMainLossRecovery streams through a 10%-forward-loss proxy on the Main
// profile and verifies every byte is recovered by ARQ (SHA-256), with no
// encryption and with PSK AES-128 and AES-256 — proving the GRE+PSK
// retransmit/NACK round-trip works end-to-end through the single-socket host,
// not just the codec unit tests. A 500ms recovery buffer and a trailing flush
// (so a lost tail has a delivered successor) leave ample room on loopback.
func TestE2EMainLossRecovery(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		aesBits int
	}{
		{"cleartext", "", 0},
		{"aes128", "ristgo-main-secret", 128},
		{"aes256", "ristgo-main-secret", 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const totalBytes = 96 * 1024
			const chunk = 1316
			const flushChunks = 24

			recvPort := freeMainPort(t)
			proxyPort := freeMainPort(t)
			for proxyPort == recvPort {
				proxyPort = freeMainPort(t)
			}

			cfg := mainConfig(tc.secret, tc.aesBits)
			cfg.BufferMin = 500 * time.Millisecond
			cfg.BufferMax = 500 * time.Millisecond

			rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()

			proxy := startMainLossyProxy(t, proxyPort, recvPort, 0.10, 1)
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
						done <- [32]byte{} // incomplete
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
				if _, werr := tx.Write(payload[off:end]); werr != nil {
					t.Fatalf("Write at %d: %v", off, werr)
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
			case got := <-done:
				if got != want {
					st := rx.Stats()
					t.Fatalf("Main %s loss recovery failed (proxy dropped=%d delivered=%d recovered=%d lost=%d)",
						tc.name, proxy.Dropped(), st.Delivered, st.Recovered, st.Lost)
				}
			case <-time.After(25 * time.Second):
				st := rx.Stats()
				t.Fatalf("Main %s timed out (proxy dropped=%d delivered=%d recovered=%d)",
					tc.name, proxy.Dropped(), st.Delivered, st.Recovered)
			}

			if proxy.Dropped() == 0 {
				t.Fatal("proxy dropped no datagrams — the loss/ARQ path was not exercised")
			}
			if st := rx.Stats(); st.Recovered == 0 {
				t.Fatalf("no packets recovered by ARQ over Main (proxy dropped=%d delivered=%d)", proxy.Dropped(), st.Delivered)
			}
		})
	}
}

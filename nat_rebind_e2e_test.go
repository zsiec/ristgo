package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// rebindProxy sits between a caller-receiver and a listener-sender and relays both
// directions. Calling rebind() swaps the socket it uses toward the listener, so the
// listener sees the receiver's traffic arrive from a NEW source tuple — exactly the
// NAT source-port rebind a dynamic-NAT caller experiences. It learns the receiver's
// address from the first forward datagram.
type rebindProxy struct {
	t            *testing.T
	front        *net.UDPConn // receiver <-> proxy
	listenerAddr *net.UDPAddr

	mu       sync.Mutex
	back     *net.UDPConn // proxy <-> listener (its source port is what the listener sees)
	recvAddr *net.UDPAddr // learned receiver address
	closed   bool
	wg       sync.WaitGroup
}

func startRebindProxy(t *testing.T, listenerPort int) (*rebindProxy, int) {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("proxy front bind: %v", err)
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("proxy back bind: %v", err)
	}
	p := &rebindProxy{
		t:            t,
		front:        front,
		back:         back,
		listenerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenerPort},
	}
	p.wg.Add(1)
	go p.forward()
	p.startBackReader()
	return p, front.LocalAddr().(*net.UDPAddr).Port
}

// forward relays receiver -> proxy -> listener, learning the receiver address.
func (p *rebindProxy) forward() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.recvAddr = src
		back := p.back
		p.mu.Unlock()
		back.WriteToUDP(buf[:n], p.listenerAddr)
	}
}

// startBackReader relays listener -> proxy -> receiver on the current back socket. It is
// restarted on rebind (the old socket is closed, ending the prior reader).
func (p *rebindProxy) startBackReader() {
	p.mu.Lock()
	back := p.back
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		buf := make([]byte, 2048)
		for {
			n, _, err := back.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.mu.Lock()
			rcv := p.recvAddr
			p.mu.Unlock()
			if rcv != nil {
				p.front.WriteToUDP(buf[:n], rcv)
			}
		}
	}()
}

// rebind swaps the back socket so the listener sees a new source tuple.
func (p *rebindProxy) rebind() {
	nb, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		p.t.Fatalf("proxy rebind bind: %v", err)
	}
	p.mu.Lock()
	old := p.back
	p.back = nb
	p.mu.Unlock()
	old.Close() // ends the old back reader
	p.startBackReader()
}

func (p *rebindProxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	back := p.back
	p.mu.Unlock()
	p.front.Close()
	back.Close()
	p.wg.Wait()
}

// TestE2ENATRebindSRPRecovery proves the SRP-gated NAT source-port rebind recovery:
// a listener-sender (EAP-SRP authenticatee) serves a caller-receiver (authenticator)
// through a proxy that, mid-stream, moves the receiver's traffic to a new source tuple.
// The listener detects the moved tuple only after the old one goes dormant, forces a
// fresh EAP-SRP re-auth (a replay/forger could not complete it), migrates the peer, and
// the stream is delivered byte-exact — recovering what a locked-address session would
// have lost to session timeout.
func TestE2ENATRebindSRPRecovery(t *testing.T) {
	const totalBytes = 512 * 1024
	const chunk = 1316
	listenerPort := freeMainPort(t)

	cfg := srpNoSecretConfig("rist", "mainprofile")
	cfg.BufferMin = 1500 * time.Millisecond // generous so ARQ recovers the rebind-window gap
	cfg.BufferMax = 1500 * time.Millisecond
	cfg.KeepaliveInterval = 100 * time.Millisecond // 2x = 200ms dormancy threshold before migrating

	tx, err := ristgo.NewListenerSender(fmt.Sprintf("127.0.0.1:%d", listenerPort), cfg)
	if err != nil {
		t.Fatalf("NewListenerSender: %v", err)
	}
	defer tx.Close()

	proxy, proxyPort := startRebindProxy(t, listenerPort)
	defer proxy.Close()

	rx, err := ristgo.NewReceiverCaller(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiverCaller: %v", err)
	}
	defer rx.Close()

	payload := make([]byte, totalBytes)
	for i := range payload {
		payload[i] = byte(i*7 + 1)
	}
	want := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(25 * time.Second))
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

	// Trigger the NAT rebind once the stream is well underway.
	rebound := false
	tx.SetWriteDeadline(time.Now().Add(25 * time.Second))
	go func() {
		// Pace the stream over ~2.5s so media keeps flowing across the rebind, the
		// ~200ms dormancy wait, and the re-auth — a continuous stream is what lets ARQ
		// reveal and recover the gap the dormancy window drops (a real flow, not a burst).
		for off := 0; off < totalBytes; off += chunk {
			end := off + chunk
			if end > totalBytes {
				end = totalBytes
			}
			if _, werr := tx.Write(payload[off:end]); werr != nil {
				return
			}
			if off > totalBytes/3 && !rebound {
				rebound = true
				proxy.rebind()
			}
			time.Sleep(6 * time.Millisecond)
		}
	}()

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("post-rebind delivery not byte-exact (authenticated=%v delivered=%d)",
				rx.Authenticated(), rx.Stats().Delivered)
		}
	case <-time.After(28 * time.Second):
		t.Fatalf("timed out after NAT rebind (authenticated=%v delivered=%d)",
			rx.Authenticated(), rx.Stats().Delivered)
	}
	if !rx.Authenticated() {
		t.Fatal("receiver not authenticated after rebind recovery")
	}
	// The recovery must have actually been exercised: ARQ healed the gap the dormancy
	// window dropped while the migration completed.
	if rx.Stats().Recovered == 0 {
		t.Fatal("no ARQ recovery — the rebind gap was not exercised (test no longer covers the path)")
	}
}

// TestE2ENATRebindForgerCannotHijack is the adversarial counterpart (libRIST's
// test_psk_cname_hijack / test_nat_port_rebind): while an authenticated EAP-SRP stream is
// live, a third party floods the listener-sender from a DIFFERENT source tuple. Because the
// established peer is not dormant and the forged datagrams do not decode under the session
// key, the re-association gate refuses them — the peer is never displaced and the stream is
// delivered byte-exact. (A forger that waited for dormancy still could not complete the
// forced re-auth; this proves the live-session case, the easiest hijack to attempt.)
func TestE2ENATRebindForgerCannotHijack(t *testing.T) {
	const totalBytes = 256 * 1024
	const chunk = 1316
	listenerPort := freeMainPort(t)

	cfg := srpNoSecretConfig("rist", "mainprofile")
	// Generous recovery buffer + deadlines (mirroring TestE2ENATRebindSRPRecovery): the
	// continuous forged flood competes for the listener's receive path — every junk
	// datagram is a failed decrypt — alongside the EAP-SRP handshake (not ARQ-protected)
	// and the media. Under -race on a loaded CI runner both the handshake and ARQ
	// recovery of flood-induced loopback loss need headroom, or delivery stalls into the
	// read deadline. The wide margins only extend the failure path; a healthy run still
	// completes in ~2 s.
	cfg.BufferMin = 1500 * time.Millisecond
	cfg.BufferMax = 1500 * time.Millisecond
	cfg.KeepaliveInterval = 100 * time.Millisecond

	tx, err := ristgo.NewListenerSender(fmt.Sprintf("127.0.0.1:%d", listenerPort), cfg)
	if err != nil {
		t.Fatalf("NewListenerSender: %v", err)
	}
	defer tx.Close()
	rx, err := ristgo.NewReceiverCaller(fmt.Sprintf("127.0.0.1:%d", listenerPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiverCaller: %v", err)
	}
	defer rx.Close()

	payload := make([]byte, totalBytes)
	for i := range payload {
		payload[i] = byte(i*5 + 3)
	}
	want := sha256.Sum256(payload)

	// The forger: a separate socket spraying garbage at the listener from its own tuple,
	// throughout the stream. None of it decodes under the session key.
	forger, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenerPort})
	if err != nil {
		t.Fatalf("forger dial: %v", err)
	}
	defer forger.Close()
	stopForge := make(chan struct{})
	go func() {
		junk := make([]byte, 200)
		for {
			select {
			case <-stopForge:
				return
			default:
				forger.Write(junk)
				// A continuous flood, but paced so rejecting junk does not starve the
				// real handshake/media on a loaded runner — still ~250 forged pkts/s
				// throughout the stream, far more than any real hijack attempt.
				time.Sleep(4 * time.Millisecond)
			}
		}
	}()

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(25 * time.Second))
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

	tx.SetWriteDeadline(time.Now().Add(25 * time.Second))
	go func() {
		for off := 0; off < totalBytes; off += chunk {
			end := off + chunk
			if end > totalBytes {
				end = totalBytes
			}
			if _, werr := tx.Write(payload[off:end]); werr != nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	select {
	case got := <-done:
		close(stopForge)
		if got != want {
			t.Fatalf("forged flood disrupted delivery (authenticated=%v delivered=%d)",
				rx.Authenticated(), rx.Stats().Delivered)
		}
	case <-time.After(28 * time.Second):
		close(stopForge)
		t.Fatalf("timed out under forged flood (delivered=%d)", rx.Stats().Delivered)
	}
	if !rx.Authenticated() {
		t.Fatal("session lost authentication under the forged flood")
	}
}

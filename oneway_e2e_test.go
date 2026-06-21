package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// oneWayConfig is fastConfig plus a profile selector for the one-way
// (no-return-channel) constructors.
func oneWayConfig(profile ristgo.Profile) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = profile
	cfg.BufferMin = 100 * time.Millisecond
	cfg.BufferMax = 100 * time.Millisecond
	return cfg
}

// runOneWayLoopback drives a one-way flow over a clean UDP loopback: the sender
// streams with no return channel and the receiver sends nothing back. On a
// loss-free link every byte still arrives in order, verified bit-identical via
// SHA-256, and the counters confirm no recovery machinery ran (the sender never
// retransmitted, the receiver never NACKed or recovered).
func runOneWayLoopback(t *testing.T, profile ristgo.Profile, secret string) {
	t.Helper()
	const totalBytes = 256 * 1024
	const chunk = 1316

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := oneWayConfig(profile)
	cfg.Secret = secret

	rx, err := ristgo.NewOneWayReceiver(addr, cfg)
	if err != nil {
		t.Fatalf("NewOneWayReceiver: %v", err)
	}
	defer rx.Close()

	tx, err := ristgo.NewOneWaySender(addr, cfg)
	if err != nil {
		t.Fatalf("NewOneWaySender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wantHash := sha256.Sum256(payload)

	done := make(chan reversedResult, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, 0, totalBytes)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < totalBytes {
			n, err := rx.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				got = append(got, buf[:n]...)
			}
			if err != nil {
				done <- reversedResult{n: len(got), err: err}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- reversedResult{hash: sum, n: len(got)}
	}()

	tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
	for off := 0; off < totalBytes; off += chunk {
		end := off + chunk
		if end > totalBytes {
			end = totalBytes
		}
		if _, err := tx.Write(payload[off:end]); err != nil {
			t.Fatalf("Write at %d: %v", off, err)
		}
		if off%(chunk*16) == 0 {
			time.Sleep(time.Millisecond)
		}
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("receive ended after %d/%d bytes: %v", r.n, totalBytes, r.err)
		}
		if r.n != totalBytes {
			t.Fatalf("received %d bytes, want %d", r.n, totalBytes)
		}
		if r.hash != wantHash {
			t.Fatalf("received stream hash mismatch:\n got %x\nwant %x", r.hash, wantHash)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the one-way stream")
	}

	// No recovery machinery ran: the sender retained no history and the receiver
	// requested nothing.
	if st := tx.Stats(); st.Retransmitted != 0 {
		t.Fatalf("one-way sender Retransmitted = %d, want 0", st.Retransmitted)
	}
	if st := rx.Stats(); st.Recovered != 0 || st.NACKsSent != 0 {
		t.Fatalf("one-way receiver Recovered/NACKsSent = %d/%d, want 0/0", st.Recovered, st.NACKsSent)
	}
}

// TestOneWayLoopbackSimple verifies one-way transport on the Simple profile.
func TestOneWayLoopbackSimple(t *testing.T) { runOneWayLoopback(t, ristgo.ProfileSimple, "") }

// TestOneWayLoopbackMain verifies one-way transport on the Main profile (single
// GRE socket; the sender emits no GRE keepalive, only media).
func TestOneWayLoopbackMain(t *testing.T) { runOneWayLoopback(t, ristgo.ProfileMain, "") }

// TestOneWayLoopbackMainPSK verifies one-way Main with PSK payload encryption —
// the keys derive from the shared passphrase, needing no handshake.
func TestOneWayLoopbackMainPSK(t *testing.T) {
	runOneWayLoopback(t, ristgo.ProfileMain, "one-way-secret")
}

// TestOneWayLoopbackAdvanced verifies one-way transport on the Advanced profile
// (the sender emits no GRE/RTCP handshake, only adv media).
func TestOneWayLoopbackAdvanced(t *testing.T) { runOneWayLoopback(t, ristgo.ProfileAdvanced, "") }

// TestOneWayLossySkipsNoRecovery sends a one-way stream through a lossy media
// path and asserts the receiver delivers what survives but recovers nothing:
// it requests no NACKs, recovers no packets, and the sender retransmits none —
// the distinguishing behavior of one-way transport. Dropped()>0 is a
// wire-independent witness that loss actually occurred.
func TestOneWayLossySkipsNoRecovery(t *testing.T) {
	const packets = 2000
	const chunk = 1200

	recvPort := freeEvenPort(t)
	proxyPort := freeEvenPort(t)
	for proxyPort == recvPort {
		proxyPort = freeEvenPort(t)
	}

	cfg := oneWayConfig(ristgo.ProfileSimple)

	rx, err := ristgo.NewOneWayReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewOneWayReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startLossyProxy(t, proxyPort, recvPort, 0.10, 7)
	defer proxy.Close()

	// The sender addresses the proxy; the proxy drops ~10% of media en route.
	tx, err := ristgo.NewOneWaySender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewOneWaySender: %v", err)
	}
	defer tx.Close()

	// A reader drains deliveries so the session never blocks on a full queue.
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		rx.SetReadDeadline(time.Now().Add(20 * time.Second))
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := rx.Read(buf); err != nil {
				return
			}
		}
	}()

	chunkBuf := make([]byte, chunk)
	if _, err := rand.Read(chunkBuf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for i := 0; i < packets; i++ {
		if _, err := tx.Write(chunkBuf); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		if i%16 == 0 {
			time.Sleep(time.Millisecond)
		}
	}

	// Let the playout buffer flush — every deliverable packet released, every
	// hole skipped — well within the default 2s session timeout.
	time.Sleep(time.Second)
	close(stop)

	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped nothing; loss path not exercised")
	}
	txSt, rxSt := tx.Stats(), rx.Stats()
	if rxSt.NACKsSent != 0 || rxSt.Recovered != 0 {
		t.Fatalf("one-way receiver recovered loss: NACKsSent=%d Recovered=%d, want 0/0", rxSt.NACKsSent, rxSt.Recovered)
	}
	if txSt.Retransmitted != 0 {
		t.Fatalf("one-way sender retransmitted %d, want 0", txSt.Retransmitted)
	}
	if rxSt.Delivered == 0 {
		t.Fatal("receiver delivered nothing; forward path broken")
	}
	if rxSt.Delivered >= txSt.Sent {
		t.Fatalf("delivered %d >= sent %d: loss appears recovered, but one-way must not recover", rxSt.Delivered, txSt.Sent)
	}
}

// TestOneWayCloseNoLeak verifies a one-way sender and receiver shut down
// cleanly: Close unblocks a pending Read with io.EOF and every goroutine the
// constructors start exits, returning the goroutine count to baseline.
func TestOneWayCloseNoLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	rx, err := ristgo.NewOneWayReceiver(addr, oneWayConfig(ristgo.ProfileSimple))
	if err != nil {
		t.Fatalf("NewOneWayReceiver: %v", err)
	}
	tx, err := ristgo.NewOneWaySender(addr, oneWayConfig(ristgo.ProfileSimple))
	if err != nil {
		rx.Close()
		t.Fatalf("NewOneWaySender: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, e := rx.Read(buf) // blocks: no media yet
		readErr <- e
	}()

	time.Sleep(50 * time.Millisecond)
	if err := tx.Close(); err != nil {
		t.Fatalf("tx.Close: %v", err)
	}
	if err := rx.Close(); err != nil {
		t.Fatalf("rx.Close: %v", err)
	}

	select {
	case e := <-readErr:
		if e != io.EOF {
			t.Fatalf("Read after Close = %v, want io.EOF", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}

	for i := 0; i < 20; i++ {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutines did not return to baseline: have %d, baseline %d", runtime.NumGoroutine(), baseline)
}

// TestOneWayConstructorErrors covers the one-way constructors' input validation:
// DTLS and EAP-SRP are rejected (their handshakes need a return channel), and
// the Simple profile still requires an even media port.
func TestOneWayConstructorErrors(t *testing.T) {
	dtls := ristgo.DefaultConfig()
	dtls.Profile = ristgo.ProfileMain
	dtls.DTLS = &ristgo.DTLSConfig{PSK: []byte("k")}

	eap := ristgo.DefaultConfig()
	eap.Profile = ristgo.ProfileMain
	eap.Username, eap.Password = "u", "p"

	oddSimple := ristgo.DefaultConfig()
	oddSimple.Profile = ristgo.ProfileSimple // odd-port rejection is a Simple rule (DefaultConfig is Advanced)

	cases := []struct {
		name string
		fn   func() error
	}{
		{"sender dtls", func() error { _, e := ristgo.NewOneWaySender("127.0.0.1:5000", dtls); return e }},
		{"receiver dtls", func() error { _, e := ristgo.NewOneWayReceiver("127.0.0.1:5000", dtls); return e }},
		{"sender eap", func() error { _, e := ristgo.NewOneWaySender("127.0.0.1:5000", eap); return e }},
		{"receiver eap", func() error { _, e := ristgo.NewOneWayReceiver("127.0.0.1:5000", eap); return e }},
		{"sender odd port", func() error { _, e := ristgo.NewOneWaySender("127.0.0.1:5001", oddSimple); return e }},
		{"receiver odd port", func() error { _, e := ristgo.NewOneWayReceiver("127.0.0.1:5001", oddSimple); return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatalf("%s: expected an error, got nil", tc.name)
			}
		})
	}
}

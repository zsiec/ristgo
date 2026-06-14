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

// reversedConfig is fastConfig plus a profile selector and a short keepalive so
// the caller-receiver's announce ↔ listener-sender learn handshake settles
// quickly in the test.
func reversedConfig(profile ristgo.Profile) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = profile
	cfg.BufferMin = 100 * time.Millisecond
	cfg.BufferMax = 100 * time.Millisecond
	cfg.KeepaliveInterval = 200 * time.Millisecond
	return cfg
}

type reversedResult struct {
	hash [32]byte
	n    int
	err  error
}

// runReversedLoopback drives a full reversed-role flow over real UDP loopback: a
// listener-sender binds the well-known port and a caller-receiver dials it,
// announcing itself so the sender learns its return address and streams. The
// received bytes are verified bit-identical via SHA-256, exercising the announce
// handshake, the Simple even/odd media-address inference, packetization, sockets,
// the event loop, and in-order playout in the reversed direction.
func runReversedLoopback(t *testing.T, profile ristgo.Profile, secret string) {
	t.Helper()
	const totalBytes = 256 * 1024
	const chunk = 1316

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := reversedConfig(profile)
	cfg.Secret = secret

	// The listener-sender binds the port first so it is reading when the
	// caller-receiver's first Receiver Report arrives.
	tx, err := ristgo.NewListenerSender(addr, cfg)
	if err != nil {
		t.Fatalf("NewListenerSender: %v", err)
	}
	defer tx.Close()

	rx, err := ristgo.NewReceiverCaller(addr, cfg)
	if err != nil {
		t.Fatalf("NewReceiverCaller: %v", err)
	}
	defer rx.Close()

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

	// Let the caller-receiver announce and the listener-sender learn its address
	// before streaming. The sender holds media until peer.Media is known, so
	// writing before the handshake would burn sequence numbers and leave a gap;
	// waiting keeps the stream bit-identical from the first byte.
	time.Sleep(300 * time.Millisecond)

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
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for the reversed stream")
	}

	if st := rx.Stats(); st.Delivered == 0 {
		t.Fatalf("receiver delivered 0 packets")
	}
}

// TestReversedLoopbackSimple verifies caller-receive ↔ listener-send on the
// Simple profile, including the even/odd media-address inference the sender uses
// to find the dialing receiver's media port.
func TestReversedLoopbackSimple(t *testing.T) {
	runReversedLoopback(t, ristgo.ProfileSimple, "")
}

// TestReversedLoopbackMain verifies the reversed flow on the Main profile
// (single GRE socket, peer learned from inbound traffic).
func TestReversedLoopbackMain(t *testing.T) {
	runReversedLoopback(t, ristgo.ProfileMain, "")
}

// TestReversedLoopbackMainPSK verifies the reversed flow on the Main profile
// with PSK payload encryption — the keys derive from the shared passphrase, so
// the reversed handshake direction does not affect them.
func TestReversedLoopbackMainPSK(t *testing.T) {
	runReversedLoopback(t, ristgo.ProfileMain, "reversed-secret")
}

// TestReversedLoopbackAdvanced verifies the reversed flow on the Advanced
// profile (single socket, native control).
func TestReversedLoopbackAdvanced(t *testing.T) {
	runReversedLoopback(t, ristgo.ProfileAdvanced, "")
}

// TestReversedCloseNoLeak verifies that a caller-receiver and a listener-sender
// shut down cleanly: Close unblocks a pending Read with io.EOF and every
// goroutine the new constructors start (the session loop, reader goroutines, and
// the context watcher) exits, returning the goroutine count to baseline.
func TestReversedCloseNoLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	tx, err := ristgo.NewListenerSender(addr, reversedConfig(ristgo.ProfileSimple))
	if err != nil {
		t.Fatalf("NewListenerSender: %v", err)
	}
	rx, err := ristgo.NewReceiverCaller(addr, reversedConfig(ristgo.ProfileSimple))
	if err != nil {
		tx.Close()
		t.Fatalf("NewReceiverCaller: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, e := rx.Read(buf) // blocks: no media yet
		readErr <- e
	}()

	time.Sleep(50 * time.Millisecond)
	if err := rx.Close(); err != nil {
		t.Fatalf("rx.Close: %v", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("tx.Close: %v", err)
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

// TestReversedConstructorErrors covers the reversed constructors' input
// validation: the as-yet-unsupported DTLS and EAP-SRP options are rejected, and
// the Simple profile still requires an even media port.
func TestReversedConstructorErrors(t *testing.T) {
	dtls := ristgo.DefaultConfig()
	dtls.Profile = ristgo.ProfileMain
	dtls.DTLS = &ristgo.DTLSConfig{PSK: []byte("k")}

	eap := ristgo.DefaultConfig()
	eap.Profile = ristgo.ProfileMain
	eap.Username, eap.Password = "u", "p"

	oddSimple := ristgo.DefaultConfig() // Simple profile, odd port below

	cases := []struct {
		name string
		fn   func() error
	}{
		{"caller dtls", func() error { _, e := ristgo.NewReceiverCaller("127.0.0.1:5000", dtls); return e }},
		{"listener dtls", func() error { _, e := ristgo.NewListenerSender("127.0.0.1:5000", dtls); return e }},
		{"caller eap", func() error { _, e := ristgo.NewReceiverCaller("127.0.0.1:5000", eap); return e }},
		{"listener eap", func() error { _, e := ristgo.NewListenerSender("127.0.0.1:5000", eap); return e }},
		{"caller odd port", func() error { _, e := ristgo.NewReceiverCaller("127.0.0.1:5001", oddSimple); return e }},
		{"listener odd port", func() error { _, e := ristgo.NewListenerSender("127.0.0.1:5001", oddSimple); return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatalf("%s: expected an error, got nil", tc.name)
			}
		})
	}
}

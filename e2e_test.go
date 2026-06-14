package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// freeEvenPort finds a free even UDP port (with port+1 also free) on the
// loopback interface for the Simple-profile media/RTCP pair. There is a small
// TOCTOU window between probing and the real bind; the retry loop tolerates it.
func freeEvenPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			continue
		}
		p := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		if p%2 != 0 {
			p--
		}
		if p <= 0 {
			continue
		}
		c1, e1 := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if e1 != nil {
			continue
		}
		c2, e2 := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p + 1})
		c1.Close()
		if e2 != nil {
			continue
		}
		c2.Close()
		return p
	}
	t.Fatal("no free even port pair found")
	return 0
}

// fastConfig shrinks the recovery buffer so playout latency is ~100ms rather
// than the 1s default, keeping the e2e tests quick.
func fastConfig() ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.BufferMin = 100 * time.Millisecond
	cfg.BufferMax = 100 * time.Millisecond
	return cfg
}

// TestE2ELoopbackIntegrity sends a multi-hundred-KB stream sender->receiver
// over real UDP loopback and verifies the received bytes are bit-identical via
// SHA-256 — exercising the full host stack: packetization, sockets, the event
// loop, real timers, and in-order playout.
func TestE2ELoopbackIntegrity(t *testing.T) {
	const totalBytes = 256 * 1024
	const chunk = 1316 // a typical 7-cell MPEG-TS RTP payload

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	rx, err := ristgo.NewReceiver(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	tx, err := ristgo.NewSender(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wantHash := sha256.Sum256(payload)

	// Receive concurrently.
	type result struct {
		hash [32]byte
		n    int
		err  error
	}
	done := make(chan result, 1)
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
				done <- result{n: len(got), err: err}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- result{hash: sum, n: len(got)}
	}()

	// Send paced so the receiver's buffer and the event loop keep up.
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
			time.Sleep(time.Millisecond) // ~light pacing
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
		t.Fatal("timed out waiting for the stream")
	}

	if st := rx.Stats(); st.Delivered == 0 {
		t.Fatalf("receiver delivered 0 packets")
	}
}

// TestE2ECloseUnblocksRead verifies Close wakes a blocked Read with ErrClosed
// and that the receiver's goroutines exit (the goroutine count returns to the
// pre-construction baseline). Run under -race for data-race coverage too.
func TestE2ECloseUnblocksRead(t *testing.T) {
	baseline := runtime.NumGoroutine()

	port := freeEvenPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	rx, err := ristgo.NewReceiver(addr, fastConfig())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, err := rx.Read(buf) // blocks: no sender
		readErr <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := rx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readErr:
		if err != io.EOF {
			t.Fatalf("Read after Close = %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
	// Read after a clean close stays at io.EOF.
	if _, err := rx.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("Read on closed receiver = %v, want io.EOF", err)
	}

	// The session's loop + reader goroutines should have exited. Allow a brief
	// settle and a small slack for runtime/test goroutines.
	for i := 0; i < 20; i++ {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutines did not return to baseline: have %d, baseline %d", runtime.NumGoroutine(), baseline)
}

// Ensure the Sender/Receiver satisfy the standard io interfaces.
var (
	_ io.WriteCloser = (*ristgo.Sender)(nil)
	_ io.ReadCloser  = (*ristgo.Receiver)(nil)
)

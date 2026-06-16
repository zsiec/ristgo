package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2EMainEAPSRPListenerSender exercises EAP-SRP in the listener-sender ↔
// caller-receiver topology (the mirror of the common push model): the listening SENDER
// is the authenticatee and the calling RECEIVER is the authenticator. The listener
// cannot speak until it learns the caller, so it defers its EAPOL-Start until the
// caller announces itself; the handshake then completes and use_key_as_passphrase media
// (keyed from the SRP session key K) is delivered byte-exact.
func TestE2EMainEAPSRPListenerSender(t *testing.T) {
	const totalBytes = 64 * 1024
	const chunk = 1316
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	// The listener sender (authenticatee) binds first; the caller receiver (authenticator)
	// dials it and announces, which is what lets the listener learn the peer and Start.
	tx, err := ristgo.NewListenerSender(addr, srpNoSecretConfig("rist", "mainprofile"))
	if err != nil {
		t.Fatalf("NewListenerSender: %v", err)
	}
	defer tx.Close()
	rx, err := ristgo.NewReceiverCaller(addr, srpNoSecretConfig("rist", "mainprofile"))
	if err != nil {
		t.Fatalf("NewReceiverCaller: %v", err)
	}
	defer rx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(15 * time.Second))
		got := make([]byte, 0, totalBytes)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < totalBytes {
			n, rerr := rx.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				got = append(got, buf[:n]...)
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

	tx.SetWriteDeadline(time.Now().Add(15 * time.Second))
	go func() {
		for off := 0; off < totalBytes; off += chunk {
			end := off + chunk
			if end > totalBytes {
				end = totalBytes
			}
			if _, werr := tx.Write(payload[off:end]); werr != nil {
				return
			}
			if off%(chunk*16) == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("listener-sender SRP delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("timed out on the listener-sender SRP stream (authenticated=%v)", rx.Authenticated())
	}
	if !rx.Authenticated() {
		t.Fatal("receiver reports not authenticated after a complete delivery")
	}
}

// TestE2EMainEAPSRPListenerSenderWrongPassword verifies the authenticator role works on
// the calling RECEIVER: a listening SENDER (authenticatee) with the wrong password fails
// the handshake, so the data channel never opens and the receiver surfaces ErrAuth (or
// the deadline fires while the FAILURE is still in flight) rather than delivering media.
func TestE2EMainEAPSRPListenerSenderWrongPassword(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	tx, err := ristgo.NewListenerSender(addr, srpNoSecretConfig("rist", "WRONG-password"))
	if err != nil {
		t.Fatalf("NewListenerSender: %v", err)
	}
	defer tx.Close()
	rx, err := ristgo.NewReceiverCaller(addr, srpNoSecretConfig("rist", "mainprofile"))
	if err != nil {
		t.Fatalf("NewReceiverCaller: %v", err)
	}
	defer rx.Close()

	go func() {
		tx.SetWriteDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1316)
		for i := 0; i < 64; i++ {
			if _, err := tx.Write(buf); err != nil {
				return
			}
		}
	}()

	rx.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := rx.Read(make([]byte, 4096))
	if n != 0 {
		t.Fatalf("delivered %d bytes despite failed authentication", n)
	}
	if err == nil {
		t.Fatal("Read returned nil error despite failed authentication")
	}
	if !errors.Is(err, ristgo.ErrAuth) && !errors.Is(err, ristgo.ErrTimeout) {
		t.Fatalf("Read error = %v, want ErrAuth or ErrTimeout", err)
	}
}

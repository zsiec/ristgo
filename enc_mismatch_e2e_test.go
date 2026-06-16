package ristgo_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2EMainEncryptedToCleartextRejected verifies the fail-closed direction of a
// Main-profile encryption mismatch: an encrypted sender (PSK, K bit set on every
// datagram) streaming to a receiver configured with NO secret delivers nothing.
// The receiver keys per-packet on the GRE K bit and has no decryptor, so every
// encrypted datagram is dropped (decodeMain errors with "encrypted datagram but
// no decryptor configured") and Read never returns media — the analog of
// libRIST's encrypted-vs-cleartext should_fail send_receive cases.
//
// NOTE: only this direction is a hard failure. The reverse (a cleartext sender
// into a keyed receiver) is accepted by design — the per-packet K bit lets a peer
// mix cleartext and encrypted datagrams, which the EAP-SRP use_key_as_passphrase
// mode relies on — so it is intentionally not asserted here. And because GRE PSK
// is AES-CTR (no authentication tag), a wrong-secret decrypt yields garbage
// rather than a clean rejection, so that is not a reliable negative either; the
// decisive, well-defined failure is encrypted-into-keyless.
func TestE2EMainEncryptedToCleartextRejected(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	// Receiver: Main profile, no secret => no decryptor.
	rx, err := ristgo.NewReceiver(addr, mainConfig("", 0))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	// Sender: Main profile, PSK AES-128 => every media datagram is encrypted.
	tx, err := ristgo.NewSender(addr, mainConfig("ristgo-enc-mismatch", 128))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	// Push media; with no decryptor on the receiver, nothing should be delivered.
	go func() {
		tx.SetWriteDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1316)
		for i := 0; i < 128; i++ {
			if _, werr := tx.Write(buf); werr != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	rx.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, rerr := rx.Read(make([]byte, 4096))
	if n != 0 {
		t.Fatalf("delivered %d bytes across an encryption mismatch (encrypted sender, keyless receiver)", n)
	}
	if rerr == nil {
		t.Fatal("Read returned nil error despite delivering nothing")
	}
	// The receiver drops every undecryptable datagram, so Read hits its deadline
	// (ErrTimeout); a session-timeout teardown (ErrClosed) is equally valid proof
	// the media path never opened.
	if !errors.Is(rerr, ristgo.ErrTimeout) && !errors.Is(rerr, ristgo.ErrClosed) {
		t.Fatalf("Read error = %v, want ErrTimeout or ErrClosed", rerr)
	}
}

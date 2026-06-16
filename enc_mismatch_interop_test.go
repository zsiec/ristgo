//go:build interop

// Negative Main-profile interop tests: a peer that cannot decrypt or authenticate
// must deliver nothing. These mirror libRIST's encrypted-vs-cleartext and SRP
// mismatch should_fail send_receive cases, proving ristgo fails closed against
// the real libRIST tools in both roles. They assert the stream does NOT get
// through (the inverse of the positive interop tests' byte-exact assertion). See
// interop_test.go / main_interop_test.go for the shared helpers reused here.
package ristgo_test

import (
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// negCaptureWindow is how long a negative interop test watches a libRIST
// receiver's UDP output before concluding nothing got through.
const negCaptureWindow = 4 * time.Second

// TestInteropMainEncMismatchGoRxFromLibristTx: libRIST ristsender (Main, PSK
// AES-128) -> ristgo Main Receiver configured with NO secret. ristgo keys
// per-packet on the GRE K bit and has no decryptor, so every encrypted datagram
// is dropped and nothing is delivered.
func TestInteropMainEncMismatchGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	feedPort := freeUDPPort(t, goPort)

	// Receiver: Main, no secret => no decryptor.
	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), npdMainCleartextConfig())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	// Sender: Main with a PSK the receiver does not share.
	spawnTool(t, sender, "-p", "1", "-s", mainInteropSecret, "-e", "128", "-b", "300",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
	waitToolReady(t, feedPort, 5*time.Second)
	go feedUDP(t, feedPort, make([]byte, interopChunk*interopN))

	rx.SetReadDeadline(time.Now().Add(negCaptureWindow))
	n, _ := rx.Read(make([]byte, 4096))
	if n != 0 {
		t.Fatalf("ristgo delivered %d bytes from a libRIST sender it shares no key with", n)
	}
}

// TestInteropMainEncMismatchLibristRxFromGoTx: ristgo Main Sender (PSK AES-128)
// -> libRIST ristreceiver configured with NO secret. libRIST cannot decrypt
// ristgo's encrypted GRE, so its UDP output stays empty.
func TestInteropMainEncMismatchLibristRxFromGoTx(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	rxPort := freeMainPort(t)
	capPort := freeUDPPort(t, rxPort)

	// libRIST receiver with NO -s secret.
	capt := newUDPCapture(t, capPort, interopN*interopChunk)
	spawnTool(t, receiver, "-p", "1", "-b", "300",
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	waitToolReady(t, rxPort, 5*time.Second)

	// ristgo sender WITH a PSK libRIST does not share.
	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), mainInteropConfig(128))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()
	tx.SetWriteDeadline(time.Now().Add(negCaptureWindow))
	go func() {
		buf := make([]byte, interopChunk)
		for i := 0; i < interopN; i++ {
			if _, werr := tx.Write(buf); werr != nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	got := capt.wait(negCaptureWindow)
	// Nothing decryptable should reach libRIST's UDP output; tolerate less than a
	// single media packet against any stray, but the ~256KB stream must not flow.
	if len(got) >= interopChunk {
		t.Fatalf("libRIST output %d bytes from a ristgo sender it shares no key with", len(got))
	}
}

// TestInteropMainSRPWrongPasswordRejected: ristgo Main Sender (EAP-SRP, WRONG
// password) -> libRIST ristreceiver acting as the SRP authenticator with a
// correct srpfile. The handshake fails, libRIST never opens its data channel, and
// its UDP output stays empty — the sender's own auth gate also withholds media.
func TestInteropMainSRPWrongPasswordRejected(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	srpfile := makeSRPFile(t) // provisions the correct "rist"/"mainprofile" verifier
	rxPort := freeMainPort(t)
	capPort := freeUDPPort(t, rxPort)

	capt := newUDPCapture(t, capPort, interopN*interopChunk)
	spawnTool(t, receiver, "-p", "1", "-b", "1000", "-F", srpfile,
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	waitToolReady(t, rxPort, 5*time.Second)

	cfg := srpUseKeyConfig()
	cfg.Password = "WRONG-password" // mismatches the srpfile verifier
	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()
	tx.SetWriteDeadline(time.Now().Add(negCaptureWindow + 2*time.Second))
	go func() {
		buf := make([]byte, interopChunk)
		for i := 0; i < interopN; i++ {
			if _, werr := tx.Write(buf); werr != nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	got := capt.wait(negCaptureWindow)
	if len(got) >= interopChunk {
		t.Fatalf("libRIST output %d bytes despite a wrong SRP password", len(got))
	}
}

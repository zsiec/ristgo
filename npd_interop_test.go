//go:build interop

// Main-profile null-packet-deletion (TR-06-2 §8.3) interop tests against the
// libRIST reference CLI tools. libRIST enables NPD on the sender with -n
// (--null-packet-deletion) and always expands on the receiver, so these prove
// ristgo's suppress (Config.NullPacketDeletion) and expand paths interoperate
// byte-exact with libRIST in both directions. The payload is built from canonical
// null packets (canonicalNullTS) so the reconstructed nulls match byte-for-byte —
// NPD reconstruction is canonical, not byte-preserving, in both implementations.
// See npd_e2e_test.go for the TS-payload builders, which this file reuses.
package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// npdInteropFrames is the number of 1316-byte (7-TS-packet) frames the NPD
// interop streams carry; 6 of every 7 packets are null, so this exercises a long
// run of suppression/expansion across the wire.
const npdInteropFrames = 128

// npdMainCleartextConfig is a cleartext Main-profile config with a 300ms buffer,
// sized for the libRIST tools' startup. NPD is orthogonal to encryption, so these
// interop tests run cleartext to isolate the suppress/expand behavior (the e2e
// suite proves NPD+PSK composition).
func npdMainCleartextConfig() ristgo.Config {
	cfg := mainConfig("", 0)
	cfg.BufferMin = 300 * time.Millisecond
	cfg.BufferMax = 300 * time.Millisecond
	return cfg
}

// TestInteropMainNPDGoRxFromLibristTx: libRIST ristsender (-p 1 -n) -> ristgo
// Main Receiver. Proves ristgo expands libRIST's NPD-suppressed payload back to
// the exact original TS frames (canonical nulls reinserted at the bitmap
// positions libRIST signalled in the RIST RTP extension).
func TestInteropMainNPDGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	feedPort := freeUDPPort(t, goPort)

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), npdMainCleartextConfig())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	// -n enables NPD on libRIST's sender; -p 1 is the Main profile.
	spawnTool(t, sender, "-p", "1", "-n", "-b", "300",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
	waitToolReady(t, feedPort, 5*time.Second)

	payload := buildTSWithNulls(npdInteropFrames)
	want := sha256.Sum256(payload)
	// feedUDP sends interopChunk(1316)-byte datagrams, and the payload is a whole
	// number of 1316-byte frames, so each datagram is exactly one 7-TS-packet
	// frame for libRIST to suppress.
	go feedUDP(t, feedPort, payload)

	got := readN(t, rx, len(payload))
	if len(got) != len(payload) || sha256.Sum256(got) != want {
		t.Fatalf("NPD GoRx: got %d/%d bytes, hash-exact=%v (delivered=%d lost=%d)",
			len(got), len(payload), sha256.Sum256(got) == want, rx.Stats().Delivered, rx.Stats().Lost)
	}
	t.Logf("NPD byte-exact: ristgo expanded %d frames of libRIST-suppressed TS", npdInteropFrames)
}

// TestInteropMainNPDLibristRxFromGoTx: ristgo Main Sender (NullPacketDeletion) ->
// libRIST ristreceiver. Proves libRIST expands ristgo's NPD-suppressed payload
// back to the exact original TS frames, i.e. ristgo's RIST RTP extension and
// suppress bitmap are byte-compatible with libRIST's expander.
func TestInteropMainNPDLibristRxFromGoTx(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	rxPort := freeMainPort(t)
	capPort := freeUDPPort(t, rxPort)

	payload := buildTSWithNulls(npdInteropFrames)
	want := sha256.Sum256(payload)

	capt := newUDPCapture(t, capPort, len(payload))
	spawnTool(t, receiver, "-p", "1", "-b", "300",
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	waitToolReady(t, rxPort, 5*time.Second)

	cfg := npdMainCleartextConfig()
	cfg.NullPacketDeletion = true
	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	const frameLen = 7 * 188
	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	go func() {
		for off := 0; off < len(payload); off += frameLen {
			tx.Write(payload[off : off+frameLen])
			if (off/frameLen)%16 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	got := capt.wait(20 * time.Second)
	if len(got) < len(payload) {
		t.Fatalf("NPD LibristRx: libRIST output %d/%d bytes", len(got), len(payload))
	}
	if sha256.Sum256(got[:len(payload)]) != want {
		t.Fatalf("NPD LibristRx: byte mismatch — libRIST did not reconstruct ristgo's suppressed TS")
	}
	t.Logf("NPD byte-exact: libRIST expanded %d frames of ristgo-suppressed TS", npdInteropFrames)
}

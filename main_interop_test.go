//go:build interop

// Main-profile (VSF TR-06-2) PSK interop tests against the libRIST reference
// CLI tools. These run only under -tags interop and t.Skip when the tools are
// absent (see interop_test.go for the tool discovery and helpers, which this
// file reuses). They prove the GRE-over-UDP + PSK AES-CTR wire format
// interoperates byte-exactly with libRIST in both directions, at AES-128 and
// AES-256.
package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// mainInteropSecret is the shared PSK passphrase for the Main interop tests.
const mainInteropSecret = "ristgo-interop-secret"

// mainInteropConfig is a fast Main-profile config with the given AES key size
// and the shared interop secret.
func mainInteropConfig(aesBits int) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileMain
	cfg.BufferMin = 200 * time.Millisecond
	cfg.BufferMax = 200 * time.Millisecond
	cfg.Secret = mainInteropSecret
	cfg.AESKeyBits = aesBits
	return cfg
}

// TestInteropMainGoRxFromLibristTx: libRIST ristsender (Main, PSK) -> ristgo
// Receiver. Proves ristgo decrypts and decodes libRIST's GRE+PSK Main-profile
// output byte-exactly, at AES-128 and AES-256.
func TestInteropMainGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	for _, bits := range []int{128, 256} {
		t.Run(fmt.Sprintf("aes%d", bits), func(t *testing.T) {
			goPort := freeMainPort(t)
			feedPort := freeUDPPort(t, goPort)

			rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), mainInteropConfig(bits))
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()

			spawnTool(t, sender, "-p", "1", "-s", mainInteropSecret, "-e", strconv.Itoa(bits), "-b", "200",
				"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
				"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
			waitToolReady(t, feedPort, 5*time.Second)

			data, want := randomData(t, interopN)
			go feedUDP(t, feedPort, data)

			got := readN(t, rx, len(data))
			if len(got) != len(data) {
				t.Fatalf("Main aes%d: received %d/%d bytes (recovered=%d lost=%d)",
					bits, len(got), len(data), rx.Stats().Recovered, rx.Stats().Lost)
			}
			if sha256.Sum256(got) != want {
				t.Fatalf("Main aes%d: byte mismatch from libRIST sender", bits)
			}
		})
	}
}

// TestInteropMainLibristRxFromGoTx: ristgo Sender (Main, PSK) -> libRIST
// ristreceiver. Proves libRIST decrypts and decodes ristgo's GRE+PSK
// Main-profile output byte-exactly, at AES-128 and AES-256.
func TestInteropMainLibristRxFromGoTx(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	for _, bits := range []int{128, 256} {
		t.Run(fmt.Sprintf("aes%d", bits), func(t *testing.T) {
			rxPort := freeMainPort(t)
			capPort := freeUDPPort(t, rxPort)

			capt := newUDPCapture(t, capPort, interopN*interopChunk)
			spawnTool(t, receiver, "-p", "1", "-s", mainInteropSecret, "-e", strconv.Itoa(bits), "-b", "200",
				"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
				"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
			waitToolReady(t, rxPort, 5*time.Second)

			tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), mainInteropConfig(bits))
			if err != nil {
				t.Fatalf("NewSender: %v", err)
			}
			defer tx.Close()

			data, want := randomData(t, interopN)
			tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
			go func() {
				for off := 0; off < len(data); off += interopChunk {
					tx.Write(data[off : off+interopChunk])
					if (off/interopChunk)%8 == 0 {
						time.Sleep(time.Millisecond)
					}
				}
			}()

			got := capt.wait(20 * time.Second)
			if len(got) != len(data) {
				t.Fatalf("Main aes%d: libRIST received %d bytes, want %d (Retransmitted=%d)",
					bits, len(got), len(data), tx.Stats().Retransmitted)
			}
			if sha256.Sum256(got[:len(data)]) != want {
				t.Fatalf("Main aes%d: byte mismatch at libRIST receiver", bits)
			}
		})
	}
}

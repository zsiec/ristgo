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
	"os"
	"os/exec"
	"path/filepath"
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

// mainSRPConfig is a Main-profile config with PSK AES-256 plus EAP-SRP
// credentials. The shared secret keys the data channel; SRP gates it. This is the
// combined PSK+SRP mode (distinct from the use_key_as_passphrase mode, which keys
// the data channel from the SRP session key when no secret is configured — see
// srpUseKeyConfig and TestInteropMainSRPUseKey*).
func mainSRPConfig() ristgo.Config {
	cfg := mainInteropConfig(256)
	cfg.Username = "rist"
	cfg.Password = "mainprofile"
	return cfg
}

// TestInteropMainSRPHandshake: libRIST ristsender (Main, SRP client) -> ristgo
// Receiver acting as the EAP-SRP authenticator. Proves ristgo's EAP-SRP
// handshake — the EAPOL/EAP/SRP framing AND the SRP-6a math — interoperates
// byte-for-byte with libRIST: libRIST's client authenticates through ristgo's
// full handshake (START, IDENTITY, CHALLENGE, CLIENT-KEY, SERVER-KEY,
// CLIENT-VALIDATOR, SERVER-VALIDATOR, SUCCESS) and ristgo's data channel opens.
// This runs in the combined PSK+SRP mode (a shared secret keys the channel); the
// use_key_as_passphrase mode (no secret, key from K) and its post-SRP media flow
// are proven byte-exact by TestInteropMainSRPUseKeyGoRxFromLibristTx and its
// reverse.
func TestInteropMainSRPHandshake(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	feedPort := freeUDPPort(t, goPort)

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), mainSRPConfig())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	// libRIST client carries username/password in the rist:// URL; the shared
	// secret + aes-type come from -s/-e.
	spawnTool(t, sender, "-p", "1", "-s", mainInteropSecret, "-e", "256", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d?username=rist&password=mainprofile", goPort))
	waitToolReady(t, feedPort, 5*time.Second)
	go feedUDP(t, feedPort, make([]byte, interopChunk*interopN))

	// The EAP-SRP handshake must complete: ristgo (the authenticator) verifies
	// libRIST's client and opens its data channel.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if rx.Authenticated() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ristgo did not authenticate the libRIST SRP client within 8s")
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

// srpUseKeyConfig is a Main-profile config with EAP-SRP credentials and NO
// pre-shared Secret: libRIST's use_key_as_passphrase mode, where the media AES
// key is derived from the SRP session key K on a successful handshake (the
// receiver->sender feedback is encrypted under K; the sender->receiver media is
// sent in the clear, matching libRIST). 1000ms buffers match the libRIST default
// so a slow EAP handshake plus the data flow have headroom.
func srpUseKeyConfig() ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileMain
	cfg.BufferMin = 1000 * time.Millisecond
	cfg.BufferMax = 1000 * time.Millisecond
	cfg.Username = "rist"
	cfg.Password = "mainprofile"
	return cfg
}

// makeSRPFile provisions the SRP credential file libRIST's receiver needs in
// authenticator (srpfile) mode, via the ristsrppasswd tool. It returns the file
// path; the test t.Cleanup removes it. If ristsrppasswd is unavailable the test
// is skipped (CI-safe).
func makeSRPFile(t *testing.T) string {
	t.Helper()
	tool := libristTool(t, "ristsrppasswd") // skips if absent
	out, err := exec.Command(tool, "rist", "mainprofile").Output()
	if err != nil || len(out) == 0 {
		t.Skipf("ristsrppasswd failed (%v); skipping SRP-file interop", err)
	}
	path := filepath.Join(t.TempDir(), "srpfile.txt")
	if werr := os.WriteFile(path, out, 0o600); werr != nil {
		t.Fatalf("write srpfile: %v", werr)
	}
	return path
}

// waitAuth blocks until the receiver reports authenticated, or fails the test
// after timeout. Used by the use_key_as_passphrase interop tests to ensure the
// EAP-SRP handshake completes before media streaming begins.
func waitAuth(t *testing.T, rx *ristgo.Receiver, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rx.Authenticated() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("EAP-SRP handshake did not authenticate within the deadline")
}

// TestInteropMainSRPUseKeyGoRxFromLibristTx: libRIST ristsender (Main, SRP, NO -s
// secret => use_key_as_passphrase) -> ristgo Receiver (EAP-SRP authenticator).
// Proves ristgo authenticates libRIST's SRP client, keys the data channel from
// the SRP session key K, and delivers libRIST's cleartext media byte-exact. This
// is the post-SRP media interop the prior SRP test (PSK+secret) did not cover.
func TestInteropMainSRPUseKeyGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	feedPort := freeUDPPort(t, goPort)

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), srpUseKeyConfig())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	// libRIST sender: SRP credentials in the URL, NO -s secret and NO -e (so its
	// key_size stays 0 and the use_key_as_passphrase data key defaults to 256).
	spawnTool(t, sender, "-p", "1", "-b", "1000",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d?username=rist&password=mainprofile", goPort))
	waitToolReady(t, feedPort, 5*time.Second)

	// Wait for the EAP-SRP handshake to authenticate before streaming. libRIST's
	// sender gates media on authenticating our RTCP peer (via our SDES), and it
	// does not buffer pre-gate input, so feeding before the gate opens drops the
	// stream on the floor. Block until ristgo reports authenticated, then settle
	// briefly so libRIST has decoded our (K-encrypted) SDES and ungated media.
	waitAuth(t, rx, 8*time.Second)
	time.Sleep(750 * time.Millisecond)

	data, want := randomData(t, interopN)
	go feedUDP(t, feedPort, data)

	got := readN(t, rx, len(data))
	if len(got) != len(data) {
		t.Fatalf("SRP use_key_as_passphrase: received %d/%d bytes (authed=%v recovered=%d lost=%d)",
			len(got), len(data), rx.Authenticated(), rx.Stats().Recovered, rx.Stats().Lost)
	}
	if sha256.Sum256(got) != want {
		t.Fatalf("SRP use_key_as_passphrase: byte mismatch from libRIST sender")
	}
	if !rx.Authenticated() {
		t.Fatal("SRP use_key_as_passphrase: not authenticated after complete delivery")
	}
}

// TestInteropMainSRPUseKeyLibristRxFromGoTx: ristgo Sender (Main, SRP, no secret
// => use_key_as_passphrase) -> libRIST ristreceiver (EAP-SRP authenticator with a
// ristsrppasswd-provisioned srpfile). Proves libRIST authenticates ristgo's SRP
// client and decodes ristgo's cleartext media byte-exact, and that ristgo keys
// its RX from K to decrypt libRIST's encrypted feedback.
func TestInteropMainSRPUseKeyLibristRxFromGoTx(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	srpfile := makeSRPFile(t)
	rxPort := freeMainPort(t)
	capPort := freeUDPPort(t, rxPort)

	capt := newUDPCapture(t, capPort, interopN*interopChunk)
	spawnTool(t, receiver, "-p", "1", "-b", "1000", "-F", srpfile,
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	waitToolReady(t, rxPort, 5*time.Second)

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), srpUseKeyConfig())
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data, want := randomData(t, interopN)
	tx.SetWriteDeadline(time.Now().Add(25 * time.Second))
	// Give the EAP-SRP handshake time to complete before streaming (the sender
	// holds media until authenticated anyway, but pacing keeps the session warm).
	time.Sleep(1500 * time.Millisecond)
	go func() {
		for off := 0; off < len(data); off += interopChunk {
			tx.Write(data[off : off+interopChunk])
			if (off/interopChunk)%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	got := capt.wait(25 * time.Second)
	if len(got) < len(data) {
		t.Fatalf("SRP use_key_as_passphrase: libRIST received %d bytes, want %d (Retransmitted=%d)",
			len(got), len(data), tx.Stats().Retransmitted)
	}
	if sha256.Sum256(got[:len(data)]) != want {
		t.Fatalf("SRP use_key_as_passphrase: byte mismatch at libRIST receiver")
	}
}

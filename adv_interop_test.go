//go:build interop

// Advanced-profile (VSF TR-06-3) interop tests against the libRIST reference CLI
// tools (ristsender / ristreceiver, -p 2). These run only under -tags interop
// and t.Skip when the tools are absent (see interop_test.go for tool discovery
// and the shared helpers, which this file reuses). They prove ristgo's Advanced
// wire format — the RTP-based header, AES-CTR payload-only encryption, LZ4
// compression, and the native NACK control plane — interoperates with libRIST
// in both directions.
package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// advInteropSecret is the shared PSK passphrase for the Advanced interop tests.
const advInteropSecret = "ristgo-adv-interop-secret"

// advInteropConfig is a fast Advanced-profile config with the given AES key size
// (0 = cleartext) and optional LZ4 compression.
func advInteropConfig(aesBits int, compress bool) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileAdvanced
	cfg.BufferMin = 200 * time.Millisecond
	cfg.BufferMax = 200 * time.Millisecond
	if aesBits != 0 {
		cfg.Secret = advInteropSecret
		cfg.AESKeyBits = aesBits
	}
	cfg.Compression = compress
	return cfg
}

// advToolArgs builds the common libRIST -p 2 argument prefix (profile, buffer,
// and optional secret/encryption-type), excluding -i/-o.
func advToolArgs(aesBits int) []string {
	args := []string{"-p", "2", "-b", "200"}
	if aesBits != 0 {
		args = append(args, "-s", advInteropSecret, "-e", strconv.Itoa(aesBits))
	}
	return args
}

// advRistURL appends ?compression=1 to a rist:// URL when compression is on, so
// libRIST emits LZ4-compressed Advanced payloads.
func advRistURL(base string, compress bool) string {
	if compress {
		return base + "?compression=1"
	}
	return base
}

// TestInteropAdvGoRxFromLibristTx: libRIST ristsender (-p 2) -> ristgo Advanced
// Receiver. Proves ristgo decodes libRIST's Advanced-profile output — the
// RTP+ext header, AES-CTR payload, and (in the lz4 case) LZ4 compression —
// across cleartext, AES-128, AES-256, and AES-256+LZ4.
func TestInteropAdvGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	cases := []struct {
		name     string
		aesBits  int
		compress bool
	}{
		{"cleartext", 0, false},
		{"aes128", 128, false},
		{"aes256", 256, false},
		{"aes256+lz4", 256, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goPort := freeMainPort(t)
			feedPort := freeUDPPort(t, goPort)

			rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), advInteropConfig(tc.aesBits, tc.compress))
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()

			args := append(advToolArgs(tc.aesBits),
				"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
				"-o", advRistURL(fmt.Sprintf("rist://127.0.0.1:%d", goPort), tc.compress))
			spawnTool(t, sender, args...)
			waitToolReady(t, feedPort, 5*time.Second)

			data, want := randomData(t, interopN)
			go feedUDP(t, feedPort, data)

			got := readN(t, rx, len(data))
			if len(got) != len(data) {
				st := rx.Stats()
				t.Fatalf("Adv %s: received %d/%d bytes (Received=%d Delivered=%d Duplicates=%d recovered=%d lost=%d)",
					tc.name, len(got), len(data), st.Received, st.Delivered, st.Duplicates, st.Recovered, st.Lost)
			}
			if sha256.Sum256(got) != want {
				t.Fatalf("Adv %s: byte mismatch from libRIST sender", tc.name)
			}
		})
	}
}

// TestInteropAdvLibristRxFromGoTx: ristgo Advanced Sender -> libRIST
// ristreceiver (-p 2). Proves libRIST decodes ristgo's Advanced-profile output
// byte-exactly across cleartext, AES-128, AES-256, and AES-256+LZ4.
func TestInteropAdvLibristRxFromGoTx(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	cases := []struct {
		name     string
		aesBits  int
		compress bool
	}{
		{"cleartext", 0, false},
		{"aes128", 128, false},
		{"aes256", 256, false},
		{"aes256+lz4", 256, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rxPort := freeMainPort(t)
			capPort := freeUDPPort(t, rxPort)

			capt := newUDPCapture(t, capPort, interopN*interopChunk)
			args := append(advToolArgs(tc.aesBits),
				"-i", advRistURL(fmt.Sprintf("rist://@127.0.0.1:%d", rxPort), tc.compress),
				"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
			spawnTool(t, receiver, args...)
			waitToolReady(t, rxPort, 5*time.Second)

			tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), advInteropConfig(tc.aesBits, tc.compress))
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
			if len(got) < len(data) {
				t.Fatalf("Adv %s: libRIST received %d/%d bytes (Retransmitted=%d)",
					tc.name, len(got), len(data), tx.Stats().Retransmitted)
			}
			if sha256.Sum256(got[:len(data)]) != want {
				t.Fatalf("Adv %s: byte mismatch at libRIST receiver", tc.name)
			}
		})
	}
}

// TestInteropAdvGoRxLossyRecovery: libRIST ristsender (-p 2) -> lossy proxy ->
// ristgo Advanced Receiver. Proves the native Advanced NACK control plane
// interoperates: ristgo's range NACKs drive libRIST's retransmits (R flag) and
// every dropped byte is recovered. Uses the profile-agnostic mainLossyProxy.
func TestInteropAdvGoRxLossyRecovery(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == goPort {
		proxyPort = freeMainPort(t)
	}
	feedPort := freeUDPPort(t, goPort, proxyPort)

	cfg := advInteropConfig(256, false)
	cfg.BufferMin = 700 * time.Millisecond
	cfg.BufferMax = 700 * time.Millisecond
	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startMainLossyProxy(t, proxyPort, goPort, 0.10, 11)
	defer proxy.Close()

	args := append(advToolArgs(256),
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", proxyPort))
	spawnTool(t, sender, args...)
	waitToolReady(t, feedPort, 5*time.Second)

	data, want := randomData(t, interopLossN)
	feed := append(append([]byte(nil), data...), make([]byte, 24*interopChunk)...)
	go feedUDP(t, feedPort, feed)

	got := readN(t, rx, len(data))
	if len(got) != len(data) || sha256.Sum256(got) != want {
		t.Fatalf("Adv lossy recovery failed: got %d/%d bytes (proxy dropped=%d recovered=%d lost=%d)",
			len(got), len(data), proxy.Dropped(), rx.Stats().Recovered, rx.Stats().Lost)
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped no media — the loss/ARQ path was not exercised")
	}
	t.Logf("byte-exact: proxy dropped %d Advanced datagrams, recovered %d via libRIST retransmits",
		proxy.Dropped(), rx.Stats().Recovered)
}

// TestInteropAdvLibristRxLossyRecovery: ristgo Advanced Sender -> lossy proxy ->
// libRIST ristreceiver (-p 2). Proves ristgo retransmits (R flag) on libRIST's
// native Advanced NACKs and libRIST recovers every byte.
func TestInteropAdvLibristRxLossyRecovery(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	rxPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == rxPort {
		proxyPort = freeMainPort(t)
	}
	capPort := freeUDPPort(t, rxPort, proxyPort)

	capt := newUDPCapture(t, capPort, interopLossN*interopChunk)
	args := append(advToolArgs(256),
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	spawnTool(t, receiver, args...)
	proxy := startMainLossyProxy(t, proxyPort, rxPort, 0.10, 13)
	defer proxy.Close()
	waitToolReady(t, rxPort, 5*time.Second)

	cfg := advInteropConfig(256, false)
	cfg.BufferMin = 700 * time.Millisecond
	cfg.BufferMax = 700 * time.Millisecond
	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data, want := randomData(t, interopLossN)
	tx.SetWriteDeadline(time.Now().Add(25 * time.Second))
	go func() {
		for off := 0; off < len(data); off += interopChunk {
			tx.Write(data[off : off+interopChunk])
			if (off/interopChunk)%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		flush := make([]byte, interopChunk)
		for i := 0; i < 24; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

	got := capt.wait(25 * time.Second)
	if len(got) < len(data) {
		t.Fatalf("libRIST received %d/%d Advanced bytes under loss (proxy dropped=%d Go retransmitted=%d)",
			len(got), len(data), proxy.Dropped(), tx.Stats().Retransmitted)
	}
	if sha256.Sum256(got[:len(data)]) != want {
		t.Fatalf("byte mismatch at libRIST Advanced receiver under loss")
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped no media — the loss/ARQ path was not exercised")
	}
	if tx.Stats().Retransmitted == 0 {
		t.Fatal("Go sender never retransmitted — libRIST's Advanced NACK path was not exercised")
	}
	t.Logf("byte-exact: proxy dropped %d Advanced datagrams, libRIST recovered via %d ristgo retransmits",
		proxy.Dropped(), tx.Stats().Retransmitted)
}

//go:build interop

// Reversed-role interop against the libRIST reference CLI tools: a libRIST
// sender in LISTEN mode (rist://@:port) feeding a ristgo caller-receiver, and a
// ristgo listener-sender feeding a libRIST receiver in CALLER mode
// (rist://host:port, no @). Together they prove ristgo's reversed announce
// handshake is wire-compatible with libRIST in both directions.
//
// Only the Main and Advanced profiles are covered. They carry everything over a
// single UDP port, so the listener-sender learns the caller's address directly
// from its inbound control traffic. The Simple profile is intentionally omitted:
// its reversed roles are broken in the pinned libRIST build (v0.2.18-rc1-30) —
// `ristsender -o rist://@:port` (Simple) fails to bind its socket, and a Simple
// `ristreceiver` caller addresses its RTCP to local_port+1 instead of the
// sender's port, so no path forms. ristgo's Simple reversed roles are covered
// ristgo↔ristgo in reversed_e2e_test.go.
//
//	go test -tags interop -run TestInteropReversed -v -count=1 -timeout 5m
package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

func reversedInteropCfg(profile ristgo.Profile) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = profile
	cfg.BufferMin = 200 * time.Millisecond
	cfg.BufferMax = 200 * time.Millisecond
	cfg.KeepaliveInterval = 200 * time.Millisecond
	return cfg
}

var reversedInteropProfiles = []struct {
	name string
	prof ristgo.Profile
	flag string // libRIST -p value
}{
	{"main", ristgo.ProfileMain, "1"},
	{"advanced", ristgo.ProfileAdvanced, "2"},
}

// TestInteropReversedGoCallerFromLibristListener: libRIST sender in LISTEN mode
// -> ristgo caller-receiver. Proves a ristgo receiver that dials and announces is
// recognized by a libRIST listening sender, which then streams bytes ristgo
// decodes exactly.
func TestInteropReversedGoCallerFromLibristListener(t *testing.T) {
	for _, p := range reversedInteropProfiles {
		t.Run(p.name, func(t *testing.T) {
			sender := libristTool(t, "ristsender")
			ristPort := freeEvenPort(t)
			feedPort := freeUDPPort(t, ristPort, ristPort+1)

			spawnTool(t, sender, "-p", p.flag, "-b", "200",
				"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
				"-o", fmt.Sprintf("rist://@127.0.0.1:%d", ristPort))
			// Wait only on the UDP input port: probing the RIST listen port would
			// race libRIST's own bind of it.
			waitToolReady(t, feedPort, 5*time.Second)

			rx, err := ristgo.NewReceiverCaller(fmt.Sprintf("127.0.0.1:%d", ristPort), reversedInteropCfg(p.prof))
			if err != nil {
				t.Fatalf("NewReceiverCaller: %v", err)
			}
			defer rx.Close()

			data, want := randomData(t, interopN)
			// Let the caller announce and libRIST learn it before feeding.
			time.Sleep(600 * time.Millisecond)
			go feedUDP(t, feedPort, data)

			got := readN(t, rx, len(data))
			if len(got) != len(data) {
				t.Fatalf("received %d/%d bytes (recovered=%d lost=%d)", len(got), len(data), rx.Stats().Recovered, rx.Stats().Lost)
			}
			if sha256.Sum256(got) != want {
				t.Fatalf("byte mismatch from libRIST listening sender")
			}
		})
	}
}

// TestInteropReversedLibristCallerFromGoListener: ristgo listener-sender ->
// libRIST receiver in CALLER mode. Proves ristgo's listener-sender, which learns
// the receiver from its inbound control traffic, is recognized by a libRIST
// caller-receiver, which decodes the stream exactly.
func TestInteropReversedLibristCallerFromGoListener(t *testing.T) {
	for _, p := range reversedInteropProfiles {
		t.Run(p.name, func(t *testing.T) {
			receiver := libristTool(t, "ristreceiver")
			ristPort := freeEvenPort(t)
			capPort := freeUDPPort(t, ristPort, ristPort+1)

			tx, err := ristgo.NewListenerSender(fmt.Sprintf("127.0.0.1:%d", ristPort), reversedInteropCfg(p.prof))
			if err != nil {
				t.Fatalf("NewListenerSender: %v", err)
			}
			defer tx.Close()

			capt := newUDPCapture(t, capPort, interopN*interopChunk)
			spawnTool(t, receiver, "-p", p.flag, "-b", "200",
				"-i", fmt.Sprintf("rist://127.0.0.1:%d", ristPort),
				"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))

			data, want := randomData(t, interopN)
			// Let libRIST dial and announce, and ristgo learn it, before streaming.
			time.Sleep(1 * time.Second)
			tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
			go func() {
				for off := 0; off < len(data); off += interopChunk {
					end := off + interopChunk
					if end > len(data) {
						end = len(data)
					}
					tx.Write(data[off:end])
					if (off/interopChunk)%8 == 0 {
						time.Sleep(time.Millisecond)
					}
				}
			}()

			got := capt.wait(20 * time.Second)
			if len(got) != len(data) {
				t.Fatalf("libRIST caller received %d bytes, want exactly %d", len(got), len(data))
			}
			if sha256.Sum256(got) != want {
				t.Fatalf("byte mismatch at libRIST caller-receiver")
			}
		})
	}
}

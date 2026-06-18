package ristgo_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// bondedEAPConfig is a Main-profile bonded config in the combined PSK+SRP mode (a Secret
// plus SRP credentials): each path authenticates with EAP-SRP before its media flows.
func bondedEAPConfig() ristgo.Config {
	c := ristgo.DefaultConfig()
	c.Profile = ristgo.ProfileMain
	c.Secret = "bond-psk"
	c.Username = "rist"
	c.Password = "bondpw"
	c.BufferMin = 300 * time.Millisecond
	c.BufferMax = 300 * time.Millisecond
	return c
}

// TestE2EBondedEAPSRP verifies bonded EAP-SRP end to end: a two-path bonded sender and
// receiver run a per-path handshake (combined PSK+SRP), each path's media is gated until
// it authenticates, then the deduplicated stream is delivered bit-exact. The receiver's
// connect callback fires with the authenticated username (the bonded connect gate).
func TestE2EBondedEAPSRP(t *testing.T) {
	pA := freeMainPort(t)
	pB := freeMainPort(t)
	for pB == pA {
		pB = freeMainPort(t)
	}
	addrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}

	var mu sync.Mutex
	var seenUser string
	recvCfg := bondedEAPConfig()
	recvCfg.OnConnect = func(info ristgo.ConnectInfo) bool {
		mu.Lock()
		seenUser = info.Username
		mu.Unlock()
		return true
	}

	rx, err := ristgo.NewBondedReceiver(addrs, recvCfg)
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewBondedSender(addrs, bondedEAPConfig())
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, 96*1024)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	want := sha256.Sum256(payload)

	const chunk = 1024
	var wg sync.WaitGroup
	var got [32]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		rx.SetReadDeadline(time.Now().Add(20 * time.Second))
		acc := make([]byte, 0, len(payload))
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(acc) < len(payload) {
			n, rerr := rx.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				acc = append(acc, buf[:n]...)
			}
			if rerr != nil {
				return
			}
		}
		copy(got[:], h.Sum(nil))
	}()

	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < len(payload); off += chunk {
		end := off + chunk
		if end > len(payload) {
			end = len(payload)
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if (off/chunk)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	flush := make([]byte, chunk)
	for i := 0; i < 24; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	if got != want {
		t.Fatalf("bonded EAP-SRP delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenUser != "rist" {
		t.Fatalf("bonded connect callback username = %q, want \"rist\"", seenUser)
	}
}

// TestBondedEAPRequiresSecret verifies pure-SRP bonding (SRP without a Secret) is
// rejected — bonded EAP-SRP is supported only in the combined PSK+SRP mode.
func TestBondedEAPRequiresSecret(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileMain
	cfg.Username = "rist"
	cfg.Password = "pw" // no Secret
	if _, err := ristgo.NewBondedReceiver([]string{addr}, cfg); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("pure-SRP bonded = %v, want ErrInvalidConfig", err)
	}
}

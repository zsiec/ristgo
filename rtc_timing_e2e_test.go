package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2ERTCTiming verifies RTC timing mode (libRIST RIST_TIMING_MODE_RTC) end to end:
// the sender stamps SourceTime from the NTP wall clock and the receiver paces playout by
// it (skipping the 32-bit source-clock wrap re-anchor), delivering bit-exact. Scheduling
// stays on the monotonic clock (no NTP-jump hazard).
func TestE2ERTCTiming(t *testing.T) {
	const totalBytes = 64 * 1024
	const chunk = 1316
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	cfg := mainConfig("", 0)
	cfg.TimingMode = ristgo.TimingRTC
	cfg.BufferMin = 250 * time.Millisecond
	cfg.BufferMax = 250 * time.Millisecond

	rx, err := ristgo.NewReceiver(addr, cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	want := sha256.Sum256(payload)

	var wg sync.WaitGroup
	var got [32]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		rx.SetReadDeadline(time.Now().Add(15 * time.Second))
		acc := make([]byte, 0, totalBytes)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(acc) < totalBytes {
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

	tx.SetWriteDeadline(time.Now().Add(15 * time.Second))
	for off := 0; off < totalBytes; off += chunk {
		end := off + chunk
		if end > totalBytes {
			end = totalBytes
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if off%(chunk*16) == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	wg.Wait()
	if got != want {
		t.Fatalf("RTC-timing delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
	}
}

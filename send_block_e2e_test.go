package ristgo_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2ESendBlockExplicitSeqAndTS submits Main-profile media with an app-chosen
// sequence number and source timestamp (Sender.SendBlock, libRIST USE_SEQ + ts_ntp)
// and verifies byte-exact delivery. This is the foundation a transparent reflector
// uses to preserve an upstream flow's (seq, sourceTime).
func TestE2ESendBlockExplicitSeqAndTS(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rx, err := ristgo.NewReceiver(addr, mainConfig("", 0))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, mainConfig("", 0))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	const frames = 30
	const frameLen = 188
	payload := make([]byte, frames*frameLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	want := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, 0, len(payload))
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < len(payload) {
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

	// A fixed app-chosen NTP-64 second anchor, advancing ~3 ms per frame in the
	// fractional low 32 bits so source-timed playout paces frames a few ms apart.
	base := uint64(2_500_000_000) << 32
	step := (uint64(1) << 32) / 1000 * 3
	tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < frames; i++ {
		seq := uint32(100_000 + i)
		st := base + uint64(i)*step
		if err := tx.SendBlock(payload[i*frameLen:(i+1)*frameLen], &seq, &st); err != nil {
			t.Fatalf("SendBlock %d: %v", i, err)
		}
		time.Sleep(3 * time.Millisecond)
	}

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("SendBlock delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("SendBlock stream timed out (delivered=%d)", rx.Stats().Delivered)
	}
}

// TestSendBlockRejectedOnNonMain checks that per-block submit is rejected on a Simple
// sender (the block channel is wired for the single-socket Main profile).
func TestSendBlockRejectedOnNonMain(t *testing.T) {
	tx, err := ristgo.NewSender("127.0.0.1:5000", ristgo.DefaultConfig()) // Simple
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()
	seq := uint32(1)
	if err := tx.SendBlock([]byte("x"), &seq, nil); !errors.Is(err, ristgo.ErrSendBlockUnsupported) {
		t.Fatalf("SendBlock on Simple = %v, want ErrSendBlockUnsupported", err)
	}
}

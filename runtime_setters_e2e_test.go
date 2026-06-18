package ristgo_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2ERuntimeSettersMainByteExact flips every runtime config setter
// (Receiver.SetNackType / SetRTTMultiplier, Sender.SetNullPacketDeletion — the
// libRIST rist_receiver_nack_type_set / rist_recovery_rtt_multiplier_set /
// rist_sender_npd_enable family) on a live Main-profile session and proves the
// stream keeps delivering byte-exact across the changes.
func TestE2ERuntimeSettersMainByteExact(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	rxCfg := mainConfig("", 0)
	// Windowed buffer so SetRTTMultiplier is eligible to act.
	rxCfg.BufferMin = 200 * time.Millisecond
	rxCfg.BufferMax = 1000 * time.Millisecond
	rx, err := ristgo.NewReceiver(addr, rxCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	tx, err := ristgo.NewSender(addr, mainConfig("", 0))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	// Flip every runtime knob before the stream really gets going.
	if err := rx.SetNackType(ristgo.NACKBitmask); err != nil {
		t.Fatalf("SetNackType: %v", err)
	}
	if err := rx.SetRTTMultiplier(3); err != nil {
		t.Fatalf("SetRTTMultiplier: %v", err)
	}
	if err := tx.SetNullPacketDeletion(true); err != nil {
		t.Fatalf("SetNullPacketDeletion: %v", err)
	}

	const frames = 40
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

	tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
	for off := 0; off < len(payload); off += frameLen {
		if _, werr := tx.Write(payload[off : off+frameLen]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		time.Sleep(3 * time.Millisecond)
		if off == len(payload)/2 {
			// A second runtime change mid-stream also lands.
			if err := tx.SetNullPacketDeletion(false); err != nil {
				t.Fatalf("disable NPD: %v", err)
			}
		}
	}

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("runtime-setter stream hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("runtime-setter stream timed out (delivered=%d)", rx.Stats().Delivered)
	}
}

// TestSetRTTMultiplierRejectsOutOfRange checks the [1, MaxRTTMultiplier] guard.
func TestSetRTTMultiplierRejectsOutOfRange(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rx, err := ristgo.NewReceiver(addr, mainConfig("", 0))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	if err := rx.SetRTTMultiplier(0); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("SetRTTMultiplier(0) = %v, want ErrInvalidConfig", err)
	}
	if err := rx.SetRTTMultiplier(ristgo.MaxRTTMultiplier + 1); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("SetRTTMultiplier(over max) = %v, want ErrInvalidConfig", err)
	}
	if err := rx.SetRTTMultiplier(1); err != nil {
		t.Fatalf("SetRTTMultiplier(1) = %v, want nil", err)
	}
	if err := rx.SetRTTMultiplier(ristgo.MaxRTTMultiplier); err != nil {
		t.Fatalf("SetRTTMultiplier(max) = %v, want nil", err)
	}
}

// TestSetNullPacketDeletionRejectsNonMain checks that NPD (a Main-profile feature)
// is rejected on a Simple sender.
func TestSetNullPacketDeletionRejectsNonMain(t *testing.T) {
	cfg := ristgo.DefaultConfig() // Simple by default
	tx, err := ristgo.NewSender("127.0.0.1:5000", cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	if err := tx.SetNullPacketDeletion(true); !errors.Is(err, ristgo.ErrNPDUnsupported) {
		t.Fatalf("SetNullPacketDeletion on Simple = %v, want ErrNPDUnsupported", err)
	}
}

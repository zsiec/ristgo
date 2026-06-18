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

// TestE2EReflectorFansToTwoOutputs proves the Main-profile transparent reflector: a
// sender feeds one input flow; the reflector recovers it and re-emits every packet to
// two outputs preserving (seq, sourceTime). Both outputs receive the stream byte-exact.
func TestE2EReflectorFansToTwoOutputs(t *testing.T) {
	cfg := mainConfig("", 0)

	out1Addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	out2Addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	out1, err := ristgo.NewReceiver(out1Addr, cfg)
	if err != nil {
		t.Fatalf("NewReceiver out1: %v", err)
	}
	defer out1.Close()
	out2, err := ristgo.NewReceiver(out2Addr, cfg)
	if err != nil {
		t.Fatalf("NewReceiver out2: %v", err)
	}
	defer out2.Close()

	inAddr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	reflector, err := ristgo.Reflect(inAddr, []string{out1Addr, out2Addr}, cfg)
	if err != nil {
		t.Fatalf("Reflect: %v", err)
	}
	defer reflector.Close()
	if reflector.OutputCount() != 2 {
		t.Fatalf("OutputCount = %d, want 2", reflector.OutputCount())
	}

	tx, err := ristgo.NewSender(inAddr, cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	const frames = 40
	const frameLen = 188
	payload := make([]byte, frames*frameLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	want := sha256.Sum256(payload)

	readAll := func(rx *ristgo.Receiver) [32]byte {
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
				return [32]byte{}
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		return sum
	}

	var wg sync.WaitGroup
	var sum1, sum2 [32]byte
	wg.Add(2)
	go func() { defer wg.Done(); sum1 = readAll(out1) }()
	go func() { defer wg.Done(); sum2 = readAll(out2) }()

	tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < frames; i++ {
		if _, werr := tx.Write(payload[i*frameLen : (i+1)*frameLen]); werr != nil {
			t.Fatalf("Write %d: %v", i, werr)
		}
		time.Sleep(3 * time.Millisecond)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("reflector outputs timed out (out1=%d out2=%d delivered)", out1.Stats().Delivered, out2.Stats().Delivered)
	}
	if sum1 != want {
		t.Fatalf("out1 hash mismatch")
	}
	if sum2 != want {
		t.Fatalf("out2 hash mismatch")
	}
}

// TestReflectRejectsNonMainAndEmptyOutputs checks the profile and output guards.
func TestReflectRejectsNonMainAndEmptyOutputs(t *testing.T) {
	if _, err := ristgo.Reflect("127.0.0.1:9000", []string{"127.0.0.1:9002"}, ristgo.DefaultConfig()); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("non-Main Reflect = %v, want ErrInvalidConfig", err)
	}
	if _, err := ristgo.Reflect("127.0.0.1:9000", nil, mainConfig("", 0)); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("empty-outputs Reflect = %v, want ErrInvalidConfig", err)
	}
}

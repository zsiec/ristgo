package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2EReceiverAddPathBindsNewInput starts a bonded receiver on a subset of its input
// paths and binds another at runtime (BondedReceiver.AddPath, libRIST rist_peer_create);
// the newly-bound path then receives media (witnessed by the receiver's per-path stats).
func TestE2EReceiverAddPathBindsNewInput(t *testing.T) {
	pA, pB := twoEvenPorts(t)
	pC, _ := twoEvenPorts(t)
	for pC == pA || pC == pB {
		pC, _ = twoEvenPorts(t)
	}
	all := []string{
		fmt.Sprintf("127.0.0.1:%d", pA),
		fmt.Sprintf("127.0.0.1:%d", pB),
		fmt.Sprintf("127.0.0.1:%d", pC),
	}

	// The receiver starts on the first two inputs; the sender dials all three (the
	// third has no listener until the receiver binds it at runtime).
	rx, err := ristgo.NewBondedReceiver(all[:2], bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewBondedSender(all, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, 96*1024)
	for i := range payload {
		payload[i] = byte(i)
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
	added := false
	for off := 0; off < len(payload); off += chunk {
		end := off + chunk
		if end > len(payload) {
			end = len(payload)
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if !added && off >= len(payload)/3 {
			// Bind the third input path at runtime (index 2 — the next slot).
			if err := rx.AddPath(2, all[2], 0); err != nil {
				t.Fatalf("receiver AddPath: %v", err)
			}
			added = true
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
		t.Fatalf("bonded stream hash mismatch after receiver AddPath")
	}

	rs := rx.Stats()
	if len(rs.Peers) != 3 {
		t.Fatalf("receiver Peers = %d, want 3 (third input bound)", len(rs.Peers))
	}
	if rs.Peers[2].Received == 0 {
		t.Fatalf("runtime-bound input path received no media: %+v", rs.Peers[2])
	}
	if err := rx.RemovePath(2); err != nil {
		t.Fatalf("receiver RemovePath: %v", err)
	}
}

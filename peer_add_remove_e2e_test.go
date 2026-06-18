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

// TestE2EAddPathRoutesMediaToNewDestination starts a bonded sender on two of three
// receiver paths, adds the third at runtime (BondedSender.AddPath, libRIST
// rist_peer_create), and verifies the new path then carries media via the receiver's
// per-path stats.
func TestE2EAddPathRoutesMediaToNewDestination(t *testing.T) {
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

	rx, err := ristgo.NewBondedReceiver(all, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()
	// The sender starts on the first two paths only.
	tx, err := ristgo.NewBondedSender(all[:2], bondConfig())
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
			// Add the third destination at runtime (index 2 — the next free index).
			if err := tx.AddPath(2, all[2], 0); err != nil {
				t.Fatalf("AddPath: %v", err)
			}
			added = true
		}
		if (off/chunk)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	// Trailing flush so the tail has successors / time to arrive.
	flush := make([]byte, chunk)
	for i := 0; i < 24; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	if got != want {
		t.Fatalf("bonded stream hash mismatch after AddPath")
	}

	rs := rx.Stats()
	if len(rs.Peers) != 3 {
		t.Fatalf("receiver Peers = %d, want 3 (third path added)", len(rs.Peers))
	}
	if rs.Peers[2].Received == 0 {
		t.Fatalf("runtime-added path carried no media: %+v", rs.Peers[2])
	}

	// Remove the path; prove it returns cleanly and an out-of-range index is rejected.
	if err := tx.RemovePath(2); err != nil {
		t.Fatalf("RemovePath: %v", err)
	}
	if err := tx.AddPath(-1, all[2], 0); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("AddPath(-1) = %v, want ErrInvalidConfig", err)
	}
}

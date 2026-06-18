package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2ESinglePathOnePeer verifies a non-bonded session reports exactly one peer
// mirroring the flow aggregate.
func TestE2ESinglePathOnePeer(t *testing.T) {
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

	const frames, frameLen = 30, 188
	payload := make([]byte, frames*frameLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	done := make(chan struct{})
	go func() {
		rx.SetReadDeadline(time.Now().Add(10 * time.Second))
		got := 0
		buf := make([]byte, 4096)
		for got < len(payload) {
			n, rerr := rx.Read(buf)
			got += n
			if rerr != nil {
				break
			}
		}
		close(done)
	}()
	tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < frames; i++ {
		if _, werr := tx.Write(payload[i*frameLen : (i+1)*frameLen]); werr != nil {
			t.Fatalf("Write %d: %v", i, werr)
		}
		time.Sleep(3 * time.Millisecond)
	}
	<-done

	rs := rx.Stats()
	if len(rs.Peers) != 1 {
		t.Fatalf("single-path receiver Peers = %d, want 1", len(rs.Peers))
	}
	if rs.Peers[0].Received != rs.Received {
		t.Fatalf("peer Received %d != flow Received %d", rs.Peers[0].Received, rs.Received)
	}
	if !rs.Peers[0].Alive {
		t.Fatalf("single peer not alive")
	}
	ss := tx.Stats()
	if len(ss.Peers) != 1 || ss.Peers[0].Sent != ss.Sent {
		t.Fatalf("single-path sender peer mismatch: %+v vs Sent=%d", ss.Peers, ss.Sent)
	}
}

// TestE2EBondedPeerPerPath verifies a 2-path bonded session reports one peer per
// path, each with its own received/sent counters and liveness.
func TestE2EBondedPeerPerPath(t *testing.T) {
	pA, pB := twoEvenPorts(t)
	addrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}
	rx, err := ristgo.NewBondedReceiver(addrs, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewBondedSender(addrs, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)
	if got := streamSHA(t, tx, rx, payload, nil); got != want {
		t.Fatalf("bonded hash mismatch")
	}

	// Receiver: one peer per path; full 2022-7 duplication means each path delivered
	// media, so both peers carry received packets and are alive.
	rs := rx.Stats()
	if len(rs.Peers) != 2 {
		t.Fatalf("bonded receiver Peers = %d, want 2", len(rs.Peers))
	}
	for i, p := range rs.Peers {
		if p.Received == 0 || !p.Alive {
			t.Fatalf("receiver path %d: %+v (want received>0, alive)", i, p)
		}
	}
	// Sender: one peer per path; full duplication means each path sent the stream.
	ss := tx.Stats()
	if len(ss.Peers) != 2 {
		t.Fatalf("bonded sender Peers = %d, want 2", len(ss.Peers))
	}
	for i, p := range ss.Peers {
		if p.Sent == 0 {
			t.Fatalf("sender path %d sent nothing: %+v", i, p)
		}
	}
}

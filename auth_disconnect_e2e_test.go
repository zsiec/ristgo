package ristgo_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2EDisconnectCallback verifies the disconnect callback (libRIST disconn_cb): a peer
// connects (the connect callback records it), then the sender closes and the receiver
// times out — its event loop exits and fires the disconnect callback with the same
// ConnectInfo.
func TestE2EDisconnectCallback(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	var mu sync.Mutex
	var connected, disconnected *ristgo.ConnectInfo

	recvCfg := eapConfig("alice", "pw")
	recvCfg.KeepaliveInterval = 100 * time.Millisecond
	recvCfg.SessionTimeout = 400 * time.Millisecond
	recvCfg.OnConnect = func(i ristgo.ConnectInfo) bool {
		mu.Lock()
		c := i
		connected = &c
		mu.Unlock()
		return true
	}
	recvCfg.OnDisconnect = func(i ristgo.ConnectInfo) {
		mu.Lock()
		d := i
		disconnected = &d
		mu.Unlock()
	}
	rx, err := ristgo.NewReceiver(addr, recvCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	sendCfg := eapConfig("alice", "pw")
	sendCfg.KeepaliveInterval = 100 * time.Millisecond
	sendCfg.SessionTimeout = 400 * time.Millisecond
	tx, err := ristgo.NewSender(addr, sendCfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}

	// Stream until at least one payload is delivered (the connect fired).
	go func() {
		tx.SetWriteDeadline(time.Now().Add(5 * time.Second))
		for i := 0; i < 40; i++ {
			if _, err := tx.Write([]byte(fmt.Sprintf("d-%d", i))); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	rx.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := rx.Read(make([]byte, 4096)); err != nil || n == 0 {
		t.Fatalf("expected a delivered payload, got n=%d err=%v", n, err)
	}
	mu.Lock()
	if connected == nil || connected.Username != "alice" {
		mu.Unlock()
		t.Fatalf("connect callback did not fire with the username: %+v", connected)
	}
	mu.Unlock()

	// Close the sender; the receiver times out, its loop exits, and disconnect fires.
	tx.Close()
	rx.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, err := rx.Read(make([]byte, 4096)); err != nil {
			break // session ended (timeout)
		}
	}
	// Give the deferred disconnect callback a moment to run after the loop exits.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := disconnected
		mu.Unlock()
		if got != nil {
			if got.Username != "alice" {
				t.Fatalf("disconnect callback username = %q, want alice", got.Username)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("disconnect callback never fired after the session ended")
}

package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// streamAuthedOK runs a sha256-checked Main stream over the authenticated rx/tx and
// fails the test unless the whole payload is delivered intact.
func streamAuthedOK(t *testing.T, rx *ristgo.Receiver, tx *ristgo.Sender) {
	t.Helper()
	const total = 48 * 1024
	const chunk = 1316
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(12 * time.Second))
		got := make([]byte, 0, total)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < total {
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

	tx.SetWriteDeadline(time.Now().Add(12 * time.Second))
	for off := 0; off < total; off += chunk {
		end := off + chunk
		if end > total {
			end = total
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if off%(chunk*16) == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case got := <-done:
		if got != want {
			t.Fatalf("authenticated delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out on the authenticated stream")
	}
}

// TestE2EMultiUserSRP configures a listener with several SRP users and authenticates a
// sender presenting the SECOND one (libRIST multi-user SRP / rist_enable_eap_srp_2): the
// authenticator looks the verifier up by the presented username.
func TestE2EMultiUserSRP(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	recvCfg := eapConfig("", "")
	recvCfg.Username, recvCfg.Password = "", ""
	recvCfg.SRPUsers = map[string]string{"alice": "alice-pw", "bob": "bob-pw"}

	rx, err := ristgo.NewReceiver(addr, recvCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, eapConfig("bob", "bob-pw"))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()
	streamAuthedOK(t, rx, tx)
}

// TestE2EConnectCallbackAccepts verifies the connect callback (libRIST
// rist_auth_handler_set) fires with the authenticated identity and, on accept, the
// stream delivers.
func TestE2EConnectCallbackAccepts(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	var mu sync.Mutex
	var seen *ristgo.ConnectInfo
	recvCfg := eapConfig("alice", "alice-pw")
	recvCfg.OnConnect = func(info ristgo.ConnectInfo) bool {
		mu.Lock()
		c := info
		seen = &c
		mu.Unlock()
		return true
	}
	rx, err := ristgo.NewReceiver(addr, recvCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, eapConfig("alice", "alice-pw"))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()
	streamAuthedOK(t, rx, tx)

	mu.Lock()
	defer mu.Unlock()
	if seen == nil {
		t.Fatal("connect callback never fired")
	}
	if seen.Username != "alice" {
		t.Fatalf("connect callback username = %q, want \"alice\"", seen.Username)
	}
	if !strings.HasPrefix(seen.Remote, "127.0.0.1:") {
		t.Fatalf("connect callback remote = %q, want a loopback addr", seen.Remote)
	}
}

// TestE2EConnectCallbackRejects verifies a connect callback that admits only "alice"
// rejects a "bob" connection: the session is torn down and Read surfaces ErrAuth.
func TestE2EConnectCallbackRejects(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	var mu sync.Mutex
	var seenUser string
	recvCfg := eapConfig("", "")
	recvCfg.Username, recvCfg.Password = "", ""
	recvCfg.SRPUsers = map[string]string{"alice": "alice-pw", "bob": "bob-pw"}
	recvCfg.OnConnect = func(info ristgo.ConnectInfo) bool {
		mu.Lock()
		seenUser = info.Username
		mu.Unlock()
		return info.Username == "alice"
	}
	rx, err := ristgo.NewReceiver(addr, recvCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, eapConfig("bob", "bob-pw"))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	go func() {
		tx.SetWriteDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1316)
		for i := 0; i < 64; i++ {
			if _, err := tx.Write(buf); err != nil {
				return
			}
		}
	}()

	rx.SetReadDeadline(time.Now().Add(4 * time.Second))
	n, err := rx.Read(make([]byte, 4096))
	if n != 0 {
		t.Fatalf("delivered %d bytes despite a rejected connection", n)
	}
	if !errors.Is(err, ristgo.ErrAuth) && !errors.Is(err, ristgo.ErrTimeout) {
		t.Fatalf("Read error = %v, want ErrAuth or ErrTimeout", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenUser != "bob" {
		t.Fatalf("connect callback saw %q, want \"bob\"", seenUser)
	}
}

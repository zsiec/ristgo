package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// TestE2EAdvHeavyLossRecovery proves ristgo's Advanced native NACK control plane
// recovers a quarter of the stream byte-exact, Go<->Go, over real UDP. This is the
// recovery the interop suite cannot prove against libRIST: libRIST's own Advanced
// receiver fails to recover 25% loss (libRIST<->libRIST also drops packets at this
// rate — its >>16 RTT-echo overflow makes it refuse the re-NACKs a doubly-dropped
// packet needs, common at 25% and rare at 10%), so the libRIST-peer heavy-loss
// test is skipped. ristgo's flow core re-NACKs correctly and its sender suppresses
// duplicate retransmits within one RTT, so the loss/ARQ round trip stays tight
// (no retransmit storm) and recovery is complete. A 500ms buffer gives ample room
// on loopback; a trailing flush gives a dropped tail a delivered successor.
func TestE2EAdvHeavyLossRecovery(t *testing.T) {
	const totalBytes = 96 * 1024
	const chunk = 1316
	const flushChunks = 24

	recvPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == recvPort {
		proxyPort = freeMainPort(t)
	}

	cfg := advConfig("", 0, false)
	cfg.BufferMin = 500 * time.Millisecond
	cfg.BufferMax = 500 * time.Millisecond

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startMainLossyProxy(t, proxyPort, recvPort, 0.25, 25)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	payload := advPayload(t, totalBytes, false)
	want := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(20 * time.Second))
		got := make([]byte, 0, totalBytes)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < totalBytes {
			n, rerr := rx.Read(buf)
			if n > 0 {
				take := n
				if len(got)+take > totalBytes {
					take = totalBytes - len(got)
				}
				h.Write(buf[:take])
				got = append(got, buf[:take]...)
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

	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < totalBytes; off += chunk {
		end := off + chunk
		if end > totalBytes {
			end = totalBytes
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if (off/chunk)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	flush := make([]byte, chunk)
	for i := 0; i < flushChunks; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}

	select {
	case gotHash := <-done:
		if gotHash != want {
			st := rx.Stats()
			t.Fatalf("Advanced 25%% recovery not byte-exact (proxy dropped=%d recovered=%d lost=%d abandoned=%d)",
				proxy.Dropped(), st.Recovered, st.Lost, st.Abandoned)
		}
	case <-time.After(22 * time.Second):
		st := rx.Stats()
		t.Fatalf("timed out (recovered=%d lost=%d)", st.Recovered, st.Lost)
	}

	if st := rx.Stats(); st.Recovered == 0 {
		t.Fatalf("no packets recovered by ARQ — loss path not exercised (delivered=%d)", st.Delivered)
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped no media — the loss/ARQ path was not exercised")
	}
}

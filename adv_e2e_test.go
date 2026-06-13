package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"runtime"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// advConfig returns a fast Advanced-profile config with the given AES key size
// (aesBits 0 means cleartext) and optional LZ4 compression.
func advConfig(secret string, aesBits int, compress bool) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileAdvanced
	cfg.BufferMin = 100 * time.Millisecond
	cfg.BufferMax = 100 * time.Millisecond
	cfg.Secret = secret
	cfg.AESKeyBits = aesBits
	cfg.Compression = compress
	return cfg
}

// advPayload builds a totalBytes test payload: random (incompressible) by
// default, or a repeating pattern when compressible so the LZ4 path actually
// engages.
func advPayload(t *testing.T, totalBytes int, compressible bool) []byte {
	t.Helper()
	p := make([]byte, totalBytes)
	if compressible {
		pat := []byte("MPEG-TS-PADDING-CELL-0123456789-")
		for i := range p {
			p[i] = pat[i%len(pat)]
		}
		return p
	}
	if _, err := rand.Read(p); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return p
}

// TestE2EAdvProfile streams a payload sender->receiver over the Advanced profile
// (single UDP port, RTP-based media + native control) and verifies bit-exact
// delivery via SHA-256: cleartext, PSK AES-128, PSK AES-256, and AES-256+LZ4. It
// exercises the full Advanced host stack in pure Go — the adv header codec, the
// DIRECT/CONTROL encapsulation-type demux on the single socket, AES-CTR
// payload-only encryption, LZ4 compression, native control framing, and in-order
// ARQ-capable playout.
func TestE2EAdvProfile(t *testing.T) {
	cases := []struct {
		name         string
		secret       string
		aesBits      int
		compress     bool
		compressible bool
	}{
		{"cleartext", "", 0, false, false},
		{"aes128", "ristgo-adv-secret", 128, false, false},
		{"aes256", "ristgo-adv-secret", 256, false, false},
		{"aes256+lz4", "ristgo-adv-secret", 256, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const totalBytes = 128 * 1024
			const chunk = 1316
			addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

			rx, err := ristgo.NewReceiver(addr, advConfig(tc.secret, tc.aesBits, tc.compress))
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()

			tx, err := ristgo.NewSender(addr, advConfig(tc.secret, tc.aesBits, tc.compress))
			if err != nil {
				t.Fatalf("NewSender: %v", err)
			}
			defer tx.Close()

			payload := advPayload(t, totalBytes, tc.compressible)
			want := sha256.Sum256(payload)

			done := make(chan [32]byte, 1)
			go func() {
				rx.SetReadDeadline(time.Now().Add(10 * time.Second))
				got := make([]byte, 0, totalBytes)
				buf := make([]byte, 4096)
				h := sha256.New()
				for len(got) < totalBytes {
					n, rerr := rx.Read(buf)
					if n > 0 {
						h.Write(buf[:n])
						got = append(got, buf[:n]...)
					}
					if rerr != nil {
						done <- [32]byte{} // incomplete
						return
					}
				}
				var sum [32]byte
				copy(sum[:], h.Sum(nil))
				done <- sum
			}()

			tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
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

			select {
			case got := <-done:
				if got != want {
					st := rx.Stats()
					t.Fatalf("Adv %s hash mismatch (delivered=%d lost=%d)", tc.name, st.Delivered, st.Lost)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("timed out waiting for the Advanced-profile stream")
			}

			if st := rx.Stats(); st.Delivered == 0 {
				t.Fatal("receiver delivered 0 packets")
			}
		})
	}
}

// TestE2EAdvLossRecovery streams through a 10%-forward-loss proxy on the Advanced
// profile and verifies every byte is recovered by ARQ (SHA-256), cleartext and
// PSK AES-256 — proving the native NACK -> retransmit (R flag) -> recovery
// round-trip works end-to-end through the single-socket host, not just in the
// codec unit tests. Reuses the profile-agnostic mainLossyProxy (it demuxes by
// source address, so it works unchanged for Advanced).
func TestE2EAdvLossRecovery(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		aesBits int
	}{
		{"cleartext", "", 0},
		{"aes256", "ristgo-adv-secret", 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const totalBytes = 96 * 1024
			const chunk = 1316
			const flushChunks = 24

			recvPort := freeMainPort(t)
			proxyPort := freeMainPort(t)
			for proxyPort == recvPort {
				proxyPort = freeMainPort(t)
			}

			cfg := advConfig(tc.secret, tc.aesBits, false)
			cfg.BufferMin = 500 * time.Millisecond
			cfg.BufferMax = 500 * time.Millisecond

			rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()

			proxy := startMainLossyProxy(t, proxyPort, recvPort, 0.10, 7)
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
			case got := <-done:
				if got != want {
					st := rx.Stats()
					t.Fatalf("Adv %s loss recovery failed (proxy dropped=%d delivered=%d recovered=%d lost=%d)",
						tc.name, proxy.Dropped(), st.Delivered, st.Recovered, st.Lost)
				}
			case <-time.After(25 * time.Second):
				st := rx.Stats()
				t.Fatalf("Adv %s timed out (proxy dropped=%d delivered=%d recovered=%d)",
					tc.name, proxy.Dropped(), st.Delivered, st.Recovered)
			}

			if proxy.Dropped() == 0 {
				t.Fatal("proxy dropped no datagrams — the loss/ARQ path was not exercised")
			}
			if st := rx.Stats(); st.Recovered == 0 {
				t.Fatalf("no packets recovered by ARQ over Advanced (proxy dropped=%d delivered=%d)", proxy.Dropped(), st.Delivered)
			}
		})
	}
}

// TestE2EAdvCloseUnblocksRead verifies Close on an Advanced receiver wakes a
// blocked Read with ErrClosed and that the session's goroutines — the event loop
// and the single readAdv reader — exit, returning the goroutine count to its
// pre-construction baseline.
func TestE2EAdvCloseUnblocksRead(t *testing.T) {
	baseline := runtime.NumGoroutine()

	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rx, err := ristgo.NewReceiver(addr, advConfig("ristgo-adv-secret", 256, false))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, err := rx.Read(buf) // blocks: no sender
		readErr <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := rx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readErr:
		if err != ristgo.ErrClosed {
			t.Fatalf("Read after Close = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}

	for i := 0; i < 20; i++ {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutines did not return to baseline: have %d, baseline %d", runtime.NumGoroutine(), baseline)
}

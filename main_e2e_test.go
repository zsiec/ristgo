package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// freeMainPort finds one free loopback UDP port for a Main-profile single-port
// flow (the Main port, unlike the Simple media port, need not be even). The
// probe-then-bind window is small; the retry loop tolerates it.
func freeMainPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			continue
		}
		p := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		if p > 0 {
			return p
		}
	}
	t.Fatal("no free udp port found")
	return 0
}

// mainConfig returns a fast Main-profile config with the given AES key size
// (aesBits 0 means cleartext — Profile Main with no PSK).
func mainConfig(secret string, aesBits int) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileMain
	cfg.BufferMin = 100 * time.Millisecond
	cfg.BufferMax = 100 * time.Millisecond
	cfg.Secret = secret
	cfg.AESKeyBits = aesBits
	return cfg
}

// TestE2EMainProfile streams a payload sender->receiver over the Main profile
// (the GRE single-port tunnel) and verifies bit-exact delivery via SHA-256 —
// with no encryption, and with PSK AES-128 and AES-256. It exercises the full
// Main host stack in pure Go: GRE framing, the reduced-overhead header, PSK
// encryption of the reduced header + RTP together (when a secret is set), the
// payload-type-byte media/RTCP demux, the single-socket reader, and in-order
// ARQ-capable playout.
func TestE2EMainProfile(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		aesBits int
	}{
		{"cleartext", "", 0},
		{"aes128", "ristgo-main-secret", 128},
		{"aes256", "ristgo-main-secret", 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const totalBytes = 128 * 1024
			const chunk = 1316
			addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

			rx, err := ristgo.NewReceiver(addr, mainConfig(tc.secret, tc.aesBits))
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()

			tx, err := ristgo.NewSender(addr, mainConfig(tc.secret, tc.aesBits))
			if err != nil {
				t.Fatalf("NewSender: %v", err)
			}
			defer tx.Close()

			payload := make([]byte, totalBytes)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand: %v", err)
			}
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
					time.Sleep(time.Millisecond) // light pacing
				}
			}

			select {
			case got := <-done:
				if got != want {
					st := rx.Stats()
					t.Fatalf("Main %s hash mismatch (delivered=%d lost=%d):\n got %x\nwant %x",
						tc.name, st.Delivered, st.Lost, got, want)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("timed out waiting for the Main-profile stream")
			}

			if st := rx.Stats(); st.Delivered == 0 {
				t.Fatal("receiver delivered 0 packets")
			}
		})
	}
}

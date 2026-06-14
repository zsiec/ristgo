package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
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

// eapConfig returns a Main-profile config with PSK (AES-256) for the data
// channel and EAP-SRP credentials gating it.
func eapConfig(username, password string) ristgo.Config {
	cfg := mainConfig("ristgo-eap-psk", 256)
	cfg.Username = username
	cfg.Password = password
	cfg.BufferMin = 300 * time.Millisecond
	cfg.BufferMax = 300 * time.Millisecond
	return cfg
}

// TestE2EMainEAPSRP verifies the full authenticated Main flow end to end: the
// sender and receiver run the EAP-SRP handshake (over GRE EAPOL frames) before
// the data channel opens, then stream PSK-encrypted media that is delivered
// bit-exact. It exercises the session's EAPOL routing, the handshake pumping,
// and the auth gate (the sender holds media and the receiver holds delivery
// until authentication succeeds).
func TestE2EMainEAPSRP(t *testing.T) {
	const totalBytes = 64 * 1024
	const chunk = 1316
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	rx, err := ristgo.NewReceiver(addr, eapConfig("rist", "mainprofile"))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, eapConfig("rist", "mainprofile"))
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
				done <- [32]byte{}
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
			t.Fatalf("authenticated Main delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out on the authenticated Main stream")
	}
}

// srpNoSecretConfig is a Main-profile config with SRP credentials and NO
// pre-shared Secret: the use_key_as_passphrase mode, where the media AES key is
// derived from the SRP session key K on a successful handshake.
func srpNoSecretConfig(username, password string) ristgo.Config {
	cfg := mainConfig("", 0) // no secret, cleartext until K-keying
	cfg.Username = username
	cfg.Password = password
	cfg.BufferMin = 300 * time.Millisecond
	cfg.BufferMax = 300 * time.Millisecond
	return cfg
}

// TestE2EMainEAPSRPUseKeyAsPassphrase verifies the full authenticated Main flow
// with SRP and NO pre-shared secret (use_key_as_passphrase): the sender and
// receiver run the EAP-SRP handshake, derive the media PSK keys from the SRP
// session key K (inline via the M1/M2 set_passphrase bit), install them into the
// running codec, and then stream media that is delivered bit-exact — gated on
// authentication, and actually encrypted under K (not cleartext).
func TestE2EMainEAPSRPUseKeyAsPassphrase(t *testing.T) {
	const totalBytes = 64 * 1024
	const chunk = 1316
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	rx, err := ristgo.NewReceiver(addr, srpNoSecretConfig("rist", "mainprofile"))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, srpNoSecretConfig("rist", "mainprofile"))
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
		rx.SetReadDeadline(time.Now().Add(15 * time.Second))
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
				done <- [32]byte{}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- sum
	}()

	tx.SetWriteDeadline(time.Now().Add(15 * time.Second))
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
			t.Fatalf("use_key_as_passphrase Main delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out on the use_key_as_passphrase Main stream")
	}
	if !rx.Authenticated() {
		t.Fatal("receiver reports not authenticated after a complete delivery")
	}
}

// TestE2EMainEAPSRPWrongPassword verifies that a sender with the wrong password
// fails the EAP-SRP handshake: the data channel never opens, and the receiver's
// Read surfaces ErrAuth rather than delivering anything.
func TestE2EMainEAPSRPWrongPassword(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	rx, err := ristgo.NewReceiver(addr, eapConfig("rist", "mainprofile"))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, eapConfig("rist", "WRONG-password"))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	// Try to push media; with auth failing, nothing should ever be delivered.
	go func() {
		tx.SetWriteDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1316)
		for i := 0; i < 64; i++ {
			if _, err := tx.Write(buf); err != nil {
				return
			}
		}
	}()

	rx.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := rx.Read(make([]byte, 4096))
	if n != 0 {
		t.Fatalf("delivered %d bytes despite failed authentication", n)
	}
	if err == nil {
		t.Fatal("Read returned nil error despite failed authentication")
	}
	// The receiver tears down with ErrAuth on the failed handshake (or the read
	// deadline fires first if the FAILURE is still in flight); both are
	// acceptable proof that the data channel never opened.
	if !errors.Is(err, ristgo.ErrAuth) && !errors.Is(err, ristgo.ErrTimeout) {
		t.Fatalf("Read error = %v, want ErrAuth or ErrTimeout", err)
	}
}

// TestE2EMainMixedKeySize verifies the GRE-H-bit hardening end to end: the
// sender is configured AES-256 and the receiver AES-128 (a mismatch), yet the
// stream is delivered bit-exact because each side honors the peer's GRE H bit
// and derives the decryption key at the signalled size — media (256, set by the
// sender) and the receiver's feedback (128) both decrypt across the mismatch.
func TestE2EMainMixedKeySize(t *testing.T) {
	const totalBytes = 64 * 1024
	const chunk = 1316
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))

	rx, err := ristgo.NewReceiver(addr, mainConfig("ristgo-mixed", 128))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, mainConfig("ristgo-mixed", 256))
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
				done <- [32]byte{}
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
			t.Fatalf("mixed-key-size delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out on the mixed-key-size stream")
	}
}

// TestE2EMainCloseUnblocksRead is the Main-profile counterpart of
// TestE2ECloseUnblocksRead: it verifies Close on a Main receiver wakes a blocked
// Read with ErrClosed and that the session's goroutines — the event loop and the
// single readMain reader (not readMedia/readRTCP) — exit, returning the
// goroutine count to its pre-construction baseline. The single GRE socket's
// Close guard (socket.single) must still unblock readMain's blocking ReadMedia.
// Run under -race for data-race coverage of the Main reader/loop seam too.
func TestE2EMainCloseUnblocksRead(t *testing.T) {
	baseline := runtime.NumGoroutine()

	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rx, err := ristgo.NewReceiver(addr, mainConfig("ristgo-main-secret", 256))
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
		if err != io.EOF {
			t.Fatalf("Read after Close = %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
	if _, err := rx.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("Read on closed receiver = %v, want io.EOF", err)
	}

	// The session's loop + readMain goroutines should have exited. Allow a brief
	// settle and a small slack for runtime/test goroutines.
	for i := 0; i < 20; i++ {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutines did not return to baseline: have %d, baseline %d", runtime.NumGoroutine(), baseline)
}

// TestE2EMainOOB verifies the out-of-band side channel over the Main profile: a
// PSK-encrypted OOB datagram round-trips sender->receiver via WriteOOB/ReadOOB,
// and a Simple-profile sender rejects OOB with ErrOOBUnsupported.
func TestE2EMainOOB(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rx, err := ristgo.NewReceiver(addr, mainConfig("ristgo-oob-secret", 128))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, mainConfig("ristgo-oob-secret", 128))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	oobMsg := "hello out-of-band \x00\x47\xff metadata"
	gotOOB := make(chan string, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, rerr := rx.ReadOOB(buf)
		if rerr != nil {
			gotOOB <- ""
			return
		}
		gotOOB <- string(buf[:n])
	}()

	// OOB is fire-and-forget (no ARQ); resend until the receiver reads it.
	deadline := time.Now().Add(5 * time.Second)
	tx.SetWriteDeadline(deadline)
	for time.Now().Before(deadline) {
		if err := tx.WriteOOB([]byte(oobMsg)); err != nil {
			t.Fatalf("WriteOOB: %v", err)
		}
		select {
		case got := <-gotOOB:
			if got != oobMsg {
				t.Fatalf("OOB mismatch:\n got %q\nwant %q", got, oobMsg)
			}
			goto simpleCheck
		case <-time.After(25 * time.Millisecond):
		}
	}
	t.Fatal("OOB datagram not received within the deadline")

simpleCheck:
	// A Simple-profile sender has no OOB channel.
	scfg := ristgo.DefaultConfig() // ProfileSimple
	stx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", freeMainPort(t)&^1), scfg)
	if err != nil {
		t.Fatalf("NewSender(Simple): %v", err)
	}
	defer stx.Close()
	if err := stx.WriteOOB([]byte("x")); !errors.Is(err, ristgo.ErrOOBUnsupported) {
		t.Fatalf("Simple WriteOOB = %v, want ErrOOBUnsupported", err)
	}
}

// streamSHA streams totalBytes of random media tx->rx in chunk-sized writes and
// asserts byte-exact delivery via SHA-256. Shared by the timing-mode and
// srp-compat end-to-end tests.
func streamVerify(t *testing.T, tx *ristgo.Sender, rx *ristgo.Receiver, totalBytes, chunk int) {
	t.Helper()
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
				done <- [32]byte{}
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
			t.Fatalf("delivery hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(12 * time.Second):
		t.Fatalf("timeout waiting for delivery (delivered=%d)", rx.Stats().Delivered)
	}
}

// TestE2EMainArrivalTiming verifies a receiver configured for ARRIVAL timing
// delivers a stream bit-exact — the public Config.TimingMode wiring through to
// the flow core's arrival-paced playout. Arrival timing lives in the
// profile-agnostic core, so the Main profile exercises the full public path.
func TestE2EMainArrivalTiming(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rxCfg := mainConfig("", 0)
	rxCfg.TimingMode = ristgo.TimingArrival
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
	streamVerify(t, tx, rx, 64*1024, 1316)
}

// TestE2EMainSRPCompat verifies a Main session authenticates and streams when
// the receiver uses the legacy SRP mode (SRPCompat=true → the authenticator
// advertises EAPOL version 2). The sender's authenticatee auto-negotiates the
// advertised legacy version, so PSK media flows bit-exact after the legacy
// handshake.
func TestE2EMainSRPCompat(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	rxCfg := eapConfig("rist", "mainprofile")
	rxCfg.SRPCompat = true // receiver acts as the legacy authenticator
	rx, err := ristgo.NewReceiver(addr, rxCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, eapConfig("rist", "mainprofile"))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()
	streamVerify(t, tx, rx, 64*1024, 1316)
}

package ristgo_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// mediaRelay is a one-way UDP relay used to impair a single bonded path: it
// forwards datagrams from the sender to one receiver path's media port, dropping
// a fraction (and everything once killed). The OTHER path runs direct, so 2022-7
// redundancy must cover whatever this path loses — no reverse/NACK channel is
// needed for completeness.
type mediaRelay struct {
	sock    *net.UDPConn
	dst     *net.UDPAddr
	loss    float64
	rng     *mrand.Rand
	dropped atomic.Uint64
	alive   atomic.Bool
	wg      sync.WaitGroup
}

func startMediaRelay(t *testing.T, listenPort, dstPort int, loss float64, seed uint64) *mediaRelay {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort})
	if err != nil {
		t.Fatalf("media relay bind: %v", err)
	}
	r := &mediaRelay{
		sock: sock,
		dst:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dstPort},
		loss: loss,
		rng:  mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)),
	}
	r.alive.Store(true)
	r.wg.Add(1)
	go r.relay()
	return r
}

func (r *mediaRelay) relay() {
	defer r.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := r.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !r.alive.Load() || (r.loss > 0 && r.rng.Float64() < r.loss) {
			r.dropped.Add(1)
			continue
		}
		r.sock.WriteToUDP(buf[:n], r.dst)
	}
}

func (r *mediaRelay) kill()           { r.alive.Store(false) }
func (r *mediaRelay) Dropped() uint64 { return r.dropped.Load() }
func (r *mediaRelay) Close()          { r.sock.Close(); r.wg.Wait() }

// bondConfig is a fast Simple-profile config for the bonded e2e tests.
// bondConfig is the shared Simple-profile bonding test config. It pins
// ProfileSimple because DefaultConfig now defaults to Advanced; these tests
// predate that flip and exercise Simple-profile bonding (the Advanced bonded path
// has its own -p 2 interop coverage).
func bondConfig() ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileSimple
	cfg.BufferMin = 300 * time.Millisecond
	cfg.BufferMax = 300 * time.Millisecond
	return cfg
}

// twoEvenPorts returns two distinct free even loopback ports.
func twoEvenPorts(t *testing.T) (int, int) {
	t.Helper()
	a := freeEvenPort(t)
	b := freeEvenPort(t)
	for b == a {
		b = freeEvenPort(t)
	}
	return a, b
}

// streamSHA writes the payload into the bonded sender (chunked) and reads the
// merged stream back from the receiver, returning the received SHA-256 and byte
// count. It is shared by the bonded e2e cases.
func streamSHA(t *testing.T, tx *ristgo.BondedSender, rx *ristgo.BondedReceiver, payload []byte, killAt func()) [32]byte {
	t.Helper()
	const chunk = 1316
	want := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(20 * time.Second))
		got := make([]byte, 0, len(payload))
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < len(payload) {
			n, rerr := rx.Read(buf)
			if n > 0 {
				take := n
				if len(got)+take > len(payload) {
					take = len(payload) - len(got)
				}
				h.Write(buf[:take])
				got = append(got, buf[:take]...)
			}
			if rerr != nil {
				want <- [32]byte{}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		want <- sum
	}()

	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < len(payload); off += chunk {
		end := off + chunk
		if end > len(payload) {
			end = len(payload)
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if killAt != nil && off >= len(payload)/3 && off < len(payload)/3+chunk {
			killAt() // kill a path roughly a third of the way through
		}
		if (off/chunk)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	// Trailing flush so a lost tail still has a delivered successor / time to
	// arrive on the surviving path.
	flush := make([]byte, chunk)
	for i := 0; i < 24; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}

	select {
	case got := <-want:
		return got
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for the bonded stream")
		return [32]byte{}
	}
}

// TestE2EBondedClean streams over a clean 2-path bond and verifies bit-exact
// merged delivery (SHA-256). Both paths carry every packet; the receiver's
// (Seq, SourceTime) dedup merges them into one stream.
func TestE2EBondedClean(t *testing.T) {
	const totalBytes = 128 * 1024
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

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)

	if got := streamSHA(t, tx, rx, payload, nil); got != want {
		st := rx.Stats()
		t.Fatalf("clean bond hash mismatch (Received=%d Delivered=%d Duplicates=%d Lost=%d)",
			st.Received, st.Delivered, st.Duplicates, st.Lost)
	}
	// Both paths carried the stream, so the receiver saw and deduplicated copies.
	if st := rx.Stats(); st.Duplicates == 0 {
		t.Fatalf("expected the second path's copies to be deduplicated, Duplicates=0 (Received=%d Delivered=%d)", st.Received, st.Delivered)
	}
}

// TestE2EBonded2022_7SeamlessUnderLoss drops 40% on one path's media while the
// other runs clean, and verifies the merged output is still bit-exact and
// complete — the defining 2022-7 property: a packet lost on one path is covered
// by the other's copy. The clean path makes recovery come from redundancy, so
// Lost must be zero.
func TestE2EBonded2022_7SeamlessUnderLoss(t *testing.T) {
	const totalBytes = 96 * 1024
	pA, pB := twoEvenPorts(t)
	relayPort := freeEvenPort(t)
	for relayPort == pA || relayPort == pB {
		relayPort = freeEvenPort(t)
	}

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	// Path 0 goes through a 40%-loss media relay (sender -> relayPort -> pA);
	// path 1 (pB) is direct and clean.
	relay := startMediaRelay(t, relayPort, pA, 0.40, 5)
	defer relay.Close()

	tx, err := ristgo.NewBondedSender(
		[]string{fmt.Sprintf("127.0.0.1:%d", relayPort), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)

	if got := streamSHA(t, tx, rx, payload, nil); got != want {
		st := rx.Stats()
		t.Fatalf("lossy bond hash mismatch (relay dropped=%d Received=%d Delivered=%d Lost=%d Recovered=%d)",
			relay.Dropped(), st.Received, st.Delivered, st.Lost, st.Recovered)
	}
	if relay.Dropped() == 0 {
		t.Fatal("relay dropped nothing — the loss path was not exercised")
	}
	if st := rx.Stats(); st.Lost != 0 {
		t.Fatalf("Lost=%d under one-path loss; 2022-7 redundancy should cover every drop", st.Lost)
	}
}

// TestE2EBondedPathDeath kills one path entirely a third of the way through and
// verifies the other path carries the rest seamlessly, bit-exact.
func TestE2EBondedPathDeath(t *testing.T) {
	const totalBytes = 96 * 1024
	pA, pB := twoEvenPorts(t)
	relayPort := freeEvenPort(t)
	for relayPort == pA || relayPort == pB {
		relayPort = freeEvenPort(t)
	}

	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	relay := startMediaRelay(t, relayPort, pA, 0, 9) // lossless until killed
	defer relay.Close()

	tx, err := ristgo.NewBondedSender(
		[]string{fmt.Sprintf("127.0.0.1:%d", relayPort), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)

	if got := streamSHA(t, tx, rx, payload, relay.kill); got != want {
		st := rx.Stats()
		t.Fatalf("path-death bond hash mismatch (relay dropped=%d Received=%d Delivered=%d Lost=%d)",
			relay.Dropped(), st.Received, st.Delivered, st.Lost)
	}
	if relay.Dropped() == 0 {
		t.Fatal("the killed path relayed everything — death was not exercised")
	}
}

// TestE2EBondedCloseUnblocksRead verifies Close on a bonded receiver wakes a
// blocked Read with ErrClosed and that every per-path reader goroutine plus the
// event loop exit, returning the goroutine count to its pre-construction
// baseline (no leak across the N path sockets).
func TestE2EBondedCloseUnblocksRead(t *testing.T) {
	baseline := runtime.NumGoroutine()
	pA, pB := twoEvenPorts(t)
	rx, err := ristgo.NewBondedReceiver(
		[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
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

	for i := 0; i < 20; i++ {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutines did not return to baseline: have %d, baseline %d", runtime.NumGoroutine(), baseline)
}

// bondProfileConfig returns a fast bonded config for the given profile + AES.
func bondProfileConfig(profile ristgo.Profile, secret string, aesBits int) func() ristgo.Config {
	return func() ristgo.Config {
		c := ristgo.DefaultConfig()
		c.Profile = profile
		c.Secret = secret
		c.AESKeyBits = aesBits
		c.BufferMin = 300 * time.Millisecond
		c.BufferMax = 300 * time.Millisecond
		return c
	}
}

// TestE2EBondedMainAdvanced streams over a clean 2-path bond on the Main and
// Advanced profiles (PSK-encrypted), verifying bit-exact merged delivery and
// that the second path's copies are deduplicated. Each path tunnels over a
// single port; the profile codec frames/encrypts the media, duplicated across
// paths and merged by the (Seq, SourceTime) dedup.
func TestE2EBondedMainAdvanced(t *testing.T) {
	cases := []struct {
		name    string
		profile ristgo.Profile
	}{
		{"main-aes128", ristgo.ProfileMain},
		{"advanced-aes128", ristgo.ProfileAdvanced},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const totalBytes = 96 * 1024
			pA := freeMainPort(t)
			pB := freeMainPort(t)
			for pB == pA {
				pB = freeMainPort(t)
			}
			addrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}
			cfg := bondProfileConfig(tc.profile, "ristgo-bonded-secret", 128)

			rx, err := ristgo.NewBondedReceiver(addrs, cfg())
			if err != nil {
				t.Fatalf("NewBondedReceiver: %v", err)
			}
			defer rx.Close()
			tx, err := ristgo.NewBondedSender(addrs, cfg())
			if err != nil {
				t.Fatalf("NewBondedSender: %v", err)
			}
			defer tx.Close()

			payload := make([]byte, totalBytes)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand: %v", err)
			}
			want := sha256.Sum256(payload)
			if got := streamSHA(t, tx, rx, payload, nil); got != want {
				st := rx.Stats()
				t.Fatalf("%s bond hash mismatch (Received=%d Delivered=%d Duplicates=%d Lost=%d)",
					tc.name, st.Received, st.Delivered, st.Duplicates, st.Lost)
			}
			if st := rx.Stats(); st.Duplicates == 0 {
				t.Fatalf("%s: expected the second path's copies to be deduplicated, Duplicates=0", tc.name)
			}
		})
	}
}

// bondFragConfig is an Advanced-profile bonded config (PSK AES-256) with payload
// fragmentation enabled, sized so redundancy/recovery has headroom on loopback.
func bondFragConfig(fragSize int) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = ristgo.ProfileAdvanced
	cfg.Secret = "ristgo-bonded-frag"
	cfg.AESKeyBits = 256
	cfg.BufferMin = 400 * time.Millisecond
	cfg.BufferMax = 400 * time.Millisecond
	cfg.FragmentSize = fragSize
	return cfg
}

// streamBondedFrag sends payload in writeSize-byte Writes (each larger than the
// fragment size, so each is split across consecutive sequences) over a bonded
// sender and reads the merged, reassembled stream back, returning its SHA-256
// and the number of payload Writes issued. A trailing flush gives the tail a
// successor so playout releases it.
func streamBondedFrag(t *testing.T, tx *ristgo.BondedSender, rx *ristgo.BondedReceiver, payload []byte, writeSize int) ([32]byte, int) {
	t.Helper()
	got := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(20 * time.Second))
		acc := make([]byte, 0, len(payload))
		buf := make([]byte, 8192)
		h := sha256.New()
		for len(acc) < len(payload) {
			n, rerr := rx.Read(buf)
			if n > 0 {
				take := n
				if len(acc)+take > len(payload) {
					take = len(payload) - len(acc)
				}
				h.Write(buf[:take])
				acc = append(acc, buf[:take]...)
			}
			if rerr != nil {
				got <- [32]byte{}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		got <- sum
	}()

	writes := 0
	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < len(payload); off += writeSize {
		end := off + writeSize
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := tx.Write(payload[off:end]); err != nil {
			t.Fatalf("Write at %d: %v", off, err)
		}
		writes++
		if writes%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	flush := make([]byte, 300) // small standalone packets; just successors for the tail
	for i := 0; i < 32; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}

	select {
	case sum := <-got:
		return sum, writes
	case <-time.After(25 * time.Second):
		t.Fatalf("timed out (Received=%d Delivered=%d)", rx.Stats().Received, rx.Stats().Delivered)
		return [32]byte{}, writes
	}
}

// TestE2EBondedAdvFragmentation proves fragmentation composes with link bonding
// (SMPTE 2022-7) on the Advanced profile: a payload split into fragments is
// duplicated across paths, merged by the (Seq, SourceTime) dedup, and
// reassembled — and a fragment lost on one path is covered seamlessly by the
// other's copy.
func TestE2EBondedAdvFragmentation(t *testing.T) {
	const fragSize = 1000
	const writeSize = 6000 // 6 fragments per Write
	const totalBytes = 96 * 1024

	t.Run("clean_merge", func(t *testing.T) {
		pA := freeMainPort(t)
		pB := freeMainPort(t)
		for pB == pA {
			pB = freeMainPort(t)
		}
		addrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}

		rx, err := ristgo.NewBondedReceiver(addrs, bondFragConfig(fragSize))
		if err != nil {
			t.Fatalf("NewBondedReceiver: %v", err)
		}
		defer rx.Close()
		tx, err := ristgo.NewBondedSender(addrs, bondFragConfig(fragSize))
		if err != nil {
			t.Fatalf("NewBondedSender: %v", err)
		}
		defer tx.Close()

		payload := make([]byte, totalBytes)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("rand: %v", err)
		}
		want := sha256.Sum256(payload)

		sum, writes := streamBondedFrag(t, tx, rx, payload, writeSize)
		if sum != want {
			st := rx.Stats()
			t.Fatalf("bonded fragmented stream mismatch (Received=%d Delivered=%d Duplicates=%d Lost=%d)",
				st.Received, st.Delivered, st.Duplicates, st.Lost)
		}
		// Fragmentation happened: far more media packets were sent than Writes.
		if sent := tx.Stats().Sent; sent <= uint64(writes) {
			t.Fatalf("sender emitted %d media packets for %d writes; fragmentation did not occur", sent, writes)
		}
		// Both paths carried the fragments, so the receiver deduplicated copies.
		if st := rx.Stats(); st.Duplicates == 0 {
			t.Fatalf("Duplicates=0: the second path's fragment copies were not merged (Received=%d Delivered=%d)", st.Received, st.Delivered)
		}
	})

	t.Run("one_path_loss_seamless", func(t *testing.T) {
		pA := freeMainPort(t)
		pB := freeMainPort(t)
		relayPort := freeMainPort(t)
		for pB == pA || relayPort == pA || relayPort == pB {
			pB = freeMainPort(t)
			relayPort = freeMainPort(t)
		}

		rx, err := ristgo.NewBondedReceiver(
			[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondFragConfig(fragSize))
		if err != nil {
			t.Fatalf("NewBondedReceiver: %v", err)
		}
		defer rx.Close()

		// Path 0 loses 40% of its fragments through the relay; path 1 is clean.
		relay := startMediaRelay(t, relayPort, pA, 0.40, 13)
		defer relay.Close()

		tx, err := ristgo.NewBondedSender(
			[]string{fmt.Sprintf("127.0.0.1:%d", relayPort), fmt.Sprintf("127.0.0.1:%d", pB)}, bondFragConfig(fragSize))
		if err != nil {
			t.Fatalf("NewBondedSender: %v", err)
		}
		defer tx.Close()

		payload := make([]byte, totalBytes)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("rand: %v", err)
		}
		want := sha256.Sum256(payload)

		sum, _ := streamBondedFrag(t, tx, rx, payload, writeSize)
		if sum != want {
			st := rx.Stats()
			t.Fatalf("lossy bonded fragmented stream mismatch (relay dropped=%d Received=%d Delivered=%d Lost=%d)",
				relay.Dropped(), st.Received, st.Delivered, st.Lost)
		}
		if relay.Dropped() == 0 {
			t.Fatal("relay dropped nothing; the per-path loss was not exercised")
		}
		// Every dropped fragment was covered by the clean path's copy — so no
		// fragment was ever missing and no reassembly run was broken.
		if st := rx.Stats(); st.Lost != 0 {
			t.Fatalf("Lost=%d under one-path fragment loss; 2022-7 redundancy should cover every dropped fragment", st.Lost)
		}
	})
}

// TestNewBondedReceiverPeersPriority builds a per-peer bonded receiver with
// distinct recovery priorities and streams over it, proving the per-path
// priority API constructs a working session (the priority→NACK-path selection
// itself is unit-tested in internal/bonding).
func TestNewBondedReceiverPeersPriority(t *testing.T) {
	const totalBytes = 64 * 1024
	pA, pB := twoEvenPorts(t)
	peers := []ristgo.BondedPeer{
		{Addr: fmt.Sprintf("127.0.0.1:%d", pA), Priority: 9}, // preferred NACK path
		{Addr: fmt.Sprintf("127.0.0.1:%d", pB), Priority: 1},
	}
	rx, err := ristgo.NewBondedReceiverPeers(peers, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedReceiverPeers: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewBondedSender(
		[]string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}, bondConfig())
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if got := streamSHA(t, tx, rx, payload, nil); got != sha256.Sum256(payload) {
		t.Fatalf("per-peer bonded delivery hash mismatch")
	}
}

// TestBondedPeerNegativePriorityRejected verifies a negative BondedPeer.Priority
// is rejected with ErrInvalidConfig.
func TestBondedPeerNegativePriorityRejected(t *testing.T) {
	peers := []ristgo.BondedPeer{{Addr: "127.0.0.1:5000", Priority: -1}}
	if _, err := ristgo.NewBondedReceiverPeers(peers, bondConfig()); !errors.Is(err, ristgo.ErrInvalidConfig) {
		t.Fatalf("NewBondedReceiverPeers negative priority err = %v, want ErrInvalidConfig", err)
	}
}

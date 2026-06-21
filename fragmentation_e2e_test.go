package ristgo_test

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// countingProxy sits on one UDP port between an Advanced sender and receiver,
// forwarding every datagram intact (no loss) and counting forward
// (sender->receiver) datagrams — a wire-level witness of how many packets the
// sender actually puts on the network.
type countingProxy struct {
	sock     *net.UDPConn
	recvAddr *net.UDPAddr
	forward  atomic.Uint64
	mu       sync.Mutex
	sender   *net.UDPAddr
	wg       sync.WaitGroup
}

func startCountingProxy(t *testing.T, proxyPort, recvPort int) *countingProxy {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort})
	if err != nil {
		t.Fatalf("counting proxy bind: %v", err)
	}
	p := &countingProxy{sock: sock, recvAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort}}
	p.wg.Add(1)
	go p.relay()
	return p
}

// Forwarded reports how many sender->receiver datagrams crossed the proxy.
func (p *countingProxy) Forwarded() uint64 { return p.forward.Load() }

func (p *countingProxy) relay() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if src.Port == p.recvAddr.Port && src.IP.Equal(p.recvAddr.IP) {
			p.mu.Lock()
			s := p.sender
			p.mu.Unlock()
			if s != nil {
				p.sock.WriteToUDP(buf[:n], s)
			}
			continue
		}
		p.mu.Lock()
		p.sender = src
		p.mu.Unlock()
		p.forward.Add(1)
		p.sock.WriteToUDP(buf[:n], p.recvAddr)
	}
}

func (p *countingProxy) Close() { p.sock.Close(); p.wg.Wait() }

// fragConfig is an Advanced-profile config with payload fragmentation enabled at
// the given fragment size, plus optional PSK. Buffers are sized so per-fragment
// ARQ has headroom on loopback.
func fragConfig(secret string, aesBits, fragSize int) ristgo.Config {
	cfg := advConfig(secret, aesBits, false)
	cfg.FragmentSize = fragSize
	cfg.BufferMin = 500 * time.Millisecond
	cfg.BufferMax = 500 * time.Millisecond
	return cfg
}

// streamFragmented sends payload in writeSize-byte Writes (each larger than the
// fragment size, so each is split into several recoverable fragments) and reads
// the reassembled stream back, returning its SHA-256. tx addresses sendAddr.
func streamFragmented(t *testing.T, tx *ristgo.Sender, rx *ristgo.Receiver, payload []byte, writeSize int) [32]byte {
	t.Helper()
	total := len(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(20 * time.Second))
		got := make([]byte, 0, total)
		buf := make([]byte, 8192)
		h := sha256.New()
		for len(got) < total {
			n, rerr := rx.Read(buf)
			if n > 0 {
				take := n
				if len(got)+take > total {
					take = total - len(got)
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
	for off := 0; off < total; off += writeSize {
		end := off + writeSize
		if end > total {
			end = total
		}
		if _, err := tx.Write(payload[off:end]); err != nil {
			t.Fatalf("Write at %d (%d bytes): %v", off, end-off, err)
		}
		if (off/writeSize)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}

	select {
	case sum := <-done:
		return sum
	case <-time.After(25 * time.Second):
		t.Fatalf("timed out (delivered=%d)", rx.Stats().Delivered)
		return [32]byte{}
	}
}

// TestE2EAdvFragmentationClean proves the full sender-split → in-order delivery →
// receiver-reassembly pipeline on a clean link: Writes several times larger than
// the fragment size arrive bit-identical (SHA-256), cleartext and AES-256.
func TestE2EAdvFragmentationClean(t *testing.T) {
	const totalBytes = 256 * 1024
	const writeSize = 7000 // 7 fragments per Write at fragSize 1000
	const fragSize = 1000

	cases := []struct {
		name    string
		secret  string
		aesBits int
	}{
		{"cleartext", "", 0},
		{"aes256", "ristgo-frag-secret", 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := freeMainPort(t)
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			cfg := fragConfig(tc.secret, tc.aesBits, fragSize)

			rx, err := ristgo.NewReceiver(addr, cfg)
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			defer rx.Close()
			tx, err := ristgo.NewSender(addr, cfg)
			if err != nil {
				t.Fatalf("NewSender: %v", err)
			}
			defer tx.Close()

			payload := advPayload(t, totalBytes, false)
			want := sha256.Sum256(payload)
			if got := streamFragmented(t, tx, rx, payload, writeSize); got != want {
				t.Fatalf("reassembled stream hash mismatch (delivered=%d)", rx.Stats().Delivered)
			}
		})
	}
}

// TestE2EAdvFragmentationLossRecovery proves per-fragment ARQ: a fragmented
// stream through a 10%-loss media path is still reassembled bit-identical,
// because each lost fragment is an independently recoverable sequence.
func TestE2EAdvFragmentationLossRecovery(t *testing.T) {
	const totalBytes = 128 * 1024
	const writeSize = 5000 // 5 fragments per Write at fragSize 1000
	const fragSize = 1000

	recvPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == recvPort {
		proxyPort = freeMainPort(t)
	}

	cfg := fragConfig("ristgo-frag-secret", 256, fragSize)

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startMainLossyProxy(t, proxyPort, recvPort, 0.10, 9)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	payload := advPayload(t, totalBytes, false)
	want := sha256.Sum256(payload)
	if got := streamFragmented(t, tx, rx, payload, writeSize); got != want {
		t.Fatalf("lossy fragmented stream not recovered: hash mismatch (recovered=%d lost=%d)",
			rx.Stats().Recovered, rx.Stats().Lost)
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped nothing; loss path not exercised")
	}
	if rx.Stats().Recovered == 0 {
		t.Fatal("no fragments recovered; per-fragment ARQ not exercised")
	}
}

// TestE2EAdvFragmentationBoundariesCompression streams Writes at sizes straddling
// the fragment boundary (fits-in-one, one-over, exact multiples, odd remainder)
// with LZ4 compression on, and verifies the reassembled stream is bit-identical.
// It exercises the split at its edges and the fragment×compression interaction.
func TestE2EAdvFragmentationBoundariesCompression(t *testing.T) {
	const fragSize = 1000

	port := freeMainPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cfg := fragConfig("ristgo-frag-secret", 256, fragSize)
	cfg.Compression = true // LZ4 on, per fragment

	rx, err := ristgo.NewReceiver(addr, cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	// Boundary sizes: standalone (<= fragSize), one-over, exact multiples, odd
	// remainder, and the max-Write cap (fragSize × the 64-fragment cap).
	// Compressible content so LZ4 engages per fragment.
	sizes := []int{1, fragSize - 1, fragSize, fragSize + 1, 2 * fragSize, 3*fragSize + 7, fragSize * 64}
	var stream []byte
	for i, sz := range sizes {
		blk := make([]byte, sz)
		for k := range blk {
			blk[k] = byte((i*7 + k) % 251) // deterministic, compressible-ish, varied
		}
		stream = append(stream, blk...)
	}
	want := sha256.Sum256(stream)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(15 * time.Second))
		got := make([]byte, 0, len(stream))
		buf := make([]byte, 8192)
		h := sha256.New()
		for len(got) < len(stream) {
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
	off := 0
	for _, sz := range sizes {
		if _, err := tx.Write(stream[off : off+sz]); err != nil {
			t.Fatalf("Write size %d: %v", sz, err)
		}
		off += sz
		time.Sleep(2 * time.Millisecond)
	}

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("boundary/compression stream hash mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	case <-time.After(18 * time.Second):
		t.Fatalf("timed out (delivered=%d)", rx.Stats().Delivered)
	}
}

// TestOneWayFragmentationCleanAndLossy exercises the two new features together.
// Clean: a one-way (no-recovery) fragmented stream reassembles bit-identical.
// Lossy: with fragments genuinely lost and never recovered, every payload the
// receiver DOES deliver is a complete, correct block (no partial or misjoined
// reassembly), some blocks are dropped, and nothing is recovered — the discard
// path an ARQ-recovering test can't reach.
func TestOneWayFragmentationCleanAndLossy(t *testing.T) {
	const blockSize = 4500 // 5 fragments at fragSize 1000 (last is 500)
	const fragSize = 1000
	const blocks = 400

	mkBlock := func(i int) []byte {
		b := make([]byte, blockSize)
		binary.BigEndian.PutUint32(b, uint32(i))
		for k := 4; k < blockSize; k++ {
			b[k] = byte((i + k) & 0xFF)
		}
		return b
	}
	// verify reports the stamped index and whether the block is a complete,
	// correct original (right length and every byte matching its pattern).
	verify := func(b []byte) (int, bool) {
		if len(b) != blockSize {
			return -1, false
		}
		i := int(binary.BigEndian.Uint32(b))
		for k := 4; k < blockSize; k++ {
			if b[k] != byte((i+k)&0xFF) {
				return i, false
			}
		}
		return i, true
	}

	t.Run("clean", func(t *testing.T) {
		port := freeMainPort(t)
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		cfg := fragConfig("", 0, fragSize)

		rx, err := ristgo.NewOneWayReceiver(addr, cfg)
		if err != nil {
			t.Fatalf("NewOneWayReceiver: %v", err)
		}
		defer rx.Close()
		tx, err := ristgo.NewOneWaySender(addr, cfg)
		if err != nil {
			t.Fatalf("NewOneWaySender: %v", err)
		}
		defer tx.Close()

		var stream []byte
		for i := 0; i < blocks; i++ {
			stream = append(stream, mkBlock(i)...)
		}
		want := sha256.Sum256(stream)
		if got := streamFragmented(t, tx, rx, stream, blockSize); got != want {
			t.Fatalf("clean one-way fragmented stream mismatch (delivered=%d)", rx.Stats().Delivered)
		}
	})

	t.Run("lossy_discard", func(t *testing.T) {
		recvPort := freeMainPort(t)
		proxyPort := freeMainPort(t)
		for proxyPort == recvPort {
			proxyPort = freeMainPort(t)
		}
		cfg := fragConfig("", 0, fragSize)

		rx, err := ristgo.NewOneWayReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
		if err != nil {
			t.Fatalf("NewOneWayReceiver: %v", err)
		}
		defer rx.Close()
		proxy := startMainLossyProxy(t, proxyPort, recvPort, 0.08, 11)
		defer proxy.Close()
		tx, err := ristgo.NewOneWaySender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
		if err != nil {
			t.Fatalf("NewOneWaySender: %v", err)
		}
		defer tx.Close()

		type result struct {
			delivered int
			badIdx    int
			ok        bool
		}
		res := make(chan result, 1)
		go func() {
			rx.SetReadDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, blockSize)
			delivered := 0
			for {
				n, rerr := rx.Read(buf)
				if n > 0 {
					if idx, valid := verify(buf[:n]); !valid {
						res <- result{delivered, idx, false}
						return
					}
					delivered++
				}
				if rerr != nil {
					res <- result{delivered, 0, true}
					return
				}
			}
		}()

		tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
		for i := 0; i < blocks; i++ {
			if _, err := tx.Write(mkBlock(i)); err != nil {
				t.Fatalf("Write %d: %v", i, err)
			}
			if i%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}

		r := <-res
		if !r.ok {
			t.Fatalf("delivered a partial/misjoined block at index %d — reassembly is incorrect", r.badIdx)
		}
		if proxy.Dropped() == 0 {
			t.Fatal("proxy dropped nothing; loss path not exercised")
		}
		if r.delivered == 0 || r.delivered >= blocks {
			t.Fatalf("delivered %d of %d blocks; want some dropped and some delivered", r.delivered, blocks)
		}
		if st := rx.Stats(); st.Recovered != 0 || st.NACKsSent != 0 {
			t.Fatalf("one-way recovered loss: Recovered=%d NACKsSent=%d, want 0/0", st.Recovered, st.NACKsSent)
		}
	})
}

// TestE2EAdvFragmentationProvenOnWire is the top-level proof that fragmentation
// is the actual mechanism, not an incidental bit-exact stream. It runs the SAME
// data through the SAME public API twice, differing only in Config.FragmentSize,
// with a datagram-counting proxy on the wire:
//
//   - The payload (1400 bytes) is small enough to send as a single packet, so it
//     is a valid Write with fragmentation OFF too — isolating FragmentSize as the
//     only variable.
//   - Proof the SENDER fragments: with FragmentSize=500 it emits exactly 3 media
//     packets per Write (Stats.Sent == writes×3); with it off, exactly 1 per
//     Write. The wire-level forward count grows in step.
//   - Proof the RECEIVER reassembles: in BOTH runs the application reads back the
//     same number of whole 1400-byte payloads. Since a fragment is at most 500
//     bytes, a delivered 1400-byte payload in the fragmented run could only have
//     been reassembled from several fragments.
//
// A bit-exact stream alone could not distinguish these; the packet counts can.
func TestE2EAdvFragmentationProvenOnWire(t *testing.T) {
	const fragSize = 500
	const writeSize = 1400  // <= MaxMediaPayload: a valid Write with or without fragmentation
	const fragsPerWrite = 3 // ceil(1400/500)
	const writes = 80

	mkBlock := func(i int) []byte {
		b := make([]byte, writeSize)
		binary.BigEndian.PutUint32(b, uint32(i))
		for k := 4; k < writeSize; k++ {
			b[k] = byte((i + k) & 0xFF)
		}
		return b
	}
	verify := func(b []byte) bool {
		if len(b) != writeSize {
			return false
		}
		i := int(binary.BigEndian.Uint32(b))
		for k := 4; k < writeSize; k++ {
			if b[k] != byte((i+k)&0xFF) {
				return false
			}
		}
		return true
	}

	type runResult struct {
		sent      uint64
		forwarded uint64
		delivered int
		corrupt   bool
	}
	run := func(t *testing.T, fragEnabled bool) runResult {
		recvPort := freeMainPort(t)
		proxyPort := freeMainPort(t)
		for proxyPort == recvPort {
			proxyPort = freeMainPort(t)
		}
		cfg := advConfig("", 0, false)
		cfg.BufferMin = 200 * time.Millisecond
		cfg.BufferMax = 200 * time.Millisecond
		if fragEnabled {
			cfg.FragmentSize = fragSize
		}

		rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
		if err != nil {
			t.Fatalf("NewReceiver: %v", err)
		}
		defer rx.Close()
		proxy := startCountingProxy(t, proxyPort, recvPort)
		defer proxy.Close()
		tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
		if err != nil {
			t.Fatalf("NewSender: %v", err)
		}
		defer tx.Close()

		res := make(chan runResult, 1)
		go func() {
			rx.SetReadDeadline(time.Now().Add(8 * time.Second))
			buf := make([]byte, writeSize)
			r := runResult{}
			for r.delivered < writes {
				n, rerr := rx.Read(buf)
				if n > 0 {
					if !verify(buf[:n]) { // wrong length or content => bad reassembly
						r.corrupt = true
						res <- r
						return
					}
					r.delivered++
				}
				if rerr != nil {
					break
				}
			}
			res <- r
		}()

		tx.SetWriteDeadline(time.Now().Add(8 * time.Second))
		for i := 0; i < writes; i++ {
			if _, err := tx.Write(mkBlock(i)); err != nil {
				t.Fatalf("Write %d: %v", i, err)
			}
			if i%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}

		r := <-res
		time.Sleep(150 * time.Millisecond) // let any trailing datagrams reach the proxy counter
		r.sent = tx.Stats().Sent
		r.forwarded = proxy.Forwarded()
		return r
	}

	frag := run(t, true)
	ctrl := run(t, false)

	if frag.corrupt || ctrl.corrupt {
		t.Fatalf("a delivered payload was the wrong length/content (frag corrupt=%v, ctrl corrupt=%v)", frag.corrupt, ctrl.corrupt)
	}

	// Proof the sender fragments: exactly fragsPerWrite media packets per Write
	// when enabled, exactly one when not.
	if frag.sent != writes*fragsPerWrite {
		t.Errorf("fragmented sender emitted %d media packets, want %d (%d writes × %d fragments)",
			frag.sent, writes*fragsPerWrite, writes, fragsPerWrite)
	}
	if ctrl.sent != writes {
		t.Errorf("unfragmented sender emitted %d media packets, want %d (one per write)", ctrl.sent, writes)
	}

	// Proof the fragments crossed the wire: the forward datagram count scales
	// with fragmentation (>= the media floor, and well above the unfragmented run).
	if frag.forwarded < writes*fragsPerWrite {
		t.Errorf("fragmented wire carried %d datagrams, want >= %d", frag.forwarded, writes*fragsPerWrite)
	}
	if frag.forwarded <= ctrl.forwarded {
		t.Errorf("wire datagram count did not grow with fragmentation: frag=%d, control=%d", frag.forwarded, ctrl.forwarded)
	}

	// Proof the receiver reassembles: both runs hand the application the same
	// number of whole writeSize-byte payloads, even though the fragmented run put
	// fragsPerWrite× the packets on the wire.
	if frag.delivered != writes || ctrl.delivered != writes {
		t.Errorf("delivered payloads: fragmented=%d, control=%d, want %d each", frag.delivered, ctrl.delivered, writes)
	}

	t.Logf("proven: %d writes -> sender packets frag=%d vs control=%d; wire datagrams frag=%d vs control=%d; app payloads frag=%d vs control=%d",
		writes, frag.sent, ctrl.sent, frag.forwarded, ctrl.forwarded, frag.delivered, ctrl.delivered)
}

// TestFragmentationConfigAndWriteErrors covers fragmentation's input validation:
// FragmentSize is Advanced-only and bounded by MaxMediaPayload, and a Write
// larger than the per-Write fragment cap is rejected.
func TestFragmentationConfigAndWriteErrors(t *testing.T) {
	simple := ristgo.DefaultConfig()
	simple.Profile = ristgo.ProfileSimple // DefaultConfig is Advanced, which allows FragmentSize
	simple.FragmentSize = 1000

	main := ristgo.DefaultConfig()
	main.Profile = ristgo.ProfileMain
	main.FragmentSize = 1000

	tooBig := ristgo.DefaultConfig()
	tooBig.Profile = ristgo.ProfileAdvanced
	tooBig.FragmentSize = ristgo.MaxMediaPayload + 1

	t.Run("simple rejected", func(t *testing.T) {
		if _, err := ristgo.NewSender("127.0.0.1:5000", simple); err == nil {
			t.Fatal("FragmentSize on Simple should be rejected")
		}
	})
	t.Run("main rejected", func(t *testing.T) {
		if _, err := ristgo.NewSender("127.0.0.1:5000", main); err == nil {
			t.Fatal("FragmentSize on Main should be rejected")
		}
	})
	t.Run("over max rejected", func(t *testing.T) {
		if _, err := ristgo.NewSender("127.0.0.1:5000", tooBig); err == nil {
			t.Fatal("FragmentSize > MaxMediaPayload should be rejected")
		}
	})

	t.Run("oversized write rejected", func(t *testing.T) {
		port := freeMainPort(t)
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		tx, err := ristgo.NewSender(addr, fragConfig("", 0, 1000))
		if err != nil {
			t.Fatalf("NewSender: %v", err)
		}
		defer tx.Close()
		// Cap is FragmentSize * 64 = 64000; one byte over must be rejected.
		if _, err := tx.Write(make([]byte, 1000*64+1)); err == nil {
			t.Fatal("Write past the fragment cap should be rejected")
		}
	})
}

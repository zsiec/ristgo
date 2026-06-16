package ristgo_test

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// canonicalNullTS builds one MPEG-TS null packet byte-for-byte as both ristgo
// (npd.appendNullPacket) and libRIST (expand_null_packets) reconstruct one:
// 0x47 sync, flags1 = 0x1FFF (the null PID), flags2 with bit 4 set (0x10), then
// 0xFF fill. Because reconstruction is canonical, a payload whose null packets
// are already in this exact form round-trips byte-exact through NPD suppression
// and expansion — a non-canonical null would come back as this canonical form
// and fail a byte comparison (the deliberate NPD deviation documented in the npd
// package).
func canonicalNullTS(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x47
	p[1] = 0x1F
	p[2] = 0xFF
	p[3] = 0x10
	for i := 4; i < size; i++ {
		p[i] = 0xFF
	}
	return p
}

// contentTS builds one non-null MPEG-TS packet: 0x47 sync, PID 0x0100 (any value
// other than the 0x1FFF null PID), then a seq-derived fill so distinct packets
// differ. NPD passes it through unchanged.
func contentTS(size, seq int) []byte {
	p := make([]byte, size)
	p[0] = 0x47
	p[1] = 0x01 // flags1 = 0x0100 — not the 0x1FFF null PID
	p[2] = 0x00
	p[3] = 0x10
	for i := 4; i < size; i++ {
		p[i] = byte(seq*31 + i)
	}
	return p
}

// buildTSWithNulls returns frames media frames of 7 TS packets each (7*188 =
// 1316 bytes, the canonical 7-cell MPEG-TS RTP payload). Each frame holds one
// content packet at a rotating position and six canonical null packets, so NPD
// suppresses 6 of every 7 packets — a dramatic, easily-witnessed reduction — and
// the rotating position exercises the full 7-bit null bitmap. The returned
// payload is a whole number of 1316-byte frames so each Sender.Write maps 1:1 to
// one ≤7-packet media packet that NPD can act on.
func buildTSWithNulls(frames int) []byte {
	const ts = 188
	const perFrame = 7
	out := make([]byte, 0, frames*perFrame*ts)
	for f := 0; f < frames; f++ {
		content := f % perFrame
		for i := 0; i < perFrame; i++ {
			if i == content {
				out = append(out, contentTS(ts, f)...)
			} else {
				out = append(out, canonicalNullTS(ts)...)
			}
		}
	}
	return out
}

// countingMainRelay forwards a Main-profile flow between a sender (which
// addresses the relay) and a receiver, passing every datagram through intact and
// counting the bytes forwarded sender->receiver. It is the witness that NPD
// actually shrank the stream on the wire: the same payload sent with NPD on
// forwards far fewer media bytes than with NPD off. Like mainLossyProxy it
// demuxes by source address (the Main profile is a single GRE port whose inner
// payload-type byte may be encrypted), relaying receiver->sender datagrams so
// keepalives and feedback keep the session alive.
type countingMainRelay struct {
	sock     *net.UDPConn
	recvAddr *net.UDPAddr
	fwd      atomic.Uint64
	mu       sync.Mutex
	sender   *net.UDPAddr
	wg       sync.WaitGroup
}

// startCountingMainRelay binds on proxyPort and relays to the receiver on
// recvPort. The caller must Close it.
func startCountingMainRelay(t *testing.T, proxyPort, recvPort int) *countingMainRelay {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort})
	if err != nil {
		t.Fatalf("counting relay bind: %v", err)
	}
	p := &countingMainRelay{
		sock:     sock,
		recvAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort},
	}
	p.wg.Add(1)
	go p.relay()
	return p
}

// Forwarded reports the total bytes forwarded sender->receiver.
func (p *countingMainRelay) Forwarded() uint64 { return p.fwd.Load() }

func (p *countingMainRelay) relay() {
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
		p.fwd.Add(uint64(n))
		p.sock.WriteToUDP(buf[:n], p.recvAddr)
	}
}

// Close stops the relay.
func (p *countingMainRelay) Close() { p.sock.Close(); p.wg.Wait() }

// streamNPDMain runs one Main-profile session through a counting relay: the
// sender (NPD per npdOn) writes payload one 1316-byte frame per Write, the
// receiver reassembles it, and the function asserts byte-exact delivery and
// returns the bytes the relay forwarded sender->receiver. payload must be a whole
// number of 1316-byte frames.
func streamNPDMain(t *testing.T, secret string, aesBits int, npdOn bool, payload []byte) uint64 {
	t.Helper()
	const frameLen = 7 * 188

	goPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == goPort {
		proxyPort = freeMainPort(t)
	}

	rxCfg := mainConfig(secret, aesBits)
	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), rxCfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	relay := startCountingMainRelay(t, proxyPort, goPort)
	defer relay.Close()

	txCfg := mainConfig(secret, aesBits)
	txCfg.NullPacketDeletion = npdOn
	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), txCfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	want := sha256.Sum256(payload)
	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, 0, len(payload))
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < len(payload) {
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
	for off := 0; off < len(payload); off += frameLen {
		end := off + frameLen
		if end > len(payload) {
			end = len(payload)
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if (off/frameLen)%16 == 0 {
			time.Sleep(time.Millisecond)
		}
	}

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("NPD(%v) delivery hash mismatch (delivered=%d)", npdOn, rx.Stats().Delivered)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("NPD(%v) timed out (delivered=%d)", npdOn, rx.Stats().Delivered)
	}
	return relay.Forwarded()
}

// TestE2EMainNPDByteExactAndSuppressed proves the integrated Main-profile NPD
// send path end to end over real UDP: a TS stream that is 6/7 null packets is
// delivered byte-exact with NPD on (the canonical nulls reconstruct identically),
// and a byte-counting relay witnesses that NPD on actually shrank the stream on
// the wire — it forwards far fewer media bytes than the same stream with NPD off.
// Byte-exactness alone would pass with NPD off, so the wire-byte comparison is
// what proves suppression engaged; the codec/fuzz tests in internal/npd cover the
// suppress/expand math, and this covers Config.NullPacketDeletion -> the running
// session -> the wire. It also runs with AES-128 to prove NPD composes with PSK
// encryption.
func TestE2EMainNPDByteExactAndSuppressed(t *testing.T) {
	const frames = 96
	payload := buildTSWithNulls(frames)
	rawMedia := uint64(len(payload)) // 96 * 1316 bytes of media submitted

	t.Run("cleartext", func(t *testing.T) {
		fwdOn := streamNPDMain(t, "", 0, true, payload)
		fwdOff := streamNPDMain(t, "", 0, false, payload)
		// NPD suppresses 6 of every 7 TS packets, so the forwarded media must
		// shrink dramatically. Assert a conservative halving (the real reduction
		// is ~6x) so GRE/RTCP overhead and keepalives never make this flaky.
		if fwdOn*2 >= fwdOff {
			t.Fatalf("NPD did not shrink the wire stream: forwarded on=%d off=%d (raw media=%d)", fwdOn, fwdOff, rawMedia)
		}
		t.Logf("NPD on forwarded %d bytes vs %d off (raw media %d) — %.1fx reduction",
			fwdOn, fwdOff, rawMedia, float64(fwdOff)/float64(fwdOn))
	})

	t.Run("aes128", func(t *testing.T) {
		// Byte-exact with NPD + PSK proves §8.6.2 composition (FEC/crypto over the
		// canonicalized payload); the cleartext subtest already witnessed suppression.
		if fwd := streamNPDMain(t, "ristgo-npd-secret", 128, true, payload); fwd == 0 {
			t.Fatal("relay forwarded no bytes")
		}
	})
}

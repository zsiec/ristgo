package ristgo_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// fecLossyProxy is a bidirectional single-port proxy for the FEC e2e: it forwards
// the reverse channel (RTCP/handshake) reliably, and on the forward channel drops
// a fraction of media-sized datagrams AFTER a warmup, so the first media packet
// always arrives and the receiver's FEC matrix aligns to the sender's ISN.
type fecLossyProxy struct {
	front, back *net.UDPConn
	recvAddr    *net.UDPAddr
	loss        float64
	minSize     int
	warmup      int
	rng         *mrand.Rand
	mu          sync.Mutex
	senderAddr  *net.UDPAddr
	seen        int
	dropped     atomic.Uint64
	wg          sync.WaitGroup
}

func startFECLossyProxy(t *testing.T, proxyPort, recvPort int, loss float64, warmup int, seed uint64) *fecLossyProxy {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort})
	if err != nil {
		t.Fatalf("fec proxy front bind: %v", err)
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		front.Close()
		t.Fatalf("fec proxy back bind: %v", err)
	}
	p := &fecLossyProxy{
		front:    front,
		back:     back,
		recvAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: recvPort},
		loss:     loss,
		minSize:  256,
		warmup:   warmup,
		rng:      mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)),
	}
	p.wg.Add(2)
	go p.forward()
	go p.backward()
	return p
}

func (p *fecLossyProxy) forward() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.senderAddr = src
		large := n >= p.minSize
		if large {
			p.seen++
		}
		drop := large && p.seen > p.warmup && p.rng.Float64() < p.loss
		p.mu.Unlock()
		if drop {
			p.dropped.Add(1)
			continue
		}
		p.back.WriteToUDP(buf[:n], p.recvAddr)
	}
}

func (p *fecLossyProxy) backward() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := p.back.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		dst := p.senderAddr
		p.mu.Unlock()
		if dst != nil {
			p.front.WriteToUDP(buf[:n], dst)
		}
	}
}

func (p *fecLossyProxy) Dropped() uint64 { return p.dropped.Load() }
func (p *fecLossyProxy) Close()          { p.front.Close(); p.back.Close(); p.wg.Wait() }

// fecSepProxy is a one-way 3-port proxy for the separate-port FEC test: it relays
// the media port (dropping one media packet per matrix, deterministically, after a
// warmup) and relays the column and row FEC ports reliably. Because FEC rides
// dedicated ports, it can drop media only — so a one-way receiver (no ARQ) must
// recover the drops by FEC alone.
type fecSepProxy struct {
	inMedia, inCol, inRow *net.UDPConn
	out                   *net.UDPConn
	dstIP                 net.IP
	dstMedia              int
	warmup, period, off   int
	mu                    sync.Mutex
	seen                  int
	dropped               atomic.Uint64
	wg                    sync.WaitGroup
}

func startFECSepProxy(t *testing.T, proxyMedia int, dstHost string, dstMedia, warmup, period, off int) *fecSepProxy {
	t.Helper()
	bindp := func(port int) *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("fec proxy bind %d: %v", port, err)
		}
		return c
	}
	out, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fec proxy out: %v", err)
	}
	p := &fecSepProxy{
		inMedia: bindp(proxyMedia), inCol: bindp(proxyMedia + 2), inRow: bindp(proxyMedia + 4),
		out:      out,
		dstIP:    net.IPv4(127, 0, 0, 1),
		dstMedia: dstMedia, warmup: warmup, period: period, off: off,
	}
	p.wg.Add(3)
	go p.relayMedia()
	go p.relay(p.inCol, dstMedia+2)
	go p.relay(p.inRow, dstMedia+4)
	return p
}

func (p *fecSepProxy) relayMedia() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := p.inMedia.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		i := p.seen
		p.seen++
		p.mu.Unlock()
		if i >= p.warmup && (i-p.warmup)%p.period == p.off {
			p.dropped.Add(1)
			continue // drop one media packet per matrix (FEC-recoverable)
		}
		p.out.WriteToUDP(buf[:n], &net.UDPAddr{IP: p.dstIP, Port: p.dstMedia})
	}
}

func (p *fecSepProxy) relay(in *net.UDPConn, dstPort int) {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := in.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.out.WriteToUDP(buf[:n], &net.UDPAddr{IP: p.dstIP, Port: dstPort})
	}
}

func (p *fecSepProxy) Dropped() uint64 { return p.dropped.Load() }
func (p *fecSepProxy) Close() {
	p.inMedia.Close()
	p.inCol.Close()
	p.inRow.Close()
	p.out.Close()
	p.wg.Wait()
}

// TestE2EFECSeparatePortsSimple runs a one-way Simple-profile stream with 2-D
// SMPTE 2022-1 FEC on separate UDP ports (the standard, interoperable carriage),
// dropping one media packet per matrix. With no return channel (no ARQ), the
// stream still reconstructs bit-exact, proving FEC alone recovered every loss.
func TestE2EFECSeparatePortsSimple(t *testing.T) {
	runSepPortsSimpleFEC(t, &ristgo.FECConfig{Columns: 5, Rows: 5})
}

// TestE2EFEC2022_5SeparatePortsSimple runs the same one-way Simple-profile,
// FEC-only recovery but in the SMPTE ST 2022-5 wire format (§7.3 header). Simple
// media carries no RTP padding/extension/CSRC/marker, so the 2022-5 recovery flag
// fields are zero and the FEC is byte-compatible with an external ST 2022-5 receiver.
func TestE2EFEC2022_5SeparatePortsSimple(t *testing.T) {
	runSepPortsSimpleFEC(t, &ristgo.FECConfig{Columns: 5, Rows: 5, Variant: ristgo.FECVariant2022_5})
}

// runSepPortsSimpleFEC drives the separate-port Simple-profile FEC-only recovery for
// the given matrix/variant.
func runSepPortsSimpleFEC(t *testing.T, fecCfg *ristgo.FECConfig) {
	const totalBytes = 256 * 1024
	const chunk = 1316
	cols, rows := fecCfg.Columns, fecCfg.Rows

	recvMedia := distinctEvenPort(t)
	proxyMedia := distinctEvenPort(t, recvMedia)

	cfg := ristgo.DefaultConfig() // Simple profile
	cfg.BufferMin = 600 * time.Millisecond
	cfg.BufferMax = 600 * time.Millisecond
	cfg.FEC = fecCfg

	rx, err := ristgo.NewOneWayReceiver(fmt.Sprintf("127.0.0.1:%d", recvMedia), cfg)
	if err != nil {
		t.Fatalf("NewOneWayReceiver: %v", err)
	}
	defer rx.Close()

	// Drop one media packet per 25-packet matrix, after a one-matrix warmup so the
	// first packet (and the receiver's matrix alignment) survives.
	proxy := startFECSepProxy(t, proxyMedia, "127.0.0.1", recvMedia, cols*rows, cols*rows, 7)
	defer proxy.Close()

	tx, err := ristgo.NewOneWaySender(fmt.Sprintf("127.0.0.1:%d", proxyMedia), cfg)
	if err != nil {
		t.Fatalf("NewOneWaySender: %v", err)
	}
	defer tx.Close()

	data := make([]byte, totalBytes)
	if _, err := crand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(data)

	go func() {
		tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			if _, werr := tx.Write(data[off:end]); werr != nil {
				return
			}
			if (off/chunk)%4 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		flush := make([]byte, chunk)
		for i := 0; i < 60; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

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
			st := rx.Stats()
			t.Fatalf("Read ended early at %d/%d: %v (dropped=%d fecRecovered=%d lost=%d)",
				len(got), totalBytes, rerr, proxy.Dropped(), st.FECRecovered, st.Lost)
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	st := rx.Stats()
	if sum != want {
		t.Fatalf("hash mismatch (dropped=%d fecRecovered=%d)", proxy.Dropped(), st.FECRecovered)
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped nothing")
	}
	if st.FECRecovered < proxy.Dropped() {
		t.Fatalf("FEC recovered %d but %d were dropped (one-way: every drop must be FEC-recovered)", st.FECRecovered, proxy.Dropped())
	}
	t.Logf("separate-port FEC e2e: dropped=%d fecRecovered=%d", proxy.Dropped(), st.FECRecovered)
}

// distinctEvenPort returns a free even port distinct from any given.
func distinctEvenPort(t *testing.T, avoid ...int) int {
	t.Helper()
	for {
		p := freeEvenPort(t)
		ok := true
		for _, a := range avoid {
			// keep the +2/+4 FEC ports clear of each other too
			if p == a || p == a+2 || p == a+4 || p+2 == a || p+4 == a {
				ok = false
			}
		}
		if ok {
			return p
		}
	}
}

// mainFECProxy relays a Main-profile session: the single media+RTCP port
// bidirectionally (dropping media after a warmup) and the two separate FEC ports
// (media+2 column, media+4 row) reliably forward — so FEC, on its own ports, can
// recover the media drops.
type mainFECProxy struct {
	inMedia, inCol, inRow *net.UDPConn
	out                   *net.UDPConn
	recvMedia             int
	loss                  float64
	warmup                int
	rng                   *mrand.Rand
	mu                    sync.Mutex
	senderAddr            *net.UDPAddr
	seen                  int
	dropped               atomic.Uint64
	wg                    sync.WaitGroup
}

func startMainFECProxy(t *testing.T, proxyMedia, recvMedia int, loss float64, warmup int, seed uint64) *mainFECProxy {
	t.Helper()
	bind := func(port int) *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("main fec proxy bind %d: %v", port, err)
		}
		return c
	}
	out, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("main fec proxy out: %v", err)
	}
	p := &mainFECProxy{
		inMedia: bind(proxyMedia), inCol: bind(proxyMedia + 2), inRow: bind(proxyMedia + 4),
		out:       out,
		recvMedia: recvMedia, loss: loss, warmup: warmup,
		rng: mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)),
	}
	p.wg.Add(4)
	go p.forwardMedia()
	go p.backward()
	go p.forward(p.inCol, recvMedia+2)
	go p.forward(p.inRow, recvMedia+4)
	return p
}

func (p *mainFECProxy) forwardMedia() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.inMedia.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.senderAddr = src
		large := n >= 256
		if large {
			p.seen++
		}
		drop := large && p.seen > p.warmup && p.rng.Float64() < p.loss
		p.mu.Unlock()
		if drop {
			p.dropped.Add(1)
			continue
		}
		p.out.WriteToUDP(buf[:n], &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p.recvMedia})
	}
}

func (p *mainFECProxy) backward() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := p.out.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		dst := p.senderAddr
		p.mu.Unlock()
		if dst != nil {
			p.inMedia.WriteToUDP(buf[:n], dst)
		}
	}
}

func (p *mainFECProxy) forward(in *net.UDPConn, dstPort int) {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := in.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.out.WriteToUDP(buf[:n], &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dstPort})
	}
}

func (p *mainFECProxy) Dropped() uint64 { return p.dropped.Load() }
func (p *mainFECProxy) Close() {
	p.inMedia.Close()
	p.inCol.Close()
	p.inRow.Close()
	p.out.Close()
	p.wg.Wait()
}

// TestE2EFECMainProfile proves FEC on the Main profile (TR-06-2 §8.4): FEC over the
// decoded inner RTP payload, carried on separate UDP ports (the standard ST 2022-1
// carriage). A PSK-encrypted GRE-tunnelled stream drops media on its port while the
// FEC ports stay clean; FEC recovers the drops and the stream is bit-exact.
func TestE2EFECMainProfile(t *testing.T) {
	const totalBytes = 192 * 1024
	const chunk = 1316

	ports := distinctMainPorts(t, 2)
	recvMedia, proxyMedia := ports[0], ports[1]

	cfg := mainConfig("ristgo-fec-main", 256)
	cfg.BufferMin = 600 * time.Millisecond
	cfg.BufferMax = 600 * time.Millisecond
	cfg.FEC = &ristgo.FECConfig{Columns: 6, Rows: 6}

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvMedia), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startMainFECProxy(t, proxyMedia, recvMedia, 0.06, 36, 0xFEC7)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyMedia), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data := advPayload(t, totalBytes, false)
	want := sha256.Sum256(data)

	go func() {
		tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			if _, werr := tx.Write(data[off:end]); werr != nil {
				return
			}
			if (off/chunk)%4 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		flush := make([]byte, chunk)
		for i := 0; i < 40; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

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
			st := rx.Stats()
			t.Fatalf("Read ended early at %d/%d: %v (dropped=%d fecRecovered=%d)", len(got), totalBytes, rerr, proxy.Dropped(), st.FECRecovered)
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	st := rx.Stats()
	if sum != want {
		t.Fatalf("Main FEC hash mismatch (dropped=%d fecRecovered=%d)", proxy.Dropped(), st.FECRecovered)
	}
	if st.FECRecovered == 0 {
		t.Fatalf("no FEC recovery on Main (dropped=%d); wiring not exercised", proxy.Dropped())
	}
	t.Logf("Main FEC e2e: dropped=%d fecRecovered=%d", proxy.Dropped(), st.FECRecovered)
}

// TestE2EFECLargePayloadFragmentsControl forces the over-MTU FEC control-message
// path: with ~1450-byte payloads the Advanced full-datagram FEC packet exceeds one
// MTU, so each FEC control message is fragmented across two control packets and the
// receiver must reassemble them before decoding. FECRecovered > 0 with these
// payloads therefore proves the FEC-message fragmentation/reassembly works (broken
// reassembly would yield zero FEC recoveries, leaving everything to ARQ).
func TestE2EFECLargePayloadFragmentsControl(t *testing.T) {
	const totalBytes = 256 * 1024
	const chunk = 1450 // > fecMaxCtrlBody once wrapped, so the FEC message fragments

	recvPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == recvPort {
		proxyPort = freeMainPort(t)
	}

	cfg := advConfig("", 0, false)
	cfg.BufferMin = 600 * time.Millisecond
	cfg.BufferMax = 600 * time.Millisecond
	cfg.FEC = &ristgo.FECConfig{Columns: 6, Rows: 6}

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startFECLossyProxy(t, proxyPort, recvPort, 0.05, 36, 0xFECB)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data := advPayload(t, totalBytes, false)
	want := sha256.Sum256(data)

	go func() {
		tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			if _, werr := tx.Write(data[off:end]); werr != nil {
				return
			}
			if (off/chunk)%4 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		flush := make([]byte, chunk)
		for i := 0; i < 40; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

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
			st := rx.Stats()
			t.Fatalf("Read ended early at %d/%d: %v (dropped=%d fecRecovered=%d)", len(got), totalBytes, rerr, proxy.Dropped(), st.FECRecovered)
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	st := rx.Stats()
	if sum != want {
		t.Fatalf("large-payload FEC hash mismatch (dropped=%d fecRecovered=%d)", proxy.Dropped(), st.FECRecovered)
	}
	if st.FECRecovered == 0 {
		t.Fatalf("no FEC recovery with fragmented FEC messages (dropped=%d); reassembly path not exercised", proxy.Dropped())
	}
	t.Logf("large-payload FEC (fragmented control) e2e: dropped=%d fecRecovered=%d", proxy.Dropped(), st.FECRecovered)
}

// TestE2EFECWithFragmentation proves FEC composes with payload fragmentation on the
// Advanced profile: large Writes are split into fragments (each its own sequence),
// the link drops some, and FEC recovers the lost fragments. Because FEC now protects
// the full wire datagram, a recovered fragment carries its original First/Last role,
// so reassembly succeeds and the stream is bit-exact. A FEC scheme that recovered
// only the media payload would mis-tag recovered fragments and corrupt the output.
func TestE2EFECWithFragmentation(t *testing.T) {
	const totalBytes = 256 * 1024
	const chunk = 1500 // splits into 3 fragments at FragmentSize 600

	recvPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == recvPort {
		proxyPort = freeMainPort(t)
	}

	cfg := advConfig("ristgo-fec-frag", 256, false) // PSK too: exercises encryption + FEC + fragmentation
	cfg.BufferMin = 600 * time.Millisecond
	cfg.BufferMax = 600 * time.Millisecond
	cfg.FragmentSize = 600
	cfg.FEC = &ristgo.FECConfig{Columns: 6, Rows: 6}

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	proxy := startFECLossyProxy(t, proxyPort, recvPort, 0.06, 36, 0xFEC5)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data := advPayload(t, totalBytes, false)
	want := sha256.Sum256(data)

	go func() {
		tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			if _, werr := tx.Write(data[off:end]); werr != nil {
				return
			}
			if (off/chunk)%4 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		flush := make([]byte, chunk)
		for i := 0; i < 40; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

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
			st := rx.Stats()
			t.Fatalf("Read ended early at %d/%d: %v (dropped=%d fecRecovered=%d)", len(got), totalBytes, rerr, proxy.Dropped(), st.FECRecovered)
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	st := rx.Stats()
	if sum != want {
		t.Fatalf("FEC+fragmentation hash mismatch (dropped=%d fecRecovered=%d)", proxy.Dropped(), st.FECRecovered)
	}
	if st.FECRecovered == 0 {
		t.Fatalf("no fragments recovered by FEC (dropped=%d); composition not exercised", proxy.Dropped())
	}
	t.Logf("FEC+fragmentation e2e: dropped=%d fecRecovered=%d", proxy.Dropped(), st.FECRecovered)
}

// TestE2EFECRecoversAdvanced runs an Advanced-profile stream with 2-D SMPTE 2022-1
// FEC over a lossy link and verifies the receiver recovers losses by FEC. The
// stream reconstructs bit-exact and Stats.FECRecovered is non-zero, proving FEC
// (not only ARQ) carried the recovery. ARQ remains the backstop, so completeness
// is guaranteed regardless.
func TestE2EFECRecoversAdvanced(t *testing.T) {
	runAdvInbandFEC(t, &ristgo.FECConfig{Columns: 5, Rows: 5})
}

// TestE2EFEC2022_5Advanced runs the Advanced-profile in-band FEC recovery in the
// SMPTE ST 2022-5 wire format (Control Index 0x0020/0x0021, §7.3 header). The
// protected unit is the full Advanced datagram, so 2022-5 recovers exact bytes just
// as 2022-1 does, exercising the variant's CI selection and header on the wire.
func TestE2EFEC2022_5Advanced(t *testing.T) {
	runAdvInbandFEC(t, &ristgo.FECConfig{Columns: 5, Rows: 5, Variant: ristgo.FECVariant2022_5})
}

// runAdvInbandFEC drives Advanced-profile in-band FEC recovery for the given
// matrix/variant over a lossy link, asserting bit-exact delivery and FEC recovery.
func runAdvInbandFEC(t *testing.T, fecCfg *ristgo.FECConfig) {
	const totalBytes = 256 * 1024
	const chunk = 1316

	recvPort := freeMainPort(t)
	proxyPort := freeMainPort(t)
	for proxyPort == recvPort {
		proxyPort = freeMainPort(t)
	}

	cfg := advConfig("", 0, false)
	cfg.BufferMin = 500 * time.Millisecond
	cfg.BufferMax = 500 * time.Millisecond
	cfg.FEC = fecCfg

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", recvPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	// 8% media loss after a one-matrix warmup, so the first packet (and the ISN
	// alignment) survives and FEC has losses to recover.
	proxy := startFECLossyProxy(t, proxyPort, recvPort, 0.08, 25, 0xFEC0)
	defer proxy.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data := advPayload(t, totalBytes, false)
	want := sha256.Sum256(data)

	go func() {
		tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			if _, werr := tx.Write(data[off:end]); werr != nil {
				return
			}
			if (off/chunk)%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		flush := make([]byte, chunk)
		for i := 0; i < 40; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

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
			st := rx.Stats()
			t.Fatalf("Read ended early at %d/%d: %v (dropped=%d fecRecovered=%d arqRecovered=%d lost=%d)",
				len(got), totalBytes, rerr, proxy.Dropped(), st.FECRecovered, st.Recovered, st.Lost)
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	st := rx.Stats()
	if sum != want {
		t.Fatalf("hash mismatch (dropped=%d fecRecovered=%d arqRecovered=%d)", proxy.Dropped(), st.FECRecovered, st.Recovered)
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped nothing; loss not exercised")
	}
	if st.FECRecovered == 0 {
		t.Fatalf("no packets recovered by FEC (dropped=%d arqRecovered=%d); FEC not effective", proxy.Dropped(), st.Recovered)
	}
	t.Logf("FEC e2e: dropped=%d fecRecovered=%d arqRecovered=%d", proxy.Dropped(), st.FECRecovered, st.Recovered)
}

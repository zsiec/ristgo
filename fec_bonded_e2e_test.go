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

// This file proves FEC composes with link bonding on every profile. The hard case
// is that SMPTE 2022-7 duplication already recovers any loss that strikes only some
// paths, so FEC earns its keep only on a CORRELATED loss that strikes every path at
// once. The relay below drops the same source datagrams on every path (selected by
// hashing the byte-identical datagram, so the decision is the same on each path), so
// the merged stream is genuinely missing them and FEC must reconstruct them. The
// relay is bidirectional, so ARQ remains the backstop for any cluster FEC cannot
// cover and completeness is guaranteed regardless.

var loopback = net.IPv4(127, 0, 0, 1)

// bondPump relays one UDP port of one bonded path in both directions on a single
// socket: a datagram from the sender (any other source) is forwarded to dstPort; a
// datagram from dstPort (the receiver's reply) is forwarded back to the learned
// sender address. A lossy pump drops a deterministic, content-selected subset of the
// large (media) datagrams: every path carries byte-identical copies, so hashing the
// datagram makes the same source packet drop on every path (correlated loss that
// 2022-7 cannot cover). Each distinct datagram is dropped at most once, so an ARQ
// retransmit (which differs by its retransmit marking, hence a different hash) is
// never dropped forever.
type bondPump struct {
	sock       *net.UDPConn
	dstPort    int
	lossy      bool
	parent     *bondFECRelay
	seenDrop   map[uint64]bool
	seen       int
	mu         sync.Mutex
	senderAddr *net.UDPAddr
}

func (pm *bondPump) run() {
	defer pm.parent.wg.Done()
	buf := make([]byte, 2048)
	dst := &net.UDPAddr{IP: loopback, Port: pm.dstPort}
	for {
		n, src, err := pm.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if src.Port == pm.dstPort && src.IP.Equal(loopback) {
			pm.mu.Lock()
			sa := pm.senderAddr
			pm.mu.Unlock()
			if sa != nil {
				pm.sock.WriteToUDP(buf[:n], sa)
			}
			continue
		}
		pm.mu.Lock()
		pm.senderAddr = src
		pm.mu.Unlock()
		if pm.lossy && n >= 256 {
			pm.seen++
			h := fnv1a(buf[:n])
			// Never drop during the warmup, so the stream establishes and the receiver
			// anchors on the true first packet (a dropped first packet would make it
			// start mid-stream — correct behavior, but not what a bit-exact test wants).
			if pm.seen > pm.parent.warmup && h%pm.parent.period == 0 && !pm.seenDrop[h] {
				pm.seenDrop[h] = true
				pm.parent.dropped.Add(1)
				continue
			}
		}
		pm.sock.WriteToUDP(buf[:n], dst)
	}
}

// fnv1a hashes a datagram so the relay's drop decision depends only on its bytes,
// making the same source packet drop identically on every bonded path.
func fnv1a(b []byte) uint64 {
	h := uint64(1469598103934665603)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// bondFECRelay is the set of per-path, per-port pumps. A lossy pump drops a datagram
// whose hash is 0 mod period (about one in period of the media), after a per-path
// warmup that protects the stream's establishment.
type bondFECRelay struct {
	pumps   []*bondPump
	period  uint64
	warmup  int
	dropped atomic.Uint64
	wg      sync.WaitGroup
}

func (r *bondFECRelay) Dropped() uint64 { return r.dropped.Load() }

func (r *bondFECRelay) Close() {
	for _, pm := range r.pumps {
		pm.sock.Close()
	}
	r.wg.Wait()
}

type bondPumpSpec struct {
	listenPort, dstPort int
	lossy               bool
}

func startBondFECRelay(t *testing.T, specs []bondPumpSpec, period uint64, warmup int) *bondFECRelay {
	t.Helper()
	r := &bondFECRelay{period: period, warmup: warmup}
	for _, m := range specs {
		sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback, Port: m.listenPort})
		if err != nil {
			r.Close()
			t.Fatalf("bond fec relay bind %d: %v", m.listenPort, err)
		}
		r.pumps = append(r.pumps, &bondPump{sock: sock, dstPort: m.dstPort, lossy: m.lossy, parent: r, seenDrop: map[uint64]bool{}})
	}
	r.wg.Add(len(r.pumps))
	for _, pm := range r.pumps {
		go pm.run()
	}
	return r
}

// spacedEvenPorts returns n free even loopback ports each at least 8 apart (so the
// media port and its +1 RTCP / +2 column / +4 row FEC neighbours never collide), and
// distinct from any port in avoid.
func spacedEvenPorts(t *testing.T, n int, avoid ...int) []int {
	t.Helper()
	var ps []int
	for len(ps) < n {
		p := freeEvenPort(t)
		ok := true
		for _, q := range append(append([]int{}, ps...), avoid...) {
			d := p - q
			if d < 0 {
				d = -d
			}
			if d < 8 {
				ok = false
				break
			}
		}
		if ok {
			ps = append(ps, p)
		}
	}
	return ps
}

// TestE2EBondedFECAdvanced bonds two Advanced-profile paths and drops the same
// source datagrams on both, so 2022-7 cannot cover them. FEC, carried in-band over
// both paths' data ports, reconstructs them: the stream is bit-exact and FEC carried
// recovery (FECRecovered > 0).
func TestE2EBondedFECAdvanced(t *testing.T) {
	runBondedFEC(t, false, func() ristgo.Config {
		cfg := bondProfileConfig(ristgo.ProfileAdvanced, "ristgo-bonded-fec", 128)()
		cfg.FEC = &ristgo.FECConfig{Columns: 5, Rows: 5}
		return cfg
	})
}

// TestE2EBondedFECMain bonds two Main-profile paths with separate-port FEC (the
// per-path column/row sockets) and the same correlated loss; FEC reconstructs the
// drops bit-exact.
func TestE2EBondedFECMain(t *testing.T) {
	runBondedFEC(t, true, func() ristgo.Config {
		cfg := bondProfileConfig(ristgo.ProfileMain, "ristgo-bonded-fec", 128)()
		cfg.FEC = &ristgo.FECConfig{Columns: 5, Rows: 5}
		return cfg
	})
}

// TestE2EBondedFECSimple bonds two Simple-profile paths with separate-port FEC and
// the same correlated loss, exercising the even/odd-port FEC socket binding.
func TestE2EBondedFECSimple(t *testing.T) {
	runBondedFEC(t, true, func() ristgo.Config {
		cfg := bondConfig() // Simple
		cfg.FEC = &ristgo.FECConfig{Columns: 5, Rows: 5}
		return cfg
	})
}

// runBondedFEC drives a two-path bonded session whose paths both pass through a
// correlated-loss relay, asserting bit-exact delivery and non-zero FEC recovery.
// separatePorts selects whether the relay also forwards the per-path column/row FEC
// ports (Simple/Main) or not (Advanced in-band).
func runBondedFEC(t *testing.T, separatePorts bool, cfgFn func() ristgo.Config) {
	const totalBytes = 256 * 1024
	const chunk = 1316
	cfg := cfgFn()
	matrix := cfg.FEC.Columns * cfg.FEC.Rows
	simple := cfg.Profile == ristgo.ProfileSimple

	recv := spacedEvenPorts(t, 2)
	proxy := spacedEvenPorts(t, 2, recv...)
	recvAddrs := []string{fmt.Sprintf("127.0.0.1:%d", recv[0]), fmt.Sprintf("127.0.0.1:%d", recv[1])}
	proxyAddrs := []string{fmt.Sprintf("127.0.0.1:%d", proxy[0]), fmt.Sprintf("127.0.0.1:%d", proxy[1])}

	rx, err := ristgo.NewBondedReceiver(recvAddrs, cfgFn())
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()

	// Build the relay: one lossy data pump per path, plus the odd RTCP pump (Simple)
	// and the column/row FEC pumps (separate-port carriage).
	var specs []bondPumpSpec
	for i := 0; i < 2; i++ {
		specs = append(specs, bondPumpSpec{proxy[i], recv[i], true})
		if simple {
			specs = append(specs, bondPumpSpec{proxy[i] + 1, recv[i] + 1, false})
		}
		if separatePorts {
			specs = append(specs, bondPumpSpec{proxy[i] + 2, recv[i] + 2, false})
			specs = append(specs, bondPumpSpec{proxy[i] + 4, recv[i] + 4, false})
		}
	}
	// Drop a correlated subset of the media (the same packets on both paths), at a
	// rate FEC comfortably recovers (about one per half-matrix); ARQ backstops any
	// rare cluster two losses land in one matrix, so delivery is bit-exact regardless.
	relay := startBondFECRelay(t, specs, uint64(matrix/2), matrix*2)
	defer relay.Close()

	tx, err := ristgo.NewBondedSender(proxyAddrs, cfgFn())
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	data := make([]byte, totalBytes)
	for i := range data {
		data[i] = byte(i*131 + 7)
	}
	want := sha256.Sum256(data)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(25 * time.Second))
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

	tx.SetWriteDeadline(time.Now().Add(25 * time.Second))
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if _, werr := tx.Write(data[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if (off/chunk)%4 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	flush := make([]byte, chunk)
	for i := 0; i < 48; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}

	select {
	case got := <-done:
		st := rx.Stats()
		if got != want {
			t.Fatalf("bonded FEC hash mismatch (dropped=%d fecRecovered=%d lost=%d recovered=%d)",
				relay.Dropped(), st.FECRecovered, st.Lost, st.Recovered)
		}
		if relay.Dropped() == 0 {
			t.Fatal("relay dropped nothing; correlated loss not exercised")
		}
		if st.FECRecovered == 0 {
			t.Fatalf("no FEC recovery over bonding (dropped=%d recovered=%d); FEC not exercised", relay.Dropped(), st.Recovered)
		}
		t.Logf("bonded FEC e2e: dropped=%d fecRecovered=%d arqRecovered=%d", relay.Dropped(), st.FECRecovered, st.Recovered)
	case <-time.After(30 * time.Second):
		st := rx.Stats()
		t.Fatalf("timed out (dropped=%d fecRecovered=%d lost=%d)", relay.Dropped(), st.FECRecovered, st.Lost)
	}
}

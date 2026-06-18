//go:build interop

// Interop tests against the libRIST reference CLI tools (ristsender /
// ristreceiver), Simple profile (VSF TR-06-1).
//
// Prerequisites: build libRIST's tools, e.g.
//
//	brew install meson ninja
//	cd ~/dev/librist && meson setup build && ninja -C build
//
// The tools are found at $RISTGO_LIBRIST_TOOLS, then ~/dev/librist/build/tools,
// then $PATH; the suite t.Skips when they are absent. Run with:
//
//	go test -tags interop -run TestInterop -v -count=1 -timeout 5m
//
// The four role/direction combos prove wire interop both ways, clean and lossy
// (the lossy combos exercise the make-or-break retransmit SSRC-toggle across
// the wire: libRIST's retransmits recognized by ristgo, and ristgo's
// recognized by libRIST).
package ristgo_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

const (
	interopChunk = 1316 // RTP media payload (one UDP datagram in / out of the tools)
	interopN     = 200  // datagrams per clean run (~256 KB)
	interopLossN = 400  // datagrams per lossy run (more, to ride out drops)
)

// libristTool locates a libRIST CLI tool or skips the test.
func libristTool(t *testing.T, name string) string {
	t.Helper()
	candidates := []string{}
	if dir := os.Getenv("RISTGO_LIBRIST_TOOLS"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "dev", "librist", "build", "tools", name))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	t.Skipf("%s not found (set RISTGO_LIBRIST_TOOLS or build ~/dev/librist/build/tools); skipping interop", name)
	return ""
}

// freeUDPPort returns a free loopback UDP port not in exclude (the already
// chosen even/odd RIST pair). The port is probed and immediately released, so
// the caller must bind it promptly; the exclude set avoids colliding with
// ports that have been allocated but not yet bound.
func freeUDPPort(t *testing.T, exclude ...int) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			continue
		}
		p := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		excluded := false
		for _, e := range exclude {
			if p == e {
				excluded = true
				break
			}
		}
		if !excluded {
			return p
		}
	}
	t.Fatal("no free udp port")
	return 0
}

// waitToolReady blocks until a libRIST tool has bound the given UDP port (its
// input socket) — i.e. the probe bind fails because the tool holds it — or the
// timeout elapses. It replaces a fixed startup sleep so data is not fed before
// the tool is listening.
func waitToolReady(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			return // port in use → the tool has bound it
		}
		c.Close()
		time.Sleep(25 * time.Millisecond)
	}
	t.Logf("timed out waiting for a libRIST tool to bind udp 127.0.0.1:%d", port)
}

// spawnTool starts a libRIST tool, capturing stderr, and registers cleanup
// that kills it and dumps its log on failure.
func spawnTool(t *testing.T, bin string, args ...string) *bytes.Buffer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start %s %v: %v", filepath.Base(bin), args, err)
	}
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
		if t.Failed() {
			t.Logf("%s %v stderr:\n%s", filepath.Base(bin), args, stderr.String())
		}
	})
	return &stderr
}

// randomData returns n*interopChunk arbitrary bytes plus the SHA-256 of all of
// them.
func randomData(t *testing.T, n int) (data []byte, hash [32]byte) {
	t.Helper()
	data = make([]byte, n*interopChunk)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return data, sha256.Sum256(data)
}

// feedUDP streams data to 127.0.0.1:port as interopChunk-sized datagrams (each becomes one
// RTP payload on the wire), as a STEADY, SUSTAINED stream — the way real RIST media flows.
// It is run as `go feedUDP(t, ...)` and feeds continuously (looping the payload, one
// datagram per millisecond) until the test ends (t.Context is cancelled just before the
// test's cleanups run). A burst-then-stop feed made the libRIST sender's pacing/rate
// estimate collapse and stall the TAIL of its queue under load — it would send ~80-99% then
// idle at a few kbps, leaving the receiver waiting forever for the last packets; a sustained
// feed keeps libRIST draining. A receiver reads only the first len(data) bytes — it listens
// before the sender starts, so it anchors on the first packet and never observes the loop.
func feedUDP(t *testing.T, port int, data []byte) {
	t.Helper()
	ctx := t.Context() // cancelled when the test ends, so the feed stops (no lingering goroutine)
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		// feedUDP runs in a detached goroutine that may outlive the test, so
		// it must not touch t; a dial failure surfaces downstream as a
		// short-read in readN.
		fmt.Fprintf(os.Stderr, "feedUDP: dial: %v\n", err)
		return
	}
	defer c.Close()
	for ctx.Err() == nil {
		for off := 0; off < len(data); off += interopChunk {
			end := off + interopChunk
			if end > len(data) {
				end = len(data)
			}
			if _, err := c.Write(data[off:end]); err != nil {
				return // the tool exited — stop feeding
			}
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Millisecond) // steady, not a burst — keeps libRIST's pacing stable
		}
	}
}

// udpCapture binds 127.0.0.1:port and collects inbound datagrams (the libRIST
// receiver's UDP output) until want bytes arrive or it times out.
type udpCapture struct {
	conn *net.UDPConn
	mu   sync.Mutex
	buf  []byte
	done chan struct{}
}

func newUDPCapture(t *testing.T, port, want int) *udpCapture {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("bind capture udp: %v", err)
	}
	c := &udpCapture{conn: conn, done: make(chan struct{})}
	go func() {
		pkt := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFromUDP(pkt)
			if err != nil {
				return
			}
			c.mu.Lock()
			c.buf = append(c.buf, pkt[:n]...)
			full := len(c.buf) >= want
			c.mu.Unlock()
			if full {
				close(c.done)
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return c
}

func (c *udpCapture) wait(d time.Duration) []byte {
	select {
	case <-c.done:
	case <-time.After(d):
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// readN reads exactly want bytes from the receiver (or until the deadline).
func readN(t *testing.T, rx *ristgo.Receiver, want int) []byte {
	t.Helper()
	rx.SetReadDeadline(time.Now().Add(20 * time.Second))
	got := make([]byte, 0, want)
	buf := make([]byte, 4096)
	for len(got) < want {
		n, err := rx.Read(buf)
		if n > 0 {
			take := n
			if len(got)+take > want {
				take = want - len(got)
			}
			got = append(got, buf[:take]...)
		}
		if err != nil {
			break
		}
	}
	return got
}

func interopReceiverConfig() ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.BufferMin = 200 * time.Millisecond
	cfg.BufferMax = 200 * time.Millisecond
	return cfg
}

// TestInteropGoRxFromLibristTx: libRIST ristsender -> ristgo Receiver, clean.
// Proves ristgo decodes libRIST's Simple-profile RTP/RTCP byte-exactly.
func TestInteropGoRxFromLibristTx(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeEvenPort(t)
	feedPort := freeUDPPort(t, goPort, goPort+1)

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), interopReceiverConfig())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close() // NewReceiver binds synchronously, so the RIST port is ready

	spawnTool(t, sender, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", goPort))
	waitToolReady(t, feedPort, 5*time.Second) // ristsender bound its UDP input

	data, want := randomData(t, interopN)
	go feedUDP(t, feedPort, data)

	got := readN(t, rx, len(data))
	if len(got) != len(data) {
		t.Fatalf("received %d/%d bytes (recovered=%d lost=%d)", len(got), len(data), rx.Stats().Recovered, rx.Stats().Lost)
	}
	if sha256.Sum256(got) != want {
		t.Fatalf("byte mismatch from libRIST sender")
	}
}

// TestInteropLibristRxFromGoTx: ristgo Sender -> libRIST ristreceiver, clean.
// Proves libRIST decodes ristgo's Simple-profile output byte-exactly.
func TestInteropLibristRxFromGoTx(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	rxPort := freeEvenPort(t)
	capPort := freeUDPPort(t, rxPort, rxPort+1)

	// The Simple profile has no GRE/auth handshake, so libRIST anchors its receive flow on
	// the first RTP packet it happens to receive; any packet dropped while it sets that flow
	// up lands BEFORE the anchor and is unrecoverable (libRIST never NACKs below its base).
	// Send a brief paced warmup so libRIST anchors before the counted data, capture both,
	// and assert the data is intact at the tail of the capture — tolerating only the
	// pre-anchor warmup loss, never any loss within the data (ARQ must recover that).
	const warmup = 24
	capt := newUDPCapture(t, capPort, (warmup+interopN)*interopChunk)
	spawnTool(t, receiver, "-p", "0", "-b", "200",
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	waitToolReady(t, rxPort, 5*time.Second) // ristreceiver bound its RIST input

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", rxPort), interopReceiverConfig())
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data, _ := randomData(t, interopN)
	filler := bytes.Repeat([]byte{0xAA}, interopChunk)
	tx.SetWriteDeadline(time.Now().Add(20 * time.Second))
	go func() {
		for i := 0; i < warmup; i++ {
			tx.Write(filler) // distinct seqs; lets libRIST anchor before the data
			time.Sleep(3 * time.Millisecond)
		}
		for off := 0; off < len(data); off += interopChunk {
			tx.Write(data[off : off+interopChunk])
			if (off/interopChunk)%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	got := capt.wait(20 * time.Second)
	if len(got) < len(data) {
		t.Fatalf("libRIST received %d bytes, want at least %d (the data)", len(got), len(data))
	}
	// The counted data must arrive contiguous and byte-exact at the tail of the capture.
	if !bytes.Equal(got[len(got)-len(data):], data) {
		t.Fatalf("byte mismatch: data not intact at the libRIST capture tail")
	}
}

// TestInteropGoRxLossyRecovery: libRIST ristsender -> lossy proxy -> ristgo
// Receiver. libRIST retransmits on ristgo's NACKs; ristgo must recognize the
// SSRC-LSB-marked retransmits and recover.
func TestInteropGoRxLossyRecovery(t *testing.T) {
	sender := libristTool(t, "ristsender")
	goPort := freeEvenPort(t)
	proxyPort := freeEvenPort(t)
	for proxyPort == goPort {
		proxyPort = freeEvenPort(t)
	}
	feedPort := freeUDPPort(t, goPort, goPort+1, proxyPort, proxyPort+1)

	cfg := ristgo.DefaultConfig()
	cfg.BufferMin = 700 * time.Millisecond
	cfg.BufferMax = 700 * time.Millisecond
	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", goPort), cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	proxy := startLossyProxy(t, proxyPort, goPort, 0.10, 7)
	defer proxy.Close()

	spawnTool(t, sender, "-p", "0", "-b", "700",
		"-i", fmt.Sprintf("udp://@127.0.0.1:%d", feedPort),
		"-o", fmt.Sprintf("rist://127.0.0.1:%d", proxyPort))
	waitToolReady(t, feedPort, 5*time.Second)

	data, want := randomData(t, interopLossN)
	// A trailing flush gives the payload's tail a delivered successor to
	// trigger its NACK (missing-detection is successor-driven, not timer-driven).
	feed := append(append([]byte(nil), data...), make([]byte, 24*interopChunk)...)
	go feedUDP(t, feedPort, feed)

	got := readN(t, rx, len(data))
	if len(got) != len(data) || sha256.Sum256(got) != want {
		t.Fatalf("lossy recovery failed: got %d/%d bytes (proxy dropped=%d recovered=%d lost=%d)",
			len(got), len(data), proxy.Dropped(), rx.Stats().Recovered, rx.Stats().Lost)
	}
	// proxy.Dropped() is the deterministic, wire-independent witness that loss
	// actually occurred; byte-exact recovery above then proves ristgo
	// recognized and recovered libRIST's SSRC-toggle retransmits. (The
	// receiver's Recovered count is logged but not asserted — libRIST can
	// retransmit before ristgo's first NACK, leaving it racily at 0.)
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped no media — the loss/ARQ path was not exercised")
	}
	t.Logf("byte-exact: proxy dropped %d media datagrams, recovered %d via libRIST retransmits",
		proxy.Dropped(), rx.Stats().Recovered)
}

// TestInteropLibristRxLossyRecovery: ristgo Sender -> lossy proxy -> libRIST
// ristreceiver. ristgo retransmits on libRIST's NACKs; libRIST must recognize
// ristgo's SSRC-LSB-marked retransmits and recover.
func TestInteropLibristRxLossyRecovery(t *testing.T) {
	receiver := libristTool(t, "ristreceiver")
	rxPort := freeEvenPort(t)
	proxyPort := freeEvenPort(t)
	for proxyPort == rxPort {
		proxyPort = freeEvenPort(t)
	}
	capPort := freeUDPPort(t, rxPort, rxPort+1, proxyPort, proxyPort+1)

	capt := newUDPCapture(t, capPort, interopLossN*interopChunk)
	spawnTool(t, receiver, "-p", "0", "-b", "700",
		"-i", fmt.Sprintf("rist://@127.0.0.1:%d", rxPort),
		"-o", fmt.Sprintf("udp://127.0.0.1:%d", capPort))
	proxy := startLossyProxy(t, proxyPort, rxPort, 0.10, 9)
	defer proxy.Close()
	waitToolReady(t, rxPort, 5*time.Second) // ristreceiver bound its RIST input

	cfg := ristgo.DefaultConfig()
	cfg.BufferMin = 700 * time.Millisecond
	cfg.BufferMax = 700 * time.Millisecond
	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", proxyPort), cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	data, want := randomData(t, interopLossN)
	tx.SetWriteDeadline(time.Now().Add(25 * time.Second))
	go func() {
		for off := 0; off < len(data); off += interopChunk {
			tx.Write(data[off : off+interopChunk])
			if (off/interopChunk)%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		// Trailing flush so a dropped payload tail has a delivered successor.
		flush := make([]byte, interopChunk)
		for i := 0; i < 24; i++ {
			tx.Write(flush)
			time.Sleep(time.Millisecond)
		}
	}()

	got := capt.wait(25 * time.Second)
	if len(got) < len(data) {
		t.Fatalf("libRIST received %d/%d bytes under loss (proxy dropped=%d Go retransmitted=%d)",
			len(got), len(data), proxy.Dropped(), tx.Stats().Retransmitted)
	}
	if sha256.Sum256(got[:len(data)]) != want {
		t.Fatalf("byte mismatch at libRIST receiver under loss")
	}
	if proxy.Dropped() == 0 {
		t.Fatal("proxy dropped no media — the loss/ARQ path was not exercised")
	}
	if tx.Stats().Retransmitted == 0 {
		t.Fatal("Go sender never retransmitted — libRIST's NACK path was not exercised")
	}
	t.Logf("byte-exact: proxy dropped %d media datagrams, libRIST recovered via %d ristgo retransmits",
		proxy.Dropped(), tx.Stats().Retransmitted)
}

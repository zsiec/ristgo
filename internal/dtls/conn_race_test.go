package dtls

import (
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"
)

// captureConn is a Transport whose inbound side is an injectable queue and whose
// outbound side records the (epoch, seq) of every DTLS record written. It backs
// the H1 race test: the test can replay a retransmitted client flight into the
// inbound queue to drive the server's RFC 6347 §4.2.4 last-flight resend, while
// the recorded epoch-1 sequence numbers prove no two epoch-1 records ever share
// a sequence — a shared seq is a reused GCM nonce under one key (catastrophic).
type captureConn struct {
	mu       sync.Mutex
	epoch1   map[uint64]int // epoch-1 record seq -> times emitted
	deadline time.Time
	inbound  chan []byte
	closed   chan struct{}
	once     sync.Once
}

func newCaptureConn() *captureConn {
	return &captureConn{
		epoch1:  make(map[uint64]int),
		inbound: make(chan []byte, 4096),
		closed:  make(chan struct{}),
	}
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	d := b
	for len(d) >= recordHeaderLen {
		epoch := binary.BigEndian.Uint16(d[3:5])
		seq := uint48(d[5:11])
		length := int(binary.BigEndian.Uint16(d[11:13]))
		if recordHeaderLen+length > len(d) {
			break
		}
		if epoch == 1 {
			c.epoch1[seq]++
		}
		d = d[recordHeaderLen+length:]
	}
	c.mu.Unlock()
	return len(b), nil
}

func (c *captureConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	var tch <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, timeoutError{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		tch = t.C
	}
	select {
	case dg, ok := <-c.inbound:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, dg), nil
	case <-tch:
		return 0, timeoutError{}
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *captureConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *captureConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *captureConn) inject(b []byte) {
	cp := append([]byte(nil), b...)
	select {
	case c.inbound <- cp:
	case <-c.closed:
	}
}

func (c *captureConn) maxEpoch1Dup() (uint64, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var worstSeq uint64
	worst := 0
	for seq, n := range c.epoch1 {
		if n > worst {
			worst, worstSeq = n, seq
		}
	}
	return worstSeq, worst
}

// TestConcurrentWriteAndLastFlightResendNoNonceReuse is the H1 regression test.
// After a normal handshake it drives the server's application-data Write path
// concurrently with its Read path, where each Read processes a retransmitted
// client handshake record and triggers the RFC 6347 §4.2.4 last-flight resend
// (an epoch-1 Finished). Both paths emit epoch-1 records and advance the same
// c.sendSeq[1]; without the sendMu serialization (the H1 fix) they race and can
// allocate the SAME epoch-1 record sequence -> the SAME GCM nonce under one key.
// The test asserts under -race that the data race is gone AND that no epoch-1
// record sequence is ever emitted twice.
func TestConcurrentWriteAndLastFlightResendNoNonceReuse(t *testing.T) {
	// The server reads from cap.inbound and writes to cap (recording epoch-1
	// seqs). A forwarder pumps the real pipe into cap.inbound during the
	// handshake; afterwards the test injects retransmitted client flights there.
	cap := newCaptureConn()
	ca, sa := newPipe()

	cfg := func() *Config {
		return &Config{
			PSK:               []byte("a-shared-secret"),
			PSKIdentity:       []byte("ristgo"),
			RetransmitTimeout: 50 * time.Millisecond,
			HandshakeTimeout:  10 * time.Second,
		}
	}

	// Snoop the client's outbound flights to capture its epoch-1 flight (Finished)
	// for post-handshake replay.
	var (
		snoopMu sync.Mutex
		flight5 []byte
	)
	clientTr := &snoopConn{Transport: ca, onWrite: func(b []byte) {
		if recordsContainEpoch1(b) {
			snoopMu.Lock()
			flight5 = append([]byte(nil), b...)
			snoopMu.Unlock()
		}
	}}
	client := Client(clientTr, cfg())
	server := Server(&serverTransport{cap: cap, pipe: sa}, cfg())

	// Forwarder: real client datagrams (from the pipe) into the server's inbound
	// queue, for the duration of the handshake.
	stopFwd := make(chan struct{})
	var fwdWG sync.WaitGroup
	fwdWG.Add(1)
	go func() {
		defer fwdWG.Done()
		buf := make([]byte, readBufSize)
		for {
			select {
			case <-stopFwd:
				return
			default:
			}
			_ = sa.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			n, err := sa.Read(buf)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				return
			}
			cap.inject(buf[:n])
		}
	}()

	var hsWG sync.WaitGroup
	var serr error
	hsWG.Add(1)
	go func() { defer hsWG.Done(); serr = server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	hsWG.Wait()
	if serr != nil {
		t.Fatalf("server handshake: %v", serr)
	}
	close(stopFwd)
	fwdWG.Wait()

	snoopMu.Lock()
	rf := flight5
	snoopMu.Unlock()
	if rf == nil {
		t.Fatal("did not capture a client epoch-1 flight to replay")
	}

	// Pre-queue retransmitted client flights: each drives one last-flight resend
	// (epoch-1 Finished) on the Read path, concurrently with epoch-1 Writes. The
	// production cap (maxFinalFlightResends) bounds how many a peer can elicit —
	// that bounded burst is the contention window; no internal state is poked.
	for i := 0; i < maxFinalFlightResends; i++ {
		cap.inject(rf)
	}

	// Drain the client's inbound side so the server's post-handshake app-data
	// writes (forwarded over the pipe) never block on a full channel.
	rg := sync.WaitGroup{}
	rg.Add(1)
	go func() {
		defer rg.Done()
		buf := make([]byte, readBufSize)
		for {
			_ = ca.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := ca.Read(buf); err != nil {
				select {
				case <-ca.closed:
					return
				default:
				}
			}
		}
	}()

	rg.Add(1)
	go func() {
		defer rg.Done()
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return // io.EOF once the transport closes at test end
			}
		}
	}()

	for i := 0; i < 4000; i++ {
		if _, err := server.Write([]byte("media payload over a protected DTLS record")); err != nil {
			t.Fatalf("server write %d: %v", i, err)
		}
	}
	cap.Close() // unblock the server Read goroutine with io.EOF
	ca.Close()  // unblock the client-drain goroutine
	rg.Wait()

	if seq, n := cap.maxEpoch1Dup(); n > 1 {
		t.Fatalf("epoch-1 record sequence %d emitted %d times: GCM nonce reuse", seq, n)
	}

	server.Close()
}

// serverTransport gives the server an inbound side fed by cap.inbound (the
// forwarder during the handshake, injected retransmits afterwards) and an
// outbound side that records every epoch-1 record sequence.
type serverTransport struct {
	cap  *captureConn
	pipe *pipeConn
}

func (s *serverTransport) Read(p []byte) (int, error) { return s.cap.Read(p) }

func (s *serverTransport) Write(b []byte) (int, error) {
	// Record epoch-1 seqs, then forward to the client over the pipe so the
	// server's Flight-6 Finished reaches the client during the handshake.
	if _, err := s.cap.Write(b); err != nil {
		return 0, err
	}
	return s.pipe.Write(b)
}

func (s *serverTransport) SetReadDeadline(t time.Time) error { return s.cap.SetReadDeadline(t) }
func (s *serverTransport) Close() error                      { _ = s.cap.Close(); return s.pipe.Close() }

// snoopConn wraps a Transport and invokes onWrite for every outbound datagram.
type snoopConn struct {
	Transport
	onWrite func([]byte)
}

func (s *snoopConn) Write(b []byte) (int, error) {
	s.onWrite(b)
	return s.Transport.Write(b)
}

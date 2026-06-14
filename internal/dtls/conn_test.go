package dtls

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// pipeConn is an in-memory datagram transport pair for handshake tests: each
// Write delivers one datagram to the peer's Read, with read-deadline support so
// the retransmission machinery can be exercised.
type pipeConn struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	deadline time.Time
}

func newPipe() (*pipeConn, *pipeConn) {
	ab := make(chan []byte, 256)
	ba := make(chan []byte, 256)
	a := &pipeConn{in: ba, out: ab, closed: make(chan struct{})}
	b := &pipeConn{in: ab, out: ba, closed: make(chan struct{})}
	return a, b
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "rist: dtls: pipe i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func (p *pipeConn) Read(buf []byte) (int, error) {
	p.mu.Lock()
	dl := p.deadline
	p.mu.Unlock()
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
	case dg, ok := <-p.in:
		if !ok {
			return 0, io.EOF
		}
		return copy(buf, dg), nil
	case <-tch:
		return 0, timeoutError{}
	case <-p.closed:
		return 0, io.EOF
	}
}

func (p *pipeConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	select {
	case p.out <- cp:
		return len(b), nil
	case <-p.closed:
		return 0, io.ErrClosedPipe
	}
}

func (p *pipeConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return nil
}

func (p *pipeConn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// handshakePair runs a client and server handshake concurrently over a fresh
// pipe and returns the connected Conns, failing the test on any handshake error.
func handshakePair(t *testing.T, clientCfg, serverCfg *Config) (*Conn, *Conn) {
	t.Helper()
	ca, sa := newPipe()
	client := Client(ca, clientCfg)
	server := Server(sa, serverCfg)

	var wg sync.WaitGroup
	var serr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serr = server.Handshake()
	}()
	cerr := client.Handshake()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", cerr, serr)
	}
	return client, server
}

// exchange asserts bidirectional protected application data flows correctly.
func exchange(t *testing.T, client, server *Conn) {
	t.Helper()
	cToS := []byte("client→server protected payload (GRE tunnel bytes)")
	sToC := []byte("server→client protected payload")

	if _, err := client.Write(cToS); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], cToS) {
		t.Fatalf("server read: got %q err %v", buf[:n], err)
	}

	if _, err := server.Write(sToC); err != nil {
		t.Fatalf("server write: %v", err)
	}
	n, err = client.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], sToC) {
		t.Fatalf("client read: got %q err %v", buf[:n], err)
	}
}

func TestHandshakePSK(t *testing.T) {
	cfg := func() *Config {
		return &Config{PSK: []byte("a-shared-secret"), PSKIdentity: []byte("ristgo")}
	}
	client, server := handshakePair(t, cfg(), cfg())
	defer client.Close()
	if cs, _ := client.ConnectionState(); cs != tlsPSKWithAES128GCMSHA256 {
		t.Fatalf("client suite = %#04x, want PSK", cs)
	}
	if cs, _ := server.ConnectionState(); cs != tlsPSKWithAES128GCMSHA256 {
		t.Fatalf("server suite = %#04x, want PSK", cs)
	}
	exchange(t, client, server)
}

func TestHandshakeECDHEInsecure(t *testing.T) {
	cert, err := GenerateSelfSigned("ristgo-dtls")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	client, server := handshakePair(t,
		&Config{Certificate: nil, InsecureSkipVerify: true},
		&Config{Certificate: cert},
	)
	defer client.Close()
	cs, leaf := client.ConnectionState()
	if cs != tlsECDHEECDSAWithAES128GCMSHA256 {
		t.Fatalf("client suite = %#04x, want ECDHE_ECDSA", cs)
	}
	if leaf == nil {
		t.Fatal("client did not capture the server certificate")
	}
	exchange(t, client, server)
}

func TestHandshakeECDHEFingerprintPin(t *testing.T) {
	cert, err := GenerateSelfSigned("ristgo-dtls")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	client, server := handshakePair(t,
		&Config{Certificate: nil, PeerCertFingerprint: cert.Fingerprint()},
		&Config{Certificate: cert},
	)
	defer client.Close()
	exchange(t, client, server)
}

func TestHandshakeECDHEFingerprintMismatch(t *testing.T) {
	cert, _ := GenerateSelfSigned("ristgo-dtls")
	var wrong [32]byte
	wrong[0] = 0xFF
	ca, sa := newPipe()
	client := Client(ca, &Config{PeerCertFingerprint: wrong})
	server := Server(sa, &Config{Certificate: cert})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = server.Handshake() }()
	if err := client.Handshake(); err == nil {
		t.Fatal("expected handshake failure on fingerprint mismatch")
	}
	client.Close()
	server.Close()
	wg.Wait()
}

func TestHandshakeMutualAuth(t *testing.T) {
	serverCert, _ := GenerateSelfSigned("ristgo-server")
	clientCert, _ := GenerateSelfSigned("ristgo-client")
	client, server := handshakePair(t,
		&Config{Certificate: clientCert, PeerCertFingerprint: serverCert.Fingerprint()},
		&Config{Certificate: serverCert, RequireClientCert: true, PeerCertFingerprint: clientCert.Fingerprint()},
	)
	defer client.Close()
	if _, peer := server.ConnectionState(); peer == nil {
		t.Fatal("server did not authenticate the client certificate")
	}
	exchange(t, client, server)
}

// TestHandshakePrefersCert checks suite selection: when both sides can do PSK and
// the server also has a certificate, ECDHE_ECDSA is chosen.
func TestHandshakePreferCert(t *testing.T) {
	cert, _ := GenerateSelfSigned("ristgo-dtls")
	client, server := handshakePair(t,
		&Config{PSK: []byte("secret"), Certificate: nil, InsecureSkipVerify: true},
		&Config{PSK: []byte("secret"), Certificate: cert},
	)
	defer client.Close()
	if cs, _ := client.ConnectionState(); cs != tlsECDHEECDSAWithAES128GCMSHA256 {
		t.Fatalf("suite = %#04x, want ECDHE_ECDSA preferred", cs)
	}
	exchange(t, client, server)
}

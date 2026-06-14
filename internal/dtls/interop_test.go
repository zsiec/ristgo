//go:build interop

// Package-level interop tests against the OpenSSL DTLS CLI. libRIST has no DTLS,
// so OpenSSL's s_server/s_client are the external reference that proves ristgo's
// DTLS bytes (handshake encoding, PRF/key schedule, record AEAD) interoperate
// with an independent implementation. Run with:
//
//	go test -tags interop -run TestInterop -v ./internal/dtls/
//
// The whole suite skips gracefully when openssl is absent or lacks DTLS 1.2.
package dtls

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func opensslPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found; skipping DTLS interop")
	}
	out, err := exec.Command(p, "s_server", "-help").CombinedOutput()
	if err == nil && !strings.Contains(string(out), "-dtls1_2") {
		t.Skip("openssl lacks -dtls1_2; skipping DTLS interop")
	}
	return p
}

// freeUDPPort returns an available UDP port on loopback.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// writePEM writes a certificate + EC private key as PEM files for openssl.
func writePEM(t *testing.T, cert *Certificate) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = dir + "/cert.pem"
	keyFile = dir + "/key.pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.DER[0]})
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// opensslServer is a running `openssl s_server` over DTLS 1.2: it prints
// received application data to stdout and sends whatever is written to its stdin
// over the connection, giving a bidirectional interop oracle (DTLS forbids the
// -rev echo mode).
type opensslServer struct {
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	lines  chan string
	stderr *bytes.Buffer
}

// startServer launches s_server on the given UDP port (no -rev; that is rejected
// for DTLS). It binds immediately, so a short settle suffices.
func startServer(t *testing.T, openssl string, port int, args ...string) *opensslServer {
	t.Helper()
	full := append([]string{
		"s_server", "-dtls1_2", "-quiet",
		"-accept", fmt.Sprintf("127.0.0.1:%d", port),
	}, args...)
	cmd := exec.Command(openssl, full...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start openssl s_server: %v", err)
	}
	s := &opensslServer{cmd: cmd, stdin: bufio.NewWriter(stdinPipe), stderr: &stderr, lines: make(chan string, 16)}
	go func() {
		sc := bufio.NewScanner(stdoutPipe)
		for sc.Scan() {
			select {
			case s.lines <- sc.Text():
			default:
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	return s
}

func (s *opensslServer) stop(t *testing.T) {
	_ = s.cmd.Process.Kill()
	_ = s.cmd.Wait()
	if t.Failed() {
		t.Logf("openssl s_server stderr:\n%s", s.stderr.String())
	}
}

// send writes a line to the server, which forwards it over DTLS to the client.
func (s *opensslServer) send(line string) error {
	if _, err := s.stdin.WriteString(line); err != nil {
		return err
	}
	return s.stdin.Flush()
}

// expectLine waits for stdout to contain want (the data the server received over
// DTLS), proving the client→server direction.
func (s *opensslServer) expectLine(t *testing.T, want string) {
	t.Helper()
	deadline := time.After(8 * time.Second)
	for {
		select {
		case line := <-s.lines:
			if strings.Contains(line, want) {
				return
			}
		case <-deadline:
			t.Fatalf("openssl server never reported receiving %q; stderr:\n%s", want, s.stderr.String())
		}
	}
}

// dialDTLS dials a DTLS server on loopback and returns a connected datagram conn.
func dialDTLS(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	return conn
}

// clientExchange handshakes as a DTLS client against the openssl s_server and
// validates both directions: the client's data appears on the server's stdout,
// and data fed to the server's stdin is received (decrypted) by the client.
func clientExchange(t *testing.T, srv *opensslServer, port int, cfg *Config) {
	t.Helper()
	udp := dialDTLS(t, port)
	defer udp.Close()
	conn := Client(udp, cfg)
	if err := conn.Handshake(); err != nil {
		t.Fatalf("client handshake vs openssl: %v", err)
	}

	// client → server
	if _, err := conn.Write([]byte("ristgo-ping\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	srv.expectLine(t, "ristgo-ping")

	// server → client
	if err := srv.send("openssl-pong\n"); err != nil {
		t.Fatalf("server send: %v", err)
	}
	buf := make([]byte, 4096)
	udp.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read from openssl: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("openssl-pong")) {
		t.Fatalf("client read = %q, want to contain %q", buf[:n], "openssl-pong")
	}
}

func TestInteropClientPSK(t *testing.T) {
	openssl := opensslPath(t)
	port := freeUDPPort(t)
	psk := []byte("ristgointeropsecret")
	srv := startServer(t, openssl, port,
		"-nocert", "-psk", hex.EncodeToString(psk),
		"-psk_identity", "ristgo", "-cipher", "PSK-AES128-GCM-SHA256",
	)
	defer srv.stop(t)
	clientExchange(t, srv, port, &Config{PSK: psk, PSKIdentity: []byte("ristgo")})
}

func TestInteropClientECDHE(t *testing.T) {
	openssl := opensslPath(t)
	cert, err := GenerateSelfSigned("ristgo-dtls")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certFile, keyFile := writePEM(t, cert)
	port := freeUDPPort(t)
	srv := startServer(t, openssl, port,
		"-cert", certFile, "-key", keyFile,
		"-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256",
	)
	defer srv.stop(t)
	clientExchange(t, srv, port, &Config{PeerCertFingerprint: cert.Fingerprint()})
}

// TestInteropServerPSK runs ristgo as the DTLS server and openssl s_client as the
// client (PSK), proving the server-side encoding too.
func TestInteropServerPSK(t *testing.T) {
	openssl := opensslPath(t)
	psk := []byte("ristgointeropsecret")
	runServerInterop(t, openssl, &Config{PSK: psk, PSKIdentity: []byte("ristgo")},
		"-psk", hex.EncodeToString(psk), "-psk_identity", "ristgo",
		"-cipher", "PSK-AES128-GCM-SHA256")
}

// TestInteropServerECDHE runs ristgo as the DTLS server with a certificate and
// openssl s_client as the client.
func TestInteropServerECDHE(t *testing.T) {
	openssl := opensslPath(t)
	cert, err := GenerateSelfSigned("ristgo-dtls")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	runServerInterop(t, openssl, &Config{Certificate: cert},
		"-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256")
}

// runServerInterop binds a ristgo DTLS server on a UDP port, launches openssl
// s_client to connect and send a line, and verifies ristgo echoes it back.
func runServerInterop(t *testing.T, openssl string, cfg *Config, clientArgs ...string) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	// Learn the client address from the first datagram, then serve a connected
	// view that replays it.
	serverDone := make(chan error, 1)
	go func() {
		adapter, err := acceptOne(pc)
		if err != nil {
			serverDone <- err
			return
		}
		conn := Server(adapter, cfg)
		if err := conn.Handshake(); err != nil {
			serverDone <- fmt.Errorf("server handshake: %w", err)
			return
		}
		// Echo one line back.
		buf := make([]byte, 4096)
		adapter.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Errorf("server read: %w", err)
			return
		}
		_, err = conn.Write(buf[:n])
		serverDone <- err
	}()

	full := append([]string{
		"s_client", "-dtls1_2", "-quiet",
		"-connect", fmt.Sprintf("127.0.0.1:%d", port),
	}, clientArgs...)
	cmd := exec.Command(openssl, full...)
	cmd.Stdin = strings.NewReader("hello-from-openssl\n")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatalf("start s_client: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-serverDone:
		if err != nil {
			_ = cmd.Process.Kill()
			t.Fatalf("ristgo server: %v\ns_client stderr:\n%s", err, errb.String())
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("server timeout; s_client stderr:\n%s", errb.String())
	}
	// Give s_client a moment to receive the echo, then stop it.
	time.Sleep(300 * time.Millisecond)
	_ = cmd.Process.Kill()
	<-done
	if !bytes.Contains(out.Bytes(), []byte("hello-from-openssl")) {
		t.Fatalf("s_client did not receive the echo; stdout=%q stderr=%q", out.String(), errb.String())
	}
}

// udpAdapter presents a connected datagram view of a listening UDP socket bound
// to one learned peer, replaying the first datagram that was peeked to learn it.
type udpAdapter struct {
	pc    *net.UDPConn
	peer  *net.UDPAddr
	first []byte
}

func acceptOne(pc *net.UDPConn) (*udpAdapter, error) {
	buf := make([]byte, readBufSize)
	n, addr, err := pc.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return &udpAdapter{pc: pc, peer: addr, first: append([]byte(nil), buf[:n]...)}, nil
}

func (a *udpAdapter) Read(p []byte) (int, error) {
	if a.first != nil {
		n := copy(p, a.first)
		a.first = nil
		return n, nil
	}
	for {
		n, addr, err := a.pc.ReadFromUDP(p)
		if err != nil {
			return 0, err
		}
		if addr.IP.Equal(a.peer.IP) && addr.Port == a.peer.Port {
			return n, nil
		}
	}
}

func (a *udpAdapter) Write(p []byte) (int, error)       { return a.pc.WriteToUDP(p, a.peer) }
func (a *udpAdapter) SetReadDeadline(t time.Time) error { return a.pc.SetReadDeadline(t) }
func (a *udpAdapter) Close() error                      { return nil }

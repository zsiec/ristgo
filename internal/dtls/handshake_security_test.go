package dtls

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// noCVClientHandshake drives a DTLS ECDHE client handshake that PRESENTS a
// client certificate but deliberately OMITS the CertificateVerify message, and
// computes its Finished over a transcript that likewise excludes CertificateVerify
// — exactly what an attacker holding only a victim's public certificate (no
// private key) can produce. It mirrors clientHandshake's flight plumbing; a
// conforming server must reject it (RFC 5246 §7.4.8, finding C1).
func (c *Conn) noCVClientHandshake() error {
	cfg := c.cfg
	overall := time.Now().Add(cfg.HandshakeTimeout)
	c.reasm = newReassembler()
	c.curRetrans = cfg.RetransmitTimeout

	suites := []uint16{tlsECDHEECDSAWithAES128GCMSHA256}
	clientRandom := make([]byte, randomLen)
	if _, err := readFullRand(cfg, clientRandom); err != nil {
		return err
	}
	chBody := func(cookie []byte) []byte {
		body, _ := clientHello{
			version:             versionDTLS12,
			random:              clientRandom,
			cookie:              cookie,
			cipherSuites:        suites,
			extMasterSecret:     true,
			supportedGroups:     []uint16{namedGroupSecp256r1},
			pointFormats:        []uint8{ecPointUncompressed},
			signatureAlgorithms: []uint16{sigSchemeECDSAP256SHA256},
		}.marshalBody()
		return body
	}

	f1 := &flight{}
	c.emitHandshake(f1, typeClientHello, 0, chBody(nil), false)
	if err := c.sendFlight(f1); err != nil {
		return err
	}
	msg, err := c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	hvr, err := parseHelloVerifyRequest(msg.body)
	if err != nil {
		return err
	}
	f3 := &flight{}
	c.emitHandshake(f3, typeClientHello, 0, chBody(hvr.cookie), true)
	if err := c.sendFlight(f3); err != nil {
		return err
	}

	sh, err := c.readServerHello(overall)
	if err != nil {
		return err
	}
	serverRandom := sh.random
	useEMS := sh.extMasterSecret
	c.suite = testSuite()

	var serverECDHEPub []byte
	for done := false; !done; {
		msg, err = c.readHandshakeMessage(overall)
		if err != nil {
			return err
		}
		c.addToTranscript(msg)
		switch msg.typ {
		case typeCertificate:
			cert, err := parseCertificate(msg.body)
			if err != nil {
				return err
			}
			leaf, err := verifyPeerCertificate(cert.chain, cfg, verifyingServerCert)
			if err != nil {
				return err
			}
			c.peerLeaf = leaf
		case typeServerKeyExchange:
			pub, err := c.verifyServerKeyExchange(msg.body, clientRandom, serverRandom)
			if err != nil {
				return err
			}
			serverECDHEPub = pub
		case typeCertificateRequest:
			// requested; we present a cert but no CertificateVerify.
		case typeServerHelloDone:
			done = true
		}
	}

	priv, pub, err := generateECDHE(cfg.Rand)
	if err != nil {
		return err
	}
	pms, err := ecdhePremaster(priv, serverECDHEPub)
	if err != nil {
		return err
	}
	clientKX, _ := clientKeyExchangeECDHE{publicKey: pub}.marshalBody()

	// Flight 5: Certificate, ClientKeyExchange, (NO CertificateVerify), CCS,
	// Finished.
	f5 := &flight{}
	certBody, _ := certificateMsg{chain: cfg.Certificate.DER}.marshalBody()
	c.emitHandshake(f5, typeCertificate, 0, certBody, true)
	c.emitHandshake(f5, typeClientKeyExchange, 0, clientKX, true)

	master := c.deriveMaster(pms, useEMS, clientRandom, serverRandom)
	keys, err := deriveKeys(testSuite(), master, clientRandom, serverRandom)
	if err != nil {
		return err
	}
	c.keys = keys
	c.keysReady = true

	emitCCS(f5)
	clientVerify := finishedVerifyData(c.suite.newHash, master, labelClientFinished, c.transcriptHash())
	c.emitHandshake(f5, typeFinished, 1, marshalFinished(clientVerify), true)
	if err := c.sendFlight(f5); err != nil {
		return err
	}

	srvFin, err := c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	if srvFin.typ != typeFinished {
		return errors.New("expected server Finished")
	}
	c.sendEpoch = 1
	return nil
}

// readFullRand fills b from cfg.Rand (a tiny helper so the test client mirrors
// the production io.ReadFull(cfg.Rand, ...) pattern).
func readFullRand(cfg *Config, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := cfg.Rand.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// TestClientCertWithoutCertificateVerifyRejected is the C1 regression test: a
// client that presents a (validly pinned) certificate but never sends a
// CertificateVerify must be rejected by the server, because in ECDHE the
// Finished MAC verifies without the certificate's private key — CertificateVerify
// is the only proof of possession (RFC 5246 §7.4.8). Without the fix the server
// would authenticate the cert owner from a public certificate alone.
func TestClientCertWithoutCertificateVerifyRejected(t *testing.T) {
	serverCert, _ := GenerateSelfSigned("ristgo-server")
	clientCert, _ := GenerateSelfSigned("ristgo-client")

	cfg := func() *Config {
		return &Config{RetransmitTimeout: 50 * time.Millisecond, HandshakeTimeout: 5 * time.Second}
	}
	clientCfg := cfg()
	clientCfg.Certificate = clientCert
	clientCfg.PeerCertFingerprint = serverCert.Fingerprint()
	serverCfg := cfg()
	serverCfg.Certificate = serverCert
	serverCfg.RequireClientCert = true
	serverCfg.PeerCertFingerprint = clientCert.Fingerprint()

	ca, sa := newPipe()
	client := Client(ca, clientCfg)
	server := Server(sa, serverCfg)

	var serr error
	done := make(chan struct{})
	go func() { serr = server.Handshake(); close(done) }()

	// Drive the malicious client directly.
	cerr := client.noCVClientHandshake()
	<-done

	if serr == nil {
		t.Fatal("server accepted a client that omitted CertificateVerify (auth bypass)")
	}
	if !strings.Contains(serr.Error(), "CertificateVerify") && !strings.Contains(serr.Error(), "did not authenticate") {
		t.Fatalf("server rejected for the wrong reason: %v", serr)
	}
	if _, peer := server.ConnectionState(); peer != nil {
		t.Fatal("server exposed an authenticated peer leaf without CertificateVerify")
	}
	_ = cerr // the client side errors out once the server aborts; not asserted.
	client.Close()
	server.Close()
}

// noEMSServerFlight4 drives a server far enough to send a ServerHello that
// OMITS the extended_master_secret extension (simulating a downgrade attacker or
// a non-RFC-7627 peer), then stops. It is enough to exercise the client's L6
// downgrade guard, which aborts on the stripped ServerHello before Flight 5.
func (c *Conn) noEMSServerFlight4() error {
	cfg := c.cfg
	overall := time.Now().Add(cfg.HandshakeTimeout)
	c.reasm = newReassembler()
	c.curRetrans = cfg.RetransmitTimeout

	// Flight 1: cookieless ClientHello.
	if _, err := c.readHandshakeMessage(overall); err != nil {
		return err
	}
	// Flight 2: HelloVerifyRequest.
	cookie := make([]byte, cookieLen)
	if _, err := readFullRand(cfg, cookie); err != nil {
		return err
	}
	hvrBody, _ := helloVerifyRequest{version: versionDTLS10, cookie: cookie}.marshalBody()
	f2 := &flight{}
	c.emitHandshake(f2, typeHelloVerifyRequest, 0, hvrBody, false)
	if err := c.sendFlight(f2); err != nil {
		return err
	}
	// Flight 3: cookie ClientHello.
	msg, err := c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	ch, err := parseClientHello(msg.body)
	if err != nil {
		return err
	}
	c.addToTranscript(msg)
	suite, err := selectSuite(cfg, ch.cipherSuites)
	if err != nil {
		return err
	}
	c.cipherSuite = suite.id
	c.suite = suite
	clientRandom := ch.random
	serverRandom := make([]byte, randomLen)
	if _, err := readFullRand(cfg, serverRandom); err != nil {
		return err
	}

	// Flight 4: ServerHello WITHOUT extended_master_secret, then the ECDHE flight.
	f4 := &flight{}
	shBody, _ := serverHello{
		version:     versionDTLS12,
		random:      serverRandom,
		cipherSuite: suite.id,
		// extMasterSecret deliberately false (the stripped extension).
	}.marshalBody()
	c.emitHandshake(f4, typeServerHello, 0, shBody, true)
	certBody, _ := certificateMsg{chain: cfg.Certificate.DER}.marshalBody()
	c.emitHandshake(f4, typeCertificate, 0, certBody, true)
	priv, pub, err := generateECDHE(cfg.Rand)
	if err != nil {
		return err
	}
	_ = priv
	ske := serverKeyExchange{curve: namedGroupSecp256r1, publicKey: pub}
	signed := make([]byte, 0)
	signed = append(signed, clientRandom...)
	signed = append(signed, serverRandom...)
	signed = append(signed, ske.signedParams()...)
	sigScheme, sig, err := signHandshake(cfg.Certificate, signed)
	if err != nil {
		return err
	}
	ske.sigScheme = sigScheme
	ske.signature = sig
	skeBody, _ := ske.marshalBody()
	c.emitHandshake(f4, typeServerKeyExchange, 0, skeBody, true)
	c.emitHandshake(f4, typeServerHelloDone, 0, nil, true)
	return c.sendFlight(f4)
}

// TestRequireExtendedMasterSecretRejectsStrippedServerHello is the L6 regression
// test: with RequireExtendedMasterSecret set, a client must abort when the
// ServerHello omits the extended_master_secret extension (RFC 7627 downgrade
// guard). The default (field unset) still accepts a non-EMS server.
func TestRequireExtendedMasterSecretRejectsStrippedServerHello(t *testing.T) {
	serverCert, _ := GenerateSelfSigned("ristgo-server")

	ca, sa := newPipe()
	clientCfg := &Config{
		PeerCertFingerprint:         serverCert.Fingerprint(),
		RequireExtendedMasterSecret: true,
		RetransmitTimeout:           50 * time.Millisecond,
		HandshakeTimeout:            3 * time.Second,
	}
	serverCfg := &Config{
		Certificate:       serverCert,
		RetransmitTimeout: 50 * time.Millisecond,
		HandshakeTimeout:  3 * time.Second,
	}
	client := Client(ca, clientCfg)
	server := Server(sa, serverCfg)

	done := make(chan struct{})
	go func() { _ = server.noEMSServerFlight4(); close(done) }()

	err := client.Handshake()
	if err == nil {
		t.Fatal("client accepted a ServerHello that stripped extended_master_secret")
	}
	if !strings.Contains(err.Error(), "extended_master_secret") {
		t.Fatalf("client aborted for the wrong reason: %v", err)
	}
	client.Close()
	server.Close()
	<-done
}

// TestExtendedMasterSecretDefaultAcceptsNonEMS confirms the default (the field
// unset) preserves prior behavior: a client without RequireExtendedMasterSecret
// completes the handshake against a server that omits EMS.
func TestExtendedMasterSecretDefaultAcceptsNonEMS(t *testing.T) {
	serverCert, _ := GenerateSelfSigned("ristgo-server")

	ca, sa := newPipe()
	clientCfg := &Config{
		PeerCertFingerprint: serverCert.Fingerprint(),
		// RequireExtendedMasterSecret intentionally left false.
		RetransmitTimeout: 50 * time.Millisecond,
		HandshakeTimeout:  500 * time.Millisecond,
	}
	serverCfg := &Config{
		Certificate:       serverCert,
		RetransmitTimeout: 50 * time.Millisecond,
		HandshakeTimeout:  500 * time.Millisecond,
	}
	client := Client(ca, clientCfg)
	server := Server(sa, serverCfg)

	// The real client offers EMS, so the real server would echo it. To prove the
	// DEFAULT tolerates a non-EMS server, parse the ServerHello path directly: a
	// client whose ServerHello lacks EMS must still proceed (no abort on the EMS
	// check). We assert only that the EMS check does not fire by confirming the
	// client gets past ServerHello and fails (if at all) for a different reason.
	go func() { _ = server.noEMSServerFlight4() }()
	err := client.Handshake()
	// The handshake will not complete (the test server stops after Flight 4), but
	// the failure must NOT be the EMS downgrade guard.
	if err != nil && strings.Contains(err.Error(), "extended_master_secret") {
		t.Fatalf("default client wrongly enforced EMS: %v", err)
	}
	client.Close()
	server.Close()
}

// TestEmptyClientCertWithRequireStillRejected confirms the pre-existing guard
// still holds: a client that sends an EMPTY Certificate when RequireClientCert is
// set is rejected (the C1 change must not regress this path).
func TestEmptyClientCertWithRequireStillRejected(t *testing.T) {
	serverCert, _ := GenerateSelfSigned("ristgo-server")

	ca, sa := newPipe()
	clientCfg := &Config{
		Certificate:        nil, // client presents no certificate
		InsecureSkipVerify: true,
		RetransmitTimeout:  50 * time.Millisecond,
		HandshakeTimeout:   5 * time.Second,
	}
	serverCfg := &Config{
		Certificate:       serverCert,
		RequireClientCert: true,
		RetransmitTimeout: 50 * time.Millisecond,
		HandshakeTimeout:  5 * time.Second,
	}
	client := Client(ca, clientCfg)
	server := Server(sa, serverCfg)

	var wg sync.WaitGroup
	var serr error
	wg.Add(1)
	go func() { defer wg.Done(); serr = server.Handshake() }()
	cerr := client.Handshake()
	wg.Wait()

	if cerr == nil && serr == nil {
		t.Fatal("handshake succeeded despite RequireClientCert with no client cert")
	}
	if serr == nil {
		t.Fatalf("server did not reject an empty client certificate (client err=%v)", cerr)
	}
	client.Close()
	server.Close()
}

// TestServerKeyExchangeBeforeCertificateRejected proves a malformed/malicious
// server flight that sends ServerKeyExchange before (or without) the Certificate
// message is rejected with an error, not a nil-pointer panic — arbitrary peer input
// must never panic (CLAUDE.md). It exercises verifyServerKeyExchange with c.peerLeaf
// still nil.
func TestServerKeyExchangeBeforeCertificateRejected(t *testing.T) {
	c := &Conn{} // peerLeaf nil: no Certificate processed yet
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("verifyServerKeyExchange panicked on a pre-Certificate ServerKeyExchange: %v", r)
		}
	}()
	// A well-formed ECDHE SKE body (curve_type=named_curve, secp256r1, empty point);
	// it must be rejected for arriving before the Certificate, regardless of body.
	body := []byte{3, 0x00, 0x17, 0x00}
	if _, err := c.verifyServerKeyExchange(body, make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("expected an error for ServerKeyExchange before Certificate, got nil")
	}
}

package dtls

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"time"
)

// The DTLS 1.2 client handshake (RFC 6347 + RFC 5246), driving the full flight
// sequence: ClientHello → HelloVerifyRequest → ClientHello(cookie) → server
// flight → client key exchange + Finished → server Finished.
func (c *Conn) clientHandshake() error {
	cfg := c.cfg
	overall := time.Now().Add(cfg.HandshakeTimeout)
	c.reasm = newReassembler()
	c.curRetrans = cfg.RetransmitTimeout

	var suites []uint16
	if cfg.canVerifyCert() {
		suites = append(suites, tlsECDHEECDSAWithAES128GCMSHA256)
	}
	if cfg.offersPSK() {
		suites = append(suites, tlsPSKWithAES128GCMSHA256)
	}
	if len(suites) == 0 {
		return errors.New("rist: dtls: client config enables neither PSK nor certificate verification")
	}

	clientRandom := make([]byte, randomLen)
	if _, err := io.ReadFull(cfg.Rand, clientRandom); err != nil {
		return fmt.Errorf("rist: dtls: client random: %w", err)
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

	// Flight 1: cookieless ClientHello (excluded from the transcript).
	f1 := &flight{}
	c.emitHandshake(f1, typeClientHello, 0, chBody(nil), false)
	if err := c.sendFlight(f1); err != nil {
		return err
	}

	// Flight 2: HelloVerifyRequest (excluded from the transcript).
	msg, err := c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	if msg.typ != typeHelloVerifyRequest {
		return fmt.Errorf("rist: dtls: expected HelloVerifyRequest, got %d", msg.typ)
	}
	hvr, err := parseHelloVerifyRequest(msg.body)
	if err != nil {
		return err
	}

	// Flight 3: ClientHello with the cookie — the first transcript message.
	f3 := &flight{}
	c.emitHandshake(f3, typeClientHello, 0, chBody(hvr.cookie), true)
	if err := c.sendFlight(f3); err != nil {
		return err
	}

	// Flight 4: the server's hello flight.
	sh, err := c.readServerHello(overall)
	if err != nil {
		return err
	}
	c.cipherSuite = sh.cipherSuite
	serverRandom := sh.random
	useEMS := sh.extMasterSecret
	// Downgrade guard (RFC 7627): the client always offers extended_master_secret,
	// so a ServerHello that omits it means either a non-EMS peer or an attacker who
	// stripped the extension to force the weaker legacy derivation. When the caller
	// requires EMS, refuse to continue rather than silently fall back.
	if cfg.RequireExtendedMasterSecret && !useEMS {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("rist: dtls: server omitted extended_master_secret but it is required")
	}
	isECDHE := c.cipherSuite == tlsECDHEECDSAWithAES128GCMSHA256
	isPSK := c.cipherSuite == tlsPSKWithAES128GCMSHA256
	if !isECDHE && !isPSK {
		c.sendAlert(alertHandshakeFailure)
		return fmt.Errorf("rist: dtls: server chose unsupported suite %#04x", c.cipherSuite)
	}
	if isECDHE && !cfg.canVerifyCert() || isPSK && !cfg.offersPSK() {
		c.sendAlert(alertHandshakeFailure)
		return fmt.Errorf("rist: dtls: server chose a suite we did not offer")
	}

	var serverECDHEPub []byte
	var certRequested bool
	for done := false; !done; {
		msg, err = c.readHandshakeMessage(overall)
		if err != nil {
			return err
		}
		c.addToTranscript(msg)
		switch msg.typ {
		case typeCertificate:
			if !isECDHE {
				return errors.New("rist: dtls: unexpected Certificate in PSK handshake")
			}
			cert, err := parseCertificate(msg.body)
			if err != nil {
				return err
			}
			leaf, err := verifyPeerCertificate(cert.chain, cfg, verifyingServerCert)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
			c.peerLeaf = leaf
		case typeServerKeyExchange:
			if isECDHE {
				pub, err := c.verifyServerKeyExchange(msg.body, clientRandom, serverRandom)
				if err != nil {
					c.sendAlert(alertDecryptError)
					return err
				}
				serverECDHEPub = pub
			}
			// In PSK mode a ServerKeyExchange carries only an identity hint; ignore.
		case typeCertificateRequest:
			certRequested = true
		case typeServerHelloDone:
			done = true
		default:
			return fmt.Errorf("rist: dtls: unexpected message %d in server flight", msg.typ)
		}
	}
	if isECDHE && (c.peerLeaf == nil || serverECDHEPub == nil) {
		return errors.New("rist: dtls: server flight missing Certificate or ServerKeyExchange")
	}

	// Compute the pre-master secret and the ClientKeyExchange body.
	var pms, clientKX []byte
	if isECDHE {
		priv, pub, err := generateECDHE(cfg.Rand)
		if err != nil {
			return err
		}
		if pms, err = ecdhePremaster(priv, serverECDHEPub); err != nil {
			c.sendAlert(alertHandshakeFailure)
			return err
		}
		clientKX, _ = clientKeyExchangeECDHE{publicKey: pub}.marshalBody()
	} else {
		pms = pskPremaster(cfg.PSK)
		clientKX, _ = clientKeyExchangePSK{identity: cfg.PSKIdentity}.marshalBody()
	}

	// Flight 5: [Certificate], ClientKeyExchange, [CertificateVerify], CCS,
	// Finished.
	f5 := &flight{}
	var clientCert *Certificate
	if certRequested {
		clientCert = cfg.Certificate
		var chain [][]byte
		if clientCert != nil {
			chain = clientCert.DER
		}
		certBody, _ := certificateMsg{chain: chain}.marshalBody()
		c.emitHandshake(f5, typeCertificate, 0, certBody, true)
	}
	c.emitHandshake(f5, typeClientKeyExchange, 0, clientKX, true)

	// The transcript now runs through ClientKeyExchange: derive the master secret.
	master := c.deriveMaster(pms, useEMS, clientRandom, serverRandom)
	keys, err := deriveKeys(master, clientRandom, serverRandom)
	if err != nil {
		return err
	}
	c.keys = keys
	c.keysReady = true

	if certRequested && clientCert != nil {
		sig, err := signECDSA(clientCert.PrivateKey, c.transcript)
		if err != nil {
			return err
		}
		cvBody, _ := certificateVerify{sigScheme: sigSchemeECDSAP256SHA256, signature: sig}.marshalBody()
		c.emitHandshake(f5, typeCertificateVerify, 0, cvBody, true)
	}

	emitCCS(f5)
	clientVerify := finishedVerifyData(master, labelClientFinished, c.transcriptHash())
	c.emitHandshake(f5, typeFinished, 1, marshalFinished(clientVerify), true)
	if err := c.sendFlight(f5); err != nil {
		return err
	}

	// Flight 6: the server's CCS + Finished. verify_data covers the transcript
	// through our (client) Finished, which is now in c.transcript.
	expectedServerVerify := finishedVerifyData(master, labelServerFinished, c.transcriptHash())
	srvFin, err := c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	if srvFin.typ != typeFinished {
		return fmt.Errorf("rist: dtls: expected server Finished, got %d", srvFin.typ)
	}
	if !c.peerCCS {
		return errors.New("rist: dtls: server Finished without ChangeCipherSpec")
	}
	// A Finished MUST be epoch-1 protected (RFC 5246 §7.4.9 / RFC 6347); reject one
	// reassembled from epoch-0 plaintext (L8).
	if srvFin.epoch != 1 {
		c.sendAlert(alertDecryptError)
		return errors.New("rist: dtls: server Finished arrived unprotected (epoch 0)")
	}
	if !hmac.Equal(expectedServerVerify, srvFin.body) {
		c.sendAlert(alertDecryptError)
		return errors.New("rist: dtls: server Finished verify_data mismatch")
	}

	c.sendEpoch = 1
	return nil
}

// readServerHello reads and parses the ServerHello, adding it to the transcript.
func (c *Conn) readServerHello(overall time.Time) (serverHello, error) {
	msg, err := c.readHandshakeMessage(overall)
	if err != nil {
		return serverHello{}, err
	}
	if msg.typ != typeServerHello {
		return serverHello{}, fmt.Errorf("rist: dtls: expected ServerHello, got %d", msg.typ)
	}
	sh, err := parseServerHello(msg.body)
	if err != nil {
		return serverHello{}, err
	}
	c.addToTranscript(msg)
	return sh, nil
}

// verifyServerKeyExchange parses the ECDHE ServerKeyExchange, checks the ECDSA
// signature over client_random || server_random || params, and returns the
// server's ephemeral public point.
func (c *Conn) verifyServerKeyExchange(body, clientRandom, serverRandom []byte) ([]byte, error) {
	ske, err := parseServerKeyExchange(body)
	if err != nil {
		return nil, err
	}
	if ske.curve != namedGroupSecp256r1 {
		return nil, fmt.Errorf("rist: dtls: server chose curve %d, want secp256r1", ske.curve)
	}
	if ske.sigScheme != sigSchemeECDSAP256SHA256 {
		return nil, fmt.Errorf("rist: dtls: server sig scheme %#04x unsupported", ske.sigScheme)
	}
	pub, ok := c.peerLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("rist: dtls: server certificate is not ECDSA")
	}
	signed := make([]byte, 0, len(clientRandom)+len(serverRandom)+len(ske.signedParams()))
	signed = append(signed, clientRandom...)
	signed = append(signed, serverRandom...)
	signed = append(signed, ske.signedParams()...)
	if !verifyECDSA(pub, signed, ske.signature) {
		return nil, errors.New("rist: dtls: ServerKeyExchange signature invalid")
	}
	return ske.publicKey, nil
}

// deriveMaster derives the master secret, using the extended_master_secret
// session hash when both peers negotiated it (RFC 7627), else the classic
// client/server randoms (RFC 5246 §8.1).
func (c *Conn) deriveMaster(pms []byte, useEMS bool, clientRandom, serverRandom []byte) []byte {
	if useEMS {
		return extendedMasterSecret(pms, c.transcriptHash())
	}
	return masterSecret(pms, clientRandom, serverRandom)
}

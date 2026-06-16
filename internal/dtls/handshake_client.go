package dtls

import (
	"crypto/hmac"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"slices"
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

	suites := cfg.clientSuites()
	if len(suites) == 0 {
		return errors.New("rist: dtls: client config enables no cipher suite (need a PSK or the ability to verify a certificate, with at least one suite not disabled)")
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
			signatureAlgorithms: offeredSignatureAlgorithms,
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
	suite, ok := lookupSuite(c.cipherSuite)
	if !ok || !slices.Contains(suites, c.cipherSuite) {
		c.sendAlert(alertHandshakeFailure)
		return fmt.Errorf("rist: dtls: server chose a suite we did not offer (%#04x)", c.cipherSuite)
	}
	c.suite = suite
	usesCert := suite.kx == kxECDHE || suite.kx == kxRSA

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
			if !usesCert {
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
			// The leaf's key type must match the negotiated suite's authentication
			// method (symmetric with the server's serverCanSelect check): an
			// ECDHE_ECDSA suite needs an ECDSA leaf, an ECDHE_RSA / RSA suite an RSA
			// leaf (RFC 5246 §7.4.2). Reject a mismatch even though the cert is
			// independently pinned/chain-verified, so the suite and credential agree.
			if at, ok := leafKeyType(leaf); !ok || at != suite.auth {
				c.sendAlert(alertHandshakeFailure)
				return fmt.Errorf("rist: dtls: server certificate key type does not match suite %#04x", suite.id)
			}
			c.peerLeaf = leaf
		case typeServerKeyExchange:
			if suite.kx == kxECDHE {
				pub, err := c.verifyServerKeyExchange(msg.body, clientRandom, serverRandom)
				if err != nil {
					c.sendAlert(alertDecryptError)
					return err
				}
				serverECDHEPub = pub
			}
			// PSK ServerKeyExchange carries only an identity hint; RSA key transport
			// has no ServerKeyExchange. Ignore an unexpected one.
		case typeCertificateRequest:
			// A CertificateRequest is meaningless in a PSK handshake (no certificate
			// authentication); reject it rather than honoring it by emitting our
			// certificate over the cleartext epoch-0 channel.
			if !usesCert {
				return errors.New("rist: dtls: unexpected CertificateRequest in PSK handshake")
			}
			certRequested = true
		case typeServerHelloDone:
			done = true
		default:
			return fmt.Errorf("rist: dtls: unexpected message %d in server flight", msg.typ)
		}
	}
	if usesCert && c.peerLeaf == nil {
		return errors.New("rist: dtls: server flight missing Certificate")
	}
	if suite.kx == kxECDHE && serverECDHEPub == nil {
		return errors.New("rist: dtls: ECDHE server flight missing ServerKeyExchange")
	}

	// Compute the pre-master secret and the ClientKeyExchange body for the suite's
	// key-exchange method.
	pms, clientKX, err := c.clientKeyExchange(suite, serverECDHEPub)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
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
	keys, err := deriveKeys(suite, master, clientRandom, serverRandom)
	if err != nil {
		return err
	}
	c.keys = keys
	c.keysReady = true

	if certRequested && clientCert != nil {
		sigScheme, sig, err := signHandshake(clientCert, c.transcript)
		if err != nil {
			return err
		}
		cvBody, _ := certificateVerify{sigScheme: sigScheme, signature: sig}.marshalBody()
		c.emitHandshake(f5, typeCertificateVerify, 0, cvBody, true)
	}

	emitCCS(f5)
	clientVerify := finishedVerifyData(suite.newHash, master, labelClientFinished, c.transcriptHash())
	c.emitHandshake(f5, typeFinished, 1, marshalFinished(clientVerify), true)
	if err := c.sendFlight(f5); err != nil {
		return err
	}

	// Flight 6: the server's CCS + Finished. verify_data covers the transcript
	// through our (client) Finished, which is now in c.transcript.
	expectedServerVerify := finishedVerifyData(suite.newHash, master, labelServerFinished, c.transcriptHash())
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

// clientKeyExchange computes the pre-master secret and the ClientKeyExchange body
// for the negotiated suite: ECDHE (ephemeral key + the server's point), RSA key
// transport (a fresh pre-master RSA-encrypted to the server's certificate), or PSK.
func (c *Conn) clientKeyExchange(suite cipherSuiteInfo, serverECDHEPub []byte) (pms, clientKX []byte, err error) {
	switch suite.kx {
	case kxECDHE:
		priv, pub, err := generateECDHE(c.cfg.Rand)
		if err != nil {
			return nil, nil, err
		}
		if pms, err = ecdhePremaster(priv, serverECDHEPub); err != nil {
			return nil, nil, err
		}
		clientKX, _ = clientKeyExchangeECDHE{publicKey: pub}.marshalBody()
		return pms, clientKX, nil
	case kxRSA:
		rsaPub, ok := c.peerLeaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("rist: dtls: RSA suite but server certificate is not RSA")
		}
		pms, err = newRSAPremaster(c.cfg.Rand)
		if err != nil {
			return nil, nil, err
		}
		enc, err := encryptRSAPremaster(c.cfg.Rand, rsaPub, pms)
		if err != nil {
			return nil, nil, err
		}
		clientKX, _ = clientKeyExchangeRSA{encrypted: enc}.marshalBody()
		return pms, clientKX, nil
	default: // kxPSK
		pms = pskPremaster(c.cfg.PSK)
		clientKX, _ = clientKeyExchangePSK{identity: c.cfg.PSKIdentity}.marshalBody()
		return pms, clientKX, nil
	}
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

// verifyServerKeyExchange parses the ECDHE ServerKeyExchange, checks the
// certificate's signature (ECDSA or RSA) over client_random || server_random ||
// params, and returns the server's ephemeral public point.
func (c *Conn) verifyServerKeyExchange(body, clientRandom, serverRandom []byte) ([]byte, error) {
	// A server that sends ServerKeyExchange before (or without) its Certificate
	// leaves c.peerLeaf nil; reject that out-of-order flight rather than
	// dereferencing a nil leaf (arbitrary peer input must never panic).
	if c.peerLeaf == nil {
		return nil, errors.New("rist: dtls: ServerKeyExchange arrived before the server Certificate")
	}
	ske, err := parseServerKeyExchange(body)
	if err != nil {
		return nil, err
	}
	if ske.curve != namedGroupSecp256r1 {
		return nil, fmt.Errorf("rist: dtls: server chose curve %d, want secp256r1", ske.curve)
	}
	signed := make([]byte, 0, len(clientRandom)+len(serverRandom)+len(ske.signedParams()))
	signed = append(signed, clientRandom...)
	signed = append(signed, serverRandom...)
	signed = append(signed, ske.signedParams()...)
	if err := verifyHandshakeSignature(c.peerLeaf.PublicKey, ske.sigScheme, signed, ske.signature); err != nil {
		return nil, fmt.Errorf("rist: dtls: ServerKeyExchange: %w", err)
	}
	return ske.publicKey, nil
}

// deriveMaster derives the master secret, using the extended_master_secret
// session hash when both peers negotiated it (RFC 7627), else the classic
// client/server randoms (RFC 5246 §8.1).
func (c *Conn) deriveMaster(pms []byte, useEMS bool, clientRandom, serverRandom []byte) []byte {
	if useEMS {
		return extendedMasterSecret(c.suite.newHash, pms, c.transcriptHash())
	}
	return masterSecret(c.suite.newHash, pms, clientRandom, serverRandom)
}

package dtls

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"
)

// cookieLen is the size of the stateless HelloVerifyRequest cookie this server
// generates (RFC 6347 §4.2.1).
const cookieLen = 20

// The DTLS 1.2 server handshake (RFC 6347 + RFC 5246), the mirror of the client:
// ClientHello → HelloVerifyRequest → ClientHello(cookie) → server hello flight →
// client key exchange + Finished → server Finished.
func (c *Conn) serverHandshake() error {
	cfg := c.cfg
	overall := time.Now().Add(cfg.HandshakeTimeout)
	c.reasm = newReassembler()
	c.curRetrans = cfg.RetransmitTimeout // first read precedes any sendFlight
	if !cfg.offersPSK() && !cfg.offersCert() {
		return errors.New("rist: dtls: server config enables neither PSK nor a certificate")
	}

	// Flight 1: the cookieless ClientHello (excluded from the transcript).
	msg, err := c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	if msg.typ != typeClientHello {
		return fmt.Errorf("rist: dtls: expected ClientHello, got %d", msg.typ)
	}
	if _, err := parseClientHello(msg.body); err != nil {
		return err
	}

	// Flight 2: HelloVerifyRequest with a fresh cookie (excluded from the
	// transcript).
	cookie := make([]byte, cookieLen)
	if _, err := io.ReadFull(cfg.Rand, cookie); err != nil {
		return fmt.Errorf("rist: dtls: cookie: %w", err)
	}
	hvrBody, _ := helloVerifyRequest{version: versionDTLS10, cookie: cookie}.marshalBody()
	f2 := &flight{}
	c.emitHandshake(f2, typeHelloVerifyRequest, 0, hvrBody, false)
	if err := c.sendFlight(f2); err != nil {
		return err
	}

	// Flight 3: the ClientHello echoing the cookie — the first transcript message.
	msg, err = c.readHandshakeMessage(overall)
	if err != nil {
		return err
	}
	if msg.typ != typeClientHello {
		return fmt.Errorf("rist: dtls: expected cookie ClientHello, got %d", msg.typ)
	}
	ch, err := parseClientHello(msg.body)
	if err != nil {
		return err
	}
	if !hmac.Equal(ch.cookie, cookie) {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("rist: dtls: client cookie mismatch")
	}
	c.addToTranscript(msg)

	clientRandom := ch.random
	suite, err := selectSuite(cfg, ch.cipherSuites)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	c.cipherSuite = suite.id
	c.suite = suite
	isECDHE := suite.kx == kxECDHE
	usesCert := suite.kx != kxPSK
	useEMS := ch.extMasterSecret

	serverRandom := make([]byte, randomLen)
	if _, err := io.ReadFull(cfg.Rand, serverRandom); err != nil {
		return fmt.Errorf("rist: dtls: server random: %w", err)
	}

	// Flight 4: ServerHello, [Certificate, [ServerKeyExchange],
	// [CertificateRequest]], ServerHelloDone.
	f4 := &flight{}
	shBody, _ := serverHello{
		version:             versionDTLS12,
		random:              serverRandom,
		cipherSuite:         suite.id,
		extMasterSecret:     useEMS,
		pointFormats:        isECDHE && ch.pointFormatsOffered,
		secureRenegotiation: ch.secureRenegotiation,
	}.marshalBody()
	c.emitHandshake(f4, typeServerHello, 0, shBody, true)

	var ecdhePriv ecdhePrivate
	if usesCert {
		certBody, _ := certificateMsg{chain: cfg.Certificate.DER}.marshalBody()
		c.emitHandshake(f4, typeCertificate, 0, certBody, true)
	}
	if isECDHE {
		priv, pub, err := generateECDHE(cfg.Rand)
		if err != nil {
			return err
		}
		ecdhePriv = priv
		ske := serverKeyExchange{curve: namedGroupSecp256r1, publicKey: pub}
		signed := make([]byte, 0, len(clientRandom)+len(serverRandom)+len(ske.signedParams()))
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
	}
	// A kxRSA suite has no ServerKeyExchange: the client RSA-encrypts the
	// pre-master to our certificate's public key.
	if usesCert && cfg.RequireClientCert {
		crBody, _ := certificateRequest{}.marshalBody()
		c.emitHandshake(f4, typeCertificateRequest, 0, crBody, true)
	}
	c.emitHandshake(f4, typeServerHelloDone, 0, nil, true)
	if err := c.sendFlight(f4); err != nil {
		return err
	}

	// Flight 5: the client's key exchange flight.
	var (
		pms        []byte
		master     []byte
		clientCert *x509.Certificate // parsed+verified client leaf, NOT yet authenticated
		gotCKE     bool
		sawValidCV bool // a CertificateVerify whose signature verified was received
	)
	for {
		msg, err = c.readHandshakeMessage(overall)
		if err != nil {
			return err
		}
		if msg.typ == typeFinished {
			// A Finished MUST arrive under epoch 1 (after ChangeCipherSpec):
			// RFC 5246 §7.4.9 / RFC 6347. A Finished reassembled from epoch-0
			// plaintext is rejected (L8 defense-in-depth — the verify_data already
			// needs the master secret, but the epoch tag is a cheap, explicit
			// guard against accepting an unprotected Finished).
			if msg.epoch != 1 {
				c.sendAlert(alertDecryptError)
				return errors.New("rist: dtls: client Finished arrived unprotected (epoch 0)")
			}
			break
		}
		// Finished is the only message after CCS; everything here is epoch 0.
		c.addToTranscript(msg)
		switch msg.typ {
		case typeCertificate:
			cert, err := parseCertificate(msg.body)
			if err != nil {
				return err
			}
			if len(cert.chain) == 0 {
				if cfg.RequireClientCert {
					c.sendAlert(alertBadCertificate)
					return errors.New("rist: dtls: client certificate required but none sent")
				}
			} else {
				leaf, err := verifyPeerCertificate(cert.chain, cfg, verifyingClientCert)
				if err != nil {
					c.sendAlert(alertBadCertificate)
					return err
				}
				// Hold the leaf aside; it is NOT authenticated until a
				// CertificateVerify proves possession of its private key
				// (RFC 5246 §7.4.8). Do not expose it via c.peerLeaf yet — the
				// client Finished MAC verifies without the cert's key, so
				// CertificateVerify is the only proof of possession. Assigning
				// c.peerLeaf here would let an attacker holding only the victim's
				// public certificate (no private key) authenticate as the owner.
				clientCert = leaf
			}
		case typeClientKeyExchange:
			pms, err = c.serverKeyExchangePMS(suite, ecdhePriv, msg.body, ch)
			if err != nil {
				c.sendAlert(alertHandshakeFailure)
				return err
			}
			gotCKE = true
			// Transcript now runs through ClientKeyExchange: derive keys so the
			// epoch-1 Finished that follows can be decrypted.
			master = c.deriveMaster(pms, useEMS, clientRandom, serverRandom)
			keys, err := deriveKeys(suite, master, clientRandom, serverRandom)
			if err != nil {
				return err
			}
			c.keys = keys
			c.keysReady = true
		case typeCertificateVerify:
			cv, err := parseCertificateVerify(msg.body)
			if err != nil {
				return err
			}
			if clientCert == nil {
				return errors.New("rist: dtls: CertificateVerify without a client certificate")
			}
			// The signature covers the transcript up to but not including this
			// CertificateVerify; addToTranscript(msg) above already appended it, so
			// verify against the transcript with the CV body removed.
			signedLen := len(c.transcript) - len(msg.fullMessageBytes())
			if err := verifyHandshakeSignature(clientCert.PublicKey, cv.sigScheme, c.transcript[:signedLen], cv.signature); err != nil {
				c.sendAlert(alertDecryptError)
				return fmt.Errorf("rist: dtls: client CertificateVerify: %w", err)
			}
			// Proof of possession established (RFC 5246 §7.4.8): the client holds
			// the private key for clientCert. Only now may the leaf be treated as
			// an authenticated peer identity.
			sawValidCV = true
		default:
			return fmt.Errorf("rist: dtls: unexpected message %d in client flight", msg.typ)
		}
	}
	if !gotCKE {
		return errors.New("rist: dtls: client flight missing ClientKeyExchange")
	}
	if !c.peerCCS {
		return errors.New("rist: dtls: client Finished without ChangeCipherSpec")
	}
	// Proof-of-possession gate (RFC 5246 §7.4.8). A client that presents a
	// non-empty Certificate MUST follow it with a CertificateVerify signed by the
	// matching private key; the Finished MAC alone proves nothing about the
	// certificate, so without this check an attacker holding only a victim's public
	// cert could impersonate the cert owner — defeating RequireClientCert and
	// PeerCertFingerprint pinning. Require a verified CertificateVerify whenever a
	// client certificate was presented or mutual auth is mandated, and only then
	// promote the leaf to the authenticated c.peerLeaf.
	if (clientCert != nil || cfg.RequireClientCert) && !sawValidCV {
		c.sendAlert(alertBadCertificate)
		return errors.New("rist: dtls: client did not authenticate (missing CertificateVerify)")
	}
	if sawValidCV {
		c.peerLeaf = clientCert
	}

	// Verify the client Finished over the transcript through CertificateVerify /
	// ClientKeyExchange (it is not yet in the transcript).
	expectedClientVerify := finishedVerifyData(suite.newHash, master, labelClientFinished, c.transcriptHash())
	if !hmac.Equal(expectedClientVerify, msg.body) {
		c.sendAlert(alertDecryptError)
		return errors.New("rist: dtls: client Finished verify_data mismatch")
	}
	c.addToTranscript(msg) // include client Finished before computing ours

	// Flight 6: server CCS + Finished.
	f6 := &flight{}
	emitCCS(f6)
	serverVerify := finishedVerifyData(suite.newHash, master, labelServerFinished, c.transcriptHash())
	c.emitHandshake(f6, typeFinished, 1, marshalFinished(serverVerify), true)
	if err := c.sendFlight(f6); err != nil {
		return err
	}

	c.sendEpoch = 1
	return nil
}

// serverKeyExchangePMS recovers the pre-master secret from a ClientKeyExchange for
// the negotiated suite's key exchange: ECDHE (the client's point against our
// ephemeral key), RSA key transport (decrypt with our certificate's private key,
// Bleichenbacher-mitigated), or PSK (the shared key, with an optional identity
// check).
func (c *Conn) serverKeyExchangePMS(suite cipherSuiteInfo, ecdhePriv ecdhePrivate, body []byte, ch clientHello) ([]byte, error) {
	cfg := c.cfg
	switch suite.kx {
	case kxECDHE:
		pub, err := parseClientKeyExchangeECDHE(body)
		if err != nil {
			return nil, err
		}
		return ecdhePremaster(ecdhePriv, pub)
	case kxRSA:
		enc, err := parseClientKeyExchangeRSA(body)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := cfg.Certificate.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("rist: dtls: RSA suite but server certificate is not RSA")
		}
		// Bleichenbacher-mitigated: a decrypt failure yields a random pre-master, so
		// the handshake fails indistinguishably at Finished rather than leaking a
		// padding oracle.
		return decryptRSAPremaster(cfg.Rand, rsaKey, enc)
	default: // kxPSK
		identity, err := parseClientKeyExchangePSK(body)
		if err != nil {
			return nil, err
		}
		// The shared PSK is the real authenticator (a wrong key fails at Finished),
		// but when a PSK identity is configured, reject a mismatched client identity
		// early — it signals a wrong or misconfigured peer. Constant-time to avoid
		// leaking the identity.
		if len(cfg.PSKIdentity) > 0 && subtle.ConstantTimeCompare(identity, cfg.PSKIdentity) != 1 {
			return nil, errors.New("rist: dtls: client PSK identity does not match configured identity")
		}
		return pskPremaster(cfg.PSK), nil
	}
}

package dtls

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Handshake message bodies and extensions (RFC 5246 §7.4, RFC 4279, RFC 4492 /
// 8422, RFC 6347, RFC 7627). Encoding uses cryptobyte for the length-prefixed
// TLS vector framing; parsing rejects malformed input without panicking.

var errMalformed = errors.New("rist: dtls: malformed handshake message")

// ---- ClientHello (RFC 5246 §7.4.1.2, DTLS cookie per RFC 6347 §4.2.1) ----

type clientHello struct {
	version             [2]byte
	random              []byte // 32 bytes
	sessionID           []byte
	cookie              []byte
	cipherSuites        []uint16
	extMasterSecret     bool
	supportedGroups     []uint16
	pointFormats        []uint8
	pointFormatsOffered bool // the ec_point_formats extension was present
	signatureAlgorithms []uint16
	secureRenegotiation bool // client offered renegotiation_info or the SCSV
}

// scsvRenegotiation is TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 §3.3): a
// signaling cipher-suite value a client may send in lieu of the
// renegotiation_info extension to advertise secure-renegotiation support.
const scsvRenegotiation uint16 = 0x00FF

func (m clientHello) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(m.version[:])
	b.AddBytes(m.random)
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.sessionID) })
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.cookie) })
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, cs := range m.cipherSuites {
			c.AddUint16(cs)
		}
	})
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddUint8(compressionNull) })
	b.AddUint16LengthPrefixed(func(ext *cryptobyte.Builder) {
		if len(m.supportedGroups) > 0 {
			addExtension(ext, extSupportedGroups, func(d *cryptobyte.Builder) {
				d.AddUint16LengthPrefixed(func(l *cryptobyte.Builder) {
					for _, g := range m.supportedGroups {
						l.AddUint16(g)
					}
				})
			})
		}
		if len(m.pointFormats) > 0 {
			addExtension(ext, extECPointFormats, func(d *cryptobyte.Builder) {
				d.AddUint8LengthPrefixed(func(l *cryptobyte.Builder) {
					for _, f := range m.pointFormats {
						l.AddUint8(f)
					}
				})
			})
		}
		if len(m.signatureAlgorithms) > 0 {
			addExtension(ext, extSignatureAlgorithms, func(d *cryptobyte.Builder) {
				d.AddUint16LengthPrefixed(func(l *cryptobyte.Builder) {
					for _, s := range m.signatureAlgorithms {
						l.AddUint16(s)
					}
				})
			})
		}
		if m.extMasterSecret {
			addExtension(ext, extExtendedMasterSecret, func(d *cryptobyte.Builder) {})
		}
	})
	return b.Bytes()
}

func parseClientHello(body []byte) (clientHello, error) {
	var m clientHello
	s := cryptobyte.String(body)
	var ver []byte
	if !s.ReadBytes(&ver, 2) {
		return m, errMalformed
	}
	copy(m.version[:], ver)
	if !s.ReadBytes(&m.random, randomLen) {
		return m, errMalformed
	}
	var sid, cookie cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sid) || !s.ReadUint8LengthPrefixed(&cookie) {
		return m, errMalformed
	}
	m.sessionID = append([]byte(nil), sid...)
	m.cookie = append([]byte(nil), cookie...)
	var suites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&suites) {
		return m, errMalformed
	}
	for !suites.Empty() {
		var cs uint16
		if !suites.ReadUint16(&cs) {
			return m, errMalformed
		}
		m.cipherSuites = append(m.cipherSuites, cs)
		if cs == scsvRenegotiation {
			m.secureRenegotiation = true
		}
	}
	var comp cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&comp) {
		return m, errMalformed
	}
	// Extensions are optional (a bare DTLS 1.0 ClientHello may omit them).
	if !s.Empty() {
		var exts cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&exts) {
			return m, errMalformed
		}
		if err := m.parseExtensions(exts); err != nil {
			return m, err
		}
	}
	return m, nil
}

func (m *clientHello) parseExtensions(exts cryptobyte.String) error {
	return walkExtensions(exts, func(typ uint16, data cryptobyte.String) error {
		switch typ {
		case extExtendedMasterSecret:
			m.extMasterSecret = true
		case extECPointFormats:
			m.pointFormatsOffered = true
		case extRenegotiationInfo:
			m.secureRenegotiation = true
		case extSupportedGroups:
			var l cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&l) {
				return errMalformed
			}
			for !l.Empty() {
				var g uint16
				if !l.ReadUint16(&g) {
					return errMalformed
				}
				m.supportedGroups = append(m.supportedGroups, g)
			}
		case extSignatureAlgorithms:
			var l cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&l) {
				return errMalformed
			}
			for !l.Empty() {
				var sa uint16
				if !l.ReadUint16(&sa) {
					return errMalformed
				}
				m.signatureAlgorithms = append(m.signatureAlgorithms, sa)
			}
		}
		return nil
	})
}

// ---- HelloVerifyRequest (RFC 6347 §4.2.1) ----

type helloVerifyRequest struct {
	version [2]byte
	cookie  []byte
}

func (m helloVerifyRequest) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(m.version[:])
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.cookie) })
	return b.Bytes()
}

func parseHelloVerifyRequest(body []byte) (helloVerifyRequest, error) {
	var m helloVerifyRequest
	s := cryptobyte.String(body)
	var ver []byte
	if !s.ReadBytes(&ver, 2) {
		return m, errMalformed
	}
	copy(m.version[:], ver)
	var cookie cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&cookie) {
		return m, errMalformed
	}
	if len(cookie) > maxCookieLen {
		return m, errMalformed
	}
	m.cookie = append([]byte(nil), cookie...)
	return m, nil
}

// ---- ServerHello (RFC 5246 §7.4.1.3) ----

type serverHello struct {
	version             [2]byte
	random              []byte
	sessionID           []byte
	cipherSuite         uint16
	extMasterSecret     bool
	pointFormats        bool // emit ec_point_formats (EC suite + client offered)
	secureRenegotiation bool // echo an empty renegotiation_info (RFC 5746)
}

func (m serverHello) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(m.version[:])
	b.AddBytes(m.random)
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.sessionID) })
	b.AddUint16(m.cipherSuite)
	b.AddUint8(compressionNull)
	b.AddUint16LengthPrefixed(func(ext *cryptobyte.Builder) {
		// A server MUST NOT send an extension the client did not offer
		// (RFC 5246 §7.4.1.4); each below is gated on the client's ClientHello.
		if m.extMasterSecret {
			addExtension(ext, extExtendedMasterSecret, func(d *cryptobyte.Builder) {})
		}
		if m.secureRenegotiation {
			// Initial-handshake renegotiation_info: an empty renegotiated
			// connection, i.e. a single zero-length vector byte (RFC 5746 §3.6).
			addExtension(ext, extRenegotiationInfo, func(d *cryptobyte.Builder) {
				d.AddUint8LengthPrefixed(func(l *cryptobyte.Builder) {})
			})
		}
		if m.pointFormats {
			addExtension(ext, extECPointFormats, func(d *cryptobyte.Builder) {
				d.AddUint8LengthPrefixed(func(l *cryptobyte.Builder) { l.AddUint8(ecPointUncompressed) })
			})
		}
	})
	return b.Bytes()
}

func parseServerHello(body []byte) (serverHello, error) {
	var m serverHello
	s := cryptobyte.String(body)
	var ver []byte
	if !s.ReadBytes(&ver, 2) {
		return m, errMalformed
	}
	copy(m.version[:], ver)
	if !s.ReadBytes(&m.random, randomLen) {
		return m, errMalformed
	}
	var sid cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sid) {
		return m, errMalformed
	}
	m.sessionID = append([]byte(nil), sid...)
	var comp uint8
	if !s.ReadUint16(&m.cipherSuite) || !s.ReadUint8(&comp) {
		return m, errMalformed
	}
	if !s.Empty() {
		var exts cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&exts) {
			return m, errMalformed
		}
		if err := walkExtensions(exts, func(typ uint16, data cryptobyte.String) error {
			if typ == extExtendedMasterSecret {
				m.extMasterSecret = true
			}
			return nil
		}); err != nil {
			return m, err
		}
	}
	return m, nil
}

// ---- Certificate (RFC 5246 §7.4.2) ----

type certificateMsg struct {
	chain [][]byte // ASN.1 DER, leaf first
}

func (m certificateMsg) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint24LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, der := range m.chain {
			list.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(der) })
		}
	})
	return b.Bytes()
}

func parseCertificate(body []byte) (certificateMsg, error) {
	var m certificateMsg
	s := cryptobyte.String(body)
	var list cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&list) {
		return m, errMalformed
	}
	for !list.Empty() {
		var der cryptobyte.String
		if !list.ReadUint24LengthPrefixed(&der) {
			return m, errMalformed
		}
		m.chain = append(m.chain, append([]byte(nil), der...))
	}
	return m, nil
}

// ---- ServerKeyExchange (ECDHE_ECDSA, RFC 4492 §5.4) ----

type serverKeyExchange struct {
	curve     uint16 // named curve
	publicKey []byte // EC point, uncompressed
	sigScheme uint16
	signature []byte
}

// signedParams returns the bytes the signature covers: the ECParameters and
// public point (curve_type || named_curve || point), to be prefixed with the
// client and server randoms before signing/verifying (RFC 4492 §5.4).
func (m serverKeyExchange) signedParams() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(3) // curve_type = named_curve
	b.AddUint16(m.curve)
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.publicKey) })
	out, _ := b.Bytes()
	return out
}

func (m serverKeyExchange) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(m.signedParams())
	b.AddUint16(m.sigScheme)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.signature) })
	return b.Bytes()
}

func parseServerKeyExchange(body []byte) (serverKeyExchange, error) {
	var m serverKeyExchange
	s := cryptobyte.String(body)
	var curveType uint8
	if !s.ReadUint8(&curveType) || curveType != 3 {
		return m, fmt.Errorf("%w: server key exchange curve_type", errMalformed)
	}
	if !s.ReadUint16(&m.curve) {
		return m, errMalformed
	}
	var point cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&point) {
		return m, errMalformed
	}
	m.publicKey = append([]byte(nil), point...)
	var sig cryptobyte.String
	if !s.ReadUint16(&m.sigScheme) || !s.ReadUint16LengthPrefixed(&sig) {
		return m, errMalformed
	}
	m.signature = append([]byte(nil), sig...)
	return m, nil
}

// ---- CertificateRequest (RFC 5246 §7.4.4) ----

type certificateRequest struct{}

func (certificateRequest) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	// certificate_types = { rsa_sign(1), ecdsa_sign(64) }
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) {
		c.AddUint8(1)
		c.AddUint8(64)
	})
	// supported_signature_algorithms = the full offered set (ECDSA + RSA, SHA-256/384)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, sa := range offeredSignatureAlgorithms {
			c.AddUint16(sa)
		}
	})
	// certificate_authorities = empty
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {})
	return b.Bytes()
}

// ---- ClientKeyExchange ----

// clientKeyExchangePSK carries the PSK identity (RFC 4279 §2).
type clientKeyExchangePSK struct{ identity []byte }

func (m clientKeyExchangePSK) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.identity) })
	return b.Bytes()
}

func parseClientKeyExchangePSK(body []byte) ([]byte, error) {
	s := cryptobyte.String(body)
	var id cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&id) || !s.Empty() {
		return nil, errMalformed
	}
	return append([]byte(nil), id...), nil
}

// clientKeyExchangeRSA carries the RSA-encrypted pre-master secret
// (RFC 5246 §7.4.7.1): EncryptedPreMasterSecret as opaque<0..2^16-1>.
type clientKeyExchangeRSA struct{ encrypted []byte }

func (m clientKeyExchangeRSA) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.encrypted) })
	return b.Bytes()
}

func parseClientKeyExchangeRSA(body []byte) ([]byte, error) {
	s := cryptobyte.String(body)
	var enc cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&enc) || !s.Empty() {
		return nil, errMalformed
	}
	return append([]byte(nil), enc...), nil
}

// clientKeyExchangeECDHE carries the client's ephemeral EC point (RFC 4492 §5.7).
type clientKeyExchangeECDHE struct{ publicKey []byte }

func (m clientKeyExchangeECDHE) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.publicKey) })
	return b.Bytes()
}

func parseClientKeyExchangeECDHE(body []byte) ([]byte, error) {
	s := cryptobyte.String(body)
	var pt cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&pt) || !s.Empty() {
		return nil, errMalformed
	}
	return append([]byte(nil), pt...), nil
}

// ---- CertificateVerify (RFC 5246 §7.4.8) ----

type certificateVerify struct {
	sigScheme uint16
	signature []byte
}

func (m certificateVerify) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(m.sigScheme)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(m.signature) })
	return b.Bytes()
}

func parseCertificateVerify(body []byte) (certificateVerify, error) {
	var m certificateVerify
	s := cryptobyte.String(body)
	var sig cryptobyte.String
	if !s.ReadUint16(&m.sigScheme) || !s.ReadUint16LengthPrefixed(&sig) {
		return m, errMalformed
	}
	m.signature = append([]byte(nil), sig...)
	return m, nil
}

// ---- Finished (RFC 5246 §7.4.9) ----

func marshalFinished(verifyData []byte) []byte { return append([]byte(nil), verifyData...) }

// ---- extension helpers ----

// addExtension appends one extension (type + opaque<0..2^16-1> data) to an
// extensions builder.
func addExtension(ext *cryptobyte.Builder, typ uint16, body func(*cryptobyte.Builder)) {
	ext.AddUint16(typ)
	ext.AddUint16LengthPrefixed(body)
}

// walkExtensions iterates the extensions vector, calling fn for each. A
// malformed extension framing is an error; fn may also return one.
func walkExtensions(exts cryptobyte.String, fn func(typ uint16, data cryptobyte.String) error) error {
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return errMalformed
		}
		if err := fn(typ, data); err != nil {
			return err
		}
	}
	return nil
}

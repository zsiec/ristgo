package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// Record protection. Two record-protection schemes are supported, selected by the
// negotiated suite: AES-GCM (RFC 5288), the AEAD used by every GCM suite, framed
// for DTLS 1.2 (RFC 6347 §4.1.2.1, RFC 5246 §6.2.3.3); and a NULL cipher with an
// appended HMAC (RFC 5246 §6.2.3.1) for TLS_RSA_WITH_NULL_SHA256, which provides
// integrity but NO confidentiality.

const (
	// gcmFixedIVLen is the per-direction salt (the implicit part of the GCM
	// nonce) taken from the key block; gcmExplicitNonceLen the on-the-wire
	// explicit nonce; gcmTagLen the GCM authentication tag.
	gcmFixedIVLen       = 4
	gcmExplicitNonceLen = 8
	gcmTagLen           = 16

	// gcmOverhead is the bytes a sealed GCM record adds over its plaintext: the
	// explicit nonce prepended on the wire plus the trailing tag.
	gcmOverhead = gcmExplicitNonceLen + gcmTagLen
)

// errBadRecordMAC is returned when a record fails authentication or is too short
// to hold its overhead (explicit nonce + tag for GCM, or the trailing MAC for the
// NULL suite). It is deliberately uniform (no distinction between "short" and
// "auth mismatch") to avoid an oracle.
var errBadRecordMAC = errors.New("rist: dtls: bad record MAC")

// halfConn protects one direction of the connection. It is not safe for
// concurrent use; the conn serializes each direction onto its own halfConn.
type halfConn interface {
	// seal returns the protected record fragment for the given record header
	// fields and plaintext.
	seal(epoch uint16, seq uint64, typ contentType, version [2]byte, plaintext []byte) []byte
	// open authenticates (and, for GCM, decrypts) a record fragment, returning a
	// freshly-allocated plaintext the caller owns. It never panics and returns
	// errBadRecordMAC for any failure.
	open(r record) ([]byte, error)
}

// gcmHalfConn is AES-GCM record protection: the AEAD keyed for one direction plus
// its 4-byte fixed IV (salt). The AES key may be 128- or 256-bit.
type gcmHalfConn struct {
	aead cipher.AEAD
	salt [gcmFixedIVLen]byte
}

// newGCMHalfConn builds a direction's GCM record protection from its write key
// (16 or 32 bytes) and fixed IV (each sliced out of the key block).
func newGCMHalfConn(key, fixedIV []byte) (*gcmHalfConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: gcm: %w", err)
	}
	h := &gcmHalfConn{aead: aead}
	copy(h.salt[:], fixedIV)
	return h, nil
}

// seal encrypts plaintext into a record fragment. The wire fragment is
// explicit_nonce(8) || GCM(ciphertext+tag); the GCM nonce is salt(4) ||
// explicit(8) where the explicit nonce is the 64-bit record sequence
// (epoch<<48 | seq), and the AAD is the DTLS additional-data block.
func (h *gcmHalfConn) seal(epoch uint16, seq uint64, typ contentType, version [2]byte, plaintext []byte) []byte {
	recordSeq := seqAndEpoch(epoch, seq)

	var nonce [gcmFixedIVLen + gcmExplicitNonceLen]byte
	copy(nonce[:gcmFixedIVLen], h.salt[:])
	binary.BigEndian.PutUint64(nonce[gcmFixedIVLen:], recordSeq)

	aad := aeadAAD(epoch, seq, typ, version, len(plaintext))

	out := make([]byte, gcmExplicitNonceLen, gcmExplicitNonceLen+len(plaintext)+gcmTagLen)
	binary.BigEndian.PutUint64(out, recordSeq)
	return h.aead.Seal(out, nonce[:], plaintext, aad)
}

// open authenticates and decrypts a GCM record fragment.
func (h *gcmHalfConn) open(r record) ([]byte, error) {
	if len(r.fragment) < gcmOverhead {
		return nil, errBadRecordMAC
	}
	explicit := r.fragment[:gcmExplicitNonceLen]
	ciphertext := r.fragment[gcmExplicitNonceLen:]

	var nonce [gcmFixedIVLen + gcmExplicitNonceLen]byte
	copy(nonce[:gcmFixedIVLen], h.salt[:])
	copy(nonce[gcmFixedIVLen:], explicit)

	plaintextLen := len(ciphertext) - gcmTagLen
	aad := aeadAAD(r.epoch, r.seq, r.typ, r.version, plaintextLen)

	pt, err := h.aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, errBadRecordMAC
	}
	return pt, nil
}

// nullMACHalfConn is the NULL-cipher-with-HMAC record protection of
// TLS_RSA_WITH_NULL_SHA256 (RFC 5246 §6.2.3.1): the fragment is plaintext || MAC,
// where MAC = HMAC_hash(MAC_write_key, seq_num || type || version || length ||
// plaintext) over the DTLS additional-data block and the plaintext. The data is
// authenticated but NOT encrypted — it provides integrity only.
type nullMACHalfConn struct {
	macKey  []byte
	newHash func() hash.Hash
	macLen  int
}

func (h *nullMACHalfConn) mac(epoch uint16, seq uint64, typ contentType, version [2]byte, plaintext []byte) []byte {
	m := hmac.New(h.newHash, h.macKey)
	m.Write(aeadAAD(epoch, seq, typ, version, len(plaintext)))
	m.Write(plaintext)
	return m.Sum(nil)
}

func (h *nullMACHalfConn) seal(epoch uint16, seq uint64, typ contentType, version [2]byte, plaintext []byte) []byte {
	mac := h.mac(epoch, seq, typ, version, plaintext)
	out := make([]byte, 0, len(plaintext)+len(mac))
	out = append(out, plaintext...)
	return append(out, mac...)
}

func (h *nullMACHalfConn) open(r record) ([]byte, error) {
	if len(r.fragment) < h.macLen {
		return nil, errBadRecordMAC
	}
	split := len(r.fragment) - h.macLen
	body := r.fragment[:split]
	gotMAC := r.fragment[split:]
	want := h.mac(r.epoch, r.seq, r.typ, r.version, body)
	if !hmac.Equal(gotMAC, want) {
		return nil, errBadRecordMAC
	}
	// Copy out: body aliases the read buffer, but the caller retains the returned
	// plaintext across later reads (matching the fresh allocation GCM open returns).
	return append([]byte(nil), body...), nil
}

// aeadAAD builds the 13-byte additional-data / MAC-prefix block for a DTLS record
// (RFC 6347 §4.1.2.1): seq_num(8) || type(1) || version(2) || length(2), where
// seq_num is the 64-bit epoch||sequence and length is the plaintext length. It is
// the AEAD AAD for GCM and the MAC-input prefix for the NULL suite.
func aeadAAD(epoch uint16, seq uint64, typ contentType, version [2]byte, plaintextLen int) []byte {
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[0:8], seqAndEpoch(epoch, seq))
	aad[8] = byte(typ)
	aad[9] = version[0]
	aad[10] = version[1]
	binary.BigEndian.PutUint16(aad[11:13], uint16(plaintextLen))
	return aad[:]
}

// connKeys holds both directions' record-protection halves, derived from the
// master secret and the two randoms.
type connKeys struct {
	clientWrite halfConn // client protects / server opens
	serverWrite halfConn // server protects / client opens
}

// deriveKeys runs the key-expansion PRF for the negotiated suite and splits the
// key block into both directions' record-protection halves (RFC 5246 §6.3). The
// key-expansion seed is server_random || client_random — the reverse of the
// master-secret seed. The key block layout is
// client_MAC || server_MAC || client_key || server_key || client_IV || server_IV
// where the MAC keys are empty for an AEAD suite and the enc keys + IVs are empty
// for the NULL suite.
func deriveKeys(suite cipherSuiteInfo, master, clientRandom, serverRandom []byte) (connKeys, error) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	encLen := suite.keyLen
	macLen := suite.macLen
	ivLen := 0
	if suite.aead {
		ivLen = gcmFixedIVLen
	}
	blockLen := 2*macLen + 2*encLen + 2*ivLen
	kb := prf(suite.newHash, master, labelKeyExpansion, seed, blockLen)

	off := 0
	take := func(n int) []byte { s := kb[off : off+n]; off += n; return s }
	clientMAC := take(macLen)
	serverMAC := take(macLen)
	clientKey := take(encLen)
	serverKey := take(encLen)
	clientIV := take(ivLen)
	serverIV := take(ivLen)

	if suite.aead {
		cw, err := newGCMHalfConn(clientKey, clientIV)
		if err != nil {
			return connKeys{}, err
		}
		sw, err := newGCMHalfConn(serverKey, serverIV)
		if err != nil {
			return connKeys{}, err
		}
		return connKeys{clientWrite: cw, serverWrite: sw}, nil
	}
	return connKeys{
		clientWrite: &nullMACHalfConn{macKey: clientMAC, newHash: suite.newHash, macLen: macLen},
		serverWrite: &nullMACHalfConn{macKey: serverMAC, newHash: suite.newHash, macLen: macLen},
	}, nil
}

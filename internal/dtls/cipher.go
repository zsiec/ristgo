package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// Record protection with AES-128-GCM (RFC 5288), the AEAD used by both supported
// cipher suites, framed for DTLS 1.2 (RFC 6347 §4.1.2.1, RFC 5246 §6.2.3.3).

const (
	// aesGCMKeyLen is the AES-128 key size; gcmFixedIVLen the per-direction salt
	// (the implicit part of the nonce) from the key block; gcmExplicitNonceLen
	// the on-the-wire explicit nonce; gcmTagLen the GCM authentication tag.
	aesGCMKeyLen        = 16
	gcmFixedIVLen       = 4
	gcmExplicitNonceLen = 8
	gcmTagLen           = 16

	// gcmOverhead is the bytes a sealed record adds over its plaintext: the
	// explicit nonce prepended on the wire plus the trailing tag.
	gcmOverhead = gcmExplicitNonceLen + gcmTagLen

	// keyBlockLen is the key-expansion output for AES-128-GCM with no MAC key:
	// two write keys (16) and two fixed IVs (4) — RFC 5246 §6.3, RFC 5288 §3.
	keyBlockLen = 2*aesGCMKeyLen + 2*gcmFixedIVLen
)

// errBadRecordMAC is returned when a record fails AEAD authentication or is too
// short to hold the explicit nonce and tag. It is deliberately uniform (no
// distinction between "short" and "tag mismatch") to avoid an oracle.
var errBadRecordMAC = errors.New("rist: dtls: bad record MAC")

// halfConn protects one direction of the connection: the AES-GCM AEAD keyed for
// that direction plus its 4-byte fixed IV (salt). It is not safe for concurrent
// use; the conn serializes each direction onto its own halfConn.
type halfConn struct {
	aead cipher.AEAD
	salt [gcmFixedIVLen]byte
}

// newHalfConn builds a direction's record protection from its write key and
// fixed IV (each sliced out of the key block).
func newHalfConn(key, fixedIV []byte) (*halfConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: gcm: %w", err)
	}
	h := &halfConn{aead: aead}
	copy(h.salt[:], fixedIV)
	return h, nil
}

// seal encrypts plaintext into a record fragment for the given record header
// fields. The wire fragment is explicit_nonce(8) || GCM(ciphertext+tag); the GCM
// nonce is salt(4) || explicit(8) where the explicit nonce is the 64-bit record
// sequence (epoch<<48 | seq), and the AAD is the DTLS additional-data block.
func (h *halfConn) seal(epoch uint16, seq uint64, typ contentType, version [2]byte, plaintext []byte) []byte {
	recordSeq := seqAndEpoch(epoch, seq)

	var nonce [gcmFixedIVLen + gcmExplicitNonceLen]byte
	copy(nonce[:gcmFixedIVLen], h.salt[:])
	binary.BigEndian.PutUint64(nonce[gcmFixedIVLen:], recordSeq)

	aad := aeadAAD(epoch, seq, typ, version, len(plaintext))

	out := make([]byte, gcmExplicitNonceLen, gcmExplicitNonceLen+len(plaintext)+gcmTagLen)
	binary.BigEndian.PutUint64(out, recordSeq)
	return h.aead.Seal(out, nonce[:], plaintext, aad)
}

// open authenticates and decrypts a record fragment, returning the plaintext. It
// never panics and returns errBadRecordMAC for any failure (short fragment, tag
// mismatch). The GCM nonce uses the explicit nonce carried in the fragment; the
// AAD uses the record header's epoch/seq/type/version and the recovered length.
func (h *halfConn) open(r record) ([]byte, error) {
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

// aeadAAD builds the 13-byte AEAD additional-data block for a DTLS record
// (RFC 6347 §4.1.2.1): seq_num(8) || type(1) || version(2) || length(2), where
// seq_num is the 64-bit epoch||sequence and length is the plaintext length.
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
	clientWrite *halfConn // client encrypts / server decrypts
	serverWrite *halfConn // server encrypts / client decrypts
}

// deriveKeys runs the key-expansion PRF and splits the key block into both
// directions' AES-128-GCM halves (RFC 5246 §6.3). The key-expansion seed is
// server_random || client_random — the reverse of the master-secret seed.
func deriveKeys(master, clientRandom, serverRandom []byte) (connKeys, error) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	kb := prf(master, labelKeyExpansion, seed, keyBlockLen)

	clientWriteKey := kb[0:aesGCMKeyLen]
	serverWriteKey := kb[aesGCMKeyLen : 2*aesGCMKeyLen]
	clientWriteIV := kb[2*aesGCMKeyLen : 2*aesGCMKeyLen+gcmFixedIVLen]
	serverWriteIV := kb[2*aesGCMKeyLen+gcmFixedIVLen : keyBlockLen]

	cw, err := newHalfConn(clientWriteKey, clientWriteIV)
	if err != nil {
		return connKeys{}, err
	}
	sw, err := newHalfConn(serverWriteKey, serverWriteIV)
	if err != nil {
		return connKeys{}, err
	}
	return connKeys{clientWrite: cw, serverWrite: sw}, nil
}

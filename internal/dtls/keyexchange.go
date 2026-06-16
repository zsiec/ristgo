package dtls

import (
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
)

// ecdhePrivate is the ephemeral ECDH private key type, aliased so the handshake
// drivers need not import crypto/ecdh directly.
type ecdhePrivate = *ecdh.PrivateKey

// Pre-master secret derivation for the two key-exchange methods.

// pskPremaster builds the pre-master secret for a PSK cipher suite (RFC 4279
// §2): for the plain PSK key exchange the "other secret" is psk-length zeros, so
// pms = uint16(len(psk)) || zeros(len(psk)) || uint16(len(psk)) || psk.
func pskPremaster(psk []byte) []byte {
	n := len(psk)
	out := make([]byte, 0, 2+n+2+n)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	out = append(out, make([]byte, n)...)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	out = append(out, psk...)
	return out
}

// generateECDHE creates an ephemeral ECDH key on P-256, returning the private
// key and the uncompressed public point (0x04 || X || Y) for the wire.
func generateECDHE(randR io.Reader) (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.P256().GenerateKey(randR)
	if err != nil {
		return nil, nil, fmt.Errorf("rist: dtls: ecdhe keygen: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// ecdhePremaster computes the ECDH shared secret (the X coordinate) from our
// private key and the peer's uncompressed public point. A malformed or
// off-curve point returns an error rather than panicking.
func ecdhePremaster(priv *ecdh.PrivateKey, peerPoint []byte) ([]byte, error) {
	peer, err := ecdh.P256().NewPublicKey(peerPoint)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: peer ecdhe point: %w", err)
	}
	secret, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: ecdh: %w", err)
	}
	return secret, nil
}

// rsaPremasterLen is the fixed RSA key-transport pre-master length: 2-byte
// client_version || 46 random bytes (RFC 5246 §7.4.7.1).
const rsaPremasterLen = 48

// newRSAPremaster generates an RSA-key-transport pre-master secret: the
// client_version this client offered (DTLS 1.2) in the first two bytes followed by
// 46 random bytes (RFC 5246 §7.4.7.1). The echoed version lets the server detect a
// version rollback.
func newRSAPremaster(randR io.Reader) ([]byte, error) {
	pms := make([]byte, rsaPremasterLen)
	pms[0] = versionDTLS12[0]
	pms[1] = versionDTLS12[1]
	if _, err := io.ReadFull(randR, pms[2:]); err != nil {
		return nil, fmt.Errorf("rist: dtls: rsa premaster: %w", err)
	}
	return pms, nil
}

// encryptRSAPremaster RSA-PKCS1v15-encrypts the pre-master to the server's RSA
// public key — the ClientKeyExchange body for an RSA-key-transport suite.
func encryptRSAPremaster(randR io.Reader, pub *rsa.PublicKey, pms []byte) ([]byte, error) {
	ct, err := rsa.EncryptPKCS1v15(randR, pub, pms)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: rsa encrypt premaster: %w", err)
	}
	return ct, nil
}

// decryptRSAPremaster recovers the RSA-key-transport pre-master from a
// ClientKeyExchange, applying the Bleichenbacher countermeasure (RFC 5246
// §7.4.7.1): on ANY decryption/padding failure, length mismatch, OR a mismatched
// embedded client_version (a rollback), it returns a RANDOM pre-master rather than
// an error, so a padding/timing oracle cannot distinguish a malformed ciphertext
// from a valid one — the handshake then fails identically at Finished. It never
// returns the reason for a failure, only an error for an inability to read
// randomness.
func decryptRSAPremaster(randR io.Reader, key *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	// Seed the output with a random fallback whose version bytes already match, so
	// a decrypt failure yields a valid-looking-but-wrong pre-master.
	random := make([]byte, rsaPremasterLen)
	if _, err := io.ReadFull(randR, random); err != nil {
		return nil, fmt.Errorf("rist: dtls: rsa fallback premaster: %w", err)
	}
	random[0] = versionDTLS12[0]
	random[1] = versionDTLS12[1]

	out := make([]byte, rsaPremasterLen)
	copy(out, random)
	// DecryptPKCS1v15SessionKey runs in constant time and copies the plaintext into
	// out only when the padding is valid and the length matches; otherwise it leaves
	// out unchanged (= the random fallback). It errors only on a wrong ciphertext
	// length, which is also indistinguishable to the peer (handshake fails later).
	if err := rsa.DecryptPKCS1v15SessionKey(randR, key, ciphertext, out); err != nil {
		return random, nil //nolint:nilerr // wrong length: fall back, do not leak the reason
	}
	// Constant-time client_version check folded into the same random fallback,
	// defending against a version rollback without a timeable branch.
	versionOK := subtle.ConstantTimeByteEq(out[0], versionDTLS12[0]) &
		subtle.ConstantTimeByteEq(out[1], versionDTLS12[1])
	subtle.ConstantTimeCopy(1-versionOK, out, random)
	return out, nil
}

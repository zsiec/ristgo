package dtls

import (
	"crypto/ecdh"
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

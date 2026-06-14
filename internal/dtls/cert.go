package dtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Certificate holding for the ECDHE_ECDSA cipher suite: an ECDSA P-256 leaf
// certificate (self-signed by default), its DER chain, and the private key.

// Certificate is one local certificate plus its signing key, supplied to a DTLS
// endpoint that authenticates with the ECDHE_ECDSA suite.
type Certificate struct {
	// DER is the certificate chain, leaf first, ASN.1 DER encoded.
	DER [][]byte
	// Leaf is the parsed leaf certificate (DER[0]).
	Leaf *x509.Certificate
	// PrivateKey is the leaf's ECDSA P-256 private key.
	PrivateKey *ecdsa.PrivateKey
}

// GenerateSelfSigned creates a fresh self-signed ECDSA P-256 certificate for the
// given common name, valid for one year. It is the default credential when an
// endpoint enables the ECDHE_ECDSA suite without supplying its own certificate —
// adequate for the RIST use case, where peer identity is typically pinned by
// fingerprint rather than a PKI (libRIST has no DTLS PKI at all).
func GenerateSelfSigned(commonName string) (*Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: create cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: parse cert: %w", err)
	}
	return &Certificate{DER: [][]byte{der}, Leaf: leaf, PrivateKey: key}, nil
}

// Fingerprint returns the SHA-256 fingerprint of the leaf certificate DER, the
// value used for fingerprint pinning.
func (c *Certificate) Fingerprint() [32]byte { return sha256.Sum256(c.DER[0]) }

// CertificateFromPEM builds a Certificate from PEM-encoded certificate and EC
// private key blocks. The certificate must be ECDSA P-256 (the suite's key type).
func CertificateFromPEM(certPEM, keyPEM []byte) (*Certificate, error) {
	cBlock, _ := pem.Decode(certPEM)
	if cBlock == nil || cBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("rist: dtls: no CERTIFICATE PEM block")
	}
	leaf, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: parse cert: %w", err)
	}
	kBlock, _ := pem.Decode(keyPEM)
	if kBlock == nil {
		return nil, fmt.Errorf("rist: dtls: no private key PEM block")
	}
	key, err := parseECKey(kBlock)
	if err != nil {
		return nil, err
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("rist: dtls: certificate is not ECDSA")
	}
	return &Certificate{DER: [][]byte{cBlock.Bytes}, Leaf: leaf, PrivateKey: key}, nil
}

// parseECKey decodes an EC private key from either an "EC PRIVATE KEY" (SEC1) or
// "PRIVATE KEY" (PKCS#8) PEM block.
func parseECKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: parse EC key: %w", err)
	}
	ec, ok := k8.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rist: dtls: private key is not ECDSA")
	}
	return ec, nil
}

// errBadCertificate is returned when peer-certificate verification fails.
var errBadCertificate = errors.New("rist: dtls: peer certificate verification failed")

// verifyPeerCertificate validates a received certificate chain per cfg: skip when
// InsecureSkipVerify; match the pinned SHA-256 fingerprint when one is set;
// otherwise verify the chain against RootCAs (or, when none are configured,
// require the pin — an unpinned, unrooted peer is rejected rather than trusted).
// It returns the parsed leaf for downstream signature checks.
func verifyPeerCertificate(chain [][]byte, cfg *Config) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty chain", errBadCertificate)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBadCertificate, err)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("%w: leaf key is not ECDSA", errBadCertificate)
	}

	if cfg.InsecureSkipVerify {
		return leaf, nil
	}
	if cfg.pinnedFingerprint {
		got := sha256.Sum256(chain[0])
		if got != cfg.PeerCertFingerprint {
			return nil, fmt.Errorf("%w: fingerprint mismatch", errBadCertificate)
		}
		return leaf, nil
	}
	if cfg.RootCAs == nil {
		return nil, fmt.Errorf("%w: no fingerprint pin and no root CAs configured", errBadCertificate)
	}

	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		if ic, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(ic)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         cfg.RootCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", errBadCertificate, err)
	}
	return leaf, nil
}

// signECDSA signs the SHA-256 digest of msg with key, returning the ASN.1 DER
// signature TLS 1.2 uses for ecdsa_secp256r1_sha256.
func signECDSA(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

// verifyECDSA checks an ASN.1 DER ECDSA signature over the SHA-256 digest of msg.
func verifyECDSA(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	digest := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

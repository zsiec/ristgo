package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Certificate holding for the certificate-authenticated suites: an ECDSA P-256 or
// RSA leaf certificate (self-signed by default), its DER chain, and the private
// key. The ECDHE_ECDSA suites need an ECDSA key; the ECDHE_RSA and RSA_WITH_NULL
// suites need an RSA key.

// rsaSelfSignedBits is the modulus size of a generated self-signed RSA key.
const rsaSelfSignedBits = 2048

// Certificate is one local certificate plus its signing key, supplied to a DTLS
// endpoint that authenticates with a certificate suite.
type Certificate struct {
	// DER is the certificate chain, leaf first, ASN.1 DER encoded.
	DER [][]byte
	// Leaf is the parsed leaf certificate (DER[0]).
	Leaf *x509.Certificate
	// PrivateKey is the leaf's private key: an *ecdsa.PrivateKey (P-256) or an
	// *rsa.PrivateKey, matching the leaf's public key type.
	PrivateKey crypto.Signer
}

// keyType reports whether the certificate authenticates with ECDSA or RSA, the
// authMethod of the suites it can serve. It returns ok=false for an unset Leaf or
// an unsupported key type rather than panicking (the Certificate fields are
// exported, so a hand-built literal may have a nil Leaf).
func (c *Certificate) keyType() (authMethod, bool) {
	if c.Leaf == nil {
		return 0, false
	}
	return leafKeyType(c.Leaf)
}

// leafKeyType maps a parsed leaf certificate's public key to its authMethod
// (ECDSA or RSA), or ok=false for any other key type.
func leafKeyType(leaf *x509.Certificate) (authMethod, bool) {
	switch leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return authECDSA, true
	case *rsa.PublicKey:
		return authRSA, true
	default:
		return 0, false
	}
}

// GenerateSelfSigned creates a fresh self-signed ECDSA P-256 certificate for the
// given common name, valid for one year. It is the default credential when an
// endpoint enables a certificate suite without supplying its own — adequate for
// the RIST use case, where peer identity is typically pinned by fingerprint
// rather than a PKI (libRIST has no DTLS PKI at all).
func GenerateSelfSigned(commonName string) (*Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: generate key: %w", err)
	}
	return selfSign(commonName, key, x509.KeyUsageDigitalSignature)
}

// GenerateSelfSignedRSA creates a fresh self-signed RSA certificate (2048-bit) for
// the given common name, valid for one year. It is the credential for the
// RSA-authenticated suites (ECDHE_RSA_* and RSA_WITH_NULL_SHA256); the key usage
// permits both signing (ECDHE_RSA ServerKeyExchange) and key encipherment (RSA
// key transport).
func GenerateSelfSignedRSA(commonName string) (*Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaSelfSignedBits)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: generate rsa key: %w", err)
	}
	return selfSign(commonName, key, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
}

// selfSign builds a one-year self-signed leaf for key with the given key usage.
func selfSign(commonName string, key crypto.Signer, usage x509.KeyUsage) (*Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
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

// CertificateFromPEM builds a Certificate from PEM-encoded certificate and private
// key blocks. The key may be ECDSA P-256 or RSA, and must match the certificate's
// public key type.
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
	key, err := parsePrivateKey(kBlock)
	if err != nil {
		return nil, err
	}
	if err := keyMatchesLeaf(key, leaf); err != nil {
		return nil, err
	}
	return &Certificate{DER: [][]byte{cBlock.Bytes}, Leaf: leaf, PrivateKey: key}, nil
}

// parsePrivateKey decodes an EC (SEC1), RSA (PKCS#1), or PKCS#8 private key from a
// PEM block, returning it as a crypto.Signer.
func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rist: dtls: parse private key: %w", err)
	}
	signer, ok := k8.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("rist: dtls: private key is not a signer")
	}
	switch signer.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
		return signer, nil
	default:
		return nil, fmt.Errorf("rist: dtls: unsupported private key type %T", signer)
	}
}

// keyMatchesLeaf verifies the private key corresponds to the leaf's public key.
func keyMatchesLeaf(key crypto.Signer, leaf *x509.Certificate) error {
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || !k.PublicKey.Equal(pub) {
			return fmt.Errorf("rist: dtls: private key does not match ECDSA certificate")
		}
	case *rsa.PublicKey:
		k, ok := key.(*rsa.PrivateKey)
		if !ok || !k.PublicKey.Equal(pub) {
			return fmt.Errorf("rist: dtls: private key does not match RSA certificate")
		}
	default:
		return fmt.Errorf("rist: dtls: unsupported certificate key type %T", leaf.PublicKey)
	}
	return nil
}

// errBadCertificate is returned when peer-certificate verification fails.
var errBadCertificate = errors.New("rist: dtls: peer certificate verification failed")

// peerRole is which side's certificate is being verified, used to constrain the
// accepted ExtKeyUsage on the RootCAs path: a client verifies the server's leaf
// (server_auth), a server verifies the client's leaf (client_auth).
type peerRole int

const (
	verifyingServerCert peerRole = iota // local endpoint is the client
	verifyingClientCert                 // local endpoint is the server
)

// verifyPeerCertificate validates a received certificate chain per cfg: skip when
// InsecureSkipVerify; match the pinned SHA-256 fingerprint when one is set;
// otherwise verify the chain against RootCAs (or, when none are configured,
// require the pin — an unpinned, unrooted peer is rejected rather than trusted).
// On the RootCAs path it constrains the accepted ExtKeyUsage to the peer's role
// and, when cfg.PeerName is set, additionally requires the leaf to be valid for
// that name (RFC 6125 SAN matching). It returns the parsed leaf for downstream
// signature checks. The leaf's key may be ECDSA P-256 or RSA.
func verifyPeerCertificate(chain [][]byte, cfg *Config, role peerRole) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty chain", errBadCertificate)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBadCertificate, err)
	}
	if !supportedLeafKey(leaf) {
		return nil, fmt.Errorf("%w: leaf key is not ECDSA P-256 or RSA", errBadCertificate)
	}

	if cfg.InsecureSkipVerify {
		return leaf, nil
	}
	if cfg.pinnedFingerprint {
		got := sha256.Sum256(chain[0])
		if got != cfg.PeerCertFingerprint {
			return nil, fmt.Errorf("%w: fingerprint mismatch", errBadCertificate)
		}
		// A pin authenticates the key, but still reject an expired or not-yet-valid
		// leaf, or an unsupported key, rather than accepting any bytes whose hash
		// matches.
		if err := checkLeafSanity(leaf); err != nil {
			return nil, err
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
	// Constrain the key usage to the peer's role rather than accepting any usage,
	// so a client-auth-only certificate cannot pose as a server (and vice versa).
	usage := x509.ExtKeyUsageServerAuth
	if role == verifyingClientCert {
		usage = x509.ExtKeyUsageClientAuth
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		// DNSName drives the standard library's hostname/SAN check when set; an
		// empty DNSName skips it, keeping the chain-of-trust-only default.
		DNSName:       cfg.PeerName,
		Roots:         cfg.RootCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", errBadCertificate, err)
	}
	return leaf, nil
}

// supportedLeafKey reports whether leaf carries a key type ristgo can verify
// against: ECDSA on P-256 or RSA.
func supportedLeafKey(leaf *x509.Certificate) bool {
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return pub.Curve == elliptic.P256()
	case *rsa.PublicKey:
		return true
	default:
		return false
	}
}

// checkLeafSanity rejects a peer leaf certificate that is outside its validity
// period or whose key is unsupported. It is applied on the fingerprint-pin path,
// where the pin authenticates the key but the certificate fields are otherwise
// unverified.
func checkLeafSanity(leaf *x509.Certificate) error {
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: certificate outside its validity period", errBadCertificate)
	}
	if !supportedLeafKey(leaf) {
		return fmt.Errorf("%w: leaf key is not ECDSA P-256 or RSA", errBadCertificate)
	}
	return nil
}

// signHandshake signs msg under the certificate's key, returning the TLS 1.2
// SignatureAndHashAlgorithm used and the signature. It always signs with SHA-256
// (a valid choice for every supported suite), choosing ECDSA or RSA-PKCS1 by the
// certificate's key type. It is used for the ECDHE ServerKeyExchange and the
// client CertificateVerify.
func signHandshake(cert *Certificate, msg []byte) (uint16, []byte, error) {
	digest := sha256.Sum256(msg)
	switch key := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			return 0, nil, fmt.Errorf("rist: dtls: ecdsa sign: %w", err)
		}
		return sigSchemeECDSAP256SHA256, sig, nil
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			return 0, nil, fmt.Errorf("rist: dtls: rsa sign: %w", err)
		}
		return sigSchemeRSAPKCS1SHA256, sig, nil
	default:
		return 0, nil, fmt.Errorf("rist: dtls: unsupported signing key type %T", cert.PrivateKey)
	}
}

// verifyHandshakeSignature verifies a handshake signature (ServerKeyExchange or
// CertificateVerify) under pub for the received TLS 1.2 sigScheme. It accepts
// ECDSA-P256 and RSA-PKCS1 over SHA-256 or SHA-384, so a peer that signs under
// either suite's hash is accepted. It returns an error (never panics) on any
// unsupported scheme, key-type mismatch, or bad signature.
func verifyHandshakeSignature(pub crypto.PublicKey, sigScheme uint16, msg, sig []byte) error {
	hashAlg := uint8(sigScheme >> 8)
	sigAlg := uint8(sigScheme)

	var digest []byte
	switch hashAlg {
	case hashAlgSHA256:
		d := sha256.Sum256(msg)
		digest = d[:]
	case hashAlgSHA384:
		d := sha512.Sum384(msg)
		digest = d[:]
	default:
		return fmt.Errorf("rist: dtls: unsupported signature hash %d", hashAlg)
	}

	switch sigAlg {
	case sigAlgECDSA:
		pk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("rist: dtls: ECDSA signature but non-ECDSA key")
		}
		if !ecdsa.VerifyASN1(pk, digest, sig) {
			return errors.New("rist: dtls: ECDSA signature invalid")
		}
		return nil
	case sigAlgRSA:
		pk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("rist: dtls: RSA signature but non-RSA key")
		}
		var h crypto.Hash
		if hashAlg == hashAlgSHA256 {
			h = crypto.SHA256
		} else {
			h = crypto.SHA384
		}
		if err := rsa.VerifyPKCS1v15(pk, h, digest, sig); err != nil {
			return fmt.Errorf("rist: dtls: RSA signature invalid: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("rist: dtls: unsupported signature algorithm %d", sigAlg)
	}
}

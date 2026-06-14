package dtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// selfSignedWithSAN mints a self-signed ECDSA P-256 leaf carrying the given DNS
// and IP Subject Alternative Names, restricted to the given ExtKeyUsage. The
// returned cert is its own CA (usable directly in a RootCAs pool), which lets the
// L9 PeerName tests exercise chain verification + SAN matching without a separate
// issuer.
func selfSignedWithSAN(t *testing.T, cn string, dns []string, ips []net.IP, eku []x509.ExtKeyUsage) *Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed root for the test pool
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return &Certificate{DER: [][]byte{der}, Leaf: leaf, PrivateKey: key}
}

func poolOf(certs ...*Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c.Leaf)
	}
	return p
}

// TestRootCAsPeerNameMatching is the L9 regression: on the RootCAs path, when
// cfg.PeerName is set the peer's leaf must be valid for that name (SAN match);
// when it is empty, RootCAs authenticates chain-of-trust only (any leaf the CA
// signed is accepted). A wrong PeerName is rejected.
func TestRootCAsPeerNameMatching(t *testing.T) {
	serverCert := selfSignedWithSAN(t, "rist-server", []string{"rist.example"}, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := poolOf(serverCert)

	tests := []struct {
		name     string
		peerName string
		wantErr  bool
	}{
		{"name matches SAN", "rist.example", false},
		{"name empty -> chain-of-trust only", "", false},
		{"name mismatches SAN", "evil.example", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Certificate:       serverCert,
				RootCAs:           roots,
				PeerName:          tc.peerName,
				RetransmitTimeout: 50 * time.Millisecond,
				HandshakeTimeout:  2 * time.Second,
			}
			_, err := verifyPeerCertificate(serverCert.DER, cfg, verifyingServerCert)
			if tc.wantErr && err == nil {
				t.Fatalf("PeerName %q: expected rejection, got accept", tc.peerName)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("PeerName %q: expected accept, got %v", tc.peerName, err)
			}
		})
	}
}

// TestRootCAsRoleRestrictsExtKeyUsage is the L9 role check: a leaf valid only for
// client_auth must be rejected when presented as a server certificate (the
// client verifies with verifyingServerCert), and accepted when verified as a
// client certificate. This stops a client-only credential from posing as a
// server under the same CA.
func TestRootCAsRoleRestrictsExtKeyUsage(t *testing.T) {
	// A leaf usable only for client authentication.
	clientOnly := selfSignedWithSAN(t, "rist-client", []string{"rist.client"}, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	roots := poolOf(clientOnly)
	cfg := &Config{RootCAs: roots}

	// As a server certificate (client's view): must be rejected.
	if _, err := verifyPeerCertificate(clientOnly.DER, cfg, verifyingServerCert); err == nil {
		t.Fatal("client-auth-only leaf accepted as a server certificate")
	}
	// As a client certificate (server's view): accepted.
	if _, err := verifyPeerCertificate(clientOnly.DER, cfg, verifyingClientCert); err != nil {
		t.Fatalf("client-auth leaf rejected as a client certificate: %v", err)
	}
}

// TestRootCAsPeerNameMismatchMessage sanity-checks the rejection is the bad-cert
// sentinel (so callers can match it), not an unrelated error.
func TestRootCAsPeerNameMismatchMessage(t *testing.T) {
	cert := selfSignedWithSAN(t, "rist-server", []string{"rist.example"}, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	cfg := &Config{RootCAs: poolOf(cert), PeerName: "nope.example"}
	_, err := verifyPeerCertificate(cert.DER, cfg, verifyingServerCert)
	if err == nil || !strings.Contains(err.Error(), "rist: dtls: peer certificate verification failed") {
		t.Fatalf("unexpected error for SAN mismatch: %v", err)
	}
}

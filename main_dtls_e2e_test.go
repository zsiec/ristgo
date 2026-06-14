package ristgo_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// genDTLSCert produces a self-signed ECDSA P-256 certificate + key as PEM and its
// SHA-256 fingerprint (over the leaf DER), for the cert-mode DTLS e2e: the
// receiver presents the certificate, the sender pins the fingerprint.
func genDTLSCert(t *testing.T) (certPEM, keyPEM []byte, fp [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ristgo-dtls-e2e"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, sha256.Sum256(der)
}

// TestE2EMainDTLS runs a full Main-profile stream over a DTLS 1.2 tunnel, both
// cipher suites, ristgo↔ristgo: the sender (DTLS client) and receiver (DTLS
// server) complete the handshake, then the GRE tunnel rides inside DTLS records
// and the payload arrives bit-exact.
func TestE2EMainDTLS(t *testing.T) {
	t.Run("PSK", func(t *testing.T) {
		psk := []byte("ristgo-dtls-main-secret")
		dc := func() *ristgo.DTLSConfig {
			return &ristgo.DTLSConfig{PSK: psk, PSKIdentity: "ristgo"}
		}
		runMainDTLS(t, dc(), dc())
	})

	t.Run("Cert", func(t *testing.T) {
		certPEM, keyPEM, fp := genDTLSCert(t)
		rxDC := &ristgo.DTLSConfig{CertPEM: certPEM, KeyPEM: keyPEM}
		txDC := &ristgo.DTLSConfig{PeerFingerprint: fp}
		runMainDTLS(t, txDC, rxDC)
	})
}

func runMainDTLS(t *testing.T, txDTLS, rxDTLS *ristgo.DTLSConfig) {
	const totalBytes = 96 * 1024
	const chunk = 1200

	port := freeEvenPort(t)

	mkcfg := func(dc *ristgo.DTLSConfig) ristgo.Config {
		c := ristgo.DefaultConfig()
		c.Profile = ristgo.ProfileMain
		c.BufferMin = 300 * time.Millisecond
		c.BufferMax = 300 * time.Millisecond
		c.DTLS = dc
		return c
	}

	rx, err := ristgo.NewReceiver(fmt.Sprintf("127.0.0.1:%d", port), mkcfg(rxDTLS))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()

	tx, err := ristgo.NewSender(fmt.Sprintf("127.0.0.1:%d", port), mkcfg(txDTLS))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	payload := make([]byte, totalBytes)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := sha256.Sum256(payload)

	done := make(chan [32]byte, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(25 * time.Second))
		got := make([]byte, 0, totalBytes)
		buf := make([]byte, 4096)
		h := sha256.New()
		for len(got) < totalBytes {
			n, rerr := rx.Read(buf)
			if n > 0 {
				take := n
				if len(got)+take > totalBytes {
					take = totalBytes - len(got)
				}
				h.Write(buf[:take])
				got = append(got, buf[:take]...)
			}
			if rerr != nil {
				done <- [32]byte{}
				return
			}
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- sum
	}()

	tx.SetWriteDeadline(time.Now().Add(25 * time.Second))
	for off := 0; off < totalBytes; off += chunk {
		end := off + chunk
		if end > totalBytes {
			end = totalBytes
		}
		if _, werr := tx.Write(payload[off:end]); werr != nil {
			t.Fatalf("Write at %d: %v", off, werr)
		}
		if (off/chunk)%8 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	flush := make([]byte, chunk)
	for i := 0; i < 24; i++ {
		tx.Write(flush)
		time.Sleep(time.Millisecond)
	}

	select {
	case got := <-done:
		if got != want {
			t.Fatalf("DTLS Main stream hash mismatch (delivered=%d recovered=%d lost=%d)",
				rx.Stats().Delivered, rx.Stats().Recovered, rx.Stats().Lost)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out (delivered=%d)", rx.Stats().Delivered)
	}
}

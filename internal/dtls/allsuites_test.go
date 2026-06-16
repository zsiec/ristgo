package dtls

import "testing"

// TestHandshakeAllSuites drives a full DTLS 1.2 handshake plus a bidirectional
// application-data exchange over the in-memory pipe for EVERY supported cipher
// suite — the five TR-06-2 §6.2 mandatory suites and the PSK suite — forcing each
// in turn via the per-suite disable knob. It proves the key schedule, record
// protection (AES-128/256-GCM and the NULL+HMAC integrity-only path), the
// SHA-256/SHA-384 PRFs, and the ECDHE/RSA-transport/PSK key exchanges all
// interoperate against ristgo itself for each suite.
func TestHandshakeAllSuites(t *testing.T) {
	ecdsaCert, err := GenerateSelfSigned("ristgo-ecdsa")
	if err != nil {
		t.Fatalf("ecdsa cert: %v", err)
	}
	rsaCert, err := GenerateSelfSignedRSA("ristgo-rsa")
	if err != nil {
		t.Fatalf("rsa cert: %v", err)
	}

	cases := []struct {
		name     string
		want     uint16
		clientFn func() *Config
		serverFn func() *Config
	}{
		{
			name: "ECDHE_ECDSA_AES128_GCM_SHA256",
			want: tlsECDHEECDSAWithAES128GCMSHA256,
			// Disable the stronger AES-256 ECDSA suite so AES-128 is chosen.
			clientFn: func() *Config {
				return &Config{InsecureSkipVerify: true, DisabledSuites: []uint16{tlsECDHEECDSAWithAES256GCMSHA384}}
			},
			serverFn: func() *Config {
				return &Config{Certificate: ecdsaCert, DisabledSuites: []uint16{tlsECDHEECDSAWithAES256GCMSHA384}}
			},
		},
		{
			name:     "ECDHE_ECDSA_AES256_GCM_SHA384",
			want:     tlsECDHEECDSAWithAES256GCMSHA384,
			clientFn: func() *Config { return &Config{InsecureSkipVerify: true} },
			serverFn: func() *Config { return &Config{Certificate: ecdsaCert} },
		},
		{
			name: "ECDHE_RSA_AES128_GCM_SHA256",
			want: tlsECDHERSAWithAES128GCMSHA256,
			clientFn: func() *Config {
				return &Config{InsecureSkipVerify: true, DisabledSuites: []uint16{tlsECDHERSAWithAES256GCMSHA384}}
			},
			serverFn: func() *Config {
				return &Config{Certificate: rsaCert, DisabledSuites: []uint16{tlsECDHERSAWithAES256GCMSHA384}}
			},
		},
		{
			name:     "ECDHE_RSA_AES256_GCM_SHA384",
			want:     tlsECDHERSAWithAES256GCMSHA384,
			clientFn: func() *Config { return &Config{InsecureSkipVerify: true} },
			serverFn: func() *Config { return &Config{Certificate: rsaCert} },
		},
		{
			name: "RSA_WITH_NULL_SHA256",
			want: tlsRSAWithNULLSHA256,
			// The integrity-only NULL suite requires the explicit AllowNullCipher
			// opt-in. Disable both ECDHE_RSA suites so it is the only one the
			// RSA-certificate server can serve.
			clientFn: func() *Config {
				return &Config{InsecureSkipVerify: true, AllowNullCipher: true, DisabledSuites: []uint16{tlsECDHERSAWithAES256GCMSHA384, tlsECDHERSAWithAES128GCMSHA256}}
			},
			serverFn: func() *Config {
				return &Config{Certificate: rsaCert, AllowNullCipher: true, DisabledSuites: []uint16{tlsECDHERSAWithAES256GCMSHA384, tlsECDHERSAWithAES128GCMSHA256}}
			},
		},
		{
			name:     "PSK_WITH_AES128_GCM_SHA256",
			want:     tlsPSKWithAES128GCMSHA256,
			clientFn: func() *Config { return &Config{PSK: []byte("shared-secret"), PSKIdentity: []byte("rist")} },
			serverFn: func() *Config { return &Config{PSK: []byte("shared-secret"), PSKIdentity: []byte("rist")} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := handshakePair(t, tc.clientFn(), tc.serverFn())
			defer client.Close()
			defer server.Close()
			if cs, _ := client.ConnectionState(); cs != tc.want {
				t.Fatalf("negotiated suite = %#04x, want %#04x", cs, tc.want)
			}
			if cs, _ := server.ConnectionState(); cs != tc.want {
				t.Fatalf("server suite = %#04x, want %#04x", cs, tc.want)
			}
			exchange(t, client, server)
		})
	}
}

// TestNullCipherRequiresOptIn proves the integrity-only TLS_RSA_WITH_NULL_SHA256
// (no confidentiality) is NOT reachable by default: with an RSA cert but the
// encrypting suites disabled and AllowNullCipher unset, the handshake fails with no
// common suite rather than silently negotiating a cleartext session. The same setup
// with AllowNullCipher succeeds (covered by TestHandshakeAllSuites).
func TestNullCipherRequiresOptIn(t *testing.T) {
	rsaCert, err := GenerateSelfSignedRSA("ristgo-rsa")
	if err != nil {
		t.Fatalf("rsa cert: %v", err)
	}
	disableECDHE := []uint16{tlsECDHERSAWithAES256GCMSHA384, tlsECDHERSAWithAES128GCMSHA256}

	ca, sa := newPipe()
	client := Client(ca, &Config{InsecureSkipVerify: true, DisabledSuites: disableECDHE}) // no AllowNullCipher
	server := Server(sa, &Config{Certificate: rsaCert, DisabledSuites: disableECDHE})     // no AllowNullCipher

	done := make(chan struct{})
	go func() { _ = server.Handshake(); close(done) }()
	if err := client.Handshake(); err == nil {
		t.Fatal("handshake succeeded negotiating the NULL cipher without AllowNullCipher; it must be opt-in")
	}
	client.Close()
	server.Close()
	<-done
}

// TestDisableAllSuitesFails confirms the §6.2 disable knob can turn a suite off:
// disabling every suite the configs could otherwise share makes the handshake
// fail with no common suite rather than silently falling back.
func TestDisableAllSuitesFails(t *testing.T) {
	cert, err := GenerateSelfSigned("ristgo-ecdsa")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	all := []uint16{
		tlsECDHEECDSAWithAES128GCMSHA256, tlsECDHEECDSAWithAES256GCMSHA384,
		tlsECDHERSAWithAES128GCMSHA256, tlsECDHERSAWithAES256GCMSHA384,
		tlsRSAWithNULLSHA256, tlsPSKWithAES128GCMSHA256,
	}
	ca, sa := newPipe()
	client := Client(ca, &Config{InsecureSkipVerify: true, DisabledSuites: all})
	server := Server(sa, &Config{Certificate: cert, DisabledSuites: all})

	done := make(chan struct{})
	go func() { _ = server.Handshake(); close(done) }()
	if err := client.Handshake(); err == nil {
		t.Fatal("handshake succeeded with every suite disabled; want failure")
	}
	client.Close()
	server.Close()
	<-done
}

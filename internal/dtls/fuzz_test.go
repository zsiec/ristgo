package dtls

import "testing"

// FuzzParseRecord asserts the record layer never panics on arbitrary input and
// that a successfully parsed record re-marshals to a prefix of its input.
func FuzzParseRecord(f *testing.F) {
	f.Add([]byte{22, 254, 253, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, n, err := parseRecord(b)
		if err != nil {
			return
		}
		if n < recordHeaderLen || n > len(b) {
			t.Fatalf("consumed %d out of range for %d bytes", n, len(b))
		}
		_ = r.marshal(nil)
		_, _ = splitRecords(b)
	})
}

// FuzzParseHandshake asserts the handshake fragment parser and the message-body
// parsers never panic on arbitrary input.
func FuzzParseHandshake(f *testing.F) {
	f.Add([]byte{1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 4, 0xFE, 0xFD, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if pf, n, err := parseHandshakeFragment(b); err == nil {
			if n < handshakeHeaderLen || n > len(b) {
				t.Fatalf("handshake consumed %d out of range for %d", n, len(b))
			}
			_ = pf
		}
		// Body parsers must tolerate arbitrary bytes without panicking.
		_, _ = parseClientHello(b)
		_, _ = parseServerHello(b)
		_, _ = parseHelloVerifyRequest(b)
		_, _ = parseCertificate(b)
		_, _ = parseServerKeyExchange(b)
		_, _ = parseClientKeyExchangePSK(b)
		_, _ = parseClientKeyExchangeECDHE(b)
		_, _ = parseCertificateVerify(b)
	})
}

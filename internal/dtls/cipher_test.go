package dtls

import (
	"bytes"
	"errors"
	"testing"
)

// TestRecordProtectionRoundTrip derives keys on two independent endpoints from
// the same master secret and randoms, then seals on one and opens on the other —
// proving the key schedule is deterministic and the AEAD framing round-trips.
func TestRecordProtectionRoundTrip(t *testing.T) {
	master := bytes.Repeat([]byte{0xAB}, masterSecretLength)
	clientRandom := bytes.Repeat([]byte{0x01}, 32)
	serverRandom := bytes.Repeat([]byte{0x02}, 32)

	a, err := deriveKeys(master, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("deriveKeys a: %v", err)
	}
	b, err := deriveKeys(master, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("deriveKeys b: %v", err)
	}

	plaintext := []byte("the quick brown fox over a lossy datagram link")

	// Client direction: a.clientWrite seals, b.clientWrite opens.
	frag := a.clientWrite.seal(1, 7, recordApplicationData, versionDTLS12, plaintext)
	if len(frag) != gcmExplicitNonceLen+len(plaintext)+gcmTagLen {
		t.Fatalf("sealed length = %d, want %d", len(frag), gcmExplicitNonceLen+len(plaintext)+gcmTagLen)
	}
	rec := record{typ: recordApplicationData, version: versionDTLS12, epoch: 1, seq: 7, fragment: frag}
	got, err := b.clientWrite.open(rec)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip: got %q want %q", got, plaintext)
	}

	// Server direction round-trips independently with the other half.
	srvFrag := a.serverWrite.seal(1, 3, recordApplicationData, versionDTLS12, plaintext)
	srvRec := record{typ: recordApplicationData, version: versionDTLS12, epoch: 1, seq: 3, fragment: srvFrag}
	if got, err := b.serverWrite.open(srvRec); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("server direction round-trip: got %q err %v", got, err)
	}
}

// TestRecordProtectionTamper verifies any mutation — ciphertext, AAD-bound
// header fields, or the explicit nonce — fails authentication with the uniform
// errBadRecordMAC.
func TestRecordProtectionTamper(t *testing.T) {
	master := bytes.Repeat([]byte{0x5A}, masterSecretLength)
	keys, err := deriveKeys(master, make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}
	plaintext := []byte("authenticate me")
	frag := keys.clientWrite.seal(1, 42, recordApplicationData, versionDTLS12, plaintext)

	tests := []struct {
		name string
		mut  func(r *record)
	}{
		{"flip ciphertext", func(r *record) { r.fragment[len(r.fragment)-1] ^= 1 }},
		{"flip explicit nonce", func(r *record) { r.fragment[0] ^= 1 }},
		{"wrong epoch (AAD)", func(r *record) { r.epoch = 2 }},
		{"wrong seq (AAD)", func(r *record) { r.seq = 43 }},
		{"wrong type (AAD)", func(r *record) { r.typ = recordHandshake }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := append([]byte(nil), frag...)
			rec := record{typ: recordApplicationData, version: versionDTLS12, epoch: 1, seq: 42, fragment: f}
			tc.mut(&rec)
			if _, err := keys.clientWrite.open(rec); !errors.Is(err, errBadRecordMAC) {
				t.Errorf("open after %s: err = %v, want errBadRecordMAC", tc.name, err)
			}
		})
	}
}

func TestOpenShortFragment(t *testing.T) {
	keys, err := deriveKeys(make([]byte, 48), make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}
	rec := record{typ: recordApplicationData, version: versionDTLS12, fragment: make([]byte, gcmOverhead-1)}
	if _, err := keys.clientWrite.open(rec); !errors.Is(err, errBadRecordMAC) {
		t.Errorf("short fragment: err = %v, want errBadRecordMAC", err)
	}
}

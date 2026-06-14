package crypto

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// mustHex decodes a hex string in a test, failing fast on malformed input.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestDeriveKeyPBKDF2KAT anchors DeriveKey's key-derivation function against
// INDEPENDENT, published PBKDF2-HMAC-SHA256 test vectors so the derivation is
// not self-referential.
//
// Source: RFC 7914 §11 "Test Vectors for PBKDF2 with HMAC-SHA-256". Those
// vectors fix PBKDF2-HMAC-SHA256(P, S, c, dkLen). Because DeriveKey pins the
// salt to a 4-byte nonce and the iteration count to RIST's 1024, we cannot
// feed RFC 7914's exact (salt, c) through DeriveKey; instead we verify the
// underlying primitive (crypto/pbkdf2.Key with sha256) reproduces the RFC
// vector bit-for-bit, and separately verify DeriveKey == that same primitive
// with RIST's fixed parameters. The RFC value below was cross-checked with
// Python's hashlib.pbkdf2_hmac('sha256', ...).
func TestDeriveKeyPBKDF2KAT(t *testing.T) {
	// RFC 7914 §11: P="passwd", S="salt", c=1, dkLen=64.
	const (
		rfcPassword = "passwd"
		rfcSalt     = "salt"
		rfcIter     = 1
		rfcDkLen    = 64
		rfcExpect   = "55ac046e56e3089fec1691c22544b605" +
			"f94185216dde0465e68b9d57c20dacbc" +
			"49ca9cccf179b645991664b39d77ef31" +
			"7c71b845b1e30bd509112041d3a19783"
	)
	got, err := pbkdf2Key([]byte(rfcPassword), []byte(rfcSalt), rfcIter, rfcDkLen)
	if err != nil {
		t.Fatalf("pbkdf2Key: %v", err)
	}
	if want := mustHex(t, rfcExpect); !bytes.Equal(got, want) {
		t.Fatalf("RFC 7914 §11 PBKDF2-HMAC-SHA256 mismatch:\n got  %x\n want %x", got, want)
	}

	// DeriveKey must equal the same primitive run with RIST's fixed salt
	// (the 4-byte nonce) and 1024 iterations.
	password := []byte("ristgo-test-passphrase")
	nonce := []byte{0x12, 0x34, 0x56, 0x78}
	for _, keyBits := range []int{KeySize128, KeySize256} {
		dk, err := DeriveKey(password, nonce, keyBits)
		if err != nil {
			t.Fatalf("DeriveKey(%d): %v", keyBits, err)
		}
		if len(dk) != keyBits/8 {
			t.Fatalf("DeriveKey(%d) length = %d, want %d", keyBits, len(dk), keyBits/8)
		}
		ref, err := pbkdf2Key(password, nonce, pbkdf2Iterations, keyBits/8)
		if err != nil {
			t.Fatalf("pbkdf2Key reference: %v", err)
		}
		if !bytes.Equal(dk, ref) {
			t.Fatalf("DeriveKey(%d) != reference PBKDF2:\n got  %x\n want %x", keyBits, dk, ref)
		}
	}
}

// pbkdf2Key is a thin test-only wrapper around the stdlib primitive, used to
// reproduce the RFC vector without DeriveKey's RIST-specific clamps.
func pbkdf2Key(password, salt []byte, iter, dkLen int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(password), salt, iter, dkLen)
}

// TestDeriveKey128IsPrefixOf256 documents that PBKDF2 derives the 128-bit key
// as the 16-byte prefix of the 256-bit key for the same inputs (a property of
// PBKDF2's block construction). This is a useful internal consistency check.
func TestDeriveKey128IsPrefixOf256(t *testing.T) {
	password := []byte("ristgo-test-passphrase")
	nonce := []byte{0x12, 0x34, 0x56, 0x78}
	k128, err := DeriveKey(password, nonce, KeySize128)
	if err != nil {
		t.Fatal(err)
	}
	k256, err := DeriveKey(password, nonce, KeySize256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k128, k256[:16]) {
		t.Fatalf("128-bit key not a prefix of 256-bit key:\n %x\n %x", k128, k256[:16])
	}
}

func TestDeriveKeyErrors(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		nonce    []byte
		keyBits  int
		wantErr  error
	}{
		{"badKeySize", []byte("p"), []byte{1, 2, 3, 4}, 192, ErrInvalidKeySize},
		{"zeroKeySize", []byte("p"), []byte{1, 2, 3, 4}, 0, ErrInvalidKeySize},
		{"emptyPassword", nil, []byte{1, 2, 3, 4}, KeySize128, ErrEmptyPassword},
		{"shortNonce", []byte("p"), []byte{1, 2, 3}, KeySize128, ErrInvalidNonceLength},
		{"longNonce", []byte("p"), []byte{1, 2, 3, 4, 5}, KeySize128, ErrInvalidNonceLength},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveKey(tt.password, tt.nonce, tt.keyBits)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("DeriveKey error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// goldenPSK pins the full PSK path (PBKDF2 → IV → AES-CTR) for fixed inputs to
// an exact ciphertext, so any regression in derivation, IV layout, or
// keystream is caught. The expected bytes were produced by three independent
// implementations that all agreed: Go's crypto stack, OpenSSL `enc
// -aes-{128,256}-ctr -nopad`, and Python's hashlib.pbkdf2_hmac. The definitive
// byte-exact proof against libRIST itself lands at WP6b (interop); this golden
// guards against drift in the meantime.
var goldenPSK = []struct {
	name      string
	password  []byte
	nonce     [NonceSize]byte
	seq       uint32
	plaintext []byte
	keyBits   int
	wantKey   string // hex of the derived AES key
	wantCT    string // hex of the AES-CTR ciphertext
}{
	{
		name:      "aes128",
		password:  []byte("ristgo-test-passphrase"),
		nonce:     [NonceSize]byte{0x12, 0x34, 0x56, 0x78},
		seq:       0x0A0B0C0D,
		plaintext: seqBytes(48),
		keyBits:   KeySize128,
		wantKey:   "e71c678c592282b5027e918d8407948a",
		wantCT: "f5883ed25bbc57d8a9bbb46bff8bae35" +
			"d5d6ee5a1f7453b4e8bddf96e962fce2" +
			"b7c5dd350c40b4ee9ec04565e1657a19",
	},
	{
		name:      "aes256",
		password:  []byte("ristgo-test-passphrase"),
		nonce:     [NonceSize]byte{0x12, 0x34, 0x56, 0x78},
		seq:       0x0A0B0C0D,
		plaintext: seqBytes(48),
		keyBits:   KeySize256,
		wantKey: "e71c678c592282b5027e918d8407948a" +
			"7f7dffaaf8cb34055f75dbfd144c2101",
		wantCT: "a9d99869d41be7d0c8528f49613572a9" +
			"7658cccac65cb2f15bb8fa6d82dca66d" +
			"c2aa610fc2c3a34b84c67262d3a2dd1e",
	},
}

// seqBytes returns n bytes 0x00, 0x01, ... used as deterministic plaintext.
func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestGoldenPSK(t *testing.T) {
	for _, g := range goldenPSK {
		t.Run(g.name, func(t *testing.T) {
			// Derived key matches the frozen value.
			dk, err := DeriveKey(g.password, g.nonce[:], g.keyBits)
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, g.wantKey); !bytes.Equal(dk, want) {
				t.Fatalf("derived key:\n got  %x\n want %x", dk, want)
			}

			// One-shot Decrypt over the golden ciphertext yields the plaintext
			// (CTR is symmetric, so Decrypt of ciphertext == plaintext).
			wantCT := mustHex(t, g.wantCT)
			pt, err := Decrypt(g.password, g.keyBits, g.nonce, g.seq, nil, wantCT)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, g.plaintext) {
				t.Fatalf("Decrypt(golden) plaintext:\n got  %x\n want %x", pt, g.plaintext)
			}

			// Decryptor reproduces the same plaintext.
			d, err := NewDecryptor(g.password, g.keyBits)
			if err != nil {
				t.Fatal(err)
			}
			pt2, err := d.Decrypt(g.nonce, g.seq, nil, wantCT)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt2, g.plaintext) {
				t.Fatalf("Decryptor plaintext:\n got  %x\n want %x", pt2, g.plaintext)
			}

			// And encrypting the plaintext under the same nonce reproduces the
			// golden ciphertext. We use a Decryptor-symmetric one-shot to keep
			// the nonce fixed (Key generates its own nonce).
			ct, err := Decrypt(g.password, g.keyBits, g.nonce, g.seq, nil, g.plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ct, wantCT) {
				t.Fatalf("encrypt(plaintext):\n got  %x\n want %x", ct, wantCT)
			}
		})
	}
}

func TestBuildIV(t *testing.T) {
	tests := []struct {
		name string
		seq  uint32
		want [16]byte
	}{
		{"zero", 0x00000000, [16]byte{}},
		{"one", 0x00000001, [16]byte{0, 0, 0, 1}},
		{"typical", 0x0A0B0C0D, [16]byte{0x0A, 0x0B, 0x0C, 0x0D}},
		{"high", 0x80000000, [16]byte{0x80, 0, 0, 0}},
		{"max", 0xFFFFFFFF, [16]byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"wrapBoundary", 0xFFFFFFFE, [16]byte{0xFF, 0xFF, 0xFF, 0xFE}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iv := BuildIV(tt.seq)
			if iv != tt.want {
				t.Fatalf("BuildIV(%#x) = %x, want %x", tt.seq, iv, tt.want)
			}
			// Bytes [4:16] must always be zero (the AES-CTR block counter
			// window).
			for i := 4; i < 16; i++ {
				if iv[i] != 0 {
					t.Fatalf("BuildIV(%#x) byte %d = %#x, want 0", tt.seq, i, iv[i])
				}
			}
		})
	}
}

func TestNewKeyValidation(t *testing.T) {
	tests := []struct {
		name        string
		password    []byte
		keyBits     int
		keyRotation int
		wantErr     error
	}{
		{"ok128", []byte("p"), KeySize128, 0, nil},
		{"ok256", []byte("p"), KeySize256, 100, nil},
		{"badBits", []byte("p"), 64, 0, ErrInvalidKeySize},
		{"emptyPassword", nil, KeySize128, 0, ErrEmptyPassword},
		{"negativeRotation", []byte("p"), KeySize128, -1, ErrNegativeRotation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := NewKey(tt.password, tt.keyBits, tt.keyRotation, false)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewKey error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil {
				if k == nil {
					t.Fatal("NewKey returned nil key without error")
				}
				if isZeroNonce(k.Nonce()) {
					t.Fatal("NewKey produced a zero nonce")
				}
			}
		})
	}
}

// TestEncryptDecryptRoundTrip exercises the stateful Key encrypt path against
// a Decryptor for several payloads and sequence numbers, asserting the
// recovered plaintext is identical.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, keyBits := range []int{KeySize128, KeySize256} {
		for _, odd := range []bool{false, true} {
			k, err := NewKey([]byte("round-trip-secret"), keyBits, 0, odd)
			if err != nil {
				t.Fatal(err)
			}
			d, err := NewDecryptor([]byte("round-trip-secret"), keyBits)
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range []int{0, 1, 7, 16, 17, 188, 1316} {
				for _, seq := range []uint32{0, 1, 0x12345678, 0xFFFFFFFF} {
					pt := seqBytes(n)
					ct, err := k.Encrypt(seq, nil, pt)
					if err != nil {
						t.Fatalf("Encrypt: %v", err)
					}
					// For payloads of a few blocks or more, an unencrypted
					// ciphertext is implausible (a coincident all-zero
					// keystream window). For single-byte payloads the
					// keystream byte can legitimately be zero, so we skip the
					// inequality check there and rely on the round-trip below.
					if n >= 16 && bytes.Equal(ct, pt) {
						t.Fatalf("ciphertext equals plaintext for n=%d", n)
					}
					got, err := d.Decrypt(k.Nonce(), seq, nil, ct)
					if err != nil {
						t.Fatalf("Decrypt: %v", err)
					}
					if !bytes.Equal(got, pt) {
						t.Fatalf("round-trip mismatch keyBits=%d n=%d seq=%#x:\n got  %x\n want %x",
							keyBits, n, seq, got, pt)
					}
				}
			}
		}
	}
}

func TestDecryptZeroNonceRejected(t *testing.T) {
	var zero [NonceSize]byte
	if _, err := Decrypt([]byte("p"), KeySize128, zero, 1, nil, []byte("data")); !errors.Is(err, ErrZeroNonce) {
		t.Fatalf("one-shot Decrypt zero nonce error = %v, want ErrZeroNonce", err)
	}
	d, err := NewDecryptor([]byte("p"), KeySize128)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decrypt(zero, 1, nil, []byte("data")); !errors.Is(err, ErrZeroNonce) {
		t.Fatalf("Decryptor zero nonce error = %v, want ErrZeroNonce", err)
	}
}

// TestNonceBBit asserts the odd/even passphrase marker: odd sets bit 7 of
// nonce[0], even clears it. We construct many keys and check
// every generated nonce.
func TestNonceBBit(t *testing.T) {
	for _, odd := range []bool{false, true} {
		for i := 0; i < 64; i++ {
			k, err := NewKey([]byte("bbit"), KeySize128, 0, odd)
			if err != nil {
				t.Fatal(err)
			}
			n := k.Nonce()
			bit := n[0]&nonceBBitMask != 0
			if bit != odd {
				t.Fatalf("nonce[0]=%#x B-bit=%v, want odd=%v", n[0], bit, odd)
			}
			if isZeroNonce(n) {
				t.Fatal("generated zero nonce")
			}
		}
	}
}

// TestKeyRotationThreshold asserts the nonce rotates after keyRotation
// encrypted packets and not before.
func TestKeyRotationThreshold(t *testing.T) {
	const rotation = 4
	k, err := NewKey([]byte("rotate"), KeySize128, rotation, false)
	if err != nil {
		t.Fatal(err)
	}
	first := k.Nonce()
	pt := []byte("payload")
	// The first `rotation` encrypts run under the initial nonce; the
	// (rotation+1)th rotates a fresh nonce first.
	for i := 0; i < rotation; i++ {
		if _, err := k.Encrypt(uint32(i), nil, pt); err != nil {
			t.Fatal(err)
		}
		if k.Nonce() != first {
			t.Fatalf("nonce rotated early after %d packets", i+1)
		}
	}
	if _, err := k.Encrypt(uint32(rotation), nil, pt); err != nil {
		t.Fatal(err)
	}
	if k.Nonce() == first {
		t.Fatalf("nonce did not rotate after reaching threshold of %d", rotation)
	}
}

// TestNoRotationWhenZero asserts keyRotation==0 never rotates within any
// reasonable packet count (it rotates only at the uint32 reuse limit).
func TestNoRotationWhenZero(t *testing.T) {
	k, err := NewKey([]byte("norotate"), KeySize128, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	first := k.Nonce()
	pt := []byte("payload")
	for i := 0; i < 100000; i++ {
		if _, err := k.Encrypt(uint32(i), nil, pt); err != nil {
			t.Fatal(err)
		}
	}
	if k.Nonce() != first {
		t.Fatal("nonce rotated with keyRotation=0")
	}
}

// TestDecryptorRekeyOnNonceChange asserts the Decryptor re-derives its key
// when the inbound nonce changes, and decrypts correctly across two nonces.
func TestDecryptorRekeyOnNonceChange(t *testing.T) {
	password := []byte("rekey-secret")
	d, err := NewDecryptor(password, KeySize256)
	if err != nil {
		t.Fatal(err)
	}
	nonceA := [NonceSize]byte{0x01, 0x02, 0x03, 0x04}
	nonceB := [NonceSize]byte{0x11, 0x22, 0x33, 0x44}
	if nonceA == nonceB {
		t.Fatal("test nonces must differ")
	}
	pt := seqBytes(100)
	seq := uint32(0xABCDEF01)

	ctA, err := Decrypt(password, KeySize256, nonceA, seq, nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	ctB, err := Decrypt(password, KeySize256, nonceB, seq, nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ctA, ctB) {
		t.Fatal("different nonces produced identical ciphertext")
	}

	gotA, err := d.Decrypt(nonceA, seq, nil, ctA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, pt) {
		t.Fatal("decrypt under nonceA mismatch")
	}
	// Switch nonce; Decryptor must re-derive.
	gotB, err := d.Decrypt(nonceB, seq, nil, ctB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, pt) {
		t.Fatal("decrypt under nonceB mismatch (rekey failed)")
	}
	// Switch back; must re-derive again and still be correct.
	gotA2, err := d.Decrypt(nonceA, seq, nil, ctA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA2, pt) {
		t.Fatal("decrypt back under nonceA mismatch")
	}
}

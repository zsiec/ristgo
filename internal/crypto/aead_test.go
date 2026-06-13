package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

// TestAESGCMKAT anchors the AES-GCM primitive (sealGCM/openGCM) against a
// PUBLISHED NIST GCM standard vector so the cipher is not self-referential.
//
// Source: NIST SP 800-38D "Recommendation for Block Cipher Modes of Operation:
// Galois/Counter Mode (GCM) and GMAC", AES-128 Test Case 4 (the McGrew-Viega
// vectors NIST adopted; this is the case with non-empty AAD, exactly the RIST
// shape). It uses a 12-byte IV, so it drives sealGCM/openGCM directly. The tag
// is asserted as the Hash-field value (RIST carries the GCM tag in the Hash
// field, not appended to the ciphertext); the ciphertext is tag-free.
func TestAESGCMKAT(t *testing.T) {
	key := mustHex(t, "feffe9928665731c6d6a8f9467308308")
	iv := mustHex(t, "cafebabefacedbaddecaf888")
	pt := mustHex(t, "d9313225f88406e5a55909c5aff5269a"+
		"86a7a9531534f7da2e4c303d8a318a72"+
		"1c3c0c95956809532fcf0e2449a6b525"+
		"b16aedf5aa0de657ba637b39")
	aad := mustHex(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
	wantCT := mustHex(t, "42831ec2217774244b7221b784d0d49c"+
		"e3aa212f2c02a4e035c17e2329aca12e"+
		"21d514b25466931c7d8f6a5aac84aa05"+
		"1ba30b396a0aac973d58e091")
	wantTag := mustHex(t, "5bc94fbc3221a5db94fae95ae7121a47")

	var nonce [aeadNonceSize]byte
	copy(nonce[:], iv)

	ct, hash, err := sealGCM(key, nonce, aad, pt)
	if err != nil {
		t.Fatalf("sealGCM: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("NIST GCM TC4 ciphertext mismatch:\n got  %x\n want %x", ct, wantCT)
	}
	if !bytes.Equal(hash[:], wantTag) {
		t.Fatalf("NIST GCM TC4 tag mismatch:\n got  %x\n want %x", hash[:], wantTag)
	}

	// And the open direction recovers the plaintext from (ct, tag-in-hash).
	got, err := openGCM(key, nonce, aad, ct, hash)
	if err != nil {
		t.Fatalf("openGCM: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("openGCM round-trip mismatch:\n got  %x\n want %x", got, pt)
	}
}

// TestChaCha20Poly1305KAT anchors the ChaCha20-Poly1305 primitive
// (sealChaCha/openChaCha) against RFC 8439 §2.8.2's worked example.
//
// Source: RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols) §2.8.2:
//
//	key   = 808182...9f (32 bytes)
//	nonce = 070000004041424344454647 (12 bytes)
//	aad   = 50515253c0c1c2c3c4c5c6c7
//	pt    = "Ladies and Gentlemen of the class of '99: ..."
//	tag   = 1ae10b594f09e26a7e902ecbd0600691
//
// The tag is asserted as the Hash-field value; the ciphertext is tag-free.
func TestChaCha20Poly1305KAT(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f"+
		"909192939495969798999a9b9c9d9e9f")
	nonceBytes := mustHex(t, "070000004041424344454647")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: " +
		"If I could offer you only one tip for the future, " +
		"sunscreen would be it.")
	wantCT := mustHex(t, "d31a8d34648e60db7b86afbc53ef7ec2"+
		"a4aded51296e08fea9e2b5a736ee62d6"+
		"3dbea45e8ca9671282fafb69da92728b"+
		"1a71de0a9e060b2905d6a5b67ecd3b36"+
		"92ddbd7f2d778b8c9803aee328091b58"+
		"fab324e4fad675945585808b4831d7bc"+
		"3ff4def08e4b7a9de576d26586cec64b"+
		"6116")
	wantTag := mustHex(t, "1ae10b594f09e26a7e902ecbd0600691")

	var nonce [aeadNonceSize]byte
	copy(nonce[:], nonceBytes)

	ct, hash, err := sealChaCha(key, nonce, aad, pt)
	if err != nil {
		t.Fatalf("sealChaCha: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("RFC 8439 §2.8.2 ciphertext mismatch:\n got  %x\n want %x", ct, wantCT)
	}
	if !bytes.Equal(hash[:], wantTag) {
		t.Fatalf("RFC 8439 §2.8.2 tag mismatch:\n got  %x\n want %x", hash[:], wantTag)
	}

	got, err := openChaCha(key, nonce, aad, ct, hash)
	if err != nil {
		t.Fatalf("openChaCha: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("openChaCha round-trip mismatch:\n got  %x\n want %x", got, pt)
	}
}

// TestAESCTRHMACGolden freezes the AES-CTR-HMAC mode (mode 3) output for a fixed
// (key, IV field, aad, plaintext) so a regression in either the AES-CTR
// keystream or the encrypt-then-MAC HMAC is caught byte-for-byte.
//
// The golden values were cross-checked with an independent stdlib program
// (crypto/cipher.NewCTR over crypto/aes + crypto/hmac with crypto/sha256,
// /tmp/golden.go during development): AES-128-CTR with the 16-byte IV =
// [iv4 big-endian | 12 zeros] over the plaintext, then HMAC-SHA256(aad ||
// ciphertext) truncated to 16 bytes. The test additionally re-derives the HMAC
// here so the assertion is anchored to the standard primitive, not just to a
// literal.
func TestAESCTRHMACGolden(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	iv4 := uint32(0x00000001)
	aad := []byte("rist-adv-aad-header")
	pt := []byte("Advanced Profile AES-CTR-HMAC golden plaintext!!")

	wantCT := mustHex(t, "d46795c34a394e801cc80682987281fb"+
		"de5bd7beabb25238d431051d917aff28"+
		"0fe59892ba9fc38b539128bdafdfcead")
	wantHash := mustHex(t, "2b4c358f0f14d0878731d04fd884980d")

	gotCT, cerr := ctrXOR(key, BuildIV(iv4), pt)
	if cerr != nil {
		t.Fatalf("ctrXOR: %v", cerr)
	}
	if !bytes.Equal(gotCT, wantCT) {
		t.Fatalf("AES-CTR-HMAC ciphertext mismatch:\n got  %x\n want %x", gotCT, wantCT)
	}

	gotHash := hmacTag(key, aad, gotCT)
	if !bytes.Equal(gotHash[:], wantHash) {
		t.Fatalf("AES-CTR-HMAC HMAC mismatch:\n got  %x\n want %x", gotHash[:], wantHash)
	}

	// Anchor the HMAC to the standard primitive independently of the literal.
	mac := hmac.New(sha256.New, key)
	mac.Write(aad)
	mac.Write(gotCT)
	full := mac.Sum(nil)
	if !bytes.Equal(gotHash[:], full[:HashSize]) {
		t.Fatalf("hmacTag != HMAC-SHA256(aad||ct)[:16]:\n got  %x\n want %x", gotHash[:], full[:HashSize])
	}
	// ciphertext must be tag-free for mode 3 (HMAC lives in the Hash field).
	if len(gotCT) != len(pt) {
		t.Fatalf("mode 3 ciphertext should be tag-free: len %d != pt %d", len(gotCT), len(pt))
	}
}

// TestSealOpenRoundTripAllModes runs SealAdvanced -> OpenAdvanced for each of
// the three authenticated modes, deriving the key from a passphrase + nonce
// exactly as the wire path will. It verifies the recovered plaintext matches and
// (for modes 4/5) that the wire ciphertext is tag-free (the tag rides the Hash
// field, not the ciphertext).
func TestSealOpenRoundTripAllModes(t *testing.T) {
	password := []byte("ristgo-advanced-passphrase")
	nonce4 := [NonceSize]byte{0x12, 0x34, 0x56, 0x78}
	iv4 := uint32(0xDEADBEEF)
	aad := []byte("cleartext header bytes with hash zeroed")
	pt := []byte("the quick brown fox jumps over the lazy dog, twice over")

	cases := []struct {
		name    string
		mode    PSKMode
		keyBits int
	}{
		{"AES-CTR-HMAC/128", PSKModeAESCTRHMAC, KeySize128},
		{"AES-CTR-HMAC/256", PSKModeAESCTRHMAC, KeySize256},
		{"AES-GCM/128", PSKModeAESGCM, KeySize128},
		{"AES-GCM/256", PSKModeAESGCM, KeySize256},
		{"ChaCha20-Poly1305/256", PSKModeChaCha20Poly1305, KeySize256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, hash, err := SealAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, aad, pt)
			if err != nil {
				t.Fatalf("SealAdvanced: %v", err)
			}
			if len(ct) != len(pt) {
				t.Fatalf("wire ciphertext should be tag-free: len %d != pt %d", len(ct), len(pt))
			}
			if bytes.Equal(ct, pt) {
				t.Fatal("ciphertext equals plaintext")
			}
			// A zero hash would mean no authentication value was produced.
			var zero [HashSize]byte
			if hash == zero {
				t.Fatal("hash field is all zero")
			}
			got, err := OpenAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, aad, ct, hash)
			if err != nil {
				t.Fatalf("OpenAdvanced: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("round-trip mismatch:\n got  %x\n want %x", got, pt)
			}
		})
	}
}

// TestSealOpenEmptyPlaintext verifies the modes handle a zero-length payload
// (still authenticated over the AAD) without panicking and round-trip cleanly.
func TestSealOpenEmptyPlaintext(t *testing.T) {
	password := []byte("pw")
	nonce4 := [NonceSize]byte{1, 2, 3, 4}
	aad := []byte("header")
	for _, mode := range []PSKMode{PSKModeAESCTRHMAC, PSKModeAESGCM, PSKModeChaCha20Poly1305} {
		keyBits := KeySize256
		ct, hash, err := SealAdvanced(mode, password, keyBits, nonce4, 7, aad, nil)
		if err != nil {
			t.Fatalf("mode %d SealAdvanced(empty): %v", mode, err)
		}
		if len(ct) != 0 {
			t.Fatalf("mode %d empty plaintext gave %d ciphertext bytes", mode, len(ct))
		}
		got, err := OpenAdvanced(mode, password, keyBits, nonce4, 7, aad, ct, hash)
		if err != nil {
			t.Fatalf("mode %d OpenAdvanced(empty): %v", mode, err)
		}
		if len(got) != 0 {
			t.Fatalf("mode %d recovered %d bytes from empty plaintext", mode, len(got))
		}
	}
}

// errIs is a small helper that fails unless err matches target via errors.Is.
func errIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
}

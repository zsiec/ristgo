package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// allModes is the set of authenticated Advanced PSK modes this file exercises.
var allModes = []struct {
	name    string
	mode    PSKMode
	keyBits int
}{
	{"AES-CTR-HMAC", PSKModeAESCTRHMAC, KeySize256},
	{"AES-GCM", PSKModeAESGCM, KeySize256},
	{"ChaCha20-Poly1305", PSKModeChaCha20Poly1305, KeySize256},
}

// TestOpenAdvancedTamperDetected flips one byte of the ciphertext, the AAD, and
// the hash in turn; each must make OpenAdvanced fail with ErrAuthFailed and
// return a nil plaintext (no plaintext leaked on a failed authentication —
// TR-06-3 §8.1 authenticate-before-use).
func TestOpenAdvancedTamperDetected(t *testing.T) {
	password := []byte("tamper-pw")
	nonce4 := [NonceSize]byte{9, 8, 7, 6}
	iv4 := uint32(0x01020304)
	aad := []byte("authenticated header region")
	pt := []byte("secret payload that must never leak on a bad tag")

	for _, tc := range allModes {
		t.Run(tc.name, func(t *testing.T) {
			ct, hash, err := SealAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, aad, pt)
			if err != nil {
				t.Fatalf("SealAdvanced: %v", err)
			}

			// 1) tamper the ciphertext.
			badCT := append([]byte(nil), ct...)
			badCT[0] ^= 0x01
			got, err := OpenAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, aad, badCT, hash)
			errIs(t, err, ErrAuthFailed)
			if got != nil {
				t.Fatalf("plaintext leaked on tampered ciphertext: %x", got)
			}

			// 2) tamper the AAD.
			badAAD := append([]byte(nil), aad...)
			badAAD[len(badAAD)-1] ^= 0x80
			got, err = OpenAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, badAAD, ct, hash)
			errIs(t, err, ErrAuthFailed)
			if got != nil {
				t.Fatalf("plaintext leaked on tampered aad: %x", got)
			}

			// 3) tamper the hash (tag).
			badHash := hash
			badHash[15] ^= 0x01
			got, err = OpenAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, aad, ct, badHash)
			errIs(t, err, ErrAuthFailed)
			if got != nil {
				t.Fatalf("plaintext leaked on tampered hash: %x", got)
			}

			// Sanity: the untampered triple still opens.
			ok, err := OpenAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, aad, ct, hash)
			if err != nil {
				t.Fatalf("untampered OpenAdvanced failed: %v", err)
			}
			if !bytes.Equal(ok, pt) {
				t.Fatalf("untampered round-trip mismatch:\n got  %x\n want %x", ok, pt)
			}
		})
	}
}

// TestOpenAdvancedWrongKey verifies a wrong passphrase, a wrong PSK nonce (which
// re-salts the derived key), and a wrong IV (which changes the AEAD nonce / CTR
// keystream) each fail authentication without leaking plaintext.
func TestOpenAdvancedWrongKey(t *testing.T) {
	password := []byte("right-pw")
	nonce4 := [NonceSize]byte{0x11, 0x22, 0x33, 0x44}
	iv4 := uint32(0xAABBCCDD)
	aad := []byte("hdr")
	pt := []byte("twelve bytes plus some more to encrypt")

	for _, tc := range allModes {
		t.Run(tc.name, func(t *testing.T) {
			ct, hash, err := SealAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4, aad, pt)
			if err != nil {
				t.Fatalf("SealAdvanced: %v", err)
			}

			// Wrong passphrase.
			got, err := OpenAdvanced(tc.mode, []byte("wrong-pw"), tc.keyBits, nonce4, iv4, aad, ct, hash)
			errIs(t, err, ErrAuthFailed)
			if got != nil {
				t.Fatalf("plaintext leaked with wrong passphrase: %x", got)
			}

			// Wrong PSK nonce (re-derives a different key).
			wrongNonce := nonce4
			wrongNonce[0] ^= 0x01
			got, err = OpenAdvanced(tc.mode, password, tc.keyBits, wrongNonce, iv4, aad, ct, hash)
			errIs(t, err, ErrAuthFailed)
			if got != nil {
				t.Fatalf("plaintext leaked with wrong nonce: %x", got)
			}

			// Wrong IV. For GCM/ChaCha the 12-byte nonce is bound into the tag,
			// so a wrong IV fails authentication. For AES-CTR-HMAC (mode 3) the
			// IV is NOT inside the authenticated region as scoped here: the HMAC
			// covers aad || ciphertext only, so changing only the iv4 argument is
			// undetected and decrypts to garbage. That is correct and intended:
			// the IV field lives in the cleartext header, and the session codec
			// (WP7c) MUST include those header bytes in the aad it supplies, which
			// is how the IV gets authenticated end-to-end. This test passes the IV
			// as a separate argument (not in aad) to isolate the primitive, so for
			// mode 3 it asserts the documented "IV not self-authenticated" property
			// rather than ErrAuthFailed. See the package interop note,
			// interpretation 2.
			got, err = OpenAdvanced(tc.mode, password, tc.keyBits, nonce4, iv4+1, aad, ct, hash)
			if tc.mode == PSKModeAESCTRHMAC {
				if err != nil {
					t.Fatalf("mode 3 wrong-IV: unexpected error %v (IV is not in the HMAC scope here)", err)
				}
				if bytes.Equal(got, pt) {
					t.Fatal("mode 3 wrong-IV decrypted to the original plaintext (keystream did not change)")
				}
			} else {
				errIs(t, err, ErrAuthFailed)
				if got != nil {
					t.Fatalf("plaintext leaked with wrong IV: %x", got)
				}
			}
		})
	}
}

// TestZeroNonceRejected verifies that a zero PSK nonce is refused by both
// SealAdvanced and OpenAdvanced (reusing the Main-path ErrZeroNonce rule:
// a zero nonce never comes from a legitimate sender).
func TestZeroNonceRejected(t *testing.T) {
	var zero [NonceSize]byte
	for _, tc := range allModes {
		_, _, err := SealAdvanced(tc.mode, []byte("pw"), tc.keyBits, zero, 1, []byte("a"), []byte("b"))
		errIs(t, err, ErrZeroNonce)

		_, err = OpenAdvanced(tc.mode, []byte("pw"), tc.keyBits, zero, 1, []byte("a"), []byte("b"), [HashSize]byte{})
		errIs(t, err, ErrZeroNonce)
	}
}

// TestUnknownPSKMode verifies a mode outside {3,4,5} is rejected with
// ErrUnknownPSKMode (mode 1 plain AES-CTR is the Main path, not this file).
func TestUnknownPSKMode(t *testing.T) {
	nonce4 := [NonceSize]byte{1, 1, 1, 1}
	for _, m := range []PSKMode{0, 1, 2, 6, 7, 99} {
		_, _, err := SealAdvanced(m, []byte("pw"), KeySize256, nonce4, 1, nil, []byte("x"))
		errIs(t, err, ErrUnknownPSKMode)
		_, err = OpenAdvanced(m, []byte("pw"), KeySize256, nonce4, 1, nil, []byte("x"), [HashSize]byte{})
		errIs(t, err, ErrUnknownPSKMode)
	}
}

// TestChaChaRequires256 verifies ChaCha20-Poly1305 with a 128-bit key request is
// rejected with ErrChaChaKeySize (ChaCha20-Poly1305 has only a 256-bit variant).
func TestChaChaRequires256(t *testing.T) {
	nonce4 := [NonceSize]byte{1, 2, 3, 4}
	_, _, err := SealAdvanced(PSKModeChaCha20Poly1305, []byte("pw"), KeySize128, nonce4, 1, nil, []byte("x"))
	errIs(t, err, ErrChaChaKeySize)
	_, err = OpenAdvanced(PSKModeChaCha20Poly1305, []byte("pw"), KeySize128, nonce4, 1, nil, []byte("x"), [HashSize]byte{})
	errIs(t, err, ErrChaChaKeySize)
}

// TestInterpretedAEADNonce documents and ASSERTS the interpreted 12-byte AEAD
// nonce construction (interop-unvalidated; pending a reference or the full
// TR-06-3 §5.2.5 detail): nonce = [IV field (4 B, big-endian) | 8 zero bytes],
// mirroring crypto.BuildIV's 16-byte AES-CTR IV truncated to 12 bytes. If the
// construction is ever changed, this guard must change with it — by design, so
// the interpretation cannot drift silently.
func TestInterpretedAEADNonce(t *testing.T) {
	for _, iv4 := range []uint32{0, 1, 0x01020304, 0xFFFFFFFF} {
		got := aeadNonce(iv4)
		var want [aeadNonceSize]byte
		binary.BigEndian.PutUint32(want[0:4], iv4)
		// bytes [4:12] are zero by construction.
		if got != want {
			t.Fatalf("aeadNonce(%#x) = %x, want %x (IV-field|8 zeros)", iv4, got, want)
		}
		// The first 12 bytes of BuildIV must equal the AEAD nonce: same layout,
		// one truncated from the other.
		full := BuildIV(iv4)
		if !bytes.Equal(got[:], full[:aeadNonceSize]) {
			t.Fatalf("aeadNonce(%#x) != BuildIV[:12]:\n got  %x\n want %x", iv4, got[:], full[:aeadNonceSize])
		}
	}
}

// TestInterpretedHMACKeyAndScope documents and asserts the interpreted mode-3
// constructions: the HMAC key IS the PBKDF2-derived AES key, and the HMAC input
// is encrypt-then-MAC over aad || ciphertext. We rebuild the expected Hash from
// the public DeriveKey + the package's own ctrXOR/hmacTag and require it to
// equal SealAdvanced's hash, so the interpretation is pinned.
func TestInterpretedHMACKeyAndScope(t *testing.T) {
	password := []byte("interpreted-pw")
	nonce4 := [NonceSize]byte{0xA1, 0xB2, 0xC3, 0xD4}
	iv4 := uint32(0x0000002A)
	aad := []byte("header-with-hash-zeroed")
	pt := []byte("payload bytes for the encrypt-then-MAC check")

	ct, hash, err := SealAdvanced(PSKModeAESCTRHMAC, password, KeySize256, nonce4, iv4, aad, pt)
	if err != nil {
		t.Fatalf("SealAdvanced: %v", err)
	}

	// Independently reconstruct using the public DeriveKey, then assert the
	// derived key is the HMAC key and aad||ct is the HMAC input.
	key, err := DeriveKey(password, nonce4[:], KeySize256)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	wantCT, cerr := ctrXOR(key, BuildIV(iv4), pt)
	if cerr != nil {
		t.Fatalf("ctrXOR: %v", cerr)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("ciphertext != AES-CTR(derived key):\n got  %x\n want %x", ct, wantCT)
	}

	// ctrXOR returns an error (never a zero keystream) for a non-AES key length.
	if _, e := ctrXOR(make([]byte, 7), BuildIV(1), []byte("x")); !errors.Is(e, ErrInvalidKeySize) {
		t.Fatalf("ctrXOR with a 7-byte key: err = %v, want ErrInvalidKeySize", e)
	}
	wantHash := hmacTag(key, aad, wantCT)
	if wantHash != hash {
		t.Fatalf("hash != HMAC(derivedKey, aad||ct)[:16]:\n got  %x\n want %x", hash, wantHash)
	}
}

// TestModeIsolation verifies a ciphertext+hash sealed under one mode does not
// open under a different mode (the mode is not carried in the ciphertext; the
// codec selects it, and a mismatch must fail authentication, not silently
// decrypt). It exercises every ordered pair of distinct modes at a shared key
// size where both are legal.
func TestModeIsolation(t *testing.T) {
	password := []byte("isolation-pw")
	nonce4 := [NonceSize]byte{5, 6, 7, 8}
	iv4 := uint32(0x11111111)
	aad := []byte("hdr")
	pt := []byte("mode isolation payload bytes here")

	modes := []PSKMode{PSKModeAESCTRHMAC, PSKModeAESGCM, PSKModeChaCha20Poly1305}
	for _, sealMode := range modes {
		ct, hash, err := SealAdvanced(sealMode, password, KeySize256, nonce4, iv4, aad, pt)
		if err != nil {
			t.Fatalf("SealAdvanced(%d): %v", sealMode, err)
		}
		for _, openMode := range modes {
			if openMode == sealMode {
				continue
			}
			got, err := OpenAdvanced(openMode, password, KeySize256, nonce4, iv4, aad, ct, hash)
			if err == nil {
				t.Fatalf("seal mode %d opened under mode %d (cross-mode leak): %x", sealMode, openMode, got)
			}
			if got != nil {
				t.Fatalf("seal mode %d, open mode %d leaked plaintext: %x", sealMode, openMode, got)
			}
		}
	}
}

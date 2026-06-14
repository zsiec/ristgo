package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"testing"
)

// TestCTRMatchesStdlib makes the package's doc claims literally true: the
// hand-rolled 0-alloc ctrState.crypt keystream must be byte-identical to
// crypto/cipher.NewCTR for the RIST IV layout (seq big-endian in IV[0:4], zeros
// below), across payload sizes that straddle the 16-byte AES block boundary and
// sequence numbers up to the 32-bit wrap.
func TestCTRMatchesStdlib(t *testing.T) {
	key, err := DeriveKey([]byte("ristgo-test-passphrase"), []byte{0x12, 0x34, 0x56, 0x78}, KeySize256)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	for _, n := range []int{0, 1, 15, 16, 17, 31, 48, 1316} {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(i*7 + 3)
		}
		for _, seq := range []uint32{0, 1, 0x0A0B0C0D, 0xFFFFFFFF} {
			iv := BuildIV(seq)
			want := make([]byte, n)
			cipher.NewCTR(block, iv[:]).XORKeyStream(want, src)

			s := ctrState{block: block}
			got := s.crypt(iv, nil, src)
			if !bytes.Equal(got, want) {
				t.Fatalf("ctrState.crypt != cipher.NewCTR for n=%d seq=%#x:\n got %x\nwant %x", n, seq, got, want)
			}
		}
	}
}

// TestDecryptorSetKeyBits verifies the GRE-H-bit hardening: a Decryptor
// constructed with the "wrong" key size adapts to the sender's actual size via
// SetKeyBits and decrypts correctly, and a no-op SetKeyBits leaves the warm path
// intact.
func TestDecryptorSetKeyBits(t *testing.T) {
	const pw = "ristgo-mixed-keysize"
	k, err := NewKey([]byte(pw), KeySize256, 0, false)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	ct, err := k.Encrypt(7, nil, []byte("hello world"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// A decryptor initialized at 128 must adapt to the 256-bit ciphertext.
	d, err := NewDecryptor([]byte(pw), KeySize128)
	if err != nil {
		t.Fatalf("NewDecryptor: %v", err)
	}
	d.SetKeyBits(KeySize256)
	pt, err := d.Decrypt(k.Nonce(), 7, nil, ct)
	if err != nil || string(pt) != "hello world" {
		t.Fatalf("after SetKeyBits(256): pt=%q err=%v", pt, err)
	}
	// A redundant SetKeyBits at the same size must not disturb the keyed state.
	d.SetKeyBits(KeySize256)
	if pt2, err := d.Decrypt(k.Nonce(), 8, nil, ct); err != nil || len(pt2) != len(ct) {
		t.Fatalf("no-op SetKeyBits broke decryption: err=%v", err)
	}
}

// TestDeriveKeyPasswordBounding pins ristgo's PBKDF2 passphrase to libRIST's
// effective bound: the bytes up to the first NUL, capped at 127. A passphrase
// longer than 127 bytes must derive identically to its 127-byte prefix, and a
// passphrase with an embedded NUL must derive identically to its pre-NUL prefix
// — otherwise PSK interop would silently key-mismatch.
func TestDeriveKeyPasswordBounding(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03, 0x04}

	long := bytes.Repeat([]byte("A"), 200)
	full, err := DeriveKey(long, nonce, KeySize256)
	if err != nil {
		t.Fatalf("DeriveKey(200B): %v", err)
	}
	capped, err := DeriveKey(long[:maxPasswordLen], nonce, KeySize256)
	if err != nil {
		t.Fatalf("DeriveKey(127B): %v", err)
	}
	if !bytes.Equal(full, capped) {
		t.Fatal("passphrase >127 bytes must derive the same key as its 127-byte prefix")
	}

	withNUL, err := DeriveKey([]byte("abc\x00def"), nonce, KeySize256)
	if err != nil {
		t.Fatalf("DeriveKey(NUL): %v", err)
	}
	preNUL, err := DeriveKey([]byte("abc"), nonce, KeySize256)
	if err != nil {
		t.Fatalf("DeriveKey(pre-NUL): %v", err)
	}
	if !bytes.Equal(withNUL, preNUL) {
		t.Fatal("passphrase with an embedded NUL must derive the same key as its pre-NUL prefix")
	}
}

// TestDeriveKeyRawNoTruncation asserts DeriveKeyRaw hashes the FULL passphrase
// bytes — no NUL-truncation, no 127-byte cap — unlike DeriveKey. This is the
// derivation libRIST uses when the passphrase is installed via
// _librist_crypto_psk_set_passphrase (the EAP-SRP use_key_as_passphrase path),
// which stores an explicit password_len and hashes all of it. The 32-byte SRP
// session key K may contain a NUL byte, so this faithfulness is load-bearing for
// interop.
func TestDeriveKeyRawNoTruncation(t *testing.T) {
	nonce := []byte{0x12, 0x34, 0x56, 0x78}

	// A passphrase with an embedded NUL must NOT be truncated by DeriveKeyRaw.
	withNUL := []byte("abc\x00def")
	raw, err := DeriveKeyRaw(withNUL, nonce, KeySize256)
	if err != nil {
		t.Fatalf("DeriveKeyRaw(NUL): %v", err)
	}
	preNUL, _ := DeriveKeyRaw([]byte("abc"), nonce, KeySize256)
	if bytes.Equal(raw, preNUL) {
		t.Fatal("DeriveKeyRaw must NOT truncate at a NUL byte")
	}
	// And it must differ from the truncating DeriveKey on the same input.
	trunc, _ := DeriveKey(withNUL, nonce, KeySize256)
	if bytes.Equal(raw, trunc) {
		t.Fatal("DeriveKeyRaw and DeriveKey must differ for a passphrase with a NUL")
	}

	// DeriveKeyRaw is standard PBKDF2-HMAC-SHA256 over the full bytes; cross-check
	// against the stdlib directly so it is anchored independent of our code path.
	want, err := pbkdf2.Key(sha256.New, string(withNUL), nonce, pbkdf2Iterations, KeySize256/8)
	if err != nil {
		t.Fatalf("stdlib pbkdf2: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("DeriveKeyRaw != stdlib PBKDF2\n got  %x\n want %x", raw, want)
	}

	// A >127-byte passphrase must hash in full (no cap), unlike DeriveKey.
	long := bytes.Repeat([]byte("A"), 200)
	rawLong, _ := DeriveKeyRaw(long, nonce, KeySize256)
	cappedLong, _ := DeriveKeyRaw(long[:maxPasswordLen], nonce, KeySize256)
	if bytes.Equal(rawLong, cappedLong) {
		t.Fatal("DeriveKeyRaw must NOT cap the passphrase at 127 bytes")
	}
}

// TestAESCTRRaw round-trips AES-CTR with an explicit 16-byte IV and checks it
// matches crypto/cipher's NewCTR for the same key/IV — the primitive used to
// protect an explicit EAP-SRP passphrase under the SRP session key K (IV = 15
// zero bytes then the EAP identifier). It also rejects a wrong-length key.
func TestAESCTRRaw(t *testing.T) {
	for _, bits := range []int{KeySize128, KeySize256} {
		key := make([]byte, bits/8)
		for i := range key {
			key[i] = byte(i*7 + 1)
		}
		var iv [16]byte
		iv[15] = 0x42 // the EAP-identifier IV
		plain := []byte("the SRP session key keys this passphrase")

		ct, err := AESCTRRaw(key, iv, nil, plain)
		if err != nil {
			t.Fatalf("AESCTRRaw encrypt (%d): %v", bits, err)
		}
		// CTR is symmetric: decrypting the ciphertext recovers the plaintext.
		pt, err := AESCTRRaw(key, iv, nil, ct)
		if err != nil {
			t.Fatalf("AESCTRRaw decrypt (%d): %v", bits, err)
		}
		if !bytes.Equal(pt, plain) {
			t.Fatalf("AESCTRRaw round-trip mismatch (%d)", bits)
		}

		// Match crypto/cipher.NewCTR for the same key and IV.
		block, _ := aes.NewCipher(key)
		want := make([]byte, len(plain))
		cipher.NewCTR(block, iv[:]).XORKeyStream(want, plain)
		if !bytes.Equal(ct, want) {
			t.Fatalf("AESCTRRaw != crypto/cipher.NewCTR (%d)\n got  %x\n want %x", bits, ct, want)
		}
	}

	// A wrong-length key is rejected, never run.
	if _, err := AESCTRRaw(make([]byte, 24), [16]byte{}, nil, []byte("x")); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("AESCTRRaw(24-byte key) = %v, want ErrInvalidKeySize", err)
	}
}

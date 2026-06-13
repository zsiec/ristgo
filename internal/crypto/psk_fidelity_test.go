package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// TestDeriveKeyPasswordBounding pins ristgo's PBKDF2 passphrase to libRIST's
// effective bound: the bytes up to the first NUL, capped at 127 (psk.c:38,327;
// psk.h:48). A passphrase longer than 127 bytes must derive identically to its
// 127-byte prefix, and a passphrase with an embedded NUL must derive identically
// to its pre-NUL prefix — otherwise PSK interop would silently key-mismatch.
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

package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// TestEncryptInPlace verifies AES-CTR over a dst that aliases src (dst==src),
// which cipher.Stream.XORKeyStream permits, leaves a correct ciphertext and
// round-trips. We encrypt in place, then decrypt in place back to plaintext.
func TestEncryptInPlace(t *testing.T) {
	password := []byte("inplace")
	nonce := [NonceSize]byte{0x09, 0x08, 0x07, 0x06}
	seq := uint32(0x55667788)
	orig := seqBytes(200)

	buf := append([]byte(nil), orig...)
	// In-place: dst is the full-length buf, src is the same slice.
	ct, err := Decrypt(password, KeySize128, nonce, seq, buf[:0], buf)
	if err != nil {
		t.Fatal(err)
	}
	if &ct[0] != &buf[0] {
		t.Fatal("in-place encrypt reallocated unexpectedly")
	}
	if bytes.Equal(ct, orig) {
		t.Fatal("ciphertext equals plaintext")
	}
	// Decrypt in place back.
	pt, err := Decrypt(password, KeySize128, nonce, seq, ct[:0], ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, orig) {
		t.Fatalf("in-place round-trip mismatch:\n got  %x\n want %x", pt, orig)
	}
}

// TestAppendIntoNonEmptyDst verifies the append-style contract: output is
// appended after existing bytes in dst, leaving the prefix intact.
func TestAppendIntoNonEmptyDst(t *testing.T) {
	password := []byte("append")
	nonce := [NonceSize]byte{0x01, 0x00, 0x00, 0x02}
	prefix := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	pt := seqBytes(32)

	dst := append([]byte(nil), prefix...)
	out, err := Decrypt(password, KeySize256, nonce, 7, dst, pt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[:len(prefix)], prefix) {
		t.Fatalf("prefix clobbered: %x", out[:len(prefix)])
	}
	if len(out) != len(prefix)+len(pt) {
		t.Fatalf("output length = %d, want %d", len(out), len(prefix)+len(pt))
	}
	// The appended portion must decrypt back to pt.
	back, err := Decrypt(password, KeySize256, nonce, 7, nil, out[len(prefix):])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("appended ciphertext did not round-trip:\n got  %x\n want %x", back, pt)
	}
}

// TestEmptyPayload verifies a zero-length payload encrypts/decrypts to empty
// without error (CTR over zero bytes is a no-op).
func TestEmptyPayload(t *testing.T) {
	k, err := NewKey([]byte("empty"), KeySize128, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	out, err := k.Encrypt(1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("empty encrypt produced %d bytes", len(out))
	}

	d, err := NewDecryptor([]byte("empty"), KeySize128)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.Decrypt(k.Nonce(), 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("empty decrypt produced %d bytes", len(got))
	}
}

// TestSeqDiffersKeystream asserts that two packets under the same key but
// different sequence numbers get different keystreams (the IV's high bytes
// differ), so identical plaintext yields different ciphertext.
func TestSeqDiffersKeystream(t *testing.T) {
	password := []byte("seqdiff")
	nonce := [NonceSize]byte{0x10, 0x20, 0x30, 0x40}
	pt := seqBytes(64)
	c1, err := Decrypt(password, KeySize128, nonce, 1, nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Decrypt(password, KeySize128, nonce, 2, nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("identical ciphertext for different sequence numbers")
	}
}

// TestBuildIVDoesNotMutateAcrossCalls guards against any shared backing
// between successive IVs; each call returns an independent array.
func TestBuildIVIndependent(t *testing.T) {
	a := BuildIV(0x11223344)
	b := BuildIV(0x55667788)
	if a == b {
		t.Fatal("distinct seqs produced equal IVs")
	}
	// Mutating one must not touch the other (value semantics).
	a[0] = 0xFF
	if b[0] == 0xFF {
		t.Fatal("BuildIV results alias each other")
	}
}

// TestDecryptInvalidKeySize asserts the one-shot Decrypt and NewDecryptor
// reject a bad key size.
func TestDecryptInvalidKeySize(t *testing.T) {
	nonce := [NonceSize]byte{1, 2, 3, 4}
	if _, err := Decrypt([]byte("p"), 100, nonce, 1, nil, []byte("x")); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("Decrypt bad key size err = %v", err)
	}
	if _, err := NewDecryptor([]byte("p"), 100); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("NewDecryptor bad key size err = %v", err)
	}
	if _, err := NewDecryptor(nil, KeySize128); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("NewDecryptor empty password err = %v", err)
	}
}

// TestKeyNonceStableUntilRotate confirms Nonce() is stable across many
// encrypts when rotation is not due, and that usedTimes increments per packet.
func TestKeyUsedTimesIncrement(t *testing.T) {
	k, err := NewKey([]byte("count"), KeySize128, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if k.usedTimes != 0 {
		t.Fatalf("fresh key usedTimes = %d, want 0", k.usedTimes)
	}
	for i := 0; i < 10; i++ {
		if _, err := k.Encrypt(uint32(i), nil, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if k.usedTimes != 10 {
		t.Fatalf("usedTimes = %d after 10 encrypts, want 10", k.usedTimes)
	}
}

// TestRotateDueAtReuseLimit drives usedTimes to the reuse limit and confirms
// the next encrypt rotates (covers the exhaustion branch without a 4-billion
// iteration loop by setting the counter directly, which is package-internal).
func TestRotateDueAtReuseLimit(t *testing.T) {
	k, err := NewKey([]byte("reuse"), KeySize128, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	first := k.Nonce()
	// One below the limit: not yet due.
	k.usedTimes = reuseLimit - 1
	if k.rotateDue() {
		t.Fatal("rotateDue true one below reuse limit")
	}
	// At the limit: usedTimes+1 would exhaust, so rotate.
	k.usedTimes = reuseLimit
	if !k.rotateDue() {
		t.Fatal("rotateDue false at reuse limit")
	}
	if _, err := k.Encrypt(0, nil, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if k.Nonce() == first {
		t.Fatal("nonce did not rotate at reuse limit")
	}
	if k.usedTimes != 1 {
		t.Fatalf("usedTimes after rotate-then-encrypt = %d, want 1", k.usedTimes)
	}
}

// TestSetBBitIdempotent verifies setBBit clears before optionally setting, so
// repeated application with the same parity is stable and flipping parity
// toggles only bit 7.
func TestSetBBit(t *testing.T) {
	tests := []struct {
		in   byte
		odd  bool
		want byte
	}{
		{0x00, false, 0x00},
		{0x00, true, 0x80},
		{0x80, false, 0x00},
		{0x80, true, 0x80},
		{0x7F, false, 0x7F},
		{0x7F, true, 0xFF},
		{0xFF, false, 0x7F},
		{0xFF, true, 0xFF},
	}
	for _, tt := range tests {
		n := [NonceSize]byte{tt.in, 0xAA, 0xBB, 0xCC}
		setBBit(&n, tt.odd)
		if n[0] != tt.want {
			t.Fatalf("setBBit(%#x, odd=%v) = %#x, want %#x", tt.in, tt.odd, n[0], tt.want)
		}
		// Lower bytes untouched.
		if n[1] != 0xAA || n[2] != 0xBB || n[3] != 0xCC {
			t.Fatalf("setBBit touched lower bytes: %x", n)
		}
	}
}

// TestIsZeroNonce covers the zero predicate including the case where only the
// B-bit would be set (still treated as zero before the bit is applied is not
// reachable here; isZeroNonce tests the raw four bytes).
func TestIsZeroNonce(t *testing.T) {
	if !isZeroNonce([NonceSize]byte{0, 0, 0, 0}) {
		t.Fatal("all-zero not reported zero")
	}
	for i := 0; i < NonceSize; i++ {
		var n [NonceSize]byte
		n[i] = 1
		if isZeroNonce(n) {
			t.Fatalf("nonce with byte %d set reported zero", i)
		}
	}
}

package crypto

import (
	"bytes"
	"testing"
)

// FuzzDecrypt feeds arbitrary nonce/seq/key-size/payload combinations to the
// decrypt path. It must never panic on any input (the no-panic contract for
// decoders, CLAUDE.md). When decryption succeeds, re-encrypting the recovered
// plaintext under the same nonce and seq must reproduce the ciphertext
// (AES-CTR is symmetric), proving round-trip stability.
func FuzzDecrypt(f *testing.F) {
	seeds := []struct {
		password       []byte
		n0, n1, n2, n3 byte
		seq            uint32
		keyBits        uint8
		payload        []byte
	}{
		{[]byte("p"), 0x12, 0x34, 0x56, 0x78, 0x0A0B0C0D, 0, seqBytes(48)},
		{[]byte("secret"), 0, 0, 0, 0, 1, 1, []byte("hello")},
		{nil, 1, 2, 3, 4, 0xFFFFFFFF, 0, nil},
		{[]byte("longerpass"), 0xFF, 0xFF, 0xFF, 0xFF, 0, 2, bytes.Repeat([]byte{0xAB}, 300)},
	}
	for _, s := range seeds {
		f.Add(s.password, s.n0, s.n1, s.n2, s.n3, s.seq, s.keyBits, s.payload)
	}

	f.Fuzz(func(t *testing.T, password []byte, n0, n1, n2, n3 byte, seq uint32, keyBitsSel uint8, payload []byte) {
		// Map the selector to a valid or invalid key size; both must be safe.
		keyBits := KeySize128
		switch keyBitsSel % 3 {
		case 0:
			keyBits = KeySize128
		case 1:
			keyBits = KeySize256
		case 2:
			keyBits = 200 // invalid: must return ErrInvalidKeySize, never panic
		}
		nonce := [NonceSize]byte{n0, n1, n2, n3}

		// One-shot Decrypt must never panic.
		out, err := Decrypt(password, keyBits, nonce, seq, nil, payload)
		if err != nil {
			return
		}
		if len(out) != len(payload) {
			t.Fatalf("Decrypt output length %d != input %d", len(out), len(payload))
		}

		// Round-trip stability: re-applying the symmetric operation to the
		// recovered bytes must reproduce the original ciphertext.
		back, err := Decrypt(password, keyBits, nonce, seq, nil, out)
		if err != nil {
			t.Fatalf("re-Decrypt of successful output errored: %v", err)
		}
		if !bytes.Equal(back, payload) {
			t.Fatalf("AES-CTR not symmetric:\n in   %x\n back %x", payload, back)
		}

		// The stateful Decryptor must agree with the one-shot path and also
		// never panic.
		d, derr := NewDecryptor(password, keyBits)
		if derr != nil {
			return
		}
		dout, derr := d.Decrypt(nonce, seq, nil, payload)
		if derr != nil {
			t.Fatalf("Decryptor errored where one-shot succeeded: %v", derr)
		}
		if !bytes.Equal(dout, out) {
			t.Fatalf("Decryptor disagrees with one-shot:\n %x\n %x", dout, out)
		}
	})
}

// FuzzDeriveKey feeds arbitrary passwords, nonces, and key sizes to DeriveKey.
// It must never panic; on success the derived key has the requested length.
func FuzzDeriveKey(f *testing.F) {
	f.Add([]byte("passwd"), []byte("salt"), uint8(0))
	f.Add([]byte(""), []byte{1, 2, 3, 4}, uint8(1))
	f.Add([]byte("p"), []byte{}, uint8(2))

	f.Fuzz(func(t *testing.T, password, nonce []byte, keyBitsSel uint8) {
		keyBits := []int{KeySize128, KeySize256, 192, 0}[keyBitsSel%4]
		dk, err := DeriveKey(password, nonce, keyBits)
		if err != nil {
			return
		}
		if len(dk) != keyBits/8 {
			t.Fatalf("DeriveKey length %d, want %d", len(dk), keyBits/8)
		}
	})
}

package crypto

import (
	"bytes"
	"testing"
)

// FuzzOpenAdvanced feeds arbitrary mode selectors, passwords, nonces, IVs, AADs,
// ciphertexts, and hashes to OpenAdvanced. It enforces two contracts:
//
//   - No-panic: arbitrary bytes through any of the three authenticated modes
//     must never panic (the decoder no-panic rule, CLAUDE.md).
//   - No leak on a bad tag: OpenAdvanced must return a nil plaintext whenever it
//     returns an error, so a forged/mismatched tag can never expose plaintext.
//
// As a positive control it also seals a fresh value with the same parameters and
// confirms that triple round-trips, so the fuzzer keeps the success path live.
func FuzzOpenAdvanced(f *testing.F) {
	seeds := []struct {
		modeSel        uint8
		password       []byte
		n0, n1, n2, n3 byte
		iv4            uint32
		keyBitsSel     uint8
		aad            []byte
		ciphertext     []byte
		hash           []byte
	}{
		{0, []byte("p"), 1, 2, 3, 4, 0, 1, []byte("aad"), []byte("ct"), bytes.Repeat([]byte{0}, 16)},
		{1, []byte("secret"), 0xFF, 0, 0, 1, 0xDEADBEEF, 0, nil, nil, nil},
		{2, []byte("longerpassphrase"), 0xAA, 0xBB, 0xCC, 0xDD, 7, 1, []byte("h"), bytes.Repeat([]byte{0xAB}, 64), bytes.Repeat([]byte{0xCD}, 16)},
		{3, nil, 0, 0, 0, 0, 0, 2, nil, nil, nil}, // zero nonce + odd selectors
	}
	for _, s := range seeds {
		f.Add(s.modeSel, s.password, s.n0, s.n1, s.n2, s.n3, s.iv4, s.keyBitsSel, s.aad, s.ciphertext, s.hash)
	}

	f.Fuzz(func(t *testing.T, modeSel uint8, password []byte, n0, n1, n2, n3 byte, iv4 uint32, keyBitsSel uint8, aad, ciphertext, hashBytes []byte) {
		mode := []PSKMode{PSKModeAESCTRHMAC, PSKModeAESGCM, PSKModeChaCha20Poly1305}[modeSel%3]
		// Bias toward 256 (legal for all three); occasionally try 128 so the
		// ChaCha key-size rejection path is exercised too.
		keyBits := KeySize256
		if keyBitsSel%2 == 0 {
			keyBits = KeySize128
		}
		nonce4 := [NonceSize]byte{n0, n1, n2, n3}
		var hash [HashSize]byte
		copy(hash[:], hashBytes) // truncates or zero-pads — always 16 bytes

		// Contract 1+2: arbitrary input must never panic, and any error path
		// must return a nil plaintext (no leak on a bad tag).
		pt, err := OpenAdvanced(mode, password, keyBits, nonce4, iv4, aad, ciphertext, hash)
		if err != nil && pt != nil {
			t.Fatalf("OpenAdvanced returned plaintext with error %v: %x", err, pt)
		}

		// Positive control: with a valid password and non-zero nonce, a fresh
		// seal/open round-trips for whatever key size is legal for the mode.
		if len(password) == 0 {
			return
		}
		if mode == PSKModeChaCha20Poly1305 {
			keyBits = KeySize256
		}
		fixedNonce := [NonceSize]byte{1, 2, 3, 4} // guaranteed non-zero
		ct, h, serr := SealAdvanced(mode, password, keyBits, fixedNonce, iv4, aad, ciphertext)
		if serr != nil {
			t.Fatalf("SealAdvanced(valid params) failed: %v", serr)
		}
		got, oerr := OpenAdvanced(mode, password, keyBits, fixedNonce, iv4, aad, ct, h)
		if oerr != nil {
			t.Fatalf("OpenAdvanced of fresh seal failed: %v", oerr)
		}
		if !bytes.Equal(got, ciphertext) {
			t.Fatalf("seal/open round-trip mismatch:\n in   %x\n out  %x", ciphertext, got)
		}
	})
}

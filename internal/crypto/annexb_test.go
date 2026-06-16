package crypto

import (
	"encoding/hex"
	"testing"
)

// TestDeriveKeyAnnexBVector anchors the PSK key derivation to VSF TR-06-2 Annex B's
// own published PBKDF2 example, not just to libRIST and RFC 7914: the passphrase
// "Reliable Internet Stream Transport", the 4-byte nonce/salt 0x52495354 ("RIST"),
// and 1024 PBKDF2-HMAC-SHA256 iterations must derive the spec's documented 128- and
// 256-bit keys. The expected bytes are exactly hashlib.pbkdf2_hmac("sha256",
// b'Reliable Internet Stream Transport', bytes.fromhex('52495354'), 1024, {16,32}).
func TestDeriveKeyAnnexBVector(t *testing.T) {
	const passphrase = "Reliable Internet Stream Transport"
	nonce := []byte{0x52, 0x49, 0x53, 0x54} // "RIST"

	cases := []struct {
		bits int
		want string
	}{
		{KeySize128, "1c2b0cfc90ae2638fea78c7fb2977047"},
		{KeySize256, "1c2b0cfc90ae2638fea78c7fb297704718bff7f4052743001a9b7ebb51cc9f1c"},
	}
	for _, tc := range cases {
		got, err := DeriveKey([]byte(passphrase), nonce, tc.bits)
		if err != nil {
			t.Fatalf("DeriveKey(%d-bit): %v", tc.bits, err)
		}
		if h := hex.EncodeToString(got); h != tc.want {
			t.Errorf("DeriveKey(%d-bit) = %s, want %s (TR-06-2 Annex B)", tc.bits, h, tc.want)
		}
	}
}

package dtls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestPRFKnownAnswer checks the TLS 1.2 P_SHA256 PRF against the canonical IETF
// test vector (the widely-cited "Test vectors for TLS 1.2 PRF", SHA-256), which
// pins the construction byte-for-byte independent of any peer.
func TestPRFKnownAnswer(t *testing.T) {
	secret := mustHex(t, "9bbe436ba940f017b17652849a71db35")
	seed := mustHex(t, "a0ba9f936cda311827a6f796ffd5198c")
	const label = "test label"
	want := mustHex(t, ""+
		"e3f229ba727be17b8d12262055"+
		"7cd453c2aab21d07c3d495329b"+
		"52d4e61edb5a6b301791e90d35"+
		"c9c9a46b4e14baf9af0fa022f7"+
		"077def17abfd3797c0564bab4f"+
		"bc91666e9def9b97fce34f7967"+
		"89baa48082d122ee42c5a72e5a"+
		"5110fff70187347b66")

	got := prf(secret, label, seed, len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("PRF mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestPRFLengthExact verifies the PRF returns exactly the requested length even
// when it is not a multiple of the hash block (32 bytes).
func TestPRFLengthExact(t *testing.T) {
	secret := []byte("secret")
	seed := []byte("seed")
	for _, n := range []int{0, 1, 12, 31, 32, 33, 48, 100} {
		if got := prf(secret, "label", seed, n); len(got) != n {
			t.Errorf("prf length = %d, want %d", len(got), n)
		}
	}
}

// TestMasterSecretLength sanity-checks the derived secrets' fixed sizes.
func TestMasterSecretLength(t *testing.T) {
	pms := make([]byte, 48)
	cr := make([]byte, 32)
	sr := make([]byte, 32)
	if got := masterSecret(pms, cr, sr); len(got) != masterSecretLength {
		t.Errorf("master secret length = %d, want %d", len(got), masterSecretLength)
	}
	if got := extendedMasterSecret(pms, make([]byte, 32)); len(got) != masterSecretLength {
		t.Errorf("extended master secret length = %d, want %d", len(got), masterSecretLength)
	}
	if got := finishedVerifyData(make([]byte, 48), labelClientFinished, make([]byte, 32)); len(got) != finishedVerifyDataLength {
		t.Errorf("verify_data length = %d, want %d", len(got), finishedVerifyDataLength)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

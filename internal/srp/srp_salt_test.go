package srp

import (
	"bytes"
	"testing"
)

// TestSaltLeadingZeroCanonicalized is the regression guard for the interop bug
// where the salt was hashed at its raw wire length instead of being
// canonicalized through a bignum. libRIST holds the salt as a BIGNUM and hashes
// it at MINIMAL length (srp.c:233) in both calc_x and calculate_m, so leading
// zero bytes must not affect x, the verifier, M1, or the session key. The KAT
// salt (72F9..) has no leading zero and cannot catch a regression here; ~1/256
// of random 32-byte salts do.
func TestSaltLeadingZeroCanonicalized(t *testing.T) {
	g := DefaultGroup()
	const user, pass = "rist", "mainprofile"

	withZeros := []byte{0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	stripped := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}

	// The verifier v = g^x depends only on the canonicalized salt, so a salt and
	// its leading-zero-stripped form must yield identical verifiers.
	if !bytes.Equal(MakeVerifier(g, user, pass, withZeros), MakeVerifier(g, user, pass, stripped)) {
		t.Fatal("verifier differs for salts that differ only in leading zeros — salt not canonicalized to bignum-minimal length")
	}

	// A full handshake using the leading-zero salt must complete end to end,
	// proving x/M1/M2/K are all computed over the canonical salt on both sides.
	verifier := MakeVerifier(g, user, pass, withZeros)
	srv, err := NewServer(g, verifier, withZeros)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	cli, err := NewClient(g, withZeros)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := srv.HandleA(cli.A()); err != nil {
		t.Fatalf("HandleA: %v", err)
	}
	if err := cli.ComputeKey(srv.B(), user, pass); err != nil {
		t.Fatalf("ComputeKey: %v", err)
	}
	if !srv.VerifyM1(user, cli.M1()) {
		t.Fatal("VerifyM1 failed with a leading-zero salt")
	}
	if !cli.VerifyM2(srv.M2()) {
		t.Fatal("VerifyM2 failed with a leading-zero salt")
	}
	if !bytes.Equal(cli.SessionKey(), srv.SessionKey()) {
		t.Fatal("session keys differ with a leading-zero salt")
	}
}

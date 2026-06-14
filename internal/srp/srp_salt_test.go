package srp

import (
	"bytes"
	"errors"
	"testing"
)

// TestSaltLengthBounds exercises the salt length bounds enforced by the
// handshake constructors and the provisioning helper: an empty salt is rejected
// with ErrInvalidSalt, a salt longer than MaxSaltLen with ErrSaltTooLong, and a
// salt exactly at the bound is accepted. MakeVerifier returns nil (rather than a
// sentinel) for the rejected cases, matching its error-free contract.
func TestSaltLengthBounds(t *testing.T) {
	g := DefaultGroup()
	const user, pass = "rist", "mainprofile"
	verifier := MakeVerifier(g, user, pass, bytes.Repeat([]byte{0x01}, 32))

	tests := []struct {
		name    string
		salt    []byte
		wantErr error // expected NewClient/NewServer error (nil => accepted)
	}{
		{name: "empty", salt: nil, wantErr: ErrInvalidSalt},
		{name: "one-byte", salt: []byte{0x01}, wantErr: nil},
		{name: "at-bound", salt: bytes.Repeat([]byte{0x01}, MaxSaltLen), wantErr: nil},
		{name: "over-bound", salt: bytes.Repeat([]byte{0x01}, MaxSaltLen+1), wantErr: ErrSaltTooLong},
		{name: "absurdly-long", salt: bytes.Repeat([]byte{0x01}, 64<<10), wantErr: ErrSaltTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cerr := NewClient(g, tt.salt)
			if !errors.Is(cerr, tt.wantErr) {
				t.Fatalf("NewClient: err=%v, want %v", cerr, tt.wantErr)
			}
			_, serr := NewServer(g, verifier, tt.salt)
			if !errors.Is(serr, tt.wantErr) {
				t.Fatalf("NewServer: err=%v, want %v", serr, tt.wantErr)
			}
			// MakeVerifier has no error return: it yields nil for any input the
			// constructors would reject, and a non-nil verifier otherwise.
			v := MakeVerifier(g, user, pass, tt.salt)
			if (v == nil) != (tt.wantErr != nil) {
				t.Fatalf("MakeVerifier(%s) = %v (nil=%t), want nil=%t", tt.name, v != nil, v == nil, tt.wantErr != nil)
			}
		})
	}
}

// TestSaltLeadingZeroCanonicalized is the regression guard for the interop bug
// where the salt was hashed at its raw wire length instead of being
// canonicalized through a bignum. libRIST holds the salt as a BIGNUM and hashes
// it at MINIMAL length in both calc_x and calculate_m, so leading
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

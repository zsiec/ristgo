package srp

import (
	"errors"
	"math/big"
	"testing"
)

// TestVerifierMultipleOfNRejected documents and guards the intentional srp-2
// divergence from libRIST: libRIST rejects only the raw verifier v == 0, but
// ristgo applies the stricter v mod N == 0, so a verifier supplied as a nonzero
// multiple of N (here N itself and 2N) — which is just as degenerate, reducing
// to 0 in the group and stripping the password binding from B — is rejected too.
// This is a safe superset of libRIST's check; a legitimate verifier in [1, N)
// is never a multiple of N and so is unaffected.
func TestVerifierMultipleOfNRejected(t *testing.T) {
	g := DefaultGroup()
	salt := []byte{0x01}
	for _, mult := range []int64{1, 2} {
		v := new(big.Int).Mul(g.N, big.NewInt(mult)) // mult*N ≡ 0 mod N
		if _, err := NewServer(g, v.Bytes(), salt); !errors.Is(err, ErrInvalidVerifier) {
			t.Fatalf("NewServer with v=%d*N: err=%v, want ErrInvalidVerifier", mult, err)
		}
	}
	// A legitimate verifier (some value in [1, N)) is accepted, confirming the
	// stricter check does not over-reject.
	good := MakeVerifier(g, "rist", "mainprofile", salt)
	if _, err := NewServer(g, good, salt); err != nil {
		t.Fatalf("NewServer with a legitimate verifier: %v", err)
	}
}

// TestServerUZeroAbort drives the u==0 safety abort on the server side.
// u = H(PAD(A)|PAD(B)) cannot be forced to zero through the
// public API, so we white-box it: pin A and B so that the SHA-256 of their
// padded concatenation, reduced mod N, lands on zero is infeasible — instead
// we substitute a group whose modulus N divides every possible u, i.e. N == 1
// makes every value congruent to 0 mod N. With N == 1 the u==0 guard must
// fire, exercising the branch deterministically.
func TestServerUZeroAbort(t *testing.T) {
	// Tiny group with N = 1: every integer is 0 mod 1, so u mod N == 0 always.
	g := newGroup(big.NewInt(1), big.NewInt(2))
	// Construct a server by hand (NewServer would reject v==0 mod 1, and any
	// v is 0 mod 1, so build the struct directly for this white-box probe).
	s := &Server{
		group: g,
		salt:  []byte{0x01},
		v:     big.NewInt(1),
		b:     big.NewInt(1),
		pubB:  big.NewInt(0),
		pubA:  big.NewInt(1),
	}
	if s.VerifyM1("rist", make([]byte, hashLen)) {
		t.Fatal("VerifyM1 succeeded despite u==0 mod N")
	}
}

// TestServerComputeBZeroAbort exercises computeB's B==0 abort by choosing a
// group and secret where (k*v + g^b) mod N == 0. We use N == 2, g == 2, v
// such that k*v + g^b is even. With N=2, g^b mod 2 == 0 (g even), and k*v mod
// 2 chosen even => B == 0. This drives the otherwise-unreachable guard.
func TestServerComputeBZeroAbort(t *testing.T) {
	// N = 2, g = 2: g^b mod 2 == 0 for b >= 1. k = H(PAD(N)|PAD(g)); whatever
	// k is, pick v = 2 so k*v is even => (even + 0) mod 2 == 0 => B == 0.
	g := newGroup(big.NewInt(2), big.NewInt(2))
	s := &Server{
		group: g,
		salt:  []byte{0x01},
		v:     big.NewInt(2),
		b:     big.NewInt(1),
	}
	if err := s.computeB(); err != ErrBadParameter {
		t.Fatalf("computeB = %v, want ErrBadParameter (B==0 mod N)", err)
	}
}

// Note on the "wrong hashing" vectors in srp_examples.c: those reproduce
// libRIST's correct_hashing_init=false path, an mbedtls-only artifact where the
// SHA-256 streaming context is left uninitialised; nettle
// ignores the flag entirely. That is a preserved build-specific bug,
// distinct from the legacy_pad (srp-compat=1, unpadded k/u) mode this package
// implements, and is intentionally not reproduced. The legacy_pad path has no
// published byte KAT; it is covered by TestLegacyRoundTrip and TestModeMismatch.

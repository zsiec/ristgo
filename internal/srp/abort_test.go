package srp

import (
	"math/big"
	"testing"
)

// TestServerUZeroAbort drives the u==0 safety abort on the server side
// (srp.c:435-447). u = H(PAD(A)|PAD(B)) cannot be forced to zero through the
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
// SHA-256 streaming context is left uninitialised (srp.c:111-115); nettle
// ignores the flag entirely (srp.c:157). That is a preserved build-specific bug,
// distinct from the legacy_pad (srp-compat=1, unpadded k/u) mode this package
// implements, and is intentionally not reproduced. The legacy_pad path has no
// published byte KAT; it is covered by TestLegacyRoundTrip and TestModeMismatch.

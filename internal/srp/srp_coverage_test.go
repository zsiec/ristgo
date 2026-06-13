package srp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
)

// katSalt decodes the KAT salt without a *testing.T, for use in benchmarks.
func katSalt() []byte {
	b, _ := hex.DecodeString(katSaltHex)
	return b
}

// TestPadAndMinimal exercises the two byte-export helpers at their boundaries:
// PAD always yields len(N) bytes (left-zero-filled); minimalBytes strips
// leading zeros and yields empty for zero.
func TestPadAndMinimal(t *testing.T) {
	g := DefaultGroup()

	// pad(2) is 256 bytes, all zero except the last == 0x02.
	p := g.pad(big.NewInt(2))
	if len(p) != g.length {
		t.Fatalf("pad len = %d, want %d", len(p), g.length)
	}
	if p[g.length-1] != 0x02 {
		t.Fatalf("pad last byte = %#x, want 0x02", p[g.length-1])
	}
	for _, b := range p[:g.length-1] {
		if b != 0 {
			t.Fatal("pad has non-zero leading byte")
		}
	}

	// minimalBytes(0) is empty (matches mbedtls/nettle zero export).
	if mb := minimalBytes(big.NewInt(0)); len(mb) != 0 {
		t.Fatalf("minimalBytes(0) = %X, want empty", mb)
	}
	// minimalBytes(2) is a single 0x02 byte.
	if mb := minimalBytes(big.NewInt(2)); !bytes.Equal(mb, []byte{0x02}) {
		t.Fatalf("minimalBytes(2) = %X, want 02", mb)
	}
}

// TestKValueDeterministic confirms k = H(PAD(N)|PAD(g)) is stable and that the
// legacy unpadded k differs from the PAD-compliant one (proving the PAD scope
// actually changes the multiplier).
func TestKValueDeterministic(t *testing.T) {
	g := DefaultGroup()
	kPad := g.kValue(false)
	kLegacy := g.kValue(true)
	if kPad.Cmp(g.kValue(false)) != 0 {
		t.Fatal("kValue not deterministic")
	}
	if kPad.Cmp(kLegacy) == 0 {
		t.Fatal("PAD and legacy k unexpectedly equal (PAD has no effect)")
	}
	// Sanity: with g=2 padded to 256 bytes, PAD(g) has 255 leading zeros, so
	// the padded and unpadded hashes must differ.
}

// TestSaltIsolation confirms the constructors copy the salt so a caller
// mutating its buffer afterward cannot change the handshake.
func TestSaltIsolation(t *testing.T) {
	g := DefaultGroup()
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand: %v", err)
	}
	v := MakeVerifier(g, katUsername, katPassword, salt)

	c, err := NewClient(g, salt)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s, err := NewServer(g, v, salt)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Scribble over the caller's salt; the handshake must still succeed
	// because both sides snapshotted it.
	for i := range salt {
		salt[i] ^= 0xFF
	}
	if err := s.HandleA(c.A()); err != nil {
		t.Fatalf("HandleA: %v", err)
	}
	if err := c.ComputeKey(s.B(), katUsername, katPassword); err != nil {
		t.Fatalf("ComputeKey: %v", err)
	}
	if !s.VerifyM1(katUsername, c.M1()) {
		t.Fatal("VerifyM1 failed after caller mutated salt buffer")
	}
}

// TestVerifierExportIsolation confirms M1/M2/SessionKey return fresh copies so
// a caller cannot mutate the internal proof or key.
func TestExportCopies(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	v := MakeVerifier(g, katUsername, katPassword, salt)
	c, _ := NewClient(g, salt)
	s, _ := NewServer(g, v, salt)
	_ = s.HandleA(c.A())
	_ = c.ComputeKey(s.B(), katUsername, katPassword)
	_ = s.VerifyM1(katUsername, c.M1())

	m1 := c.M1()
	m1[0] ^= 0xFF
	if bytes.Equal(c.M1(), m1) {
		t.Fatal("M1() returned a mutable alias of internal state")
	}
	k := c.SessionKey()
	k[0] ^= 0xFF
	if bytes.Equal(c.SessionKey(), k) {
		t.Fatal("SessionKey() returned a mutable alias of internal state")
	}
	m2 := s.M2()
	m2[0] ^= 0xFF
	if bytes.Equal(s.M2(), m2) {
		t.Fatal("M2() returned a mutable alias of internal state")
	}
}

// TestReadSecretRange confirms the per-handshake secret is reduced into [0, N).
func TestReadSecretRange(t *testing.T) {
	g := DefaultGroup()
	for i := 0; i < 8; i++ {
		x, err := readSecret(rand.Reader, g.N)
		if err != nil {
			t.Fatalf("readSecret: %v", err)
		}
		if x.Sign() < 0 || x.Cmp(g.N) >= 0 {
			t.Fatalf("secret out of [0,N): %s", x)
		}
	}
}

// errReader always fails, to exercise the CSPRNG error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errFakeRead }

var errFakeRead = bytesError("forced read failure")

type bytesError string

func (e bytesError) Error() string { return string(e) }

func TestCSPRNGFailure(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	if _, err := newClient(g, salt, false, errReader{}); !errors.Is(err, ErrCSPRNG) {
		t.Fatalf("newClient err = %v, want wrapping ErrCSPRNG", err)
	}
	v := MakeVerifier(g, katUsername, katPassword, salt)
	if _, err := newServer(g, v, salt, false, errReader{}); !errors.Is(err, ErrCSPRNG) {
		t.Fatalf("newServer err = %v, want wrapping ErrCSPRNG", err)
	}
}

func BenchmarkClientCompute(b *testing.B) {
	g := DefaultGroup()
	salt := katSalt()
	v := MakeVerifier(g, katUsername, katPassword, salt)
	srv, _ := NewServer(g, v, salt)
	srvB := srv.B()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, _ := NewClient(g, salt)
		_ = c.ComputeKey(srvB, katUsername, katPassword)
	}
}

func BenchmarkServerVerifyM1(b *testing.B) {
	g := DefaultGroup()
	salt := katSalt()
	v := MakeVerifier(g, katUsername, katPassword, salt)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, _ := NewClient(g, salt)
		s, _ := NewServer(g, v, salt)
		_ = s.HandleA(c.A())
		_ = c.ComputeKey(s.B(), katUsername, katPassword)
		_ = s.VerifyM1(katUsername, c.M1())
	}
}

func BenchmarkMakeVerifier(b *testing.B) {
	g := DefaultGroup()
	salt := katSalt()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakeVerifier(g, katUsername, katPassword, salt)
	}
}

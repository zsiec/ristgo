package srp

import (
	"encoding/hex"
	"testing"
)

// FuzzClientCompute feeds arbitrary serverB bytes into a client's ComputeKey.
// A malformed or hostile B must never panic; it either errors or completes.
func FuzzClientCompute(f *testing.F) {
	g := DefaultGroup()
	salt, _ := hex.DecodeString(katSaltHex)
	v := MakeVerifier(g, katUsername, katPassword, salt)
	// Seed with a valid B and a few pathological shapes.
	s, err := NewServer(g, v, salt)
	if err != nil {
		f.Fatalf("seed NewServer: %v", err)
	}
	f.Add(s.B())
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, g.length))   // B == 0 mod N
	f.Add(make([]byte, g.length+1)) // oversize
	f.Add([]byte{0x02})

	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := NewClient(g, salt)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		// Must not panic; result (error or nil) is irrelevant here.
		_ = c.ComputeKey(b, katUsername, katPassword)
		// If it succeeded, the accessors must also not panic.
		_ = c.M1()
		_ = c.SessionKey()
		_ = c.VerifyM2(b)
	})
}

// FuzzServerHandleA feeds arbitrary clientA bytes into a server's HandleA and
// then attempts a VerifyM1. Arbitrary input must never panic.
func FuzzServerHandleA(f *testing.F) {
	g := DefaultGroup()
	salt, _ := hex.DecodeString(katSaltHex)
	v := MakeVerifier(g, katUsername, katPassword, salt)
	c, err := NewClient(g, salt)
	if err != nil {
		f.Fatalf("seed NewClient: %v", err)
	}
	f.Add(c.A())
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, g.length))   // A == 0 mod N
	f.Add(make([]byte, g.length+1)) // oversize
	f.Add([]byte{0x02})

	f.Fuzz(func(t *testing.T, a []byte) {
		s, err := NewServer(g, v, salt)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if err := s.HandleA(a); err != nil {
			// Rejected A: VerifyM1 must still be safe (no A stored).
			_ = s.VerifyM1(katUsername, make([]byte, 32))
			return
		}
		// Accepted A: a VerifyM1 with an arbitrary proof must not panic.
		_ = s.VerifyM1(katUsername, make([]byte, 32))
		_ = s.M2()
		_ = s.SessionKey()
	})
}

// FuzzHash: Hash must never panic on arbitrary input parts.
func FuzzHash(f *testing.F) {
	f.Add([]byte("rist:mainprofile"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = Hash(b)
		_ = Hash(b, b, b)
	})
}

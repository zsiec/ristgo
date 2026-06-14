package srp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// KAT fixtures from libRIST, the PAD-compliant
// "correct hashing" exchange (DEBUG_USE_EXAMPLE_CONSTANTS=1) on the 2048-bit
// NG_DEFAULT group. username="rist", password="mainprofile".
const (
	katSaltHex = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32"
	// Deterministic secrets a and b, DEBUG_USE_EXAMPLE_CONSTANTS branch.
	katAHex = "138AB4045633AD14961CB1AD0720B1989104151C0708794491113302CCCC27D5"
	katBHex = "ED0D58FF861A1FC75A0829BEA5F1392D2B13AB2B05CBCD6ED1E71AAAD761E856"

	katInnerHash = "8427F6E0E69DC9B99DFE1052DDAF7E50D4FEA316C63C6AD23FE197C9C1DA2AF1"

	katVerifier = "16B380409C1D6A43A96B42DD0FAC130D54A1932205F51F26AC13FB5332331C7B" +
		"66A313ED969E24CB2AC5447C04FFC6565BC9FEA75A79D865FF7BB0DD65C62065" +
		"EAAE7A27048F3B4C1FC0502C622FFE5B196400AD9470DB9F9DFB55CC4710081F" +
		"DAEE3B63B69C15D43E189EF3E6E1C1FB1A9268F8E6DCDF16E1726585B883960E" +
		"E09B318D3DD9E1C93D1B3EC98C148C00927028C1ED14D342B72811B962C233B7" +
		"1096BDD2EE505539DDC04ED03FDAA69926417E86016406480F8EB41317FF3D5E" +
		"3B4735C76BCE67333B1F1E5E6A467E7E45A70D66EE1FC474A179697C5690AC1A" +
		"525D2ADD050CC9D9824232AEC6FD8206CBEA5144AA2AC31B9865CEACF3BA2A72"

	katA = "545DD89CD403BA71172016F156A537A2D369B8551004AB521CC62D76B71BD278" +
		"E687294A3D265B96393A582D8823E4BB3A7960F641D7A01DD7E13C982F06B052" +
		"2EC147B1451C63F099FD08A9D5A6FD5CA73907B13E0672DEFAEF976BEA78E8F4" +
		"C3E60E85B86FE68F84658D3A792D90F2FB834E657C5F1E6AAA532A3D3F4F2D74" +
		"7D8F3D0C0CC8F999773ED4FFE159A8B8ACB2761C6C523C68BC866EE464091B6F" +
		"86720EFFB02824AC1FB31675B7F07DD2292B937C9EDE73C2420A3204CA0BBD51" +
		"9274B5D35771019265BE5E213C9634540A0D56EA94BA306AD1965EFF986AF896" +
		"3ECE5E30E057517A0D0082205E1086520039A03D60D739FCD7BB335CBB3AF39A"

	katB = "461F82DB9BBD64DD580800C38B854437F0AE29CA14B0AD4A03797CA4EB6A27CD" +
		"3C1B90E06E1C539A5FFE61E905497E78E8433F5303BEC8ECB23008DA86EBFB1B" +
		"1B2FED35129BBC2ED346A810CC2A0AB20E44E2B94E048C9F9A17ABD87651CD1F" +
		"2642873E487E0DDB3987D68F1B831CA8598AB88B377FAA7B06DCFE0E83A6D97F" +
		"FB50D429285518209A4AEFA66F5A2BA499918209362CF0907EDC9E265156FCB8" +
		"A945027F4DCDE178B8169D796187B79AA133E3BE02AF81C6AEC0B675D5F9E25E" +
		"78CE00D5A0FE3BADC7106A2DAFB078BF30EF8677DD4D1EE60B50B110446C576C" +
		"DDA3FA930C837938FE4AC4CF2F28185A2DD87F9524F1D5746E93D9A8FFF53626"

	katM1 = "2EE41138D2C447E7469EB589B89CF96FAF869B55DD684897DAB173056F1D8F90"
	katM2 = "28E0412112CD83DDC97B3395AB0D27F5C0A1EB4FA89205CD505957F53988A639"

	katUsername = "rist"
	katPassword = "mainprofile"
)

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// setA injects a deterministic client secret a (white-box), mirroring
// libRIST's DEBUG_USE_EXAMPLE_CONSTANTS, and recomputes A = g^a mod N.
func (c *Client) setA(a *big.Int) {
	c.a = a
	c.pubA = new(big.Int).Exp(c.group.G, a, c.group.N)
}

// setB injects a deterministic server secret b (white-box) and recomputes B.
func (s *Server) setB(t *testing.T, b *big.Int) {
	t.Helper()
	s.b = b
	if err := s.computeB(); err != nil {
		t.Fatalf("computeB after inject: %v", err)
	}
}

func TestHash(t *testing.T) {
	// H("rist:mainprofile") == katInnerHash; this is the inner hash of calc_x.
	got := Hash([]byte("rist:mainprofile"))
	want := mustHex(t, katInnerHash)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("Hash(\"rist:mainprofile\") = %X, want %s", got, katInnerHash)
	}

	// Concatenation behaves as a single SHA-256 over the joined parts.
	split := Hash([]byte("rist"), []byte(":"), []byte("mainprofile"))
	if !bytes.Equal(split[:], want) {
		t.Fatalf("Hash split = %X, want %s", split, katInnerHash)
	}

	// Empty input is the SHA-256 of the empty string.
	empty := Hash()
	stdEmpty := sha256.Sum256(nil)
	if !bytes.Equal(empty[:], stdEmpty[:]) {
		t.Fatalf("Hash() = %X, want %X", empty, stdEmpty)
	}
}

func TestDefaultGroup(t *testing.T) {
	g := DefaultGroup()
	wantN, _ := new(big.Int).SetString(defaultNHex, 16)
	if g.N.Cmp(wantN) != 0 {
		t.Fatalf("N mismatch")
	}
	if g.G.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("g = %s, want 2", g.G)
	}
	if g.length != 256 {
		t.Fatalf("len(N) = %d bytes, want 256", g.length)
	}
	// N is exactly 2048 bits.
	if g.N.BitLen() != 2048 {
		t.Fatalf("N bitlen = %d, want 2048", g.N.BitLen())
	}
}

func TestVerifierKAT(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	v := MakeVerifier(g, katUsername, katPassword, salt)
	want := mustHex(t, katVerifier)
	if !bytes.Equal(v, want) {
		t.Fatalf("verifier = %X\nwant       %s", v, katVerifier)
	}
	if len(v) != 256 {
		t.Fatalf("verifier len = %d, want 256", len(v))
	}
}

// TestClientServerKAT injects the deterministic a/b and asserts A, B, M1, M2
// match the libRIST KAT byte-for-byte, and that the two derived session keys
// agree and both proofs verify.
func TestClientServerKAT(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	a, _ := new(big.Int).SetString(katAHex, 16)
	b, _ := new(big.Int).SetString(katBHex, 16)

	v := MakeVerifier(g, katUsername, katPassword, salt)

	c, err := NewClient(g, salt)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.setA(a)

	s, err := NewServer(g, v, salt)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setB(t, b)

	if got, want := c.A(), mustHex(t, katA); !bytes.Equal(got, want) {
		t.Fatalf("A = %X\nwant %s", got, katA)
	}
	if got, want := s.B(), mustHex(t, katB); !bytes.Equal(got, want) {
		t.Fatalf("B = %X\nwant %s", got, katB)
	}

	// Client side: ComputeKey then M1.
	if err := c.ComputeKey(s.B(), katUsername, katPassword); err != nil {
		t.Fatalf("ComputeKey: %v", err)
	}
	if got, want := c.M1(), mustHex(t, katM1); !bytes.Equal(got, want) {
		t.Fatalf("M1 = %X\nwant %s", got, katM1)
	}

	// Server side: HandleA then VerifyM1, then M2.
	if err := s.HandleA(c.A()); err != nil {
		t.Fatalf("HandleA: %v", err)
	}
	if !s.VerifyM1(katUsername, c.M1()) {
		t.Fatal("server VerifyM1 = false, want true")
	}
	if got, want := s.M2(), mustHex(t, katM2); !bytes.Equal(got, want) {
		t.Fatalf("M2 = %X\nwant %s", got, katM2)
	}

	// Client verifies M2.
	if !c.VerifyM2(s.M2()) {
		t.Fatal("client VerifyM2 = false, want true")
	}

	// Session keys agree and are 32 bytes.
	ck, sk := c.SessionKey(), s.SessionKey()
	if !bytes.Equal(ck, sk) {
		t.Fatalf("session keys differ: client %X server %X", ck, sk)
	}
	if len(ck) != 32 {
		t.Fatalf("session key len = %d, want 32", len(ck))
	}
	// K = H(S); confirm it is exactly the value the probe observed.
	const katK = "0E7822B56248FFE74D0A4639BD7194E848DF0E590A5D9AD414021EE7FAB360A8"
	if !bytes.Equal(ck, mustHex(t, katK)) {
		t.Fatalf("K = %X, want %s", ck, katK)
	}
}

// TestRoundTripRandom runs the full SRP exchange with fresh random a/b several
// times: both proofs verify and the keys match each run.
func TestRoundTripRandom(t *testing.T) {
	g := DefaultGroup()
	for i := 0; i < 16; i++ {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			t.Fatalf("salt rand: %v", err)
		}
		username, password := "operator", "s3cr3t-pass-w0rd"
		v := MakeVerifier(g, username, password, salt)

		c, err := NewClient(g, salt)
		if err != nil {
			t.Fatalf("iter %d NewClient: %v", i, err)
		}
		s, err := NewServer(g, v, salt)
		if err != nil {
			t.Fatalf("iter %d NewServer: %v", i, err)
		}

		if err := s.HandleA(c.A()); err != nil {
			t.Fatalf("iter %d HandleA: %v", i, err)
		}
		if err := c.ComputeKey(s.B(), username, password); err != nil {
			t.Fatalf("iter %d ComputeKey: %v", i, err)
		}
		if !s.VerifyM1(username, c.M1()) {
			t.Fatalf("iter %d server VerifyM1 failed", i)
		}
		if !c.VerifyM2(s.M2()) {
			t.Fatalf("iter %d client VerifyM2 failed", i)
		}
		if !bytes.Equal(c.SessionKey(), s.SessionKey()) {
			t.Fatalf("iter %d session keys differ", i)
		}
	}
}

// TestLegacyRoundTrip exercises the unpadded k/u (srp-compat=1) path: a legacy
// client and legacy server still complete the exchange.
func TestLegacyRoundTrip(t *testing.T) {
	g := DefaultGroup()
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("salt rand: %v", err)
	}
	username, password := "rist", "mainprofile"
	v := MakeVerifier(g, username, password, salt)

	c, err := NewClientLegacy(g, salt)
	if err != nil {
		t.Fatalf("NewClientLegacy: %v", err)
	}
	s, err := NewServerLegacy(g, v, salt)
	if err != nil {
		t.Fatalf("NewServerLegacy: %v", err)
	}
	if err := s.HandleA(c.A()); err != nil {
		t.Fatalf("HandleA: %v", err)
	}
	if err := c.ComputeKey(s.B(), username, password); err != nil {
		t.Fatalf("ComputeKey: %v", err)
	}
	if !s.VerifyM1(username, c.M1()) {
		t.Fatal("legacy server VerifyM1 failed")
	}
	if !c.VerifyM2(s.M2()) {
		t.Fatal("legacy client VerifyM2 failed")
	}
	if !bytes.Equal(c.SessionKey(), s.SessionKey()) {
		t.Fatal("legacy session keys differ")
	}
}

// TestModeMismatch confirms that a PAD client against a legacy server (and vice
// versa) fails at M1 — the "operator forgot srp-compat on one side" case
// (test_srp_compat_mismatch_*).
func TestModeMismatch(t *testing.T) {
	g := DefaultGroup()
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("salt rand: %v", err)
	}
	username, password := "rist", "mainprofile"
	v := MakeVerifier(g, username, password, salt)

	cases := []struct {
		name         string
		serverLegacy bool
		clientLegacy bool
	}{
		{"auth_pad_client_legacy", false, true},
		{"auth_legacy_client_pad", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c *Client
			var s *Server
			var err error
			if tc.clientLegacy {
				c, err = NewClientLegacy(g, salt)
			} else {
				c, err = NewClient(g, salt)
			}
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			if tc.serverLegacy {
				s, err = NewServerLegacy(g, v, salt)
			} else {
				s, err = NewServer(g, v, salt)
			}
			if err != nil {
				t.Fatalf("server: %v", err)
			}
			if err := s.HandleA(c.A()); err != nil {
				t.Fatalf("HandleA: %v", err)
			}
			if err := c.ComputeKey(s.B(), username, password); err != nil {
				t.Fatalf("ComputeKey: %v", err)
			}
			if s.VerifyM1(username, c.M1()) {
				t.Fatal("mode mismatch unexpectedly verified M1")
			}
		})
	}
}

// TestWrongPassword: a client that uses the wrong password derives the wrong
// M1, which the server rejects, and the keys do not match.
func TestWrongPassword(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	v := MakeVerifier(g, katUsername, katPassword, salt)

	c, err := NewClient(g, salt)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s, err := NewServer(g, v, salt)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := s.HandleA(c.A()); err != nil {
		t.Fatalf("HandleA: %v", err)
	}
	if err := c.ComputeKey(s.B(), katUsername, "wrong-password"); err != nil {
		t.Fatalf("ComputeKey: %v", err)
	}
	if s.VerifyM1(katUsername, c.M1()) {
		t.Fatal("server VerifyM1 accepted wrong password")
	}
	// Server still cannot expose a key/M2 since VerifyM1 did not succeed.
	if s.M2() != nil {
		t.Fatal("M2 available after failed VerifyM1")
	}
	if s.SessionKey() != nil {
		t.Fatal("SessionKey available after failed VerifyM1")
	}
}

// TestSafetyAborts: A mod N == 0 and B mod N == 0 are rejected, M1/M2
// mismatches are rejected, and short proofs are rejected.
func TestSafetyAborts(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	v := MakeVerifier(g, katUsername, katPassword, salt)

	t.Run("server rejects A==0 mod N", func(t *testing.T) {
		s, err := NewServer(g, v, salt)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		// A = N (=> A mod N == 0), exported at len(N).
		nBytes := make([]byte, g.length)
		g.N.FillBytes(nBytes)
		if err := s.HandleA(nBytes); err != ErrBadParameter {
			t.Fatalf("HandleA(N) = %v, want ErrBadParameter", err)
		}
		// A == 0 too.
		if err := s.HandleA(make([]byte, g.length)); err != ErrBadParameter {
			t.Fatalf("HandleA(0) = %v, want ErrBadParameter", err)
		}
		// Empty and oversize.
		if err := s.HandleA(nil); err != ErrBadParameter {
			t.Fatalf("HandleA(nil) = %v, want ErrBadParameter", err)
		}
		if err := s.HandleA(make([]byte, g.length+1)); err != ErrBadParameter {
			t.Fatalf("HandleA(oversize) = %v, want ErrBadParameter", err)
		}
	})

	t.Run("client rejects B==0 mod N", func(t *testing.T) {
		c, err := NewClient(g, salt)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		nBytes := make([]byte, g.length)
		g.N.FillBytes(nBytes)
		if err := c.ComputeKey(nBytes, katUsername, katPassword); err != ErrBadParameter {
			t.Fatalf("ComputeKey(B=N) = %v, want ErrBadParameter", err)
		}
		if err := c.ComputeKey(make([]byte, g.length), katUsername, katPassword); err != ErrBadParameter {
			t.Fatalf("ComputeKey(B=0) = %v, want ErrBadParameter", err)
		}
		if err := c.ComputeKey(nil, katUsername, katPassword); err != ErrBadParameter {
			t.Fatalf("ComputeKey(nil) = %v, want ErrBadParameter", err)
		}
		if err := c.ComputeKey(make([]byte, g.length+1), katUsername, katPassword); err != ErrBadParameter {
			t.Fatalf("ComputeKey(oversize) = %v, want ErrBadParameter", err)
		}
	})

	t.Run("server rejects verifier v==0", func(t *testing.T) {
		if _, err := NewServer(g, make([]byte, g.length), salt); err != ErrInvalidVerifier {
			t.Fatalf("NewServer(v=0) = %v, want ErrInvalidVerifier", err)
		}
		if _, err := NewServer(g, nil, salt); err != ErrInvalidVerifier {
			t.Fatalf("NewServer(v=nil) = %v, want ErrInvalidVerifier", err)
		}
	})

	t.Run("M1 mismatch rejected", func(t *testing.T) {
		s, err := NewServer(g, v, salt)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		c, err := NewClient(g, salt)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := s.HandleA(c.A()); err != nil {
			t.Fatalf("HandleA: %v", err)
		}
		if err := c.ComputeKey(s.B(), katUsername, katPassword); err != nil {
			t.Fatalf("ComputeKey: %v", err)
		}
		// Corrupt one byte of M1.
		bad := append([]byte(nil), c.M1()...)
		bad[0] ^= 0xFF
		if s.VerifyM1(katUsername, bad) {
			t.Fatal("VerifyM1 accepted corrupted M1")
		}
		// Wrong length M1.
		if s.VerifyM1(katUsername, bad[:16]) {
			t.Fatal("VerifyM1 accepted short M1")
		}
	})

	t.Run("M2 mismatch rejected", func(t *testing.T) {
		s, err := NewServer(g, v, salt)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		c, err := NewClient(g, salt)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := s.HandleA(c.A()); err != nil {
			t.Fatalf("HandleA: %v", err)
		}
		if err := c.ComputeKey(s.B(), katUsername, katPassword); err != nil {
			t.Fatalf("ComputeKey: %v", err)
		}
		if !s.VerifyM1(katUsername, c.M1()) {
			t.Fatal("VerifyM1 failed unexpectedly")
		}
		bad := append([]byte(nil), s.M2()...)
		bad[31] ^= 0x01
		if c.VerifyM2(bad) {
			t.Fatal("VerifyM2 accepted corrupted M2")
		}
		if c.VerifyM2(bad[:16]) {
			t.Fatal("VerifyM2 accepted short M2")
		}
	})
}

// TestAccessorsBeforeReady: M1/M2/SessionKey return nil before their
// precondition is met.
func TestAccessorsBeforeReady(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	v := MakeVerifier(g, katUsername, katPassword, salt)

	c, err := NewClient(g, salt)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.M1() != nil {
		t.Fatal("M1 non-nil before ComputeKey")
	}
	if c.SessionKey() != nil {
		t.Fatal("client SessionKey non-nil before ComputeKey")
	}
	if c.VerifyM2(make([]byte, 32)) {
		t.Fatal("VerifyM2 true before ComputeKey")
	}

	s, err := NewServer(g, v, salt)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.M2() != nil {
		t.Fatal("M2 non-nil before VerifyM1")
	}
	if s.SessionKey() != nil {
		t.Fatal("server SessionKey non-nil before VerifyM1")
	}
	// VerifyM1 before HandleA must be false (no A stored).
	if s.VerifyM1(katUsername, make([]byte, 32)) {
		t.Fatal("VerifyM1 true before HandleA")
	}
}

// TestConstructorValidation covers invalid groups and salts.
func TestConstructorValidation(t *testing.T) {
	salt := mustHex(t, katSaltHex)
	bad := &Group{N: big.NewInt(0), G: big.NewInt(2)}

	if _, err := NewClient(nil, salt); err != ErrInvalidGroup {
		t.Fatalf("NewClient(nil group) = %v", err)
	}
	if _, err := NewClient(bad, salt); err != ErrInvalidGroup {
		t.Fatalf("NewClient(bad group) = %v", err)
	}
	g := DefaultGroup()
	if _, err := NewClient(g, nil); err != ErrInvalidSalt {
		t.Fatalf("NewClient(nil salt) = %v", err)
	}
	v := MakeVerifier(g, katUsername, katPassword, salt)
	if _, err := NewServer(nil, v, salt); err != ErrInvalidGroup {
		t.Fatalf("NewServer(nil group) = %v", err)
	}
	if _, err := NewServer(g, v, nil); err != ErrInvalidSalt {
		t.Fatalf("NewServer(nil salt) = %v", err)
	}
	if got := MakeVerifier(nil, katUsername, katPassword, salt); got != nil {
		t.Fatalf("MakeVerifier(nil group) = %X, want nil", got)
	}
	if got := MakeVerifier(g, katUsername, katPassword, nil); got != nil {
		t.Fatalf("MakeVerifier(nil salt) = %X, want nil", got)
	}
}

// TestExportSizes: A and B are always PADded to len(N) even for small values.
func TestExportSizes(t *testing.T) {
	g := DefaultGroup()
	salt := mustHex(t, katSaltHex)
	c, err := NewClient(g, salt)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if len(c.A()) != g.length {
		t.Fatalf("len(A) = %d, want %d", len(c.A()), g.length)
	}
	v := MakeVerifier(g, katUsername, katPassword, salt)
	s, err := NewServer(g, v, salt)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if len(s.B()) != g.length {
		t.Fatalf("len(B) = %d, want %d", len(s.B()), g.length)
	}
}

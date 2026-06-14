// Package srp implements SRP-6a (Secure Remote Password) over SHA-256, the
// RFC 5054 PAD-compliant variant, byte-exact with libRIST v0.2.18-rc1.
// It is the cryptographic
// engine behind RIST Main-profile EAP-SRP authentication: the eap package
// drives a Client (authenticatee) and Server (authenticator) through the
// SRP-6a message exchange and derives the shared session key K.
//
// The protocol, with H = SHA-256, "|" = concatenation, all bignums big-endian
// on the wire, and PAD(x) = x left-zero-padded to len(N) bytes (256 for the
// 2048-bit group):
//
//   - x  = H( salt | H( username | ":" | password ) )   (calc_x)
//   - k  = H( PAD(N) | PAD(g) )
//   - v  = g^x mod N                                     (the verifier)
//   - A  = g^a mod N                                     (client)
//   - B  = (k*v + g^b) mod N                             (server)
//   - u  = H( PAD(A) | PAD(B) )
//   - client S = (B - k*(g^x mod N)) ^ (a + u*x) mod N
//   - server S = (A * (v^u mod N)) ^ b mod N
//   - K  = H( S )   (S at its NATURAL minimal byte length, NOT PADded;
//     hash_bignum)
//   - M1 = H( (H(N) XOR H(g)) | H(I) | salt | A | B | K )
//     (calculate_m: N,g via hash_bignum and salt,A,B via
//     hash_update_bignum — all at MINIMAL length, NOT PADded; only k and
//     u use PAD)
//   - M2 = H( A | M1 | K )   (A minimal/unpadded; calculate_m2)
//
// PAD scope is the one subtlety: libRIST's PAD-compliant mode (the 0.2.16+
// default, hashversion=1) pads only the operands of k and u to len(N). In the
// M1/M2 component hashes N, g, salt, A, B are written at their minimal
// big-endian length, and K hashes S at its minimal length too. This package
// matches that exactly; the libRIST KAT is reproduced
// byte-for-byte by the tests. A legacy pre-0.2.16 unpadded k/u mode (the
// legacy_pad / srp-compat=1 mode) is exposed via NewClientLegacy / NewServerLegacy
// for interop with old peers, but the default and required path is
// PAD-compliant.
//
// Like the rest of ristgo's crypto, this package is deterministic in the
// host's hands: it never reads a clock, opens a socket, or spawns a goroutine.
// The only non-determinism is the per-handshake secret (the client's a and the
// server's b), drawn from crypto/rand at construction; everything downstream
// is a pure function of the inputs. White-box tests inject deterministic a/b
// (mirroring libRIST's DEBUG_USE_EXAMPLE_CONSTANTS) to reproduce the KAT.
package srp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

// Sentinel errors returned by this package. Callers should test for them with
// errors.Is; returned errors may wrap these with additional context.
var (
	// ErrInvalidGroup is returned by NewClient/NewServer when the group is nil
	// or has a non-positive modulus or generator.
	ErrInvalidGroup = errors.New("rist: srp: invalid group")

	// ErrInvalidSalt is returned by NewClient/NewServer when the salt is empty.
	// libRIST bounds the salt at 1..64 bytes; we accept any
	// non-empty salt and never reject on the upper bound, since the salt is the
	// caller's to choose.
	ErrInvalidSalt = errors.New("rist: srp: empty salt")

	// ErrInvalidVerifier is returned by NewServer when the verifier is empty or
	// is congruent to zero modulo N (RFC 5054 rejects v == 0).
	ErrInvalidVerifier = errors.New("rist: srp: invalid verifier")

	// ErrBadParameter is returned by HandleA/ComputeKey when a peer-supplied
	// public value is malformed (empty, longer than len(N), or congruent to
	// zero modulo N), or when the derived scrambling parameter u is zero. These
	// are the SRP-6a safety aborts (RFC 5054 §2.6). They never panic on
	// arbitrary input.
	ErrBadParameter = errors.New("rist: srp: bad SRP parameter")

	// ErrCSPRNG wraps a failure to read from the random source while generating
	// the per-handshake secret a (client) or b (server).
	ErrCSPRNG = errors.New("rist: srp: CSPRNG read failed")
)

// hashLen is the SHA-256 digest length in bytes; the SRP hash output size and
// the size of M1, M2, and the session key K.
const hashLen = sha256.Size

// Hash returns SHA-256 over the concatenation of parts. It is the SRP hash
// (libRIST's librist_crypto_srp_hash) and is exported because
// the EAP layer hashes the same way over message transcripts.
func Hash(parts ...[]byte) [hashLen]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [hashLen]byte
	h.Sum(out[:0])
	return out
}

// Group is an SRP-6a group: a safe-prime modulus N and a generator g. The
// 2048-bit RFC 5054 Appendix A group returned by DefaultGroup is libRIST's
// LIBRIST_SRP_NG_DEFAULT (the second table entry).
type Group struct {
	// N is the group modulus (a safe prime). len is the byte length of N, the
	// PAD target for k and u and the size of an exported A or B.
	N *big.Int
	// G is the group generator (2 for the default group).
	G *big.Int
	// length is len(N) in bytes, cached for PAD and export.
	length int
}

// defaultNHex is the 2048-bit RFC 5054 Appendix A modulus, libRIST's
// NG_DEFAULT (second {n_hex,g_hex} entry). g = 2.
const defaultNHex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
	"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
	"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
	"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
	"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
	"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
	"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
	"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

// defaultN is the 2048-bit modulus parsed once from the compile-time constant
// defaultNHex (TestDefaultGroup asserts it parsed to a valid 2048-bit value).
// Parsing at package init rather than per call keeps DefaultGroup free of a
// fallible parse and the "no panics in library code" rule intact. It is never
// mutated (SRP computations allocate fresh results), so groups may share it.
var defaultN, _ = new(big.Int).SetString(defaultNHex, 16)

// DefaultGroup returns the 2048-bit RFC 5054 Appendix A group with g = 2,
// libRIST's LIBRIST_SRP_NG_DEFAULT. Callers may treat the returned *Group as
// immutable (and it shares the package-level modulus).
func DefaultGroup() *Group {
	return newGroup(defaultN, big.NewInt(2))
}

// newGroup builds a Group from N and g, caching len(N).
func newGroup(n, g *big.Int) *Group {
	return &Group{N: n, G: g, length: (n.BitLen() + 7) / 8}
}

// valid reports whether the group has a positive modulus and generator.
func (gr *Group) valid() bool {
	return gr != nil && gr.N != nil && gr.G != nil && gr.N.Sign() > 0 && gr.G.Sign() > 0
}

// pad returns the big-endian bytes of x left-zero-padded to len(N) bytes,
// RFC 5054 PAD(x). It is used for the operands of k and u, and to export A and
// B on the wire (FillBytes panics if x does not fit in len(N) bytes, which
// cannot happen for values already reduced mod N).
func (gr *Group) pad(x *big.Int) []byte {
	buf := make([]byte, gr.length)
	x.FillBytes(buf)
	return buf
}

// minimalBytes returns the big-endian bytes of x at its natural minimal length
// (no leading zero bytes), matching libRIST's BIGNUM_GET_BINARY_SIZE export
// used by hash_bignum and hash_update_bignum in the M1/M2/K hashes. A zero
// value yields an empty slice, as mbedtls/nettle export zero as zero bytes.
func minimalBytes(x *big.Int) []byte {
	return x.Bytes()
}

// hashPadded computes H(PAD(a) | PAD(b)) for the group's len(N), the
// RFC 5054 PAD-compliant hash used for k = H(PAD(N)|PAD(g)) and
// u = H(PAD(A)|PAD(B)) (srp_hash_uk padded branch).
func (gr *Group) hashPadded(a, b *big.Int) [hashLen]byte {
	return Hash(gr.pad(a), gr.pad(b))
}

// hashUnpadded computes H(min(a) | min(b)), the legacy pre-0.2.16 unpadded
// k/u hash (srp_hash_uk unpadded branch).
func hashUnpadded(a, b *big.Int) [hashLen]byte {
	return Hash(minimalBytes(a), minimalBytes(b))
}

// canonSalt strips leading zero bytes from the salt, matching libRIST, which
// holds the salt as a BIGNUM and re-exports it at its minimal big-endian length
// (BIGNUM_GET_BINARY_SIZE) wherever it is hashed — in calc_x and in
// calculate_m. The wire salt keeps its leading zeros (create_verifier preserves
// the raw 32 bytes), but the HASHED form must not, or x/v/M1/K
// diverge from a libRIST peer for any salt whose first byte is 0x00 (~1/256 of
// random salts). An all-zero salt yields an empty slice, as the bignum export
// does.
func canonSalt(salt []byte) []byte {
	return new(big.Int).SetBytes(salt).Bytes()
}

// calcX computes x = H( PAD-stripped salt | H( username | ":" | password ) ),
// libRIST's librist_crypto_srp_calc_x. The salt is hashed at
// its MINIMAL big-endian length (BIGNUM_GET_BINARY_SIZE), not its
// supplied wire length; the inner hash H("user:pass") is unpadded.
func calcX(salt []byte, username, password string) *big.Int {
	inner := Hash([]byte(username), []byte(":"), []byte(password))
	outer := Hash(canonSalt(salt), inner[:])
	return new(big.Int).SetBytes(outer[:])
}

// kValue computes the SRP-6a multiplier k for the group: PAD-compliant
// k = H(PAD(N)|PAD(g)), or legacy unpadded k = H(N|g).
func (gr *Group) kValue(legacyPad bool) *big.Int {
	var d [hashLen]byte
	if legacyPad {
		d = hashUnpadded(gr.N, gr.G)
	} else {
		d = gr.hashPadded(gr.N, gr.G)
	}
	return new(big.Int).SetBytes(d[:])
}

// uValue computes the SRP-6a scrambling parameter u from A and B:
// PAD-compliant u = H(PAD(A)|PAD(B)), or legacy unpadded u = H(A|B).
func (gr *Group) uValue(a, b *big.Int, legacyPad bool) *big.Int {
	var d [hashLen]byte
	if legacyPad {
		d = hashUnpadded(a, b)
	} else {
		d = gr.hashPadded(a, b)
	}
	return new(big.Int).SetBytes(d[:])
}

// sessionKey computes K = H(S) with S exported at its natural minimal length,
// matching libRIST's hash_bignum (server and client). S is
// already reduced mod N by the caller.
func sessionKey(s *big.Int) [hashLen]byte {
	return Hash(minimalBytes(s))
}

// calcM1 computes M1 = H( (H(N) XOR H(g)) | H(I) | salt | A | B | K ), libRIST's
// librist_crypto_srp_calculate_m. N, g, salt, A, B are all
// hashed at their MINIMAL big-endian length (hash_bignum / hash_update_bignum),
// NOT PADded — only k and u use PAD in the PAD-compliant variant. The salt, like
// libRIST's BIGNUM ctx->s, is canonicalized to minimal length (canonSalt).
func (gr *Group) calcM1(username string, salt []byte, a, b *big.Int, key [hashLen]byte) [hashLen]byte {
	hN := Hash(minimalBytes(gr.N))
	hG := Hash(minimalBytes(gr.G))
	var xored [hashLen]byte
	for i := range xored {
		xored[i] = hN[i] ^ hG[i]
	}
	hI := Hash([]byte(username))
	return Hash(xored[:], hI[:], canonSalt(salt), minimalBytes(a), minimalBytes(b), key[:])
}

// calcM2 computes M2 = H( A | M1 | K ), libRIST's
// librist_crypto_srp_calculate_m2. A is hashed at its minimal
// big-endian length.
func calcM2(a *big.Int, m1, key [hashLen]byte) [hashLen]byte {
	return Hash(minimalBytes(a), m1[:], key[:])
}

// MakeVerifier returns the SRP-6a verifier v = g^x mod N for the given
// credentials and salt, where x = H(salt | H(username | ":" | password)). The
// result is the big-endian verifier at its natural minimal length, matching
// libRIST's librist_crypto_srp_create_verifier
// (BIGNUM_WRITE_BYTES_ALLOC at the verifier's mpi_size). It uses the
// PAD-compliant ("correct hashing") path. A nil or invalid group yields nil.
func MakeVerifier(g *Group, username, password string, salt []byte) []byte {
	if !g.valid() || len(salt) == 0 {
		return nil
	}
	x := calcX(salt, username, password)
	v := new(big.Int).Exp(g.G, x, g.N)
	return v.Bytes()
}

// readSecret draws a per-handshake secret in [0, N) from src. libRIST uses
// BIGNUM_RANDOM(num, &N) (an integer uniformly in [0, N)). We draw len(N)
// random bytes and reduce mod N, which is
// indistinguishable in practice for a 2048-bit N and never produces a value
// outside [0, N).
func readSecret(src io.Reader, n *big.Int) (*big.Int, error) {
	buf := make([]byte, (n.BitLen()+7)/8)
	if _, err := io.ReadFull(src, buf); err != nil {
		return nil, errors.Join(ErrCSPRNG, err)
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(buf), n), nil
}

// Client is an SRP-6a authenticatee. It holds the group, salt, the
// per-handshake secret a and public A, and — after ComputeKey — the shared
// session key K and the proofs M1/M2. A Client is single-use and not safe for
// concurrent use.
type Client struct {
	group     *Group
	salt      []byte
	a         *big.Int // private secret
	pubA      *big.Int // A = g^a mod N
	legacyPad bool

	computed bool
	key      [hashLen]byte // K = H(S)
	m1       [hashLen]byte // client proof
}

// NewClient creates an SRP-6a client for the group and salt, drawing a random
// secret a from crypto/rand and computing A = g^a mod N. It returns an error
// for an invalid group, an empty salt, or a CSPRNG failure.
func NewClient(g *Group, salt []byte) (*Client, error) {
	return newClient(g, salt, false, rand.Reader)
}

// NewClientLegacy is NewClient with the pre-0.2.16 unpadded k/u hashing
// (libRIST srp-compat=1). Use only to interoperate with old peers.
func NewClientLegacy(g *Group, salt []byte) (*Client, error) {
	return newClient(g, salt, true, rand.Reader)
}

func newClient(g *Group, salt []byte, legacyPad bool, src io.Reader) (*Client, error) {
	if !g.valid() {
		return nil, ErrInvalidGroup
	}
	if len(salt) == 0 {
		return nil, ErrInvalidSalt
	}
	a, err := readSecret(src, g.N)
	if err != nil {
		return nil, err
	}
	c := &Client{
		group:     g,
		salt:      append([]byte(nil), salt...),
		a:         a,
		legacyPad: legacyPad,
	}
	c.pubA = new(big.Int).Exp(g.G, a, g.N)
	return c, nil
}

// A returns the client public value A = g^a mod N, big-endian and PADded to
// len(N) bytes (256 for the default group). The returned slice is freshly
// allocated.
//
// libRIST's librist_crypto_srp_client_write_A_bytes returns the MINIMAL
// mpi_size(A) bytes, and EAP transmits A at that minimal length
// with an explicit length field — it does not pad to len(N).
// ristgo deliberately pads instead, which is value-preserving and interop-safe:
// the peer reconstructs the identical bignum via SetBytes regardless of leading
// zeros, and u = H(PAD(A)|PAD(B)) re-pads both operands on each side.
func (c *Client) A() []byte {
	return c.group.pad(c.pubA)
}

// ComputeKey processes the server public value B and derives x, u, the premaster
// secret S, the session key K = H(S), and the client proof M1, following
// librist_crypto_srp_client_handle_B. It returns ErrBadParameter
// if B is empty, longer than len(N), congruent to zero mod N, or if the derived
// u is zero (the SRP-6a safety aborts). The base (B - k*(g^x mod N)) is reduced
// mod N before exponentiation, adding N if it is negative.
func (c *Client) ComputeKey(serverB []byte, username, password string) error {
	gr := c.group
	if len(serverB) == 0 || len(serverB) > gr.length {
		return ErrBadParameter
	}
	bPub := new(big.Int).SetBytes(serverB)

	// RFC 5054: client aborts if B mod N == 0.
	if new(big.Int).Mod(bPub, gr.N).Sign() == 0 {
		return ErrBadParameter
	}

	// u = H(PAD(A)|PAD(B)); abort if u mod N == 0.
	u := gr.uValue(c.pubA, bPub, c.legacyPad)
	if new(big.Int).Mod(u, gr.N).Sign() == 0 {
		return ErrBadParameter
	}

	k := gr.kValue(c.legacyPad)
	x := calcX(c.salt, username, password)

	// gx = g^x mod N (this is v).
	gx := new(big.Int).Exp(gr.G, x, gr.N)

	// base = (B - k*gx) mod N, normalised to [0, N) — the subtraction can be
	// negative before reduction (Go's Mod already returns a
	// non-negative result for a positive modulus, matching the +N fixup).
	kgx := new(big.Int).Mul(k, gx)
	base := new(big.Int).Sub(bPub, kgx)
	base.Mod(base, gr.N)

	// exp = a + u*x.
	ux := new(big.Int).Mul(u, x)
	exp := new(big.Int).Add(c.a, ux)

	// S = base^exp mod N.
	s := new(big.Int).Exp(base, exp, gr.N)

	c.key = sessionKey(s)
	c.m1 = gr.calcM1(username, c.salt, c.pubA, bPub, c.key)
	c.computed = true
	return nil
}

// M1 returns the 32-byte client proof, valid only after ComputeKey has
// succeeded; before that it returns nil.
func (c *Client) M1() []byte {
	if !c.computed {
		return nil
	}
	out := c.m1
	return out[:]
}

// VerifyM2 reports whether the server proof M2 matches H(A | M1 | K), using a
// constant-time comparison. It returns false if ComputeKey has not run or if
// m2 is not 32 bytes.
func (c *Client) VerifyM2(m2 []byte) bool {
	if !c.computed || len(m2) != hashLen {
		return false
	}
	want := calcM2(c.pubA, c.m1, c.key)
	return subtle.ConstantTimeCompare(want[:], m2) == 1
}

// SessionKey returns the 32-byte shared session key K = H(S), valid only after
// ComputeKey has succeeded; before that it returns nil. The returned slice is
// freshly allocated.
func (c *Client) SessionKey() []byte {
	if !c.computed {
		return nil
	}
	out := c.key
	return out[:]
}

// Server is an SRP-6a authenticator. It holds the group, salt, verifier v, the
// per-handshake secret b and public B, the client public A (after HandleA),
// and — after VerifyM1 succeeds — the shared session key K and the proof M2. A
// Server is single-use and not safe for concurrent use.
type Server struct {
	group     *Group
	salt      []byte
	v         *big.Int // verifier
	b         *big.Int // private secret
	pubB      *big.Int // B = (k*v + g^b) mod N
	pubA      *big.Int // client A, set by HandleA
	legacyPad bool

	verified bool
	key      [hashLen]byte // K = H(S)
	m2       [hashLen]byte // server proof
}

// NewServer creates an SRP-6a server for the group, verifier, and salt, drawing
// a random secret b from crypto/rand and computing B = (k*v + g^b) mod N,
// following librist_crypto_srp_authenticator_handle_A's B computation (which
// libRIST defers to handle_A but is deterministic given b). It
// returns an error for an invalid group, empty salt, empty or zero-mod-N
// verifier, a CSPRNG failure, or if the computed B is congruent to zero mod N.
func NewServer(g *Group, verifier, salt []byte) (*Server, error) {
	return newServer(g, verifier, salt, false, rand.Reader)
}

// NewServerLegacy is NewServer with the pre-0.2.16 unpadded k/u hashing
// (libRIST srp-compat=1). Use only to interoperate with old peers.
func NewServerLegacy(g *Group, verifier, salt []byte) (*Server, error) {
	return newServer(g, verifier, salt, true, rand.Reader)
}

func newServer(g *Group, verifier, salt []byte, legacyPad bool, src io.Reader) (*Server, error) {
	if !g.valid() {
		return nil, ErrInvalidGroup
	}
	if len(salt) == 0 {
		return nil, ErrInvalidSalt
	}
	if len(verifier) == 0 {
		return nil, ErrInvalidVerifier
	}
	v := new(big.Int).SetBytes(verifier)
	// RFC 5054: reject v == 0. We test v mod N == 0 so a
	// verifier supplied as a multiple of N is also rejected.
	if new(big.Int).Mod(v, g.N).Sign() == 0 {
		return nil, ErrInvalidVerifier
	}
	b, err := readSecret(src, g.N)
	if err != nil {
		return nil, err
	}
	s := &Server{
		group:     g,
		salt:      append([]byte(nil), salt...),
		v:         v,
		b:         b,
		legacyPad: legacyPad,
	}
	if err := s.computeB(); err != nil {
		return nil, err
	}
	return s, nil
}

// computeB sets B = (k*v + g^b) mod N, rejecting B == 0 mod N.
func (s *Server) computeB() error {
	gr := s.group
	k := gr.kValue(s.legacyPad)
	kv := new(big.Int).Mul(k, s.v)
	gb := new(big.Int).Exp(gr.G, s.b, gr.N)
	sum := new(big.Int).Add(kv, gb)
	s.pubB = sum.Mod(sum, gr.N)
	if s.pubB.Sign() == 0 {
		return ErrBadParameter
	}
	return nil
}

// B returns the server public value B = (k*v + g^b) mod N, big-endian and
// PADded to len(N) bytes. The returned slice is freshly allocated.
//
// As with A, libRIST's write_B_bytes returns the MINIMAL mpi_size(B)
// and EAP sends B at minimal length with an explicit length
// field, not padded to len(N); ristgo's deliberate PAD is
// value-preserving and interop-safe (the peer parses via SetBytes and
// u = H(PAD(A)|PAD(B)) re-pads).
func (s *Server) B() []byte {
	return s.group.pad(s.pubB)
}

// HandleA stores the client public value A and validates it, following
// librist_crypto_srp_authenticator_handle_A's A handling. It
// returns ErrBadParameter if A is empty, longer than len(N), or congruent to
// zero modulo N (the SRP-6a safety abort). It never panics on arbitrary input.
func (s *Server) HandleA(clientA []byte) error {
	gr := s.group
	if len(clientA) == 0 || len(clientA) > gr.length {
		return ErrBadParameter
	}
	a := new(big.Int).SetBytes(clientA)
	// RFC 5054 / SRP-6a: abort if A mod N == 0.
	if new(big.Int).Mod(a, gr.N).Sign() == 0 {
		return ErrBadParameter
	}
	s.pubA = a
	return nil
}

// VerifyM1 derives u, the premaster secret S = (A * v^u)^b mod N, the session
// key K = H(S), and the server-side M1, then compares M1 against the client's
// proof in constant time; on a match it computes M2 and returns true. It
// follows librist_crypto_srp_authenticator_verify_m1. It
// returns false if HandleA has not run, if m1 is not 32 bytes, if u is zero, or
// if the proof does not match.
func (s *Server) VerifyM1(username string, m1 []byte) bool {
	gr := s.group
	if s.pubA == nil || len(m1) != hashLen {
		return false
	}

	// u = H(PAD(A)|PAD(B)); abort if u mod N == 0.
	u := gr.uValue(s.pubA, s.pubB, s.legacyPad)
	if new(big.Int).Mod(u, gr.N).Sign() == 0 {
		return false
	}

	// S = (A * (v^u mod N))^b mod N.
	vu := new(big.Int).Exp(s.v, u, gr.N)
	avu := new(big.Int).Mul(s.pubA, vu)
	sShared := new(big.Int).Exp(avu, s.b, gr.N)

	s.key = sessionKey(sShared)
	want := gr.calcM1(username, s.salt, s.pubA, s.pubB, s.key)

	// Constant-time M1 comparison.
	if subtle.ConstantTimeCompare(want[:], m1) != 1 {
		return false
	}

	s.m2 = calcM2(s.pubA, want, s.key)
	s.verified = true
	return true
}

// M2 returns the 32-byte server proof, valid only after VerifyM1 has succeeded;
// before that it returns nil. The returned slice is freshly allocated.
func (s *Server) M2() []byte {
	if !s.verified {
		return nil
	}
	out := s.m2
	return out[:]
}

// SessionKey returns the 32-byte shared session key K = H(S), valid only after
// VerifyM1 has succeeded; before that it returns nil. The returned slice is
// freshly allocated.
func (s *Server) SessionKey() []byte {
	if !s.verified {
		return nil
	}
	out := s.key
	return out[:]
}

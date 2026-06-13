package eap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/zsiec/ristgo/internal/srp"
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

// goldenFrames are framing known-answer vectors: each Frame and its exact wire
// encoding. The bodies are small (short salt/A/B/proof) so the golden bytes are
// readable; the framing under test is the EAPOL/EAP/EAP-SRP header layout, not
// the SRP payload sizes.
func goldenFrames() []struct {
	name string
	f    Frame
	want []byte
} {
	salt := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	pub := []byte{0x01, 0x02, 0x03}
	proof := bytes.Repeat([]byte{0x5A}, proofLen)
	return []struct {
		name string
		f    Frame
		want []byte
	}{
		{
			name: "start",
			f:    Frame{Version: 3, Kind: KindStart},
			// EAPOL: ver=3, type=START(1), len=0.
			want: []byte{0x03, 0x01, 0x00, 0x00},
		},
		{
			name: "logoff",
			f:    Frame{Version: 3, Kind: KindLogoff},
			want: []byte{0x03, 0x02, 0x00, 0x00},
		},
		{
			name: "identity-request",
			f:    Frame{Version: 3, Code: CodeRequest, Identifier: 0x11, Kind: KindIdentityRequest},
			// EAPOL(ver=3,type=EAP,len=5) EAP(code=1,id=0x11,len=5) body=[1].
			want: []byte{0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x05, 0x01},
		},
		{
			name: "identity-response",
			f:    Frame{Version: 3, Code: CodeResponse, Identifier: 0x11, Kind: KindIdentityResponse, Username: "rist"},
			// body = [1] + "rist" => 5 bytes; EAP len = 4+5 = 9.
			want: append([]byte{0x03, 0x00, 0x00, 0x09, 0x02, 0x11, 0x00, 0x09, 0x01}, []byte("rist")...),
		},
		{
			name: "challenge-default-group",
			f:    Frame{Version: 3, Code: CodeRequest, Identifier: 0x22, Kind: KindChallenge, Salt: salt},
			// SRP body: type=19,sub=1, name_len=0, salt_len=4, salt, gen_len=0.
			// body len = 2 + 2 + (2+4) + 2 = 12; EAP len = 4+12 = 16.
			want: func() []byte {
				body := []byte{0x13, 0x01, 0x00, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00}
				out := []byte{0x03, 0x00, 0x00, byte(4 + len(body)), 0x01, 0x22, 0x00, byte(4 + len(body))}
				return append(out, body...)
			}(),
		},
		{
			name: "client-key",
			f:    Frame{Version: 3, Code: CodeResponse, Identifier: 0x22, Kind: KindClientKey, Public: pub},
			// SRP body: type=19, sub=1 (CHALLENGE in RESPONSE dir), A.
			want: func() []byte {
				body := append([]byte{0x13, 0x01}, pub...)
				out := []byte{0x03, 0x00, 0x00, byte(4 + len(body)), 0x02, 0x22, 0x00, byte(4 + len(body))}
				return append(out, body...)
			}(),
		},
		{
			name: "server-key",
			f:    Frame{Version: 3, Code: CodeRequest, Identifier: 0x23, Kind: KindServerKey, Public: pub},
			// SRP body: type=19, sub=2 (SERVER_KEY), B.
			want: func() []byte {
				body := append([]byte{0x13, 0x02}, pub...)
				out := []byte{0x03, 0x00, 0x00, byte(4 + len(body)), 0x01, 0x23, 0x00, byte(4 + len(body))}
				return append(out, body...)
			}(),
		},
		{
			name: "client-validator",
			f:    Frame{Version: 3, Code: CodeResponse, Identifier: 0x23, Kind: KindClientValidator, Proof: proof},
			// SRP body: type=19, sub=2 (CLIENT_VALIDATOR in RESPONSE dir),
			// 4-byte flags(0), M1(32). body len = 2+4+32 = 38; EAP = 42.
			want: func() []byte {
				body := append([]byte{0x13, 0x02, 0, 0, 0, 0}, proof...)
				out := []byte{0x03, 0x00, 0x00, byte(4 + len(body)), 0x02, 0x23, 0x00, byte(4 + len(body))}
				return append(out, body...)
			}(),
		},
		{
			name: "server-validator",
			f:    Frame{Version: 3, Code: CodeRequest, Identifier: 0x24, Kind: KindServerValidator, Proof: proof},
			// SRP body: type=19, sub=3 (SERVER_VALIDATOR), flags(0), M2(32).
			want: func() []byte {
				body := append([]byte{0x13, 0x03, 0, 0, 0, 0}, proof...)
				out := []byte{0x03, 0x00, 0x00, byte(4 + len(body)), 0x01, 0x24, 0x00, byte(4 + len(body))}
				return append(out, body...)
			}(),
		},
		{
			name: "failure",
			f:    Frame{Version: 3, Code: CodeFailure, Identifier: 0x24, Kind: KindFailure},
			// no body; EAP len = 4.
			want: []byte{0x03, 0x00, 0x00, 0x04, 0x04, 0x24, 0x00, 0x04},
		},
	}
}

// TestGoldenBytes asserts AppendTo produces the exact wire bytes for each
// EAP-SRP message kind.
func TestGoldenBytes(t *testing.T) {
	for _, tc := range goldenFrames() {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.f.AppendTo(nil)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("AppendTo mismatch\n got %X\nwant %X", got, tc.want)
			}
			if tc.f.MarshalSize() != len(tc.want) {
				t.Fatalf("MarshalSize = %d, want %d", tc.f.MarshalSize(), len(tc.want))
			}
		})
	}
}

// TestRoundTrip asserts Parse(AppendTo(x)) reproduces the semantic fields of
// each golden frame and that the re-encoding is byte-stable.
func TestRoundTrip(t *testing.T) {
	for _, tc := range goldenFrames() {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.f.AppendTo(nil)
			got, err := Parse(wire)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			// Re-encode must be byte-stable.
			if re := got.AppendTo(nil); !bytes.Equal(re, wire) {
				t.Fatalf("re-encode not stable\n got %X\nwant %X", re, wire)
			}
			// Compare the load-bearing fields.
			assertFieldsEqual(t, tc.f, got)
		})
	}
}

func assertFieldsEqual(t *testing.T, want, got Frame) {
	t.Helper()
	if got.Kind != want.Kind {
		t.Fatalf("Kind = %v, want %v", got.Kind, want.Kind)
	}
	if got.Code != want.Code && want.Kind != KindStart && want.Kind != KindLogoff {
		t.Fatalf("Code = %v, want %v", got.Code, want.Code)
	}
	if got.Identifier != want.Identifier && want.Kind != KindStart && want.Kind != KindLogoff {
		t.Fatalf("Identifier = %v, want %v", got.Identifier, want.Identifier)
	}
	if got.Username != want.Username {
		t.Fatalf("Username = %q, want %q", got.Username, want.Username)
	}
	if !bytes.Equal(got.Salt, want.Salt) {
		t.Fatalf("Salt = %X, want %X", got.Salt, want.Salt)
	}
	if !bytes.Equal(got.Public, want.Public) {
		t.Fatalf("Public = %X, want %X", got.Public, want.Public)
	}
	if !bytes.Equal(got.Proof, want.Proof) {
		t.Fatalf("Proof = %X, want %X", got.Proof, want.Proof)
	}
}

// TestHandshakeSuccess drives an in-memory client<->server EAP-SRP handshake to
// mutual SUCCESS and asserts the derived SRP session keys match.
func TestHandshakeSuccess(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := mustHex(t, "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)

	authee, err := NewAuthenticatee(user, pass)
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	auth, err := NewAuthenticator(StaticVerifier(user, verifier, salt))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	// The client opens with EAPOL-START.
	frame := authee.Start()
	// Drive the exchange: alternate the frame between the two roles, feeding
	// each the other's last output, until both are Done.
	transcript := []string{frame.Kind.String()}
	cur := frame
	turn := serverTurn // the server receives START first
	for steps := 0; steps < 12; steps++ {
		wire := cur.AppendTo(nil)
		var out *Frame
		var rerr error
		if turn == serverTurn {
			out, rerr = auth.Recv(wire)
		} else {
			out, rerr = authee.Recv(wire)
		}
		if rerr != nil {
			t.Fatalf("Recv at step %d (%s): %v", steps, cur.Kind, rerr)
		}
		if out == nil {
			break
		}
		transcript = append(transcript, out.Kind.String())
		cur = *out
		turn = !turn
	}

	if !authee.Authenticated() {
		t.Fatalf("authenticatee not authenticated; transcript=%v", transcript)
	}
	if !auth.Authenticated() {
		t.Fatalf("authenticator not authenticated; transcript=%v", transcript)
	}
	if !authee.Done() || !auth.Done() {
		t.Fatalf("roles not Done")
	}
	ck, sk := authee.SessionKey(), auth.SessionKey()
	if len(ck) != 32 || !bytes.Equal(ck, sk) {
		t.Fatalf("session keys differ\nclient %X\nserver %X", ck, sk)
	}
	t.Logf("transcript: %v", transcript)
}

type turnSide bool

const serverTurn turnSide = true

// TestHandshakeWrongPassword asserts that a client with the wrong password
// drives the authenticator to FAILURE (emitting an EAP-FAILURE and
// ErrAuthFailed), and that no session key is established.
func TestHandshakeWrongPassword(t *testing.T) {
	const user = "rist"
	salt := mustHex(t, "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, "rightpass", salt)

	authee, _ := NewAuthenticatee(user, "wrongpass")
	auth, _ := NewAuthenticator(StaticVerifier(user, verifier, salt))

	cur := authee.Start()
	turn := serverTurn
	var failErr error
	for steps := 0; steps < 12; steps++ {
		wire := cur.AppendTo(nil)
		var out *Frame
		var rerr error
		if turn == serverTurn {
			out, rerr = auth.Recv(wire)
		} else {
			out, rerr = authee.Recv(wire)
		}
		if rerr != nil {
			failErr = rerr
			// The server emits an EAP-FAILURE alongside the error; deliver
			// it to the client so it too goes FAILED.
			if out != nil {
				_, _ = authee.Recv(out.AppendTo(nil))
			}
			break
		}
		if out == nil {
			break
		}
		cur = *out
		turn = !turn
	}

	if failErr == nil {
		t.Fatalf("expected an authentication failure error")
	}
	if auth.Authenticated() {
		t.Fatalf("authenticator authenticated with wrong password")
	}
	if auth.State() != StateFailed {
		t.Fatalf("authenticator state = %v, want FAILED", auth.State())
	}
	if authee.Authenticated() {
		t.Fatalf("authenticatee authenticated with wrong password")
	}
	if auth.SessionKey() != nil {
		t.Fatalf("session key established despite failure")
	}
}

// TestHandshakeUnknownUser asserts the authenticator rejects an IDENTITY
// RESPONSE for a user with no verifier.
func TestHandshakeUnknownUser(t *testing.T) {
	auth, _ := NewAuthenticator(StaticVerifier("known", []byte{1}, []byte{2}))
	authee, _ := NewAuthenticatee("stranger", "pw")

	start := authee.Start()
	idReq, err := auth.Recv(start.AppendTo(nil))
	if err != nil {
		t.Fatalf("server START handling: %v", err)
	}
	idResp, err := authee.Recv(idReq.AppendTo(nil))
	if err != nil {
		t.Fatalf("client IDENTITY-REQUEST handling: %v", err)
	}
	if _, err := auth.Recv(idResp.AppendTo(nil)); err != ErrNoVerifier {
		t.Fatalf("err = %v, want ErrNoVerifier", err)
	}
	if auth.State() != StateFailed {
		t.Fatalf("state = %v, want FAILED", auth.State())
	}
}

// TestParseRejectsTruncated asserts truncated/garbage frames are rejected with
// an error and never panic.
func TestParseRejectsTruncated(t *testing.T) {
	cases := map[string][]byte{
		"empty":               nil,
		"one byte":            {0x03},
		"eapol hdr only":      {0x03, 0x00, 0x00, 0x05}, // claims 5 body bytes, none present
		"eap hdr truncated":   {0x03, 0x00, 0x00, 0x02, 0x01, 0x11},
		"eap len mismatch":    {0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x09, 0x01},
		"unknown eapol type":  {0x03, 0x09, 0x00, 0x00},
		"srp truncated":       {0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x05, 0x13},
		"unknown method type": {0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x05, 0x07},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(in); err == nil {
				t.Fatalf("Parse(%X) = nil error, want error", in)
			}
		})
	}
}

// TestParseChallengeBounds asserts the CHALLENGE TLV length checks reject
// overruns without panicking.
func TestParseChallengeBounds(t *testing.T) {
	// name_len that overruns the buffer.
	body := []byte{0x13, 0x01, 0xFF, 0xFF}
	wire := wrapSRP(t, CodeRequest, 0x01, body)
	if _, err := Parse(wire); err == nil {
		t.Fatalf("expected error for overrunning name_len")
	}
	// Valid name_len=0 but salt_len overruns.
	body = []byte{0x13, 0x01, 0x00, 0x00, 0x00, 0x10}
	wire = wrapSRP(t, CodeRequest, 0x01, body)
	if _, err := Parse(wire); err == nil {
		t.Fatalf("expected error for overrunning salt_len")
	}
}

// wrapSRP wraps a raw EAP body (starting with the SRP type byte) in EAPOL+EAP
// headers with a correct length field, for negative-path framing tests.
func wrapSRP(t *testing.T, code Code, id uint8, body []byte) []byte {
	t.Helper()
	eapLen := eapHdrSize + len(body)
	out := []byte{0x03, 0x00, byte(eapLen >> 8), byte(eapLen), byte(code), id, byte(eapLen >> 8), byte(eapLen)}
	return append(out, body...)
}

// TestKindString exercises the String methods for coverage and stability.
func TestKindString(t *testing.T) {
	kinds := []Kind{
		KindStart, KindLogoff, KindIdentityRequest, KindIdentityResponse,
		KindChallenge, KindClientKey, KindServerKey, KindClientValidator,
		KindServerValidator, KindSuccess, KindFailure, KindUnknown,
	}
	for _, k := range kinds {
		if k.String() == "" {
			t.Fatalf("empty string for kind %d", k)
		}
	}
	for _, s := range []State{StateUnauth, StateInProgress, StateSuccess, StateFailed, State(99)} {
		if s.String() == "" {
			t.Fatalf("empty string for state %d", s)
		}
	}
}

// TestChallengeGroupRejectsExplicit asserts an explicit (g,N) challenge is
// rejected, since only the default group is supported.
func TestChallengeGroupRejectsExplicit(t *testing.T) {
	f := Frame{Kind: KindChallenge, Salt: []byte{1, 2, 3, 4}, GenG: []byte{2}, GenN: bytes.Repeat([]byte{0xFF}, 256)}
	if _, err := challengeGroup(f); err != ErrUnsupportedGroup {
		t.Fatalf("err = %v, want ErrUnsupportedGroup", err)
	}
}

// TestParseDoesNotAlias asserts parsed slices do not alias the input buffer.
func TestParseDoesNotAlias(t *testing.T) {
	f := Frame{Version: 3, Code: CodeResponse, Identifier: 1, Kind: KindIdentityResponse, Username: "abc"}
	wire := f.AppendTo(nil)
	got, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Mutate the original buffer; parsed fields must be unaffected.
	for i := range wire {
		wire[i] = 0
	}
	if got.Username != "abc" {
		t.Fatalf("Username aliased input: %q", got.Username)
	}
}

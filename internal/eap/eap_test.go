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

// driveExchange runs the SRP exchange from an opening frame (the server receives it
// first) until both roles stop emitting, returning the transcript. Shared by the
// success and re-auth tests.
func driveExchange(t *testing.T, authee *Authenticatee, auth *Authenticator, open Frame) []string {
	t.Helper()
	transcript := []string{open.Kind.String()}
	cur := open
	turn := serverTurn
	for steps := 0; steps < 12; steps++ {
		var (
			out  *Frame
			rerr error
		)
		if turn == serverTurn {
			out, rerr = auth.Recv(cur.AppendTo(nil))
		} else {
			out, rerr = authee.Recv(cur.AppendTo(nil))
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
	return transcript
}

// TestHandshakeReauth proves a session can RE-AUTHENTICATE after reaching SUCCESS: the
// authenticatee Restart()s and re-opens with an EAPOL-START, the authenticator (already
// SUCCESS) accepts it as a re-auth and re-runs the exchange, and both reach SUCCESS again
// with a FRESH session key (fresh SRP nonces) — the replay-proof identity proof the
// NAT-rebind re-association relies on. The keying generation advances so the host
// re-derives the data-channel key.
func TestHandshakeReauth(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := mustHex(t, "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)

	authee, err := NewAuthenticatee(user, pass)
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	authee.UseKeyAsPassphrase(true)
	auth, err := NewAuthenticator(StaticVerifier(user, verifier, salt))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	auth.UseKeyAsPassphrase(true)

	driveExchange(t, authee, auth, authee.Start())
	if !authee.Authenticated() || !auth.Authenticated() {
		t.Fatal("first handshake did not authenticate both roles")
	}
	k1 := append([]byte(nil), authee.SessionKey()...)
	if len(k1) != 32 {
		t.Fatalf("first session key length %d, want 32", len(k1))
	}
	txGen1, _ := auth.TxKeying()

	// Re-authenticate: the authenticatee resets and re-opens; the authenticator accepts
	// the post-SUCCESS START as a re-auth.
	authee.Restart()
	tr := driveExchange(t, authee, auth, authee.Start())
	if !authee.Authenticated() || !auth.Authenticated() {
		t.Fatalf("re-auth did not authenticate both roles; transcript=%v", tr)
	}
	k2 := authee.SessionKey()
	if len(k2) != 32 || !bytes.Equal(k2, auth.SessionKey()) {
		t.Fatalf("re-auth session keys differ or wrong length")
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("re-auth produced the same session key — fresh nonces should yield a fresh K")
	}
	// The authenticator's TX keying generation must advance so the host re-keys.
	if txGen2, ok := auth.TxKeying(); !ok || txGen2.Gen <= txGen1.Gen {
		t.Fatalf("authenticator TX keying gen did not advance: %d -> %d (ok=%v)", txGen1.Gen, txGen2.Gen, ok)
	}
}

// TestAuthenticateeRejectsStaleReauthFrames proves the re-auth gate: an authenticatee in
// SUCCESS ignores a CHALLENGE/SERVER_KEY/SERVER_VALIDATOR that arrives without a fresh
// IDENTITY REQUEST (a replayed/forged frame must not knock a live session out of SUCCESS),
// while a genuine IDENTITY REQUEST resets it cleanly for a re-auth.
func TestAuthenticateeRejectsStaleReauthFrames(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := mustHex(t, "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)
	authee, _ := NewAuthenticatee(user, pass)
	auth, _ := NewAuthenticator(StaticVerifier(user, verifier, salt))
	driveExchange(t, authee, auth, authee.Start())
	if !authee.Authenticated() {
		t.Fatal("setup: authenticatee not authenticated")
	}

	// An injected CHALLENGE (with an in-window identifier) from SUCCESS must be ignored:
	// no reply, and the session stays SUCCESS.
	stale := Frame{Version: 3, Code: CodeRequest, Identifier: authee.id + 1, Kind: KindChallenge, Salt: salt}
	out, err := authee.Recv(stale.AppendTo(nil))
	if err != nil {
		t.Fatalf("stale CHALLENGE returned error: %v", err)
	}
	if out != nil {
		t.Fatalf("stale CHALLENGE was answered (kind=%v); it must be ignored", out.Kind)
	}
	if !authee.Authenticated() {
		t.Fatal("stale CHALLENGE knocked the authenticatee out of SUCCESS")
	}

	// A genuine IDENTITY REQUEST is a re-auth: it resets the authenticatee (no longer
	// SUCCESS) and is answered with an IDENTITY RESPONSE.
	req := Frame{Version: 3, Code: CodeRequest, Identifier: 9, Kind: KindIdentityRequest}
	out, err = authee.Recv(req.AppendTo(nil))
	if err != nil {
		t.Fatalf("re-auth IDENTITY REQUEST returned error: %v", err)
	}
	if out == nil || out.Kind != KindIdentityResponse {
		t.Fatalf("re-auth IDENTITY REQUEST not answered with IDENTITY RESPONSE, got %v", out)
	}
	if authee.Authenticated() {
		t.Fatal("authenticatee still reports SUCCESS mid-re-auth after an IDENTITY REQUEST")
	}
}

// TestReplayedFailureCannotTearDownSuccess proves a replayed/forged EAP-FAILURE cannot knock
// a live authenticated session out of SUCCESS — for EITHER role — even when it echoes the
// last identifier (the value left in a.id after SUCCESS, which is observable on the wire).
// EAPOL is never encrypted, so a FAILURE is trivially forgeable; honoring one in SUCCESS
// would let an off-path attacker drop an established session with a single spoofed datagram.
func TestReplayedFailureCannotTearDownSuccess(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := mustHex(t, "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)
	authee, _ := NewAuthenticatee(user, pass)
	auth, _ := NewAuthenticator(StaticVerifier(user, verifier, salt))
	driveExchange(t, authee, auth, authee.Start())
	if !authee.Authenticated() || !auth.Authenticated() {
		t.Fatal("setup: both roles must be authenticated")
	}

	// Authenticatee: a FAILURE echoing its last identifier must be ignored (no reply, stays
	// SUCCESS). Try a.id and a.id±1 to cover the identifiers an observer could replay.
	for _, id := range []uint8{authee.id, authee.id + 1, authee.id - 1} {
		fail := Frame{Version: 3, Code: CodeFailure, Identifier: id, Kind: KindFailure}
		out, err := authee.Recv(fail.AppendTo(nil))
		if err != nil {
			t.Fatalf("authenticatee FAILURE(id=%d) returned error: %v", id, err)
		}
		if out != nil {
			t.Fatalf("authenticatee answered a FAILURE(id=%d): %v", id, out.Kind)
		}
		if !authee.Authenticated() {
			t.Fatalf("authenticatee FAILURE(id=%d) knocked it out of SUCCESS", id)
		}
	}

	// Authenticator: same — a forged FAILURE in SUCCESS must not reach StateFailed.
	for _, id := range []uint8{auth.id, auth.id + 1, auth.id - 1} {
		fail := Frame{Version: 3, Code: CodeFailure, Identifier: id, Kind: KindFailure}
		out, err := auth.Recv(fail.AppendTo(nil))
		if err != nil {
			t.Fatalf("authenticator FAILURE(id=%d) returned error: %v", id, err)
		}
		if out != nil {
			t.Fatalf("authenticator answered a FAILURE(id=%d): %v", id, out.Kind)
		}
		if !auth.Authenticated() {
			t.Fatalf("authenticator FAILURE(id=%d) knocked it out of SUCCESS", id)
		}
	}
}

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

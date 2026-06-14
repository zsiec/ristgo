package eap

import (
	"bytes"
	"errors"
	"testing"

	"github.com/zsiec/ristgo/internal/srp"
)

// staticLookup returns a VerifierLookup serving one provisioned user.
func staticLookup(user string, verifier, salt []byte) VerifierLookup {
	return func(u string) ([]byte, []byte, bool) {
		if u == user {
			return verifier, salt, true
		}
		return nil, nil, false
	}
}

// TestOutOfOrderRejected verifies that an SRP step arriving before its
// prerequisite is rejected with ErrUnexpected and fails the role, mirroring
// libRIST's EAP_UNEXPECTEDREQUEST/RESPONSE rejections.
func TestOutOfOrderRejected(t *testing.T) {
	// Authenticatee: SERVER_KEY before a CHALLENGE created the client.
	authee, err := NewAuthenticatee("rist", "mainprofile")
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	sk := Frame{Version: 3, Code: CodeRequest, Kind: KindServerKey, Public: bytes.Repeat([]byte{1}, 256)}
	if _, err := authee.Recv(sk.AppendTo(nil)); !errors.Is(err, ErrUnexpected) {
		t.Fatalf("SERVER_KEY before CHALLENGE: err=%v, want ErrUnexpected", err)
	}
	if authee.State() != StateFailed {
		t.Fatalf("authenticatee state=%v, want FAILED", authee.State())
	}

	// Authenticator: CLIENT_KEY before an IDENTITY RESPONSE created the server.
	auth, err := NewAuthenticator(staticLookup("rist", nil, nil))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	ck := Frame{Version: 3, Code: CodeResponse, Kind: KindClientKey, Public: bytes.Repeat([]byte{1}, 256)}
	if _, err := auth.Recv(ck.AppendTo(nil)); !errors.Is(err, ErrUnexpected) {
		t.Fatalf("CLIENT_KEY before IDENTITY: err=%v, want ErrUnexpected", err)
	}
}

// TestSeedIdentifier verifies the host can seed the authenticator's EAP
// identifier (to match libRIST's randomized seed) before Start, and that it is
// frozen afterward.
func TestSeedIdentifier(t *testing.T) {
	auth, err := NewAuthenticator(staticLookup("rist", nil, nil))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	auth.SeedIdentifier(0x5A)
	if got := auth.Start().Identifier; got != 0x5A {
		t.Fatalf("seeded IDENTITY REQUEST identifier = %#x, want 0x5A", got)
	}
	auth.SeedIdentifier(0x99) // no effect once started
	if auth.id != 0x5A {
		t.Fatalf("SeedIdentifier changed the identifier after Start: %#x", auth.id)
	}
}

// TestAuthenticatorDefersSuccessToAck drives a full handshake and asserts the
// authenticator does NOT reach terminal SUCCESS when it verifies M1 and sends
// the SERVER_VALIDATOR — only after the client's closing EAP-SUCCESS ack, as
// libRIST does (sets authenticated; reaches SUCCESS on the ack).
func TestAuthenticatorDefersSuccessToAck(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := bytes.Repeat([]byte{0x42}, 32)
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)

	auth, err := NewAuthenticator(staticLookup(user, verifier, salt))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	authee, err := NewAuthenticatee(user, pass)
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}

	cur := authee.Start()
	turn := serverTurn
	sawM2 := false
	for steps := 0; steps < 12; steps++ {
		wire := cur.AppendTo(nil)
		var out *Frame
		var rerr error
		serverReceiving := turn == serverTurn
		if serverReceiving {
			out, rerr = auth.Recv(wire)
		} else {
			out, rerr = authee.Recv(wire)
		}
		if rerr != nil {
			t.Fatalf("Recv at step %d: %v", steps, rerr)
		}
		// The server's reply carrying M2 means it has just verified M1; it must
		// not yet be at terminal SUCCESS (that is deferred to the client ack).
		if serverReceiving && out != nil && out.Kind == KindServerValidator {
			sawM2 = true
			if auth.Authenticated() {
				t.Fatal("authenticator reached SUCCESS on M1 verify, before the client's ack")
			}
		}
		if out == nil {
			break
		}
		cur = *out
		turn = !turn
	}
	if !sawM2 {
		t.Fatal("never observed the SERVER_VALIDATOR (M2) step")
	}
	if !auth.Authenticated() || !authee.Authenticated() {
		t.Fatalf("handshake did not reach mutual SUCCESS after the ack (auth=%v authee=%v)", auth.State(), authee.State())
	}
}

// TestStaleFailureDropped verifies a FAILURE whose identifier does not match
// the in-flight request is dropped (not force-failing the session), while a
// matching-identifier FAILURE does fail it.
func TestStaleFailureDropped(t *testing.T) {
	authee, err := NewAuthenticatee("rist", "mainprofile")
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	authee.Start() // StateInProgress
	// Process an IDENTITY REQUEST with identifier 7 so the live identifier is 7.
	idReq := Frame{Version: 3, Code: CodeRequest, Identifier: 7, Kind: KindIdentityRequest}
	if _, err := authee.Recv(idReq.AppendTo(nil)); err != nil {
		t.Fatalf("IDENTITY REQUEST: %v", err)
	}
	// A FAILURE with a different identifier must be dropped silently.
	stale := Frame{Version: 3, Code: CodeFailure, Identifier: 9, Kind: KindFailure}
	if out, err := authee.Recv(stale.AppendTo(nil)); out != nil || err != nil {
		t.Fatalf("stale FAILURE: out=%v err=%v, want (nil,nil)", out, err)
	}
	if authee.State() == StateFailed {
		t.Fatal("a stale-identifier FAILURE force-failed the session")
	}
	// A matching-identifier FAILURE does fail the session.
	match := Frame{Version: 3, Code: CodeFailure, Identifier: 7, Kind: KindFailure}
	if _, err := authee.Recv(match.AppendTo(nil)); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("matching FAILURE: err=%v, want ErrAuthFailed", err)
	}
}

// TestParseEdgeKinds covers parse branches not exercised by the golden vectors:
// the password subtype (0x10) maps to KindPasswordRequest (REQUEST) or
// KindPasswordResponse (RESPONSE), a bodyless SERVER_VALIDATOR RESPONSE (subtype
// 3) parses with no proof, and a CLIENT_VALIDATOR with a too-short proof is
// rejected.
func TestParseEdgeKinds(t *testing.T) {
	// EAPOL(ver=3,type=EAP,len=6) EAP(code,id,len=6) EAP-SRP(type=0x13,subtype).
	frame := func(code byte, srpHdr ...byte) []byte {
		body := append([]byte{0x13}, srpHdr...)
		eapLen := byte(4 + len(body))
		out := []byte{0x03, 0x00, 0x00, eapLen, code, 0x01, 0x00, eapLen}
		return append(out, body...)
	}

	// Password subtype (0x10), REQUEST (code 1) -> KindPasswordRequest, no body.
	f, err := Parse(frame(0x01, 0x10))
	if err != nil || f.Kind != KindPasswordRequest {
		t.Fatalf("password request: kind=%v err=%v, want KindPasswordRequest,nil", f.Kind, err)
	}

	// Password subtype (0x10), RESPONSE (code 2) with a flag byte ->
	// KindPasswordResponse carrying the flag byte (bit 7 = use session key).
	f, err = Parse(frame(0x02, 0x10, 0x80))
	if err != nil || f.Kind != KindPasswordResponse || !f.PwUseSessionKey() {
		t.Fatalf("password response: kind=%v useSession=%v err=%v", f.Kind, f.PwUseSessionKey(), err)
	}

	// Bodyless SERVER_VALIDATOR RESPONSE (subtype 3, no flags/proof).
	f, err = Parse(frame(0x02, 0x03))
	if err != nil || f.Kind != KindServerValidator || len(f.Proof) != 0 {
		t.Fatalf("bodyless server-validator: kind=%v proof=%d err=%v", f.Kind, len(f.Proof), err)
	}

	// CLIENT_VALIDATOR (RESPONSE subtype 2) with 4 flag bytes + a short proof.
	short := append([]byte{0x13, 0x02, 0, 0, 0, 0}, 1, 2, 3) // 3-byte proof < proofLen
	eapLen := byte(4 + len(short))
	raw := append([]byte{0x03, 0x00, 0x00, eapLen, 0x02, 0x01, 0x00, eapLen}, short...)
	if _, err := Parse(raw); err == nil {
		t.Fatal("short CLIENT_VALIDATOR proof: got nil error, want rejection")
	}
}

// TestSpoofedSuccessCannotDefeatFailureGate verifies that a spoofed no-op frame
// (a SUCCESS, or an unexpected frame) cannot overwrite the authenticatee's
// tracked identifier and thereby make a legitimate in-flight FAILURE be dropped.
// The identifier is adopted only from a legitimately processed request.
func TestSpoofedSuccessCannotDefeatFailureGate(t *testing.T) {
	authee, err := NewAuthenticatee("rist", "mainprofile")
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	authee.Start()
	idReq := Frame{Version: 3, Code: CodeRequest, Identifier: 7, Kind: KindIdentityRequest}
	if _, err := authee.Recv(idReq.AppendTo(nil)); err != nil {
		t.Fatalf("IDENTITY REQUEST: %v", err)
	}
	// Attacker injects a SUCCESS with a bogus identifier; it is a no-op and must
	// NOT change the tracked identifier (which stays 7).
	spoof := Frame{Version: 3, Code: CodeSuccess, Identifier: 99, Kind: KindSuccess}
	if out, err := authee.Recv(spoof.AppendTo(nil)); out != nil || err != nil {
		t.Fatalf("spoofed SUCCESS: out=%v err=%v, want (nil,nil)", out, err)
	}
	// The legitimate FAILURE for the live exchange (id 7) must still fail it.
	fail := Frame{Version: 3, Code: CodeFailure, Identifier: 7, Kind: KindFailure}
	if _, err := authee.Recv(fail.AppendTo(nil)); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("legit FAILURE after spoofed SUCCESS: err=%v, want ErrAuthFailed (identifier was corrupted)", err)
	}
}

// TestAuthenticatorStartGuardAndLogoff verifies the authenticator ignores a
// spurious mid-handshake EAPOL-START (so a spoofed START cannot reset the live
// exchange) and treats EAPOL-LOGOFF as a reset to UNAUTH rather than an error.
func TestAuthenticatorStartGuardAndLogoff(t *testing.T) {
	salt := make([]byte, 32)
	verifier := srp.MakeVerifier(srp.DefaultGroup(), "user", "pass", salt)
	a, err := NewAuthenticator(func(u string) ([]byte, []byte, bool) {
		if u == "user" {
			return verifier, salt, true
		}
		return nil, nil, false
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	a.Start() // -> IN-PROGRESS
	idResp := Frame{Version: 3, Code: CodeResponse, Identifier: a.id, Kind: KindIdentityResponse, Username: "user"}
	if _, err := a.Recv(idResp.AppendTo(nil)); err != nil {
		t.Fatalf("identity response: %v", err)
	}
	// A spurious START once the SRP exchange has begun is ignored, not answered.
	start := Frame{Version: 3, Kind: KindStart}
	if out, err := a.Recv(start.AppendTo(nil)); out != nil || err != nil {
		t.Fatalf("mid-handshake START: out=%v err=%v, want (nil,nil)", out, err)
	}
	// EAPOL-LOGOFF resets to UNAUTH (no error).
	logoff := Frame{Version: 3, Kind: KindLogoff}
	if out, err := a.Recv(logoff.AppendTo(nil)); out != nil || err != nil {
		t.Fatalf("LOGOFF: out=%v err=%v, want (nil,nil)", out, err)
	}
	if a.State() != StateUnauth {
		t.Fatalf("after LOGOFF state=%v, want UNAUTH", a.State())
	}
}

// driveToSuccess runs a full EAP-SRP handshake between a freshly created
// authenticator and authenticatee, returning both roles at mutual terminal
// SUCCESS. It fails the test if the handshake does not complete.
func driveToSuccess(t *testing.T, user, pass string, salt []byte) (*Authenticator, *Authenticatee) {
	t.Helper()
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)
	auth, err := NewAuthenticator(staticLookup(user, verifier, salt))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	authee, err := NewAuthenticatee(user, pass)
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	cur := authee.Start()
	turn := serverTurn // the server receives START first
	for steps := 0; steps < 12; steps++ {
		var out *Frame
		var rerr error
		if turn == serverTurn {
			out, rerr = auth.Recv(cur.AppendTo(nil))
		} else {
			out, rerr = authee.Recv(cur.AppendTo(nil))
		}
		if rerr != nil {
			t.Fatalf("Recv at step %d: %v", steps, rerr)
		}
		if out == nil {
			break
		}
		cur = *out
		turn = !turn
	}
	if !auth.Authenticated() || !authee.Authenticated() {
		t.Fatalf("handshake did not reach mutual SUCCESS (auth=%v authee=%v)", auth.State(), authee.State())
	}
	return auth, authee
}

// TestAuthenticatorLogoffRefusedAfterSuccess is the M4 regression guard: an
// EAPOL-LOGOFF is unauthenticated and trivially spoofable, so once the
// authenticator has reached terminal SUCCESS a (possibly off-path) LOGOFF must
// NOT tear the session back down. It must be refused with ErrUnexpected and
// leave the SUCCESS state and session key intact, matching libRIST, which
// returns EAP_UNEXPECTEDREQUEST and does not reset at/above SUCCESS.
func TestAuthenticatorLogoffRefusedAfterSuccess(t *testing.T) {
	auth, _ := driveToSuccess(t, "rist", "mainprofile", bytes.Repeat([]byte{0x42}, 32))
	if auth.State() != StateSuccess {
		t.Fatalf("precondition: authenticator state=%v, want SUCCESS", auth.State())
	}
	keyBefore := auth.SessionKey()

	// A spoofed LOGOFF after SUCCESS must be refused, not honored.
	logoff := Frame{Version: 3, Kind: KindLogoff}
	out, err := auth.Recv(logoff.AppendTo(nil))
	if !errors.Is(err, ErrUnexpected) {
		t.Fatalf("post-SUCCESS LOGOFF: err=%v, want ErrUnexpected", err)
	}
	if out != nil {
		t.Fatalf("post-SUCCESS LOGOFF produced a reply frame %v, want none", out.Kind)
	}
	if auth.State() != StateSuccess {
		t.Fatalf("post-SUCCESS LOGOFF reset the session to %v, want SUCCESS", auth.State())
	}
	if !bytes.Equal(auth.SessionKey(), keyBefore) || len(keyBefore) != 32 {
		t.Fatal("post-SUCCESS LOGOFF disturbed the established session key")
	}
}

// TestAuthenticatorLogoffHonoredWhileOpen is the companion to the M4 guard: a
// LOGOFF arriving while the handshake is still open (UNAUTH or IN-PROGRESS) is
// still honored and resets to UNAUTH, so the hardening does not over-reach.
func TestAuthenticatorLogoffHonoredWhileOpen(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) *Authenticator
	}{
		{
			name: "unauth",
			setup: func(t *testing.T) *Authenticator {
				a, err := NewAuthenticator(staticLookup("user", nil, nil))
				if err != nil {
					t.Fatalf("NewAuthenticator: %v", err)
				}
				return a
			},
		},
		{
			name: "in-progress",
			setup: func(t *testing.T) *Authenticator {
				salt := make([]byte, 32)
				verifier := srp.MakeVerifier(srp.DefaultGroup(), "user", "pass", salt)
				a, err := NewAuthenticator(staticLookup("user", verifier, salt))
				if err != nil {
					t.Fatalf("NewAuthenticator: %v", err)
				}
				a.Start()
				idResp := Frame{Version: 3, Code: CodeResponse, Identifier: a.id, Kind: KindIdentityResponse, Username: "user"}
				if _, err := a.Recv(idResp.AppendTo(nil)); err != nil {
					t.Fatalf("identity response: %v", err)
				}
				if a.State() != StateInProgress {
					t.Fatalf("precondition: state=%v, want IN-PROGRESS", a.State())
				}
				return a
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.setup(t)
			logoff := Frame{Version: 3, Kind: KindLogoff}
			out, err := a.Recv(logoff.AppendTo(nil))
			if out != nil || err != nil {
				t.Fatalf("open-state LOGOFF: out=%v err=%v, want (nil,nil)", out, err)
			}
			if a.State() != StateUnauth {
				t.Fatalf("open-state LOGOFF: state=%v, want UNAUTH", a.State())
			}
		})
	}
}

// TestAuthenticateeIgnoresUnexpectedIdentifier is the L10 regression guard: the
// authenticatee adopts a server-driven SRP request's identifier into a.id, so
// an off-path injected request carrying an unexpected identifier could poison
// a.id and prime a spoofed-FAILURE DoS. The authenticatee must instead ignore a
// server-driven request whose identifier is neither the expected next one
// (a.id+1) nor a retransmit of the current one (a.id), leaving a.id intact.
func TestAuthenticateeIgnoresUnexpectedIdentifier(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := bytes.Repeat([]byte{0x42}, 32)
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)

	// Bring the authenticatee to a live exchange: process IDENTITY REQUEST (id 7)
	// then the matching CHALLENGE (id 8), so a.id is 8 and a client exists.
	authee, err := NewAuthenticatee(user, pass)
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	authee.Start()
	idReq := Frame{Version: 3, Code: CodeRequest, Identifier: 7, Kind: KindIdentityRequest}
	if _, err := authee.Recv(idReq.AppendTo(nil)); err != nil {
		t.Fatalf("IDENTITY REQUEST: %v", err)
	}
	chal := Frame{Version: 3, Code: CodeRequest, Identifier: 8, Kind: KindChallenge, Salt: salt}
	if _, err := authee.Recv(chal.AppendTo(nil)); err != nil {
		t.Fatalf("CHALLENGE: %v", err)
	}
	if authee.id != 8 {
		t.Fatalf("precondition: a.id=%d, want 8", authee.id)
	}

	// An off-path SERVER_KEY with a bogus identifier (neither 8 nor 9) must be
	// ignored — no reply, no error — and must NOT poison a.id.
	bogus := Frame{Version: 3, Code: CodeRequest, Identifier: 200, Kind: KindServerKey, Public: bytes.Repeat([]byte{1}, 256)}
	if out, err := authee.Recv(bogus.AppendTo(nil)); out != nil || err != nil {
		t.Fatalf("bogus-identifier SERVER_KEY: out=%v err=%v, want (nil,nil)", out, err)
	}
	if authee.id != 8 {
		t.Fatalf("bogus-identifier SERVER_KEY poisoned a.id to %d, want 8 unchanged", authee.id)
	}
	if authee.State() == StateFailed {
		t.Fatal("bogus-identifier SERVER_KEY failed the session")
	}

	// Because a.id is still 8, a spoofed FAILURE keyed on the injected id 200 is
	// still dropped (the poisoning attack is defeated)...
	spoofFail := Frame{Version: 3, Code: CodeFailure, Identifier: 200, Kind: KindFailure}
	if out, err := authee.Recv(spoofFail.AppendTo(nil)); out != nil || err != nil {
		t.Fatalf("spoofed FAILURE(id=200): out=%v err=%v, want (nil,nil)", out, err)
	}
	if authee.State() == StateFailed {
		t.Fatal("spoofed FAILURE(id=200) force-failed the session via a poisoned identifier")
	}

	// ...while the legitimate next SERVER_KEY (id 9 = a.id+1) is still accepted
	// and advances the exchange (the matching verifier/salt prove the path).
	srv, err := srp.NewServer(srp.DefaultGroup(), verifier, salt)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.HandleA(authee.client.A()); err != nil {
		t.Fatalf("HandleA: %v", err)
	}
	serverKey := Frame{Version: 3, Code: CodeRequest, Identifier: 9, Kind: KindServerKey, Public: srv.B()}
	out, err := authee.Recv(serverKey.AppendTo(nil))
	if err != nil {
		t.Fatalf("legit SERVER_KEY(id=9): %v", err)
	}
	if out == nil || out.Kind != KindClientValidator {
		t.Fatalf("legit SERVER_KEY(id=9): out=%v, want CLIENT_VALIDATOR", out)
	}
	if authee.id != 9 {
		t.Fatalf("legit SERVER_KEY(id=9): a.id=%d, want 9", authee.id)
	}
}

// driveHandshake runs the full SRP handshake between authee and auth (alternating
// frames), returning the post-handshake transcript. It stops when a role returns
// no reply. It does not drive the post-SUCCESS PASSWORD exchange (that is
// caller-driven via PasswordRequest).
func driveHandshake(t *testing.T, authee *Authenticatee, auth *Authenticator) {
	t.Helper()
	cur := authee.Start()
	turn := serverTurn
	for steps := 0; steps < 14; steps++ {
		wire := cur.AppendTo(nil)
		var out *Frame
		var err error
		if turn == serverTurn {
			out, err = auth.Recv(wire)
		} else {
			out, err = authee.Recv(wire)
		}
		if err != nil {
			t.Fatalf("Recv at step %d (%s): %v", steps, cur.Kind, err)
		}
		if out == nil {
			return
		}
		cur = *out
		turn = !turn
	}
}

// TestUseKeyAsPassphraseKeying drives the full EAP-SRP handshake plus the
// post-SUCCESS PASSWORD exchange in use_key_as_passphrase mode, asserting the
// inline M2 keying (authenticator TX = K, authenticatee RX = K) and the 0x10
// exchange (the authenticatee requests, the authenticator responds bit-7, the
// authenticatee installs its RX = K). It verifies the keying material is the
// 32-byte SRP session key K and matches on both ends.
func TestUseKeyAsPassphraseKeying(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := mustHex(t, "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)

	authee, _ := NewAuthenticatee(user, pass)
	authee.UseKeyAsPassphrase(true)
	auth, _ := NewAuthenticator(staticLookup(user, verifier, salt))
	auth.UseKeyAsPassphrase(true)

	driveHandshake(t, authee, auth)
	if !authee.Authenticated() || !auth.Authenticated() {
		t.Fatalf("handshake did not authenticate (authee=%v auth=%v)", authee.Authenticated(), auth.Authenticated())
	}

	K := authee.SessionKey()
	if len(K) != 32 || !bytes.Equal(K, auth.SessionKey()) {
		t.Fatalf("session keys differ or wrong length")
	}

	// After M2 the authenticator has keyed its TX = K (it encrypts the
	// receiver->sender feedback under K); the authenticatee has keyed its RX = K
	// (from the M2 set_passphrase bit) so it can decrypt that feedback.
	tx, ok := auth.TxKeying()
	if !ok || !bytes.Equal(tx.Key, K) {
		t.Fatalf("authenticator TxKeying: ok=%v matchesK=%v", ok, bytes.Equal(tx.Key, K))
	}
	rx, ok := authee.RxKeying()
	if !ok || !bytes.Equal(rx.Key, K) {
		t.Fatalf("authenticatee RxKeying: ok=%v matchesK=%v", ok, bytes.Equal(rx.Key, K))
	}
	// The authenticatee never keys its TX (its media is sent in the clear,
	// matching libRIST). The authenticator never keys its RX (the media direction
	// is cleartext, decoded per-packet on the GRE K bit).
	if _, ok := authee.TxKeying(); ok {
		t.Fatal("authenticatee should NOT key its TX (media is cleartext)")
	}
	if _, ok := auth.RxKeying(); ok {
		t.Fatal("authenticator should NOT key its RX from the handshake (media is cleartext)")
	}

	// Drive the post-SUCCESS PASSWORD exchange: the authenticatee requests, the
	// authenticator responds with bit-7 (use session key), the authenticatee
	// acknowledges. This confirms (re-installs) the authenticatee's RX = K.
	req, ok := authee.PasswordRequest()
	if !ok {
		t.Fatal("authenticatee did not produce a PASSWORD_REQUEST after SUCCESS")
	}
	if req.Kind != KindPasswordRequest {
		t.Fatalf("PasswordRequest kind = %v, want KindPasswordRequest", req.Kind)
	}
	resp, err := auth.Recv(req.AppendTo(nil))
	if err != nil {
		t.Fatalf("authenticator processing PASSWORD_REQUEST: %v", err)
	}
	if resp == nil || resp.Kind != KindPasswordResponse || !resp.PwUseSessionKey() {
		t.Fatalf("authenticator response = %v useSession=%v", resp, resp != nil && resp.PwUseSessionKey())
	}
	ack, err := authee.Recv(resp.AppendTo(nil))
	if err != nil {
		t.Fatalf("authenticatee processing PASSWORD_RESPONSE: %v", err)
	}
	if ack == nil || ack.Kind != KindSuccess {
		t.Fatalf("authenticatee did not ack the PASSWORD_RESPONSE with SUCCESS: %v", ack)
	}
	// The RX key remains K (re-installed; its generation advanced).
	rx2, _ := authee.RxKeying()
	if !bytes.Equal(rx2.Key, K) {
		t.Fatal("authenticatee RX key changed after the PASSWORD exchange")
	}
	if rx2.Gen <= rx.Gen {
		t.Fatalf("RX keying generation did not advance on re-install: %d <= %d", rx2.Gen, rx.Gen)
	}
}

// TestM2SetPassphraseBitOnWire asserts the authenticator's M2 carries the
// set_passphrase bit (bit 0 of the 4-byte flags word's last byte) in
// use_key_as_passphrase mode, and that an authenticator WITHOUT the mode does not
// set it.
func TestM2SetPassphraseBitOnWire(t *testing.T) {
	const user, pass = "rist", "mainprofile"
	salt := mustHex(t, "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)

	for _, useKey := range []bool{true, false} {
		authee, _ := NewAuthenticatee(user, pass)
		auth, _ := NewAuthenticator(staticLookup(user, verifier, salt))
		if useKey {
			authee.UseKeyAsPassphrase(true)
			auth.UseKeyAsPassphrase(true)
		}
		// Drive only up to M2 (the SERVER_VALIDATOR the authenticator emits).
		cur := authee.Start()
		turn := serverTurn
		var m2 *Frame
		for steps := 0; steps < 14 && m2 == nil; steps++ {
			wire := cur.AppendTo(nil)
			var out *Frame
			var err error
			if turn == serverTurn {
				out, err = auth.Recv(wire)
			} else {
				out, err = authee.Recv(wire)
			}
			if err != nil {
				t.Fatalf("useKey=%v Recv: %v", useKey, err)
			}
			if out == nil {
				break
			}
			if out.Kind == KindServerValidator {
				parsed, perr := Parse(out.AppendTo(nil))
				if perr != nil {
					t.Fatalf("parse M2: %v", perr)
				}
				m2 = &parsed
			}
			cur = *out
			turn = !turn
		}
		if m2 == nil {
			t.Fatalf("useKey=%v: never observed M2", useKey)
		}
		if m2.SetPassphrase() != useKey {
			t.Fatalf("useKey=%v: M2 SetPassphrase()=%v, want %v (flags=%x)", useKey, m2.SetPassphrase(), useKey, m2.Flags)
		}
	}
}

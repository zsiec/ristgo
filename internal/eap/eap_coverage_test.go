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
// the password subtype (0x10) maps to KindUnknown, a bodyless SERVER_VALIDATOR
// RESPONSE (subtype 3) parses with no proof, and a CLIENT_VALIDATOR with a
// too-short proof is rejected.
func TestParseEdgeKinds(t *testing.T) {
	// EAPOL(ver=3,type=EAP,len=6) EAP(code,id,len=6) EAP-SRP(type=0x13,subtype).
	frame := func(code byte, srpHdr ...byte) []byte {
		body := append([]byte{0x13}, srpHdr...)
		eapLen := byte(4 + len(body))
		out := []byte{0x03, 0x00, 0x00, eapLen, code, 0x01, 0x00, eapLen}
		return append(out, body...)
	}

	// Password subtype (0x10) -> KindUnknown, no error.
	f, err := Parse(frame(0x02, 0x10))
	if err != nil || f.Kind != KindUnknown {
		t.Fatalf("password subtype: kind=%v err=%v, want KindUnknown,nil", f.Kind, err)
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

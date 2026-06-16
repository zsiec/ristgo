package session

import (
	"testing"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/eap"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/srp"
)

// driveEAPToSuccess runs a full EAP-SRP handshake between a standalone authenticatee and
// authenticator until both reach SUCCESS, so a test can then exercise post-SUCCESS session
// behavior on the authenticator.
func driveEAPToSuccess(t *testing.T, authee *eap.Authenticatee, auth *eap.Authenticator) {
	t.Helper()
	cur := authee.Start()
	serverTurn := true // the authenticator processes the opening START first
	for i := 0; i < 12; i++ {
		var (
			out *eap.Frame
			err error
		)
		if serverTurn {
			out, err = auth.Recv(cur.AppendTo(nil))
		} else {
			out, err = authee.Recv(cur.AppendTo(nil))
		}
		if err != nil {
			t.Fatalf("Recv at step %d: %v", i, err)
		}
		if out == nil {
			break
		}
		cur = *out
		serverTurn = !serverTurn
	}
	if !authee.Authenticated() || !auth.Authenticated() {
		t.Fatal("setup: handshake did not authenticate both roles")
	}
}

// newAuthedReceiverSession builds a minimal authenticated Main-receiver Session around a
// freshly-SUCCESS authenticator, with no codec/socket (s.main nil), so handleEAP's state
// transitions can be driven directly: sendEAP and installEAPKeying are no-ops without a
// codec, and the data-channel gate (authed) and re-auth bookkeeping are exercised in
// isolation.
func newAuthedReceiverSession(t *testing.T) *Session {
	t.Helper()
	const user, pass = "rist", "mainprofile"
	salt := []byte("0123456789abcdef0123456789abcdef")
	verifier := srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt)
	authee, err := eap.NewAuthenticatee(user, pass)
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	auth, err := eap.NewAuthenticator(eap.StaticVerifier(user, verifier, salt))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	driveEAPToSuccess(t, authee, auth)

	s := &Session{
		eapServer: auth,
		cfg: Config{
			KeepaliveInterval: clock.Millisecond * 1000,
			SessionTimeout:    clock.Millisecond * 2000,
			Flow:              flow.Config{RecoveryBufferMax: clock.Millisecond * 1000},
		},
	}
	// Mirror the post-SUCCESS session state handleEAP would have established.
	s.authed.Store(true)
	s.everAuthed = true
	return s
}

// TestHandleEAPHoldsMediaOnForcedReauth proves the F1 fix: when an inbound EAPOL frame
// regresses an already-authenticated role OUT of SUCCESS (an in-band re-auth — the genuine
// peer re-proving, OR a forged cleartext EAPOL frame spoofed from the peer's tuple, since
// EAPOL is never encrypted), the session DROPS the data-channel gate and arms a bounded
// re-auth window, rather than continuing to deliver media under the now-desynced handshake.
func TestHandleEAPHoldsMediaOnForcedReauth(t *testing.T) {
	s := newAuthedReceiverSession(t)
	now := clock.NewMockClock().Now()

	// A forged EAPOL-START (valid frame, unauthenticated) from the established tuple forces
	// the authenticator to re-open its handshake. The session must hold media.
	start := mustStartFrame(t)
	s.handleEAP(now, start.AppendTo(nil))

	if s.authed.Load() {
		t.Fatal("authed not dropped: media would be delivered under a desynced re-auth")
	}
	if !s.reauthing {
		t.Fatal("reauthing not armed after a forced re-auth")
	}
	if !s.reauthDeadline.After(now) {
		t.Fatalf("reauthDeadline %v not after now %v: the re-auth window is not bounded", s.reauthDeadline, now)
	}
}

// TestHandleEAPForgedFailureDoesNotTearDown proves a forged EAPOL-FAILURE cannot drop a live
// authenticated session: handleEAP keeps authed true and does not enter the re-auth hold.
func TestHandleEAPForgedFailureDoesNotTearDown(t *testing.T) {
	s := newAuthedReceiverSession(t)
	now := clock.NewMockClock().Now()

	fail := eap.Frame{Version: 3, Code: eap.CodeFailure, Kind: eap.KindFailure}
	s.handleEAP(now, fail.AppendTo(nil))

	if !s.authed.Load() {
		t.Fatal("a forged FAILURE dropped the data channel of a live authenticated session")
	}
	if s.reauthing {
		t.Fatal("a forged FAILURE put the session into a re-auth hold")
	}
}

// mustStartFrame returns a valid EAPOL-START frame (as a fresh authenticatee would emit) to
// stand in for a forged re-auth trigger.
func mustStartFrame(t *testing.T) eap.Frame {
	t.Helper()
	a, err := eap.NewAuthenticatee("x", "y")
	if err != nil {
		t.Fatalf("NewAuthenticatee: %v", err)
	}
	return a.Start()
}

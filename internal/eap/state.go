package eap

import (
	"crypto/subtle"
	"errors"

	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/srp"
)

// State is the EAP authentication state of a role, mirroring libRIST's
// EAP_AUTH_STATE_*. The wire timers and retry counts that drive the full
// libRIST state machine live in the host; this package tracks only the
// handshake progression and the terminal authenticated/failed outcome.
type State uint8

// Authentication states.
const (
	// StateUnauth is the initial state: no handshake completed (UNAUTH).
	StateUnauth State = iota
	// StateInProgress means the handshake has begun but not yet succeeded or
	// failed (no direct libRIST analog; a refinement of UNAUTH for the host).
	StateInProgress
	// StateSuccess means authentication succeeded (SUCCESS).
	StateSuccess
	// StateFailed means authentication failed (FAILED).
	StateFailed
)

// Passphrase is data-channel keying material the EAP-SRP handshake installs for
// one direction (transmit or receive) under the use_key_as_passphrase mode. The
// host polls TxKeying / RxKeying after pumping a role and, when a Passphrase
// becomes available (or its Gen advances), (re)derives the corresponding
// Main-profile PSK key from it.
type Passphrase struct {
	// Key is the raw passphrase bytes the host runs through PBKDF2 (no
	// NUL-truncation). For the inline M1/M2 keying and the bit-7 PASSWORD-RESPONSE
	// it is the 32-byte SRP session key K; for an explicit (bit-6) push it is the
	// decrypted explicit passphrase. The host must not log it.
	Key []byte
	// Gen increments each time new keying material is installed for this
	// direction, so the host can detect a rollover even if the bytes repeat.
	Gen uint64
}

// keying tracks the installed transmit/receive passphrases for a role under the
// use_key_as_passphrase mode, shared by both Authenticatee and Authenticator.
type keying struct {
	enabled bool // use_key_as_passphrase configured for this role
	tx      Passphrase
	rx      Passphrase
}

func (k *keying) setTx(key []byte) {
	k.tx.Key = append([]byte(nil), key...)
	k.tx.Gen++
}

func (k *keying) setRx(key []byte) {
	k.rx.Key = append([]byte(nil), key...)
	k.rx.Gen++
}

// String returns a human-readable name for the state.
func (s State) String() string {
	switch s {
	case StateUnauth:
		return "UNAUTH"
	case StateInProgress:
		return "IN-PROGRESS"
	case StateSuccess:
		return "SUCCESS"
	case StateFailed:
		return "FAILED"
	default:
		return "INVALID"
	}
}

// Authenticatee is the EAP-SRP client role (the side being authenticated, e.g.
// a RIST sender). The host drives it by handing received EAPOL payloads to
// Recv and transmitting any returned Frame. It is sans-I/O and single-use; it
// is not safe for concurrent use. It corresponds to the EAP_ROLE_AUTHENTICATEE
// paths in libRIST.
type Authenticatee struct {
	username string
	password string

	state State
	id    uint8 // last EAP identifier adopted from a processed request, echoed on responses
	// idValid reports whether id reflects an adopted in-flight request (i.e. at
	// least one request has been processed). Until then there is nothing to gate
	// a subsequent request's identifier against, so the first request bootstraps
	// the sequence.
	idValid bool

	client  *srp.Client
	salt    []byte
	session []byte // SRP session key K, valid after success

	// keying carries the use_key_as_passphrase data-channel keying state. The
	// client does NOT key its own TX from K (it sends media in the clear, matching
	// libRIST, which sets use_key_as_passphrase only on the authenticator); it
	// installs K as its RX passphrase from the server's M2 set_passphrase bit and
	// from the server's PASSWORD-RESPONSE, so it can decrypt the server's encrypted
	// feedback.
	keying keying
	// pwReqID is the identifier of the post-SUCCESS PASSWORD_REQUEST the client
	// drives (eap_request_passphrase, called from process_eap_request_srp_server_
	// validator on reaching SUCCESS). pwReqActive gates the matching response.
	pwReqID     uint8
	pwReqActive bool
}

// NewAuthenticatee creates an EAP-SRP client for the given credentials. The
// username and password must be non-empty (libRIST bounds both at 1..255
// bytes); this constructor enforces non-emptiness.
func NewAuthenticatee(username, password string) (*Authenticatee, error) {
	if username == "" || password == "" {
		return nil, ErrEmptyCredentials
	}
	if len(username) > 255 || len(password) > 255 {
		return nil, ErrCredentialsTooLong
	}
	return &Authenticatee{username: username, password: password}, nil
}

// UseKeyAsPassphrase enables the EAP-SRP use_key_as_passphrase data-channel
// keying: the SRP session key K is installed as the Main-profile media
// passphrase for both directions (libRIST's mode when no pre-shared secret is
// configured). Call it before Start. It is a no-op once the handshake has begun.
func (a *Authenticatee) UseKeyAsPassphrase(enabled bool) {
	if a.state == StateUnauth {
		a.keying.enabled = enabled
	}
}

// TxKeying returns the transmit-direction data-channel passphrase the handshake
// installed (the SRP session key K under use_key_as_passphrase) and whether any
// is available. The host polls it after pumping the role; a Gen advance signals
// a rollover.
func (a *Authenticatee) TxKeying() (Passphrase, bool) {
	return a.keying.tx, a.keying.tx.Key != nil
}

// RxKeying returns the receive-direction data-channel passphrase the handshake
// installed and whether any is available.
func (a *Authenticatee) RxKeying() (Passphrase, bool) {
	return a.keying.rx, a.keying.rx.Key != nil
}

// PasswordRequest returns the post-SUCCESS EAP PASSWORD_REQUEST (subtype 0x10)
// the authenticatee (RIST sender) sends after verifying M2 to solicit the
// receiver's data-channel keying confirmation (eap_request_passphrase, invoked
// from process_eap_request_srp_server_validator on reaching SUCCESS). It returns
// ok=false unless the handshake has succeeded under use_key_as_passphrase. The
// identifier carries libRIST's bit-7 (authenticatee role) and bit-6 markers and
// gates the matching PASSWORD_RESPONSE. The host sends it once on SUCCESS.
func (a *Authenticatee) PasswordRequest() (Frame, bool) {
	if a.state != StateSuccess || !a.keying.enabled {
		return Frame{}, false
	}
	// eap_request_passphrase(start=true): bump the identifier and set bit 7 (the
	// authenticatee role marker) and bit 6.
	a.pwReqID++
	a.pwReqID |= 1 << pwUseSessionKeyBit // SET_BIT(.., 7) for the authenticatee
	a.pwReqID |= 1 << pwExplicitBit      // SET_BIT(.., 6)
	a.pwReqActive = true
	return Frame{
		Version:    eapVersion3,
		Code:       CodeRequest,
		Identifier: a.pwReqID,
		Kind:       KindPasswordRequest,
	}, true
}

// State returns the current authentication state.
func (a *Authenticatee) State() State { return a.state }

// Done reports whether the handshake has reached a terminal state (success or
// failure); the host stops pumping the role once Done is true.
func (a *Authenticatee) Done() bool {
	return a.state == StateSuccess || a.state == StateFailed
}

// Authenticated reports whether authentication succeeded.
func (a *Authenticatee) Authenticated() bool { return a.state == StateSuccess }

// SessionKey returns the SRP session key K derived during a successful
// handshake, or nil before then. It is the same K the peer derives and is what
// the RIST PSK key-rollover path keys on.
func (a *Authenticatee) SessionKey() []byte {
	return append([]byte(nil), a.session...)
}

// Start returns the EAPOL-START frame that opens the handshake from the client
// side (_librist_proto_eap_start, called for a non-multicast authenticatee in
// rist_enable_eap_srp_2). The host sends it and then pumps Recv with whatever
// the authenticator replies.
func (a *Authenticatee) Start() Frame {
	if a.state == StateUnauth {
		a.state = StateInProgress
	}
	return startFrame()
}

// Restart resets the authenticatee to the unauthenticated state so a fresh handshake can
// re-run (EAP re-authentication — e.g. after a NAT source-port rebind). Credentials and
// the use_key_as_passphrase keying state (its Gen) are preserved, so a successful re-auth
// ROLLS the data-channel keys rather than resetting them, and the host detects the new K
// via the advanced Gen. The host re-emits the EAPOL-Start after calling this.
func (a *Authenticatee) Restart() {
	a.state = StateUnauth
	a.id = 0 // the next IDENTITY REQUEST re-bootstraps it; a stale value would widen the gate
	a.idValid = false
	a.client = nil
	a.salt = nil
	a.session = nil
	a.pwReqActive = false
}

// Recv processes one received EAPOL frame (raw wire bytes as delivered out of
// the GRE EAPOL frame) and returns the frame to transmit in reply, if any. A
// nil out frame with a nil error means the input was handled with nothing to
// send. It never panics on arbitrary input. On a definitive authentication
// failure it sets the state to StateFailed and returns ErrAuthFailed.
func (a *Authenticatee) Recv(payload []byte) (out *Frame, err error) {
	f, err := Parse(payload)
	if err != nil {
		return nil, err
	}
	return a.handle(f)
}

// negotiatedVersion returns the EAPOL version to emit in reply to req: the peer's
// legacy version 2 when it advertises it, otherwise the current version 3.
// libRIST drives BOTH the on-wire version byte and the SRP hashing mode (PAD vs
// the pre-0.2.16 unpadded k/u) from the authenticator's advertised version, so a
// reply must echo it rather than hardcode 3 — otherwise a legacy (srp-compat=1)
// libRIST peer cannot interoperate.
func negotiatedVersion(req Frame) uint8 {
	if req.Version == 2 {
		return 2
	}
	return eapVersion3
}

// handle drives the authenticatee state machine for a parsed frame.
func (a *Authenticatee) handle(f Frame) (*Frame, error) {
	if f.Kind == KindFailure {
		// Honor a FAILURE only while a handshake is actually in flight (StateInProgress)
		// and only when its identifier matches the in-flight request. In StateSuccess a
		// FAILURE is stale or forged: a live authenticated session is re-proven via a
		// fresh IDENTITY REQUEST (the SUCCESS-state gate below), never torn down by an
		// injected FAILURE — so a replayed FAILURE echoing the last identifier cannot
		// knock us out of SUCCESS. (StateUnauth has no exchange to fail; StateFailed is
		// already terminal.) The identifier is adopted (below) only from a processed
		// request, so a.id tracks the live exchange.
		if a.state != StateInProgress || f.Identifier != a.id {
			return nil, nil
		}
		a.state = StateFailed
		return nil, ErrAuthFailed
	}
	// Re-authentication gate: a re-auth MUST begin with a fresh IDENTITY REQUEST. Once
	// SUCCESS has been reached, a CHALLENGE/SERVER_KEY/SERVER_VALIDATOR arriving with no
	// intervening IDENTITY REQUEST is stale or forged — ignore it so a replayed/injected
	// frame cannot knock a live session out of SUCCESS and restart its SRP state. A genuine
	// IDENTITY REQUEST while in SUCCESS is the authenticator driving a re-auth: reset to a
	// clean slate here so Done()/Authenticated() correctly report the re-auth as in progress
	// (rather than answering from stale client/session state while still reporting SUCCESS).
	if a.state == StateSuccess {
		switch f.Kind {
		case KindIdentityRequest:
			a.Restart()
		case KindChallenge, KindServerKey, KindServerValidator:
			return nil, nil
		}
	}
	// NOTE: the request identifier is adopted into a.id only inside the cases
	// that legitimately process a request (below), NEVER in the prologue. Doing
	// it here would let an unauthenticated spoofed frame — a no-op SUCCESS or a
	// rejected/unexpected frame — overwrite a.id and so defeat the
	// stale-FAILURE-identifier gate above. libRIST hardened exactly this path
	// (it assigns last_identifier only after subtype validation passes).
	//
	// Identifier gate (mirrors the authenticator's up-front gate): the
	// authenticator drives the SRP exchange with a fresh, per-request
	// incrementing identifier (IDENTITY_REQUEST → CHALLENGE → SERVER_KEY →
	// SERVER_VALIDATOR), so each successive server-driven request carries
	// a.id+1, and an authenticator retransmit repeats a.id. Once an in-flight
	// request has been adopted, only accept (and so adopt) a server-driven SRP
	// request whose identifier is the expected next one or a retransmit of the
	// current one; ignore anything else. Without this an off-path injected frame
	// could poison a.id and prime a spoofed-FAILURE handshake DoS (the SRP key
	// agreement itself stays safe — a forged validator fails VerifyM2). The
	// IDENTITY_REQUEST that opens the exchange is exempt: it bootstraps the
	// sequence, as libRIST's process_eap_request_identity accepts any identifier.
	if a.idValid && (f.Kind == KindChallenge || f.Kind == KindServerKey || f.Kind == KindServerValidator) {
		if f.Identifier != a.id && f.Identifier != a.id+1 {
			return nil, nil
		}
	}
	switch f.Kind {
	case KindIdentityRequest:
		// Reply with our identity (process_eap_request_identity).
		a.id = f.Identifier // echoed on our reply; tracks the live exchange
		a.idValid = true
		if a.state == StateUnauth {
			a.state = StateInProgress
		}
		out := Frame{
			Version:    negotiatedVersion(f),
			Code:       CodeResponse,
			Identifier: f.Identifier,
			Kind:       KindIdentityResponse,
			Username:   a.username,
		}
		return &out, nil

	case KindChallenge:
		// Create the SRP client and send CLIENT_KEY(A)
		// (process_eap_request_srp_challenge).
		grp, err := challengeGroup(f)
		if err != nil {
			a.state = StateFailed
			return nil, err
		}
		if len(f.Salt) == 0 {
			a.state = StateFailed
			return nil, ErrBadLength
		}
		// The challenge's version selects the SRP hashing mode for the rest of
		// the handshake: legacy (pre-0.2.16, unpadded k/u) for version 2, the
		// PAD-compliant mode for version 3 (libRIST process_eap_request_srp_challenge).
		newClient := srp.NewClient
		if negotiatedVersion(f) == 2 {
			newClient = srp.NewClientLegacy
		}
		client, err := newClient(grp, f.Salt)
		if err != nil {
			a.state = StateFailed
			return nil, errors.Join(ErrSRP, err)
		}
		a.id = f.Identifier // adopt only now that the challenge is accepted
		a.idValid = true
		a.client = client
		a.salt = f.Salt
		a.state = StateInProgress
		out := Frame{
			Version:    negotiatedVersion(f),
			Code:       CodeResponse,
			Identifier: f.Identifier,
			Kind:       KindClientKey,
			Public:     client.A(),
		}
		return &out, nil

	case KindServerKey:
		// Derive K and M1 from B, send CLIENT_VALIDATOR(M1)
		// (process_eap_request_srp_server_key).
		if a.client == nil {
			a.state = StateFailed
			return nil, ErrUnexpected
		}
		a.id = f.Identifier // adopt only now that the frame is in-sequence
		a.idValid = true
		if err := a.client.ComputeKey(f.Public, a.username, a.password); err != nil {
			// libRIST treats a bad B as a permanent failure.
			a.state = StateFailed
			return nil, errors.Join(ErrSRP, err)
		}
		out := Frame{
			Version:    negotiatedVersion(f),
			Code:       CodeResponse,
			Identifier: f.Identifier,
			Kind:       KindClientValidator,
			Proof:      a.client.M1(),
		}
		// NOTE: the authenticatee (client) does NOT set the M1 set_passphrase bit
		// and does NOT key its TX from K. libRIST only sets use_key_as_passphrase on
		// the AUTHENTICATOR (rist_enable_eap_srp_2), so the client's M1 keying branch
		// (process_eap_request_srp_server_key) never fires: the client sends its
		// media in the CLEAR. The client's RX is keyed from the server's M2
		// set_passphrase bit (below) so it can decrypt the server's encrypted
		// feedback; the server keys its own RX from the post-SUCCESS PASSWORD
		// exchange. This asymmetry is verified against libRIST on the wire (the
		// sender->receiver GRE datagrams carry no K bit).
		return &out, nil

	case KindServerValidator:
		// Verify M2; success or permanent failure
		// (process_eap_request_srp_server_validator).
		if a.client == nil || len(f.Proof) == 0 {
			a.state = StateFailed
			return nil, ErrAuthFailed
		}
		a.id = f.Identifier // adopt only now that the frame is in-sequence
		a.idValid = true
		if !a.client.VerifyM2(f.Proof) {
			a.state = StateFailed
			return nil, ErrAuthFailed
		}
		a.session = a.client.SessionKey()
		// use_key_as_passphrase inline keying (process_eap_request_srp_server_
		// validator): if the server set the set_passphrase bit in M2, install K as
		// our RX passphrase (v3-only). Net with the M1 keying above: client TX =
		// server RX = K and server TX = client RX = K, so both GRE directions key
		// from K.
		if f.SetPassphrase() && negotiatedVersion(f) == eapVersion3 {
			a.keying.setRx(a.client.SessionKey())
		}
		a.state = StateSuccess
		// Acknowledge with the closing v3 EAP-SUCCESS, echoing the request
		// identifier. This is what drives the authenticator to its terminal
		// SUCCESS; without it the peer waits on its retransmit timer.
		ack := Frame{
			Version:    negotiatedVersion(f),
			Code:       CodeSuccess,
			Identifier: f.Identifier,
			Kind:       KindSuccess,
		}
		return &ack, nil

	case KindSuccess:
		// The authenticatee normally SENDS the closing SUCCESS rather than
		// receiving one; tolerate a received SUCCESS as a no-op
		// (process_eap_succes).
		return nil, nil

	case KindPasswordRequest:
		// An unsolicited PASSWORD_REQUEST (the peer soliciting our passphrase).
		// In the client role this is uncommon — the client is normally the one
		// requesting — but libRIST's handler is symmetric. Under
		// use_key_as_passphrase reply with the bit-7 "use session key" flag.
		if a.state != StateSuccess {
			return nil, nil
		}
		return a.passwordResponse(f.Identifier), nil

	case KindPasswordResponse:
		// The receiver's reply to our post-SUCCESS PASSWORD_REQUEST
		// (process_eap_response_passphrase, requester side). When a request is
		// outstanding, accept only an identifier-matching response (anti-replay,
		// constant-time). Install K (bit 7) or the explicit AES-CTR-under-K
		// passphrase (bit 6) as our RX key — so we can decrypt the receiver's
		// encrypted feedback — then acknowledge with EAP-SUCCESS.
		if a.state != StateSuccess {
			return nil, nil
		}
		if a.pwReqActive && subtle.ConstantTimeCompare([]byte{f.Identifier}, []byte{a.pwReqID}) != 1 {
			return nil, nil
		}
		if err := installPushedRx(&a.keying, a.session, f); err != nil {
			return nil, err
		}
		a.pwReqActive = false
		ack := Frame{
			Version:    negotiatedVersion(f),
			Code:       CodeSuccess,
			Identifier: f.Identifier,
			Kind:       KindSuccess,
		}
		return &ack, nil

	default:
		return nil, ErrUnexpected
	}
}

// Authenticator is the EAP-SRP server role (the side verifying a peer, e.g. a
// RIST receiver/listener). The host drives it by handing received EAPOL
// payloads to Recv and transmitting any returned Frame; it opens the handshake
// with Start. It is sans-I/O and single-use; it is not safe for concurrent
// use. It corresponds to the EAP_ROLE_AUTHENTICATOR paths in libRIST.
type Authenticator struct {
	lookup VerifierLookup

	// version is the EAPOL version this authenticator advertises in every REQUEST
	// it originates (IDENTITY_REQUEST → CHALLENGE → SERVER_KEY → SERVER_VALIDATOR
	// and the post-SUCCESS PASSWORD exchange). It is eapVersion3 (RFC 5054
	// PAD-compliant) for the default NewAuthenticator and eapVersion2 (legacy
	// unpadded k/u) for NewAuthenticatorLegacy. The version byte is the in-band
	// signal that drives the authenticatee into the matching SRP hashing mode
	// (negotiatedVersion), so it MUST agree with legacyPad below.
	version uint8
	// legacyPad selects the pre-0.2.16 unpadded k/u SRP hashing (srp.NewServerLegacy)
	// instead of the PAD-compliant srp.NewServer. It is true exactly when version is
	// eapVersion2.
	legacyPad bool

	state State
	id    uint8 // last EAP identifier we issued (incremented per request)

	server   *srp.Server
	username string
	session  []byte
	verified bool // M1 verified; terminal SUCCESS is deferred to the client's ack
	// everAuthed records that this authenticator reached SUCCESS at least once. Once true,
	// a spoofed EAPOL-LOGOFF can no longer tear the exchange down even while a re-auth is
	// IN-PROGRESS (an established session is only re-proven, never reset, by the peer).
	everAuthed bool

	// keying carries the use_key_as_passphrase data-channel keying state. When
	// enabled, the authenticator keys its TX from K in M2 (signalling it with the
	// set_passphrase bit), so it can encrypt the receiver->sender feedback. It does
	// NOT key its RX from K: libRIST's authenticatee sends its media in the clear,
	// so the receiver decodes media per-packet on the GRE K bit (cleartext). The
	// authenticator responds to the authenticatee's post-SUCCESS PASSWORD_REQUEST
	// with a bit-7 PASSWORD_RESPONSE (process_eap_request_srp_passphrase), which is
	// how the authenticatee confirms its RX key.
	keying keying
}

// NewAuthenticator creates an EAP-SRP server that resolves verifiers via the
// supplied lookup callback (ctx->config.lookup_func). lookup must be non-nil. It
// advertises EAPOL version 3 and uses the RFC 5054 PAD-compliant SRP hashing
// (the libRIST 0.2.16+ default); for interop with a legacy (pre-0.2.16,
// srp-compat=1) peer use NewAuthenticatorLegacy instead.
func NewAuthenticator(lookup VerifierLookup) (*Authenticator, error) {
	return newAuthenticator(lookup, eapVersion3, false)
}

// NewAuthenticatorLegacy creates an EAP-SRP server in the legacy (pre-0.2.16,
// libRIST srp-compat=1) compatibility mode: it advertises EAPOL version 2 in
// every REQUEST it originates and uses the unpadded k = H(N|g) / u = H(A|B) SRP
// hashing (srp.NewServerLegacy) instead of the PAD-compliant default. The version
// byte drives the authenticatee into the matching legacy SRP math, so the whole
// handshake — CHALLENGE → SERVER_KEY/M1 → SERVER_VALIDATOR/M2 → SUCCESS, plus the
// use_key_as_passphrase keying — runs in legacy mode end to end. Use only to
// interoperate with old peers; the default and required path is NewAuthenticator.
// lookup must be non-nil.
func NewAuthenticatorLegacy(lookup VerifierLookup) (*Authenticator, error) {
	return newAuthenticator(lookup, eapVersion2, true)
}

// newAuthenticator constructs an Authenticator with the given on-wire EAPOL
// version and SRP hashing mode, shared by NewAuthenticator (version 3, PAD) and
// NewAuthenticatorLegacy (version 2, legacy unpadded k/u).
func newAuthenticator(lookup VerifierLookup, version uint8, legacyPad bool) (*Authenticator, error) {
	if lookup == nil {
		return nil, ErrNilLookup
	}
	return &Authenticator{lookup: lookup, version: version, legacyPad: legacyPad}, nil
}

// SeedIdentifier sets the initial EAP identifier the authenticator issues. To
// match libRIST's unpredictable-on-the-wire identifier (it seeds it from a
// random byte) the host should pass a crypto/rand byte before
// Start; the default zero is fine for a trusted in-process path. It has no
// effect once the handshake has begun.
func (a *Authenticator) SeedIdentifier(id uint8) {
	if a.state == StateUnauth {
		a.id = id
	}
}

// State returns the current authentication state.
func (a *Authenticator) State() State { return a.state }

// Done reports whether the handshake has reached a terminal state.
func (a *Authenticator) Done() bool {
	return a.state == StateSuccess || a.state == StateFailed
}

// Authenticated reports whether the peer authenticated successfully
// (eap_is_authenticated).
func (a *Authenticator) Authenticated() bool { return a.state == StateSuccess }

// SessionKey returns the SRP session key K derived during a successful
// handshake, or nil before then.
func (a *Authenticator) SessionKey() []byte {
	return append([]byte(nil), a.session...)
}

// UseKeyAsPassphrase enables the EAP-SRP use_key_as_passphrase data-channel
// keying (see Authenticatee.UseKeyAsPassphrase). Call it before Start.
func (a *Authenticator) UseKeyAsPassphrase(enabled bool) {
	if a.state == StateUnauth {
		a.keying.enabled = enabled
	}
}

// TxKeying returns the transmit-direction data-channel passphrase the handshake
// installed (K under use_key_as_passphrase) and whether any is available.
func (a *Authenticator) TxKeying() (Passphrase, bool) {
	return a.keying.tx, a.keying.tx.Key != nil
}

// RxKeying returns the receive-direction data-channel passphrase the handshake
// installed and whether any is available.
func (a *Authenticator) RxKeying() (Passphrase, bool) {
	return a.keying.rx, a.keying.rx.Key != nil
}

// Start returns the EAP IDENTITY REQUEST that opens the handshake from the
// server side (eap_request_identity). The identifier starts at
// zero (or the SeedIdentifier value) and increments per request; call
// SeedIdentifier with a crypto/rand byte beforehand to match libRIST's
// unpredictable-on-the-wire identifier.
func (a *Authenticator) Start() Frame {
	if a.state == StateUnauth {
		a.state = StateInProgress
	}
	return Frame{
		Version:    a.version,
		Code:       CodeRequest,
		Identifier: a.id,
		Kind:       KindIdentityRequest,
	}
}

// Restart resets the authenticator to the unauthenticated state for a fresh handshake
// (EAP re-authentication). The verifier lookup, advertised version, and keying Gen are
// preserved; the EAP identifier advances so the re-auth's requests are distinct on the
// wire. A subsequent Start re-opens the exchange. A failed re-auth is non-fatal at the
// host: the previously installed keys remain until a new SUCCESS rolls them.
func (a *Authenticator) Restart() {
	a.state = StateUnauth
	a.server = nil
	a.session = nil
	a.verified = false
	a.id++
}

// Recv processes one received EAPOL frame and returns the frame to transmit in
// reply, if any. It never panics on arbitrary input. On a definitive failure
// (unknown user or a failed client proof) it sets StateFailed; a failed proof
// also yields an EAP-FAILURE frame to send and ErrAuthFailed.
func (a *Authenticator) Recv(payload []byte) (out *Frame, err error) {
	f, err := Parse(payload)
	if err != nil {
		return nil, err
	}
	return a.handle(f)
}

// handle drives the authenticator state machine for a parsed frame.
func (a *Authenticator) handle(f Frame) (*Frame, error) {
	// Reject a RESPONSE or FAILURE whose identifier does not match the request we
	// last issued. KindStart and KindLogoff open/close the exchange and carry no
	// meaningful identifier, so they are exempt. KindPasswordRequest is exempt too:
	// it is the authenticatee's post-SUCCESS solicitation carrying its own separate
	// identifier (bits 6/7 set), which libRIST accepts regardless of last_identifier
	// (process_eap_request, subtype 0x10) and echoes in the response.
	if a.state != StateUnauth && f.Kind != KindStart && f.Kind != KindLogoff &&
		f.Kind != KindPasswordRequest && f.Identifier != a.id {
		return nil, nil
	}
	switch f.Kind {
	case KindStart:
		// A client EAPOL-START prompts an IDENTITY REQUEST (eap_process_eapol
		// EAPOL_TYPE_START). While a handshake is IN-PROGRESS, ignore a further START so a
		// spoofed mid-handshake START cannot reset the live exchange (libRIST's !last_pkt
		// guard). From a TERMINAL state — SUCCESS, or FAILED after a prior success (an
		// abandoned/failed re-auth; an initial failure tears the session down at the host,
		// so StateFailed here always follows a SUCCESS) — a START is a legitimate
		// re-authentication request: re-run from a clean slate. A forger cannot complete
		// the re-auth (it fails M1 verification), and a failed re-auth is non-fatal at the
		// host, so neither a spoofed START nor a failed re-prove can tear an established
		// session down. Accepting a START from FAILED is what lets the genuine peer recover
		// after a transient re-auth failure.
		if a.state == StateInProgress {
			return nil, nil
		}
		if a.state != StateUnauth {
			a.Restart()
		}
		out := a.Start()
		return &out, nil

	case KindLogoff:
		// EAPOL-LOGOFF is unauthenticated and trivially spoofable, so an
		// off-path attacker must not be able to use it to tear down an
		// established session. Honor it only while the INITIAL handshake is still open and
		// has never authenticated; once we have reached a terminal state OR have
		// authenticated before (everAuthed — so a LOGOFF cannot abort an in-progress
		// re-auth either), refuse it with ErrUnexpected and leave the session untouched.
		// This matches libRIST, which returns EAP_UNEXPECTEDREQUEST and does NOT reset at
		// or beyond SUCCESS (re-auth is host/peer driven, never torn down by a peer LOGOFF).
		if a.state == StateSuccess || a.state == StateFailed || a.everAuthed {
			return nil, ErrUnexpected
		}
		// Open handshake: LOGOFF tears it back down to the unauthenticated state
		// rather than being an error (libRIST resets to UNAUTH).
		a.state = StateUnauth
		a.server = nil
		a.session = nil
		a.verified = false
		return nil, nil

	case KindIdentityResponse:
		// Look up the verifier and send CHALLENGE
		// (process_eap_response_identity).
		verifier, salt, ok := a.lookup(f.Username)
		if !ok {
			a.state = StateFailed
			return nil, ErrNoVerifier
		}
		grp := srp.DefaultGroup()
		// Legacy (srp-compat=1) authenticators use the unpadded k/u hashing; the
		// default uses the RFC 5054 PAD-compliant mode. The choice is fixed at
		// construction and signalled on the wire via a.version (eapVersion2 vs 3).
		newServer := srp.NewServer
		if a.legacyPad {
			newServer = srp.NewServerLegacy
		}
		server, err := newServer(grp, verifier, salt)
		if err != nil {
			a.state = StateFailed
			return nil, errors.Join(ErrSRP, err)
		}
		a.server = server
		a.username = f.Username
		a.state = StateInProgress
		a.id++ // ctx->last_identifier++
		out := Frame{
			Version:    a.version,
			Code:       CodeRequest,
			Identifier: a.id,
			Kind:       KindChallenge,
			Salt:       append([]byte(nil), salt...),
			// default group: no g/N.
		}
		return &out, nil

	case KindClientKey:
		// Validate A and send SERVER_KEY(B)
		// (process_eap_response_client_key).
		if a.server == nil {
			a.state = StateFailed
			return nil, ErrUnexpected
		}
		if err := a.server.HandleA(f.Public); err != nil {
			a.state = StateFailed
			return nil, errors.Join(ErrSRP, err)
		}
		a.id++
		out := Frame{
			Version:    a.version,
			Code:       CodeRequest,
			Identifier: a.id,
			Kind:       KindServerKey,
			Public:     a.server.B(),
		}
		return &out, nil

	case KindClientValidator:
		// Verify M1; on success send SERVER_VALIDATOR(M2), else FAILURE
		// (process_eap_response_client_validator).
		if a.server == nil {
			a.state = StateFailed
			return nil, ErrUnexpected
		}
		if !a.server.VerifyM1(a.username, f.Proof) {
			a.state = StateFailed
			fail := Frame{
				Version:    a.version,
				Code:       CodeFailure,
				Identifier: a.id,
				Kind:       KindFailure,
			}
			return &fail, ErrAuthFailed
		}
		a.session = a.server.SessionKey()
		// use_key_as_passphrase inline keying (process_eap_response_client_
		// validator): the client's M1 carries the set_passphrase bit when it keyed
		// its TX from K; install K as our RX passphrase to match (client TX =
		// server RX). v3-only — the legacy (v2) authenticatee never sets the bit, so
		// this never fires there, matching libRIST's "&& ctx->eapversion3" gate.
		if f.SetPassphrase() && a.version == eapVersion3 {
			a.keying.setRx(a.server.SessionKey())
		}
		// M1 verified, but defer terminal SUCCESS until the client acknowledges
		// the SERVER_VALIDATOR: libRIST sets only ctx->authenticated here and
		// reaches SUCCESS on the client's ack.
		a.verified = true
		a.id++
		out := Frame{
			Version:    a.version,
			Code:       CodeRequest,
			Identifier: a.id,
			Kind:       KindServerValidator,
			Proof:      a.server.M2(),
		}
		// use_key_as_passphrase inline keying (process_eap_response_client_
		// validator): signal in M2 that we keyed our TX from K, and install K as our
		// TX passphrase, so the receiver->sender feedback is encrypted under K (the
		// client installs K as its RX from this bit). The media direction stays
		// cleartext (the client never keys its TX), so we do NOT key our RX here.
		// Gated to v3, matching libRIST's "use_key_as_passphrase && ctx->eapversion3":
		// the legacy authenticatee ignores the bit (negotiatedVersion(f) != 3), so a
		// legacy authenticator must not set it either, keeping the keying symmetric.
		if a.keying.enabled && a.version == eapVersion3 {
			out.setSetPassphrase(true)
			a.keying.setTx(a.server.SessionKey())
		}
		return &out, nil

	case KindServerValidator, KindSuccess:
		// The client acknowledges the SERVER_VALIDATOR with a closing v3
		// EAP-SUCCESS (or a bodyless SERVER_VALIDATOR RESPONSE on v2); only now,
		// gated on the verified M1, does the authenticator reach terminal SUCCESS
		// (process_eap_response_srp_server_validator).
		if a.verified {
			a.state = StateSuccess
			a.everAuthed = true
			a.id++ // ctx->last_identifier++ on terminal SUCCESS
		}
		return nil, nil

	case KindPasswordRequest:
		// The authenticatee's post-SUCCESS PASSWORD_REQUEST soliciting our
		// data-channel keying confirmation (process_eap_request_srp_passphrase).
		// Under use_key_as_passphrase reply with a bit-7 "use session key"
		// PASSWORD_RESPONSE, echoing the request identifier. This is what the
		// authenticatee waits on (otherwise libRIST logs "Failed to receive
		// requested passphrase"). Only meaningful after SUCCESS.
		if a.state != StateSuccess {
			return nil, nil
		}
		return passwordResponseFrame(a.version, f.Identifier), nil

	case KindPasswordResponse:
		// An unsolicited PASSWORD_RESPONSE pushing a new RX key (the symmetric
		// process_eap_response_passphrase path). Install K (bit 7) or the explicit
		// AES-CTR-under-K passphrase (bit 6) as our RX key, then acknowledge with
		// EAP-SUCCESS.
		if a.state != StateSuccess {
			return nil, nil
		}
		if err := installPushedRx(&a.keying, a.session, f); err != nil {
			return nil, err
		}
		ack := Frame{
			Version:    a.version,
			Code:       CodeSuccess,
			Identifier: f.Identifier,
			Kind:       KindSuccess,
		}
		return &ack, nil

	case KindFailure:
		// Honor a FAILURE only while a handshake is actually in flight. In SUCCESS it is
		// stale or forged and must not tear a live session down — re-auth is driven by a
		// START/IDENTITY exchange, never by an injected FAILURE. (The up-front identifier
		// gate already drops a mismatched-identifier FAILURE; this also closes the
		// matching-identifier FAILURE that a.id++-on-SUCCESS would otherwise admit.)
		if a.state != StateInProgress {
			return nil, nil
		}
		a.state = StateFailed
		return nil, ErrAuthFailed

	default:
		return nil, ErrUnexpected
	}
}

// passwordResponse builds the authenticatee's reply to a PASSWORD_REQUEST under
// use_key_as_passphrase. The authenticatee always runs the v3 SRP hashing on its
// own-initiated password exchange (libRIST's authenticatee ctx->eapversion3), so
// it replies at version 3. See passwordResponseFrame.
func (a *Authenticatee) passwordResponse(identifier uint8) *Frame {
	return passwordResponseFrame(eapVersion3, identifier)
}

// passwordResponseFrame builds a PASSWORD_RESPONSE under use_key_as_passphrase:
// an EAP RESPONSE subtype 0x10 with bit 7 set ("use the SRP session key K", no
// encrypted payload), echoing the request identifier (eap_srp_send_password with
// password_len == 0). It is used by whichever role receives a PASSWORD_REQUEST;
// version is the sender's advertised EAPOL version (eapVersion3 by default,
// eapVersion2 for a legacy authenticator).
func passwordResponseFrame(version, identifier uint8) *Frame {
	return &Frame{
		Version:    version,
		Code:       CodeResponse,
		Identifier: identifier,
		Kind:       KindPasswordResponse,
		PwFlags:    1 << pwUseSessionKeyBit,
	}
}

// installPushedRx installs the receive-direction passphrase a PASSWORD_RESPONSE
// pushes into k (process_eap_response_passphrase): bit 7 means "use the SRP
// session key K" directly; bit 6 means an explicit passphrase follows,
// AES-CTR-encrypted under K with IV = 15 zero bytes then the EAP identifier. The
// explicit decrypt uses K at 256 bits when bit 6 is set (CHECK_BIT(pkt[0],6) ?
// 256 : 128 in libRIST; the encrypt side always uses 256, and bit 6 is set
// exactly when an explicit passphrase is present). session is the 32-byte K.
func installPushedRx(k *keying, session []byte, f Frame) error {
	switch {
	case f.PwUseSessionKey():
		k.setRx(session)
		return nil
	case f.PwHasExplicit():
		// AES-CTR decrypt the explicit passphrase under K. IV is 15 zero bytes
		// then the EAP identifier byte (a fresh, non-repeating IV per identifier).
		var iv [16]byte
		iv[15] = f.Identifier
		keyBits := crypto.KeySize128
		if f.PwHasExplicit() { // bit 6 also selects AES-256 on the receive side
			keyBits = crypto.KeySize256
		}
		aesKey := session
		if len(aesKey) != keyBits/8 {
			// K is a 32-byte SHA-256 digest; for AES-128 libRIST uses the first 16
			// bytes of the key buffer. Guard the length defensively.
			if len(aesKey) < keyBits/8 {
				return ErrShortBuffer
			}
			aesKey = aesKey[:keyBits/8]
		}
		pt, err := crypto.AESCTRRaw(aesKey, iv, nil, f.PwPayload)
		if err != nil {
			return err
		}
		k.setRx(pt)
		return nil
	default:
		// Neither bit set: no keying material. Treat as a no-op (libRIST would
		// install a zero-length passphrase, which is degenerate; we ignore it).
		return nil
	}
}

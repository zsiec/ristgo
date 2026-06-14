package eap

import (
	"errors"

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
	id    uint8 // last EAP identifier seen, echoed on responses

	client  *srp.Client
	salt    []byte
	session []byte // SRP session key K, valid after success
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

// handle drives the authenticatee state machine for a parsed frame.
func (a *Authenticatee) handle(f Frame) (*Frame, error) {
	if f.Kind == KindFailure {
		// Drop a stale or spoofed FAILURE whose identifier does not match the
		// in-flight request, so it cannot force-fail an active session. The
		// identifier is adopted (below) only from a processed request, so a.id
		// tracks the live exchange.
		if a.state != StateUnauth && f.Identifier != a.id {
			return nil, nil
		}
		a.state = StateFailed
		return nil, ErrAuthFailed
	}
	a.id = f.Identifier // adopt the request identifier; we echo it on our reply
	switch f.Kind {
	case KindIdentityRequest:
		// Reply with our identity (process_eap_request_identity).
		if a.state == StateUnauth {
			a.state = StateInProgress
		}
		out := Frame{
			Version:    eapVersion3,
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
		client, err := srp.NewClient(grp, f.Salt)
		if err != nil {
			a.state = StateFailed
			return nil, errors.Join(ErrSRP, err)
		}
		a.client = client
		a.salt = f.Salt
		a.state = StateInProgress
		out := Frame{
			Version:    eapVersion3,
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
		if err := a.client.ComputeKey(f.Public, a.username, a.password); err != nil {
			// libRIST treats a bad B as a permanent failure.
			a.state = StateFailed
			return nil, errors.Join(ErrSRP, err)
		}
		out := Frame{
			Version:    eapVersion3,
			Code:       CodeResponse,
			Identifier: f.Identifier,
			Kind:       KindClientValidator,
			Proof:      a.client.M1(),
		}
		return &out, nil

	case KindServerValidator:
		// Verify M2; success or permanent failure
		// (process_eap_request_srp_server_validator).
		if a.client == nil || len(f.Proof) == 0 {
			a.state = StateFailed
			return nil, ErrAuthFailed
		}
		if !a.client.VerifyM2(f.Proof) {
			a.state = StateFailed
			return nil, ErrAuthFailed
		}
		a.session = a.client.SessionKey()
		a.state = StateSuccess
		// Acknowledge with the closing v3 EAP-SUCCESS, echoing the request
		// identifier. This is what drives the authenticator to its terminal
		// SUCCESS; without it the peer waits on its retransmit timer.
		ack := Frame{
			Version:    eapVersion3,
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

	state State
	id    uint8 // last EAP identifier we issued (incremented per request)

	server   *srp.Server
	username string
	session  []byte
	verified bool // M1 verified; terminal SUCCESS is deferred to the client's ack
}

// NewAuthenticator creates an EAP-SRP server that resolves verifiers via the
// supplied lookup callback (ctx->config.lookup_func). lookup must be non-nil.
func NewAuthenticator(lookup VerifierLookup) (*Authenticator, error) {
	if lookup == nil {
		return nil, ErrNilLookup
	}
	return &Authenticator{lookup: lookup}, nil
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
		Version:    eapVersion3,
		Code:       CodeRequest,
		Identifier: a.id,
		Kind:       KindIdentityRequest,
	}
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
	// last issued. KindStart opens the exchange and carries no meaningful
	// identifier, so it is exempt.
	if a.state != StateUnauth && f.Kind != KindStart && f.Identifier != a.id {
		return nil, nil
	}
	switch f.Kind {
	case KindStart:
		// A client EAPOL-START prompts an IDENTITY REQUEST
		// (eap_process_eapol EAPOL_TYPE_START).
		out := a.Start()
		return &out, nil

	case KindIdentityResponse:
		// Look up the verifier and send CHALLENGE
		// (process_eap_response_identity).
		verifier, salt, ok := a.lookup(f.Username)
		if !ok {
			a.state = StateFailed
			return nil, ErrNoVerifier
		}
		grp := srp.DefaultGroup()
		server, err := srp.NewServer(grp, verifier, salt)
		if err != nil {
			a.state = StateFailed
			return nil, errors.Join(ErrSRP, err)
		}
		a.server = server
		a.username = f.Username
		a.state = StateInProgress
		a.id++ // ctx->last_identifier++
		out := Frame{
			Version:    eapVersion3,
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
			Version:    eapVersion3,
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
				Version:    eapVersion3,
				Code:       CodeFailure,
				Identifier: a.id,
				Kind:       KindFailure,
			}
			return &fail, ErrAuthFailed
		}
		a.session = a.server.SessionKey()
		// M1 verified, but defer terminal SUCCESS until the client acknowledges
		// the SERVER_VALIDATOR: libRIST sets only ctx->authenticated here and
		// reaches SUCCESS on the client's ack.
		a.verified = true
		a.id++
		out := Frame{
			Version:    eapVersion3,
			Code:       CodeRequest,
			Identifier: a.id,
			Kind:       KindServerValidator,
			Proof:      a.server.M2(),
		}
		return &out, nil

	case KindServerValidator, KindSuccess:
		// The client acknowledges the SERVER_VALIDATOR with a closing v3
		// EAP-SUCCESS (or a bodyless SERVER_VALIDATOR RESPONSE on v2); only now,
		// gated on the verified M1, does the authenticator reach terminal SUCCESS
		// (process_eap_response_srp_server_validator).
		if a.verified {
			a.state = StateSuccess
		}
		return nil, nil

	case KindFailure:
		a.state = StateFailed
		return nil, ErrAuthFailed

	default:
		return nil, ErrUnexpected
	}
}

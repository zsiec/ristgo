// Package eap implements the RIST Main-profile EAP-SRP-SHA256 authentication
// framing and state machine, byte-exact with libRIST v0.2.18-rc1. EAP frames
// ride inside a GRE EAPOL frame
// (protocol type 0x888E, internal/gre.ProtoEAPOL); the SRP-6a math is delegated
// to internal/srp. This package owns only the EAP-over-EAPOL framing and the
// authenticatee/authenticator handshake sequencing.
//
// # Wire framing
//
// Three nested headers precede every EAP-SRP body:
//
//	EAPOL header (4 bytes, struct eapol_hdr):
//	    eapversion (1)  -- 2, or 3 for RFC 5054 PAD-compliant hashing
//	    eaptype    (1)  -- EAP=0, START=1, LOGOFF=2
//	    length     (2)  -- big-endian; the EAP packet length (set equal to
//	                       eap_hdr->length)
//	EAP header (4 bytes, struct eap_hdr):
//	    code       (1)  -- REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4
//	    identifier (1)  -- request/response correlation id
//	    length     (2)  -- big-endian; total EAP packet length (the EAP header
//	                       plus its body); libRIST requires length == len
//	EAP-SRP subtype header (2 bytes, struct eap_srp_hdr):
//	    type       (1)  -- EAP_TYPE_SRP_SHA1 = 19
//	    subtype    (1)  -- see SRP subtype constants below
//
// The IDENTITY messages do not carry the SRP subtype header: their EAP body is
// a single type byte EAP_TYPE_IDENTITY (1) optionally followed by the username
// (RESPONSE and REQUEST).
//
// # SRP subtypes and bodies
//
// The subtype number's meaning depends on the EAP code (REQUEST vs RESPONSE);
// libRIST reuses values 1 and 2 in both directions:
//
//	IDENTITY REQUEST  (code REQUEST):   body = [EAP_TYPE_IDENTITY]
//	IDENTITY RESPONSE (code RESPONSE):  body = [EAP_TYPE_IDENTITY | username]
//	CHALLENGE         (REQUEST, subtype 1, server->client): SRP-hdr then
//	    name_len(2 BE) | name | salt_len(2 BE) | salt | gen_len(2 BE) |
//	    [g | N]. For the default 2048-bit group gen_len==0
//	    and g/N are omitted.
//	CLIENT_KEY        (RESPONSE, subtype 1, client->server): SRP-hdr | A.
//	SERVER_KEY        (REQUEST, subtype 2, server->client): SRP-hdr | B.
//	CLIENT_VALIDATOR  (RESPONSE, subtype 2, client->server): SRP-hdr |
//	    flags(4) | M1; the 4-byte flags word is zero in this
//	    implementation (M1 is the 32-byte client proof).
//	SERVER_VALIDATOR  (REQUEST, subtype 3, server->client): SRP-hdr |
//	    flags(4) | M2; flags zero, M2 the 32-byte proof.
//
// # State machine
//
// Two roles drive the same message exchange (the process_eap_* handlers):
//
//	Authenticatee (client): UNAUTH
//	    --(recv IDENTITY REQUEST)-->  send IDENTITY RESPONSE(username)
//	    --(recv CHALLENGE)-->         create srp.Client, send CLIENT_KEY(A)
//	    --(recv SERVER_KEY B)-->      srp ComputeKey, send CLIENT_VALIDATOR(M1)
//	    --(recv SERVER_VALIDATOR M2)->srp VerifyM2 -> SUCCESS (else FAILURE)
//
//	Authenticator (server): UNAUTH -> send IDENTITY REQUEST
//	    --(recv IDENTITY RESPONSE)--> lookup(verifier,salt), create srp.Server,
//	                                  send CHALLENGE(salt[,g,N])
//	    --(recv CLIENT_KEY A)-->      srp HandleA, send SERVER_KEY(B)
//	    --(recv CLIENT_VALIDATOR M1)->srp VerifyM1 -> send SERVER_VALIDATOR(M2)
//	                                  + SUCCESS (else FAILURE)
//
// EAPOL frames are never encrypted, even under a PSK (libRIST excludes EAPOL
// from payload encryption), so this package deals only in plaintext frames.
//
// # Design
//
// Sans-I/O, like the flow core: the host hands received EAPOL payloads to
// Recv and transmits whatever frames Recv (or Start) returns. The package never
// reads a clock, opens a socket, or spawns a goroutine. SRP secrets come from
// internal/srp (which draws from crypto/rand at construction). The verifier
// lookup (username -> verifier, salt) is a callback the host supplies to the
// Authenticator.
package eap

import (
	"encoding/binary"
	"errors"

	"github.com/zsiec/ristgo/internal/srp"
)

// Sentinel errors returned by this package. Callers should test for them with
// errors.Is; returned errors may wrap these with additional context.
var (
	// ErrShortBuffer is returned by Parse when the input is too short to hold
	// the EAPOL/EAP/SRP headers or a field a header announces (the
	// EAP_LENERR length checks).
	ErrShortBuffer = errors.New("rist: eap: short buffer")

	// ErrBadLength is returned by Parse when the EAPOL or EAP length field is
	// inconsistent with the buffer (length validation).
	ErrBadLength = errors.New("rist: eap: inconsistent length field")

	// ErrUnsupportedType is returned by Parse for an EAPOL type or EAP-SRP
	// type byte this implementation does not handle.
	ErrUnsupportedType = errors.New("rist: eap: unsupported type")

	// ErrUnexpected is returned by Recv when a frame arrives in a state where
	// the role does not expect it (the EAP_UNEXPECTEDREQUEST /
	// EAP_UNEXPECTEDRESPONSE / EAP_SRP_WRONGSUBTYPE rejections).
	ErrUnexpected = errors.New("rist: eap: unexpected frame for state")

	// ErrNoVerifier is returned by the Authenticator when the lookup callback
	// reports no verifier for the requested username (found==false).
	ErrNoVerifier = errors.New("rist: eap: no verifier for user")

	// ErrSRP wraps an SRP-layer failure (a rejected public value, a failed
	// proof, or an out-of-order step) surfaced from internal/srp.
	ErrSRP = errors.New("rist: eap: srp failure")

	// ErrAuthFailed is returned by Recv when authentication has definitively
	// failed: the peer's proof did not verify (server M2 fail or client M1
	// fail).
	ErrAuthFailed = errors.New("rist: eap: authentication failed")

	// ErrEmptyCredentials is returned by NewAuthenticatee when the username or
	// password is empty.
	ErrEmptyCredentials = errors.New("rist: eap: empty username or password")

	// ErrCredentialsTooLong is returned by NewAuthenticatee when the username or
	// password exceeds 255 bytes (libRIST bounds both at 1..255).
	ErrCredentialsTooLong = errors.New("rist: eap: username or password too long")

	// ErrNilLookup is returned by NewAuthenticator when the verifier-lookup
	// callback is nil.
	ErrNilLookup = errors.New("rist: eap: nil verifier lookup")

	// ErrUnsupportedGroup is returned when a CHALLENGE carries an explicit (g, N)
	// rather than selecting the default 2048-bit group. The RIST Main-profile
	// default and TR-06-2 use the default group exclusively (default_ng);
	// internal/srp exposes only that group, so an explicit group is rejected.
	ErrUnsupportedGroup = errors.New("rist: eap: non-default SRP group unsupported")
)

// EAPOL types (802.1X-2010 §11).
const (
	eapolTypeEAP    uint8 = 0
	eapolTypeStart  uint8 = 1
	eapolTypeLogoff uint8 = 2
)

// EAP codes (RFC 3748).
const (
	eapCodeRequest  uint8 = 1
	eapCodeResponse uint8 = 2
	eapCodeSuccess  uint8 = 3
	eapCodeFailure  uint8 = 4
)

// EAP method types.
const (
	eapTypeIdentity uint8 = 1
	eapTypeSRPSHA1  uint8 = 19
)

// EAP-SRP subtypes. Values 1 and 2 are reused across the
// REQUEST/RESPONSE directions; the EAP code disambiguates them.
const (
	srpSubtypeChallenge uint8 = 1 // REQUEST: server->client; RESPONSE: client A (CLIENT_KEY)
	srpSubtypeServerKey uint8 = 2 // REQUEST: server B; RESPONSE: client M1 (CLIENT_VALIDATOR)
	srpSubtypeServerVal uint8 = 3 // either direction: server validator (M2)
	srpSubtypePassword  uint8 = 0x10
)

// eapVersion3 is the EAPOL version this implementation emits: 3 signals RFC
// 5054 PAD-compliant SRP hashing (ctx->eapversion3 ? 3 : 2). libRIST
// 0.2.16+ always uses 3 for new contexts.
const eapVersion3 uint8 = 3

// Header sizes.
const (
	eapolHdrSize = 4 // struct eapol_hdr
	eapHdrSize   = 4 // struct eap_hdr
	srpHdrSize   = 2 // struct eap_srp_hdr

	// hdrsOffset is EAPOL_EAP_HDRS_OFFSET: the EAPOL header plus
	// the EAP header, i.e. the offset of an EAP body within an EAPOL frame.
	hdrsOffset = eapolHdrSize + eapHdrSize

	// proofLen is the SHA-256 proof size for M1/M2 (DIGEST_LENGTH).
	proofLen = 32

	// validatorFlagsLen is the 4-byte flags word that prefixes M1 in
	// CLIENT_VALIDATOR and M2 in SERVER_VALIDATOR.
	validatorFlagsLen = 4
)

// Code identifies an EAP packet's code field.
type Code uint8

// EAP codes exposed for inspection of a parsed Frame.
const (
	CodeRequest  = Code(eapCodeRequest)
	CodeResponse = Code(eapCodeResponse)
	CodeSuccess  = Code(eapCodeSuccess)
	CodeFailure  = Code(eapCodeFailure)
)

// Kind classifies a parsed EAP-SRP frame by its logical message, abstracting
// over the code/subtype encoding so callers can switch on intent.
type Kind uint8

// Frame kinds. KindUnknown covers EAP bodies this package parses structurally
// but does not act on (e.g. the password push messages).
const (
	KindUnknown Kind = iota
	KindStart
	KindLogoff
	KindIdentityRequest
	KindIdentityResponse
	KindChallenge
	KindClientKey
	KindServerKey
	KindClientValidator
	KindServerValidator
	KindSuccess
	KindFailure
)

// String returns a human-readable name for the kind.
func (k Kind) String() string {
	switch k {
	case KindStart:
		return "START"
	case KindLogoff:
		return "LOGOFF"
	case KindIdentityRequest:
		return "IDENTITY-REQUEST"
	case KindIdentityResponse:
		return "IDENTITY-RESPONSE"
	case KindChallenge:
		return "CHALLENGE"
	case KindClientKey:
		return "CLIENT-KEY"
	case KindServerKey:
		return "SERVER-KEY"
	case KindClientValidator:
		return "CLIENT-VALIDATOR"
	case KindServerValidator:
		return "SERVER-VALIDATOR"
	case KindSuccess:
		return "SUCCESS"
	case KindFailure:
		return "FAILURE"
	default:
		return "UNKNOWN"
	}
}

// Frame is a decoded EAPOL frame carrying an EAP-SRP message. It is the
// normalized form Parse produces and AppendTo encodes. The role state machines
// consume Frames and produce Frames; the host only sees their wire bytes.
type Frame struct {
	// Version is the EAPOL version byte (2 or 3).
	Version uint8
	// Code is the EAP code (meaningful only when the EAPOL type is EAP; for
	// START/LOGOFF it is zero).
	Code Code
	// Identifier is the EAP request/response correlation id.
	Identifier uint8
	// Kind is the classified message.
	Kind Kind

	// Username is set for IDENTITY-RESPONSE (may be empty for the request).
	Username string

	// Salt, GenN, GenG carry the CHALLENGE parameters. GenG/GenN are nil for
	// the default group (gen_len == 0).
	Salt []byte
	GenG []byte
	GenN []byte

	// Public carries A (CLIENT-KEY) or B (SERVER-KEY).
	Public []byte

	// Proof carries M1 (CLIENT-VALIDATOR) or M2 (SERVER-VALIDATOR).
	Proof []byte

	// Flags is the 4-byte flags word of a validator message (zero here).
	Flags [validatorFlagsLen]byte
}

// startFrame builds the EAPOL-START frame, which carries no EAP payload
// (_librist_proto_eap_start): version 3, type START, length 0.
func startFrame() Frame {
	return Frame{Version: eapVersion3, Kind: KindStart}
}

// AppendTo encodes the frame in EAPOL/EAP/EAP-SRP wire form and appends it to
// buf, returning the extended slice. It mirrors send_eapol_pkt:
// the EAPOL length and EAP length fields both carry the EAP packet length.
// It never panics; an unknown kind appends nothing and returns buf
// unchanged.
func (f Frame) AppendTo(buf []byte) []byte {
	version := f.Version
	if version == 0 {
		version = eapVersion3
	}

	// START and LOGOFF are bare EAPOL frames with a zero-length body and no
	// EAP header (eapol.length = 0, struct eapol_hdr only).
	switch f.Kind {
	case KindStart, KindLogoff:
		typ := eapolTypeStart
		if f.Kind == KindLogoff {
			typ = eapolTypeLogoff
		}
		buf = append(buf, version, typ, 0, 0)
		return buf
	}

	body := f.encodeBody()
	eapLen := eapHdrSize + len(body)

	// EAPOL header: version, type EAP, length = EAP packet length.
	buf = append(buf, version, eapolTypeEAP)
	buf = appendU16(buf, uint16(eapLen))
	// EAP header: code, identifier, length = EAP packet length.
	buf = append(buf, uint8(f.Code), f.Identifier)
	buf = appendU16(buf, uint16(eapLen))
	buf = append(buf, body...)
	return buf
}

// encodeBody encodes the EAP body (everything after the EAP header) for a
// frame, including the EAP-SRP subtype header where applicable.
func (f Frame) encodeBody() []byte {
	switch f.Kind {
	case KindIdentityRequest:
		return []byte{eapTypeIdentity}
	case KindIdentityResponse:
		// type byte then the raw username.
		return append([]byte{eapTypeIdentity}, f.Username...)
	case KindChallenge:
		// SRP header then name_len|name|salt_len|salt|gen_len[|g|N].
		// name is empty.
		out := []byte{eapTypeSRPSHA1, srpSubtypeChallenge}
		out = appendU16(out, 0) // name length, no server name
		out = appendU16(out, uint16(len(f.Salt)))
		out = append(out, f.Salt...)
		if len(f.GenG) == 0 {
			out = appendU16(out, 0) // default group: gen_len 0, no g/N
		} else {
			out = appendU16(out, uint16(len(f.GenG)))
			out = append(out, f.GenG...)
			out = append(out, f.GenN...)
		}
		return out
	case KindClientKey:
		// CLIENT_KEY rides on subtype CHALLENGE in the RESPONSE direction:
		// SRP header then A.
		out := []byte{eapTypeSRPSHA1, srpSubtypeChallenge}
		return append(out, f.Public...)
	case KindServerKey:
		// SERVER_KEY REQUEST: SRP header then B.
		out := []byte{eapTypeSRPSHA1, srpSubtypeServerKey}
		return append(out, f.Public...)
	case KindClientValidator:
		// CLIENT_VALIDATOR rides on subtype SERVER_KEY in the RESPONSE
		// direction: SRP header, 4-byte flags, M1.
		out := []byte{eapTypeSRPSHA1, srpSubtypeServerKey}
		out = append(out, f.Flags[:]...)
		return append(out, f.Proof...)
	case KindServerValidator:
		// SERVER_VALIDATOR REQUEST: SRP header, flags, M2.
		out := []byte{eapTypeSRPSHA1, srpSubtypeServerVal}
		out = append(out, f.Flags[:]...)
		return append(out, f.Proof...)
	case KindSuccess:
		// The v3 EAP-SUCCESS body is a zeroed eap_srp_hdr — two zero bytes, not a
		// populated SRP header: libRIST builds outpkt = {0} and sets type/subtype
		// only on the v2 RESPONSE branch, returning before it on v3.
		// Emit two zero bytes to match the wire.
		return []byte{0, 0}
	case KindFailure:
		// FAILURE carries no body.
		return nil
	default:
		return nil
	}
}

// MarshalSize returns the encoded length of the frame in bytes.
func (f Frame) MarshalSize() int {
	switch f.Kind {
	case KindStart, KindLogoff:
		return eapolHdrSize
	default:
		return hdrsOffset + len(f.encodeBody())
	}
}

// Parse decodes one EAPOL frame from b and returns the normalized Frame. It
// validates framing only — the EAPOL/EAP length fields, the SRP type byte, and
// the per-message body lengths — never enforcing role expectations (that is the
// state machine's job). It returns a sentinel error and never panics on
// arbitrary input. The returned Frame does not alias b.
func Parse(b []byte) (Frame, error) {
	if len(b) < eapolHdrSize {
		return Frame{}, ErrShortBuffer
	}
	version := b[0]
	eapolType := b[1]
	bodyLen := int(binary.BigEndian.Uint16(b[2:4]))

	// The announced EAP packet length must fit in what we received.
	if bodyLen+eapolHdrSize > len(b) {
		return Frame{}, ErrBadLength
	}

	switch eapolType {
	case eapolTypeStart:
		return Frame{Version: version, Kind: KindStart}, nil
	case eapolTypeLogoff:
		return Frame{Version: version, Kind: KindLogoff}, nil
	case eapolTypeEAP:
		return parseEAP(version, b[eapolHdrSize:eapolHdrSize+bodyLen])
	default:
		return Frame{}, ErrUnsupportedType
	}
}

// parseEAP decodes the EAP packet (header + body) of length matching eapPkt.
func parseEAP(version uint8, eapPkt []byte) (Frame, error) {
	if len(eapPkt) < eapHdrSize {
		return Frame{}, ErrShortBuffer
	}
	code := eapPkt[0]
	identifier := eapPkt[1]
	length := int(binary.BigEndian.Uint16(eapPkt[2:4]))
	// The EAP header length must equal the packet length.
	if length != len(eapPkt) {
		return Frame{}, ErrBadLength
	}
	body := eapPkt[eapHdrSize:]

	f := Frame{Version: version, Code: Code(code), Identifier: identifier}

	switch code {
	case eapCodeRequest, eapCodeResponse:
		return parseMethod(f, code, body)
	case eapCodeSuccess:
		f.Kind = KindSuccess
		return f, nil
	case eapCodeFailure:
		f.Kind = KindFailure
		return f, nil
	default:
		return Frame{}, ErrUnsupportedType
	}
}

// parseMethod decodes the EAP method body of a REQUEST or RESPONSE.
func parseMethod(f Frame, code uint8, body []byte) (Frame, error) {
	if len(body) < 1 {
		return Frame{}, ErrShortBuffer
	}
	mType := body[0]
	switch mType {
	case eapTypeIdentity:
		if code == eapCodeRequest {
			f.Kind = KindIdentityRequest
		} else {
			f.Kind = KindIdentityResponse
			f.Username = string(body[1:])
		}
		return f, nil
	case eapTypeSRPSHA1:
		if len(body) < srpHdrSize {
			return Frame{}, ErrShortBuffer
		}
		return parseSRP(f, code, body[1], body[srpHdrSize:])
	default:
		return Frame{}, ErrUnsupportedType
	}
}

// parseSRP decodes the EAP-SRP body after the 2-byte subtype header. payload is
// everything past the SRP header. code disambiguates the reused subtype values.
func parseSRP(f Frame, code, subtype uint8, payload []byte) (Frame, error) {
	switch {
	case subtype == srpSubtypeChallenge && code == eapCodeRequest:
		return parseChallenge(f, payload)
	case subtype == srpSubtypeChallenge && code == eapCodeResponse:
		// CLIENT_KEY: the body is A.
		f.Kind = KindClientKey
		f.Public = cloneBytes(payload)
		return f, nil
	case subtype == srpSubtypeServerKey && code == eapCodeRequest:
		// SERVER_KEY: the body is B.
		f.Kind = KindServerKey
		f.Public = cloneBytes(payload)
		return f, nil
	case subtype == srpSubtypeServerKey && code == eapCodeResponse:
		// CLIENT_VALIDATOR: 4-byte flags then M1.
		return parseValidator(f, KindClientValidator, payload)
	case subtype == srpSubtypeServerVal:
		// SERVER_VALIDATOR: 4-byte flags then M2. On the RESPONSE side libRIST
		// treats subtype 3 as the server-validator acknowledgement carrying no
		// proof (process_eap_response_srp_server_validator); we surface it as a
		// bodyless server-validator so the host can complete the handshake on it.
		if code == eapCodeResponse && len(payload) < validatorFlagsLen+proofLen {
			f.Kind = KindServerValidator
			return f, nil
		}
		return parseValidator(f, KindServerValidator, payload)
	case subtype == srpSubtypePassword:
		// Password push/response; parsed structurally but not acted on here.
		f.Kind = KindUnknown
		return f, nil
	default:
		return Frame{}, ErrUnsupportedType
	}
}

// parseChallenge decodes the CHALLENGE TLVs: name_len|name|
// salt_len|salt|gen_len[|g|N]. Each length is a 2-byte big-endian prefix.
func parseChallenge(f Frame, p []byte) (Frame, error) {
	off := 0
	nameLen, err := readU16(p, &off)
	if err != nil {
		return Frame{}, err
	}
	if nameLen > len(p)-off {
		return Frame{}, ErrBadLength
	}
	off += nameLen // name ignored

	saltLen, err := readU16(p, &off)
	if err != nil {
		return Frame{}, err
	}
	if saltLen > len(p)-off {
		return Frame{}, ErrBadLength
	}
	salt := cloneBytes(p[off : off+saltLen])
	off += saltLen

	genLen, err := readU16(p, &off)
	if err != nil {
		return Frame{}, err
	}

	f.Kind = KindChallenge
	f.Salt = salt
	if genLen != 0 {
		if genLen > len(p)-off {
			return Frame{}, ErrBadLength
		}
		f.GenG = cloneBytes(p[off : off+genLen])
		off += genLen
		f.GenN = cloneBytes(p[off:]) // N runs to the end
	}
	return f, nil
}

// parseValidator decodes a validator body: a 4-byte flags word followed by the
// 32-byte proof (M1 or M2). It requires the exact length.
func parseValidator(f Frame, kind Kind, p []byte) (Frame, error) {
	if len(p) < validatorFlagsLen+proofLen {
		return Frame{}, ErrShortBuffer
	}
	f.Kind = kind
	copy(f.Flags[:], p[:validatorFlagsLen])
	f.Proof = cloneBytes(p[validatorFlagsLen : validatorFlagsLen+proofLen])
	return f, nil
}

// appendU16 appends v as two big-endian bytes.
func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// readU16 reads a 2-byte big-endian value at *off, advancing *off by 2. It
// returns ErrShortBuffer if fewer than two bytes remain.
func readU16(b []byte, off *int) (int, error) {
	if *off+2 > len(b) {
		return 0, ErrShortBuffer
	}
	v := int(binary.BigEndian.Uint16(b[*off : *off+2]))
	*off += 2
	return v, nil
}

// cloneBytes returns a copy of b (nil for an empty slice), so parsed frames
// never alias the input buffer.
func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

// VerifierLookup is the host-supplied callback the Authenticator uses to find a
// user's SRP verifier and salt. It returns ok==false when the username is
// unknown. The returned slices are treated as read-only.
type VerifierLookup func(username string) (verifier, salt []byte, ok bool)

// staticVerifier returns a VerifierLookup that serves a single (username,
// verifier, salt) tuple, mirroring libRIST's internal_user_verifier_lookup
// single-user mode. It is the common host configuration.
func staticVerifier(user string, verifier, salt []byte) VerifierLookup {
	return func(u string) ([]byte, []byte, bool) {
		if u != user {
			return nil, nil, false
		}
		return verifier, salt, true
	}
}

// StaticVerifier is the exported form of staticVerifier, convenient for hosts
// that authenticate a single configured user.
func StaticVerifier(user string, verifier, salt []byte) VerifierLookup {
	return staticVerifier(user, verifier, salt)
}

// challengeGroup returns the SRP group a CHALLENGE selects. Only the default
// 2048-bit group (gen_len == 0) is supported; an explicit group is rejected
// with ErrUnsupportedGroup.
func challengeGroup(f Frame) (*srp.Group, error) {
	if len(f.GenG) == 0 {
		return srp.DefaultGroup(), nil
	}
	return nil, ErrUnsupportedGroup
}

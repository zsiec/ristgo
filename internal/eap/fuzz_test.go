package eap

import (
	"bytes"
	"testing"
)

// fuzzSeeds returns wire seeds for the parser fuzz corpus: every golden frame
// plus degenerate and boundary inputs.
func fuzzSeeds() [][]byte {
	seeds := [][]byte{
		nil,
		{0x03},
		{0x03, 0x00},
		{0x03, 0x00, 0x00, 0x00},
		{0x03, 0x01, 0x00, 0x00},
		bytes.Repeat([]byte{0xFF}, 4),
		bytes.Repeat([]byte{0xFF}, 64),
		bytes.Repeat([]byte{0x00}, 64),
	}
	for _, g := range goldenFramesNoT() {
		w := g.AppendTo(nil)
		seeds = append(seeds, w, w[:len(w)/2])
	}
	return seeds
}

// goldenFramesNoT mirrors goldenFrames without the *testing.T dependency, for
// use as fuzz seeds.
func goldenFramesNoT() []Frame {
	salt := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	pub := []byte{0x01, 0x02, 0x03}
	proof := bytes.Repeat([]byte{0x5A}, proofLen)
	return []Frame{
		{Version: 3, Kind: KindStart},
		{Version: 3, Kind: KindLogoff},
		{Version: 3, Code: CodeRequest, Identifier: 0x11, Kind: KindIdentityRequest},
		{Version: 3, Code: CodeResponse, Identifier: 0x11, Kind: KindIdentityResponse, Username: "rist"},
		{Version: 3, Code: CodeRequest, Identifier: 0x22, Kind: KindChallenge, Salt: salt},
		{Version: 3, Code: CodeResponse, Identifier: 0x22, Kind: KindClientKey, Public: pub},
		{Version: 3, Code: CodeRequest, Identifier: 0x23, Kind: KindServerKey, Public: pub},
		{Version: 3, Code: CodeResponse, Identifier: 0x23, Kind: KindClientValidator, Proof: proof},
		{Version: 3, Code: CodeRequest, Identifier: 0x24, Kind: KindServerValidator, Proof: proof},
		{Version: 3, Code: CodeFailure, Identifier: 0x24, Kind: KindFailure},
	}
}

// FuzzParseEAPOL feeds arbitrary bytes to Parse. It must never panic; on a
// successful parse the frame must re-encode and re-parse byte-stably for the
// kinds the encoder round-trips losslessly.
func FuzzParseEAPOL(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := Parse(data)
		if err != nil {
			return
		}
		// KindUnknown covers bodies the package parses structurally but does
		// not model for re-encoding (e.g. the password push subtype, eap.c
		// EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE); it has no canonical
		// AppendTo form, so it is exempt from the round-trip assertion.
		if frame.Kind == KindUnknown {
			return
		}
		// Re-encoding a parsed frame must itself parse without error and be
		// byte-stable on the second round (idempotent encode/decode).
		wire := frame.AppendTo(nil)
		frame2, err := Parse(wire)
		if err != nil {
			t.Fatalf("re-parse of encoded frame failed: %v (kind=%v)", err, frame.Kind)
		}
		if wire2 := frame2.AppendTo(nil); !bytes.Equal(wire, wire2) {
			t.Fatalf("encode not byte-stable\n first %X\nsecond %X", wire, wire2)
		}
	})
}

// FuzzAuthenticateeRecv feeds arbitrary bytes to a client's Recv. It must never
// panic regardless of state.
func FuzzAuthenticateeRecv(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := NewAuthenticatee("rist", "mainprofile")
		if err != nil {
			t.Fatalf("NewAuthenticatee: %v", err)
		}
		_ = a.Start()
		_, _ = a.Recv(data)
		_ = a.Authenticated()
		_ = a.SessionKey()
	})
}

// FuzzAuthenticatorRecv feeds arbitrary bytes to a server's Recv. It must never
// panic regardless of state.
func FuzzAuthenticatorRecv(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := NewAuthenticator(StaticVerifier("rist", []byte{1, 2, 3}, []byte{4, 5, 6}))
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}
		_ = a.Start()
		_, _ = a.Recv(data)
		_ = a.Authenticated()
		_ = a.SessionKey()
	})
}

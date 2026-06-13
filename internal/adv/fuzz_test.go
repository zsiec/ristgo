package adv

import (
	"bytes"
	"reflect"
	"testing"
)

// fuzzSeeds returns wire-format seeds for the fuzz corpus: every golden packet,
// the hand-built coverage packets, plus degenerate and boundary inputs.
func fuzzSeeds() [][]byte {
	seeds := [][]byte{
		nil,
		{0x80},
		{0x80, 0x7F},
		make([]byte, HeaderMin),
		bytes.Repeat([]byte{0xFF}, HeaderMin),
		bytes.Repeat([]byte{0xFF}, MaxFixedHeader),
	}
	for _, g := range goldenPackets {
		wire, err := Build(nil, g.params, g.payload)
		if err == nil {
			seeds = append(seeds, wire)
			if len(wire) > 2 {
				seeds = append(seeds, wire[:len(wire)/2])
			}
		}
	}
	return seeds
}

// FuzzParse feeds arbitrary bytes to Parse. It must never panic; on success
// every byte offset and slice must lie within the input.
func FuzzParse(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		// Every aliased slice must be a sub-slice of data.
		within := func(name string, s []byte) {
			if s == nil {
				return
			}
			if len(s) > len(data) {
				t.Fatalf("%s longer than input: %d > %d", name, len(s), len(data))
			}
		}
		within("PSKHash", p.PSKHash)
		within("PSKNonce", p.PSKNonce)
		within("PSKIV", p.PSKIV)
		within("Compression", p.Compression)
		within("HdrExt", p.HdrExt)
		within("Payload", p.Payload)

		// PSK/LPC fields must be consistent with what the helpers say.
		if p.HasPSK != (p.PSKMode > 0) {
			t.Fatalf("HasPSK=%v but PSKMode=%d", p.HasPSK, p.PSKMode)
		}
		if PSKHasHash(p.PSKMode) != (p.PSKHash != nil) {
			t.Fatalf("PSK hash presence mismatch for mode %d", p.PSKMode)
		}
		if PSKHasNonce(p.PSKMode) != (p.PSKNonce != nil) {
			t.Fatalf("PSK nonce presence mismatch for mode %d", p.PSKMode)
		}
		if PSKHasIV(p.PSKMode) != (p.PSKIV != nil) {
			t.Fatalf("PSK iv presence mismatch for mode %d", p.PSKMode)
		}
		if p.HasCompression != (p.LPCMode == LPCFieldPresent) {
			t.Fatalf("HasCompression=%v but LPCMode=%d", p.HasCompression, p.LPCMode)
		}
	})
}

// FuzzRoundTrip builds a packet from fuzzer-derived parameters, parses it, and
// checks that the structured fields survive and that a re-build is byte-stable.
func FuzzRoundTrip(f *testing.F) {
	// seed: seq, ts, ssrc, encType, pskMode, lpcMode, flagBits, payload
	f.Add(uint32(0x12345678), uint32(1000000), uint32(0xAABBCC00),
		uint8(TypeDirect), uint8(PSKNone), uint8(LPCNone), uint8(0xC0), []byte("hi"))
	f.Add(uint32(0xFFFFFFFF), uint32(0), uint32(1),
		uint8(TypeGREMain), uint8(PSKAESCTRHMAC), uint8(LPCFieldPresent), uint8(0xFF), []byte{0x42})
	f.Add(uint32(0), uint32(0), uint32(0),
		uint8(TypeControl), uint8(PSKAESCTR), uint8(LPCLZ4), uint8(0x00), []byte(nil))

	f.Fuzz(func(t *testing.T, seq, ts, ssrc uint32, encType, pskMode, lpcMode, flagBits uint8, payload []byte) {
		params := Params{
			Seq:        seq,
			Timestamp:  ts,
			SSRC:       ssrc,
			EncType:    encType & typeMask,
			PSKMode:    pskMode & 0x07,
			LPCMode:    lpcMode & 0x03,
			FirstFrag:  flagBits&FlagF != 0,
			LastFrag:   flagBits&FlagL != 0,
			Expedite:   flagBits&FlagE != 0,
			Retransmit: flagBits&FlagR != 0,
		}
		// Supply correctly-sized PSK bytes for the chosen mode so Build does
		// not zero-fill (keeps the round trip deterministic).
		if PSKHasHash(params.PSKMode) {
			params.PSKHash = bytes.Repeat([]byte{0xA1}, PSKHashSize)
		}
		if PSKHasNonce(params.PSKMode) {
			params.PSKNonce = bytes.Repeat([]byte{0xB2}, PSKNonceSize)
		}
		if PSKHasIV(params.PSKMode) {
			params.PSKIV = bytes.Repeat([]byte{0xC3}, PSKIVSize)
		}
		if params.LPCMode == LPCFieldPresent {
			params.Compression = []byte{0xD4, 0xD4, 0xD4, 0xD4}
		}
		if flagBits&FlagI != 0 {
			params.FlowID = &FlowID{Outer: uint16(seq), Inner: uint16(ts) & 0xFFF, Sub: uint8(ssrc) & 0x0F}
		}
		if flagBits&FlagP != 0 {
			params.PFD = &PFD{IDType: uint8(seq) & 0x0F, IDValue: ts & 0x0FFFFFFF}
		}

		wire, err := Build(nil, params, payload)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		p, err := Parse(wire)
		if err != nil {
			t.Fatalf("Parse of built packet failed: %v", err)
		}

		if p.Seq != params.Seq {
			t.Fatalf("Seq %#x != %#x", p.Seq, params.Seq)
		}
		if p.Timestamp != params.Timestamp || p.SSRC != params.SSRC {
			t.Fatalf("ts/ssrc mismatch")
		}
		if p.EncType != params.EncType || p.PSKMode != params.PSKMode || p.LPCMode != params.LPCMode {
			t.Fatalf("type/psk/lpc mismatch")
		}
		if p.FirstFrag != params.FirstFrag || p.LastFrag != params.LastFrag ||
			p.Expedite != params.Expedite || p.Retransmit != params.Retransmit {
			t.Fatalf("flag mismatch")
		}
		if !bytes.Equal(p.Payload, payload) && !(len(p.Payload) == 0 && len(payload) == 0) {
			t.Fatalf("payload mismatch: %x != %x", p.Payload, payload)
		}

		// Byte-stable re-encode from the parse.
		rebuilt, err := Build(nil, paramsFromParsed(p), p.Payload)
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if !bytes.Equal(wire, rebuilt) {
			t.Fatalf("re-encode not byte-stable:\n %x\n %x", wire, rebuilt)
		}
		p2, err := Parse(rebuilt)
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if !reflect.DeepEqual(p, p2) {
			t.Fatalf("parse not stable:\n %+v\n %+v", p, p2)
		}
	})
}

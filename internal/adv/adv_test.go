package adv

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// goldenPackets carries hand-derived wire bytes for full Advanced Profile
// packets. The bytes were written out by hand from adv.c, not produced by the
// encoder, so they pin the framing independent of the round-trip tests.
var goldenPackets = []struct {
	name    string
	params  Params
	payload []byte
	want    []byte
}{
	{
		// Basic DIRECT, no PSK (mirrors test_adv_roundtrip.c
		// test_basic_roundtrip). seq=0x12345678 -> rtp seq 0x5678, seq_ext
		// 0x1234 (adv.h:300-307). ts=1000000=0x000F4240. ssrc=0xAABBCC00
		// (even = protected). flags = F|L = 0xC0 (adv.c:191-192). params:
		// PSK=0, LPC=0, Type=DIRECT(5) -> 0x05 (adv.h:113-145). RTP first
		// byte 0x80, PT 0x7F=127 (adv.c:178-179).
		name: "basic-direct-no-psk",
		params: Params{
			Seq:       0x12345678,
			Timestamp: 1000000,
			SSRC:      0xAABBCC00,
			EncType:   TypeDirect,
			PSKMode:   PSKNone,
			LPCMode:   LPCNone,
			FirstFrag: true,
			LastFrag:  true,
		},
		payload: append([]byte("Hello RIST Advanced Profile!"), 0),
		want: append([]byte{
			0x80, 0x7F, 0x56, 0x78, // RTP flags, PT, seq(low)
			0x00, 0x0F, 0x42, 0x40, // timestamp = 1000000
			0xAA, 0xBB, 0xCC, 0x00, // ssrc
			0x12, 0x34, // seq_ext (high)
			0xC0, // flags F|L
			0x05, // params: PSK=0 LPC=0 Type=5
		}, append([]byte("Hello RIST Advanced Profile!"), 0)...),
	},
	{
		// AES-CTR PSK (mode 1): nonce + IV, no hash (adv.h:187-204).
		// seq=1 -> rtp seq 0x0001, seq_ext 0x0000. ssrc=0x10 (even). flags
		// = F|L|PSK2; PSK mode 1 has bit2=0 so PSK2 stays clear -> 0xC0
		// (adv.h:113-117). params: PSK[1:0]=01<<6=0x40 | Type=DIRECT(5) ->
		// 0x45. Then nonce (4B) + IV (4B) per adv.c:218-227. payload 0x42.
		name: "psk-aes-ctr-nonce-iv",
		params: Params{
			Seq:       0x00000001,
			Timestamp: 0,
			SSRC:      0x00000010,
			EncType:   TypeDirect,
			PSKMode:   PSKAESCTR,
			FirstFrag: true,
			LastFrag:  true,
			PSKNonce:  []byte{0x11, 0x11, 0x11, 0x11},
			PSKIV:     []byte{0x22, 0x22, 0x22, 0x22},
		},
		payload: []byte{0x42},
		want: []byte{
			0x80, 0x7F, 0x00, 0x01, // RTP flags, PT, seq(low)=1
			0x00, 0x00, 0x00, 0x00, // timestamp = 0
			0x00, 0x00, 0x00, 0x10, // ssrc = 0x10
			0x00, 0x00, // seq_ext = 0
			0xC0,                   // flags F|L (PSK2 clear for mode 1)
			0x45,                   // params: PSK[1:0]=01 LPC=0 Type=5
			0x11, 0x11, 0x11, 0x11, // PSK nonce
			0x22, 0x22, 0x22, 0x22, // PSK IV
			0x42, // payload
		},
	},
}

// TestGoldenBytes pins the exact wire framing for the hand-derived vectors.
func TestGoldenBytes(t *testing.T) {
	for _, g := range goldenPackets {
		t.Run(g.name, func(t *testing.T) {
			got, err := Build(nil, g.params, g.payload)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if !bytes.Equal(got, g.want) {
				t.Fatalf("Build bytes mismatch:\n got  %x\n want %x", got, g.want)
			}
			if HeaderSize(g.params) != len(g.want)-len(g.payload) {
				t.Fatalf("HeaderSize = %d, want %d", HeaderSize(g.params), len(g.want)-len(g.payload))
			}
		})
	}
}

// TestBasicRoundTrip mirrors test_adv_roundtrip.c test_basic_roundtrip.
func TestBasicRoundTrip(t *testing.T) {
	payload := append([]byte("Hello RIST Advanced Profile!"), 0)
	params := Params{
		Seq:       0x12345678,
		Timestamp: 1000000,
		SSRC:      0xAABBCC00,
		EncType:   TypeDirect,
		PSKMode:   PSKNone,
		LPCMode:   LPCNone,
		FirstFrag: true,
		LastFrag:  true,
	}

	wire, err := Build(nil, params, payload)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(wire) != HeaderMin+len(payload) {
		t.Fatalf("len = %d, want %d", len(wire), HeaderMin+len(payload))
	}

	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Seq != 0x12345678 {
		t.Errorf("Seq = %#x, want 0x12345678", p.Seq)
	}
	if p.Timestamp != 1000000 {
		t.Errorf("Timestamp = %d, want 1000000", p.Timestamp)
	}
	if p.SSRC != 0xAABBCC00 {
		t.Errorf("SSRC = %#x, want 0xAABBCC00", p.SSRC)
	}
	if p.EncType != TypeDirect {
		t.Errorf("EncType = %d, want %d", p.EncType, TypeDirect)
	}
	if p.PSKMode != PSKNone {
		t.Errorf("PSKMode = %d, want %d", p.PSKMode, PSKNone)
	}
	if p.LPCMode != LPCNone {
		t.Errorf("LPCMode = %d, want %d", p.LPCMode, LPCNone)
	}
	if !p.FirstFrag || !p.LastFrag {
		t.Errorf("FirstFrag/LastFrag = %v/%v, want true/true", p.FirstFrag, p.LastFrag)
	}
	if p.Expedite || p.Retransmit {
		t.Errorf("Expedite/Retransmit = %v/%v, want false/false", p.Expedite, p.Retransmit)
	}
	if p.HasFlowID || p.HasPFD || p.HasHdrExt {
		t.Errorf("unexpected optional flags: flow=%v pfd=%v hdr=%v", p.HasFlowID, p.HasPFD, p.HasHdrExt)
	}
	if !bytes.Equal(p.Payload, payload) {
		t.Errorf("Payload = %x, want %x", p.Payload, payload)
	}
}

// TestFlagsRoundTrip mirrors test_adv_roundtrip.c test_flags_roundtrip
// (E+R flags, Control type, 32-bit seq wrap).
func TestFlagsRoundTrip(t *testing.T) {
	params := Params{
		Seq:        0xFFFF0001,
		Timestamp:  999999,
		SSRC:       0x00000002,
		EncType:    TypeControl,
		FirstFrag:  true,
		LastFrag:   true,
		Expedite:   true,
		Retransmit: true,
	}
	wire, err := Build(nil, params, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Expedite {
		t.Error("Expedite not round-tripped")
	}
	if !p.Retransmit {
		t.Error("Retransmit not round-tripped")
	}
	if p.EncType != TypeControl {
		t.Errorf("EncType = %d, want %d", p.EncType, TypeControl)
	}
	if p.Seq != 0xFFFF0001 {
		t.Errorf("Seq = %#x, want 0xFFFF0001", p.Seq)
	}
}

// TestFlowIDRoundTrip mirrors test_adv_roundtrip.c test_flow_id_roundtrip:
// outer 0x1234, inner 0xABC, sub 0x5.
func TestFlowIDRoundTrip(t *testing.T) {
	params := Params{
		Seq:       100,
		Timestamp: 500,
		SSRC:      0x10,
		EncType:   TypeDirect,
		FirstFrag: true,
		LastFrag:  true,
		FlowID:    &FlowID{Outer: 0x1234, Inner: 0xABC, Sub: 0x5},
	}
	wire, err := Build(nil, params, []byte{0xAA})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.HasFlowID {
		t.Fatal("HasFlowID = false")
	}
	if p.FlowID.Outer != 0x1234 {
		t.Errorf("Outer = %#x, want 0x1234", p.FlowID.Outer)
	}
	if p.FlowID.Inner != 0xABC {
		t.Errorf("Inner = %#x, want 0xABC", p.FlowID.Inner)
	}
	if p.FlowID.Sub != 0x5 {
		t.Errorf("Sub = %#x, want 0x5", p.FlowID.Sub)
	}
}

// TestPFDRoundTrip mirrors test_adv_roundtrip.c test_pfd_roundtrip:
// id_type=1, id_value=0x0ABCDEF.
func TestPFDRoundTrip(t *testing.T) {
	params := Params{
		Seq:       200,
		Timestamp: 1000,
		SSRC:      0x20,
		EncType:   TypeDirect,
		FirstFrag: true,
		LastFrag:  true,
		PFD:       &PFD{IDType: 1, IDValue: 0x0ABCDEF},
	}
	wire, err := Build(nil, params, []byte{0x55})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.HasPFD {
		t.Fatal("HasPFD = false")
	}
	if p.PFD.IDType != 1 {
		t.Errorf("IDType = %d, want 1", p.PFD.IDType)
	}
	if p.PFD.IDValue != 0x0ABCDEF {
		t.Errorf("IDValue = %#x, want 0x0ABCDEF", p.PFD.IDValue)
	}
}

// TestAllPSKModes mirrors test_adv_roundtrip.c test_all_psk_modes: builds and
// parses each of the eight PSK modes, asserting hash/nonce/iv presence and
// byte content per the mode's Table-1 layout.
func TestAllPSKModes(t *testing.T) {
	for psk := uint8(0); psk <= 7; psk++ {
		hash := bytes.Repeat([]byte{psk}, 16)
		nonce := bytes.Repeat([]byte{psk + 0x10}, 4)
		iv := bytes.Repeat([]byte{psk + 0x20}, 4)

		params := Params{
			Seq:       uint32(300 + int(psk)),
			Timestamp: 2000,
			SSRC:      0x30,
			EncType:   TypeDirect,
			PSKMode:   psk,
			FirstFrag: true,
			LastFrag:  true,
		}
		if PSKHasHash(psk) {
			params.PSKHash = hash
		}
		if PSKHasNonce(psk) {
			params.PSKNonce = nonce
		}
		if PSKHasIV(psk) {
			params.PSKIV = iv
		}

		wire, err := Build(nil, params, []byte{0x42})
		if err != nil {
			t.Fatalf("psk=%d Build: %v", psk, err)
		}
		p, err := Parse(wire)
		if err != nil {
			t.Fatalf("psk=%d Parse: %v", psk, err)
		}
		if p.PSKMode != psk {
			t.Errorf("psk=%d: PSKMode = %d", psk, p.PSKMode)
		}
		if p.HasPSK != (psk > 0) {
			t.Errorf("psk=%d: HasPSK = %v", psk, p.HasPSK)
		}
		if PSKHasHash(psk) {
			if !bytes.Equal(p.PSKHash, hash) {
				t.Errorf("psk=%d: hash = %x, want %x", psk, p.PSKHash, hash)
			}
		} else if p.PSKHash != nil {
			t.Errorf("psk=%d: unexpected hash %x", psk, p.PSKHash)
		}
		if PSKHasNonce(psk) {
			if !bytes.Equal(p.PSKNonce, nonce) {
				t.Errorf("psk=%d: nonce = %x, want %x", psk, p.PSKNonce, nonce)
			}
		} else if p.PSKNonce != nil {
			t.Errorf("psk=%d: unexpected nonce %x", psk, p.PSKNonce)
		}
		if PSKHasIV(psk) {
			if !bytes.Equal(p.PSKIV, iv) {
				t.Errorf("psk=%d: iv = %x, want %x", psk, p.PSKIV, iv)
			}
		} else if p.PSKIV != nil {
			t.Errorf("psk=%d: unexpected iv %x", psk, p.PSKIV)
		}
	}
}

// TestSeq32Wraparound mirrors test_adv_roundtrip.c test_seq32_wraparound.
func TestSeq32Wraparound(t *testing.T) {
	seqs := []uint32{0, 1, 0xFFFF, 0x10000, 0xFFFFFFFE, 0xFFFFFFFF}
	for _, seq := range seqs {
		params := Params{
			Seq:       seq,
			SSRC:      0x40,
			EncType:   TypeDirect,
			FirstFrag: true,
			LastFrag:  true,
		}
		wire, err := Build(nil, params, []byte{0})
		if err != nil {
			t.Fatalf("seq=%#x Build: %v", seq, err)
		}
		p, err := Parse(wire)
		if err != nil {
			t.Fatalf("seq=%#x Parse: %v", seq, err)
		}
		if p.Seq != seq {
			t.Errorf("Seq = %#x, want %#x", p.Seq, seq)
		}
	}
}

// TestType8RoundTrip mirrors test_adv_roundtrip.c test_type8_roundtrip: a
// GRE-Main (Type=8) payload carried verbatim.
func TestType8RoundTrip(t *testing.T) {
	gre := []byte{0x00, 0x00, 0x08, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	params := Params{
		Seq:       0x00010042,
		Timestamp: 123456,
		SSRC:      0xAABBCC00,
		EncType:   TypeGREMain,
		FirstFrag: true,
		LastFrag:  true,
		Expedite:  true,
	}
	wire, err := Build(nil, params, gre)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.EncType != TypeGREMain {
		t.Errorf("EncType = %d, want %d", p.EncType, TypeGREMain)
	}
	if p.Seq != 0x00010042 {
		t.Errorf("Seq = %#x, want 0x00010042", p.Seq)
	}
	if !bytes.Equal(p.Payload, gre) {
		t.Errorf("Payload = %x, want %x", p.Payload, gre)
	}
}

// TestLPCRoundTrip exercises LPC modes: LZ4 (no compression field) and
// FieldPresent (a 4-byte compression field). Mirrors test_lz4_header_roundtrip
// for the framing aspects (the actual LZ4 codec lives elsewhere).
func TestLPCRoundTrip(t *testing.T) {
	t.Run("lz4-no-field", func(t *testing.T) {
		params := Params{
			Seq:       99,
			Timestamp: 12345,
			SSRC:      0x1000,
			EncType:   TypeDirect,
			LPCMode:   LPCLZ4,
			FirstFrag: true,
			LastFrag:  true,
		}
		payload := []byte("compressed-bytes-go-here")
		wire, err := Build(nil, params, payload)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(wire) != HeaderMin+len(payload) {
			t.Fatalf("LZ4 mode must not add a compression field: len=%d", len(wire))
		}
		p, err := Parse(wire)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if p.LPCMode != LPCLZ4 {
			t.Errorf("LPCMode = %d, want %d", p.LPCMode, LPCLZ4)
		}
		if p.HasCompression {
			t.Error("HasCompression set for LZ4 mode")
		}
		if !bytes.Equal(p.Payload, payload) {
			t.Errorf("Payload mismatch")
		}
	})

	t.Run("field-present", func(t *testing.T) {
		comp := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		params := Params{
			Seq:         7,
			EncType:     TypeDirect,
			LPCMode:     LPCFieldPresent,
			FirstFrag:   true,
			LastFrag:    true,
			Compression: comp,
		}
		wire, err := Build(nil, params, []byte{0xAB})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		p, err := Parse(wire)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !p.HasCompression {
			t.Fatal("HasCompression = false")
		}
		if !bytes.Equal(p.Compression, comp) {
			t.Errorf("Compression = %x, want %x", p.Compression, comp)
		}
	})
}

// TestHdrExtRoundTrip exercises the RIST Header Extension (H flag): an RFC
// 3550-style extension carried verbatim (adv.c:160-167).
func TestHdrExtRoundTrip(t *testing.T) {
	// 4-byte extension header (profile 0x5249, length 1 word) + 4-byte body.
	ext := []byte{0x52, 0x49, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD}
	params := Params{
		Seq:       1,
		EncType:   TypeDirect,
		FirstFrag: true,
		LastFrag:  true,
		HdrExt:    ext,
	}
	payload := []byte{0x01, 0x02}
	wire, err := Build(nil, params, payload)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.HasHdrExt {
		t.Fatal("HasHdrExt = false")
	}
	if !bytes.Equal(p.HdrExt, ext) {
		t.Errorf("HdrExt = %x, want %x", p.HdrExt, ext)
	}
	if !bytes.Equal(p.Payload, payload) {
		t.Errorf("Payload = %x, want %x", p.Payload, payload)
	}
}

// TestControlPayload mirrors test_adv_roundtrip.c test_flow_attr_control_
// roundtrip: a Type-Control packet carrying a CI+Len+body control message in
// its payload (the codec treats the control body as opaque payload).
func TestControlPayload(t *testing.T) {
	json := []byte(`{"session":"test","flow_id":5000}`)
	ctrl := make([]byte, 0, 4+len(json))
	ctrl = append(ctrl, byte(CIFlowAttr>>8), byte(CIFlowAttr&0xFF))
	ctrl = append(ctrl, byte(len(json)>>8), byte(len(json)))
	ctrl = append(ctrl, json...)

	params := Params{
		Seq:       777,
		Timestamp: 54321,
		SSRC:      0x60 | 1, // odd = unprotected
		EncType:   TypeControl,
		FirstFrag: true,
		LastFrag:  true,
		Expedite:  true,
	}
	wire, err := Build(nil, params, ctrl)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.EncType != TypeControl {
		t.Errorf("EncType = %d, want %d", p.EncType, TypeControl)
	}
	if SSRCIsProtected(p.SSRC) {
		t.Error("odd SSRC should be unprotected")
	}
	if len(p.Payload) < CtrlHdrSize {
		t.Fatalf("control payload too short: %d", len(p.Payload))
	}
	ci := uint16(p.Payload[0])<<8 | uint16(p.Payload[1])
	bl := uint16(p.Payload[2])<<8 | uint16(p.Payload[3])
	if ci != CIFlowAttr {
		t.Errorf("CI = %#x, want %#x", ci, CIFlowAttr)
	}
	if int(bl) != len(json) {
		t.Errorf("body len = %d, want %d", bl, len(json))
	}
	if !bytes.Equal(p.Payload[4:], json) {
		t.Errorf("control body mismatch")
	}
}

// TestSSRCParity mirrors test_adv_roundtrip.c test_ssrc_parity.
func TestSSRCParity(t *testing.T) {
	cases := []struct {
		ssrc      uint32
		protected bool
	}{
		{0x00000000, true},
		{0x00000001, false},
		{0xFFFFFFFE, true},
		{0xFFFFFFFF, false},
	}
	for _, c := range cases {
		if got := SSRCIsProtected(c.ssrc); got != c.protected {
			t.Errorf("SSRCIsProtected(%#x) = %v, want %v", c.ssrc, got, c.protected)
		}
	}
	if got := SSRCProtected(0x12345679); got != 0x12345678 {
		t.Errorf("SSRCProtected(0x12345679) = %#x, want 0x12345678", got)
	}
	if got := SSRCUnprotected(0x12345678); got != 0x12345679 {
		t.Errorf("SSRCUnprotected(0x12345678) = %#x, want 0x12345679", got)
	}
}

// TestPSKHdrSizes mirrors test_adv_roundtrip.c test_psk_hdr_sizes.
func TestPSKHdrSizes(t *testing.T) {
	want := map[uint8]int{0: 0, 1: 8, 2: 20, 3: 24, 4: 24, 5: 24, 6: 8, 7: 24}
	for psk := uint8(0); psk <= 7; psk++ {
		if got := PSKHdrSize(psk); got != want[psk] {
			t.Errorf("PSKHdrSize(%d) = %d, want %d", psk, got, want[psk])
		}
	}
}

// TestPSKHelperTables freezes the per-mode hash/nonce/iv presence flags
// (adv.h:182-204).
func TestPSKHelperTables(t *testing.T) {
	cases := []struct {
		psk             uint8
		hash, nonce, iv bool
	}{
		{0, false, false, false},
		{1, false, true, true},
		{2, true, true, false},
		{3, true, true, true},
		{4, true, true, true},
		{5, true, true, true},
		{6, false, true, true},
		{7, true, true, true},
	}
	for _, c := range cases {
		if got := PSKHasHash(c.psk); got != c.hash {
			t.Errorf("PSKHasHash(%d) = %v, want %v", c.psk, got, c.hash)
		}
		if got := PSKHasNonce(c.psk); got != c.nonce {
			t.Errorf("PSKHasNonce(%d) = %v, want %v", c.psk, got, c.nonce)
		}
		if got := PSKHasIV(c.psk); got != c.iv {
			t.Errorf("PSKHasIV(%d) = %v, want %v", c.psk, got, c.iv)
		}
	}
}

// TestMalformedPackets mirrors test_adv_roundtrip.c test_malformed_packets.
func TestMalformedPackets(t *testing.T) {
	if _, err := Parse(nil); !errors.Is(err, ErrShortBuffer) {
		t.Errorf("nil buf: err = %v, want ErrShortBuffer", err)
	}
	if _, err := Parse(make([]byte, 8)); !errors.Is(err, ErrShortBuffer) {
		t.Errorf("short packet: err = %v, want ErrShortBuffer", err)
	}
	bad := make([]byte, 32)
	bad[0] = 0x40 // V=1
	bad[1] = PayloadType
	if _, err := Parse(bad); !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("bad version: err = %v, want ErrInvalidVersion", err)
	}
}

// TestParseAliasesInput verifies the optional fields and payload alias the
// input buffer (zero-copy house style).
func TestParseAliasesInput(t *testing.T) {
	params := Params{
		Seq:       1,
		EncType:   TypeDirect,
		PSKMode:   PSKAESGCM,
		FirstFrag: true,
		LastFrag:  true,
		PSKHash:   bytes.Repeat([]byte{0x11}, 16),
		PSKNonce:  bytes.Repeat([]byte{0x22}, 4),
		PSKIV:     bytes.Repeat([]byte{0x33}, 4),
	}
	wire, err := Build(nil, params, []byte{0x99})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Mutate the underlying buffer; the parsed slices must reflect it.
	for i := range p.PSKHash {
		wire[12+4+i] = 0xEE
	}
	if p.PSKHash[0] != 0xEE {
		t.Error("PSKHash does not alias input buffer")
	}
}

// TestRoundTripDeepEqual verifies a parsed packet rebuilds byte-identically,
// across a representative matrix of optional-field combinations.
func TestRoundTripDeepEqual(t *testing.T) {
	for _, g := range goldenPackets {
		t.Run(g.name, func(t *testing.T) {
			wire, err := Build(nil, g.params, g.payload)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			p1, err := Parse(wire)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			// Re-build from a Params reconstructed from the parse, then
			// re-parse, and compare the two parses.
			rebuilt, err := Build(nil, paramsFromParsed(p1), p1.Payload)
			if err != nil {
				t.Fatalf("rebuild: %v", err)
			}
			if !bytes.Equal(wire, rebuilt) {
				t.Fatalf("rebuild not byte-stable:\n %x\n %x", wire, rebuilt)
			}
			p2, err := Parse(rebuilt)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			if !reflect.DeepEqual(p1, p2) {
				t.Fatalf("parse not stable:\n %+v\n %+v", p1, p2)
			}
		})
	}
}

// paramsFromParsed reconstructs Build input from a Parsed packet, used to test
// the structured round trip.
func paramsFromParsed(p Parsed) Params {
	params := Params{
		Seq:         p.Seq,
		Timestamp:   p.Timestamp,
		SSRC:        p.SSRC,
		EncType:     p.EncType,
		PSKMode:     p.PSKMode,
		LPCMode:     p.LPCMode,
		FirstFrag:   p.FirstFrag,
		LastFrag:    p.LastFrag,
		Expedite:    p.Expedite,
		Retransmit:  p.Retransmit,
		PSKHash:     p.PSKHash,
		PSKNonce:    p.PSKNonce,
		PSKIV:       p.PSKIV,
		Compression: p.Compression,
		HdrExt:      p.HdrExt,
	}
	if p.HasFlowID {
		f := p.FlowID
		params.FlowID = &f
	}
	if p.HasPFD {
		pfd := p.PFD
		params.PFD = &pfd
	}
	return params
}

// TestFragmentHelpers freezes the F/L predicate truth table (adv.h:316-336).
func TestFragmentHelpers(t *testing.T) {
	cases := []struct {
		flags                     uint8
		unfrag, frag, first, last bool
	}{
		{FlagF | FlagL, true, false, false, false},
		{FlagF, false, true, true, false},
		{0, false, true, false, false},
		{FlagL, false, true, false, true},
	}
	for _, c := range cases {
		if got := IsUnfragmented(c.flags); got != c.unfrag {
			t.Errorf("IsUnfragmented(%#x) = %v, want %v", c.flags, got, c.unfrag)
		}
		if got := IsFragmented(c.flags); got != c.frag {
			t.Errorf("IsFragmented(%#x) = %v, want %v", c.flags, got, c.frag)
		}
		if got := IsFirstFragment(c.flags); got != c.first {
			t.Errorf("IsFirstFragment(%#x) = %v, want %v", c.flags, got, c.first)
		}
		if got := IsLastFragment(c.flags); got != c.last {
			t.Errorf("IsLastFragment(%#x) = %v, want %v", c.flags, got, c.last)
		}
	}
}

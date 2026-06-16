package adv

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestControlGolden pins each control message's wire bytes against the layouts
// verified directly from libRIST. The sub-header is CI(2) +
// Length(2), big-endian, followed by the per-index body.
func TestControlGolden(t *testing.T) {
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{
			// CI 0x0000, len 12, SSRC|PSS|BLP.
			name: "nack-bitmask",
			got:  BuildNackBitmask(nil, NackBitmask{MediaSSRC: 0x11223344, PSS: 0x00000064, BLP: 0x00000005}),
			want: "0000000c11223344000000640000 0005",
		},
		{
			// CI 0x0001, len 12, SSRC|PSS|NALP.
			name: "nack-range",
			got:  BuildNackRange(nil, NackRange{MediaSSRC: 0x11223344, PSS: 0x00010002, NALP: 5}),
			want: "0001000c1122334400010002 00000005",
		},
		{
			// CI 0x0010, len 16, ReqSSRC|MSW|LSW|ProcDelay.
			name: "rtt-echo-request",
			got:  BuildRTTEchoRequest(nil, RTTEchoFromTimestamp(0xAABBCCDD, 0x1122334455667788, 0)),
			want: "00100010aabbccdd1122334455667788 00000000",
		},
		{
			// CI 0x0011, len 16, with processing delay.
			name: "rtt-echo-response",
			got:  BuildRTTEchoResponse(nil, RTTEchoFromTimestamp(0xAABBCCDD, 0x1122334455667788, 0x00000190)),
			want: "00110010aabbccdd1122334455667788 00000190",
		},
		{
			// CI 0x8000, len 10, MAC(6)|Caps(4); I bit set.
			name: "keepalive",
			got:  BuildKeepalive(nil, Keepalive{MAC: [6]byte{1, 2, 3, 4, 5, 6}, Caps: KeepaliveCapI}),
			want: "8000000a01020304050680000000",
		},
		{
			// CI 0x8011, len 8, Nonce(4)|KeyBits(2)|Rsvd(2).
			name: "psk-nonce",
			got:  BuildPSKNonce(nil, PSKNonce{Nonce: [4]byte{0xAA, 0xBB, 0xCC, 0xDD}, KeyBits: 256}),
			want: "80110008aabbccdd01000000",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := mustHex(t, tc.want)
			if !bytes.Equal(tc.got, want) {
				t.Fatalf("%s wire bytes:\n got  %x\n want %x", tc.name, tc.got, want)
			}
			// ParseControl must recover the control index and body.
			ci, body, err := ParseControl(tc.got)
			if err != nil {
				t.Fatalf("ParseControl: %v", err)
			}
			if int(ci) == 0 && tc.name != "nack-bitmask" {
				t.Fatalf("unexpected zero CI for %s", tc.name)
			}
			if 4+len(body) != len(tc.got) {
				t.Fatalf("body length %d + 4 != datagram %d", len(body), len(tc.got))
			}
		})
	}
}

// TestControlRoundTrip checks Build then Parse recovers every field for each
// message type.
func TestControlRoundTrip(t *testing.T) {
	t.Run("nack-bitmask", func(t *testing.T) {
		in := NackBitmask{MediaSSRC: 0xDEADBEEF, PSS: 0x01020304, BLP: 0x80000001}
		_, body, err := ParseControl(BuildNackBitmask(nil, in))
		if err != nil {
			t.Fatal(err)
		}
		out, err := ParseNackBitmask(body)
		if err != nil || out != in {
			t.Fatalf("round-trip: got %+v err %v, want %+v", out, err, in)
		}
	})
	t.Run("nack-range", func(t *testing.T) {
		in := NackRange{MediaSSRC: 0xDEADBEEF, PSS: 0x01020304, NALP: 42}
		_, body, err := ParseControl(BuildNackRange(nil, in))
		if err != nil {
			t.Fatal(err)
		}
		out, err := ParseNackRange(body)
		if err != nil || out != in {
			t.Fatalf("round-trip: got %+v err %v, want %+v", out, err, in)
		}
	})
	t.Run("rtt-echo", func(t *testing.T) {
		in := RTTEchoFromTimestamp(0x12345678, 0xCAFEF00DDEADBEEF, 0x1234)
		_, body, err := ParseControl(BuildRTTEchoResponse(nil, in))
		if err != nil {
			t.Fatal(err)
		}
		out, err := ParseRTTEcho(body)
		if err != nil || out != in {
			t.Fatalf("round-trip: got %+v err %v, want %+v", out, err, in)
		}
		if out.Timestamp() != 0xCAFEF00DDEADBEEF {
			t.Fatalf("Timestamp() = %#x", out.Timestamp())
		}
	})
	t.Run("keepalive", func(t *testing.T) {
		in := Keepalive{MAC: [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, Caps: KeepaliveCapI | KeepaliveCapC}
		_, body, err := ParseControl(BuildKeepalive(nil, in))
		if err != nil {
			t.Fatal(err)
		}
		out, err := ParseKeepalive(body)
		if err != nil || out != in {
			t.Fatalf("round-trip: got %+v err %v, want %+v", out, err, in)
		}
	})
	t.Run("psk-nonce", func(t *testing.T) {
		in := PSKNonce{Nonce: [4]byte{0x01, 0x80, 0x00, 0xFF}, KeyBits: 128}
		_, body, err := ParseControl(BuildPSKNonce(nil, in))
		if err != nil {
			t.Fatal(err)
		}
		out, err := ParsePSKNonce(body)
		if err != nil || out != in {
			t.Fatalf("round-trip: got %+v err %v, want %+v", out, err, in)
		}
	})
}

// TestNackBitmaskMissing checks the BLP expansion (bit i -> PSS+1+i, plus PSS).
func TestNackBitmaskMissing(t *testing.T) {
	n := NackBitmask{PSS: 100, BLP: 0b1011} // bits 0,1,3 -> 101,102,104
	want := []uint32{100, 101, 102, 104}
	if got := n.Missing(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Missing() = %v, want %v", got, want)
	}
	if got := (NackBitmask{PSS: 7, BLP: 0}).Missing(); !reflect.DeepEqual(got, []uint32{7}) {
		t.Fatalf("Missing() with BLP=0 = %v, want [7]", got)
	}
}

// TestNackRangeMissing checks the inclusive PSS..PSS+NALP expansion and the
// decode cap that bounds a hostile NALP.
func TestNackRangeMissing(t *testing.T) {
	if got := (NackRange{PSS: 10, NALP: 3}).Missing(); !reflect.DeepEqual(got, []uint32{10, 11, 12, 13}) {
		t.Fatalf("Missing() = %v, want [10 11 12 13]", got)
	}
	// A huge NALP is clamped to maxNACKDecodeRange+1 entries, never unbounded.
	if got := (NackRange{PSS: 0, NALP: 1 << 30}).Missing(); len(got) != maxNACKDecodeRange+1 {
		t.Fatalf("clamped Missing() len = %d, want %d", len(got), maxNACKDecodeRange+1)
	}
}

// TestEncodeNACK checks both encoders pack a missing list correctly and that the
// expansion round-trips back to the sorted, de-duplicated input.
func TestEncodeNACK(t *testing.T) {
	cases := [][]uint32{
		{5},
		{10, 11, 12, 20, 21},
		{100, 102, 104, 140},     // gaps within and beyond a bitmask window
		{7, 7, 8, 8, 9},          // duplicates
		{300, 299, 298, 1, 2, 3}, // unsorted, two runs
		{0, 32, 33},              // bitmask boundary: 0+32 in window, 33 not
	}
	for _, missing := range cases {
		// Range NACK.
		var fromRange []uint32
		for _, n := range EncodeRangeNACK(0xABCD, missing) {
			if n.MediaSSRC != 0xABCD {
				t.Fatalf("range entry SSRC = %#x", n.MediaSSRC)
			}
			fromRange = append(fromRange, n.Missing()...)
		}
		if !reflect.DeepEqual(sortedUniq(fromRange), sortedUniq(missing)) {
			t.Fatalf("range round-trip for %v: got %v", missing, sortedUniq(fromRange))
		}
		// Bitmask NACK.
		var fromBitmask []uint32
		for _, n := range EncodeBitmaskNACK(0xABCD, missing) {
			fromBitmask = append(fromBitmask, n.Missing()...)
		}
		if !reflect.DeepEqual(sortedUniq(fromBitmask), sortedUniq(missing)) {
			t.Fatalf("bitmask round-trip for %v: got %v", missing, sortedUniq(fromBitmask))
		}
	}
	if EncodeRangeNACK(1, nil) != nil || EncodeBitmaskNACK(1, nil) != nil {
		t.Fatalf("empty missing list must encode to nil")
	}
}

// TestEncodeRangeSplitsLongRun verifies a run longer than the decode cap is
// split into multiple entries so the peer's recovery cap recovers every seq.
func TestEncodeRangeSplitsLongRun(t *testing.T) {
	n := maxNACKDecodeRange + 50
	missing := make([]uint32, n)
	for i := range missing {
		missing[i] = uint32(i)
	}
	entries := EncodeRangeNACK(1, missing)
	if len(entries) < 2 {
		t.Fatalf("expected the long run to split into >=2 entries, got %d", len(entries))
	}
	var all []uint32
	for _, e := range entries {
		all = append(all, e.Missing()...)
	}
	if !reflect.DeepEqual(sortedUniq(all), missing) {
		t.Fatalf("split range did not cover the full run")
	}
}

// TestParseControlErrors checks malformed control payloads return ErrShortControl
// rather than panicking.
func TestParseControlErrors(t *testing.T) {
	if _, _, err := ParseControl([]byte{0x00, 0x00, 0x00}); !errors.Is(err, ErrShortControl) {
		t.Fatalf("short sub-header: err = %v, want ErrShortControl", err)
	}
	// Length claims more than is present.
	if _, _, err := ParseControl([]byte{0x00, 0x00, 0x00, 0xFF, 0x01}); !errors.Is(err, ErrShortControl) {
		t.Fatalf("overlong length: err = %v, want ErrShortControl", err)
	}
	// Each body parser rejects a too-short body.
	if _, err := ParseNackRange([]byte{1, 2, 3}); !errors.Is(err, ErrShortControl) {
		t.Fatalf("short nack range: %v", err)
	}
	if _, err := ParseRTTEcho([]byte{1, 2, 3}); !errors.Is(err, ErrShortControl) {
		t.Fatalf("short rtt echo: %v", err)
	}
	if _, err := ParseKeepalive([]byte{1}); !errors.Is(err, ErrShortControl) {
		t.Fatalf("short keepalive: %v", err)
	}
	if _, err := ParsePSKNonce([]byte{1}); !errors.Is(err, ErrShortControl) {
		t.Fatalf("short psk nonce: %v", err)
	}
}

// TestParseControlTrailingTolerated checks a Length shorter than the bytes
// present is tolerated (libRIST's Unsupported-message quirk writes 16 body bytes
// but stamps Length=12).
func TestParseControlTrailingTolerated(t *testing.T) {
	// CI 0x8020, Length 12, but 16 trailing bytes.
	payload := append([]byte{0x80, 0x20, 0x00, 0x0C}, make([]byte, 16)...)
	ci, body, err := ParseControl(payload)
	if err != nil {
		t.Fatalf("ParseControl tolerant decode: %v", err)
	}
	if ci != CIUnsupported {
		t.Fatalf("ci = %#x, want %#x", ci, CIUnsupported)
	}
	if len(body) != 12 {
		t.Fatalf("body trimmed to Length: got %d, want 12", len(body))
	}
}

func sortedUniq(s []uint32) []uint32 {
	if len(s) == 0 {
		return nil
	}
	c := append([]uint32(nil), s...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	out := c[:1]
	for _, v := range c[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// TestBuildUnsupportedRoundTrip checks the Control Message Unsupported Response
// (CI 0x8020) framing: CI, echoed incoming CI, head bytes, and the 16-byte body.
func TestBuildUnsupportedRoundTrip(t *testing.T) {
	u := Unsupported{ResponderSSRC: 0x0ACE0AC1, IncomingCI: 0x7abc, Head: [6]byte{1, 2, 3, 4, 5, 6}}
	ci, body, err := ParseControl(BuildUnsupported(nil, u))
	if err != nil {
		t.Fatalf("ParseControl: %v", err)
	}
	if ci != CIUnsupported {
		t.Fatalf("ci = %#x, want %#x", ci, CIUnsupported)
	}
	if want := 4 + 2 + 2 + unsupportedHeadLen + 2; len(body) != want {
		t.Fatalf("body len = %d, want %d", len(body), want)
	}
	if got := uint16(body[4])<<8 | uint16(body[5]); got != u.IncomingCI {
		t.Errorf("echoed CI = %#x, want %#x", got, u.IncomingCI)
	}
	if got := [6]byte(body[8:14]); got != u.Head {
		t.Errorf("head = % x, want % x", got, u.Head)
	}
}

package adapt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
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

// TestLQMGolden pins the 44-byte wire layout against TR-06-4 Part 1 Figure 2:
// eleven 32-bit big-endian fields in the documented order.
func TestLQMGolden(t *testing.T) {
	m := LQM{
		SequenceNumber:              1,
		ReportingPeriodMS:           1000,
		NACKWindowMS:                500,
		SourceReceived:              1000,
		OriginalLost:                10,
		RetransmittedReceived:       8,
		Recovered:                   7,
		Unrecovered:                 3,
		Late:                        2,
		DataBandwidthKbps:           5000,
		RetransmissionBandwidthKbps: 120,
	}
	want := mustHex(t, "00000001 000003e8 000001f4 000003e8 0000000a"+
		"00000008 00000007 00000003 00000002 00001388 00000078")
	got := m.Marshal()
	if len(got) != LQMSize {
		t.Fatalf("Marshal len = %d, want %d", len(got), LQMSize)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("LQM wire bytes:\n got  %x\n want %x", got, want)
	}
}

// TestLQMRoundTrip checks Marshal then Parse recovers every field, including
// when there are trailing bytes (an RR extension or adv control body may carry
// padding/more data after the 44-byte block).
func TestLQMRoundTrip(t *testing.T) {
	in := LQM{
		SequenceNumber: 0xDEADBEEF, ReportingPeriodMS: 250, NACKWindowMS: 1000,
		SourceReceived: 123456, OriginalLost: 789, RetransmittedReceived: 456,
		Recovered: 700, Unrecovered: 89, Late: 12,
		DataBandwidthKbps: 0x01020304, RetransmissionBandwidthKbps: 0xFFFFFFFF,
	}
	out, err := Parse(append(in.Marshal(), 0xAA, 0xBB)) // trailing bytes
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip:\n got  %+v\n want %+v", out, in)
	}
}

// TestLQMParseShort checks short input returns ErrShortLQM, never panics.
func TestLQMParseShort(t *testing.T) {
	for n := 0; n < LQMSize; n++ {
		if _, err := Parse(make([]byte, n)); !errors.Is(err, ErrShortLQM) {
			t.Fatalf("Parse(%d bytes) err = %v, want ErrShortLQM", n, err)
		}
	}
}

// TestLossFractions checks the derived loss signals.
func TestLossFractions(t *testing.T) {
	m := LQM{SourceReceived: 990, OriginalLost: 10, Unrecovered: 2}
	if got := m.LossFraction(); math.Abs(got-0.01) > 1e-9 {
		t.Fatalf("LossFraction = %v, want 0.01", got)
	}
	if got := m.ResidualLossFraction(); math.Abs(got-0.002) > 1e-9 {
		t.Fatalf("ResidualLossFraction = %v, want 0.002", got)
	}
	// No accounting -> 0, not NaN.
	if got := (LQM{}).LossFraction(); got != 0 {
		t.Fatalf("empty LossFraction = %v, want 0", got)
	}
}

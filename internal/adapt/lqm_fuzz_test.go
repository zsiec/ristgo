package adapt

import (
	"bytes"
	"testing"

	"github.com/zsiec/ristgo/internal/adv"
)

// FuzzParseLQM feeds arbitrary bytes to Parse: it must never panic, and any
// successful parse must Marshal back to the same first 44 bytes (byte-stable).
func FuzzParseLQM(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, LQMSize))
	f.Add(bytes.Repeat([]byte{0xFF}, LQMSize))
	f.Add(append((LQM{SequenceNumber: 7, OriginalLost: 3}).Marshal(), 0xAA))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			return
		}
		if re := m.Marshal(); !bytes.Equal(re, data[:LQMSize]) {
			t.Fatalf("re-marshal not byte-stable:\n got  %x\n want %x", re, data[:LQMSize])
		}
		// Loss fractions must be finite and in [0,1].
		if lf := m.LossFraction(); lf < 0 || lf > 1 {
			t.Fatalf("LossFraction out of range: %v", lf)
		}
	})
}

// TestAdvEncapsulationRoundTrip checks the Advanced-profile encapsulation
// (TR-06-4 §5.4, Figure 5): an LQM as the body of a Type=Control message with
// Control Index 0x0002 (Global), framed by the WP7 adv control codec, parses
// back to the same message.
func TestAdvEncapsulationRoundTrip(t *testing.T) {
	in := LQM{SequenceNumber: 42, ReportingPeriodMS: 1000, SourceReceived: 5000, OriginalLost: 17}
	payload := adv.BuildControl(nil, adv.CILQMGlobal, in.Marshal())

	ci, body, err := adv.ParseControl(payload)
	if err != nil {
		t.Fatalf("ParseControl: %v", err)
	}
	if ci != adv.CILQMGlobal {
		t.Fatalf("control index = %#x, want %#x (LQM Global)", ci, adv.CILQMGlobal)
	}
	if len(body) != LQMSize {
		t.Fatalf("control body length = %d, want %d", len(body), LQMSize)
	}
	out, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse LQM body: %v", err)
	}
	if out != in {
		t.Fatalf("adv-encapsulated LQM round-trip:\n got  %+v\n want %+v", out, in)
	}
}

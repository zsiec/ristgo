package rtp

import "testing"

func TestSSRCHelpers(t *testing.T) {
	tests := []struct {
		name           string
		ssrc           uint32
		wantNormalize  uint32
		wantMark       uint32
		wantRetransmit bool
	}{
		{"zero", 0x00000000, 0x00000000, 0x00000001, false},
		{"one", 0x00000001, 0x00000000, 0x00000001, true},
		{"even-flow", 0x4D4F4F56, 0x4D4F4F56, 0x4D4F4F57, false},
		{"odd-marked", 0x4D4F4F57, 0x4D4F4F56, 0x4D4F4F57, true},
		{"max-even", 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF, false},
		{"max-odd", 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, true},
		// Only the LSB is the retransmit marker; high bits are
		// untouched (librist shows the rejected alternative
		// ssrc |= 1<<31 commented out).
		{"high-bit-set", 0x80000002, 0x80000002, 0x80000003, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeSSRC(tc.ssrc); got != tc.wantNormalize {
				t.Errorf("NormalizeSSRC(%#x) = %#x, want %#x", tc.ssrc, got, tc.wantNormalize)
			}
			if got := MarkRetransmit(tc.ssrc); got != tc.wantMark {
				t.Errorf("MarkRetransmit(%#x) = %#x, want %#x", tc.ssrc, got, tc.wantMark)
			}
			if got := IsRetransmit(tc.ssrc); got != tc.wantRetransmit {
				t.Errorf("IsRetransmit(%#x) = %v, want %v", tc.ssrc, got, tc.wantRetransmit)
			}
		})
	}
}

func TestSSRCHelperProperties(t *testing.T) {
	// Algebraic properties over a spread of values, mirroring the
	// libRIST TX/RX pair: TX sets the LSB on the even flow id,
	// RX tests and clears it.
	ssrcs := []uint32{0, 1, 2, 3, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678}
	for _, s := range ssrcs {
		base := NormalizeSSRC(s)
		if IsRetransmit(base) {
			t.Errorf("IsRetransmit(NormalizeSSRC(%#x)) = true, want false", s)
		}
		if NormalizeSSRC(base) != base {
			t.Errorf("NormalizeSSRC not idempotent at %#x", s)
		}
		marked := MarkRetransmit(base)
		if !IsRetransmit(marked) {
			t.Errorf("IsRetransmit(MarkRetransmit(%#x)) = false, want true", base)
		}
		if NormalizeSSRC(marked) != base {
			t.Errorf("NormalizeSSRC(MarkRetransmit(%#x)) = %#x, want %#x", base, NormalizeSSRC(marked), base)
		}
		if MarkRetransmit(marked) != marked {
			t.Errorf("MarkRetransmit not idempotent at %#x", base)
		}
	}
}

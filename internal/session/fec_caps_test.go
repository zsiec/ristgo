package session

import "testing"

// TestLocalCapsAdvertisesFECWhenEnabled checks that a Main-profile session advertises
// the SMPTE-2022 FEC capability flag (P) in its keepalive only when FEC is configured
// (TR-06-2 keepalive Capability Flags).
func TestLocalCapsAdvertisesFECWhenEnabled(t *testing.T) {
	noFEC := &Session{cfg: Config{}}
	if noFEC.localCaps().P {
		t.Fatal("P (FEC) capability advertised without FEC configured")
	}
	withFEC := &Session{cfg: Config{FEC: &FECParams{Cols: 5, Rows: 5}}}
	if !withFEC.localCaps().P {
		t.Fatal("P (FEC) capability not advertised with FEC configured")
	}
	// The standard flags must still be present alongside P.
	caps := withFEC.localCaps()
	if !caps.N || !caps.E || !caps.B {
		t.Fatalf("FEC P flag clobbered the standard caps: %+v", caps)
	}
}

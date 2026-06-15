package ristgo

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/session"
)

// FECConfig configures SMPTE ST 2022-1 forward error correction: a Columns (L) by
// Rows (D) matrix over the protected media. By default it is 2-D (a column FEC
// packet per column and a row FEC packet per row), recovering any single loss per
// row and per column and, by cascade, many 2-D loss patterns. ColumnOnly keeps
// only the column FEC (1-D), halving the overhead.
//
// It is enabled via [Config.FEC] / [WithFEC] on the Advanced profile, where the
// FEC packets ride the data port as Advanced control messages (TR-06-3 §5.3.5).
// FEC complements ARQ: it recovers losses with no NACK round trip, while ARQ
// remains the backstop for losses FEC cannot cover.
type FECConfig struct {
	// Columns is L, the matrix width (the spacing between a column's packets).
	Columns int
	// Rows is D, the matrix height (the number of packets a column protects).
	Rows int
	// ColumnOnly suppresses the row FEC, leaving 1-D column-only protection.
	ColumnOnly bool
	// Carriage selects how the FEC packets are carried. The zero value picks a
	// sensible default per profile: in-band Advanced control messages for the
	// Advanced profile, separate UDP ports for the Simple profile.
	Carriage FECCarriage
}

// FECCarriage selects how SMPTE ST 2022-1 FEC packets travel.
type FECCarriage int

const (
	// FECCarriageDefault picks per profile: in-band for Advanced, separate-ports
	// for Simple.
	FECCarriageDefault FECCarriage = iota
	// FECCarriageInBand carries FEC as Advanced control messages on the data port
	// (TR-06-3 §5.3.5). Advanced profile only.
	FECCarriageInBand
	// FECCarriageSeparatePorts carries FEC as standard ST 2022-1 RTP packets on
	// dedicated UDP ports (the media port + 2 for column FEC, + 4 for row FEC).
	// This is the interoperable carriage (GStreamer/FFmpeg 2022-1).
	FECCarriageSeparatePorts
)

// carriage resolves the effective carriage for the given profile.
func (f *FECConfig) carriage(advanced bool) FECCarriage {
	if f.Carriage != FECCarriageDefault {
		return f.Carriage
	}
	if advanced {
		return FECCarriageInBand
	}
	return FECCarriageSeparatePorts
}

// validate enforces the TR-06-3 ST 2022-1 matrix bounds: L in [1,20] (column-only)
// or [4,20] (2-D), D in [4,20], and L*D <= 100.
func (f *FECConfig) validate() error {
	minL := 4
	if f.ColumnOnly {
		minL = 1
	}
	if f.Columns < minL || f.Columns > 20 {
		return fmt.Errorf("rist: FEC Columns (L) must be in [%d,20], got %d", minL, f.Columns)
	}
	if f.Rows < 4 || f.Rows > 20 {
		return fmt.Errorf("rist: FEC Rows (D) must be in [4,20], got %d", f.Rows)
	}
	if f.Columns*f.Rows > 100 {
		return fmt.Errorf("rist: FEC matrix L*D = %d exceeds the ST 2022-1 limit of 100", f.Columns*f.Rows)
	}
	return nil
}

// toSessionFEC maps the public FEC config to the session params, or nil,
// resolving the carriage against the profile.
func toSessionFEC(f *FECConfig, advanced bool) *session.FECParams {
	if f == nil {
		return nil
	}
	return &session.FECParams{
		Cols:          f.Columns,
		Rows:          f.Rows,
		ColumnOnly:    f.ColumnOnly,
		SeparatePorts: f.carriage(advanced) == FECCarriageSeparatePorts,
	}
}

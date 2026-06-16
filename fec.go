package ristgo

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/fec"
	"github.com/zsiec/ristgo/internal/session"
)

// FECConfig configures SMPTE ST 2022-1 / ST 2022-5 forward error correction: a
// Columns (L) by Rows (D) matrix over the protected media. By default it is 2-D (a
// column FEC packet per column and a row FEC packet per row), recovering any single
// loss per row and per column and, by cascade, many 2-D loss patterns. ColumnOnly
// keeps only the column FEC (1-D), roughly halving the overhead.
//
// Enable it via [Config.FEC] or [WithFEC]. FEC complements ARQ: it recovers losses
// with no NACK round trip, while ARQ remains the backstop for losses FEC cannot
// cover. The matrix must satisfy the TR-06-3 limits for the chosen Variant: for the
// default ST 2022-1, L in [1,20] (column-only) or [4,20] (2-D), D in [4,20], and
// L*D <= 100; for ST 2022-5, L in [1,1020] or [4,1020], D in [4,255], L*D <= 6000.
//
// FEC composes with link bonding: a bonded sender fans its FEC across every path
// (in-band on the Advanced profile, on the per-path column/row ports on Simple and
// Main), and the receiver recovers a packet lost on every path at once, the
// correlated loss SMPTE 2022-7 duplication cannot cover.
//
// # Domain and interop
//
// On the Advanced profile FEC is computed over the full wire datagram after
// compression and PSK encryption, per TR-06-3 §5.3.5, so a recovery is the missing
// packet's exact bytes and composes with payload fragmentation, PSK encryption, and
// flow identification. On the Simple and Main profiles FEC is standard ST 2022-1
// over the RTP payload, the form that interoperates with any ST 2022-1 receiver (the
// Advanced in-band carriage is ristgo-to-ristgo).
//
// Set [FECConfig.Variant] to [FECVariant2022_5] for the high-bit-rate ST 2022-5 wire
// format (SMPTE ST 2022-5:2013 §7.3), which raises the matrix ceiling to L*D <= 6000.
//
// # Not yet supported
//
//   - Encrypted FEC packets.
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
	// Variant selects the SMPTE FEC wire format. The zero value is ST 2022-1; set
	// it to [FECVariant2022_5] for the high-bit-rate ST 2022-5 format, which carries
	// a 16-bit base sequence and 10-bit matrix dimensions (raising the matrix ceiling
	// to L*D <= 6000) for interop with ST 2022-5/ST 2022-6 equipment.
	Variant FECVariant
}

// FECVariant selects the SMPTE FEC wire format. The matrix math is identical; the
// header layout and matrix limits differ (see [FECConfig.Variant]).
type FECVariant uint8

const (
	// FECVariant2022_1 is SMPTE ST 2022-1, the default (TR-06-2 §8.4 / TR-06-3
	// §5.3.5).
	FECVariant2022_1 FECVariant = iota
	// FECVariant2022_5 is SMPTE ST 2022-5, the high-bit-rate format defined in
	// SMPTE ST 2022-5:2013 §7.3.
	FECVariant2022_5
)

// FECCarriage selects how SMPTE ST 2022-1 / ST 2022-5 FEC packets travel.
type FECCarriage int

const (
	// FECCarriageDefault picks per profile: in-band for Advanced, separate-ports
	// for Simple.
	FECCarriageDefault FECCarriage = iota
	// FECCarriageInBand carries FEC as Advanced control messages on the data port
	// (TR-06-3 §5.3.5). Advanced profile only.
	FECCarriageInBand
	// FECCarriageSeparatePorts carries FEC as standard ST 2022-1 or ST 2022-5 RTP
	// packets on dedicated UDP ports (the media port + 2 for column FEC, + 4 for row
	// FEC). This is the interoperable carriage (GStreamer/FFmpeg ST 2022-1).
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

// validate enforces the TR-06-3 matrix bounds for the configured variant. ST 2022-1:
// L in [1,20] (column-only) or [4,20] (2-D), D in [4,20], L*D <= 100. ST 2022-5:
// L in [1,1020] or [4,1020], D in [4,255], L*D <= 6000.
func (f *FECConfig) validate() error {
	maxL, maxD, maxMatrix, std := 20, 20, 100, "ST 2022-1"
	switch f.Variant {
	case FECVariant2022_1:
	case FECVariant2022_5:
		maxL, maxD, maxMatrix, std = 1020, 255, 6000, "ST 2022-5"
	default:
		return fmt.Errorf("rist: FEC Variant %d is not a known SMPTE FEC variant", f.Variant)
	}
	minL := 4
	if f.ColumnOnly {
		minL = 1
	}
	if f.Columns < minL || f.Columns > maxL {
		return fmt.Errorf("rist: FEC Columns (L) must be in [%d,%d] for %s, got %d", minL, maxL, std, f.Columns)
	}
	if f.Rows < 4 || f.Rows > maxD {
		return fmt.Errorf("rist: FEC Rows (D) must be in [4,%d] for %s, got %d", maxD, std, f.Rows)
	}
	if f.Columns*f.Rows > maxMatrix {
		return fmt.Errorf("rist: FEC matrix L*D = %d exceeds the %s limit of %d", f.Columns*f.Rows, std, maxMatrix)
	}
	return nil
}

// toSessionFEC maps the public FEC config to the session params, or nil,
// resolving the carriage against the profile.
func toSessionFEC(f *FECConfig, advanced bool) *session.FECParams {
	if f == nil {
		return nil
	}
	variant := fec.Variant20221
	if f.Variant == FECVariant2022_5 {
		variant = fec.Variant20225
	}
	return &session.FECParams{
		Cols:          f.Columns,
		Rows:          f.Rows,
		ColumnOnly:    f.ColumnOnly,
		SeparatePorts: f.carriage(advanced) == FECCarriageSeparatePorts,
		Variant:       variant,
	}
}

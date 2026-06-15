package ristgo

import "github.com/zsiec/ristgo/internal/flow"

// Stats is a snapshot of a Sender's or Receiver's counters. Sender-only and
// receiver-only fields are zero on the other role.
type Stats struct {
	// --- Receiver ---

	// Received counts media packets accepted into the recovery buffer
	// (first copies and accepted retransmissions).
	Received uint64
	// Delivered counts packets handed to the application via Read.
	Delivered uint64
	// Lost counts sequence numbers given up on (never recovered before their
	// playout deadline).
	Lost uint64
	// Recovered counts packets recovered by retransmission after a NACK.
	Recovered uint64
	// FECRecovered counts packets reconstructed by SMPTE ST 2022-1 FEC (no NACK
	// round trip), distinct from Recovered (ARQ retransmission).
	FECRecovered uint64
	// Duplicates counts dropped duplicate packets (ARQ re-sends and extra
	// SMPTE 2022-7 path copies).
	Duplicates uint64
	// Reordered counts accepted packets that arrived out of order.
	Reordered uint64
	// NACKsSent counts sequence numbers requested in NACK feedback.
	NACKsSent uint64
	// Abandoned counts missing packets given up on after exhausting retries
	// or ageing past the recovery window.
	Abandoned uint64
	// Discontinuities counts gaps in the delivered stream (one per contiguous
	// run of unrecovered sequence numbers) — the receiver's view of
	// unrecoverable loss.
	Discontinuities uint64

	// --- Sender ---

	// Sent counts first-transmission media packets.
	Sent uint64
	// Retransmitted counts retransmitted media packets.
	Retransmitted uint64
	// RetransmitSkipped counts NACKed sequences no longer in the history
	// (aged out of the buffer).
	RetransmitSkipped uint64
	// RetransmitSuppressed counts NACKed sequences withheld because the
	// previous retransmission was less than one RTT ago.
	RetransmitSuppressed uint64
}

// toStats maps the internal flow counters to the public Stats.
func toStats(f flow.Stats) Stats {
	return Stats{
		Received:             f.Received,
		Delivered:            f.Delivered,
		Lost:                 f.Lost,
		Recovered:            f.Recovered,
		Duplicates:           f.Duplicates,
		Reordered:            f.Reordered,
		NACKsSent:            f.NacksSent,
		Abandoned:            f.Abandoned,
		Discontinuities:      f.Discontinuities,
		Sent:                 f.Sent,
		Retransmitted:        f.Retransmitted,
		RetransmitSkipped:    f.RetransmitSkipped,
		RetransmitSuppressed: f.RetransmitSuppressed,
	}
}

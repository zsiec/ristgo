package ristgo

import (
	"fmt"
	"time"

	"github.com/zsiec/ristgo/internal/flow"
)

// Stats is a snapshot of a Sender's or Receiver's counters and gauges. Sender-only
// and receiver-only fields are zero on the other role.
type Stats struct {
	// --- Receiver ---

	// Received counts media packets accepted into the recovery buffer
	// (first copies and accepted retransmissions).
	Received uint64
	// ReceivedBytes is the payload-byte analog of Received.
	ReceivedBytes uint64
	// Delivered counts packets handed to the application via Read.
	Delivered uint64
	// Lost counts sequence numbers given up on (never recovered before their
	// playout deadline).
	Lost uint64
	// Recovered counts packets recovered by retransmission after a NACK.
	Recovered uint64
	// FECRecovered counts packets reconstructed by SMPTE ST 2022-1 / 2022-5 FEC
	// (no NACK round trip), distinct from Recovered (ARQ retransmission).
	FECRecovered uint64
	// Duplicates counts dropped duplicate packets (ARQ re-sends and extra
	// SMPTE 2022-7 path copies).
	Duplicates uint64
	// Reordered counts accepted packets that arrived out of order.
	Reordered uint64
	// TooLate counts packets dropped because they arrived too late to be
	// delivered (older than the recovery window, or behind the playout cursor).
	TooLate uint64
	// TooLateRetransmit counts the retransmitted subset of TooLate.
	TooLateRetransmit uint64
	// RetransmittedReceived counts inbound packets flagged as retransmissions
	// that reached the flow (before any dedup/too-late test).
	RetransmittedReceived uint64
	// ClockResync counts source-clock re-anchors after a 32-bit RTP-timestamp wrap.
	ClockResync uint64
	// Missing counts missing entries created by gap detection (each lost
	// sequence once).
	Missing uint64
	// NACKsSent counts sequence numbers requested in NACK feedback.
	NACKsSent uint64
	// Abandoned counts missing packets given up on after exhausting retries
	// or ageing past the recovery window.
	Abandoned uint64
	// Overwritten counts ring slots overwritten because they held a stale entry.
	Overwritten uint64
	// FlowResets counts flow-id changes that reset the receiver's buffered state.
	FlowResets uint64
	// Discontinuities counts gaps in the delivered stream (one per contiguous
	// run of unrecovered sequence numbers) — the receiver's view of
	// unrecoverable loss.
	Discontinuities uint64

	// --- Sender ---

	// Sent counts first-transmission media packets.
	Sent uint64
	// SentBytes is the payload-byte analog of Sent.
	SentBytes uint64
	// Retransmitted counts retransmitted media packets.
	Retransmitted uint64
	// RetransmittedBytes is the payload-byte analog of Retransmitted.
	RetransmittedBytes uint64
	// RetransmitSkipped counts NACKed sequences no longer in the history
	// (aged out of the buffer).
	RetransmitSkipped uint64
	// RetransmitSuppressed counts NACKed sequences withheld because the
	// previous retransmission was less than one RTT ago.
	RetransmitSuppressed uint64
	// RetransmitExhausted counts NACKed sequences refused because the packet was
	// already retransmitted the maximum number of times.
	RetransmitExhausted uint64
	// BandwidthSkipped counts NACKed sequences refused because the retransmit
	// would have exceeded recovery_maxbitrate under the active congestion mode.
	BandwidthSkipped uint64

	// --- Gauges ---

	// RTT is the smoothed round-trip time (the RTT EWMA); zero before the first
	// sample.
	RTT time.Duration
	// BandwidthBps is the sender's smoothed first-transmission bit rate, bits/sec
	// (libRIST bandwidth); zero on a receiver.
	BandwidthBps uint64
	// RetryBandwidthBps is the sender's smoothed retransmission bit rate, bits/sec
	// (libRIST retry_bandwidth); zero on a receiver.
	RetryBandwidthBps uint64
	// Quality is a derived receiver link-quality percentage in [0, 100]: the
	// fraction of expected packets that arrived (including via recovery),
	// 100 * Received / (Received + Lost). 100 when no packets are expected.
	Quality float64

	// InterPacketMin/Cur/Max are the inter-packet arrival spacing gauges
	// (libRIST min_ips/cur_ips/max_ips): the gap between consecutive received
	// media packets. Zero before the first inter-arrival sample, and on a sender.
	InterPacketMin time.Duration
	InterPacketCur time.Duration
	InterPacketMax time.Duration
}

// toStats maps the internal flow counters and gauges to the public Stats and
// derives Quality. FECRecovered is layered on by the caller (host-tracked).
func toStats(f flow.Stats) Stats {
	expected := f.Received + f.Lost
	quality := 100.0
	if expected != 0 {
		quality = 100.0 * float64(f.Received) / float64(expected)
	}
	return Stats{
		Received:              f.Received,
		ReceivedBytes:         f.ReceivedBytes,
		Delivered:             f.Delivered,
		Lost:                  f.Lost,
		Recovered:             f.Recovered,
		Duplicates:            f.Duplicates,
		Reordered:             f.Reordered,
		TooLate:               f.TooLate,
		TooLateRetransmit:     f.TooLateRetransmit,
		RetransmittedReceived: f.RetransmittedReceived,
		ClockResync:           f.ClockResync,
		Missing:               f.Missing,
		NACKsSent:             f.NacksSent,
		Abandoned:             f.Abandoned,
		Overwritten:           f.Overwritten,
		FlowResets:            f.FlowResets,
		Discontinuities:       f.Discontinuities,
		Sent:                  f.Sent,
		SentBytes:             f.SentBytes,
		Retransmitted:         f.Retransmitted,
		RetransmittedBytes:    f.RetransmittedBytes,
		RetransmitSkipped:     f.RetransmitSkipped,
		RetransmitSuppressed:  f.RetransmitSuppressed,
		RetransmitExhausted:   f.RetransmitExhausted,
		BandwidthSkipped:      f.BandwidthSkipped,
		RTT:                   time.Duration(maxI64(f.SmoothedRTTUs, 0)) * time.Microsecond,
		BandwidthBps:          uint64(maxI64(f.DataBitrateBps, 0)),
		RetryBandwidthBps:     uint64(maxI64(f.RetryBitrateBps, 0)),
		Quality:               quality,
		InterPacketMin:        time.Duration(maxI64(f.IpsMinUs, 0)) * time.Microsecond,
		InterPacketCur:        time.Duration(maxI64(f.IpsCurUs, 0)) * time.Microsecond,
		InterPacketMax:        time.Duration(maxI64(f.IpsMaxUs, 0)) * time.Microsecond,
	}
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ToJSON serializes the snapshot to a flat JSON object (libRIST's stats_json
// analog), every counter and gauge as a field. Hand-rolled to keep the
// dependency set to the standard library.
func (s Stats) ToJSON() string {
	return fmt.Sprintf(
		`{"received":%d,"received_bytes":%d,"delivered":%d,"lost":%d,`+
			`"recovered":%d,"fec_recovered":%d,"duplicates":%d,"reordered":%d,`+
			`"too_late":%d,"too_late_retransmit":%d,"retransmitted_received":%d,`+
			`"clock_resync":%d,"missing":%d,"nacks_sent":%d,"abandoned":%d,`+
			`"overwritten":%d,"flow_resets":%d,"discontinuities":%d,`+
			`"sent":%d,"sent_bytes":%d,"retransmitted":%d,"retransmitted_bytes":%d,`+
			`"retransmit_skipped":%d,"retransmit_suppressed":%d,`+
			`"retransmit_exhausted":%d,"bandwidth_skipped":%d,`+
			`"rtt_us":%d,"bandwidth_bps":%d,"retry_bandwidth_bps":%d,"quality":%.3f,`+
			`"ips_min_us":%d,"ips_cur_us":%d,"ips_max_us":%d}`,
		s.Received, s.ReceivedBytes, s.Delivered, s.Lost,
		s.Recovered, s.FECRecovered, s.Duplicates, s.Reordered,
		s.TooLate, s.TooLateRetransmit, s.RetransmittedReceived,
		s.ClockResync, s.Missing, s.NACKsSent, s.Abandoned,
		s.Overwritten, s.FlowResets, s.Discontinuities,
		s.Sent, s.SentBytes, s.Retransmitted, s.RetransmittedBytes,
		s.RetransmitSkipped, s.RetransmitSuppressed,
		s.RetransmitExhausted, s.BandwidthSkipped,
		s.RTT.Microseconds(), s.BandwidthBps, s.RetryBandwidthBps, s.Quality,
		s.InterPacketMin.Microseconds(), s.InterPacketCur.Microseconds(), s.InterPacketMax.Microseconds(),
	)
}

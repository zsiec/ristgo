package ristgo

import (
	"strings"
	"testing"
	"time"

	"github.com/zsiec/ristgo/internal/flow"
)

func TestToStatsMapsBytesGaugesAndQuality(t *testing.T) {
	var f flow.Stats
	f.Received, f.ReceivedBytes, f.Lost = 90, 90*1316, 10
	f.Sent, f.SentBytes = 100, 100*1316
	f.Retransmitted, f.RetransmittedBytes = 7, 7*1316
	f.TooLate, f.Missing = 2, 12
	f.SmoothedRTTUs, f.DataBitrateBps, f.RetryBitrateBps = 8000, 12_000_000, 800_000
	f.IpsMinUs, f.IpsCurUs, f.IpsMaxUs = 3_000, 4_000, 9_000
	f.Recovered, f.RecoveredOneRetry, f.AvgBufferTimeUs = 5, 4, 600_000
	s := toStats(f)
	if s.ReceivedBytes != 90*1316 || s.SentBytes != 100*1316 || s.RetransmittedBytes != 7*1316 {
		t.Fatalf("byte counts: %+v", s)
	}
	if s.TooLate != 2 || s.Missing != 12 {
		t.Fatalf("surfaced counters: %+v", s)
	}
	if s.RTT != 8000*time.Microsecond || s.BandwidthBps != 12_000_000 || s.RetryBandwidthBps != 800_000 {
		t.Fatalf("gauges: %+v", s)
	}
	if s.InterPacketMin != 3_000*time.Microsecond || s.InterPacketCur != 4_000*time.Microsecond || s.InterPacketMax != 9_000*time.Microsecond {
		t.Fatalf("ips gauges: %+v", s)
	}
	if s.RecoveredOneRetry != 4 || s.AvgBufferTime != 600_000*time.Microsecond {
		t.Fatalf("recovered_one_retry/avg_buffer_time: %+v", s)
	}
	if d := s.Quality - 90.0; d > 1e-9 || d < -1e-9 {
		t.Fatalf("quality = %v, want 90", s.Quality)
	}
}

func TestQualityIs100WhenNoPacketsExpected(t *testing.T) {
	if q := toStats(flow.Stats{}).Quality; q != 100.0 {
		t.Fatalf("quality = %v, want 100", q)
	}
}

func TestToJSONIsFlatAndContainsFields(t *testing.T) {
	var f flow.Stats
	f.Received, f.SentBytes, f.SmoothedRTTUs = 3, 4096, 5000
	f.RecoveredOneRetry, f.AvgBufferTimeUs = 2, 700_000
	f.RecoveredTwoNacks, f.RecoveredMoreNacks = 6, 1
	s := toStats(f)
	// Framing fields are stamped by the handle via Session.Framing() in real use
	// (not by toStats); set them directly to exercise ToJSON serialization.
	s.Profile, s.SeqBits, s.AdvancedActive = ProfileAdvanced, 32, true
	j := s.ToJSON()
	if !strings.HasPrefix(j, "{") || !strings.HasSuffix(j, "}") {
		t.Fatalf("not a JSON object: %s", j)
	}
	for _, key := range []string{
		`"received":3`, `"sent_bytes":4096`, `"rtt_us":5000`, `"bandwidth_bps":0`,
		`"quality":100.000`, `"ips_max_us":0`, `"recovered_one_retry":2`, `"avg_buffer_time_us":700000`,
		// libRIST-parity fields (4d55974, 8cf3c81).
		`"recovered_two_nacks":6`, `"recovered_more_nacks":1`,
		`"profile":2`, `"seq_bits":32`, `"advanced_active":true`,
	} {
		if !strings.Contains(j, key) {
			t.Fatalf("JSON missing %q: %s", key, j)
		}
	}
}

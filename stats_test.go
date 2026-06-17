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
	j := toStats(f).ToJSON()
	if !strings.HasPrefix(j, "{") || !strings.HasSuffix(j, "}") {
		t.Fatalf("not a JSON object: %s", j)
	}
	for _, key := range []string{`"received":3`, `"sent_bytes":4096`, `"rtt_us":5000`, `"bandwidth_bps":0`, `"quality":100.000`} {
		if !strings.Contains(j, key) {
			t.Fatalf("JSON missing %q: %s", key, j)
		}
	}
}

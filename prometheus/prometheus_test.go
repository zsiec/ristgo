package prometheus_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
	"github.com/zsiec/ristgo/prometheus"
)

func TestEncode(t *testing.T) {
	s := ristgo.Stats{
		Received:  100,
		Delivered: 98,
		Lost:      2,
		RTT:       20 * time.Millisecond,
		Quality:   0.98,
		Peers: []ristgo.PeerStats{
			{Received: 60, RTT: 10 * time.Millisecond},
			{Received: 40, RTT: 12 * time.Millisecond},
		},
	}
	out := prometheus.Encode(s)

	for _, want := range []string{
		"# TYPE rist_client_flow_received_packets counter\nrist_client_flow_received_packets 100\n",
		"# TYPE rist_client_flow_rtt_seconds gauge\nrist_client_flow_rtt_seconds 0.02\n",
		"rist_client_flow_quality_ratio 0.98\n",
		"rist_client_flow_peers 2\n",
		"rist_peer_received_packets{peer=\"0\"} 60\n",
		"rist_peer_received_packets{peer=\"1\"} 40\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Encode output missing %q\n--- got ---\n%s", want, out)
		}
	}
	// Every HELP has a matching TYPE.
	if h, ty := strings.Count(out, "# HELP "), strings.Count(out, "# TYPE "); h != ty {
		t.Errorf("HELP count %d != TYPE count %d", h, ty)
	}
}

func TestServe(t *testing.T) {
	exp, err := prometheus.Serve("127.0.0.1:0", func() ristgo.Stats {
		return ristgo.Stats{Received: 4242, Quality: 0.97}
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer exp.Close()
	base := "http://" + exp.Addr().String()

	// GET /metrics -> 200 with the encoded metrics.
	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("Content-Type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "rist_client_flow_received_packets 4242") {
		t.Fatalf("metrics body missing the received counter:\n%s", body)
	}

	// GET / -> 404 (only /metrics is served).
	other, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Fatalf("GET / status = %d, want 404", other.StatusCode)
	}
}

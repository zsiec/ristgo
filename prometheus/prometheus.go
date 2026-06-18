// Package prometheus is a Prometheus text-format exporter for ristgo session Stats
// (libRIST's prometheus-exporter). Encode renders a Stats snapshot as the Prometheus
// text exposition format; Serve runs an HTTP /metrics endpoint that calls a stats
// closure on each scrape. Metric names follow libRIST's rist_client_flow_* /
// rist_peer_* convention.
//
//	exp, err := prometheus.Serve(":9100", func() ristgo.Stats { return rx.Stats() })
//	// ... later:
//	exp.Close()
package prometheus

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	ristgo "github.com/zsiec/ristgo"
)

// counter appends one counter metric (HELP + TYPE + value) in the text format.
func counter(b *strings.Builder, name, help string, v uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}

// gauge appends one gauge metric (HELP + TYPE + value).
func gauge(b *strings.Builder, name, help string, v float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
}

// Encode renders a Stats snapshot as a Prometheus text-exposition document (content
// type text/plain; version=0.0.4). Counters are cumulative session totals; gauges are
// the current RTT / bitrate / quality / inter-arrival / buffer values. Per-peer metrics
// (bonded paths) carry a peer="<index>" label.
func Encode(s ristgo.Stats) string {
	var b strings.Builder
	b.Grow(2048)
	counter(&b, "rist_client_flow_received_packets", "Media packets received.", s.Received)
	counter(&b, "rist_client_flow_delivered_packets", "Media packets delivered in order.", s.Delivered)
	counter(&b, "rist_client_flow_lost_packets", "Packets abandoned as unrecoverable.", s.Lost)
	counter(&b, "rist_client_flow_recovered_packets", "Packets recovered by ARQ or FEC.", s.Recovered)
	counter(&b, "rist_client_flow_recovered_one_retry_packets", "Packets recovered on the first retry.", s.RecoveredOneRetry)
	counter(&b, "rist_client_flow_reordered_packets", "Packets that arrived out of order.", s.Reordered)
	counter(&b, "rist_client_flow_sent_packets", "Media packets sent (sender).", s.Sent)
	counter(&b, "rist_client_flow_nacks_sent", "NACK requests emitted (receiver).", s.NACKsSent)
	gauge(&b, "rist_client_flow_missing_packets", "Packets currently outstanding awaiting recovery.", float64(s.Missing))
	gauge(&b, "rist_client_flow_rtt_seconds", "Smoothed round-trip time.", s.RTT.Seconds())
	gauge(&b, "rist_client_flow_bandwidth_bps", "Media bitrate, bits per second.", float64(s.BandwidthBps))
	gauge(&b, "rist_client_flow_retry_bandwidth_bps", "Retransmission bitrate, bits per second.", float64(s.RetryBandwidthBps))
	gauge(&b, "rist_client_flow_quality_ratio", "Delivery quality ratio (0..1).", s.Quality)
	gauge(&b, "rist_client_flow_min_iat_seconds", "Minimum inter-packet arrival interval.", s.InterPacketMin.Seconds())
	gauge(&b, "rist_client_flow_cur_iat_seconds", "Current inter-packet arrival interval.", s.InterPacketCur.Seconds())
	gauge(&b, "rist_client_flow_max_iat_seconds", "Maximum inter-packet arrival interval.", s.InterPacketMax.Seconds())
	gauge(&b, "rist_client_flow_avg_buffer_time_seconds", "Average playout buffer depth.", s.AvgBufferTime.Seconds())
	gauge(&b, "rist_client_flow_peers", "Number of bonded peers.", float64(len(s.Peers)))
	encodePeers(&b, s)
	return b.String()
}

// encodePeers appends the per-peer (bonded path) metrics, each name{peer="<index>"}
// value under a single HELP/TYPE header. A no-op for a single-path session.
func encodePeers(b *strings.Builder, s ristgo.Stats) {
	if len(s.Peers) == 0 {
		return
	}
	fmt.Fprint(b, "# HELP rist_peer_rtt_seconds Per-peer smoothed round-trip time.\n# TYPE rist_peer_rtt_seconds gauge\n")
	for i, p := range s.Peers {
		fmt.Fprintf(b, "rist_peer_rtt_seconds{peer=\"%d\"} %g\n", i, p.RTT.Seconds())
	}
	peerCounter(b, "rist_peer_received_packets", "Per-peer media packets received.", s, func(p ristgo.PeerStats) uint64 { return p.Received })
	peerCounter(b, "rist_peer_received_bytes", "Per-peer media bytes received.", s, func(p ristgo.PeerStats) uint64 { return p.ReceivedBytes })
	peerCounter(b, "rist_peer_sent_packets", "Per-peer media packets sent.", s, func(p ristgo.PeerStats) uint64 { return p.Sent })
	peerCounter(b, "rist_peer_sent_bytes", "Per-peer media bytes sent.", s, func(p ristgo.PeerStats) uint64 { return p.SentBytes })
	peerCounter(b, "rist_peer_retransmitted_packets", "Per-peer retransmitted packets.", s, func(p ristgo.PeerStats) uint64 { return p.Retransmitted })
}

// peerCounter appends one per-peer counter: a HELP/TYPE header then a labelled value per peer.
func peerCounter(b *strings.Builder, name, help string, s ristgo.Stats, f func(ristgo.PeerStats) uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	for i, p := range s.Peers {
		fmt.Fprintf(b, "%s{peer=\"%d\"} %d\n", name, i, f(p))
	}
}

// Exporter is a running Prometheus /metrics HTTP server. Close stops it.
type Exporter struct {
	srv *http.Server
	ln  net.Listener
}

// Addr returns the address the exporter is listening on (resolving an ephemeral :0 port).
func (e *Exporter) Addr() net.Addr { return e.ln.Addr() }

// Close stops the exporter's HTTP server.
func (e *Exporter) Close() error { return e.srv.Close() }

// Serve starts a Prometheus /metrics HTTP endpoint on addr ("host:port"), calling stats
// to snapshot the current counters on each scrape. It returns immediately with a running
// Exporter; any non-/metrics path gets a 404. Built on net/http (no external dependency).
func Serve(addr string, stats func() ristgo.Stats) (*Exporter, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("rist: prometheus: listen %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, Encode(stats()))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return &Exporter{srv: srv, ln: ln}, nil
}

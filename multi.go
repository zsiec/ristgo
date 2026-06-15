package ristgo

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// MultiReceiver binds one port and demultiplexes the several media flows that
// arrive on it (each identified by its RTP SSRC / flow_id) into independent
// receivers, matching libRIST's per-flow receiver model. It is RIST stream
// multiplexing: one transport, many streams.
//
// Each flow is surfaced by Accept as its own [Receiver] with independent ARQ
// recovery, in-order delivery, and statistics. Use it when several senders feed
// one port, or one source emits several flows.
type MultiReceiver struct {
	m       *session.MultiReceiver
	ctxStop func()
}

// NewMultiReceiver binds a RIST receiver at addr ("host:port" or a rist:// URL)
// and demultiplexes the media flows arriving on it. Call Accept in a loop to
// obtain a [Receiver] per discovered flow.
//
// Currently the Simple profile only. (Advanced demuxes by the cleartext SSRC
// too and is the next profile to land; Main with PSK encrypts the SSRC and is
// demultiplexed by source address, which follows.)
func NewMultiReceiver(addr string, cfg Config) (*MultiReceiver, error) {
	addr, cfg, err := ParseURL(addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if cfg.Profile != ProfileSimple {
		return nil, fmt.Errorf("%w: multi-flow receive currently supports only the Simple profile", ErrInvalidConfig)
	}
	host, port, err := resolveMediaPort(addr)
	if err != nil {
		return nil, err
	}
	conn, err := socket.Listen(host, port)
	if err != nil {
		return nil, err
	}
	if err := joinReceiverMulticast(conn, cfg, host); err != nil {
		conn.Close()
		return nil, err
	}
	fc := toFlowConfig(cfg)
	// The per-flow SSRC is assigned by the demultiplexer; this template value is
	// overwritten for each flow.
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sc.AdaptLQM = cfg.SourceAdaptation
	return &MultiReceiver{m: session.NewMultiReceiver(conn, sc)}, nil
}

// Accept blocks until a new flow appears on the port and returns a Receiver for
// it. The returned Receiver reads that one flow's recovered, in-order stream and
// has its own Stats; close it independently, or close the whole MultiReceiver to
// stop every flow. Accept returns ErrClosed once the MultiReceiver is closed.
func (r *MultiReceiver) Accept() (*Receiver, error) {
	s, err := r.m.Accept()
	if err != nil {
		return nil, err
	}
	return &Receiver{sess: s}, nil
}

// LocalPort returns the bound even media UDP port.
func (r *MultiReceiver) LocalPort() int { return r.m.MediaPort() }

// Close stops demultiplexing, releases the socket, and closes every accepted
// flow's Receiver.
func (r *MultiReceiver) Close() error {
	if r.ctxStop != nil {
		r.ctxStop()
	}
	return r.m.Close()
}

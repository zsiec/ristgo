package ristgo

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/bonding"
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
// Supported on the Simple profile (demultiplexed by the cleartext RTP SSRC) and
// the Advanced profile without encryption (demultiplexed by source address). The
// Main profile and PSK-encrypted Advanced demux by source address and follow.
func NewMultiReceiver(addr string, cfg Config) (*MultiReceiver, error) {
	addr, cfg, err := ParseURL(addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	switch cfg.Profile {
	case ProfileSimple:
		return newSimpleMultiReceiver(addr, cfg)
	case ProfileMain:
		return newMainMultiReceiver(addr, cfg)
	case ProfileAdvanced:
		return newAdvMultiReceiver(addr, cfg)
	default:
		return nil, fmt.Errorf("%w: multi-flow receive supports the Simple, Main, and Advanced profiles (cleartext)", ErrInvalidConfig)
	}
}

func newMainMultiReceiver(addr string, cfg Config) (*MultiReceiver, error) {
	if cfg.DTLS != nil {
		// DTLS is a single secure channel per socket; it cannot demultiplex
		// several peers/flows on one port.
		return nil, fmt.Errorf("%w: multi-flow Main with DTLS is not supported", ErrInvalidConfig)
	}
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	// Validate the per-flow config once (PSK keys, and the EAP authenticator when
	// credentials are set); the factory rebuilds both so this error is impossible
	// there, giving each flow its own key/auth state.
	if _, err := buildMainParams(cfg); err != nil {
		return nil, err
	}
	if _, err := buildEAPServer(cfg); err != nil {
		return nil, err
	}
	conn, err := socket.ListenSingle(host, port)
	if err != nil {
		return nil, err
	}
	if err := joinReceiverMulticast(conn, cfg, host); err != nil {
		conn.Close()
		return nil, err
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sc.AdaptLQM = cfg.SourceAdaptation
	mkFlow := func(c *socket.Conn, flowCfg session.Config) *session.Session {
		mp, _ := buildMainParams(cfg) // validated above; fresh PSK key state per flow
		mp.EAPServer, _ = buildEAPServer(cfg)
		flowCfg.Main = mp
		return session.NewInjectedMainReceiver(c, flowCfg)
	}
	return &MultiReceiver{m: session.NewMultiReceiverSingle(conn, sc, mkFlow)}, nil
}

func newSimpleMultiReceiver(addr string, cfg Config) (*MultiReceiver, error) {
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

func newAdvMultiReceiver(addr string, cfg Config) (*MultiReceiver, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	if _, err := buildAdvParams(cfg); err != nil {
		return nil, err
	}
	conn, err := socket.ListenSingle(host, port)
	if err != nil {
		return nil, err
	}
	if err := joinReceiverMulticast(conn, cfg, host); err != nil {
		conn.Close()
		return nil, err
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sc.AdaptLQM = cfg.SourceAdaptation
	mkFlow := func(c *socket.Conn, flowCfg session.Config) *session.Session {
		ap, _ := buildAdvParams(cfg) // validated above; fresh PSK key state per flow
		flowCfg.Adv = ap
		return session.NewInjectedAdvReceiver(c, flowCfg)
	}
	return &MultiReceiver{m: session.NewMultiReceiverSingle(conn, sc, mkFlow)}, nil
}

// NewMultiBondedReceiver binds several paths (addrs) and demultiplexes the media
// flows arriving on them, merging each flow across all paths (SMPTE 2022-7). It
// combines stream multiplexing with link bonding: N flows, each reconstructed
// over M redundant paths. Call Accept in a loop for a [Receiver] per flow.
//
// Currently the Simple profile (the flow SSRC must be in cleartext to group the
// paths of one flow).
func NewMultiBondedReceiver(addrs []string, cfg Config) (*MultiReceiver, error) {
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if cfg.Profile != ProfileSimple {
		return nil, fmt.Errorf("%w: multi-flow bonding currently supports only the Simple profile", ErrInvalidConfig)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a bonded receiver needs at least one address", ErrInvalidConfig)
	}
	conns := make([]*socket.Conn, 0, len(addrs))
	for _, a := range addrs {
		c, err := listenBondPath(a, cfg)
		if err != nil {
			closeConns(conns)
			return nil, err
		}
		conns = append(conns, c)
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC()) // per-flow SSRC set by the demuxer
	sc.AdaptLQM = cfg.SourceAdaptation
	newGroup := func() *bonding.Group { return newBondingGroup(cfg) }
	return &MultiReceiver{m: session.NewMultiBondedReceiver(conns, sc, newGroup)}, nil
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

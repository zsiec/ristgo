package ristgo

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/zsiec/ristgo/internal/bonding"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// BondedReceiver receives a single media flow carried redundantly over several
// network paths (RIST link bonding / SMPTE 2022-7) and delivers the merged,
// in-order, deduplicated stream. It is the multipath counterpart of Receiver:
// the same flow arrives on every path, and a packet lost on one path is covered
// by another's copy with no retransmission — seamless reconstruction.
//
// Like Receiver it is an io.ReadCloser with single-consumer stream semantics.
type BondedReceiver struct {
	sess    *session.Session
	ctxStop func() // ends the context watcher (set by ListenBonded)
}

// BondedSender transmits one media flow redundantly across several receiver
// addresses (full SMPTE 2022-7 duplication): every payload is sent on every
// path with identical sequence and timestamp, so the receiver can merge them.
type BondedSender struct {
	sess    *session.Session
	remote  *net.UDPAddr // the first path, for RemoteAddr
	ctxStop func()       // ends the context watcher (set by DialBonded)
}

// newBondingGroup builds the per-flow bonding group from cfg's liveness and RTT
// bounds.
func newBondingGroup(cfg Config) *bonding.Group {
	return bonding.NewGroup(
		clock.FromDuration(cfg.SessionTimeout),
		clock.FromDuration(cfg.RTTMin),
		clock.FromDuration(cfg.RTTMax),
	)
}

// NewBondedReceiver binds a bonded receiver across addrs, merging all paths into
// one deduplicated flow. The socket topology follows cfg.Profile: the Simple
// profile uses an even/odd media/RTCP pair per path (so each addr's port must be
// even); the Main and Advanced profiles tunnel each path over a single port,
// with PSK encryption when a Secret is set. At least one address is required; two
// or more gives 2022-7 redundancy. Bonded DTLS and EAP-SRP are not supported.
//
// See [ListenBonded] for the context-aware constructor with functional options.
func NewBondedReceiver(addrs []string, cfg Config) (*BondedReceiver, error) {
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if err := bondedSupported(cfg); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a bonded receiver needs at least one address", ErrInvalidConfig)
	}
	conns := make([]*socket.Conn, 0, len(addrs))
	for _, a := range addrs {
		c, err := listenBondPath(a, cfg.Profile)
		if err != nil {
			closeConns(conns)
			return nil, err
		}
		conns = append(conns, c)
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	if err := applyBondProfile(&sc, cfg); err != nil {
		closeConns(conns)
		return nil, err
	}
	sess := session.NewBondedReceiver(conns, newBondingGroup(cfg), sc)
	return &BondedReceiver{sess: sess}, nil
}

// NewBondedSender dials a bonded sender to addrs, duplicating every payload to
// all of them. The destination form follows cfg.Profile: the Simple profile
// targets each receiver's even media port (RTCP on port+1); the Main and
// Advanced profiles tunnel each path over a single port, with PSK encryption when
// a Secret is set. At least one address is required; two or more gives 2022-7
// redundancy. Bonded DTLS and EAP-SRP are not supported.
//
// See [DialBonded] for the context-aware constructor with functional options.
func NewBondedSender(addrs []string, cfg Config) (*BondedSender, error) {
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if err := bondedSupported(cfg); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a bonded sender needs at least one address", ErrInvalidConfig)
	}
	remotes := make([][2]*net.UDPAddr, 0, len(addrs))
	for _, a := range addrs {
		r, err := bondSenderRemote(a, cfg.Profile)
		if err != nil {
			return nil, err
		}
		remotes = append(remotes, r)
	}
	// Main/Advanced tunnel each path over a single port; Simple uses an even/odd
	// pair, so the local send socket must match.
	var conn *socket.Conn
	var err error
	if cfg.Profile == ProfileSimple {
		conn, err = socket.ListenEphemeral("")
	} else {
		conn, err = socket.ListenEphemeralSingle("")
	}
	if err != nil {
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq()
	sc := toSessionConfig(cfg, fc, ssrc)
	if err := applyBondProfile(&sc, cfg); err != nil {
		conn.Close()
		return nil, err
	}
	sess := session.NewBondedSender(conn, remotes, newBondingGroup(cfg), sc)
	return &BondedSender{sess: sess, remote: remotes[0][0]}, nil
}

// bondedSupported fails closed on the bonded features not implemented: DTLS over
// multipath and EAP-SRP authentication over multipath. All three profiles
// (Simple, Main, Advanced) are supported, including Main/Advanced PSK encryption.
func bondedSupported(cfg Config) error {
	if cfg.DTLS != nil {
		return fmt.Errorf("%w: bonded DTLS is not supported", ErrInvalidConfig)
	}
	if cfg.Username != "" {
		return fmt.Errorf("%w: bonded EAP-SRP authentication is not supported", ErrInvalidConfig)
	}
	return nil
}

// listenBondPath binds one receiver path socket for the configured profile: the
// Simple profile uses an even/odd media+RTCP pair (so the port must be even);
// the Main and Advanced profiles tunnel each path over a single port.
func listenBondPath(addr string, profile Profile) (*socket.Conn, error) {
	if profile == ProfileSimple {
		host, port, err := resolveMediaPort(addr)
		if err != nil {
			return nil, err
		}
		return socket.Listen(host, port)
	}
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	return socket.ListenSingle(host, port)
}

// bondSenderRemote resolves one sender path's destination for the profile: the
// Simple profile returns the even media and odd+1 RTCP pair; the Main/Advanced
// profiles tunnel over a single port, so both entries are that one address.
func bondSenderRemote(addr string, profile Profile) ([2]*net.UDPAddr, error) {
	var out [2]*net.UDPAddr
	if profile == ProfileSimple {
		host, port, err := resolveMediaPort(addr)
		if err != nil {
			return out, err
		}
		media, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return out, fmt.Errorf("%w: resolve media address %q: %v", ErrInvalidConfig, addr, err)
		}
		rtcp, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port+1)))
		if err != nil {
			return out, fmt.Errorf("%w: resolve rtcp address for %q: %v", ErrInvalidConfig, addr, err)
		}
		return [2]*net.UDPAddr{media, rtcp}, nil
	}
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return out, err
	}
	a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return out, fmt.Errorf("%w: resolve address %q: %v", ErrInvalidConfig, addr, err)
	}
	return [2]*net.UDPAddr{a, a}, nil
}

// applyBondProfile fills the session config's profile parameters (PSK keys,
// virtual ports) for a Main- or Advanced-profile bonded session, mirroring the
// non-bonded constructors. A no-op for the Simple profile.
func applyBondProfile(sc *session.Config, cfg Config) error {
	switch cfg.Profile {
	case ProfileMain:
		mp, err := buildMainParams(cfg)
		if err != nil {
			return err
		}
		sc.Main = mp
	case ProfileAdvanced:
		ap, err := buildAdvParams(cfg)
		if err != nil {
			return err
		}
		sc.Adv = ap
	}
	return nil
}

// closeConns closes a partially-built set of receiver sockets on error.
func closeConns(conns []*socket.Conn) {
	for _, c := range conns {
		c.Close()
	}
}

// Read returns the next in-order, merged media payload. It blocks until data is
// available, the read deadline passes (ErrTimeout), or the stream ends. A clean
// Close ends the stream with io.EOF (so io.Copy returns nil); an abnormal
// teardown returns ErrSessionTimeout, ErrBufferOverflow, or ErrAuth.
func (r *BondedReceiver) Read(p []byte) (int, error) { return readEOF(r.sess.Read(p)) }

// SetReadDeadline sets the deadline for future Read calls; a zero time clears it.
func (r *BondedReceiver) SetReadDeadline(t time.Time) error {
	r.sess.SetReadDeadline(t)
	return nil
}

// Stats returns a snapshot of the merged flow's counters.
func (r *BondedReceiver) Stats() Stats { return toStats(r.sess.Stats()) }

// Close stops the receiver and releases every path's sockets and goroutines.
func (r *BondedReceiver) Close() error {
	if r.ctxStop != nil {
		r.ctxStop()
	}
	return r.sess.Close()
}

// Write submits one media payload, duplicated to every path. It returns len(p).
// The payload must be at most MaxMediaPayload bytes.
func (s *BondedSender) Write(p []byte) (int, error) {
	if len(p) > MaxMediaPayload {
		return 0, fmt.Errorf("rist: payload %d bytes exceeds MaxMediaPayload %d; chunk media before Write", len(p), MaxMediaPayload)
	}
	if err := s.sess.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SetWriteDeadline sets the deadline for future Write calls; a zero time clears
// it.
func (s *BondedSender) SetWriteDeadline(t time.Time) error {
	s.sess.SetWriteDeadline(t)
	return nil
}

// Stats returns a snapshot of the sender's counters.
func (s *BondedSender) Stats() Stats { return toStats(s.sess.Stats()) }

// RemoteAddr returns the first path's media address.
func (s *BondedSender) RemoteAddr() net.Addr { return s.remote }

// Close stops the sender and releases its socket and goroutines.
func (s *BondedSender) Close() error {
	if s.ctxStop != nil {
		s.ctxStop()
	}
	return s.sess.Close()
}

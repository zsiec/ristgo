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
	sess *session.Session
}

// BondedSender transmits one media flow redundantly across several receiver
// addresses (full SMPTE 2022-7 duplication): every payload is sent on every
// path with identical sequence and timestamp, so the receiver can merge them.
type BondedSender struct {
	sess   *session.Session
	remote *net.UDPAddr // the first path, for RemoteAddr
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

// NewBondedReceiver binds a bonded receiver across addrs — one Simple-profile
// even/odd media/RTCP socket pair per path (so each addr's port must be even) —
// merging all paths into one flow. At least one address is required; two or more
// gives 2022-7 redundancy.
func NewBondedReceiver(addrs []string, cfg Config) (*BondedReceiver, error) {
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a bonded receiver needs at least one address", ErrInvalidConfig)
	}
	conns := make([]*socket.Conn, 0, len(addrs))
	for _, a := range addrs {
		host, port, err := resolveMediaPort(a)
		if err != nil {
			closeConns(conns)
			return nil, err
		}
		c, err := socket.Listen(host, port)
		if err != nil {
			closeConns(conns)
			return nil, err
		}
		conns = append(conns, c)
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sess := session.NewBondedReceiver(conns, newBondingGroup(cfg), sc)
	return &BondedReceiver{sess: sess}, nil
}

// NewBondedSender dials a bonded sender to addrs — each a receiver's even
// media port (RTCP on port+1) — duplicating every payload to all of them. At
// least one address is required; two or more gives 2022-7 redundancy.
func NewBondedSender(addrs []string, cfg Config) (*BondedSender, error) {
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a bonded sender needs at least one address", ErrInvalidConfig)
	}
	remotes := make([][2]*net.UDPAddr, 0, len(addrs))
	for _, a := range addrs {
		host, port, err := resolveMediaPort(a)
		if err != nil {
			return nil, err
		}
		media, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return nil, fmt.Errorf("%w: resolve media address %q: %v", ErrInvalidConfig, a, err)
		}
		rtcp, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port+1)))
		if err != nil {
			return nil, fmt.Errorf("%w: resolve rtcp address for %q: %v", ErrInvalidConfig, a, err)
		}
		remotes = append(remotes, [2]*net.UDPAddr{media, rtcp})
	}
	conn, err := socket.ListenEphemeral("")
	if err != nil {
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq()
	sc := toSessionConfig(cfg, fc, ssrc)
	sess := session.NewBondedSender(conn, remotes, newBondingGroup(cfg), sc)
	return &BondedSender{sess: sess, remote: remotes[0][0]}, nil
}

// closeConns closes a partially-built set of receiver sockets on error.
func closeConns(conns []*socket.Conn) {
	for _, c := range conns {
		c.Close()
	}
}

// Read returns the next in-order, merged media payload. It blocks until data is
// available, the read deadline passes (ErrTimeout), or the receiver is closed
// (ErrClosed, after buffered payloads drain).
func (r *BondedReceiver) Read(p []byte) (int, error) { return r.sess.Read(p) }

// SetReadDeadline sets the deadline for future Read calls; a zero time clears it.
func (r *BondedReceiver) SetReadDeadline(t time.Time) error {
	r.sess.SetReadDeadline(t)
	return nil
}

// Stats returns a snapshot of the merged flow's counters.
func (r *BondedReceiver) Stats() Stats { return toStats(r.sess.Stats()) }

// Close stops the receiver and releases every path's sockets and goroutines.
func (r *BondedReceiver) Close() error { return r.sess.Close() }

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
func (s *BondedSender) Close() error { return s.sess.Close() }

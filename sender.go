package ristgo

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// MaxMediaPayload is the largest payload a single Write may submit. The Simple
// profile sends one RTP packet per Write with no fragmentation, so the payload
// plus the 12-byte RTP header and the UDP/IPv4 headers must fit a standard
// 1500-byte MTU without IP fragmentation: 1500 − 20 (IP) − 8 (UDP) − 12 (RTP)
// = 1460. Callers chunk larger media before Write (the example sender uses
// 1316, a 7-cell MPEG-TS payload).
const MaxMediaPayload = 1460

// Sender transmits media to a RIST receiver. It is an io.WriteCloser: each
// Write submits one media payload (e.g. a batch of MPEG-TS packets), which the
// sender packetizes as RTP, transmits, and retains for retransmission until it
// ages out of the recovery buffer. Methods are safe for concurrent use with
// the sender's internal goroutines, but Write is not safe to call from
// multiple goroutines at once.
type Sender struct {
	sess   *session.Session
	remote *net.UDPAddr
}

// NewSender dials a RIST receiver at addr ("host:port" or a rist:// URL whose
// query parameters override cfg) and returns a ready Sender. The port is the
// receiver's even media port; RTCP feedback flows on port+1. Only the Simple
// profile is implemented; other profiles return an error wrapping
// ErrInvalidConfig.
func NewSender(addr string, cfg Config) (*Sender, error) {
	addr, cfg, err := ParseURL(addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if cfg.Profile != ProfileSimple {
		return nil, fmt.Errorf("%w: only the Simple profile is implemented (got %s)", ErrInvalidConfig, cfg.Profile)
	}
	host, port, err := resolveMediaPort(addr)
	if err != nil {
		return nil, err
	}
	mediaAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve media address: %v", ErrInvalidConfig, err)
	}
	rtcpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port+1)))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve rtcp address: %v", ErrInvalidConfig, err)
	}
	conn, err := socket.ListenEphemeral("")
	if err != nil {
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq()
	sess := session.NewSender(conn, mediaAddr, rtcpAddr, toSessionConfig(cfg, fc, ssrc))
	return &Sender{sess: sess, remote: mediaAddr}, nil
}

// Write submits one media payload for transmission and returns len(p). The
// payload must be at most MaxMediaPayload bytes (one RTP packet, no
// fragmentation); a larger payload returns an error without sending, rather
// than silently failing on the wire. Write blocks only briefly under
// back-pressure; it does not wait for delivery (RIST is best-effort with ARQ
// recovery). After Close it returns ErrClosed.
func (s *Sender) Write(p []byte) (int, error) {
	if len(p) > MaxMediaPayload {
		return 0, fmt.Errorf("rist: payload %d bytes exceeds MaxMediaPayload %d; chunk media before Write", len(p), MaxMediaPayload)
	}
	if err := s.sess.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SetWriteDeadline sets the deadline for future Write calls; a zero time
// clears it. Write returns ErrTimeout when the deadline passes.
func (s *Sender) SetWriteDeadline(t time.Time) error {
	s.sess.SetWriteDeadline(t)
	return nil
}

// Stats returns a snapshot of the sender's counters.
func (s *Sender) Stats() Stats { return toStats(s.sess.Stats()) }

// RemoteAddr returns the receiver's media address.
func (s *Sender) RemoteAddr() net.Addr { return s.remote }

// Close stops the sender and releases its sockets and goroutines.
func (s *Sender) Close() error { return s.sess.Close() }

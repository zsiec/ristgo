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
// = 1460. The Main profile adds ~12–16 bytes of GRE + reduced-overhead framing
// (plus the nonce when encrypted), so a Main payload at this limit is
// IP-fragmented on a strict-MTU path — Main callers should chunk smaller.
// Callers chunk larger media before Write anyway (the example sender uses 1316,
// a 7-cell MPEG-TS payload, which is safe for both profiles).
const MaxMediaPayload = 1460

// Sender transmits media to a RIST receiver. It is an io.WriteCloser: each
// Write submits one media payload (e.g. a batch of MPEG-TS packets), which the
// sender packetizes as RTP, transmits, and retains for retransmission until it
// ages out of the recovery buffer. Methods are safe for concurrent use with
// the sender's internal goroutines, but Write is not safe to call from
// multiple goroutines at once.
type Sender struct {
	sess    *session.Session
	remote  *net.UDPAddr
	ctxStop func() // ends the context watcher (set by Dial); nil for New* constructors
}

// NewSender dials a RIST receiver at addr ("host:port" or a rist:// URL whose
// query parameters override cfg) and returns a ready Sender. For the Simple
// profile the port is the receiver's even media port and RTCP feedback flows on
// port+1; for the Main and Advanced profiles a single port carries the flow
// (GRE-tunnelled for Main, RTP-based with native control for Advanced).
//
// See [Dial] for the context-aware constructor with functional options.
func NewSender(addr string, cfg Config) (*Sender, error) {
	addr, cfg, err := ParseURL(addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	switch cfg.Profile {
	case ProfileSimple:
		return newSimpleSender(addr, cfg)
	case ProfileMain:
		return newMainSender(addr, cfg)
	case ProfileAdvanced:
		return newAdvSender(addr, cfg)
	default:
		return nil, fmt.Errorf("%w: the %s profile is not implemented", ErrInvalidConfig, cfg.Profile)
	}
}

// newSimpleSender constructs a Simple-profile sender: RTP on the receiver's
// even media port, RTCP on port+1.
func newSimpleSender(addr string, cfg Config) (*Sender, error) {
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
	sc := toSessionConfig(cfg, fc, ssrc)
	applyRateAdapt(&sc, cfg)
	sess := session.NewSender(conn, mediaAddr, rtcpAddr, sc)
	return &Sender{sess: sess, remote: mediaAddr}, nil
}

// newMainSender constructs a Main-profile sender: the GRE-tunnelled flow (with
// optional PSK encryption) over the single port at addr.
func newMainSender(addr string, cfg Config) (*Sender, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve address: %v", ErrInvalidConfig, err)
	}
	mp, err := buildMainParams(cfg)
	if err != nil {
		return nil, err
	}
	if mp.EAPClient, err = buildEAPClient(cfg); err != nil {
		return nil, err
	}
	conn, err := socket.ListenEphemeralSingle("")
	if err != nil {
		return nil, err
	}
	if cfg.DTLS != nil {
		dcfg, err := buildDTLSConfig(cfg.DTLS, true)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn.EnableDTLSClient(remote, dcfg)
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq()
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.Main = mp
	applyRateAdapt(&sc, cfg)
	sess := session.NewMainSender(conn, remote, sc)
	return &Sender{sess: sess, remote: remote}, nil
}

// newAdvSender constructs an Advanced-profile sender: RTP-based media (with
// optional AES-CTR payload encryption and LZ4 compression) over the single port
// at addr, with native control messages on the same port.
func newAdvSender(addr string, cfg Config) (*Sender, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve address: %v", ErrInvalidConfig, err)
	}
	ap, err := buildAdvParams(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := socket.ListenEphemeralSingle("")
	if err != nil {
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq()
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.Adv = ap
	applyRateAdapt(&sc, cfg)
	sess := session.NewAdvSender(conn, remote, sc)
	return &Sender{sess: sess, remote: remote}, nil
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

// WriteOOB sends one out-of-band datagram to the peer (Main and Advanced
// profiles). OOB is a fire-and-forget side channel — it rides the same socket as
// the media but bypasses ARQ recovery, so a lost OOB datagram is not
// retransmitted. The payload must be at most MaxMediaPayload bytes. It returns
// ErrOOBUnsupported on a Simple-profile sender.
func (s *Sender) WriteOOB(p []byte) error {
	if len(p) > MaxMediaPayload {
		return fmt.Errorf("rist: OOB payload %d bytes exceeds MaxMediaPayload %d", len(p), MaxMediaPayload)
	}
	return s.sess.WriteOOB(p)
}

// ReadOOB returns the next out-of-band datagram received from the peer,
// truncated to len(buf) (OOB is datagram-oriented, not a stream). It blocks
// until one arrives, the deadline passes (ErrTimeout), or the sender closes
// (ErrClosed). It returns ErrOOBUnsupported on a Simple-profile sender.
func (s *Sender) ReadOOB(buf []byte) (int, error) { return s.sess.ReadOOB(buf) }

// Stats returns a snapshot of the sender's counters.
func (s *Sender) Stats() Stats { return toStats(s.sess.Stats()) }

// Authenticated reports whether the data channel is open. For a Main-profile
// sender configured with EAP-SRP credentials it becomes true once the peer has
// authenticated it; otherwise it is always true.
func (s *Sender) Authenticated() bool { return s.sess.Authenticated() }

// RemoteAddr returns the receiver's media address.
func (s *Sender) RemoteAddr() net.Addr { return s.remote }

// Close stops the sender and releases its sockets and goroutines.
func (s *Sender) Close() error {
	if s.ctxStop != nil {
		s.ctxStop()
	}
	return s.sess.Close()
}

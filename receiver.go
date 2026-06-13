package ristgo

import (
	"fmt"
	"time"

	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// Receiver receives media from a RIST sender, recovering lost packets via ARQ
// and delivering them in order. It is an io.ReadCloser: each Read returns the
// next in-order, recovered media payload, with stream semantics (a payload
// larger than the supplied buffer is returned across successive calls), so
// io.Copy(dst, rx) works.
//
// Close, SetReadDeadline, and Stats are safe to call concurrently with Read,
// but Read itself is not safe to call from multiple goroutines at once (it is
// a single-consumer stream, like a net.Conn).
type Receiver struct {
	sess *session.Session
}

// NewReceiver binds a RIST receiver at addr ("host:port" or a rist:// URL
// whose query parameters override cfg). For the Simple profile the port is the
// even media port and RTCP is bound on port+1; for the Main profile a single
// port carries the GRE-tunnelled flow. The Advanced profile is not yet
// implemented and returns an error wrapping ErrInvalidConfig.
func NewReceiver(addr string, cfg Config) (*Receiver, error) {
	addr, cfg, err := ParseURL(addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	switch cfg.Profile {
	case ProfileSimple:
		return newSimpleReceiver(addr, cfg)
	case ProfileMain:
		return newMainReceiver(addr, cfg)
	default:
		return nil, fmt.Errorf("%w: the %s profile is not implemented", ErrInvalidConfig, cfg.Profile)
	}
}

// newSimpleReceiver binds a Simple-profile receiver: RTP on the even port,
// RTCP on port+1.
func newSimpleReceiver(addr string, cfg Config) (*Receiver, error) {
	host, port, err := resolveMediaPort(addr)
	if err != nil {
		return nil, err
	}
	conn, err := socket.Listen(host, port)
	if err != nil {
		return nil, err
	}
	fc := toFlowConfig(cfg)
	sess := session.NewReceiver(conn, toSessionConfig(cfg, fc, randomEvenSSRC()))
	return &Receiver{sess: sess}, nil
}

// newMainReceiver binds a Main-profile receiver: the GRE-tunnelled flow (with
// optional PSK decryption) on the single port at addr.
func newMainReceiver(addr string, cfg Config) (*Receiver, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	mp, err := buildMainParams(cfg)
	if err != nil {
		return nil, err
	}
	if mp.EAPServer, err = buildEAPServer(cfg); err != nil {
		return nil, err
	}
	conn, err := socket.ListenSingle(host, port)
	if err != nil {
		return nil, err
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sc.Main = mp
	sess := session.NewMainReceiver(conn, sc)
	return &Receiver{sess: sess}, nil
}

// Read returns the next in-order media payload. It blocks until data is
// available, the read deadline passes (ErrTimeout), or the receiver is closed
// (ErrClosed, after any buffered payloads are drained).
func (r *Receiver) Read(p []byte) (int, error) { return r.sess.Read(p) }

// SetReadDeadline sets the deadline for future Read calls; a zero time clears
// it.
func (r *Receiver) SetReadDeadline(t time.Time) error {
	r.sess.SetReadDeadline(t)
	return nil
}

// LocalPort returns the bound even media UDP port.
func (r *Receiver) LocalPort() int { return r.sess.MediaPort() }

// Stats returns a snapshot of the receiver's counters.
func (r *Receiver) Stats() Stats { return toStats(r.sess.Stats()) }

// Authenticated reports whether the data channel is open. For a Main-profile
// receiver configured with EAP-SRP credentials it becomes true once the sender
// has been authenticated; otherwise it is always true.
func (r *Receiver) Authenticated() bool { return r.sess.Authenticated() }

// Close stops the receiver and releases its sockets and goroutines.
func (r *Receiver) Close() error { return r.sess.Close() }

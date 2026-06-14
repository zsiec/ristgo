package ristgo

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// readEOF maps a clean close (ErrClosed) to io.EOF so a Receiver behaves like a
// well-mannered io.Reader: io.Copy and bufio stop cleanly at end-of-stream
// instead of reporting a spurious error. Abnormal teardown
// (ErrSessionTimeout/ErrBufferOverflow/ErrAuth) is passed through unchanged so
// callers can still distinguish it.
func readEOF(n int, err error) (int, error) {
	if errors.Is(err, ErrClosed) {
		return n, io.EOF
	}
	return n, err
}

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
	sess    *session.Session
	ctxStop func() // ends the context watcher (set by Listen); nil for New* constructors
}

// NewReceiver binds a RIST receiver at addr ("host:port" or a rist:// URL
// whose query parameters override cfg). For the Simple profile the port is the
// even media port and RTCP is bound on port+1; for the Main and Advanced
// profiles a single port carries the flow (GRE-tunnelled for Main, RTP-based
// with native control for Advanced).
//
// See [Listen] for the context-aware constructor with functional options.
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
	case ProfileAdvanced:
		return newAdvReceiver(addr, cfg)
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
	if err := joinReceiverMulticast(conn, cfg, host); err != nil {
		conn.Close()
		return nil, err
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sc.AdaptLQM = cfg.SourceAdaptation
	sess := session.NewReceiver(conn, sc)
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
	if err := joinReceiverMulticast(conn, cfg, host); err != nil {
		conn.Close()
		return nil, err
	}
	if cfg.DTLS != nil {
		dcfg, err := buildDTLSConfig(cfg.DTLS, false)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn.EnableDTLSServer(dcfg)
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sc.Main = mp
	sc.AdaptLQM = cfg.SourceAdaptation
	sess := session.NewMainReceiver(conn, sc)
	return &Receiver{sess: sess}, nil
}

// newAdvReceiver binds an Advanced-profile receiver: RTP-based media (with
// optional AES-CTR payload decryption) on the single port at addr, with native
// control messages on the same port.
func newAdvReceiver(addr string, cfg Config) (*Receiver, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	ap, err := buildAdvParams(cfg)
	if err != nil {
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
	sc.Adv = ap
	sc.AdaptLQM = cfg.SourceAdaptation
	sess := session.NewAdvReceiver(conn, sc)
	return &Receiver{sess: sess}, nil
}

// Read returns the next in-order media payload. It blocks until data is
// available, the read deadline passes (ErrTimeout), or the stream ends. A clean
// Close ends the stream with io.EOF (so io.Copy returns nil); an abnormal
// teardown returns ErrSessionTimeout, ErrBufferOverflow, or ErrAuth.
func (r *Receiver) Read(p []byte) (int, error) { return readEOF(r.sess.Read(p)) }

// SetReadDeadline sets the deadline for future Read calls; a zero time clears
// it.
func (r *Receiver) SetReadDeadline(t time.Time) error {
	r.sess.SetReadDeadline(t)
	return nil
}

// ReadOOB returns the next out-of-band datagram received from the peer,
// truncated to len(buf) (OOB is datagram-oriented, not a stream). It blocks
// until one arrives, the deadline passes (ErrTimeout), or the receiver closes
// (ErrClosed). It returns ErrOOBUnsupported on a Simple-profile receiver.
func (r *Receiver) ReadOOB(buf []byte) (int, error) { return r.sess.ReadOOB(buf) }

// WriteOOB sends one out-of-band datagram to the peer (Main and Advanced
// profiles). OOB is a fire-and-forget side channel that bypasses ARQ recovery.
// The payload must be at most MaxMediaPayload bytes. It returns ErrOOBUnsupported
// on a Simple-profile receiver.
func (r *Receiver) WriteOOB(p []byte) error {
	if len(p) > MaxMediaPayload {
		return fmt.Errorf("rist: OOB payload %d bytes exceeds MaxMediaPayload %d", len(p), MaxMediaPayload)
	}
	return r.sess.WriteOOB(p)
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
func (r *Receiver) Close() error {
	if r.ctxStop != nil {
		r.ctxStop()
	}
	return r.sess.Close()
}

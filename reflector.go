package ristgo

import (
	"fmt"

	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// Reflector is a Main-profile transparent one-to-many fan-out relay (libRIST
// reflector). It listens for one inbound RIST flow, recovers and orders it through a
// full receiver (ARQ, reorder, dedup), then re-emits every recovered packet to each
// output preserving its original (seq, sourceTime) via Sender.SendBlock. Downstream
// receivers see the same sequence space and source clock as the origin, so the relay
// is transparent: an unrecoverable gap on the input reproduces as the same gap on
// every output. Create it with Reflect; Close it to tear everything down.
type Reflector struct {
	sess     *session.Session // the recovered input flow
	senders  []*Sender        // the output destinations
	pumpDone chan struct{}    // closed when the pump goroutine exits
}

// Reflect starts a transparent reflector: listen for one inbound Main-profile flow on
// input and re-emit every recovered packet to each address in outputs, preserving the
// original (seq, sourceTime). input and each output may be a "host:port" or a rist://
// URL whose query parameters refine cfg. cfg must select the Main profile.
//
// It returns ErrInvalidConfig if cfg is not Main or outputs is empty, or a bind/dial
// error from the input listen or an output dial.
func Reflect(input string, outputs []string, cfg Config) (*Reflector, error) {
	if cfg.Profile != ProfileMain {
		return nil, fmt.Errorf("%w: reflector requires ProfileMain", ErrInvalidConfig)
	}
	if len(outputs) == 0 {
		return nil, fmt.Errorf("%w: reflector needs at least one output", ErrInvalidConfig)
	}
	in, cfg, err := ParseURL(input, cfg)
	if err != nil {
		return nil, err
	}

	// Dial each output as an ordinary Main sender (each gets its own SendBlock path).
	senders := make([]*Sender, 0, len(outputs))
	for _, out := range outputs {
		s, derr := NewSender(out, cfg)
		if derr != nil {
			for _, prev := range senders {
				prev.Close()
			}
			return nil, derr
		}
		senders = append(senders, s)
	}

	sess, err := newReflectorInput(in, cfg)
	if err != nil {
		for _, s := range senders {
			s.Close()
		}
		return nil, err
	}

	r := &Reflector{sess: sess, senders: senders, pumpDone: make(chan struct{})}
	go r.pump()
	return r, nil
}

// OutputCount is the number of output destinations the input flow is fanned out to.
func (r *Reflector) OutputCount() int { return len(r.senders) }

// Stats returns a snapshot of the input flow's receiver counters (recovered, lost,
// RTT, …). The reflected outputs are fire-and-forget; per-output stats are not tracked.
func (r *Reflector) Stats() Stats { return toStats(r.sess.Stats()) }

// Close stops the reflector: it closes the inbound receiver (which ends the pump) and
// every output sender, releasing all sockets.
func (r *Reflector) Close() error {
	err := r.sess.Close()
	<-r.pumpDone // the pump exits once RecvBlock reports the closed input
	for _, s := range r.senders {
		s.Close()
	}
	return err
}

// pump forwards each recovered input block to every output, preserving
// (seq, sourceTime). The fan-out is best-effort — a dead or back-pressured output is
// skipped for that block (its SendBlock error is ignored) so one stalled destination
// never blocks the others or the relay. It exits when the input session closes.
func (r *Reflector) pump() {
	defer close(r.pumpDone)
	for {
		seq, sourceTime, payload, err := r.sess.RecvBlock()
		if err != nil {
			return // input closed
		}
		for _, s := range r.senders {
			_ = s.SendBlock(payload, &seq, &sourceTime)
		}
	}
}

// newReflectorInput binds a Main-profile reflector input: the GRE-tunnelled flow (with
// optional PSK decryption) on the single port at addr, delivering recovered blocks over
// Session.RecvBlock. It mirrors newMainReceiver but uses the reflector-input session.
func newReflectorInput(addr string, cfg Config) (*session.Session, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	mp, err := buildMainFlowParams(cfg)
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
	if cfg.DTLS != nil {
		dcfg, derr := buildDTLSConfig(cfg.DTLS, false)
		if derr != nil {
			conn.Close()
			return nil, derr
		}
		conn.EnableDTLSServer(dcfg)
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	sc.Main = mp
	sc.AdaptLQM = cfg.SourceAdaptation
	if cfg.FEC != nil && cfg.FEC.carriage(false) == FECCarriageSeparatePorts {
		if err := bindFECSockets(&sc, host, conn.MediaPort(), cfg.FEC.ColumnOnly); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return session.NewMainReflectorInput(conn, sc), nil
}

// Package session is the goroutine host for one RIST Simple-profile flow. It
// owns the real clock, the UDP sockets, and the timer wheel, and drives the
// sans-I/O flow core: a single event-loop goroutine is the sole owner of the
// flow.Flow (which is not safe for concurrent use), reader goroutines forward
// decoded packets to it over channels, and the loop performs the core's
// returned effects on the wire.
//
// The loop selects over: inbound media (receiver), inbound RTCP, application
// input (sender Write), the flow's declarative timer, and a liveness ticker.
// After every input it drains the flow's effects — encoding and sending media
// and compound RTCP, (re)arming the timer, and queueing delivered payloads for
// Read — exactly once. Close stops every goroutine without leaks.
package session

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/peer"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/socket"
	"github.com/zsiec/ristgo/internal/wire"
)

// maxDatagram bounds a single UDP read (RIST packets are MTU-sized).
const maxDatagram = 2048

// Config carries the per-session parameters the host needs, already translated
// from the public ristgo.Config (kept separate to avoid an import cycle).
type Config struct {
	// Flow is the deterministic core's configuration.
	Flow flow.Config
	// SSRC is the base (even) flow SSRC the sender stamps; for a receiver it
	// is the reporter SSRC used in its RTCP until the media SSRC is learned.
	SSRC uint32
	// CNAME is the SDES canonical name advertised in compound RTCP.
	CNAME string
	// Bitmask selects the RFC 4585 bitmask NACK encoding instead of the
	// default RIST range NACK.
	Bitmask bool
	// KeepaliveInterval paces the host liveness check.
	KeepaliveInterval clock.Microseconds
	// SessionTimeout tears the session down after this much peer silence.
	SessionTimeout clock.Microseconds
	// Logf, when non-nil, receives diagnostic messages.
	Logf func(format string, args ...any)

	// ErrClosed, ErrTimeout, ErrSessionTimeout, and ErrBufferOverflow are the
	// sentinel errors the session returns to the caller. The public layer
	// supplies its own identities so callers can match them with errors.Is;
	// this keeps the session decoupled from the public package (no import
	// cycle).
	ErrClosed         error
	ErrTimeout        error
	ErrSessionTimeout error
	ErrBufferOverflow error
}

// inbound is one datagram handed from a reader goroutine to the event loop.
type inbound struct {
	data []byte
	src  *net.UDPAddr
}

// Session hosts one flow. Construct it with NewSender or NewReceiver.
type Session struct {
	cfg    Config
	clk    clock.Clock
	conn   *socket.Conn
	flow   *flow.Flow
	peer   *peer.Peer
	sender bool // role
	mdec   mediaDecoder

	// timers is the host's declarative timer wheel: the deadline the flow
	// requested for each TimerID. A single time.Timer tracks the earliest.
	timers map[flow.TimerID]clock.Timestamp

	// addressing
	highestSent uint32 // sender: reference for widening inbound NACK seqs

	// lastTx is the instant of the last RTCP/media transmission; the
	// keepalive ticker only emits a periodic RTCP when the flow has been
	// quiet for a full interval, so it fills idle gaps without doubling the
	// flow's own RTT-echo cadence.
	lastTx clock.Timestamp
	// rx accumulates receiver-side reception statistics for the full RR.
	rx rxStats

	// event-loop inputs
	mediaIn chan inbound
	rtcpIn  chan inbound
	appIn   chan []byte

	// delivery to Read
	delivery chan []byte
	leftover []byte // partially-read payload (stream semantics)

	// scratch encode buffers (loop-owned)
	mediaBuf []byte
	rtcpBuf  []byte

	stats atomic.Pointer[flow.Stats]

	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
	// readWake/writeWake wake a Read/Write blocked in its select when the
	// corresponding deadline changes, so a freshly set deadline takes effect
	// on an in-progress call (mirrors srtgo's signalReadReady/WriteReady).
	readWake  chan struct{}
	writeWake chan struct{}

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	closeErr  atomic.Pointer[error]
}

// NewSender builds a sender-role session that transmits RTP to mediaAddr and
// compound RTCP to rtcpAddr, and reads feedback on conn's RTCP socket.
func NewSender(conn *socket.Conn, mediaAddr, rtcpAddr *net.UDPAddr, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	s.peer.Media = mediaAddr
	s.peer.RTCP = rtcpAddr
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	s.start()
	return s
}

// NewReceiver builds a receiver-role session that reads RTP and RTCP on conn
// and learns the sender's return addresses from inbound traffic.
func NewReceiver(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

func newSession(conn *socket.Conn, cfg Config, sender bool) *Session {
	s := &Session{
		cfg:       cfg,
		clk:       clock.NewRealClock(),
		conn:      conn,
		peer:      peer.New(cfg.SessionTimeout),
		sender:    sender,
		timers:    make(map[flow.TimerID]clock.Timestamp),
		rtcpIn:    make(chan inbound, 64),
		mediaBuf:  make([]byte, 0, maxDatagram),
		rtcpBuf:   make([]byte, 0, maxDatagram),
		readWake:  make(chan struct{}, 1),
		writeWake: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	if sender {
		s.appIn = make(chan []byte, 64)
	} else {
		s.mediaIn = make(chan inbound, 256)
		s.delivery = make(chan []byte, 4096)
	}
	var zero flow.Stats
	s.stats.Store(&zero)
	return s
}

// start launches the reader goroutines and the event loop.
func (s *Session) start() {
	s.wg.Add(1)
	go s.loop()
	s.wg.Add(1)
	go s.readRTCP()
	if !s.sender {
		s.wg.Add(1)
		go s.readMedia()
	}
}

// loop is the single owner of the flow. It processes one input at a time and
// drains the resulting effects after each.
func (s *Session) loop() {
	defer s.wg.Done()

	timer := time.NewTimer(time.Hour)
	stopTimer(timer)
	defer timer.Stop()

	ka := s.cfg.KeepaliveInterval
	if ka <= 0 {
		ka = 1000 * clock.Millisecond // defensive; the public path validates
	}
	ticker := time.NewTicker(ka.Duration())
	defer ticker.Stop()

	// A sender knows the peer's RTCP address from the start; an immediate
	// keepalive lets the receiver learn the sender's return address (and thus
	// send NACKs) without waiting a full keepalive interval.
	if s.sender {
		s.sendKeepalive(s.clk.Now())
	}

	for {
		select {
		case <-s.done:
			return
		case m := <-s.mediaIn:
			now := s.clk.Now()
			s.peer.LearnMedia(m.src)
			s.peer.Observe(now)
			if pkt, err := s.mdec.decode(m.data); err == nil {
				s.flow.Feed(now, 0, pkt)
				s.observeRx(now, pkt)
			}
			s.afterInput(now, timer)
		case r := <-s.rtcpIn:
			now := s.clk.Now()
			s.peer.LearnRTCP(r.src)
			s.peer.Observe(now)
			if fbs, err := decodeFeedback(r.data, s.highestSent); err == nil {
				for _, fb := range fbs {
					s.flow.FeedFeedback(now, fb)
				}
			}
			s.afterInput(now, timer)
		case p := <-s.appIn:
			now := s.clk.Now()
			s.flow.PushApp(now, p)
			s.afterInput(now, timer)
		case <-timer.C:
			now := s.clk.Now()
			s.fireTimers(now)
			s.afterInput(now, timer)
		case <-ticker.C:
			now := s.clk.Now()
			if s.peer.Expired(now) {
				s.shutdown(s.cfg.ErrSessionTimeout)
				return
			}
			// Emit a periodic keepalive only if the flow has been quiet for a
			// full interval (its own RTT-echo cadence covers the active case).
			if s.peer.RTCP != nil && now.Sub(s.lastTx) >= ka {
				s.sendKeepalive(now)
			}
		}
	}
}

// afterInput drains effects and re-arms the timer; called after every loop
// input so the flow's effect queue never backs up.
func (s *Session) afterInput(now clock.Timestamp, timer *time.Timer) {
	s.drain(now)
	s.rearm(timer, now)
	s.stats.Store(ptr(s.flow.Stats()))
}

// fireTimers delivers every due declarative timer to the flow in deadline
// order, mirroring the simulator's TimerWheel.PopDue.
func (s *Session) fireTimers(now clock.Timestamp) {
	for {
		id, deadline, ok := s.earliestTimer()
		if !ok || deadline.After(now) {
			return
		}
		delete(s.timers, id)
		s.flow.HandleTimer(now, id)
	}
}

// drain performs every pending flow effect once: media sends immediately,
// feedback is batched into one compound, timers update the wheel, and
// delivered payloads are queued for Read.
func (s *Session) drain(now clock.Timestamp) {
	var fbs []wire.Feedback
	for {
		out, ok := s.flow.PollOutput()
		if !ok {
			break
		}
		switch o := out.(type) {
		case flow.SendMedia:
			if !o.Pkt.Retransmit && seqAfter(o.Pkt.Seq, s.highestSent) {
				s.highestSent = o.Pkt.Seq
			}
			s.sendMedia(now, o.Pkt)
		case flow.SendFeedback:
			fbs = append(fbs, o.FB)
		case flow.SetTimer:
			s.setTimer(o.ID, o.Deadline)
		case flow.ClearTimer:
			s.clearTimer(o.ID)
		}
	}
	if len(fbs) > 0 {
		s.sendFeedback(fbs, now)
	}
	for {
		ev, ok := s.flow.PollEvent()
		if !ok {
			break
		}
		if d, ok := ev.(flow.Deliver); ok {
			s.queueDelivery(d.Payload)
		}
	}
}

// sendMedia encodes and transmits one RTP packet to the peer's media address.
func (s *Session) sendMedia(now clock.Timestamp, pkt wire.MediaPacket) {
	if s.peer.Media == nil {
		return
	}
	s.mediaBuf = s.mediaBuf[:0]
	b, err := encodeMedia(s.mediaBuf, pkt)
	if err != nil {
		s.logf("encode media seq %d: %v", pkt.Seq, err)
		return
	}
	s.mediaBuf = b
	if err := s.conn.WriteMedia(b, s.peer.Media); err != nil {
		s.logf("write media: %v", err)
	}
	s.lastTx = now
}

// sendFeedback builds one compound RTCP datagram from the drained feedback and
// transmits it to the peer's RTCP address.
func (s *Session) sendFeedback(fbs []wire.Feedback, now clock.Timestamp) {
	if s.peer.RTCP == nil {
		return // return path not learned yet
	}
	var lead rtcp.Packet
	if s.sender {
		// SR fields are session-relative (the receiver ignores SR contents
		// this stage — SR-based playout-offset refinement is deferred). NTP
		// and the RTP timestamp are taken from the same instant.
		lead = rtcp.SenderReport{
			SSRC:    s.cfg.SSRC,
			NTP:     uint64(clock.NTPTimeFromTimestamp(now)),
			RTPTime: uint32(rtpTicksFromMicros(int64(now))),
		}
	} else {
		lead = rtcp.EmptyReceiverReport{SSRC: s.cfg.SSRC}
	}
	s.rtcpBuf = s.rtcpBuf[:0]
	b, err := encodeFeedback(s.rtcpBuf, lead, s.cfg.SSRC, s.cfg.CNAME, fbs, s.cfg.Bitmask)
	if err != nil {
		s.logf("encode feedback: %v", err)
		return
	}
	s.rtcpBuf = b
	if err := s.conn.WriteRTCP(b, s.peer.RTCP); err != nil {
		s.logf("write rtcp: %v", err)
	}
	s.lastTx = now
}

// queueDelivery copies the delivered payload onto the read queue. The flow
// hands back a reference into the receive buffer; the copy lets that buffer be
// reclaimed and decouples the loop from a slow Read.
//
// If the (large) read queue is full, the consumer is persistently slower than
// the stream. Silently dropping an in-order, ARQ-recovered payload would break
// the completeness the whole stack guarantees, so instead the session fails
// with ErrBufferOverflow — the next Read surfaces it. (shutdown is safe to call
// from the loop; it does not wait on goroutines.)
func (s *Session) queueDelivery(payload []byte) {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	select {
	case s.delivery <- cp:
	default:
		s.logf("delivery queue full: consumer too slow, tearing down")
		s.shutdown(s.cfg.ErrBufferOverflow)
	}
}

// Allocation strategy: each inbound datagram gets a fresh buffer. A media
// payload is retained by reference inside the flow core (its zero-copy
// contract) until it is delivered or its ring slot is reused — up to the
// recovery-buffer window — so the receive buffer cannot be pooled and returned
// without reference-counting across that window, which is a deliberate
// non-goal at this stage. queueDelivery copies the payload out to decouple the
// loop from a slow Read and to free the receive buffer; that copy is handed to
// the caller and likewise cannot be pooled. RTCP datagrams are not retained,
// but arrive at a low rate, so they are not worth a pool either. The hot
// per-byte path (the codecs) stays zero-alloc; these per-datagram allocations
// are control-rate.

// readMedia reads RTP datagrams and forwards them to the loop.
func (s *Session) readMedia() {
	defer s.wg.Done()
	for {
		buf := make([]byte, maxDatagram)
		n, src, err := s.conn.ReadMedia(buf)
		if err != nil {
			return
		}
		select {
		case s.mediaIn <- inbound{data: buf[:n], src: src}:
		case <-s.done:
			return
		}
	}
}

// readRTCP reads RTCP datagrams and forwards them to the loop.
func (s *Session) readRTCP() {
	defer s.wg.Done()
	for {
		buf := make([]byte, maxDatagram)
		n, src, err := s.conn.ReadRTCP(buf)
		if err != nil {
			return
		}
		select {
		case s.rtcpIn <- inbound{data: buf[:n], src: src}:
		case <-s.done:
			return
		}
	}
}

// logf emits a diagnostic if a logger is configured.
func (s *Session) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

func ptr(v flow.Stats) *flow.Stats { return &v }

// seqAfter reports whether a is circularly after b (wrap-aware).
func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// stopTimer stops t. Under Go 1.23+ timer semantics Stop guarantees no stale
// value is delivered after it returns, so no channel drain is needed.
func stopTimer(t *time.Timer) { t.Stop() }

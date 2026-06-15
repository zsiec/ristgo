package session

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/rtp"
	"github.com/zsiec/ristgo/internal/socket"
)

// This file implements receiver-side stream multiplexing: one bound socket
// demultiplexed into N independent media flows, matching libRIST's per-flow
// receiver model. Each flow is a normal receiver Session run in "injected" mode:
// the MultiReceiver owns the socket read, decides which flow a datagram belongs
// to, and feeds the right session; the session itself owns its flow core,
// recovery, timers, and feedback (written back out the shared socket to its own
// learned peer).
//
// Two demux strategies, by profile:
//   - Simple (even/odd RTP/RTCP): key by the RTP SSRC, which is in cleartext.
//   - Main/Advanced (single port): key by the datagram source address. This
//     matches libRIST's peer->flow routing and is the only option for Main+PSK,
//     where the SSRC is inside the encrypted payload. Each source becomes its own
//     session, which decrypts and authenticates independently, exactly as a
//     libRIST peer does.

// InjectMedia hands one raw media datagram (from src) to an injected session.
func (s *Session) InjectMedia(data []byte, src netip.AddrPort) { s.inject(s.mediaIn, data, src) }

// InjectRTCP hands one raw RTCP datagram (from src) to an injected session.
func (s *Session) InjectRTCP(data []byte, src netip.AddrPort) { s.inject(s.rtcpIn, data, src) }

// Inject hands one raw single-socket datagram (Main GRE or Advanced) to an
// injected session, routing to whichever inbound channel the profile uses.
func (s *Session) Inject(data []byte, src netip.AddrPort) {
	switch {
	case s.main != nil:
		s.inject(s.mainIn, data, src)
	case s.adv != nil:
		s.inject(s.advIn, data, src)
	default:
		s.inject(s.mediaIn, data, src)
	}
}

func (s *Session) inject(ch chan inbound, data []byte, src netip.AddrPort) {
	select {
	case ch <- inbound{data: data, src: src}:
	case <-s.done:
	}
}

// SSRC returns the flow's media SSRC (the demux key the MultiReceiver assigned
// for the Simple profile; for source-keyed profiles it is the reporter SSRC).
func (s *Session) SSRC() uint32 { return s.cfg.SSRC }

// Done returns a channel closed when the session has shut down (clean Close or a
// timeout/overflow teardown). A MultiReceiver watches it to retire a dead flow.
func (s *Session) Done() <-chan struct{} { return s.done }

// NewInjectedReceiver builds a Simple-profile receiver session driven by an
// external demultiplexer rather than its own socket readers. conn is the shared
// socket; cfg.SSRC must be the flow's (even) SSRC so the session tags its
// Receiver Reports and NACKs with the flow identity libRIST expects.
func NewInjectedReceiver(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.injected = true
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// NewInjectedAdvReceiver builds an Advanced-profile receiver session in injected
// mode (cfg.Adv must be set).
func NewInjectedAdvReceiver(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.injected = true
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// NewInjectedMainReceiver builds a Main-profile receiver session in injected
// mode (cfg.Main must be set).
func NewInjectedMainReceiver(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.injected = true
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// FlowFactory builds an injected per-flow receiver session on the shared conn.
type FlowFactory func(conn *socket.Conn, cfg Config) *Session

// MultiReceiver binds one socket and demultiplexes the media flows arriving on it
// into independent receiver Sessions. New flows are surfaced via Accept. It is
// the receiver-side of RIST stream multiplexing.
type MultiReceiver struct {
	conn   *socket.Conn
	cfg    Config // template; the Simple path overwrites SSRC per flow
	single bool   // single-socket source-keyed demux (Main/Advanced)
	mkFlow FlowFactory

	mu    sync.Mutex
	flows map[any]*Session // key: uint32 SSRC (Simple) or netip.AddrPort (single)

	accept    chan *Session
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewMultiReceiver starts demultiplexing Simple-profile media on conn (keyed by
// RTP SSRC).
func NewMultiReceiver(conn *socket.Conn, cfg Config) *MultiReceiver {
	m := newMulti(conn, cfg, false, NewInjectedReceiver)
	m.wg.Add(2)
	go m.readMedia()
	go m.readRTCP()
	return m
}

// NewMultiReceiverSingle starts demultiplexing a single-socket profile
// (Main/Advanced) on conn, keyed by datagram source address. mkFlow builds the
// per-source injected session for the configured profile.
func NewMultiReceiverSingle(conn *socket.Conn, cfg Config, mkFlow FlowFactory) *MultiReceiver {
	m := newMulti(conn, cfg, true, mkFlow)
	m.wg.Add(1)
	go m.readSingle()
	return m
}

func newMulti(conn *socket.Conn, cfg Config, single bool, mkFlow FlowFactory) *MultiReceiver {
	return &MultiReceiver{
		conn:   conn,
		cfg:    cfg,
		single: single,
		mkFlow: mkFlow,
		flows:  make(map[any]*Session),
		accept: make(chan *Session, 64),
		done:   make(chan struct{}),
	}
}

// readMedia (Simple) keys each RTP datagram by its normalized SSRC.
func (m *MultiReceiver) readMedia() {
	defer m.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, src, err := m.conn.ReadMedia(buf)
		if err != nil {
			return
		}
		ssrc, ok := peekMediaSSRC(buf[:n])
		if !ok {
			continue
		}
		s, stop := m.flowFor(ssrc, ssrc)
		if stop {
			return
		}
		if s == nil {
			continue // flow cap reached
		}
		s.InjectMedia(clone(buf[:n]), src)
	}
}

// readRTCP (Simple) routes each compound to its flow by the lead report's SSRC.
func (m *MultiReceiver) readRTCP() {
	defer m.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, src, err := m.conn.ReadRTCP(buf)
		if err != nil {
			return
		}
		ssrc, ok := peekRTCPSSRC(buf[:n])
		if !ok {
			continue
		}
		s, stop := m.flowFor(ssrc, ssrc)
		if stop {
			return
		}
		if s == nil {
			continue // flow cap reached
		}
		s.InjectRTCP(clone(buf[:n]), src)
	}
}

// readSingle (Main/Advanced) keys each datagram by its source address.
func (m *MultiReceiver) readSingle() {
	defer m.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, src, err := m.conn.ReadMedia(buf)
		if err != nil {
			return
		}
		s, stop := m.flowFor(src, 0)
		if stop {
			return
		}
		if s == nil {
			continue // flow cap reached
		}
		s.Inject(clone(buf[:n]), src)
	}
}

// maxFlows caps the number of concurrent demultiplexed flows, so a burst of
// datagrams with spurious SSRCs/sources cannot open unbounded sessions. It
// matches libRIST's RIST_MAX_FLOWS.
const maxFlows = 256

// flowFor returns the session for key, creating it (and surfacing it via Accept)
// on first sight. For the Simple path, ssrc is the flow's SSRC (tagged into its
// reports); for the source-keyed path it is 0. stop is true only once the
// MultiReceiver is closed (the reader should exit); a nil session with stop
// false means the datagram should be dropped (the flow cap is reached) and the
// reader should continue.
func (m *MultiReceiver) flowFor(key any, ssrc uint32) (s *Session, stop bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return nil, true
	default:
	}
	if s, ok := m.flows[key]; ok {
		return s, false
	}
	if len(m.flows) >= maxFlows {
		return nil, false // at capacity: drop the datagram, keep reading
	}
	cfg := m.cfg
	if !m.single {
		cfg.SSRC = ssrc // tag this flow's RR/NACK with the flow SSRC (libRIST flow_id)
	}
	s = m.mkFlow(m.conn, cfg)
	m.flows[key] = s
	m.wg.Add(1)
	go m.retire(key, s)
	select {
	case m.accept <- s:
	default: // Accept backlog full; the flow still recovers and delivers
	}
	return s, false
}

// retire removes a flow from the map once its session ends, but only if the map
// still holds this exact session (a re-created flow for the same key is kept).
func (m *MultiReceiver) retire(key any, s *Session) {
	defer m.wg.Done()
	select {
	case <-s.Done():
	case <-m.done:
		return
	}
	m.mu.Lock()
	if m.flows[key] == s {
		delete(m.flows, key)
	}
	m.mu.Unlock()
}

// Accept blocks until a new flow appears and returns its session, or returns the
// close error once the MultiReceiver is closed.
func (m *MultiReceiver) Accept() (*Session, error) {
	select {
	case s := <-m.accept:
		return s, nil
	case <-m.done:
		return nil, m.cfg.ErrClosed
	}
}

// MediaPort returns the bound media port.
func (m *MultiReceiver) MediaPort() int { return m.conn.MediaPort() }

// Close stops demultiplexing, closes the shared socket, and closes every flow.
func (m *MultiReceiver) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
		m.conn.Close()
	})
	m.wg.Wait()
	m.mu.Lock()
	flows := make([]*Session, 0, len(m.flows))
	for _, s := range m.flows {
		flows = append(flows, s)
	}
	m.mu.Unlock()
	for _, s := range flows {
		s.Close()
	}
	return nil
}

// rtpHeaderSize is the minimum RTP header (no CSRCs): the SSRC ends at byte 12.
const rtpHeaderSize = 12

// peekMediaSSRC returns the (normalized) SSRC of an RTP media datagram (bytes
// 8..11), used to route it to a flow. Returns false on a runt datagram.
func peekMediaSSRC(b []byte) (uint32, bool) {
	if len(b) < rtpHeaderSize {
		return 0, false
	}
	return rtp.NormalizeSSRC(binary.BigEndian.Uint32(b[8:12])), true
}

// peekRTCPSSRC returns the (normalized) SSRC of a compound RTCP datagram's lead
// report (SR/RR/SDES carry the SSRC at offset 4), used to route it to a flow.
func peekRTCPSSRC(b []byte) (uint32, bool) {
	if len(b) < 8 {
		return 0, false
	}
	return rtp.NormalizeSSRC(binary.BigEndian.Uint32(b[4:8])), true
}

// clone returns a fresh copy of b (the flow core retains the slice).
func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

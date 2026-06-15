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
// demultiplexed into N independent media flows keyed by SSRC (flow_id), matching
// libRIST's per-flow_id receiver model. Each flow is a normal receiver Session
// run in "injected" mode: the MultiReceiver owns the socket read, peeks the
// flow's SSRC, and feeds the right session's inbound channels; the session
// itself owns its flow core, recovery, timers, and feedback (which it writes
// back out the shared socket to its own learned peer).

// InjectMedia hands one raw media datagram (from src) to an injected session's
// event loop. It is how a MultiReceiver feeds a demultiplexed flow.
func (s *Session) InjectMedia(data []byte, src netip.AddrPort) {
	select {
	case s.mediaIn <- inbound{data: data, src: src}:
	case <-s.done:
	}
}

// InjectRTCP hands one raw RTCP datagram (from src) to an injected session.
func (s *Session) InjectRTCP(data []byte, src netip.AddrPort) {
	select {
	case s.rtcpIn <- inbound{data: data, src: src}:
	case <-s.done:
	}
}

// SSRC returns the flow's media SSRC (the demux key the MultiReceiver assigned).
func (s *Session) SSRC() uint32 { return s.cfg.SSRC }

// Done returns a channel closed when the session has shut down (clean Close or a
// timeout/overflow teardown). A MultiReceiver watches it to retire a dead flow.
func (s *Session) Done() <-chan struct{} { return s.done }

// NewInjectedReceiver builds a Simple-profile receiver session driven by an
// external demultiplexer rather than its own socket readers. conn is the shared
// socket the MultiReceiver owns; cfg.SSRC must be the flow's (even) SSRC so the
// session tags its Receiver Reports and NACKs with the flow identity libRIST
// expects.
func NewInjectedReceiver(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.injected = true
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// MultiReceiver binds one socket and demultiplexes the media flows arriving on
// it into independent receiver Sessions, one per SSRC. New flows are surfaced
// via Accept. It is the receiver-side of RIST stream multiplexing.
type MultiReceiver struct {
	conn *socket.Conn
	cfg  Config // template; per-flow SSRC is overwritten per flow

	mu    sync.Mutex
	flows map[uint32]*Session

	accept    chan *Session
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewMultiReceiver starts demultiplexing Simple-profile media on conn. cfg is the
// template applied to each demuxed flow (its SSRC is set per flow).
func NewMultiReceiver(conn *socket.Conn, cfg Config) *MultiReceiver {
	m := &MultiReceiver{
		conn:   conn,
		cfg:    cfg,
		flows:  make(map[uint32]*Session),
		accept: make(chan *Session, 64),
		done:   make(chan struct{}),
	}
	m.wg.Add(2)
	go m.readMedia()
	go m.readRTCP()
	return m
}

// readMedia reads RTP media datagrams, keys each by its (normalized) SSRC, and
// feeds the matching flow's session.
func (m *MultiReceiver) readMedia() {
	defer m.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, src, err := m.conn.ReadMedia(buf)
		if err != nil {
			return
		}
		if n < rtpHeaderSize {
			continue
		}
		ssrc := rtp.NormalizeSSRC(binary.BigEndian.Uint32(buf[8:12]))
		s := m.flowFor(ssrc)
		if s == nil {
			return // closed
		}
		s.InjectMedia(clone(buf[:n]), src)
	}
}

// readRTCP reads RTCP from the senders and routes each compound to its flow by
// the lead report's SSRC (the sender's flow SSRC). RTCP can arrive before the
// first media packet (the sender's startup SR/SDES), so it can open a flow too.
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
		s := m.flowFor(ssrc)
		if s == nil {
			return
		}
		s.InjectRTCP(clone(buf[:n]), src)
	}
}

// flowFor returns the session for ssrc, creating it (and surfacing it via Accept)
// on first sight. Returns nil once the MultiReceiver is closed.
func (m *MultiReceiver) flowFor(ssrc uint32) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return nil
	default:
	}
	if s, ok := m.flows[ssrc]; ok {
		return s
	}
	cfg := m.cfg
	cfg.SSRC = ssrc // tag this flow's RR/NACK with the flow SSRC (libRIST flow_id)
	s := NewInjectedReceiver(m.conn, cfg)
	m.flows[ssrc] = s
	// Retire the flow when its session shuts down (idle timeout, overflow, or a
	// Receiver Close), so a later resumption of the same flow_id is re-created
	// rather than fed to a dead session.
	m.wg.Add(1)
	go m.retire(ssrc, s)
	select {
	case m.accept <- s:
	default: // Accept backlog full; the flow still recovers and delivers
	}
	return s
}

// retire removes a flow from the map once its session ends, but only if the map
// still holds this exact session (a re-created flow for the same SSRC is kept).
func (m *MultiReceiver) retire(ssrc uint32, s *Session) {
	defer m.wg.Done()
	select {
	case <-s.Done():
	case <-m.done:
		return
	}
	m.mu.Lock()
	if m.flows[ssrc] == s {
		delete(m.flows, ssrc)
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

// MediaPort returns the bound even media port.
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

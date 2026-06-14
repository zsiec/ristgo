// Package peer tracks one remote endpoint of a RIST flow: its media and RTCP
// return addresses and a liveness clock. For the Simple profile a flow has a
// single peer; SMPTE 2022-7 bonding (WP8) attaches several to one flow, which
// is why this is its own type rather than fields on the session.
//
// A Peer is owned by the session event loop and is not safe for concurrent
// use; the loop is the only goroutine that reads or writes it.
package peer

import (
	"net"

	"github.com/zsiec/ristgo/internal/clock"
)

// Peer is a remote endpoint's addressing and liveness state.
type Peer struct {
	// Media is where this side sends RTP (the receiver learns it from the
	// source of inbound RTP; the sender is configured with it).
	Media *net.UDPAddr
	// RTCP is where this side sends compound RTCP (NACKs, reports, echoes).
	RTCP *net.UDPAddr

	timeout  clock.Microseconds
	lastSeen clock.Timestamp
	seen     bool
}

// New returns a Peer with the given session timeout. Addresses are filled in
// by the constructors (sender) or learned via LearnMedia/LearnRTCP (receiver).
func New(timeout clock.Microseconds) *Peer {
	return &Peer{timeout: timeout}
}

// LearnMedia records the peer's media return address if not already known.
func (p *Peer) LearnMedia(addr *net.UDPAddr) {
	if p.Media == nil {
		p.Media = addr
	}
}

// LearnRTCP records the peer's RTCP return address if not already known.
func (p *Peer) LearnRTCP(addr *net.UDPAddr) {
	if p.RTCP == nil {
		p.RTCP = addr
	}
}

// Observe marks that traffic arrived from the peer at instant now, resetting
// the liveness clock.
func (p *Peer) Observe(now clock.Timestamp) {
	p.lastSeen = now
	p.seen = true
}

// Seen reports whether any traffic has ever arrived from the peer.
func (p *Peer) Seen() bool { return p.seen }

// Expired reports whether the peer was once seen but has now been silent for
// longer than the session timeout — the condition for tearing the session
// down (libRIST checks now - last_pkt_received > session_timeout). A peer
// that has never been seen does not expire (the session is still forming).
func (p *Peer) Expired(now clock.Timestamp) bool {
	return p.seen && now.Sub(p.lastSeen) > p.timeout
}

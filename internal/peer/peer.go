// Package peer tracks one remote endpoint of a RIST flow: its media and RTCP
// return addresses and a liveness clock. For the Simple profile a flow has a
// single peer; SMPTE 2022-7 bonding (WP8) attaches several to one flow, which
// is why this is its own type rather than fields on the session.
//
// A Peer is owned by the session event loop and is not safe for concurrent
// use; the loop is the only goroutine that reads or writes it.
package peer

import (
	"net/netip"

	"github.com/zsiec/ristgo/internal/clock"
)

// Peer is a remote endpoint's addressing and liveness state. Addresses are
// netip.AddrPort values (not *net.UDPAddr) so the per-datagram receive path is
// allocation-free; the zero AddrPort (!IsValid()) means "not yet known".
type Peer struct {
	// Media is where this side sends RTP (the receiver learns it from the
	// source of inbound RTP; the sender is configured with it).
	Media netip.AddrPort
	// RTCP is where this side sends compound RTCP (NACKs, reports, echoes).
	RTCP netip.AddrPort

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
func (p *Peer) LearnMedia(addr netip.AddrPort) {
	if !p.Media.IsValid() {
		p.Media = addr
	}
}

// LearnRTCP records the peer's RTCP return address if not already known. When
// the media return address is already known, it only accepts an RTCP source on
// the same host (matching IP): a RIST sender's RTCP and media originate from one
// host (the source ports may differ, the IP does not), so this rejects an
// off-path datagram spoofed to the RTCP port that would otherwise redirect the
// receiver's NACK/RR feedback to a victim address — a low-factor reflection
// vector. Until media is known there is nothing to validate against, so
// first-source-wins applies (as it must, the session is still forming).
//
// IPs are compared unmapped so an IPv4 source seen as 4-in-6 on a dual-stack
// socket still matches its plain-IPv4 form (the net.IP.Equal semantics this
// replaced).
func (p *Peer) LearnRTCP(addr netip.AddrPort) {
	if p.RTCP.IsValid() {
		return
	}
	if p.Media.IsValid() && addr.IsValid() && p.Media.Addr().Unmap() != addr.Addr().Unmap() {
		return // RTCP source on a different host than media: reject as a spoof
	}
	p.RTCP = addr
}

// Observe marks that traffic arrived from the peer at instant now, resetting
// the liveness clock.
func (p *Peer) Observe(now clock.Timestamp) {
	p.lastSeen = now
	p.seen = true
}

// Rebind replaces the peer's media and RTCP return addresses with addr. Unlike Learn*,
// which lock the first address learned, this is the deliberate override used to migrate the
// tuple during a NAT source-port rebind recovery (the caller MUST gate it on forcing a fresh
// authentication; see the session's re-association path). It does NOT touch the liveness
// clock — the migration alone is not evidence of liveness. The held re-auth that follows is
// bounded by the session's reauthDeadline (a teardown), NOT by this liveness clock, because
// once the migrated tuple's own datagrams arrive they refresh lastSeen via Observe and so
// could otherwise extend the session timeout indefinitely on an unproven tuple.
func (p *Peer) Rebind(addr netip.AddrPort) {
	p.Media = addr
	p.RTCP = addr
}

// SilentFor reports whether the peer was seen at least once and has now been silent for
// longer than d. It is the "dormant candidate" test for NAT-rebind re-association: a tuple
// is migrated to a new source only when the established one has gone quiet (libRIST
// requires silence beyond 2x the keepalive interval before re-associating).
func (p *Peer) SilentFor(now clock.Timestamp, d clock.Microseconds) bool {
	return p.seen && now.Sub(p.lastSeen) > d
}

// Seen reports whether any traffic has ever arrived from the peer.
func (p *Peer) Seen() bool { return p.seen }

// LastSeen returns the instant the most recent datagram from the peer was
// observed (Observe), or the zero Timestamp if none has been. The caller-rebind
// recovery check compares it against the last rebind to tell whether real traffic
// arrived afterward (the rebind recovered the stream).
func (p *Peer) LastSeen() clock.Timestamp { return p.lastSeen }

// Expired reports whether the peer was once seen but has now been silent for
// longer than the session timeout — the condition for tearing the session
// down (libRIST checks now - last_pkt_received > session_timeout). A peer
// that has never been seen does not expire (the session is still forming).
// It is the silence test with the configured session timeout as the threshold.
func (p *Peer) Expired(now clock.Timestamp) bool {
	return p.SilentFor(now, p.timeout)
}

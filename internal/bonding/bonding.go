// Package bonding implements RIST link bonding / SMPTE 2022-7 multipath at the
// host layer: it registers N network paths onto one flow, tracks per-path
// liveness and RTT, and decides which path to route a NACK to. The packet-level
// merge itself is NOT here — it lives in internal/flow, where every copy of a
// media packet (first transmission, ARQ retransmit, or a duplicate from another
// 2022-7 path) lands in one seq-indexed ring and is deduplicated by the same
// (Seq, SourceTime) test. Bonding is the surrounding path management the host
// drives around that single shared buffer.
//
// # Sans-I/O
//
// A Group is deterministic: time enters only as explicit now arguments, and it
// owns no clock, socket, or goroutine. The goroutine host (internal/session)
// feeds it liveness observations and RTT samples and consults it for routing
// decisions, then performs the I/O. This keeps the bonding policy — the part
// with interesting edge cases (a path dying mid-stream, NACK-peer selection
// under priority ties) — exhaustively unit-testable without the network.
//
// # Modes
//
// A path's Weight selects its mode. Weight 0 (WeightDuplicate) is the SMPTE
// 2022-7 full-redundancy mode: the sender transmits the identical packet (same
// Seq/SourceTime) on the path and the receiver merges by the shared (Seq,
// SourceTime) dedup, matching libRIST's RIST_PEER_WEIGHT_DUPLICATE. A positive
// Weight joins the weighted load-share rotation (SelectWeighted): the sender
// routes each datagram to exactly one weighted path, splitting the stream in
// proportion to the weights (libRIST's weight/w_count). The two modes compose —
// duplicate paths carry every packet while the weighted paths share the rest —
// and a weight can change at runtime (SetWeight, libRIST rist_peer_weight_set).
// Either way the receiver is unchanged: it merges whatever arrives into the one
// seq-indexed ring, so load-share is purely a sender-side routing policy.
package bonding

import (
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/rtt"
)

// WeightDuplicate is the weight that marks a path for full duplication — every
// packet is sent on it (SMPTE 2022-7), rather than joining a weighted rotation.
// It matches libRIST's RIST_PEER_WEIGHT_DUPLICATE (peer.h).
const WeightDuplicate = 0

// Path is the per-path state a Group tracks: stable identity, the configured
// load-balancing weight and NACK recovery priority, a smoothed RTT estimate,
// and liveness. It is exported for inspection (stats); the host mutates it only
// through Group methods.
type Path struct {
	// Index is the stable path index the flow core and the host's routing
	// tables key on (flow.Feed(now, Index, pkt), SendMedia{Path: Index}).
	Index uint8

	// Weight is the libRIST load-balancing weight; WeightDuplicate (0) selects
	// full 2022-7 duplication, a positive weight joins the weighted rotation
	// (SelectWeighted) and receives a proportional share of the packets.
	Weight int

	// Priority is the NACK recovery priority (libRIST recovery_priority): the
	// receiver routes each NACK to the live path with the highest Priority,
	// ties broken by the lowest measured RTT (rist_nack_peer_preferred).
	Priority uint32

	// wCount is the remaining send credit for this weighted path in the current
	// rotation round (libRIST peer->w_count); it refills to Weight each round.
	wCount int

	rtt      rtt.Estimator
	lastSeen clock.Timestamp
	seen     bool
	dead     bool // edge-detection flag for Tick's "report death once"; not the
	// authoritative liveness — use Group.Alive(index, now) for that.
}

// RTT returns the path's smoothed RTT estimate clamped to the group's
// [rttMin, rttMax] — a stable stat. NACK-peer tie-breaking uses nackRTT (the
// raw last sample) to match libRIST.
func (p *Path) RTT(g *Group) clock.Microseconds { return p.rtt.Clamped(g.rttMin, g.rttMax) }

// nackRTT is the raw most-recent RTT sample clamped to [rttMin, rttMax] — the
// exact quantity libRIST's rist_nack_peer_preferred compares (peer->last_rtt),
// rather than the smoothed EWMA.
func (p *Path) nackRTT(g *Group) clock.Microseconds { return p.rtt.LastClamped(g.rttMin, g.rttMax) }

// Group manages the set of paths bonded onto one flow. It is not safe for
// concurrent use; the host's single event-loop goroutine owns it.
type Group struct {
	paths          []*Path
	timeout        clock.Microseconds
	rttMin, rttMax clock.Microseconds
}

// NewGroup builds an empty Group. sessionTimeout is the per-path silence after
// which a path is declared dead (libRIST session_timeout); rttMin/rttMax bound
// every path's RTT estimate (libRIST rtt_min/rtt_max).
func NewGroup(sessionTimeout, rttMin, rttMax clock.Microseconds) *Group {
	return &Group{timeout: sessionTimeout, rttMin: rttMin, rttMax: rttMax}
}

// AddPath registers a path with the given index, weight, and NACK recovery
// priority. A path begins un-seen (not yet alive) until its first Observe.
// Re-adding an existing index updates its weight/priority in place.
func (g *Group) AddPath(index uint8, weight int, priority uint32) *Path {
	if p := g.path(index); p != nil {
		p.Weight, p.Priority = weight, priority
		p.wCount = weight // re-seed the rotation credit for the new weight
		return p
	}
	p := &Path{Index: index, Weight: weight, Priority: priority, wCount: weight, rtt: rtt.New(g.rttMin)}
	g.paths = append(g.paths, p)
	return p
}

// HasPath reports whether a path with the given index is already registered.
// The host uses it to avoid overwriting a path's priority/weight that was
// configured before the session was built.
func (g *Group) HasPath(index uint8) bool { return g.path(index) != nil }

// path returns the registered Path with the given index, or nil.
func (g *Group) path(index uint8) *Path {
	for _, p := range g.paths {
		if p.Index == index {
			return p
		}
	}
	return nil
}

// Paths returns the registered paths in registration order (read-only).
func (g *Group) Paths() []*Path { return g.paths }

// Observe records that a datagram arrived on path index at instant now: it
// refreshes liveness and resurrects a path that had been declared dead. Unknown
// indices are ignored (the host only observes registered paths).
func (g *Group) Observe(index uint8, now clock.Timestamp) {
	p := g.path(index)
	if p == nil {
		return
	}
	p.seen = true
	p.lastSeen = now
	p.dead = false
}

// ObserveRTT folds one RTT sample into path index's estimator. Unknown indices
// are ignored.
func (g *Group) ObserveRTT(index uint8, sample clock.Microseconds) {
	if p := g.path(index); p != nil {
		p.rtt = p.rtt.Observe(sample)
	}
}

// Alive reports whether path index has been seen and has not been silent longer
// than the session timeout as of now.
func (g *Group) Alive(index uint8, now clock.Timestamp) bool {
	p := g.path(index)
	return p != nil && p.seen && now.Sub(p.lastSeen) <= g.timeout
}

// Tick ages the paths at instant now and returns the indices of any that just
// transitioned from alive to dead (a path silent for longer than the session
// timeout). The host emits a PathDead notification for each. A subsequent
// Observe resurrects the path. Already-dead and never-seen paths are not
// reported again.
func (g *Group) Tick(now clock.Timestamp) []uint8 {
	var died []uint8
	for _, p := range g.paths {
		if !p.seen || p.dead {
			continue
		}
		if now.Sub(p.lastSeen) > g.timeout {
			p.dead = true
			died = append(died, p.Index)
		}
	}
	return died
}

// SelectNackPath chooses the path to route a NACK on, matching libRIST's
// rist_nack_peer_preferred (src/rist-nack-select.h): among the live paths, the
// one with the highest Priority, ties broken by the lowest clamped RTT. If no
// path is live it falls back to the path that died most recently (best chance of
// having recovered), so retransmission requests are not silently abandoned while
// a path flaps. ok is false only when no path is registered.
//
// addrKnown, when non-nil, reports whether a path's return address has been
// learned; paths for which it returns false are skipped in BOTH the live and the
// fallback selection, so SelectNackPath never returns a path the caller cannot
// actually send on (which would silently drop the NACK). A nil predicate treats
// every path as addressable.
func (g *Group) SelectNackPath(now clock.Timestamp, addrKnown func(index uint8) bool) (index uint8, ok bool) {
	usable := func(p *Path) bool { return addrKnown == nil || addrKnown(p.Index) }
	var best *Path
	for _, p := range g.paths {
		if !g.Alive(p.Index, now) || !usable(p) {
			continue
		}
		if best == nil || preferred(p, best, g) {
			best = p
		}
	}
	if best != nil {
		return best.Index, true
	}
	// No live path: fall back to a SEEN path with a known return address, the one
	// observed most recently (best chance of having recovered), so a NACK is still
	// routed somewhere sendable while paths flap. A never-seen path — or one whose
	// return address is not yet learned — is never chosen (mirrors libRIST gating
	// its fallback on dead_since > 0). With Tick declaring a batch of paths dead in
	// a single call they share no per-path death instant, so lastSeen — which does
	// differ per path — is the meaningful "most recently usable" key.
	for _, p := range g.paths {
		if !p.seen || !usable(p) {
			continue
		}
		if best == nil || p.lastSeen.After(best.lastSeen) {
			best = p
		}
	}
	if best == nil {
		return 0, false
	}
	return best.Index, true
}

// preferred reports whether candidate is a better NACK target than best: higher
// Priority wins; on a Priority tie the lower raw RTT wins (rist_nack_peer_preferred,
// which compares peer->last_rtt — the raw last sample, not the smoothed EWMA).
func preferred(cand, best *Path, g *Group) bool {
	if cand.Priority != best.Priority {
		return cand.Priority > best.Priority
	}
	return cand.nackRTT(g) < best.nackRTT(g)
}

// ShouldDuplicate reports whether a bonded sender should still fan a media
// datagram to the given path: the per-path, allocation-free form of
// DuplicateTargets for the per-packet send loop. It is true for a
// duplication-mode path (Weight == WeightDuplicate) that is not proven dead
// (never-seen included; only a path seen and then silent past the session
// timeout is dropped — libRIST's hard-dead duplicate-peer prune).
func (g *Group) ShouldDuplicate(index uint8, now clock.Timestamp) bool {
	p := g.path(index)
	if p == nil || p.Weight != WeightDuplicate {
		return false
	}
	return g.sendable(p, now)
}

// sendable reports whether a sender should still transmit on path p as of now: a
// never-seen path is sendable (a sender blasts every configured peer from the
// start, before any return traffic proves it live), and only a path seen and then
// silent past the session timeout is dropped (libRIST's hard-dead prune).
func (g *Group) sendable(p *Path, now clock.Timestamp) bool {
	return !(p.seen && now.Sub(p.lastSeen) > g.timeout)
}

// HasWeighted reports whether any path is configured for weighted load-sharing
// (Weight > 0). A sender consults SelectWeighted only when this is true; with no
// weighted path it duplicates to the WeightDuplicate paths alone.
func (g *Group) HasWeighted() bool {
	for _, p := range g.paths {
		if p.Weight > 0 {
			return true
		}
	}
	return false
}

// SelectWeighted elects the single weighted path a bonded sender routes the next
// media datagram to, sharing the stream across the weighted (Weight > 0) paths in
// proportion to their weights. It is the load-balancing counterpart of
// DuplicateTargets: the WeightDuplicate paths get every packet (2022-7), while the
// weighted paths split the packets one-per-datagram via this election.
//
// The rotation follows libRIST's weighted send (rist_sender_send_data_balanced):
// each round, every live weighted path is granted Weight credits; the path with
// the most remaining credit is elected and spends one, so over a round of
// sum(Weight) packets each path carries exactly its Weight share. A path proven
// dead is skipped and its credit redistributes to the survivors, so a failed link
// shifts its share onto the others rather than black-holing those packets. ok is
// false when no weighted path is configured (the caller duplicates only) or when
// every weighted path is currently dead.
func (g *Group) SelectWeighted(now clock.Timestamp) (index uint8, ok bool) {
	if !g.HasWeighted() {
		return 0, false
	}
	best := g.bestWeighted(now)
	if best == nil {
		return 0, false // every weighted path is dead
	}
	if best.wCount <= 0 {
		// The round is exhausted among the live weighted paths: refill them (dead
		// paths are left empty, so their share passes to the survivors) and re-elect.
		for _, p := range g.paths {
			if p.Weight > 0 && g.sendable(p, now) {
				p.wCount = p.Weight
			}
		}
		best = g.bestWeighted(now)
	}
	best.wCount--
	return best.Index, true
}

// bestWeighted returns the live weighted path with the most remaining credit, ties
// broken by registration order (the first such path), or nil if none is live.
func (g *Group) bestWeighted(now clock.Timestamp) *Path {
	var best *Path
	for _, p := range g.paths {
		if p.Weight <= 0 || !g.sendable(p, now) {
			continue
		}
		if best == nil || p.wCount > best.wCount {
			best = p
		}
	}
	return best
}

// SetWeight changes path index's load-balancing weight at runtime (libRIST
// rist_peer_weight_set): 0 returns it to full 2022-7 duplication, a positive value
// makes it carry that share of the weighted rotation. It restarts the rotation so
// the new proportion takes effect cleanly from the next packet, every weighted
// path regaining full credit. Unknown indices are ignored.
func (g *Group) SetWeight(index uint8, weight int) {
	p := g.path(index)
	if p == nil {
		return
	}
	p.Weight = weight
	for _, q := range g.paths {
		q.wCount = q.Weight // restart the round at the new weights
	}
}

// DuplicateTargets returns the indices of the paths a bonded sender fans each
// media datagram across in SMPTE 2022-7 full-redundancy mode: the paths
// configured for duplication (Weight == WeightDuplicate) that are not currently
// dead. A never-seen path IS included — a sender transmits on every configured
// peer from the start, before any return traffic has had a chance to prove it
// live — and only a path seen and then silent past the session timeout is
// dropped.
func (g *Group) DuplicateTargets(now clock.Timestamp) []uint8 {
	var out []uint8
	for _, p := range g.paths {
		if p.Weight != WeightDuplicate {
			continue
		}
		if p.seen && now.Sub(p.lastSeen) > g.timeout {
			continue // proven dead
		}
		out = append(out, p.Index)
	}
	return out
}

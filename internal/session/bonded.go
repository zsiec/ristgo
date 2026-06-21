package session

import (
	"net/netip"

	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/bonding"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/eap"
	"github.com/zsiec/ristgo/internal/fec"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/peer"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/rtp"
	"github.com/zsiec/ristgo/internal/socket"
	"github.com/zsiec/ristgo/internal/wire"
)

// bondAuth is one bonded path's EAP-SRP state (combined PSK+SRP mode): a sender path
// drives an Authenticatee, a receiver path an Authenticator, gating that path's media
// until its handshake succeeds. In the combined PSK+SRP mode the media stays keyed by the
// shared PSK codec, so only the gate is per-path; in the pure-SRP use_key_as_passphrase
// mode each path also re-keys its own codec (bondState.codecs) to its session key K, and
// txKeyGen/rxKeyGen track which K generation is installed. Empty (the whole slice nil)
// when authentication is disabled.
type bondAuth struct {
	client    *eap.Authenticatee // sender role (nil on a receiver)
	server    *eap.Authenticator // receiver role (nil on a sender)
	authed    bool               // this path's handshake has succeeded
	startSent bool               // sender: EAPOL-Start emitted once the peer is known
	lastTx    *eap.Frame         // the outstanding frame to retransmit under loss
	retx      int                // consecutive keepalive-driven retransmits
	txKeyGen  uint64             // pure-SRP: generation of the installed per-path send key
	rxKeyGen  uint64             // pure-SRP: generation of the installed per-path recv key
	pwReqSent bool               // pure-SRP sender: post-SUCCESS PASSWORD_REQUEST emitted
}

// This file is the link-bonding / SMPTE 2022-7 host: N network paths feeding one
// flow. It is the Simple-profile bonded analog of the single-path host — the
// 2022-7 merge itself lives in the flow core (one seq-indexed ring deduplicated
// by (Seq, SourceTime)); this host just fans transmissions across the paths and
// feeds every path's arrivals into that one ring.
//
// # Topology
//
// A bonded RECEIVER binds one socket per path (conns[i]); each path learns its
// own sender address and feeds media into the flow with its path index. A
// bonded SENDER uses one socket and a list of remote {media, rtcp} address pairs
// (remotes[i]); it DUPLICATES every media datagram to all of them (full
// redundancy) so identical (Seq, SourceTime) copies arrive on every path and the
// receiver merges them.
//
// # Decoder sharing
//
// Both directions transmit byte-identical RTP on every path, so the receiver
// MUST decode them with ONE shared mediaDecoder (s.mdec): a per-path decoder
// would anchor its sequence/timestamp widening independently and reconstruct
// different (Seq, SourceTime) values for the same packet on different paths,
// defeating the dedup. The loop is single-goroutine, so the shared decoder is
// safe and yields identical normalized packets for identical wire bytes.

// bondInbound is one datagram a per-path reader hands to the event loop, tagged
// with the path it arrived on (for a receiver) and whether it is RTCP. src is a
// netip.AddrPort value so the per-datagram receive path allocates nothing.
type bondInbound struct {
	idx    uint8
	isRTCP bool
	data   []byte
	src    netip.AddrPort
}

// weightSet is a runtime load-balancing weight change for one path, delivered to
// the event loop via Session.weightCmd (the loop owns the bonding Group).
type weightSet struct {
	path   uint8
	weight int
}

// peerSet is a runtime bonded-path add/remove (BondedSender.AddPath/RemovePath,
// libRIST rist_peer_create/_destroy) delivered to the event loop, which owns the
// bonding Group and the per-path remotes. remove drops the path at index; otherwise
// it adds a destination at index sending to media (weight 0 = full 2022-7 duplication).
type peerSet struct {
	remove   bool
	index    uint8
	remote   [2]netip.AddrPort // {media, rtcp} for a sender add
	conn     *socket.Conn      // the bound listen socket for a receiver add (nil otherwise)
	weight   int
	priority uint32
}

// bondState holds the per-path I/O and policy for a bonded session.
type bondState struct {
	group *bonding.Group

	// lastWeighted is the weighted load-share path the most recent media datagram was
	// routed to (lastWeightedOK reports whether one was elected). FEC fans out to this
	// same path rather than re-electing one: SelectWeighted spends a rotation credit per
	// call, so electing again for each FEC packet would double-spend the credit and skew
	// the per-path media distribution away from the configured weights.
	lastWeighted   uint8
	lastWeightedOK bool

	// conns is one socket per path on a receiver, or the single send socket
	// (conns[0]) on a sender.
	conns []*socket.Conn

	// remotes is the sender's per-path {media, rtcp} destination pair; nil on a
	// receiver (which learns each path's peer from inbound traffic). The
	// addresses are netip.AddrPort values, matching the rest of the send path.
	remotes [][2]netip.AddrPort

	// peers tracks each path's learned/known addresses and liveness.
	peers []*peer.Peer

	// fecReasm reassembles over-MTU in-band FEC control messages per path: a bonded
	// sender fans each FEC fragment to every path, so the receiver must reassemble
	// each path's fragment run independently (a single shared reassembler would
	// interleave fragments arriving on different paths). Each tracks its own control
	// sequence so a dropped fragment is detected per path. nil unless FEC is enabled.
	fecReasm []fecCtrlReassembler

	// auth is the per-path EAP-SRP state (both PSK+SRP and pure-SRP modes). nil when no
	// credentials are configured; otherwise one entry per path, gating that path's
	// media until its handshake succeeds. See bondAuth.
	auth []bondAuth

	// codecs are per-path Main codecs, used ONLY in the pure-SRP use_key_as_passphrase
	// mode so each path can key its own feedback channel to that path's session key K (the
	// media stays cleartext). nil in every other mode (including PSK+SRP), where the one
	// shared s.main codec carries all paths. When non-nil, bondCodec(idx) returns
	// codecs[idx] in place of s.main.
	codecs []*mainCodec

	// everConnected records that the host connect callback has fired (the first path
	// to authenticate); the bonded session connects once though paths auth per-path.
	everConnected bool
}

// NewBondedReceiver builds a Simple-profile bonded receiver: one socket per
// path, all feeding flow into a single deduplicated ring. group must already
// have a path registered per conn (index = conn index); the constructor
// registers them if empty.
// eapServers, when non-nil, is one EAP-SRP Authenticator per path (combined PSK+SRP
// mode): each path authenticates the connecting sender before its media is accepted.
func NewBondedReceiver(conns []*socket.Conn, group *bonding.Group, cfg Config, eapServers []*eap.Authenticator) *Session {
	s := newSession(conns[0], cfg, false)
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	bs := &bondState{group: group, conns: conns, peers: make([]*peer.Peer, len(conns))}
	if cfg.FEC != nil {
		bs.fecReasm = make([]fecCtrlReassembler, len(conns))
	}
	if len(eapServers) > 0 {
		bs.auth = make([]bondAuth, len(conns))
		for i := range eapServers {
			bs.auth[i].server = eapServers[i]
		}
		s.authed.Store(false) // hold every path's media until its handshake succeeds
	}
	buildBondCodecs(s, bs, len(conns))
	for i := range conns {
		bs.peers[i] = peer.New(cfg.SessionTimeout)
		// Register the path with the default duplicate weight / priority 0 unless
		// the host pre-registered it with a chosen recovery priority.
		if !group.HasPath(uint8(i)) {
			group.AddPath(uint8(i), bonding.WeightDuplicate, 0)
		}
	}
	s.bond = bs
	s.bondIn = make(chan bondInbound, 256*len(conns))
	s.peerCmd = make(chan peerSet, 4) // runtime BondedReceiver.AddPath/RemovePath
	s.start()
	return s
}

// NewBondedSender builds a Simple-profile bonded sender: one socket that
// duplicates every media datagram to each remote {media, rtcp} pair. conn is the
// local ephemeral socket; remotes are the per-path receiver addresses.
// eapClients, when non-nil, is one EAP-SRP Authenticatee per path (combined PSK+SRP
// mode): each path runs its own handshake to the receiver before its media flows.
func NewBondedSender(conn *socket.Conn, remotes [][2]netip.AddrPort, group *bonding.Group, cfg Config, eapClients []*eap.Authenticatee) *Session {
	s := newSession(conn, cfg, true)
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	bs := &bondState{group: group, conns: []*socket.Conn{conn}, remotes: remotes, peers: make([]*peer.Peer, len(remotes))}
	if cfg.FEC != nil {
		bs.fecReasm = make([]fecCtrlReassembler, len(remotes))
	}
	if len(eapClients) > 0 {
		bs.auth = make([]bondAuth, len(remotes))
		for i := range eapClients {
			bs.auth[i].client = eapClients[i]
		}
		s.authed.Store(false) // hold media until at least one path's handshake succeeds
	}
	buildBondCodecs(s, bs, len(remotes))
	for i := range remotes {
		bs.peers[i] = peer.New(cfg.SessionTimeout)
		bs.peers[i].Media = remotes[i][0]
		bs.peers[i].RTCP = remotes[i][1]
		// Register with default duplicate weight / priority 0 unless the host
		// pre-registered this path with a chosen recovery priority.
		if !group.HasPath(uint8(i)) {
			group.AddPath(uint8(i), bonding.WeightDuplicate, 0)
		}
	}
	// The base Session's peer guards (peer.Media/RTCP != nil) gate transmission;
	// point them at path 0 so the keepalive/feedback guards pass.
	s.peer.Media = remotes[0][0]
	s.peer.RTCP = remotes[0][1]
	s.bond = bs
	s.bondIn = make(chan bondInbound, 256)
	s.weightCmd = make(chan weightSet, 4) // runtime BondedSender.SetWeight
	s.peerCmd = make(chan peerSet, 4)     // runtime BondedSender.AddPath/RemovePath
	s.start()
	return s
}

// AddPath adds a bonded destination path at runtime (BondedSender.AddPath, libRIST
// rist_peer_create): the sender begins transmitting to media at index, with load-share
// weight (0 = full SMPTE 2022-7 duplication). The caller owns the index space (the
// construction paths are 0..N); a duplicate index is ignored. It marshals the change
// onto the event loop, which owns the bonding Group and remotes, so it is safe from any
// goroutine. Returns ErrOOBUnsupported on a non-bonded sender and the close reason once
// the session is closed.
func (s *Session) AddPath(index uint8, remote [2]netip.AddrPort, weight int, priority uint32) error {
	if s.peerCmd == nil {
		return s.cfg.ErrOOBUnsupported
	}
	select {
	case s.peerCmd <- peerSet{index: index, remote: remote, weight: weight, priority: priority}:
		return nil
	case <-s.done:
		return s.closeReason()
	}
}

// AddPathConn adds a bonded input path at runtime (BondedReceiver.AddPath, libRIST
// rist_peer_create): the receiver reads conn (a socket the host already bound) as a new
// path at index, recovering and merging its media into the same flow. index must be the
// next slot (the conns slice is positional); a non-contiguous index is rejected on the
// loop and conn closed. The loop owns the Group, conns, and the new reader goroutine, so
// this is safe from any goroutine. Returns ErrOOBUnsupported on a non-bonded receiver and
// the close reason once the session is closed.
func (s *Session) AddPathConn(index uint8, conn *socket.Conn, weight int, priority uint32) error {
	if s.peerCmd == nil {
		conn.Close()
		return s.cfg.ErrOOBUnsupported
	}
	select {
	case s.peerCmd <- peerSet{index: index, conn: conn, weight: weight, priority: priority}:
		return nil
	case <-s.done:
		conn.Close()
		return s.closeReason()
	}
}

// RemovePath removes a bonded path at runtime (BondedSender.RemovePath /
// BondedReceiver.RemovePath, libRIST rist_peer_destroy): the sender stops transmitting on
// index, or the receiver stops reading its socket; either way the path drops from NACK
// selection and per-peer stats. An unknown index is a no-op. Returns ErrOOBUnsupported on
// a non-bonded session and the close reason once the session is closed.
func (s *Session) RemovePath(index uint8) error {
	if s.peerCmd == nil {
		return s.cfg.ErrOOBUnsupported
	}
	select {
	case s.peerCmd <- peerSet{remove: true, index: index}:
		return nil
	case <-s.done:
		return s.closeReason()
	}
}

// applyPeerCmd applies one runtime path add/remove on the loop goroutine, which owns
// the bonding Group and the per-path remotes/peers. Add grows the remotes/peers (filling
// any index gap with placeholders the Group never selects) and registers the path so the
// next fan-out reaches it; Remove drops it from the Group (the shared socket stays for
// the others), leaving its remotes slot as an inert tombstone.
func (s *Session) applyPeerCmd(ps peerSet) {
	if s.bond == nil {
		return
	}
	if ps.remove {
		s.bond.group.RemovePath(ps.index)
		// A removed receiver path's reader exits when its socket closes; the closed
		// conn stays in the slice as an inert tombstone (closeBond is idempotent).
		if !s.sender && int(ps.index) < len(s.bond.conns) && s.bond.conns[ps.index] != nil {
			s.bond.conns[ps.index].Close()
		}
		return
	}
	if s.bond.group.HasPath(ps.index) {
		return // duplicate index: ignore (matches Group.AddPath)
	}
	if s.sender {
		// Grow the per-path remotes/peers, filling any index gap with placeholders the
		// Group never selects, then register the destination.
		for int(ps.index) >= len(s.bond.remotes) {
			s.bond.remotes = append(s.bond.remotes, [2]netip.AddrPort{})
			s.bond.peers = append(s.bond.peers, peer.New(s.cfg.SessionTimeout))
			if s.bond.fecReasm != nil {
				s.bond.fecReasm = append(s.bond.fecReasm, fecCtrlReassembler{})
			}
		}
		p := peer.New(s.cfg.SessionTimeout)
		p.Media, p.RTCP = ps.remote[0], ps.remote[1]
		s.bond.peers[ps.index] = p
		s.bond.remotes[ps.index] = ps.remote
		s.bond.group.AddPath(ps.index, ps.weight, ps.priority)
		return
	}
	// Receiver: the host bound the socket; append it (contiguous index), register the
	// path, and spawn its reader(s) feeding the shared inbound channel. A non-contiguous
	// index is rejected (the conns slice is positional, indexed by the readers).
	if int(ps.index) != len(s.bond.conns) || ps.conn == nil {
		if ps.conn != nil {
			ps.conn.Close()
		}
		s.logf("bond: receiver add_path index %d not the next slot (%d); ignored", ps.index, len(s.bond.conns))
		return
	}
	s.bond.conns = append(s.bond.conns, ps.conn)
	s.bond.peers = append(s.bond.peers, peer.New(s.cfg.SessionTimeout))
	if s.bond.fecReasm != nil {
		s.bond.fecReasm = append(s.bond.fecReasm, fecCtrlReassembler{})
	}
	s.bond.group.AddPath(ps.index, ps.weight, ps.priority)
	// Spawn the path reader(s): one media reader for single-port (Main/Advanced), a
	// media + RTCP pair for the even/odd Simple profile.
	if s.main != nil || s.adv != nil {
		s.wg.Add(1)
		go s.readBond(ps.index, false, ps.conn.ReadMedia)
	} else {
		s.wg.Add(2)
		go s.readBond(ps.index, false, ps.conn.ReadMedia)
		go s.readBond(ps.index, true, ps.conn.ReadRTCP)
	}
}

// SetPathWeight changes path's load-balancing weight at runtime (BondedSender.
// SetWeight, libRIST rist_peer_weight_set). It marshals the change onto the event
// loop, which owns the bonding Group, so it is safe to call from any goroutine. It
// returns ErrOOBUnsupported when the session has no weight channel (not a bonded
// sender) and the close reason once the session is closed.
func (s *Session) SetPathWeight(path uint8, weight int) error {
	if s.weightCmd == nil {
		return s.cfg.ErrOOBUnsupported
	}
	select {
	case s.weightCmd <- weightSet{path: path, weight: weight}:
		return nil
	case <-s.done:
		return s.closeReason()
	}
}

// startBondReaders launches the per-path reader goroutines. A receiver runs a
// media and an RTCP reader per path socket; a sender runs a single RTCP reader
// on its one socket (it never receives media), and resolves the path by source
// address.
func (s *Session) startBondReaders() {
	// The Main and Advanced profiles tunnel each path over a single socket
	// (media and control demultiplexed by the codec), so one reader per path
	// suffices; the Simple profile uses an even/odd media+RTCP socket pair.
	singlePort := s.main != nil || s.adv != nil
	if s.sender {
		s.wg.Add(1)
		if singlePort {
			go s.readBond(0, false, s.bond.conns[0].ReadMedia)
		} else {
			go s.readBond(0, true, s.bond.conns[0].ReadRTCP)
		}
		return
	}
	for i, c := range s.bond.conns {
		if singlePort {
			s.wg.Add(1)
			go s.readBond(uint8(i), false, c.ReadMedia)
			continue
		}
		s.wg.Add(2)
		go s.readBond(uint8(i), false, c.ReadMedia)
		go s.readBond(uint8(i), true, c.ReadRTCP)
	}
}

// readBond reads datagrams from one path socket (media or RTCP) and forwards
// them to the loop tagged with the path index.
func (s *Session) readBond(idx uint8, isRTCP bool, read func([]byte) (int, netip.AddrPort, error)) {
	defer s.wg.Done()
	for {
		buf := make([]byte, maxDatagram)
		n, src, err := read(buf)
		if err != nil {
			return
		}
		select {
		case s.bondIn <- bondInbound{idx: idx, isRTCP: isRTCP, data: buf[:n], src: src}:
		case <-s.done:
			return
		}
	}
}

// handleBondInbound processes one inbound bonded datagram: it resolves the path
// (a sender resolves by source address), refreshes liveness, and routes media
// into the flow with its path index (the merge) or feedback into the flow.
func (s *Session) handleBondInbound(now clock.Timestamp, bi bondInbound) {
	idx := bi.idx
	if s.sender {
		var ok bool
		if idx, ok = s.bondPathForSrc(bi.src); !ok {
			return // a datagram from an unknown source; ignore
		}
	}
	if int(idx) >= len(s.bond.peers) {
		return
	}
	p := s.bond.peers[idx]
	p.Observe(now)
	s.peer.Observe(now)
	s.bond.group.Observe(idx, now)

	switch {
	case s.main != nil:
		s.handleBondMain(now, idx, p, bi)
	case s.adv != nil:
		s.handleBondAdv(now, idx, p, bi)
	default:
		s.handleBondSimple(now, idx, p, bi)
	}
}

// bondObserveRTT attributes an RTT-echo response in fbs to a bonded path so the
// NACK-peer selection can prefer the lower-latency return path, then feeds all
// of fbs into the flow. Shared by every profile's bonded feedback path.
func (s *Session) bondObserveRTT(now clock.Timestamp, idx uint8, fbs []wire.Feedback) {
	for _, fb := range fbs {
		if resp, ok := fb.(wire.RttEchoResponse); ok {
			sent := clock.NTPTime(resp.Timestamp).Timestamp()
			s.bond.group.ObserveRTT(idx, now.Sub(sent)-clock.Microseconds(resp.ProcessingDelay))
		}
		// A Flow Attribute is a host-level metadata signal, not flow input — surface
		// it to the application instead of feeding the flow core, matching the
		// interception feedFeedback does on the non-bonded path.
		if fa, ok := fb.(wire.FlowAttribute); ok {
			s.handleFlowAttr(fa.JSON)
			continue
		}
		s.flow.FeedFeedback(now, fb)
	}
}

// buildBondCodecs sets up the pure-SRP use_key_as_passphrase per-path state: a Main codec
// per path (clone of s.main) so each path can key its feedback channel to that path's own
// session key K (the media stays cleartext), and the use_key flag on each per-path EAP role
// so the handshake exports K as feedback keying (without it the role yields no
// TxKeying/RxKeying and the peer's encrypted feedback cannot be decrypted). A no-op in
// every other mode (bs.codecs stays nil and the one shared s.main codec carries all paths).
func buildBondCodecs(s *Session, bs *bondState, n int) {
	if !s.useKeyAsPassphrase || s.main == nil {
		return
	}
	bs.codecs = make([]*mainCodec, n)
	for i := range bs.codecs {
		bs.codecs[i] = s.main.cloneFresh()
	}
	for i := range bs.auth {
		if bs.auth[i].client != nil {
			bs.auth[i].client.UseKeyAsPassphrase(true)
		}
		if bs.auth[i].server != nil {
			bs.auth[i].server.UseKeyAsPassphrase(true)
		}
	}
}

// bondCodec returns the Main codec carrying path idx: the per-path codec in the pure-SRP
// mode (each path keyed to its own K), else the one shared s.main codec.
func (s *Session) bondCodec(idx uint8) *mainCodec {
	if int(idx) < len(s.bond.codecs) {
		return s.bond.codecs[idx]
	}
	return s.main
}

// bondPathAuthed reports whether path idx may carry media: always true when bonded
// authentication is disabled, otherwise once that path's EAP-SRP handshake has succeeded.
func (s *Session) bondPathAuthed(idx uint8) bool {
	return len(s.bond.auth) == 0 || (int(idx) < len(s.bond.auth) && s.bond.auth[idx].authed)
}

// maybeStartBondEAP emits each sender path's EAPOL-Start exactly once (the remotes are
// known at construction). A no-op on a receiver, a session without EAP, or after Start.
func (s *Session) maybeStartBondEAP(now clock.Timestamp) {
	for i := range s.bond.auth {
		a := &s.bond.auth[i]
		if a.client == nil || a.startSent {
			continue
		}
		a.startSent = true
		a.retx = 0
		f := a.client.Start()
		a.lastTx = &f
		s.sendBondEAP(uint8(i), f, now)
	}
}

// handleBondEAP drives path idx's EAP-SRP handshake with one inbound EAPOL frame: the
// sender's Authenticatee or the receiver's Authenticator. On the first path to
// authenticate it opens the session data channel (s.authed) and, on a receiver, runs the
// host connect gate (rejecting tears the whole bonded session down). The media stays
// keyed by the shared PSK codec — SRP only gates here — so no re-keying is done.
func (s *Session) handleBondEAP(now clock.Timestamp, idx uint8, payload []byte) {
	if int(idx) >= len(s.bond.auth) {
		return
	}
	a := &s.bond.auth[idx]
	a.retx = 0
	var (
		out      *eap.Frame
		err      error
		authedAt bool
	)
	switch {
	case a.client != nil:
		out, err = a.client.Recv(payload)
		authedAt = a.client.Authenticated()
	case a.server != nil:
		out, err = a.server.Recv(payload)
		authedAt = a.server.Authenticated()
	default:
		return
	}
	if err != nil {
		s.logf("bond: eap path %d: %v", idx, err)
	}
	if out != nil {
		a.lastTx = out
		s.sendBondEAP(idx, *out, now)
	}
	// Pure-SRP: re-key this path's codec from its session key K once available (sent the
	// EAPOL reply cleartext first; keying is idempotent per generation). A no-op in PSK+SRP.
	if s.useKeyAsPassphrase {
		s.installBondEAPKeying(idx)
		// Authenticatee: once at SUCCESS (keys installed), drive the post-SUCCESS
		// PASSWORD_REQUEST, which makes the authenticator install its RX key (= K) so it
		// can decrypt our media. Without it the peer keys only its TX and drops our media.
		if a.client != nil && !a.pwReqSent {
			if f, ok := a.client.PasswordRequest(); ok {
				a.pwReqSent = true
				s.sendBondEAP(idx, f, now)
			}
		}
	}
	wasAuthed := a.authed
	a.authed = authedAt
	if a.authed && !wasAuthed {
		// First successful auth on this path. On a receiver, gate the connection once
		// (the session connects on its first authenticated path).
		if a.server != nil && !s.bond.everConnected {
			s.bond.everConnected = true
			if !s.admitBondPeer(idx) {
				s.shutdown(s.cfg.ErrAuth)
				return
			}
		}
		// Open the session data channel on the first path up: app media + feedback flow,
		// and sendBondMedia begins fanning to the now-authenticated path(s).
		s.authed.Store(true)
	}
}

// installBondEAPKeying re-keys path idx's codec from that path's EAP-SRP session key K
// (the pure-SRP use_key_as_passphrase mode), once the handshake has produced keying
// material. It is the per-path analog of installEAPKeying: idempotent per direction via
// the per-path key generation (a no-op until K is available and after the current
// generation is installed). K never reaches a log here.
func (s *Session) installBondEAPKeying(idx uint8) {
	if int(idx) >= len(s.bond.codecs) || int(idx) >= len(s.bond.auth) {
		return
	}
	a := &s.bond.auth[idx]
	codec := s.bond.codecs[idx]
	keyBits := crypto.KeySize128
	if s.eapKeySize256 {
		keyBits = crypto.KeySize256
	}
	var (
		tx, rx         eap.Passphrase
		haveTx, haveRx bool
	)
	switch {
	case a.client != nil:
		tx, haveTx = a.client.TxKeying()
		rx, haveRx = a.client.RxKeying()
	case a.server != nil:
		tx, haveTx = a.server.TxKeying()
		rx, haveRx = a.server.RxKeying()
	}
	if haveTx && tx.Gen != a.txKeyGen {
		if k, err := crypto.NewKeyRaw(tx.Key, keyBits, s.eapKeyRotation, false); err != nil {
			s.logf("bond: derive send key path %d: %v", idx, err)
		} else {
			codec.setSendKey(k, s.eapKeySize256)
			a.txKeyGen = tx.Gen
		}
	}
	if haveRx && rx.Gen != a.rxKeyGen {
		if d, err := crypto.NewDecryptorRaw(rx.Key, keyBits); err != nil {
			s.logf("bond: derive recv key path %d: %v", idx, err)
		} else {
			codec.setRecvKey(d)
			a.rxKeyGen = rx.Gen
		}
	}
}

// sendBondEAP frames an EAPOL payload through path idx's codec and sends it on path idx
// to that path's peer: a sender writes its one socket to remote idx; a receiver writes
// path idx's socket to the learned sender address. EAPOL rides the path's codec while it
// is still cleartext (pre-K), so each path's GRE sequence stays self-consistent.
func (s *Session) sendBondEAP(idx uint8, f eap.Frame, now clock.Timestamp) {
	s.lastTx = now
	s.rtcpBuf = s.rtcpBuf[:0]
	b, err := s.bondCodec(idx).encodeEAPOL(s.rtcpBuf, f.AppendTo(nil))
	if err != nil {
		s.logf("bond: encode eap path %d: %v", idx, err)
		return
	}
	s.rtcpBuf = b
	var (
		conn *socket.Conn
		dst  netip.AddrPort
	)
	if s.sender {
		conn, dst = s.bond.conns[0], s.bond.remotes[idx][0]
	} else {
		conn, dst = s.bond.conns[idx], s.bond.peers[idx].Media
	}
	if !dst.IsValid() {
		return
	}
	if err := conn.WriteMedia(b, dst); err != nil {
		s.logf("bond: write eap path %d: %v", idx, err)
	}
}

// admitBondPeer offers path idx's just-authenticated peer to the host connect callback
// (libRIST rist_auth_handler_set) and records the ConnectInfo for the disconnect
// callback. Returns whether the peer is admitted (true when no callback is set).
func (s *Session) admitBondPeer(idx uint8) bool {
	info := ConnectInfo{Remote: s.bond.peers[idx].Media.String()}
	if a := s.bond.auth[idx].server; a != nil {
		info.Username = a.PeerUsername()
	}
	if s.cfg.OnConnect != nil && !s.cfg.OnConnect(info) {
		return false
	}
	s.connected = &info
	return true
}

// maybeRetransmitBondEAP re-sends each not-yet-authenticated path's outstanding EAPOL
// frame (EAP-SRP frames are not ARQ-protected, so a dropped handshake datagram would
// otherwise deadlock auth under loss). Called on the keepalive tick; the peer replays
// its reply idempotently, and a stalled handshake is bounded by the session timeout.
func (s *Session) maybeRetransmitBondEAP(now clock.Timestamp) {
	for i := range s.bond.auth {
		a := &s.bond.auth[i]
		if a.authed || a.lastTx == nil || a.retx >= maxEAPRetx {
			continue
		}
		a.retx++
		s.sendBondEAP(uint8(i), *a.lastTx, now)
	}
}

// handleBondSimple routes one Simple-profile bonded datagram: RTCP into feedback
// (with per-path RTT), media into the flow with its path index. Media is decoded
// with the SHARED decoder so identical wire bytes from any path reconstruct to
// the same (Seq, SourceTime), which is what the dedup merges.
func (s *Session) handleBondSimple(now clock.Timestamp, idx uint8, p *peer.Peer, bi bondInbound) {
	if bi.isRTCP {
		p.LearnRTCP(bi.src)
		if fbs, err := decodeFeedback(bi.data, s.highestSent); err == nil {
			s.bondObserveRTT(now, idx, fbs)
		}
		return
	}
	p.LearnMedia(bi.src)
	if pkt, err := s.mdec.decode(bi.data); err == nil {
		s.feedMedia(now, idx, pkt)
		if s.fecEnabled() {
			s.fecRecvRTP(now, s.mdec.lastWireTS, pkt)
		}
	}
}

// handleBondMain routes one Main-profile bonded datagram. Each path tunnels over
// one socket, so the shared Main codec demuxes media vs feedback (and OOB); media
// is fed with its path index and feedback attributed per path.
func (s *Session) handleBondMain(now clock.Timestamp, idx uint8, p *peer.Peer, bi bondInbound) {
	p.LearnMedia(bi.src)
	p.LearnRTCP(bi.src)
	codec := s.bondCodec(idx)
	if oob, proto, ok, oerr := codec.peekOOB(bi.data); ok {
		if oerr == nil {
			s.deliverOOB(proto, oob)
		}
		return
	}
	// EAP-SRP authentication frame: route to this path's handshake (both auth modes).
	if len(s.bond.auth) > 0 {
		if eapPayload, ok := codec.peekEAPOL(bi.data); ok {
			s.handleBondEAP(now, idx, eapPayload)
			return
		}
	}
	isMedia, pkt, fbs, bn, err := codec.decodeMain(bi.data, s.highestSent)
	if err != nil {
		return
	}
	if bn != nil {
		s.handleBufferNeg(*bn)
		return
	}
	if isMedia {
		// Drop media on a path that has not completed its EAP-SRP handshake (a no-op
		// when authentication is disabled — bondPathAuthed is then always true).
		if !s.bondPathAuthed(idx) {
			return
		}
		s.feedMedia(now, idx, pkt)
		if s.fecEnabled() {
			s.fecRecvRTP(now, codec.dec.lastWireTS, pkt)
		}
		return
	}
	s.bondObserveRTT(now, idx, fbs)
}

// handleBondAdv routes one Advanced-profile bonded datagram: adv RTP media into
// the flow with its path index, or the Main-GRE control substrate (Type-8 or raw
// GRE RTCP) into feedback. It mirrors handleAdvInbound but is path-aware.
func (s *Session) handleBondAdv(now clock.Timestamp, idx uint8, p *peer.Peer, bi bondInbound) {
	p.LearnMedia(bi.src)
	p.LearnRTCP(bi.src)
	data := bi.data
	if len(data) >= 2 && data[0]&0xC0 == 0x80 {
		if pt := data[1] & 0x7f; pt == adv.PayloadType || pt >= 96 {
			if pr, err := adv.Parse(data); err == nil {
				if pr.EncType == adv.TypeGREMain {
					s.handleBondAdvGRE(now, idx, pr.Payload)
					return
				}
				// In-band SMPTE 2022 FEC control message (TR-06-3 §5.3.5): route to
				// the FEC decoder, reassembling a fragmented one per path.
				if s.fecEnabled() && pr.EncType == adv.TypeControl {
					s.handleBondFECControl(now, idx, pr)
					return
				}
				if isMedia, pkt, fbs, derr := s.adv.decodeParsed(pr); derr == nil {
					if isMedia {
						s.feedMedia(now, idx, pkt)
						if s.fecEnabled() {
							s.fecRecvAdv(now, pkt.Seq, data) // FEC over the full datagram
						}
					} else {
						s.bondObserveRTT(now, idx, s.filterAdvEcho(fbs))
					}
					// TR-06-3 §9: a peer's native Advanced keep-alive I bit upgrades the
					// sender's media framing to Advanced (see Session.remoteSupportsAdvanced).
					if advI, ok := s.adv.takePeerAdvCap(); ok && advI {
						s.remoteSupportsAdvanced = true
					}
				}
				return
			}
		}
	}
	s.handleBondAdvGRE(now, idx, data)
}

// handleBondAdvGRE decodes one Main-profile GRE datagram on a bonded Advanced
// path (the RTCP/keepalive substrate), feeding any NACK/feedback into the flow
// with per-path RTT attribution.
func (s *Session) handleBondAdvGRE(now clock.Timestamp, idx uint8, data []byte) {
	// A GRE keep-alive on a bonded path advertises pair-split (L bit, merge=auto)
	// and, in Advanced mode, the peer's Advanced capability (extended I bit) that
	// upgrades the sender's media framing to Advanced (TR-06-3 §9).
	if kind, ka, _, cerr := s.advGRE.peekControl(data); kind == controlKeepalive {
		if cerr == nil {
			s.applyRemoteCaps(ka.Caps)
			if ka.HasAdvExt && ka.AdvExt.I {
				s.remoteSupportsAdvanced = true
			}
		}
		return
	}
	if oob, proto, ok, oerr := s.advGRE.peekOOB(data); ok {
		if oerr == nil {
			s.deliverOOB(proto, oob)
		}
		return
	}
	isMedia, pkt, fbs, bn, err := s.advGRE.decodeMain(data, s.highestSent)
	if err != nil {
		return
	}
	if bn != nil {
		s.handleBufferNeg(*bn)
		return
	}
	if isMedia {
		s.feedMedia(now, idx, pkt)
		return
	}
	s.bondObserveRTT(now, idx, s.filterAdvEcho(fbs))
}

// bondPathForSrc resolves a sender's inbound source address (a receiver path's
// RTCP socket) to its path index.
func (s *Session) bondPathForSrc(src netip.AddrPort) (uint8, bool) {
	if !src.IsValid() {
		return 0, false
	}
	for i, r := range s.bond.remotes {
		if addrPortEqual(src, r[1]) {
			return uint8(i), true
		}
	}
	return 0, false
}

// addrPortEqual reports whether two UDP addresses share host and port. The host
// is compared unmapped so an IPv4 source seen as 4-in-6 on a dual-stack socket
// still matches its plain-IPv4 destination form.
func addrPortEqual(a, b netip.AddrPort) bool {
	return a.IsValid() && b.IsValid() && a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}

// sendBondMedia duplicates one encoded media datagram to every path (full 2022-7
// redundancy). It encodes ONCE with the profile codec and writes the identical
// bytes to each path's media destination. The encrypted Main/Advanced transport
// sequence (the GRE/IV seq) is therefore identical on every path, which is
// interop-safe: the dedup key is the inner RTP (Seq, SourceTime), identical
// across paths, and the receiver reads each datagram's transport seq from the
// wire (libRIST frames per-peer but the receiver merges on the same RTP key).
func (s *Session) sendBondMedia(now clock.Timestamp, pkt wire.MediaPacket) {
	// Pure-SRP mode: each path encodes with its own K-keyed codec (different ciphertext
	// per path), so the encode moves inside the fan. FEC is disallowed in this mode.
	if len(s.bond.codecs) > 0 {
		s.sendBondMediaPerPath(now, pkt)
		return
	}
	s.mediaBuf = s.mediaBuf[:0]
	var (
		b   []byte
		err error
	)
	switch {
	case s.main != nil:
		b, err = s.main.encodeMainMedia(s.mediaBuf, pkt)
	case s.advInMainWindow():
		// TR-06-3 §9 (AdvSenderStartMain): start in Main framing until a peer
		// advertises Advanced (I=1). Bonded paths all carry one flow to one logical
		// receiver, so a single session-level upgrade switches every path together.
		b, err = s.advGRE.encodeMainMedia(s.mediaBuf, pkt)
	case s.adv != nil:
		b, err = s.adv.encodeAdvMedia(s.mediaBuf, pkt)
	default:
		b, err = encodeMedia(s.mediaBuf, pkt)
	}
	if err != nil {
		s.logf("bond: encode media seq %d: %v", pkt.Seq, err)
		return
	}
	s.mediaBuf = b
	for i := range s.bond.remotes {
		// Skip a path proven dead (seen and then silent past the session timeout)
		// so the sender stops blasting media at a permanently-down path; a
		// never-seen path is still sent to (libRIST's hard-dead prune).
		if !s.bond.group.ShouldDuplicate(uint8(i), now) {
			continue
		}
		// Don't transmit media on a path whose EAP-SRP handshake has not yet succeeded
		// (a no-op when authentication is disabled).
		if !s.bondPathAuthed(uint8(i)) {
			continue
		}
		s.bond.group.CountSent(uint8(i), len(pkt.Payload), pkt.Retransmit)
		if err := s.bond.conns[0].WriteMedia(b, s.bond.remotes[i][0]); err != nil {
			s.logf("bond: write media path %d: %v", i, err)
		}
	}
	// Weighted load-share paths (Weight > 0): route this datagram to one elected
	// path, splitting the stream across them in proportion to their weights
	// (libRIST weighted send). These paths are disjoint from the duplicate paths
	// above, so no path is sent the same datagram twice. Record the election so the
	// FEC fan-out reuses it instead of spending another rotation credit (see fanBondPaths).
	idx, ok := s.bond.group.SelectWeighted(now)
	s.bond.lastWeighted, s.bond.lastWeightedOK = idx, ok && int(idx) < len(s.bond.remotes) && s.bondPathAuthed(idx)
	if s.bond.lastWeightedOK {
		s.bond.group.CountSent(idx, len(pkt.Payload), pkt.Retransmit)
		if err := s.bond.conns[0].WriteMedia(b, s.bond.remotes[idx][0]); err != nil {
			s.logf("bond: write media weighted path %d: %v", idx, err)
		}
	}
	s.lastTx = now
	// Suppressed during the §9 Main-framing window (see advInMainWindow): the adv FEC
	// matrix must not mix Main- and Advanced-framed datagrams; the window relies on ARQ.
	if s.fecEnabled() && !s.advInMainWindow() {
		s.fecOnSend(now, pkt, b) // generate row/column FEC and fan it across the paths
	}
}

// sendBondMediaPerPath is sendBondMedia's pure-SRP variant: each path encodes the packet
// with its OWN codec (keyed to that path's session key K), so the ciphertext differs per
// path. It mirrors the duplicate + weighted fan, gating each path on its handshake; the
// dedup key is still the inner RTP (Seq, SourceTime), identical across paths. FEC is not
// supported here (rejected at construction), so there is no FEC fan.
func (s *Session) sendBondMediaPerPath(now clock.Timestamp, pkt wire.MediaPacket) {
	send := func(i uint8) {
		s.mediaBuf = s.mediaBuf[:0]
		b, err := s.bond.codecs[i].encodeMainMedia(s.mediaBuf, pkt)
		if err != nil {
			s.logf("bond: encode media path %d seq %d: %v", i, pkt.Seq, err)
			return
		}
		s.mediaBuf = b
		s.bond.group.CountSent(i, len(pkt.Payload), pkt.Retransmit)
		if werr := s.bond.conns[0].WriteMedia(b, s.bond.remotes[i][0]); werr != nil {
			s.logf("bond: write media path %d: %v", i, werr)
		}
	}
	for i := range s.bond.remotes {
		// Skip a proven-dead path or one whose handshake has not completed.
		if !s.bond.group.ShouldDuplicate(uint8(i), now) || !s.bondPathAuthed(uint8(i)) {
			continue
		}
		send(uint8(i))
	}
	// Weighted load-share paths: one elected path carries this datagram (disjoint from
	// the duplicate paths above), recorded for the (absent) FEC fan's parity.
	idx, ok := s.bond.group.SelectWeighted(now)
	s.bond.lastWeighted, s.bond.lastWeightedOK = idx, ok && int(idx) < len(s.bond.remotes) && s.bondPathAuthed(idx)
	if s.bond.lastWeightedOK {
		send(idx)
	}
	s.lastTx = now
}

// sendBondFEC fans one FEC packet across the bonded paths in the configured
// carriage. FEC protects the source stream, which every path carries (2022-7
// duplication), so the FEC is duplicated the same way media is: to every sendable
// duplicate path plus the elected weighted path. The receiver feeds all paths'
// media and FEC into the one per-session decoder, which dedups by sequence, so FEC
// recovers only the rare loss that struck every path at once.
func (s *Session) sendBondFEC(now clock.Timestamp, fp fec.Packet) {
	if s.cfg.FEC.SeparatePorts {
		s.sendBondFECSeparate(now, fp)
		return
	}
	rowCI, colCI := s.fecControlIndices()
	ci := colCI
	if fp.Direction == fec.Row {
		ci = rowCI
	}
	body := adv.BuildControl(nil, ci, fp.Data)
	if len(body) <= fecMaxCtrlBody {
		s.writeBondFECControl(now, body, true, true)
		return
	}
	for off := 0; off < len(body); off += fecMaxCtrlBody {
		end := off + fecMaxCtrlBody
		if end > len(body) {
			end = len(body)
		}
		s.writeBondFECControl(now, body[off:end], off == 0, end == len(body))
	}
}

// writeBondFECControl frames one (possibly fragmented) in-band FEC control message
// and fans it across the paths.
func (s *Session) writeBondFECControl(now clock.Timestamp, body []byte, first, last bool) {
	b, err := s.adv.frameControlFrag(s.fecBuf[:0], body, first, last, advCtrlTS(now))
	if err != nil {
		s.logf("bond fec: frame control: %v", err)
		return
	}
	s.fecBuf = b
	s.fanBondPaths(now, func(media netip.AddrPort) {
		if werr := s.bond.conns[0].WriteMedia(b, media); werr != nil {
			s.logf("bond: write fec control: %v", werr)
		}
	})
}

// sendBondFECSeparate wraps a FEC packet in an RTP header (standard ST 2022-x) and
// fans it to each path's column/row FEC port (the path's media port + 2 / + 4).
func (s *Session) sendBondFECSeparate(now clock.Timestamp, fp fec.Packet) {
	seqp := &s.fecColSeq
	off := uint16(fecColumnPortOffset)
	if fp.Direction == fec.Row {
		seqp = &s.fecRowSeq
		off = fecRowPortOffset
	}
	p := rtp.Packet{
		Header:  rtp.Header{Version: rtp.Version, PayloadType: fecPT, SequenceNumber: *seqp, SSRC: s.cfg.SSRC},
		Payload: fp.Data,
	}
	*seqp++
	b, err := p.AppendTo(s.fecBuf[:0])
	if err != nil {
		s.logf("bond fec: rtp wrap: %v", err)
		return
	}
	s.fecBuf = b
	s.fanBondPaths(now, func(media netip.AddrPort) {
		dst := netip.AddrPortFrom(media.Addr(), media.Port()+off)
		if werr := s.bond.conns[0].WriteMedia(b, dst); werr != nil {
			s.logf("bond: write fec separate: %v", werr)
		}
	})
}

// fanBondPaths invokes write with the media address of each path the FEC for the most
// recent media datagram is sent to: every sendable 2022-7 duplicate path plus the
// weighted load-share path that media datagram was routed to. It reuses the recorded
// election (lastWeighted) rather than calling SelectWeighted, which would spend a second
// rotation credit per FEC packet and skew the weighted media distribution.
func (s *Session) fanBondPaths(now clock.Timestamp, write func(media netip.AddrPort)) {
	for i := range s.bond.remotes {
		if !s.bond.group.ShouldDuplicate(uint8(i), now) {
			continue
		}
		write(s.bond.remotes[i][0])
	}
	if s.bond.lastWeightedOK && int(s.bond.lastWeighted) < len(s.bond.remotes) {
		write(s.bond.remotes[s.bond.lastWeighted][0])
	}
}

// handleBondFECControl reassembles a (possibly fragmented) in-band FEC control
// message arriving on path idx and feeds its FEC body to the decoder. Each path is
// reassembled independently because the sender duplicates every fragment to all
// paths, so a single shared reassembler would interleave their runs.
func (s *Session) handleBondFECControl(now clock.Timestamp, idx uint8, pr adv.Parsed) {
	if int(idx) >= len(s.bond.fecReasm) {
		return
	}
	if !pr.FirstFrag || !pr.LastFrag {
		full, ok := s.bond.fecReasm[idx].push(pr.Seq, fecFragRole(pr.FirstFrag, pr.LastFrag), pr.Payload)
		if !ok {
			return
		}
		if ci, body, cerr := adv.ParseControl(full); cerr == nil && s.fecControlIndex(ci) {
			s.fecOnRecvFEC(now, body)
		}
		return
	}
	if ci, body, cerr := adv.ParseControl(pr.Payload); cerr == nil && s.fecControlIndex(ci) {
		s.fecOnRecvFEC(now, body)
	}
}

// sendBondFeedback transmits drained feedback. A sender sends its compound on
// every path so each path's liveness/RTT is exercised. A receiver splits the
// feedback: RTT-echo requests fan out to EVERY learned path (so each path's RTT
// refreshes at the flow's 100 ms echo cadence, feeding the NACK-peer RTT
// tie-break on all paths, not only the selected one at the 1000 ms keepalive),
// while NACK groups route to the single NACK-peer-selected path (bonding.
// SelectNackPath) to avoid duplicate retransmissions.
func (s *Session) sendBondFeedback(fbs []wire.Feedback, now clock.Timestamp) {
	// Main and Advanced tunnel feedback as a GRE compound (the Main codec, or the
	// Advanced profile's GRE control substrate) over the single per-path socket;
	// the Simple profile sends bare compound RTCP on the odd port.
	greCodec := s.bondGRECodec()

	if s.sender {
		lead := rtcp.SenderReport{
			SSRC:    s.cfg.SSRC,
			NTP:     s.wallNTP(now), // absolute wall-clock NTP (RFC 3550); see wallNTP
			RTPTime: uint32(rtpTicksFromMicros(int64(now))),
		}
		s.rtcpBuf = s.rtcpBuf[:0]
		b, err := s.encodeBondFeedback(lead, fbs, greCodec)
		if err != nil {
			s.logf("bond: encode feedback: %v", err)
			return
		}
		s.rtcpBuf = b
		// Send on every path so RTT echoes and SDES reach each receiver path.
		for i := range s.bond.remotes {
			if err := s.writeBondFeedback(s.bond.conns[0], greCodec, s.bond.remotes[i][1], s.bond.remotes[i][0]); err != nil {
				s.logf("bond: write feedback path %d: %v", i, err)
			}
		}
		s.lastTx = now
		return
	}

	// Receiver: split RTT echoes (fan out to every path) from NACKs (selected
	// path only).
	var echoes, nacks []wire.Feedback
	for _, fb := range fbs {
		if _, ok := fb.(wire.RttEchoRequest); ok {
			echoes = append(echoes, fb)
		} else {
			nacks = append(nacks, fb)
		}
	}
	if len(echoes) > 0 {
		s.fanReceiverFeedback(echoes, greCodec, now)
	}
	if len(nacks) > 0 {
		s.routeReceiverNacks(nacks, greCodec, now)
	}
}

// encodeBondFeedback encodes a bonded RTCP compound (profile-aware: GRE-tunnelled
// for Main/Advanced, bare compound for Simple) into s.rtcpBuf.
func (s *Session) encodeBondFeedback(lead rtcp.Packet, fbs []wire.Feedback, greCodec *mainCodec) ([]byte, error) {
	s.rtcpBuf = s.rtcpBuf[:0]
	if greCodec != nil {
		return greCodec.encodeMainFeedback(s.rtcpBuf, lead, fbs, s.cfg.Bitmask)
	}
	return encodeFeedback(s.rtcpBuf, lead, s.cfg.SSRC, s.cfg.CNAME, fbs, s.cfg.Bitmask)
}

// fanReceiverFeedback writes a receiver compound (RR + fbs) to every learned
// path, mirroring sendBondKeepalive — used for the receiver-originated RTT echo
// so every path's RTT is refreshed at the echo cadence.
func (s *Session) fanReceiverFeedback(fbs []wire.Feedback, greCodec *mainCodec, now clock.Timestamp) {
	b, err := s.encodeBondFeedback(s.receiverReport(), fbs, greCodec)
	if err != nil {
		s.logf("bond: encode receiver feedback: %v", err)
		return
	}
	s.rtcpBuf = b
	sent := false
	for i := range s.bond.peers {
		p := s.bond.peers[i]
		if !p.RTCP.IsValid() {
			continue
		}
		if err := s.writeBondFeedback(s.bond.conns[i], greCodec, p.RTCP, p.RTCP); err != nil {
			s.logf("bond: write echo path %d: %v", i, err)
			continue
		}
		sent = true
	}
	if sent {
		s.lastTx = now
	}
}

// routeReceiverNacks writes a receiver compound (RR + NACKs) to the single
// NACK-peer-selected live path. The addrKnown predicate keeps SelectNackPath
// from choosing a path whose return address is not yet learned — including in
// the all-dead fallback, which would otherwise pick a seen-but-unaddressable
// path and silently drop the NACK.
func (s *Session) routeReceiverNacks(fbs []wire.Feedback, greCodec *mainCodec, now clock.Timestamp) {
	idx, ok := s.bond.group.SelectNackPath(now, func(i uint8) bool { return s.bond.peers[i].RTCP.IsValid() })
	if !ok {
		return
	}
	p := s.bond.peers[idx]
	if !p.RTCP.IsValid() {
		return // defensive: predicate already excluded unaddressable paths
	}
	b, err := s.encodeBondFeedback(s.receiverReport(), fbs, greCodec)
	if err != nil {
		s.logf("bond: encode nacks: %v", err)
		return
	}
	s.rtcpBuf = b
	if err := s.writeBondFeedback(s.bond.conns[idx], greCodec, p.RTCP, p.RTCP); err != nil {
		s.logf("bond: write feedback on path %d: %v", idx, err)
	}
	s.lastTx = now
}

// bondGRECodec returns the GRE codec a bonded session uses to tunnel feedback:
// the Main codec for a Main bonded session, the Advanced GRE control substrate
// for an Advanced one, or nil for the Simple profile (bare RTCP).
func (s *Session) bondGRECodec() *mainCodec {
	if s.main != nil {
		return s.main
	}
	return s.advGRE
}

// writeBondFeedback writes one encoded feedback datagram to a path. Single-port
// profiles (greCodec != nil) write the media-side socket/address; the Simple
// profile writes the RTCP socket/odd-port address.
func (s *Session) writeBondFeedback(conn *socket.Conn, greCodec *mainCodec, simpleRTCP, singlePort netip.AddrPort) error {
	if greCodec != nil {
		return conn.WriteMedia(s.rtcpBuf, singlePort)
	}
	return conn.WriteRTCP(s.rtcpBuf, simpleRTCP)
}

// sendBondKeepalive emits a periodic keepalive. A sender sends SR + SDES +
// RTT-echo on every path (sendBondFeedback already fans out). A receiver fans
// its RR + RTT-echo request out to EVERY learned path — not just the selected
// NACK path — so each path's RTT and return-path liveness are exercised;
// otherwise only the selected path's RTT is ever measured and the NACK-peer
// RTT tie-break has no data. NACK groups still route to the single selected path
// via sendBondFeedback.
//
// A bonded Main session does NOT emit the GRE capability keepalive beacon (the MAC +
// capability-flags message sendGREKeepalive sends on the non-bonded Main path), so it
// never advertises the SMPTE-2022 FEC capability (the P flag). This is intentional: the
// bonded keepalive is an RTCP RR + RTT-echo compound tunnelled over GRE, not the
// capability beacon, and the P flag is purely informational — a ristgo receiver decodes
// FEC regardless of it, so the only effect is that a peer inspecting the beacon is not
// told FEC is in use on a bonded Main link.
func (s *Session) sendBondKeepalive(now clock.Timestamp) {
	// Retransmit any path's outstanding EAP-SRP frame until it authenticates (EAPOL is
	// not ARQ-protected); a no-op once every path is up or auth is disabled.
	if len(s.bond.auth) > 0 {
		s.maybeRetransmitBondEAP(now)
	}
	echo := []wire.Feedback{wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(now))}}
	if s.sender {
		s.sendBondFeedback(echo, now)
		return
	}
	s.rtcpBuf = s.rtcpBuf[:0]
	greCodec := s.bondGRECodec()
	var (
		b   []byte
		err error
	)
	if greCodec != nil {
		b, err = greCodec.encodeMainFeedback(s.rtcpBuf, s.receiverReport(), echo, s.cfg.Bitmask)
	} else {
		b, err = encodeFeedback(s.rtcpBuf, s.receiverReport(), s.cfg.SSRC, s.cfg.CNAME, echo, s.cfg.Bitmask)
	}
	if err != nil {
		s.logf("bond: encode keepalive: %v", err)
		return
	}
	s.rtcpBuf = b
	sent := false
	for i := range s.bond.peers {
		p := s.bond.peers[i]
		if !p.RTCP.IsValid() {
			continue // path's return address not learned yet
		}
		if err := s.writeBondFeedback(s.bond.conns[i], greCodec, p.RTCP, p.RTCP); err != nil {
			s.logf("bond: write keepalive path %d: %v", i, err)
			continue
		}
		sent = true
	}
	if sent {
		s.lastTx = now
	}
}

// tickBond ages the paths and logs any that died this interval. (The flow keeps
// running on the survivors; the merge needs no notification.)
func (s *Session) tickBond(now clock.Timestamp) {
	for _, idx := range s.bond.group.Tick(now) {
		s.logAt(LogNote, CatBonding, "bond: path %d declared dead", idx)
	}
}

// closeBond closes every path socket. Called from shutdown for a bonded session.
func (s *Session) closeBond() {
	for _, c := range s.bond.conns {
		c.Close()
	}
}

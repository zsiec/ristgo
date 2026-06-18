package ristgo

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/zsiec/ristgo/internal/bonding"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/eap"
	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// BondedReceiver receives a single media flow carried redundantly over several
// network paths (RIST link bonding / SMPTE 2022-7) and delivers the merged,
// in-order, deduplicated stream. It is the multipath counterpart of Receiver:
// the same flow arrives on every path, and a packet lost on one path is covered
// by another's copy with no retransmission — seamless reconstruction.
//
// Like Receiver it is an io.ReadCloser with single-consumer stream semantics.
type BondedReceiver struct {
	sess    *session.Session
	ctxStop func() // ends the context watcher (set by ListenBonded)
	cfg     Config // retained so AddPath can bind a new input path's socket
}

// BondedSender transmits one media flow across several receiver addresses. By
// default it is full SMPTE 2022-7 duplication: every payload is sent on every path
// with identical sequence and timestamp, so the receiver merges them seamlessly.
// Per-path weights (BondedPeer.Weight / Config.Weight) switch a path to weighted
// load-share instead, splitting the stream across paths in proportion to their
// weights; weights can change at runtime with SetWeight.
type BondedSender struct {
	sess    *session.Session
	remote  netip.AddrPort // the first path, for RemoteAddr
	ctxStop func()         // ends the context watcher (set by DialBonded)

	// maxWrite is the largest payload a single Write accepts — MaxMediaPayload
	// unless FragmentSize is configured (Advanced), in which case a larger Write
	// is split into fragments duplicated across the paths. Zero means the
	// MaxMediaPayload default.
	maxWrite int

	// paths is the number of bonded paths (== len(addrs) at construction), used to
	// bounds-check SetWeight's path index.
	paths int

	// profile resolves a runtime AddPath address (Simple needs the even/odd pair;
	// Main/Advanced use the single port).
	profile Profile
}

// newBondingGroup builds the per-flow bonding group from cfg's liveness and RTT
// bounds. The duplicate-path grace is the recovery buffer (libRIST's hard_dead
// recovery_buffer_ticks), so a 2022-7 path keeps its redundancy for that long
// after it goes dead. The RTT clamp bounds are the effective ones (the buffer-size
// rtt_min floor applied), matching the flow core so per-path RTT stats and NACK
// tie-breaking use the same floor as the core's retry cadence.
func newBondingGroup(cfg Config) *bonding.Group {
	rttMin, rttMax := effectiveRTTBounds(cfg)
	return bonding.NewGroup(
		clock.FromDuration(cfg.SessionTimeout),
		clock.FromDuration(cfg.recoveryBufferTime()),
		rttMin,
		rttMax,
	)
}

// BondedPeer is one path of a per-peer bonded configuration: an address plus its
// NACK recovery priority. Use it with [NewBondedReceiverPeers] /
// [NewBondedSenderPeers] when paths need distinct priorities; the plain
// [NewBondedReceiver] / [NewBondedSender] ([]string forms) give every path the
// default priority 0.
type BondedPeer struct {
	// Addr is the path's "host:port" (even media port for the Simple profile, a
	// single port for the Main/Advanced profiles).
	Addr string

	// Priority is the NACK recovery priority (libRIST recovery-priority): a
	// bonded receiver routes each retransmission request to the live path with
	// the HIGHEST priority, ties broken by the lowest RTT. Higher is preferred;
	// the default 0 is the lowest. Must be >= 0. It is meaningful on a receiver
	// (which selects a NACK path); a sender duplicates to every path regardless.
	Priority int

	// Weight is the load-balancing weight (libRIST weight): 0 (the default) keeps
	// the path in SMPTE 2022-7 full duplication, while a positive value makes it
	// carry that share of a weighted load-share rotation. It is meaningful on a
	// sender, which routes each datagram to one weighted path in proportion to the
	// weights; a receiver ignores it (it merges whatever arrives). Mixing duplicate
	// (0) and weighted (>0) paths is allowed: the duplicate paths get every packet
	// and the weighted paths split the rest. Must be >= 0.
	Weight int
}

// splitBondedPeers validates peers and splits them into parallel address,
// priority, and weight slices.
func splitBondedPeers(peers []BondedPeer) (addrs []string, priorities []uint32, weights []int, err error) {
	addrs = make([]string, len(peers))
	priorities = make([]uint32, len(peers))
	weights = make([]int, len(peers))
	for i, p := range peers {
		if p.Priority < 0 {
			return nil, nil, nil, fmt.Errorf("%w: BondedPeer.Priority must be >= 0", ErrInvalidConfig)
		}
		if p.Weight < 0 {
			return nil, nil, nil, fmt.Errorf("%w: BondedPeer.Weight must be >= 0 (0 = duplicate)", ErrInvalidConfig)
		}
		addrs[i] = p.Addr
		priorities[i] = uint32(p.Priority)
		weights[i] = p.Weight
	}
	return addrs, priorities, weights, nil
}

// bondingGroupWith builds the bonding group and pre-registers each path with its
// recovery priority and load-balancing weight; the session then skips
// re-registering those paths (Group.HasPath), preserving both. Nil priorities and
// weights leave the group empty for the session to populate with the duplicate /
// priority-0 defaults. The slices may differ in length (a path absent from one
// takes that field's default).
func bondingGroupWith(cfg Config, priorities []uint32, weights []int) *bonding.Group {
	g := newBondingGroup(cfg)
	n := len(priorities)
	if len(weights) > n {
		n = len(weights)
	}
	for i := 0; i < n; i++ {
		var pr uint32
		if i < len(priorities) {
			pr = priorities[i]
		}
		w := bonding.WeightDuplicate
		if i < len(weights) {
			w = weights[i]
		}
		g.AddPath(uint8(i), w, pr)
	}
	return g
}

// NewBondedReceiver binds a bonded receiver across addrs, merging all paths into
// one deduplicated flow. The socket topology follows cfg.Profile: the Simple
// profile uses an even/odd media/RTCP pair per path (so each addr's port must be
// even); the Main and Advanced profiles tunnel each path over a single port,
// with PSK encryption when a Secret is set. At least one address is required; two
// or more gives 2022-7 redundancy. Bonded DTLS and EAP-SRP are not supported.
// Every path is given recovery priority 0; use [NewBondedReceiverPeers] for
// per-path priorities.
//
// See [ListenBonded] for the context-aware constructor with functional options.
func NewBondedReceiver(addrs []string, cfg Config) (*BondedReceiver, error) {
	return newBondedReceiver(addrs, nil, cfg)
}

// NewBondedReceiverPeers is [NewBondedReceiver] with a per-path NACK recovery
// priority (libRIST recovery-priority): retransmission requests prefer the live
// path with the highest priority.
func NewBondedReceiverPeers(peers []BondedPeer, cfg Config) (*BondedReceiver, error) {
	addrs, priorities, _, err := splitBondedPeers(peers)
	if err != nil {
		return nil, err
	}
	return newBondedReceiver(addrs, priorities, cfg)
}

func newBondedReceiver(addrs []string, priorities []uint32, cfg Config) (*BondedReceiver, error) {
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if err := bondedSupported(cfg); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a bonded receiver needs at least one address", ErrInvalidConfig)
	}
	conns := make([]*socket.Conn, 0, len(addrs))
	for _, a := range addrs {
		c, err := listenBondPath(a, cfg)
		if err != nil {
			closeConns(conns)
			return nil, err
		}
		conns = append(conns, c)
	}
	fc := toFlowConfig(cfg)
	sc := toSessionConfig(cfg, fc, randomEvenSSRC())
	if err := applyBondProfile(&sc, cfg); err != nil {
		closeConns(conns)
		return nil, err
	}
	// Separate-port FEC (Simple/Main bonding) binds dedicated column/row sockets next
	// to each path's media port; the Advanced profile carries FEC in-band and needs
	// none. The session owns and closes them.
	if cfg.FEC != nil && cfg.FEC.carriage(cfg.Profile == ProfileAdvanced) == FECCarriageSeparatePorts {
		if err := bindBondFECSockets(&sc, addrs, cfg); err != nil {
			closeConns(conns)
			return nil, err
		}
	}
	// Bonded EAP-SRP (combined PSK+SRP; validated to require a Secret): one fresh
	// Authenticator per path, each with its own salt/verifier, gating that path's media.
	var eapServers []*eap.Authenticator
	if cfg.Username != "" {
		eapServers = make([]*eap.Authenticator, len(conns))
		for i := range conns {
			srv, eerr := buildEAPServer(cfg)
			if eerr != nil {
				closeConns(conns)
				return nil, eerr
			}
			eapServers[i] = srv
		}
	}
	sess := session.NewBondedReceiver(conns, bondingGroupWith(cfg, priorities, nil), sc, eapServers)
	return &BondedReceiver{sess: sess, cfg: cfg}, nil
}

// bindBondFECSockets binds a column (media port + 2) and, for 2-D FEC, row (media
// port + 4) FEC socket for every bonded receiver path, storing them on the session
// config. Column-only FEC binds the column socket alone (it emits no row packets). On
// any error it closes whatever it has already bound and leaves sc untouched.
func bindBondFECSockets(sc *session.Config, addrs []string, cfg Config) error {
	var bound []*net.UDPConn
	for i, a := range addrs {
		host, port, err := bondPathHostPort(a, cfg.Profile)
		if err != nil {
			closeUDPConns(bound)
			return err
		}
		col, err := socket.BindUDP(host, port+2)
		if err != nil {
			closeUDPConns(bound)
			return fmt.Errorf("rist: bind column FEC port %d for bonded path %d: %w", port+2, i, err)
		}
		bound = append(bound, col)
		if cfg.FEC.ColumnOnly {
			continue // no row FEC on the +4 port for this path
		}
		row, err := socket.BindUDP(host, port+4)
		if err != nil {
			closeUDPConns(bound)
			return fmt.Errorf("rist: bind row FEC port %d for bonded path %d: %w", port+4, i, err)
		}
		bound = append(bound, row)
	}
	sc.FECSockets = bound
	return nil
}

// bondPathHostPort resolves a bonded path address to its host and media port: the
// even media port for the Simple profile, the single tunnel port otherwise.
func bondPathHostPort(addr string, profile Profile) (string, int, error) {
	if profile == ProfileSimple {
		return resolveMediaPort(addr)
	}
	return resolveSinglePort(addr)
}

// closeUDPConns closes every non-nil UDP socket in cs.
func closeUDPConns(cs []*net.UDPConn) {
	for _, c := range cs {
		if c != nil {
			c.Close()
		}
	}
}

// NewBondedSender dials a bonded sender to addrs, duplicating every payload to
// all of them. The destination form follows cfg.Profile: the Simple profile
// targets each receiver's even media port (RTCP on port+1); the Main and
// Advanced profiles tunnel each path over a single port, with PSK encryption when
// a Secret is set. At least one address is required; two or more gives 2022-7
// redundancy. Bonded DTLS and EAP-SRP are not supported.
//
// Every path is given recovery priority 0; use [NewBondedSenderPeers] for
// per-path priorities.
//
// See [DialBonded] for the context-aware constructor with functional options.
func NewBondedSender(addrs []string, cfg Config) (*BondedSender, error) {
	return newBondedSender(addrs, nil, nil, cfg)
}

// NewBondedSenderPeers is [NewBondedSender] with per-path configuration. The
// sender-meaningful field is BondedPeer.Weight: 0 keeps a path on full SMPTE
// 2022-7 duplication, a positive value gives it that share of a weighted
// load-share rotation (mixing the two is allowed). Priority is carried for
// symmetry but is meaningful on a receiver, not a sender.
func NewBondedSenderPeers(peers []BondedPeer, cfg Config) (*BondedSender, error) {
	addrs, priorities, weights, err := splitBondedPeers(peers)
	if err != nil {
		return nil, err
	}
	return newBondedSender(addrs, priorities, weights, cfg)
}

func newBondedSender(addrs []string, priorities []uint32, weights []int, cfg Config) (*BondedSender, error) {
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if err := bondedSupported(cfg); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: a bonded sender needs at least one address", ErrInvalidConfig)
	}
	// The []string form (no per-peer weights) honors a uniform Config.Weight
	// (WithWeight / ?weight=): a positive value load-shares evenly across all
	// paths, zero keeps full 2022-7 duplication. Per-peer BondedPeer.Weight, when
	// given, takes precedence.
	if weights == nil && cfg.Weight > 0 {
		weights = make([]int, len(addrs))
		for i := range weights {
			weights[i] = cfg.Weight
		}
	}
	remotes := make([][2]netip.AddrPort, 0, len(addrs))
	for _, a := range addrs {
		r, err := bondSenderRemote(a, cfg.Profile)
		if err != nil {
			return nil, err
		}
		remotes = append(remotes, r)
	}
	// Main/Advanced tunnel each path over a single port; Simple uses an even/odd
	// pair, so the local send socket must match. When any path targets a
	// multicast group, the socket is bound in that group's address family (see
	// openSenderConn).
	var mcDst netip.Addr
	for _, r := range remotes {
		if d := r[0].Addr(); d.IsMulticast() {
			mcDst = d
			break
		}
	}
	conn, err := openSenderConn(cfg.Profile != ProfileSimple, mcDst, cfg.LocalPort)
	if err != nil {
		return nil, err
	}
	// Apply outbound multicast egress (TTL/interface/loopback) when a path
	// targets a multicast group. The bonded sender duplicates over one socket, so
	// the options apply to that socket. A no-op when every path is unicast.
	if mcDst.IsMulticast() {
		if err := setSenderMulticast(conn, cfg, mcDst); err != nil {
			conn.Close()
			return nil, err
		}
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq(cfg.SplitMode != SplitOff)
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.FragmentSize = cfg.FragmentSize // Advanced-only (validate gates it); 0 otherwise
	if err := applyBondProfile(&sc, cfg); err != nil {
		conn.Close()
		return nil, err
	}
	// Bonded EAP-SRP (combined PSK+SRP): one Authenticatee per path, each running its
	// own handshake to the receiver before that path's media flows.
	var eapClients []*eap.Authenticatee
	if cfg.Username != "" {
		eapClients = make([]*eap.Authenticatee, len(remotes))
		for i := range remotes {
			cl, eerr := buildEAPClient(cfg)
			if eerr != nil {
				conn.Close()
				return nil, eerr
			}
			eapClients[i] = cl
		}
	}
	sess := session.NewBondedSender(conn, remotes, bondingGroupWith(cfg, priorities, weights), sc, eapClients)
	maxWrite := 0
	if cfg.FragmentSize > 0 {
		maxWrite = cfg.FragmentSize * maxFragmentsPerWrite
	}
	return &BondedSender{sess: sess, remote: remotes[0][0], maxWrite: maxWrite, paths: len(remotes), profile: cfg.Profile}, nil
}

// bondedSupported fails closed on the one bonded feature not implemented: DTLS over
// multipath. All three profiles (Simple, Main, Advanced) are supported, including
// Main/Advanced PSK encryption and EAP-SRP authentication. Bonded EAP-SRP runs in two
// modes, both per-path (each path authenticates with its own handshake): the combined
// PSK+SRP mode (a Secret is set) keeps the media keyed by the shared PSK so the gate
// rides on one shared codec; the pure-SRP use_key_as_passphrase mode (no Secret) keeps the
// media cleartext (SRP authenticates) and keys each path's feedback channel with that
// path's own SRP session key K on a per-path codec.
func bondedSupported(cfg Config) error {
	if cfg.DTLS != nil {
		return fmt.Errorf("%w: bonded DTLS is not supported", ErrInvalidConfig)
	}
	// Pure-SRP bonding gives each path its own per-path codec keyed (feedback only) to that
	// path's session key K; FEC's per-path fan would then need per-path handling that is not
	// wired. PSK+SRP bonding (a Secret is set) keeps the shared codec, so it combines with FEC.
	if cfg.Username != "" && cfg.Secret == "" && cfg.FEC != nil {
		return fmt.Errorf("%w: bonded pure-SRP (no Secret) with FEC is not supported; set a Secret to use the PSK+SRP mode with FEC", ErrInvalidConfig)
	}
	return nil
}

// listenBondPath binds one receiver path socket for the configured profile: the
// Simple profile uses an even/odd media+RTCP pair (so the port must be even);
// the Main and Advanced profiles tunnel each path over a single port. When the
// path's bind host is a multicast group it also joins the group (per cfg), so a
// bonded receiver can pull each redundant path from its own multicast group.
func listenBondPath(addr string, cfg Config) (*socket.Conn, error) {
	var (
		conn *socket.Conn
		host string
		err  error
	)
	if cfg.Profile == ProfileSimple {
		var port int
		host, port, err = resolveMediaPort(addr)
		if err != nil {
			return nil, err
		}
		conn, err = socket.Listen(host, port)
	} else {
		var port int
		host, port, err = resolveSinglePort(addr)
		if err != nil {
			return nil, err
		}
		conn, err = socket.ListenSingle(host, port)
	}
	if err != nil {
		return nil, err
	}
	if err := joinReceiverMulticast(conn, cfg, host); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// bondSenderRemote resolves one sender path's destination for the profile: the
// Simple profile returns the even media and odd+1 RTCP pair; the Main/Advanced
// profiles tunnel over a single port, so both entries are that one address.
func bondSenderRemote(addr string, profile Profile) ([2]netip.AddrPort, error) {
	var out [2]netip.AddrPort
	if profile == ProfileSimple {
		host, port, err := resolveMediaPort(addr)
		if err != nil {
			return out, err
		}
		media, err := resolveAddrPort(host, port)
		if err != nil {
			return out, fmt.Errorf("%w: resolve media address %q: %w", ErrInvalidConfig, addr, err)
		}
		rtcp, err := resolveAddrPort(host, port+1)
		if err != nil {
			return out, fmt.Errorf("%w: resolve rtcp address for %q: %w", ErrInvalidConfig, addr, err)
		}
		return [2]netip.AddrPort{media, rtcp}, nil
	}
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return out, err
	}
	a, err := resolveAddrPort(host, port)
	if err != nil {
		return out, fmt.Errorf("%w: resolve address %q: %w", ErrInvalidConfig, addr, err)
	}
	return [2]netip.AddrPort{a, a}, nil
}

// applyBondProfile fills the session config's profile parameters (PSK keys,
// virtual ports) for a Main- or Advanced-profile bonded session, mirroring the
// non-bonded constructors. A no-op for the Simple profile.
func applyBondProfile(sc *session.Config, cfg Config) error {
	switch cfg.Profile {
	case ProfileMain:
		mp, err := buildMainParams(cfg)
		if err != nil {
			return err
		}
		sc.Main = mp
	case ProfileAdvanced:
		ap, err := buildAdvParams(cfg)
		if err != nil {
			return err
		}
		sc.Adv = ap
	}
	return nil
}

// closeConns closes a partially-built set of receiver sockets on error.
func closeConns(conns []*socket.Conn) {
	for _, c := range conns {
		c.Close()
	}
}

// Read returns the next in-order, merged media payload. It blocks until data is
// available, the read deadline passes (ErrTimeout), or the stream ends. A clean
// Close ends the stream with io.EOF (so io.Copy returns nil); an abnormal
// teardown returns ErrSessionTimeout, ErrBufferOverflow, or ErrAuth.
func (r *BondedReceiver) Read(p []byte) (int, error) { return readEOF(r.sess.Read(p)) }

// SetReadDeadline sets the deadline for future Read calls; a zero time clears it.
func (r *BondedReceiver) SetReadDeadline(t time.Time) error {
	r.sess.SetReadDeadline(t)
	return nil
}

// Stats returns a snapshot of the merged flow's counters.
func (r *BondedReceiver) Stats() Stats {
	st := toStats(r.sess.Stats())
	st.FECRecovered = r.sess.FECRecovered()
	return withPeers(st, r.sess.PeerStats())
}

// SetNackType switches the NACK feedback format at runtime (libRIST
// rist_receiver_nack_type_set): NACKRange (the default) or NACKBitmask. It takes
// effect from the next NACK the merged receiver emits. It returns ErrInvalidConfig
// for an unknown nack type, or the close reason if the session has shut down.
func (r *BondedReceiver) SetNackType(nack NACKType) error {
	if nack != NACKRange && nack != NACKBitmask {
		return fmt.Errorf("%w: NACKType must be NACKRange (0) or NACKBitmask (1)", ErrInvalidConfig)
	}
	return r.sess.SetNackType(nack == NACKBitmask)
}

// SetRTTMultiplier sets the recovery-buffer RTT multiplier at runtime (libRIST
// rist_recovery_rtt_multiplier_set). multiplier must be in [1, MaxRTTMultiplier]. It
// returns ErrInvalidConfig for an out-of-range value, or the close reason if the
// session has shut down. See [Receiver.SetRTTMultiplier].
func (r *BondedReceiver) SetRTTMultiplier(multiplier int) error {
	if multiplier < 1 || multiplier > MaxRTTMultiplier {
		return fmt.Errorf("%w: RTTMultiplier %d out of range [1,%d]", ErrInvalidConfig, multiplier, MaxRTTMultiplier)
	}
	return r.sess.SetRTTMultiplier(multiplier)
}

// AddPath adds a bonded input path at runtime (libRIST rist_peer_create): the receiver
// binds addr ("host:port") as a new path at index and merges its recovered media into
// the same flow. index must be the next free slot (the construction paths are 0..N, and
// the slice is positional); weight is the path's load-share weight. It is safe to call
// from any goroutine. It returns an error for an out-of-range index/weight or a bad
// address, or the close reason if the receiver is closed.
func (r *BondedReceiver) AddPath(index int, addr string, weight int) error {
	if index < 0 || index > 255 {
		return fmt.Errorf("%w: path index %d out of range [0,255]", ErrInvalidConfig, index)
	}
	if weight < 0 {
		return fmt.Errorf("%w: weight must be >= 0 (0 = duplicate)", ErrInvalidConfig)
	}
	conn, err := listenBondPath(addr, r.cfg)
	if err != nil {
		return err
	}
	return r.sess.AddPathConn(uint8(index), conn, weight, 0)
}

// RemovePath removes a bonded input path at runtime (libRIST rist_peer_destroy): the
// receiver stops reading index's socket and drops it from the merge, NACK selection, and
// per-peer stats. An unknown index is a no-op. It is safe to call from any goroutine. It
// returns an error for an out-of-range index, or the close reason if the receiver is
// closed.
func (r *BondedReceiver) RemovePath(index int) error {
	if index < 0 || index > 255 {
		return fmt.Errorf("%w: path index %d out of range [0,255]", ErrInvalidConfig, index)
	}
	return r.sess.RemovePath(uint8(index))
}

// Close stops the receiver and releases every path's sockets and goroutines.
func (r *BondedReceiver) Close() error {
	if r.ctxStop != nil {
		r.ctxStop()
	}
	return r.sess.Close()
}

// Write submits one media payload, duplicated to every path. It returns len(p).
// The payload must be at most MaxMediaPayload bytes, unless FragmentSize is
// configured (Advanced profile), in which case a larger payload — up to
// FragmentSize × the internal fragment cap — is split into fragments, each
// duplicated across the paths and reassembled by the bonded receiver.
func (s *BondedSender) Write(p []byte) (int, error) {
	max := s.maxWrite
	if max == 0 {
		max = MaxMediaPayload
	}
	if len(p) > max {
		return 0, fmt.Errorf("rist: payload %d bytes exceeds the maximum %d; chunk media before Write", len(p), max)
	}
	if err := s.sess.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SetWriteDeadline sets the deadline for future Write calls; a zero time clears
// it.
func (s *BondedSender) SetWriteDeadline(t time.Time) error {
	s.sess.SetWriteDeadline(t)
	return nil
}

// Stats returns a snapshot of the sender's counters.
func (s *BondedSender) Stats() Stats {
	return withPeers(toStats(s.sess.Stats()), s.sess.PeerStats())
}

// RemoteAddr returns the first path's media address.
func (s *BondedSender) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(s.remote) }

// SetWeight changes the load-balancing weight of one path at runtime (libRIST
// rist_peer_weight_set). path is the zero-based index into the addresses or peers
// given at construction; weight is 0 to return the path to SMPTE 2022-7 full
// duplication, or a positive value for its share of the weighted load-share
// rotation. The change takes effect on the next datagram. It is safe to call from
// any goroutine. It returns an error for an out-of-range path or a negative
// weight, or the close reason if the sender is closed.
func (s *BondedSender) SetWeight(path int, weight int) error {
	if path < 0 || path >= s.paths {
		return fmt.Errorf("%w: path %d out of range [0,%d)", ErrInvalidConfig, path, s.paths)
	}
	if weight < 0 {
		return fmt.Errorf("%w: weight must be >= 0 (0 = duplicate)", ErrInvalidConfig)
	}
	return s.sess.SetPathWeight(uint8(path), weight)
}

// AddPath adds a bonded destination path at runtime (libRIST rist_peer_create): the
// sender begins transmitting to addr ("host:port") at index, with load-share weight
// (0 = full SMPTE 2022-7 duplication). The caller owns the index space — the
// construction paths are 0..N, so a fresh path uses an unused index >= N; a duplicate
// index is ignored. The path joins the fan-out on the next media send. It is safe to
// call from any goroutine. It returns an error for an out-of-range index/weight or a
// bad address, or the close reason if the sender is closed.
func (s *BondedSender) AddPath(index int, addr string, weight int) error {
	if index < 0 || index > 255 {
		return fmt.Errorf("%w: path index %d out of range [0,255]", ErrInvalidConfig, index)
	}
	if weight < 0 {
		return fmt.Errorf("%w: weight must be >= 0 (0 = duplicate)", ErrInvalidConfig)
	}
	remote, err := bondSenderRemote(addr, s.profile)
	if err != nil {
		return err
	}
	return s.sess.AddPath(uint8(index), remote, weight, 0)
}

// RemovePath removes a bonded path at runtime (libRIST rist_peer_destroy): the sender
// stops transmitting on index and drops it from NACK selection and per-peer stats. The
// shared source socket stays open for the remaining paths. An unknown index is a no-op.
// It is safe to call from any goroutine. It returns an error for an out-of-range index,
// or the close reason if the sender is closed.
func (s *BondedSender) RemovePath(index int) error {
	if index < 0 || index > 255 {
		return fmt.Errorf("%w: path index %d out of range [0,255]", ErrInvalidConfig, index)
	}
	return s.sess.RemovePath(uint8(index))
}

// SetNullPacketDeletion enables or disables null-packet deletion on the send path at
// runtime (libRIST rist_sender_npd_enable/_disable). The Main bonded sender encodes
// media through one codec, so the toggle applies to every path's 2022-7 copy. It
// returns ErrNPDUnsupported on a non-Main bonded sender and the close reason once
// closed. See [Sender.SetNullPacketDeletion].
func (s *BondedSender) SetNullPacketDeletion(on bool) error {
	return s.sess.SetNullPacketDeletion(on)
}

// Close stops the sender and releases its socket and goroutines.
func (s *BondedSender) Close() error {
	if s.ctxStop != nil {
		s.ctxStop()
	}
	return s.sess.Close()
}

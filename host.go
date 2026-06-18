package ristgo

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/zsiec/ristgo/internal/adapt"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/dtls"
	"github.com/zsiec/ristgo/internal/eap"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
	"github.com/zsiec/ristgo/internal/split"
	"github.com/zsiec/ristgo/internal/srp"
)

// buildDTLSConfig maps the public DTLSConfig to the internal dtls.Config for one
// role (the RIST sender is the DTLS client, the receiver the DTLS server). PSK
// mode reuses the shared key; cert mode parses a supplied certificate or, for a
// server with none, generates a self-signed one. Peer verification (fingerprint
// pin or InsecureSkipVerify) applies to the verifying side.
func buildDTLSConfig(dc *DTLSConfig, isClient bool) (*dtls.Config, error) {
	out := &dtls.Config{
		PSK:                 dc.PSK,
		PSKIdentity:         []byte(dc.PSKIdentity),
		InsecureSkipVerify:  dc.InsecureSkipVerify,
		PeerCertFingerprint: dc.PeerFingerprint,
		DisabledSuites:      dc.DisabledSuites,
		AllowNullCipher:     dc.AllowNullCipher,
	}
	if len(dc.CertPEM) > 0 || len(dc.KeyPEM) > 0 {
		cert, err := dtls.CertificateFromPEM(dc.CertPEM, dc.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		out.Certificate = cert
	} else if !isClient && dc.PSK == nil {
		// A cert-mode server with no supplied certificate self-signs.
		cert, err := dtls.GenerateSelfSigned("ristgo-dtls")
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		out.Certificate = cert
	}
	return out, nil
}

// wrapInvalid wraps a validation error so callers can match it with
// errors.Is(err, ErrInvalidConfig), per the WP4 binding. The redundant
// "rist: " prefix the inner message carries is trimmed.
func wrapInvalid(err error) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, strings.TrimPrefix(err.Error(), "rist: "))
}

// resolveMediaPort splits a "host:port" address and requires an even media
// port (TR-06-1: RTP on the even port, RTCP on the adjacent odd port).
func resolveMediaPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65534 {
		return "", 0, fmt.Errorf("%w: port %q out of range", ErrInvalidConfig, p)
	}
	if port%2 != 0 {
		return "", 0, fmt.Errorf("%w: media port %d must be even (RTCP uses port+1)", ErrInvalidConfig, port)
	}
	return h, port, nil
}

// multicastGroup parses host as an IP and reports the group Addr together with
// whether it is a multicast address. A name that is not an IP literal (e.g.
// "localhost") or an empty/unicast host yields (zero, false): multicast bind/dst
// addresses must be IP literals, as a group has no DNS name.
func multicastGroup(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	return a, a.IsMulticast()
}

// senderMulticastOptions builds the socket egress options for a sender whose
// destination Addr is dst. It returns (zero, false) when dst is not a multicast
// group (the unicast path, unchanged). The interface is resolved from
// cfg.Interface (validate already proved it resolves).
func senderMulticastOptions(cfg Config, dst netip.Addr) (socket.MulticastOptions, bool, error) {
	g := dst.Unmap()
	if !g.IsMulticast() {
		return socket.MulticastOptions{}, false, nil
	}
	ifi, err := multicastInterface(cfg.Interface)
	if err != nil {
		return socket.MulticastOptions{}, false, err
	}
	return socket.MulticastOptions{
		Group:    g,
		Iface:    ifi,
		TTL:      cfg.MulticastTTL,
		Loopback: cfg.MulticastLoopback,
	}, true, nil
}

// receiverMulticastOptions builds the socket join options for a receiver bound
// to host. It returns (zero, false) when host is not a multicast group (the
// unicast path, unchanged). It enforces that MulticastSource (SSM) is only set
// on a multicast bind: a source filter is meaningless on a unicast address.
func receiverMulticastOptions(cfg Config, host string) (socket.MulticastOptions, bool, error) {
	g, isMC := multicastGroup(host)
	if !isMC {
		if cfg.MulticastSource != "" {
			return socket.MulticastOptions{}, false, fmt.Errorf("%w: MulticastSource is set but the bind address %q is not a multicast group", ErrInvalidConfig, host)
		}
		return socket.MulticastOptions{}, false, nil
	}
	ifi, err := multicastInterface(cfg.Interface)
	if err != nil {
		return socket.MulticastOptions{}, false, err
	}
	var src netip.Addr
	if cfg.MulticastSource != "" {
		// validate() already proved it parses; this cannot fail.
		src, _ = netip.ParseAddr(cfg.MulticastSource)
	}
	return socket.MulticastOptions{Group: g, Source: src, Iface: ifi}, true, nil
}

// openSenderConn binds a sender's ephemeral local socket. single chooses the
// Main/Advanced single-socket form vs the Simple even/odd pair. When dst is a
// multicast group the socket is bound in the group's address family ("udp4" or
// "udp6") rather than the dual-stack default, because a v6 dual-stack socket
// cannot have IPv4 multicast options (interface/TTL/loopback) set on it. A
// unicast destination keeps the original dual-stack ("udp") bind unchanged.
// localPort is the libRIST local-port fixed caller source port (0 = ephemeral).
func openSenderConn(single bool, dst netip.Addr, localPort int) (*socket.Conn, error) {
	network := ""
	if d := dst.Unmap(); d.IsMulticast() {
		if d.Is4() {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	if single {
		return socket.ListenEphemeralSingleFamily(network, "", localPort)
	}
	return socket.ListenEphemeralFamily(network, "", localPort)
}

// joinReceiverMulticast joins the multicast group on a freshly-bound receiver
// Conn when its bind host is a group address, per cfg (ASM, or SSM when
// MulticastSource is set). It is a no-op for a unicast bind, leaving the plain
// unicast receiver completely unchanged.
func joinReceiverMulticast(conn *socket.Conn, cfg Config, host string) error {
	opts, isMC, err := receiverMulticastOptions(cfg, host)
	if err != nil {
		return err
	}
	if !isMC {
		return nil
	}
	if err := conn.JoinMulticast(opts); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return nil
}

// setSenderMulticast applies the outbound multicast egress options (TTL,
// interface, loopback) on a sender Conn when its destination Addr is a multicast
// group, per cfg. It is a no-op for a unicast destination, leaving the plain
// unicast sender completely unchanged.
func setSenderMulticast(conn *socket.Conn, cfg Config, dst netip.Addr) error {
	opts, isMC, err := senderMulticastOptions(cfg, dst)
	if err != nil {
		return err
	}
	if !isMC {
		return nil
	}
	if err := conn.SetMulticast(opts); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return nil
}

// multicastInterface resolves a configured interface name to a *net.Interface,
// or nil for the empty name (OS default). validate() already proved a non-empty
// name resolves; this re-resolves it where the socket options are built.
func multicastInterface(name string) (*net.Interface, error) {
	if name == "" {
		return nil, nil
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("%w: interface %q: %w", ErrInvalidConfig, name, err)
	}
	return ifi, nil
}

// resolveAddrPort resolves host:port to a netip.AddrPort, which the send path
// uses end-to-end (the alloc-free address type). host may be a name or an IP
// literal; it is resolved via net.ResolveUDPAddr, then narrowed to its
// netip.AddrPort form. An unresolvable or zero address is an error.
func resolveAddrPort(host string, port int) (netip.AddrPort, error) {
	ua, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := ua.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("address %q resolved to an invalid AddrPort", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return ap, nil
}

// resolveSinglePort splits a "host:port" address for the Main profile, which
// tunnels everything over one port (not the Simple even/odd pair), so any port
// in 1-65535 is valid.
func resolveSinglePort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("%w: port %q out of range", ErrInvalidConfig, p)
	}
	return h, port, nil
}

// buildMainParams derives the session Main-profile parameters from cfg,
// constructing the PSK keys when a Secret is configured (cfg must already be
// validated, so AESKeyBits is 128 or 256 — defaulted to 256 when Secret is
// set). With no Secret the Main flow runs in cleartext.
// randRead reads cryptographic randomness; it is a package var so a test can
// force the otherwise-effectively-impossible read error and assert the per-flow
// auth/key build fails closed (drops the flow) rather than installing a nil
// authenticator. It is crand.Read in production.
var randRead = crand.Read

func buildMainParams(cfg Config) (*session.MainParams, error) {
	mp := &session.MainParams{
		VirtSrcPort: cfg.VirtSrcPort,
		VirtDstPort: cfg.VirtDstPort,
		NPD:         cfg.NullPacketDeletion,
	}
	if cfg.Secret == "" {
		// No pre-shared secret. With SRP credentials this is the
		// use_key_as_passphrase mode: the session derives the media keys from the
		// SRP session key K once the handshake succeeds (see the session's
		// installEAPKeying), so the codec starts cleartext and is re-keyed in flight.
		// Without SRP credentials the Main flow is genuinely cleartext.
		if cfg.Username != "" {
			mp.UseKeyAsPassphrase = true
			mp.EAPKeySize256 = cfg.AESKeyBits == crypto.KeySize256
			mp.EAPKeyRotation = cfg.KeyRotation
		}
		return mp, nil
	}
	sendKey, err := crypto.NewKey([]byte(cfg.Secret), cfg.AESKeyBits, cfg.KeyRotation, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	recvKey, err := crypto.NewDecryptor([]byte(cfg.Secret), cfg.AESKeyBits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	mp.SendKey = sendKey
	mp.RecvKey = recvKey
	mp.KeySize256 = cfg.AESKeyBits == crypto.KeySize256
	return mp, nil
}

// buildAdvParams derives the session Advanced-profile parameters from cfg,
// constructing the PSK keys when a Secret is configured (cfg is already
// validated, so AESKeyBits is 128 or 256). With no Secret the Advanced flow runs
// in cleartext. Only AES-CTR (mode 1) is used — the sole encryption mode libRIST
// implements for the Advanced profile.
func buildAdvParams(cfg Config) (*session.AdvParams, error) {
	ap := &session.AdvParams{
		Compression: cfg.Compression,
		VirtSrcPort: cfg.VirtSrcPort,
		VirtDstPort: cfg.VirtDstPort,
	}
	if cfg.Secret == "" {
		return ap, nil
	}
	sendKey, err := crypto.NewKey([]byte(cfg.Secret), cfg.AESKeyBits, cfg.KeyRotation, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	recvKey, err := crypto.NewDecryptor([]byte(cfg.Secret), cfg.AESKeyBits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	ap.SendKey = sendKey
	ap.RecvKey = recvKey
	// Separate key/decryptor instances for the GRE control substrate (the RTCP
	// handshake): GRE framing and adv media advance independent IV/seq state, so
	// they cannot share a stateful crypto.Key, though both derive from the same
	// passphrase.
	greSendKey, err := crypto.NewKey([]byte(cfg.Secret), cfg.AESKeyBits, cfg.KeyRotation, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	greRecvKey, err := crypto.NewDecryptor([]byte(cfg.Secret), cfg.AESKeyBits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	ap.GRESendKey = greSendKey
	ap.GRERecvKey = greRecvKey
	ap.KeySize256 = cfg.AESKeyBits == crypto.KeySize256
	return ap, nil
}

// buildEAPClient builds the EAP-SRP authenticatee for a Main sender when
// credentials are configured (the sender authenticates to the receiver); it
// returns (nil, nil) when no Username is set.
func buildEAPClient(cfg Config) (*eap.Authenticatee, error) {
	if cfg.Username == "" {
		return nil, nil
	}
	a, err := eap.NewAuthenticatee(cfg.Username, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return a, nil
}

// buildEAPServer builds the EAP-SRP authenticator for a Main receiver when
// credentials are configured (the receiver authenticates the sender). It
// provisions a fresh random salt and the verifier derived from the configured
// username/password, served by a single-user lookup. Returns (nil, nil) when no
// Username is set.
func buildEAPServer(cfg Config) (*eap.Authenticator, error) {
	// Collect the single user plus any multi-user credentials (libRIST multi-user SRP).
	creds := make(map[string]string)
	if cfg.Username != "" {
		creds[cfg.Username] = cfg.Password
	}
	for u, p := range cfg.SRPUsers {
		creds[u] = p
	}
	if len(creds) == 0 {
		return nil, nil
	}
	// Derive a fresh per-session salt + verifier per user into a lookup table keyed by
	// username (libRIST's user_verifier_lookup_t resolves by the username a connecting
	// peer presents in its IDENTITY RESPONSE).
	type vs struct{ verifier, salt []byte }
	table := make(map[string]vs, len(creds))
	for user, pass := range creds {
		if user == "" || pass == "" {
			return nil, fmt.Errorf("%w: SRP username and password must be non-empty", ErrInvalidConfig)
		}
		salt := make([]byte, 32)
		if _, err := randRead(salt); err != nil {
			return nil, fmt.Errorf("%w: SRP salt: %w", ErrInvalidConfig, err)
		}
		table[user] = vs{srp.MakeVerifier(srp.DefaultGroup(), user, pass, salt), salt}
	}
	lookup := func(user string) ([]byte, []byte, bool) {
		if e, ok := table[user]; ok {
			return e.verifier, e.salt, true
		}
		return nil, nil, false
	}
	newAuth := eap.NewAuthenticator
	if cfg.SRPCompat {
		// Legacy pre-0.2.16 SRP: the authenticator advertises EAPOL version 2 and
		// uses the unpadded k/u hashing (libRIST srp-compat=1).
		newAuth = eap.NewAuthenticatorLegacy
	}
	a, err := newAuth(lookup)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	// Seed the first EAP identifier from crypto/rand so it is unpredictable on
	// the wire (libRIST seeds last_identifier from a random byte). A read error
	// is effectively impossible; leave the identifier at 0 if it ever happens.
	var seed [1]byte
	if _, err := randRead(seed[:]); err == nil {
		a.SeedIdentifier(seed[0])
	}
	return a, nil
}

// buildMainFlowParams builds a Main flow's complete per-flow profile params:
// fresh PSK key state plus, when EAP-SRP credentials are configured, a fresh
// authenticator. It returns an error rather than installing a nil authenticator,
// so a caller drops the flow (fail closed) instead of delivering unauthenticated
// media (fail open) on a key/salt derivation failure. Each call mints independent
// key state, so distinct flows never share one stateful cipher. This is the single
// composition used by every Main receiver path (single-flow and multiplexed).
func buildMainFlowParams(cfg Config) (*session.MainParams, error) {
	mp, err := buildMainParams(cfg)
	if err != nil {
		return nil, err
	}
	eapServer, err := buildEAPServer(cfg)
	if err != nil {
		return nil, err
	}
	mp.EAPServer = eapServer
	return mp, nil
}

// applyRateAdapt wires source-adaptation rate control onto a sender's session
// config when the caller supplied an OnRateAdapt callback (TR-06-4 Part 1): it
// builds an AIMD controller whose ceiling is the configured MaxBitrate (the
// recovery_maxbitrate) and forwards each new target to the callback. A no-op
// when OnRateAdapt is nil.
func applyRateAdapt(sc *session.Config, cfg Config) {
	if cfg.OnRateAdapt == nil {
		return
	}
	cc := adapt.DefaultControllerConfig()
	cc.MaxKbps = cfg.MaxBitrate
	cc.InitialKbps = cfg.MaxBitrate
	if cfg.MinBitrate > 0 {
		cc.MinKbps = cfg.MinBitrate
	}
	if step := cfg.MaxBitrate / 100; step > 0 {
		cc.IncreaseKbps = step
	}
	sc.RateController = adapt.NewController(cc)
	sc.OnRateAdapt = cfg.OnRateAdapt
}

// toFlowConfig maps the public Config to the deterministic core's config.
func toFlowConfig(cfg Config) flow.Config {
	rttMin, rttMax := effectiveRTTBounds(cfg)
	return flow.Config{
		RecoveryBufferMin:  clock.FromDuration(cfg.BufferMin),
		RecoveryBufferMax:  clock.FromDuration(cfg.BufferMax),
		ReorderBuffer:      clock.FromDuration(cfg.ReorderBuffer),
		RTTMin:             rttMin,
		RTTMax:             rttMax,
		RTTMultiplier:      cfg.RTTMultiplier,
		MinRetries:         cfg.MinRetries,
		MaxRetries:         cfg.MaxRetries,
		RecoveryMaxBitrate: cfg.MaxBitrate,
		ReturnMaxBitrate:   cfg.ReturnBandwidth,
		CongestionControl:  toFlowCongestion(cfg.CongestionControl),
		TimingMode:         toFlowTiming(cfg.TimingMode),
	}
}

// effectiveRTTBounds derives the [rtt_min, rtt_max] clamp the flow core uses,
// applying libRIST's "rtt_min is too small for the buffer size" floor from
// store_peer_settings: the effective recovery_rtt_min is raised to
// recovery_length_min / max_retries whenever the configured rtt_min is below it.
// With the defaults (BufferMin 1000 ms, MaxRetries 20) that floor is 50 ms, not
// the configured 5 ms. The floor keeps the NACK retry cadence (1.1x the clamped
// RTT) and the max_retries abandon budget commensurate with the buffer: without
// it, on a low-RTT link the receiver re-NACKs an order of magnitude too often and
// exhausts all max_retries attempts in a small fraction of the playout buffer,
// giving up on recoverable loss far sooner than a libRIST receiver and looking
// like a retransmit storm to a libRIST sender. (The hard 3 ms RIST_RTT_MIN floor
// is applied separately, inside internal/rtt.) rtt_max is raised to the floored
// rtt_min when a degenerate config would otherwise leave it below — matching
// libRIST, which sets recovery_rtt_max = recovery_rtt_min in that case.
//
// The configured cfg.RTTMin is left untouched (it remains the reported value);
// only the value handed to the core is floored, exactly as libRIST computes the
// effective recovery_rtt_min once in store_peer_settings rather than mutating the
// user's setting.
func effectiveRTTBounds(cfg Config) (rttMin, rttMax clock.Microseconds) {
	rttMin = clock.FromDuration(cfg.RTTMin)
	if cfg.MaxRetries > 0 {
		if floor := clock.FromDuration(cfg.BufferMin) / clock.Microseconds(cfg.MaxRetries); floor > rttMin {
			rttMin = floor
		}
	}
	rttMax = clock.FromDuration(cfg.RTTMax)
	if rttMax < rttMin {
		rttMax = rttMin
	}
	return rttMin, rttMax
}

// toFlowTiming maps the public TimingMode to the flow core's TimingMode (the
// values align — SOURCE=0, ARRIVAL=1, RTC=2 — but the mapping keeps the public and
// core types decoupled).
func toFlowTiming(m TimingMode) flow.TimingMode {
	switch m {
	case TimingArrival:
		return flow.TimingArrival
	case TimingRTC:
		return flow.TimingRTC
	default:
		return flow.TimingSource
	}
}

// toFlowCongestion maps the public CongestionControl mode to the flow core's
// CongestionMode (the public API uses a zero-is-default encoding distinct from
// the core's iota order).
func toFlowCongestion(c CongestionControl) flow.CongestionMode {
	switch c {
	case CongestionAggressive:
		return flow.CongestionAggressive
	case CongestionOff:
		return flow.CongestionOff
	default:
		return flow.CongestionNormal
	}
}

// mapLogLevel translates a session severity to the public ristgo.LogLevel.
func mapLogLevel(l session.LogLevel) LogLevel {
	switch l {
	case session.LogNote:
		return LogNote
	case session.LogWarning:
		return LogWarning
	case session.LogError:
		return LogError
	default:
		return LogDebug
	}
}

// mapLogCategory translates a session category to the public ristgo.LogCategory.
func mapLogCategory(c session.LogCategory) LogCategory {
	switch c {
	case session.CatCrypto:
		return LogCrypto
	case session.CatSocket:
		return LogSocket
	case session.CatRTCP:
		return LogRTCP
	case session.CatFlow:
		return LogFlow
	case session.CatBonding:
		return LogBonding
	default:
		return LogSession
	}
}

// toSessionConfig assembles the host config, supplying the public sentinel
// errors so the session can return them directly.
func toSessionConfig(cfg Config, fc flow.Config, ssrc uint32) session.Config {
	var logf func(session.LogLevel, session.LogCategory, string, ...any)
	if cfg.Logger != nil {
		logger := cfg.Logger
		logf = func(level session.LogLevel, category session.LogCategory, format string, args ...any) {
			logger.Log(mapLogLevel(level), mapLogCategory(category), fmt.Sprintf(format, args...))
		}
	}
	cname := cfg.CNAME
	if cname == "" {
		cname = "ristgo"
	}
	// FragmentSize is deliberately not copied here: it is a sender-only split cap,
	// set explicitly on the sender paths (NewSender, NewBondedSender). Receive-side
	// reassembly is driven entirely by the wire FragRole bits, not by this field,
	// so MultiReceiver and other receivers reassemble correctly without it. Anyone
	// making reassembly conditional on FragmentSize must revisit this omission.
	return session.Config{
		Flow:                    fc,
		SSRC:                    ssrc,
		FEC:                     toSessionFEC(cfg.FEC, cfg.Profile == ProfileAdvanced),
		CNAME:                   cname,
		Bitmask:                 cfg.NACKType == NACKBitmask,
		KeepaliveInterval:       clock.FromDuration(cfg.KeepaliveInterval),
		SessionTimeout:          clock.FromDuration(cfg.SessionTimeout),
		Logf:                    logf,
		ErrClosed:               ErrClosed,
		ErrTimeout:              ErrTimeout,
		ErrSessionTimeout:       ErrSessionTimeout,
		ErrBufferOverflow:       ErrBufferOverflow,
		ErrAuth:                 ErrAuth,
		ErrOOBUnsupported:       ErrOOBUnsupported,
		ErrFlowAttrUnsupported:  ErrFlowAttrUnsupported,
		ErrNPDUnsupported:       ErrNPDUnsupported,
		ErrSendBlockUnsupported: ErrSendBlockUnsupported,
		OnFlowAttr:              cfg.OnFlowAttr,
		OnConnect:               toSessionConnectCB(cfg.OnConnect),
		SplitMode:               toSplitMode(cfg.SplitMode),
		MergeMode:               toMergeMode(cfg.MergeMode),
	}
}

// toSessionConnectCB adapts the public OnConnect callback to the session's ConnectInfo
// type (the two packages keep separate ConnectInfo types to avoid an import cycle).
func toSessionConnectCB(cb func(ConnectInfo) bool) func(session.ConnectInfo) bool {
	if cb == nil {
		return nil
	}
	return func(si session.ConnectInfo) bool {
		return cb(ConnectInfo{Remote: si.Remote, Username: si.Username})
	}
}

// toSplitMode maps the public SplitMode to the internal split package's enum.
func toSplitMode(m SplitMode) split.SplitMode {
	switch m {
	case SplitAuto:
		return split.SplitAuto
	case SplitHalf:
		return split.SplitHalf
	default:
		return split.SplitOff
	}
}

// toMergeMode maps the public MergeMode to the internal split package's enum.
func toMergeMode(m MergeMode) split.MergeMode {
	switch m {
	case MergePairs:
		return split.MergePairs
	case MergeAuto:
		return split.MergeAuto
	default:
		return split.MergeOff
	}
}

// cryptoUint32 returns a cryptographically-random uint32. The SSRC and initial
// sequence number are randomized to resist off-path injection, so they are
// drawn from crypto/rand rather than the predictable math/rand PRNG.
// crypto/rand.Read effectively never fails on supported platforms; on that
// impossible error it falls back to the randomly auto-seeded math/rand/v2
// global so the library never panics.
func cryptoUint32() uint32 {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		return rand.Uint32()
	}
	return binary.BigEndian.Uint32(b[:])
}

// randomEvenSSRC returns a random even 32-bit flow SSRC. The LSB is reserved
// as the retransmit marker, so the base SSRC must be even (libRIST).
func randomEvenSSRC() uint32 { return cryptoUint32() &^ 1 }

// randomStartSeq returns a random initial RTP sequence number (RFC 3550
// recommends randomizing it), kept in the low 16 bits since the wire sequence
// is 16-bit. When even is set (packet-split bonding is active) the low bit is
// cleared so the initial sequence is even: split emits every payload as an
// even/+1 pair, and an even start keeps each pair's first half on an even
// sequence — the parity the receiver's merge keys on. A slip would strand a later
// pair across an (odd, even) boundary and corrupt the merge.
func randomStartSeq(even bool) uint32 {
	s := cryptoUint32() & 0xFFFF
	if even {
		s &^= 1
	}
	return s
}

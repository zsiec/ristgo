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

	"github.com/zsiec/ristgo/internal/adapt"
	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/eap"
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
	// ErrAuth is returned to the caller when the Main-profile EAP-SRP handshake
	// fails (wrong credentials or a refused proof). Supplied by the public layer.
	ErrAuth error

	// Main, when non-nil, selects the Main profile (VSF TR-06-2): the flow is
	// tunnelled over a single GRE port instead of the Simple even/odd RTP/RTCP
	// pair. nil means the Simple profile.
	Main *MainParams

	// Adv, when non-nil, selects the Advanced profile (VSF TR-06-3): a single
	// UDP port carrying RTP-based media (PT=127, 1 MHz) and native control
	// messages, with no GRE framing. At most one of Main/Adv is non-nil; both
	// nil means the Simple profile.
	Adv *AdvParams

	// Source adaptation (TR-06-4 Part 1, see adapt.go). AdaptLQM makes a
	// receiver emit periodic Link Quality Messages. RateController + OnRateAdapt,
	// when both set on a sender, feed each inbound LQM to the controller and
	// report the new encoder-rate target to the application. All three are off by
	// default, leaving non-adaptive sessions unchanged.
	AdaptLQM       bool
	RateController *adapt.Controller
	OnRateAdapt    func(kbps int)
}

// MainParams carries the Main-profile codec parameters. The public layer builds
// the PSK keys (so the session constructor stays infallible) and supplies the
// virtual ports; nil keys mean cleartext Main (no encryption).
type MainParams struct {
	// SendKey encrypts outbound datagrams; nil disables encryption.
	SendKey *crypto.Key
	// RecvKey decrypts inbound datagrams; nil disables decryption. It must be
	// non-nil exactly when SendKey is (both derive from the same passphrase).
	RecvKey *crypto.Decryptor
	// KeySize256 sets the GRE H bit for outbound encrypted datagrams (true for
	// a 256-bit AES key). Meaningful only when SendKey is non-nil.
	KeySize256 bool
	// NPD enables null-packet-deletion suppression on the media encode path.
	NPD bool
	// VirtSrcPort and VirtDstPort are the reduced-overhead virtual ports.
	VirtSrcPort uint16
	VirtDstPort uint16

	// EAPClient, when non-nil, runs the EAP-SRP authenticatee handshake (a Main
	// sender authenticating to the peer); outbound media is held until it
	// succeeds. EAPServer, when non-nil, runs the authenticator handshake (a
	// Main receiver authenticating the peer); delivery is held until it
	// succeeds. At most one is set; both nil means no authentication.
	EAPClient *eap.Authenticatee
	EAPServer *eap.Authenticator
}

// AdvParams carries the Advanced-profile codec parameters. As with MainParams
// the public layer builds the PSK keys (so the session constructor stays
// infallible); nil keys mean cleartext Advanced (no encryption).
type AdvParams struct {
	// SendKey encrypts outbound media payloads (AES-CTR, payload-only); nil
	// disables encryption.
	SendKey *crypto.Key
	// RecvKey decrypts inbound media payloads; nil disables decryption. It must
	// be non-nil exactly when SendKey is (both derive from the same passphrase).
	RecvKey *crypto.Decryptor
	// GRESendKey / GRERecvKey encrypt and decrypt the Main-profile GRE control
	// substrate (the RTCP SDES handshake) when a secret is configured. They are
	// SEPARATE crypto instances from SendKey/RecvKey — GRE framing and adv media
	// advance independent IV/sequence state — derived from the same passphrase.
	// Both nil means a cleartext GRE substrate.
	GRESendKey *crypto.Key
	GRERecvKey *crypto.Decryptor
	// KeySize256 sets the GRE H bit for the encrypted control substrate (true
	// for a 256-bit AES key), mirroring MainParams.
	KeySize256 bool
	// Compression enables LZ4 payload compression on the media send path.
	Compression bool
	// VirtSrcPort and VirtDstPort are the reduced-overhead virtual ports encoded
	// into the optional Flow ID field on the media send path.
	VirtSrcPort uint16
	VirtDstPort uint16
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

	// dtlsReady is closed by loop after the optional Main-profile DTLS handshake
	// completes (or fails), gating the reader goroutine so it never touches the
	// socket while the handshake owns it.
	dtlsReady chan struct{}

	// main is the Main-profile codec, non-nil in Main mode. When set, the
	// session reads/writes one GRE-tunnelled socket and demuxes media vs
	// feedback by the inner payload-type byte instead of by socket.
	main *mainCodec

	// adv is the Advanced-profile codec, non-nil in Advanced mode. Like main it
	// reads/writes one UDP socket, demuxing media vs control by the
	// encapsulation Type field rather than by socket.
	adv *advCodec

	// bond holds the link-bonding / SMPTE 2022-7 multipath state (N paths onto
	// one flow), non-nil in bonded mode. See bonded.go.
	bond *bondState

	// advGRE is the Main-profile GRE control substrate used in Advanced mode.
	// libRIST's Advanced profile begins with the Main-profile GRE handshake —
	// it authenticates a peer ONLY via a GRE-framed RTCP SDES packet
	// (rist-common.c:2455, the gate at :1932 that lets data flow) — and gates
	// media transmission on that authentication (udp.c:960). So an Advanced
	// session sends the same GRE RTCP (SR/RR + SDES) handshake the Main profile
	// does (which WP6 proved interoperates byte-exactly), advertises Advanced
	// capability via the adv keepalive I-bit, and then carries media as adv
	// Type=5 and NACK/RTT as adv Type=4. advGRE also decodes inbound raw-GRE
	// (RTCP feedback) and the inner GRE of Type=8 (GRE_MAIN) adv packets.
	advGRE *mainCodec

	// eapClient/eapServer drive the Main-profile EAP-SRP handshake when
	// authentication is configured; at most one is non-nil. authed gates the
	// data channel: true once the handshake succeeds (or immediately when no
	// EAP role is configured). A sender holds outbound media and a receiver
	// holds delivery until authed.
	eapClient *eap.Authenticatee
	eapServer *eap.Authenticator
	// authed gates the data channel; written by the loop, read by the loop and
	// by Authenticated() (hence atomic).
	authed atomic.Bool

	// timers is the host's declarative timer wheel: the deadline the flow
	// requested for each TimerID. A single time.Timer tracks the earliest.
	timers map[flow.TimerID]clock.Timestamp

	// addressing
	highestSent uint32 // sender: reference for widening inbound NACK seqs

	// advPeerKnown records that an Advanced session has learned its peer and
	// sent the immediate authentication handshake (so it is sent once, on the
	// first inbound datagram, not repeatedly).
	advPeerKnown bool

	// Source-adaptation state (adapt.go), loop-owned. rxBytes/lqmPrevBytes meter
	// the measured data bandwidth; lqmSeq/lqmPrev/lqmLast carry the per-reporting
	// -period deltas a receiver folds into each Link Quality Message.
	rxBytes      uint64
	lqmPrevBytes uint64
	lqmSeq       uint32
	lqmPrev      flow.Stats
	lqmLast      clock.Timestamp

	// lastTx is the instant of the last RTCP/media transmission; the
	// keepalive ticker only emits a periodic RTCP when the flow has been
	// quiet for a full interval, so it fills idle gaps without doubling the
	// flow's own RTT-echo cadence.
	lastTx clock.Timestamp
	// rx accumulates receiver-side reception statistics for the full RR.
	rx rxStats

	// event-loop inputs
	mediaIn chan inbound     // Simple media socket
	rtcpIn  chan inbound     // Simple RTCP socket
	mainIn  chan inbound     // Main single GRE socket (media and feedback)
	advIn   chan inbound     // Advanced single UDP socket (media and control)
	bondIn  chan bondInbound // bonded multipath: per-path media/RTCP, tagged
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

// NewMainSender builds a Main-profile sender that tunnels media and reads
// feedback over the single GRE socket conn, addressing remote. cfg.Main must be
// set.
func NewMainSender(conn *socket.Conn, remote *net.UDPAddr, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	// In Main profile a single port carries everything, so the media and RTCP
	// peer addresses are the same; setting both keeps the liveness/feedback
	// guards (peer.Media/RTCP != nil) working unchanged.
	s.peer.Media = remote
	s.peer.RTCP = remote
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	s.start()
	return s
}

// NewMainReceiver builds a Main-profile receiver that reads media and feedback
// over the single GRE socket conn and learns the sender's address from inbound
// traffic. cfg.Main must be set.
func NewMainReceiver(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// NewAdvSender builds an Advanced-profile sender that transmits RTP-based media
// and reads control over the single UDP socket conn, addressing remote. cfg.Adv
// must be set.
func NewAdvSender(conn *socket.Conn, remote *net.UDPAddr, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	// One UDP port carries everything, so the media and control peer addresses
	// are the same (matching the Main profile's single-port model).
	s.peer.Media = remote
	s.peer.RTCP = remote
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	s.start()
	return s
}

// NewAdvReceiver builds an Advanced-profile receiver that reads media and
// control over the single UDP socket conn and learns the sender's address from
// inbound traffic. cfg.Adv must be set.
func NewAdvReceiver(conn *socket.Conn, cfg Config) *Session {
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
		mediaBuf:  make([]byte, 0, maxDatagram),
		rtcpBuf:   make([]byte, 0, maxDatagram),
		readWake:  make(chan struct{}, 1),
		writeWake: make(chan struct{}, 1),
		done:      make(chan struct{}),
		dtlsReady: make(chan struct{}),
	}
	if sender {
		s.appIn = make(chan []byte, 64)
	} else {
		s.delivery = make(chan []byte, 4096)
	}
	s.authed.Store(true) // no EAP gate by default (Simple, or Main without auth)
	if cfg.Main != nil {
		mp := cfg.Main
		s.main = newMainCodec(mp.SendKey, mp.RecvKey, mp.KeySize256, mp.VirtSrcPort, mp.VirtDstPort, mp.NPD, cfg.SSRC, cfg.CNAME, cfg.Bitmask)
		s.mainIn = make(chan inbound, 256)
		s.eapClient = mp.EAPClient
		s.eapServer = mp.EAPServer
		if s.eapClient != nil || s.eapServer != nil {
			s.authed.Store(false) // hold the data channel until the handshake succeeds
		}
	} else if cfg.Adv != nil {
		ap := cfg.Adv
		s.adv = newAdvCodec(ap.SendKey, ap.RecvKey, ap.Compression, cfg.SSRC, ap.VirtSrcPort, ap.VirtDstPort)
		// The GRE control substrate carries the RTCP SDES handshake that
		// authenticates this peer to libRIST. It uses the same PSK as the adv
		// media path when encryption is configured (matching libRIST, which
		// keeps the GRE control plane encrypted), with its own key/decryptor
		// instances since GRE and adv media advance independent IV/seq state.
		s.advGRE = newMainCodec(ap.GRESendKey, ap.GRERecvKey, ap.KeySize256, ap.VirtSrcPort, ap.VirtDstPort, false, cfg.SSRC, cfg.CNAME, cfg.Bitmask)
		s.advIn = make(chan inbound, 256)
	} else {
		s.rtcpIn = make(chan inbound, 64)
		if !sender {
			s.mediaIn = make(chan inbound, 256)
		}
	}
	var zero flow.Stats
	s.stats.Store(&zero)
	return s
}

// start launches the reader goroutines and the event loop. The Main profile
// runs one reader on its single GRE socket; the Simple profile runs a reader
// per socket (RTCP always, media on a receiver).
func (s *Session) start() {
	s.wg.Add(1)
	go s.loop()
	if s.bond != nil {
		s.startBondReaders()
		return
	}
	if s.main != nil {
		s.wg.Add(1)
		go s.readMain()
		return
	}
	if s.adv != nil {
		s.wg.Add(1)
		go s.readAdv()
		return
	}
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
	// Backstop: guarantee dtlsReady is closed on every exit path so the reader
	// goroutine (which waits on it) can never block forever — even if a future
	// edit adds an early return before the explicit closes below.
	dtlsReadyClosed := false
	closeDTLSReady := func() {
		if !dtlsReadyClosed {
			dtlsReadyClosed = true
			close(s.dtlsReady)
		}
	}
	defer closeDTLSReady()

	// Optional Main-profile DTLS: establish the secure channel before any socket
	// I/O. The reader goroutine waits on dtlsReady, so the handshake (which reads
	// and writes the socket itself) runs without contention.
	if s.conn.DTLSEnabled() {
		if err := s.conn.Handshake(); err != nil {
			s.shutdown(s.cfg.ErrAuth)
			closeDTLSReady()
			s.logf("dtls: handshake failed: %v", err)
			return
		}
	}
	closeDTLSReady()

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
	// Anchor the LQM reporting period at start-up so the first report covers a
	// real interval rather than the whole epoch.
	s.lqmLast = s.clk.Now()
	// A Main-profile EAP client opens authentication immediately with an
	// EAPOL-START; media is held (appIn is gated below) until it succeeds.
	if s.eapClient != nil {
		s.sendEAP(s.eapClient.Start(), s.clk.Now())
	}

	for {
		// Hold outbound media (appIn) until the data channel is authenticated;
		// a nil channel never fires in the select, applying back-pressure to
		// Write until the EAP handshake completes (or instantly when unused).
		var appIn chan []byte
		if s.authed.Load() {
			appIn = s.appIn
		}
		select {
		case <-s.done:
			return
		case m := <-s.mediaIn:
			now := s.clk.Now()
			s.peer.LearnMedia(m.src)
			s.peer.Observe(now)
			s.observeRxBytes(len(m.data))
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
				s.feedFeedback(now, fbs)
			}
			s.afterInput(now, timer)
		case d := <-s.mainIn:
			now := s.clk.Now()
			// One GRE socket carries both directions, so the peer's media and
			// RTCP addresses are the one learned address.
			s.peer.LearnMedia(d.src)
			s.peer.LearnRTCP(d.src)
			s.peer.Observe(now)
			if eapPayload, ok := s.main.peekEAPOL(d.data); ok {
				// Authentication frame: route to the EAP state machine.
				s.handleEAP(now, eapPayload)
			} else if isMedia, pkt, fbs, err := s.main.decodeMain(d.data, s.highestSent); err == nil {
				if isMedia {
					s.observeRxBytes(len(d.data))
					s.flow.Feed(now, 0, pkt)
					s.observeRx(now, pkt)
				} else {
					s.feedFeedback(now, fbs)
				}
			} else {
				// A decode failure on an otherwise-delivered datagram usually
				// means a PSK secret or AES-key-size mismatch (decryption yields
				// garbage), which would otherwise look like total packet loss.
				// Surface it so it is diagnosable; logf is zero-cost when no
				// logger is set.
				s.logf("main: drop undecodable datagram (%d bytes): %v", len(d.data), err)
			}
			s.afterInput(now, timer)
		case d := <-s.advIn:
			now := s.clk.Now()
			// One UDP port carries both directions, so the peer's media and
			// control addresses are the one learned address.
			s.peer.LearnMedia(d.src)
			s.peer.LearnRTCP(d.src)
			s.peer.Observe(now)
			// Send our GRE+RTCP handshake the instant we learn the peer, rather
			// than waiting for the keepalive ticker: libRIST's sender gates media
			// on authenticating us (via our SDES), so a one-interval delay here
			// would let it drop the early input before we are authenticated.
			if !s.advPeerKnown {
				s.advPeerKnown = true
				s.sendKeepalive(now)
			}
			s.handleAdvInbound(now, d.data)
			s.afterInput(now, timer)
		case bi := <-s.bondIn:
			now := s.clk.Now()
			s.handleBondInbound(now, bi)
			s.afterInput(now, timer)
		case p := <-appIn:
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
			// Emit a periodic keepalive. Bonding ages its paths and sends every
			// interval (a sender must keep advertising its return address on all
			// paths; both ends keep RTT/liveness fresh). The Advanced profile
			// sends its GRE+RTCP handshake every interval (matching libRIST's
			// unconditional periodic RTCP); the Simple/Main profiles only fill
			// idle gaps so the flow's own RTT-echo cadence is not doubled.
			if s.bond != nil {
				s.tickBond(now)
				s.sendKeepalive(now)
			} else if s.peer.RTCP != nil && (s.adv != nil || now.Sub(s.lastTx) >= ka) {
				s.sendKeepalive(now)
			}
			// A receiver that opted into source adaptation emits a Link Quality
			// Message each interval (TR-06-4 Part 1).
			if s.adaptEmitsLQM() {
				s.sendLQM(now)
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

// sendMedia encodes and transmits one media datagram to the peer's media
// address: a bare RTP packet on the Simple profile, a GRE-tunnelled (and
// PSK-encrypted) one on the Main profile, sent over the single GRE socket.
func (s *Session) sendMedia(now clock.Timestamp, pkt wire.MediaPacket) {
	if s.bond != nil {
		s.sendBondMedia(now, pkt)
		return
	}
	if s.peer.Media == nil {
		return
	}
	s.mediaBuf = s.mediaBuf[:0]
	var b []byte
	var err error
	if s.main != nil {
		b, err = s.main.encodeMainMedia(s.mediaBuf, pkt)
	} else if s.adv != nil {
		b, err = s.adv.encodeAdvMedia(s.mediaBuf, pkt)
	} else {
		b, err = encodeMedia(s.mediaBuf, pkt)
	}
	if err != nil {
		s.logf("encode media seq %d: %v", pkt.Seq, err)
		return
	}
	s.mediaBuf = b
	// WriteMedia targets the single GRE socket in Main mode (media == rtcp).
	if err := s.conn.WriteMedia(b, s.peer.Media); err != nil {
		s.logf("write media: %v", err)
	}
	s.lastTx = now
}

// sendFeedback builds one compound RTCP datagram from the drained feedback and
// transmits it to the peer's RTCP address.
func (s *Session) sendFeedback(fbs []wire.Feedback, now clock.Timestamp) {
	if s.bond != nil {
		s.sendBondFeedback(fbs, now)
		return
	}
	if s.peer.RTCP == nil {
		return // return path not learned yet
	}
	// Advanced profile has no compound RTCP: each feedback item is its own
	// Type=Control datagram (libRIST sends/reads one entry per datagram).
	if s.adv != nil {
		s.sendAdvFeedback(fbs, now)
		return
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
	b, err := s.encodeCompound(s.rtcpBuf, lead, fbs)
	if err != nil {
		s.logf("encode feedback: %v", err)
		return
	}
	s.rtcpBuf = b
	if err := s.writeFeedback(b); err != nil {
		s.logf("write rtcp: %v", err)
	}
	s.lastTx = now
}

// encodeCompound builds one compound-RTCP datagram for the configured profile:
// bare compound RTCP on the Simple profile, GRE-tunnelled (and PSK-encrypted)
// on the Main profile.
func (s *Session) encodeCompound(dst []byte, lead rtcp.Packet, fbs []wire.Feedback) ([]byte, error) {
	if s.main != nil {
		return s.main.encodeMainFeedback(dst, lead, fbs, s.cfg.Bitmask)
	}
	return encodeFeedback(dst, lead, s.cfg.SSRC, s.cfg.CNAME, fbs, s.cfg.Bitmask)
}

// writeFeedback transmits a feedback datagram to the peer: the RTCP socket on
// the Simple profile, the single GRE socket (== media) on the Main profile.
func (s *Session) writeFeedback(b []byte) error {
	if s.main != nil {
		return s.conn.WriteMedia(b, s.peer.RTCP)
	}
	return s.conn.WriteRTCP(b, s.peer.RTCP)
}

// advCtrlTS is the Advanced RTP timestamp stamped into an outbound control
// packet's header, encoded at the same effective 2^16 MHz rate as media
// (microseconds << advClockShift) so both paths and libRIST agree on the field's
// units. It is informational — the peer ignores it (adv_ctrl.c does not read the
// control timestamp).
func advCtrlTS(now clock.Timestamp) uint32 { return uint32(uint64(int64(now)) << advClockShift) }

// sendAdvFeedback encodes the drained feedback into Advanced-profile control
// datagrams and sends each to the peer over the single UDP socket. Unlike the
// Simple/Main compound-RTCP path, each feedback item becomes one or more
// independent Type=Control datagrams.
func (s *Session) sendAdvFeedback(fbs []wire.Feedback, now clock.Timestamp) {
	dgs, err := s.adv.encodeFeedback(fbs, s.cfg.Bitmask, advCtrlTS(now))
	if err != nil {
		s.logf("adv: encode feedback: %v", err)
		return
	}
	// Send every datagram; a single write error must not drop the remaining
	// NACK ranges / echoes (control rate is low and the rest may succeed).
	for _, dg := range dgs {
		if werr := s.conn.WriteMedia(dg, s.peer.RTCP); werr != nil {
			s.logf("adv: write control: %v", werr)
		}
	}
	if len(dgs) > 0 {
		s.lastTx = now
	}
}

// sendAdvKeepalive emits one Advanced keep-alive control (CI 0x8000, I-bit) to
// the peer — the Advanced analog of the periodic Main keepalive — advertising
// Advanced capability so libRIST negotiates the profile and maintaining liveness
// while idle. RTT echo requests are NOT sent here: the flow core drives them on
// its own cadence (TimerRttEcho -> SendFeedback -> sendAdvFeedback), so emitting
// one here too would double the echo rate.
func (s *Session) sendAdvKeepalive(now clock.Timestamp) {
	ka, err := s.adv.keepaliveDatagram(advCtrlTS(now))
	if err != nil {
		s.logf("adv: encode keepalive: %v", err)
		return
	}
	if werr := s.conn.WriteMedia(ka, s.peer.RTCP); werr != nil {
		s.logf("adv: write keepalive: %v", werr)
		return
	}
	s.lastTx = now
}

// sendAdvGREHandshake sends the Main-profile GRE RTCP (SR/RR + SDES) datagram
// that authenticates this peer to libRIST's Advanced receiver/sender — the
// handshake libRIST requires before it accepts data or ungates media
// transmission (rist-common.c:1932/2455, udp.c:960). It reuses the same GRE+RTCP
// encoding WP6 proved interoperable; advGRE encrypts it under the PSK when one
// is configured.
func (s *Session) sendAdvGREHandshake(now clock.Timestamp) {
	if s.peer.RTCP == nil {
		return
	}
	s.rtcpBuf = s.rtcpBuf[:0]
	b, err := s.advGRE.encodeMainFeedback(s.rtcpBuf, s.keepaliveLead(now), nil, s.cfg.Bitmask)
	if err != nil {
		s.logf("adv: encode GRE handshake: %v", err)
		return
	}
	s.rtcpBuf = b
	if err := s.conn.WriteMedia(b, s.peer.RTCP); err != nil {
		s.logf("adv: write GRE handshake: %v", err)
	}
	s.lastTx = now
}

// handleAdvInbound demultiplexes one inbound Advanced-profile datagram. libRIST
// mixes PT=127 adv framing (Type=5 media, Type=4 control, Type=8 GRE-wrapped)
// with raw Main-profile GRE (the RTCP handshake and keepalives), so the host
// tries adv framing first and falls back to the GRE substrate.
func (s *Session) handleAdvInbound(now clock.Timestamp, data []byte) {
	// Adv framing: RTP V=2 with PT 127 (or a dynamic type >= 96).
	if len(data) >= 2 && data[0]&0xC0 == 0x80 {
		if pt := data[1] & 0x7f; pt == adv.PayloadType || pt >= 96 {
			if p, err := adv.Parse(data); err == nil {
				if p.EncType == adv.TypeGREMain {
					// Type=8: the payload is an inner Main-profile GRE packet.
					s.handleAdvGRE(now, p.Payload)
					return
				}
				if isMedia, pkt, fbs, derr := s.adv.decodeParsed(p); derr == nil {
					if isMedia {
						s.observeRxBytes(len(data))
						s.flow.Feed(now, 0, pkt)
						s.observeRx(now, pkt)
					} else {
						s.feedFeedback(now, fbs)
					}
				} else {
					s.logf("adv: drop undecodable adv datagram (%d bytes): %v", len(data), derr)
				}
				return
			}
			// not parseable as adv; fall through to the GRE substrate
		}
	}
	// Raw Main-profile GRE: the RTCP handshake (SDES auth, SR/RR, NACK) or a
	// keepalive. Liveness was already recorded by peer.Observe.
	s.handleAdvGRE(now, data)
}

// handleAdvGRE decodes one Main-profile GRE datagram on the Advanced path: an
// RTCP NACK becomes flow feedback; SR/RR/SDES and keepalives carry no flow data
// (they served their handshake/liveness purpose at the peer layer). A decode
// error (e.g. a GRE keepalive, whose protocol type is not REDUCED) is ignored.
func (s *Session) handleAdvGRE(now clock.Timestamp, data []byte) {
	isMedia, pkt, fbs, err := s.advGRE.decodeMain(data, s.highestSent)
	if err != nil {
		return // keepalive or otherwise not a GRE media/RTCP datagram; ignore
	}
	if isMedia {
		// libRIST does not send GRE-framed media in Advanced mode; accept it
		// defensively all the same.
		s.observeRxBytes(len(data))
		s.flow.Feed(now, 0, pkt)
		s.observeRx(now, pkt)
		return
	}
	s.feedFeedback(now, fbs)
}

// handleEAP drives the Main-profile EAP-SRP handshake for one received EAPOL
// payload: it feeds the configured role, sends any reply EAPOL frame, opens the
// data channel (authed) once the handshake authenticates, and tears the session
// down with ErrAuth if it definitively fails.
func (s *Session) handleEAP(now clock.Timestamp, payload []byte) {
	var (
		out  *eap.Frame
		err  error
		role interface {
			Authenticated() bool
			Done() bool
		}
	)
	switch {
	case s.eapClient != nil:
		out, err = s.eapClient.Recv(payload)
		role = s.eapClient
	case s.eapServer != nil:
		out, err = s.eapServer.Recv(payload)
		role = s.eapServer
	default:
		return // not configured for EAP; ignore a stray EAPOL frame
	}
	if out != nil {
		s.sendEAP(*out, now)
	}
	if err != nil {
		s.logf("eap: %v", err)
	}
	if role.Authenticated() {
		s.authed.Store(true)
	} else if role.Done() {
		// A terminal state without success means authentication failed.
		s.shutdown(s.cfg.ErrAuth)
	}
}

// sendEAP frames an EAP frame as a GRE EAPOL datagram and sends it to the peer
// over the single Main socket. EAPOL is never encrypted (gre.c:25).
func (s *Session) sendEAP(f eap.Frame, now clock.Timestamp) {
	if s.main == nil || s.peer.Media == nil {
		return
	}
	s.rtcpBuf = s.rtcpBuf[:0]
	b, err := s.main.encodeEAPOL(s.rtcpBuf, f.AppendTo(nil))
	if err != nil {
		s.logf("encode eap: %v", err)
		return
	}
	s.rtcpBuf = b
	if err := s.conn.WriteMedia(b, s.peer.Media); err != nil {
		s.logf("write eap: %v", err)
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
	if !s.authed.Load() {
		return // hold delivery until the EAP-SRP handshake authenticates the peer
	}
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

// readMain reads datagrams off the single Main-profile GRE socket and forwards
// them to the loop, which demuxes media vs feedback by the inner payload-type
// byte. It is the Main-profile counterpart of readMedia + readRTCP.
func (s *Session) readMain() {
	defer s.wg.Done()
	// Wait for the optional DTLS handshake (driven by loop) before touching the
	// socket; bail out if the session was torn down during it.
	<-s.dtlsReady
	select {
	case <-s.done:
		return
	default:
	}
	for {
		buf := make([]byte, maxDatagram)
		n, src, err := s.conn.ReadMedia(buf) // single GRE socket
		if err != nil {
			return
		}
		select {
		case s.mainIn <- inbound{data: buf[:n], src: src}:
		case <-s.done:
			return
		}
	}
}

// readAdv reads datagrams off the single Advanced-profile UDP socket and
// forwards them to the loop, which demuxes media vs control by the encapsulation
// Type field. It is the Advanced-profile counterpart of readMain.
func (s *Session) readAdv() {
	defer s.wg.Done()
	for {
		buf := make([]byte, maxDatagram)
		n, src, err := s.conn.ReadMedia(buf) // single UDP socket
		if err != nil {
			return
		}
		select {
		case s.advIn <- inbound{data: buf[:n], src: src}:
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

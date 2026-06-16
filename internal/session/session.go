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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zsiec/ristgo/internal/adapt"
	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/eap"
	"github.com/zsiec/ristgo/internal/fec"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/gre"
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
	// Logf, when non-nil, receives diagnostic messages tagged with a severity
	// and a category. The host maps LogLevel/LogCategory to the public
	// ristgo.LogLevel/LogCategory (the session is decoupled from the public
	// package to avoid an import cycle).
	Logf func(level LogLevel, category LogCategory, format string, args ...any)

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
	// ErrOOBUnsupported is returned by WriteOOB/ReadOOB when the session has no
	// out-of-band channel (the Simple profile). Supplied by the public layer.
	ErrOOBUnsupported error
	// ErrFlowAttrUnsupported is returned by WriteFlowAttribute when the session is
	// not Advanced (flow attributes are an Advanced-profile control message).
	// Supplied by the public layer.
	ErrFlowAttrUnsupported error

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

	// OnFlowAttr, set on an Advanced receiver, is called with the JSON body of each
	// inbound Flow Attribute control message (TR-06-3 §5.3.7). The slice is valid
	// only for the duration of the call (it aliases codec scratch); the callback
	// runs on the event loop, so it must not block. nil disables the channel.
	OnFlowAttr func(json []byte)

	// FragmentSize, when > 0, makes the sender split an application payload
	// larger than this many bytes across consecutive sequences, each an
	// independently recoverable fragment (Advanced profile only; the codec maps
	// the pieces to the header F/L bits). The receiver reassembles them after
	// in-order delivery. 0 (the default) sends each payload as a single packet.
	// This is a ristgo<->ristgo capability: libRIST implements neither
	// fragmentation nor reassembly.
	FragmentSize int

	// FEC, when non-nil, enables SMPTE ST 2022-1 forward error correction over the
	// media stream (TR-06-3 §5.3.5). The sender emits row/column FEC packets and
	// the receiver recovers single losses per row/column without a NACK round trip.
	FEC *FECParams

	// FECColumn and FECRow are the receiver's bound column/row FEC sockets for the
	// separate-port carriage (FEC.SeparatePorts); nil otherwise and on a sender.
	// The session owns and closes them.
	FECColumn, FECRow *net.UDPConn

	// FECSockets are a bonded receiver's per-path column/row FEC sockets for the
	// separate-port carriage (two per path, all feeding the one FEC decoder). The
	// session owns and closes them. nil on a single-path session or a sender.
	FECSockets []*net.UDPConn

	// OneWay runs the session as one-way / no-return-channel transport: the
	// host emits no RTCP at all (no Sender/Receiver Reports, SDES, NACKs, RTT
	// echoes, keepalives, GRE keepalives, LQM, or buffer negotiation), only
	// media. Pair it with Flow.NoRecovery, which disables the core's ARQ so
	// the sender keeps no history and the receiver requests no retransmits. A
	// one-way sender does not time out on peer silence (the peer is silent by
	// design — an unseen peer never expires). The zero value is the normal
	// bidirectional session.
	OneWay bool
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

	// UseKeyAsPassphrase enables the EAP-SRP use_key_as_passphrase data-channel
	// keying: when SRP is configured WITHOUT a pre-shared Secret, the media PSK
	// keys are derived from the SRP session key K (both directions) on a
	// successful handshake and installed into the running codec. SendKey/RecvKey
	// are nil at construction in this mode (no secret); the handshake fills them.
	// Meaningful only when EAPClient or EAPServer is set.
	UseKeyAsPassphrase bool

	// EAPKeySize256 selects the AES key size derived from K under
	// use_key_as_passphrase: true for 256-bit (the libRIST default when no
	// aes-type is given, since _librist_crypto_psk_set_passphrase defaults
	// key_size to 256), false for 128-bit. Meaningful only when
	// UseKeyAsPassphrase is set.
	EAPKeySize256 bool

	// EAPKeyRotation is the key-rotation threshold for the K-derived send key
	// (packets per nonce; 0 = the library default). Meaningful only under
	// UseKeyAsPassphrase.
	EAPKeyRotation int
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

// inbound is one datagram handed from a reader goroutine to the event loop. src
// is a netip.AddrPort value (not *net.UDPAddr) so the per-datagram receive path
// allocates nothing; the zero AddrPort (!IsValid()) means the source is unknown.
type inbound struct {
	data []byte
	src  netip.AddrPort
}

// Session hosts one flow. Construct it with NewSender or NewReceiver.
type Session struct {
	cfg    Config
	clk    clock.Clock
	conn   *socket.Conn
	flow   *flow.Flow
	peer   *peer.Peer
	sender bool // role
	// injected runs the session without its own socket reader goroutines: an
	// external demultiplexer (a MultiReceiver) owns the socket read, keys each
	// datagram to its flow, and feeds this session's inbound channels via
	// InjectMedia / InjectRTCP (Simple), Inject (single-socket Main/Advanced), or
	// InjectBond (bonded). The session still owns its event loop, flow core,
	// timers, and feedback writes (which go out the shared conn). On shutdown it
	// does not close the shared conn (the MultiReceiver does).
	injected bool
	// announce makes a receiver send an immediate startup keepalive (a Receiver
	// Report) to its seeded peer.RTCP — the caller-receive (pull) mode, where the
	// receiver dials a listening sender and must announce itself so that sender
	// learns its return address and begins streaming. A normal (listening)
	// receiver leaves this false and stays silent until it has heard the sender.
	announce bool
	mdec     mediaDecoder

	// dtlsReady is closed by loop after the optional Main-profile DTLS handshake
	// completes (or fails), gating the reader goroutine so it never touches the
	// socket while the handshake owns it.
	dtlsReady chan struct{}

	// main is the Main-profile codec, non-nil in Main mode. When set, the
	// session reads/writes one GRE-tunnelled socket and demuxes media vs
	// feedback by the inner payload-type byte instead of by socket.
	main *mainCodec

	// Main-profile GRE keepalive negotiation state (loop-owned). greVersion is
	// the monotonically-upgraded negotiated GRE version (starts at VersionMin);
	// localMAC is this node's MAC advertised in keepalives; remoteCaps/remoteMAC
	// are what the peer last advertised; senderMaxBufferMs is the buffer the peer
	// allows as a sender (from buffer negotiation, observe-only). greBurstSent
	// guards the one-shot connect burst.
	greVersion        uint8
	localMAC          [6]byte
	remoteCaps        gre.Capabilities
	remoteMAC         [6]byte
	senderMaxBufferMs uint16
	greBurstSent      bool

	// adv is the Advanced-profile codec, non-nil in Advanced mode. Like main it
	// reads/writes one UDP socket, demuxing media vs control by the
	// encapsulation Type field rather than by socket.
	adv *advCodec

	// bond holds the link-bonding / SMPTE 2022-7 multipath state (N paths onto
	// one flow), non-nil in bonded mode. See bonded.go.
	bond *bondState

	// FEC (SMPTE ST 2022-1) state, non-nil/active only when cfg.FEC is set. fecEnc
	// generates row/column FEC from sent media; fecDec recovers lost media on
	// receive and feeds it into the flow like a retransmit. Both are lazily
	// constructed from the first packet's sequence. See fec.go.
	fecEnc       *fec.Encoder
	fecDec       *fec.Decoder
	fecBuf       []byte        // scratch for framing FEC packets
	fecRecovered atomic.Uint64 // packets reconstructed by FEC
	// Separate-port FEC carriage: fecCol/fecRow are the receiver's bound column/row
	// FEC sockets; fecIn forwards their RTP-stripped FEC bodies to the loop; the
	// per-stream RTP sequence counters number the outbound FEC streams.
	fecCol, fecRow       *net.UDPConn
	fecSockets           []*net.UDPConn // bonded receiver's per-path FEC sockets
	fecIn                chan []byte
	fecColSeq, fecRowSeq uint16
	fecCtrlReasm         fecCtrlReassembler // reassembles over-MTU in-band FEC control messages

	// advGRE is the Main-profile GRE control substrate used in Advanced mode.
	// libRIST's Advanced profile begins with the Main-profile GRE handshake —
	// it authenticates a peer ONLY via a GRE-framed RTCP SDES packet (the gate
	// that lets data flow) — and gates media transmission on that
	// authentication. So an Advanced session sends the same GRE RTCP (SR/RR +
	// SDES) handshake the Main profile
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
	// eapStartSent records that the authenticatee's EAPOL-Start has been emitted.
	// A caller authenticatee knows its peer at start-up and sends it immediately; a
	// listener authenticatee (listener-sender topology) cannot speak until it learns
	// the caller, so the loop defers the Start until the peer's address is known.
	eapStartSent bool
	// peerCNAME is the peer's RTCP SDES canonical name, recorded ONLY from an
	// authenticated EAP-SRP session (forgeable otherwise). It is the identity key for
	// NAT source-port rebind re-association (see maybeReassociate). Empty until learned.
	peerCNAME string
	// everAuthed records that the EAP-SRP handshake has succeeded at least once, so a
	// LATER handshake failure or a regression out of SUCCESS is treated as a re-auth (a
	// held re-auth, not an initial-auth failure that tears the session down). This is the
	// session-layer signal, written only here on the SUCCESS transition and read by
	// srpAuthenticated/handleEAP; it is distinct from eap.Authenticator.everAuthed, which
	// is the role's own internal LOGOFF guard — neither reads the other, so they are not
	// kept in lockstep across the layer boundary.
	everAuthed bool
	// reauthing is true while a NAT-rebind / in-band EAP re-authentication is in flight to
	// a migrated or regressed tuple: media is held (authed false) and further new-source
	// datagrams are ignored until the fresh handshake completes (success) or the session is
	// torn down at reauthDeadline. While it is set, the ordinary session-timeout teardown is
	// suppressed so the re-auth gets its full round-trip.
	reauthing      bool
	reauthDeadline clock.Timestamp // when an unfinished re-auth tears the session down
	// authed gates the data channel; written by the loop, read by the loop and
	// by Authenticated() (hence atomic).
	authed atomic.Bool

	// useKeyAsPassphrase enables the EAP-SRP use_key_as_passphrase keying: on a
	// successful handshake the media PSK keys are derived from the SRP session key
	// K and installed into s.main. eapKeySize256 selects the derived AES key size
	// (256-bit to match libRIST's default when no aes-type is given). pwReqSent
	// latches the one-shot post-SUCCESS PASSWORD_REQUEST the authenticator emits.
	// txKeyGen/rxKeyGen track the last installed keying generation so a rollover
	// (a repeated K) still re-derives.
	useKeyAsPassphrase bool
	eapKeySize256      bool
	eapKeyRotation     int
	pwReqSent          bool
	txKeyGen           uint64
	rxKeyGen           uint64

	// timers is the host's declarative timer wheel: the deadline the flow
	// requested for each TimerID. A single time.Timer tracks the earliest.
	timers map[flow.TimerID]clock.Timestamp

	// addressing
	highestSent uint32 // sender: reference for widening inbound NACK seqs

	// advPeerKnown records that an Advanced session has learned its peer and
	// sent the immediate authentication handshake (so it is sent once, on the
	// first inbound datagram, not repeatedly).
	advPeerKnown bool

	// Source-adaptation state (adapt.go), loop-owned. rxBytes/rxRetransBytes meter
	// RTP-level bytes (TR-06-4 Part 1 §5.1: payload + RTP header, NOT the GRE/adv
	// encapsulation), split so the LQM reports source Data Bandwidth and
	// Retransmission Bandwidth separately; the lqmPrev* snapshots carry the
	// per-reporting-period deltas; lqmSeq/lqmPrev/lqmLast carry the rest of the
	// per-period state a receiver folds into each Link Quality Message.
	rxBytes             uint64
	rxRetransBytes      uint64
	lqmPrevBytes        uint64
	lqmPrevRetransBytes uint64
	lqmPrevFEC          uint64 // fecRecovered at the last LQM, for the per-period FEC delta
	lqmSeq              uint32
	lqmPrev             flow.Stats
	lqmLast             clock.Timestamp

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

	// weightCmd carries runtime load-balancing weight changes (BondedSender.SetWeight,
	// libRIST rist_peer_weight_set) onto the event loop, which owns the (not
	// concurrency-safe) bonding Group. Non-nil only on a bonded sender.
	weightCmd chan weightSet

	// Out-of-band side channel (Main/Advanced only). oobIn carries application
	// WriteOOB payloads to the loop; oobOut carries received OOB datagrams to
	// ReadOOB. Each carries the GRE protocol type so a tunnelled datagram's
	// protocol survives the round trip. OOB bypasses the flow core entirely (no
	// ARQ/reorder/dedup), like EAPOL — it is purely a host concern.
	oobIn  chan oobData
	oobOut chan oobData

	// flowAttrIn carries application WriteFlowAttribute JSON bodies to the loop,
	// which emits each as an Advanced Flow Attribute control message (TR-06-3
	// §5.3.7). Advanced senders only; nil otherwise. Like OOB it bypasses the flow
	// core (pure host concern, no ARQ).
	flowAttrIn chan []byte

	// delivery to Read
	delivery chan []byte
	leftover []byte // partially-read payload (stream semantics)

	// scratch encode buffers (loop-owned)
	mediaBuf []byte
	rtcpBuf  []byte

	// Fragmentation (Advanced profile, loop-owned). fragSize > 0 makes the
	// sender split a Write larger than fragSize across consecutive sequences;
	// reasm reassembles the delivered fragments on the receive side. Both are
	// zero/unused when fragmentation is off and for non-Advanced profiles.
	fragSize int
	reasm    fragReassembler

	// statsVal is the published flow-stats snapshot, refreshed after every loop
	// input by the loop goroutine and read by the public Stats(). It is guarded
	// by statsMu rather than an atomic.Pointer so the per-input refresh reuses
	// the same struct (a 144-byte copy under an uncontended lock) instead of
	// heap-allocating a fresh snapshot on every media packet — the hot path
	// CLAUDE.md requires to stay alloc-free.
	statsMu  sync.Mutex
	statsVal flow.Stats

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
func NewSender(conn *socket.Conn, mediaAddr, rtcpAddr netip.AddrPort, cfg Config) *Session {
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
func NewMainSender(conn *socket.Conn, remote netip.AddrPort, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	// In Main profile a single port carries everything, so the media and RTCP
	// peer addresses are the same; setting both keeps the liveness/feedback
	// guards (peer.Media/RTCP.IsValid()) working unchanged.
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
func NewAdvSender(conn *socket.Conn, remote netip.AddrPort, cfg Config) *Session {
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

// NewReceiverCaller builds a Simple-profile caller-receiver: a receiver that
// dials a listening sender instead of binding a well-known port. It is seeded
// with the sender's RTCP address (peerRTCP) and announces itself immediately and
// every keepalive interval; the listening sender learns this receiver from those
// Receiver Reports and starts streaming. conn is an ephemeral even/odd socket
// pair so the sender can infer this receiver's media port as its RTCP port − 1.
func NewReceiverCaller(conn *socket.Conn, peerRTCP netip.AddrPort, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.peer.RTCP = peerRTCP
	s.announce = true
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// NewMainReceiverCaller builds a Main-profile caller-receiver that dials remote
// over the single GRE socket, announcing itself until the listening sender
// streams. cfg.Main must be set.
func NewMainReceiverCaller(conn *socket.Conn, remote netip.AddrPort, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.peer.Media = remote
	s.peer.RTCP = remote
	s.announce = true
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// NewAdvReceiverCaller builds an Advanced-profile caller-receiver that dials
// remote over the single UDP socket, announcing itself until the listening
// sender streams. cfg.Adv must be set.
func NewAdvReceiverCaller(conn *socket.Conn, remote netip.AddrPort, cfg Config) *Session {
	s := newSession(conn, cfg, false)
	s.peer.Media = remote
	s.peer.RTCP = remote
	s.announce = true
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	s.start()
	return s
}

// NewListenerSender builds a Simple-profile listener-sender: a sender that binds
// a well-known port and waits for a caller-receiver to announce itself, then
// streams. The peer is not seeded — peer.RTCP is learned from the receiver's
// inbound RTCP and peer.Media is inferred as its RTCP port − 1 (the even/odd
// rule) — so sendMedia holds the stream until a receiver is known.
func NewListenerSender(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	s.start()
	return s
}

// NewMainListenerSender builds a Main-profile listener-sender that binds the
// single GRE port and learns the receiver from its inbound traffic. cfg.Main
// must be set.
func NewMainListenerSender(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	s.start()
	return s
}

// NewAdvListenerSender builds an Advanced-profile listener-sender that binds the
// single UDP port and learns the receiver from its inbound traffic. cfg.Adv must
// be set.
func NewAdvListenerSender(conn *socket.Conn, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
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
		fragSize:  cfg.FragmentSize,
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
	// Separate-port FEC carriage: the receiver binds column/row FEC sockets and
	// forwards their bodies to the loop over fecIn (created before the loop starts).
	s.fecCol, s.fecRow = cfg.FECColumn, cfg.FECRow
	s.fecSockets = cfg.FECSockets
	if s.fecCol != nil || len(s.fecSockets) > 0 {
		s.fecIn = make(chan []byte, 64)
	}
	s.authed.Store(true) // no EAP gate by default (Simple, or Main without auth)
	if cfg.Main != nil || cfg.Adv != nil {
		// OOB side channel is available on the Main and Advanced profiles only.
		s.oobIn = make(chan oobData, 16)
		s.oobOut = make(chan oobData, 16)
	}
	if cfg.Adv != nil {
		// Flow attributes are an Advanced-profile control message; the send channel
		// exists only there (the receive side is the OnFlowAttr callback).
		s.flowAttrIn = make(chan []byte, 16)
	}
	if cfg.Main != nil {
		mp := cfg.Main
		s.main = newMainCodec(mp.SendKey, mp.RecvKey, mp.KeySize256, mp.VirtSrcPort, mp.VirtDstPort, mp.NPD, cfg.SSRC, cfg.CNAME, cfg.Bitmask)
		s.mainIn = make(chan inbound, 256)
		s.greVersion = gre.VersionMin // negotiated up to VersionCur on receiving a v2 frame
		s.localMAC = localHardwareMAC()
		s.eapClient = mp.EAPClient
		s.eapServer = mp.EAPServer
		s.useKeyAsPassphrase = mp.UseKeyAsPassphrase
		s.eapKeySize256 = mp.EAPKeySize256
		s.eapKeyRotation = mp.EAPKeyRotation
		if s.eapClient != nil || s.eapServer != nil {
			s.authed.Store(false) // hold the data channel until the handshake succeeds
			// Under use_key_as_passphrase the media key is derived from K during
			// the handshake; arm both EAP roles for that keying.
			if mp.UseKeyAsPassphrase {
				if s.eapClient != nil {
					s.eapClient.UseKeyAsPassphrase(true)
				}
				if s.eapServer != nil {
					s.eapServer.UseKeyAsPassphrase(true)
				}
			}
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
	return s
}

// start launches the reader goroutines and the event loop. The Main profile
// runs one reader on its single GRE socket; the Simple profile runs a reader
// per socket (RTCP always, media on a receiver).
func (s *Session) start() {
	s.wg.Add(1)
	go s.loop()
	// Separate-port FEC: read whichever of the column/row FEC sockets is bound. They are
	// guarded independently because column-only FEC binds the column socket alone (no +4
	// row port), so fecRow can be nil; reading a nil socket would panic the goroutine.
	if s.fecCol != nil {
		s.wg.Add(1)
		go s.readFEC(s.fecCol)
	}
	if s.fecRow != nil {
		s.wg.Add(1)
		go s.readFEC(s.fecRow)
	}
	for _, c := range s.fecSockets { // bonded separate-port FEC: one reader per path socket
		s.wg.Add(1)
		go s.readFEC(c)
	}
	if s.injected {
		return // a MultiReceiver owns the socket read and feeds Inject*
	}
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
			s.logAt(LogError, CatCrypto, "dtls: handshake failed: %v", err)
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
	// send NACKs) without waiting a full keepalive interval. A caller-receiver
	// (s.announce) does the symmetric thing: it announces itself to its seeded
	// peer.RTCP so a listening sender learns this receiver and starts streaming.
	if s.sender || s.announce {
		s.sendKeepalive(s.clk.Now())
	}
	// Anchor the LQM reporting period at start-up so the first report covers a
	// real interval rather than the whole epoch.
	s.lqmLast = s.clk.Now()
	// A Main-profile EAP authenticatee opens authentication with an EAPOL-START.
	// A caller knows its peer now, so it starts immediately; a listener authenticatee
	// has no peer yet and defers until one is learned (maybeStartEAP from the loop).
	s.maybeStartEAP(s.clk.Now())

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
			if pkt, err := s.mdec.decode(m.data); err == nil {
				s.feedMedia(now, 0, pkt)
				if s.fecEnabled() {
					// lastWireTS is the raw on-the-wire RTP timestamp, the value the FEC XOR is keyed on.
					s.fecRecvRTP(now, s.mdec.lastWireTS, pkt)
				}
			}
			s.afterInput(now, timer)
		case body := <-s.fecIn:
			now := s.clk.Now()
			s.fecOnRecvFEC(now, body)
			s.afterInput(now, timer)
		case r := <-s.rtcpIn:
			now := s.clk.Now()
			s.peer.LearnRTCP(r.src)
			s.inferSenderMediaFromRTCP()
			s.peer.Observe(now)
			if fbs, err := decodeFeedback(r.data, s.highestSent); err == nil {
				s.feedFeedback(now, fbs)
			}
			s.afterInput(now, timer)
		case d := <-s.mainIn:
			now := s.clk.Now()
			s.handleMainDatagram(now, d)
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
		case wc := <-s.weightCmd:
			// Apply a runtime load-balancing weight change on the loop goroutine,
			// which owns the bonding Group. It takes effect on the next media send.
			if s.bond != nil {
				s.bond.group.SetWeight(wc.path, wc.weight)
			}
		case p := <-appIn:
			now := s.clk.Now()
			s.pushApp(now, p)
			s.afterInput(now, timer)
		case od := <-s.oobIn:
			now := s.clk.Now()
			s.sendOOB(now, od)
			s.afterInput(now, timer)
		case fa := <-s.flowAttrIn:
			now := s.clk.Now()
			s.sendFlowAttr(now, fa)
			s.afterInput(now, timer)
		case <-timer.C:
			now := s.clk.Now()
			s.fireTimers(now)
			s.afterInput(now, timer)
		case <-ticker.C:
			now := s.clk.Now()
			// Liveness / teardown. A NAT-rebind or in-band EAP re-auth holds media on an
			// as-yet-unproven tuple; while that re-auth window is open the ordinary
			// Expired() teardown is SUPPRESSED so a genuine re-auth gets its full
			// round-trip. The rebind only fires once the old tuple is already dormant
			// (silent > 2x keepalive == the session timeout by default), so without this
			// suppression Expired() would fire on the very next tick and tear the recovery
			// down before the handshake could complete. When the window closes without a
			// completed re-auth, the session IS torn down: a stalled or forged re-auth can
			// never complete, and an unproven/forged tuple must not keep the session alive
			// (a frozen-lastSeen heuristic does not hold once the migrated tuple's own
			// datagrams refresh it) — a fresh reconnect re-establishes the session cleanly.
			// The deadline is polled here at keepalive granularity; reauthTimeout is sized
			// well above the keepalive interval so the slack is bounded.
			if s.reauthing {
				if now.After(s.reauthDeadline) {
					s.reauthing = false
					s.logAt(LogNote, CatCrypto, "nat-rebind: re-auth timed out; tearing down (awaiting a fresh connection)")
					s.shutdown(s.cfg.ErrSessionTimeout)
					return
				}
			} else if s.peer.Expired(now) {
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
			} else if s.peer.RTCP.IsValid() && !s.reauthing && (s.adv != nil || now.Sub(s.lastTx) >= ka) {
				// Suppressed during a re-auth (like the GRE keepalive below): the peer
				// tuple is unproven then, so a full RTCP compound (SR/RR + SDES + RTT echo)
				// must not be reflected to it — only the EAPOL handshake is sent.
				s.sendKeepalive(now)
			}
			// Main profile (non-bonded): also emit the periodic GRE keepalive (the
			// node-MAC + capability beacon), at the negotiated GRE version. It is
			// distinct from the RTCP keepalive above (libRIST runs both timers).
			// Bonded sessions drive their own per-path keepalives. Suppressed during a
			// NAT-rebind re-auth: the peer tuple is unproven then, and only the EAPOL
			// handshake (not the periodic beacon) should be sent to it — so a forged
			// trigger carrying a victim source cannot turn this into a reflection.
			if s.main != nil && s.bond == nil && s.peer.RTCP.IsValid() && !s.reauthing {
				s.sendGREKeepalive(s.greVersion)
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
	s.publishStats()
}

// publishStats copies the flow's current counters into the published snapshot
// for the public Stats() reader. It runs on the loop goroutine after every
// input and allocates nothing: the snapshot struct is reused under statsMu.
func (s *Session) publishStats() {
	v := s.flow.Stats()
	s.statsMu.Lock()
	s.statsVal = v
	s.statsMu.Unlock()
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
	// Suppress reflected feedback (NACKs, echoes) toward an unauthenticated peer:
	// before the EAP-SRP handshake completes authed is false, so a spoofed source
	// cannot elicit reflected datagrams (M7). feedMedia already withholds pre-auth
	// media, so fbs is normally empty here; this is the matching belt-and-braces
	// on the emit side. For non-authenticated sessions authed is always true.
	if len(fbs) > 0 && s.authed.Load() {
		s.sendFeedback(fbs, now)
	}
	for {
		ev, ok := s.flow.PollEvent()
		if !ok {
			break
		}
		if d, ok := ev.(flow.Deliver); ok {
			s.deliverFragment(d)
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
	if !s.peer.Media.IsValid() {
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
		s.logAt(LogWarning, CatSocket, "write media: %v", err)
	}
	s.lastTx = now
	if s.fecEnabled() {
		s.fecOnSend(now, pkt, b) // generate row/column FEC from this original media
	}
}

// inferSenderMediaFromRTCP gives a Simple-profile listener-sender its media
// destination once it has learned the receiver's RTCP source. The Simple profile
// puts media on an even port and RTCP on the adjacent odd port, so the receiver's
// media address is its RTCP address with the port decremented by one (the libRIST
// even/odd rule). A sender only reads its RTCP socket (never its media socket),
// so without this it would learn peer.RTCP but never peer.Media and sendMedia
// would hold forever. It is a no-op for a normal (dialing) sender, whose
// peer.Media is configured and thus already valid, and for the single-socket
// Main/Advanced profiles, whose inbound handlers learn both addresses at once.
func (s *Session) inferSenderMediaFromRTCP() {
	if !s.sender || s.peer.Media.IsValid() || !s.peer.RTCP.IsValid() {
		return
	}
	rt := s.peer.RTCP
	if rt.Port() == 0 {
		return
	}
	s.peer.Media = netip.AddrPortFrom(rt.Addr(), rt.Port()-1)
}

// sendFeedback builds one compound RTCP datagram from the drained feedback and
// transmits it to the peer's RTCP address.
func (s *Session) sendFeedback(fbs []wire.Feedback, now clock.Timestamp) {
	if s.cfg.OneWay {
		return // one-way transport emits no RTCP feedback, only media
	}
	if s.bond != nil {
		s.sendBondFeedback(fbs, now)
		return
	}
	if !s.peer.RTCP.IsValid() {
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
		// The SR NTP field is absolute wall-clock NTP (RFC 3550); the RTP
		// timestamp is taken from the same instant. See wallNTP.
		lead = rtcp.SenderReport{
			SSRC:    s.cfg.SSRC,
			NTP:     s.wallNTP(now),
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
		s.logAt(LogWarning, CatSocket, "write rtcp: %v", err)
	}
	s.lastTx = now
}

// wallNTP returns the absolute wall-clock NTP-64 value for instant now, for the
// RTCP Sender Report's NTP field (RFC 3550): a libRIST receiver in RTC timing
// mode derives time_offset from it, so a session-relative value would corrupt
// its playout (off by ~70 years). Deterministic test clocks that cannot report
// wall time fall back to the session-relative form (harmless: the receiver
// ignores SR contents at this stage and echo timestamps cancel the epoch).
func (s *Session) wallNTP(now clock.Timestamp) uint64 {
	if wc, ok := s.clk.(clock.WallClocker); ok {
		return uint64(wc.WallNTP(now))
	}
	return uint64(clock.NTPTimeFromTimestamp(now))
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
// units. It is informational — the peer ignores it (libRIST does not read the
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
// transmission. It reuses the same GRE+RTCP encoding WP6 proved interoperable;
// advGRE encrypts it under the PSK when one is configured.
func (s *Session) sendAdvGREHandshake(now clock.Timestamp) {
	if !s.peer.RTCP.IsValid() {
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
				// SMPTE 2022-1 FEC control message: route to the FEC decoder rather
				// than the feedback path (it is neither media nor RTCP feedback). A
				// fragmented control message (only FEC messages are fragmented) is
				// reassembled before its FEC body is decoded.
				if s.fecEnabled() && p.EncType == adv.TypeControl {
					if !p.FirstFrag || !p.LastFrag {
						full, ok := s.fecCtrlReasm.push(p.Seq, fecFragRole(p.FirstFrag, p.LastFrag), p.Payload)
						if ok {
							if ci, body, cerr := adv.ParseControl(full); cerr == nil && s.fecControlIndex(ci) {
								s.fecOnRecvFEC(now, body)
							}
						}
						return
					}
					if ci, body, cerr := adv.ParseControl(p.Payload); cerr == nil && s.fecControlIndex(ci) {
						s.fecOnRecvFEC(now, body)
						return
					}
				}
				if isMedia, pkt, fbs, derr := s.adv.decodeParsed(p); derr == nil {
					if isMedia {
						s.feedMedia(now, 0, pkt)
						if s.fecEnabled() {
							s.fecRecvAdv(now, pkt.Seq, data) // protect/recover the full wire datagram
						}
					} else {
						s.feedAdvFeedback(now, fbs)
					}
				} else {
					s.logAt(LogWarning, CatCrypto, "adv: drop undecodable adv datagram (%d bytes): %v", len(data), derr)
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
	if oob, proto, ok, oerr := s.advGRE.peekOOB(data); ok {
		if oerr != nil {
			s.logf("adv: drop undecodable OOB: %v", oerr)
		} else {
			s.deliverOOB(proto, oob)
		}
		return
	}
	isMedia, pkt, fbs, err := s.advGRE.decodeMain(data, s.highestSent)
	if err != nil {
		return // keepalive or otherwise not a GRE media/RTCP datagram; ignore
	}
	if isMedia {
		// libRIST does not send GRE-framed media in Advanced mode; accept it
		// defensively all the same.
		s.feedMedia(now, 0, pkt)
		return
	}
	s.feedAdvFeedback(now, fbs)
}

// feedAdvFeedback feeds decoded feedback to the flow on the Advanced path,
// dropping any inbound RTT-echo *request* first (see dropAdvEchoRequests).
func (s *Session) feedAdvFeedback(now clock.Timestamp, fbs []wire.Feedback) {
	s.feedFeedback(now, dropAdvEchoRequests(fbs))
}

// dropAdvEchoRequests removes inbound RTT-echo requests from an Advanced-path
// feedback slice so the flow never generates a response to them. Echoing such a
// request verbatim is spec-correct, but libRIST's Advanced-profile RTT-echo
// response handler mis-scales the NTP-64 round-trip — it shifts the fractional
// diff by 16 instead of 32, inflating the measured RTT by 2^16. A response from
// us therefore poisons libRIST's peer last_rtt to hundreds of seconds, which
// jams its own retransmit re-queue gate (it refuses a re-NACK while delta <
// rtt), so a single dropped retransmit is never re-sent and one packet is
// permanently lost under loss. Not answering keeps libRIST's last_rtt at its
// sane default and recovery works; ristgo still originates its own RTT-echo
// requests (scaled correctly by both ends), so this does not affect ristgo's
// RTT estimation. Advanced-only — the Main/Simple RTT echo uses libRIST's
// correct path and must keep answering for those estimators to converge. It
// reuses the input backing array (the caller does not retain fbs).
func dropAdvEchoRequests(fbs []wire.Feedback) []wire.Feedback {
	filtered := fbs[:0]
	for _, fb := range fbs {
		if _, isEchoReq := fb.(wire.RttEchoRequest); isEchoReq {
			continue
		}
		filtered = append(filtered, fb)
	}
	return filtered
}

// sendOOB encodes one out-of-band datagram (GRE FULL framing, PSK-encrypted when
// configured) and writes it to the learned peer. OOB is a Main/Advanced-only
// side channel that bypasses the flow core (no ARQ); it is dropped, with a log,
// before the peer's address is known.
func (s *Session) sendOOB(now clock.Timestamp, od oobData) {
	if !s.peer.Media.IsValid() {
		s.logf("oob: peer not learned yet, dropping %d-byte datagram", len(od.data))
		return
	}
	var (
		b   []byte
		err error
	)
	switch {
	case s.main != nil:
		b, err = s.main.encodeOOB(nil, od.data, od.proto)
	case s.advGRE != nil:
		b, err = s.advGRE.encodeOOB(nil, od.data, od.proto)
	default:
		return // not a Main/Advanced session
	}
	if err != nil {
		s.logf("oob: encode: %v", err)
		return
	}
	if err := s.conn.WriteMedia(b, s.peer.Media); err != nil {
		s.logf("oob: write: %v", err)
		return
	}
	s.lastTx = now
}

// sendFlowAttr emits one Advanced Flow Attribute control message (CI 0x8001,
// TR-06-3 §5.3.7) carrying the application's JSON body to the peer. Like the
// Advanced keepalive/feedback it rides the control target (peer.RTCP); it is
// dropped, with a log, before the peer's return address is known. Advanced only —
// the loop only selects on flowAttrIn for an Advanced session, where s.adv is set.
func (s *Session) sendFlowAttr(now clock.Timestamp, json []byte) {
	if s.adv == nil {
		return
	}
	if !s.peer.RTCP.IsValid() {
		s.logf("flowattr: peer not learned yet, dropping %d-byte attribute", len(json))
		return
	}
	dg, err := s.adv.frameControl(nil, adv.BuildFlowAttr(nil, json), advCtrlTS(now))
	if err != nil {
		s.logf("flowattr: encode: %v", err)
		return
	}
	if err := s.conn.WriteMedia(dg, s.peer.RTCP); err != nil {
		s.logf("flowattr: write: %v", err)
		return
	}
	s.lastTx = now
}

// oobData is one out-of-band datagram and the GRE protocol type (EtherType) it
// is tunnelled under, carried on the oobIn/oobOut channels so the protocol type
// survives the application round trip.
type oobData struct {
	proto uint16
	data  []byte
}

// deliverOOB queues a received OOB payload (tagged with its protocol type) for
// ReadOOB, copying it (the decode buffer is reused downstream) and dropping it
// non-blocking if the consumer is too slow — OOB is best-effort and must never
// stall the media event loop.
func (s *Session) deliverOOB(proto uint16, oob []byte) {
	cp := append([]byte(nil), oob...)
	select {
	case s.oobOut <- oobData{proto: proto, data: cp}:
	default:
		s.logf("oob: receive queue full, dropping %d-byte datagram", len(oob))
	}
}

// localHardwareMAC returns this host's first non-zero, non-loopback hardware
// (MAC) address for the GRE keepalive node-MAC field, or all-zeros if none is
// found. The MAC is informational in libRIST (it logs it and detects keepalive
// changes by it); it never drives routing or identity, so a zero MAC is harmless.
func localHardwareMAC() [6]byte {
	var mac [6]byte
	ifaces, err := net.Interfaces()
	if err != nil {
		return mac
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) != 6 {
			continue
		}
		var cand [6]byte
		copy(cand[:], ifc.HardwareAddr)
		if cand != ([6]byte{}) {
			return cand
		}
	}
	return mac
}

// sendGREKeepalive emits one GRE keepalive advertising this node's MAC and
// capability bits at the given GRE version (libRIST
// _librist_proto_gre_send_keepalive). It is the Main-profile capability/liveness
// localCaps returns the Main-profile keepalive capabilities this session
// advertises: the standard set, plus the SMPTE-2022 FEC flag (P) when FEC is
// enabled, so a peer learns FEC is in use (TR-06-2 keepalive Capability Flags).
func (s *Session) localCaps() gre.Capabilities {
	caps := gre.StandardCapabilities()
	if s.fecEnabled() {
		caps.P = true
	}
	return caps
}

// beacon, distinct from the periodic RTCP. A no-op until the peer is learned.
func (s *Session) sendGREKeepalive(version uint8) {
	if s.cfg.OneWay {
		return // one-way transport emits no GRE keepalive, only media
	}
	if s.main == nil || !s.peer.RTCP.IsValid() {
		return
	}
	ka := gre.Keepalive{MAC: s.localMAC, Caps: s.localCaps()}
	b, err := s.main.encodeKeepalive(nil, ka, version)
	if err != nil {
		s.logf("gre keepalive encode: %v", err)
		return
	}
	if err := s.conn.WriteMedia(b, s.peer.RTCP); err != nil {
		s.logf("gre keepalive write: %v", err)
	}
}

// sendGREKeepaliveBurst sends the connect-time probe: three version-2
// (VSF-wrapped) keepalives then three version-1 keepalives, so a v2-capable peer
// upgrades while a v1-only peer still hears us (libRIST's dual-version probe). A
// sender also advertises its max buffer via buffer negotiation.
func (s *Session) sendGREKeepaliveBurst() {
	if s.main == nil || !s.peer.RTCP.IsValid() {
		return
	}
	for i := 0; i < 3; i++ {
		s.sendGREKeepalive(gre.VersionCur)
	}
	for i := 0; i < 3; i++ {
		s.sendGREKeepalive(gre.VersionMin)
	}
	if s.sender {
		s.sendBufferNegotiation()
	}
}

// sendBufferNegotiation advertises this sender's maximum buffer (recovery window
// + 2*rtt_min, libRIST sender_recover_min_time), three times for datagram
// redundancy. Version 2 only.
func (s *Session) sendBufferNegotiation() {
	if s.cfg.OneWay {
		return // one-way transport emits no buffer negotiation, only media
	}
	if s.main == nil || !s.peer.RTCP.IsValid() || !s.sender {
		return
	}
	maxMs := uint16((s.cfg.Flow.RecoveryBufferMax + 2*s.cfg.Flow.RTTMin) / clock.Millisecond)
	bn := gre.BufferNegotiation{SenderMaxMs: maxMs}
	for i := 0; i < 3; i++ {
		if b, err := s.main.encodeBufferNeg(nil, bn); err == nil {
			_ = s.conn.WriteMedia(b, s.peer.RTCP)
		}
	}
}

// handleGREControl records the peer's capabilities and MAC from an inbound GRE
// keepalive. (The monotonic version upgrade is driven separately from every
// datagram's GRE-header version; see upgradeGREVersion.)
func (s *Session) handleGREControl(ka gre.Keepalive) {
	s.remoteCaps = ka.Caps
	s.remoteMAC = ka.MAC
}

// upgradeGREVersion applies libRIST's monotonic version-upgrade rule: adopt a
// higher GRE version observed from the peer (never downgrade), and on the first
// crossing past VersionMin kick off buffer negotiation on a sender.
func (s *Session) upgradeGREVersion(version uint8) {
	if version <= s.greVersion || version > gre.VersionCur {
		return
	}
	crossing := s.greVersion == gre.VersionMin
	s.greVersion = version
	s.logf("gre: negotiated up to version %d", version)
	if crossing && s.sender {
		s.sendBufferNegotiation()
	}
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
	// Install any data-channel keying material the handshake produced under
	// use_key_as_passphrase BEFORE opening the gate, so the first media datagram
	// is already keyed. This polls the role each step: the TX key is installed at
	// M1/M2 and the RX key on processing the peer's validator, so by SUCCESS both
	// are available.
	wasAuthed := s.authed.Load()
	s.installEAPKeying()
	switch {
	case role.Authenticated():
		// SUCCESS — the initial handshake, or a NAT-rebind / in-band re-auth just
		// completed and re-proved the tuple. The authenticatee drives the post-SUCCESS
		// PASSWORD_REQUEST once, after installing its keys (eap_request_passphrase on
		// SUCCESS).
		s.maybeSendPasswordRequest(now)
		s.authed.Store(true)
		s.everAuthed = true
		s.reauthing = false // any re-auth is now proven and complete
		// On the transition to authenticated under use_key_as_passphrase, send an
		// immediate keepalive (a GRE MAC beacon and, on a receiver, the RTCP SDES
		// handshake) so the peer gets fresh liveness — now keyed under K on a
		// receiver — without waiting a full keepalive interval. libRIST's
		// liveness window is tight right after auth (it is "Waiting for EAP
		// authentication"); a prompt beacon keeps it from aging the peer out and
		// cycling, which would drop the first media burst.
		if !wasAuthed && s.useKeyAsPassphrase {
			s.sendPostAuthBeacon(now)
		}
	case role.Done():
		// A terminal state without success means authentication failed. An initial
		// failure (never authenticated) tears the session down (ErrAuth). A failure AFTER
		// a prior success is a re-authentication failure (e.g. a forged/replayed re-auth
		// that could not complete the fresh handshake): HOLD media (authed false) and keep
		// the re-auth window armed so the ticker abandons it at reauthDeadline — never
		// deliver under the failed handshake, and never leave an unproven tuple holding
		// the session open indefinitely.
		if !s.everAuthed {
			s.shutdown(s.cfg.ErrAuth)
			return
		}
		s.authed.Store(false)
		if !s.reauthing {
			s.reauthing = true
			s.reauthDeadline = now.Add(s.reauthTimeout())
		}
		s.logAt(LogNote, CatCrypto, "eap: re-auth failed; media held pending re-proof or timeout")
	default:
		// The role is mid-handshake (StateInProgress/Unauth). If it had authenticated
		// before, an inbound EAPOL frame just regressed it OUT of SUCCESS — an in-band
		// re-auth: the genuine peer re-proving after its own rebind/restart (it honors a
		// peer-driven IDENTITY REQUEST / START, which is required for the rebind recovery
		// to work), OR a forged EAPOL frame spoofed from the peer's tuple (EAPOL is never
		// encrypted). Either way the tuple is no longer proven, so DROP authed and hold
		// media until the fresh handshake re-proves identity. Arming the re-auth window
		// bounds a stalled or forged re-auth (the ticker tears it down at reauthDeadline)
		// instead of silently delivering under a desynced handshake — the same hold the
		// gated NAT-rebind path uses. A forger cannot complete the SRP exchange, so it can
		// at most force a bounded media gap, never receive media.
		if wasAuthed && s.everAuthed {
			s.authed.Store(false)
			if !s.reauthing {
				s.reauthing = true
				s.reauthDeadline = now.Add(s.reauthTimeout())
				s.logAt(LogNote, CatCrypto, "eap: re-auth in progress; media held pending re-proof")
			}
		}
	}
}

// sendPostAuthBeacon sends an immediate liveness/handshake burst the instant the
// EAP-SRP handshake authenticates under use_key_as_passphrase: the GRE keepalive
// (MAC beacon) plus, on a receiver, the RTCP keepalive (the SDES the peer needs to
// authenticate our RTCP peer and ungate media). Both now ride the K-derived key
// on a receiver. The RTCP/SDES is sent a few times for datagram redundancy: it is
// the gate that lets a libRIST sender start streaming, and a single lost copy in
// the narrow post-auth window would otherwise delay the stream by a full keepalive
// interval (or, with cycling, drop the opening burst).
func (s *Session) sendPostAuthBeacon(now clock.Timestamp) {
	if s.main == nil || !s.peer.RTCP.IsValid() {
		return
	}
	s.sendGREKeepalive(s.greVersion)
	for i := 0; i < 3; i++ {
		s.sendKeepalive(now)
	}
}

// installEAPKeying derives and installs the Main media PSK keys from the SRP
// session key K when the EAP-SRP use_key_as_passphrase mode produced new keying
// material. It is idempotent: each direction is re-keyed only when its keying
// generation advances (so a rollover with a repeated K still re-derives, and an
// unchanged generation is a no-op). The send key is derived with NewKeyRaw and
// the receive key with NewDecryptorRaw (no NUL-truncation — K is a raw digest),
// matching libRIST's _librist_crypto_psk_set_passphrase, which hashes the full
// 32 K bytes. K never reaches a log here.
func (s *Session) installEAPKeying() {
	if !s.useKeyAsPassphrase || s.main == nil {
		return
	}
	var (
		tx, rx     eap.Passphrase
		haveTx     bool
		haveRx     bool
		keyBits    = crypto.KeySize128
		keySize256 = s.eapKeySize256
	)
	if keySize256 {
		keyBits = crypto.KeySize256
	}
	switch {
	case s.eapClient != nil:
		tx, haveTx = s.eapClient.TxKeying()
		rx, haveRx = s.eapClient.RxKeying()
	case s.eapServer != nil:
		tx, haveTx = s.eapServer.TxKeying()
		rx, haveRx = s.eapServer.RxKeying()
	}
	if haveTx && tx.Gen != s.txKeyGen {
		k, err := crypto.NewKeyRaw(tx.Key, keyBits, s.eapKeyRotation, false)
		if err != nil {
			s.logAt(LogError, CatCrypto, "eap: derive send key from session key: %v", err)
		} else {
			s.main.setSendKey(k, keySize256)
			s.txKeyGen = tx.Gen
		}
	}
	if haveRx && rx.Gen != s.rxKeyGen {
		d, err := crypto.NewDecryptorRaw(rx.Key, keyBits)
		if err != nil {
			s.logAt(LogError, CatCrypto, "eap: derive recv key from session key: %v", err)
		} else {
			s.main.setRecvKey(d)
			s.rxKeyGen = rx.Gen
		}
	}
}

// maybeSendPasswordRequest sends the authenticatee's one-shot post-SUCCESS EAP
// PASSWORD_REQUEST (subtype 0x10) soliciting the receiver's data-channel keying
// confirmation. libRIST's authenticatee (the RIST sender) issues it once on
// verifying M2 / reaching SUCCESS (eap_request_passphrase, from
// process_eap_request_srp_server_validator); the authenticator answers with a
// PASSWORD_RESPONSE the handleEAP path routes back, which keys the authenticatee's
// RX. A no-op for the authenticator role or when not in use_key_as_passphrase mode.
func (s *Session) maybeSendPasswordRequest(now clock.Timestamp) {
	if s.eapClient == nil || !s.useKeyAsPassphrase || s.pwReqSent {
		return
	}
	if f, ok := s.eapClient.PasswordRequest(); ok {
		s.pwReqSent = true
		s.sendEAP(f, now)
	}
}

// maybeStartEAP emits the authenticatee's EAPOL-Start exactly once, as soon as the
// peer's address is known. A caller authenticatee satisfies this at loop start; a
// listener authenticatee only after it learns the caller from inbound traffic. A no-op
// for a session with no EAP authenticatee, after the Start was already sent, or while
// the peer is still unknown.
func (s *Session) maybeStartEAP(now clock.Timestamp) {
	if s.eapClient == nil || s.eapStartSent || !s.peer.Media.IsValid() {
		return
	}
	s.sendEAP(s.eapClient.Start(), now)
	s.eapStartSent = true
}

// handleMainDatagram processes one inbound Main-profile datagram. It first offers it to the
// NAT source-port rebind recovery: on an authenticated SRP session a datagram from a source
// other than the established peer is consumed there (re-associated under a fresh EAP-SRP
// re-auth, or ignored) instead of through first-source learning. For the established peer it
// learns the address, advances the GRE version, and dispatches keepalive / EAPOL / OOB /
// media / feedback.
func (s *Session) handleMainDatagram(now clock.Timestamp, d inbound) {
	if s.maybeReassociate(now, d.src, d.data) {
		return
	}
	// One GRE socket carries both directions, so the peer's media and
	// RTCP addresses are the one learned address.
	s.peer.LearnMedia(d.src)
	s.peer.LearnRTCP(d.src)
	s.peer.Observe(now)
	// A listener authenticatee can only EAPOL-Start once it has learned the
	// calling peer; a caller already started at loop entry (no-op here).
	s.maybeStartEAP(now)
	// Probe the GRE version with a dual-version keepalive burst the
	// instant the peer is learned, so a v2-capable peer can upgrade.
	if !s.greBurstSent && s.peer.RTCP.IsValid() {
		s.greBurstSent = true
		s.sendGREKeepaliveBurst()
	}
	// Apply the monotonic GRE-version upgrade from every datagram's
	// header version, and learn capabilities/MAC from a v1 keepalive.
	kind, ka, ver, cerr := s.main.peekControl(d.data)
	s.upgradeGREVersion(ver)
	if kind == controlKeepalive {
		if cerr != nil {
			s.logf("main: drop undecodable GRE keepalive: %v", cerr)
		} else {
			s.handleGREControl(ka)
		}
	} else if eapPayload, ok := s.main.peekEAPOL(d.data); ok {
		// Authentication frame: route to the EAP state machine.
		s.handleEAP(now, eapPayload)
	} else if oob, proto, ok, oerr := s.main.peekOOB(d.data); ok {
		// Tunnelled / out-of-band data: deliver via ReadOOB tagged with its
		// protocol type, bypassing the media flow entirely.
		if oerr != nil {
			s.logf("main: drop undecodable OOB (%d bytes): %v", len(d.data), oerr)
		} else {
			s.deliverOOB(proto, oob)
		}
	} else if isMedia, pkt, fbs, err := s.main.decodeMain(d.data, s.highestSent); err == nil {
		if isMedia {
			s.feedMedia(now, 0, pkt)
			if s.fecEnabled() {
				// FEC over the decoded inner RTP payload (TR-06-2 §8.6);
				// lastWireTS is the raw inner RTP timestamp.
				s.fecRecvRTP(now, s.main.dec.lastWireTS, pkt)
			}
		} else {
			s.feedFeedback(now, fbs)
		}
	} else {
		// A decode failure on an otherwise-delivered datagram usually
		// means a PSK secret or AES-key-size mismatch (decryption yields
		// garbage), which would otherwise look like total packet loss.
		// Surface it so it is diagnosable; logf is zero-cost when no
		// logger is set.
		s.logAt(LogWarning, CatCrypto, "main: drop undecodable datagram (%d bytes): %v", len(d.data), err)
	}
}

// sameSource reports whether src is the established peer's tuple (for Main the media and
// RTCP addresses are the one learned address).
func (s *Session) sameSource(src netip.AddrPort) bool {
	return addrPortEqual(src, s.peer.Media) || addrPortEqual(src, s.peer.RTCP)
}

// mainReassocTrigger reports whether data is a valid NAT-rebind re-association trigger from
// a new source: an ENCRYPTED RTCP feedback datagram that decrypts under the per-peer session
// key AND carries the established peer's CNAME. The decrypt-under-key is the unforgeable
// proof a forger (no key) cannot produce, and it is required to be ENCRYPTED so a cleartext
// sender (use_key_as_passphrase media) or a cleartext-RTCP forger cannot supply a matching
// CNAME either; the CNAME match is libRIST's identity key. It does NOT advance the media
// decoder (feedbackCNAME parses only the RTCP, leaving the sequence/timestamp reconstruction
// untouched), so probing a datagram that is then dropped cannot corrupt media decode. EAPOL
// (forgeable, never encrypted) and media (no SDES, may be cleartext) are NOT triggers. (A
// replay carries the genuine CNAME, so this still does not prove liveness — the forced
// re-auth that follows does; this gate only blocks the trivially-forged triggers.)
//
// Direction limit: because the trigger must be ENCRYPTED, it detects a peer rebind only when
// that peer's RTCP is keyed. Under bare use_key_as_passphrase (Username, no Secret) only the
// receiver->sender feedback is keyed, so a SENDER rebind toward a receiver carries cleartext
// RTCP and is NOT detected here (it falls back to session-timeout + reconnect); both
// directions are covered when SRP runs with an explicit Secret (a symmetric PSK keys both).
func (s *Session) mainReassocTrigger(data []byte) bool {
	if s.main == nil || s.peerCNAME == "" {
		return false
	}
	cname, ok := s.main.feedbackCNAME(data)
	return ok && cname == s.peerCNAME
}

// maybeReassociate recovers a NAT source-port rebind on an authenticated single-flow
// EAP-SRP session. It returns true when it has consumed the datagram — by starting a
// re-association OR by ignoring a datagram from a source other than the established peer —
// so the caller skips the normal first-source-wins learning for it; false lets the normal
// path run (non-SRP, still-forming, or the established peer).
//
// Security (mirrors libRIST issue #188 / faa39c4, SRP only): a tuple change is honored only
// when an authenticated per-peer SRP session is in force, the established tuple is DORMANT
// (silent > 2x the keepalive interval), and the datagram is a valid trigger (see
// mainReassocTrigger: an ENCRYPTED RTCP feedback that decrypts under the session key and
// carries the peer's CNAME — EAPOL and cleartext media are NOT triggers, so a forger with no
// key cannot force a re-auth). Even then the new tuple is NOT trusted: the address migrates
// and a fresh EAP-SRP RE-AUTH is forced with media held (authed dropped), so a replay or
// forger that cannot complete the handshake never receives media. The held re-auth is bounded
// by reauthDeadline (the ticker tears the session down if it does not complete), so an
// unproven/forged tuple cannot pin the session open and a stalled re-auth cannot wedge it;
// the genuine peer recovers either by completing the re-auth or via a fresh connection. Under
// plaintext or a shared PSK (no per-peer SRP) the CNAME and source are forgeable, so a rebind
// is left to the caller-side socket-rebind path.
//
// Scope: single-flow Main sessions only. A demultiplexing MultiReceiver keys flows by source
// address, so a rebinding peer there surfaces as a NEW flow (a fresh Accept that re-runs the
// handshake) rather than reaching this path — the old flow simply ages out on timeout.
//
// Cost: media is held for the re-auth round trip; a rebind that takes longer than the
// recovery buffer leaves a real gap (the held media ages out of the ring), which is why the
// buffer should exceed the expected re-auth time. This is the deliberate trade for not
// delivering to an unproven tuple.
func (s *Session) maybeReassociate(now clock.Timestamp, src netip.AddrPort, data []byte) bool {
	if !s.srpAuthenticated() || !s.peer.RTCP.IsValid() || s.sameSource(src) {
		return false
	}
	if s.reauthing || !s.peer.SilentFor(now, 2*s.cfg.KeepaliveInterval) || !s.mainReassocTrigger(data) {
		return true // re-auth already in flight, the peer is still live, or not a valid trigger: ignore
	}
	s.peer.Rebind(src)
	s.reauthing = true
	s.reauthDeadline = now.Add(s.reauthTimeout())
	s.authed.Store(false) // hold media until the migrated tuple re-proves identity
	s.pwReqSent = false   // the post-SUCCESS PASSWORD exchange must re-run on the fresh handshake
	if s.eapClient != nil {
		s.eapClient.Restart()
	}
	if s.eapServer != nil {
		s.eapServer.Restart()
	}
	s.startReauth(now)
	s.logAt(LogNote, CatSession, "nat-rebind: peer moved to %v; forcing EAP-SRP re-auth", src)
	return true
}

// reauthTimeout is the window a NAT-rebind / in-band re-auth is given to complete before the
// session is torn down (so a stalled handshake — a lost frame, or a forger that never
// completes — cannot wedge the session, and an unproven tuple cannot hold it open). It is the
// larger of the recovery buffer (held media that outlives the buffer is lost anyway) and
// 4 keepalive intervals (a floor comfortably above a handshake round-trip, so a genuine
// re-auth is never cut off, and well above the keepalive-granularity poll that enforces it).
func (s *Session) reauthTimeout() clock.Microseconds {
	return max(s.cfg.Flow.RecoveryBufferMax, 4*s.cfg.KeepaliveInterval)
}

// startReauth re-opens the EAP-SRP handshake to the (migrated) peer: the authenticatee
// re-emits its EAPOL-Start; the authenticator re-issues an IDENTITY REQUEST.
func (s *Session) startReauth(now clock.Timestamp) {
	switch {
	case s.eapClient != nil:
		s.eapStartSent = false
		s.maybeStartEAP(now)
	case s.eapServer != nil:
		s.sendEAP(s.eapServer.Start(), now)
	}
}

// sendEAP frames an EAP frame as a GRE EAPOL datagram and sends it to the peer
// over the single Main socket. EAPOL is never encrypted.
func (s *Session) sendEAP(f eap.Frame, now clock.Timestamp) {
	if s.main == nil || !s.peer.Media.IsValid() {
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

// pushApp feeds one application payload to the flow core, splitting it across
// consecutive sequences when fragmentation is enabled (Advanced profile) and
// the payload exceeds the configured fragment size. Each fragment is an
// independently recoverable sequence tagged with its F/L role; the receiver
// reassembles them. Without fragmentation, or for a payload that already fits,
// it is a single unfragmented PushApp. p is a session-owned buffer (Write
// copied it), so the fragment subslices the flow retains stay valid.
func (s *Session) pushApp(now clock.Timestamp, p []byte) {
	if s.fragSize <= 0 || len(p) <= s.fragSize {
		s.flow.PushApp(now, p)
		return
	}
	for off := 0; off < len(p); off += s.fragSize {
		end := off + s.fragSize
		if end > len(p) {
			end = len(p)
		}
		var role wire.FragRole
		switch {
		case off == 0:
			role = wire.FragFirst
		case end == len(p):
			role = wire.FragLast
		default:
			role = wire.FragMiddle
		}
		s.flow.PushAppFrag(now, p[off:end], role)
	}
}

// deliverFragment reassembles a fragmented Advanced payload before queueing it
// for Read. The flow core delivers fragments in sequence order carrying their
// F/L role; the reassembler concatenates a FragFirst..FragLast run, and a
// Discontinuity (a lost fragment) or a fragment with no open run drops the
// partial run — the application sees the same gap any unrecovered loss
// produces. An unfragmented payload (FragStandalone) passes straight through,
// so non-Advanced sessions and unfragmented Advanced streams are unaffected.
func (s *Session) deliverFragment(d flow.Deliver) {
	if out, ready := s.reasm.push(d.Frag, d.Payload, d.Discontinuity); ready {
		s.queueDelivery(out) // copies internally before reasm's buffer is reused
	}
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

// LogLevel is the severity of a session diagnostic; the host maps it to the
// public ristgo.LogLevel. Values are ordered least-to-most severe.
type LogLevel int

// Session log severities.
const (
	LogDebug LogLevel = iota
	LogNote
	LogWarning
	LogError
)

// LogCategory tags a session diagnostic by subsystem; the host maps it to the
// public ristgo.LogCategory.
type LogCategory int

// Session log categories.
const (
	CatSession LogCategory = iota
	CatCrypto
	CatSocket
	CatRTCP
	CatFlow
	CatBonding
)

// logf emits a routine diagnostic (LogDebug / CatSession) if a logger is
// configured. Use logAt to emit at a different severity or category.
func (s *Session) logf(format string, args ...any) {
	s.logAt(LogDebug, CatSession, format, args...)
}

// logAt emits a diagnostic at the given severity and category if a logger is
// configured. It is zero-cost (no formatting) when no logger is set.
func (s *Session) logAt(level LogLevel, category LogCategory, format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(level, category, format, args...)
	}
}

// seqAfter reports whether a is circularly after b (wrap-aware).
func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// stopTimer stops t. Under Go 1.23+ timer semantics Stop guarantees no stale
// value is delivered after it returns, so no channel drain is needed.
func stopTimer(t *time.Timer) { t.Stop() }

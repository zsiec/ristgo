package ristgo

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/zsiec/ristgo/internal/session"
	"github.com/zsiec/ristgo/internal/socket"
)

// MaxMediaPayload is the largest payload a single Write may submit. The Simple
// profile sends one RTP packet per Write with no fragmentation, so the payload
// plus the 12-byte RTP header and the UDP/IPv4 headers must fit a standard
// 1500-byte MTU without IP fragmentation: 1500 − 20 (IP) − 8 (UDP) − 12 (RTP)
// = 1460. This is an UPPER bound (the Simple-profile ceiling), not a portable
// one: the Main profile adds ~12–16 bytes of GRE + reduced-overhead framing
// (plus the nonce when encrypted), and DTLS adds ~37 bytes (record header,
// explicit nonce, GCM tag), so a payload at this limit is IP-fragmented on a
// strict-MTU path. For a payload size safe on EVERY profile (Simple, Main,
// Advanced, and Main+DTLS), keep each Write at or below SafeMediaPayload.
const MaxMediaPayload = 1460

// SafeMediaPayload is the largest payload that fits without IP fragmentation on
// any profile, including Main+DTLS, on a standard 1500-byte MTU path. It is the
// 7-cell MPEG-TS payload (7 × 188) the example sender uses; callers that chunk
// to this size never fragment regardless of profile or encryption.
const SafeMediaPayload = 1316

// Sender transmits media to a RIST receiver. It is an io.WriteCloser: each
// Write submits one media payload (e.g. a batch of MPEG-TS packets), which the
// sender packetizes as RTP, transmits, and retains for retransmission until it
// ages out of the recovery buffer. Methods are safe for concurrent use with
// the sender's internal goroutines, but Write is not safe to call from
// multiple goroutines at once.
type Sender struct {
	sess    *session.Session
	remote  netip.AddrPort
	ctxStop func() // ends the context watcher (set by Dial); nil for New* constructors

	// maxWrite is the largest payload a single Write accepts. It is
	// MaxMediaPayload (one packet) unless FragmentSize is configured, in which
	// case a Write up to FragmentSize × maxFragmentsPerWrite is split into
	// fragments. Zero means the MaxMediaPayload default (the unfragmented case).
	maxWrite int
}

// maxFragmentsPerWrite bounds how many fragments one Write may split into when
// FragmentSize is configured, capping the per-Write payload and the burst of
// sequences it enqueues at once. It is the receiver's reassembly cap
// (session.MaxReassemblyFragments), shared so the sender can never split a Write
// into more fragments than the receiver will reassemble: the two are one value.
const maxFragmentsPerWrite = session.MaxReassemblyFragments

// NewSender dials a RIST receiver at addr ("host:port" or a rist:// URL whose
// query parameters override cfg) and returns a ready Sender. For the Simple
// profile the port is the receiver's even media port and RTCP feedback flows on
// port+1; for the Main and Advanced profiles a single port carries the flow
// (GRE-tunnelled for Main, RTP-based with native control for Advanced).
//
// See [Dial] for the context-aware constructor with functional options.
func NewSender(addr string, cfg Config) (*Sender, error) {
	return newSenderMode(addr, cfg, false)
}

// NewOneWaySender dials a RIST receiver at addr ("host:port" or a rist:// URL)
// and returns a Sender for one-way / no-return-channel transport: it streams
// media but never expects feedback. There is no ARQ recovery — the sender
// retains no retransmit history and emits no RTCP at all (no Sender Reports,
// SDES, RTT echoes, or keepalives), only media — so a lost packet is not
// recovered. Use it for satellite, broadcast, or strictly asymmetric paths with
// no return channel, paired with a [NewOneWayReceiver], which likewise sends
// nothing back.
//
// Supported on the Simple, Main, and Advanced profiles with optional PSK
// (Secret) encryption; DTLS and EAP-SRP are rejected, as their handshakes need
// a return channel. Because the receiver is silent by design, the sender never
// times out on peer silence.
func NewOneWaySender(addr string, cfg Config) (*Sender, error) {
	return newSenderMode(addr, cfg, true)
}

// newSenderMode is the shared body of NewSender and NewOneWaySender. oneWay
// disables ARQ (Flow.NoRecovery) and all RTCP egress (session OneWay).
func newSenderMode(addr string, cfg Config, oneWay bool) (*Sender, error) {
	addr, cfg, err := ParseURL(addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if oneWay && (cfg.DTLS != nil || cfg.Username != "") {
		return nil, fmt.Errorf("%w: DTLS and EAP-SRP are not supported in one-way mode", ErrInvalidConfig)
	}
	switch cfg.Profile {
	case ProfileSimple:
		return newSimpleSender(addr, cfg, oneWay)
	case ProfileMain:
		return newMainSender(addr, cfg, oneWay)
	case ProfileAdvanced:
		return newAdvSender(addr, cfg, oneWay)
	default:
		return nil, fmt.Errorf("%w: the %s profile is not implemented", ErrInvalidConfig, cfg.Profile)
	}
}

// newSimpleSender constructs a Simple-profile sender: RTP on the receiver's
// even media port, RTCP on port+1.
func newSimpleSender(addr string, cfg Config, oneWay bool) (*Sender, error) {
	host, port, err := resolveMediaPort(addr)
	if err != nil {
		return nil, err
	}
	mediaAddr, err := resolveAddrPort(host, port)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve media address: %w", ErrInvalidConfig, err)
	}
	rtcpAddr, err := resolveAddrPort(host, port+1)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve rtcp address: %w", ErrInvalidConfig, err)
	}
	conn, err := openSenderConn(false, mediaAddr.Addr(), cfg.LocalPort)
	if err != nil {
		return nil, err
	}
	if err := setSenderMulticast(conn, cfg, mediaAddr.Addr()); err != nil {
		conn.Close()
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq(cfg.SplitMode != SplitOff)
	fc.NoRecovery = oneWay
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.OneWay = oneWay
	applyRateAdapt(&sc, cfg)
	sess := session.NewSender(conn, mediaAddr, rtcpAddr, sc)
	return &Sender{sess: sess, remote: mediaAddr}, nil
}

// newMainSender constructs a Main-profile sender: the GRE-tunnelled flow (with
// optional PSK encryption) over the single port at addr.
func newMainSender(addr string, cfg Config, oneWay bool) (*Sender, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	remote, err := resolveAddrPort(host, port)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve address: %w", ErrInvalidConfig, err)
	}
	mp, err := buildMainParams(cfg)
	if err != nil {
		return nil, err
	}
	if mp.EAPClient, err = buildEAPClient(cfg); err != nil {
		return nil, err
	}
	conn, err := openSenderConn(true, remote.Addr(), cfg.LocalPort)
	if err != nil {
		return nil, err
	}
	if err := setSenderMulticast(conn, cfg, remote.Addr()); err != nil {
		conn.Close()
		return nil, err
	}
	if cfg.DTLS != nil {
		dcfg, err := buildDTLSConfig(cfg.DTLS, true)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn.EnableDTLSClient(net.UDPAddrFromAddrPort(remote), dcfg)
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq(cfg.SplitMode != SplitOff)
	fc.NoRecovery = oneWay
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.Main = mp
	sc.OneWay = oneWay
	applyRateAdapt(&sc, cfg)
	sess := session.NewMainSender(conn, remote, sc)
	return &Sender{sess: sess, remote: remote}, nil
}

// newAdvSender constructs an Advanced-profile sender: RTP-based media (with
// optional AES-CTR payload encryption and LZ4 compression) over the single port
// at addr, with native control messages on the same port.
func newAdvSender(addr string, cfg Config, oneWay bool) (*Sender, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	remote, err := resolveAddrPort(host, port)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve address: %w", ErrInvalidConfig, err)
	}
	ap, err := buildAdvParams(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := openSenderConn(true, remote.Addr(), cfg.LocalPort)
	if err != nil {
		return nil, err
	}
	if err := setSenderMulticast(conn, cfg, remote.Addr()); err != nil {
		conn.Close()
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq(cfg.SplitMode != SplitOff)
	fc.NoRecovery = oneWay
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.Adv = ap
	sc.OneWay = oneWay
	sc.FragmentSize = cfg.FragmentSize
	applyRateAdapt(&sc, cfg)
	sess := session.NewAdvSender(conn, remote, sc)
	maxWrite := 0
	if cfg.FragmentSize > 0 {
		maxWrite = cfg.FragmentSize * maxFragmentsPerWrite
	}
	return &Sender{sess: sess, remote: remote, maxWrite: maxWrite}, nil
}

// NewListenerSender binds addr ("host:port" or a rist:// URL) and returns a
// Sender that streams to a caller-mode receiver once it connects — the RIST
// listener-send mode. Unlike [NewSender], which dials a receiver at addr, this
// binds the well-known port(s) and waits: the receiver's address is learned from
// its inbound RTCP, so until a receiver appears RemoteAddr is unspecified and
// submitted media is held (the recovery buffer) or dropped rather than sent.
//
// DTLS is not supported in listener-send mode; PSK (Secret) encryption on the Main
// and Advanced profiles, and EAP-SRP on the Main profile (the listening sender is the
// authenticatee), are. See [ListenSender] for the context-aware constructor with
// functional options.
func NewListenerSender(addr string, cfg Config) (*Sender, error) {
	addr, cfg, err := ParseURL(addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, wrapInvalid(err)
	}
	if cfg.DTLS != nil {
		return nil, fmt.Errorf("%w: DTLS is not yet supported in listener-send mode", ErrInvalidConfig)
	}
	switch cfg.Profile {
	case ProfileSimple:
		return newSimpleListenerSender(addr, cfg)
	case ProfileMain:
		return newMainListenerSender(addr, cfg)
	case ProfileAdvanced:
		return newAdvListenerSender(addr, cfg)
	default:
		return nil, fmt.Errorf("%w: the %s profile is not implemented", ErrInvalidConfig, cfg.Profile)
	}
}

// newSimpleListenerSender binds the Simple-profile even/odd pair at addr and
// waits for a caller-receiver. peer.RTCP is learned from the receiver's reports
// and peer.Media inferred from it (even/odd), so media flows once it connects.
func newSimpleListenerSender(addr string, cfg Config) (*Sender, error) {
	host, port, err := resolveMediaPort(addr)
	if err != nil {
		return nil, err
	}
	conn, err := socket.Listen(host, port)
	if err != nil {
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq(cfg.SplitMode != SplitOff)
	sc := toSessionConfig(cfg, fc, ssrc)
	applyRateAdapt(&sc, cfg)
	sess := session.NewListenerSender(conn, sc)
	return &Sender{sess: sess}, nil
}

// newMainListenerSender binds the Main-profile single GRE port at addr and waits
// for a caller-receiver. With EAP-SRP credentials the listening sender is the
// authenticatee (it sends the EAPOL-Start once a caller is learned).
func newMainListenerSender(addr string, cfg Config) (*Sender, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	mp, err := buildMainParams(cfg)
	if err != nil {
		return nil, err
	}
	if mp.EAPClient, err = buildEAPClient(cfg); err != nil {
		return nil, err
	}
	conn, err := socket.ListenSingle(host, port)
	if err != nil {
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq(cfg.SplitMode != SplitOff)
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.Main = mp
	applyRateAdapt(&sc, cfg)
	sess := session.NewMainListenerSender(conn, sc)
	return &Sender{sess: sess}, nil
}

// newAdvListenerSender binds the Advanced-profile single port at addr and waits
// for a caller-receiver.
func newAdvListenerSender(addr string, cfg Config) (*Sender, error) {
	host, port, err := resolveSinglePort(addr)
	if err != nil {
		return nil, err
	}
	ap, err := buildAdvParams(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := socket.ListenSingle(host, port)
	if err != nil {
		return nil, err
	}
	ssrc := randomEvenSSRC()
	fc := toFlowConfig(cfg)
	fc.SSRC = ssrc
	fc.StartSeq = randomStartSeq(cfg.SplitMode != SplitOff)
	sc := toSessionConfig(cfg, fc, ssrc)
	sc.Adv = ap
	applyRateAdapt(&sc, cfg)
	sess := session.NewAdvListenerSender(conn, sc)
	return &Sender{sess: sess}, nil
}

// Write submits one media payload for transmission and returns len(p). The
// payload must be at most MaxMediaPayload bytes (one RTP packet), unless the
// Advanced-profile sender was built with a FragmentSize, in which case a payload
// up to FragmentSize × the internal fragment cap is split into independently
// recoverable fragments and reassembled by the receiver. A larger payload returns
// an error without sending, rather than silently failing on the wire. Write blocks
// only briefly under back-pressure; it does not wait for delivery (RIST is
// best-effort with ARQ recovery). After Close it returns ErrClosed.
func (s *Sender) Write(p []byte) (int, error) {
	if len(p) == 0 {
		// Conventional io.Writer no-op: a zero-length Write transmits nothing
		// rather than emitting an empty media packet on the wire.
		return 0, nil
	}
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

// SetWriteDeadline sets the deadline for future Write calls; a zero time
// clears it. Write returns ErrTimeout when the deadline passes.
func (s *Sender) SetWriteDeadline(t time.Time) error {
	s.sess.SetWriteDeadline(t)
	return nil
}

// WriteOOB sends one out-of-band datagram to the peer (Main and Advanced
// profiles). OOB is a fire-and-forget side channel: it rides the same socket as
// the media but bypasses ARQ recovery, so a lost OOB datagram is not
// retransmitted. The payload must be at most MaxMediaPayload bytes. It returns
// ErrOOBUnsupported on a Simple-profile sender.
//
// The payload is carried verbatim in a GRE full frame (protocol type 0x0800),
// byte-identical to libRIST's out-of-band data path. A complete IP packet, with
// its original headers including a multicast destination, therefore survives the
// tunnel intact: this is RIST stream IP preservation. The application builds and
// parses the IP packet; ristgo carries it transparently. Use [Sender.WriteOOBTyped]
// to tunnel a non-IP protocol identified by its own EtherType.
func (s *Sender) WriteOOB(p []byte) error { return writeOOBTyped(s.sess, OOBProtocolIP, p) }

// WriteOOBTyped is [Sender.WriteOOB] with an explicit GRE protocol type (EtherType)
// so the peer can dispatch on the encapsulated protocol — see [Receiver.ReadOOBTyped].
// proto [OOBProtocolIP] is the libRIST-interoperable default; any other non-reserved
// EtherType tunnels an arbitrary protocol between two ristgo peers (a libRIST peer
// drops it). It returns [ErrOOBProtocol] if proto is reserved for RIST framing.
func (s *Sender) WriteOOBTyped(proto uint16, p []byte) error { return writeOOBTyped(s.sess, proto, p) }

// WriteFlowAttribute sends an Advanced-profile Flow Attribute message (TR-06-3
// §5.3.7) carrying the UTF-8 JSON body to the receiver, which surfaces it to its
// [Config.OnFlowAttr] callback. It is opaque session/flow metadata sent
// fire-and-forget (no ARQ) — call it periodically if the application wants the
// receiver to stay current, the way libRIST emits one roughly every second. It
// returns [ErrFlowAttrUnsupported] on a Simple- or Main-profile sender, and blocks
// under back-pressure honoring the write deadline ([ErrTimeout]) and close
// ([ErrClosed]). The body is dropped, with a log, until the peer's address is
// learned (so send after the stream is flowing).
func (s *Sender) WriteFlowAttribute(json []byte) error { return s.sess.WriteFlowAttribute(json) }

// ReadOOB returns the next out-of-band datagram received from the peer,
// truncated to len(buf) (OOB is datagram-oriented, not a stream). It blocks
// until one arrives, the deadline passes (ErrTimeout), or the sender closes
// (ErrClosed). It returns ErrOOBUnsupported on a Simple-profile sender.
func (s *Sender) ReadOOB(buf []byte) (int, error) {
	n, _, err := s.sess.ReadOOB(buf)
	return n, err
}

// ReadOOBTyped is [Sender.ReadOOB] but also returns the datagram's GRE protocol
// type (EtherType), so an application tunnelling several protocols can dispatch on
// it. A datagram from libRIST, or a plain WriteOOB, reports [OOBProtocolIP].
func (s *Sender) ReadOOBTyped(buf []byte) (n int, proto uint16, err error) {
	return s.sess.ReadOOB(buf)
}

// Stats returns a snapshot of the sender's counters.
func (s *Sender) Stats() Stats {
	return withPeers(withFraming(toStats(s.sess.Stats()), s.sess), s.sess.PeerStats())
}

// Authenticated reports whether the data channel is open. For a Main-profile
// sender configured with EAP-SRP credentials it becomes true once the peer has
// authenticated it; otherwise it is always true.
func (s *Sender) Authenticated() bool { return s.sess.Authenticated() }

// RemoteAddr returns the receiver's media address.
func (s *Sender) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(s.remote) }

// SetNullPacketDeletion enables or disables null-packet deletion (NPD) on the send
// path at runtime — the counterpart of libRIST's rist_sender_npd_enable /
// rist_sender_npd_disable. NPD suppresses MPEG-TS null packets before transmission
// and signals their positions so the receiver reconstructs them byte-exact, shrinking
// the wire on a padded stream. It takes effect from the next submitted packet; the
// receiver always expands, so the toggle is one-sided. It returns ErrNPDUnsupported on
// a non-Main sender (NPD is a Main-profile feature) and the close reason once closed.
func (s *Sender) SetNullPacketDeletion(on bool) error { return s.sess.SetNullPacketDeletion(on) }

// SendBlock submits one media payload with explicit per-block metadata: an app-chosen
// sequence number (seq, libRIST's RIST_DATA_FLAGS_USE_SEQ) and/or source timestamp
// (sourceTime, NTP-64 bits — libRIST's ts_ntp). A nil pointer for either takes the
// flow's auto-incremented sequence or a now-derived timestamp, exactly like Write.
// Supplying both lets a transparent relay re-emit an upstream flow's packets preserving
// their (seq, sourceTime) — the pair a receiver's SMPTE 2022-7 merge and playout key
// on. payload is copied, so the caller may reuse the slice immediately. It returns
// ErrSendBlockUnsupported on a non-Main sender, or the close reason once closed.
func (s *Sender) SendBlock(payload []byte, seq *uint32, sourceTime *uint64) error {
	buf := make([]byte, len(payload))
	copy(buf, payload)
	// Deep-copy the overrides: they cross to the event loop asynchronously, so
	// forwarding the caller's pointers would race a caller that reuses the variable.
	var seqCopy *uint32
	if seq != nil {
		v := *seq
		seqCopy = &v
	}
	var stCopy *uint64
	if sourceTime != nil {
		v := *sourceTime
		stCopy = &v
	}
	return s.sess.SendBlock(buf, seqCopy, stCopy)
}

// Close stops the sender and releases its sockets and goroutines.
func (s *Sender) Close() error {
	if s.ctxStop != nil {
		s.ctxStop()
	}
	return s.sess.Close()
}

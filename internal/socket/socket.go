// Package socket is the UDP transport for RIST. The Simple profile (VSF
// TR-06-1) uses a pair of unconnected UDP sockets on adjacent even/odd ports —
// RTP media on the even port P, compound RTCP on the odd port P+1. The Main
// profile (TR-06-2) tunnels everything over a single GRE port; ListenSingle /
// ListenEphemeralSingle bind that one socket (the Conn's media and rtcp aliases
// then refer to it, and the session reads/writes it via ReadMedia/WriteMedia).
//
// The sockets are deliberately unconnected (net.ListenUDP, not DialUDP) and
// every send takes an explicit destination, so one transport serves both
// roles: a receiver binds the well-known port pair and learns the sender's
// source addresses from inbound datagrams, while a sender binds an ephemeral
// pair and addresses the receiver's well-known ports. Address learning and the
// even/odd split mirror libRIST (bind, address matching).
//
// This package only moves bytes; it never parses RTP/RTCP or touches the flow
// core. Read/Write are safe for concurrent use across the two sockets (each
// *net.UDPConn is independently goroutine-safe), which is how the host runs a
// reader goroutine per socket alongside the event loop.
package socket

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/zsiec/ristgo/internal/dtls"
)

// Conn is a RIST UDP transport. For the Simple profile it holds a media socket
// (even port) and an RTCP socket (odd port). For the Main profile it holds one
// socket carrying everything: media and rtcp both alias it and single is true.
type Conn struct {
	// media and rtcp are atomic.Pointers so the single media socket can be
	// hot-swapped under the reader goroutine by Rebind (caller-receiver NAT
	// recovery) without racing the per-datagram Read/Write path. For the Simple
	// profile they are distinct sockets; for the Main/Advanced profile both point
	// at the one GRE socket and single is true.
	media  atomic.Pointer[net.UDPConn]
	rtcp   atomic.Pointer[net.UDPConn]
	single bool

	// rebindGen counts caller-receiver socket rebinds (see Rebind). The session's
	// read loop reads it to distinguish a rebind-induced socket close — after which
	// it continues on the fresh socket — from a genuine teardown, on which it exits.
	rebindGen atomic.Uint64

	// DTLS transport security (Main profile, optional): when dtlsCfg is set,
	// Handshake establishes a DTLS 1.2 session over the single socket and
	// ReadMedia/WriteMedia carry the GRE tunnel as DTLS application records. See
	// dtls.go.
	dtlsCfg    *dtls.Config
	dtlsClient bool
	dtlsRemote *net.UDPAddr   // client role: the peer to converse with
	dtls       *dtls.Conn     // established by Handshake
	dtlsPeer   netip.AddrPort // known (client) or learned (server) peer address
}

// newConn builds a Conn from already-bound media and rtcp sockets (which alias the
// same socket when single is true), storing them into the atomic slots.
func newConn(media, rtcp *net.UDPConn, single bool) *Conn {
	c := &Conn{single: single}
	c.media.Store(media)
	c.rtcp.Store(rtcp)
	return c
}

// Listen binds the media socket to host:port and the RTCP socket to
// host:port+1. port must be even (TR-06-1 §4: the media port is even, RTCP is
// the adjacent odd port); port 0 is rejected because the pair cannot be
// derived from an ephemeral media bind. host may be empty to bind all
// interfaces. It is the receiver-side constructor.
func Listen(host string, port int) (*Conn, error) {
	if port <= 0 || port%2 != 0 {
		return nil, fmt.Errorf("rist: socket: media port %d must be a positive even number", port)
	}
	media, err := bind(host, port)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind media port %d: %w", port, err)
	}
	rtcp, err := bind(host, port+1)
	if err != nil {
		media.Close()
		return nil, fmt.Errorf("rist: socket: bind rtcp port %d: %w", port+1, err)
	}
	return newConn(media, rtcp, false), nil
}

// ListenEphemeral binds both sockets to OS-chosen ports on host (empty host
// binds all interfaces). It is the sender-side constructor: the sender's local
// ports are arbitrary; the receiver learns them from inbound datagrams.
func ListenEphemeral(host string) (*Conn, error) {
	media, err := bind(host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind media: %w", err)
	}
	rtcp, err := bind(host, 0)
	if err != nil {
		media.Close()
		return nil, fmt.Errorf("rist: socket: bind rtcp: %w", err)
	}
	return newConn(media, rtcp, false), nil
}

// ListenEphemeralEvenOdd binds an OS-chosen even media port and the adjacent odd
// RTCP port on host (empty host binds all interfaces). It is the Simple-profile
// caller-receiver constructor: a receiver that dials a listening sender still
// needs a local even/odd pair, because a Simple listener-sender infers the
// receiver's media address as its RTCP source port − 1 (the even/odd rule). A
// probe bind picks a free port; if it is odd the even neighbour below is tried,
// then port+1. The small TOCTOU window between probe and the real binds is
// tolerated by retrying.
func ListenEphemeralEvenOdd(host string) (*Conn, error) {
	var lastErr error
	for i := 0; i < 100; i++ {
		probe, err := bind(host, 0)
		if err != nil {
			lastErr = err
			continue
		}
		p := probe.LocalAddr().(*net.UDPAddr).Port
		probe.Close()
		if p%2 != 0 {
			p--
		}
		if p <= 0 {
			continue
		}
		media, err := bind(host, p)
		if err != nil {
			lastErr = err
			continue
		}
		rtcp, err := bind(host, p+1)
		if err != nil {
			media.Close()
			lastErr = err
			continue
		}
		return newConn(media, rtcp, false), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no free even/odd port pair after 100 tries")
	}
	return nil, fmt.Errorf("rist: socket: bind ephemeral even/odd pair: %w", lastErr)
}

// ListenEphemeralFamily is ListenEphemeral with an explicit address family
// ("udp4" or "udp6"). A multicast sender must bind its egress socket in the
// group's family: a dual-stack ("udp", [::]) socket cannot have an IPv4
// multicast interface/TTL set on it (the ipv4 socket options reject a
// v6-bound fd with EINVAL). network "udp" (the default) preserves the
// dual-stack unicast behavior.
func ListenEphemeralFamily(network, host string) (*Conn, error) {
	media, err := bindNet(network, host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind media: %w", err)
	}
	rtcp, err := bindNet(network, host, 0)
	if err != nil {
		media.Close()
		return nil, fmt.Errorf("rist: socket: bind rtcp: %w", err)
	}
	return newConn(media, rtcp, false), nil
}

// ListenEphemeralSingleFamily is ListenEphemeralSingle with an explicit address
// family ("udp4"/"udp6"); see ListenEphemeralFamily for why a multicast sender
// needs it.
func ListenEphemeralSingleFamily(network, host string) (*Conn, error) {
	c, err := bindNet(network, host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind main: %w", err)
	}
	return newConn(c, c, true), nil
}

// FromConns wraps two already-bound UDP sockets (media even, rtcp odd). It
// lets a caller inject sockets — for tests or to satisfy a PacketConn-style
// API — and takes ownership: Close closes both.
func FromConns(media, rtcp *net.UDPConn) *Conn {
	return newConn(media, rtcp, false)
}

// ListenSingle binds one UDP socket on host:port for the Main profile, where a
// single GRE-tunnelled port carries both media and feedback (TR-06-2). Unlike
// Listen it accepts any port (the Main port is not constrained to be even);
// host may be empty to bind all interfaces. It is the Main receiver-side
// constructor. Reads and writes use ReadMedia/WriteMedia on the single socket.
func ListenSingle(host string, port int) (*Conn, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("rist: socket: main port %d out of range", port)
	}
	c, err := bind(host, port)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind main port %d: %w", port, err)
	}
	return newConn(c, c, true), nil
}

// ListenEphemeralSingle binds one OS-chosen UDP socket on host (empty host
// binds all interfaces) for the Main profile. It is the Main sender-side
// constructor; the receiver learns the local port from inbound datagrams.
func ListenEphemeralSingle(host string) (*Conn, error) {
	c, err := bind(host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind main: %w", err)
	}
	return newConn(c, c, true), nil
}

// bind opens an unconnected UDP socket on host:port using the dual-stack "udp"
// network (the default unicast behavior).
func bind(host string, port int) (*net.UDPConn, error) {
	return bindNet("udp", host, port)
}

// BindUDP opens an unconnected UDP socket on host:port, for an auxiliary stream
// the host layer manages itself (e.g. the separate-port SMPTE 2022-1 FEC sockets).
func BindUDP(host string, port int) (*net.UDPConn, error) {
	return bind(host, port)
}

// SocketBufferBytes is the UDP send and receive buffer ristgo requests on every
// socket. The OS-default UDP receive buffer (notably ~208 KB on Linux) overflows
// under a sender's startup burst, silently dropping media at the kernel before the
// read goroutine drains it — a loss the peer then has to recover by retransmission,
// or, if its congestion control reacts to the reported loss, by throttling. libRIST
// raises its own socket buffers (1 MB) for the same reason. The kernel clamps the
// request to its maximum (net.core.rmem_max / wmem_max on Linux), so enlarging it is
// best-effort: a clamp or failure must not fail the bind.
const SocketBufferBytes = 1 << 21 // 2 MiB

// bindNet opens an unconnected UDP socket on host:port in the given network
// ("udp", "udp4", or "udp6"). An empty network defaults to "udp".
func bindNet(network, host string, port int) (*net.UDPConn, error) {
	if network == "" {
		network = "udp"
	}
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if host == "" {
		addr.IP = nil
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, err
	}
	// Best-effort buffer enlargement; the kernel clamps to its max, and a failure
	// to grow the buffer must not fail the bind.
	_ = conn.SetReadBuffer(SocketBufferBytes)
	_ = conn.SetWriteBuffer(SocketBufferBytes)
	return conn, nil
}

// MediaPort returns the local media (even) port the transport is bound to.
func (c *Conn) MediaPort() int { return c.media.Load().LocalAddr().(*net.UDPAddr).Port }

// ReadMedia reads one media (RTP) datagram into buf, returning the byte count
// and the source address (the sender's media address, for a receiver). When DTLS
// is enabled (Main profile), it returns the next decrypted application record and
// the established peer's address.
//
// It uses (*net.UDPConn).ReadFromUDPAddrPort so the per-datagram receive path is
// allocation-free: a netip.AddrPort is a value type, so the source address is not
// heap-allocated the way ReadFromUDP's *net.UDPAddr was.
func (c *Conn) ReadMedia(buf []byte) (int, netip.AddrPort, error) {
	if c.dtls != nil {
		n, err := c.dtls.Read(buf)
		return n, c.dtlsPeer, err
	}
	return c.media.Load().ReadFromUDPAddrPort(buf)
}

// ReadRTCP reads one RTCP datagram into buf, returning the byte count and the
// source address. Like ReadMedia it reads via ReadFromUDPAddrPort (alloc-free).
func (c *Conn) ReadRTCP(buf []byte) (int, netip.AddrPort, error) {
	return c.rtcp.Load().ReadFromUDPAddrPort(buf)
}

// WriteMedia sends a media (RTP) datagram to dst. When DTLS is enabled (Main
// profile) it seals b as a DTLS application record to the established peer and
// dst is ignored (the DTLS session is bound to one peer).
func (c *Conn) WriteMedia(b []byte, dst netip.AddrPort) error {
	if c.dtls != nil {
		_, err := c.dtls.Write(b)
		return err
	}
	_, err := c.media.Load().WriteToUDPAddrPort(b, dst)
	return err
}

// WriteRTCP sends an RTCP datagram to dst.
func (c *Conn) WriteRTCP(b []byte, dst netip.AddrPort) error {
	_, err := c.rtcp.Load().WriteToUDPAddrPort(b, dst)
	return err
}

// Close closes both sockets, unblocking any in-flight reads (which return a
// net.ErrClosed-wrapped error). It is safe to call more than once.
func (c *Conn) Close() error {
	err := c.media.Load().Close()
	if c.single {
		return err // media and rtcp are the same socket; close it once
	}
	if e := c.rtcp.Load().Close(); e != nil && err == nil {
		err = e
	}
	return err
}

// RebindGen returns the current rebind generation; the session read loop compares
// it across a read error to tell a Rebind-induced close (continue on the fresh
// socket) from a genuine teardown (exit).
func (c *Conn) RebindGen() uint64 { return c.rebindGen.Load() }

// Rebind recovers a caller-receiver NAT/dynamic-IP source-port change on a
// single-socket (Main/Advanced) plaintext-or-PSK transport (libRIST's
// try_caller_socket_rebind): it binds a FRESH ephemeral socket on the same host
// family and atomically swaps it in, then closes the old one (unblocking the
// reader, which continues on the new socket after seeing RebindGen advance). The
// fresh local port makes the peer re-learn this side's source on the next outbound
// keepalive. It is rejected for a DTLS connection (the handshake is bound to the
// old socket) and for a non-single (Simple even/odd) transport.
func (c *Conn) Rebind() error {
	if c.dtls != nil {
		return errors.New("rist: socket: cannot rebind a DTLS connection")
	}
	if !c.single {
		return errors.New("rist: socket: rebind is only supported on a single-socket (Main/Advanced) transport")
	}
	old := c.media.Load()
	la, ok := old.LocalAddr().(*net.UDPAddr)
	if !ok {
		return errors.New("rist: socket: rebind: unexpected local address type")
	}
	network := "udp"
	if la.IP != nil {
		if la.IP.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	fresh, err := bindNet(network, "", 0) // fresh OS-chosen ephemeral port
	if err != nil {
		return fmt.Errorf("rist: socket: rebind: %w", err)
	}
	// Publish the new socket BEFORE bumping the generation and closing the old one,
	// so the reader (which re-loads media after its blocked read errors) always sees
	// the fresh socket once it observes the advanced generation.
	c.media.Store(fresh)
	c.rtcp.Store(fresh)
	c.rebindGen.Add(1)
	_ = old.Close()
	return nil
}
